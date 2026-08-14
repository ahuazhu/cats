//! Host-scoped recovery coordination shared by product mutation roots.
//!
//! A provider attempt is not itself product authority.  The Control recovery
//! attempt freezes one complete assigned set under the source NodeIdentity
//! lock.  While that attempt can still publish a terminal batch, ordinary
//! product mutations must not change either the frozen Cats or create a new
//! assignment on the same Node.

use std::collections::{BTreeMap, BTreeSet};

use cats_api::error::ApiError;
use cats_api::runtime_host_loss_recovery::{
    host_loss_recovery_terminal_receipt_sha256, validate_host_loss_recovery_apply_v1,
    validate_host_loss_recovery_discovery_result_v1, validate_host_loss_recovery_discovery_v1,
    HostLossRecoveryApplyResultV1, HostLossRecoveryApplyV1, HostLossRecoveryBlockedReasonV1,
    HostLossRecoveryCommittedCatV1, HostLossRecoveryCurrentAuthorityComponentV1,
    HostLossRecoveryDiscoveryOutcomeV1, HostLossRecoveryDiscoveryResultV1,
    HostLossRecoveryDiscoveryV1, HostLossRecoveryInventoryUnavailableReasonV1,
    HostLossRecoveryStrictVolumeProblemV1, HostLossRecoveryTargetProblemV1,
    HostLossRecoveryTerminalOutcomeV1, HostLossRecoveryTerminalReceiptV1,
};
use cats_api::runtime_reconciliation::{
    decode_desired_read_snapshot, decode_node_observation, encode_desired_read_snapshot,
    encode_node_observation, encode_operation, spec_digest, AgentSession, AuthorizationState,
    ContractVersion, DesiredReadSnapshot, DesiredRuntimeSpec, Epoch, Id, NodeIdentity,
    NodeIdentityState, Operation, OperationFailure, OperationPhase, OperationTerminal,
    ProviderScope, Revision, SessionBinding, Sha256Digest, UnixMillis, VolumeAcquire,
    VolumeAdminState, VolumeAuthorization, WireU64,
};
use cats_storage::authority::{
    validate_authorization_record, validate_volume_record, VolumeOwnerBinding,
};
use cats_storage::host_fence::{
    host_fence_authority_bindings_sha256, resolve_host_fence_authority_host_v1,
    HostFenceAttemptRequest, HostFenceAuthorityBindingsV1, HostFenceBinding,
    ObjectWriterFenceTarget,
};
use cats_storage::object_write_authority::{
    validate_object_write_authority, ObjectWriteAuthority, ObjectWriteAuthorityState,
};
use cats_storage::trusted_host_fence::{
    decode_trusted_host_fence_event_v1, encode_trusted_host_fence_event_v1,
    trusted_host_fence_event_v1, validate_trusted_host_fence_event_v1, TrustedHostFenceEventV1,
};
use cats_storage::trusted_host_recovery::{
    canonicalize_trusted_host_fence_recovery_blocked_reasons_v1,
    decode_trusted_host_fence_recovery_attempt_v1, encode_trusted_host_fence_recovery_attempt_v1,
    trusted_host_fence_assigned_cat_sha256, trusted_host_fence_assigned_set_sha256,
    trusted_host_fence_assigned_volume_sha256, trusted_host_fence_batch_recovery_sha256,
    trusted_host_fence_recovery_attempt_id, trusted_host_fence_recovery_attempt_sha256,
    trusted_host_fence_recovery_blockers, validate_trusted_host_fence_batch_recovery_commit_v1,
    validate_trusted_host_fence_recovery_attempt_v1, TrustedHostFenceAssignedCatInventoryV1,
    TrustedHostFenceAssignedCatV1, TrustedHostFenceAssignedVolumeInventoryV1,
    TrustedHostFenceBatchRecoveryCommitReceiptV1, TrustedHostFenceBatchRecoveryCommitV1,
    TrustedHostFenceBlockedReceiptV1, TrustedHostFenceCanonicalArtifactV1,
    TrustedHostFenceCurrentAuthorityComponentV1, TrustedHostFenceExpectedVolumeAuthorityV1,
    TrustedHostFenceInventoryUnavailableReasonV1, TrustedHostFenceRecoveryAttemptRecordV1,
    TrustedHostFenceRecoveryAttemptStateV1, TrustedHostFenceRecoveryAttemptV1,
    TrustedHostFenceRecoveryBlockedReasonV1, TrustedHostFenceRecoveryTargetProblemV1,
    TrustedHostFenceSourceInventoryV1, MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS,
    MAX_TRUSTED_HOST_FENCE_TOTAL_VOLUME_PROOFS, TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES,
    TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES,
};
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use super::gateway_identity::lock_route_v2_machine_authority_exclusive;
use super::host_fence_commit::{
    insert_takeover_authorization, insert_terminal_event, replace_desired, retire_source_node,
    update_hostname_lookups,
};
use super::host_fence_provider_queue::{
    enqueue_host_fence_provider_attempt_in, load_queue_for_update, HostFenceProviderQueueStateV1,
};
use super::placement_planner::host_recovery_replacements_fit;
use super::placement_policy::load_policy_for_update;
use super::product_rows::{
    insert_operation, load_assigned_desired_for_update_bounded, load_cat_by_id_for_update,
    load_desired_for_update, load_operation_for_update, load_pending_operation_by_cat_for_update,
    update_operation,
};
use super::rows::{database_now, load_stored_volume_for_update, StoredVolume};
use super::runtime_spine::{
    load_admission_inventory_state_for_update, load_placement_admission_at_in,
    PlacementAdmissionLoad, PlacementAdmissionRejection,
};
use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_node_for_update,
    lock_exact_credential_lineage, CredentialLineageState,
};

use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::Store;

const BLOCKED_RECEIPT_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.recovery-blocked-receipt.v1";
const BATCH_RECEIPT_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.batch-recovery-receipt.v1";
const CAT_VOLUME_SET_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.assigned-cat-volume-set.v1";
const MAX_CAT_SNAPSHOT_BYTES: usize = TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES;
const MAX_VOLUMES_PER_ASSIGNED_CAT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrustedHostFenceBatchRecoveryStoreOutcomeV1 {
    Blocked(Box<TrustedHostFenceBlockedReceiptV1>),
    Committed(TrustedHostFenceBatchRecoveryCommitReceiptV1),
}

fn assigned_set_limit_problem(
    volume_counts: impl IntoIterator<Item = usize>,
) -> Option<&'static str> {
    let mut cat_count = 0_usize;
    let mut total_volumes = 0_usize;
    for volume_count in volume_counts {
        cat_count = match cat_count.checked_add(1) {
            Some(count) => count,
            None => return Some("assigned Cat count overflow"),
        };
        if volume_count == 0 || volume_count > MAX_VOLUMES_PER_ASSIGNED_CAT {
            return Some("one assigned Cat exceeds its Volume proof bound");
        }
        total_volumes = match total_volumes.checked_add(volume_count) {
            Some(total) => total,
            None => return Some("assigned Volume proof count overflow"),
        };
        if total_volumes > MAX_TRUSTED_HOST_FENCE_TOTAL_VOLUME_PROOFS {
            return Some("assigned Volume proof set exceeds its hard cap");
        }
    }
    if cat_count == 0 || cat_count > MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS {
        return Some("assigned Cat set exceeds its hard cap");
    }
    None
}

fn application(error: ApiError) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(error)
}

fn corrupt(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

fn conflict(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::conflict(message.into()))
}

fn rejected(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

fn pg(value: u64, label: &'static str) -> AuthorityTxResult<i64> {
    i64::try_from(value).map_err(|_| corrupt(format!("{label} exceeds PostgreSQL BIGINT")))
}

fn wire(value: i64, label: &'static str) -> AuthorityTxResult<u64> {
    u64::try_from(value).map_err(|_| corrupt(format!("stored {label} is negative")))
}

fn time(value: i64, label: &'static str) -> AuthorityTxResult<UnixMillis> {
    UnixMillis::new(wire(value, label)?)
        .ok_or_else(|| corrupt(format!("stored {label} is invalid")))
}

fn canonical<T: Serialize>(value: &T, context: &'static str) -> AuthorityTxResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| corrupt(format!("encode {context}: {error}")))
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    context: &'static str,
) -> AuthorityTxResult<T> {
    let value = serde_json::from_slice(bytes)
        .map_err(|error| corrupt(format!("decode {context}: {error}")))?;
    if canonical(&value, context)? != bytes {
        return Err(corrupt(format!("stored {context} is not canonical JSON")));
    }
    Ok(value)
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
    context: &'static str,
) -> AuthorityTxResult<Sha256Digest> {
    let bytes = canonical(value, context)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn content_sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

#[derive(Debug, Clone)]
struct SourceArtifacts {
    full_observation_bytes: Option<Vec<u8>>,
    assigned_snapshot_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct StoredRecoveryAttempt {
    record: TrustedHostFenceRecoveryAttemptRecordV1,
    source_artifacts: SourceArtifacts,
}

fn cat_volume_set_sha256(cat: &TrustedHostFenceAssignedCatV1) -> AuthorityTxResult<Sha256Digest> {
    let digests = cat
        .volumes
        .iter()
        .map(trusted_host_fence_assigned_volume_sha256)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| corrupt(format!("digest assigned Volume proof: {error}")))?;
    domain_digest(
        CAT_VOLUME_SET_DIGEST_DOMAIN,
        &digests,
        "assigned Cat Volume digest set",
    )
}

fn recovery_attempt_bytes(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> AuthorityTxResult<(Vec<u8>, Sha256Digest)> {
    let bytes = encode_trusted_host_fence_recovery_attempt_v1(attempt)
        .map_err(|error| rejected(format!("invalid Host recovery attempt: {error}")))?;
    if bytes.len() > TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES {
        return Err(rejected("Host recovery attempt exceeds its hard byte cap"));
    }
    let digest = trusted_host_fence_recovery_attempt_sha256(attempt)
        .map_err(|error| rejected(format!("digest Host recovery attempt: {error}")))?;
    Ok((bytes, digest))
}

const ATTEMPT_SELECT: &str = "
    fence_attempt_id, apply_id, attempt_bytes, attempt_sha256,
    provider, host_partition, host_account_id, host_region,
    immutable_host_id, node_id, expected_node_boot_id,
    agent_instance_id, expected_agent_session_epoch,
    physical_snapshot_state, inventory_epoch, inventory_digest,
    inventory_read_position, full_observation_id,
    full_observation_bytes, full_observation_sha256, full_observation_length,
    assigned_snapshot_bytes, assigned_snapshot_sha256, assigned_snapshot_length,
    assigned_set_sha256, assigned_cat_count, state,
    provider_evidence_bytes, provider_evidence_sha256,
    provider_completed_at_unix_ms, outcome_bytes, outcome_sha256,
    enqueued_at_unix_ms, outcome_completed_at_unix_ms";

fn load_attempt_for_update(
    transaction: &mut Transaction<'_>,
    fence_attempt_id: &Id,
) -> AuthorityTxResult<Option<StoredRecoveryAttempt>> {
    let sql = format!(
        "SELECT {ATTEMPT_SELECT}
           FROM trusted_host_fence_recovery_attempts_v1
          WHERE fence_attempt_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&fence_attempt_id.as_str()])?
        .map(|row| decode_attempt_row(transaction, &row))
        .transpose()
}

fn lock_recovery_apply_id(
    transaction: &mut Transaction<'_>,
    apply_id: &cats_api::runtime_reconciliation::RandomId128,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':host-recovery-apply:' || $1, 0::BIGINT))",
        &[&apply_id.as_str()],
    )?;
    Ok(())
}

fn load_attempt_by_apply_for_update(
    transaction: &mut Transaction<'_>,
    apply_id: &cats_api::runtime_reconciliation::RandomId128,
) -> AuthorityTxResult<Option<StoredRecoveryAttempt>> {
    let sql = format!(
        "SELECT {ATTEMPT_SELECT}
           FROM trusted_host_fence_recovery_attempts_v1
          WHERE apply_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&apply_id.as_str()])?
        .map(|row| decode_attempt_row(transaction, &row))
        .transpose()
}

fn decode_attempt_row(
    transaction: &mut Transaction<'_>,
    row: &Row,
) -> AuthorityTxResult<StoredRecoveryAttempt> {
    let attempt_bytes: Vec<u8> = row.try_get("attempt_bytes")?;
    let attempt = decode_trusted_host_fence_recovery_attempt_v1(&attempt_bytes)
        .map_err(|error| corrupt(format!("decode stored Host recovery attempt: {error}")))?;
    let attempt_sha256 = trusted_host_fence_recovery_attempt_sha256(&attempt)
        .map_err(|error| corrupt(format!("digest stored Host recovery attempt: {error}")))?;
    if row.try_get::<_, String>("attempt_sha256")? != attempt_sha256.as_str()
        || row.try_get::<_, String>("fence_attempt_id")?
            != attempt.binding.fence_attempt_id.as_str()
        || row.try_get::<_, String>("apply_id")? != attempt.apply_id.as_str()
        || row.try_get::<_, String>("provider")? != attempt.binding.provider_scope.provider.as_str()
        || row.try_get::<_, String>("host_partition")?
            != attempt.binding.provider_scope.partition.as_str()
        || row.try_get::<_, String>("host_account_id")?
            != attempt.binding.provider_scope.account_id.as_str()
        || row.try_get::<_, String>("host_region")?
            != attempt.binding.provider_scope.region.as_str()
        || row.try_get::<_, String>("immutable_host_id")?
            != attempt.binding.immutable_host_id.as_str()
        || row.try_get::<_, String>("node_id")? != attempt.binding.node_id.as_str()
        || row.try_get::<_, String>("expected_node_boot_id")?
            != attempt.binding.expected_node_boot_id.as_str()
        || wire(
            row.try_get("expected_agent_session_epoch")?,
            "attempt AgentSession epoch",
        )? != attempt.binding.expected_agent_session_epoch.get()
        || row.try_get::<_, String>("assigned_set_sha256")? != attempt.assigned_set_sha256.as_str()
        || wire(row.try_get("assigned_cat_count")?, "assigned Cat count")?
            != attempt.assigned_cats.len() as u64
    {
        return Err(corrupt(
            "stored Host recovery attempt scalar projection changed",
        ));
    }

    let source_artifacts = decode_source_projection(row, &attempt)?;
    let children = load_attempt_cats(transaction, &attempt.binding.fence_attempt_id)?;
    if assigned_set_limit_problem(children.iter().map(|cat| cat.volumes.len())).is_some()
        || children != attempt.assigned_cats
    {
        return Err(corrupt(
            "stored Host recovery child snapshots differ from the attempt or exceed their cap",
        ));
    }

    let state_name: String = row.try_get("state")?;
    let provider_event = row
        .try_get::<_, Option<Vec<u8>>>("provider_evidence_bytes")?
        .map(|bytes| {
            decode_trusted_host_fence_event_v1(&bytes)
                .map_err(|error| corrupt(format!("decode stored terminal Host event: {error}")))
        })
        .transpose()?;
    if let Some(event) = &provider_event {
        if event.binding != attempt.binding
            || row
                .try_get::<_, Option<String>>("provider_evidence_sha256")?
                .as_deref()
                != Some(event.provider_evidence_sha256.as_str())
            || row
                .try_get::<_, Option<i64>>("provider_completed_at_unix_ms")?
                .map(|value| wire(value, "provider completion time"))
                .transpose()?
                != Some(event.provider_evidence.completed_at_unix_ms.get())
        {
            return Err(corrupt(
                "stored Host recovery terminal evidence projection changed",
            ));
        }
    }
    let outcome_bytes: Option<Vec<u8>> = row.try_get("outcome_bytes")?;
    let outcome_sha: Option<String> = row.try_get("outcome_sha256")?;
    let outcome_time: Option<UnixMillis> = row
        .try_get::<_, Option<i64>>("outcome_completed_at_unix_ms")?
        .map(|value| time(value, "Host recovery outcome time"))
        .transpose()?;
    let enqueued_at = time(row.try_get("enqueued_at_unix_ms")?, "recovery enqueue time")?;
    let (state, updated_at_unix_ms) = match state_name.as_str() {
        "provider_pending"
            if provider_event.is_none()
                && outcome_bytes.is_none()
                && outcome_sha.is_none()
                && outcome_time.is_none() =>
        {
            (
                TrustedHostFenceRecoveryAttemptStateV1::ProviderPending,
                enqueued_at,
            )
        }
        "provider_terminal" if outcome_bytes.is_none() && outcome_sha.is_none() => {
            let event = provider_event
                .ok_or_else(|| corrupt("provider-terminal attempt has no terminal event"))?;
            let updated = event.committed_at_unix_ms;
            (
                TrustedHostFenceRecoveryAttemptStateV1::ProviderTerminal {
                    terminal_event: event,
                },
                updated,
            )
        }
        "blocked" => {
            let event = provider_event
                .ok_or_else(|| corrupt("Blocked recovery attempt has no terminal event"))?;
            let bytes =
                outcome_bytes.ok_or_else(|| corrupt("Blocked recovery attempt has no receipt"))?;
            let receipt: TrustedHostFenceBlockedReceiptV1 =
                decode_canonical(&bytes, "Host recovery Blocked receipt")?;
            cats_storage::trusted_host_recovery::validate_trusted_host_fence_blocked_receipt_v1(
                &receipt,
            )
            .map_err(|error| corrupt(format!("invalid stored Blocked receipt: {error}")))?;
            let digest = domain_digest(
                BLOCKED_RECEIPT_DIGEST_DOMAIN,
                &receipt,
                "Host recovery Blocked receipt",
            )?;
            if receipt.terminal_event != event
                || outcome_sha.as_deref() != Some(digest.as_str())
                || outcome_time != Some(receipt.blocked_at_unix_ms)
            {
                return Err(corrupt("stored Blocked receipt projection changed"));
            }
            let updated = receipt.blocked_at_unix_ms;
            (
                TrustedHostFenceRecoveryAttemptStateV1::Blocked { receipt },
                updated,
            )
        }
        "committed" => {
            let event = provider_event
                .ok_or_else(|| corrupt("committed recovery attempt has no terminal event"))?;
            let bytes = outcome_bytes
                .ok_or_else(|| corrupt("committed recovery attempt has no batch receipt"))?;
            let receipt: TrustedHostFenceBatchRecoveryCommitReceiptV1 =
                decode_canonical(&bytes, "Host recovery batch receipt")?;
            let request_sha = validate_trusted_host_fence_batch_recovery_commit_v1(
                &attempt,
                receipt.commit.as_ref(),
            )
            .map_err(|error| corrupt(format!("invalid stored batch receipt: {error}")))?;
            let receipt_sha = domain_digest(
                BATCH_RECEIPT_DIGEST_DOMAIN,
                &receipt,
                "Host recovery batch receipt",
            )?;
            if receipt.request_sha256 != request_sha
                || receipt.commit.terminal_event != event
                || outcome_sha.as_deref() != Some(receipt_sha.as_str())
                || outcome_time != Some(receipt.committed_at_unix_ms)
            {
                return Err(corrupt("stored batch receipt projection changed"));
            }
            let updated = receipt.committed_at_unix_ms;
            (
                TrustedHostFenceRecoveryAttemptStateV1::Committed {
                    terminal_event_id: event.event_id,
                    batch_request_sha256: request_sha,
                    committed_at_unix_ms: updated,
                },
                updated,
            )
        }
        _ => {
            return Err(corrupt(
                "stored Host recovery attempt state shape is invalid",
            ))
        }
    };
    Ok(StoredRecoveryAttempt {
        record: TrustedHostFenceRecoveryAttemptRecordV1 {
            attempt,
            attempt_sha256,
            state,
            updated_at_unix_ms,
        },
        source_artifacts,
    })
}

fn decode_source_projection(
    row: &Row,
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> AuthorityTxResult<SourceArtifacts> {
    let physical_state: String = row.try_get("physical_snapshot_state")?;
    let full_bytes: Option<Vec<u8>> = row.try_get("full_observation_bytes")?;
    let assigned_bytes: Option<Vec<u8>> = row.try_get("assigned_snapshot_bytes")?;
    match &attempt.source_inventory {
        TrustedHostFenceSourceInventoryV1::AcceptedFull {
            session,
            attestation,
            full_observation,
            assigned_snapshot,
        } => {
            let full_bytes = full_bytes
                .ok_or_else(|| corrupt("accepted Host recovery has no observation bytes"))?;
            let assigned_bytes = assigned_bytes
                .ok_or_else(|| corrupt("accepted Host recovery has no assigned snapshot bytes"))?;
            let observation = decode_node_observation(&full_bytes)
                .map_err(|error| corrupt(format!("decode frozen full observation: {error}")))?;
            if encode_node_observation(&observation)
                .map_err(|error| corrupt(format!("encode frozen full observation: {error}")))?
                != full_bytes
            {
                return Err(corrupt("frozen full observation is not canonical"));
            }
            let snapshot = decode_desired_read_snapshot(&assigned_bytes)
                .map_err(|error| corrupt(format!("decode frozen Desired snapshot: {error}")))?;
            if encode_desired_read_snapshot(&snapshot)
                .map_err(|error| corrupt(format!("encode frozen Desired snapshot: {error}")))?
                != assigned_bytes
            {
                return Err(corrupt("frozen Desired snapshot is not canonical"));
            }
            if physical_state != "accepted_full"
                || observation.node_id != session.node_id
                || observation.node_boot_id != session.node_boot_id
                || observation.agent_instance_id != session.agent_instance_id
                || observation.agent_session_epoch != session.agent_session_epoch
                || snapshot.session != *session
                || snapshot.desired_specs
                    != attempt
                        .assigned_cats
                        .iter()
                        .map(|cat| cat.expected_current_desired.clone())
                        .collect::<Vec<_>>()
                || row.try_get::<_, Option<i64>>("inventory_epoch")?
                    != Some(pg(attestation.inventory_epoch.get(), "inventory epoch")?)
                || row
                    .try_get::<_, Option<String>>("inventory_digest")?
                    .as_deref()
                    != Some(attestation.inventory_digest.as_str())
                || row.try_get::<_, Option<i64>>("inventory_read_position")?
                    != Some(pg(
                        attestation.inventory_read_position.get(),
                        "inventory read position",
                    )?)
                || row
                    .try_get::<_, Option<String>>("full_observation_id")?
                    .as_deref()
                    != Some(observation.observation_id.as_str())
                || content_sha256(&full_bytes) != full_observation.content_sha256
                || full_bytes.len() as u64 != full_observation.length_bytes.get()
                || row
                    .try_get::<_, Option<String>>("full_observation_sha256")?
                    .as_deref()
                    != Some(full_observation.content_sha256.as_str())
                || row.try_get::<_, Option<i64>>("full_observation_length")?
                    != Some(pg(
                        full_observation.length_bytes.get(),
                        "full observation length",
                    )?)
                || content_sha256(&assigned_bytes) != assigned_snapshot.content_sha256
                || assigned_bytes.len() as u64 != assigned_snapshot.length_bytes.get()
                || row
                    .try_get::<_, Option<String>>("assigned_snapshot_sha256")?
                    .as_deref()
                    != Some(assigned_snapshot.content_sha256.as_str())
                || row.try_get::<_, Option<i64>>("assigned_snapshot_length")?
                    != Some(pg(
                        assigned_snapshot.length_bytes.get(),
                        "assigned snapshot length",
                    )?)
            {
                return Err(corrupt(
                    "stored accepted inventory projection changed or is inconsistent",
                ));
            }
            Ok(SourceArtifacts {
                full_observation_bytes: Some(full_bytes),
                assigned_snapshot_bytes: Some(assigned_bytes),
            })
        }
        TrustedHostFenceSourceInventoryV1::Unavailable { .. } => {
            let has_scalar = row.try_get::<_, Option<i64>>("inventory_epoch")?.is_some()
                || row
                    .try_get::<_, Option<String>>("inventory_digest")?
                    .is_some()
                || row
                    .try_get::<_, Option<i64>>("inventory_read_position")?
                    .is_some()
                || row
                    .try_get::<_, Option<String>>("full_observation_id")?
                    .is_some()
                || row
                    .try_get::<_, Option<String>>("full_observation_sha256")?
                    .is_some()
                || row
                    .try_get::<_, Option<i64>>("full_observation_length")?
                    .is_some()
                || row
                    .try_get::<_, Option<String>>("assigned_snapshot_sha256")?
                    .is_some()
                || row
                    .try_get::<_, Option<i64>>("assigned_snapshot_length")?
                    .is_some();
            if physical_state != "unavailable"
                || full_bytes.is_some()
                || assigned_bytes.is_some()
                || has_scalar
            {
                return Err(corrupt(
                    "stored unavailable inventory has accepted proof fields",
                ));
            }
            Ok(SourceArtifacts {
                full_observation_bytes: None,
                assigned_snapshot_bytes: None,
            })
        }
    }
}

fn load_attempt_cats(
    transaction: &mut Transaction<'_>,
    fence_attempt_id: &Id,
) -> AuthorityTxResult<Vec<TrustedHostFenceAssignedCatV1>> {
    let rows = transaction.query(
        "SELECT ordinal, cat_id, cat_snapshot_bytes, cat_snapshot_sha256,
                workspace_id, expected_desired_revision,
                expected_desired_spec_digest, expected_old_operation_id,
                volume_count, volume_set_sha256
           FROM trusted_host_fence_recovery_attempt_cats_v1
          WHERE fence_attempt_id=$1 ORDER BY ordinal FOR UPDATE",
        &[&fence_attempt_id.as_str()],
    )?;
    let mut cats = Vec::with_capacity(rows.len());
    for (expected_ordinal, row) in rows.iter().enumerate() {
        if wire(row.try_get("ordinal")?, "assigned Cat ordinal")? != expected_ordinal as u64 {
            return Err(corrupt("stored assigned Cat ordinals are not contiguous"));
        }
        let bytes: Vec<u8> = row.try_get("cat_snapshot_bytes")?;
        if bytes.len() > MAX_CAT_SNAPSHOT_BYTES {
            return Err(corrupt("stored assigned Cat snapshot exceeds its hard cap"));
        }
        let cat: TrustedHostFenceAssignedCatV1 =
            decode_canonical(&bytes, "assigned Cat recovery snapshot")?;
        let digest = trusted_host_fence_assigned_cat_sha256(&cat)
            .map_err(|error| corrupt(format!("digest assigned Cat snapshot: {error}")))?;
        let volume_digest = cat_volume_set_sha256(&cat)?;
        if row.try_get::<_, String>("cat_snapshot_sha256")? != digest.as_str()
            || row.try_get::<_, String>("cat_id")? != cat.expected_current_desired.cat_id.as_str()
            || row.try_get::<_, String>("workspace_id")?
                != cat.expected_current_desired.workspace_id.as_str()
            || wire(
                row.try_get("expected_desired_revision")?,
                "expected Desired revision",
            )? != cat.expected_current_desired.desired_revision.get()
            || row.try_get::<_, String>("expected_desired_spec_digest")?
                != cat.expected_current_desired.spec_digest.as_str()
            || row.try_get::<_, String>("expected_old_operation_id")?
                != cat.expected_old_operation.operation_id.as_str()
            || wire(row.try_get("volume_count")?, "assigned Volume count")?
                != cat.volumes.len() as u64
            || row.try_get::<_, String>("volume_set_sha256")? != volume_digest.as_str()
        {
            return Err(corrupt("stored assigned Cat scalar projection changed"));
        }
        cats.push(cat);
    }
    Ok(cats)
}

fn validate_source_identity(
    identity: &NodeIdentity,
    apply: &HostLossRecoveryApplyV1,
    bindings: &HostFenceAuthorityBindingsV1,
) -> AuthorityTxResult<()> {
    if identity.state != NodeIdentityState::Provisioned
        || identity.node_id != apply.source_node_id
        || identity.provider_scope != bindings.provider_scope
        || resolve_host_fence_authority_host_v1(
            bindings,
            &identity.immutable_host_id,
            &identity.node_id,
        )
        .is_err()
    {
        return Err(conflict(
            "Host recovery authority artifact does not bind the current provisioned NodeIdentity",
        ));
    }
    Ok(())
}

fn require_active_credential_lineage(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
) -> AuthorityTxResult<()> {
    if lock_exact_credential_lineage(transaction, identity)?
        .is_some_and(|state| state != CredentialLineageState::Active)
    {
        return Err(conflict(
            "Host recovery source credential lineage is no longer active",
        ));
    }
    Ok(())
}

fn validate_source_session(
    session: &AgentSession,
    apply: &HostLossRecoveryApplyV1,
    immutable_host_id: &Id,
) -> AuthorityTxResult<()> {
    if session.node_id != apply.source_node_id
        || session.immutable_host_id != *immutable_host_id
        || session.node_boot_id != apply.expected_node_boot_id
        || session.agent_session_epoch != apply.expected_agent_session_epoch
    {
        return Err(conflict(
            "Host recovery does not bind the exact current AgentSession",
        ));
    }
    Ok(())
}

fn load_current_open_writer_for_update(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
    bindings: &HostFenceAuthorityBindingsV1,
) -> AuthorityTxResult<ObjectWriteAuthority> {
    let scope = &bindings.provider_scope;
    let rows = transaction.query(
        "SELECT record::text AS record_json
           FROM object_write_authorities
          WHERE host_provider=$1 AND host_partition=$2
            AND host_account_id=$3 AND host_region=$4
            AND immutable_host_id=$5 AND state='open'
          ORDER BY writer_authority_id COLLATE \"C\"
          LIMIT 2 FOR UPDATE",
        &[
            &scope.provider.as_str(),
            &scope.partition.as_str(),
            &scope.account_id.as_str(),
            &scope.region.as_str(),
            &identity.immutable_host_id.as_str(),
        ],
    )?;
    let [row] = rows.as_slice() else {
        return Err(conflict(
            "Host recovery authority artifact does not select exactly one current Open writer",
        ));
    };
    let authority: ObjectWriteAuthority = serde_json::from_str(row.try_get("record_json")?)
        .map_err(|error| corrupt(format!("decode current object writer: {error}")))?;
    validate_object_write_authority(&authority)
        .map_err(|error| corrupt(format!("invalid current object writer: {error}")))?;
    if !matches!(authority.state, ObjectWriteAuthorityState::Open)
        || authority.writer.host_provider_scope != bindings.provider_scope
        || authority.writer.immutable_host_id != identity.immutable_host_id
        || authority.writer.node_id != identity.node_id
        || authority.writer.object_provider_scope != bindings.provider_scope
        || authority.writer.workload_principal_id != bindings.workload_principal_id
        || authority.writer.object_store_scope_id != bindings.object_store_scope_id
    {
        return Err(corrupt(
            "current Open object writer differs from its indexed authority projection",
        ));
    }
    Ok(authority)
}

fn load_attempt_volumes(
    transaction: &mut Transaction<'_>,
    desired: &[DesiredRuntimeSpec],
    source_node_id: &Id,
) -> AuthorityTxResult<BTreeMap<Id, StoredVolume>> {
    let mut intents = BTreeMap::new();
    for spec in desired {
        for intent in &spec.volumes {
            if intents.insert(intent.volume_id.clone(), intent).is_some() {
                return Err(corrupt(
                    "one source Node assigned the same Volume to more than one intent",
                ));
            }
        }
    }
    let mut volumes = BTreeMap::new();
    for (volume_id, intent) in intents {
        let stored = load_stored_volume_for_update(transaction, &volume_id)?
            .ok_or_else(|| conflict("Host recovery assigned Volume is absent"))?;
        validate_volume_record(&stored.record)
            .map_err(|error| corrupt(format!("invalid current Volume record: {error}")))?;
        let expected_owner = VolumeOwnerBinding {
            volume_id: volume_id.clone(),
            owner_node_id: source_node_id.clone(),
            attachment_id: intent.attachment_id.clone(),
            attachment_epoch: stored.record.lease_epoch,
        };
        if stored.record.size_bytes != intent.size_bytes
            || stored.record.durability != intent.durability
            || !matches!(stored.record.admin_state, VolumeAdminState::Active)
            || stored.record.lease_owner.as_ref() != Some(&intent.attachment_id)
            || stored.owner_binding.as_ref() != Some(&expected_owner)
        {
            return Err(conflict(
                "Host recovery assigned Volume is not owned by the exact source intent",
            ));
        }
        volumes.insert(volume_id, stored);
    }
    Ok(volumes)
}

fn unavailable_source(
    session: &AgentSession,
    reason: TrustedHostFenceInventoryUnavailableReasonV1,
    now: UnixMillis,
) -> (TrustedHostFenceSourceInventoryV1, SourceArtifacts) {
    (
        TrustedHostFenceSourceInventoryV1::Unavailable {
            session: session_binding(session),
            reason,
            recorded_at_unix_ms: now,
        },
        SourceArtifacts {
            full_observation_bytes: None,
            assigned_snapshot_bytes: None,
        },
    )
}

fn accepted_source(
    snapshot: &super::runtime_spine::PlacementAdmissionSnapshot,
    assigned_snapshot: &DesiredReadSnapshot,
) -> AuthorityTxResult<(TrustedHostFenceSourceInventoryV1, SourceArtifacts)> {
    let full_observation_bytes = encode_node_observation(&snapshot.full_inventory_observation)
        .map_err(|error| corrupt(format!("encode accepted full observation: {error}")))?;
    let assigned_snapshot_bytes = encode_desired_read_snapshot(assigned_snapshot)
        .map_err(|error| corrupt(format!("encode accepted Desired snapshot: {error}")))?;
    let full_length = WireU64::new(full_observation_bytes.len() as u64)
        .ok_or_else(|| corrupt("accepted full observation length is zero"))?;
    let assigned_length = WireU64::new(assigned_snapshot_bytes.len() as u64)
        .ok_or_else(|| corrupt("accepted Desired snapshot length is zero"))?;
    let source = TrustedHostFenceSourceInventoryV1::AcceptedFull {
        session: session_binding(&snapshot.agent_session),
        attestation: Box::new(snapshot.inventory_attestation.clone()),
        full_observation: TrustedHostFenceCanonicalArtifactV1 {
            content_sha256: content_sha256(&full_observation_bytes),
            length_bytes: full_length,
        },
        assigned_snapshot: TrustedHostFenceCanonicalArtifactV1 {
            content_sha256: content_sha256(&assigned_snapshot_bytes),
            length_bytes: assigned_length,
        },
    };
    Ok((
        source,
        SourceArtifacts {
            full_observation_bytes: Some(full_observation_bytes),
            assigned_snapshot_bytes: Some(assigned_snapshot_bytes),
        },
    ))
}

fn observation_is_complete_for_attempt(
    desired: &[DesiredRuntimeSpec],
    observation: &cats_api::runtime_reconciliation::NodeObservation,
) -> bool {
    if observation.runtimes.len() != desired.len() {
        return false;
    }
    desired.iter().all(|spec| {
        let runtimes = observation
            .runtimes
            .iter()
            .filter(|runtime| runtime.cat_id == spec.cat_id)
            .collect::<Vec<_>>();
        let [runtime] = runtimes.as_slice() else {
            return false;
        };
        runtime.volumes.len() == spec.volumes.len()
            && spec.volumes.iter().all(|intent| {
                runtime
                    .volumes
                    .iter()
                    .filter(|volume| {
                        volume.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
                            && volume.volume_id == intent.volume_id
                    })
                    .count()
                    == 1
            })
    })
}

fn derive_assigned_cats(
    desired: Vec<DesiredRuntimeSpec>,
    operations: BTreeMap<Id, Operation>,
    volumes: &BTreeMap<Id, StoredVolume>,
    observation: Option<&cats_api::runtime_reconciliation::NodeObservation>,
) -> AuthorityTxResult<Vec<TrustedHostFenceAssignedCatV1>> {
    let mut result = Vec::with_capacity(desired.len());
    for spec in desired {
        let operation = operations
            .get(&spec.cat_id)
            .ok_or_else(|| corrupt("locked assigned Cat lost its Pending Operation"))?
            .clone();
        let observed_runtime = observation.and_then(|full| {
            full.runtimes
                .iter()
                .find(|runtime| runtime.cat_id == spec.cat_id)
        });
        let inventory = match observed_runtime {
            Some(runtime) => TrustedHostFenceAssignedCatInventoryV1::AcceptedFull {
                observed_runtime: Box::new(runtime.clone()),
            },
            None => TrustedHostFenceAssignedCatInventoryV1::Unavailable,
        };
        let mut proofs = Vec::with_capacity(spec.volumes.len());
        for intent in &spec.volumes {
            let stored = volumes
                .get(&intent.volume_id)
                .ok_or_else(|| corrupt("locked assigned Volume disappeared from snapshot"))?;
            let owner = stored
                .owner_binding
                .clone()
                .ok_or_else(|| conflict("assigned recovery Volume has no exact owner"))?;
            let volume_inventory = match observed_runtime {
                Some(runtime) => {
                    let observed = runtime
                        .volumes
                        .iter()
                        .find(|volume| {
                            volume.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
                                && volume.volume_id == intent.volume_id
                        })
                        .ok_or_else(|| corrupt("accepted recovery inventory lost a Volume"))?;
                    TrustedHostFenceAssignedVolumeInventoryV1::AcceptedFull {
                        observed_volume: Box::new(observed.clone()),
                    }
                }
                None => TrustedHostFenceAssignedVolumeInventoryV1::Unavailable,
            };
            proofs.push(TrustedHostFenceExpectedVolumeAuthorityV1 {
                volume_intent_id: intent.volume_intent_id.clone(),
                expected_current_volume: stored.record.clone(),
                expected_owner: owner,
                inventory: volume_inventory,
            });
        }
        result.push(TrustedHostFenceAssignedCatV1 {
            expected_current_desired: spec,
            expected_old_operation: operation,
            inventory,
            volumes: proofs,
        });
    }
    Ok(result)
}

fn derive_attempt_in(
    transaction: &mut Transaction<'_>,
    apply: &HostLossRecoveryApplyV1,
    principal: &cats_api::runtime_reconciliation::FleetPolicyPrincipal,
    authority_bindings: &HostFenceAuthorityBindingsV1,
    identity: &NodeIdentity,
    session: &AgentSession,
    now: UnixMillis,
) -> AuthorityTxResult<(TrustedHostFenceRecoveryAttemptV1, SourceArtifacts)> {
    let desired = load_assigned_desired_for_update_bounded(
        transaction,
        &identity.node_id,
        MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS.saturating_add(1),
    )?;
    if let Some(problem) = assigned_set_limit_problem(desired.iter().map(|spec| spec.volumes.len()))
    {
        return Err(rejected(format!("Host recovery {problem}")));
    }

    let mut operations = BTreeMap::new();
    for spec in &desired {
        let cat = load_cat_by_id_for_update(transaction, &spec.cat_id)?
            .ok_or_else(|| corrupt("assigned recovery Desired has no Cat row"))?;
        if cat.workspace_id != spec.workspace_id {
            return Err(corrupt("assigned recovery Cat changed Workspace"));
        }
        let operation = load_pending_operation_by_cat_for_update(transaction, &spec.cat_id)?
            .ok_or_else(|| conflict("assigned recovery Cat has no Pending Operation"))?;
        operations.insert(spec.cat_id.clone(), operation);
    }
    let volumes = load_attempt_volumes(transaction, &desired, &identity.node_id)?;

    let admission = load_placement_admission_at_in(
        transaction,
        &identity.node_id,
        &session.guest_config_digest,
        now,
    )?;
    let (source_inventory, source_artifacts, accepted_observation) = match admission {
        PlacementAdmissionLoad::Accepted(snapshot)
            if observation_is_complete_for_attempt(
                &desired,
                &snapshot.full_inventory_observation,
            ) =>
        {
            let inventory =
                load_admission_inventory_state_for_update(transaction, &identity.node_id)?
                    .ok_or_else(|| corrupt("accepted recovery admission inventory disappeared"))?;
            if inventory.attestation != snapshot.inventory_attestation
                || inventory.full_observation != snapshot.full_inventory_observation
                || inventory.assigned_snapshot.desired_specs != desired
            {
                return Err(corrupt(
                    "locked recovery admission differs from its accepted snapshot",
                ));
            }
            let (source, artifacts) = accepted_source(&snapshot, &inventory.assigned_snapshot)?;
            (
                source,
                artifacts,
                Some(snapshot.full_inventory_observation.clone()),
            )
        }
        PlacementAdmissionLoad::Accepted(_) => {
            let (source, artifacts) = unavailable_source(
                session,
                TrustedHostFenceInventoryUnavailableReasonV1::AcceptedFullInventoryNotCurrent,
                now,
            );
            (source, artifacts, None)
        }
        PlacementAdmissionLoad::Rejected(PlacementAdmissionRejection::HostRecoveryActive) => {
            return Err(conflict(
                "Node already has an active or Blocked Host recovery attempt",
            ));
        }
        PlacementAdmissionLoad::Rejected(PlacementAdmissionRejection::InventoryMissing) => {
            let (source, artifacts) = unavailable_source(
                session,
                TrustedHostFenceInventoryUnavailableReasonV1::NoAcceptedFullInventory,
                now,
            );
            (source, artifacts, None)
        }
        PlacementAdmissionLoad::Rejected(_) => {
            let (source, artifacts) = unavailable_source(
                session,
                TrustedHostFenceInventoryUnavailableReasonV1::AcceptedFullInventoryNotCurrent,
                now,
            );
            (source, artifacts, None)
        }
    };
    let assigned_cats =
        derive_assigned_cats(desired, operations, &volumes, accepted_observation.as_ref())?;
    let assigned_set_sha256 = trusted_host_fence_assigned_set_sha256(&assigned_cats)
        .map_err(|error| corrupt(format!("digest current Host assigned set: {error}")))?;
    let writer = load_current_open_writer_for_update(transaction, identity, authority_bindings)?;
    // The attempt-ID digest deliberately excludes `fence_attempt_id`; use an
    // already-validated source ID as the temporary value, then install the
    // derived ID before validating or persisting the binding.
    let mut binding = HostFenceBinding {
        provider_scope: identity.provider_scope.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_id: identity.node_id.clone(),
        expected_node_boot_id: apply.expected_node_boot_id.clone(),
        expected_agent_session_epoch: apply.expected_agent_session_epoch,
        fence_attempt_id: identity.node_id.clone(),
    };
    binding.fence_attempt_id =
        trusted_host_fence_recovery_attempt_id(&apply.apply_id, &binding, &assigned_set_sha256)
            .map_err(|error| corrupt(format!("derive Host recovery attempt ID: {error}")))?;
    let provider_request = HostFenceAttemptRequest {
        binding: binding.clone(),
        network_quarantine_boundary_id: authority_bindings.network_quarantine_boundary_id.clone(),
        object_writer: ObjectWriterFenceTarget {
            writer_authority_id: writer.writer.authority_id.clone(),
            provider_scope: writer.writer.object_provider_scope.clone(),
            workload_principal_id: writer.writer.workload_principal_id.clone(),
            object_store_scope_id: writer.writer.object_store_scope_id.clone(),
        },
    };
    let derived = TrustedHostFenceRecoveryAttemptV1 {
        version: ContractVersion::V1,
        apply_id: apply.apply_id.clone(),
        principal: principal.clone(),
        binding,
        provider_request,
        source_inventory,
        assigned_cats,
        assigned_set_sha256,
        requested_at_unix_ms: now,
    };
    validate_trusted_host_fence_recovery_attempt_v1(&derived)
        .map_err(|error| rejected(format!("derived Host recovery attempt is invalid: {error}")))?;
    if !public_apply_matches_attempt(apply, &derived) {
        return Err(conflict(
            "Host recovery apply does not equal the server-derived current authority coordinates",
        ));
    }
    Ok((derived, source_artifacts))
}

fn insert_attempt_in(
    transaction: &mut Transaction<'_>,
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    source_artifacts: &SourceArtifacts,
    enqueued_at: UnixMillis,
) -> AuthorityTxResult<()> {
    if let Some(problem) =
        assigned_set_limit_problem(attempt.assigned_cats.iter().map(|cat| cat.volumes.len()))
    {
        return Err(rejected(format!("Host recovery {problem}")));
    }
    let (attempt_bytes, attempt_sha256) = recovery_attempt_bytes(attempt)?;
    let session = attempt.source_inventory.session();
    let (
        physical_state,
        inventory_epoch,
        inventory_digest,
        inventory_read_position,
        full_observation_id,
        full_observation_sha256,
        full_observation_length,
        assigned_snapshot_sha256,
        assigned_snapshot_length,
    ) = match &attempt.source_inventory {
        TrustedHostFenceSourceInventoryV1::AcceptedFull {
            attestation,
            full_observation,
            assigned_snapshot,
            ..
        } => {
            let full_bytes = source_artifacts
                .full_observation_bytes
                .as_ref()
                .ok_or_else(|| corrupt("accepted recovery source has no observation bytes"))?;
            let observation = decode_node_observation(full_bytes)
                .map_err(|error| corrupt(format!("decode accepted observation: {error}")))?;
            (
                "accepted_full",
                Some(pg(attestation.inventory_epoch.get(), "inventory epoch")?),
                Some(attestation.inventory_digest.as_str().to_owned()),
                Some(pg(
                    attestation.inventory_read_position.get(),
                    "inventory read position",
                )?),
                Some(observation.observation_id.as_str().to_owned()),
                Some(full_observation.content_sha256.as_str().to_owned()),
                Some(pg(
                    full_observation.length_bytes.get(),
                    "full observation length",
                )?),
                Some(assigned_snapshot.content_sha256.as_str().to_owned()),
                Some(pg(
                    assigned_snapshot.length_bytes.get(),
                    "assigned snapshot length",
                )?),
            )
        }
        TrustedHostFenceSourceInventoryV1::Unavailable { .. } => (
            "unavailable",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    };
    let binding = &attempt.binding;
    let inserted = transaction.execute(
        "INSERT INTO trusted_host_fence_recovery_attempts_v1 (
            fence_attempt_id, apply_id, attempt_bytes, attempt_sha256,
            provider, host_partition, host_account_id, host_region,
            immutable_host_id, node_id, expected_node_boot_id,
            agent_instance_id, expected_agent_session_epoch,
            physical_snapshot_state, inventory_epoch, inventory_digest,
            inventory_read_position, full_observation_id,
            full_observation_bytes, full_observation_sha256,
            full_observation_length, assigned_snapshot_bytes,
            assigned_snapshot_sha256, assigned_snapshot_length,
            assigned_set_sha256, assigned_cat_count, state,
            enqueued_at_unix_ms
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
            $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,'provider_pending',$27
         )",
        &[
            &binding.fence_attempt_id.as_str(),
            &attempt.apply_id.as_str(),
            &attempt_bytes,
            &attempt_sha256.as_str(),
            &binding.provider_scope.provider.as_str(),
            &binding.provider_scope.partition.as_str(),
            &binding.provider_scope.account_id.as_str(),
            &binding.provider_scope.region.as_str(),
            &binding.immutable_host_id.as_str(),
            &binding.node_id.as_str(),
            &binding.expected_node_boot_id.as_str(),
            &session.agent_instance_id.as_str(),
            &pg(
                binding.expected_agent_session_epoch.get(),
                "AgentSession epoch",
            )?,
            &physical_state,
            &inventory_epoch,
            &inventory_digest,
            &inventory_read_position,
            &full_observation_id,
            &source_artifacts.full_observation_bytes,
            &full_observation_sha256,
            &full_observation_length,
            &source_artifacts.assigned_snapshot_bytes,
            &assigned_snapshot_sha256,
            &assigned_snapshot_length,
            &attempt.assigned_set_sha256.as_str(),
            &pg(attempt.assigned_cats.len() as u64, "assigned Cat count")?,
            &pg(enqueued_at.get(), "recovery enqueue time")?,
        ],
    )?;
    if inserted != 1 {
        return Err(corrupt("Host recovery attempt insert affected no row"));
    }
    for (ordinal, cat) in attempt.assigned_cats.iter().enumerate() {
        let cat_bytes = canonical(cat, "assigned Cat recovery snapshot")?;
        if cat_bytes.len() > MAX_CAT_SNAPSHOT_BYTES {
            return Err(rejected("assigned Cat snapshot exceeds its hard cap"));
        }
        let cat_sha = trusted_host_fence_assigned_cat_sha256(cat)
            .map_err(|error| corrupt(format!("digest assigned Cat snapshot: {error}")))?;
        let volume_sha = cat_volume_set_sha256(cat)?;
        let inserted = transaction.execute(
            "INSERT INTO trusted_host_fence_recovery_attempt_cats_v1 (
                fence_attempt_id, ordinal, cat_id, cat_snapshot_bytes,
                cat_snapshot_sha256, workspace_id, expected_desired_revision,
                expected_desired_spec_digest, expected_old_operation_id,
                volume_count, volume_set_sha256
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[
                &binding.fence_attempt_id.as_str(),
                &pg(ordinal as u64, "assigned Cat ordinal")?,
                &cat.expected_current_desired.cat_id.as_str(),
                &cat_bytes,
                &cat_sha.as_str(),
                &cat.expected_current_desired.workspace_id.as_str(),
                &pg(
                    cat.expected_current_desired.desired_revision.get(),
                    "expected Desired revision",
                )?,
                &cat.expected_current_desired.spec_digest.as_str(),
                &cat.expected_old_operation.operation_id.as_str(),
                &pg(cat.volumes.len() as u64, "assigned Volume count")?,
                &volume_sha.as_str(),
            ],
        )?;
        if inserted != 1 {
            return Err(corrupt("assigned Cat recovery insert affected no row"));
        }
    }
    Ok(())
}

fn exact_attempt_replay(
    transaction: &mut Transaction<'_>,
    stored: StoredRecoveryAttempt,
    apply: &HostLossRecoveryApplyV1,
    principal: &cats_api::runtime_reconciliation::FleetPolicyPrincipal,
    authority_bindings: &HostFenceAuthorityBindingsV1,
) -> AuthorityTxResult<TrustedHostFenceRecoveryAttemptRecordV1> {
    let attempt = &stored.record.attempt;
    let host_is_bound = resolve_host_fence_authority_host_v1(
        authority_bindings,
        &attempt.binding.immutable_host_id,
        &attempt.binding.node_id,
    )
    .is_ok();
    if !public_apply_matches_attempt(apply, attempt)
        || attempt.principal != *principal
        || !host_is_bound
        || attempt.binding.provider_scope != authority_bindings.provider_scope
        || attempt.provider_request.network_quarantine_boundary_id
            != authority_bindings.network_quarantine_boundary_id
        || attempt.provider_request.object_writer.provider_scope
            != authority_bindings.provider_scope
        || attempt.provider_request.object_writer.workload_principal_id
            != authority_bindings.workload_principal_id
        || attempt.provider_request.object_writer.object_store_scope_id
            != authority_bindings.object_store_scope_id
    {
        return Err(conflict(
            "Host recovery apply replay changed its immutable authority inputs",
        ));
    }
    let queue = load_queue_for_update(transaction, &attempt.binding.fence_attempt_id)?
        .ok_or_else(|| corrupt("Host recovery attempt has no provider queue row"))?;
    if queue.request != attempt.provider_request {
        return Err(corrupt(
            "Host recovery attempt/provider queue request projection changed",
        ));
    }
    Ok(stored.record)
}

fn load_committed_batch_receipt(
    transaction: &mut Transaction<'_>,
    fence_attempt_id: &Id,
) -> AuthorityTxResult<TrustedHostFenceBatchRecoveryCommitReceiptV1> {
    let bytes = transaction
        .query_one(
            "SELECT outcome_bytes
               FROM trusted_host_fence_recovery_attempts_v1
              WHERE fence_attempt_id=$1 AND state='committed' FOR UPDATE",
            &[&fence_attempt_id.as_str()],
        )?
        .try_get::<_, Vec<u8>>("outcome_bytes")?;
    decode_canonical(&bytes, "Host recovery batch receipt")
}

fn begin_attempt_in(
    transaction: &mut Transaction<'_>,
    apply: &HostLossRecoveryApplyV1,
    principal: &cats_api::runtime_reconciliation::FleetPolicyPrincipal,
    authority_bindings: &HostFenceAuthorityBindingsV1,
) -> AuthorityTxResult<TrustedHostFenceRecoveryAttemptRecordV1> {
    validate_host_loss_recovery_apply_v1(apply)
        .map_err(|error| rejected(format!("invalid Host recovery apply: {error}")))?;
    host_fence_authority_bindings_sha256(authority_bindings)
        .map_err(|error| rejected(format!("invalid Host recovery authority artifact: {error}")))?;

    // `apply_id` is the caller's response-loss discovery key. Serialize it
    // before reading mutable Node state, then resolve an immutable committed
    // attempt without requiring the source identity/session to remain active.
    lock_recovery_apply_id(transaction, &apply.apply_id)?;
    if let Some(stored) = load_attempt_by_apply_for_update(transaction, &apply.apply_id)? {
        return exact_attempt_replay(transaction, stored, apply, principal, authority_bindings);
    }

    // Route signing and Node authority apply take the shared form before
    // locking NodeIdentity. Recovery takes the exclusive form first, then the
    // Host-global advisory before the identity row, so no route/credential
    // snapshot or fresh same-Host Provision can cross the seal.
    lock_route_v2_machine_authority_exclusive(transaction)?;
    let source_host = authority_bindings
        .hosts
        .iter()
        .find(|host| host.node_id == apply.source_node_id)
        .ok_or_else(|| {
            conflict("Host recovery authority artifact does not bind the requested source Node")
        })?;
    require_host_recovery_unblocked_in(
        transaction,
        &authority_bindings.provider_scope,
        &source_host.immutable_host_id,
    )?;
    let identity = load_identity_by_node_for_update(transaction, &apply.source_node_id)?
        .ok_or_else(|| conflict("Host recovery source NodeIdentity is absent"))?;
    validate_source_identity(&identity, apply, authority_bindings)?;
    require_active_credential_lineage(transaction, &identity)?;
    let session = load_current_session_for_update(transaction, &identity.node_id)?
        .ok_or_else(|| conflict("Host recovery source has no current AgentSession"))?;
    validate_source_session(&session, apply, &identity.immutable_host_id)?;
    require_product_mutation_unblocked_in(transaction, &identity.node_id)?;

    let now = database_now(transaction)?;
    let (derived, artifacts) = derive_attempt_in(
        transaction,
        apply,
        principal,
        authority_bindings,
        &identity,
        &session,
        now,
    )?;

    // A deterministic attempt ID collision cannot be resolved through mutable
    // source state. Exact response-loss replay was already resolved by the
    // globally unique apply ID before any current authority read.
    if load_attempt_for_update(transaction, &derived.binding.fence_attempt_id)?.is_some() {
        return Err(conflict(
            "Host recovery fence-attempt ID is owned by another immutable apply",
        ));
    }
    if load_queue_for_update(transaction, &derived.binding.fence_attempt_id)?.is_some() {
        return Err(conflict(
            "provider queue attempt exists without its Host recovery assigned-set barrier",
        ));
    }
    let queue = enqueue_host_fence_provider_attempt_in(transaction, &derived.provider_request)?;
    if queue.request != derived.provider_request
        || !matches!(queue.state, HostFenceProviderQueueStateV1::Pending)
    {
        return Err(corrupt(
            "new Host recovery provider queue did not remain pending",
        ));
    }
    insert_attempt_in(transaction, &derived, &artifacts, queue.enqueued_at_unix_ms)?;
    load_attempt_for_update(transaction, &derived.binding.fence_attempt_id)?
        .map(|stored| stored.record)
        .ok_or_else(|| corrupt("Host recovery attempt disappeared after insert"))
}

fn transition_provider_terminal_in(
    transaction: &mut Transaction<'_>,
    fence_attempt_id: &Id,
    event: &TrustedHostFenceEventV1,
) -> AuthorityTxResult<()> {
    let bytes = encode_trusted_host_fence_event_v1(event)
        .map_err(|error| corrupt(format!("encode terminal Host event: {error}")))?;
    let changed = transaction.execute(
        "UPDATE trusted_host_fence_recovery_attempts_v1 SET
            state='provider_terminal', provider_evidence_bytes=$2,
            provider_evidence_sha256=$3, provider_completed_at_unix_ms=$4
          WHERE fence_attempt_id=$1 AND state='provider_pending'",
        &[
            &fence_attempt_id.as_str(),
            &bytes,
            &event.provider_evidence_sha256.as_str(),
            &pg(
                event.provider_evidence.completed_at_unix_ms.get(),
                "provider completion time",
            )?,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "locked Host recovery attempt did not enter provider-terminal state",
        ));
    }
    Ok(())
}

fn transition_blocked_in(
    transaction: &mut Transaction<'_>,
    fence_attempt_id: &Id,
    terminal_event: &TrustedHostFenceEventV1,
    mut reasons: Vec<TrustedHostFenceRecoveryBlockedReasonV1>,
    blocked_at: UnixMillis,
) -> AuthorityTxResult<()> {
    canonicalize_trusted_host_fence_recovery_blocked_reasons_v1(&mut reasons)
        .map_err(|error| corrupt(format!("canonicalize Host recovery blockers: {error}")))?;
    let receipt = TrustedHostFenceBlockedReceiptV1 {
        terminal_event: terminal_event.clone(),
        reasons,
        blocked_at_unix_ms: blocked_at,
    };
    cats_storage::trusted_host_recovery::validate_trusted_host_fence_blocked_receipt_v1(&receipt)
        .map_err(|error| corrupt(format!("invalid Host recovery Blocked receipt: {error}")))?;
    let bytes = canonical(&receipt, "Host recovery Blocked receipt")?;
    let digest = domain_digest(
        BLOCKED_RECEIPT_DIGEST_DOMAIN,
        &receipt,
        "Host recovery Blocked receipt",
    )?;
    let changed = transaction.execute(
        "UPDATE trusted_host_fence_recovery_attempts_v1 SET
            state='blocked', outcome_bytes=$2, outcome_sha256=$3,
            outcome_completed_at_unix_ms=$4
          WHERE fence_attempt_id=$1 AND state='provider_terminal'",
        &[
            &fence_attempt_id.as_str(),
            &bytes,
            &digest.as_str(),
            &pg(blocked_at.get(), "Blocked completion time")?,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "locked Host recovery attempt did not enter Blocked state",
        ));
    }
    Ok(())
}

fn terminal_event_from_state(
    state: &TrustedHostFenceRecoveryAttemptStateV1,
) -> Option<&TrustedHostFenceEventV1> {
    match state {
        TrustedHostFenceRecoveryAttemptStateV1::ProviderPending => None,
        TrustedHostFenceRecoveryAttemptStateV1::ProviderTerminal { terminal_event } => {
            Some(terminal_event)
        }
        TrustedHostFenceRecoveryAttemptStateV1::Blocked { receipt } => {
            Some(&receipt.terminal_event)
        }
        TrustedHostFenceRecoveryAttemptStateV1::Committed { .. } => None,
    }
}

fn observe_provider_terminal_in(
    transaction: &mut Transaction<'_>,
    binding: &cats_storage::host_fence::HostFenceBinding,
) -> AuthorityTxResult<TrustedHostFenceRecoveryAttemptRecordV1> {
    let _identity = load_identity_by_node_for_update(transaction, &binding.node_id)?
        .ok_or_else(|| conflict("Host recovery source NodeIdentity is absent"))?;
    let stored = load_attempt_for_update(transaction, &binding.fence_attempt_id)?
        .ok_or_else(|| application(ApiError::not_found("Host recovery attempt")))?;
    if stored.record.attempt.binding != *binding {
        return Err(conflict(
            "Host recovery terminal discovery changed its complete Host binding",
        ));
    }
    let queue = load_queue_for_update(transaction, &binding.fence_attempt_id)?
        .ok_or_else(|| corrupt("Host recovery attempt has no provider queue row"))?;
    if queue.request != stored.record.attempt.provider_request {
        return Err(corrupt(
            "Host recovery provider queue request changed after enqueue",
        ));
    }
    let HostFenceProviderQueueStateV1::Terminal { evidence, .. } = queue.state else {
        return Err(application(ApiError::unavailable(
            "Host-fence provider attempt is not terminal",
        )));
    };
    if let Some(existing) = terminal_event_from_state(&stored.record.state) {
        if existing.provider_evidence != *evidence {
            return Err(corrupt(
                "Host recovery terminal event differs from provider queue evidence",
            ));
        }
        return Ok(stored.record);
    }
    if matches!(
        stored.record.state,
        TrustedHostFenceRecoveryAttemptStateV1::Committed { .. }
    ) {
        // The immutable committed receipt decoder already validates its full
        // event; compare through the retained provider bytes before returning.
        let event_bytes = transaction
            .query_one(
                "SELECT provider_evidence_bytes
                   FROM trusted_host_fence_recovery_attempts_v1
                  WHERE fence_attempt_id=$1",
                &[&binding.fence_attempt_id.as_str()],
            )?
            .try_get::<_, Vec<u8>>("provider_evidence_bytes")?;
        let event = decode_trusted_host_fence_event_v1(&event_bytes)
            .map_err(|error| corrupt(format!("decode committed Host event: {error}")))?;
        if event.provider_evidence != *evidence {
            return Err(corrupt(
                "committed Host recovery differs from provider queue evidence",
            ));
        }
        return Ok(stored.record);
    }

    let now = database_now(transaction)?;
    let event = trusted_host_fence_event_v1(*evidence, now)
        .map_err(|error| rejected(format!("provider evidence is not terminal: {error}")))?;
    if event.binding != *binding {
        return Err(corrupt(
            "provider terminal evidence changed the recovery Host binding",
        ));
    }
    transition_provider_terminal_in(transaction, &binding.fence_attempt_id, &event)?;
    let blockers = trusted_host_fence_recovery_blockers(&stored.record.attempt)
        .map_err(|error| corrupt(format!("derive Host recovery blockers: {error}")))?;
    if !blockers.is_empty() {
        transition_blocked_in(
            transaction,
            &binding.fence_attempt_id,
            &event,
            blockers,
            now,
        )?;
    }
    load_attempt_for_update(transaction, &binding.fence_attempt_id)?
        .map(|stored| stored.record)
        .ok_or_else(|| corrupt("Host recovery attempt disappeared after terminal transition"))
}

fn current_changed(
    component: TrustedHostFenceCurrentAuthorityComponentV1,
    cat_id: Option<&Id>,
    volume_id: Option<&Id>,
) -> TrustedHostFenceRecoveryBlockedReasonV1 {
    TrustedHostFenceRecoveryBlockedReasonV1::CurrentAuthorityChanged {
        cat_id: cat_id.cloned(),
        volume_id: volume_id.cloned(),
        component,
    }
}

fn target_unavailable(
    cat_id: &Id,
    problem: TrustedHostFenceRecoveryTargetProblemV1,
) -> TrustedHostFenceRecoveryBlockedReasonV1 {
    TrustedHostFenceRecoveryBlockedReasonV1::RecoveryTargetUnavailable {
        cat_id: cat_id.clone(),
        problem,
    }
}

fn next_revision(value: Revision) -> Option<Revision> {
    value.get().checked_add(1).and_then(Revision::new)
}

fn next_epoch(value: Epoch) -> Option<Epoch> {
    value.get().checked_add(1).and_then(Epoch::new)
}

fn operation_matches_desired(operation: &Operation, desired: &DesiredRuntimeSpec) -> bool {
    encode_operation(operation).is_ok()
        && operation.version == ContractVersion::V1
        && operation.workspace_id == desired.workspace_id
        && operation.cat_id == desired.cat_id
        && operation.desired_revision == desired.desired_revision
        && operation.desired_spec_digest == desired.spec_digest
        && operation.placement == desired.placement
        && operation.target == desired.target
}

fn cat_recovery_shape_is_exact(
    assigned: &TrustedHostFenceAssignedCatV1,
    recovery: &cats_storage::trusted_host_recovery::TrustedHostFenceCatRecoveryV1,
    event: &TrustedHostFenceEventV1,
    now: UnixMillis,
) -> AuthorityTxResult<bool> {
    let current = &assigned.expected_current_desired;
    let replacement = &recovery.replacement_desired;
    let Some(expected_revision) = next_revision(current.desired_revision) else {
        return Ok(false);
    };
    let Some(expected_placement_epoch) = next_epoch(current.placement.placement_epoch) else {
        return Ok(false);
    };
    if spec_digest(current).ok().as_ref() != Some(&current.spec_digest)
        || spec_digest(replacement).ok().as_ref() != Some(&replacement.spec_digest)
        || current.version != ContractVersion::V1
        || replacement.version != ContractVersion::V1
        || replacement.workspace_id != current.workspace_id
        || replacement.cat_id != current.cat_id
        || replacement.desired_revision != expected_revision
        || replacement.placement.placement_epoch != expected_placement_epoch
        || replacement.placement.kind != current.placement.kind
        || replacement.placement.node_id == current.placement.node_id
        || replacement.target != current.target
        || replacement.runtime != current.runtime
        || replacement.endpoints != current.endpoints
        || replacement.transition != current.transition
        || replacement.volumes.len() != current.volumes.len()
        || recovery.volumes.len() != current.volumes.len()
    {
        return Ok(false);
    }

    let mut expected_settlement = assigned.expected_old_operation.clone();
    expected_settlement.phase = OperationPhase::Failed;
    expected_settlement.terminal = Some(OperationTerminal::Failed {
        error: Box::new(OperationFailure::HostLost {
            node_id: event.binding.node_id.clone(),
            agent_session_epoch: event.binding.expected_agent_session_epoch,
            host_fence_event_id: event.event_id.clone(),
        }),
        completed_at_unix_ms: event.committed_at_unix_ms,
    });
    expected_settlement.updated_at_unix_ms = event.committed_at_unix_ms;
    if recovery.settled_old_operation != expected_settlement
        || !operation_matches_desired(&recovery.recovery_operation, replacement)
        || recovery.recovery_operation.operation_id == assigned.expected_old_operation.operation_id
        || recovery.recovery_operation.phase != OperationPhase::Pending
        || recovery.recovery_operation.terminal.is_some()
        || recovery.recovery_operation.created_at_unix_ms != event.committed_at_unix_ms
        || recovery.recovery_operation.updated_at_unix_ms != event.committed_at_unix_ms
    {
        return Ok(false);
    }

    for (((intent, successor), expected), volume_recovery) in current
        .volumes
        .iter()
        .zip(&replacement.volumes)
        .zip(&assigned.volumes)
        .zip(&recovery.volumes)
    {
        if volume_recovery.volume_id != expected.expected_current_volume.volume_id
            || volume_recovery.expected_volume_sha256
                != trusted_host_fence_assigned_volume_sha256(expected)
                    .map_err(|error| corrupt(format!("digest assigned Volume: {error}")))?
        {
            return Ok(false);
        }
        validate_authorization_record(&volume_recovery.takeover_authorization)
            .map_err(|error| rejected(format!("invalid takeover authorization: {error}")))?;
        if !matches!(
            volume_recovery.takeover_authorization.state,
            AuthorizationState::Unconsumed
        ) {
            return Ok(false);
        }
        let VolumeAuthorization::Takeover(authorization) =
            &volume_recovery.takeover_authorization.authorization
        else {
            return Ok(false);
        };
        let mut exact_successor = intent.clone();
        exact_successor.attachment_id = authorization.new_attachment_id.clone();
        exact_successor.acquire = VolumeAcquire::Takeover {
            authorization_id: authorization.authorization_id.clone(),
        };
        if successor != &exact_successor
            || authorization.host_fence_event_id != event.event_id
            || authorization.authorized_node_id != replacement.placement.node_id
            || authorization.volume_id != intent.volume_id
            || authorization.expected_attachment_id != intent.attachment_id
            || authorization.expected_epoch != expected.expected_owner.attachment_epoch
            || authorization.expected_head != expected.expected_current_volume.head
            || authorization.desired_revision != replacement.desired_revision
            || authorization.new_placement_epoch != replacement.placement.placement_epoch
            || authorization.not_after <= now
            || authorization.not_after < event.committed_at_unix_ms
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn lock_identity_union(
    transaction: &mut Transaction<'_>,
    source_node_id: &Id,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> AuthorityTxResult<BTreeMap<Id, NodeIdentity>> {
    let mut node_ids = BTreeSet::new();
    node_ids.insert(source_node_id.clone());
    for recovery in &commit.recoveries {
        node_ids.insert(recovery.replacement_desired.placement.node_id.clone());
    }
    let mut identities = BTreeMap::new();
    for node_id in node_ids {
        if let Some(identity) = load_identity_by_node_for_update(transaction, &node_id)? {
            identities.insert(node_id, identity);
        }
    }
    Ok(identities)
}

fn recovery_request_blockers(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
    now: UnixMillis,
) -> AuthorityTxResult<Vec<TrustedHostFenceRecoveryBlockedReasonV1>> {
    let mut blockers = Vec::new();
    let mut operation_ids = BTreeSet::new();
    let mut authorization_ids = BTreeSet::new();
    if commit.recoveries.len() != attempt.assigned_cats.len() {
        for assigned in &attempt.assigned_cats {
            blockers.push(target_unavailable(
                &assigned.expected_current_desired.cat_id,
                TrustedHostFenceRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable,
            ));
        }
        return Ok(blockers);
    }
    for (assigned, recovery) in attempt.assigned_cats.iter().zip(&commit.recoveries) {
        let cat_id = &assigned.expected_current_desired.cat_id;
        let mut valid = recovery.cat_id == *cat_id
            && recovery.assigned_cat_sha256
                == trusted_host_fence_assigned_cat_sha256(assigned)
                    .map_err(|error| corrupt(format!("digest assigned Cat: {error}")))?
            && operation_ids.insert(recovery.recovery_operation.operation_id.clone())
            && recovery.volumes.len() == assigned.volumes.len()
            && !recovery.volumes.is_empty();
        for volume in &recovery.volumes {
            match &volume.takeover_authorization.authorization {
                VolumeAuthorization::Takeover(authorization) => {
                    valid &= authorization_ids.insert(authorization.authorization_id.clone());
                }
                VolumeAuthorization::DisposableRootDelete(_) => valid = false,
            }
        }
        valid &= cat_recovery_shape_is_exact(assigned, recovery, &commit.terminal_event, now)?;
        if !valid {
            blockers.push(target_unavailable(
                cat_id,
                TrustedHostFenceRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable,
            ));
        }
    }
    Ok(blockers)
}

fn target_policy_blockers_in(
    transaction: &mut Transaction<'_>,
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
    identities: &BTreeMap<Id, NodeIdentity>,
    now: UnixMillis,
) -> AuthorityTxResult<Vec<TrustedHostFenceRecoveryBlockedReasonV1>> {
    let mut by_target: BTreeMap<Id, Vec<DesiredRuntimeSpec>> = BTreeMap::new();
    for recovery in &commit.recoveries {
        by_target
            .entry(recovery.replacement_desired.placement.node_id.clone())
            .or_default()
            .push(recovery.replacement_desired.clone());
    }
    let mut blockers = Vec::new();
    for (target_node_id, replacements) in by_target {
        let eligible_identity = identities.get(&target_node_id).is_some_and(|identity| {
            identity.state == NodeIdentityState::Provisioned
                && !(identity.provider_scope == attempt.binding.provider_scope
                    && identity.immutable_host_id == attempt.binding.immutable_host_id)
        });
        if !eligible_identity {
            for replacement in replacements {
                blockers.push(target_unavailable(
                    &replacement.cat_id,
                    TrustedHostFenceRecoveryTargetProblemV1::NoEligibleReplacementNode,
                ));
            }
            continue;
        }
        let Some(policy) = load_policy_for_update(transaction, &target_node_id)? else {
            for replacement in replacements {
                blockers.push(target_unavailable(
                    &replacement.cat_id,
                    TrustedHostFenceRecoveryTargetProblemV1::ReplacementPolicyChanged,
                ));
            }
            continue;
        };
        let admission = load_placement_admission_at_in(
            transaction,
            &target_node_id,
            &policy.capabilities.guest_config_digest,
            now,
        )?;
        let fits = match admission {
            PlacementAdmissionLoad::Accepted(admission) => {
                host_recovery_replacements_fit(&policy, &admission, &replacements)?
            }
            PlacementAdmissionLoad::Rejected(_) => false,
        };
        if !fits {
            for replacement in replacements {
                blockers.push(target_unavailable(
                    &replacement.cat_id,
                    TrustedHostFenceRecoveryTargetProblemV1::ReplacementPolicyChanged,
                ));
            }
        }
    }
    Ok(blockers)
}

fn current_authority_blockers_in(
    transaction: &mut Transaction<'_>,
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    source_identity: Option<&NodeIdentity>,
) -> AuthorityTxResult<(
    Vec<TrustedHostFenceRecoveryBlockedReasonV1>,
    Option<AgentSession>,
)> {
    let mut blockers = Vec::new();
    let source_identity_changed = source_identity.is_none_or(|identity| {
        identity.state != NodeIdentityState::Provisioned
            || identity.node_id != attempt.binding.node_id
            || identity.provider_scope != attempt.binding.provider_scope
            || identity.immutable_host_id != attempt.binding.immutable_host_id
    });
    if source_identity_changed {
        blockers.push(current_changed(
            TrustedHostFenceCurrentAuthorityComponentV1::SourceIdentity,
            None,
            None,
        ));
    }
    if let Some(identity) = source_identity.filter(|_| !source_identity_changed) {
        if lock_exact_credential_lineage(transaction, identity)?
            .is_none_or(|state| state != CredentialLineageState::Active)
        {
            blockers.push(current_changed(
                TrustedHostFenceCurrentAuthorityComponentV1::SourceIdentity,
                None,
                None,
            ));
        }
    }
    let session = load_current_session_for_update(transaction, &attempt.binding.node_id)?;
    if session.as_ref().is_none_or(|session| {
        session.immutable_host_id != attempt.binding.immutable_host_id
            || session_binding(session) != *attempt.source_inventory.session()
    }) {
        blockers.push(current_changed(
            TrustedHostFenceCurrentAuthorityComponentV1::SourceAgentSession,
            None,
            None,
        ));
    }

    let current_assigned = load_assigned_desired_for_update_bounded(
        transaction,
        &attempt.binding.node_id,
        MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS.saturating_add(1),
    )?;
    let expected_assigned = attempt
        .assigned_cats
        .iter()
        .map(|cat| cat.expected_current_desired.clone())
        .collect::<Vec<_>>();
    if current_assigned != expected_assigned {
        blockers.push(current_changed(
            TrustedHostFenceCurrentAuthorityComponentV1::AssignedCatSet,
            None,
            None,
        ));
    }
    for assigned in &attempt.assigned_cats {
        let cat_id = &assigned.expected_current_desired.cat_id;
        let desired = load_desired_for_update(transaction, cat_id)?;
        if desired.as_ref() != Some(&assigned.expected_current_desired) {
            blockers.push(current_changed(
                TrustedHostFenceCurrentAuthorityComponentV1::Desired,
                Some(cat_id),
                None,
            ));
        }
        let operation = load_pending_operation_by_cat_for_update(transaction, cat_id)?;
        if operation.as_ref() != Some(&assigned.expected_old_operation) {
            blockers.push(current_changed(
                TrustedHostFenceCurrentAuthorityComponentV1::OldOperation,
                Some(cat_id),
                None,
            ));
        }
    }

    let mut proofs = BTreeMap::new();
    for assigned in &attempt.assigned_cats {
        for proof in &assigned.volumes {
            proofs.insert(
                proof.expected_current_volume.volume_id.clone(),
                (&assigned.expected_current_desired.cat_id, proof),
            );
        }
    }
    for (volume_id, (cat_id, proof)) in proofs {
        match load_stored_volume_for_update(transaction, &volume_id)? {
            None => blockers.push(current_changed(
                TrustedHostFenceCurrentAuthorityComponentV1::VolumeRecord,
                Some(cat_id),
                Some(&volume_id),
            )),
            Some(stored) => {
                if stored.record != proof.expected_current_volume {
                    blockers.push(current_changed(
                        TrustedHostFenceCurrentAuthorityComponentV1::VolumeRecord,
                        Some(cat_id),
                        Some(&volume_id),
                    ));
                }
                if stored.owner_binding.as_ref() != Some(&proof.expected_owner) {
                    blockers.push(current_changed(
                        TrustedHostFenceCurrentAuthorityComponentV1::VolumeOwner,
                        Some(cat_id),
                        Some(&volume_id),
                    ));
                }
            }
        }
    }
    Ok((blockers, session))
}

fn authorization_blockers_in(
    transaction: &mut Transaction<'_>,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> AuthorityTxResult<Vec<TrustedHostFenceRecoveryBlockedReasonV1>> {
    let mut authorizations = BTreeMap::new();
    let mut new_operations = BTreeMap::new();
    for recovery in &commit.recoveries {
        new_operations.insert(
            recovery.recovery_operation.operation_id.clone(),
            recovery.cat_id.clone(),
        );
        for volume in &recovery.volumes {
            let VolumeAuthorization::Takeover(authorization) =
                &volume.takeover_authorization.authorization
            else {
                continue;
            };
            authorizations.insert(
                authorization.authorization_id.clone(),
                (recovery.cat_id.clone(), authorization.volume_id.clone()),
            );
        }
    }
    let mut blockers = Vec::new();
    for (operation_id, cat_id) in new_operations {
        if load_operation_for_update(transaction, &operation_id)?.is_some() {
            blockers.push(target_unavailable(
                &cat_id,
                TrustedHostFenceRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable,
            ));
        }
    }
    for (authorization_id, (cat_id, volume_id)) in authorizations {
        if transaction
            .query_opt(
                "SELECT authorization_id FROM volume_authorizations
                  WHERE authorization_id=$1 FOR UPDATE",
                &[&authorization_id.as_str()],
            )?
            .is_some()
        {
            blockers.push(current_changed(
                TrustedHostFenceCurrentAuthorityComponentV1::TakeoverAuthorization,
                Some(&cat_id),
                Some(&volume_id),
            ));
        }
    }
    Ok(blockers)
}

fn update_attempt_committed_in(
    transaction: &mut Transaction<'_>,
    receipt: &TrustedHostFenceBatchRecoveryCommitReceiptV1,
) -> AuthorityTxResult<()> {
    let bytes = canonical(receipt, "Host recovery batch receipt")?;
    if bytes.len() > TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES {
        return Err(rejected("Host recovery batch receipt exceeds its hard cap"));
    }
    let digest = domain_digest(
        BATCH_RECEIPT_DIGEST_DOMAIN,
        receipt,
        "Host recovery batch receipt",
    )?;
    let changed = transaction.execute(
        "UPDATE trusted_host_fence_recovery_attempts_v1 SET
            state='committed', outcome_bytes=$2, outcome_sha256=$3,
            outcome_completed_at_unix_ms=$4
          WHERE fence_attempt_id=$1 AND state='provider_terminal'",
        &[
            &receipt.commit.fence_attempt_id.as_str(),
            &bytes,
            &digest.as_str(),
            &pg(receipt.committed_at_unix_ms.get(), "batch commit time")?,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "locked Host recovery attempt did not enter committed state",
        ));
    }
    Ok(())
}

fn persist_blocked_and_load(
    transaction: &mut Transaction<'_>,
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    event: &TrustedHostFenceEventV1,
    reasons: Vec<TrustedHostFenceRecoveryBlockedReasonV1>,
    now: UnixMillis,
) -> AuthorityTxResult<TrustedHostFenceBatchRecoveryStoreOutcomeV1> {
    transition_blocked_in(
        transaction,
        &attempt.binding.fence_attempt_id,
        event,
        reasons,
        now,
    )?;
    let stored = load_attempt_for_update(transaction, &attempt.binding.fence_attempt_id)?
        .ok_or_else(|| corrupt("Blocked Host recovery attempt disappeared"))?;
    let TrustedHostFenceRecoveryAttemptStateV1::Blocked { receipt } = stored.record.state else {
        return Err(corrupt(
            "Host recovery Blocked transition stored another state",
        ));
    };
    Ok(TrustedHostFenceBatchRecoveryStoreOutcomeV1::Blocked(
        Box::new(receipt),
    ))
}

fn batch_recovery_in(
    transaction: &mut Transaction<'_>,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> AuthorityTxResult<TrustedHostFenceBatchRecoveryStoreOutcomeV1> {
    validate_trusted_host_fence_event_v1(&commit.terminal_event)
        .map_err(|error| rejected(format!("invalid terminal Host event: {error}")))?;
    if commit.version != ContractVersion::V1
        || commit.fence_attempt_id != commit.terminal_event.binding.fence_attempt_id
    {
        return Err(rejected(
            "Host recovery batch does not bind its terminal event",
        ));
    }
    let commit_bytes = canonical(commit, "Host recovery batch request")?;
    if commit_bytes.len() > TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES {
        return Err(rejected("Host recovery batch exceeds its hard byte cap"));
    }
    let request_sha256 = trusted_host_fence_batch_recovery_sha256(commit)
        .map_err(|error| rejected(format!("digest Host recovery batch: {error}")))?;

    lock_route_v2_machine_authority_exclusive(transaction)?;
    let identities =
        lock_identity_union(transaction, &commit.terminal_event.binding.node_id, commit)?;
    let stored = load_attempt_for_update(transaction, &commit.fence_attempt_id)?
        .ok_or_else(|| application(ApiError::not_found("Host recovery attempt")))?;
    let attempt = &stored.record.attempt;
    if attempt.binding != commit.terminal_event.binding
        || stored.record.attempt_sha256 != commit.recovery_attempt_sha256
    {
        return Err(conflict(
            "Host recovery batch changed its immutable attempt or Host binding",
        ));
    }
    match &stored.record.state {
        TrustedHostFenceRecoveryAttemptStateV1::ProviderPending => {
            return Err(application(ApiError::unavailable(
                "Host-fence provider attempt is not terminal",
            )));
        }
        TrustedHostFenceRecoveryAttemptStateV1::Blocked { receipt } => {
            if receipt.terminal_event != commit.terminal_event {
                return Err(conflict(
                    "Blocked Host recovery replay changed its terminal provider evidence",
                ));
            }
            return Ok(TrustedHostFenceBatchRecoveryStoreOutcomeV1::Blocked(
                Box::new(receipt.clone()),
            ));
        }
        TrustedHostFenceRecoveryAttemptStateV1::Committed {
            batch_request_sha256,
            ..
        } => {
            let receipt = load_committed_batch_receipt(transaction, &commit.fence_attempt_id)?;
            if *batch_request_sha256 == request_sha256
                && receipt.request_sha256 == request_sha256
                && receipt.commit.as_ref() == commit
            {
                return Ok(TrustedHostFenceBatchRecoveryStoreOutcomeV1::Committed(
                    receipt,
                ));
            }
            return Err(conflict(
                "Host recovery batch replay changed its immutable commit",
            ));
        }
        TrustedHostFenceRecoveryAttemptStateV1::ProviderTerminal { terminal_event }
            if terminal_event != &commit.terminal_event =>
        {
            return Err(conflict(
                "Host recovery batch changed the accepted terminal event",
            ));
        }
        TrustedHostFenceRecoveryAttemptStateV1::ProviderTerminal { .. } => {}
    }
    let now = database_now(transaction)?;
    if commit.terminal_event.committed_at_unix_ms > now {
        return Err(rejected("terminal Host event time is in the future"));
    }
    let queue = load_queue_for_update(transaction, &commit.fence_attempt_id)?
        .ok_or_else(|| corrupt("Host recovery attempt has no provider queue row"))?;
    let HostFenceProviderQueueStateV1::Terminal { evidence, .. } = queue.state else {
        return Err(corrupt(
            "provider-terminal Host recovery has a nonterminal provider queue",
        ));
    };
    if queue.request != attempt.provider_request
        || *evidence != commit.terminal_event.provider_evidence
    {
        return Err(corrupt(
            "Host recovery terminal event/provider queue evidence changed",
        ));
    }

    let mut blockers = trusted_host_fence_recovery_blockers(attempt)
        .map_err(|error| corrupt(format!("derive frozen Host recovery blockers: {error}")))?;
    blockers.extend(recovery_request_blockers(attempt, commit, now)?);
    let (current_blockers, source_session) = current_authority_blockers_in(
        transaction,
        attempt,
        identities.get(&attempt.binding.node_id),
    )?;
    blockers.extend(current_blockers);
    blockers.extend(target_policy_blockers_in(
        transaction,
        attempt,
        commit,
        &identities,
        now,
    )?);
    blockers.extend(authorization_blockers_in(transaction, commit)?);
    if !blockers.is_empty() {
        return persist_blocked_and_load(
            transaction,
            attempt,
            &commit.terminal_event,
            blockers,
            now,
        );
    }

    let validated_sha = validate_trusted_host_fence_batch_recovery_commit_v1(attempt, commit)
        .map_err(|error| corrupt(format!("unclassified Host recovery batch error: {error}")))?;
    if validated_sha != request_sha256 {
        return Err(corrupt(
            "Host recovery batch digest changed after validation",
        ));
    }
    let source_identity = identities
        .get(&attempt.binding.node_id)
        .ok_or_else(|| corrupt("safe Host recovery lost its source NodeIdentity"))?;
    let source_session = source_session
        .as_ref()
        .ok_or_else(|| corrupt("safe Host recovery lost its source AgentSession"))?;

    insert_terminal_event(transaction, &commit.terminal_event)?;
    for recovery in &commit.recoveries {
        for volume in &recovery.volumes {
            insert_takeover_authorization(transaction, &volume.takeover_authorization)?;
        }
    }
    for (assigned, recovery) in attempt.assigned_cats.iter().zip(&commit.recoveries) {
        replace_desired(
            transaction,
            &assigned.expected_current_desired,
            &recovery.replacement_desired,
        )?;
        update_hostname_lookups(
            transaction,
            &assigned.expected_current_desired,
            &recovery.replacement_desired,
        )?;
        update_operation(transaction, &recovery.settled_old_operation)?;
        insert_operation(transaction, &recovery.recovery_operation)?;
    }

    // Once-only source retirement is deliberately the final authority effect;
    // every Cat/Volume/target precondition and write has already succeeded.
    retire_source_node(transaction, source_identity, source_session, now)?;
    let receipt = TrustedHostFenceBatchRecoveryCommitReceiptV1 {
        request_sha256,
        commit: Box::new(commit.clone()),
        committed_at_unix_ms: now,
    };
    update_attempt_committed_in(transaction, &receipt)?;
    Ok(TrustedHostFenceBatchRecoveryStoreOutcomeV1::Committed(
        receipt,
    ))
}

fn public_apply_matches_attempt(
    apply: &HostLossRecoveryApplyV1,
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> bool {
    if apply.version != ContractVersion::V1
        || apply.apply_id != attempt.apply_id
        || apply.source_node_id != attempt.binding.node_id
        || apply.expected_node_boot_id != attempt.binding.expected_node_boot_id
        || apply.expected_agent_session_epoch != attempt.binding.expected_agent_session_epoch
        || apply.expected_assigned.len() != attempt.assigned_cats.len()
    {
        return false;
    }
    let inventory_matches = match (&apply.expected_source_inventory, &attempt.source_inventory) {
        (
            cats_api::runtime_host_loss_recovery::HostLossRecoveryExpectedSourceInventoryV1::AcceptedFull {
                inventory_epoch,
                inventory_digest,
                inventory_read_position,
            },
            TrustedHostFenceSourceInventoryV1::AcceptedFull { attestation, .. },
        ) => {
            *inventory_epoch == attestation.inventory_epoch
                && *inventory_digest == attestation.inventory_digest
                && *inventory_read_position == attestation.inventory_read_position
        }
        (
            cats_api::runtime_host_loss_recovery::HostLossRecoveryExpectedSourceInventoryV1::Unavailable,
            TrustedHostFenceSourceInventoryV1::Unavailable { .. },
        ) => true,
        _ => false,
    };
    inventory_matches
        && apply
            .expected_assigned
            .iter()
            .zip(&attempt.assigned_cats)
            .all(|(expected, assigned)| {
                let desired = &assigned.expected_current_desired;
                let runtime_incarnation = match &assigned.inventory {
                    TrustedHostFenceAssignedCatInventoryV1::AcceptedFull { observed_runtime } => {
                        observed_runtime.runtime_incarnation.clone()
                    }
                    TrustedHostFenceAssignedCatInventoryV1::Unavailable => None,
                };
                expected.workspace_id == desired.workspace_id
                    && expected.cat_id == desired.cat_id
                    && expected.desired_revision == desired.desired_revision
                    && expected.spec_digest == desired.spec_digest
                    && expected.placement_epoch == desired.placement.placement_epoch
                    && expected.expected_runtime_incarnation == runtime_incarnation
            })
}

fn public_inventory_reason(
    reason: TrustedHostFenceInventoryUnavailableReasonV1,
) -> HostLossRecoveryInventoryUnavailableReasonV1 {
    match reason {
        TrustedHostFenceInventoryUnavailableReasonV1::NoAcceptedFullInventory => {
            HostLossRecoveryInventoryUnavailableReasonV1::NoAcceptedFullInventory
        }
        TrustedHostFenceInventoryUnavailableReasonV1::AcceptedFullInventoryNotCurrent => {
            HostLossRecoveryInventoryUnavailableReasonV1::AcceptedFullInventoryNotCurrent
        }
    }
}

fn public_strict_problem(
    problem: cats_storage::trusted_host_recovery::TrustedHostFenceStrictVolumeProblemV1,
) -> HostLossRecoveryStrictVolumeProblemV1 {
    use cats_storage::trusted_host_recovery::TrustedHostFenceStrictVolumeProblemV1 as Storage;
    match problem {
        Storage::InventoryUnavailable => {
            HostLossRecoveryStrictVolumeProblemV1::InventoryUnavailable
        }
        Storage::DesiredOrAuthorityBindingMismatch => {
            HostLossRecoveryStrictVolumeProblemV1::DesiredOrAuthorityBindingMismatch
        }
        Storage::ObservedVolumeBindingMismatch => {
            HostLossRecoveryStrictVolumeProblemV1::ObservedVolumeBindingMismatch
        }
        Storage::ObservedAuthorityNotExactOwner => {
            HostLossRecoveryStrictVolumeProblemV1::ObservedAuthorityNotExactOwner
        }
        Storage::LocalLineagesNotCanonical => {
            HostLossRecoveryStrictVolumeProblemV1::LocalLineagesNotCanonical
        }
        Storage::CurrentLineageMissing => {
            HostLossRecoveryStrictVolumeProblemV1::CurrentLineageMissing
        }
        Storage::CurrentLineageDuplicated => {
            HostLossRecoveryStrictVolumeProblemV1::CurrentLineageDuplicated
        }
        Storage::CurrentLineageBindingMismatch => {
            HostLossRecoveryStrictVolumeProblemV1::CurrentLineageBindingMismatch
        }
        Storage::CurrentLineageNotActive => {
            HostLossRecoveryStrictVolumeProblemV1::CurrentLineageNotActive
        }
        Storage::LocalGenerationAheadOfRemote => {
            HostLossRecoveryStrictVolumeProblemV1::LocalGenerationAheadOfRemote
        }
        Storage::RemoteGenerationDoesNotMatchHead => {
            HostLossRecoveryStrictVolumeProblemV1::RemoteGenerationDoesNotMatchHead
        }
        Storage::PendingPacksRemain => HostLossRecoveryStrictVolumeProblemV1::PendingPacksRemain,
    }
}

fn public_current_component(
    component: TrustedHostFenceCurrentAuthorityComponentV1,
) -> HostLossRecoveryCurrentAuthorityComponentV1 {
    match component {
        TrustedHostFenceCurrentAuthorityComponentV1::SourceIdentity => {
            HostLossRecoveryCurrentAuthorityComponentV1::SourceIdentity
        }
        TrustedHostFenceCurrentAuthorityComponentV1::SourceAgentSession => {
            HostLossRecoveryCurrentAuthorityComponentV1::SourceAgentSession
        }
        TrustedHostFenceCurrentAuthorityComponentV1::AssignedCatSet => {
            HostLossRecoveryCurrentAuthorityComponentV1::AssignedCatSet
        }
        TrustedHostFenceCurrentAuthorityComponentV1::Desired => {
            HostLossRecoveryCurrentAuthorityComponentV1::Desired
        }
        TrustedHostFenceCurrentAuthorityComponentV1::OldOperation => {
            HostLossRecoveryCurrentAuthorityComponentV1::OldOperation
        }
        TrustedHostFenceCurrentAuthorityComponentV1::VolumeRecord => {
            HostLossRecoveryCurrentAuthorityComponentV1::VolumeRecord
        }
        TrustedHostFenceCurrentAuthorityComponentV1::VolumeOwner => {
            HostLossRecoveryCurrentAuthorityComponentV1::VolumeOwner
        }
        TrustedHostFenceCurrentAuthorityComponentV1::TakeoverAuthorization => {
            HostLossRecoveryCurrentAuthorityComponentV1::TakeoverAuthorization
        }
    }
}

fn public_target_problem(
    problem: TrustedHostFenceRecoveryTargetProblemV1,
) -> HostLossRecoveryTargetProblemV1 {
    match problem {
        TrustedHostFenceRecoveryTargetProblemV1::NoEligibleReplacementNode => {
            HostLossRecoveryTargetProblemV1::NoEligibleReplacementNode
        }
        TrustedHostFenceRecoveryTargetProblemV1::ReplacementPolicyChanged => {
            HostLossRecoveryTargetProblemV1::ReplacementPolicyChanged
        }
        TrustedHostFenceRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable => {
            HostLossRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable
        }
    }
}

fn public_blocked_reason(
    reason: &TrustedHostFenceRecoveryBlockedReasonV1,
) -> HostLossRecoveryBlockedReasonV1 {
    match reason {
        TrustedHostFenceRecoveryBlockedReasonV1::SourceInventoryUnavailable { reason } => {
            HostLossRecoveryBlockedReasonV1::SourceInventoryUnavailable {
                unavailable_reason: public_inventory_reason(*reason),
            }
        }
        TrustedHostFenceRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
            cat_id,
            volume_id,
        } => HostLossRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
            cat_id: cat_id.clone(),
            volume_id: volume_id.clone(),
        },
        TrustedHostFenceRecoveryBlockedReasonV1::StrictVolumeNotSafelyRecoverable {
            cat_id,
            volume_id,
            problem,
        } => HostLossRecoveryBlockedReasonV1::StrictVolumeNotSafelyRecoverable {
            cat_id: cat_id.clone(),
            volume_id: volume_id.clone(),
            problem: public_strict_problem(*problem),
        },
        TrustedHostFenceRecoveryBlockedReasonV1::CurrentAuthorityChanged {
            cat_id,
            volume_id,
            component,
        } => HostLossRecoveryBlockedReasonV1::CurrentAuthorityChanged {
            cat_id: cat_id.clone(),
            volume_id: volume_id.clone(),
            component: public_current_component(*component),
        },
        TrustedHostFenceRecoveryBlockedReasonV1::RecoveryTargetUnavailable { cat_id, problem } => {
            HostLossRecoveryBlockedReasonV1::RecoveryTargetUnavailable {
                cat_id: cat_id.clone(),
                problem: public_target_problem(*problem),
            }
        }
    }
}

fn public_terminal_receipt(
    attempt: &TrustedHostFenceRecoveryAttemptRecordV1,
    event: &TrustedHostFenceEventV1,
    outcome: HostLossRecoveryTerminalOutcomeV1,
    completed_at: UnixMillis,
) -> AuthorityTxResult<(HostLossRecoveryTerminalReceiptV1, Sha256Digest)> {
    let receipt = HostLossRecoveryTerminalReceiptV1 {
        version: ContractVersion::V1,
        apply_id: attempt.attempt.apply_id.clone(),
        fence_attempt_id: attempt.attempt.binding.fence_attempt_id.clone(),
        source_provider_scope: attempt.attempt.binding.provider_scope.clone(),
        immutable_host_id: attempt.attempt.binding.immutable_host_id.clone(),
        source_node_id: attempt.attempt.binding.node_id.clone(),
        expected_node_boot_id: attempt.attempt.binding.expected_node_boot_id.clone(),
        expected_agent_session_epoch: attempt.attempt.binding.expected_agent_session_epoch,
        recovery_attempt_sha256: attempt.attempt_sha256.clone(),
        assigned_set_sha256: attempt.attempt.assigned_set_sha256.clone(),
        host_fence_event_id: event.event_id.clone(),
        provider_evidence_sha256: event.provider_evidence_sha256.clone(),
        outcome,
        completed_at_unix_ms: completed_at,
    };
    let digest = host_loss_recovery_terminal_receipt_sha256(&receipt)
        .map_err(|error| corrupt(format!("encode public Host recovery receipt: {error}")))?;
    Ok((receipt, digest))
}

fn public_committed_cats(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> AuthorityTxResult<Vec<HostLossRecoveryCommittedCatV1>> {
    attempt
        .assigned_cats
        .iter()
        .zip(&commit.recoveries)
        .map(|(assigned, recovery)| {
            let takeover_authorization_ids = recovery
                .volumes
                .iter()
                .map(
                    |volume| match &volume.takeover_authorization.authorization {
                        VolumeAuthorization::Takeover(authorization) => {
                            Ok(authorization.authorization_id.clone())
                        }
                        VolumeAuthorization::DisposableRootDelete(_) => Err(corrupt(
                            "committed Host recovery contains a non-takeover authorization",
                        )),
                    },
                )
                .collect::<AuthorityTxResult<Vec<_>>>()?;
            Ok(HostLossRecoveryCommittedCatV1 {
                workspace_id: assigned.expected_current_desired.workspace_id.clone(),
                cat_id: assigned.expected_current_desired.cat_id.clone(),
                old_desired_revision: assigned.expected_current_desired.desired_revision,
                old_placement_epoch: assigned.expected_current_desired.placement.placement_epoch,
                old_operation_id: assigned.expected_old_operation.operation_id.clone(),
                replacement_desired_revision: recovery.replacement_desired.desired_revision,
                replacement_spec_digest: recovery.replacement_desired.spec_digest.clone(),
                replacement_node_id: recovery.replacement_desired.placement.node_id.clone(),
                replacement_placement_epoch: recovery.replacement_desired.placement.placement_epoch,
                settled_old_operation_id: recovery.settled_old_operation.operation_id.clone(),
                recovery_operation_id: recovery.recovery_operation.operation_id.clone(),
                takeover_authorization_ids,
            })
        })
        .collect()
}

fn public_apply_result(
    record: &TrustedHostFenceRecoveryAttemptRecordV1,
) -> HostLossRecoveryApplyResultV1 {
    HostLossRecoveryApplyResultV1 {
        version: ContractVersion::V1,
        apply_id: record.attempt.apply_id.clone(),
        fence_attempt_id: record.attempt.binding.fence_attempt_id.clone(),
        recovery_attempt_sha256: record.attempt_sha256.clone(),
        assigned_set_sha256: record.attempt.assigned_set_sha256.clone(),
    }
}

fn public_discovery_result_in(
    transaction: &mut Transaction<'_>,
    discovery: &HostLossRecoveryDiscoveryV1,
) -> AuthorityTxResult<Option<HostLossRecoveryDiscoveryResultV1>> {
    validate_host_loss_recovery_discovery_v1(discovery)
        .map_err(|error| rejected(format!("invalid Host recovery discovery: {error}")))?;
    lock_recovery_apply_id(transaction, &discovery.apply_id)?;
    let Some(stored) = load_attempt_by_apply_for_update(transaction, &discovery.apply_id)? else {
        return Ok(None);
    };
    let attempt = &stored.record;
    if attempt.attempt.binding.node_id != discovery.source_node_id
        || attempt.attempt.binding.fence_attempt_id != discovery.fence_attempt_id
    {
        return Err(conflict(
            "Host recovery discovery changed its immutable source or fence attempt",
        ));
    }

    let outcome = match &attempt.state {
        TrustedHostFenceRecoveryAttemptStateV1::ProviderPending
        | TrustedHostFenceRecoveryAttemptStateV1::ProviderTerminal { .. } => {
            HostLossRecoveryDiscoveryOutcomeV1::Pending
        }
        TrustedHostFenceRecoveryAttemptStateV1::Blocked { receipt } => {
            let public_outcome = HostLossRecoveryTerminalOutcomeV1::Blocked {
                reasons: receipt.reasons.iter().map(public_blocked_reason).collect(),
            };
            let (receipt, receipt_sha256) = public_terminal_receipt(
                attempt,
                &receipt.terminal_event,
                public_outcome,
                receipt.blocked_at_unix_ms,
            )?;
            HostLossRecoveryDiscoveryOutcomeV1::Terminal {
                receipt: Box::new(receipt),
                receipt_sha256,
            }
        }
        TrustedHostFenceRecoveryAttemptStateV1::Committed {
            terminal_event_id,
            batch_request_sha256,
            committed_at_unix_ms,
        } => {
            let receipt = load_committed_batch_receipt(
                transaction,
                &attempt.attempt.binding.fence_attempt_id,
            )?;
            if receipt.request_sha256 != *batch_request_sha256
                || receipt.commit.terminal_event.event_id != *terminal_event_id
                || receipt.committed_at_unix_ms != *committed_at_unix_ms
            {
                return Err(corrupt(
                    "Host recovery committed discovery projection changed",
                ));
            }
            let public_outcome = HostLossRecoveryTerminalOutcomeV1::Committed {
                batch_request_sha256: receipt.request_sha256.clone(),
                source_retired_at_unix_ms: receipt.committed_at_unix_ms,
                cats: public_committed_cats(&attempt.attempt, receipt.commit.as_ref())?,
            };
            let (public_receipt, receipt_sha256) = public_terminal_receipt(
                attempt,
                &receipt.commit.terminal_event,
                public_outcome,
                receipt.committed_at_unix_ms,
            )?;
            HostLossRecoveryDiscoveryOutcomeV1::Terminal {
                receipt: Box::new(public_receipt),
                receipt_sha256,
            }
        }
    };
    let result = HostLossRecoveryDiscoveryResultV1 {
        version: ContractVersion::V1,
        apply_id: attempt.attempt.apply_id.clone(),
        fence_attempt_id: attempt.attempt.binding.fence_attempt_id.clone(),
        recovery_attempt_sha256: attempt.attempt_sha256.clone(),
        assigned_set_sha256: attempt.attempt.assigned_set_sha256.clone(),
        outcome,
    };
    validate_host_loss_recovery_discovery_result_v1(&result)
        .map_err(|error| corrupt(format!("invalid public Host recovery discovery: {error}")))?;
    Ok(Some(result))
}

impl Store {
    /// Internal authority seam. The future authenticated fleet service must
    /// pass its authenticated principal and preloaded immutable authority
    /// artifact. Control constructs the complete attempt from locked rows; no
    /// HTTP client can submit a provider request or authority snapshot.
    pub(crate) fn begin_trusted_host_fence_recovery_attempt_v1(
        &self,
        principal: &cats_api::runtime_reconciliation::FleetPolicyPrincipal,
        apply: &HostLossRecoveryApplyV1,
        authority_bindings: &HostFenceAuthorityBindingsV1,
    ) -> crate::store::Result<HostLossRecoveryApplyResultV1> {
        self.authority_transaction(|transaction| {
            let record = begin_attempt_in(transaction, apply, principal, authority_bindings)?;
            Ok(public_apply_result(&record))
        })
    }

    pub(crate) fn observe_trusted_host_fence_provider_terminal_v1(
        &self,
        binding: &cats_storage::host_fence::HostFenceBinding,
    ) -> crate::store::Result<TrustedHostFenceRecoveryAttemptRecordV1> {
        self.authority_transaction(|transaction| observe_provider_terminal_in(transaction, binding))
    }

    pub(crate) fn commit_trusted_host_fence_batch_recovery_v1(
        &self,
        commit: &TrustedHostFenceBatchRecoveryCommitV1,
    ) -> crate::store::Result<TrustedHostFenceBatchRecoveryStoreOutcomeV1> {
        self.authority_transaction(|transaction| batch_recovery_in(transaction, commit))
    }

    /// Owner-side discovery requires the complete Host/Node/session binding;
    /// no attempt-ID-only list or provider credential is exposed.
    pub(crate) fn get_trusted_host_fence_recovery_attempt_v1(
        &self,
        binding: &cats_storage::host_fence::HostFenceBinding,
    ) -> crate::store::Result<Option<TrustedHostFenceRecoveryAttemptRecordV1>> {
        self.authority_transaction(|transaction| {
            let stored = load_attempt_for_update(transaction, &binding.fence_attempt_id)?;
            match stored {
                Some(stored) if stored.record.attempt.binding != *binding => Err(conflict(
                    "Host recovery discovery changed its complete Host binding",
                )),
                Some(stored) => Ok(Some(stored.record)),
                None => Ok(None),
            }
        })
    }

    /// Authenticated owner-side discovery by the exact immutable apply key.
    /// It exposes only the frozen public projection, never provider claim
    /// tokens, queue internals, or a raw attempt list.
    pub(crate) fn discover_trusted_host_fence_recovery_v1(
        &self,
        discovery: &HostLossRecoveryDiscoveryV1,
    ) -> crate::store::Result<Option<HostLossRecoveryDiscoveryResultV1>> {
        self.authority_transaction(|transaction| public_discovery_result_in(transaction, discovery))
    }
}

/// Serialize Host-scoped recovery with fresh Node provisioning, including
/// the missing-row case where no `node_identities` row can provide a lock.
/// The exact provider tuple is part of the key; an immutable Host ID is not a
/// globally meaningful provider identifier on its own.
pub(in crate::store) fn require_host_recovery_unblocked_in(
    transaction: &mut Transaction<'_>,
    provider_scope: &ProviderScope,
    immutable_host_id: &Id,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':host-recovery-source:' ||
            jsonb_build_array(
                $1::TEXT,$2::TEXT,$3::TEXT,$4::TEXT,$5::TEXT
            )::TEXT,
            0::BIGINT))",
        &[
            &provider_scope.provider.as_str(),
            &provider_scope.partition.as_str(),
            &provider_scope.account_id.as_str(),
            &provider_scope.region.as_str(),
            &immutable_host_id.as_str(),
        ],
    )?;
    let rows = transaction.query(
        "SELECT fence_attempt_id, node_id
           FROM trusted_host_fence_recovery_attempts_v1
          WHERE provider=$1 AND host_partition=$2
            AND host_account_id=$3 AND host_region=$4
            AND immutable_host_id=$5
            AND state IN ('provider_pending', 'provider_terminal', 'blocked')
          ORDER BY fence_attempt_id COLLATE \"C\" LIMIT 2 FOR UPDATE",
        &[
            &provider_scope.provider.as_str(),
            &provider_scope.partition.as_str(),
            &provider_scope.account_id.as_str(),
            &provider_scope.region.as_str(),
            &immutable_host_id.as_str(),
        ],
    )?;
    if rows.len() > 1 {
        return Err(corrupt(
            "more than one active Host recovery attempt exists for one immutable Host",
        ));
    }
    if !rows.is_empty() {
        return Err(application(ApiError::conflict(
            "immutable Host is sealed by an active recovery attempt",
        )));
    }
    Ok(())
}

/// Requires the caller to hold this Node's `node_identities` row lock.
///
/// The missing-row case is serialized by that parent lock: recovery enqueue
/// takes the same lock before inserting its barrier.  Exact mutation replay
/// is resolved before calling this helper, so rejecting here never hides a
/// previously committed response.
pub(in crate::store) fn require_product_mutation_unblocked_in(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<()> {
    let rows = load_active_attempts(transaction, node_id, "FOR UPDATE")?;
    if rows.len() > 1 {
        return Err(corrupt(
            "more than one active Host recovery attempt exists for one Node",
        ));
    }
    if !rows.is_empty() {
        return Err(application(ApiError::conflict(
            "Node is sealed by an active Host recovery attempt",
        )));
    }
    Ok(())
}

/// Observation and heartbeat ingestion deliberately do not call this read.
/// Placement and Route admission do: an active recovery attempt is a closed
/// server-side source gate even before provider network isolation finishes.
pub(super) fn product_admission_is_blocked_in(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<bool> {
    let rows = load_active_attempts(transaction, node_id, "")?;
    if rows.len() > 1 {
        return Err(corrupt(
            "more than one active Host recovery attempt exists for one Node",
        ));
    }
    Ok(!rows.is_empty())
}

fn load_active_attempts(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    lock: &str,
) -> AuthorityTxResult<Vec<postgres::Row>> {
    let sql = format!(
        "SELECT fence_attempt_id
           FROM trusted_host_fence_recovery_attempts_v1
          WHERE node_id=$1 AND state IN ('provider_pending', 'provider_terminal', 'blocked')
          ORDER BY fence_attempt_id COLLATE \"C\" LIMIT 2 {lock}"
    );
    transaction
        .query(&sql, &[&node_id.as_str()])
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        assigned_set_limit_problem, MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS,
        MAX_TRUSTED_HOST_FENCE_TOTAL_VOLUME_PROOFS, MAX_VOLUMES_PER_ASSIGNED_CAT,
    };

    #[test]
    fn store_assigned_set_limits_accept_one_two_and_exact_1024_cat_boundary() {
        assert_eq!(assigned_set_limit_problem([1]), None);
        assert_eq!(assigned_set_limit_problem([1, 1]), None);
        let boundary = vec![MAX_VOLUMES_PER_ASSIGNED_CAT; MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS];
        assert_eq!(
            boundary.iter().sum::<usize>(),
            MAX_TRUSTED_HOST_FENCE_TOTAL_VOLUME_PROOFS
        );
        assert_eq!(assigned_set_limit_problem(boundary), None);
    }

    #[test]
    fn store_assigned_set_limits_reject_empty_per_cat_and_total_overflow() {
        assert!(assigned_set_limit_problem(Vec::<usize>::new()).is_some());
        assert!(assigned_set_limit_problem([0]).is_some());
        assert!(assigned_set_limit_problem([MAX_VOLUMES_PER_ASSIGNED_CAT + 1]).is_some());
        assert!(assigned_set_limit_problem(vec![
            MAX_VOLUMES_PER_ASSIGNED_CAT;
            MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS + 1
        ])
        .is_some());
    }
}

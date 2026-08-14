//! One PostgreSQL commit for a terminal Host fence and its recovery Desired.
//!
//! The provider proof has already crossed the compute, workload-network and
//! object-write terminal/visibility barriers.  This module is the only writer
//! that may turn that immutable D2 fact into per-Volume takeover authorities,
//! replace the current Desired and publish the recovery Operation.  No legacy
//! Active/Rejoined event is accepted here.

use std::collections::{BTreeMap, BTreeSet};

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_operation, spec_digest, AgentSession, AuthorizationRecord,
    AuthorizationState, ContractVersion, DesiredRuntimeSpec, Epoch, Id, NodeBootId, NodeIdentity,
    NodeIdentityState, Operation, OperationFailure, OperationPhase, OperationTerminal, RemoteHead,
    Revision, Sha256Digest, UnixMillis, VolumeAcquire, VolumeAdminState, VolumeAuthorization,
    VolumeRecord,
};
use cats_storage::authority::{
    validate_authorization_record, validate_volume_record, VolumeOwnerBinding,
};
use cats_storage::trusted_host_fence::{
    decode_trusted_host_fence_event_v1, encode_trusted_host_fence_event_v1,
    validate_trusted_host_fence_event_v1, TrustedHostFenceEventV1,
};
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::product::HostnameDesiredLookup;
use super::product_rows::{
    insert_operation, load_assigned_desired_for_update, load_cat_by_id_for_update,
    load_desired_for_update, load_operation_for_update, load_pending_operation_by_cat_for_update,
    update_operation,
};
use super::rows::{database_now, load_stored_volume_for_update};
use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_node_for_update, retire_node_identity_in,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::Store;

const RECOVERY_REQUEST_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence-recovery-commit.v1";
const MAX_TAKEOVER_VOLUMES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTakeoverAuthorizationV1 {
    pub expected_current_volume: VolumeRecord,
    pub authorization: AuthorizationRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceRecoveryCommitV1 {
    pub terminal_event: TrustedHostFenceEventV1,
    pub expected_old_node_id: Id,
    pub expected_old_node_boot_id: NodeBootId,
    pub expected_old_agent_session_epoch: Epoch,
    pub expected_current_desired: DesiredRuntimeSpec,
    pub takeover_authorizations: Vec<TrustedTakeoverAuthorizationV1>,
    pub replacement_desired: DesiredRuntimeSpec,
    pub expected_old_operation: Operation,
    pub settled_old_operation: Operation,
    pub recovery_operation: Operation,
}

/// Immutable result used to resolve a lost PostgreSQL COMMIT response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceRecoveryCommitReceiptV1 {
    pub request_sha256: Sha256Digest,
    pub commit: Box<TrustedHostFenceRecoveryCommitV1>,
    pub committed_at_unix_ms: UnixMillis,
}

fn application(error: ApiError) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(error)
}

fn rejected(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

fn conflict(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::conflict(message.into()))
}

fn corrupt(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

fn pg(value: u64, field: &'static str) -> AuthorityTxResult<i64> {
    i64::try_from(value).map_err(|_| corrupt(format!("{field} exceeds PostgreSQL BIGINT")))
}

fn canonical<T: Serialize>(value: &T, context: &'static str) -> AuthorityTxResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| corrupt(format!("encode {context}: {error}")))
}

fn decode<T: DeserializeOwned>(bytes: &[u8], context: &'static str) -> AuthorityTxResult<T> {
    serde_json::from_slice(bytes).map_err(|error| corrupt(format!("decode {context}: {error}")))
}

fn request_sha256(request: &TrustedHostFenceRecoveryCommitV1) -> AuthorityTxResult<Sha256Digest> {
    let bytes = canonical(request, "trusted Host-fence recovery request")?;
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_REQUEST_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn validate_desired_digest(desired: &DesiredRuntimeSpec) -> AuthorityTxResult<()> {
    let computed = spec_digest(desired)
        .map_err(|error| rejected(format!("invalid recovery Desired: {error}")))?;
    if computed != desired.spec_digest {
        return Err(rejected("recovery Desired digest does not match its body"));
    }
    Ok(())
}

fn validate_operation_binding(
    operation: &Operation,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    encode_operation(operation)
        .map_err(|error| rejected(format!("invalid recovery Operation: {error}")))?;
    if operation.version != ContractVersion::V1
        || operation.workspace_id != desired.workspace_id
        || operation.cat_id != desired.cat_id
        || operation.desired_revision != desired.desired_revision
        || operation.desired_spec_digest != desired.spec_digest
        || operation.placement != desired.placement
        || operation.target != desired.target
    {
        return Err(rejected(
            "recovery Operation is not bound to its exact Desired",
        ));
    }
    Ok(())
}

fn next_revision(value: Revision) -> AuthorityTxResult<Revision> {
    value
        .get()
        .checked_add(1)
        .and_then(Revision::new)
        .ok_or_else(|| rejected("recovery Desired revision is exhausted"))
}

fn next_epoch(value: Epoch) -> AuthorityTxResult<Epoch> {
    value
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or_else(|| rejected("recovery placement epoch is exhausted"))
}

pub(super) fn takeover_payload(
    record: &AuthorizationRecord,
) -> AuthorityTxResult<&cats_api::runtime_reconciliation::VolumeTakeoverAuthorization> {
    if !matches!(record.state, AuthorizationState::Unconsumed) {
        return Err(rejected(
            "recovery takeover authorization is already consumed",
        ));
    }
    let VolumeAuthorization::Takeover(authorization) = &record.authorization else {
        return Err(rejected("recovery contains a non-takeover authorization"));
    };
    Ok(authorization)
}

fn validate_recovery_shape(
    request: &TrustedHostFenceRecoveryCommitV1,
) -> AuthorityTxResult<Sha256Digest> {
    validate_trusted_host_fence_event_v1(&request.terminal_event)
        .map_err(|error| rejected(format!("untrusted Host-fence event: {error}")))?;
    let binding = &request.terminal_event.binding;
    if request.expected_old_node_id != binding.node_id
        || request.expected_old_node_boot_id != binding.expected_node_boot_id
        || request.expected_old_agent_session_epoch != binding.expected_agent_session_epoch
    {
        return Err(rejected(
            "recovery old Node/boot/session does not match terminal evidence",
        ));
    }

    let current = &request.expected_current_desired;
    let replacement = &request.replacement_desired;
    validate_desired_digest(current)?;
    validate_desired_digest(replacement)?;
    if current.version != ContractVersion::V1
        || replacement.version != ContractVersion::V1
        || current.workspace_id != replacement.workspace_id
        || current.cat_id != replacement.cat_id
        || current.placement.node_id != binding.node_id
        || replacement.placement.node_id == binding.node_id
        || replacement.desired_revision != next_revision(current.desired_revision)?
        || replacement.placement.placement_epoch != next_epoch(current.placement.placement_epoch)?
        || current.placement.kind != replacement.placement.kind
        || current.target != replacement.target
        || current.runtime != replacement.runtime
        || current.endpoints != replacement.endpoints
        || current.transition != replacement.transition
    {
        return Err(rejected(
            "replacement Desired is not the exact one-revision Host recovery successor",
        ));
    }

    if request.takeover_authorizations.is_empty()
        || request.takeover_authorizations.len() > MAX_TAKEOVER_VOLUMES
        || request.takeover_authorizations.len() != current.volumes.len()
        || current.volumes.len() != replacement.volumes.len()
    {
        return Err(rejected(
            "recovery must bind every Desired Volume exactly once",
        ));
    }

    let mut authorizations = BTreeMap::new();
    let mut previous_volume_id: Option<&Id> = None;
    for candidate in &request.takeover_authorizations {
        validate_volume_record(&candidate.expected_current_volume)
            .map_err(|error| rejected(format!("invalid expected Volume: {error}")))?;
        validate_authorization_record(&candidate.authorization)
            .map_err(|error| rejected(format!("invalid takeover authorization: {error}")))?;
        let authorization = takeover_payload(&candidate.authorization)?;
        if previous_volume_id.is_some_and(|previous| previous >= &authorization.volume_id) {
            return Err(rejected(
                "recovery takeover authorizations are not in strict Volume order",
            ));
        }
        previous_volume_id = Some(&authorization.volume_id);
        let volume = &candidate.expected_current_volume;
        if authorization.host_fence_event_id != request.terminal_event.event_id
            || authorization.authorized_node_id != replacement.placement.node_id
            || authorization.desired_revision != replacement.desired_revision
            || authorization.new_placement_epoch != replacement.placement.placement_epoch
            || authorization.volume_id != volume.volume_id
            || authorization.expected_attachment_id
                != volume
                    .lease_owner
                    .clone()
                    .ok_or_else(|| rejected("recovery expected Volume has no old writer"))?
            || authorization.expected_epoch != volume.lease_epoch
            || authorization.expected_head != volume.head
            || !matches!(volume.admin_state, VolumeAdminState::Active)
            || authorization.not_after < request.terminal_event.committed_at_unix_ms
        {
            return Err(rejected(
                "takeover authorization does not bind the exact terminal Volume tuple",
            ));
        }
        if authorizations
            .insert(authorization.volume_id.clone(), candidate)
            .is_some()
        {
            return Err(rejected("duplicate recovery Volume authorization"));
        }
    }

    for (source, successor) in current.volumes.iter().zip(&replacement.volumes) {
        if source.volume_id != successor.volume_id {
            return Err(rejected(
                "recovery changed Desired Volume order or identity",
            ));
        }
        let Some(candidate) = authorizations.get(&source.volume_id) else {
            return Err(rejected("recovery Desired Volume has no authorization"));
        };
        let authorization = takeover_payload(&candidate.authorization)?;
        let volume = &candidate.expected_current_volume;
        let mut exact_successor = source.clone();
        exact_successor.attachment_id = authorization.new_attachment_id.clone();
        exact_successor.acquire = VolumeAcquire::Takeover {
            authorization_id: authorization.authorization_id.clone(),
        };
        if successor != &exact_successor
            || source.attachment_id != authorization.expected_attachment_id
            || successor.attachment_id != authorization.new_attachment_id
            || source.size_bytes != volume.size_bytes
            || source.durability != volume.durability
        {
            return Err(rejected(
                "recovery Desired does not copy the exact Volume contract",
            ));
        }
    }

    validate_operation_binding(&request.expected_old_operation, current)?;
    if request.expected_old_operation.phase != OperationPhase::Pending
        || request.expected_old_operation.terminal.is_some()
    {
        return Err(rejected(
            "Host recovery requires the exact old Pending Operation",
        ));
    }
    let completed_at = request.terminal_event.committed_at_unix_ms;
    let mut expected_settlement = request.expected_old_operation.clone();
    expected_settlement.phase = OperationPhase::Failed;
    expected_settlement.terminal = Some(OperationTerminal::Failed {
        error: Box::new(OperationFailure::HostLost {
            node_id: binding.node_id.clone(),
            agent_session_epoch: binding.expected_agent_session_epoch,
            host_fence_event_id: request.terminal_event.event_id.clone(),
        }),
        completed_at_unix_ms: completed_at,
    });
    expected_settlement.updated_at_unix_ms = completed_at;
    if request.settled_old_operation != expected_settlement
        || completed_at < request.expected_old_operation.updated_at_unix_ms
    {
        return Err(rejected("old Operation HostLost settlement is not exact"));
    }

    validate_operation_binding(&request.recovery_operation, replacement)?;
    if request.recovery_operation.operation_id == request.expected_old_operation.operation_id
        || request.recovery_operation.phase != OperationPhase::Pending
        || request.recovery_operation.terminal.is_some()
        || request.recovery_operation.created_at_unix_ms != completed_at
        || request.recovery_operation.updated_at_unix_ms != completed_at
    {
        return Err(rejected(
            "recovery Operation must be a fresh exact Pending publication",
        ));
    }
    request_sha256(request)
}

fn validate_identity_binding(
    identity: &NodeIdentity,
    request: &TrustedHostFenceRecoveryCommitV1,
) -> AuthorityTxResult<()> {
    let binding = &request.terminal_event.binding;
    if identity.node_id != binding.node_id
        || identity.provider_scope != binding.provider_scope
        || identity.immutable_host_id != binding.immutable_host_id
    {
        return Err(conflict(
            "terminal Host-fence evidence names another immutable Node identity",
        ));
    }
    Ok(())
}

fn lock_node_identities(
    transaction: &mut Transaction<'_>,
    request: &TrustedHostFenceRecoveryCommitV1,
) -> AuthorityTxResult<(NodeIdentity, NodeIdentity)> {
    let old_node = &request.expected_old_node_id;
    let new_node = &request.replacement_desired.placement.node_id;
    let mut keys = BTreeSet::new();
    keys.insert(old_node.clone());
    keys.insert(new_node.clone());
    if keys.len() != 2 {
        return Err(rejected("Host recovery target must be a different Node"));
    }
    let mut locked = BTreeMap::new();
    for node_id in keys {
        let identity = load_identity_by_node_for_update(transaction, &node_id)?
            .ok_or_else(|| conflict("Host recovery NodeIdentity is absent"))?;
        locked.insert(node_id, identity);
    }
    let old = locked
        .remove(old_node)
        .ok_or_else(|| corrupt("old NodeIdentity lock disappeared"))?;
    let new = locked
        .remove(new_node)
        .ok_or_else(|| corrupt("new NodeIdentity lock disappeared"))?;
    validate_identity_binding(&old, request)?;
    if old.provider_scope == new.provider_scope && old.immutable_host_id == new.immutable_host_id {
        return Err(rejected(
            "Host recovery target reuses the fenced immutable Host",
        ));
    }
    Ok((old, new))
}

fn jsonb_matches_canonical(record_json: String, canonical: &[u8]) -> AuthorityTxResult<bool> {
    let stored: serde_json::Value = decode(record_json.as_bytes(), "authority JSONB")?;
    let expected: serde_json::Value = decode(canonical, "canonical authority JSON")?;
    Ok(stored == expected)
}

fn decode_terminal_event_row(row: &Row) -> AuthorityTxResult<TrustedHostFenceEventV1> {
    let state: String = row.try_get("state")?;
    if state != "terminal_v1" {
        return Err(conflict(
            "Host-fence event ID is owned by a retired authority kind",
        ));
    }
    let canonical: Vec<u8> = row
        .try_get::<_, Option<Vec<u8>>>("canonical_record")?
        .ok_or_else(|| corrupt("terminal Host-fence row has no canonical record"))?;
    let event = decode_trusted_host_fence_event_v1(&canonical)
        .map_err(|error| corrupt(format!("invalid terminal Host-fence row: {error}")))?;
    if !jsonb_matches_canonical(row.try_get("record_json")?, &canonical)? {
        return Err(corrupt("terminal Host-fence JSONB/canonical mismatch"));
    }
    let expected_session = pg(
        event.binding.expected_agent_session_epoch.get(),
        "session epoch",
    )?;
    let observed_at = pg(
        event.provider_evidence.completed_at_unix_ms.get(),
        "provider completed time",
    )?;
    let committed_at = pg(event.committed_at_unix_ms.get(), "event committed time")?;
    if row.try_get::<_, String>("event_id")? != event.event_id.as_str()
        || row.try_get::<_, String>("provider")? != event.binding.provider_scope.provider.as_str()
        || row
            .try_get::<_, Option<String>>("host_partition")?
            .as_deref()
            != Some(event.binding.provider_scope.partition.as_str())
        || row
            .try_get::<_, Option<String>>("host_account_id")?
            .as_deref()
            != Some(event.binding.provider_scope.account_id.as_str())
        || row.try_get::<_, Option<String>>("host_region")?.as_deref()
            != Some(event.binding.provider_scope.region.as_str())
        || row.try_get::<_, String>("immutable_host_id")?
            != event.binding.immutable_host_id.as_str()
        || row.try_get::<_, String>("node_id")? != event.binding.node_id.as_str()
        || row.try_get::<_, String>("expected_node_boot_id")?
            != event.binding.expected_node_boot_id.as_str()
        || row.try_get::<_, i64>("expected_agent_session_epoch")? != expected_session
        || row.try_get::<_, String>("fence_attempt_id")? != event.binding.fence_attempt_id.as_str()
        || row.try_get::<_, String>("isolation_state")? != "trusted_provider_evidence_v1"
        || row.try_get::<_, i64>("observed_at")? != observed_at
        || row.try_get::<_, Option<i64>>("destroyed_at")?.is_some()
        || row
            .try_get::<_, Option<String>>("provider_evidence_sha256")?
            .as_deref()
            != Some(event.provider_evidence_sha256.as_str())
        || row.try_get::<_, Option<i64>>("committed_at")? != Some(committed_at)
    {
        return Err(corrupt("terminal Host-fence scalar projection mismatch"));
    }
    Ok(event)
}

pub(super) fn load_terminal_event_for_update(
    transaction: &mut Transaction<'_>,
    event_id: &Id,
) -> AuthorityTxResult<Option<TrustedHostFenceEventV1>> {
    transaction
        .query_opt(
            "SELECT event_id, record::text AS record_json, canonical_record,
                    provider, host_partition, host_account_id, host_region,
                    immutable_host_id, node_id, expected_node_boot_id,
                    expected_agent_session_epoch, fence_attempt_id,
                    isolation_state, observed_at, state, destroyed_at,
                    provider_evidence_sha256, committed_at
               FROM host_fence_events WHERE event_id=$1 FOR UPDATE",
            &[&event_id.as_str()],
        )?
        .map(|row| decode_terminal_event_row(&row))
        .transpose()
}

fn decode_receipt_row(row: &Row) -> AuthorityTxResult<TrustedHostFenceRecoveryCommitReceiptV1> {
    let canonical_bytes: Vec<u8> = row.try_get("canonical_record")?;
    let receipt: TrustedHostFenceRecoveryCommitReceiptV1 =
        decode(&canonical_bytes, "Host-fence recovery receipt")?;
    if canonical(&receipt, "Host-fence recovery receipt")? != canonical_bytes
        || !jsonb_matches_canonical(row.try_get("record_json")?, &canonical_bytes)?
    {
        return Err(corrupt("Host-fence recovery receipt is not canonical"));
    }
    let request = receipt.commit.as_ref();
    if validate_recovery_shape(request)? != receipt.request_sha256
        || receipt.committed_at_unix_ms != request.terminal_event.committed_at_unix_ms
        || row.try_get::<_, String>("event_id")? != request.terminal_event.event_id.as_str()
        || row.try_get::<_, String>("event_state")? != "terminal_v1"
        || row.try_get::<_, String>("request_sha256")? != receipt.request_sha256.as_str()
        || row.try_get::<_, String>("old_node_id")? != request.expected_old_node_id.as_str()
        || row.try_get::<_, String>("old_node_boot_id")?
            != request.expected_old_node_boot_id.as_str()
        || row.try_get::<_, i64>("old_agent_session_epoch")?
            != pg(
                request.expected_old_agent_session_epoch.get(),
                "old session epoch",
            )?
        || row.try_get::<_, String>("cat_id")? != request.expected_current_desired.cat_id.as_str()
        || row.try_get::<_, i64>("expected_desired_revision")?
            != pg(
                request.expected_current_desired.desired_revision.get(),
                "expected Desired revision",
            )?
        || row.try_get::<_, i64>("replacement_desired_revision")?
            != pg(
                request.replacement_desired.desired_revision.get(),
                "replacement Desired revision",
            )?
        || row.try_get::<_, String>("old_operation_id")?
            != request.expected_old_operation.operation_id.as_str()
        || row.try_get::<_, String>("recovery_operation_id")?
            != request.recovery_operation.operation_id.as_str()
        || row.try_get::<_, i64>("committed_at")?
            != pg(receipt.committed_at_unix_ms.get(), "receipt commit time")?
    {
        return Err(corrupt(
            "Host-fence recovery receipt scalar projection mismatch",
        ));
    }
    Ok(receipt)
}

fn load_receipt_for_update(
    transaction: &mut Transaction<'_>,
    event_id: &Id,
) -> AuthorityTxResult<Option<TrustedHostFenceRecoveryCommitReceiptV1>> {
    transaction
        .query_opt(
            "SELECT event_id, event_state, record::text AS record_json,
                    canonical_record, request_sha256, old_node_id,
                    old_node_boot_id, old_agent_session_epoch, cat_id,
                    expected_desired_revision, replacement_desired_revision,
                    old_operation_id, recovery_operation_id, committed_at
               FROM trusted_host_fence_recovery_commits_v1
              WHERE event_id=$1 FOR UPDATE",
            &[&event_id.as_str()],
        )?
        .map(|row| decode_receipt_row(&row))
        .transpose()
}

fn exact_replay(
    transaction: &mut Transaction<'_>,
    request: &TrustedHostFenceRecoveryCommitV1,
    digest: &Sha256Digest,
) -> AuthorityTxResult<Option<TrustedHostFenceRecoveryCommitReceiptV1>> {
    let Some(event) =
        load_terminal_event_for_update(transaction, &request.terminal_event.event_id)?
    else {
        return Ok(None);
    };
    let Some(receipt) = load_receipt_for_update(transaction, &event.event_id)? else {
        return Err(corrupt(
            "terminal Host-fence event has no atomic recovery commit receipt",
        ));
    };
    if event != request.terminal_event
        || receipt.request_sha256 != *digest
        || receipt.commit.as_ref() != request
    {
        return Err(conflict(
            "Host-fence event replay changed its evidence or recovery binding",
        ));
    }
    Ok(Some(receipt))
}

fn lock_fresh_preconditions(
    transaction: &mut Transaction<'_>,
    request: &TrustedHostFenceRecoveryCommitV1,
    old_identity: &NodeIdentity,
    new_identity: &NodeIdentity,
) -> AuthorityTxResult<AgentSession> {
    if old_identity.state != NodeIdentityState::Provisioned
        || new_identity.state != NodeIdentityState::Provisioned
    {
        return Err(conflict(
            "Host recovery requires two provisioned Node identities",
        ));
    }
    let session = load_current_session_for_update(transaction, &request.expected_old_node_id)?
        .ok_or_else(|| conflict("fenced Node has no exact current Agent session row"))?;
    if session.immutable_host_id != request.terminal_event.binding.immutable_host_id
        || session.node_boot_id != request.expected_old_node_boot_id
        || session.agent_session_epoch != request.expected_old_agent_session_epoch
    {
        return Err(conflict(
            "fenced Node current boot/session no longer matches provider evidence",
        ));
    }

    let terminal = &request.terminal_event;
    let scope = &terminal.binding.provider_scope;
    let event_rows = transaction.query(
        "SELECT event_id FROM host_fence_events
          WHERE provider=$1 AND host_partition=$2 AND host_account_id=$3
            AND host_region=$4 AND immutable_host_id=$5 AND node_id=$6
            AND expected_node_boot_id=$7 AND expected_agent_session_epoch=$8
            AND state='terminal_v1'
          ORDER BY event_id COLLATE \"C\" LIMIT 2 FOR UPDATE",
        &[
            &scope.provider.as_str(),
            &scope.partition.as_str(),
            &scope.account_id.as_str(),
            &scope.region.as_str(),
            &terminal.binding.immutable_host_id.as_str(),
            &terminal.binding.node_id.as_str(),
            &terminal.binding.expected_node_boot_id.as_str(),
            &pg(
                terminal.binding.expected_agent_session_epoch.get(),
                "event session epoch",
            )?,
        ],
    )?;
    if !event_rows.is_empty() {
        return Err(conflict(
            "immutable Host binding already has another terminal fence event",
        ));
    }

    for candidate in &request.takeover_authorizations {
        let authorization = takeover_payload(&candidate.authorization)?;
        if transaction
            .query_opt(
                "SELECT authorization_id FROM volume_authorizations
                  WHERE authorization_id=$1 FOR UPDATE",
                &[&authorization.authorization_id.as_str()],
            )?
            .is_some()
        {
            return Err(conflict("takeover authorization ID already exists"));
        }
    }
    for candidate in &request.takeover_authorizations {
        let expected = &candidate.expected_current_volume;
        let stored = load_stored_volume_for_update(transaction, &expected.volume_id)?
            .ok_or_else(|| conflict("recovery Volume is absent"))?;
        let expected_owner = VolumeOwnerBinding {
            volume_id: expected.volume_id.clone(),
            owner_node_id: request.expected_old_node_id.clone(),
            attachment_id: expected
                .lease_owner
                .clone()
                .ok_or_else(|| rejected("recovery expected Volume has no old writer"))?,
            attachment_epoch: expected.lease_epoch,
        };
        if stored.record != *expected || stored.owner_binding.as_ref() != Some(&expected_owner) {
            return Err(conflict(
                "recovery Volume Node owner, attachment, epoch, head or immutable shape changed",
            ));
        }
    }

    let expected = &request.expected_current_desired;
    let assigned = load_assigned_desired_for_update(transaction, &request.expected_old_node_id)?;
    if assigned.len() != 1 || assigned.first() != Some(expected) {
        return Err(conflict(
            "single-Cat Host recovery cannot cover the exact assigned set",
        ));
    }
    let cat = load_cat_by_id_for_update(transaction, &expected.cat_id)?
        .ok_or_else(|| corrupt("recovery Desired has no immutable Cat row"))?;
    if cat.workspace_id != expected.workspace_id {
        return Err(corrupt("recovery Cat belongs to another Workspace"));
    }
    let stored_desired = load_desired_for_update(transaction, &expected.cat_id)?
        .ok_or_else(|| conflict("recovery current Desired is absent"))?;
    if stored_desired != *expected {
        return Err(conflict(
            "recovery current Desired revision or body changed",
        ));
    }

    let pending = load_pending_operation_by_cat_for_update(transaction, &expected.cat_id)?
        .ok_or_else(|| conflict("recovery old Pending Operation is absent"))?;
    if pending != request.expected_old_operation {
        return Err(conflict("recovery old Operation identity or state changed"));
    }
    if load_operation_for_update(transaction, &request.recovery_operation.operation_id)?.is_some() {
        return Err(conflict("recovery Operation ID already exists"));
    }

    let hostnames = transaction.query(
        "SELECT hostname FROM hostname_desired_lookups
          WHERE cat_id=$1 ORDER BY hostname COLLATE \"C\" FOR UPDATE",
        &[&expected.cat_id.as_str()],
    )?;
    let stored_hostnames = hostnames
        .iter()
        .map(|row| row.try_get::<_, String>("hostname"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_hostnames = expected
        .endpoints
        .iter()
        .map(|endpoint| endpoint.hostname.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if stored_hostnames != expected_hostnames {
        return Err(corrupt("recovery Desired hostname lookup set changed"));
    }

    if transaction
        .query_opt(
            "SELECT event_id FROM trusted_host_fence_recovery_commits_v1
              WHERE cat_id=$1 AND expected_desired_revision=$2 FOR UPDATE",
            &[
                &expected.cat_id.as_str(),
                &pg(expected.desired_revision.get(), "expected Desired revision")?,
            ],
        )?
        .is_some()
    {
        return Err(conflict(
            "recovery source revision already has another fence commit",
        ));
    }
    Ok(session)
}

pub(super) fn retire_source_node(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
    session: &AgentSession,
    retired_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let removed = transaction.execute(
        "DELETE FROM current_agent_sessions
          WHERE node_id=$1 AND immutable_host_id=$2 AND node_boot_id=$3
            AND agent_instance_id=$4 AND agent_session_epoch=$5
            AND registration_attempt_id=$6 AND guest_config_digest=$7
            AND lease_deadline_unix_ms=$8",
        &[
            &session.node_id.as_str(),
            &session.immutable_host_id.as_str(),
            &session.node_boot_id.as_str(),
            &session.agent_instance_id.as_str(),
            &pg(session.agent_session_epoch.get(), "source session epoch")?,
            &session.registration_attempt_id.as_str(),
            &session.guest_config_digest.as_str(),
            &pg(
                session.lease_deadline_unix_ms.get(),
                "source session deadline",
            )?,
        ],
    )?;
    if removed != 1 {
        return Err(corrupt(
            "locked source AgentSession changed before terminal retirement",
        ));
    }
    let retired = retire_node_identity_in(transaction, identity, retired_at)?;
    if retired.state != NodeIdentityState::Retired {
        return Err(corrupt("source NodeIdentity did not become retired"));
    }
    Ok(())
}

pub(super) fn insert_terminal_event(
    transaction: &mut Transaction<'_>,
    event: &TrustedHostFenceEventV1,
) -> AuthorityTxResult<()> {
    let canonical = encode_trusted_host_fence_event_v1(event)
        .map_err(|error| corrupt(format!("encode terminal Host-fence event: {error}")))?;
    let json = String::from_utf8(canonical.clone())
        .map_err(|_| corrupt("terminal Host-fence event JSON is not UTF-8"))?;
    let binding = &event.binding;
    let inserted = transaction.execute(
        "INSERT INTO host_fence_events (
            event_id, record, canonical_record, provider, host_partition,
            host_account_id, host_region, immutable_host_id, node_id,
            expected_node_boot_id, expected_agent_session_epoch,
            fence_attempt_id, isolation_state, observed_at, state,
            destroyed_at, provider_evidence_sha256, committed_at
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, 'trusted_provider_evidence_v1', $13, 'terminal_v1', NULL,
            $14, $15
         )",
        &[
            &event.event_id.as_str(),
            &json,
            &canonical,
            &binding.provider_scope.provider.as_str(),
            &binding.provider_scope.partition.as_str(),
            &binding.provider_scope.account_id.as_str(),
            &binding.provider_scope.region.as_str(),
            &binding.immutable_host_id.as_str(),
            &binding.node_id.as_str(),
            &binding.expected_node_boot_id.as_str(),
            &pg(binding.expected_agent_session_epoch.get(), "session epoch")?,
            &binding.fence_attempt_id.as_str(),
            &pg(
                event.provider_evidence.completed_at_unix_ms.get(),
                "provider evidence time",
            )?,
            &event.provider_evidence_sha256.as_str(),
            &pg(event.committed_at_unix_ms.get(), "event commit time")?,
        ],
    )?;
    if inserted != 1 {
        return Err(corrupt("terminal Host-fence event insert affected no row"));
    }
    Ok(())
}

fn head_projection(head: &RemoteHead) -> AuthorityTxResult<(i64, Option<String>, Option<String>)> {
    Ok((
        pg(head.generation.get(), "expected head generation")?,
        head.root_hash.as_ref().map(ToString::to_string),
        head.root_object_id.as_ref().map(ToString::to_string),
    ))
}

pub(super) fn insert_takeover_authorization(
    transaction: &mut Transaction<'_>,
    record: &AuthorizationRecord,
) -> AuthorityTxResult<()> {
    let authorization = takeover_payload(record)?;
    let record_json = String::from_utf8(canonical(record, "takeover authorization")?)
        .map_err(|_| corrupt("takeover authorization JSON is not UTF-8"))?;
    let (generation, root_hash, root_object_id) = head_projection(&authorization.expected_head)?;
    let inserted = transaction.execute(
        "INSERT INTO volume_authorizations (
            authorization_id, record, kind, authorized_node_id,
            host_fence_event_id, volume_id, state, desired_revision,
            placement_epoch, lease_duration_ms, expected_head_generation,
            expected_head_root_hash, expected_head_root_object_id,
            not_after, consumed_at
         ) VALUES (
            $1, $2::TEXT::jsonb, 'takeover', $3, $4, $5, 'unconsumed',
            $6, $7, $8, $9, $10, $11, $12, NULL
         )",
        &[
            &authorization.authorization_id.as_str(),
            &record_json,
            &authorization.authorized_node_id.as_str(),
            &authorization.host_fence_event_id.as_str(),
            &authorization.volume_id.as_str(),
            &pg(
                authorization.desired_revision.get(),
                "authorization Desired revision",
            )?,
            &pg(
                authorization.new_placement_epoch.get(),
                "authorization placement epoch",
            )?,
            &pg(
                authorization.lease_duration_ms,
                "authorization lease duration",
            )?,
            &generation,
            &root_hash,
            &root_object_id,
            &pg(authorization.not_after.get(), "authorization deadline")?,
        ],
    )?;
    if inserted != 1 {
        return Err(corrupt("takeover authorization insert affected no row"));
    }
    Ok(())
}

pub(super) fn replace_desired(
    transaction: &mut Transaction<'_>,
    expected: &DesiredRuntimeSpec,
    replacement: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    let canonical = encode_desired_runtime_spec(replacement)
        .map_err(|error| corrupt(format!("encode replacement Desired: {error}")))?;
    let json = String::from_utf8(canonical)
        .map_err(|_| corrupt("replacement Desired JSON is not UTF-8"))?;
    let changed = transaction.execute(
        "UPDATE desired_runtime_specs SET
            record=$2::TEXT::jsonb, workspace_id=$3, desired_revision=$4,
            spec_digest=$5, target=$6, node_id=$7, placement_epoch=$8
          WHERE cat_id=$1 AND workspace_id=$9 AND desired_revision=$10
            AND spec_digest=$11 AND node_id=$12 AND placement_epoch=$13",
        &[
            &replacement.cat_id.as_str(),
            &json,
            &replacement.workspace_id.as_str(),
            &pg(
                replacement.desired_revision.get(),
                "replacement Desired revision",
            )?,
            &replacement.spec_digest.as_str(),
            &match replacement.target {
                cats_api::runtime_reconciliation::RuntimeTarget::Running => "running",
                cats_api::runtime_reconciliation::RuntimeTarget::Suspended => "suspended",
                cats_api::runtime_reconciliation::RuntimeTarget::Warm => "warm",
                cats_api::runtime_reconciliation::RuntimeTarget::Cold => "cold",
                cats_api::runtime_reconciliation::RuntimeTarget::Deleted => "deleted",
            },
            &replacement.placement.node_id.as_str(),
            &pg(
                replacement.placement.placement_epoch.get(),
                "replacement placement epoch",
            )?,
            &expected.workspace_id.as_str(),
            &pg(expected.desired_revision.get(), "expected Desired revision")?,
            &expected.spec_digest.as_str(),
            &expected.placement.node_id.as_str(),
            &pg(
                expected.placement.placement_epoch.get(),
                "expected placement epoch",
            )?,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("locked recovery Desired lost its exact scalar CAS"));
    }
    Ok(())
}

pub(super) fn update_hostname_lookups(
    transaction: &mut Transaction<'_>,
    expected: &DesiredRuntimeSpec,
    replacement: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    for endpoint in &expected.endpoints {
        let lookup = HostnameDesiredLookup {
            hostname: endpoint.hostname.clone(),
            workspace_id: expected.workspace_id.clone(),
            cat_id: expected.cat_id.clone(),
            endpoint_id: endpoint.endpoint_id.clone(),
            desired_revision: replacement.desired_revision,
        };
        let record = String::from_utf8(canonical(&lookup, "hostname Desired lookup")?)
            .map_err(|_| corrupt("hostname Desired lookup JSON is not UTF-8"))?;
        let changed = transaction.execute(
            "UPDATE hostname_desired_lookups
                SET record=$2::TEXT::jsonb, desired_revision=$3
              WHERE hostname=$1 AND workspace_id=$4 AND cat_id=$5
                AND endpoint_id=$6 AND desired_revision=$7",
            &[
                &endpoint.hostname.as_str(),
                &record,
                &pg(
                    replacement.desired_revision.get(),
                    "replacement Desired revision",
                )?,
                &expected.workspace_id.as_str(),
                &expected.cat_id.as_str(),
                &endpoint.endpoint_id.as_str(),
                &pg(expected.desired_revision.get(), "expected Desired revision")?,
            ],
        )?;
        if changed != 1 {
            return Err(corrupt(
                "locked hostname Desired lookup changed before recovery",
            ));
        }
    }
    Ok(())
}

fn insert_receipt(
    transaction: &mut Transaction<'_>,
    receipt: &TrustedHostFenceRecoveryCommitReceiptV1,
) -> AuthorityTxResult<()> {
    let request = receipt.commit.as_ref();
    let canonical = canonical(receipt, "Host-fence recovery receipt")?;
    let json = String::from_utf8(canonical.clone())
        .map_err(|_| corrupt("Host-fence recovery receipt JSON is not UTF-8"))?;
    let inserted = transaction.execute(
        "INSERT INTO trusted_host_fence_recovery_commits_v1 (
            event_id, event_state, record, canonical_record, request_sha256,
            old_node_id, old_node_boot_id, old_agent_session_epoch, cat_id,
            expected_desired_revision, replacement_desired_revision,
            old_operation_id, recovery_operation_id, committed_at
         ) VALUES (
            $1, 'terminal_v1', $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13
         )",
        &[
            &request.terminal_event.event_id.as_str(),
            &json,
            &canonical,
            &receipt.request_sha256.as_str(),
            &request.expected_old_node_id.as_str(),
            &request.expected_old_node_boot_id.as_str(),
            &pg(
                request.expected_old_agent_session_epoch.get(),
                "old session epoch",
            )?,
            &request.expected_current_desired.cat_id.as_str(),
            &pg(
                request.expected_current_desired.desired_revision.get(),
                "expected Desired revision",
            )?,
            &pg(
                request.replacement_desired.desired_revision.get(),
                "replacement Desired revision",
            )?,
            &request.expected_old_operation.operation_id.as_str(),
            &request.recovery_operation.operation_id.as_str(),
            &pg(receipt.committed_at_unix_ms.get(), "receipt commit time")?,
        ],
    )?;
    if inserted != 1 {
        return Err(corrupt(
            "Host-fence recovery receipt insert affected no row",
        ));
    }
    Ok(())
}

fn commit_in(
    transaction: &mut Transaction<'_>,
    request: &TrustedHostFenceRecoveryCommitV1,
    digest: &Sha256Digest,
) -> AuthorityTxResult<TrustedHostFenceRecoveryCommitReceiptV1> {
    let (old_identity, new_identity) = lock_node_identities(transaction, request)?;
    if let Some(receipt) = exact_replay(transaction, request, digest)? {
        return Ok(receipt);
    }
    let old_session = lock_fresh_preconditions(transaction, request, &old_identity, &new_identity)?;
    let now = database_now(transaction)?;
    if request.terminal_event.committed_at_unix_ms > now {
        return Err(rejected("terminal Host-fence commit time is in the future"));
    }
    for candidate in &request.takeover_authorizations {
        if takeover_payload(&candidate.authorization)?.not_after <= now {
            return Err(rejected(
                "recovery takeover authorization is already expired at commit",
            ));
        }
    }

    insert_terminal_event(transaction, &request.terminal_event)?;
    for authorization in &request.takeover_authorizations {
        insert_takeover_authorization(transaction, &authorization.authorization)?;
    }
    replace_desired(
        transaction,
        &request.expected_current_desired,
        &request.replacement_desired,
    )?;
    update_hostname_lookups(
        transaction,
        &request.expected_current_desired,
        &request.replacement_desired,
    )?;
    update_operation(transaction, &request.settled_old_operation)?;
    insert_operation(transaction, &request.recovery_operation)?;
    retire_source_node(transaction, &old_identity, &old_session, now)?;
    let receipt = TrustedHostFenceRecoveryCommitReceiptV1 {
        request_sha256: digest.clone(),
        commit: Box::new(request.clone()),
        committed_at_unix_ms: request.terminal_event.committed_at_unix_ms,
    };
    insert_receipt(transaction, &receipt)?;
    Ok(receipt)
}

impl Store {
    pub fn commit_trusted_host_fence_recovery_v1(
        &self,
        request: &TrustedHostFenceRecoveryCommitV1,
    ) -> crate::store::Result<TrustedHostFenceRecoveryCommitReceiptV1> {
        self.authority_transaction(|transaction| {
            let digest = validate_recovery_shape(request)?;
            commit_in(transaction, request, &digest)
        })
    }
}

//! Shared PostgreSQL writers for trusted Host-fence batch recovery.
//!
//! The provider proof has already crossed the compute, workload-network and
//! object-write terminal/visibility barriers. The Host-scoped attempt and
//! complete assigned-set transaction own validation and atomic composition;
//! this module contains only their narrow event, takeover, Desired, and source
//! retirement row writers. No singular recovery Store entrypoint or legacy
//! Active/Rejoined event exists in the v16 production surface.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AgentSession, AuthorizationRecord, AuthorizationState,
    DesiredRuntimeSpec, Id, NodeIdentity, NodeIdentityState, RemoteHead, UnixMillis,
    VolumeAuthorization,
};
use cats_storage::trusted_host_fence::{
    decode_trusted_host_fence_event_v1, encode_trusted_host_fence_event_v1, TrustedHostFenceEventV1,
};
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use super::product::HostnameDesiredLookup;
use crate::store::agent_sessions::retire_node_identity_in;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

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

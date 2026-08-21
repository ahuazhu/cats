//! Closed authority rows and their checked PostgreSQL projections.

use cats_api::runtime_lifecycle::{
    decode_lifecycle_command_envelope, DiskRole as LifecycleDiskRole, LifecycleCommand,
    LifecycleCommandEnvelope, LifecycleCommandKind, RequestedVolumeDisposition,
    RuntimeVolumeAuthorityInput,
};
use cats_api::runtime_lifecycle_volume::{
    LifecycleCommandStartVolumeGrantReceipt, LifecycleStartVolumeGrantAuthority,
};
use cats_api::runtime_reconciliation::{
    Epoch, FenceEpoch, Generation, Id, Sha256Digest, UnixMillis, WireU64,
};
use cats_storage::authority::{
    project_volume_record, validate_authorization_record, validate_delete_completion_receipt,
    validate_host_fence_event, validate_volume_owner_binding, AuthorizationConsumedReceipt,
    AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt,
    DisposableDeleteIsolationBasis, HostFenceEvent, HostFenceEventState, HostIsolationState,
    RemoteHead, VolumeAuthorization, VolumeOwnerBinding, VolumeRecord, VolumeRecordProjection,
};
use cats_storage::lifecycle_volume::{
    decode_canonical_command_already_unowned_receipt,
    decode_canonical_command_delete_completion_receipt,
    decode_canonical_command_disposable_authorization_consumed_receipt,
    decode_canonical_command_normal_release_receipt,
    decode_canonical_command_start_volume_grant_receipt, CanonicalLifecycleVolumeReceipt,
    CommandAlreadyUnownedReceipt, CommandBoundDisposableRootAuthorization,
    CommandDeleteCompletionReceipt, CommandDisposableAuthorizationConsumedReceipt,
    CommandNormalReleaseReceipt, DeleteCommandVolumeSet, LifecycleVolumeCommandScope,
    LifecycleVolumeIdentity,
};
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use super::pg_codec::{LeaseDurationMs, PgBigInt, SizeBytes};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

pub(super) const VOLUME_COLUMNS: &str = "
    volume_id, record::text AS record_json, size_bytes, durability,
    admin_state, delete_id, head_generation, head_root_hash,
    head_root_object_id, lease_owner, lease_epoch, lease_expires_at,
    last_transition_kind, last_transition_id, transition_source_kind,
    transition_operation_id, transition_request_fingerprint,
    transition_placement_epoch, transition_lease_duration_ms,
    owner_binding::text AS owner_binding_json, owner_node_id";

pub(super) const EVENT_COLUMNS: &str = "
    event_id, record::text AS record_json, provider, immutable_host_id,
    node_id, expected_node_boot_id, expected_agent_session_epoch,
    fence_attempt_id, isolation_state, observed_at, state, destroyed_at";

pub(super) const AUTHORIZATION_COLUMNS: &str = "
    authorization_id, record::text AS record_json, kind, authorized_node_id,
    host_fence_event_id, volume_id, state, lifecycle_operation_id,
    lifecycle_request_fingerprint, placement_epoch, lease_duration_ms,
    delete_id, disk_id, cat_id, expected_attachment_id,
    expected_attachment_epoch, disposition, persistent_dispositions_digest,
    isolation_basis_kind, strong_stop_receipt_digest,
    strong_stop_agent_session_epoch, execution_absence_proof_digest,
    inventory_attestation_digest, interrupted_operation_id,
    host_lost_result_digest, expected_head_generation,
    expected_head_root_hash, expected_head_root_object_id, not_after, consumed_at";

pub(super) const DELETE_COMPLETION_COLUMNS: &str = "
    delete_id, record::text AS record_json, kind, disk_id, volume_id,
    authorization_id, prior_attachment_id, deleting_epoch,
    head_generation, head_root_hash, head_root_object_id, completed_at";

const LIFECYCLE_VOLUME_RECEIPT_COLUMNS: &str = "
    operation_id, request_fingerprint, workspace_id, cat_id, node_id,
    placement_epoch, runtime_config_id, runtime_config_sha256,
    source_command_kind, delete_id, disk_id, volume_id, disk_role,
    receipt_kind, receipt_sequence, canonical_receipt_bytes, receipt_digest,
    created_at_unix_ms";

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeadProjection {
    generation: Generation,
    root_hash: Option<String>,
    root_object_id: Option<String>,
}

impl HeadProjection {
    fn from_head(head: &RemoteHead) -> Self {
        Self {
            generation: head.generation,
            root_hash: head.root_hash.as_ref().map(ToString::to_string),
            root_object_id: head.root_object_id.as_ref().map(ToString::to_string),
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            generation: from_pg(row.try_get("head_generation")?)?,
            root_hash: row.try_get("head_root_hash")?,
            root_object_id: row.try_get("head_root_object_id")?,
        })
    }
}

fn volume_projection_from_row(row: &Row) -> AuthorityTxResult<VolumeRecordProjection> {
    let durability = static_value(row.try_get("durability")?, &["strict", "relaxed"])?;
    let admin_state = static_value(row.try_get("admin_state")?, &["active", "deleting"])?;
    let last_transition_kind = match row.try_get::<_, Option<String>>("last_transition_kind")? {
        None => None,
        Some(value) => Some(static_value(
            value,
            &[
                "normal_acquire",
                "release",
                "takeover",
                "begin_delete",
                "begin_disposable_delete",
            ],
        )?),
    };
    let size_bytes: SizeBytes = from_pg(row.try_get("size_bytes")?)?;
    let transition_duration: Option<LeaseDurationMs> =
        optional_from_pg(row.try_get("transition_lease_duration_ms")?)?;
    Ok(VolumeRecordProjection {
        volume_id: row.try_get("volume_id")?,
        size_bytes: size_bytes.get(),
        durability,
        admin_state,
        delete_id: row.try_get("delete_id")?,
        head_generation: from_pg(row.try_get("head_generation")?)?,
        head_root_hash: row.try_get("head_root_hash")?,
        head_root_object_id: row.try_get("head_root_object_id")?,
        lease_owner: row.try_get("lease_owner")?,
        lease_epoch: from_pg(row.try_get("lease_epoch")?)?,
        lease_expires_at: optional_from_pg(row.try_get("lease_expires_at")?)?,
        last_transition_kind,
        last_transition_id: row.try_get("last_transition_id")?,
        transition_source_kind: row
            .try_get::<_, Option<String>>("transition_source_kind")?
            .map(|value| static_value(value, &["independent", "lifecycle"]))
            .transpose()?,
        transition_operation_id: row.try_get("transition_operation_id")?,
        transition_request_fingerprint: row.try_get("transition_request_fingerprint")?,
        transition_placement_epoch: optional_from_pg(row.try_get("transition_placement_epoch")?)?,
        transition_lease_duration_ms: transition_duration.map(PgBigInt::get),
    })
}

pub(super) fn load_volume_for_update(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> AuthorityTxResult<Option<VolumeRecord>> {
    let sql = format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE volume_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&volume_id.as_str()])?
        .map(|row| decode_volume(&row))
        .transpose()
}

/// Lock every row that could claim this Volume identity in either the scalar
/// projection or canonical JSON. A second match is stored corruption rather
/// than a candidate collision.
pub(super) fn load_any_volume_by_id_for_update(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> AuthorityTxResult<Option<VolumeRecord>> {
    let sql = format!(
        "SELECT {VOLUME_COLUMNS} FROM volume_records
          WHERE volume_id=$1 OR record->>'volume_id'=$1
          ORDER BY volume_id
          LIMIT 2
          FOR UPDATE"
    );
    let rows = transaction.query(&sql, &[&volume_id.as_str()])?;
    let mut decoded = rows
        .iter()
        .map(decode_volume)
        .collect::<AuthorityTxResult<Vec<_>>>()?;
    if decoded.len() > 1 {
        return Err(corrupt(()));
    }
    Ok(decoded.pop())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredVolume {
    pub(super) record: VolumeRecord,
    pub(super) owner_binding: Option<VolumeOwnerBinding>,
}

pub(super) fn load_stored_volume_for_update(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredVolume>> {
    let sql = format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE volume_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&volume_id.as_str()])?
        .map(|row| decode_stored_volume(&row))
        .transpose()
}

#[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
pub(super) fn load_volume_unlocked(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> AuthorityTxResult<Option<VolumeRecord>> {
    let sql = format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE volume_id=$1");
    transaction
        .query_opt(&sql, &[&volume_id.as_str()])?
        .map(|row| decode_volume(&row))
        .transpose()
}

// F1 deliberately exposes row creation only as a transaction-local building
// block; the API/controller wiring that will call it is a later cutover slice.
#[allow(dead_code)]
pub(super) fn insert_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> AuthorityTxResult<()> {
    if record.lease_owner.is_some() {
        return Err(corrupt(
            "an inserted Volume owner requires an exact Node binding",
        ));
    }
    let projection = project_volume_record(record)?;
    let record_json = encode(record)?;
    let size_bytes = SizeBytes::new(projection.size_bytes)
        .map_err(corrupt)?
        .to_pg()
        .map_err(corrupt)?;
    let head_generation = projection.head_generation.to_pg().map_err(corrupt)?;
    let lease_epoch = projection.lease_epoch.to_pg().map_err(corrupt)?;
    let lease_expires_at = optional_to_pg(projection.lease_expires_at)?;
    let transition_placement = optional_to_pg(projection.transition_placement_epoch)?;
    let transition_duration = projection
        .transition_lease_duration_ms
        .map(LeaseDurationMs::new)
        .transpose()
        .map_err(corrupt)?;
    let transition_duration = optional_to_pg(transition_duration)?;
    transaction.execute(
        "INSERT INTO volume_records (
            volume_id, record, size_bytes, durability, admin_state, delete_id,
            head_generation, head_root_hash, head_root_object_id, lease_owner,
            lease_epoch, lease_expires_at, last_transition_kind,
            last_transition_id, transition_source_kind, transition_operation_id,
            transition_request_fingerprint,
            transition_placement_epoch, transition_lease_duration_ms
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18, $19
         )",
        &[
            &projection.volume_id,
            &record_json,
            &size_bytes,
            &projection.durability,
            &projection.admin_state,
            &projection.delete_id,
            &head_generation,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &projection.lease_owner,
            &lease_epoch,
            &lease_expires_at,
            &projection.last_transition_kind,
            &projection.last_transition_id,
            &projection.transition_source_kind,
            &projection.transition_operation_id,
            &projection.transition_request_fingerprint,
            &transition_placement,
            &transition_duration,
        ],
    )?;
    Ok(())
}

pub(super) fn update_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> AuthorityTxResult<()> {
    let projection = project_volume_record(record)?;
    let record_json = encode(record)?;
    let size_bytes = SizeBytes::new(projection.size_bytes)
        .map_err(corrupt)?
        .to_pg()
        .map_err(corrupt)?;
    let head_generation = projection.head_generation.to_pg().map_err(corrupt)?;
    let lease_epoch = projection.lease_epoch.to_pg().map_err(corrupt)?;
    let lease_expires_at = optional_to_pg(projection.lease_expires_at)?;
    let transition_placement = optional_to_pg(projection.transition_placement_epoch)?;
    let transition_duration = projection
        .transition_lease_duration_ms
        .map(LeaseDurationMs::new)
        .transpose()
        .map_err(corrupt)?;
    let transition_duration = optional_to_pg(transition_duration)?;
    let changed = transaction.execute(
        "UPDATE volume_records SET
            record=$2::TEXT::jsonb, size_bytes=$3, durability=$4, admin_state=$5,
            delete_id=$6, head_generation=$7, head_root_hash=$8,
            head_root_object_id=$9, lease_owner=$10, lease_epoch=$11,
            lease_expires_at=$12, last_transition_kind=$13,
            last_transition_id=$14, transition_source_kind=$15,
            transition_operation_id=$16, transition_request_fingerprint=$17,
            transition_placement_epoch=$18, transition_lease_duration_ms=$19
          WHERE volume_id=$1
            AND (
                ($10::TEXT IS NULL AND owner_binding IS NULL) OR
                ($10::TEXT IS NOT NULL
                    AND owner_binding->>'attachment_id'=$10::TEXT
                    AND (owner_binding->>'attachment_epoch')::BIGINT=$11)
            )",
        &[
            &projection.volume_id,
            &record_json,
            &size_bytes,
            &projection.durability,
            &projection.admin_state,
            &projection.delete_id,
            &head_generation,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &projection.lease_owner,
            &lease_epoch,
            &lease_expires_at,
            &projection.last_transition_kind,
            &projection.last_transition_id,
            &projection.transition_source_kind,
            &projection.transition_operation_id,
            &projection.transition_request_fingerprint,
            &transition_placement,
            &transition_duration,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn update_volume_owner(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
    owner_binding: Option<&VolumeOwnerBinding>,
) -> AuthorityTxResult<()> {
    match owner_binding {
        Some(binding) => validate_volume_owner_binding(binding, record)?,
        None if record.lease_owner.is_none() => {}
        None => return Err(corrupt("an owned Volume is missing its Node binding")),
    }
    let projection = project_volume_record(record)?;
    let record_json = encode(record)?;
    let owner_binding_json = owner_binding.map(encode).transpose()?;
    let owner_node_id = owner_binding.map(|binding| binding.owner_node_id.as_str());
    let size_bytes = SizeBytes::new(projection.size_bytes)
        .map_err(corrupt)?
        .to_pg()
        .map_err(corrupt)?;
    let head_generation = projection.head_generation.to_pg().map_err(corrupt)?;
    let lease_epoch = projection.lease_epoch.to_pg().map_err(corrupt)?;
    let lease_expires_at = optional_to_pg(projection.lease_expires_at)?;
    let transition_placement = optional_to_pg(projection.transition_placement_epoch)?;
    let transition_duration = projection
        .transition_lease_duration_ms
        .map(LeaseDurationMs::new)
        .transpose()
        .map_err(corrupt)?;
    let transition_duration = optional_to_pg(transition_duration)?;
    let changed = transaction.execute(
        "UPDATE volume_records SET
            record=$2::TEXT::jsonb, size_bytes=$3, durability=$4, admin_state=$5,
            delete_id=$6, head_generation=$7, head_root_hash=$8,
            head_root_object_id=$9, lease_owner=$10, lease_epoch=$11,
            lease_expires_at=$12, last_transition_kind=$13,
            last_transition_id=$14, transition_source_kind=$15,
            transition_operation_id=$16, transition_request_fingerprint=$17,
            transition_placement_epoch=$18, transition_lease_duration_ms=$19,
            owner_binding=$20::TEXT::jsonb, owner_node_id=$21
          WHERE volume_id=$1",
        &[
            &projection.volume_id,
            &record_json,
            &size_bytes,
            &projection.durability,
            &projection.admin_state,
            &projection.delete_id,
            &head_generation,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &projection.lease_owner,
            &lease_epoch,
            &lease_expires_at,
            &projection.last_transition_kind,
            &projection.last_transition_id,
            &projection.transition_source_kind,
            &projection.transition_operation_id,
            &projection.transition_request_fingerprint,
            &transition_placement,
            &transition_duration,
            &owner_binding_json,
            &owner_node_id,
        ],
    )?;
    exactly_one(changed)
}

fn decode_volume(row: &Row) -> AuthorityTxResult<VolumeRecord> {
    Ok(decode_stored_volume(row)?.record)
}

fn decode_stored_volume(row: &Row) -> AuthorityTxResult<StoredVolume> {
    let stored = volume_projection_from_row(row)?;
    let record: VolumeRecord = decode(row.try_get("record_json")?)?;
    let derived = project_volume_record(&record)?;
    if stored != derived {
        return Err(corrupt(()));
    }
    let owner_binding_json: Option<String> = row.try_get("owner_binding_json")?;
    let owner_node_id: Option<String> = row.try_get("owner_node_id")?;
    let owner_binding = owner_binding_json
        .map(decode::<VolumeOwnerBinding>)
        .transpose()?;
    match (&owner_binding, owner_node_id.as_deref()) {
        (None, None) if record.lease_owner.is_none() => {}
        (Some(binding), Some(projected_node_id))
            if binding.owner_node_id.as_str() == projected_node_id =>
        {
            validate_volume_owner_binding(binding, &record)?;
        }
        _ => return Err(corrupt("Volume owner binding projection is inconsistent")),
    }
    Ok(StoredVolume {
        record,
        owner_binding,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventProjection {
    event_id: String,
    provider: String,
    immutable_host_id: String,
    node_id: String,
    expected_node_boot_id: String,
    expected_agent_session_epoch: Epoch,
    fence_attempt_id: String,
    isolation_state: &'static str,
    observed_at: UnixMillis,
    state: &'static str,
    destroyed_at: Option<UnixMillis>,
}

impl EventProjection {
    fn from_record(event: &HostFenceEvent) -> AuthorityTxResult<Self> {
        validate_host_fence_event(event)?;
        let (isolation_state, destroyed_at) = match &event.isolation_state {
            HostIsolationState::Isolated => ("isolated", None),
            HostIsolationState::HostDestroyed { receipt } => {
                ("host_destroyed", Some(receipt.destroyed_at_unix_ms))
            }
        };
        Ok(Self {
            event_id: event.event_id.to_string(),
            provider: event.provider.to_string(),
            immutable_host_id: event.immutable_host_id.to_string(),
            node_id: event.node_id.to_string(),
            expected_node_boot_id: event.expected_node_boot_id.to_string(),
            expected_agent_session_epoch: event.expected_agent_session_epoch,
            fence_attempt_id: event.fence_attempt_id.to_string(),
            isolation_state,
            observed_at: event.observed_at,
            state: match event.state {
                HostFenceEventState::Active => "active",
            },
            destroyed_at,
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            event_id: row.try_get("event_id")?,
            provider: row.try_get("provider")?,
            immutable_host_id: row.try_get("immutable_host_id")?,
            node_id: row.try_get("node_id")?,
            expected_node_boot_id: row.try_get("expected_node_boot_id")?,
            expected_agent_session_epoch: from_pg(row.try_get("expected_agent_session_epoch")?)?,
            fence_attempt_id: row.try_get("fence_attempt_id")?,
            isolation_state: static_value(
                row.try_get("isolation_state")?,
                &["isolated", "host_destroyed"],
            )?,
            observed_at: from_pg(row.try_get("observed_at")?)?,
            state: static_value(row.try_get("state")?, &["active", "rejoined"])?,
            destroyed_at: optional_from_pg(row.try_get("destroyed_at")?)?,
        })
    }
}

pub(super) fn load_event_for_update(
    transaction: &mut Transaction<'_>,
    event_id: &Id,
) -> AuthorityTxResult<Option<HostFenceEvent>> {
    let sql = format!("SELECT {EVENT_COLUMNS} FROM host_fence_events WHERE event_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&event_id.as_str()])?
        .map(|row| decode_event(&row))
        .transpose()
}

/// Loads the at-most-one active fence for a Node after the caller has taken
/// the NodeIdentity serialization lock (mutation) or inside one repeatable-
/// read authority snapshot (planner). The partial unique index is a physical
/// backstop; checking the cardinality here also fails closed on a schema or
/// projection drift instead of choosing an arbitrary event.
pub(super) fn load_active_event_by_node_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<HostFenceEvent>> {
    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM host_fence_events
          WHERE (node_id=$1 OR record->>'node_id'=$1)
            AND (state='active' OR record->>'state'='active')
          ORDER BY event_id COLLATE \"C\" LIMIT 2"
    );
    let rows = transaction.query(&sql, &[&node_id.as_str()])?;
    if rows.len() > 1 {
        return Err(corrupt("multiple active HostFenceEvents for one Node"));
    }
    rows.first().map(decode_event).transpose()
}

// Event creation must compose with its caller's transaction; it must never
// grow a convenience Store method that commits independently.
#[allow(dead_code)]
pub(super) fn insert_event(
    transaction: &mut Transaction<'_>,
    event: &HostFenceEvent,
) -> AuthorityTxResult<()> {
    let projection = EventProjection::from_record(event)?;
    let record_json = encode(event)?;
    let expected_session = projection
        .expected_agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    let observed_at = projection.observed_at.to_pg().map_err(corrupt)?;
    let destroyed_at = optional_to_pg(projection.destroyed_at)?;
    transaction.execute(
        "INSERT INTO host_fence_events (
            event_id, record, provider, immutable_host_id, node_id,
            expected_node_boot_id, expected_agent_session_epoch,
            fence_attempt_id, isolation_state, observed_at, state, destroyed_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        &[
            &projection.event_id,
            &record_json,
            &projection.provider,
            &projection.immutable_host_id,
            &projection.node_id,
            &projection.expected_node_boot_id,
            &expected_session,
            &projection.fence_attempt_id,
            &projection.isolation_state,
            &observed_at,
            &projection.state,
            &destroyed_at,
        ],
    )?;
    Ok(())
}

fn decode_event(row: &Row) -> AuthorityTxResult<HostFenceEvent> {
    let stored = EventProjection::from_row(row)?;
    let event: HostFenceEvent = decode(row.try_get("record_json")?)?;
    let derived = EventProjection::from_record(&event)?;
    if stored != derived {
        return Err(corrupt(()));
    }
    Ok(event)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizationProjection {
    authorization_id: String,
    kind: &'static str,
    authorized_node_id: String,
    host_fence_event_id: Option<String>,
    volume_id: String,
    state: &'static str,
    lifecycle_operation_id: String,
    lifecycle_request_fingerprint: String,
    placement_epoch: Epoch,
    lease_duration_ms: Option<LeaseDurationMs>,
    delete_id: Option<String>,
    disk_id: String,
    cat_id: String,
    expected_attachment_id: String,
    expected_attachment_epoch: FenceEpoch,
    disposition: Option<&'static str>,
    persistent_dispositions_digest: Option<String>,
    isolation_basis_kind: Option<&'static str>,
    strong_stop_receipt_digest: Option<String>,
    strong_stop_agent_session_epoch: Option<Epoch>,
    execution_absence_proof_digest: Option<String>,
    inventory_attestation_digest: Option<String>,
    interrupted_operation_id: Option<String>,
    host_lost_result_digest: Option<String>,
    expected_head_generation: Generation,
    expected_head_root_hash: Option<String>,
    expected_head_root_object_id: Option<String>,
    not_after: UnixMillis,
    consumed_at: Option<UnixMillis>,
}

impl AuthorizationProjection {
    fn from_record(record: &AuthorizationRecord) -> AuthorityTxResult<Self> {
        validate_authorization_record(record)?;
        let (state, consumed_at) = match &record.state {
            AuthorizationState::Unconsumed => ("unconsumed", None),
            AuthorizationState::Consumed(receipt) => {
                let consumed_at = match receipt.as_ref() {
                    AuthorizationConsumedReceipt::Takeover(receipt) => receipt.consumed_at,
                    AuthorizationConsumedReceipt::BeginDisposableDelete(receipt) => {
                        receipt.consumed_at
                    }
                };
                ("consumed", Some(consumed_at))
            }
        };
        match &record.authorization {
            VolumeAuthorization::Takeover(authorization) => {
                let expected_head = HeadProjection::from_head(&authorization.expected_head);
                Ok(Self {
                    authorization_id: authorization.authorization_id.to_string(),
                    kind: "takeover",
                    authorized_node_id: authorization.authorized_node_id.to_string(),
                    host_fence_event_id: Some(authorization.host_fence_event_id.to_string()),
                    volume_id: authorization.volume_id.to_string(),
                    state,
                    lifecycle_operation_id: authorization.operation_id.to_string(),
                    lifecycle_request_fingerprint: authorization.request_fingerprint.to_string(),
                    placement_epoch: authorization.new_placement_epoch,
                    lease_duration_ms: Some(
                        LeaseDurationMs::new(authorization.lease_duration_ms).map_err(corrupt)?,
                    ),
                    delete_id: None,
                    disk_id: authorization.disk_id.to_string(),
                    cat_id: authorization.cat_id.to_string(),
                    expected_attachment_id: authorization.expected_attachment_id.to_string(),
                    expected_attachment_epoch: authorization.expected_epoch,
                    disposition: None,
                    persistent_dispositions_digest: None,
                    isolation_basis_kind: None,
                    strong_stop_receipt_digest: None,
                    strong_stop_agent_session_epoch: None,
                    execution_absence_proof_digest: None,
                    inventory_attestation_digest: None,
                    interrupted_operation_id: Some(
                        authorization.interrupted_operation_id.to_string(),
                    ),
                    host_lost_result_digest: Some(
                        authorization.host_lost_result_digest.to_string(),
                    ),
                    expected_head_generation: expected_head.generation,
                    expected_head_root_hash: expected_head.root_hash,
                    expected_head_root_object_id: expected_head.root_object_id,
                    not_after: authorization.not_after,
                    consumed_at,
                })
            }
            VolumeAuthorization::DisposableRootDelete(authorization) => {
                let expected_head = HeadProjection::from_head(&authorization.expected_head);
                let (
                    host_fence_event_id,
                    isolation_basis_kind,
                    strong_stop_receipt_digest,
                    strong_stop_agent_session_epoch,
                    execution_absence_proof_digest,
                    inventory_attestation_digest,
                    interrupted_operation_id,
                    host_lost_result_digest,
                ) = match &authorization.isolation_basis {
                    DisposableDeleteIsolationBasis::LifecycleStrongStop {
                        agent_session_epoch,
                        strong_stop_receipt_digest,
                        execution_absence_proof_digest,
                        inventory_attestation_digest,
                        ..
                    } => (
                        None,
                        Some("lifecycle_strong_stop"),
                        Some(strong_stop_receipt_digest.to_string()),
                        Some(*agent_session_epoch),
                        Some(execution_absence_proof_digest.to_string()),
                        Some(inventory_attestation_digest.to_string()),
                        None,
                        None,
                    ),
                    DisposableDeleteIsolationBasis::HostFenceEvent {
                        event_id,
                        interrupted_operation_id,
                        host_lost_result_digest,
                    } => (
                        Some(event_id.to_string()),
                        Some("host_fence_event"),
                        None,
                        None,
                        None,
                        None,
                        Some(interrupted_operation_id.to_string()),
                        Some(host_lost_result_digest.to_string()),
                    ),
                };
                Ok(Self {
                    authorization_id: authorization.authorization_id.to_string(),
                    kind: "disposable_root_delete",
                    authorized_node_id: authorization.authorized_node_id.to_string(),
                    host_fence_event_id,
                    volume_id: authorization.volume_id.to_string(),
                    state,
                    lifecycle_operation_id: authorization.operation_id.to_string(),
                    lifecycle_request_fingerprint: authorization.request_fingerprint.to_string(),
                    placement_epoch: authorization.placement_epoch,
                    lease_duration_ms: None,
                    delete_id: Some(authorization.delete_id.to_string()),
                    disk_id: authorization.disk_id.to_string(),
                    cat_id: authorization.cat_id.to_string(),
                    expected_attachment_id: authorization.expected_attachment_id.to_string(),
                    expected_attachment_epoch: authorization.expected_epoch,
                    disposition: Some("discard_with_cat"),
                    persistent_dispositions_digest: Some(
                        authorization.persistent_dispositions_digest.to_string(),
                    ),
                    isolation_basis_kind,
                    strong_stop_receipt_digest,
                    strong_stop_agent_session_epoch,
                    execution_absence_proof_digest,
                    inventory_attestation_digest,
                    interrupted_operation_id,
                    host_lost_result_digest,
                    expected_head_generation: expected_head.generation,
                    expected_head_root_hash: expected_head.root_hash,
                    expected_head_root_object_id: expected_head.root_object_id,
                    not_after: authorization.not_after,
                    consumed_at,
                })
            }
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            authorization_id: row.try_get("authorization_id")?,
            kind: static_value(
                row.try_get("kind")?,
                &["takeover", "disposable_root_delete"],
            )?,
            authorized_node_id: row.try_get("authorized_node_id")?,
            host_fence_event_id: row.try_get("host_fence_event_id")?,
            volume_id: row.try_get("volume_id")?,
            state: static_value(row.try_get("state")?, &["unconsumed", "consumed"])?,
            lifecycle_operation_id: row.try_get("lifecycle_operation_id")?,
            lifecycle_request_fingerprint: row.try_get("lifecycle_request_fingerprint")?,
            placement_epoch: from_pg(row.try_get("placement_epoch")?)?,
            lease_duration_ms: optional_from_pg(row.try_get("lease_duration_ms")?)?,
            delete_id: row.try_get("delete_id")?,
            disk_id: row.try_get("disk_id")?,
            cat_id: row.try_get("cat_id")?,
            expected_attachment_id: row.try_get("expected_attachment_id")?,
            expected_attachment_epoch: from_pg(row.try_get("expected_attachment_epoch")?)?,
            disposition: row
                .try_get::<_, Option<String>>("disposition")?
                .map(|value| static_value(value, &["discard_with_cat"]))
                .transpose()?,
            persistent_dispositions_digest: row.try_get("persistent_dispositions_digest")?,
            isolation_basis_kind: row
                .try_get::<_, Option<String>>("isolation_basis_kind")?
                .map(|value| static_value(value, &["lifecycle_strong_stop", "host_fence_event"]))
                .transpose()?,
            strong_stop_receipt_digest: row.try_get("strong_stop_receipt_digest")?,
            strong_stop_agent_session_epoch: optional_from_pg(
                row.try_get("strong_stop_agent_session_epoch")?,
            )?,
            execution_absence_proof_digest: row.try_get("execution_absence_proof_digest")?,
            inventory_attestation_digest: row.try_get("inventory_attestation_digest")?,
            interrupted_operation_id: row.try_get("interrupted_operation_id")?,
            host_lost_result_digest: row.try_get("host_lost_result_digest")?,
            expected_head_generation: from_pg(row.try_get("expected_head_generation")?)?,
            expected_head_root_hash: row.try_get("expected_head_root_hash")?,
            expected_head_root_object_id: row.try_get("expected_head_root_object_id")?,
            not_after: from_pg(row.try_get("not_after")?)?,
            consumed_at: optional_from_pg(row.try_get("consumed_at")?)?,
        })
    }
}

pub(super) fn load_authorization_for_update(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
) -> AuthorityTxResult<Option<AuthorizationRecord>> {
    let sql = format!(
        "SELECT {AUTHORIZATION_COLUMNS} FROM volume_authorizations
          WHERE authorization_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&authorization_id.as_str()])?
        .map(|row| decode_authorization(&row))
        .transpose()
}

pub(super) fn delete_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> AuthorityTxResult<()> {
    let projection = project_volume_record(record)?;
    let changed = transaction.execute(
        "DELETE FROM volume_records
          WHERE volume_id=$1 AND admin_state='deleting' AND delete_id=$2
            AND lease_epoch=$3 AND head_generation=$4
            AND head_root_hash IS NOT DISTINCT FROM $5
            AND head_root_object_id IS NOT DISTINCT FROM $6",
        &[
            &projection.volume_id,
            &projection.delete_id,
            &projection.lease_epoch.to_pg().map_err(corrupt)?,
            &projection.head_generation.to_pg().map_err(corrupt)?,
            &projection.head_root_hash,
            &projection.head_root_object_id,
        ],
    )?;
    exactly_one(changed)
}

/// Loads the primary evidence row through the one non-enumerating access
/// predicate. A missing id and an id owned by another Node are intentionally
/// indistinguishable, and neither path decodes the protected JSON payload.
#[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
pub(super) fn load_authorization_for_evidence(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
    authorized_node_id: &Id,
) -> AuthorityTxResult<Option<AuthorizationRecord>> {
    let sql = format!(
        "SELECT {AUTHORIZATION_COLUMNS} FROM volume_authorizations
          WHERE authorization_id=$1 AND authorized_node_id=$2"
    );
    transaction
        .query_opt(
            &sql,
            &[&authorization_id.as_str(), &authorized_node_id.as_str()],
        )?
        .map(|row| decode_authorization(&row))
        .transpose()
}

#[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
pub(super) fn load_authorization_unlocked(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
) -> AuthorityTxResult<Option<AuthorizationRecord>> {
    let sql = format!(
        "WITH candidate_ids AS MATERIALIZED (
            (SELECT authorization_id FROM volume_authorizations
              WHERE authorization_id=$1 LIMIT 2)
            UNION
            (SELECT authorization_id FROM volume_authorizations
              WHERE record->'authorization' @> jsonb_build_object(
                        'authorization_id', $1::text
                    )
              LIMIT 2)
         )
         SELECT {AUTHORIZATION_COLUMNS} FROM volume_authorizations
          WHERE authorization_id IN (SELECT authorization_id FROM candidate_ids)
          ORDER BY authorization_id COLLATE \"C\" LIMIT 2"
    );
    let rows = transaction.query(&sql, &[&authorization_id.as_str()])?;
    if rows.len() > 1 {
        return Err(corrupt("duplicate canonical authorization id"));
    }
    rows.first().map(decode_authorization).transpose()
}

// Authorization creation is intentionally transaction-local so the event row
// remains its serialization point in the later workflow.
#[allow(dead_code)]
pub(super) fn insert_authorization(
    transaction: &mut Transaction<'_>,
    record: &AuthorizationRecord,
) -> AuthorityTxResult<()> {
    let projection = AuthorizationProjection::from_record(record)?;
    if !matches!(record.state, AuthorizationState::Unconsumed) {
        return Err(corrupt(()));
    }

    // Authorization creation shares the event row serial point. The helper
    // owns no transaction and therefore cannot accidentally commit an event
    // and its authorization independently.
    if let Some(event_id) = &projection.host_fence_event_id {
        let event_id = Id::new(event_id.clone()).ok_or_else(|| corrupt(()))?;
        let event = load_event_for_update(transaction, &event_id)?.ok_or_else(|| {
            AuthorityTransactionError::from(
                cats_storage::authority::AuthorityError::InvalidAuthorization,
            )
        })?;
        if event.state != HostFenceEventState::Active {
            return Err(cats_storage::authority::AuthorityError::InvalidAuthorization.into());
        }
    }

    let authorization_id =
        Id::new(projection.authorization_id.clone()).ok_or_else(|| corrupt(()))?;
    if let Some(existing) = load_authorization_for_update(transaction, &authorization_id)? {
        return if existing == *record {
            Ok(())
        } else {
            Err(cats_storage::authority::AuthorityError::InvalidAuthorization.into())
        };
    }

    let record_json = encode(record)?;
    let placement_epoch = projection.placement_epoch.to_pg().map_err(corrupt)?;
    let lease_duration_ms = optional_to_pg(projection.lease_duration_ms)?;
    let expected_attachment_epoch = projection
        .expected_attachment_epoch
        .to_pg()
        .map_err(corrupt)?;
    let strong_stop_agent_session_epoch =
        optional_to_pg(projection.strong_stop_agent_session_epoch)?;
    let expected_head_generation = projection
        .expected_head_generation
        .to_pg()
        .map_err(corrupt)?;
    let not_after = projection.not_after.to_pg().map_err(corrupt)?;
    let consumed_at = optional_to_pg(projection.consumed_at)?;
    let inserted = transaction.execute(
        "INSERT INTO volume_authorizations (
            authorization_id, record, kind, authorized_node_id,
            host_fence_event_id, volume_id,
            state, lifecycle_operation_id, lifecycle_request_fingerprint,
            placement_epoch, lease_duration_ms,
            delete_id, disk_id, cat_id, expected_attachment_id,
            expected_attachment_epoch, disposition,
            persistent_dispositions_digest, isolation_basis_kind,
            strong_stop_receipt_digest, strong_stop_agent_session_epoch,
            execution_absence_proof_digest, inventory_attestation_digest,
            interrupted_operation_id, host_lost_result_digest,
            expected_head_generation, expected_head_root_hash,
            expected_head_root_object_id, not_after, consumed_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10,
                   $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                   $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
         ON CONFLICT (authorization_id) DO NOTHING",
        &[
            &projection.authorization_id,
            &record_json,
            &projection.kind,
            &projection.authorized_node_id,
            &projection.host_fence_event_id,
            &projection.volume_id,
            &projection.state,
            &projection.lifecycle_operation_id,
            &projection.lifecycle_request_fingerprint,
            &placement_epoch,
            &lease_duration_ms,
            &projection.delete_id,
            &projection.disk_id,
            &projection.cat_id,
            &projection.expected_attachment_id,
            &expected_attachment_epoch,
            &projection.disposition,
            &projection.persistent_dispositions_digest,
            &projection.isolation_basis_kind,
            &projection.strong_stop_receipt_digest,
            &strong_stop_agent_session_epoch,
            &projection.execution_absence_proof_digest,
            &projection.inventory_attestation_digest,
            &projection.interrupted_operation_id,
            &projection.host_lost_result_digest,
            &expected_head_generation,
            &projection.expected_head_root_hash,
            &projection.expected_head_root_object_id,
            &not_after,
            &consumed_at,
        ],
    )?;
    if inserted == 1 {
        return Ok(());
    }
    match load_authorization_for_update(transaction, &authorization_id)? {
        Some(existing) if existing == *record => Ok(()),
        Some(_) => Err(cats_storage::authority::AuthorityError::InvalidAuthorization.into()),
        None => Err(corrupt(())),
    }
}

pub(super) fn update_authorization(
    transaction: &mut Transaction<'_>,
    original: &AuthorizationRecord,
    record: &AuthorizationRecord,
) -> AuthorityTxResult<()> {
    if original.authorization != record.authorization
        || !matches!(
            (&original.state, &record.state),
            (
                AuthorizationState::Unconsumed,
                AuthorizationState::Consumed(_)
            )
        )
    {
        return Err(corrupt(()));
    }
    let projection = AuthorizationProjection::from_record(record)?;
    let record_json = encode(record)?;
    let original_json = encode(original)?;
    let consumed_at = optional_to_pg(projection.consumed_at)?;
    let changed = transaction.execute(
        "UPDATE volume_authorizations SET
            record=$2::TEXT::jsonb, state=$3, consumed_at=$4
          WHERE authorization_id=$1 AND record=$5::TEXT::jsonb",
        &[
            &projection.authorization_id,
            &record_json,
            &projection.state,
            &consumed_at,
            &original_json,
        ],
    )?;
    exactly_one(changed)
}

fn decode_authorization(row: &Row) -> AuthorityTxResult<AuthorizationRecord> {
    let stored = AuthorizationProjection::from_row(row)?;
    let record: AuthorizationRecord = decode(row.try_get("record_json")?)?;
    // A domain-looking validation failure here describes persisted state, not
    // the caller's request. Collapse it to corruption so an invalid stored
    // authorization can never be reported as a retryable/request-side
    // rejection.
    let derived = AuthorizationProjection::from_record(&record).map_err(|_| corrupt(()))?;
    if stored != derived {
        return Err(corrupt(()));
    }
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeleteCompletionProjection {
    delete_id: String,
    kind: &'static str,
    disk_id: String,
    volume_id: String,
    authorization_id: Option<String>,
    prior_attachment_id: Option<String>,
    deleting_epoch: FenceEpoch,
    head: HeadProjection,
    completed_at: UnixMillis,
}

impl DeleteCompletionProjection {
    fn from_record(receipt: &DeleteCompletionReceipt) -> AuthorityTxResult<Self> {
        validate_delete_completion_receipt(receipt)?;
        Ok(match receipt {
            DeleteCompletionReceipt::Normal {
                request,
                deleting_epoch,
                deleting_head,
                completed_at,
            } => Self {
                delete_id: request.delete_id.to_string(),
                kind: "normal",
                disk_id: request.disk_id.to_string(),
                volume_id: request.volume_id.to_string(),
                authorization_id: None,
                prior_attachment_id: None,
                deleting_epoch: *deleting_epoch,
                head: HeadProjection::from_head(deleting_head),
                completed_at: *completed_at,
            },
            DeleteCompletionReceipt::DisposableRoot {
                disk_id,
                volume_id,
                delete_id,
                authorization_id,
                prior_attachment_id,
                deleting_epoch,
                deleting_head,
                completed_at,
            } => Self {
                delete_id: delete_id.to_string(),
                kind: "disposable_root",
                disk_id: disk_id.to_string(),
                volume_id: volume_id.to_string(),
                authorization_id: Some(authorization_id.to_string()),
                prior_attachment_id: Some(prior_attachment_id.to_string()),
                deleting_epoch: *deleting_epoch,
                head: HeadProjection::from_head(deleting_head),
                completed_at: *completed_at,
            },
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            delete_id: row.try_get("delete_id")?,
            kind: static_value(row.try_get("kind")?, &["normal", "disposable_root"])?,
            disk_id: row.try_get("disk_id")?,
            volume_id: row.try_get("volume_id")?,
            authorization_id: row.try_get("authorization_id")?,
            prior_attachment_id: row.try_get("prior_attachment_id")?,
            deleting_epoch: from_pg(row.try_get("deleting_epoch")?)?,
            head: HeadProjection::from_row(row)?,
            completed_at: from_pg(row.try_get("completed_at")?)?,
        })
    }
}

pub(super) fn load_delete_completion_for_update(
    transaction: &mut Transaction<'_>,
    delete_id: &Id,
) -> AuthorityTxResult<Option<DeleteCompletionReceipt>> {
    let sql = format!(
        "SELECT {DELETE_COMPLETION_COLUMNS} FROM delete_completion_receipts
          WHERE delete_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&delete_id.as_str()])?
        .map(|row| decode_delete_completion(&row))
        .transpose()
}

#[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
pub(super) fn load_delete_completions_by_volume(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> AuthorityTxResult<Vec<DeleteCompletionReceipt>> {
    let sql = format!(
        "SELECT {DELETE_COMPLETION_COLUMNS} FROM delete_completion_receipts
          WHERE volume_id=$1 ORDER BY delete_id LIMIT 2"
    );
    transaction
        .query(&sql, &[&volume_id.as_str()])?
        .iter()
        .map(decode_delete_completion)
        .collect()
}

pub(super) fn insert_delete_completion(
    transaction: &mut Transaction<'_>,
    receipt: &DeleteCompletionReceipt,
) -> AuthorityTxResult<()> {
    let projection = DeleteCompletionProjection::from_record(receipt)?;
    let delete_id = Id::new(projection.delete_id.clone()).ok_or_else(|| corrupt(()))?;
    if let Some(existing) = load_delete_completion_for_update(transaction, &delete_id)? {
        return if existing == *receipt {
            Ok(())
        } else {
            Err(cats_storage::authority::AuthorityError::StaleTransition.into())
        };
    }
    let record_json = encode(receipt)?;
    let deleting_epoch = projection.deleting_epoch.to_pg().map_err(corrupt)?;
    let head_generation = projection.head.generation.to_pg().map_err(corrupt)?;
    let completed_at = projection.completed_at.to_pg().map_err(corrupt)?;
    let inserted = transaction.execute(
        "INSERT INTO delete_completion_receipts (
            delete_id, record, kind, disk_id, volume_id, authorization_id,
            prior_attachment_id, deleting_epoch, head_generation,
            head_root_hash, head_root_object_id, completed_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (delete_id) DO NOTHING",
        &[
            &projection.delete_id,
            &record_json,
            &projection.kind,
            &projection.disk_id,
            &projection.volume_id,
            &projection.authorization_id,
            &projection.prior_attachment_id,
            &deleting_epoch,
            &head_generation,
            &projection.head.root_hash,
            &projection.head.root_object_id,
            &completed_at,
        ],
    )?;
    if inserted == 1 {
        return Ok(());
    }
    match load_delete_completion_for_update(transaction, &delete_id)? {
        Some(existing) if existing == *receipt => Ok(()),
        Some(_) => Err(cats_storage::authority::AuthorityError::StaleTransition.into()),
        None => Err(corrupt(())),
    }
}

fn decode_delete_completion(row: &Row) -> AuthorityTxResult<DeleteCompletionReceipt> {
    let stored = DeleteCompletionProjection::from_row(row)?;
    let receipt: DeleteCompletionReceipt = decode(row.try_get("record_json")?)?;
    let derived = DeleteCompletionProjection::from_record(&receipt)?;
    if stored != derived {
        return Err(corrupt(()));
    }
    Ok(receipt)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LifecycleVolumeReceiptKind {
    StartGrant,
    NormalRelease,
    AlreadyUnowned,
    DisposableAuthorizationConsumed,
    DeleteCompletion,
}

impl LifecycleVolumeReceiptKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StartGrant => "start_grant",
            Self::NormalRelease => "normal_release",
            Self::AlreadyUnowned => "already_unowned",
            Self::DisposableAuthorizationConsumed => "disposable_consumed",
            Self::DeleteCompletion => "delete_completion",
        }
    }

    fn parse(value: &str) -> AuthorityTxResult<Self> {
        match value {
            "start_grant" => Ok(Self::StartGrant),
            "normal_release" => Ok(Self::NormalRelease),
            "already_unowned" => Ok(Self::AlreadyUnowned),
            "disposable_consumed" => Ok(Self::DisposableAuthorizationConsumed),
            "delete_completion" => Ok(Self::DeleteCompletion),
            _ => Err(corrupt("unknown lifecycle Volume receipt kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCommandNormalReleaseReceipt {
    pub(super) operation: LifecycleCommandEnvelope,
    pub(super) delete_id: Option<Id>,
    pub(super) receipt_digest: Sha256Digest,
    pub(super) receipt: CommandNormalReleaseReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCommandAlreadyUnownedReceipt {
    pub(super) operation: LifecycleCommandEnvelope,
    pub(super) delete_id: Option<Id>,
    pub(super) receipt_digest: Sha256Digest,
    pub(super) receipt: CommandAlreadyUnownedReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCommandStartVolumeGrantReceipt {
    pub(super) operation: LifecycleCommandEnvelope,
    pub(super) receipt_digest: Sha256Digest,
    pub(super) receipt: LifecycleCommandStartVolumeGrantReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCommandDisposableAuthorizationConsumedReceipt {
    pub(super) operation: LifecycleCommandEnvelope,
    pub(super) delete_id: Id,
    pub(super) receipt_digest: Sha256Digest,
    pub(super) receipt: CommandDisposableAuthorizationConsumedReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCommandDeleteCompletionReceipt {
    pub(super) operation: LifecycleCommandEnvelope,
    pub(super) delete_id: Id,
    pub(super) receipt_digest: Sha256Digest,
    pub(super) receipt: CommandDeleteCompletionReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StoredLifecycleVolumeReceipt {
    StartGrant(Box<StoredCommandStartVolumeGrantReceipt>),
    NormalRelease(Box<StoredCommandNormalReleaseReceipt>),
    AlreadyUnowned(Box<StoredCommandAlreadyUnownedReceipt>),
    DisposableAuthorizationConsumed(Box<StoredCommandDisposableAuthorizationConsumedReceipt>),
    DeleteCompletion(Box<StoredCommandDeleteCompletionReceipt>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LifecycleReceiptOperationState {
    Unresolved,
    Terminal,
}

impl StoredLifecycleVolumeReceipt {
    fn receipt_digest(&self) -> &Sha256Digest {
        match self {
            Self::StartGrant(stored) => &stored.receipt_digest,
            Self::NormalRelease(stored) => &stored.receipt_digest,
            Self::AlreadyUnowned(stored) => &stored.receipt_digest,
            Self::DisposableAuthorizationConsumed(stored) => &stored.receipt_digest,
            Self::DeleteCompletion(stored) => &stored.receipt_digest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleReceiptSourceCommandKind {
    Start,
    Cold,
    Delete,
}

impl LifecycleReceiptSourceCommandKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Cold => "cold",
            Self::Delete => "delete",
        }
    }

    fn parse(value: &str) -> AuthorityTxResult<Self> {
        match value {
            "start" => Ok(Self::Start),
            "cold" => Ok(Self::Cold),
            "delete" => Ok(Self::Delete),
            _ => Err(corrupt("unknown lifecycle receipt source command")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleVolumeReceiptProjection {
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    workspace_id: Id,
    cat_id: Id,
    node_id: Id,
    placement_epoch: Epoch,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    source_command_kind: LifecycleReceiptSourceCommandKind,
    delete_id: Option<Id>,
    disk_id: Id,
    volume_id: Id,
    disk_role: LifecycleDiskRole,
    receipt_kind: LifecycleVolumeReceiptKind,
    receipt_sequence: u64,
    canonical_receipt_bytes: Vec<u8>,
    receipt_digest: Sha256Digest,
    created_at: UnixMillis,
}

impl LifecycleVolumeReceiptProjection {
    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            operation_id: parse_lifecycle_id(row.try_get("operation_id")?)?,
            request_fingerprint: parse_lifecycle_digest(row.try_get("request_fingerprint")?)?,
            workspace_id: parse_lifecycle_id(row.try_get("workspace_id")?)?,
            cat_id: parse_lifecycle_id(row.try_get("cat_id")?)?,
            node_id: parse_lifecycle_id(row.try_get("node_id")?)?,
            placement_epoch: from_pg(row.try_get("placement_epoch")?)?,
            runtime_config_id: parse_lifecycle_id(row.try_get("runtime_config_id")?)?,
            runtime_config_digest: parse_lifecycle_digest(row.try_get("runtime_config_sha256")?)?,
            source_command_kind: LifecycleReceiptSourceCommandKind::parse(
                &row.try_get::<_, String>("source_command_kind")?,
            )?,
            delete_id: row
                .try_get::<_, Option<String>>("delete_id")?
                .map(parse_lifecycle_id)
                .transpose()?,
            disk_id: parse_lifecycle_id(row.try_get("disk_id")?)?,
            volume_id: parse_lifecycle_id(row.try_get("volume_id")?)?,
            disk_role: parse_lifecycle_disk_role(&row.try_get::<_, String>("disk_role")?)?,
            receipt_kind: LifecycleVolumeReceiptKind::parse(
                &row.try_get::<_, String>("receipt_kind")?,
            )?,
            receipt_sequence: u64::try_from(row.try_get::<_, i64>("receipt_sequence")?)
                .map_err(corrupt)?,
            canonical_receipt_bytes: row.try_get("canonical_receipt_bytes")?,
            receipt_digest: parse_lifecycle_digest(row.try_get("receipt_digest")?)?,
            created_at: from_pg(row.try_get("created_at_unix_ms")?)?,
        })
    }
}

/// Loads one immutable command receipt by its bounded primary key. The
/// returned typed receipt has canonical bytes and exact ledger/Operation
/// projections, but its digest still must be recomputed with the appropriate
/// storage `encode_command_*` helper and current authority rows.
pub(super) fn load_lifecycle_volume_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
    kind: LifecycleVolumeReceiptKind,
    receipt_sequence: u64,
) -> AuthorityTxResult<Option<StoredLifecycleVolumeReceipt>> {
    load_lifecycle_volume_receipt(
        transaction,
        operation_id,
        volume_id,
        kind,
        receipt_sequence,
        true,
    )
}

pub(super) fn load_lifecycle_volume_receipt_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
    kind: LifecycleVolumeReceiptKind,
    receipt_sequence: u64,
) -> AuthorityTxResult<Option<StoredLifecycleVolumeReceipt>> {
    load_lifecycle_volume_receipt(
        transaction,
        operation_id,
        volume_id,
        kind,
        receipt_sequence,
        false,
    )
}

fn load_lifecycle_volume_receipt(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
    kind: LifecycleVolumeReceiptKind,
    receipt_sequence: u64,
    lock: bool,
) -> AuthorityTxResult<Option<StoredLifecycleVolumeReceipt>> {
    let lock = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT {LIFECYCLE_VOLUME_RECEIPT_COLUMNS}
           FROM lifecycle_volume_receipts
          WHERE operation_id=$1 AND volume_id=$2 AND receipt_kind=$3
            AND receipt_sequence=$4
          {lock}"
    );
    transaction
        .query_opt(
            &sql,
            &[
                &operation_id.as_str(),
                &volume_id.as_str(),
                &kind.as_str(),
                &i64::try_from(receipt_sequence).map_err(corrupt)?,
            ],
        )?
        .map(|row| decode_lifecycle_volume_receipt(transaction, &row))
        .transpose()
}

pub(super) fn load_command_start_volume_grant_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
    grant_sequence: u64,
) -> AuthorityTxResult<Option<StoredCommandStartVolumeGrantReceipt>> {
    match load_lifecycle_volume_receipt_for_update(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::StartGrant,
        grant_sequence,
    )? {
        Some(StoredLifecycleVolumeReceipt::StartGrant(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

/// Locks the latest immutable Start grant for one exact Start Operation and
/// Volume. The descending lookup is bounded by the receipt primary-key prefix;
/// callers must still compare the decoded receipt/digest with the current
/// Volume owner and terminal projection.
pub(super) fn load_latest_command_start_volume_grant_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandStartVolumeGrantReceipt>> {
    let sql = format!(
        "SELECT {LIFECYCLE_VOLUME_RECEIPT_COLUMNS}
           FROM lifecycle_volume_receipts
          WHERE operation_id=$1 AND volume_id=$2 AND receipt_kind='start_grant'
          ORDER BY receipt_sequence DESC
          LIMIT 1
          FOR UPDATE"
    );
    match transaction
        .query_opt(&sql, &[&operation_id.as_str(), &volume_id.as_str()])?
        .map(|row| decode_lifecycle_volume_receipt(transaction, &row))
        .transpose()?
    {
        Some(StoredLifecycleVolumeReceipt::StartGrant(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

pub(super) fn load_command_normal_release_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandNormalReleaseReceipt>> {
    match load_lifecycle_volume_receipt_for_update(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::NormalRelease,
        0,
    )? {
        Some(StoredLifecycleVolumeReceipt::NormalRelease(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

pub(super) fn load_command_normal_release_receipt_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandNormalReleaseReceipt>> {
    match load_lifecycle_volume_receipt_unlocked(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::NormalRelease,
        0,
    )? {
        Some(StoredLifecycleVolumeReceipt::NormalRelease(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

pub(super) fn load_command_already_unowned_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandAlreadyUnownedReceipt>> {
    match load_lifecycle_volume_receipt_for_update(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::AlreadyUnowned,
        0,
    )? {
        Some(StoredLifecycleVolumeReceipt::AlreadyUnowned(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

pub(super) fn load_command_already_unowned_receipt_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandAlreadyUnownedReceipt>> {
    match load_lifecycle_volume_receipt_unlocked(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::AlreadyUnowned,
        0,
    )? {
        Some(StoredLifecycleVolumeReceipt::AlreadyUnowned(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

pub(super) fn load_command_disposable_authorization_consumed_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandDisposableAuthorizationConsumedReceipt>> {
    match load_lifecycle_volume_receipt_for_update(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed,
        0,
    )? {
        Some(StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(stored)) => {
            Ok(Some(*stored))
        }
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

pub(super) fn load_command_delete_completion_receipt_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Option<StoredCommandDeleteCompletionReceipt>> {
    match load_lifecycle_volume_receipt_for_update(
        transaction,
        operation_id,
        volume_id,
        LifecycleVolumeReceiptKind::DeleteCompletion,
        0,
    )? {
        Some(StoredLifecycleVolumeReceipt::DeleteCompletion(stored)) => Ok(Some(*stored)),
        Some(_) => Err(corrupt("lifecycle receipt kind decoder mismatch")),
        None => Ok(None),
    }
}

/// Bounded DeleteSweeper source lookup. History is never scanned or guessed:
/// the current Deleting row supplies `(volume_id, delete_id)` and the closed
/// receipt kind completes the indexed lookup. Zero rows means this is not an
/// atomic lifecycle source; more than one is corruption.
pub(super) fn load_delete_lifecycle_volume_receipt_source_for_update(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
    delete_id: &Id,
    kind: LifecycleVolumeReceiptKind,
) -> AuthorityTxResult<Option<StoredLifecycleVolumeReceipt>> {
    load_delete_lifecycle_volume_receipt_source(transaction, volume_id, delete_id, kind, true)
}

pub(super) fn load_delete_lifecycle_volume_receipt_source_unlocked(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
    delete_id: &Id,
    kind: LifecycleVolumeReceiptKind,
) -> AuthorityTxResult<Option<StoredLifecycleVolumeReceipt>> {
    load_delete_lifecycle_volume_receipt_source(transaction, volume_id, delete_id, kind, false)
}

fn load_delete_lifecycle_volume_receipt_source(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
    delete_id: &Id,
    kind: LifecycleVolumeReceiptKind,
    lock: bool,
) -> AuthorityTxResult<Option<StoredLifecycleVolumeReceipt>> {
    if !matches!(
        kind,
        LifecycleVolumeReceiptKind::NormalRelease
            | LifecycleVolumeReceiptKind::AlreadyUnowned
            | LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed
    ) {
        return Err(corrupt("receipt kind is not a DeleteSweeper source"));
    }
    let lock = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT {LIFECYCLE_VOLUME_RECEIPT_COLUMNS}
           FROM lifecycle_volume_receipts
          WHERE volume_id=$1 AND delete_id=$2 AND receipt_kind=$3
          ORDER BY operation_id COLLATE \"C\" LIMIT 2
          {lock}"
    );
    let rows = transaction.query(
        &sql,
        &[&volume_id.as_str(), &delete_id.as_str(), &kind.as_str()],
    )?;
    if rows.len() > 1 {
        return Err(corrupt("multiple exact lifecycle delete receipt sources"));
    }
    rows.first()
        .map(|row| decode_lifecycle_volume_receipt(transaction, row))
        .transpose()
}

/// `locked_operation` must be the exact unresolved Start Operation locked
/// after Cat and before the sorted Volume/Disk graph. The receipt is inserted
/// in the same transaction as the acquire or renewal authority mutation.
pub(super) fn insert_command_start_volume_grant_receipt(
    transaction: &mut Transaction<'_>,
    locked_operation: &LifecycleCommandEnvelope,
    grant_sequence: WireU64,
    current_volume: &VolumeRecord,
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> AuthorityTxResult<Sha256Digest> {
    let expected_volume = locked_operation
        .runtime_config
        .volumes
        .iter()
        .find(|volume| volume.volume_id == receipt.volume.volume_id)
        .ok_or_else(|| corrupt("Start grant volume is absent from runtime config"))?;
    let expected_scope = LifecycleVolumeCommandScope {
        operation_id: locked_operation.operation_id.clone(),
        request_fingerprint: locked_operation.request_fingerprint.clone(),
        cat_id: locked_operation.cat_id.clone(),
        node_id: locked_operation.node_id.clone(),
        placement_identity: locked_operation.placement_identity.clone(),
    };
    let encoded = cats_storage::lifecycle_volume::encode_command_start_volume_grant_receipt(
        &expected_scope,
        grant_sequence,
        expected_volume,
        current_volume,
        receipt,
    )
    .map_err(corrupt)?;
    insert_lifecycle_volume_receipt(
        transaction,
        StoredLifecycleVolumeReceipt::StartGrant(Box::new(StoredCommandStartVolumeGrantReceipt {
            operation: locked_operation.clone(),
            receipt_digest: encoded.receipt_digest.clone(),
            receipt: receipt.clone(),
        })),
        encoded,
    )
}

/// `locked_operation` must have been loaded `FOR UPDATE` while unresolved
/// after locking Cat and before locking sorted Volume and sorted Disk rows.
/// Writers do not reacquire Cat/Operation after a Volume transition.
pub(super) fn insert_command_normal_release_receipt(
    transaction: &mut Transaction<'_>,
    locked_operation: &LifecycleCommandEnvelope,
    current_released_volume: &VolumeRecord,
    receipt: &CommandNormalReleaseReceipt,
) -> AuthorityTxResult<Sha256Digest> {
    let encoded = cats_storage::lifecycle_volume::encode_command_normal_release_receipt(
        &receipt.durability.scope,
        &receipt.durability.volume,
        current_released_volume,
        receipt,
    )
    .map_err(corrupt)?;
    let (_, delete_id) = operation_receipt_source(locked_operation)?;
    insert_lifecycle_volume_receipt(
        transaction,
        StoredLifecycleVolumeReceipt::NormalRelease(Box::new(StoredCommandNormalReleaseReceipt {
            operation: locked_operation.clone(),
            delete_id,
            receipt_digest: encoded.receipt_digest.clone(),
            receipt: receipt.clone(),
        })),
        encoded,
    )
}

/// Writes the exact Cold/Delete already-Unowned command receipt in the same
/// transaction that locks and validates the unchanged Active+Unowned row.
pub(super) fn insert_command_already_unowned_receipt(
    transaction: &mut Transaction<'_>,
    locked_operation: &LifecycleCommandEnvelope,
    current_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> AuthorityTxResult<Sha256Digest> {
    let encoded = match &locked_operation.command {
        LifecycleCommand::Cold(_) => {
            cats_storage::lifecycle_volume::encode_command_cold_already_unowned_receipt(
                &receipt.scope,
                &receipt.volume,
                current_volume,
                receipt,
            )
        }
        LifecycleCommand::Delete(_) => {
            cats_storage::lifecycle_volume::encode_command_delete_already_unowned_receipt(
                &receipt.scope,
                &receipt.volume,
                current_volume,
                receipt,
            )
        }
        _ => return Err(corrupt("already-Unowned receipt has wrong command kind")),
    }
    .map_err(corrupt)?;
    let (_, delete_id) = operation_receipt_source(locked_operation)?;
    insert_lifecycle_volume_receipt(
        transaction,
        StoredLifecycleVolumeReceipt::AlreadyUnowned(Box::new(
            StoredCommandAlreadyUnownedReceipt {
                operation: locked_operation.clone(),
                delete_id,
                receipt_digest: encoded.receipt_digest.clone(),
                receipt: receipt.clone(),
            },
        )),
        encoded,
    )
}

/// Same lock-order precondition as [`insert_command_normal_release_receipt`].
pub(super) fn insert_command_disposable_authorization_consumed_receipt(
    transaction: &mut Transaction<'_>,
    locked_operation: &LifecycleCommandEnvelope,
    current_deleting_root_volume: &VolumeRecord,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    receipt: &CommandDisposableAuthorizationConsumedReceipt,
) -> AuthorityTxResult<Sha256Digest> {
    let encoded =
        cats_storage::lifecycle_volume::encode_command_disposable_authorization_consumed_receipt(
            &receipt.command,
            current_deleting_root_volume,
            consumed_authorization,
            receipt,
        )
        .map_err(corrupt)?;
    insert_lifecycle_volume_receipt(
        transaction,
        StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(Box::new(
            StoredCommandDisposableAuthorizationConsumedReceipt {
                operation: locked_operation.clone(),
                delete_id: receipt.command.root_disposition.delete_id.clone(),
                receipt_digest: encoded.receipt_digest.clone(),
                receipt: receipt.clone(),
            },
        )),
        encoded,
    )
}

/// Same lock-order precondition as [`insert_command_normal_release_receipt`].
pub(super) fn insert_command_delete_completion_receipt(
    transaction: &mut Transaction<'_>,
    locked_operation: &LifecycleCommandEnvelope,
    consumed_authorization: Option<&CommandBoundDisposableRootAuthorization>,
    receipt: &CommandDeleteCompletionReceipt,
) -> AuthorityTxResult<Sha256Digest> {
    let encoded = cats_storage::lifecycle_volume::encode_command_delete_completion_receipt(
        &receipt.command,
        None,
        consumed_authorization,
        receipt,
    )
    .map_err(corrupt)?;
    insert_lifecycle_volume_receipt(
        transaction,
        StoredLifecycleVolumeReceipt::DeleteCompletion(Box::new(
            StoredCommandDeleteCompletionReceipt {
                operation: locked_operation.clone(),
                delete_id: receipt.command.root_disposition.delete_id.clone(),
                receipt_digest: encoded.receipt_digest.clone(),
                receipt: receipt.clone(),
            },
        )),
        encoded,
    )
}

fn insert_lifecycle_volume_receipt(
    transaction: &mut Transaction<'_>,
    stored: StoredLifecycleVolumeReceipt,
    encoded: CanonicalLifecycleVolumeReceipt,
) -> AuthorityTxResult<Sha256Digest> {
    let (operation, delete_id, target, kind, receipt_sequence) =
        lifecycle_receipt_binding(&stored)?;
    validate_lifecycle_receipt_against_operation(operation, delete_id, &target, kind, &stored)?;
    let operation_state = transaction
        .query_one(
            "SELECT state FROM runtime_operations WHERE operation_id=$1",
            &[&operation.operation_id.as_str()],
        )?
        .try_get::<_, String>("state")?;
    if operation_state != "unresolved" {
        return Err(corrupt(
            "new lifecycle receipt requires a prelocked unresolved Operation",
        ));
    }
    if stored.receipt_digest() != &encoded.receipt_digest {
        return Err(corrupt(
            "validated lifecycle receipt digest changed before insert",
        ));
    }
    if let Some(existing) = load_lifecycle_volume_receipt_for_update(
        transaction,
        &operation.operation_id,
        &target.volume_id,
        kind,
        receipt_sequence,
    )? {
        return if existing == stored {
            Ok(encoded.receipt_digest)
        } else {
            Err(cats_storage::authority::AuthorityError::StaleTransition.into())
        };
    }
    let created_at = database_now(transaction)?;
    let placement_epoch = operation
        .placement_identity
        .placement_epoch
        .to_pg()
        .map_err(corrupt)?;
    let created_at = created_at.to_pg().map_err(corrupt)?;
    let (source_kind, projected_delete_id) = operation_receipt_source(operation)?;
    if projected_delete_id.as_ref() != delete_id {
        return Err(corrupt("receipt delete_id differs from exact Operation"));
    }
    let inserted = transaction.execute(
        "INSERT INTO lifecycle_volume_receipts (
            operation_id, request_fingerprint, workspace_id, cat_id, node_id,
            placement_epoch, runtime_config_id, runtime_config_sha256,
            source_command_kind, delete_id, disk_id, volume_id, disk_role,
            receipt_kind, receipt_sequence, canonical_receipt_bytes,
            receipt_digest, created_at_unix_ms
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
         ) ON CONFLICT (operation_id, volume_id, receipt_kind, receipt_sequence) DO NOTHING",
        &[
            &operation.operation_id.as_str(),
            &operation.request_fingerprint.as_str(),
            &operation.workspace_id.as_str(),
            &operation.cat_id.as_str(),
            &operation.node_id.as_str(),
            &placement_epoch,
            &operation.runtime_config.config_id.as_str(),
            &operation.runtime_config.config_digest.as_str(),
            &source_kind.as_str(),
            &projected_delete_id.as_ref().map(Id::as_str),
            &target.disk_id.as_str(),
            &target.volume_id.as_str(),
            &lifecycle_disk_role_text(target.disk_role),
            &kind.as_str(),
            &i64::try_from(receipt_sequence).map_err(corrupt)?,
            &encoded.canonical_receipt_bytes,
            &encoded.receipt_digest.as_str(),
            &created_at,
        ],
    )?;
    if inserted == 1 {
        return Ok(encoded.receipt_digest);
    }
    match load_lifecycle_volume_receipt_for_update(
        transaction,
        &operation.operation_id,
        &target.volume_id,
        kind,
        receipt_sequence,
    )? {
        Some(existing) if existing == stored => Ok(encoded.receipt_digest),
        Some(_) => Err(cats_storage::authority::AuthorityError::StaleTransition.into()),
        None => Err(corrupt("receipt insert conflict disappeared")),
    }
}

fn decode_lifecycle_volume_receipt(
    transaction: &mut Transaction<'_>,
    row: &Row,
) -> AuthorityTxResult<StoredLifecycleVolumeReceipt> {
    let projection = LifecycleVolumeReceiptProjection::from_row(row)?;
    let operation = load_receipt_operation(transaction, &projection.operation_id, false)?
        .ok_or_else(|| corrupt("receipt references a missing lifecycle Operation"))?;
    validate_receipt_projection_against_operation(&projection, &operation)?;
    let stored = match projection.receipt_kind {
        LifecycleVolumeReceiptKind::StartGrant => {
            let receipt = decode_canonical_command_start_volume_grant_receipt(
                &projection.canonical_receipt_bytes,
            )
            .map_err(corrupt)?;
            StoredLifecycleVolumeReceipt::StartGrant(Box::new(
                StoredCommandStartVolumeGrantReceipt {
                    operation,
                    receipt_digest: projection.receipt_digest.clone(),
                    receipt,
                },
            ))
        }
        LifecycleVolumeReceiptKind::NormalRelease => {
            let receipt = decode_canonical_command_normal_release_receipt(
                &projection.canonical_receipt_bytes,
            )
            .map_err(corrupt)?;
            StoredLifecycleVolumeReceipt::NormalRelease(Box::new(
                StoredCommandNormalReleaseReceipt {
                    operation,
                    delete_id: projection.delete_id.clone(),
                    receipt_digest: projection.receipt_digest.clone(),
                    receipt,
                },
            ))
        }
        LifecycleVolumeReceiptKind::AlreadyUnowned => {
            let receipt = decode_canonical_command_already_unowned_receipt(
                &projection.canonical_receipt_bytes,
            )
            .map_err(corrupt)?;
            StoredLifecycleVolumeReceipt::AlreadyUnowned(Box::new(
                StoredCommandAlreadyUnownedReceipt {
                    operation,
                    delete_id: projection.delete_id.clone(),
                    receipt_digest: projection.receipt_digest.clone(),
                    receipt,
                },
            ))
        }
        LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed => {
            let receipt = decode_canonical_command_disposable_authorization_consumed_receipt(
                &projection.canonical_receipt_bytes,
            )
            .map_err(corrupt)?;
            StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(Box::new(
                StoredCommandDisposableAuthorizationConsumedReceipt {
                    operation,
                    delete_id: projection
                        .delete_id
                        .clone()
                        .ok_or_else(|| corrupt("Delete receipt omitted delete_id"))?,
                    receipt_digest: projection.receipt_digest.clone(),
                    receipt,
                },
            ))
        }
        LifecycleVolumeReceiptKind::DeleteCompletion => {
            let receipt = decode_canonical_command_delete_completion_receipt(
                &projection.canonical_receipt_bytes,
            )
            .map_err(corrupt)?;
            StoredLifecycleVolumeReceipt::DeleteCompletion(Box::new(
                StoredCommandDeleteCompletionReceipt {
                    operation,
                    delete_id: projection
                        .delete_id
                        .clone()
                        .ok_or_else(|| corrupt("Delete receipt omitted delete_id"))?,
                    receipt_digest: projection.receipt_digest.clone(),
                    receipt,
                },
            ))
        }
    };
    let (operation, delete_id, target, kind, receipt_sequence) =
        lifecycle_receipt_binding(&stored)?;
    if kind != projection.receipt_kind
        || delete_id != projection.delete_id.as_ref()
        || target.disk_id != projection.disk_id
        || target.volume_id != projection.volume_id
        || target.disk_role != projection.disk_role
        || receipt_sequence != projection.receipt_sequence
    {
        return Err(corrupt("lifecycle receipt canonical/projection mismatch"));
    }
    validate_lifecycle_receipt_against_operation(operation, delete_id, &target, kind, &stored)?;
    Ok(stored)
}

fn lifecycle_receipt_binding(
    stored: &StoredLifecycleVolumeReceipt,
) -> AuthorityTxResult<(
    &LifecycleCommandEnvelope,
    Option<&Id>,
    LifecycleVolumeIdentity,
    LifecycleVolumeReceiptKind,
    u64,
)> {
    Ok(match stored {
        StoredLifecycleVolumeReceipt::StartGrant(stored) => (
            &stored.operation,
            None,
            LifecycleVolumeIdentity {
                disk_id: stored.receipt.volume.disk_id.clone(),
                disk_role: stored.receipt.volume.disk_role,
                volume_id: stored.receipt.volume.volume_id.clone(),
            },
            LifecycleVolumeReceiptKind::StartGrant,
            stored.receipt.grant_sequence.get(),
        ),
        StoredLifecycleVolumeReceipt::NormalRelease(stored) => (
            &stored.operation,
            stored.delete_id.as_ref(),
            stored.receipt.durability.volume.identity(),
            LifecycleVolumeReceiptKind::NormalRelease,
            0,
        ),
        StoredLifecycleVolumeReceipt::AlreadyUnowned(stored) => (
            &stored.operation,
            stored.delete_id.as_ref(),
            stored.receipt.volume.clone(),
            LifecycleVolumeReceiptKind::AlreadyUnowned,
            0,
        ),
        StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(stored) => (
            &stored.operation,
            Some(&stored.delete_id),
            stored.receipt.command.root_disposition.root.clone(),
            LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed,
            0,
        ),
        StoredLifecycleVolumeReceipt::DeleteCompletion(stored) => (
            &stored.operation,
            Some(&stored.delete_id),
            stored.receipt.command.root_disposition.root.clone(),
            LifecycleVolumeReceiptKind::DeleteCompletion,
            0,
        ),
    })
}

fn validate_lifecycle_receipt_against_operation(
    operation: &LifecycleCommandEnvelope,
    delete_id: Option<&Id>,
    target: &LifecycleVolumeIdentity,
    kind: LifecycleVolumeReceiptKind,
    stored: &StoredLifecycleVolumeReceipt,
) -> AuthorityTxResult<()> {
    let expected_scope = LifecycleVolumeCommandScope {
        operation_id: operation.operation_id.clone(),
        request_fingerprint: operation.request_fingerprint.clone(),
        cat_id: operation.cat_id.clone(),
        node_id: operation.node_id.clone(),
        placement_identity: operation.placement_identity.clone(),
    };
    let scope_matches = match stored {
        StoredLifecycleVolumeReceipt::StartGrant(stored) => {
            stored.receipt.scope.operation_id == expected_scope.operation_id
                && stored.receipt.scope.request_fingerprint == expected_scope.request_fingerprint
                && stored.receipt.scope.cat_id == expected_scope.cat_id
                && stored.receipt.scope.node_id == expected_scope.node_id
                && stored.receipt.scope.placement_identity == expected_scope.placement_identity
        }
        StoredLifecycleVolumeReceipt::NormalRelease(stored) => {
            stored.receipt.durability.scope == expected_scope
        }
        StoredLifecycleVolumeReceipt::AlreadyUnowned(stored) => {
            stored.receipt.scope == expected_scope
        }
        StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(stored) => {
            stored.receipt.command.scope == expected_scope
        }
        StoredLifecycleVolumeReceipt::DeleteCompletion(stored) => {
            stored.receipt.command.scope == expected_scope
        }
    };
    if !scope_matches {
        return Err(corrupt(
            "receipt command scope differs from exact Operation",
        ));
    }
    let (source, operation_delete_id) = operation_receipt_source(operation)?;
    if operation_delete_id.as_ref() != delete_id {
        return Err(corrupt("receipt delete_id differs from exact Operation"));
    }
    match (source, kind) {
        (LifecycleReceiptSourceCommandKind::Start, LifecycleVolumeReceiptKind::StartGrant) => {}
        (LifecycleReceiptSourceCommandKind::Cold, LifecycleVolumeReceiptKind::NormalRelease) => {}
        (LifecycleReceiptSourceCommandKind::Cold, LifecycleVolumeReceiptKind::AlreadyUnowned) => {}
        (LifecycleReceiptSourceCommandKind::Delete, _) => {}
        _ => return Err(corrupt("receipt kind is impossible for source command")),
    }
    validate_lifecycle_target_against_operation(operation, target)?;
    match stored {
        StoredLifecycleVolumeReceipt::StartGrant(stored) => {
            validate_start_grant_against_operation(operation, &stored.receipt)?;
        }
        StoredLifecycleVolumeReceipt::NormalRelease(_) => {}
        StoredLifecycleVolumeReceipt::AlreadyUnowned(_) => {}
        StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(stored) => {
            validate_delete_command_against_operation(operation, &stored.receipt.command)?;
        }
        StoredLifecycleVolumeReceipt::DeleteCompletion(stored) => {
            validate_delete_command_against_operation(operation, &stored.receipt.command)?;
        }
    }
    Ok(())
}

fn validate_lifecycle_target_against_operation(
    operation: &LifecycleCommandEnvelope,
    target: &LifecycleVolumeIdentity,
) -> AuthorityTxResult<()> {
    let config = operation
        .runtime_config
        .volumes
        .iter()
        .find(|volume| volume.volume_id == target.volume_id)
        .ok_or_else(|| corrupt("receipt volume is absent from runtime config"))?;
    if config.disk_id != target.disk_id || config.disk_role != target.disk_role {
        return Err(corrupt("receipt target differs from runtime config"));
    }
    if let LifecycleCommand::Delete(spec) = &operation.command {
        let disposition = spec
            .volume_dispositions
            .iter()
            .find(|disposition| disposition.volume_id() == &target.volume_id)
            .ok_or_else(|| corrupt("receipt volume is absent from Delete disposition"))?;
        let matches = match disposition {
            RequestedVolumeDisposition::DiscardWithCat {
                disk_id, disk_role, ..
            } => {
                target.disk_role == LifecycleDiskRole::Root
                    && disk_id == &target.disk_id
                    && disk_role == &target.disk_role
            }
            RequestedVolumeDisposition::RetainDetached {
                disk_id, disk_role, ..
            } => {
                target.disk_role == LifecycleDiskRole::Persistent
                    && disk_id == &target.disk_id
                    && disk_role == &target.disk_role
            }
        };
        if !matches {
            return Err(corrupt("receipt target differs from Delete disposition"));
        }
    }
    Ok(())
}

fn validate_start_grant_against_operation(
    operation: &LifecycleCommandEnvelope,
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> AuthorityTxResult<()> {
    let LifecycleCommand::Start(spec) = &operation.command else {
        return Err(corrupt("Start grant references a non-Start Operation"));
    };
    let config = operation
        .runtime_config
        .volumes
        .iter()
        .find(|volume| volume.volume_id == receipt.volume.volume_id)
        .ok_or_else(|| corrupt("Start grant volume is absent from runtime config"))?;
    if config != &receipt.volume {
        return Err(corrupt("Start grant config differs from exact Operation"));
    }
    let authority = spec
        .volume_authorities
        .iter()
        .find(|authority| authority.volume_id == config.volume_id)
        .ok_or_else(|| corrupt("Start grant has no command authority slot"))?;
    if authority.disk_id != config.disk_id {
        return Err(corrupt("Start authority disk differs from runtime config"));
    }
    let matches = match (&authority.authority, &receipt.authority) {
        (
            RuntimeVolumeAuthorityInput::NormalUnowned {
                expected_unowned_epoch,
                transition_id,
            },
            LifecycleStartVolumeGrantAuthority::NormalAcquire { request, .. },
        ) if receipt.grant_sequence.get() == 0 => {
            request.expected_unowned_epoch == *expected_unowned_epoch
                && request.transition_id == *transition_id
        }
        (
            RuntimeVolumeAuthorityInput::SameNodeOwned {
                attachment_id,
                attachment_epoch,
            },
            LifecycleStartVolumeGrantAuthority::RenewSameNode { request, .. },
        ) if receipt.grant_sequence.get() == 0 => {
            request.attachment_id == *attachment_id && request.expected_epoch == *attachment_epoch
        }
        (
            RuntimeVolumeAuthorityInput::NormalUnowned {
                expected_unowned_epoch,
                transition_id,
            },
            LifecycleStartVolumeGrantAuthority::RenewSameNode {
                serving_acquire,
                request,
                result,
                ..
            },
        ) if receipt.grant_sequence.get() > 0 => {
            let cats_api::runtime_lifecycle_volume::LifecycleServingAcquire::Normal {
                request: acquire_request,
                result: acquire_result,
            } = serving_acquire.as_ref();
            acquire_request.expected_unowned_epoch == *expected_unowned_epoch
                && acquire_request.transition_id == *transition_id
                && acquire_result.transition_id == *transition_id
                && request.attachment_id == acquire_result.attachment_id
                && request.expected_epoch == acquire_result.resulting_epoch
                && result.attachment_id == request.attachment_id
                && result.epoch == request.expected_epoch
        }
        (
            RuntimeVolumeAuthorityInput::SameNodeOwned {
                attachment_id,
                attachment_epoch,
            },
            LifecycleStartVolumeGrantAuthority::RenewSameNode {
                request, result, ..
            },
        ) if receipt.grant_sequence.get() > 0 => {
            request.attachment_id == *attachment_id
                && request.expected_epoch == *attachment_epoch
                && result.attachment_id == *attachment_id
                && result.epoch == *attachment_epoch
        }
        _ => false,
    };
    if !matches {
        return Err(corrupt("Start grant differs from command authority input"));
    }
    Ok(())
}

fn validate_delete_command_against_operation(
    operation: &LifecycleCommandEnvelope,
    command: &DeleteCommandVolumeSet,
) -> AuthorityTxResult<()> {
    let LifecycleCommand::Delete(spec) = &operation.command else {
        return Err(corrupt("Delete receipt references a non-Delete Operation"));
    };
    if command.root_disposition.delete_id != spec.delete_id {
        return Err(corrupt("Delete receipt has the wrong delete_id"));
    }
    validate_lifecycle_target_against_operation(operation, &command.root_disposition.root)?;
    let persistent_config: Vec<_> = operation
        .runtime_config
        .volumes
        .iter()
        .filter(|volume| volume.disk_role == LifecycleDiskRole::Persistent)
        .collect();
    if command.persistent_volumes.len() != persistent_config.len()
        || command
            .persistent_volumes
            .iter()
            .zip(persistent_config)
            .any(|(target, config)| {
                target.volume_id != config.volume_id
                    || target.disk_id != config.disk_id
                    || target.disk_role != config.disk_role
            })
    {
        return Err(corrupt(
            "Delete receipt does not retain the complete ordered Persistent set",
        ));
    }
    for target in &command.persistent_volumes {
        validate_lifecycle_target_against_operation(operation, target)?;
    }
    Ok(())
}

fn operation_receipt_source(
    operation: &LifecycleCommandEnvelope,
) -> AuthorityTxResult<(LifecycleReceiptSourceCommandKind, Option<Id>)> {
    match &operation.command {
        LifecycleCommand::Start(_) => Ok((LifecycleReceiptSourceCommandKind::Start, None)),
        LifecycleCommand::Cold(_) => Ok((LifecycleReceiptSourceCommandKind::Cold, None)),
        LifecycleCommand::Delete(spec) => Ok((
            LifecycleReceiptSourceCommandKind::Delete,
            Some(spec.delete_id.clone()),
        )),
        _ => Err(corrupt(
            "lifecycle Volume receipt references an unsupported command",
        )),
    }
}

fn validate_receipt_projection_against_operation(
    projection: &LifecycleVolumeReceiptProjection,
    operation: &LifecycleCommandEnvelope,
) -> AuthorityTxResult<()> {
    let (source, delete_id) = operation_receipt_source(operation)?;
    if projection.operation_id != operation.operation_id
        || projection.request_fingerprint != operation.request_fingerprint
        || projection.workspace_id != operation.workspace_id
        || projection.cat_id != operation.cat_id
        || projection.node_id != operation.node_id
        || projection.placement_epoch != operation.placement_identity.placement_epoch
        || projection.runtime_config_id != operation.runtime_config.config_id
        || projection.runtime_config_digest != operation.runtime_config.config_digest
        || projection.source_command_kind != source
        || projection.delete_id != delete_id
    {
        return Err(corrupt("lifecycle receipt ledger/Operation mismatch"));
    }
    Ok(())
}

fn load_receipt_operation_for_insert(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<LifecycleCommandEnvelope> {
    let operation = load_receipt_operation(transaction, operation_id, true)?
        .ok_or_else(|| corrupt("lifecycle receipt Operation is missing"))?;
    Ok(operation)
}

pub(super) fn lock_lifecycle_receipt_operation_unresolved(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<LifecycleCommandEnvelope> {
    load_receipt_operation_for_insert(transaction, operation_id)
}

pub(super) fn lock_lifecycle_receipt_operation(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<(LifecycleCommandEnvelope, LifecycleReceiptOperationState)>> {
    let Some(operation) = load_receipt_operation(transaction, operation_id, false)? else {
        return Ok(None);
    };
    let row = transaction.query_one(
        "SELECT state FROM runtime_operations WHERE operation_id=$1 FOR UPDATE",
        &[&operation_id.as_str()],
    )?;
    let state = match row.try_get::<_, String>("state")?.as_str() {
        "unresolved" => LifecycleReceiptOperationState::Unresolved,
        "terminal" => LifecycleReceiptOperationState::Terminal,
        _ => return Err(corrupt("lifecycle Operation has unknown state")),
    };
    Ok(Some((operation, state)))
}

pub(super) fn load_lifecycle_receipt_operation_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<LifecycleCommandEnvelope>> {
    load_receipt_operation(transaction, operation_id, false)
}

fn load_receipt_operation(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    require_unresolved: bool,
) -> AuthorityTxResult<Option<LifecycleCommandEnvelope>> {
    let lock = if require_unresolved {
        " FOR UPDATE"
    } else {
        ""
    };
    let sql = format!(
        "SELECT workspace_id, cat_id, node_id, placement_epoch, command_kind,
                canonical_request_bytes, canonical_request_sha256,
                runtime_config_id, runtime_config_sha256, state
           FROM runtime_operations WHERE operation_id=$1{lock}"
    );
    let Some(row) = transaction.query_opt(&sql, &[&operation_id.as_str()])? else {
        return Ok(None);
    };
    let bytes: Vec<u8> = row.try_get("canonical_request_bytes")?;
    let operation = decode_lifecycle_command_envelope(&bytes).map_err(corrupt)?;
    let row_kind: String = row.try_get("command_kind")?;
    let expected_kind = match operation.command_kind() {
        LifecycleCommandKind::Start => "start",
        LifecycleCommandKind::Cold => "cold",
        LifecycleCommandKind::Delete => "delete",
        _ => return Err(corrupt("receipt Operation has an unsupported command kind")),
    };
    let placement_epoch: Epoch = from_pg(row.try_get("placement_epoch")?)?;
    if operation.operation_id != *operation_id
        || row.try_get::<_, String>("workspace_id")? != operation.workspace_id.as_str()
        || row.try_get::<_, String>("cat_id")? != operation.cat_id.as_str()
        || row.try_get::<_, String>("node_id")? != operation.node_id.as_str()
        || placement_epoch != operation.placement_identity.placement_epoch
        || operation.node_id != operation.placement_identity.node_id
        || row_kind != expected_kind
        || row.try_get::<_, String>("canonical_request_sha256")?
            != operation.request_fingerprint.as_str()
        || row.try_get::<_, String>("runtime_config_id")?
            != operation.runtime_config.config_id.as_str()
        || row.try_get::<_, String>("runtime_config_sha256")?
            != operation.runtime_config.config_digest.as_str()
    {
        return Err(corrupt("lifecycle receipt Operation projection mismatch"));
    }
    let state: String = row.try_get("state")?;
    if require_unresolved && state != "unresolved" {
        return Err(corrupt(
            "new lifecycle receipt requires unresolved Operation",
        ));
    }
    if state != "unresolved" && state != "terminal" {
        return Err(corrupt("lifecycle Operation has unknown state"));
    }
    Ok(Some(operation))
}

fn parse_lifecycle_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("invalid lifecycle receipt Id"))
}

fn parse_lifecycle_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("invalid lifecycle receipt digest"))
}

fn parse_lifecycle_disk_role(value: &str) -> AuthorityTxResult<LifecycleDiskRole> {
    match value {
        "root" => Ok(LifecycleDiskRole::Root),
        "persistent" => Ok(LifecycleDiskRole::Persistent),
        _ => Err(corrupt("unknown lifecycle receipt disk role")),
    }
}

const fn lifecycle_disk_role_text(role: LifecycleDiskRole) -> &'static str {
    match role {
        LifecycleDiskRole::Root => "root",
        LifecycleDiskRole::Persistent => "persistent",
    }
}

pub(in crate::store) fn database_now(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<UnixMillis> {
    let value = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
            &[],
        )?
        .try_get::<_, i64>(0)?;
    from_pg(value)
}

fn encode<T: Serialize>(value: &T) -> AuthorityTxResult<String> {
    serde_json::to_string(value).map_err(corrupt)
}

fn decode<T: DeserializeOwned>(value: String) -> AuthorityTxResult<T> {
    serde_json::from_str(&value).map_err(corrupt)
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt(()))
    }
}

fn static_value(value: String, allowed: &[&'static str]) -> AuthorityTxResult<&'static str> {
    allowed
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .ok_or_else(|| corrupt(()))
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn optional_from_pg<T: PgBigInt>(value: Option<i64>) -> AuthorityTxResult<Option<T>> {
    value.map(from_pg).transpose()
}

fn optional_to_pg<T: PgBigInt>(value: Option<T>) -> AuthorityTxResult<Option<i64>> {
    value
        .map(|value| value.to_pg().map_err(corrupt))
        .transpose()
}

fn corrupt(_: impl std::fmt::Debug) -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

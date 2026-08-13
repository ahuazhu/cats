//! Closed authority rows and their checked PostgreSQL projections.

use cats_api::runtime_reconciliation::{Epoch, FenceEpoch, Generation, Id, Revision, UnixMillis};
use cats_storage::authority::{
    project_volume_record, validate_authorization_record, validate_delete_completion_receipt,
    validate_host_fence_event, validate_volume_owner_binding, AuthorizationConsumedReceipt,
    AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt,
    DisposableDeleteIsolationBasis, HostFenceEvent, HostFenceEventState, HostIsolationState,
    RemoteHead, VolumeAuthorization, VolumeOwnerBinding, VolumeRecord, VolumeRecordProjection,
};
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use super::pg_codec::{LeaseDurationMs, PgBigInt, SizeBytes};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

pub(super) const VOLUME_COLUMNS: &str = "
    volume_id, record::text AS record_json, size_bytes, durability,
    admin_state, delete_id, head_generation, head_root_hash,
    head_root_object_id, lease_owner, lease_epoch, lease_expires_at,
    last_transition_kind, last_transition_id, transition_desired_revision,
    transition_placement_epoch, transition_lease_duration_ms,
    owner_binding::text AS owner_binding_json, owner_node_id";

pub(super) const EVENT_COLUMNS: &str = "
    event_id, record::text AS record_json, provider, immutable_host_id,
    node_id, expected_node_boot_id, expected_agent_session_epoch,
    fence_attempt_id, isolation_state, observed_at, state, destroyed_at";

pub(super) const AUTHORIZATION_COLUMNS: &str = "
    authorization_id, record::text AS record_json, kind, authorized_node_id,
    host_fence_event_id, volume_id, state, desired_revision,
    placement_epoch, lease_duration_ms, not_after, consumed_at";

pub(super) const DELETE_COMPLETION_COLUMNS: &str = "
    delete_id, record::text AS record_json, kind, disk_id, volume_id,
    authorization_id, prior_attachment_id, deleting_epoch,
    head_generation, head_root_hash, head_root_object_id, completed_at";

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
        transition_desired_revision: optional_from_pg(row.try_get("transition_desired_revision")?)?,
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
    let transition_revision = optional_to_pg(projection.transition_desired_revision)?;
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
            last_transition_id, transition_desired_revision,
            transition_placement_epoch, transition_lease_duration_ms
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17
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
            &transition_revision,
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
    let transition_revision = optional_to_pg(projection.transition_desired_revision)?;
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
            last_transition_id=$14, transition_desired_revision=$15,
            transition_placement_epoch=$16, transition_lease_duration_ms=$17
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
            &transition_revision,
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
    let transition_revision = optional_to_pg(projection.transition_desired_revision)?;
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
            last_transition_id=$14, transition_desired_revision=$15,
            transition_placement_epoch=$16, transition_lease_duration_ms=$17,
            owner_binding=$18::TEXT::jsonb, owner_node_id=$19
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
            &transition_revision,
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
                HostFenceEventState::Rejoined => "rejoined",
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

// Host rejoin is not an F1 public mutation. This remains transaction-local for
// the later owner and for lock-order contract tests.
#[allow(dead_code)]
pub(super) fn update_event(
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
    let changed = transaction.execute(
        "UPDATE host_fence_events SET
            record=$2::TEXT::jsonb, provider=$3, immutable_host_id=$4, node_id=$5,
            expected_node_boot_id=$6, expected_agent_session_epoch=$7,
            fence_attempt_id=$8, isolation_state=$9, observed_at=$10,
            state=$11, destroyed_at=$12
          WHERE event_id=$1",
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
    exactly_one(changed)
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
    desired_revision: Revision,
    placement_epoch: Epoch,
    lease_duration_ms: Option<LeaseDurationMs>,
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
        let (
            authorization_id,
            kind,
            authorized_node_id,
            host_fence_event_id,
            volume_id,
            desired_revision,
            placement_epoch,
            lease_duration_ms,
            not_after,
        ) = match &record.authorization {
            VolumeAuthorization::Takeover(authorization) => (
                authorization.authorization_id.to_string(),
                "takeover",
                authorization.authorized_node_id.to_string(),
                Some(authorization.host_fence_event_id.to_string()),
                authorization.volume_id.to_string(),
                authorization.desired_revision,
                authorization.new_placement_epoch,
                Some(LeaseDurationMs::new(authorization.lease_duration_ms).map_err(corrupt)?),
                authorization.not_after,
            ),
            VolumeAuthorization::DisposableRootDelete(authorization) => (
                authorization.authorization_id.to_string(),
                "disposable_root_delete",
                authorization.authorized_node_id.to_string(),
                match &authorization.isolation_basis {
                    DisposableDeleteIsolationBasis::RuntimeStopped { .. } => None,
                    DisposableDeleteIsolationBasis::HostFenceEvent { event_id } => {
                        Some(event_id.to_string())
                    }
                },
                authorization.volume_id.to_string(),
                authorization.desired_revision,
                authorization.placement_epoch,
                None,
                authorization.not_after,
            ),
        };
        Ok(Self {
            authorization_id,
            kind,
            authorized_node_id,
            host_fence_event_id,
            volume_id,
            state,
            desired_revision,
            placement_epoch,
            lease_duration_ms,
            not_after,
            consumed_at,
        })
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
            desired_revision: from_pg(row.try_get("desired_revision")?)?,
            placement_epoch: from_pg(row.try_get("placement_epoch")?)?,
            lease_duration_ms: optional_from_pg(row.try_get("lease_duration_ms")?)?,
            not_after: from_pg(row.try_get("not_after")?)?,
            consumed_at: optional_from_pg(row.try_get("consumed_at")?)?,
        })
    }
}

/// Returns only the HostFence routing key for a takeover authorization that
/// is already bounded to the authenticated Node and the current Desired
/// intent.  A wrong Node, stale Desired revision/placement or unrelated
/// volume is indistinguishable from an absent authorization and, critically,
/// does not decode or lock the protected JSON row.
pub(super) fn takeover_authorization_route_for_intent(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
    authorized_node_id: &Id,
    volume_id: &Id,
    desired_revision: Revision,
    placement_epoch: Epoch,
) -> AuthorityTxResult<Option<Id>> {
    let desired_revision = desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = placement_epoch.to_pg().map_err(corrupt)?;
    let Some(row) = transaction.query_opt(
        "SELECT host_fence_event_id
           FROM volume_authorizations
          WHERE authorization_id=$1
            AND authorized_node_id=$2
            AND kind='takeover'
            AND volume_id=$3
            AND desired_revision=$4
            AND placement_epoch=$5",
        &[
            &authorization_id.as_str(),
            &authorized_node_id.as_str(),
            &volume_id.as_str(),
            &desired_revision,
            &placement_epoch,
        ],
    )?
    else {
        return Ok(None);
    };
    let event_id: Option<String> = row.try_get("host_fence_event_id")?;
    let event_id = event_id.ok_or_else(|| corrupt(()))?;
    Ok(Some(Id::new(event_id).ok_or_else(|| corrupt(()))?))
}

/// Distinguishes the only ordinary miss after the exact routing predicate:
/// an authorization that is immutably owned by another Node. This query does
/// not decode or lock the protected authority payload. Absence, or any other
/// projection mismatch for the authenticated Node, remains stored corruption.
pub(super) fn takeover_authorization_is_owned_by_other_node(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
    authenticated_node_id: &Id,
) -> AuthorityTxResult<bool> {
    transaction
        .query_one(
            "SELECT EXISTS(
                 SELECT 1
                   FROM volume_authorizations
                  WHERE authorization_id=$1
                    AND authorized_node_id<>$2
             )",
            &[&authorization_id.as_str(), &authenticated_node_id.as_str()],
        )?
        .try_get(0)
        .map_err(Into::into)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeAuthorizationRoute {
    pub(super) kind: &'static str,
    pub(super) volume_id: Id,
    pub(super) host_fence_event_id: Option<Id>,
}

/// Reads only immutable scalar projections needed to prove that an A22
/// authorization id belongs to the authenticated Node and current wrapper.
/// The protected JSON payload is decoded only after its optional event has
/// been locked in the canonical DAG.
pub(super) fn runtime_authorization_route_for_context(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
    authorized_node_id: &Id,
    desired_revision: Revision,
    placement_epoch: Epoch,
) -> AuthorityTxResult<Option<RuntimeAuthorizationRoute>> {
    let desired_revision = desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = placement_epoch.to_pg().map_err(corrupt)?;
    let Some(row) = transaction.query_opt(
        "SELECT kind, volume_id, host_fence_event_id
           FROM volume_authorizations
          WHERE authorization_id=$1
            AND authorized_node_id=$2
            AND desired_revision=$3
            AND placement_epoch=$4",
        &[
            &authorization_id.as_str(),
            &authorized_node_id.as_str(),
            &desired_revision,
            &placement_epoch,
        ],
    )?
    else {
        return Ok(None);
    };
    let kind = static_value(
        row.try_get("kind")?,
        &["takeover", "disposable_root_delete"],
    )?;
    let volume_id = Id::new(row.try_get::<_, String>("volume_id")?)
        .ok_or_else(|| corrupt("invalid projected authorization volume id"))?;
    let host_fence_event_id = match row.try_get::<_, Option<String>>("host_fence_event_id")? {
        Some(value) => Some(
            Id::new(value).ok_or_else(|| corrupt("invalid projected authorization event id"))?,
        ),
        None => None,
    };
    Ok(Some(RuntimeAuthorizationRoute {
        kind,
        volume_id,
        host_fence_event_id,
    }))
}

/// Fresh branch check performed only after the matching Volume and product
/// rows have been locked and the cleanup evidence has been validated.
/// Authorization derivation takes the same Volume lock before inserting this
/// exact disposable-delete lineage, so release and derive cannot both commit.
/// Historical takeover records and authorizations for an older delete
/// lineage are immutable evidence, not a branch conflict for the current
/// normal Root delete. The independently indexed scalar and canonical arms
/// each bound candidate IDs before their union removes the healthy row's
/// double match; callers then fully decode at most two distinct rows.
pub(super) fn disposable_root_authorization_candidates_sql() -> String {
    format!(
        "WITH candidate_ids AS MATERIALIZED (
            (
                SELECT authorization_id
                  FROM volume_authorizations
                 WHERE volume_id=$1
                   AND kind='disposable_root_delete'
                   AND desired_revision=$2
                   AND placement_epoch=$3
                 ORDER BY authorization_id COLLATE \"C\"
                 LIMIT 2
            )
            UNION
            (
                SELECT authorization_id
                  FROM volume_authorizations
                 WHERE record->'authorization' @> jsonb_build_object(
                           'kind', 'disposable_root_delete'::text,
                           'volume_id', $1::text,
                           'desired_revision', $2::bigint,
                           'placement_epoch', $3::bigint,
                           'delete_id', $4::text
                       )
                 LIMIT 2
            )
        )
        SELECT {AUTHORIZATION_COLUMNS}
          FROM volume_authorizations
         WHERE authorization_id IN (SELECT authorization_id FROM candidate_ids)
         ORDER BY authorization_id COLLATE \"C\"
         LIMIT 2"
    )
}

pub(super) fn volume_has_disposable_root_authorization_for_delete(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
    delete_id: &Id,
    desired_revision: Revision,
    placement_epoch: Epoch,
) -> AuthorityTxResult<bool> {
    let desired_revision = desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = placement_epoch.to_pg().map_err(corrupt)?;
    let sql = disposable_root_authorization_candidates_sql();
    let rows = transaction.query(
        &sql,
        &[
            &volume_id.as_str(),
            &desired_revision,
            &placement_epoch,
            &delete_id.as_str(),
        ],
    )?;
    if rows.len() > 1 {
        return Err(corrupt(
            "multiple disposable authorizations share one current delete scope",
        ));
    }
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let authorization = decode_authorization(row)?;
    let VolumeAuthorization::DisposableRootDelete(payload) = authorization.authorization else {
        return Err(corrupt(
            "current disposable authorization scope decoded another kind",
        ));
    };
    if payload.delete_id != *delete_id {
        return Err(corrupt(
            "current disposable authorization names another delete lineage",
        ));
    }
    Ok(true)
}

/// Locks and decodes the same bounded takeover row after its HostFenceEvent
/// serialization point has been acquired.  Repeating the access predicate at
/// the authority read prevents a routing hint from becoming an authorization
/// result if the row was changed or was never in the caller's current intent.
pub(super) fn load_takeover_authorization_for_intent_update(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
    authorized_node_id: &Id,
    volume_id: &Id,
    desired_revision: Revision,
    placement_epoch: Epoch,
) -> AuthorityTxResult<Option<AuthorizationRecord>> {
    let desired_revision = desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = placement_epoch.to_pg().map_err(corrupt)?;
    let sql = format!(
        "SELECT {AUTHORIZATION_COLUMNS} FROM volume_authorizations
          WHERE authorization_id=$1
            AND authorized_node_id=$2
            AND kind='takeover'
            AND volume_id=$3
            AND desired_revision=$4
            AND placement_epoch=$5
          FOR UPDATE"
    );
    transaction
        .query_opt(
            &sql,
            &[
                &authorization_id.as_str(),
                &authorized_node_id.as_str(),
                &volume_id.as_str(),
                &desired_revision,
                &placement_epoch,
            ],
        )?
        .map(|row| decode_authorization(&row))
        .transpose()
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

pub(super) fn load_disposable_root_graph_authorizations(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
    volume_id: &Id,
    delete_id: &Id,
    desired_revision: Revision,
    placement_epoch: Epoch,
) -> AuthorityTxResult<Vec<AuthorizationRecord>> {
    let desired_revision = desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = placement_epoch.to_pg().map_err(corrupt)?;
    let sql = format!(
        "WITH candidate_ids AS MATERIALIZED (
            (SELECT authorization_id FROM volume_authorizations
              WHERE authorization_id=$1 LIMIT 2)
            UNION
            (SELECT authorization_id FROM volume_authorizations
              WHERE kind='disposable_root_delete'
                AND volume_id=$2
                AND desired_revision=$4
                AND placement_epoch=$5
              ORDER BY authorization_id COLLATE \"C\" LIMIT 2)
            UNION
            (SELECT authorization_id FROM volume_authorizations
              WHERE record->'authorization' @> jsonb_build_object(
                        'kind', 'disposable_root_delete'::text,
                        'authorization_id', $1::text
                    )
              LIMIT 2)
            UNION
            (SELECT authorization_id FROM volume_authorizations
              WHERE record->'authorization' @> jsonb_build_object(
                        'kind', 'disposable_root_delete'::text,
                        'volume_id', $2::text,
                        'desired_revision', $4::bigint,
                        'placement_epoch', $5::bigint
                    )
              LIMIT 2)
            UNION
            (SELECT authorization_id FROM volume_authorizations
              WHERE record->'authorization' @> jsonb_build_object(
                        'kind', 'disposable_root_delete'::text,
                        'delete_id', $3::text
                    )
              LIMIT 2)
         )
         SELECT {AUTHORIZATION_COLUMNS} FROM volume_authorizations
          WHERE authorization_id IN (SELECT authorization_id FROM candidate_ids)
          ORDER BY authorization_id COLLATE \"C\" LIMIT 2"
    );
    transaction
        .query(
            &sql,
            &[
                &authorization_id.as_str(),
                &volume_id.as_str(),
                &delete_id.as_str(),
                &desired_revision,
                &placement_epoch,
            ],
        )?
        .iter()
        .map(decode_authorization)
        .collect()
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
    let desired_revision = projection.desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = projection.placement_epoch.to_pg().map_err(corrupt)?;
    let lease_duration_ms = optional_to_pg(projection.lease_duration_ms)?;
    let not_after = projection.not_after.to_pg().map_err(corrupt)?;
    let consumed_at = optional_to_pg(projection.consumed_at)?;
    let inserted = transaction.execute(
        "INSERT INTO volume_authorizations (
            authorization_id, record, kind, authorized_node_id,
            host_fence_event_id, volume_id,
            state, desired_revision, placement_epoch, lease_duration_ms,
            not_after, consumed_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (authorization_id) DO NOTHING",
        &[
            &projection.authorization_id,
            &record_json,
            &projection.kind,
            &projection.authorized_node_id,
            &projection.host_fence_event_id,
            &projection.volume_id,
            &projection.state,
            &desired_revision,
            &placement_epoch,
            &lease_duration_ms,
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
    let desired_revision = projection.desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = projection.placement_epoch.to_pg().map_err(corrupt)?;
    let lease_duration_ms = optional_to_pg(projection.lease_duration_ms)?;
    let not_after = projection.not_after.to_pg().map_err(corrupt)?;
    let consumed_at = optional_to_pg(projection.consumed_at)?;
    let changed = transaction.execute(
        "UPDATE volume_authorizations SET
            record=$2::TEXT::jsonb, kind=$3, authorized_node_id=$4,
            host_fence_event_id=$5, volume_id=$6, state=$7,
            desired_revision=$8, placement_epoch=$9,
            lease_duration_ms=$10, not_after=$11, consumed_at=$12
          WHERE authorization_id=$1 AND record=$13::TEXT::jsonb",
        &[
            &projection.authorization_id,
            &record_json,
            &projection.kind,
            &projection.authorized_node_id,
            &projection.host_fence_event_id,
            &projection.volume_id,
            &projection.state,
            &desired_revision,
            &placement_epoch,
            &lease_duration_ms,
            &not_after,
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

pub(super) fn load_root_delete_completion_candidates(
    transaction: &mut Transaction<'_>,
    delete_id: &Id,
    disk_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Vec<DeleteCompletionReceipt>> {
    let sql = format!(
        "WITH candidate_ids AS MATERIALIZED (
            (SELECT delete_id FROM delete_completion_receipts
              WHERE delete_id=$1 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE volume_id=$3 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE disk_id=$2 ORDER BY delete_id COLLATE \"C\" LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE record->>'delete_id'=$1 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE record->>'disk_id'=$2 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE record->>'volume_id'=$3 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE record->'request'->>'delete_id'=$1 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE record->'request'->>'disk_id'=$2 LIMIT 2)
            UNION
            (SELECT delete_id FROM delete_completion_receipts
              WHERE record->'request'->>'volume_id'=$3 LIMIT 2)
         )
         SELECT {DELETE_COMPLETION_COLUMNS} FROM delete_completion_receipts
          WHERE delete_id IN (SELECT delete_id FROM candidate_ids)
          ORDER BY delete_id COLLATE \"C\" LIMIT 2"
    );
    transaction
        .query(
            &sql,
            &[&delete_id.as_str(), &disk_id.as_str(), &volume_id.as_str()],
        )?
        .iter()
        .map(decode_delete_completion)
        .collect()
}

// The A12 sweeper is out of scope; F1 owns only this exact row codec and
// transaction-local idempotent persistence primitive.
#[allow(dead_code)]
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

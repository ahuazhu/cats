//! Closed authority rows and their checked PostgreSQL projections.

use cats_api::runtime_reconciliation::{Epoch, FenceEpoch, Generation, Id, Revision, UnixMillis};
use cats_storage::authority::{
    project_volume_record, validate_authorization_record, validate_delete_completion_receipt,
    validate_host_fence_event, AuthorizationConsumedReceipt, AuthorizationRecord,
    AuthorizationState, DeleteCompletionReceipt, DisposableDeleteIsolationBasis, HostFenceEvent,
    HostFenceEventState, HostIsolationState, RemoteHead, VolumeAuthorization, VolumeRecord,
    VolumeRecordProjection,
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
    transition_placement_epoch, transition_lease_duration_ms";

pub(super) const EVENT_COLUMNS: &str = "
    event_id, record::text AS record_json, provider, immutable_host_id,
    node_id, expected_node_boot_id, expected_agent_session_epoch,
    fence_attempt_id, isolation_state, observed_at, state, destroyed_at";

pub(super) const AUTHORIZATION_COLUMNS: &str = "
    authorization_id, record::text AS record_json, kind,
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

// F1 deliberately exposes row creation only as a transaction-local building
// block; the API/controller wiring that will call it is a later cutover slice.
#[allow(dead_code)]
pub(super) fn insert_volume(
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
        ],
    )?;
    exactly_one(changed)
}

fn decode_volume(row: &Row) -> AuthorityTxResult<VolumeRecord> {
    let stored = volume_projection_from_row(row)?;
    let record: VolumeRecord = decode(row.try_get("record_json")?)?;
    let derived = project_volume_record(&record)?;
    if stored != derived {
        return Err(corrupt(()));
    }
    Ok(record)
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

pub(super) fn authorization_hint(
    transaction: &mut Transaction<'_>,
    authorization_id: &Id,
) -> AuthorityTxResult<Option<(Option<Id>, Id)>> {
    let Some(row) = transaction.query_opt(
        "SELECT host_fence_event_id, volume_id
           FROM volume_authorizations
          WHERE authorization_id=$1",
        &[&authorization_id.as_str()],
    )?
    else {
        return Ok(None);
    };
    let event_id = row
        .try_get::<_, Option<String>>("host_fence_event_id")?
        .map(|value| Id::new(value).ok_or_else(|| corrupt(())))
        .transpose()?;
    let volume_id = Id::new(row.try_get::<_, String>("volume_id")?).ok_or_else(|| corrupt(()))?;
    Ok(Some((event_id, volume_id)))
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
            authorization_id, record, kind, host_fence_event_id, volume_id,
            state, desired_revision, placement_epoch, lease_duration_ms,
            not_after, consumed_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (authorization_id) DO NOTHING",
        &[
            &projection.authorization_id,
            &record_json,
            &projection.kind,
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
            record=$2::TEXT::jsonb, kind=$3, host_fence_event_id=$4, volume_id=$5,
            state=$6, desired_revision=$7, placement_epoch=$8,
            lease_duration_ms=$9, not_after=$10, consumed_at=$11
          WHERE authorization_id=$1 AND record=$12::TEXT::jsonb",
        &[
            &projection.authorization_id,
            &record_json,
            &projection.kind,
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

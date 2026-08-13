//! Closed row codecs for covered product mutations.

use cats_api::runtime_reconciliation::{
    decode_desired_runtime_spec, decode_operation, encode_desired_runtime_spec, encode_operation,
    DesiredRuntimeSpec, Epoch, Generation, Hostname, Id, Operation, OperationPhase,
    OperationTerminal, Revision, RuntimeTarget, Sha256Digest, UnixMillis,
};
use cats_storage::authority::{remote_head_is_valid, AuthorityError, VolumeDurability};
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use super::pg_codec::{PgBigInt, SizeBytes};
use super::product::{
    ApiIdempotencyRequest, ApiIdempotencyResult, CatRecord, DesiredMutationRowCapability,
    DiskAdminState, DiskRecord, DiskRole, DiskSnapshotRecord, EndpointRecord, ExactContentType,
    HostnameDesiredLookup, PersistentDiskInitialization, RuntimeOperationRead,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{internal, Result, Store};

pub(super) const CAT_COLUMNS: &str =
    "cat_id, record::text AS record_json, workspace_id, name, created_at";
const ENDPOINT_COLUMNS: &str = "
    endpoint_id, record::text AS record_json, workspace_id, cat_id, name,
    created_at";
pub(super) const DISK_COLUMNS: &str = "
    disk_id, record::text AS record_json, workspace_id, name, volume_id,
    size_bytes, durability, created_at, admin_state, delete_id, role_kind,
    root_cat_id, initialization_kind, initialization_token, filesystem_uuid,
    expected_blank_generation, expected_blank_root_hash,
    expected_blank_root_object_id, initialized_generation,
    initialized_root_hash, initialized_root_object_id, initialized_at";
const DISK_SNAPSHOT_COLUMNS: &str = "
    snapshot_id, record::text AS record_json, disk_id, volume_id, size_bytes,
    head_generation, head_root_hash, head_root_object_id, created_at";
pub(super) const DESIRED_COLUMNS: &str = "
    cat_id, record::text AS record_json, workspace_id, desired_revision,
    spec_digest, target, node_id, placement_epoch";
const HOSTNAME_LOOKUP_COLUMNS: &str = "
    hostname, record::text AS record_json, workspace_id, cat_id, endpoint_id,
    desired_revision";
const OPERATION_COLUMNS: &str = "
    operation_id, record::text AS record_json, workspace_id, cat_id,
    desired_revision, desired_spec_digest, node_id, placement_epoch, target,
    phase, terminal_kind, created_at, updated_at";
const API_RESULT_COLUMNS: &str = "
    authenticated_workspace_id, canonical_route, idempotency_key,
    request_fingerprint, http_status, content_type, response_body, created_at";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatProjection {
    cat_id: String,
    workspace_id: String,
    name: String,
    created_at: UnixMillis,
}

impl CatProjection {
    fn from_record(record: &CatRecord) -> Self {
        Self {
            cat_id: record.cat_id.to_string(),
            workspace_id: record.workspace_id.to_string(),
            name: record.name.to_string(),
            created_at: record.created_at,
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            cat_id: row.try_get("cat_id")?,
            workspace_id: row.try_get("workspace_id")?,
            name: row.try_get("name")?,
            created_at: from_pg(row.try_get("created_at")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointProjection {
    endpoint_id: String,
    workspace_id: String,
    cat_id: String,
    name: String,
    created_at: UnixMillis,
}

impl EndpointProjection {
    fn from_record(record: &EndpointRecord) -> Self {
        Self {
            endpoint_id: record.endpoint_id.to_string(),
            workspace_id: record.workspace_id.to_string(),
            cat_id: record.cat_id.to_string(),
            name: record.name.to_string(),
            created_at: record.created_at,
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            endpoint_id: row.try_get("endpoint_id")?,
            workspace_id: row.try_get("workspace_id")?,
            cat_id: row.try_get("cat_id")?,
            name: row.try_get("name")?,
            created_at: from_pg(row.try_get("created_at")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostnameLookupProjection {
    hostname: String,
    workspace_id: String,
    cat_id: String,
    endpoint_id: String,
    desired_revision: Revision,
}

impl HostnameLookupProjection {
    fn from_record(record: &HostnameDesiredLookup) -> Self {
        Self {
            hostname: record.hostname.to_string(),
            workspace_id: record.workspace_id.to_string(),
            cat_id: record.cat_id.to_string(),
            endpoint_id: record.endpoint_id.to_string(),
            desired_revision: record.desired_revision,
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            hostname: row.try_get("hostname")?,
            workspace_id: row.try_get("workspace_id")?,
            cat_id: row.try_get("cat_id")?,
            endpoint_id: row.try_get("endpoint_id")?,
            desired_revision: from_pg(row.try_get("desired_revision")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiskProjection {
    disk_id: String,
    workspace_id: String,
    name: String,
    volume_id: String,
    size_bytes: SizeBytes,
    durability: String,
    created_at: UnixMillis,
    admin_state: String,
    delete_id: Option<String>,
    role_kind: String,
    root_cat_id: Option<String>,
    initialization_kind: Option<String>,
    initialization_token: Option<String>,
    filesystem_uuid: Option<String>,
    expected_blank_generation: Option<Generation>,
    expected_blank_root_hash: Option<String>,
    expected_blank_root_object_id: Option<String>,
    initialized_generation: Option<Generation>,
    initialized_root_hash: Option<String>,
    initialized_root_object_id: Option<String>,
    initialized_at: Option<UnixMillis>,
}

impl DiskProjection {
    fn from_record(record: &DiskRecord) -> AuthorityTxResult<Self> {
        validate_disk(record)?;
        let (admin_state, delete_id) = match &record.admin_state {
            DiskAdminState::Active => ("active", None),
            DiskAdminState::Deleting { delete_id } => ("deleting", Some(delete_id.to_string())),
        };
        let durability = match record.durability {
            VolumeDurability::Strict => "strict",
            VolumeDurability::Relaxed => "relaxed",
        };
        let (
            role_kind,
            root_cat_id,
            initialization_kind,
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            initialized_at,
        ) = match &record.role {
            DiskRole::Root { cat_id } => (
                "root",
                Some(cat_id.to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            DiskRole::Persistent { initialization } => match initialization.as_ref() {
                PersistentDiskInitialization::Uninitialized {
                    initialization_token,
                    filesystem_uuid,
                    expected_blank_head,
                } => (
                    "persistent",
                    None,
                    Some("uninitialized"),
                    Some(initialization_token.to_string()),
                    Some(filesystem_uuid.to_string()),
                    Some(expected_blank_head),
                    None,
                    None,
                ),
                PersistentDiskInitialization::Initialized {
                    initialization_token,
                    filesystem_uuid,
                    expected_blank_head,
                    initialized_head,
                    initialized_at,
                } => (
                    "persistent",
                    None,
                    Some("initialized"),
                    Some(initialization_token.to_string()),
                    Some(filesystem_uuid.to_string()),
                    Some(expected_blank_head),
                    Some(initialized_head),
                    Some(*initialized_at),
                ),
            },
        };
        Ok(Self {
            disk_id: record.disk_id.to_string(),
            workspace_id: record.workspace_id.to_string(),
            name: record.name.to_string(),
            volume_id: record.volume_id.to_string(),
            size_bytes: SizeBytes::new(record.size_bytes).map_err(corrupt)?,
            durability: durability.to_owned(),
            created_at: record.created_at,
            admin_state: admin_state.to_owned(),
            delete_id,
            role_kind: role_kind.to_owned(),
            root_cat_id,
            initialization_kind: initialization_kind.map(str::to_owned),
            initialization_token,
            filesystem_uuid,
            expected_blank_generation: expected_blank_head.map(|head| head.generation),
            expected_blank_root_hash: expected_blank_head
                .and_then(|head| head.root_hash.as_ref().map(ToString::to_string)),
            expected_blank_root_object_id: expected_blank_head
                .and_then(|head| head.root_object_id.as_ref().map(ToString::to_string)),
            initialized_generation: initialized_head.map(|head| head.generation),
            initialized_root_hash: initialized_head
                .and_then(|head| head.root_hash.as_ref().map(ToString::to_string)),
            initialized_root_object_id: initialized_head
                .and_then(|head| head.root_object_id.as_ref().map(ToString::to_string)),
            initialized_at,
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            disk_id: row.try_get("disk_id")?,
            workspace_id: row.try_get("workspace_id")?,
            name: row.try_get("name")?,
            volume_id: row.try_get("volume_id")?,
            size_bytes: from_pg(row.try_get("size_bytes")?)?,
            durability: closed_text(row.try_get("durability")?, &["strict", "relaxed"])?.to_owned(),
            created_at: from_pg(row.try_get("created_at")?)?,
            admin_state: closed_text(row.try_get("admin_state")?, &["active", "deleting"])?
                .to_owned(),
            delete_id: row.try_get("delete_id")?,
            role_kind: closed_text(row.try_get("role_kind")?, &["root", "persistent"])?.to_owned(),
            root_cat_id: row.try_get("root_cat_id")?,
            initialization_kind: row
                .try_get::<_, Option<String>>("initialization_kind")?
                .map(|value| closed_text(value, &["uninitialized", "initialized"]))
                .transpose()?
                .map(str::to_owned),
            initialization_token: row.try_get("initialization_token")?,
            filesystem_uuid: row.try_get("filesystem_uuid")?,
            expected_blank_generation: optional_from_pg(row.try_get("expected_blank_generation")?)?,
            expected_blank_root_hash: row.try_get("expected_blank_root_hash")?,
            expected_blank_root_object_id: row.try_get("expected_blank_root_object_id")?,
            initialized_generation: optional_from_pg(row.try_get("initialized_generation")?)?,
            initialized_root_hash: row.try_get("initialized_root_hash")?,
            initialized_root_object_id: row.try_get("initialized_root_object_id")?,
            initialized_at: optional_from_pg(row.try_get("initialized_at")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiskSnapshotProjection {
    snapshot_id: String,
    disk_id: String,
    volume_id: String,
    size_bytes: SizeBytes,
    head_generation: Generation,
    head_root_hash: Option<String>,
    head_root_object_id: Option<String>,
    created_at: UnixMillis,
}

impl DiskSnapshotProjection {
    fn from_record(record: &DiskSnapshotRecord) -> AuthorityTxResult<Self> {
        validate_disk_snapshot(record)?;
        Ok(Self {
            snapshot_id: record.snapshot_id.to_string(),
            disk_id: record.disk_id.to_string(),
            volume_id: record.volume_id.to_string(),
            size_bytes: SizeBytes::new(record.size_bytes).map_err(corrupt)?,
            head_generation: record.head.generation,
            head_root_hash: record.head.root_hash.as_ref().map(ToString::to_string),
            head_root_object_id: record.head.root_object_id.as_ref().map(ToString::to_string),
            created_at: record.created_at,
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            snapshot_id: row.try_get("snapshot_id")?,
            disk_id: row.try_get("disk_id")?,
            volume_id: row.try_get("volume_id")?,
            size_bytes: from_pg(row.try_get("size_bytes")?)?,
            head_generation: from_pg(row.try_get("head_generation")?)?,
            head_root_hash: row.try_get("head_root_hash")?,
            head_root_object_id: row.try_get("head_root_object_id")?,
            created_at: from_pg(row.try_get("created_at")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredProjection {
    cat_id: String,
    workspace_id: String,
    desired_revision: Revision,
    spec_digest: String,
    target: String,
    node_id: String,
    placement_epoch: Epoch,
}

impl DesiredProjection {
    fn from_record(record: &DesiredRuntimeSpec) -> AuthorityTxResult<Self> {
        encode_desired_runtime_spec(record).map_err(corrupt)?;
        Ok(Self {
            cat_id: record.cat_id.to_string(),
            workspace_id: record.workspace_id.to_string(),
            desired_revision: record.desired_revision,
            spec_digest: record.spec_digest.to_string(),
            target: target_text(record.target).to_owned(),
            node_id: record.placement.node_id.to_string(),
            placement_epoch: record.placement.placement_epoch,
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            cat_id: row.try_get("cat_id")?,
            workspace_id: row.try_get("workspace_id")?,
            desired_revision: from_pg(row.try_get("desired_revision")?)?,
            spec_digest: parse_digest(row.try_get("spec_digest")?)?.to_string(),
            target: closed_text(
                row.try_get("target")?,
                &["running", "suspended", "warm", "cold", "deleted"],
            )?
            .to_owned(),
            node_id: row.try_get("node_id")?,
            placement_epoch: from_pg(row.try_get("placement_epoch")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperationProjection {
    operation_id: String,
    workspace_id: String,
    cat_id: String,
    desired_revision: Revision,
    desired_spec_digest: String,
    node_id: String,
    placement_epoch: Epoch,
    target: String,
    phase: String,
    terminal_kind: Option<String>,
    created_at: UnixMillis,
    updated_at: UnixMillis,
}

impl OperationProjection {
    fn from_record(record: &Operation) -> AuthorityTxResult<Self> {
        encode_operation(record).map_err(corrupt)?;
        Ok(Self {
            operation_id: record.operation_id.to_string(),
            workspace_id: record.workspace_id.to_string(),
            cat_id: record.cat_id.to_string(),
            desired_revision: record.desired_revision,
            desired_spec_digest: record.desired_spec_digest.to_string(),
            node_id: record.placement.node_id.to_string(),
            placement_epoch: record.placement.placement_epoch,
            target: target_text(record.target).to_owned(),
            phase: phase_text(record.phase).to_owned(),
            terminal_kind: terminal_text(record.terminal.as_ref()).map(str::to_owned),
            created_at: record.created_at_unix_ms,
            updated_at: record.updated_at_unix_ms,
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            operation_id: row.try_get("operation_id")?,
            workspace_id: row.try_get("workspace_id")?,
            cat_id: row.try_get("cat_id")?,
            desired_revision: from_pg(row.try_get("desired_revision")?)?,
            desired_spec_digest: parse_digest(row.try_get("desired_spec_digest")?)?.to_string(),
            node_id: row.try_get("node_id")?,
            placement_epoch: from_pg(row.try_get("placement_epoch")?)?,
            target: closed_text(
                row.try_get("target")?,
                &["running", "suspended", "warm", "cold", "deleted"],
            )?
            .to_owned(),
            phase: closed_text(
                row.try_get("phase")?,
                &["pending", "succeeded", "failed", "superseded"],
            )?
            .to_owned(),
            terminal_kind: row
                .try_get::<_, Option<String>>("terminal_kind")?
                .map(|value| closed_text(value, &["succeeded", "failed", "superseded"]))
                .transpose()?
                .map(str::to_owned),
            created_at: from_pg(row.try_get("created_at")?)?,
            updated_at: from_pg(row.try_get("updated_at")?)?,
        })
    }
}

pub(super) fn insert_cat(
    transaction: &mut Transaction<'_>,
    record: &CatRecord,
) -> AuthorityTxResult<()> {
    let projection = CatProjection::from_record(record);
    let json = encode_json(record)?;
    let created_at = projection.created_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO cat_records (cat_id, record, workspace_id, name, created_at)
         VALUES ($1, $2::TEXT::jsonb, $3, $4, $5)",
        &[
            &projection.cat_id,
            &json,
            &projection.workspace_id,
            &projection.name,
            &created_at,
        ],
    )?)
}

pub(super) fn load_cat_by_id_for_update(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CatRecord>> {
    let sql = format!("SELECT {CAT_COLUMNS} FROM cat_records WHERE cat_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_cat(&row))
        .transpose()
}

pub(super) fn load_cat_by_id_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CatRecord>> {
    let sql = format!("SELECT {CAT_COLUMNS} FROM cat_records WHERE cat_id=$1");
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_cat(&row))
        .transpose()
}

pub(super) fn load_cat_by_name_unlocked(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    name: &Id,
) -> AuthorityTxResult<Option<CatRecord>> {
    let sql = format!("SELECT {CAT_COLUMNS} FROM cat_records WHERE workspace_id=$1 AND name=$2");
    transaction
        .query_opt(&sql, &[&workspace_id.as_str(), &name.as_str()])?
        .map(|row| decode_cat(&row))
        .transpose()
}

pub(super) fn load_root_disk_by_cat_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<DiskRecord>> {
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records
          WHERE role_kind='root' AND root_cat_id=$1"
    );
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_disk(&row))
        .transpose()
}

pub(super) fn decode_cat(row: &Row) -> AuthorityTxResult<CatRecord> {
    let stored = CatProjection::from_row(row)?;
    let record: CatRecord = decode_json(row.try_get("record_json")?)?;
    if stored != CatProjection::from_record(&record) {
        return Err(corrupt(()));
    }
    Ok(record)
}

pub(super) fn insert_endpoint(
    transaction: &mut Transaction<'_>,
    record: &EndpointRecord,
) -> AuthorityTxResult<()> {
    let projection = EndpointProjection::from_record(record);
    let json = encode_json(record)?;
    let created_at = projection.created_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO endpoint_records (
            endpoint_id, record, workspace_id, cat_id, name, created_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6)",
        &[
            &projection.endpoint_id,
            &json,
            &projection.workspace_id,
            &projection.cat_id,
            &projection.name,
            &created_at,
        ],
    )?)
}

pub(super) fn load_endpoint_by_id_for_update(
    transaction: &mut Transaction<'_>,
    endpoint_id: &Id,
) -> AuthorityTxResult<Option<EndpointRecord>> {
    let sql =
        format!("SELECT {ENDPOINT_COLUMNS} FROM endpoint_records WHERE endpoint_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&endpoint_id.as_str()])?
        .map(|row| decode_endpoint(&row))
        .transpose()
}

pub(super) fn load_endpoint_by_id_unlocked(
    transaction: &mut Transaction<'_>,
    endpoint_id: &Id,
) -> AuthorityTxResult<Option<EndpointRecord>> {
    let sql = format!("SELECT {ENDPOINT_COLUMNS} FROM endpoint_records WHERE endpoint_id=$1");
    transaction
        .query_opt(&sql, &[&endpoint_id.as_str()])?
        .map(|row| decode_endpoint(&row))
        .transpose()
}

pub(super) fn load_endpoint_by_cat_name_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
    name: &Id,
) -> AuthorityTxResult<Option<EndpointRecord>> {
    let sql =
        format!("SELECT {ENDPOINT_COLUMNS} FROM endpoint_records WHERE cat_id=$1 AND name=$2");
    transaction
        .query_opt(&sql, &[&cat_id.as_str(), &name.as_str()])?
        .map(|row| decode_endpoint(&row))
        .transpose()
}

fn decode_endpoint(row: &Row) -> AuthorityTxResult<EndpointRecord> {
    let stored = EndpointProjection::from_row(row)?;
    let record: EndpointRecord = decode_json(row.try_get("record_json")?)?;
    if stored != EndpointProjection::from_record(&record) {
        return Err(corrupt(()));
    }
    Ok(record)
}

pub(super) fn insert_disk(
    transaction: &mut Transaction<'_>,
    record: &DiskRecord,
) -> AuthorityTxResult<()> {
    let projection = DiskProjection::from_record(record)?;
    let json = encode_json(record)?;
    let size_bytes = projection.size_bytes.to_pg().map_err(corrupt)?;
    let created_at = projection.created_at.to_pg().map_err(corrupt)?;
    let expected_blank_generation = optional_to_pg(projection.expected_blank_generation)?;
    let initialized_generation = optional_to_pg(projection.initialized_generation)?;
    let initialized_at = optional_to_pg(projection.initialized_at)?;
    exactly_one(transaction.execute(
        "INSERT INTO disk_records (
            disk_id, record, workspace_id, name, volume_id, size_bytes,
            durability, created_at, admin_state, delete_id, role_kind,
            root_cat_id, initialization_kind, initialization_token,
            filesystem_uuid, expected_blank_generation,
            expected_blank_root_hash, expected_blank_root_object_id,
            initialized_generation, initialized_root_hash,
            initialized_root_object_id, initialized_at
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
         )",
        &[
            &projection.disk_id,
            &json,
            &projection.workspace_id,
            &projection.name,
            &projection.volume_id,
            &size_bytes,
            &projection.durability,
            &created_at,
            &projection.admin_state,
            &projection.delete_id,
            &projection.role_kind,
            &projection.root_cat_id,
            &projection.initialization_kind,
            &projection.initialization_token,
            &projection.filesystem_uuid,
            &expected_blank_generation,
            &projection.expected_blank_root_hash,
            &projection.expected_blank_root_object_id,
            &initialized_generation,
            &projection.initialized_root_hash,
            &projection.initialized_root_object_id,
            &initialized_at,
        ],
    )?)
}

pub(super) fn load_disk_by_id_for_update(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
) -> AuthorityTxResult<Option<DiskRecord>> {
    let sql = format!("SELECT {DISK_COLUMNS} FROM disk_records WHERE disk_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&disk_id.as_str()])?
        .map(|row| decode_disk(&row))
        .transpose()
}

pub(super) fn load_disk_by_volume_unlocked(
    transaction: &mut Transaction<'_>,
    volume_id: &cats_api::runtime_reconciliation::Id,
) -> AuthorityTxResult<Option<DiskRecord>> {
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records
          WHERE volume_id=$1 OR record->>'volume_id'=$1
          ORDER BY disk_id COLLATE \"C\" LIMIT 2"
    );
    decode_at_most_one_disk(transaction.query(&sql, &[&volume_id.as_str()])?)
}

pub(super) fn delete_disk(
    transaction: &mut Transaction<'_>,
    record: &DiskRecord,
) -> AuthorityTxResult<()> {
    let projection = DiskProjection::from_record(record)?;
    let changed = transaction.execute(
        "DELETE FROM disk_records
          WHERE disk_id=$1 AND volume_id=$2 AND admin_state='deleting'
            AND delete_id=$3",
        &[
            &projection.disk_id,
            &projection.volume_id,
            &projection.delete_id,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn update_disk(
    transaction: &mut Transaction<'_>,
    record: &DiskRecord,
) -> AuthorityTxResult<()> {
    let projection = DiskProjection::from_record(record)?;
    let json = encode_json(record)?;
    let size_bytes = projection.size_bytes.to_pg().map_err(corrupt)?;
    let created_at = projection.created_at.to_pg().map_err(corrupt)?;
    let expected_blank_generation = optional_to_pg(projection.expected_blank_generation)?;
    let initialized_generation = optional_to_pg(projection.initialized_generation)?;
    let initialized_at = optional_to_pg(projection.initialized_at)?;
    let changed = transaction.execute(
        "UPDATE disk_records SET
            record=$2::TEXT::jsonb, workspace_id=$3, name=$4, volume_id=$5,
            size_bytes=$6, durability=$7, created_at=$8, admin_state=$9,
            delete_id=$10, role_kind=$11, root_cat_id=$12,
            initialization_kind=$13, initialization_token=$14,
            filesystem_uuid=$15, expected_blank_generation=$16,
            expected_blank_root_hash=$17, expected_blank_root_object_id=$18,
            initialized_generation=$19, initialized_root_hash=$20,
            initialized_root_object_id=$21, initialized_at=$22
          WHERE disk_id=$1",
        &[
            &projection.disk_id,
            &json,
            &projection.workspace_id,
            &projection.name,
            &projection.volume_id,
            &size_bytes,
            &projection.durability,
            &created_at,
            &projection.admin_state,
            &projection.delete_id,
            &projection.role_kind,
            &projection.root_cat_id,
            &projection.initialization_kind,
            &projection.initialization_token,
            &projection.filesystem_uuid,
            &expected_blank_generation,
            &projection.expected_blank_root_hash,
            &projection.expected_blank_root_object_id,
            &initialized_generation,
            &projection.initialized_root_hash,
            &projection.initialized_root_object_id,
            &initialized_at,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn load_disk_by_name_for_update(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    name: &Id,
) -> AuthorityTxResult<Option<DiskRecord>> {
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records WHERE workspace_id=$1 AND name=$2 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&workspace_id.as_str(), &name.as_str()])?
        .map(|row| decode_disk(&row))
        .transpose()
}

/// Bounded exact lookup used before the Volume -> Disk lock suffix for a
/// PersistentDisk name conflict. Both scalar and canonical JSON projections
/// participate so stored drift cannot turn an existing name into apparent
/// absence.
pub(super) fn load_any_disk_by_name_unlocked(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    name: &Id,
) -> AuthorityTxResult<Option<DiskRecord>> {
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records
          WHERE (workspace_id=$1 AND name=$2)
             OR (record->>'workspace_id'=$1 AND record->>'name'=$2)
          ORDER BY disk_id
          LIMIT 2"
    );
    decode_at_most_one_disk(transaction.query(&sql, &[&workspace_id.as_str(), &name.as_str()])?)
}

/// Lock every row that could claim this Disk identity in either projection.
pub(super) fn load_any_disk_by_id_for_update(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
) -> AuthorityTxResult<Option<DiskRecord>> {
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records
          WHERE disk_id=$1 OR record->>'disk_id'=$1
          ORDER BY disk_id
          LIMIT 2
          FOR UPDATE"
    );
    decode_at_most_one_disk(transaction.query(&sql, &[&disk_id.as_str()])?)
}

pub(super) fn load_any_disk_by_initialization_token_for_update(
    transaction: &mut Transaction<'_>,
    token: &cats_api::runtime_reconciliation::RandomId128,
) -> AuthorityTxResult<Option<DiskRecord>> {
    load_any_disk_by_persistent_identity_for_update(
        transaction,
        "initialization_token",
        "initialization_token",
        token.as_str(),
    )
}

pub(super) fn load_any_disk_by_filesystem_uuid_for_update(
    transaction: &mut Transaction<'_>,
    filesystem_uuid: &cats_api::runtime_reconciliation::RandomId128,
) -> AuthorityTxResult<Option<DiskRecord>> {
    load_any_disk_by_persistent_identity_for_update(
        transaction,
        "filesystem_uuid",
        "filesystem_uuid",
        filesystem_uuid.as_str(),
    )
}

fn load_any_disk_by_persistent_identity_for_update(
    transaction: &mut Transaction<'_>,
    column: &'static str,
    json_field: &'static str,
    value: &str,
) -> AuthorityTxResult<Option<DiskRecord>> {
    // `column` and `json_field` are closed call-site constants, never input.
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records
          WHERE {column}=$1
             OR record #>> '{{role,initialization,{json_field}}}'=$1
          ORDER BY disk_id
          LIMIT 2
          FOR UPDATE"
    );
    decode_at_most_one_disk(transaction.query(&sql, &[&value])?)
}

fn decode_at_most_one_disk(rows: Vec<Row>) -> AuthorityTxResult<Option<DiskRecord>> {
    let mut decoded = rows
        .iter()
        .map(decode_disk)
        .collect::<AuthorityTxResult<Vec<_>>>()?;
    if decoded.len() > 1 {
        return Err(corrupt(()));
    }
    Ok(decoded.pop())
}

pub(super) fn decode_disk(row: &Row) -> AuthorityTxResult<DiskRecord> {
    let stored = DiskProjection::from_row(row)?;
    let record: DiskRecord = decode_json(row.try_get("record_json")?)?;
    if stored != DiskProjection::from_record(&record)? {
        return Err(corrupt(()));
    }
    Ok(record)
}

/// Lock and strictly decode a live snapshot that protects this exact
/// Disk/Volume pair. The JSON selectors make projection drift visible instead
/// of letting a corrupt scalar move a snapshot out of the absence query.
pub(super) fn load_any_disk_snapshot_for_update(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
    volume_id: &Id,
    size_bytes: u64,
) -> AuthorityTxResult<Option<DiskSnapshotRecord>> {
    let sql = format!(
        "SELECT {DISK_SNAPSHOT_COLUMNS}
           FROM disk_snapshot_records
          WHERE disk_id=$1 OR volume_id=$2
             OR record->>'disk_id'=$1 OR record->>'volume_id'=$2
          ORDER BY snapshot_id
          LIMIT 2
          FOR UPDATE"
    );
    let rows = transaction.query(&sql, &[&disk_id.as_str(), &volume_id.as_str()])?;
    let mut first = None;
    for row in rows {
        let record = decode_disk_snapshot(&row)?;
        if record.disk_id != *disk_id
            || record.volume_id != *volume_id
            || record.size_bytes != size_bytes
        {
            return Err(corrupt(()));
        }
        first.get_or_insert(record);
    }
    Ok(first)
}

/// Repeatable-read candidate qualification before any external delete. The
/// completion transaction takes the `FOR UPDATE` version again to close a
/// snapshot-create race before metadata removal.
pub(super) fn load_any_disk_snapshot_unlocked(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
    volume_id: &Id,
    size_bytes: u64,
) -> AuthorityTxResult<Option<DiskSnapshotRecord>> {
    let sql = format!(
        "SELECT {DISK_SNAPSHOT_COLUMNS}
           FROM disk_snapshot_records
          WHERE disk_id=$1 OR volume_id=$2
             OR record->>'disk_id'=$1 OR record->>'volume_id'=$2
          ORDER BY snapshot_id
          LIMIT 2"
    );
    let rows = transaction.query(&sql, &[&disk_id.as_str(), &volume_id.as_str()])?;
    let mut first = None;
    for row in rows {
        let record = decode_disk_snapshot(&row)?;
        if record.disk_id != *disk_id
            || record.volume_id != *volume_id
            || record.size_bytes != size_bytes
        {
            return Err(corrupt(()));
        }
        first.get_or_insert(record);
    }
    Ok(first)
}

#[cfg(test)]
pub(super) fn insert_disk_snapshot(
    transaction: &mut Transaction<'_>,
    record: &DiskSnapshotRecord,
) -> AuthorityTxResult<()> {
    let projection = DiskSnapshotProjection::from_record(record)?;
    let json = encode_json(record)?;
    let size_bytes = projection.size_bytes.to_pg().map_err(corrupt)?;
    let head_generation = projection.head_generation.to_pg().map_err(corrupt)?;
    let created_at = projection.created_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO disk_snapshot_records (
            snapshot_id, record, disk_id, volume_id, size_bytes,
            head_generation, head_root_hash, head_root_object_id, created_at
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &projection.snapshot_id,
            &json,
            &projection.disk_id,
            &projection.volume_id,
            &size_bytes,
            &head_generation,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &created_at,
        ],
    )?)
}

fn decode_disk_snapshot(row: &Row) -> AuthorityTxResult<DiskSnapshotRecord> {
    let stored = DiskSnapshotProjection::from_row(row)?;
    let record: DiskSnapshotRecord = decode_json(row.try_get("record_json")?)?;
    if stored != DiskSnapshotProjection::from_record(&record)? {
        return Err(corrupt(()));
    }
    Ok(record)
}

pub(super) fn insert_desired(
    transaction: &mut Transaction<'_>,
    record: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    let projection = DesiredProjection::from_record(record)?;
    let json = String::from_utf8(encode_desired_runtime_spec(record).map_err(corrupt)?)
        .map_err(corrupt)?;
    let revision = projection.desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = projection.placement_epoch.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO desired_runtime_specs (
            cat_id, record, workspace_id, desired_revision, spec_digest,
            target, node_id, placement_epoch
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8)",
        &[
            &projection.cat_id,
            &json,
            &projection.workspace_id,
            &revision,
            &projection.spec_digest,
            &projection.target,
            &projection.node_id,
            &placement_epoch,
        ],
    )?)
}

#[allow(
    dead_code,
    reason = "A1 row CAS is consumed when A2/G4 production Desired routes are composed"
)]
pub(super) fn replace_desired(
    transaction: &mut Transaction<'_>,
    _capability: &DesiredMutationRowCapability,
    expected: &DesiredRuntimeSpec,
    record: &DesiredRuntimeSpec,
) -> AuthorityTxResult<bool> {
    let expected_projection = DesiredProjection::from_record(expected)?;
    let projection = DesiredProjection::from_record(record)?;
    let json = String::from_utf8(encode_desired_runtime_spec(record).map_err(corrupt)?)
        .map_err(corrupt)?;
    let desired_revision = projection.desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = projection.placement_epoch.to_pg().map_err(corrupt)?;
    let expected_revision = expected_projection
        .desired_revision
        .to_pg()
        .map_err(corrupt)?;
    let expected_placement_epoch = expected_projection
        .placement_epoch
        .to_pg()
        .map_err(corrupt)?;
    let changed = transaction.execute(
        "UPDATE desired_runtime_specs SET
            record=$2::TEXT::jsonb, workspace_id=$3, desired_revision=$4,
            spec_digest=$5, target=$6, node_id=$7, placement_epoch=$8
          WHERE cat_id=$1
            AND workspace_id=$9
            AND desired_revision=$10
            AND spec_digest=$11
            AND node_id=$12
            AND placement_epoch=$13",
        &[
            &projection.cat_id,
            &json,
            &projection.workspace_id,
            &desired_revision,
            &projection.spec_digest,
            &projection.target,
            &projection.node_id,
            &placement_epoch,
            &expected_projection.workspace_id,
            &expected_revision,
            &expected_projection.spec_digest,
            &expected_projection.node_id,
            &expected_placement_epoch,
        ],
    )?;
    if changed > 1 {
        return Err(corrupt(
            "Desired CAS update affected more than one current row",
        ));
    }
    Ok(changed == 1)
}

pub(super) fn load_desired_for_update(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<DesiredRuntimeSpec>> {
    let sql =
        format!("SELECT {DESIRED_COLUMNS} FROM desired_runtime_specs WHERE cat_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_desired(&row))
        .transpose()
}

pub(super) fn load_desired_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<DesiredRuntimeSpec>> {
    let sql = format!("SELECT {DESIRED_COLUMNS} FROM desired_runtime_specs WHERE cat_id=$1");
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_desired(&row))
        .transpose()
}

/// Looks up the globally unique Guest network identity without introducing a
/// second scheduler/lease table. Callers use one repeatable-read planner
/// snapshot or hold the matching candidate advisory lock in a mutation.
pub(super) fn load_desired_by_network_id_unlocked(
    transaction: &mut Transaction<'_>,
    network_id: &Id,
) -> AuthorityTxResult<Option<DesiredRuntimeSpec>> {
    let sql = format!(
        "SELECT {DESIRED_COLUMNS} FROM desired_runtime_specs
          WHERE record->'runtime'->'network_config'->>'network_id'=$1
          ORDER BY cat_id COLLATE \"C\" LIMIT 2"
    );
    let rows = transaction.query(&sql, &[&network_id.as_str()])?;
    if rows.len() > 1 {
        return Err(corrupt(()));
    }
    let desired = rows.first().map(decode_desired).transpose()?;
    if desired
        .as_ref()
        .is_some_and(|desired| desired.runtime.network_config.network_id != *network_id)
    {
        return Err(corrupt(()));
    }
    Ok(desired)
}

pub(super) fn decode_desired(row: &Row) -> AuthorityTxResult<DesiredRuntimeSpec> {
    let stored = DesiredProjection::from_row(row)?;
    let json: String = row.try_get("record_json")?;
    let record = decode_desired_runtime_spec(json.as_bytes()).map_err(corrupt)?;
    if stored != DesiredProjection::from_record(&record)? {
        return Err(corrupt(()));
    }
    Ok(record)
}

pub(super) fn load_assigned_desired_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Vec<DesiredRuntimeSpec>> {
    let sql = format!(
        "SELECT {DESIRED_COLUMNS} FROM desired_runtime_specs
          WHERE node_id=$1 OR record->'placement'->>'node_id'=$1
          ORDER BY cat_id COLLATE \"C\" FOR UPDATE"
    );
    transaction
        .query(&sql, &[&node_id.as_str()])?
        .iter()
        .map(decode_desired)
        .collect()
}

pub(super) fn load_assigned_desired_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    limit: usize,
) -> AuthorityTxResult<Vec<DesiredRuntimeSpec>> {
    let limit = i64::try_from(limit).map_err(corrupt)?;
    let sql = format!(
        "SELECT {DESIRED_COLUMNS} FROM desired_runtime_specs
          WHERE node_id=$1 OR record->'placement'->>'node_id'=$1
          ORDER BY cat_id COLLATE \"C\" LIMIT $2"
    );
    transaction
        .query(&sql, &[&node_id.as_str(), &limit])?
        .iter()
        .map(decode_desired)
        .collect()
}

pub(super) fn insert_hostname_lookup(
    transaction: &mut Transaction<'_>,
    record: &HostnameDesiredLookup,
) -> AuthorityTxResult<()> {
    let projection = HostnameLookupProjection::from_record(record);
    let json = encode_json(record)?;
    let desired_revision = projection.desired_revision.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO hostname_desired_lookups (
            hostname, record, workspace_id, cat_id, endpoint_id,
            desired_revision
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6)",
        &[
            &projection.hostname,
            &json,
            &projection.workspace_id,
            &projection.cat_id,
            &projection.endpoint_id,
            &desired_revision,
        ],
    )?)
}

pub(super) fn load_hostname_lookup_for_update(
    transaction: &mut Transaction<'_>,
    hostname: &Hostname,
) -> AuthorityTxResult<Option<HostnameDesiredLookup>> {
    let sql = format!(
        "SELECT {HOSTNAME_LOOKUP_COLUMNS} FROM hostname_desired_lookups
          WHERE hostname=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&hostname.as_str()])?
        .map(|row| decode_hostname_lookup(&row))
        .transpose()
}

pub(super) fn load_hostname_lookup_unlocked(
    transaction: &mut Transaction<'_>,
    hostname: &Hostname,
) -> AuthorityTxResult<Option<HostnameDesiredLookup>> {
    let sql =
        format!("SELECT {HOSTNAME_LOOKUP_COLUMNS} FROM hostname_desired_lookups WHERE hostname=$1");
    transaction
        .query_opt(&sql, &[&hostname.as_str()])?
        .map(|row| decode_hostname_lookup(&row))
        .transpose()
}

pub(super) fn load_hostname_lookups_by_cat_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Vec<HostnameDesiredLookup>> {
    let sql = format!(
        "SELECT {HOSTNAME_LOOKUP_COLUMNS} FROM hostname_desired_lookups
          WHERE cat_id=$1 ORDER BY endpoint_id"
    );
    transaction
        .query(&sql, &[&cat_id.as_str()])?
        .iter()
        .map(decode_hostname_lookup)
        .collect()
}

#[allow(
    dead_code,
    reason = "A1 row CAS is consumed when A2/G4 production Desired routes are composed"
)]
pub(super) fn delete_hostname_lookups_by_cat(
    transaction: &mut Transaction<'_>,
    _capability: &DesiredMutationRowCapability,
    cat_id: &Id,
) -> AuthorityTxResult<u64> {
    transaction
        .execute(
            "DELETE FROM hostname_desired_lookups WHERE cat_id=$1",
            &[&cat_id.as_str()],
        )
        .map_err(AuthorityTransactionError::from)
}

fn decode_hostname_lookup(row: &Row) -> AuthorityTxResult<HostnameDesiredLookup> {
    let stored = HostnameLookupProjection::from_row(row)?;
    let record: HostnameDesiredLookup = decode_json(row.try_get("record_json")?)?;
    if stored != HostnameLookupProjection::from_record(&record) {
        return Err(corrupt(()));
    }
    Ok(record)
}

pub(super) fn insert_operation(
    transaction: &mut Transaction<'_>,
    record: &Operation,
) -> AuthorityTxResult<()> {
    let projection = OperationProjection::from_record(record)?;
    let json = String::from_utf8(encode_operation(record).map_err(corrupt)?).map_err(corrupt)?;
    let revision = projection.desired_revision.to_pg().map_err(corrupt)?;
    let placement_epoch = projection.placement_epoch.to_pg().map_err(corrupt)?;
    let created_at = projection.created_at.to_pg().map_err(corrupt)?;
    let updated_at = projection.updated_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO runtime_operations (
            operation_id, record, workspace_id, cat_id, desired_revision,
            desired_spec_digest, node_id, placement_epoch, target, phase,
            terminal_kind, created_at, updated_at
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13
         )",
        &[
            &projection.operation_id,
            &json,
            &projection.workspace_id,
            &projection.cat_id,
            &revision,
            &projection.desired_spec_digest,
            &projection.node_id,
            &placement_epoch,
            &projection.target,
            &projection.phase,
            &projection.terminal_kind,
            &created_at,
            &updated_at,
        ],
    )?)
}

pub(super) fn load_operation_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<Operation>> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} FROM runtime_operations WHERE operation_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&operation_id.as_str()])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

pub(super) fn load_operation_by_workspace_unlocked(
    store: &Store,
    workspace_id: &Id,
    operation_id: &Id,
) -> Result<RuntimeOperationRead> {
    let sql = operation_by_workspace_candidates_sql();
    let rows = store
        .with(|client| client.query(&sql, &[&workspace_id.as_str(), &operation_id.as_str()]))?;
    if rows.len() > 1 {
        return Ok(RuntimeOperationRead::Corrupt);
    }
    let Some(row) = rows.first() else {
        return Ok(RuntimeOperationRead::NotFound);
    };
    let Ok(operation) = decode_operation_row(row) else {
        return Ok(RuntimeOperationRead::Corrupt);
    };
    if operation.workspace_id != *workspace_id || operation.operation_id != *operation_id {
        return Ok(RuntimeOperationRead::Corrupt);
    }
    Ok(RuntimeOperationRead::Found(Box::new(operation)))
}

/// Find every bounded row that can claim the workspace-qualified Operation
/// key through either its scalar or canonical JSON projection. The four
/// branches are deliberately disjoint: each has its own exact two-key index
/// and reads at most two rows, so duplicate corruption cannot turn this API
/// into an unbounded scan.
pub(super) fn operation_by_workspace_candidates_sql() -> String {
    format!(
        "(SELECT {OPERATION_COLUMNS} FROM runtime_operations
           WHERE workspace_id COLLATE \"C\"=$1 AND operation_id COLLATE \"C\"=$2
           LIMIT 2)
         UNION ALL
         (SELECT {OPERATION_COLUMNS} FROM runtime_operations
           WHERE workspace_id COLLATE \"C\"=$1
             AND (record->>'operation_id') COLLATE \"C\"=$2
             AND operation_id COLLATE \"C\"<>$2
             AND operation_id COLLATE \"C\" IS DISTINCT FROM
                 (record->>'operation_id') COLLATE \"C\"
           LIMIT 2)
         UNION ALL
         (SELECT {OPERATION_COLUMNS} FROM runtime_operations
           WHERE (record->>'workspace_id') COLLATE \"C\"=$1
             AND operation_id COLLATE \"C\"=$2
             AND workspace_id COLLATE \"C\"<>$1
             AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                 (record->>'workspace_id') COLLATE \"C\"
           LIMIT 2)
         UNION ALL
         (SELECT {OPERATION_COLUMNS} FROM runtime_operations
           WHERE (record->>'workspace_id') COLLATE \"C\"=$1
             AND (record->>'operation_id') COLLATE \"C\"=$2
             AND workspace_id COLLATE \"C\"<>$1
             AND operation_id COLLATE \"C\"<>$2
             AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                 (record->>'workspace_id') COLLATE \"C\"
             AND operation_id COLLATE \"C\" IS DISTINCT FROM
                 (record->>'operation_id') COLLATE \"C\"
           LIMIT 2)"
    )
}

pub(super) fn load_operation_by_cat_revision_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
    revision: Revision,
) -> AuthorityTxResult<Option<Operation>> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} FROM runtime_operations
          WHERE cat_id=$1 AND desired_revision=$2"
    );
    let revision = revision.to_pg().map_err(corrupt)?;
    transaction
        .query_opt(&sql, &[&cat_id.as_str(), &revision])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

#[allow(
    dead_code,
    reason = "A1 row CAS is consumed when A2/G4 production Desired routes are composed"
)]
pub(super) fn load_operation_by_cat_revision_for_update(
    transaction: &mut Transaction<'_>,
    _capability: &DesiredMutationRowCapability,
    cat_id: &Id,
    revision: Revision,
) -> AuthorityTxResult<Option<Operation>> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} FROM runtime_operations
          WHERE cat_id=$1 AND desired_revision=$2 FOR UPDATE"
    );
    let revision = revision.to_pg().map_err(corrupt)?;
    transaction
        .query_opt(&sql, &[&cat_id.as_str(), &revision])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

pub(super) fn load_pending_operation_by_cat_for_update(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<Operation>> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} FROM runtime_operations
          WHERE cat_id=$1 AND phase='pending' FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

pub(super) fn update_operation(
    transaction: &mut Transaction<'_>,
    record: &Operation,
) -> AuthorityTxResult<()> {
    let projection = OperationProjection::from_record(record)?;
    let json = String::from_utf8(encode_operation(record).map_err(corrupt)?).map_err(corrupt)?;
    let updated_at = projection.updated_at.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "UPDATE runtime_operations SET
            record=$2::TEXT::jsonb, phase=$3, terminal_kind=$4, updated_at=$5
          WHERE operation_id=$1",
        &[
            &projection.operation_id,
            &json,
            &projection.phase,
            &projection.terminal_kind,
            &updated_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "runtime Operation update affected an unexpected row count",
        ));
    }
    Ok(())
}

fn decode_operation_row(row: &Row) -> AuthorityTxResult<Operation> {
    let stored = OperationProjection::from_row(row)?;
    let json: String = row.try_get("record_json")?;
    let record = decode_operation(json.as_bytes()).map_err(corrupt)?;
    if stored != OperationProjection::from_record(&record)? {
        return Err(corrupt(()));
    }
    Ok(record)
}

pub(super) fn insert_api_result(
    transaction: &mut Transaction<'_>,
    result: &ApiIdempotencyResult,
) -> AuthorityTxResult<()> {
    validate_api_result(result)?;
    let status = i16::try_from(result.http_status).map_err(corrupt)?;
    let content_type = result.content_type.map(ExactContentType::as_str);
    let created_at = result.created_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO api_idempotency_results (
            authenticated_workspace_id, canonical_route, idempotency_key,
            request_fingerprint, http_status, content_type, response_body,
            created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &result.authenticated_workspace_id.as_str(),
            &result.canonical_route.as_str(),
            &result.idempotency_key.as_str(),
            &result.request_fingerprint.as_str(),
            &status,
            &content_type,
            &result.response_body,
            &created_at,
        ],
    )?)
}

pub(super) fn load_api_result_for_update(
    transaction: &mut Transaction<'_>,
    request: &ApiIdempotencyRequest,
) -> AuthorityTxResult<Option<ApiIdempotencyResult>> {
    let sql = format!(
        "SELECT {API_RESULT_COLUMNS} FROM api_idempotency_results
          WHERE authenticated_workspace_id=$1 AND canonical_route=$2
            AND idempotency_key=$3
          FOR UPDATE"
    );
    transaction
        .query_opt(
            &sql,
            &[
                &request.authenticated_workspace_id.as_str(),
                &request.canonical_route.as_str(),
                &request.idempotency_key.as_str(),
            ],
        )?
        .map(|row| decode_api_result(&row))
        .transpose()
}

pub(super) fn load_api_result_unlocked(
    store: &Store,
    request: &ApiIdempotencyRequest,
) -> Result<Option<ApiIdempotencyResult>> {
    let sql = format!(
        "SELECT {API_RESULT_COLUMNS} FROM api_idempotency_results
          WHERE authenticated_workspace_id=$1 AND canonical_route=$2
            AND idempotency_key=$3"
    );
    let row = store.with(|client| {
        client.query_opt(
            &sql,
            &[
                &request.authenticated_workspace_id.as_str(),
                &request.canonical_route.as_str(),
                &request.idempotency_key.as_str(),
            ],
        )
    })?;
    row.map(|row| {
        decode_api_result(&row).map_err(|_| internal("stored API idempotency result is corrupt"))
    })
    .transpose()
}

fn decode_api_result(row: &Row) -> AuthorityTxResult<ApiIdempotencyResult> {
    let authenticated_workspace_id =
        Id::new(row.try_get::<_, String>("authenticated_workspace_id")?)
            .ok_or_else(|| corrupt(()))?;
    let canonical_route = cats_api::runtime_reconciliation::AsciiText::new(
        row.try_get::<_, String>("canonical_route")?,
    )
    .ok_or_else(|| corrupt(()))?;
    let idempotency_key = cats_api::runtime_reconciliation::AsciiText::new(
        row.try_get::<_, String>("idempotency_key")?,
    )
    .ok_or_else(|| corrupt(()))?;
    let request_fingerprint = parse_digest(row.try_get("request_fingerprint")?)?;
    let status: i16 = row.try_get("http_status")?;
    let http_status = u16::try_from(status).map_err(corrupt)?;
    let content_type = match row.try_get::<_, Option<String>>("content_type")? {
        None => None,
        Some(value) if value == "application/json" => Some(ExactContentType::ApplicationJson),
        Some(_) => return Err(corrupt(())),
    };
    let result = ApiIdempotencyResult {
        authenticated_workspace_id,
        canonical_route,
        idempotency_key,
        request_fingerprint,
        http_status,
        content_type,
        response_body: row.try_get("response_body")?,
        created_at: from_pg(row.try_get("created_at")?)?,
    };
    validate_api_result(&result)?;
    Ok(result)
}

fn validate_disk(record: &DiskRecord) -> AuthorityTxResult<()> {
    SizeBytes::new(record.size_bytes).map_err(corrupt)?;
    match &record.role {
        DiskRole::Root { .. } => {
            if record.name != record.disk_id {
                return Err(corrupt(()));
            }
        }
        DiskRole::Persistent { initialization } => match initialization.as_ref() {
            PersistentDiskInitialization::Uninitialized {
                expected_blank_head,
                ..
            } => {
                if expected_blank_head.generation.get() != 0
                    || !remote_head_is_valid(expected_blank_head)
                {
                    return Err(corrupt(()));
                }
            }
            PersistentDiskInitialization::Initialized {
                expected_blank_head,
                initialized_head,
                ..
            } => {
                if expected_blank_head.generation.get() != 0
                    || !remote_head_is_valid(expected_blank_head)
                    || initialized_head.generation.get() == 0
                    || !remote_head_is_valid(initialized_head)
                {
                    return Err(corrupt(()));
                }
            }
        },
    }
    Ok(())
}

fn validate_disk_snapshot(record: &DiskSnapshotRecord) -> AuthorityTxResult<()> {
    SizeBytes::new(record.size_bytes).map_err(corrupt)?;
    if !remote_head_is_valid(&record.head) {
        return Err(corrupt(()));
    }
    Ok(())
}

fn validate_api_result(result: &ApiIdempotencyResult) -> AuthorityTxResult<()> {
    if !(200..=599).contains(&result.http_status) || result.response_body.len() > 1_048_576 {
        return Err(corrupt(()));
    }
    Ok(())
}

fn target_text(target: RuntimeTarget) -> &'static str {
    match target {
        RuntimeTarget::Running => "running",
        RuntimeTarget::Suspended => "suspended",
        RuntimeTarget::Warm => "warm",
        RuntimeTarget::Cold => "cold",
        RuntimeTarget::Deleted => "deleted",
    }
}

fn phase_text(phase: OperationPhase) -> &'static str {
    match phase {
        OperationPhase::Pending => "pending",
        OperationPhase::Succeeded => "succeeded",
        OperationPhase::Failed => "failed",
        OperationPhase::Superseded => "superseded",
    }
}

fn terminal_text(terminal: Option<&OperationTerminal>) -> Option<&'static str> {
    terminal.map(|terminal| match terminal {
        OperationTerminal::Succeeded { .. } => "succeeded",
        OperationTerminal::Failed { .. } => "failed",
        OperationTerminal::Superseded { .. } => "superseded",
    })
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt(()))
}

fn closed_text(value: String, allowed: &[&'static str]) -> AuthorityTxResult<&'static str> {
    allowed
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .ok_or_else(|| corrupt(()))
}

fn encode_json<T: Serialize>(value: &T) -> AuthorityTxResult<String> {
    serde_json::to_string(value).map_err(corrupt)
}

fn decode_json<T: DeserializeOwned>(value: String) -> AuthorityTxResult<T> {
    serde_json::from_str(&value).map_err(corrupt)
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

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt(()))
    }
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

//! Scenario-idempotent Strict PersistentDisk authority for the semantic API.
//!
//! The semantic resource row supplies one immutable candidate. This module
//! owns only the PostgreSQL seam needed to create, discover and remove that
//! exact Strict volume; it does not restore retired Operation/product stores.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{FenceEpoch, Generation, Id, RandomId128};
use cats_storage::authority::{
    begin_delete, project_volume_record, BeginDeleteRequest, RemoteHead, VolumeAdminState,
    VolumeDurability, VolumeRecord,
};
use postgres::{Row, Transaction};
use serde_json::{json, Value};

use super::rows::database_now;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result, Store};

const DISK_COLUMNS: &str = "
    disk_id, record::text AS record_json, workspace_id, name, volume_id,
    size_bytes, durability, created_at, admin_state, delete_id, role_kind,
    initialization_kind, initialization_token, filesystem_uuid,
    expected_blank_generation, expected_blank_root_hash,
    expected_blank_root_object_id";

const VOLUME_COLUMNS: &str = "
    volume_id, record::text AS record_json, size_bytes, durability,
    admin_state, delete_id, gc_required, gc_id, gc_roots_digest,
    gc_started_at, head_generation, head_root_hash, head_root_object_id,
    lease_owner, lease_epoch, lease_expires_at,
    last_transition_kind, last_transition_id,
    transition_placement_epoch, transition_lease_duration_ms";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticStrictPersistentDisk {
    pub(crate) disk_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) name: Id,
    pub(crate) volume_id: Id,
    pub(crate) size_bytes: u64,
    pub(crate) initialization_token: RandomId128,
    pub(crate) filesystem_uuid: RandomId128,
    pub(crate) delete_id: Id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticStrictDeleteState {
    Absent,
    Deleting,
}

#[derive(Debug)]
struct StoredDisk {
    disk_id: String,
    record: Value,
    workspace_id: String,
    name: String,
    volume_id: String,
    size_bytes: i64,
    durability: String,
    created_at: i64,
    admin_state: String,
    delete_id: Option<String>,
    role_kind: String,
    initialization_kind: Option<String>,
    initialization_token: Option<String>,
    filesystem_uuid: Option<String>,
    expected_blank_generation: Option<i64>,
    expected_blank_root_hash: Option<String>,
    expected_blank_root_object_id: Option<String>,
}

impl StoredDisk {
    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        let record_json: String = row.try_get("record_json")?;
        let record = serde_json::from_str(&record_json).map_err(|_| corrupt_tx())?;
        Ok(Self {
            disk_id: row.try_get("disk_id")?,
            record,
            workspace_id: row.try_get("workspace_id")?,
            name: row.try_get("name")?,
            volume_id: row.try_get("volume_id")?,
            size_bytes: row.try_get("size_bytes")?,
            durability: row.try_get("durability")?,
            created_at: row.try_get("created_at")?,
            admin_state: row.try_get("admin_state")?,
            delete_id: row.try_get("delete_id")?,
            role_kind: row.try_get("role_kind")?,
            initialization_kind: row.try_get("initialization_kind")?,
            initialization_token: row.try_get("initialization_token")?,
            filesystem_uuid: row.try_get("filesystem_uuid")?,
            expected_blank_generation: row.try_get("expected_blank_generation")?,
            expected_blank_root_hash: row.try_get("expected_blank_root_hash")?,
            expected_blank_root_object_id: row.try_get("expected_blank_root_object_id")?,
        })
    }

    fn exact_identity(&self, candidate: &SemanticStrictPersistentDisk) -> bool {
        self.disk_id == candidate.disk_id.as_str()
            && self.workspace_id == candidate.workspace_id.as_str()
            && self.name == candidate.name.as_str()
            && self.volume_id == candidate.volume_id.as_str()
            && u64::try_from(self.size_bytes).ok() == Some(candidate.size_bytes)
            && self.durability == "strict"
            && self.created_at >= 0
            && self.role_kind == "persistent"
            && matches!(
                self.initialization_kind.as_deref(),
                Some("uninitialized" | "initialized")
            )
            && self.initialization_token.as_deref() == Some(candidate.initialization_token.as_str())
            && self.filesystem_uuid.as_deref() == Some(candidate.filesystem_uuid.as_str())
            && self.expected_blank_generation == Some(0)
            && self.expected_blank_root_hash.is_none()
            && self.expected_blank_root_object_id.is_none()
            && json_text(&self.record, &["disk_id"]) == Some(candidate.disk_id.as_str())
            && json_text(&self.record, &["workspace_id"]) == Some(candidate.workspace_id.as_str())
            && json_text(&self.record, &["name"]) == Some(candidate.name.as_str())
            && json_text(&self.record, &["volume_id"]) == Some(candidate.volume_id.as_str())
            && self.record.get("size_bytes").and_then(Value::as_u64) == Some(candidate.size_bytes)
            && json_text(&self.record, &["durability"]) == Some("strict")
            && json_text(&self.record, &["role", "kind"]) == Some("persistent")
            && json_text(&self.record, &["role", "initialization", "kind"])
                == self.initialization_kind.as_deref()
            && json_text(
                &self.record,
                &["role", "initialization", "initialization_token"],
            ) == Some(candidate.initialization_token.as_str())
            && json_text(&self.record, &["role", "initialization", "filesystem_uuid"])
                == Some(candidate.filesystem_uuid.as_str())
    }

    fn exact_state(&self, candidate: &SemanticStrictPersistentDisk, deleting: bool) -> bool {
        let expected_state = if deleting { "deleting" } else { "active" };
        let expected_delete = deleting.then_some(candidate.delete_id.as_str());
        self.exact_identity(candidate)
            && self.admin_state == expected_state
            && self.delete_id.as_deref() == expected_delete
            && json_text(&self.record, &["admin_state", "kind"]) == Some(expected_state)
            && json_text(&self.record, &["admin_state", "delete_id"]) == expected_delete
    }
}

impl Store {
    /// Create or discover one exact blank Strict Volume and Disk identity.
    pub(crate) fn ensure_semantic_strict_disk_created(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<()> {
        validate_candidate(candidate)?;
        self.authority_transaction(|transaction| {
            lock_candidate(transaction, candidate)?;
            let disk = load_candidate_disk(transaction, candidate)?;
            let volume = load_candidate_volume(transaction, candidate)?;
            match (disk, volume) {
                (Some(disk), Some(volume))
                    if disk.exact_state(candidate, false)
                        && exact_volume(candidate, &volume, false) =>
                {
                    Ok(())
                }
                (None, None) => {
                    insert_volume(transaction, &blank_volume(candidate))?;
                    let created_at = database_now(transaction)?.get();
                    insert_disk(transaction, candidate, created_at)
                }
                _ => Err(corrupt_tx()),
            }
        })
    }

    /// Start or discover the exact independent normal-delete transition.
    pub(crate) fn begin_semantic_strict_disk_delete(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<SemanticStrictDeleteState> {
        validate_candidate(candidate)?;
        self.authority_transaction(|transaction| {
            lock_candidate(transaction, candidate)?;
            let disk = load_candidate_disk(transaction, candidate)?;
            let volume = load_candidate_volume(transaction, candidate)?;
            let (mut disk, volume) = match (disk, volume) {
                (None, None) => return Ok(SemanticStrictDeleteState::Absent),
                (Some(disk), Some(volume)) => (disk, volume),
                _ => return Err(corrupt_tx()),
            };
            if !disk.exact_identity(candidate) || !exact_volume_identity(candidate, &volume) {
                return Err(corrupt_tx());
            }
            ensure_no_snapshot(transaction, candidate)?;
            if disk.exact_state(candidate, true) && exact_volume(candidate, &volume, true) {
                return Ok(SemanticStrictDeleteState::Deleting);
            }
            if !disk.exact_state(candidate, false)
                || !matches!(volume.admin_state, VolumeAdminState::Active)
            {
                return Err(corrupt_tx());
            }
            let request = BeginDeleteRequest {
                delete_id: candidate.delete_id.clone(),
                disk_id: candidate.disk_id.clone(),
                volume_id: candidate.volume_id.clone(),
                expected_unowned_epoch: volume.lease_epoch,
                expected_head: volume.head.clone(),
            };
            let (deleting, _) = begin_delete(&volume, &request).map_err(|_| corrupt_tx())?;
            disk.admin_state = "deleting".to_owned();
            disk.delete_id = Some(candidate.delete_id.to_string());
            disk.record["admin_state"] = json!({
                "kind": "deleting",
                "delete_id": candidate.delete_id.as_str(),
            });
            update_volume(transaction, &deleting)?;
            update_disk(transaction, &disk)?;
            Ok(SemanticStrictDeleteState::Deleting)
        })
    }

    /// Remove authority metadata after the BlobStore prefix was re-listed empty.
    pub(crate) fn complete_semantic_strict_disk_delete(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<()> {
        validate_candidate(candidate)?;
        self.authority_transaction(|transaction| {
            lock_candidate(transaction, candidate)?;
            let disk = load_candidate_disk(transaction, candidate)?;
            let volume = load_candidate_volume(transaction, candidate)?;
            let (disk, volume) = match (disk, volume) {
                (None, None) => return Ok(()),
                (Some(disk), Some(volume)) => (disk, volume),
                _ => return Err(corrupt_tx()),
            };
            if !disk.exact_state(candidate, true) || !exact_volume(candidate, &volume, true) {
                return Err(corrupt_tx());
            }
            ensure_no_snapshot(transaction, candidate)?;
            exactly_one(transaction.execute(
                "DELETE FROM disk_records
                  WHERE disk_id=$1 AND volume_id=$2
                    AND admin_state='deleting' AND delete_id=$3",
                &[
                    &candidate.disk_id.as_str(),
                    &candidate.volume_id.as_str(),
                    &candidate.delete_id.as_str(),
                ],
            )?)?;
            exactly_one(transaction.execute(
                "DELETE FROM volume_records
                  WHERE volume_id=$1 AND admin_state='deleting' AND delete_id=$2
                    AND lease_owner IS NULL AND owner_binding IS NULL",
                &[&candidate.volume_id.as_str(), &candidate.delete_id.as_str()],
            )?)
        })
    }

    pub(crate) fn semantic_strict_disk_is_absent(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<bool> {
        validate_candidate(candidate)?;
        self.authority_read_snapshot(|transaction| {
            let disk = transaction.query_opt(
                "SELECT disk_id FROM disk_records
                  WHERE disk_id=$1 OR record->>'disk_id'=$1 LIMIT 1",
                &[&candidate.disk_id.as_str()],
            )?;
            let volume = transaction.query_opt(
                "SELECT volume_id FROM volume_records
                  WHERE volume_id=$1 OR record->>'volume_id'=$1 LIMIT 1",
                &[&candidate.volume_id.as_str()],
            )?;
            match (disk.is_some(), volume.is_some()) {
                (false, false) => Ok(true),
                (true, true) => Ok(false),
                _ => Err(corrupt_tx()),
            }
        })
    }
}

fn load_candidate_disk(
    transaction: &mut Transaction<'_>,
    candidate: &SemanticStrictPersistentDisk,
) -> AuthorityTxResult<Option<StoredDisk>> {
    let sql = format!(
        "SELECT {DISK_COLUMNS} FROM disk_records
          WHERE disk_id=$1 OR record->>'disk_id'=$1
             OR (workspace_id=$2 AND name=$3)
             OR (record->>'workspace_id'=$2 AND record->>'name'=$3)
             OR initialization_token=$4
             OR record #>> '{{role,initialization,initialization_token}}'=$4
             OR filesystem_uuid=$5
             OR record #>> '{{role,initialization,filesystem_uuid}}'=$5
          ORDER BY disk_id LIMIT 2 FOR UPDATE"
    );
    let rows = transaction.query(
        &sql,
        &[
            &candidate.disk_id.as_str(),
            &candidate.workspace_id.as_str(),
            &candidate.name.as_str(),
            &candidate.initialization_token.as_str(),
            &candidate.filesystem_uuid.as_str(),
        ],
    )?;
    if rows.len() > 1 {
        return Err(corrupt_tx());
    }
    rows.first().map(StoredDisk::from_row).transpose()
}

fn load_candidate_volume(
    transaction: &mut Transaction<'_>,
    candidate: &SemanticStrictPersistentDisk,
) -> AuthorityTxResult<Option<VolumeRecord>> {
    let sql = format!(
        "SELECT {VOLUME_COLUMNS} FROM volume_records
          WHERE volume_id=$1 OR record->>'volume_id'=$1
          ORDER BY volume_id LIMIT 2 FOR UPDATE"
    );
    let rows = transaction.query(&sql, &[&candidate.volume_id.as_str()])?;
    if rows.len() > 1 {
        return Err(corrupt_tx());
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let record_json: String = row.try_get("record_json")?;
    let record: VolumeRecord = serde_json::from_str(&record_json).map_err(|_| corrupt_tx())?;
    volume_projection_matches(row, &record)
        .then_some(record)
        .ok_or_else(corrupt_tx)
        .map(Some)
}

fn volume_projection_matches(row: &Row, record: &VolumeRecord) -> bool {
    let Ok(projection) = project_volume_record(record) else {
        return false;
    };
    row.try_get::<_, String>("volume_id").ok().as_deref() == Some(&projection.volume_id)
        && row
            .try_get::<_, i64>("size_bytes")
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            == Some(projection.size_bytes)
        && row.try_get::<_, String>("durability").ok().as_deref() == Some(projection.durability)
        && row.try_get::<_, String>("admin_state").ok().as_deref() == Some(projection.admin_state)
        && row.try_get::<_, Option<String>>("delete_id").ok().flatten() == projection.delete_id
        && row.try_get::<_, bool>("gc_required").ok() == Some(projection.gc_required)
        && row.try_get::<_, Option<String>>("gc_id").ok().flatten() == projection.gc_id
        && row
            .try_get::<_, Option<String>>("gc_roots_digest")
            .ok()
            .flatten()
            == projection.gc_roots_digest
        && row
            .try_get::<_, Option<i64>>("gc_started_at")
            .ok()
            .flatten()
            == projection
                .gc_started_at
                .and_then(|value| i64::try_from(value.get()).ok())
        && row.try_get::<_, i64>("head_generation").ok()
            == i64::try_from(projection.head_generation.get()).ok()
        && row
            .try_get::<_, Option<String>>("head_root_hash")
            .ok()
            .flatten()
            == projection.head_root_hash
        && row
            .try_get::<_, Option<String>>("head_root_object_id")
            .ok()
            .flatten()
            == projection.head_root_object_id
        && row
            .try_get::<_, Option<String>>("lease_owner")
            .ok()
            .flatten()
            == projection.lease_owner
        && row.try_get::<_, i64>("lease_epoch").ok()
            == i64::try_from(projection.lease_epoch.get()).ok()
        && row
            .try_get::<_, Option<i64>>("lease_expires_at")
            .ok()
            .flatten()
            == projection
                .lease_expires_at
                .and_then(|value| i64::try_from(value.get()).ok())
        && row
            .try_get::<_, Option<String>>("last_transition_kind")
            .ok()
            .flatten()
            .as_deref()
            == projection.last_transition_kind
        && row
            .try_get::<_, Option<String>>("last_transition_id")
            .ok()
            .flatten()
            == projection.last_transition_id
        && row
            .try_get::<_, Option<i64>>("transition_placement_epoch")
            .ok()
            .flatten()
            == projection
                .transition_placement_epoch
                .and_then(|value| i64::try_from(value.get()).ok())
        && row
            .try_get::<_, Option<i64>>("transition_lease_duration_ms")
            .ok()
            .flatten()
            == projection
                .transition_lease_duration_ms
                .and_then(|value| i64::try_from(value).ok())
}

fn insert_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> AuthorityTxResult<()> {
    let projection = project_volume_record(record).map_err(|_| corrupt_tx())?;
    let record_json = serde_json::to_string(record).map_err(|_| corrupt_tx())?;
    exactly_one(
        transaction.execute(
            "INSERT INTO volume_records (
            volume_id, record, size_bytes, durability, admin_state, delete_id,
            gc_required, gc_id, gc_roots_digest, gc_started_at,
            head_generation, head_root_hash, head_root_object_id, lease_owner,
            lease_epoch, lease_expires_at, last_transition_kind,
            last_transition_id, transition_placement_epoch,
            transition_lease_duration_ms, owner_binding, owner_node_id
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, NULL, $14, NULL, NULL, NULL, NULL, NULL, NULL, NULL
         )",
            &[
                &projection.volume_id,
                &record_json,
                &to_i64(projection.size_bytes)?,
                &projection.durability,
                &projection.admin_state,
                &projection.delete_id,
                &projection.gc_required,
                &projection.gc_id,
                &projection.gc_roots_digest,
                &projection
                    .gc_started_at
                    .map(|value| to_i64(value.get()))
                    .transpose()?,
                &to_i64(projection.head_generation.get())?,
                &projection.head_root_hash,
                &projection.head_root_object_id,
                &to_i64(projection.lease_epoch.get())?,
            ],
        )?,
    )
}

fn insert_disk(
    transaction: &mut Transaction<'_>,
    candidate: &SemanticStrictPersistentDisk,
    created_at: u64,
) -> AuthorityTxResult<()> {
    let record = json!({
        "disk_id": candidate.disk_id.as_str(),
        "workspace_id": candidate.workspace_id.as_str(),
        "name": candidate.name.as_str(),
        "volume_id": candidate.volume_id.as_str(),
        "size_bytes": candidate.size_bytes,
        "durability": "strict",
        "created_at": created_at,
        "admin_state": { "kind": "active" },
        "role": {
            "kind": "persistent",
            "initialization": {
                "kind": "uninitialized",
                "initialization_token": candidate.initialization_token.as_str(),
                "filesystem_uuid": candidate.filesystem_uuid.as_str(),
                "expected_blank_head": {
                    "generation": 0,
                    "root_hash": null,
                    "root_object_id": null
                }
            }
        }
    });
    let record_json = serde_json::to_string(&record).map_err(|_| corrupt_tx())?;
    exactly_one(transaction.execute(
        "INSERT INTO disk_records (
            disk_id, record, workspace_id, name, volume_id, size_bytes,
            durability, created_at, admin_state, delete_id, role_kind,
            root_cat_id, initialization_kind, initialization_token,
            filesystem_uuid, expected_blank_generation,
            expected_blank_root_hash, expected_blank_root_object_id,
            initialized_generation, initialized_root_hash,
            initialized_root_object_id, initialized_at,
            initialization_commit_receipt_bytes,
            initialization_commit_receipt_digest
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, 'strict', $7, 'active',
            NULL, 'persistent', NULL, 'uninitialized', $8, $9, 0,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
         )",
        &[
            &candidate.disk_id.as_str(),
            &record_json,
            &candidate.workspace_id.as_str(),
            &candidate.name.as_str(),
            &candidate.volume_id.as_str(),
            &to_i64(candidate.size_bytes)?,
            &to_i64(created_at)?,
            &candidate.initialization_token.as_str(),
            &candidate.filesystem_uuid.as_str(),
        ],
    )?)
}

fn update_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> AuthorityTxResult<()> {
    let projection = project_volume_record(record).map_err(|_| corrupt_tx())?;
    let record_json = serde_json::to_string(record).map_err(|_| corrupt_tx())?;
    let lease_expires_at = projection
        .lease_expires_at
        .map(|value| to_i64(value.get()))
        .transpose()?;
    let transition_placement = projection
        .transition_placement_epoch
        .map(|value| to_i64(value.get()))
        .transpose()?;
    let transition_duration = projection
        .transition_lease_duration_ms
        .map(to_i64)
        .transpose()?;
    let gc_started_at = projection
        .gc_started_at
        .map(|value| to_i64(value.get()))
        .transpose()?;
    exactly_one(transaction.execute(
        "UPDATE volume_records SET
            record=$2::TEXT::jsonb, size_bytes=$3, durability=$4,
            admin_state=$5, delete_id=$6, gc_required=$7, gc_id=$8,
            gc_roots_digest=$9, gc_started_at=$10, head_generation=$11,
            head_root_hash=$12, head_root_object_id=$13, lease_owner=$14,
            lease_epoch=$15, lease_expires_at=$16,
            last_transition_kind=$17, last_transition_id=$18,
            transition_placement_epoch=$19,
            transition_lease_duration_ms=$20
          WHERE volume_id=$1 AND owner_binding IS NULL AND owner_node_id IS NULL",
        &[
            &projection.volume_id,
            &record_json,
            &to_i64(projection.size_bytes)?,
            &projection.durability,
            &projection.admin_state,
            &projection.delete_id,
            &projection.gc_required,
            &projection.gc_id,
            &projection.gc_roots_digest,
            &gc_started_at,
            &to_i64(projection.head_generation.get())?,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &projection.lease_owner,
            &to_i64(projection.lease_epoch.get())?,
            &lease_expires_at,
            &projection.last_transition_kind,
            &projection.last_transition_id,
            &transition_placement,
            &transition_duration,
        ],
    )?)
}

fn update_disk(transaction: &mut Transaction<'_>, disk: &StoredDisk) -> AuthorityTxResult<()> {
    let record_json = serde_json::to_string(&disk.record).map_err(|_| corrupt_tx())?;
    exactly_one(transaction.execute(
        "UPDATE disk_records SET record=$2::TEXT::jsonb,
            admin_state=$3, delete_id=$4
          WHERE disk_id=$1 AND volume_id=$5",
        &[
            &disk.disk_id,
            &record_json,
            &disk.admin_state,
            &disk.delete_id,
            &disk.volume_id,
        ],
    )?)
}

fn ensure_no_snapshot(
    transaction: &mut Transaction<'_>,
    candidate: &SemanticStrictPersistentDisk,
) -> AuthorityTxResult<()> {
    let snapshot = transaction.query_opt(
        "SELECT snapshot_id FROM disk_snapshot_records
          WHERE disk_id=$1 OR volume_id=$2
             OR record->>'disk_id'=$1 OR record->>'volume_id'=$2
          LIMIT 1 FOR UPDATE",
        &[&candidate.disk_id.as_str(), &candidate.volume_id.as_str()],
    )?;
    if snapshot.is_some() {
        return Err(AuthorityTransactionError::Application(
            ApiError::failed_precondition("PersistentDisk has a live DiskSnapshot"),
        ));
    }
    Ok(())
}

fn lock_candidate(
    transaction: &mut Transaction<'_>,
    candidate: &SemanticStrictPersistentDisk,
) -> AuthorityTxResult<()> {
    for (kind, value) in [
        (
            "disk-name",
            format!("{}:{}", candidate.workspace_id, candidate.name),
        ),
        ("disk", candidate.disk_id.to_string()),
        ("volume", candidate.volume_id.to_string()),
        (
            "disk-initialization-token",
            candidate.initialization_token.to_string(),
        ),
        (
            "disk-filesystem-uuid",
            candidate.filesystem_uuid.to_string(),
        ),
    ] {
        transaction.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':semantic-disk:' || $1 || ':' || $2,
                0::BIGINT
             ))",
            &[&kind, &value],
        )?;
    }
    Ok(())
}

fn exact_volume_identity(candidate: &SemanticStrictPersistentDisk, volume: &VolumeRecord) -> bool {
    volume.volume_id == candidate.volume_id
        && volume.size_bytes == candidate.size_bytes
        && volume.durability == VolumeDurability::Strict
}

fn exact_volume(
    candidate: &SemanticStrictPersistentDisk,
    volume: &VolumeRecord,
    deleting: bool,
) -> bool {
    exact_volume_identity(candidate, volume)
        && volume.lease_owner.is_none()
        && if deleting {
            matches!(
                &volume.admin_state,
                VolumeAdminState::Deleting { delete_id } if delete_id == &candidate.delete_id
            )
        } else {
            matches!(volume.admin_state, VolumeAdminState::Active)
        }
}

fn blank_volume(candidate: &SemanticStrictPersistentDisk) -> VolumeRecord {
    VolumeRecord {
        volume_id: candidate.volume_id.clone(),
        size_bytes: candidate.size_bytes,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        gc_required: false,
        head: blank_head(),
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).expect("zero is a valid initial Volume epoch"),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).expect("zero is a valid initial generation"),
        root_hash: None,
        root_object_id: None,
    }
}

fn json_text<'a>(record: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(record, |value, key| value.get(*key))
        .and_then(Value::as_str)
}

fn validate_candidate(candidate: &SemanticStrictPersistentDisk) -> Result<()> {
    validate_prefixed_random_id(&candidate.disk_id, "disk_")?;
    validate_prefixed_random_id(&candidate.volume_id, "vol_")?;
    if candidate.size_bytes == 0
        || candidate.initialization_token == candidate.filesystem_uuid
        || candidate.delete_id == candidate.disk_id
        || candidate.delete_id == candidate.volume_id
    {
        return Err(inconsistent("candidate values are invalid"));
    }
    Ok(())
}

fn validate_prefixed_random_id(value: &Id, prefix: &str) -> Result<()> {
    let valid = value.as_str().strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !valid {
        return Err(inconsistent(format!(
            "identity must be {prefix} plus 32 lowercase hex digits"
        )));
    }
    Ok(())
}

fn to_i64(value: u64) -> AuthorityTxResult<i64> {
    i64::try_from(value).map_err(|_| corrupt_tx())
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    (changed == 1).then_some(()).ok_or_else(corrupt_tx)
}

fn corrupt_tx() -> AuthorityTransactionError {
    AuthorityTransactionError::Application(inconsistent("stored identity or projection differs"))
}

fn inconsistent(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "semantic Strict PersistentDisk authority is inconsistent: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        disk_hex: char,
        volume_hex: char,
        initialization_hex: char,
        filesystem_hex: char,
        delete_hex: char,
    ) -> SemanticStrictPersistentDisk {
        SemanticStrictPersistentDisk {
            disk_id: Id::new(format!("disk_{}", disk_hex.to_string().repeat(32))).unwrap(),
            workspace_id: Id::new("ws_strict_semantic").unwrap(),
            name: Id::new("data").unwrap(),
            volume_id: Id::new(format!("vol_{}", volume_hex.to_string().repeat(32))).unwrap(),
            size_bytes: 4 * 1024 * 1024,
            initialization_token: RandomId128::new(initialization_hex.to_string().repeat(32))
                .unwrap(),
            filesystem_uuid: RandomId128::new(filesystem_hex.to_string().repeat(32)).unwrap(),
            delete_id: Id::new(format!("delete_{}", delete_hex.to_string().repeat(32))).unwrap(),
        }
    }

    fn store() -> Store {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        store
            .with(|client| {
                client.batch_execute(
                    "INSERT INTO accounts (
                        id,slug,display_name,kind,workos_organization_id,billing_account_id,
                        personal_owner_user_id,status,created_at
                     ) VALUES (
                        'acct_strict_semantic','strict-semantic','Strict Semantic',
                        'organization','org_strict_semantic','billing_strict_semantic',
                        NULL,'active',1
                     );
                     INSERT INTO workspaces (
                        id,account_id,slug,display_name,is_default,created_at
                     ) VALUES (
                        'ws_strict_semantic','acct_strict_semantic','default','Default',TRUE,1
                     );",
                )
            })
            .unwrap();
        store
    }

    #[test]
    fn create_delete_and_name_reuse_are_exact_without_operation_identity() {
        let store = store();
        let first = candidate('1', '2', '3', '4', '5');

        store.ensure_semantic_strict_disk_created(&first).unwrap();
        store.ensure_semantic_strict_disk_created(&first).unwrap();
        store
            .with(|client| {
                let row = client.query_one(
                    "SELECT d.admin_state,v.admin_state,v.lease_epoch
                   FROM disk_records d JOIN volume_records v USING (volume_id)
                  WHERE d.disk_id=$1",
                    &[&first.disk_id.as_str()],
                )?;
                assert_eq!(row.get::<_, String>(0), "active");
                assert_eq!(row.get::<_, String>(1), "active");
                assert_eq!(row.get::<_, i64>(2), 0);
                Ok(())
            })
            .unwrap();

        assert_eq!(
            store.begin_semantic_strict_disk_delete(&first).unwrap(),
            SemanticStrictDeleteState::Deleting
        );
        assert_eq!(
            store.begin_semantic_strict_disk_delete(&first).unwrap(),
            SemanticStrictDeleteState::Deleting
        );
        store.complete_semantic_strict_disk_delete(&first).unwrap();
        store.complete_semantic_strict_disk_delete(&first).unwrap();
        assert!(store.semantic_strict_disk_is_absent(&first).unwrap());

        let replacement = candidate('6', '7', '8', '9', 'a');
        store
            .ensure_semantic_strict_disk_created(&replacement)
            .unwrap();
        assert!(!store.semantic_strict_disk_is_absent(&replacement).unwrap());
    }
}

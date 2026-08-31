//! Workspace-scoped DiskSnapshot product rows and live-root transactions.
//!
//! `disk_snapshots` retains immutable identity/tombstones. A matching
//! `disk_snapshot_records` row exists only while the snapshot is a live GC
//! root, and keeps PostgreSQL foreign keys to the exact Disk/Volume authority.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    Generation, Id, RandomId128, RemoteHead, Sha256Digest, SnapshotRestoreRequest,
    SnapshotRestoreResult,
};
use cats_storage::authority::{
    project_volume_record, restore_snapshot, AuthorityError, LastVolumeTransition,
    VolumeAdminState, VolumeDurability, VolumeRecord,
};
use postgres::{Row, Transaction};
use serde::{Deserialize, Serialize};

use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result, Store};

const SNAPSHOT_COLUMNS: &str = "
    s.snapshot_id, s.workspace_id, s.snapshot_slug, s.disk_id,
    s.disk_slug, s.volume_id, s.size_bytes, s.captured_generation,
    r.record::text AS snapshot_record_json, r.head_generation,
    r.head_root_hash, r.head_root_object_id, s.created_at, s.deleted_at";

const VOLUME_COLUMNS: &str = "
    volume_id, record::text AS record_json, size_bytes, durability,
    admin_state, delete_id, gc_required, gc_id, gc_roots_digest,
    gc_started_at, head_generation, head_root_hash, head_root_object_id,
    lease_owner, lease_epoch, lease_expires_at,
    last_transition_kind, last_transition_id,
    transition_placement_epoch, transition_lease_duration_ms,
    owner_binding::text AS owner_binding_json, owner_node_id";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalDiskSnapshotRecord {
    snapshot_id: Id,
    disk_id: Id,
    volume_id: Id,
    size_bytes: u64,
    head: RemoteHead,
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPersistentDiskRecord {
    disk_id: Id,
    workspace_id: Id,
    name: Id,
    volume_id: Id,
    size_bytes: u64,
    durability: VolumeDurability,
    created_at: u64,
    admin_state: CanonicalDiskAdminState,
    role: CanonicalPersistentDiskRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CanonicalDiskAdminState {
    Active,
    Deleting { delete_id: Id },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CanonicalPersistentDiskRole {
    Persistent {
        initialization: CanonicalDiskInitialization,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CanonicalDiskInitialization {
    Uninitialized {
        initialization_token: RandomId128,
        filesystem_uuid: RandomId128,
        expected_blank_head: RemoteHead,
    },
    Initialized {
        initialization_token: RandomId128,
        filesystem_uuid: RandomId128,
        expected_blank_head: RemoteHead,
        initialized_head: RemoteHead,
        initialized_at: u64,
        commit_receipt_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSnapshotRecord {
    pub snapshot_id: String,
    pub workspace_id: String,
    pub snapshot_slug: String,
    pub disk_id: String,
    pub disk_slug: String,
    pub volume_id: String,
    pub size_bytes: i64,
    pub captured_generation: i64,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDiskSnapshot<'a> {
    pub snapshot_id: &'a str,
    pub workspace_id: &'a str,
    pub snapshot_slug: &'a str,
    pub disk_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateDiskSnapshotOutcome {
    Created(DiskSnapshotRecord),
    Existing(DiskSnapshotRecord),
    ConfigurationConflict(DiskSnapshotRecord),
    DiskNotFound,
    DiskDeleted,
    DiskNotInitialized,
    CatMustBeCold,
    DiskWriterActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteDiskSnapshotOutcome {
    Deleted(DiskSnapshotRecord),
    AlreadyDeleted(DiskSnapshotRecord),
    NotFound,
    DiskDeleted,
    DiskNotInitialized,
    CatMustBeCold,
    DiskWriterActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreDiskSnapshotOutcome {
    Restored {
        snapshot: DiskSnapshotRecord,
        result: SnapshotRestoreResult,
    },
    AlreadyRestored {
        snapshot: DiskSnapshotRecord,
        result: SnapshotRestoreResult,
    },
    NotFound,
    DiskDeleted,
    DiskNotInitialized,
    CatMustBeCold,
    DiskWriterActive,
    HeadConflict,
    AuthorityExhausted,
}

#[derive(Debug)]
struct ProductDisk {
    disk_id: String,
    workspace_id: String,
    disk_slug: String,
    size_bytes: i64,
    volume_id: String,
    filesystem_uuid: String,
    status: String,
}

#[derive(Debug)]
struct StoredDiskAuthority {
    record: CanonicalPersistentDiskRecord,
    disk_id: String,
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
    initialized_generation: Option<i64>,
    initialized_root_hash: Option<String>,
    initialized_root_object_id: Option<String>,
    initialized_at: Option<i64>,
    initialization_commit_receipt_bytes: Option<Vec<u8>>,
    initialization_commit_receipt_digest: Option<String>,
}

impl Store {
    pub fn list_current_semantic_snapshot_ids(&self, workspace_id: &str) -> Result<Vec<String>> {
        self.authority_read_snapshot(|transaction| {
            transaction
                .query(
                    "SELECT snapshot_id FROM disk_snapshots
                      WHERE workspace_id=$1 AND deleted_at IS NULL
                      ORDER BY snapshot_slug,snapshot_id",
                    &[&workspace_id],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
                .map_err(Into::into)
        })
    }

    pub fn find_current_semantic_snapshot(
        &self,
        workspace_id: &str,
        snapshot_slug: &str,
    ) -> Result<Option<DiskSnapshotRecord>> {
        self.authority_read_snapshot(|transaction| {
            load_current_snapshot(transaction, workspace_id, snapshot_slug, false)
        })
    }

    pub fn find_semantic_snapshot_by_id(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<DiskSnapshotRecord>> {
        self.authority_read_snapshot(|transaction| {
            load_snapshot_by_id(transaction, snapshot_id, false)
                .map(|value| value.map(|(row, _)| row))
        })
    }

    /// Read the current remotely durable generation without exposing the
    /// internal Root tuple. An initialized normal Disk must join an exact
    /// canonical Disk/Volume authority row; an uninitialized Disk has no
    /// public head yet, and a deleted product row has no storage authority.
    pub fn semantic_disk_head_generation(
        &self,
        product: &super::PersistentDiskRecord,
    ) -> Result<Option<i64>> {
        if product.status == "deleted" {
            return Ok(None);
        }
        self.authority_read_snapshot(|transaction| {
            let Some(current) =
                load_product_disk(transaction, &product.workspace_id, &product.disk_id, false)?
            else {
                return Err(corrupt());
            };
            if current.disk_slug != product.disk_slug
                || current.volume_id != product.volume_id
                || current.size_bytes != product.size_bytes
                || current.filesystem_uuid != product.filesystem_uuid
                || current.status != product.status
            {
                return Err(corrupt());
            }
            let disk = load_disk_authority(transaction, &product.disk_id, false)?;
            if !disk_identity_exact(&disk, &current) {
                return Err(corrupt());
            }
            if !disk_is_initialized(&disk) {
                return Ok(None);
            }
            let volume = load_volume(transaction, &product.volume_id, false)?;
            if !volume_identity_exact(&volume, &current)
                || !matches!(volume.admin_state, VolumeAdminState::Active)
                || !head_is_same_or_later(&volume.head, &initialized_head(&disk)?)
            {
                return Err(corrupt());
            }
            Ok(Some(generation_to_i64(volume.head.generation)?))
        })
    }

    pub fn create_semantic_disk_snapshot(
        &self,
        request: NewDiskSnapshot<'_>,
    ) -> Result<CreateDiskSnapshotOutcome> {
        self.authority_transaction(|transaction| {
            lock_snapshot_slug(transaction, request.workspace_id, request.snapshot_slug)?;
            if let Some(existing) = load_current_snapshot(
                transaction,
                request.workspace_id,
                request.snapshot_slug,
                true,
            )? {
                return Ok(if existing.disk_id == request.disk_id {
                    CreateDiskSnapshotOutcome::Existing(existing)
                } else {
                    CreateDiskSnapshotOutcome::ConfigurationConflict(existing)
                });
            }
            lock_semantic_disk(transaction, request.disk_id)?;
            let Some(product) =
                load_product_disk(transaction, request.workspace_id, request.disk_id, true)?
            else {
                return Ok(CreateDiskSnapshotOutcome::DiskNotFound);
            };
            if product.status != "normal" {
                return Ok(CreateDiskSnapshotOutcome::DiskDeleted);
            }
            if !bound_cat_is_stable_cold(transaction, &product)? {
                return Ok(CreateDiskSnapshotOutcome::CatMustBeCold);
            }
            let disk = load_disk_authority(transaction, &product.disk_id, true)?;
            if !disk_identity_exact(&disk, &product) {
                return Err(corrupt());
            }
            if !disk_is_initialized(&disk) {
                return Ok(CreateDiskSnapshotOutcome::DiskNotInitialized);
            }
            let volume = load_volume(transaction, &product.volume_id, true)?;
            if !volume_identity_exact(&volume, &product)
                || !head_is_same_or_later(&volume.head, &initialized_head(&disk)?)
                || volume.head.generation.get() == 0
            {
                return Err(corrupt());
            }
            if !matches!(volume.admin_state, VolumeAdminState::Active) {
                return Ok(CreateDiskSnapshotOutcome::DiskDeleted);
            }
            if volume.lease_owner.is_some() {
                return Ok(CreateDiskSnapshotOutcome::DiskWriterActive);
            }

            let created_at: i64 = transaction
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
                    &[],
                )?
                .get(0);
            transaction.execute(
                "INSERT INTO disk_snapshots (
                    snapshot_id,workspace_id,snapshot_slug,disk_id,disk_slug,
                    volume_id,size_bytes,captured_generation,created_at,deleted_at
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL)",
                &[
                    &request.snapshot_id,
                    &request.workspace_id,
                    &request.snapshot_slug,
                    &request.disk_id,
                    &product.disk_slug,
                    &product.volume_id,
                    &product.size_bytes,
                    &generation_to_i64(volume.head.generation)?,
                    &created_at,
                ],
            )?;
            let record = CanonicalDiskSnapshotRecord {
                snapshot_id: parse_id(request.snapshot_id)?,
                disk_id: parse_id(&product.disk_id)?,
                volume_id: parse_id(&product.volume_id)?,
                size_bytes: u64::try_from(product.size_bytes).map_err(|_| corrupt())?,
                head: volume.head.clone(),
                created_at: u64::try_from(created_at).map_err(|_| corrupt())?,
            };
            let record_json = serde_json::to_string(&record).map_err(|_| corrupt())?;
            transaction.execute(
                "INSERT INTO disk_snapshot_records (
                    snapshot_id,record,disk_id,volume_id,size_bytes,
                    head_generation,head_root_hash,head_root_object_id,created_at
                 ) VALUES ($1,$2::TEXT::jsonb,$3,$4,$5,$6,$7,$8,$9)",
                &[
                    &request.snapshot_id,
                    &record_json,
                    &request.disk_id,
                    &product.volume_id,
                    &product.size_bytes,
                    &generation_to_i64(volume.head.generation)?,
                    &volume.head.root_hash.as_ref().map(ToString::to_string),
                    &volume.head.root_object_id.as_ref().map(ToString::to_string),
                    &created_at,
                ],
            )?;
            let created = load_snapshot_by_id(transaction, request.snapshot_id, true)?
                .and_then(|(record, head)| head.map(|_| record))
                .ok_or_else(corrupt)?;
            Ok(CreateDiskSnapshotOutcome::Created(created))
        })
    }

    /// Remove the live-root row only while the same Disk remains initialized,
    /// Strict, Active, Unowned and (if bound) on a stable Cold Cat.
    pub fn delete_semantic_disk_snapshot(
        &self,
        workspace_id: &str,
        snapshot_id: &str,
    ) -> Result<DeleteDiskSnapshotOutcome> {
        self.authority_transaction(|transaction| {
            let Some(identity) = transaction.query_opt(
                "SELECT snapshot_slug,disk_id FROM disk_snapshots
                  WHERE snapshot_id=$1 AND workspace_id=$2",
                &[&snapshot_id, &workspace_id],
            )?
            else {
                return Ok(DeleteDiskSnapshotOutcome::NotFound);
            };
            let snapshot_slug: String = identity.get(0);
            let original_disk_id: String = identity.get(1);
            lock_snapshot_slug(transaction, workspace_id, &snapshot_slug)?;
            lock_semantic_disk(transaction, &original_disk_id)?;
            let Some((identity, live_head)) = load_snapshot_by_id(transaction, snapshot_id, true)?
            else {
                return Ok(DeleteDiskSnapshotOutcome::NotFound);
            };
            if identity.workspace_id != workspace_id {
                return Ok(DeleteDiskSnapshotOutcome::NotFound);
            }
            if identity.deleted_at.is_some() {
                return Ok(DeleteDiskSnapshotOutcome::AlreadyDeleted(identity));
            }
            let live_head = live_head.ok_or_else(corrupt)?;

            let Some(product) =
                load_product_disk(transaction, workspace_id, &original_disk_id, true)?
            else {
                return Err(corrupt());
            };
            if product.status != "normal" {
                return Ok(DeleteDiskSnapshotOutcome::DiskDeleted);
            }
            if !snapshot_matches_product(&identity, &product)
                || generation_to_i64(live_head.generation)? != identity.captured_generation
            {
                return Err(corrupt());
            }
            if !bound_cat_is_stable_cold(transaction, &product)? {
                return Ok(DeleteDiskSnapshotOutcome::CatMustBeCold);
            }
            let disk = load_disk_authority(transaction, &product.disk_id, true)?;
            if !disk_identity_exact(&disk, &product) {
                return Err(corrupt());
            }
            if !disk_is_initialized(&disk) {
                return Ok(DeleteDiskSnapshotOutcome::DiskNotInitialized);
            }
            let volume = load_volume(transaction, &product.volume_id, true)?;
            if !volume_identity_exact(&volume, &product)
                || !matches!(volume.admin_state, VolumeAdminState::Active)
            {
                return Ok(DeleteDiskSnapshotOutcome::DiskDeleted);
            }
            if volume.lease_owner.is_some() {
                return Ok(DeleteDiskSnapshotOutcome::DiskWriterActive);
            }
            let deleted_at: i64 = transaction
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
                    &[],
                )?
                .get(0);
            exactly_one(transaction.execute(
                "UPDATE disk_snapshots SET deleted_at=$3
                  WHERE snapshot_id=$1 AND workspace_id=$2 AND deleted_at IS NULL",
                &[&snapshot_id, &workspace_id, &deleted_at],
            )?)?;
            exactly_one(transaction.execute(
                "DELETE FROM disk_snapshot_records WHERE snapshot_id=$1",
                &[&snapshot_id],
            )?)?;
            let mut updated_volume = volume;
            updated_volume.gc_required = true;
            update_volume_record(transaction, &updated_volume)?;
            let deleted = load_snapshot_by_id(transaction, snapshot_id, true)?
                .map(|(record, _)| record)
                .ok_or_else(corrupt)?;
            Ok(DeleteDiskSnapshotOutcome::Deleted(deleted))
        })
    }

    /// Republish the selected live Snapshot Root to its original Disk while
    /// preserving both generation and epoch monotonicity. `expected_generation`
    /// is the caller's just-read predecessor. A response-loss retry is accepted
    /// only while the exact restore marker remains the current transition.
    pub fn restore_semantic_disk_snapshot(
        &self,
        workspace_id: &str,
        snapshot_id: &str,
        expected_generation: u64,
    ) -> Result<RestoreDiskSnapshotOutcome> {
        self.authority_transaction(|transaction| {
            let Some(lock_row) = transaction.query_opt(
                "SELECT disk_id FROM disk_snapshots
                  WHERE snapshot_id=$1 AND workspace_id=$2 AND deleted_at IS NULL",
                &[&snapshot_id, &workspace_id],
            )?
            else {
                return Ok(RestoreDiskSnapshotOutcome::NotFound);
            };
            let disk_id: String = lock_row.get(0);
            lock_semantic_disk(transaction, &disk_id)?;
            let Some((snapshot, snapshot_head)) =
                load_snapshot_by_id(transaction, snapshot_id, true)?
            else {
                return Ok(RestoreDiskSnapshotOutcome::NotFound);
            };
            if snapshot.workspace_id != workspace_id || snapshot.deleted_at.is_some() {
                return Ok(RestoreDiskSnapshotOutcome::NotFound);
            }
            let snapshot_head = snapshot_head.ok_or_else(corrupt)?;
            let Some(product) = load_product_disk(transaction, workspace_id, &disk_id, true)?
            else {
                return Err(corrupt());
            };
            if product.status != "normal" {
                return Ok(RestoreDiskSnapshotOutcome::DiskDeleted);
            }
            if !snapshot_matches_product(&snapshot, &product)
                || generation_to_i64(snapshot_head.generation)? != snapshot.captured_generation
            {
                return Err(corrupt());
            }
            if !bound_cat_is_stable_cold(transaction, &product)? {
                return Ok(RestoreDiskSnapshotOutcome::CatMustBeCold);
            }
            let disk = load_disk_authority(transaction, &product.disk_id, true)?;
            if !disk_identity_exact(&disk, &product) {
                return Err(corrupt());
            }
            if !disk_is_initialized(&disk) {
                return Ok(RestoreDiskSnapshotOutcome::DiskNotInitialized);
            }
            let volume = load_volume(transaction, &product.volume_id, true)?;
            if !volume_identity_exact(&volume, &product)
                || !matches!(volume.admin_state, VolumeAdminState::Active)
                || !head_is_same_or_later(&volume.head, &initialized_head(&disk)?)
            {
                return Err(corrupt());
            }
            if volume.lease_owner.is_some() {
                return Ok(RestoreDiskSnapshotOutcome::DiskWriterActive);
            }

            if let Some(LastVolumeTransition::SnapshotRestore { request, result }) =
                volume.last_transition.as_ref()
            {
                let exact_replay = request.snapshot_id.as_str() == snapshot_id
                    && request.disk_id.as_str() == snapshot.disk_id
                    && request.volume_id.as_str() == snapshot.volume_id
                    && request.expected_size_bytes
                        == u64::try_from(snapshot.size_bytes).map_err(|_| corrupt())?
                    && request.expected_head.generation.get() == expected_generation
                    && request.snapshot_head == snapshot_head
                    && result.snapshot_id == request.snapshot_id
                    && result.disk_id == request.disk_id
                    && result.volume_id == request.volume_id
                    && result.resulting_epoch == volume.lease_epoch
                    && result.resulting_head == volume.head;
                if exact_replay {
                    return Ok(RestoreDiskSnapshotOutcome::AlreadyRestored {
                        snapshot,
                        result: result.clone(),
                    });
                }
            }
            if volume.head.generation.get() != expected_generation {
                return Ok(RestoreDiskSnapshotOutcome::HeadConflict);
            }
            let request = SnapshotRestoreRequest {
                snapshot_id: parse_id(snapshot_id)?,
                disk_id: parse_id(&snapshot.disk_id)?,
                volume_id: parse_id(&snapshot.volume_id)?,
                expected_size_bytes: u64::try_from(snapshot.size_bytes).map_err(|_| corrupt())?,
                expected_unowned_epoch: volume.lease_epoch,
                expected_head: volume.head.clone(),
                snapshot_head,
            };
            let (updated, result) = match restore_snapshot(&volume, &request) {
                Ok(value) => value,
                Err(AuthorityError::EpochExhausted | AuthorityError::GenerationExhausted) => {
                    return Ok(RestoreDiskSnapshotOutcome::AuthorityExhausted);
                }
                Err(_) => return Err(corrupt()),
            };
            update_volume_record(transaction, &updated)?;
            Ok(RestoreDiskSnapshotOutcome::Restored { snapshot, result })
        })
    }
}

fn load_current_snapshot(
    transaction: &mut Transaction<'_>,
    workspace_id: &str,
    snapshot_slug: &str,
    lock: bool,
) -> AuthorityTxResult<Option<DiskSnapshotRecord>> {
    let suffix = if lock { "FOR UPDATE" } else { "" };
    let identity = transaction.query_opt(
        &format!(
            "SELECT snapshot_id FROM disk_snapshots
              WHERE workspace_id=$1 AND snapshot_slug=$2 AND deleted_at IS NULL
              {suffix}"
        ),
        &[&workspace_id, &snapshot_slug],
    )?;
    let Some(identity) = identity else {
        return Ok(None);
    };
    let snapshot_id: String = identity.try_get(0)?;
    let Some((record, live_head)) = load_snapshot_by_id(transaction, &snapshot_id, lock)? else {
        return Err(corrupt());
    };
    if record.workspace_id != workspace_id
        || record.snapshot_slug != snapshot_slug
        || record.deleted_at.is_some()
        || live_head.is_none()
    {
        return Err(corrupt());
    }
    Ok(Some(record))
}

fn load_snapshot_by_id(
    transaction: &mut Transaction<'_>,
    snapshot_id: &str,
    lock: bool,
) -> AuthorityTxResult<Option<(DiskSnapshotRecord, Option<RemoteHead>)>> {
    if lock {
        if transaction
            .query_opt(
                "SELECT snapshot_id FROM disk_snapshots WHERE snapshot_id=$1 FOR UPDATE",
                &[&snapshot_id],
            )?
            .is_none()
        {
            return Ok(None);
        }
        transaction.query_opt(
            "SELECT snapshot_id FROM disk_snapshot_records WHERE snapshot_id=$1 FOR UPDATE",
            &[&snapshot_id],
        )?;
    }
    transaction
        .query_opt(
            &format!(
                "SELECT {SNAPSHOT_COLUMNS}
                   FROM disk_snapshots s
                   LEFT JOIN disk_snapshot_records r USING (snapshot_id)
                  WHERE s.snapshot_id=$1"
            ),
            &[&snapshot_id],
        )?
        .map(|row| snapshot_from_joined_row(&row))
        .transpose()
}

fn snapshot_from_joined_row(
    row: &Row,
) -> AuthorityTxResult<(DiskSnapshotRecord, Option<RemoteHead>)> {
    let snapshot_id: String = row.try_get("snapshot_id")?;
    let workspace_id: String = row.try_get("workspace_id")?;
    let snapshot_slug: String = row.try_get("snapshot_slug")?;
    let disk_id: String = row.try_get("disk_id")?;
    let disk_slug: String = row.try_get("disk_slug")?;
    let volume_id: String = row.try_get("volume_id")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    let captured_generation: i64 = row.try_get("captured_generation")?;
    let record_json: Option<String> = row.try_get("snapshot_record_json")?;
    let generation: Option<i64> = row.try_get("head_generation")?;
    let root_hash: Option<String> = row.try_get("head_root_hash")?;
    let root_object_id: Option<String> = row.try_get("head_root_object_id")?;
    let created_at: i64 = row.try_get("created_at")?;
    let deleted_at: Option<i64> = row.try_get("deleted_at")?;
    if size_bytes <= 0 || captured_generation <= 0 || created_at < 0 {
        return Err(corrupt());
    }
    let product = DiskSnapshotRecord {
        snapshot_id,
        workspace_id,
        snapshot_slug,
        disk_id,
        disk_slug,
        volume_id,
        size_bytes,
        captured_generation,
        created_at,
        deleted_at,
    };
    let live_head = match (record_json, generation) {
        (Some(record_json), Some(generation)) if product.deleted_at.is_none() => {
            let head = remote_head(generation, root_hash, root_object_id)?;
            let canonical: CanonicalDiskSnapshotRecord =
                serde_json::from_str(&record_json).map_err(|_| corrupt())?;
            let exact = canonical.snapshot_id.as_str() == product.snapshot_id
                && canonical.disk_id.as_str() == product.disk_id
                && canonical.volume_id.as_str() == product.volume_id
                && i64::try_from(canonical.size_bytes).ok() == Some(product.size_bytes)
                && i64::try_from(canonical.created_at).ok() == Some(product.created_at)
                && canonical.head == head
                && generation_to_i64(head.generation)? == product.captured_generation;
            if !exact {
                return Err(corrupt());
            }
            Some(head)
        }
        (None, None) if product.deleted_at.is_some() => {
            if root_hash.is_some() || root_object_id.is_some() {
                return Err(corrupt());
            }
            None
        }
        _ => return Err(corrupt()),
    };
    Ok((product, live_head))
}

fn load_product_disk(
    transaction: &mut Transaction<'_>,
    workspace_id: &str,
    disk_id: &str,
    lock: bool,
) -> AuthorityTxResult<Option<ProductDisk>> {
    let suffix = if lock { "FOR UPDATE" } else { "" };
    transaction
        .query_opt(
            &format!(
                "SELECT disk_id,workspace_id,disk_slug,size_bytes,volume_id,
                        filesystem_uuid,status
                   FROM persistent_disks
                  WHERE disk_id=$1 AND workspace_id=$2 {suffix}"
            ),
            &[&disk_id, &workspace_id],
        )?
        .map(|row| {
            Ok(ProductDisk {
                disk_id: row.try_get(0)?,
                workspace_id: row.try_get(1)?,
                disk_slug: row.try_get(2)?,
                size_bytes: row.try_get(3)?,
                volume_id: row.try_get(4)?,
                filesystem_uuid: row.try_get(5)?,
                status: row.try_get(6)?,
            })
        })
        .transpose()
}

fn bound_cat_is_stable_cold(
    transaction: &mut Transaction<'_>,
    product: &ProductDisk,
) -> AuthorityTxResult<bool> {
    let binding = transaction.query_opt(
        "SELECT workspace_id,cat_id FROM disk_bindings WHERE disk_id=$1 FOR UPDATE",
        &[&product.disk_id],
    )?;
    let Some(binding) = binding else {
        return Ok(true);
    };
    if binding.try_get::<_, String>(0)? != product.workspace_id {
        return Err(corrupt());
    }
    let cat_id: String = binding.try_get(1)?;
    let cat = transaction.query_one(
        "SELECT workspace_id,state,current_action,node_id
           FROM cats WHERE cat_id=$1 FOR UPDATE",
        &[&cat_id],
    )?;
    Ok(cat.try_get::<_, String>(0)? == product.workspace_id
        && cat.try_get::<_, Option<String>>(1)?.as_deref() == Some("cold")
        && cat.try_get::<_, Option<String>>(2)?.is_none()
        && cat.try_get::<_, Option<String>>(3)?.is_none())
}

fn load_disk_authority(
    transaction: &mut Transaction<'_>,
    disk_id: &str,
    lock: bool,
) -> AuthorityTxResult<StoredDiskAuthority> {
    let suffix = if lock { "FOR UPDATE" } else { "" };
    let row = transaction.query_one(
        &format!(
            "SELECT record::text AS record_json,disk_id,workspace_id,name,volume_id,
                size_bytes,durability,created_at,admin_state,delete_id,
                role_kind,initialization_kind,
                initialization_token,filesystem_uuid,expected_blank_generation,
                expected_blank_root_hash,expected_blank_root_object_id,
                initialized_generation,initialized_root_hash,
                initialized_root_object_id,initialized_at,
                initialization_commit_receipt_bytes,
                initialization_commit_receipt_digest
           FROM disk_records WHERE disk_id=$1 {suffix}"
        ),
        &[&disk_id],
    )?;
    let record_json: String = row.try_get("record_json")?;
    Ok(StoredDiskAuthority {
        record: serde_json::from_str(&record_json).map_err(|_| corrupt())?,
        disk_id: row.try_get("disk_id")?,
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
        initialized_generation: row.try_get("initialized_generation")?,
        initialized_root_hash: row.try_get("initialized_root_hash")?,
        initialized_root_object_id: row.try_get("initialized_root_object_id")?,
        initialized_at: row.try_get("initialized_at")?,
        initialization_commit_receipt_bytes: row.try_get("initialization_commit_receipt_bytes")?,
        initialization_commit_receipt_digest: row
            .try_get("initialization_commit_receipt_digest")?,
    })
}

fn disk_identity_exact(disk: &StoredDiskAuthority, product: &ProductDisk) -> bool {
    let canonical = &disk.record;
    disk.disk_id == product.disk_id
        && disk.workspace_id == product.workspace_id
        && disk.name == product.disk_slug
        && disk.volume_id == product.volume_id
        && disk.size_bytes == product.size_bytes
        && disk.durability == "strict"
        && disk.created_at >= 0
        && disk.admin_state == "active"
        && disk.delete_id.is_none()
        && disk.role_kind == "persistent"
        && disk.filesystem_uuid.as_deref() == Some(product.filesystem_uuid.as_str())
        && canonical.disk_id.as_str() == product.disk_id
        && canonical.workspace_id.as_str() == product.workspace_id
        && canonical.name.as_str() == product.disk_slug
        && canonical.volume_id.as_str() == product.volume_id
        && i64::try_from(canonical.size_bytes).ok() == Some(product.size_bytes)
        && canonical.durability == VolumeDurability::Strict
        && i64::try_from(canonical.created_at).ok() == Some(disk.created_at)
        && matches!(canonical.admin_state, CanonicalDiskAdminState::Active)
        && matches!(
            canonical.role,
            CanonicalPersistentDiskRole::Persistent { .. }
        )
        && match (&canonical.role, disk.initialization_kind.as_deref()) {
            (
                CanonicalPersistentDiskRole::Persistent {
                    initialization: CanonicalDiskInitialization::Uninitialized { .. },
                },
                Some("uninitialized"),
            )
            | (
                CanonicalPersistentDiskRole::Persistent {
                    initialization: CanonicalDiskInitialization::Initialized { .. },
                },
                Some("initialized"),
            ) => true,
            _ => false,
        }
}

fn disk_is_initialized(disk: &StoredDiskAuthority) -> bool {
    let CanonicalPersistentDiskRole::Persistent { initialization } = &disk.record.role;
    let CanonicalDiskInitialization::Initialized {
        initialization_token,
        filesystem_uuid,
        expected_blank_head,
        initialized_head,
        initialized_at,
        commit_receipt_digest,
    } = initialization
    else {
        return false;
    };
    disk.initialization_kind.as_deref() == Some("initialized")
        && disk.initialization_token.as_deref() == Some(initialization_token.as_str())
        && disk.filesystem_uuid.as_deref() == Some(filesystem_uuid.as_str())
        && disk.expected_blank_generation == Some(0)
        && disk.expected_blank_root_hash.is_none()
        && disk.expected_blank_root_object_id.is_none()
        && expected_blank_head.generation.get() == 0
        && expected_blank_head.root_hash.is_none()
        && expected_blank_head.root_object_id.is_none()
        && disk
            .initialized_generation
            .and_then(|value| u64::try_from(value).ok())
            == Some(initialized_head.generation.get())
        && disk.initialized_root_hash.as_deref()
            == initialized_head
                .root_hash
                .as_ref()
                .map(Sha256Digest::as_str)
        && disk.initialized_root_object_id.as_deref()
            == initialized_head
                .root_object_id
                .as_ref()
                .map(|value| value.as_str())
        && initialized_head.generation.get() > 0
        && disk
            .initialized_at
            .and_then(|value| u64::try_from(value).ok())
            == Some(*initialized_at)
        && disk
            .initialization_commit_receipt_bytes
            .as_ref()
            .is_some_and(|bytes| !bytes.is_empty())
        && disk.initialization_commit_receipt_digest.as_deref()
            == Some(commit_receipt_digest.as_str())
}

fn initialized_head(disk: &StoredDiskAuthority) -> AuthorityTxResult<RemoteHead> {
    remote_head(
        disk.initialized_generation.ok_or_else(corrupt)?,
        disk.initialized_root_hash.clone(),
        disk.initialized_root_object_id.clone(),
    )
}

fn load_volume(
    transaction: &mut Transaction<'_>,
    volume_id: &str,
    lock: bool,
) -> AuthorityTxResult<VolumeRecord> {
    let suffix = if lock { "FOR UPDATE" } else { "" };
    let row = transaction.query_one(
        &format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE volume_id=$1 {suffix}"),
        &[&volume_id],
    )?;
    let record_json: String = row.try_get("record_json")?;
    let record: VolumeRecord = serde_json::from_str(&record_json).map_err(|_| corrupt())?;
    volume_projection_matches(&row, &record)
        .then_some(record)
        .ok_or_else(corrupt)
}

fn volume_projection_matches(row: &Row, record: &VolumeRecord) -> bool {
    let Ok(projection) = project_volume_record(record) else {
        return false;
    };
    row.try_get::<_, String>("volume_id").ok().as_deref() == Some(&projection.volume_id)
        && row
            .try_get::<_, i64>("size_bytes")
            .ok()
            .and_then(|v| u64::try_from(v).ok())
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
        && row
            .try_get::<_, Option<String>>("owner_binding_json")
            .ok()
            .flatten()
            .is_none()
        && row
            .try_get::<_, Option<String>>("owner_node_id")
            .ok()
            .flatten()
            .is_none()
}

fn update_volume_record(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> AuthorityTxResult<()> {
    let projection = project_volume_record(record).map_err(|_| corrupt())?;
    let record_json = serde_json::to_string(record).map_err(|_| corrupt())?;
    let size_bytes = i64::try_from(projection.size_bytes).map_err(|_| corrupt())?;
    let head_generation = generation_to_i64(projection.head_generation)?;
    let lease_epoch = i64::try_from(projection.lease_epoch.get()).map_err(|_| corrupt())?;
    let lease_expires_at = projection
        .lease_expires_at
        .map(|value| i64::try_from(value.get()).map_err(|_| corrupt()))
        .transpose()?;
    let gc_started_at = projection
        .gc_started_at
        .map(|value| i64::try_from(value.get()).map_err(|_| corrupt()))
        .transpose()?;
    let transition_placement_epoch = projection
        .transition_placement_epoch
        .map(|value| i64::try_from(value.get()).map_err(|_| corrupt()))
        .transpose()?;
    let transition_lease_duration_ms = projection
        .transition_lease_duration_ms
        .map(|value| i64::try_from(value).map_err(|_| corrupt()))
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
            &size_bytes,
            &projection.durability,
            &projection.admin_state,
            &projection.delete_id,
            &projection.gc_required,
            &projection.gc_id,
            &projection.gc_roots_digest,
            &gc_started_at,
            &head_generation,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &projection.lease_owner,
            &lease_epoch,
            &lease_expires_at,
            &projection.last_transition_kind,
            &projection.last_transition_id,
            &transition_placement_epoch,
            &transition_lease_duration_ms,
        ],
    )?)
}

fn volume_identity_exact(volume: &VolumeRecord, product: &ProductDisk) -> bool {
    volume.volume_id.as_str() == product.volume_id
        && u64::try_from(product.size_bytes).ok() == Some(volume.size_bytes)
        && volume.durability == VolumeDurability::Strict
}

fn remote_head(
    generation: i64,
    root_hash: Option<String>,
    root_object_id: Option<String>,
) -> AuthorityTxResult<RemoteHead> {
    let generation = u64::try_from(generation)
        .ok()
        .and_then(Generation::new)
        .ok_or_else(corrupt)?;
    let root_hash = root_hash
        .map(|value| Sha256Digest::new(value).ok_or_else(corrupt))
        .transpose()?;
    let root_object_id = root_object_id
        .map(|value| cats_api::runtime_reconciliation::AsciiText::new(value).ok_or_else(corrupt))
        .transpose()?;
    if (generation.get() == 0) != (root_hash.is_none() && root_object_id.is_none())
        || (root_hash.is_some() != root_object_id.is_some())
    {
        return Err(corrupt());
    }
    Ok(RemoteHead {
        generation,
        root_hash,
        root_object_id,
    })
}

fn head_is_same_or_later(current: &RemoteHead, initialized: &RemoteHead) -> bool {
    current.generation > initialized.generation
        || (current.generation == initialized.generation && current == initialized)
}

fn snapshot_matches_product(snapshot: &DiskSnapshotRecord, product: &ProductDisk) -> bool {
    snapshot.workspace_id == product.workspace_id
        && snapshot.disk_id == product.disk_id
        && snapshot.disk_slug == product.disk_slug
        && snapshot.volume_id == product.volume_id
        && snapshot.size_bytes == product.size_bytes
}

fn lock_semantic_disk(transaction: &mut Transaction<'_>, disk_id: &str) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':semantic-disk:disk:' || $1,
            0::BIGINT
         ))",
        &[&disk_id],
    )?;
    Ok(())
}

fn lock_snapshot_slug(
    transaction: &mut Transaction<'_>,
    workspace_id: &str,
    snapshot_slug: &str,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':semantic-snapshot:' || $1 || ':' || $2,
            0::BIGINT
         ))",
        &[&workspace_id, &snapshot_slug],
    )?;
    Ok(())
}

fn parse_id(value: &str) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(corrupt)
}

fn generation_to_i64(generation: Generation) -> AuthorityTxResult<i64> {
    i64::try_from(generation.get()).map_err(|_| corrupt())
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    (changed == 1).then_some(()).ok_or_else(corrupt)
}

fn corrupt() -> AuthorityTransactionError {
    AuthorityTransactionError::Application(ApiError::internal(
        "DiskSnapshot product or storage authority is inconsistent",
    ))
}

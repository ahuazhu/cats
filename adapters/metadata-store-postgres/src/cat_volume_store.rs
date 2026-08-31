//! PostgreSQL transitions used by the direct Control/Node composition.
//!
//! Product calls remain request-ID-free. This adapter derives each storage
//! transition from the current Cat/volume/node tuple under one row lock and
//! returns the original result when that exact scenario is already current.

use cats_api::runtime_reconciliation::{
    Epoch, FenceEpoch, Generation, HostPath, Id, LastVolumeTransition, NormalAcquireRequest,
    RandomId128, ReleaseRequest, RemoteHead, Sha256Digest, VolumeAdminState, VolumeDurability,
    VolumeRecord,
};
use cats_storage::authority::{
    authorized_serving_attachment_from_direct_acquire, begin_delete, normal_acquire,
    project_volume_record, release, renew_lease, AttachedVolume, AuthorityError, CatVolume,
    CatVolumeRole, CatVolumeStore, DirectAcquireServingInput, PersistentInitialization,
    PersistentInitializationCommit, RenewLeaseRequest, RootDeleteState, RootVolumeSpec,
    VolumeAttachRequest, VolumeOwnerBinding,
};
use postgres::{Row, Transaction};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::target_authority::{database_now, load_volume_for_update, update_volume_and_owner};
use super::PostgresVolumeDataAuthority;

const DISK_COLUMNS: &str = "
    disk_id, record::text AS record_json, workspace_id, name, volume_id,
    size_bytes, durability, created_at, admin_state, delete_id, role_kind,
    root_cat_id, initialization_kind, initialization_token, filesystem_uuid,
    expected_blank_generation, expected_blank_root_hash,
    expected_blank_root_object_id, initialized_generation,
    initialized_root_hash, initialized_root_object_id, initialized_at,
    initialization_commit_receipt_bytes,
    initialization_commit_receipt_digest";

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
    root_cat_id: Option<String>,
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

impl StoredDisk {
    fn from_row(row: &Row) -> Result<Self, AuthorityError> {
        let record_json: String = row
            .try_get("record_json")
            .map_err(|_| AuthorityError::BackendUnknown)?;
        Ok(Self {
            disk_id: column(row, "disk_id")?,
            record: serde_json::from_str(&record_json)
                .map_err(|_| AuthorityError::BackendUnknown)?,
            workspace_id: column(row, "workspace_id")?,
            name: column(row, "name")?,
            volume_id: column(row, "volume_id")?,
            size_bytes: row
                .try_get("size_bytes")
                .map_err(|_| AuthorityError::BackendUnknown)?,
            durability: column(row, "durability")?,
            created_at: row
                .try_get("created_at")
                .map_err(|_| AuthorityError::BackendUnknown)?,
            admin_state: column(row, "admin_state")?,
            delete_id: optional_column(row, "delete_id")?,
            role_kind: column(row, "role_kind")?,
            root_cat_id: optional_column(row, "root_cat_id")?,
            initialization_kind: optional_column(row, "initialization_kind")?,
            initialization_token: optional_column(row, "initialization_token")?,
            filesystem_uuid: optional_column(row, "filesystem_uuid")?,
            expected_blank_generation: optional_i64(row, "expected_blank_generation")?,
            expected_blank_root_hash: optional_column(row, "expected_blank_root_hash")?,
            expected_blank_root_object_id: optional_column(row, "expected_blank_root_object_id")?,
            initialized_generation: optional_i64(row, "initialized_generation")?,
            initialized_root_hash: optional_column(row, "initialized_root_hash")?,
            initialized_root_object_id: optional_column(row, "initialized_root_object_id")?,
            initialized_at: optional_i64(row, "initialized_at")?,
            initialization_commit_receipt_bytes: row
                .try_get("initialization_commit_receipt_bytes")
                .map_err(|_| AuthorityError::BackendUnknown)?,
            initialization_commit_receipt_digest: optional_column(
                row,
                "initialization_commit_receipt_digest",
            )?,
        })
    }

    fn common_identity_exact(&self, descriptor: &CatVolume) -> bool {
        self.disk_id == descriptor.disk_id.as_str()
            && self.workspace_id == descriptor.workspace_id.as_str()
            && self.volume_id == descriptor.volume_id.as_str()
            && u64::try_from(self.size_bytes).ok() == Some(descriptor.size_bytes)
            && self.durability == "strict"
            && self.created_at >= 0
            && json_text(&self.record, &["disk_id"]) == Some(self.disk_id.as_str())
            && json_text(&self.record, &["workspace_id"]) == Some(self.workspace_id.as_str())
            && json_text(&self.record, &["volume_id"]) == Some(self.volume_id.as_str())
            && self.record.get("size_bytes").and_then(Value::as_u64) == Some(descriptor.size_bytes)
            && json_text(&self.record, &["durability"]) == Some("strict")
    }

    fn common_exact(&self, descriptor: &CatVolume) -> bool {
        self.common_identity_exact(descriptor)
            && self.admin_state == "active"
            && self.delete_id.is_none()
            && json_text(&self.record, &["admin_state", "kind"]) == Some("active")
    }
}

impl CatVolumeStore for PostgresVolumeDataAuthority {
    fn ensure_root_volume(&self, spec: &RootVolumeSpec) -> Result<CatVolume, AuthorityError> {
        validate_root_spec(spec)?;
        let spec = spec.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            lock_volume_setup(&mut transaction, &spec.volume_id)?;
            let existing_disk = load_root_disk(&mut transaction, &spec.cat_id)?;
            let existing_volume = load_optional_volume(&mut transaction, &spec.volume_id)?;
            let descriptor = root_descriptor(&spec, existing_volume.as_ref());
            match (existing_disk, existing_volume) {
                (None, None) => {
                    let volume = blank_volume(&spec.volume_id, spec.size_bytes)?;
                    insert_volume(&mut transaction, &volume)?;
                    let created_at = database_now(&mut transaction)?.get();
                    insert_root_disk(&mut transaction, &spec, created_at)?;
                    transaction
                        .commit()
                        .map_err(|_| AuthorityError::BackendUnknown)?;
                    Ok(root_descriptor(&spec, Some(&volume)))
                }
                (Some(disk), Some(volume))
                    if root_disk_exact(&disk, &descriptor, &spec.cat_id)
                        && volume_exact(&volume, &descriptor) =>
                {
                    transaction
                        .commit()
                        .map_err(|_| AuthorityError::BackendUnknown)?;
                    Ok(root_descriptor(&spec, Some(&volume)))
                }
                _ => Err(AuthorityError::BackendUnknown),
            }
        })
    }

    fn load_persistent_volume(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
        disk_id: &Id,
        volume_id: &Id,
        filesystem_uuid: &RandomId128,
        mount_path: &HostPath,
    ) -> Result<CatVolume, AuthorityError> {
        let workspace_id = workspace_id.clone();
        let cat_id = cat_id.clone();
        let disk_id = disk_id.clone();
        let volume_id = volume_id.clone();
        let filesystem_uuid = filesystem_uuid.clone();
        let mount_path = mount_path.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let disk = load_disk_by_id(&mut transaction, &disk_id)?;
            validate_persistent_product_binding(
                &mut transaction,
                &workspace_id,
                &cat_id,
                &disk_id,
                &volume_id,
                &filesystem_uuid,
                &mount_path,
            )?;
            let volume = load_volume_for_update(&mut transaction, &volume_id)?;
            let descriptor = persistent_descriptor(
                &disk,
                &volume,
                &workspace_id,
                &cat_id,
                &filesystem_uuid,
                &mount_path,
            )?;
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(descriptor)
        })
    }

    fn attach_volume(
        &self,
        request: &VolumeAttachRequest,
    ) -> Result<AttachedVolume, AuthorityError> {
        validate_descriptor(&request.volume)?;
        if request.lease_duration_ms == 0 {
            return Err(AuthorityError::InvalidLeaseDuration);
        }
        let request = request.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let disk = load_disk_by_id(&mut transaction, &request.volume.disk_id)?;
            validate_locked_descriptor(&mut transaction, &disk, &request.volume)?;
            let mut volume = load_volume_for_update(&mut transaction, &request.volume.volume_id)?;
            if !volume_exact(&volume, &request.volume) {
                return Err(AuthorityError::BackendUnknown);
            }
            let db_now = database_now(&mut transaction)?;
            let (acquire_request, acquire_result) = match (
                volume.lease_owner.as_ref(),
                owner_node_id(&mut transaction, &volume.volume_id)?,
            ) {
                (None, None) => acquire_from_unowned(&volume, &request, db_now)?,
                (Some(_), Some(owner_node)) if owner_node == request.node_id => {
                    attach_replay(&volume, &request)?
                }
                (Some(_), Some(owner_node)) => {
                    require_offline_owner(&mut transaction, &owner_node)?;
                    // The accepted semantic protocol permits recovery before
                    // the old Host is proven stopped. Advancing the storage
                    // epoch makes any later old remote publish fail closed;
                    // it does not claim that the old Guest has stopped.
                    volume.lease_owner = None;
                    volume.lease_expires_at = None;
                    volume.last_transition = None;
                    acquire_from_unowned(&volume, &request, db_now)?
                }
                _ => return Err(AuthorityError::BackendUnknown),
            };
            if volume.lease_owner.as_ref() != Some(&acquire_result.attachment_id)
                || volume.lease_epoch != acquire_result.resulting_epoch
            {
                let (updated, replay) = normal_acquire(&volume, &acquire_request, db_now)?;
                if replay != acquire_result {
                    return Err(AuthorityError::BackendUnknown);
                }
                volume = updated;
            }
            let (renewed_volume, renewed) = renew_lease(
                &volume,
                &RenewLeaseRequest {
                    volume_id: volume.volume_id.clone(),
                    attachment_id: acquire_result.attachment_id.clone(),
                    expected_epoch: acquire_result.resulting_epoch,
                    lease_duration_ms: request.lease_duration_ms,
                },
                db_now,
            )?;
            volume = renewed_volume;
            update_volume_owner(&mut transaction, &volume, Some(&request.node_id))?;
            let serving =
                authorized_serving_attachment_from_direct_acquire(DirectAcquireServingInput {
                    node_id: request.node_id,
                    size_bytes: volume.size_bytes,
                    durability: volume.durability,
                    request: acquire_request,
                    result: acquire_result,
                    current_head: volume.head.clone(),
                    current_lease_expires_at: renewed.lease_expires_at,
                })?;
            let mut descriptor = request.volume;
            descriptor.head = volume.head.clone();
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(AttachedVolume {
                volume: descriptor,
                serving,
            })
        })
    }

    fn detach_volume(&self, attached: &AttachedVolume) -> Result<(), AuthorityError> {
        validate_descriptor(&attached.volume)?;
        let attached = attached.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let volume = load_volume_for_update(&mut transaction, &attached.volume.volume_id)?;
            if volume.lease_owner.is_none()
                || volume.lease_epoch > attached.serving.identity.attachment_epoch
            {
                transaction
                    .commit()
                    .map_err(|_| AuthorityError::BackendUnknown)?;
                return Ok(());
            }
            if volume.lease_owner.as_ref() != Some(&attached.serving.identity.attachment_id)
                || volume.lease_epoch != attached.serving.identity.attachment_epoch
            {
                return Err(AuthorityError::Fenced);
            }
            let release_request = ReleaseRequest {
                volume_id: volume.volume_id.clone(),
                transition_id: derived_random(
                    b"cats.cat-volume.release.v1\0",
                    &[
                        attached_role_cat_id(&attached.volume)?.as_str(),
                        volume.volume_id.as_str(),
                        &volume.lease_epoch.get().to_string(),
                    ],
                )?,
                attachment_id: attached.serving.identity.attachment_id.clone(),
                expected_epoch: attached.serving.identity.attachment_epoch,
            };
            let (released, _) = release(&volume, &release_request)?;
            update_volume_owner(&mut transaction, &released, None)?;
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)
        })
    }

    fn detach_node_volumes(&self, node_id: &Id) -> Result<usize, AuthorityError> {
        let node_id = node_id.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let volume_ids = transaction
                .query(
                    "SELECT volume_id FROM volume_records
                      WHERE owner_node_id=$1 ORDER BY volume_id FOR UPDATE",
                    &[&node_id.as_str()],
                )
                .map_err(|_| AuthorityError::BackendUnknown)?
                .into_iter()
                .map(|row| row.try_get::<_, String>(0))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let mut detached = 0_usize;
            for volume_id in volume_ids {
                let volume_id = Id::new(volume_id).ok_or(AuthorityError::BackendUnknown)?;
                let volume = load_volume_for_update(&mut transaction, &volume_id)?;
                let attachment_id = volume
                    .lease_owner
                    .clone()
                    .ok_or(AuthorityError::BackendUnknown)?;
                let transition_id = derived_random(
                    b"cats.node-volume.reset-release.v1\0",
                    &[
                        node_id.as_str(),
                        volume.volume_id.as_str(),
                        &volume.lease_epoch.get().to_string(),
                    ],
                )?;
                let (released, _) = release(
                    &volume,
                    &ReleaseRequest {
                        volume_id: volume.volume_id.clone(),
                        transition_id,
                        attachment_id,
                        expected_epoch: volume.lease_epoch,
                    },
                )?;
                update_volume_owner(&mut transaction, &released, None)?;
                detached += 1;
            }
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(detached)
        })
    }

    fn commit_persistent_initialization(
        &self,
        commit: &PersistentInitializationCommit,
    ) -> Result<CatVolume, AuthorityError> {
        let commit = commit.clone();
        validate_descriptor(&commit.attached.volume)?;
        if commit.guest_evidence.is_empty() || commit.guest_evidence.len() > 2 * 1024 * 1024 {
            return Err(AuthorityError::BackendUnknown);
        }
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let mut disk = load_disk_by_id(&mut transaction, &commit.attached.volume.disk_id)?;
            let CatVolumeRole::Persistent {
                cat_id,
                filesystem_uuid,
                mount_path,
                ..
            } = &commit.attached.volume.role
            else {
                return Err(AuthorityError::BackendUnknown);
            };
            validate_persistent_product_binding(
                &mut transaction,
                &commit.attached.volume.workspace_id,
                cat_id,
                &commit.attached.volume.disk_id,
                &commit.attached.volume.volume_id,
                filesystem_uuid,
                mount_path,
            )?;
            if !persistent_disk_identity_exact(&disk, &commit.attached.volume) {
                return Err(AuthorityError::BackendUnknown);
            }
            let volume =
                load_volume_for_update(&mut transaction, &commit.attached.volume.volume_id)?;
            if volume.lease_owner.as_ref() != Some(&commit.attached.serving.identity.attachment_id)
                || volume.lease_epoch != commit.attached.serving.identity.attachment_epoch
                || volume.head != commit.initialized_head
                || commit.initialized_head.generation.get() == 0
            {
                return Err(AuthorityError::BackendUnknown);
            }
            let digest = Sha256Digest::from_bytes(Sha256::digest(&commit.guest_evidence).into());
            if disk.initialization_kind.as_deref() == Some("initialized") {
                if disk.initialization_commit_receipt_bytes.as_deref()
                    != Some(commit.guest_evidence.as_slice())
                    || disk.initialization_commit_receipt_digest.as_deref() != Some(digest.as_str())
                    || initialized_head(&disk)? != commit.initialized_head
                {
                    return Err(AuthorityError::BackendUnknown);
                }
            } else {
                let (initialization_token, filesystem_uuid) =
                    persistent_initialization_identity(&disk)?;
                disk.initialization_kind = Some("initialized".to_owned());
                disk.initialized_generation =
                    i64::try_from(commit.initialized_head.generation.get()).ok();
                disk.initialized_root_hash = commit
                    .initialized_head
                    .root_hash
                    .as_ref()
                    .map(ToString::to_string);
                disk.initialized_root_object_id = commit
                    .initialized_head
                    .root_object_id
                    .as_ref()
                    .map(ToString::to_string);
                disk.initialized_at = Some(
                    i64::try_from(database_now(&mut transaction)?.get())
                        .map_err(|_| AuthorityError::BackendUnknown)?,
                );
                disk.initialization_commit_receipt_bytes = Some(commit.guest_evidence.clone());
                disk.initialization_commit_receipt_digest = Some(digest.to_string());
                disk.record["role"]["initialization"] = json!({
                    "kind": "initialized",
                    "initialization_token": initialization_token.as_str(),
                    "filesystem_uuid": filesystem_uuid.as_str(),
                    "expected_blank_head": blank_head(),
                    "initialized_head": commit.initialized_head,
                    "initialized_at": disk.initialized_at,
                    "commit_receipt_digest": digest.as_str()
                });
                update_disk(&mut transaction, &disk)?;
            }
            let descriptor =
                persistent_descriptor_from_locked(&disk, &volume, &commit.attached.volume)?;
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(descriptor)
        })
    }

    fn begin_root_delete(&self, descriptor: &CatVolume) -> Result<RootDeleteState, AuthorityError> {
        validate_descriptor(descriptor)?;
        let descriptor = descriptor.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let disk = load_optional_disk_by_id(&mut transaction, &descriptor.disk_id)?;
            let volume = load_optional_volume(&mut transaction, &descriptor.volume_id)?;
            let (mut disk, volume) = match (disk, volume) {
                (None, None) => return Ok(RootDeleteState::Absent),
                (Some(disk), Some(volume)) => (disk, volume),
                _ => return Err(AuthorityError::BackendUnknown),
            };
            if !root_disk_identity_exact(&disk, &descriptor, attached_role_cat_id(&descriptor)?)
                || !volume_identity_exact(&volume, &descriptor)
            {
                return Err(AuthorityError::BackendUnknown);
            }
            if disk.admin_state == "deleting" {
                let Some(disk_delete_id) = disk.delete_id.as_deref() else {
                    return Err(AuthorityError::BackendUnknown);
                };
                let VolumeAdminState::Deleting { delete_id } = &volume.admin_state else {
                    return Err(AuthorityError::BackendUnknown);
                };
                if delete_id.as_str() != disk_delete_id
                    || json_text(&disk.record, &["admin_state", "delete_id"])
                        != Some(disk_delete_id)
                {
                    return Err(AuthorityError::BackendUnknown);
                }
                transaction
                    .commit()
                    .map_err(|_| AuthorityError::BackendUnknown)?;
                return Ok(RootDeleteState::Deleting);
            }
            if volume.lease_owner.is_some() {
                return Err(AuthorityError::OtherWriter);
            }
            let delete_id = Id::new(format!(
                "delete_{}",
                derived_random(
                    b"cats.root-volume.delete.v1\0",
                    &[descriptor.disk_id.as_str(), descriptor.volume_id.as_str()],
                )?
            ))
            .ok_or(AuthorityError::BackendUnknown)?;
            let (deleting, _) = begin_delete(
                &volume,
                &cats_api::runtime_reconciliation::BeginDeleteRequest {
                    delete_id: delete_id.clone(),
                    disk_id: descriptor.disk_id.clone(),
                    volume_id: descriptor.volume_id.clone(),
                    expected_unowned_epoch: volume.lease_epoch,
                    expected_head: volume.head.clone(),
                },
            )?;
            update_volume_owner(&mut transaction, &deleting, None)?;
            disk.admin_state = "deleting".to_owned();
            disk.delete_id = Some(delete_id.to_string());
            disk.record["admin_state"] =
                json!({ "kind": "deleting", "delete_id": delete_id.as_str() });
            update_disk(&mut transaction, &disk)?;
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(RootDeleteState::Deleting)
        })
    }

    fn complete_root_delete(&self, descriptor: &CatVolume) -> Result<(), AuthorityError> {
        validate_descriptor(descriptor)?;
        let descriptor = descriptor.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let disk = load_optional_disk_by_id(&mut transaction, &descriptor.disk_id)?;
            let volume = load_optional_volume(&mut transaction, &descriptor.volume_id)?;
            match (disk, volume) {
                (None, None) => Ok(()),
                (Some(disk), Some(volume)) => {
                    let delete_ids_match = match (
                        disk.delete_id.as_deref(),
                        &volume.admin_state,
                    ) {
                        (Some(disk_delete_id), VolumeAdminState::Deleting { delete_id }) => {
                            disk_delete_id == delete_id.as_str()
                                && json_text(&disk.record, &["admin_state", "delete_id"])
                                    == Some(disk_delete_id)
                        }
                        _ => false,
                    };
                    if !root_disk_identity_exact(
                        &disk,
                        &descriptor,
                        attached_role_cat_id(&descriptor)?,
                    ) || !volume_identity_exact(&volume, &descriptor)
                        || disk.admin_state != "deleting"
                        || !delete_ids_match
                        || volume.lease_owner.is_some()
                    {
                        return Err(AuthorityError::BackendUnknown);
                    }
                    let disk_changed = transaction
                        .execute(
                            "DELETE FROM disk_records WHERE disk_id=$1 AND volume_id=$2 AND admin_state='deleting'",
                            &[&descriptor.disk_id.as_str(), &descriptor.volume_id.as_str()],
                        )
                        .map_err(|_| AuthorityError::BackendUnknown)?;
                    let volume_changed = transaction
                        .execute(
                            "DELETE FROM volume_records WHERE volume_id=$1 AND admin_state='deleting' AND lease_owner IS NULL",
                            &[&descriptor.volume_id.as_str()],
                        )
                        .map_err(|_| AuthorityError::BackendUnknown)?;
                    if disk_changed != 1 || volume_changed != 1 {
                        return Err(AuthorityError::BackendUnknown);
                    }
                    transaction
                        .commit()
                        .map_err(|_| AuthorityError::BackendUnknown)
                }
                _ => Err(AuthorityError::BackendUnknown),
            }
        })
    }
}

fn validate_root_spec(spec: &RootVolumeSpec) -> Result<(), AuthorityError> {
    if spec.size_bytes == 0
        || !prefixed_random_id(&spec.disk_id, "disk_")
        || !prefixed_random_id(&spec.volume_id, "vol_")
        || !spec.cat_id.as_str().starts_with("cat_")
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

fn root_descriptor(spec: &RootVolumeSpec, volume: Option<&VolumeRecord>) -> CatVolume {
    CatVolume {
        workspace_id: spec.workspace_id.clone(),
        disk_id: spec.disk_id.clone(),
        volume_id: spec.volume_id.clone(),
        size_bytes: spec.size_bytes,
        durability: VolumeDurability::Strict,
        head: volume.map_or_else(blank_head, |volume| volume.head.clone()),
        role: CatVolumeRole::Root {
            cat_id: spec.cat_id.clone(),
        },
    }
}

fn blank_volume(volume_id: &Id, size_bytes: u64) -> Result<VolumeRecord, AuthorityError> {
    if size_bytes == 0 {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(VolumeRecord {
        volume_id: volume_id.clone(),
        size_bytes,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        gc_required: false,
        head: blank_head(),
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).ok_or(AuthorityError::BackendUnknown)?,
        lease_expires_at: None,
        last_transition: None,
    })
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).expect("zero generation is valid"),
        root_hash: None,
        root_object_id: None,
    }
}

fn insert_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> Result<(), AuthorityError> {
    let projection = project_volume_record(record)?;
    let record_json = serde_json::to_string(record).map_err(|_| AuthorityError::BackendUnknown)?;
    let changed = transaction
        .execute(
            "INSERT INTO volume_records (
                volume_id,record,size_bytes,durability,admin_state,delete_id,
                gc_required,gc_id,gc_roots_digest,gc_started_at,
                head_generation,head_root_hash,head_root_object_id,lease_owner,
                lease_epoch,lease_expires_at,last_transition_kind,last_transition_id,
                transition_placement_epoch,
                transition_lease_duration_ms,owner_binding,owner_node_id
             ) VALUES ($1,$2::TEXT::jsonb,$3,'strict','active',NULL,
                       FALSE,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,
                       NULL,NULL,NULL,NULL)",
            &[
                &projection.volume_id,
                &record_json,
                &i64::try_from(projection.size_bytes)
                    .map_err(|_| AuthorityError::BackendUnknown)?,
            ],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?;
    (changed == 1)
        .then_some(())
        .ok_or(AuthorityError::BackendUnknown)
}

fn insert_root_disk(
    transaction: &mut Transaction<'_>,
    spec: &RootVolumeSpec,
    created_at: u64,
) -> Result<(), AuthorityError> {
    let record = json!({
        "disk_id": spec.disk_id.as_str(),
        "workspace_id": spec.workspace_id.as_str(),
        "name": spec.disk_id.as_str(),
        "volume_id": spec.volume_id.as_str(),
        "size_bytes": spec.size_bytes,
        "durability": "strict",
        "created_at": created_at,
        "admin_state": { "kind": "active" },
        "role": { "kind": "root", "cat_id": spec.cat_id.as_str() }
    });
    let record_json = serde_json::to_string(&record).map_err(|_| AuthorityError::BackendUnknown)?;
    let changed = transaction
        .execute(
            "INSERT INTO disk_records (
                disk_id,record,workspace_id,name,volume_id,size_bytes,durability,
                created_at,admin_state,delete_id,role_kind,root_cat_id,
                initialization_kind,initialization_token,filesystem_uuid,
                expected_blank_generation,expected_blank_root_hash,
                expected_blank_root_object_id,initialized_generation,
                initialized_root_hash,initialized_root_object_id,initialized_at,
                initialization_commit_receipt_bytes,
                initialization_commit_receipt_digest
             ) VALUES ($1,$2::TEXT::jsonb,$3,$1,$4,$5,'strict',$6,'active',NULL,
                       'root',$7,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
            &[
                &spec.disk_id.as_str(),
                &record_json,
                &spec.workspace_id.as_str(),
                &spec.volume_id.as_str(),
                &i64::try_from(spec.size_bytes).map_err(|_| AuthorityError::BackendUnknown)?,
                &i64::try_from(created_at).map_err(|_| AuthorityError::BackendUnknown)?,
                &spec.cat_id.as_str(),
            ],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?;
    (changed == 1)
        .then_some(())
        .ok_or(AuthorityError::BackendUnknown)
}

fn load_root_disk(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> Result<Option<StoredDisk>, AuthorityError> {
    let sql = format!("SELECT {DISK_COLUMNS} FROM disk_records WHERE root_cat_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])
        .map_err(|_| AuthorityError::BackendUnknown)?
        .map(|row| StoredDisk::from_row(&row))
        .transpose()
}

fn load_disk_by_id(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
) -> Result<StoredDisk, AuthorityError> {
    load_optional_disk_by_id(transaction, disk_id)?.ok_or(AuthorityError::NotFound)
}

fn load_optional_disk_by_id(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
) -> Result<Option<StoredDisk>, AuthorityError> {
    let sql = format!("SELECT {DISK_COLUMNS} FROM disk_records WHERE disk_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&disk_id.as_str()])
        .map_err(|_| AuthorityError::BackendUnknown)?
        .map(|row| StoredDisk::from_row(&row))
        .transpose()
}

fn load_optional_volume(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> Result<Option<VolumeRecord>, AuthorityError> {
    match load_volume_for_update(transaction, volume_id) {
        Ok(volume) => Ok(Some(volume)),
        Err(AuthorityError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_persistent_product_binding(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    disk_id: &Id,
    volume_id: &Id,
    filesystem_uuid: &RandomId128,
    mount_path: &HostPath,
) -> Result<(), AuthorityError> {
    let exact = transaction
        .query_opt(
            "SELECT 1
               FROM persistent_disks p
               JOIN disk_bindings b
                 ON b.disk_id=p.disk_id AND b.workspace_id=p.workspace_id
              WHERE p.disk_id=$1 AND p.workspace_id=$2 AND p.volume_id=$3
                AND p.filesystem_uuid=$4 AND p.disk_format='ext4'
                AND p.status='normal' AND p.deleted_at IS NULL
                AND b.cat_id=$5 AND b.mount_path=$6",
            &[
                &disk_id.as_str(),
                &workspace_id.as_str(),
                &volume_id.as_str(),
                &filesystem_uuid.as_str(),
                &cat_id.as_str(),
                &mount_path.as_str(),
            ],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?
        .is_some();
    exact.then_some(()).ok_or(AuthorityError::NotFound)
}

fn persistent_descriptor(
    disk: &StoredDisk,
    volume: &VolumeRecord,
    workspace_id: &Id,
    cat_id: &Id,
    filesystem_uuid: &RandomId128,
    mount_path: &HostPath,
) -> Result<CatVolume, AuthorityError> {
    let descriptor = CatVolume {
        workspace_id: workspace_id.clone(),
        disk_id: Id::new(disk.disk_id.clone()).ok_or(AuthorityError::BackendUnknown)?,
        volume_id: volume.volume_id.clone(),
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        head: volume.head.clone(),
        role: CatVolumeRole::Persistent {
            cat_id: cat_id.clone(),
            filesystem_uuid: filesystem_uuid.clone(),
            mount_path: mount_path.clone(),
            initialization: stored_initialization(disk)?,
        },
    };
    if !persistent_disk_exact(disk, &descriptor) || !volume_exact(volume, &descriptor) {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(descriptor)
}

fn persistent_descriptor_from_locked(
    disk: &StoredDisk,
    volume: &VolumeRecord,
    expected: &CatVolume,
) -> Result<CatVolume, AuthorityError> {
    let CatVolumeRole::Persistent {
        cat_id,
        filesystem_uuid,
        mount_path,
        ..
    } = &expected.role
    else {
        return Err(AuthorityError::BackendUnknown);
    };
    persistent_descriptor(
        disk,
        volume,
        &expected.workspace_id,
        cat_id,
        filesystem_uuid,
        mount_path,
    )
}

fn stored_initialization(disk: &StoredDisk) -> Result<PersistentInitialization, AuthorityError> {
    let (token, _) = persistent_initialization_identity(disk)?;
    match disk.initialization_kind.as_deref() {
        Some("uninitialized") => {
            if disk.expected_blank_generation != Some(0)
                || disk.expected_blank_root_hash.is_some()
                || disk.expected_blank_root_object_id.is_some()
                || disk.initialized_generation.is_some()
                || disk.initialized_root_hash.is_some()
                || disk.initialized_root_object_id.is_some()
                || disk.initialized_at.is_some()
                || disk.initialization_commit_receipt_bytes.is_some()
                || disk.initialization_commit_receipt_digest.is_some()
            {
                return Err(AuthorityError::BackendUnknown);
            }
            Ok(PersistentInitialization::Uninitialized {
                initialization_token: token,
                expected_blank_head: blank_head(),
            })
        }
        Some("initialized") => Ok(PersistentInitialization::Initialized {
            initialized_head: initialized_head(disk)?,
        }),
        _ => Err(AuthorityError::BackendUnknown),
    }
}

fn initialized_head(disk: &StoredDisk) -> Result<RemoteHead, AuthorityError> {
    let generation = disk
        .initialized_generation
        .and_then(|value| u64::try_from(value).ok())
        .and_then(Generation::new)
        .filter(|generation| generation.get() > 0)
        .ok_or(AuthorityError::BackendUnknown)?;
    let root_hash = disk
        .initialized_root_hash
        .as_ref()
        .and_then(|value| Sha256Digest::new(value.clone()))
        .ok_or(AuthorityError::BackendUnknown)?;
    let root_object_id = disk
        .initialized_root_object_id
        .as_ref()
        .and_then(|value| cats_api::runtime_reconciliation::AsciiText::new(value.clone()))
        .ok_or(AuthorityError::BackendUnknown)?;
    Ok(RemoteHead {
        generation,
        root_hash: Some(root_hash),
        root_object_id: Some(root_object_id),
    })
}

fn persistent_initialization_identity(
    disk: &StoredDisk,
) -> Result<(RandomId128, RandomId128), AuthorityError> {
    let token = disk
        .initialization_token
        .as_ref()
        .and_then(|value| RandomId128::new(value.clone()))
        .ok_or(AuthorityError::BackendUnknown)?;
    let filesystem_uuid = disk
        .filesystem_uuid
        .as_ref()
        .and_then(|value| RandomId128::new(value.clone()))
        .ok_or(AuthorityError::BackendUnknown)?;
    if token == filesystem_uuid {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok((token, filesystem_uuid))
}

fn validate_descriptor(descriptor: &CatVolume) -> Result<(), AuthorityError> {
    if descriptor.size_bytes == 0 || descriptor.durability != VolumeDurability::Strict {
        return Err(AuthorityError::BackendUnknown);
    }
    match &descriptor.role {
        CatVolumeRole::Root { cat_id } if cat_id.as_str().starts_with("cat_") => Ok(()),
        CatVolumeRole::Persistent { cat_id, .. } if cat_id.as_str().starts_with("cat_") => Ok(()),
        _ => Err(AuthorityError::BackendUnknown),
    }
}

fn validate_locked_descriptor(
    transaction: &mut Transaction<'_>,
    disk: &StoredDisk,
    descriptor: &CatVolume,
) -> Result<(), AuthorityError> {
    match &descriptor.role {
        CatVolumeRole::Root { cat_id } => {
            if root_disk_exact(disk, descriptor, cat_id) {
                Ok(())
            } else {
                Err(AuthorityError::BackendUnknown)
            }
        }
        CatVolumeRole::Persistent {
            cat_id,
            filesystem_uuid,
            mount_path,
            ..
        } => {
            validate_persistent_product_binding(
                transaction,
                &descriptor.workspace_id,
                cat_id,
                &descriptor.disk_id,
                &descriptor.volume_id,
                filesystem_uuid,
                mount_path,
            )?;
            if persistent_disk_exact(disk, descriptor) {
                Ok(())
            } else {
                Err(AuthorityError::BackendUnknown)
            }
        }
    }
}

fn root_disk_exact(disk: &StoredDisk, descriptor: &CatVolume, cat_id: &Id) -> bool {
    root_disk_identity_exact(disk, descriptor, cat_id) && disk.common_exact(descriptor)
}

fn root_disk_identity_exact(disk: &StoredDisk, descriptor: &CatVolume, cat_id: &Id) -> bool {
    disk.common_identity_exact(descriptor)
        && disk.name == descriptor.disk_id.as_str()
        && disk.role_kind == "root"
        && disk.root_cat_id.as_deref() == Some(cat_id.as_str())
        && disk.initialization_kind.is_none()
        && disk.initialization_token.is_none()
        && disk.filesystem_uuid.is_none()
        && json_text(&disk.record, &["name"]) == Some(descriptor.disk_id.as_str())
        && json_text(&disk.record, &["role", "kind"]) == Some("root")
        && json_text(&disk.record, &["role", "cat_id"]) == Some(cat_id.as_str())
}

fn persistent_disk_exact(disk: &StoredDisk, descriptor: &CatVolume) -> bool {
    let CatVolumeRole::Persistent { initialization, .. } = &descriptor.role else {
        return false;
    };
    let initialization_matches = match (initialization, stored_initialization(disk)) {
        (
            PersistentInitialization::Uninitialized {
                initialization_token,
                expected_blank_head,
            },
            Ok(PersistentInitialization::Uninitialized {
                initialization_token: stored_token,
                expected_blank_head: stored_head,
            }),
        ) => initialization_token == &stored_token && expected_blank_head == &stored_head,
        (
            PersistentInitialization::Initialized { initialized_head },
            Ok(PersistentInitialization::Initialized {
                initialized_head: stored_head,
            }),
        ) => initialized_head == &stored_head,
        _ => false,
    };
    persistent_disk_identity_exact(disk, descriptor) && initialization_matches
}

fn persistent_disk_identity_exact(disk: &StoredDisk, descriptor: &CatVolume) -> bool {
    let CatVolumeRole::Persistent {
        filesystem_uuid, ..
    } = &descriptor.role
    else {
        return false;
    };
    disk.common_exact(descriptor)
        && disk.role_kind == "persistent"
        && disk.root_cat_id.is_none()
        && disk.filesystem_uuid.as_deref() == Some(filesystem_uuid.as_str())
        && json_text(&disk.record, &["role", "kind"]) == Some("persistent")
        && json_text(&disk.record, &["role", "initialization", "filesystem_uuid"])
            == Some(filesystem_uuid.as_str())
}

fn volume_exact(volume: &VolumeRecord, descriptor: &CatVolume) -> bool {
    volume_identity_exact(volume, descriptor)
        && matches!(volume.admin_state, VolumeAdminState::Active)
}

fn volume_identity_exact(volume: &VolumeRecord, descriptor: &CatVolume) -> bool {
    volume.volume_id == descriptor.volume_id
        && volume.size_bytes == descriptor.size_bytes
        && volume.durability == VolumeDurability::Strict
}

fn attached_role_cat_id(descriptor: &CatVolume) -> Result<&Id, AuthorityError> {
    match &descriptor.role {
        CatVolumeRole::Root { cat_id } | CatVolumeRole::Persistent { cat_id, .. } => Ok(cat_id),
    }
}

fn acquire_from_unowned(
    volume: &VolumeRecord,
    request: &VolumeAttachRequest,
    db_now: cats_api::runtime_reconciliation::UnixMillis,
) -> Result<
    (
        NormalAcquireRequest,
        cats_api::runtime_reconciliation::NormalAcquireResult,
    ),
    AuthorityError,
> {
    if volume.lease_owner.is_some() {
        return Err(AuthorityError::OtherWriter);
    }
    let cat_id = attached_role_cat_id(&request.volume)?;
    let epoch_text = volume.lease_epoch.get().to_string();
    let transition_id = derived_random(
        b"cats.cat-volume.acquire.v1\0",
        &[
            cat_id.as_str(),
            volume.volume_id.as_str(),
            request.node_id.as_str(),
            &epoch_text,
        ],
    )?;
    let attachment_random = derived_random(
        b"cats.cat-volume.attachment.v1\0",
        &[
            cat_id.as_str(),
            volume.volume_id.as_str(),
            request.node_id.as_str(),
            &epoch_text,
        ],
    )?;
    let acquire = NormalAcquireRequest {
        volume_id: volume.volume_id.clone(),
        transition_id,
        attachment_id: Id::new(format!("attach_{}", attachment_random.as_str()))
            .ok_or(AuthorityError::BackendUnknown)?,
        expected_unowned_epoch: volume.lease_epoch,
        placement_epoch: Epoch::new(
            volume
                .lease_epoch
                .get()
                .checked_add(1)
                .ok_or(AuthorityError::EpochExhausted)?,
        )
        .ok_or(AuthorityError::EpochExhausted)?,
        lease_duration_ms: request.lease_duration_ms,
    };
    let (_, result) = normal_acquire(volume, &acquire, db_now)?;
    Ok((acquire, result))
}

fn attach_replay(
    volume: &VolumeRecord,
    request: &VolumeAttachRequest,
) -> Result<
    (
        NormalAcquireRequest,
        cats_api::runtime_reconciliation::NormalAcquireResult,
    ),
    AuthorityError,
> {
    let LastVolumeTransition::NormalAcquire {
        request: acquire,
        result,
    } = volume
        .last_transition
        .as_ref()
        .ok_or(AuthorityError::BackendUnknown)?
    else {
        return Err(AuthorityError::BackendUnknown);
    };
    let cat_id = attached_role_cat_id(&request.volume)?;
    let epoch_text = acquire.expected_unowned_epoch.get().to_string();
    let expected_transition = derived_random(
        b"cats.cat-volume.acquire.v1\0",
        &[
            cat_id.as_str(),
            volume.volume_id.as_str(),
            request.node_id.as_str(),
            &epoch_text,
        ],
    )?;
    let expected_attachment = derived_random(
        b"cats.cat-volume.attachment.v1\0",
        &[
            cat_id.as_str(),
            volume.volume_id.as_str(),
            request.node_id.as_str(),
            &epoch_text,
        ],
    )?;
    if acquire.transition_id != expected_transition
        || acquire.attachment_id.as_str() != format!("attach_{}", expected_attachment.as_str())
        || acquire.lease_duration_ms != request.lease_duration_ms
        || volume.lease_owner.as_ref() != Some(&result.attachment_id)
        || volume.lease_epoch != result.resulting_epoch
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok((acquire.clone(), result.clone()))
}

fn require_offline_owner(
    transaction: &mut Transaction<'_>,
    owner_node_id: &Id,
) -> Result<(), AuthorityError> {
    let status = transaction
        .query_opt(
            "SELECT status FROM nodes WHERE node_id=$1 FOR SHARE",
            &[&owner_node_id.as_str()],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?
        .map(|row| row.get::<_, String>(0));
    matches!(status.as_deref(), Some("offline" | "reset_required"))
        .then_some(())
        .ok_or(AuthorityError::OtherWriter)
}

fn owner_node_id(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> Result<Option<Id>, AuthorityError> {
    let value = transaction
        .query_one(
            "SELECT owner_node_id FROM volume_records WHERE volume_id=$1",
            &[&volume_id.as_str()],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?
        .try_get::<_, Option<String>>(0)
        .map_err(|_| AuthorityError::BackendUnknown)?;
    value
        .map(|value| Id::new(value).ok_or(AuthorityError::BackendUnknown))
        .transpose()
}

fn update_volume_owner(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
    owner_node_id: Option<&Id>,
) -> Result<(), AuthorityError> {
    let owner_binding = match (&record.lease_owner, owner_node_id) {
        (None, None) => None,
        (Some(attachment_id), Some(node_id)) => Some(VolumeOwnerBinding {
            volume_id: record.volume_id.clone(),
            owner_node_id: node_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: record.lease_epoch,
        }),
        _ => return Err(AuthorityError::BackendUnknown),
    };
    update_volume_and_owner(transaction, record, owner_binding.as_ref())
}

fn update_disk(transaction: &mut Transaction<'_>, disk: &StoredDisk) -> Result<(), AuthorityError> {
    let record_json =
        serde_json::to_string(&disk.record).map_err(|_| AuthorityError::BackendUnknown)?;
    let changed = transaction
        .execute(
            "UPDATE disk_records SET
                record=$2::TEXT::jsonb,admin_state=$3,delete_id=$4,
                initialization_kind=$5,initialized_generation=$6,
                initialized_root_hash=$7,initialized_root_object_id=$8,
                initialized_at=$9,initialization_commit_receipt_bytes=$10,
                initialization_commit_receipt_digest=$11
              WHERE disk_id=$1 AND volume_id=$12",
            &[
                &disk.disk_id,
                &record_json,
                &disk.admin_state,
                &disk.delete_id,
                &disk.initialization_kind,
                &disk.initialized_generation,
                &disk.initialized_root_hash,
                &disk.initialized_root_object_id,
                &disk.initialized_at,
                &disk.initialization_commit_receipt_bytes,
                &disk.initialization_commit_receipt_digest,
                &disk.volume_id,
            ],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?;
    (changed == 1)
        .then_some(())
        .ok_or(AuthorityError::BackendUnknown)
}

fn lock_volume_setup(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> Result<(), AuthorityError> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':cat-volume:' || $1,0::BIGINT
             ))",
            &[&volume_id.as_str()],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?;
    Ok(())
}

fn derived_random(domain: &[u8], parts: &[&str]) -> Result<RandomId128, AuthorityError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    let encoded = format!("{:x}", digest.finalize());
    RandomId128::new(encoded[..32].to_owned()).ok_or(AuthorityError::BackendUnknown)
}

fn prefixed_random_id(value: &Id, prefix: &str) -> bool {
    value.as_str().strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn json_text<'a>(record: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(record, |value, key| value.get(*key))
        .and_then(Value::as_str)
}

fn column(row: &Row, name: &str) -> Result<String, AuthorityError> {
    row.try_get(name)
        .map_err(|_| AuthorityError::BackendUnknown)
}

fn optional_column(row: &Row, name: &str) -> Result<Option<String>, AuthorityError> {
    row.try_get(name)
        .map_err(|_| AuthorityError::BackendUnknown)
}

fn optional_i64(row: &Row, name: &str) -> Result<Option<i64>, AuthorityError> {
    row.try_get(name)
        .map_err(|_| AuthorityError::BackendUnknown)
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::AsciiText;
    use cats_control_plane::store::Store;
    use cats_storage::authority::{
        CatVolumeStore as _, RootVolumeSpec, VolumeAttachRequest, VolumeDataAuthority as _,
        VolumeHeadCasRequest,
    };
    use postgres::{Client, NoTls};

    use super::*;

    const WORKSPACE_ID: &str = "ws_cat_volume";
    const CAT_ID: &str = "cat_cat_volume";
    const ROOT_DISK_ID: &str = "disk_11111111111111111111111111111111";
    const ROOT_VOLUME_ID: &str = "vol_22222222222222222222222222222222";
    const NODE_A: &str = "node_cat_volume_a";
    const NODE_B: &str = "node_cat_volume_b";
    const PERSISTENT_DISK_ID: &str = "disk_33333333333333333333333333333333";
    const PERSISTENT_VOLUME_ID: &str = "vol_44444444444444444444444444444444";
    const FILESYSTEM_UUID: &str = "55555555555555555555555555555555";
    const INITIALIZATION_TOKEN: &str = "66666666666666666666666666666666";

    struct Fixture {
        client: Client,
        authority: PostgresVolumeDataAuthority,
    }

    impl Fixture {
        fn new() -> Self {
            let url = cats_control_plane::testsupport::isolated_control_store_url();
            drop(Store::connect(&url, None).expect("initialize final Control schema"));
            let mut client = Client::connect(&url, NoTls).expect("connect test PostgreSQL");
            client
                .batch_execute(&format!(
                    "INSERT INTO accounts (
                        id,slug,display_name,kind,workos_organization_id,billing_account_id,
                        personal_owner_user_id,status,created_at
                     ) VALUES (
                        'acct_cat_volume','cat-volume','Cat Volume','organization',
                        'org_cat_volume','billing_cat_volume',NULL,'active',1
                     );
                     INSERT INTO workspaces (
                        id,account_id,slug,display_name,is_default,created_at
                     ) VALUES (
                        '{WORKSPACE_ID}','acct_cat_volume','default','Default',TRUE,1
                     );
                     INSERT INTO nodes (
                        node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
                        machine_type,node_version,status,created_at,updated_at
                     ) VALUES
                        ('{NODE_A}','worker-a','http://127.0.0.1:7001','test','test-1',
                         'test-1a','instance-a','test.large','test','running',1,1),
                        ('{NODE_B}','worker-b','http://127.0.0.1:7002','test','test-1',
                         'test-1b','instance-b','test.large','test','running',1,1);
                     INSERT INTO cats (
                        cat_id,workspace_id,cat_slug,state,current_action,
                        current_action_started_at,current_action_node_id,node_id,cpu_count,
                        memory_bytes,boot_image,last_error_code,last_error_message,created_at,
                        updated_at,destroyed_at
                     ) VALUES (
                        '{CAT_ID}','{WORKSPACE_ID}','cat-volume','cold',NULL,NULL,NULL,NULL,
                        2,1073741824,'sha256:test',NULL,NULL,1,1,NULL
                     );"
                ))
                .expect("seed semantic product rows");
            let authority = PostgresVolumeDataAuthority::connect(&url, None)
                .expect("connect Cat volume authority");
            Self { client, authority }
        }

        fn root_spec() -> RootVolumeSpec {
            RootVolumeSpec {
                workspace_id: id(WORKSPACE_ID),
                cat_id: id(CAT_ID),
                disk_id: id(ROOT_DISK_ID),
                volume_id: id(ROOT_VOLUME_ID),
                size_bytes: 8 * 1024 * 1024,
            }
        }

        fn attach(&self, node_id: &str, volume: CatVolume) -> AttachedVolume {
            self.authority
                .attach_volume(&VolumeAttachRequest {
                    node_id: id(node_id),
                    volume,
                    lease_duration_ms: 60_000,
                })
                .expect("attach RootDisk")
        }

        fn seed_persistent(&mut self) {
            let size_bytes = 16 * 1024 * 1024_i64;
            let record = json!({
                "disk_id": PERSISTENT_DISK_ID,
                "workspace_id": WORKSPACE_ID,
                "name": "data",
                "volume_id": PERSISTENT_VOLUME_ID,
                "size_bytes": size_bytes,
                "durability": "strict",
                "created_at": 1,
                "admin_state": { "kind": "active" },
                "role": {
                    "kind": "persistent",
                    "initialization": {
                        "kind": "uninitialized",
                        "initialization_token": INITIALIZATION_TOKEN,
                        "filesystem_uuid": FILESYSTEM_UUID,
                        "expected_blank_head": {
                            "generation": 0,
                            "root_hash": null,
                            "root_object_id": null
                        }
                    }
                }
            });
            let record_json = serde_json::to_string(&record).expect("encode disk record");
            let mut transaction = self.client.transaction().expect("begin persistent seed");
            insert_volume(
                &mut transaction,
                &blank_volume(&id(PERSISTENT_VOLUME_ID), size_bytes as u64)
                    .expect("blank PersistentDisk volume"),
            )
            .expect("insert PersistentDisk volume");
            transaction
                .execute(
                    "INSERT INTO persistent_disks (
                        disk_id,workspace_id,disk_slug,size_bytes,volume_id,filesystem_uuid,
                        disk_format,status,created_at,deleted_at
                     ) VALUES ($1,$2,'data',$3,$4,$5,'ext4','normal',1,NULL)",
                    &[
                        &PERSISTENT_DISK_ID,
                        &WORKSPACE_ID,
                        &size_bytes,
                        &PERSISTENT_VOLUME_ID,
                        &FILESYSTEM_UUID,
                    ],
                )
                .expect("insert PersistentDisk product row");
            transaction
                .execute(
                    "INSERT INTO disk_bindings (
                        binding_id,workspace_id,disk_id,cat_id,mount_path,created_at
                     ) VALUES ('binding_cat_volume',$1,$2,$3,'/data',1)",
                    &[&WORKSPACE_ID, &PERSISTENT_DISK_ID, &CAT_ID],
                )
                .expect("insert PersistentDisk binding");
            transaction
                .execute(
                    "INSERT INTO disk_records (
                        disk_id,record,workspace_id,name,volume_id,size_bytes,durability,
                        created_at,admin_state,delete_id,role_kind,root_cat_id,
                        initialization_kind,initialization_token,filesystem_uuid,
                        expected_blank_generation,expected_blank_root_hash,
                        expected_blank_root_object_id,initialized_generation,
                        initialized_root_hash,initialized_root_object_id,initialized_at,
                        initialization_commit_receipt_bytes,
                        initialization_commit_receipt_digest
                     ) VALUES (
                        $1,$2::TEXT::jsonb,$3,'data',$4,$5,'strict',1,'active',NULL,
                        'persistent',NULL,'uninitialized',$6,$7,0,NULL,NULL,NULL,NULL,NULL,
                        NULL,NULL,NULL
                     )",
                    &[
                        &PERSISTENT_DISK_ID,
                        &record_json,
                        &WORKSPACE_ID,
                        &PERSISTENT_VOLUME_ID,
                        &size_bytes,
                        &INITIALIZATION_TOKEN,
                        &FILESYSTEM_UUID,
                    ],
                )
                .expect("insert PersistentDisk authority row");
            transaction.commit().expect("commit persistent seed");
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).expect("test ID is valid")
    }

    #[test]
    fn root_lifecycle_replays_by_current_volume_state() {
        let fixture = Fixture::new();
        let root = fixture
            .authority
            .ensure_root_volume(&Fixture::root_spec())
            .expect("create RootDisk");
        assert_eq!(
            fixture
                .authority
                .ensure_root_volume(&Fixture::root_spec())
                .expect("replay RootDisk create"),
            root
        );

        let first = fixture.attach(NODE_A, root.clone());
        let replay = fixture.attach(NODE_A, root.clone());
        assert_eq!(replay.serving.identity, first.serving.identity);
        fixture
            .authority
            .detach_volume(&first)
            .expect("detach RootDisk");
        fixture
            .authority
            .detach_volume(&first)
            .expect("replay RootDisk detach");

        let second = fixture.attach(NODE_B, root.clone());
        assert!(second.serving.identity.attachment_epoch > first.serving.identity.attachment_epoch);
        fixture
            .authority
            .detach_volume(&second)
            .expect("detach second owner");

        assert_eq!(
            fixture
                .authority
                .begin_root_delete(&root)
                .expect("begin RootDisk delete"),
            RootDeleteState::Deleting
        );
        assert_eq!(
            fixture
                .authority
                .begin_root_delete(&root)
                .expect("replay RootDisk delete"),
            RootDeleteState::Deleting
        );
        fixture
            .authority
            .complete_root_delete(&root)
            .expect("complete RootDisk delete");
        fixture
            .authority
            .complete_root_delete(&root)
            .expect("replay RootDisk delete completion");
    }

    #[test]
    fn offline_cross_node_attach_advances_epoch_and_fences_old_detach() {
        let mut fixture = Fixture::new();
        let root = fixture
            .authority
            .ensure_root_volume(&Fixture::root_spec())
            .expect("create RootDisk");
        let old = fixture.attach(NODE_A, root.clone());
        fixture
            .client
            .execute(
                "UPDATE nodes SET status='offline',updated_at=2 WHERE node_id=$1",
                &[&NODE_A],
            )
            .expect("mark old Node offline");

        let recovered = fixture.attach(NODE_B, root);
        assert!(
            recovered.serving.identity.attachment_epoch > old.serving.identity.attachment_epoch
        );
        fixture
            .authority
            .detach_volume(&old)
            .expect("stale detach is an idempotent no-op");
        let stored = fixture
            .authority
            .load_volume(&id(ROOT_VOLUME_ID))
            .expect("load recovered volume");
        assert_eq!(
            stored.lease_owner.as_ref(),
            Some(&recovered.serving.identity.attachment_id)
        );
        assert_eq!(
            stored.lease_epoch,
            recovered.serving.identity.attachment_epoch
        );
    }

    #[test]
    fn persistent_initialization_commits_exact_guest_evidence_once() {
        let mut fixture = Fixture::new();
        fixture.seed_persistent();
        let mount_path = HostPath::new("/data".to_owned()).expect("valid mount path");
        let persistent = fixture
            .authority
            .load_persistent_volume(
                &id(WORKSPACE_ID),
                &id(CAT_ID),
                &id(PERSISTENT_DISK_ID),
                &id(PERSISTENT_VOLUME_ID),
                &RandomId128::new(FILESYSTEM_UUID.to_owned()).expect("filesystem UUID"),
                &mount_path,
            )
            .expect("load PersistentDisk binding");
        assert!(matches!(
            persistent.role,
            CatVolumeRole::Persistent {
                initialization: PersistentInitialization::Uninitialized { .. },
                ..
            }
        ));
        let attached = fixture.attach(NODE_A, persistent);
        let initialized_head = RemoteHead {
            generation: Generation::new(1).expect("generation one"),
            root_hash: Some(Sha256Digest::from_bytes([7; 32])),
            root_object_id: Some(
                AsciiText::new("root-initialized.node".to_owned()).expect("root object ID"),
            ),
        };
        fixture
            .authority
            .compare_and_swap_head(&VolumeHeadCasRequest {
                volume_id: attached.volume.volume_id.clone(),
                attachment_id: attached.serving.identity.attachment_id.clone(),
                expected_epoch: attached.serving.identity.attachment_epoch,
                expected_size_bytes: attached.volume.size_bytes,
                expected_head: attached.volume.head.clone(),
                new_head: initialized_head.clone(),
            })
            .expect("publish initialized filesystem head");
        let commit = PersistentInitializationCommit {
            attached,
            initialized_head: initialized_head.clone(),
            guest_evidence: br#"{"probe":"ext4","flush":"remote"}"#.to_vec(),
        };
        let initialized = fixture
            .authority
            .commit_persistent_initialization(&commit)
            .expect("commit PersistentDisk initialization");
        assert!(matches!(
            initialized.role,
            CatVolumeRole::Persistent {
                initialization: PersistentInitialization::Initialized {
                    initialized_head: ref stored,
                },
                ..
            } if stored == &initialized_head
        ));
        assert_eq!(
            fixture
                .authority
                .commit_persistent_initialization(&commit)
                .expect("replay PersistentDisk initialization"),
            initialized
        );
        let mut conflict = commit;
        conflict.guest_evidence = b"different evidence".to_vec();
        assert_eq!(
            fixture
                .authority
                .commit_persistent_initialization(&conflict),
            Err(AuthorityError::BackendUnknown)
        );
    }
}

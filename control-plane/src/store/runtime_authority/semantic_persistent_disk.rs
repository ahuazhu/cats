//! Scenario-idempotent Strict PersistentDisk authority for the semantic API.
//!
//! The semantic row is admitted first and supplies one immutable candidate.
//! This module discovers or creates exactly that candidate in the existing
//! Volume Authority catalog. It deliberately has no caller request token and
//! no lifecycle Operation.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{FenceEpoch, Generation, Id, RandomId128};
use cats_storage::authority::{
    begin_delete, BeginDeleteRequest, LastVolumeTransition, RemoteHead, VolumeAdminState,
    VolumeDurability, VolumeRecord, VolumeTransitionSource,
};

use super::product::{
    lock_candidate_id, lock_candidate_text, lock_disk_name, DiskAdminState, DiskRecord, DiskRole,
    PersistentDiskInitialization,
};
use super::product_rows::{
    insert_disk, load_any_disk_by_filesystem_uuid_for_update, load_any_disk_by_id_for_update,
    load_any_disk_by_initialization_token_for_update, load_any_disk_by_name_unlocked,
    load_any_disk_snapshot_for_update, update_disk,
};
use super::rows::{
    insert_volume, load_any_volume_by_id_for_update, load_volume_unlocked, update_volume,
};
use crate::store::{Result, Store};

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

impl Store {
    /// Creates or discovers one exact blank Strict Volume and its persistent
    /// Disk identity. PostgreSQL commit is the provision terminal for an empty
    /// remotely durable Volume: there are no BlobStore objects to publish.
    pub(crate) fn ensure_semantic_strict_disk_created(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<()> {
        validate_candidate(candidate)?;
        self.authority_transaction(|transaction| {
            lock_disk_name(transaction, &candidate.workspace_id, &candidate.name)?;
            lock_candidate_id(transaction, "volume", &candidate.volume_id)?;
            lock_candidate_id(transaction, "disk", &candidate.disk_id)?;
            lock_candidate_text(
                transaction,
                "disk-initialization-token",
                candidate.initialization_token.as_str(),
            )?;
            lock_candidate_text(
                transaction,
                "disk-filesystem-uuid",
                candidate.filesystem_uuid.as_str(),
            )?;

            let by_name = load_any_disk_by_name_unlocked(
                transaction,
                &candidate.workspace_id,
                &candidate.name,
            )?;
            let by_id = load_any_disk_by_id_for_update(transaction, &candidate.disk_id)?;
            let volume = load_any_volume_by_id_for_update(transaction, &candidate.volume_id)?;
            let by_initialization = load_any_disk_by_initialization_token_for_update(
                transaction,
                &candidate.initialization_token,
            )?;
            let by_filesystem = load_any_disk_by_filesystem_uuid_for_update(
                transaction,
                &candidate.filesystem_uuid,
            )?;

            match (by_id, volume) {
                (Some(disk), Some(volume)) => {
                    if by_name.as_ref() != Some(&disk)
                        || by_initialization.as_ref() != Some(&disk)
                        || by_filesystem.as_ref() != Some(&disk)
                        || !exact_blank_candidate(candidate, &disk, &volume)
                    {
                        return Err(inconsistent("stored provision identity differs").into());
                    }
                    Ok(())
                }
                (None, None)
                    if by_name.is_none()
                        && by_initialization.is_none()
                        && by_filesystem.is_none() =>
                {
                    let blank_head = blank_head();
                    let volume = VolumeRecord {
                        volume_id: candidate.volume_id.clone(),
                        size_bytes: candidate.size_bytes,
                        durability: VolumeDurability::Strict,
                        admin_state: VolumeAdminState::Active,
                        head: blank_head.clone(),
                        lease_owner: None,
                        lease_epoch: FenceEpoch::new(0)
                            .expect("zero is a valid initial Volume epoch"),
                        lease_expires_at: None,
                        last_transition: None,
                    };
                    let disk = DiskRecord {
                        disk_id: candidate.disk_id.clone(),
                        workspace_id: candidate.workspace_id.clone(),
                        name: candidate.name.clone(),
                        volume_id: candidate.volume_id.clone(),
                        size_bytes: candidate.size_bytes,
                        durability: VolumeDurability::Strict,
                        created_at: super::rows::database_now(transaction)?,
                        admin_state: DiskAdminState::Active,
                        role: DiskRole::Persistent {
                            initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                                initialization_token: candidate.initialization_token.clone(),
                                filesystem_uuid: candidate.filesystem_uuid.clone(),
                                expected_blank_head: blank_head,
                            }),
                        },
                    };
                    insert_volume(transaction, &volume)?;
                    insert_disk(transaction, &disk)
                }
                _ => Err(inconsistent("partially occupied provision identity").into()),
            }
        })
    }

    /// Starts or discovers the exact independent normal-delete transition.
    /// The caller must subsequently drive [`super::delete_sweeper::DeleteSweeper`]
    /// and publish semantic deletion only after both authority rows disappear.
    pub(crate) fn begin_semantic_strict_disk_delete(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<SemanticStrictDeleteState> {
        validate_candidate(candidate)?;
        self.authority_transaction(|transaction| {
            lock_candidate_id(transaction, "volume", &candidate.volume_id)?;
            lock_candidate_id(transaction, "disk", &candidate.disk_id)?;
            let volume = load_any_volume_by_id_for_update(transaction, &candidate.volume_id)?;
            let disk = load_any_disk_by_id_for_update(transaction, &candidate.disk_id)?;
            let (volume, mut disk) = match (volume, disk) {
                (Some(volume), Some(disk)) => (volume, disk),
                (None, None) => return Ok(SemanticStrictDeleteState::Absent),
                _ => {
                    return Err(inconsistent("only one authority row remains during delete").into());
                }
            };
            if !exact_persistent_identity(candidate, &disk, &volume) {
                return Err(inconsistent("delete identity differs from authority").into());
            }
            if load_any_disk_snapshot_for_update(
                transaction,
                &disk.disk_id,
                &volume.volume_id,
                disk.size_bytes,
            )?
            .is_some()
            {
                return Err(ApiError::failed_precondition(
                    "PersistentDisk has a live DiskSnapshot",
                )
                .into());
            }
            match (&disk.admin_state, &volume.admin_state) {
                (DiskAdminState::Active, VolumeAdminState::Active) => {
                    let request = BeginDeleteRequest {
                        delete_id: candidate.delete_id.clone(),
                        disk_id: candidate.disk_id.clone(),
                        volume_id: candidate.volume_id.clone(),
                        expected_unowned_epoch: volume.lease_epoch,
                        expected_head: volume.head.clone(),
                    };
                    let (deleting, _) = begin_delete(&volume, &request)?;
                    disk.admin_state = DiskAdminState::Deleting {
                        delete_id: candidate.delete_id.clone(),
                    };
                    update_volume(transaction, &deleting)?;
                    update_disk(transaction, &disk)?;
                }
                (
                    DiskAdminState::Deleting {
                        delete_id: disk_delete_id,
                    },
                    VolumeAdminState::Deleting {
                        delete_id: volume_delete_id,
                    },
                ) if disk_delete_id == &candidate.delete_id
                    && volume_delete_id == &candidate.delete_id
                    && matches!(
                        volume.last_transition.as_ref(),
                        Some(LastVolumeTransition::BeginDelete {
                            source: VolumeTransitionSource::Independent,
                            request,
                            result,
                        }) if request.delete_id == candidate.delete_id
                            && request.disk_id == candidate.disk_id
                            && request.volume_id == candidate.volume_id
                            && result.delete_id == candidate.delete_id
                            && result.disk_id == candidate.disk_id
                            && result.volume_id == candidate.volume_id
                            && result.resulting_epoch == volume.lease_epoch
                            && result.resulting_head == volume.head
                    ) => {}
                _ => {
                    return Err(inconsistent("delete transition identity differs").into());
                }
            }
            Ok(SemanticStrictDeleteState::Deleting)
        })
    }

    /// Exact postcondition discovery used after an ambiguous delete sweep.
    pub(crate) fn semantic_strict_disk_is_absent(
        &self,
        candidate: &SemanticStrictPersistentDisk,
    ) -> Result<bool> {
        validate_candidate(candidate)?;
        self.authority_read_snapshot(|transaction| {
            let disk =
                super::product_rows::load_disk_by_id_unlocked(transaction, &candidate.disk_id)?;
            let volume = load_volume_unlocked(transaction, &candidate.volume_id)?;
            match (disk, volume) {
                (None, None) => Ok(true),
                (Some(disk), Some(volume))
                    if exact_persistent_identity(candidate, &disk, &volume) =>
                {
                    Ok(false)
                }
                _ => Err(inconsistent("delete discovery found a mismatched authority").into()),
            }
        })
    }
}

fn exact_blank_candidate(
    candidate: &SemanticStrictPersistentDisk,
    disk: &DiskRecord,
    volume: &VolumeRecord,
) -> bool {
    exact_persistent_identity(candidate, disk, volume)
        && matches!(disk.admin_state, DiskAdminState::Active)
        && matches!(volume.admin_state, VolumeAdminState::Active)
        && volume.head == blank_head()
        && volume.lease_owner.is_none()
        && volume.lease_epoch.get() == 0
        && volume.lease_expires_at.is_none()
        && volume.last_transition.is_none()
        && matches!(
            disk.role,
            DiskRole::Persistent {
                initialization: ref value
            } if matches!(
                value.as_ref(),
                PersistentDiskInitialization::Uninitialized { .. }
            )
        )
}

fn exact_persistent_identity(
    candidate: &SemanticStrictPersistentDisk,
    disk: &DiskRecord,
    volume: &VolumeRecord,
) -> bool {
    let initialization_matches = match &disk.role {
        DiskRole::Persistent { initialization } => match initialization.as_ref() {
            PersistentDiskInitialization::Uninitialized {
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
            }
            | PersistentDiskInitialization::Initialized {
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
                ..
            } => {
                initialization_token == &candidate.initialization_token
                    && filesystem_uuid == &candidate.filesystem_uuid
                    && expected_blank_head == &blank_head()
            }
        },
        DiskRole::Root { .. } => false,
    };
    disk.disk_id == candidate.disk_id
        && disk.workspace_id == candidate.workspace_id
        && disk.name == candidate.name
        && disk.volume_id == candidate.volume_id
        && disk.size_bytes == candidate.size_bytes
        && disk.durability == VolumeDurability::Strict
        && volume.volume_id == candidate.volume_id
        && volume.size_bytes == candidate.size_bytes
        && volume.durability == VolumeDurability::Strict
        && initialization_matches
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).expect("zero is a valid initial generation"),
        root_hash: None,
        root_object_id: None,
    }
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

fn inconsistent(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "semantic Strict PersistentDisk authority is inconsistent: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::runtime_authority::lifecycle_commands_tests::{test_store, workspace_id};

    fn candidate(store: &Store) -> SemanticStrictPersistentDisk {
        SemanticStrictPersistentDisk {
            disk_id: Id::new("disk_11111111111111111111111111111111").unwrap(),
            workspace_id: workspace_id(store, "semantic-strict-disk"),
            name: Id::new("data").unwrap(),
            volume_id: Id::new("vol_22222222222222222222222222222222").unwrap(),
            size_bytes: 4 * 1024 * 1024,
            initialization_token: RandomId128::new("33333333333333333333333333333333").unwrap(),
            filesystem_uuid: RandomId128::new("44444444444444444444444444444444").unwrap(),
            delete_id: Id::new("delete_55555555555555555555555555555555").unwrap(),
        }
    }

    #[test]
    fn exact_create_and_delete_begin_replay_without_request_identity() {
        let store = test_store();
        let candidate = candidate(&store);

        store
            .ensure_semantic_strict_disk_created(&candidate)
            .unwrap();
        store
            .ensure_semantic_strict_disk_created(&candidate)
            .unwrap();
        assert_eq!(
            store.begin_semantic_strict_disk_delete(&candidate).unwrap(),
            SemanticStrictDeleteState::Deleting
        );
        assert_eq!(
            store.begin_semantic_strict_disk_delete(&candidate).unwrap(),
            SemanticStrictDeleteState::Deleting
        );
        assert!(!store.semantic_strict_disk_is_absent(&candidate).unwrap());
    }

    #[test]
    fn create_discovery_rejects_an_identity_mismatch() {
        let store = test_store();
        let candidate = candidate(&store);
        store
            .ensure_semantic_strict_disk_created(&candidate)
            .unwrap();

        let mut mismatch = candidate.clone();
        mismatch.size_bytes += 1;
        assert!(store
            .ensure_semantic_strict_disk_created(&mismatch)
            .is_err());
    }
}

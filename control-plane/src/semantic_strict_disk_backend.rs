//! Production Strict-volume adapter for the semantic PersistentDisk API.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::runtime_reconciliation::{Id, RandomId128};
use cats_storage::{delete_volume_objects_page, BlobStore, DeletePrefixPage};
use sha2::{Digest, Sha256};

use crate::api::semantic_resources::SemanticResourceFuture;
use crate::semantic_resource_service::{ResourceStoreError, SemanticPersistentDiskBackend};
use crate::store::runtime_authority::semantic_persistent_disk::{
    SemanticStrictDeleteState, SemanticStrictPersistentDisk,
};
use crate::store::semantic::PersistentDiskRecord;
use crate::store::Store;

const DELETE_DEADLINE: Duration = Duration::from_secs(10);

/// Uses the selected PostgreSQL Volume Authority and BlobStore delete
/// postcondition. It owns no compatibility MetadataStore path.
pub struct AuthorityPersistentDiskBackend {
    store: Arc<Store>,
    blob: Arc<dyn BlobStore>,
}

impl AuthorityPersistentDiskBackend {
    pub fn new(store: Arc<Store>, blob: Arc<dyn BlobStore>) -> Self {
        Self { store, blob }
    }
}

impl SemanticPersistentDiskBackend for AuthorityPersistentDiskBackend {
    fn ensure_created<'a>(
        &'a self,
        disk: &'a PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>> {
        let candidate = match authority_candidate(disk) {
            Ok(candidate) => candidate,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| store.ensure_semantic_strict_disk_created(&candidate))
                .await
                .map_err(resource_error)
        })
    }

    fn ensure_destroyed<'a>(
        &'a self,
        disk: &'a PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>> {
        let candidate = match authority_candidate(disk) {
            Ok(candidate) => candidate,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let store = Arc::clone(&self.store);
        let blob = Arc::clone(&self.blob);
        Box::pin(async move {
            let begin_candidate = candidate.clone();
            let state = store
                .execute(move |store| store.begin_semantic_strict_disk_delete(&begin_candidate))
                .await
                .map_err(resource_error)?;
            if state == SemanticStrictDeleteState::Absent {
                return Ok(());
            }

            let deadline = Instant::now() + DELETE_DEADLINE;
            loop {
                if Instant::now() >= deadline {
                    return Err(ResourceStoreError {
                        message: "strict PersistentDisk deletion did not reach its exact backend postcondition"
                            .to_owned(),
                    });
                }
                let page_blob = Arc::clone(&blob);
                let volume_id = candidate.volume_id.clone();
                let page = tokio::task::spawn_blocking(move || {
                    delete_volume_objects_page(
                        page_blob.as_ref(),
                        &volume_id,
                        cats_storage::BLOB_LIST_PAGE_MAX_KEYS,
                        deadline,
                    )
                })
                .await
                .map_err(|error| ResourceStoreError {
                    message: format!("strict PersistentDisk delete worker failed: {error}"),
                })?
                .map_err(|error| ResourceStoreError {
                    message: format!("strict PersistentDisk delete sweep failed: {error}"),
                })?;
                if matches!(
                    page,
                    DeletePrefixPage::Empty
                        | DeletePrefixPage::Progress {
                            now_empty: true,
                            ..
                        }
                ) {
                    let completion_candidate = candidate.clone();
                    store
                        .execute(move |store| {
                            store.complete_semantic_strict_disk_delete(&completion_candidate)
                        })
                        .await
                        .map_err(resource_error)?;
                    let discovery_candidate = candidate.clone();
                    if store
                        .execute(move |store| {
                            store.semantic_strict_disk_is_absent(&discovery_candidate)
                        })
                        .await
                        .map_err(resource_error)?
                    {
                        return Ok(());
                    }
                }
                tokio::task::yield_now().await;
            }
        })
    }
}

fn authority_candidate(
    disk: &PersistentDiskRecord,
) -> Result<SemanticStrictPersistentDisk, ResourceStoreError> {
    if disk.disk_format != "ext4" || disk.size_bytes <= 0 {
        return Err(invalid_record("format or size is invalid"));
    }
    let disk_id = parse_id(&disk.disk_id, "disk_")?;
    let volume_id = parse_id(&disk.volume_id, "vol_")?;
    let workspace_id = Id::new(disk.workspace_id.clone())
        .ok_or_else(|| invalid_record("Workspace ID is invalid"))?;
    let name =
        Id::new(disk.disk_slug.clone()).ok_or_else(|| invalid_record("Disk slug is invalid"))?;
    let filesystem_uuid = RandomId128::new(disk.filesystem_uuid.clone())
        .ok_or_else(|| invalid_record("filesystem UUID is invalid"))?;
    let mut initialization_token = derive_random_id(
        b"cats.semantic-strict-disk.initialization.v1\0",
        disk_id.as_str(),
    );
    if initialization_token == filesystem_uuid {
        initialization_token = derive_random_id(
            b"cats.semantic-strict-disk.initialization.v1.collision\0",
            disk_id.as_str(),
        );
    }
    let delete_random =
        derive_random_id(b"cats.semantic-strict-disk.delete.v1\0", disk_id.as_str());
    let delete_id = Id::new(format!("delete_{}", delete_random.as_str()))
        .ok_or_else(|| invalid_record("derived delete ID is invalid"))?;
    Ok(SemanticStrictPersistentDisk {
        disk_id,
        workspace_id,
        name,
        volume_id,
        size_bytes: u64::try_from(disk.size_bytes)
            .map_err(|_| invalid_record("size is invalid"))?,
        initialization_token,
        filesystem_uuid,
        delete_id,
    })
}

fn parse_id(value: &str, prefix: &str) -> Result<Id, ResourceStoreError> {
    let id = Id::new(value.to_owned()).ok_or_else(|| invalid_record("immutable ID is invalid"))?;
    let valid = id.as_str().strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    valid
        .then_some(id)
        .ok_or_else(|| invalid_record("immutable ID is not a full random identity"))
}

fn derive_random_id(namespace: &[u8], value: &str) -> RandomId128 {
    let mut digest = Sha256::new();
    digest.update(namespace);
    digest.update(value.as_bytes());
    RandomId128::new(hex::encode(&digest.finalize()[..16]))
        .expect("a 16-byte SHA-256 prefix is a valid RandomId128")
}

fn resource_error(error: cats_api::error::ApiError) -> ResourceStoreError {
    ResourceStoreError {
        message: error.message,
    }
}

fn invalid_record(message: &str) -> ResourceStoreError {
    ResourceStoreError {
        message: format!("stored semantic PersistentDisk {message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_derivation_is_stable_and_binds_exact_identity() {
        let disk = PersistentDiskRecord {
            disk_id: "disk_11111111111111111111111111111111".to_owned(),
            workspace_id: "ws_test".to_owned(),
            disk_slug: "data".to_owned(),
            size_bytes: 4096,
            volume_id: "vol_22222222222222222222222222222222".to_owned(),
            filesystem_uuid: "33333333333333333333333333333333".to_owned(),
            disk_format: "ext4".to_owned(),
            status: "provisioning".to_owned(),
            created_at: 1,
            deleted_at: None,
        };
        let first = authority_candidate(&disk).unwrap();
        let second = authority_candidate(&disk).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.disk_id.as_str(), disk.disk_id);
        assert_eq!(first.volume_id.as_str(), disk.volume_id);
        assert_eq!(first.filesystem_uuid.as_str(), disk.filesystem_uuid);
        assert_ne!(first.initialization_token, first.filesystem_uuid);
    }

    #[test]
    fn short_or_non_ext4_semantic_identity_fails_closed() {
        let mut disk = PersistentDiskRecord {
            disk_id: "disk_short".to_owned(),
            workspace_id: "ws_test".to_owned(),
            disk_slug: "data".to_owned(),
            size_bytes: 4096,
            volume_id: "vol_22222222222222222222222222222222".to_owned(),
            filesystem_uuid: "33333333333333333333333333333333".to_owned(),
            disk_format: "ext4".to_owned(),
            status: "provisioning".to_owned(),
            created_at: 1,
            deleted_at: None,
        };
        assert!(authority_candidate(&disk).is_err());
        disk.disk_id = "disk_11111111111111111111111111111111".to_owned();
        disk.disk_format = "xfs".to_owned();
        assert!(authority_candidate(&disk).is_err());
    }
}

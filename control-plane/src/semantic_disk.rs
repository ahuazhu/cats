//! Scenario-semantic PersistentDisk control state.
//!
//! This module deliberately knows nothing about lifecycle Operations.  A
//! caller runs one method while it owns the corresponding PostgreSQL row
//! locks, persists the resulting aggregate, and sends the returned complete
//! mount set to the Node.  The storage backend remains the existing strict,
//! remotely durable volume implementation.

use std::collections::BTreeMap;

use cats_api::chunk::MAX_VOLUME_BYTES;
use cats_api::runtime_reconciliation::{Id, RandomId128};
use cats_api::semantic_control::{
    AttachDiskRequest, CreateDiskRequest, DetachDiskRequest, DiskStatus, NodedDiskMount,
    PersistentDiskFormat, PersistentMountPath, ResourceSlug,
};
use serde::{Deserialize, Serialize};

/// The Cat state relevant to PersistentDisk configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatDiskState {
    Creating,
    Running,
    Suspended,
    Warm,
    Cold,
    Failure,
    Destroyed,
}

/// The immutable handle returned by the existing strict remote disk backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictVolumeDescriptor {
    pub volume_id: Id,
    pub filesystem_uuid: RandomId128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentDisk {
    pub disk_id: Id,
    pub workspace_id: Id,
    pub disk_slug: ResourceSlug,
    pub size_bytes: u64,
    pub status: DiskStatus,
    pub strict_volume: StrictVolumeDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskBinding {
    pub disk_id: Id,
    pub cat_id: Id,
    pub mount_path: PersistentMountPath,
}

/// Complete snapshot, never a binding delta. Entries are shared-wire
/// [`NodedDiskMount`] values sorted by disk ID.
pub type CompleteMountSet = Vec<NodedDiskMount>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateDiskOutcome {
    Created(PersistentDisk),
    AlreadyExists(PersistentDisk),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachDiskOutcome {
    Attached(CompleteMountSet),
    AlreadyAttached(CompleteMountSet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetachDiskOutcome {
    Detached(CompleteMountSet),
    AlreadyDetached(CompleteMountSet),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyDiskOutcome {
    Destroyed,
    AlreadyDeleted,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SemanticDiskError {
    #[error("PersistentDisk size is outside the supported range")]
    InvalidSize,
    #[error("the immutable disk ID is already used")]
    DiskIdConflict,
    #[error("the active disk with this slug has size {existing}, not {requested}")]
    DiskSizeConflict { existing: u64, requested: u64 },
    #[error("PersistentDisk was not found")]
    DiskNotFound,
    #[error("PersistentDisk is deleted")]
    DiskDeleted,
    #[error("Cat and PersistentDisk belong to different Workspaces")]
    WorkspaceMismatch,
    #[error("PersistentDisk configuration requires a creating or Cold Cat")]
    CatMustBeCold,
    #[error("PersistentDisk detach requires a Cold Cat")]
    DetachRequiresCold,
    #[error("request Cat slug does not identify the locked Cat")]
    CatIdentityMismatch,
    #[error("PersistentDisk is already attached to another Cat")]
    DiskAlreadyAttached,
    #[error("PersistentDisk is attached to this Cat at a different path")]
    MountPathConflict,
    #[error("another PersistentDisk already uses this Cat mount path")]
    CatMountPathConflict,
    #[error("the requested Cat does not own this PersistentDisk binding")]
    DiskBindingConflict,
    #[error("PersistentDisk is still bound to a Cat")]
    DiskInUse,
}

#[derive(Debug, thiserror::Error)]
pub enum SemanticDiskServiceError<E> {
    #[error(transparent)]
    Semantic(#[from] SemanticDiskError),
    #[error("strict remote disk backend failed: {0}")]
    Backend(E),
}

/// Narrow adapter over the already selected strict remote volume backend.
///
/// Implementations must not acknowledge `create_strict` until the immutable
/// volume identity is durably reserved, and must make repeated destroy of the
/// same descriptor safe.
pub trait StrictPersistentDiskBackend {
    type Error;

    fn create_strict(
        &mut self,
        disk_id: &Id,
        size_bytes: u64,
    ) -> Result<StrictVolumeDescriptor, Self::Error>;

    fn destroy_strict(&mut self, disk: &PersistentDisk) -> Result<(), Self::Error>;
}

/// Transaction aggregate for the current disk rows and bindings.
///
/// PostgreSQL remains responsible for concurrent row locking and the partial
/// unique indexes.  Keeping the decisions here makes the same scenario rules
/// available to HTTP handlers, timeout recovery and tests.
#[derive(Debug, Default)]
pub struct SemanticDiskCatalog {
    disks: BTreeMap<Id, PersistentDisk>,
    current_slugs: BTreeMap<(Id, ResourceSlug), Id>,
    bindings: BTreeMap<Id, DiskBinding>,
    cat_mounts: BTreeMap<(Id, PersistentMountPath), Id>,
}

impl SemanticDiskCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_disk<B: StrictPersistentDiskBackend>(
        &mut self,
        backend: &mut B,
        workspace_id: Id,
        request: CreateDiskRequest,
        new_disk_id: Id,
    ) -> Result<CreateDiskOutcome, SemanticDiskServiceError<B::Error>> {
        if request.validate().is_err() || request.size_bytes > MAX_VOLUME_BYTES {
            return Err(SemanticDiskError::InvalidSize.into());
        }
        let slug_key = (workspace_id.clone(), request.disk_slug.clone());
        if let Some(current_id) = self.current_slugs.get(&slug_key) {
            let current = self
                .disks
                .get(current_id)
                .expect("current slug index must reference a disk");
            return if current.size_bytes == request.size_bytes {
                Ok(CreateDiskOutcome::AlreadyExists(current.clone()))
            } else {
                Err(SemanticDiskError::DiskSizeConflict {
                    existing: current.size_bytes,
                    requested: request.size_bytes,
                }
                .into())
            };
        }
        if self.disks.contains_key(&new_disk_id) {
            return Err(SemanticDiskError::DiskIdConflict.into());
        }

        let strict_volume = backend
            .create_strict(&new_disk_id, request.size_bytes)
            .map_err(SemanticDiskServiceError::Backend)?;
        let disk = PersistentDisk {
            disk_id: new_disk_id.clone(),
            workspace_id,
            disk_slug: request.disk_slug,
            size_bytes: request.size_bytes,
            status: DiskStatus::Normal,
            strict_volume,
        };
        self.current_slugs.insert(slug_key, new_disk_id.clone());
        self.disks.insert(new_disk_id, disk.clone());
        Ok(CreateDiskOutcome::Created(disk))
    }

    pub fn attach_disk(
        &mut self,
        cat_id: &Id,
        cat_slug: &ResourceSlug,
        cat_workspace_id: &Id,
        cat_state: CatDiskState,
        disk_id: &Id,
        request: AttachDiskRequest,
    ) -> Result<AttachDiskOutcome, SemanticDiskError> {
        if !matches!(cat_state, CatDiskState::Creating | CatDiskState::Cold) {
            return Err(SemanticDiskError::CatMustBeCold);
        }
        if &request.cat_slug != cat_slug {
            return Err(SemanticDiskError::CatIdentityMismatch);
        }
        let disk = self
            .disks
            .get(disk_id)
            .ok_or(SemanticDiskError::DiskNotFound)?;
        if disk.status == DiskStatus::Deleted {
            return Err(SemanticDiskError::DiskDeleted);
        }
        if &disk.workspace_id != cat_workspace_id {
            return Err(SemanticDiskError::WorkspaceMismatch);
        }

        if let Some(binding) = self.bindings.get(disk_id) {
            if &binding.cat_id != cat_id {
                return Err(SemanticDiskError::DiskAlreadyAttached);
            }
            if binding.mount_path != request.mount_path {
                return Err(SemanticDiskError::MountPathConflict);
            }
            return Ok(AttachDiskOutcome::AlreadyAttached(
                self.complete_mount_set(cat_id)?,
            ));
        }
        if self
            .cat_mounts
            .contains_key(&(cat_id.clone(), request.mount_path.clone()))
        {
            return Err(SemanticDiskError::CatMountPathConflict);
        }

        let binding = DiskBinding {
            disk_id: disk_id.clone(),
            cat_id: cat_id.clone(),
            mount_path: request.mount_path.clone(),
        };
        self.bindings.insert(disk_id.clone(), binding);
        self.cat_mounts
            .insert((cat_id.clone(), request.mount_path), disk_id.clone());
        Ok(AttachDiskOutcome::Attached(
            self.complete_mount_set(cat_id)?,
        ))
    }

    pub fn detach_disk(
        &mut self,
        cat_id: &Id,
        cat_slug: &ResourceSlug,
        cat_state: CatDiskState,
        disk_id: &Id,
        request: DetachDiskRequest,
    ) -> Result<DetachDiskOutcome, SemanticDiskError> {
        if cat_state != CatDiskState::Cold {
            return Err(SemanticDiskError::DetachRequiresCold);
        }
        if &request.cat_slug != cat_slug {
            return Err(SemanticDiskError::CatIdentityMismatch);
        }
        if !self.disks.contains_key(disk_id) {
            return Err(SemanticDiskError::DiskNotFound);
        }
        let Some(binding) = self.bindings.get(disk_id).cloned() else {
            return Ok(DetachDiskOutcome::AlreadyDetached(
                self.complete_mount_set(cat_id)?,
            ));
        };
        if &binding.cat_id != cat_id {
            return Err(SemanticDiskError::DiskBindingConflict);
        }
        self.bindings.remove(disk_id);
        self.cat_mounts
            .remove(&(cat_id.clone(), binding.mount_path));
        Ok(DetachDiskOutcome::Detached(
            self.complete_mount_set(cat_id)?,
        ))
    }

    /// Product Cat destroy only removes configuration bindings.
    pub fn destroy_cat_bindings(
        &mut self,
        cat_id: &Id,
    ) -> Result<Vec<DiskBinding>, SemanticDiskError> {
        let disk_ids = self
            .bindings
            .values()
            .filter(|binding| &binding.cat_id == cat_id)
            .map(|binding| binding.disk_id.clone())
            .collect::<Vec<_>>();
        let mut removed = Vec::with_capacity(disk_ids.len());
        for disk_id in disk_ids {
            let binding = self
                .bindings
                .remove(&disk_id)
                .expect("binding selected from the same map must exist");
            self.cat_mounts
                .remove(&(cat_id.clone(), binding.mount_path.clone()));
            removed.push(binding);
        }
        removed.sort_by(|left, right| left.disk_id.cmp(&right.disk_id));
        Ok(removed)
    }

    pub fn destroy_disk<B: StrictPersistentDiskBackend>(
        &mut self,
        backend: &mut B,
        disk_id: &Id,
    ) -> Result<DestroyDiskOutcome, SemanticDiskServiceError<B::Error>> {
        let disk = self
            .disks
            .get(disk_id)
            .ok_or(SemanticDiskError::DiskNotFound)?;
        if disk.status == DiskStatus::Deleted {
            return Ok(DestroyDiskOutcome::AlreadyDeleted);
        }
        if self.bindings.contains_key(disk_id) {
            return Err(SemanticDiskError::DiskInUse.into());
        }
        backend
            .destroy_strict(disk)
            .map_err(SemanticDiskServiceError::Backend)?;

        let disk = self.disks.get_mut(disk_id).expect("disk was checked above");
        disk.status = DiskStatus::Deleted;
        self.current_slugs
            .remove(&(disk.workspace_id.clone(), disk.disk_slug.clone()));
        Ok(DestroyDiskOutcome::Destroyed)
    }

    pub fn complete_mount_set(&self, cat_id: &Id) -> Result<CompleteMountSet, SemanticDiskError> {
        let mut mounts = Vec::new();
        for binding in self
            .bindings
            .values()
            .filter(|binding| &binding.cat_id == cat_id)
        {
            let disk = self
                .disks
                .get(&binding.disk_id)
                .ok_or(SemanticDiskError::DiskNotFound)?;
            if disk.status != DiskStatus::Normal {
                return Err(SemanticDiskError::DiskDeleted);
            }
            mounts.push(NodedDiskMount {
                disk_id: disk.disk_id.clone(),
                volume_id: disk.strict_volume.volume_id.clone(),
                filesystem_uuid: disk.strict_volume.filesystem_uuid.clone(),
                format: PersistentDiskFormat::Ext4,
                mount_path: binding.mount_path.clone(),
            });
        }
        mounts.sort_by(|left, right| left.disk_id.cmp(&right.disk_id));
        Ok(mounts)
    }

    pub fn current_disk(&self, workspace_id: &Id, slug: &ResourceSlug) -> Option<&PersistentDisk> {
        self.current_slugs
            .get(&(workspace_id.clone(), slug.clone()))
            .and_then(|disk_id| self.disks.get(disk_id))
    }

    pub fn disk_by_id(&self, disk_id: &Id) -> Option<&PersistentDisk> {
        self.disks.get(disk_id)
    }

    pub fn binding(&self, disk_id: &Id) -> Option<&DiskBinding> {
        self.bindings.get(disk_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("injected backend failure")]
    struct BackendError;

    #[derive(Default)]
    struct RecordingBackend {
        creates: Vec<Id>,
        destroys: Vec<Id>,
        fail_create: bool,
        fail_destroy: bool,
    }

    impl StrictPersistentDiskBackend for RecordingBackend {
        type Error = BackendError;

        fn create_strict(
            &mut self,
            disk_id: &Id,
            _size_bytes: u64,
        ) -> Result<StrictVolumeDescriptor, Self::Error> {
            if self.fail_create {
                return Err(BackendError);
            }
            self.creates.push(disk_id.clone());
            let suffix = disk_id.as_str().rsplit('_').next().unwrap_or("1");
            let digit = suffix.bytes().last().unwrap_or(b'1');
            let hex = if digit.is_ascii_hexdigit() {
                digit as char
            } else {
                '1'
            };
            Ok(StrictVolumeDescriptor {
                volume_id: id(&format!("vol_{suffix}")),
                filesystem_uuid: random(&hex.to_string().repeat(32)),
            })
        }

        fn destroy_strict(&mut self, disk: &PersistentDisk) -> Result<(), Self::Error> {
            if self.fail_destroy {
                return Err(BackendError);
            }
            self.destroys.push(disk.disk_id.clone());
            Ok(())
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: &str) -> RandomId128 {
        RandomId128::new(value).unwrap()
    }

    fn slug(value: &str) -> ResourceSlug {
        ResourceSlug::new(value).unwrap()
    }

    fn attach_request(cat_slug: &str, mount_path: &str) -> AttachDiskRequest {
        AttachDiskRequest {
            cat_slug: slug(cat_slug),
            mount_path: PersistentMountPath::new(mount_path).unwrap(),
        }
    }

    fn detach_request(cat_slug: &str) -> DetachDiskRequest {
        DetachDiskRequest {
            cat_slug: slug(cat_slug),
        }
    }

    fn create(
        catalog: &mut SemanticDiskCatalog,
        backend: &mut RecordingBackend,
        workspace: &str,
        slug: &str,
        size: u64,
        disk_id: &str,
    ) -> CreateDiskOutcome {
        catalog
            .create_disk(
                backend,
                id(workspace),
                CreateDiskRequest {
                    disk_slug: self::slug(slug),
                    size_bytes: size,
                },
                id(disk_id),
            )
            .unwrap()
    }

    #[test]
    fn create_is_semantically_idempotent_and_slug_reuses_after_delete() {
        let mut catalog = SemanticDiskCatalog::new();
        let mut backend = RecordingBackend::default();
        let first = create(&mut catalog, &mut backend, "ws_a", "data", 100, "disk_1");
        assert!(matches!(first, CreateDiskOutcome::Created(_)));

        let retry = create(&mut catalog, &mut backend, "ws_a", "data", 100, "disk_2");
        let CreateDiskOutcome::AlreadyExists(existing) = retry else {
            panic!("same semantic create did not return the current disk");
        };
        assert_eq!(existing.disk_id, id("disk_1"));
        assert_eq!(backend.creates, vec![id("disk_1")]);
        assert!(matches!(
            catalog.create_disk(
                &mut backend,
                id("ws_a"),
                CreateDiskRequest {
                    disk_slug: slug("data"),
                    size_bytes: 101,
                },
                id("disk_2")
            ),
            Err(SemanticDiskServiceError::Semantic(
                SemanticDiskError::DiskSizeConflict { .. }
            ))
        ));

        assert_eq!(
            catalog.destroy_disk(&mut backend, &id("disk_1")).unwrap(),
            DestroyDiskOutcome::Destroyed
        );
        let second = create(&mut catalog, &mut backend, "ws_a", "data", 101, "disk_2");
        let CreateDiskOutcome::Created(second) = second else {
            panic!("released slug did not create a new disk");
        };
        assert_eq!(second.disk_id, id("disk_2"));
        assert_eq!(
            catalog
                .current_disk(&id("ws_a"), &slug("data"))
                .unwrap()
                .disk_id,
            id("disk_2")
        );
        assert_eq!(
            catalog.disk_by_id(&id("disk_1")).unwrap().status,
            DiskStatus::Deleted
        );
    }

    #[test]
    fn binding_enforces_rwo_mount_uniqueness_and_cold_mutation() {
        let mut catalog = SemanticDiskCatalog::new();
        let mut backend = RecordingBackend::default();
        create(&mut catalog, &mut backend, "ws_a", "one", 100, "disk_1");
        create(&mut catalog, &mut backend, "ws_a", "two", 100, "disk_2");

        let attached = catalog
            .attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Creating,
                &id("disk_1"),
                attach_request("cat-a", "/data"),
            )
            .unwrap();
        assert!(matches!(attached, AttachDiskOutcome::Attached(_)));
        assert!(matches!(
            catalog.attach_disk(
                &id("cat_b"),
                &slug("cat-b"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_1"),
                attach_request("cat-b", "/data")
            ),
            Err(SemanticDiskError::DiskAlreadyAttached)
        ));
        assert!(matches!(
            catalog.attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_2"),
                attach_request("cat-a", "/data")
            ),
            Err(SemanticDiskError::CatMountPathConflict)
        ));
        assert!(matches!(
            catalog.detach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                CatDiskState::Running,
                &id("disk_1"),
                detach_request("cat-a")
            ),
            Err(SemanticDiskError::DetachRequiresCold)
        ));
        assert!(matches!(
            catalog.attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Running,
                &id("disk_2"),
                attach_request("cat-a", "/other")
            ),
            Err(SemanticDiskError::CatMustBeCold)
        ));
    }

    #[test]
    fn attach_and_detach_retries_are_decided_from_the_current_binding() {
        let mut catalog = SemanticDiskCatalog::new();
        let mut backend = RecordingBackend::default();
        create(&mut catalog, &mut backend, "ws_a", "data", 100, "disk_1");
        catalog
            .attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_1"),
                attach_request("cat-a", "/data"),
            )
            .unwrap();
        assert!(matches!(
            catalog.attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_1"),
                attach_request("cat-a", "/data")
            ),
            Ok(AttachDiskOutcome::AlreadyAttached(_))
        ));
        assert!(matches!(
            catalog.attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_1"),
                attach_request("cat-a", "/other")
            ),
            Err(SemanticDiskError::MountPathConflict)
        ));

        assert!(matches!(
            catalog.detach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                CatDiskState::Cold,
                &id("disk_1"),
                detach_request("cat-a")
            ),
            Ok(DetachDiskOutcome::Detached(_))
        ));
        assert!(matches!(
            catalog.detach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                CatDiskState::Cold,
                &id("disk_1"),
                detach_request("cat-a")
            ),
            Ok(DetachDiskOutcome::AlreadyDetached(_))
        ));
    }

    #[test]
    fn cat_destroy_removes_bindings_but_keeps_disk() {
        let mut catalog = SemanticDiskCatalog::new();
        let mut backend = RecordingBackend::default();
        create(&mut catalog, &mut backend, "ws_a", "data", 100, "disk_1");
        catalog
            .attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_1"),
                attach_request("cat-a", "/data"),
            )
            .unwrap();
        assert!(matches!(
            catalog.destroy_disk(&mut backend, &id("disk_1")),
            Err(SemanticDiskServiceError::Semantic(
                SemanticDiskError::DiskInUse
            ))
        ));

        let removed = catalog.destroy_cat_bindings(&id("cat_a")).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(
            catalog.disk_by_id(&id("disk_1")).unwrap().status,
            DiskStatus::Normal
        );
        assert!(backend.destroys.is_empty());
        assert_eq!(
            catalog.destroy_disk(&mut backend, &id("disk_1")).unwrap(),
            DestroyDiskOutcome::Destroyed
        );
        assert_eq!(
            catalog.destroy_disk(&mut backend, &id("disk_1")).unwrap(),
            DestroyDiskOutcome::AlreadyDeleted
        );
        assert_eq!(backend.destroys, vec![id("disk_1")]);
    }

    #[test]
    fn every_binding_mutation_returns_the_complete_sorted_mount_set() {
        let mut catalog = SemanticDiskCatalog::new();
        let mut backend = RecordingBackend::default();
        create(&mut catalog, &mut backend, "ws_a", "z", 200, "disk_2");
        create(&mut catalog, &mut backend, "ws_a", "a", 100, "disk_1");
        catalog
            .attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_2"),
                attach_request("cat-a", "/two"),
            )
            .unwrap();
        let AttachDiskOutcome::Attached(complete) = catalog
            .attach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                &id("ws_a"),
                CatDiskState::Cold,
                &id("disk_1"),
                attach_request("cat-a", "/one"),
            )
            .unwrap()
        else {
            panic!("second attach was not committed");
        };
        assert_eq!(
            complete
                .iter()
                .map(|mount| mount.disk_id.as_str())
                .collect::<Vec<_>>(),
            vec!["disk_1", "disk_2"]
        );

        let DetachDiskOutcome::Detached(complete) = catalog
            .detach_disk(
                &id("cat_a"),
                &slug("cat-a"),
                CatDiskState::Cold,
                &id("disk_1"),
                detach_request("cat-a"),
            )
            .unwrap()
        else {
            panic!("detach was not committed");
        };
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].disk_id, id("disk_2"));
    }

    #[test]
    fn backend_failure_does_not_publish_control_state() {
        let mut catalog = SemanticDiskCatalog::new();
        let mut backend = RecordingBackend {
            fail_create: true,
            ..RecordingBackend::default()
        };
        assert!(matches!(
            catalog.create_disk(
                &mut backend,
                id("ws_a"),
                CreateDiskRequest {
                    disk_slug: slug("data"),
                    size_bytes: 100,
                },
                id("disk_1")
            ),
            Err(SemanticDiskServiceError::Backend(BackendError))
        ));
        assert!(catalog.current_disk(&id("ws_a"), &slug("data")).is_none());

        backend.fail_create = false;
        create(&mut catalog, &mut backend, "ws_a", "data", 100, "disk_1");
        backend.fail_destroy = true;
        assert!(matches!(
            catalog.destroy_disk(&mut backend, &id("disk_1")),
            Err(SemanticDiskServiceError::Backend(BackendError))
        ));
        assert_eq!(
            catalog.disk_by_id(&id("disk_1")).unwrap().status,
            DiskStatus::Normal
        );
    }
}

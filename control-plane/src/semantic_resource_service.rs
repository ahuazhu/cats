//! Production aggregation for the public semantic Cat/Disk API.
//!
//! Public slugs are resolved only to the current resource. From that point on,
//! lifecycle and binding mutations use immutable internal IDs. No request ID,
//! lifecycle Operation, or compatibility protocol enters this adapter.

use std::sync::Arc;
use std::time::Duration;

use cats_protocol::runtime_reconciliation::{Id, RemoteHead};
use cats_protocol::semantic_control as wire;
use sha2::{Digest, Sha256};

use crate::api::semantic_resources::{SemanticResourceApi, SemanticResourceFuture};
use crate::semantic_lifecycle as lifecycle;
use crate::store::semantic as db;
use crate::store::{new_id, Store};

const STRICT_DISK_BACKEND_GAP: &str =
    "strict PersistentDisk backend is not installed in this Control composition";

pub trait LifecycleResourcePort: Send + Sync {
    fn create<'a>(
        &'a self,
        request: lifecycle::CreateCatRequest,
    ) -> SemanticResourceFuture<'a, Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>>;

    fn action<'a>(
        &'a self,
        selector: lifecycle::CatSelector,
        action: lifecycle::CatAction,
    ) -> SemanticResourceFuture<'a, Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>>;
}

impl<S, N, I> LifecycleResourcePort for lifecycle::SemanticLifecycleService<S, N, I>
where
    S: lifecycle::SemanticLifecycleStore,
    N: lifecycle::NodedClient,
    I: lifecycle::IngressPort,
{
    fn create<'a>(
        &'a self,
        request: lifecycle::CreateCatRequest,
    ) -> SemanticResourceFuture<'a, Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>>
    {
        Box::pin(async move { self.create(request).await })
    }

    fn action<'a>(
        &'a self,
        selector: lifecycle::CatSelector,
        action: lifecycle::CatAction,
    ) -> SemanticResourceFuture<'a, Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>>
    {
        Box::pin(async move {
            match action {
                lifecycle::CatAction::Create => Err(lifecycle::LifecycleError::Rejected {
                    code: "invalid_state".to_owned(),
                    message: "create is not a Cat action route".to_owned(),
                }),
                lifecycle::CatAction::Run => self.run(selector).await,
                lifecycle::CatAction::Suspend => self.suspend(selector).await,
                lifecycle::CatAction::Warm => self.warm(selector).await,
                lifecycle::CatAction::Cold => self.cold(selector).await,
                lifecycle::CatAction::Destroy => self.destroy(selector).await,
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CatProjection {
    pub cat: db::CatWithMounts,
    pub node_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskProjection {
    pub disk: db::PersistentDiskRecord,
    pub binding: Option<db::DiskBindingWithCat>,
    pub head_generation: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStoreError {
    pub message: String,
}

impl ResourceStoreError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotGraphValidationError {
    Corrupt(String),
    StorageUnavailable(String),
}

pub trait SemanticResourceStore: Send + Sync {
    fn current_cat_ids<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>>;

    fn current_disk_ids<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>>;

    fn current_snapshot_ids<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>> {
        let _ = workspace_id;
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn current_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::PersistentDiskRecord>, ResourceStoreError>>;

    fn current_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::CatRecord>, ResourceStoreError>>;

    fn cat_projection<'a>(
        &'a self,
        cat_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<CatProjection>, ResourceStoreError>>;

    fn disk_projection<'a>(
        &'a self,
        disk_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<DiskProjection>, ResourceStoreError>>;

    fn current_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::DiskSnapshotRecord>, ResourceStoreError>>
    {
        let _ = (workspace_id, snapshot_slug);
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn snapshot_by_id<'a>(
        &'a self,
        snapshot_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::DiskSnapshotRecord>, ResourceStoreError>>
    {
        let _ = snapshot_id;
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn disk_snapshot_graph_candidate<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_id: &'a str,
    ) -> SemanticResourceFuture<
        'a,
        Result<Option<db::DiskSnapshotGraphCandidate>, ResourceStoreError>,
    > {
        let _ = (workspace_id, disk_id);
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn snapshot_graph_candidate<'a>(
        &'a self,
        snapshot_id: &'a str,
    ) -> SemanticResourceFuture<
        'a,
        Result<Option<db::DiskSnapshotGraphCandidate>, ResourceStoreError>,
    > {
        let _ = snapshot_id;
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn create_snapshot<'a>(
        &'a self,
        snapshot_id: String,
        workspace_id: String,
        snapshot_slug: String,
        disk_id: String,
        expected_head: RemoteHead,
    ) -> SemanticResourceFuture<'a, Result<db::CreateDiskSnapshotOutcome, ResourceStoreError>> {
        let _ = (
            snapshot_id,
            workspace_id,
            snapshot_slug,
            disk_id,
            expected_head,
        );
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn delete_snapshot<'a>(
        &'a self,
        workspace_id: String,
        snapshot_id: String,
    ) -> SemanticResourceFuture<'a, Result<db::DeleteDiskSnapshotOutcome, ResourceStoreError>> {
        let _ = (workspace_id, snapshot_id);
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn restore_snapshot<'a>(
        &'a self,
        workspace_id: String,
        snapshot_id: String,
        expected_generation: u64,
        expected_snapshot: db::DiskSnapshotGraphCandidate,
    ) -> SemanticResourceFuture<'a, Result<db::RestoreDiskSnapshotOutcome, ResourceStoreError>>
    {
        let _ = (
            workspace_id,
            snapshot_id,
            expected_generation,
            expected_snapshot,
        );
        Box::pin(async { Err(ResourceStoreError::new("DiskSnapshot store is unavailable")) })
    }

    fn attach<'a>(
        &'a self,
        binding_id: String,
        cat_id: String,
        disk_id: String,
        mount_path: String,
    ) -> SemanticResourceFuture<'a, Result<db::AttachDiskOutcome, ResourceStoreError>>;

    fn detach<'a>(
        &'a self,
        cat_id: String,
        disk_id: String,
    ) -> SemanticResourceFuture<'a, Result<db::DetachDiskOutcome, ResourceStoreError>>;

    fn admit_disk_create<'a>(
        &'a self,
        candidate: DiskCreateCandidate,
    ) -> SemanticResourceFuture<'a, Result<db::CreatePersistentDiskOutcome, ResourceStoreError>>;

    fn complete_disk_create<'a>(
        &'a self,
        disk: db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<db::PersistentDiskRecord, ResourceStoreError>>;

    fn begin_disk_destroy<'a>(
        &'a self,
        disk_id: String,
    ) -> SemanticResourceFuture<'a, Result<db::DeletePersistentDiskOutcome, ResourceStoreError>>;

    fn complete_disk_destroy<'a>(
        &'a self,
        disk: db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<db::PersistentDiskRecord, ResourceStoreError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCreateCandidate {
    pub disk_id: String,
    pub workspace_id: String,
    pub disk_slug: String,
    pub size_bytes: i64,
    pub volume_id: String,
    pub filesystem_uuid: String,
}

/// Async-safe PostgreSQL adapter. Every synchronous Store call runs on the
/// existing bounded blocking executor.
#[derive(Clone)]
pub struct PostgresSemanticResourceStore {
    store: Arc<Store>,
}

impl PostgresSemanticResourceStore {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl SemanticResourceStore for PostgresSemanticResourceStore {
    fn current_cat_ids<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.list_current_semantic_cat_ids(&workspace_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn disk_snapshot_graph_candidate<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_id: &'a str,
    ) -> SemanticResourceFuture<
        'a,
        Result<Option<db::DiskSnapshotGraphCandidate>, ResourceStoreError>,
    > {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        let disk_id = disk_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.semantic_disk_snapshot_graph_candidate(&workspace_id, &disk_id)
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn snapshot_graph_candidate<'a>(
        &'a self,
        snapshot_id: &'a str,
    ) -> SemanticResourceFuture<
        'a,
        Result<Option<db::DiskSnapshotGraphCandidate>, ResourceStoreError>,
    > {
        let store = Arc::clone(&self.store);
        let snapshot_id = snapshot_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.semantic_snapshot_graph_candidate(&snapshot_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn current_snapshot_ids<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.list_current_semantic_snapshot_ids(&workspace_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn current_disk_ids<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.list_current_semantic_disk_ids(&workspace_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn current_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::PersistentDiskRecord>, ResourceStoreError>>
    {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        let disk_slug = disk_slug.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.find_current_semantic_disk(&workspace_id, &disk_slug))
                .await
                .map_err(resource_store_error)
        })
    }

    fn current_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::CatRecord>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        let cat_slug = cat_slug.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.find_current_semantic_cat(&workspace_id, &cat_slug))
                .await
                .map_err(resource_store_error)
        })
    }

    fn cat_projection<'a>(
        &'a self,
        cat_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<CatProjection>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let cat_id = cat_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let Some(cat) = store.find_semantic_cat_with_mounts_by_id(&cat_id)? else {
                        return Ok(None);
                    };
                    let node_name = cat
                        .cat
                        .node_id
                        .as_deref()
                        .map(|node_id| {
                            store.find_semantic_node(node_id).and_then(|node| {
                                node.map(|node| node.node_name).ok_or_else(|| {
                                    cats_protocol::error::ApiError::internal(
                                        "Cat placement references a missing Node",
                                    )
                                })
                            })
                        })
                        .transpose()?;
                    Ok(Some(CatProjection { cat, node_name }))
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn disk_projection<'a>(
        &'a self,
        disk_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<DiskProjection>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let disk_id = disk_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let Some(disk) = store.find_semantic_disk_by_id(&disk_id)? else {
                        return Ok(None);
                    };
                    let binding = store.find_semantic_disk_binding(&disk_id)?;
                    let head_generation = store.semantic_disk_head_generation(&disk)?;
                    Ok(Some(DiskProjection {
                        disk,
                        binding,
                        head_generation,
                    }))
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn current_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::DiskSnapshotRecord>, ResourceStoreError>>
    {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        let snapshot_slug = snapshot_slug.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.find_current_semantic_snapshot(&workspace_id, &snapshot_slug)
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn snapshot_by_id<'a>(
        &'a self,
        snapshot_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::DiskSnapshotRecord>, ResourceStoreError>>
    {
        let store = Arc::clone(&self.store);
        let snapshot_id = snapshot_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| store.find_semantic_snapshot_by_id(&snapshot_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        snapshot_id: String,
        workspace_id: String,
        snapshot_slug: String,
        disk_id: String,
        expected_head: RemoteHead,
    ) -> SemanticResourceFuture<'a, Result<db::CreateDiskSnapshotOutcome, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.create_semantic_disk_snapshot(db::NewDiskSnapshot {
                        snapshot_id: &snapshot_id,
                        workspace_id: &workspace_id,
                        snapshot_slug: &snapshot_slug,
                        disk_id: &disk_id,
                        expected_head: &expected_head,
                    })
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn delete_snapshot<'a>(
        &'a self,
        workspace_id: String,
        snapshot_id: String,
    ) -> SemanticResourceFuture<'a, Result<db::DeleteDiskSnapshotOutcome, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.delete_semantic_disk_snapshot(&workspace_id, &snapshot_id)
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn restore_snapshot<'a>(
        &'a self,
        workspace_id: String,
        snapshot_id: String,
        expected_generation: u64,
        expected_snapshot: db::DiskSnapshotGraphCandidate,
    ) -> SemanticResourceFuture<'a, Result<db::RestoreDiskSnapshotOutcome, ResourceStoreError>>
    {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.restore_semantic_disk_snapshot(
                        &workspace_id,
                        &snapshot_id,
                        expected_generation,
                        &expected_snapshot,
                    )
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn attach<'a>(
        &'a self,
        binding_id: String,
        cat_id: String,
        disk_id: String,
        mount_path: String,
    ) -> SemanticResourceFuture<'a, Result<db::AttachDiskOutcome, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.attach_semantic_disk(&binding_id, &cat_id, &disk_id, &mount_path)
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn detach<'a>(
        &'a self,
        cat_id: String,
        disk_id: String,
    ) -> SemanticResourceFuture<'a, Result<db::DetachDiskOutcome, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| store.detach_semantic_disk(&cat_id, &disk_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn admit_disk_create<'a>(
        &'a self,
        candidate: DiskCreateCandidate,
    ) -> SemanticResourceFuture<'a, Result<db::CreatePersistentDiskOutcome, ResourceStoreError>>
    {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.create_semantic_persistent_disk(db::NewPersistentDisk {
                        disk_id: &candidate.disk_id,
                        workspace_id: &candidate.workspace_id,
                        disk_slug: &candidate.disk_slug,
                        size_bytes: candidate.size_bytes,
                        volume_id: &candidate.volume_id,
                        filesystem_uuid: &candidate.filesystem_uuid,
                        disk_format: "ext4",
                    })
                })
                .await
                .map_err(resource_store_error)
        })
    }

    fn complete_disk_create<'a>(
        &'a self,
        disk: db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<db::PersistentDiskRecord, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let disk_id = disk.disk_id.clone();
            store
                .execute(move |store| {
                    store.complete_semantic_persistent_disk_create(
                        &disk.disk_id,
                        &disk.volume_id,
                        &disk.filesystem_uuid,
                        disk.size_bytes,
                    )
                })
                .await
                .map_err(resource_store_error)?
                .ok_or_else(|| {
                    ResourceStoreError::new(format!(
                        "strict create completion no longer matches disk {disk_id}"
                    ))
                })
        })
    }

    fn begin_disk_destroy<'a>(
        &'a self,
        disk_id: String,
    ) -> SemanticResourceFuture<'a, Result<db::DeletePersistentDiskOutcome, ResourceStoreError>>
    {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| store.delete_semantic_persistent_disk(&disk_id))
                .await
                .map_err(resource_store_error)
        })
    }

    fn complete_disk_destroy<'a>(
        &'a self,
        disk: db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<db::PersistentDiskRecord, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let disk_id = disk.disk_id.clone();
            store
                .execute(move |store| {
                    store.complete_semantic_persistent_disk_delete(&disk.disk_id, &disk.volume_id)
                })
                .await
                .map_err(resource_store_error)?
                .ok_or_else(|| {
                    ResourceStoreError::new(format!(
                        "strict delete completion no longer matches disk {disk_id}"
                    ))
                })
        })
    }
}

fn resource_store_error(error: cats_protocol::error::ApiError) -> ResourceStoreError {
    ResourceStoreError::new(error.message)
}

/// Strict, remotely durable Volume boundary. The immutable identity is
/// allocated and persisted before either method is invoked, so discovery
/// after an ambiguous response always uses the same `volume_id`.
pub trait SemanticPersistentDiskBackend: Send + Sync {
    fn ensure_created<'a>(
        &'a self,
        disk: &'a db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>>;

    fn ensure_destroyed<'a>(
        &'a self,
        disk: &'a db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>>;

    fn validate_snapshot_graph<'a>(
        &'a self,
        candidate: db::DiskSnapshotGraphCandidate,
    ) -> SemanticResourceFuture<'a, Result<(), SnapshotGraphValidationError>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailablePersistentDiskBackend;

impl SemanticPersistentDiskBackend for UnavailablePersistentDiskBackend {
    fn ensure_created<'a>(
        &'a self,
        _disk: &'a db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>> {
        Box::pin(async { Err(ResourceStoreError::new(STRICT_DISK_BACKEND_GAP)) })
    }

    fn ensure_destroyed<'a>(
        &'a self,
        _disk: &'a db::PersistentDiskRecord,
    ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>> {
        Box::pin(async { Err(ResourceStoreError::new(STRICT_DISK_BACKEND_GAP)) })
    }

    fn validate_snapshot_graph<'a>(
        &'a self,
        _candidate: db::DiskSnapshotGraphCandidate,
    ) -> SemanticResourceFuture<'a, Result<(), SnapshotGraphValidationError>> {
        Box::pin(async {
            Err(SnapshotGraphValidationError::StorageUnavailable(
                STRICT_DISK_BACKEND_GAP.to_owned(),
            ))
        })
    }
}

/// Store adapter used by [`lifecycle::SemanticLifecycleService`].
#[derive(Clone)]
pub struct PostgresSemanticLifecycleStore {
    store: Arc<Store>,
}

impl PostgresSemanticLifecycleStore {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl lifecycle::SemanticLifecycleStore for PostgresSemanticLifecycleStore {
    fn admit_create<'a>(
        &'a self,
        request: &'a lifecycle::CreateCatRequest,
    ) -> lifecycle::SemanticFuture<'a, Result<lifecycle::Admission, lifecycle::StoreError>> {
        let store = Arc::clone(&self.store);
        let request = request.clone();
        let cat_id = new_id("cat_");
        let mounts = request
            .config
            .mounts
            .iter()
            .map(|mount| (new_id("mnt_"), mount.clone()))
            .collect::<Vec<_>>();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let db_mounts = mounts
                        .iter()
                        .map(|(binding_id, mount)| db::NewCatMount {
                            binding_id,
                            disk_id: &mount.disk_id,
                            mount_path: &mount.mount_path,
                        })
                        .collect::<Vec<_>>();
                    let cpu_count = i64::from(request.config.cpu_count);
                    let memory_bytes =
                        i64::try_from(request.config.memory_bytes).map_err(|_| {
                            cats_protocol::error::ApiError::invalid(
                                "Cat memory exceeds PostgreSQL BIGINT",
                            )
                        })?;
                    store.admit_semantic_cat_create(db::AtomicCatCreate {
                        cat_id: &cat_id,
                        workspace_id: &request.workspace_id,
                        cat_slug: &request.cat_slug,
                        cpu_count,
                        memory_bytes,
                        boot_image: &request.config.boot_image,
                        mounts: &db_mounts,
                    })
                })
                .await
                .map_err(lifecycle_store_error)
                .and_then(map_create_admission)
        })
    }

    fn admit_action<'a>(
        &'a self,
        selector: &'a lifecycle::CatSelector,
        action: lifecycle::CatAction,
    ) -> lifecycle::SemanticFuture<'a, Result<lifecycle::Admission, lifecycle::StoreError>> {
        let store = Arc::clone(&self.store);
        let selector = selector.clone();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let selector = match &selector {
                        lifecycle::CatSelector::Id(cat_id) => db::SemanticCatSelector::Id(cat_id),
                        lifecycle::CatSelector::Slug {
                            workspace_id,
                            cat_slug,
                        } => db::SemanticCatSelector::Slug {
                            workspace_id,
                            cat_slug,
                        },
                    };
                    store.admit_semantic_cat_action(selector, lifecycle_action_to_db(action))
                })
                .await
                .map_err(lifecycle_store_error)
                .and_then(map_action_admission)
        })
    }

    fn pending_destroy_claims<'a>(
        &'a self,
        minimum_age: Duration,
        limit: usize,
    ) -> lifecycle::SemanticFuture<'a, Result<Vec<lifecycle::ActionClaim>, lifecycle::StoreError>>
    {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let minimum_age_ms = i64::try_from(minimum_age.as_millis()).unwrap_or(i64::MAX);
            let limit = i64::try_from(limit).unwrap_or(i64::MAX);
            store
                .execute(move |store| {
                    store.claim_pending_semantic_destroy_claims(minimum_age_ms, limit)
                })
                .await
                .map_err(lifecycle_store_error)?
                .into_iter()
                .map(|cat| action_claim(cat, lifecycle::CatAction::Destroy))
                .collect()
        })
    }

    fn rotate_pending_destroy<'a>(
        &'a self,
        claim: &'a lifecycle::ActionClaim,
    ) -> lifecycle::SemanticFuture<'a, Result<bool, lifecycle::StoreError>> {
        let store = Arc::clone(&self.store);
        let cat_id = claim.cat.cat_id.clone();
        let node_id = claim.node_id.clone();
        let started_at_unix_ms = claim.started_at_unix_ms;
        let Some(recovery_started_at_unix_ms) = claim.recovery_started_at_unix_ms else {
            return Box::pin(async {
                Err(lifecycle::StoreError::new(
                    "Destroy recovery rotation omitted its recovery lease",
                ))
            });
        };
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.rotate_pending_semantic_destroy_claim(
                        &cat_id,
                        node_id.as_deref(),
                        started_at_unix_ms,
                        recovery_started_at_unix_ms,
                    )
                })
                .await
                .map_err(lifecycle_store_error)
        })
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> lifecycle::SemanticFuture<'a, Result<lifecycle::NodeControlEndpoint, lifecycle::StoreError>>
    {
        let store = Arc::clone(&self.store);
        let node_id = node_id.to_owned();
        Box::pin(async move {
            let node = store
                .execute(move |store| store.find_semantic_node(&node_id))
                .await
                .map_err(lifecycle_store_error)?
                .ok_or_else(|| lifecycle::StoreError::new("selected Node no longer exists"))?;
            lifecycle::NodeControlEndpoint::new(node.control_endpoint)
        })
    }

    fn complete_action<'a>(
        &'a self,
        claim: &'a lifecycle::ActionClaim,
        resulting_state: lifecycle::CatState,
    ) -> lifecycle::SemanticFuture<'a, Result<lifecycle::CatRecord, lifecycle::StoreError>> {
        self.finish_action(claim, resulting_state, None, None)
    }

    fn fail_action<'a>(
        &'a self,
        claim: &'a lifecycle::ActionClaim,
        code: &'a str,
        message: &'a str,
    ) -> lifecycle::SemanticFuture<'a, Result<lifecycle::CatRecord, lifecycle::StoreError>> {
        self.finish_action(
            claim,
            lifecycle::CatState::Failure,
            Some(code.to_owned()),
            Some(message.to_owned()),
        )
    }
}

impl PostgresSemanticLifecycleStore {
    fn finish_action<'a>(
        &'a self,
        claim: &'a lifecycle::ActionClaim,
        state: lifecycle::CatState,
        error_code: Option<String>,
        error_message: Option<String>,
    ) -> lifecycle::SemanticFuture<'a, Result<lifecycle::CatRecord, lifecycle::StoreError>> {
        let store = Arc::clone(&self.store);
        let claim = claim.clone();
        Box::pin(async move {
            let final_node_id = matches!(
                state,
                lifecycle::CatState::Running
                    | lifecycle::CatState::Suspended
                    | lifecycle::CatState::Warm
                    | lifecycle::CatState::Failure
            )
            .then(|| claim.node_id.as_deref().or(claim.cat.node_id.as_deref()))
            .flatten()
            .map(str::to_owned);
            store
                .execute(move |store| {
                    let row = store.finish_semantic_cat_action(
                        &claim.cat.cat_id,
                        db::FinishCatAction {
                            expected_action: lifecycle_action_to_db(claim.action),
                            expected_action_started_at: claim.started_at_unix_ms,
                            expected_recovery_started_at: claim.recovery_started_at_unix_ms,
                            expected_node_id: claim.node_id.as_deref(),
                            final_state: lifecycle_state_to_db(state),
                            final_node_id: final_node_id.as_deref(),
                            error_code: error_code.as_deref(),
                            error_message: error_message.as_deref(),
                        },
                    )?;
                    let Some(row) = row else {
                        return Ok(None);
                    };
                    store.find_semantic_cat_with_mounts_by_id(&row.cat_id)
                })
                .await
                .map_err(lifecycle_store_error)?
                .ok_or_else(|| lifecycle::StoreError::new("Cat action claim became stale"))
                .and_then(db_aggregate_to_lifecycle)
        })
    }
}

fn lifecycle_store_error(error: cats_protocol::error::ApiError) -> lifecycle::StoreError {
    lifecycle::StoreError::new(error.message)
}

fn map_create_admission(
    outcome: db::AdmitCatCreateOutcome,
) -> Result<lifecycle::Admission, lifecycle::StoreError> {
    Ok(match outcome {
        db::AdmitCatCreateOutcome::Created(cat) => {
            lifecycle::Admission::Claimed(action_claim(cat, lifecycle::CatAction::Create)?)
        }
        db::AdmitCatCreateOutcome::SameAction(cat) => {
            lifecycle::Admission::SameAction(action_claim(cat, lifecycle::CatAction::Create)?)
        }
        db::AdmitCatCreateOutcome::AlreadyExists(cat) => lifecycle::Admission::Already {
            cat: db_aggregate_to_lifecycle(cat)?,
            code: "already_exists",
        },
        db::AdmitCatCreateOutcome::Busy(cat) => {
            lifecycle::Admission::Busy(db_aggregate_to_lifecycle(cat)?)
        }
        db::AdmitCatCreateOutcome::ConfigurationConflict(cat) => lifecycle::Admission::Conflict {
            cat: db_aggregate_to_lifecycle(cat)?,
            code: "cat_configuration_conflict",
        },
        db::AdmitCatCreateOutcome::NodeNotSchedulable => lifecycle::Admission::Rejected {
            code: "node_unavailable".to_owned(),
            message: "no running Node accepts placement".to_owned(),
        },
        db::AdmitCatCreateOutcome::MountRejected { code, message } => {
            lifecycle::Admission::Rejected { code, message }
        }
    })
}

fn map_action_admission(
    outcome: db::AdmitCatActionOutcome,
) -> Result<lifecycle::Admission, lifecycle::StoreError> {
    Ok(match outcome {
        db::AdmitCatActionOutcome::Acquired(cat) => {
            let action = cat
                .cat
                .current_action
                .ok_or_else(|| lifecycle::StoreError::new("acquired Cat omitted current action"))?;
            lifecycle::Admission::Claimed(action_claim(cat, db_action_to_lifecycle(action))?)
        }
        db::AdmitCatActionOutcome::SameAction(cat) => {
            let action = cat.cat.current_action.ok_or_else(|| {
                lifecycle::StoreError::new("same-action Cat omitted current action")
            })?;
            lifecycle::Admission::SameAction(action_claim(cat, db_action_to_lifecycle(action))?)
        }
        db::AdmitCatActionOutcome::AlreadyDone(cat) => lifecycle::Admission::Already {
            code: already_code(
                cat.cat
                    .state
                    .ok_or_else(|| lifecycle::StoreError::new("settled Cat omitted state"))?,
            ),
            cat: db_aggregate_to_lifecycle(cat)?,
        },
        db::AdmitCatActionOutcome::Busy(cat) => {
            lifecycle::Admission::Busy(db_aggregate_to_lifecycle(cat)?)
        }
        db::AdmitCatActionOutcome::InvalidState(cat) => {
            lifecycle::Admission::InvalidState(db_aggregate_to_lifecycle(cat)?)
        }
        db::AdmitCatActionOutcome::NotFound => lifecycle::Admission::NotFound,
        db::AdmitCatActionOutcome::NodeNotSchedulable(_) => lifecycle::Admission::Rejected {
            code: "node_unavailable".to_owned(),
            message: "no running Node accepts placement".to_owned(),
        },
    })
}

fn action_claim(
    cat: db::CatWithMounts,
    action: lifecycle::CatAction,
) -> Result<lifecycle::ActionClaim, lifecycle::StoreError> {
    let node_id = cat.cat.current_action_node_id.clone();
    let started_at_unix_ms = cat.cat.current_action_started_at.ok_or_else(|| {
        lifecycle::StoreError::new("claimed semantic Cat action omitted its start time")
    })?;
    let recovery_started_at_unix_ms = cat.cat.current_action_recovery_started_at;
    Ok(lifecycle::ActionClaim {
        cat: db_aggregate_to_lifecycle(cat)?,
        action,
        started_at_unix_ms,
        recovery_started_at_unix_ms,
        node_id,
    })
}

fn db_aggregate_to_lifecycle(
    aggregate: db::CatWithMounts,
) -> Result<lifecycle::CatRecord, lifecycle::StoreError> {
    let mounts = aggregate
        .mounts
        .into_iter()
        .map(|mount| lifecycle::CatMount {
            disk_id: mount.disk_id,
            volume_id: mount.volume_id,
            filesystem_uuid: mount.filesystem_uuid,
            disk_format: mount.disk_format,
            mount_path: mount.mount_path,
        })
        .collect();
    db_cat_to_lifecycle_with_mounts(aggregate.cat, mounts)
}

fn db_cat_to_lifecycle_with_mounts(
    cat: db::CatRecord,
    mounts: Vec<lifecycle::CatMount>,
) -> Result<lifecycle::CatRecord, lifecycle::StoreError> {
    Ok(lifecycle::CatRecord {
        cat_id: cat.cat_id,
        workspace_id: cat.workspace_id,
        cat_slug: cat.cat_slug,
        state: cat.state.map(db_state_to_lifecycle),
        current_action: cat.current_action.map(db_action_to_lifecycle),
        current_action_node_id: cat.current_action_node_id,
        node_id: cat.node_id,
        config: lifecycle::CatCreateConfig {
            cpu_count: u32::try_from(cat.cpu_count)
                .map_err(|_| lifecycle::StoreError::new("stored Cat CPU is invalid"))?,
            memory_bytes: u64::try_from(cat.memory_bytes)
                .map_err(|_| lifecycle::StoreError::new("stored Cat memory is invalid"))?,
            boot_image: cat.boot_image,
            mounts,
        },
    })
}

fn lifecycle_action_to_db(action: lifecycle::CatAction) -> db::CatAction {
    match action {
        lifecycle::CatAction::Create => db::CatAction::Create,
        lifecycle::CatAction::Run => db::CatAction::Run,
        lifecycle::CatAction::Suspend => db::CatAction::Suspend,
        lifecycle::CatAction::Warm => db::CatAction::Warm,
        lifecycle::CatAction::Cold => db::CatAction::Cold,
        lifecycle::CatAction::Destroy => db::CatAction::Destroy,
    }
}

fn db_action_to_lifecycle(action: db::CatAction) -> lifecycle::CatAction {
    match action {
        db::CatAction::Create => lifecycle::CatAction::Create,
        db::CatAction::Run => lifecycle::CatAction::Run,
        db::CatAction::Suspend => lifecycle::CatAction::Suspend,
        db::CatAction::Warm => lifecycle::CatAction::Warm,
        db::CatAction::Cold => lifecycle::CatAction::Cold,
        db::CatAction::Destroy => lifecycle::CatAction::Destroy,
    }
}

fn lifecycle_state_to_db(state: lifecycle::CatState) -> db::CatState {
    match state {
        lifecycle::CatState::Running => db::CatState::Running,
        lifecycle::CatState::Suspended => db::CatState::Suspended,
        lifecycle::CatState::Warm => db::CatState::Warm,
        lifecycle::CatState::Cold => db::CatState::Cold,
        lifecycle::CatState::Failure => db::CatState::Failure,
        lifecycle::CatState::Destroyed => db::CatState::Destroyed,
    }
}

fn db_state_to_lifecycle(state: db::CatState) -> lifecycle::CatState {
    match state {
        db::CatState::Running => lifecycle::CatState::Running,
        db::CatState::Suspended => lifecycle::CatState::Suspended,
        db::CatState::Warm => lifecycle::CatState::Warm,
        db::CatState::Cold => lifecycle::CatState::Cold,
        db::CatState::Failure => lifecycle::CatState::Failure,
        db::CatState::Destroyed => lifecycle::CatState::Destroyed,
    }
}

fn already_code(state: db::CatState) -> &'static str {
    match state {
        db::CatState::Running => "already_running",
        db::CatState::Suspended => "already_suspended",
        db::CatState::Warm => "already_warm",
        db::CatState::Cold => "already_cold",
        db::CatState::Destroyed => "already_destroyed",
        db::CatState::Failure => "invalid_state",
    }
}

/// Aggregate supplied to `semantic_resources::routes` by production
/// composition. The router itself remains independent of this type.
pub struct ProductionSemanticResourceApi<L, R, B = UnavailablePersistentDiskBackend> {
    lifecycle: L,
    resources: R,
    disk_backend: B,
    default_boot_image: String,
}

impl<L, R> ProductionSemanticResourceApi<L, R, UnavailablePersistentDiskBackend> {
    pub fn new(lifecycle: L, resources: R, default_boot_image: impl Into<String>) -> Self {
        Self {
            lifecycle,
            resources,
            disk_backend: UnavailablePersistentDiskBackend,
            default_boot_image: default_boot_image.into(),
        }
    }
}

impl<L, R, B> ProductionSemanticResourceApi<L, R, B> {
    pub fn with_disk_backend(
        lifecycle: L,
        resources: R,
        disk_backend: B,
        default_boot_image: impl Into<String>,
    ) -> Self {
        Self {
            lifecycle,
            resources,
            disk_backend,
            default_boot_image: default_boot_image.into(),
        }
    }
}

impl<L, R, B> SemanticResourceApi for ProductionSemanticResourceApi<L, R, B>
where
    L: LifecycleResourcePort,
    R: SemanticResourceStore,
    B: SemanticPersistentDiskBackend,
{
    fn list_cats<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<wire::CatView>, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let ids = self
                .resources
                .current_cat_ids(workspace_id)
                .await
                .map_err(internal_resource_error)?;
            let mut cats = Vec::with_capacity(ids.len());
            for id in ids {
                cats.push(self.project_cat(&id).await?);
            }
            Ok(cats)
        })
    }

    fn get_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: wire::ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<wire::CatView, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let cat = self.current_cat(workspace_id, &cat_slug).await?;
            self.project_cat(&cat.cat_id).await
        })
    }

    fn list_disks<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<wire::DiskView>, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let ids = self
                .resources
                .current_disk_ids(workspace_id)
                .await
                .map_err(internal_resource_error)?;
            let mut disks = Vec::with_capacity(ids.len());
            for id in ids {
                disks.push(self.project_disk(&id).await?);
            }
            Ok(disks)
        })
    }

    fn get_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: wire::ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskView, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let disk = self.current_disk(workspace_id, &disk_slug).await?;
            self.project_disk(&disk.disk_id).await
        })
    }

    fn list_snapshots<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<wire::DiskSnapshotView>, wire::SemanticErrorBody>>
    {
        Box::pin(async move {
            let ids = self
                .resources
                .current_snapshot_ids(workspace_id)
                .await
                .map_err(internal_resource_error)?;
            let mut snapshots = Vec::with_capacity(ids.len());
            for id in ids {
                snapshots.push(self.project_snapshot(&id).await?);
            }
            Ok(snapshots)
        })
    }

    fn get_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: wire::ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskSnapshotView, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let snapshot = self.current_snapshot(workspace_id, &snapshot_slug).await?;
            snapshot_view(snapshot).map_err(internal_resource_error)
        })
    }

    fn create_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        request: wire::CreateCatRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::CatResponse, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let mut mounts = Vec::with_capacity(request.mounts.len());
            for mount in request.mounts {
                let disk = self
                    .resources
                    .current_disk(workspace_id, mount.disk_slug.as_str())
                    .await
                    .map_err(internal_resource_error)?
                    .ok_or_else(|| {
                        semantic_error(
                            wire::SemanticErrorCode::DiskNotFound,
                            "PersistentDisk was not found",
                        )
                    })?;
                mounts.push(lifecycle::CatMount {
                    disk_id: disk.disk_id,
                    volume_id: disk.volume_id,
                    filesystem_uuid: disk.filesystem_uuid,
                    disk_format: disk.disk_format,
                    mount_path: mount.mount_path.to_string(),
                });
            }
            let outcome = self
                .lifecycle
                .create(lifecycle::CreateCatRequest {
                    workspace_id: workspace_id.to_owned(),
                    cat_slug: request.cat_slug.to_string(),
                    config: lifecycle::CatCreateConfig {
                        cpu_count: request.cpu,
                        memory_bytes: request.memory_bytes,
                        boot_image: self.default_boot_image.clone(),
                        mounts,
                    },
                })
                .await
                .map_err(map_lifecycle_error)?;
            let cat = self.project_cat(&outcome.cat.cat_id).await?;
            Ok(wire::CatResponse {
                status: map_outcome_status(outcome.status),
                code: success_code(outcome.code)?,
                cat,
            })
        })
    }

    fn cat_action<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: wire::ResourceSlug,
        action: wire::CatAction,
    ) -> SemanticResourceFuture<'a, Result<wire::CatResponse, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let outcome = self
                .lifecycle
                .action(
                    lifecycle::CatSelector::Slug {
                        workspace_id: workspace_id.to_owned(),
                        cat_slug: cat_slug.to_string(),
                    },
                    wire_action_to_lifecycle(action),
                )
                .await
                .map_err(map_lifecycle_error)?;
            let cat = self.project_cat(&outcome.cat.cat_id).await?;
            Ok(wire::CatResponse {
                status: map_outcome_status(outcome.status),
                code: success_code(outcome.code)?,
                cat,
            })
        })
    }

    fn create_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        request: wire::CreateDiskRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskResponse, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let (disk, created) = if let Some(disk) = self
                .resources
                .current_disk(workspace_id, request.disk_slug.as_str())
                .await
                .map_err(internal_resource_error)?
            {
                if u64::try_from(disk.size_bytes).ok() != Some(request.size_bytes) {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskSizeConflict,
                        "current PersistentDisk has a different size",
                    ));
                }
                (disk, false)
            } else {
                let candidate = disk_create_candidate(
                    workspace_id,
                    request.disk_slug.as_str(),
                    request.size_bytes,
                )?;
                match self
                    .resources
                    .admit_disk_create(candidate)
                    .await
                    .map_err(internal_resource_error)?
                {
                    db::CreatePersistentDiskOutcome::Created(disk) => (disk, true),
                    db::CreatePersistentDiskOutcome::Existing(disk) => {
                        if u64::try_from(disk.size_bytes).ok() != Some(request.size_bytes) {
                            return Err(semantic_error(
                                wire::SemanticErrorCode::DiskSizeConflict,
                                "current PersistentDisk has a different size",
                            ));
                        }
                        (disk, false)
                    }
                }
            };
            let disk = match disk.status.as_str() {
                "normal" => disk,
                "provisioning" => {
                    self.disk_backend
                        .ensure_created(&disk)
                        .await
                        .map_err(internal_resource_error)?;
                    self.resources
                        .complete_disk_create(disk)
                        .await
                        .map_err(internal_resource_error)?
                }
                _ => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskDeleted,
                        "PersistentDisk is being deleted",
                    ));
                }
            };
            Ok(wire::DiskResponse {
                status: if created {
                    wire::SemanticStatus::Ok
                } else {
                    wire::SemanticStatus::AlreadyExists
                },
                code: if created {
                    wire::SemanticSuccessCode::DiskCreated
                } else {
                    wire::SemanticSuccessCode::AlreadyExists
                },
                disk: self.project_disk(&disk.disk_id).await?,
            })
        })
    }

    fn attach_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: wire::ResourceSlug,
        request: wire::AttachDiskRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskResponse, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let disk = self.current_disk(workspace_id, &disk_slug).await?;
            let cat = self.current_cat(workspace_id, &request.cat_slug).await?;
            let outcome = self
                .resources
                .attach(
                    new_id("mnt_"),
                    cat.cat_id,
                    disk.disk_id.clone(),
                    request.mount_path.to_string(),
                )
                .await
                .map_err(internal_resource_error)?;
            let (status, code) = map_attach_outcome(outcome)?;
            Ok(wire::DiskResponse {
                status,
                code,
                disk: self.project_disk(&disk.disk_id).await?,
            })
        })
    }

    fn detach_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: wire::ResourceSlug,
        request: wire::DetachDiskRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskResponse, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let disk = self.current_disk(workspace_id, &disk_slug).await?;
            let cat = self.current_cat(workspace_id, &request.cat_slug).await?;
            let outcome = self
                .resources
                .detach(cat.cat_id, disk.disk_id.clone())
                .await
                .map_err(internal_resource_error)?;
            let (status, code) = map_detach_outcome(outcome)?;
            Ok(wire::DiskResponse {
                status,
                code,
                disk: self.project_disk(&disk.disk_id).await?,
            })
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        request: wire::CreateDiskSnapshotRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskSnapshotResponse, wire::SemanticErrorBody>>
    {
        Box::pin(async move {
            let disk = self.current_disk(workspace_id, &request.disk_slug).await?;
            if let Some(existing) = self
                .resources
                .current_snapshot(workspace_id, request.snapshot_slug.as_str())
                .await
                .map_err(internal_resource_error)?
            {
                if existing.disk_id != disk.disk_id {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::SnapshotConfigurationConflict,
                        "current DiskSnapshot belongs to a different PersistentDisk",
                    ));
                }
                let generation = self.disk_generation(&existing.disk_id).await?;
                return Ok(wire::DiskSnapshotResponse {
                    status: wire::SemanticStatus::AlreadyExists,
                    code: wire::SemanticSuccessCode::AlreadyExists,
                    snapshot: snapshot_view(existing).map_err(internal_resource_error)?,
                    disk_head_generation: generation,
                });
            }
            let candidate = self
                .resources
                .disk_snapshot_graph_candidate(workspace_id, &disk.disk_id)
                .await
                .map_err(internal_resource_error)?
                .ok_or_else(|| {
                    semantic_error(
                        wire::SemanticErrorCode::DiskNotInitialized,
                        "PersistentDisk has no remotely durable initialized Root",
                    )
                })?;
            self.disk_backend
                .validate_snapshot_graph(candidate.clone())
                .await
                .map_err(snapshot_graph_validation_error)?;
            let outcome = self
                .resources
                .create_snapshot(
                    new_id("snapshot_"),
                    workspace_id.to_owned(),
                    request.snapshot_slug.to_string(),
                    disk.disk_id,
                    candidate.head,
                )
                .await
                .map_err(internal_resource_error)?;
            let (snapshot, status, code) = match outcome {
                db::CreateDiskSnapshotOutcome::Created(snapshot) => (
                    snapshot,
                    wire::SemanticStatus::Ok,
                    wire::SemanticSuccessCode::SnapshotCreated,
                ),
                db::CreateDiskSnapshotOutcome::Existing(snapshot) => (
                    snapshot,
                    wire::SemanticStatus::AlreadyExists,
                    wire::SemanticSuccessCode::AlreadyExists,
                ),
                db::CreateDiskSnapshotOutcome::ConfigurationConflict(_) => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::SnapshotConfigurationConflict,
                        "current DiskSnapshot belongs to a different PersistentDisk",
                    ));
                }
                db::CreateDiskSnapshotOutcome::DiskNotFound => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskNotFound,
                        "PersistentDisk was not found",
                    ));
                }
                db::CreateDiskSnapshotOutcome::DiskDeleted => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskDeleted,
                        "PersistentDisk is deleted or in maintenance",
                    ));
                }
                db::CreateDiskSnapshotOutcome::DiskNotInitialized => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskNotInitialized,
                        "PersistentDisk is not initialized",
                    ));
                }
                db::CreateDiskSnapshotOutcome::CatMustBeCold => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::CatMustBeCold,
                        "bound Cat must be stably Cold",
                    ));
                }
                db::CreateDiskSnapshotOutcome::DiskWriterActive => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskOwned,
                        "PersistentDisk still has an active writer",
                    ));
                }
                db::CreateDiskSnapshotOutcome::HeadConflict => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::HeadConflict,
                        "PersistentDisk generation changed during snapshot validation",
                    ));
                }
            };
            let generation = self.disk_generation(&snapshot.disk_id).await?;
            Ok(wire::DiskSnapshotResponse {
                status,
                code,
                snapshot: snapshot_view(snapshot).map_err(internal_resource_error)?,
                disk_head_generation: generation,
            })
        })
    }

    fn destroy_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: wire::ResourceSlug,
        request: wire::DestroyDiskSnapshotRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskSnapshotResponse, wire::SemanticErrorBody>>
    {
        Box::pin(async move {
            match self
                .resources
                .current_snapshot(workspace_id, snapshot_slug.as_str())
                .await
                .map_err(internal_resource_error)?
            {
                Some(current)
                    if current.snapshot_id != request.expected_snapshot_id.as_str() =>
                {
                    return Err(snapshot_occurrence_conflict());
                }
                Some(_) => {}
                None => {
                    let Some(previous) = self
                        .resources
                        .snapshot_by_id(request.expected_snapshot_id.as_str())
                        .await
                        .map_err(internal_resource_error)?
                    else {
                        return Err(snapshot_not_found());
                    };
                    if previous.workspace_id != workspace_id
                        || previous.snapshot_slug != snapshot_slug.as_str()
                        || previous.deleted_at.is_none()
                    {
                        return Err(snapshot_not_found());
                    }
                }
            }
            let outcome = self
                .resources
                .delete_snapshot(
                    workspace_id.to_owned(),
                    request.expected_snapshot_id.to_string(),
                )
                .await
                .map_err(internal_resource_error)?;
            let (snapshot, status, code) = match outcome {
                db::DeleteDiskSnapshotOutcome::Deleted(snapshot) => (
                    snapshot,
                    wire::SemanticStatus::Ok,
                    wire::SemanticSuccessCode::SnapshotDestroyed,
                ),
                db::DeleteDiskSnapshotOutcome::AlreadyDeleted(snapshot) => (
                    snapshot,
                    wire::SemanticStatus::AlreadyDone,
                    wire::SemanticSuccessCode::AlreadyDeleted,
                ),
                db::DeleteDiskSnapshotOutcome::NotFound => {
                    return Err(snapshot_not_found());
                }
                db::DeleteDiskSnapshotOutcome::DiskDeleted => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskDeleted,
                        "PersistentDisk is deleted or in maintenance",
                    ));
                }
                db::DeleteDiskSnapshotOutcome::DiskNotInitialized => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskNotInitialized,
                        "PersistentDisk is not initialized",
                    ));
                }
                db::DeleteDiskSnapshotOutcome::CatMustBeCold => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::CatMustBeCold,
                        "bound Cat must be stably Cold",
                    ));
                }
                db::DeleteDiskSnapshotOutcome::DiskWriterActive => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskOwned,
                        "PersistentDisk still has an active writer",
                    ));
                }
            };
            let generation = self.disk_generation(&snapshot.disk_id).await?;
            Ok(wire::DiskSnapshotResponse {
                status,
                code,
                snapshot: snapshot_view(snapshot).map_err(internal_resource_error)?,
                disk_head_generation: generation,
            })
        })
    }

    fn restore_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: wire::ResourceSlug,
        request: wire::RestoreDiskSnapshotRequest,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskSnapshotResponse, wire::SemanticErrorBody>>
    {
        Box::pin(async move {
            let current = self.current_snapshot(workspace_id, &snapshot_slug).await?;
            if current.snapshot_id != request.expected_snapshot_id.as_str() {
                return Err(snapshot_occurrence_conflict());
            }
            let candidate = self
                .resources
                .snapshot_graph_candidate(&current.snapshot_id)
                .await
                .map_err(internal_resource_error)?
                .ok_or_else(|| {
                    semantic_error(
                        wire::SemanticErrorCode::SnapshotCorrupt,
                        "DiskSnapshot has no retained Root",
                    )
                })?;
            self.disk_backend
                .validate_snapshot_graph(candidate.clone())
                .await
                .map_err(snapshot_graph_validation_error)?;
            let outcome = self
                .resources
                .restore_snapshot(
                    workspace_id.to_owned(),
                    request.expected_snapshot_id.to_string(),
                    request.expected_generation,
                    candidate,
                )
                .await
                .map_err(internal_resource_error)?;
            let (snapshot, result, status, code) = match outcome {
                db::RestoreDiskSnapshotOutcome::Restored { snapshot, result } => (
                    snapshot,
                    result,
                    wire::SemanticStatus::Ok,
                    wire::SemanticSuccessCode::SnapshotRestored,
                ),
                db::RestoreDiskSnapshotOutcome::AlreadyRestored { snapshot, result } => (
                    snapshot,
                    result,
                    wire::SemanticStatus::AlreadyDone,
                    wire::SemanticSuccessCode::AlreadyRestored,
                ),
                db::RestoreDiskSnapshotOutcome::NotFound => return Err(snapshot_not_found()),
                db::RestoreDiskSnapshotOutcome::DiskDeleted => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskDeleted,
                        "PersistentDisk is deleted or in maintenance",
                    ));
                }
                db::RestoreDiskSnapshotOutcome::DiskNotInitialized => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskNotInitialized,
                        "PersistentDisk is not initialized",
                    ));
                }
                db::RestoreDiskSnapshotOutcome::CatMustBeCold => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::CatMustBeCold,
                        "bound Cat must be stably Cold",
                    ));
                }
                db::RestoreDiskSnapshotOutcome::DiskWriterActive => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskOwned,
                        "PersistentDisk still has an active writer",
                    ));
                }
                db::RestoreDiskSnapshotOutcome::HeadConflict => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::HeadConflict,
                        "PersistentDisk generation changed",
                    ));
                }
                db::RestoreDiskSnapshotOutcome::SnapshotConflict => {
                    return Err(snapshot_occurrence_conflict());
                }
                db::RestoreDiskSnapshotOutcome::AuthorityExhausted => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::GenerationExhausted,
                        "PersistentDisk generation or writer epoch is exhausted",
                    ));
                }
            };
            Ok(wire::DiskSnapshotResponse {
                status,
                code,
                snapshot: snapshot_view(snapshot).map_err(internal_resource_error)?,
                disk_head_generation: result.resulting_head.generation.get(),
            })
        })
    }

    fn destroy_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: wire::ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<wire::DiskResponse, wire::SemanticErrorBody>> {
        Box::pin(async move {
            let disk = self.current_disk(workspace_id, &disk_slug).await?;
            let projection = self
                .resources
                .disk_projection(&disk.disk_id)
                .await
                .map_err(internal_resource_error)?
                .ok_or_else(|| {
                    semantic_error(
                        wire::SemanticErrorCode::DiskNotFound,
                        "PersistentDisk was not found",
                    )
                })?;
            if projection.binding.is_some() {
                return Err(semantic_error(
                    wire::SemanticErrorCode::DiskInUse,
                    "PersistentDisk is still bound to a Cat",
                ));
            }
            let deleting = match self
                .resources
                .begin_disk_destroy(disk.disk_id.clone())
                .await
                .map_err(internal_resource_error)?
            {
                db::DeletePersistentDiskOutcome::Deleting(disk)
                | db::DeletePersistentDiskOutcome::AlreadyDeleted(disk) => disk,
                db::DeletePersistentDiskOutcome::Attached => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskInUse,
                        "PersistentDisk is still bound to a Cat",
                    ));
                }
                db::DeletePersistentDiskOutcome::SnapshotInUse => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::SnapshotInUse,
                        "PersistentDisk still has a live DiskSnapshot",
                    ));
                }
                db::DeletePersistentDiskOutcome::NotFound => {
                    return Err(semantic_error(
                        wire::SemanticErrorCode::DiskNotFound,
                        "PersistentDisk was not found",
                    ));
                }
            };
            if deleting.status != "deleted" {
                self.disk_backend
                    .ensure_destroyed(&deleting)
                    .await
                    .map_err(internal_resource_error)?;
            }
            let deleted = if deleting.status == "deleted" {
                deleting
            } else {
                self.resources
                    .complete_disk_destroy(deleting)
                    .await
                    .map_err(internal_resource_error)?
            };
            Ok(wire::DiskResponse {
                status: wire::SemanticStatus::Ok,
                code: wire::SemanticSuccessCode::DiskDeleted,
                disk: self.project_disk(&deleted.disk_id).await?,
            })
        })
    }
}

impl<L, R, B> ProductionSemanticResourceApi<L, R, B>
where
    L: LifecycleResourcePort,
    R: SemanticResourceStore,
    B: SemanticPersistentDiskBackend,
{
    async fn current_disk(
        &self,
        workspace_id: &str,
        slug: &wire::ResourceSlug,
    ) -> Result<db::PersistentDiskRecord, wire::SemanticErrorBody> {
        self.resources
            .current_disk(workspace_id, slug.as_str())
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(|| {
                semantic_error(
                    wire::SemanticErrorCode::DiskNotFound,
                    "PersistentDisk was not found",
                )
            })
    }

    async fn current_cat(
        &self,
        workspace_id: &str,
        slug: &wire::ResourceSlug,
    ) -> Result<db::CatRecord, wire::SemanticErrorBody> {
        self.resources
            .current_cat(workspace_id, slug.as_str())
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(|| {
                semantic_error(wire::SemanticErrorCode::CatNotFound, "Cat was not found")
            })
    }

    async fn current_snapshot(
        &self,
        workspace_id: &str,
        slug: &wire::ResourceSlug,
    ) -> Result<db::DiskSnapshotRecord, wire::SemanticErrorBody> {
        self.resources
            .current_snapshot(workspace_id, slug.as_str())
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(snapshot_not_found)
    }

    async fn project_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<wire::DiskSnapshotView, wire::SemanticErrorBody> {
        let snapshot = self
            .resources
            .snapshot_by_id(snapshot_id)
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(snapshot_not_found)?;
        snapshot_view(snapshot).map_err(internal_resource_error)
    }

    async fn disk_generation(&self, disk_id: &str) -> Result<u64, wire::SemanticErrorBody> {
        self.project_disk(disk_id)
            .await?
            .head_generation
            .ok_or_else(|| {
                semantic_error(
                    wire::SemanticErrorCode::DiskNotInitialized,
                    "PersistentDisk has no initialized remote head",
                )
            })
    }

    async fn project_cat(&self, cat_id: &str) -> Result<wire::CatView, wire::SemanticErrorBody> {
        let projection = self
            .resources
            .cat_projection(cat_id)
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(|| {
                semantic_error(wire::SemanticErrorCode::CatNotFound, "Cat was not found")
            })?;
        cat_view(projection).map_err(internal_resource_error)
    }

    async fn project_disk(&self, disk_id: &str) -> Result<wire::DiskView, wire::SemanticErrorBody> {
        let projection = self
            .resources
            .disk_projection(disk_id)
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(|| {
                semantic_error(
                    wire::SemanticErrorCode::DiskNotFound,
                    "PersistentDisk was not found",
                )
            })?;
        disk_view(projection).map_err(internal_resource_error)
    }
}

fn cat_view(projection: CatProjection) -> Result<wire::CatView, ResourceStoreError> {
    let cat = projection.cat.cat;
    let node_id = cat.node_id.as_deref().map(parse_id).transpose()?;
    let node_name = projection
        .node_name
        .map(|name| {
            wire::NodeName::new(name)
                .ok_or_else(|| ResourceStoreError::new("stored Node name is invalid"))
        })
        .transpose()?;
    let last_error = cat.last_error_code.map(|code| wire::SemanticErrorBody {
        code: semantic_error_code(&code),
        message: cat.last_error_message.unwrap_or(code),
    });
    Ok(wire::CatView {
        cat_id: parse_id(&cat.cat_id)?,
        workspace_id: parse_id(&cat.workspace_id)?,
        cat_slug: wire::ResourceSlug::new(cat.cat_slug)
            .ok_or_else(|| ResourceStoreError::new("stored Cat slug is invalid"))?,
        state: cat.state.map(db_state_to_wire),
        current_action: cat.current_action.map(db_action_to_wire),
        node_id,
        node_name,
        cpu: u32::try_from(cat.cpu_count)
            .map_err(|_| ResourceStoreError::new("stored Cat CPU is invalid"))?,
        memory_bytes: u64::try_from(cat.memory_bytes)
            .map_err(|_| ResourceStoreError::new("stored Cat memory is invalid"))?,
        boot_image: cat.boot_image,
        mounts: projection
            .cat
            .mounts
            .into_iter()
            .map(|mount| {
                Ok(wire::CatMountView {
                    disk_id: parse_id(&mount.disk_id)?,
                    disk_slug: wire::ResourceSlug::new(mount.disk_slug)
                        .ok_or_else(|| ResourceStoreError::new("stored Disk slug is invalid"))?,
                    mount_path: wire::PersistentMountPath::new(mount.mount_path)
                        .ok_or_else(|| ResourceStoreError::new("stored mount path is invalid"))?,
                })
            })
            .collect::<Result<Vec<_>, ResourceStoreError>>()?,
        last_error,
        created_at_unix_ms: nonnegative_time(cat.created_at)?,
        updated_at_unix_ms: nonnegative_time(cat.updated_at)?,
        destroyed_at_unix_ms: cat.destroyed_at.map(nonnegative_time).transpose()?,
        current_action_started_at_unix_ms: cat
            .current_action_started_at
            .map(nonnegative_time)
            .transpose()?,
        last_running_at_unix_ms: cat.last_running_at.map(nonnegative_time).transpose()?,
    })
}

fn disk_view(projection: DiskProjection) -> Result<wire::DiskView, ResourceStoreError> {
    let disk = projection.disk;
    Ok(wire::DiskView {
        disk_id: parse_id(&disk.disk_id)?,
        workspace_id: parse_id(&disk.workspace_id)?,
        disk_slug: wire::ResourceSlug::new(disk.disk_slug)
            .ok_or_else(|| ResourceStoreError::new("stored Disk slug is invalid"))?,
        size_bytes: u64::try_from(disk.size_bytes)
            .map_err(|_| ResourceStoreError::new("stored Disk size is invalid"))?,
        head_generation: projection
            .head_generation
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| ResourceStoreError::new("stored Disk generation is invalid"))
            })
            .transpose()?,
        status: match disk.status.as_str() {
            "normal" => wire::DiskStatus::Normal,
            "deleted" => wire::DiskStatus::Deleted,
            _ => return Err(ResourceStoreError::new("stored Disk status is invalid")),
        },
        binding: projection
            .binding
            .map(|binding| {
                Ok(wire::DiskBindingView {
                    cat_id: parse_id(&binding.binding.cat_id)?,
                    cat_slug: wire::ResourceSlug::new(binding.cat_slug)
                        .ok_or_else(|| ResourceStoreError::new("stored Cat slug is invalid"))?,
                    mount_path: wire::PersistentMountPath::new(binding.binding.mount_path)
                        .ok_or_else(|| ResourceStoreError::new("stored mount path is invalid"))?,
                })
            })
            .transpose()?,
        created_at_unix_ms: nonnegative_time(disk.created_at)?,
        deleted_at_unix_ms: disk.deleted_at.map(nonnegative_time).transpose()?,
    })
}

fn snapshot_view(
    snapshot: db::DiskSnapshotRecord,
) -> Result<wire::DiskSnapshotView, ResourceStoreError> {
    Ok(wire::DiskSnapshotView {
        snapshot_id: parse_id(&snapshot.snapshot_id)?,
        workspace_id: parse_id(&snapshot.workspace_id)?,
        snapshot_slug: wire::ResourceSlug::new(snapshot.snapshot_slug)
            .ok_or_else(|| ResourceStoreError::new("stored Snapshot slug is invalid"))?,
        disk_id: parse_id(&snapshot.disk_id)?,
        disk_slug: wire::ResourceSlug::new(snapshot.disk_slug)
            .ok_or_else(|| ResourceStoreError::new("stored Disk slug is invalid"))?,
        size_bytes: u64::try_from(snapshot.size_bytes)
            .map_err(|_| ResourceStoreError::new("stored Snapshot size is invalid"))?,
        status: if snapshot.deleted_at.is_some() {
            wire::DiskSnapshotStatus::Deleted
        } else {
            wire::DiskSnapshotStatus::Normal
        },
        captured_generation: u64::try_from(snapshot.captured_generation)
            .map_err(|_| ResourceStoreError::new("stored Snapshot generation is invalid"))?,
        created_at_unix_ms: nonnegative_time(snapshot.created_at)?,
        deleted_at_unix_ms: snapshot.deleted_at.map(nonnegative_time).transpose()?,
    })
}

fn parse_id(value: &str) -> Result<Id, ResourceStoreError> {
    Id::new(value).ok_or_else(|| ResourceStoreError::new("stored immutable ID is invalid"))
}

fn nonnegative_time(value: i64) -> Result<u64, ResourceStoreError> {
    u64::try_from(value).map_err(|_| ResourceStoreError::new("stored timestamp is negative"))
}

fn disk_create_candidate(
    workspace_id: &str,
    disk_slug: &str,
    size_bytes: u64,
) -> Result<DiskCreateCandidate, wire::SemanticErrorBody> {
    let disk_id = format!("disk_{}", uuid::Uuid::new_v4().simple());
    let volume_id = format!("vol_{}", uuid::Uuid::new_v4().simple());
    let size_bytes = i64::try_from(size_bytes).map_err(|_| {
        semantic_error(
            wire::SemanticErrorCode::InvalidRequest,
            "PersistentDisk size is too large",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"cats.semantic-persistent-disk-filesystem.v1\0");
    hasher.update(disk_id.as_bytes());
    let filesystem_uuid = hex::encode(&hasher.finalize()[..16]);
    Ok(DiskCreateCandidate {
        disk_id,
        workspace_id: workspace_id.to_owned(),
        disk_slug: disk_slug.to_owned(),
        size_bytes,
        volume_id,
        filesystem_uuid,
    })
}

fn map_outcome_status(status: lifecycle::OutcomeStatus) -> wire::SemanticStatus {
    match status {
        lifecycle::OutcomeStatus::Ok => wire::SemanticStatus::Ok,
        lifecycle::OutcomeStatus::AlreadyDone => wire::SemanticStatus::AlreadyDone,
        lifecycle::OutcomeStatus::AlreadyExists => wire::SemanticStatus::AlreadyExists,
    }
}

fn success_code(code: &str) -> Result<wire::SemanticSuccessCode, wire::SemanticErrorBody> {
    match code {
        "cat_created" => Ok(wire::SemanticSuccessCode::CatCreated),
        "cat_running" => Ok(wire::SemanticSuccessCode::CatRunning),
        "cat_suspended" => Ok(wire::SemanticSuccessCode::CatSuspended),
        "cat_warm" => Ok(wire::SemanticSuccessCode::CatWarm),
        "cat_cold" => Ok(wire::SemanticSuccessCode::CatCold),
        "cat_destroyed" => Ok(wire::SemanticSuccessCode::CatDestroyed),
        "already_exists" => Ok(wire::SemanticSuccessCode::AlreadyExists),
        "already_running" => Ok(wire::SemanticSuccessCode::AlreadyRunning),
        "already_suspended" => Ok(wire::SemanticSuccessCode::AlreadySuspended),
        "already_warm" => Ok(wire::SemanticSuccessCode::AlreadyWarm),
        "already_cold" => Ok(wire::SemanticSuccessCode::AlreadyCold),
        "already_destroyed" => Ok(wire::SemanticSuccessCode::AlreadyDestroyed),
        _ => Err(semantic_error(
            wire::SemanticErrorCode::InternalError,
            "lifecycle returned an unknown success code",
        )),
    }
}

fn wire_action_to_lifecycle(action: wire::CatAction) -> lifecycle::CatAction {
    match action {
        wire::CatAction::Create => lifecycle::CatAction::Create,
        wire::CatAction::Run => lifecycle::CatAction::Run,
        wire::CatAction::Suspend => lifecycle::CatAction::Suspend,
        wire::CatAction::Warm => lifecycle::CatAction::Warm,
        wire::CatAction::Cold => lifecycle::CatAction::Cold,
        wire::CatAction::Destroy => lifecycle::CatAction::Destroy,
    }
}

fn db_state_to_wire(state: db::CatState) -> wire::CatState {
    match state {
        db::CatState::Running => wire::CatState::Running,
        db::CatState::Suspended => wire::CatState::Suspended,
        db::CatState::Warm => wire::CatState::Warm,
        db::CatState::Cold => wire::CatState::Cold,
        db::CatState::Failure => wire::CatState::Failure,
        db::CatState::Destroyed => wire::CatState::Destroyed,
    }
}

fn db_action_to_wire(action: db::CatAction) -> wire::CatAction {
    match action {
        db::CatAction::Create => wire::CatAction::Create,
        db::CatAction::Run => wire::CatAction::Run,
        db::CatAction::Suspend => wire::CatAction::Suspend,
        db::CatAction::Warm => wire::CatAction::Warm,
        db::CatAction::Cold => wire::CatAction::Cold,
        db::CatAction::Destroy => wire::CatAction::Destroy,
    }
}

fn semantic_error_code(code: &str) -> wire::SemanticErrorCode {
    match code {
        "cat_not_found" => wire::SemanticErrorCode::CatNotFound,
        "cat_configuration_conflict" => wire::SemanticErrorCode::CatConfigurationConflict,
        "invalid_state" => wire::SemanticErrorCode::InvalidState,
        "busy" | "node_busy" => wire::SemanticErrorCode::Busy,
        "node_unavailable" => wire::SemanticErrorCode::NodeUnavailable,
        "disk_not_found" => wire::SemanticErrorCode::DiskNotFound,
        "disk_deleted" => wire::SemanticErrorCode::DiskDeleted,
        "disk_already_attached" => wire::SemanticErrorCode::DiskAlreadyAttached,
        "mount_path_conflict" | "duplicate_mount_path" => {
            wire::SemanticErrorCode::MountPathConflict
        }
        "cat_must_be_cold" => wire::SemanticErrorCode::CatMustBeCold,
        "timeout" => wire::SemanticErrorCode::Timeout,
        _ => wire::SemanticErrorCode::InternalError,
    }
}

fn snapshot_not_found() -> wire::SemanticErrorBody {
    semantic_error(
        wire::SemanticErrorCode::SnapshotNotFound,
        "DiskSnapshot was not found",
    )
}

fn snapshot_occurrence_conflict() -> wire::SemanticErrorBody {
    semantic_error(
        wire::SemanticErrorCode::SnapshotConfigurationConflict,
        "current DiskSnapshot occurrence does not match expected_snapshot_id",
    )
}

pub(crate) fn map_lifecycle_error(error: lifecycle::LifecycleError) -> wire::SemanticErrorBody {
    match error {
        lifecycle::LifecycleError::Store(error) => {
            semantic_error(wire::SemanticErrorCode::InternalError, error.message)
        }
        lifecycle::LifecycleError::NotFound => {
            semantic_error(wire::SemanticErrorCode::CatNotFound, "Cat was not found")
        }
        lifecycle::LifecycleError::Busy(_) => semantic_error(
            wire::SemanticErrorCode::Busy,
            "another Cat action is running",
        ),
        lifecycle::LifecycleError::Conflict { code, .. } => {
            semantic_error(semantic_error_code(code), code)
        }
        lifecycle::LifecycleError::InvalidState(_) => semantic_error(
            wire::SemanticErrorCode::InvalidState,
            "Cat action is invalid from the current state",
        ),
        lifecycle::LifecycleError::Failed { code, message, .. }
        | lifecycle::LifecycleError::Rejected { code, message } => {
            semantic_error(semantic_error_code(&code), message)
        }
        lifecycle::LifecycleError::Timeout { .. } => {
            semantic_error(wire::SemanticErrorCode::Timeout, "Cat action timed out")
        }
    }
}

fn map_attach_outcome(
    outcome: db::AttachDiskOutcome,
) -> Result<(wire::SemanticStatus, wire::SemanticSuccessCode), wire::SemanticErrorBody> {
    match outcome {
        db::AttachDiskOutcome::Attached(_) => Ok((
            wire::SemanticStatus::Ok,
            wire::SemanticSuccessCode::DiskAttached,
        )),
        db::AttachDiskOutcome::AlreadyAttached(_) => Ok((
            wire::SemanticStatus::AlreadyDone,
            wire::SemanticSuccessCode::AlreadyAttached,
        )),
        db::AttachDiskOutcome::MountPathConflict(_) => Err(semantic_error(
            wire::SemanticErrorCode::MountPathConflict,
            "PersistentDisk binding uses a different mount path",
        )),
        db::AttachDiskOutcome::DiskAlreadyAttached(_) => Err(semantic_error(
            wire::SemanticErrorCode::DiskAlreadyAttached,
            "PersistentDisk is attached to another Cat",
        )),
        db::AttachDiskOutcome::CatMustBeCold => Err(semantic_error(
            wire::SemanticErrorCode::CatMustBeCold,
            "Cat must be Cold",
        )),
        db::AttachDiskOutcome::DiskDeleted => Err(semantic_error(
            wire::SemanticErrorCode::DiskDeleted,
            "PersistentDisk is deleted",
        )),
        db::AttachDiskOutcome::WorkspaceMismatch
        | db::AttachDiskOutcome::CatNotFound
        | db::AttachDiskOutcome::DiskNotFound => Err(semantic_error(
            wire::SemanticErrorCode::DiskNotFound,
            "Cat or PersistentDisk was not found in this Workspace",
        )),
    }
}

fn map_detach_outcome(
    outcome: db::DetachDiskOutcome,
) -> Result<(wire::SemanticStatus, wire::SemanticSuccessCode), wire::SemanticErrorBody> {
    match outcome {
        db::DetachDiskOutcome::Detached => Ok((
            wire::SemanticStatus::Ok,
            wire::SemanticSuccessCode::DiskDetached,
        )),
        db::DetachDiskOutcome::AlreadyDetached => Ok((
            wire::SemanticStatus::AlreadyDone,
            wire::SemanticSuccessCode::AlreadyDetached,
        )),
        db::DetachDiskOutcome::DiskBindingConflict(_) => Err(semantic_error(
            wire::SemanticErrorCode::DiskBindingConflict,
            "PersistentDisk is bound to another Cat",
        )),
        db::DetachDiskOutcome::CatMustBeCold => Err(semantic_error(
            wire::SemanticErrorCode::CatMustBeCold,
            "Cat must be Cold",
        )),
        db::DetachDiskOutcome::CatNotFound => Err(semantic_error(
            wire::SemanticErrorCode::CatNotFound,
            "Cat was not found",
        )),
    }
}

fn internal_resource_error(error: ResourceStoreError) -> wire::SemanticErrorBody {
    semantic_error(wire::SemanticErrorCode::InternalError, error.message)
}

fn snapshot_graph_validation_error(error: SnapshotGraphValidationError) -> wire::SemanticErrorBody {
    match error {
        SnapshotGraphValidationError::Corrupt(message) => {
            semantic_error(wire::SemanticErrorCode::SnapshotCorrupt, message)
        }
        SnapshotGraphValidationError::StorageUnavailable(message) => {
            semantic_error(wire::SemanticErrorCode::StorageUnavailable, message)
        }
    }
}

fn semantic_error(
    code: wire::SemanticErrorCode,
    message: impl Into<String>,
) -> wire::SemanticErrorBody {
    wire::SemanticErrorBody {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const DEFAULT_BOOT_IMAGE: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct MockLifecycle {
        creates: Mutex<Vec<lifecycle::CreateCatRequest>>,
    }

    impl MockLifecycle {
        fn new() -> Self {
            Self {
                creates: Mutex::new(Vec::new()),
            }
        }
    }

    impl LifecycleResourcePort for MockLifecycle {
        fn create<'a>(
            &'a self,
            request: lifecycle::CreateCatRequest,
        ) -> SemanticResourceFuture<
            'a,
            Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>,
        > {
            self.creates.lock().unwrap().push(request.clone());
            Box::pin(async move {
                Ok(lifecycle::LifecycleOutcome {
                    status: lifecycle::OutcomeStatus::Ok,
                    code: "cat_created",
                    cat: lifecycle_cat(&request, "cat_current"),
                })
            })
        }

        fn action<'a>(
            &'a self,
            _selector: lifecycle::CatSelector,
            _action: lifecycle::CatAction,
        ) -> SemanticResourceFuture<
            'a,
            Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>,
        > {
            Box::pin(async {
                Err(lifecycle::LifecycleError::Rejected {
                    code: "unused".to_owned(),
                    message: "unused test path".to_owned(),
                })
            })
        }
    }

    struct MockResources {
        disk: Mutex<Option<db::PersistentDiskRecord>>,
        cat: Option<db::CatRecord>,
        binding: Option<db::DiskBindingWithCat>,
        snapshots: Mutex<Vec<db::DiskSnapshotRecord>>,
        attaches: Mutex<Vec<(String, String, String)>>,
    }

    impl MockResources {
        fn populated() -> Self {
            Self {
                disk: Mutex::new(Some(disk_record("disk_current", "data", 100))),
                cat: Some(cat_record("cat_current", "worker")),
                binding: None,
                snapshots: Mutex::new(Vec::new()),
                attaches: Mutex::new(Vec::new()),
            }
        }
    }

    impl SemanticResourceStore for MockResources {
        fn current_cat_ids<'a>(
            &'a self,
            workspace_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>> {
            let ids = self
                .cat
                .iter()
                .filter(|cat| cat.workspace_id == workspace_id)
                .map(|cat| cat.cat_id.clone())
                .collect();
            Box::pin(async move { Ok(ids) })
        }

        fn current_disk_ids<'a>(
            &'a self,
            workspace_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Vec<String>, ResourceStoreError>> {
            let ids = self
                .disk
                .lock()
                .unwrap()
                .iter()
                .filter(|disk| disk.workspace_id == workspace_id)
                .map(|disk| disk.disk_id.clone())
                .collect();
            Box::pin(async move { Ok(ids) })
        }

        fn current_disk<'a>(
            &'a self,
            workspace_id: &'a str,
            disk_slug: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<db::PersistentDiskRecord>, ResourceStoreError>>
        {
            let disk =
                self.disk.lock().unwrap().clone().filter(|disk| {
                    disk.workspace_id == workspace_id && disk.disk_slug == disk_slug
                });
            Box::pin(async move { Ok(disk) })
        }

        fn current_cat<'a>(
            &'a self,
            workspace_id: &'a str,
            cat_slug: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<db::CatRecord>, ResourceStoreError>> {
            let cat = self
                .cat
                .clone()
                .filter(|cat| cat.workspace_id == workspace_id && cat.cat_slug == cat_slug);
            Box::pin(async move { Ok(cat) })
        }

        fn cat_projection<'a>(
            &'a self,
            cat_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<CatProjection>, ResourceStoreError>> {
            let cat = self.cat.clone().filter(|cat| cat.cat_id == cat_id);
            let disk = self.disk.lock().unwrap().clone();
            Box::pin(async move {
                Ok(cat.map(|cat| CatProjection {
                    cat: db::CatWithMounts {
                        cat,
                        mounts: disk
                            .map(|disk| db::CatMountRecord {
                                disk_id: disk.disk_id,
                                disk_slug: disk.disk_slug,
                                volume_id: disk.volume_id,
                                filesystem_uuid: disk.filesystem_uuid,
                                disk_format: disk.disk_format,
                                mount_path: "/data".to_owned(),
                            })
                            .into_iter()
                            .collect(),
                    },
                    node_name: None,
                }))
            })
        }

        fn disk_projection<'a>(
            &'a self,
            disk_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<DiskProjection>, ResourceStoreError>>
        {
            let disk = self
                .disk
                .lock()
                .unwrap()
                .clone()
                .filter(|disk| disk.disk_id == disk_id);
            let binding = self.binding.clone();
            Box::pin(async move {
                Ok(disk.map(|disk| DiskProjection {
                    disk,
                    binding,
                    head_generation: Some(1),
                }))
            })
        }

        fn current_snapshot<'a>(
            &'a self,
            workspace_id: &'a str,
            snapshot_slug: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<db::DiskSnapshotRecord>, ResourceStoreError>>
        {
            let snapshot = self
                .snapshots
                .lock()
                .unwrap()
                .iter()
                .find(|snapshot| {
                    snapshot.workspace_id == workspace_id
                        && snapshot.snapshot_slug == snapshot_slug
                        && snapshot.deleted_at.is_none()
                })
                .cloned();
            Box::pin(async move { Ok(snapshot) })
        }

        fn snapshot_by_id<'a>(
            &'a self,
            snapshot_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<db::DiskSnapshotRecord>, ResourceStoreError>>
        {
            let snapshot = self
                .snapshots
                .lock()
                .unwrap()
                .iter()
                .find(|snapshot| snapshot.snapshot_id == snapshot_id)
                .cloned();
            Box::pin(async move { Ok(snapshot) })
        }

        fn delete_snapshot<'a>(
            &'a self,
            workspace_id: String,
            snapshot_id: String,
        ) -> SemanticResourceFuture<'a, Result<db::DeleteDiskSnapshotOutcome, ResourceStoreError>>
        {
            let mut snapshots = self.snapshots.lock().unwrap();
            let outcome = snapshots
                .iter_mut()
                .find(|snapshot| {
                    snapshot.workspace_id == workspace_id && snapshot.snapshot_id == snapshot_id
                })
                .map(|snapshot| {
                    if snapshot.deleted_at.is_some() {
                        db::DeleteDiskSnapshotOutcome::AlreadyDeleted(snapshot.clone())
                    } else {
                        snapshot.deleted_at = Some(2);
                        db::DeleteDiskSnapshotOutcome::Deleted(snapshot.clone())
                    }
                })
                .unwrap_or(db::DeleteDiskSnapshotOutcome::NotFound);
            Box::pin(async move { Ok(outcome) })
        }

        fn attach<'a>(
            &'a self,
            binding_id: String,
            cat_id: String,
            disk_id: String,
            mount_path: String,
        ) -> SemanticResourceFuture<'a, Result<db::AttachDiskOutcome, ResourceStoreError>> {
            self.attaches.lock().unwrap().push((
                cat_id.clone(),
                disk_id.clone(),
                mount_path.clone(),
            ));
            Box::pin(async move {
                Ok(db::AttachDiskOutcome::Attached(db::DiskBindingRecord {
                    binding_id,
                    workspace_id: "ws_test".to_owned(),
                    disk_id,
                    cat_id,
                    mount_path,
                    created_at: 1,
                }))
            })
        }

        fn detach<'a>(
            &'a self,
            _cat_id: String,
            _disk_id: String,
        ) -> SemanticResourceFuture<'a, Result<db::DetachDiskOutcome, ResourceStoreError>> {
            Box::pin(async { Ok(db::DetachDiskOutcome::AlreadyDetached) })
        }

        fn admit_disk_create<'a>(
            &'a self,
            candidate: DiskCreateCandidate,
        ) -> SemanticResourceFuture<'a, Result<db::CreatePersistentDiskOutcome, ResourceStoreError>>
        {
            let disk = candidate_disk(candidate, "provisioning");
            *self.disk.lock().unwrap() = Some(disk.clone());
            Box::pin(async move { Ok(db::CreatePersistentDiskOutcome::Created(disk)) })
        }

        fn complete_disk_create<'a>(
            &'a self,
            mut disk: db::PersistentDiskRecord,
        ) -> SemanticResourceFuture<'a, Result<db::PersistentDiskRecord, ResourceStoreError>>
        {
            disk.status = "normal".to_owned();
            *self.disk.lock().unwrap() = Some(disk.clone());
            Box::pin(async move { Ok(disk) })
        }

        fn begin_disk_destroy<'a>(
            &'a self,
            _disk_id: String,
        ) -> SemanticResourceFuture<'a, Result<db::DeletePersistentDiskOutcome, ResourceStoreError>>
        {
            let mut disk = self.disk.lock().unwrap().clone().unwrap();
            disk.status = "deleting".to_owned();
            *self.disk.lock().unwrap() = Some(disk.clone());
            Box::pin(async move { Ok(db::DeletePersistentDiskOutcome::Deleting(disk)) })
        }

        fn complete_disk_destroy<'a>(
            &'a self,
            mut disk: db::PersistentDiskRecord,
        ) -> SemanticResourceFuture<'a, Result<db::PersistentDiskRecord, ResourceStoreError>>
        {
            disk.status = "deleted".to_owned();
            disk.deleted_at = Some(2);
            *self.disk.lock().unwrap() = Some(disk.clone());
            Box::pin(async move { Ok(disk) })
        }
    }

    #[derive(Default)]
    struct RecordingDiskBackend {
        creates: Mutex<Vec<db::PersistentDiskRecord>>,
        lose_first_create_response: Mutex<bool>,
    }

    impl SemanticPersistentDiskBackend for RecordingDiskBackend {
        fn ensure_created<'a>(
            &'a self,
            disk: &'a db::PersistentDiskRecord,
        ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>> {
            self.creates.lock().unwrap().push(disk.clone());
            let lose_response =
                std::mem::take(&mut *self.lose_first_create_response.lock().unwrap());
            Box::pin(async move {
                if lose_response {
                    Err(ResourceStoreError::new("strict create response was lost"))
                } else {
                    Ok(())
                }
            })
        }

        fn ensure_destroyed<'a>(
            &'a self,
            _disk: &'a db::PersistentDiskRecord,
        ) -> SemanticResourceFuture<'a, Result<(), ResourceStoreError>> {
            Box::pin(async { Ok(()) })
        }

        fn validate_snapshot_graph<'a>(
            &'a self,
            _candidate: db::DiskSnapshotGraphCandidate,
        ) -> SemanticResourceFuture<'a, Result<(), SnapshotGraphValidationError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn candidate_disk(candidate: DiskCreateCandidate, status: &str) -> db::PersistentDiskRecord {
        db::PersistentDiskRecord {
            disk_id: candidate.disk_id,
            workspace_id: candidate.workspace_id,
            disk_slug: candidate.disk_slug,
            size_bytes: candidate.size_bytes,
            volume_id: candidate.volume_id,
            filesystem_uuid: candidate.filesystem_uuid,
            disk_format: "ext4".to_owned(),
            status: status.to_owned(),
            created_at: 1,
            deleted_at: None,
        }
    }

    fn lifecycle_cat(request: &lifecycle::CreateCatRequest, cat_id: &str) -> lifecycle::CatRecord {
        lifecycle::CatRecord {
            cat_id: cat_id.to_owned(),
            workspace_id: request.workspace_id.clone(),
            cat_slug: request.cat_slug.clone(),
            state: Some(lifecycle::CatState::Cold),
            current_action: None,
            current_action_node_id: None,
            node_id: None,
            config: request.config.clone(),
        }
    }

    fn cat_record(cat_id: &str, cat_slug: &str) -> db::CatRecord {
        db::CatRecord {
            cat_id: cat_id.to_owned(),
            workspace_id: "ws_test".to_owned(),
            cat_slug: cat_slug.to_owned(),
            state: Some(db::CatState::Cold),
            current_action: None,
            current_action_started_at: None,
            current_action_recovery_started_at: None,
            current_action_node_id: None,
            node_id: None,
            cpu_count: 2,
            memory_bytes: 1024,
            boot_image: "image".to_owned(),
            last_error_code: None,
            last_error_message: None,
            created_at: 1,
            updated_at: 1,
            destroyed_at: None,
            last_running_at: None,
        }
    }

    fn disk_record(disk_id: &str, disk_slug: &str, size_bytes: i64) -> db::PersistentDiskRecord {
        db::PersistentDiskRecord {
            disk_id: disk_id.to_owned(),
            workspace_id: "ws_test".to_owned(),
            disk_slug: disk_slug.to_owned(),
            size_bytes,
            volume_id: "vol_current".to_owned(),
            filesystem_uuid: "11111111111111111111111111111111".to_owned(),
            disk_format: "ext4".to_owned(),
            status: "normal".to_owned(),
            created_at: 1,
            deleted_at: None,
        }
    }

    fn snapshot_record(snapshot_id: &str, snapshot_slug: &str) -> db::DiskSnapshotRecord {
        db::DiskSnapshotRecord {
            snapshot_id: snapshot_id.to_owned(),
            workspace_id: "ws_test".to_owned(),
            snapshot_slug: snapshot_slug.to_owned(),
            disk_id: "disk_current".to_owned(),
            disk_slug: "data".to_owned(),
            volume_id: "vol_current".to_owned(),
            size_bytes: 100,
            captured_generation: 1,
            created_at: 1,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn create_cat_resolves_mount_slug_to_immutable_disk_id() {
        let api = ProductionSemanticResourceApi::new(
            MockLifecycle::new(),
            MockResources::populated(),
            DEFAULT_BOOT_IMAGE,
        );

        let response = api
            .create_cat(
                "ws_test",
                wire::CreateCatRequest {
                    cat_slug: wire::ResourceSlug::new("worker").unwrap(),
                    cpu: 2,
                    memory_bytes: 1024,
                    mounts: vec![wire::CatMountRequest {
                        disk_slug: wire::ResourceSlug::new("data").unwrap(),
                        mount_path: wire::PersistentMountPath::new("/data").unwrap(),
                    }],
                },
            )
            .await
            .unwrap();

        let creates = api.lifecycle.creates.lock().unwrap();
        assert_eq!(creates[0].config.boot_image, DEFAULT_BOOT_IMAGE);
        assert_eq!(creates[0].config.mounts[0].disk_id, "disk_current");
        assert_eq!(response.status, wire::SemanticStatus::Ok);
        assert_eq!(response.cat.mounts[0].disk_id.as_str(), "disk_current");
    }

    #[tokio::test]
    async fn disk_create_retries_by_current_slug_and_fails_closed_without_backend() {
        let api = ProductionSemanticResourceApi::new(
            MockLifecycle::new(),
            MockResources::populated(),
            DEFAULT_BOOT_IMAGE,
        );

        let existing = api
            .create_disk(
                "ws_test",
                wire::CreateDiskRequest {
                    disk_slug: wire::ResourceSlug::new("data").unwrap(),
                    size_bytes: 100,
                },
            )
            .await
            .unwrap();
        assert_eq!(existing.status, wire::SemanticStatus::AlreadyExists);

        let conflict = api
            .create_disk(
                "ws_test",
                wire::CreateDiskRequest {
                    disk_slug: wire::ResourceSlug::new("data").unwrap(),
                    size_bytes: 101,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(conflict.code, wire::SemanticErrorCode::DiskSizeConflict);

        let unavailable = api
            .create_disk(
                "ws_test",
                wire::CreateDiskRequest {
                    disk_slug: wire::ResourceSlug::new("new-data").unwrap(),
                    size_bytes: 100,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(unavailable.code, wire::SemanticErrorCode::InternalError);
        assert!(unavailable.message.contains("backend is not installed"));
    }

    #[tokio::test]
    async fn lost_backend_response_resumes_the_persisted_immutable_disk_identity() {
        let resources = MockResources::populated();
        *resources.disk.lock().unwrap() = None;
        let backend = RecordingDiskBackend {
            lose_first_create_response: Mutex::new(true),
            ..RecordingDiskBackend::default()
        };
        let api = ProductionSemanticResourceApi::with_disk_backend(
            MockLifecycle::new(),
            resources,
            backend,
            DEFAULT_BOOT_IMAGE,
        );
        let request = || wire::CreateDiskRequest {
            disk_slug: wire::ResourceSlug::new("recoverable-data").unwrap(),
            size_bytes: 4096,
        };

        let lost = api.create_disk("ws_test", request()).await.unwrap_err();
        assert_eq!(lost.code, wire::SemanticErrorCode::InternalError);

        let response = api.create_disk("ws_test", request()).await.unwrap();
        assert_eq!(response.status, wire::SemanticStatus::AlreadyExists);
        assert_eq!(response.disk.status, wire::DiskStatus::Normal);

        let attempts = api.disk_backend.creates.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].disk_id, attempts[1].disk_id);
        assert_eq!(attempts[0].volume_id, attempts[1].volume_id);
        assert_eq!(attempts[0].filesystem_uuid, attempts[1].filesystem_uuid);
        assert_eq!(attempts[0].size_bytes, attempts[1].size_bytes);
        assert_eq!(attempts[0].status, "provisioning");
    }

    #[tokio::test]
    async fn attach_resolves_both_slugs_before_mutation() {
        let api = ProductionSemanticResourceApi::new(
            MockLifecycle::new(),
            MockResources::populated(),
            DEFAULT_BOOT_IMAGE,
        );

        let response = api
            .attach_disk(
                "ws_test",
                wire::ResourceSlug::new("data").unwrap(),
                wire::AttachDiskRequest {
                    cat_slug: wire::ResourceSlug::new("worker").unwrap(),
                    mount_path: wire::PersistentMountPath::new("/data").unwrap(),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.code, wire::SemanticSuccessCode::DiskAttached);
        assert_eq!(
            api.resources.attaches.lock().unwrap().as_slice(),
            &[(
                "cat_current".to_owned(),
                "disk_current".to_owned(),
                "/data".to_owned()
            )]
        );
    }

    #[tokio::test]
    async fn destroy_snapshot_replays_the_exact_deleted_occurrence() {
        let resources = MockResources::populated();
        resources
            .snapshots
            .lock()
            .unwrap()
            .push(snapshot_record("snapshot_original", "checkpoint"));
        let api =
            ProductionSemanticResourceApi::new(MockLifecycle::new(), resources, DEFAULT_BOOT_IMAGE);
        let request = || wire::DestroyDiskSnapshotRequest {
            expected_snapshot_id: Id::new("snapshot_original").unwrap(),
        };

        let destroyed = api
            .destroy_snapshot(
                "ws_test",
                wire::ResourceSlug::new("checkpoint").unwrap(),
                request(),
            )
            .await
            .unwrap();
        assert_eq!(destroyed.code, wire::SemanticSuccessCode::SnapshotDestroyed);

        let replayed = api
            .destroy_snapshot(
                "ws_test",
                wire::ResourceSlug::new("checkpoint").unwrap(),
                request(),
            )
            .await
            .unwrap();
        assert_eq!(replayed.status, wire::SemanticStatus::AlreadyDone);
        assert_eq!(replayed.code, wire::SemanticSuccessCode::AlreadyDeleted);
        assert_eq!(replayed.snapshot.snapshot_id.as_str(), "snapshot_original");
    }

    #[tokio::test]
    async fn destroy_snapshot_replay_rejects_a_reused_slug() {
        let resources = MockResources::populated();
        let mut original = snapshot_record("snapshot_original", "checkpoint");
        original.deleted_at = Some(2);
        resources.snapshots.lock().unwrap().extend([
            original,
            snapshot_record("snapshot_replacement", "checkpoint"),
        ]);
        let api =
            ProductionSemanticResourceApi::new(MockLifecycle::new(), resources, DEFAULT_BOOT_IMAGE);

        let error = api
            .destroy_snapshot(
                "ws_test",
                wire::ResourceSlug::new("checkpoint").unwrap(),
                wire::DestroyDiskSnapshotRequest {
                    expected_snapshot_id: Id::new("snapshot_original").unwrap(),
                },
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, wire::SemanticErrorCode::SnapshotConflict);
        let snapshots = api.resources.snapshots.lock().unwrap();
        assert!(snapshots
            .iter()
            .any(|snapshot| snapshot.snapshot_id == "snapshot_replacement"
                && snapshot.deleted_at.is_none()));
    }

    #[tokio::test]
    async fn destroy_snapshot_does_not_replay_a_tombstone_from_another_path() {
        let resources = MockResources::populated();
        let mut snapshot = snapshot_record("snapshot_original", "other-checkpoint");
        snapshot.deleted_at = Some(2);
        resources.snapshots.lock().unwrap().push(snapshot);
        let api =
            ProductionSemanticResourceApi::new(MockLifecycle::new(), resources, DEFAULT_BOOT_IMAGE);

        let error = api
            .destroy_snapshot(
                "ws_test",
                wire::ResourceSlug::new("checkpoint").unwrap(),
                wire::DestroyDiskSnapshotRequest {
                    expected_snapshot_id: Id::new("snapshot_original").unwrap(),
                },
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, wire::SemanticErrorCode::SnapshotNotFound);
    }

    #[tokio::test]
    async fn destroy_disk_checks_binding_before_fail_closed_backend() {
        let mut resources = MockResources::populated();
        resources.binding = Some(db::DiskBindingWithCat {
            binding: db::DiskBindingRecord {
                binding_id: "binding_current".to_owned(),
                workspace_id: "ws_test".to_owned(),
                disk_id: "disk_current".to_owned(),
                cat_id: "cat_current".to_owned(),
                mount_path: "/data".to_owned(),
                created_at: 1,
            },
            cat_slug: "worker".to_owned(),
        });
        let api =
            ProductionSemanticResourceApi::new(MockLifecycle::new(), resources, DEFAULT_BOOT_IMAGE);

        let in_use = api
            .destroy_disk("ws_test", wire::ResourceSlug::new("data").unwrap())
            .await
            .unwrap_err();
        assert_eq!(in_use.code, wire::SemanticErrorCode::DiskInUse);
    }
}

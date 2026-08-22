//! Production aggregation for the public semantic Cat/Disk API.
//!
//! Public slugs are resolved only to the current resource. From that point on,
//! lifecycle and binding mutations use immutable internal IDs. No request ID,
//! lifecycle Operation, or compatibility protocol enters this adapter.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control as wire;

use crate::api::semantic_resources::{SemanticResourceApi, SemanticResourceFuture};
use crate::semantic_lifecycle as lifecycle;
use crate::store::semantic as db;
use crate::store::{new_id, Store};

const STRICT_DISK_BACKEND_GAP: &str = "strict PersistentDisk backend is unavailable: the semantic schema does not persist the exact volume/filesystem identity, create has no atomic strict-volume provision boundary, delete has no backend completion boundary, and noded receives only disk_id plus mount_path";

pub trait LifecycleResourcePort: Send + Sync {
    fn create<'a>(
        &'a self,
        request: lifecycle::CreateCatRequest,
    ) -> SemanticResourceFuture<
        'a,
        Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>,
    >;

    fn action<'a>(
        &'a self,
        selector: lifecycle::CatSelector,
        action: lifecycle::CatAction,
    ) -> SemanticResourceFuture<
        'a,
        Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>,
    >;
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
    ) -> SemanticResourceFuture<
        'a,
        Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>,
    > {
        Box::pin(async move { self.create(request).await })
    }

    fn action<'a>(
        &'a self,
        selector: lifecycle::CatSelector,
        action: lifecycle::CatAction,
    ) -> SemanticResourceFuture<
        'a,
        Result<lifecycle::LifecycleOutcome, lifecycle::LifecycleError>,
    > {
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

pub trait SemanticResourceStore: Send + Sync {
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
    fn current_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<db::PersistentDiskRecord>, ResourceStoreError>> {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        let disk_slug = disk_slug.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.find_current_semantic_disk(&workspace_id, &disk_slug)
                })
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
                                    cats_api::error::ApiError::internal(
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
                    Ok(Some(DiskProjection { disk, binding }))
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
}

fn resource_store_error(error: cats_api::error::ApiError) -> ResourceStoreError {
    ResourceStoreError::new(error.message)
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
        let cat_id = new_id("cat");
        let mounts = request
            .config
            .mounts
            .iter()
            .map(|mount| (new_id("binding"), mount.clone()))
            .collect::<Vec<_>>();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let node_id = store
                        .list_running_semantic_nodes()?
                        .into_iter()
                        .next()
                        .map(|node| node.node_id);
                    let db_mounts = mounts
                        .iter()
                        .map(|(binding_id, mount)| db::NewCatMount {
                            binding_id,
                            disk_id: &mount.disk_id,
                            mount_path: &mount.mount_path,
                        })
                        .collect::<Vec<_>>();
                    let cpu_count = i64::from(request.config.cpu_count);
                    let memory_bytes = i64::try_from(request.config.memory_bytes).map_err(|_| {
                        cats_api::error::ApiError::invalid("Cat memory exceeds PostgreSQL BIGINT")
                    })?;
                    store.admit_semantic_cat_create(db::AtomicCatCreate {
                        cat_id: &cat_id,
                        workspace_id: &request.workspace_id,
                        cat_slug: &request.cat_slug,
                        node_id: node_id.as_deref(),
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
                    let selected_node = if action == lifecycle::CatAction::Run {
                        store
                            .list_running_semantic_nodes()?
                            .into_iter()
                            .next()
                            .map(|node| node.node_id)
                    } else {
                        None
                    };
                    let selector = match &selector {
                        lifecycle::CatSelector::Id(cat_id) => {
                            db::SemanticCatSelector::Id(cat_id)
                        }
                        lifecycle::CatSelector::Slug {
                            workspace_id,
                            cat_slug,
                        } => db::SemanticCatSelector::Slug {
                            workspace_id,
                            cat_slug,
                        },
                    };
                    store.admit_semantic_cat_action(
                        selector,
                        lifecycle_action_to_db(action),
                        selected_node.as_deref(),
                    )
                })
                .await
                .map_err(lifecycle_store_error)
                .and_then(map_action_admission)
        })
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> lifecycle::SemanticFuture<
        'a,
        Result<lifecycle::NodeControlEndpoint, lifecycle::StoreError>,
    > {
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
                    store.finish_semantic_cat_action(
                        &claim.cat.cat_id,
                        db::FinishCatAction {
                            expected_action: lifecycle_action_to_db(claim.action),
                            expected_node_id: claim.node_id.as_deref(),
                            final_state: lifecycle_state_to_db(state),
                            final_node_id: final_node_id.as_deref(),
                            error_code: error_code.as_deref(),
                            error_message: error_message.as_deref(),
                        },
                    )
                })
                .await
                .map_err(lifecycle_store_error)?
                .ok_or_else(|| lifecycle::StoreError::new("Cat action claim became stale"))
                .and_then(db_cat_to_lifecycle)
        })
    }
}

fn lifecycle_store_error(error: cats_api::error::ApiError) -> lifecycle::StoreError {
    lifecycle::StoreError::new(error.message)
}

fn map_create_admission(
    outcome: db::AdmitCatCreateOutcome,
) -> Result<lifecycle::Admission, lifecycle::StoreError> {
    Ok(match outcome {
        db::AdmitCatCreateOutcome::Created(cat) => lifecycle::Admission::Claimed(action_claim(
            cat,
            lifecycle::CatAction::Create,
        )?),
        db::AdmitCatCreateOutcome::SameAction(cat) => lifecycle::Admission::SameAction(
            action_claim(cat, lifecycle::CatAction::Create)?,
        ),
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
    Ok(lifecycle::ActionClaim {
        cat: db_aggregate_to_lifecycle(cat)?,
        action,
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
            mount_path: mount.mount_path,
        })
        .collect();
    db_cat_to_lifecycle_with_mounts(aggregate.cat, mounts)
}

fn db_cat_to_lifecycle(cat: db::CatRecord) -> Result<lifecycle::CatRecord, lifecycle::StoreError> {
    db_cat_to_lifecycle_with_mounts(cat, Vec::new())
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
pub struct ProductionSemanticResourceApi<L, R> {
    lifecycle: L,
    resources: R,
}

impl<L, R> ProductionSemanticResourceApi<L, R> {
    pub fn new(lifecycle: L, resources: R) -> Self {
        Self {
            lifecycle,
            resources,
        }
    }
}

impl<L, R> SemanticResourceApi for ProductionSemanticResourceApi<L, R>
where
    L: LifecycleResourcePort,
    R: SemanticResourceStore,
{
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
                    .ok_or_else(|| semantic_error(wire::SemanticErrorCode::DiskNotFound, "PersistentDisk was not found"))?;
                mounts.push(lifecycle::CatMount {
                    disk_id: disk.disk_id,
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
                        boot_image: request.boot_image,
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
            if let Some(disk) = self
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
                return Ok(wire::DiskResponse {
                    status: wire::SemanticStatus::AlreadyExists,
                    code: wire::SemanticSuccessCode::AlreadyExists,
                    disk: self.project_disk(&disk.disk_id).await?,
                });
            }
            Err(strict_disk_backend_gap())
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
                    new_id("binding"),
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
                .ok_or_else(|| semantic_error(wire::SemanticErrorCode::DiskNotFound, "PersistentDisk was not found"))?;
            if projection.binding.is_some() {
                return Err(semantic_error(
                    wire::SemanticErrorCode::DiskInUse,
                    "PersistentDisk is still bound to a Cat",
                ));
            }
            Err(strict_disk_backend_gap())
        })
    }
}

impl<L, R> ProductionSemanticResourceApi<L, R>
where
    L: LifecycleResourcePort,
    R: SemanticResourceStore,
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

    async fn project_cat(
        &self,
        cat_id: &str,
    ) -> Result<wire::CatView, wire::SemanticErrorBody> {
        let projection = self
            .resources
            .cat_projection(cat_id)
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(|| semantic_error(wire::SemanticErrorCode::CatNotFound, "Cat was not found"))?;
        cat_view(projection).map_err(internal_resource_error)
    }

    async fn project_disk(
        &self,
        disk_id: &str,
    ) -> Result<wire::DiskView, wire::SemanticErrorBody> {
        let projection = self
            .resources
            .disk_projection(disk_id)
            .await
            .map_err(internal_resource_error)?
            .ok_or_else(|| semantic_error(wire::SemanticErrorCode::DiskNotFound, "PersistentDisk was not found"))?;
        disk_view(projection).map_err(internal_resource_error)
    }
}

fn cat_view(projection: CatProjection) -> Result<wire::CatView, ResourceStoreError> {
    let cat = projection.cat.cat;
    let node_id = cat.node_id.as_deref().map(parse_id).transpose()?;
    let node_name = projection
        .node_name
        .map(|name| wire::NodeName::new(name).ok_or_else(|| ResourceStoreError::new("stored Node name is invalid")))
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

fn parse_id(value: &str) -> Result<Id, ResourceStoreError> {
    Id::new(value).ok_or_else(|| ResourceStoreError::new("stored immutable ID is invalid"))
}

fn nonnegative_time(value: i64) -> Result<u64, ResourceStoreError> {
    u64::try_from(value).map_err(|_| ResourceStoreError::new("stored timestamp is negative"))
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

fn map_lifecycle_error(error: lifecycle::LifecycleError) -> wire::SemanticErrorBody {
    match error {
        lifecycle::LifecycleError::Store(error) => {
            semantic_error(wire::SemanticErrorCode::InternalError, error.message)
        }
        lifecycle::LifecycleError::NotFound => {
            semantic_error(wire::SemanticErrorCode::CatNotFound, "Cat was not found")
        }
        lifecycle::LifecycleError::Busy(_) => {
            semantic_error(wire::SemanticErrorCode::Busy, "another Cat action is running")
        }
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

fn strict_disk_backend_gap() -> wire::SemanticErrorBody {
    semantic_error(
        wire::SemanticErrorCode::InternalError,
        STRICT_DISK_BACKEND_GAP,
    )
}

fn internal_resource_error(error: ResourceStoreError) -> wire::SemanticErrorBody {
    semantic_error(wire::SemanticErrorCode::InternalError, error.message)
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


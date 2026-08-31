//! Public synchronous Cat and PersistentDisk semantic resource routes.
//!
//! The adapter authenticates the Workspace, parses only the shared semantic
//! DTOs, and calls one synchronous service method. Scenario identity lives in
//! resource state and target state; this surface has no request ID,
//! idempotency key, or Operation resource.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use cats_api::error::ErrorCode;
use cats_api::semantic_control::{
    AttachDiskRequest, CatAction, CatResponse, CatView, CreateCatRequest, CreateDiskRequest,
    CreateDiskSnapshotRequest, DestroyDiskSnapshotRequest, DetachDiskRequest, DiskResponse,
    DiskSnapshotResponse, DiskSnapshotView, DiskView, ResourceSlug, RestoreDiskSnapshotRequest,
    SemanticErrorBody, SemanticErrorCode, SemanticSuccessCode,
};
use serde::de::DeserializeOwned;

use super::{check_workspace_auth, Failure};
use crate::server::AppState;

pub const CATS_COLLECTION_PATH: &str = "/v1/workspaces/{workspace}/cats";
pub const CAT_ITEM_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}";
pub const CAT_RUN_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/actions/run";
pub const CAT_SUSPEND_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/actions/suspend";
pub const CAT_WARM_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/actions/warm";
pub const CAT_COLD_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/actions/cold";
pub const CAT_DESTROY_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/actions/destroy";
pub const DISKS_COLLECTION_PATH: &str = "/v1/workspaces/{workspace}/disks";
pub const DISK_ITEM_PATH: &str = "/v1/workspaces/{workspace}/disks/{disk}";
pub const DISK_ATTACH_PATH: &str = "/v1/workspaces/{workspace}/disks/{disk}/actions/attach";
pub const DISK_DETACH_PATH: &str = "/v1/workspaces/{workspace}/disks/{disk}/actions/detach";
pub const DISK_DESTROY_PATH: &str = "/v1/workspaces/{workspace}/disks/{disk}/actions/destroy";
pub const SNAPSHOTS_COLLECTION_PATH: &str = "/v1/workspaces/{workspace}/snapshots";
pub const SNAPSHOT_ITEM_PATH: &str = "/v1/workspaces/{workspace}/snapshots/{snapshot}";
pub const SNAPSHOT_DESTROY_PATH: &str =
    "/v1/workspaces/{workspace}/snapshots/{snapshot}/actions/destroy";
pub const SNAPSHOT_RESTORE_PATH: &str =
    "/v1/workspaces/{workspace}/snapshots/{snapshot}/actions/restore";

const JSON_BODY_LIMIT: usize = 16 * 1024;
const IDEMPOTENCY_KEY: &str = "idempotency-key";

/// Boxed future returned by the mockable resource service port.
pub type SemanticResourceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Synchronous semantic resource service boundary.
///
/// `workspace_id` is the authenticated immutable Workspace ID returned by
/// `check_workspace_auth`, never an untrusted value copied from the URL.
pub trait SemanticResourceApi: Send + Sync {
    fn list_cats<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<CatView>, SemanticErrorBody>>;

    fn get_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<CatView, SemanticErrorBody>>;

    fn list_disks<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<DiskView>, SemanticErrorBody>>;

    fn get_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<DiskView, SemanticErrorBody>>;

    fn create_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        request: CreateCatRequest,
    ) -> SemanticResourceFuture<'a, Result<CatResponse, SemanticErrorBody>>;

    fn cat_action<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: ResourceSlug,
        action: CatAction,
    ) -> SemanticResourceFuture<'a, Result<CatResponse, SemanticErrorBody>>;

    fn create_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        request: CreateDiskRequest,
    ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>>;

    fn attach_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: ResourceSlug,
        request: AttachDiskRequest,
    ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>>;

    fn detach_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: ResourceSlug,
        request: DetachDiskRequest,
    ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>>;

    fn destroy_disk<'a>(
        &'a self,
        workspace_id: &'a str,
        disk_slug: ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>>;

    fn list_snapshots<'a>(
        &'a self,
        workspace_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Vec<DiskSnapshotView>, SemanticErrorBody>> {
        let _ = workspace_id;
        Box::pin(async { Err(unavailable_snapshot_api()) })
    }

    fn get_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: ResourceSlug,
    ) -> SemanticResourceFuture<'a, Result<DiskSnapshotView, SemanticErrorBody>> {
        let _ = (workspace_id, snapshot_slug);
        Box::pin(async { Err(unavailable_snapshot_api()) })
    }

    fn create_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        request: CreateDiskSnapshotRequest,
    ) -> SemanticResourceFuture<'a, Result<DiskSnapshotResponse, SemanticErrorBody>> {
        let _ = (workspace_id, request);
        Box::pin(async { Err(unavailable_snapshot_api()) })
    }

    fn destroy_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: ResourceSlug,
        request: DestroyDiskSnapshotRequest,
    ) -> SemanticResourceFuture<'a, Result<DiskSnapshotResponse, SemanticErrorBody>> {
        let _ = (workspace_id, snapshot_slug, request);
        Box::pin(async { Err(unavailable_snapshot_api()) })
    }

    fn restore_snapshot<'a>(
        &'a self,
        workspace_id: &'a str,
        snapshot_slug: ResourceSlug,
        request: RestoreDiskSnapshotRequest,
    ) -> SemanticResourceFuture<'a, Result<DiskSnapshotResponse, SemanticErrorBody>> {
        let _ = (workspace_id, snapshot_slug, request);
        Box::pin(async { Err(unavailable_snapshot_api()) })
    }
}

fn unavailable_snapshot_api() -> SemanticErrorBody {
    SemanticErrorBody {
        code: SemanticErrorCode::InternalError,
        message: "DiskSnapshot service is unavailable".to_owned(),
    }
}

/// Builds the clean-slate semantic resource routes. Production composition
/// merges this router explicitly after retiring the old product handlers.
pub fn routes(service: Arc<dyn SemanticResourceApi>) -> Router<AppState> {
    Router::<AppState>::new()
        .route(CATS_COLLECTION_PATH, post(create_cat).get(list_cats))
        .route(CAT_ITEM_PATH, axum::routing::get(get_cat))
        .route(CAT_RUN_PATH, post(run_cat))
        .route(CAT_SUSPEND_PATH, post(suspend_cat))
        .route(CAT_WARM_PATH, post(warm_cat))
        .route(CAT_COLD_PATH, post(cold_cat))
        .route(CAT_DESTROY_PATH, post(destroy_cat))
        .route(DISKS_COLLECTION_PATH, post(create_disk).get(list_disks))
        .route(DISK_ITEM_PATH, axum::routing::get(get_disk))
        .route(DISK_ATTACH_PATH, post(attach_disk))
        .route(DISK_DETACH_PATH, post(detach_disk))
        .route(DISK_DESTROY_PATH, post(destroy_disk))
        .route(
            SNAPSHOTS_COLLECTION_PATH,
            post(create_snapshot).get(list_snapshots),
        )
        .route(SNAPSHOT_ITEM_PATH, axum::routing::get(get_snapshot))
        .route(SNAPSHOT_DESTROY_PATH, post(destroy_snapshot))
        .route(SNAPSHOT_RESTORE_PATH, post(restore_snapshot))
        .layer(Extension(service))
}

async fn list_cats(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let cats = service
        .list_cats(&workspace_id)
        .await
        .map_err(SemanticHttpFailure)?;
    for cat in &cats {
        cat.validate()
            .map_err(|error| internal_error(format!("service returned invalid Cat: {error}")))?;
    }
    Ok(success_response(StatusCode::OK, cats))
}

async fn get_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let cat = service
        .get_cat(&workspace_id, resource_slug(cat, "Cat")?)
        .await
        .map_err(SemanticHttpFailure)?;
    cat.validate()
        .map_err(|error| internal_error(format!("service returned invalid Cat: {error}")))?;
    Ok(success_response(StatusCode::OK, cat))
}

async fn list_disks(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let disks = service
        .list_disks(&workspace_id)
        .await
        .map_err(SemanticHttpFailure)?;
    for disk in &disks {
        disk.validate().map_err(|error| {
            internal_error(format!("service returned invalid PersistentDisk: {error}"))
        })?;
    }
    Ok(success_response(StatusCode::OK, disks))
}

async fn get_disk(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let disk = service
        .get_disk(&workspace_id, resource_slug(disk, "PersistentDisk")?)
        .await
        .map_err(SemanticHttpFailure)?;
    disk.validate().map_err(|error| {
        internal_error(format!("service returned invalid PersistentDisk: {error}"))
    })?;
    Ok(success_response(StatusCode::OK, disk))
}

async fn list_snapshots(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let snapshots = service
        .list_snapshots(&workspace_id)
        .await
        .map_err(SemanticHttpFailure)?;
    for snapshot in &snapshots {
        snapshot.validate().map_err(|error| {
            internal_error(format!("service returned invalid DiskSnapshot: {error}"))
        })?;
    }
    Ok(success_response(StatusCode::OK, snapshots))
}

async fn get_snapshot(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, snapshot)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let snapshot = service
        .get_snapshot(&workspace_id, resource_slug(snapshot, "DiskSnapshot")?)
        .await
        .map_err(SemanticHttpFailure)?;
    snapshot.validate().map_err(|error| {
        internal_error(format!("service returned invalid DiskSnapshot: {error}"))
    })?;
    Ok(success_response(StatusCode::OK, snapshot))
}

async fn create_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let request: CreateCatRequest = parse_json(request).await?;
    request
        .validate()
        .map_err(|error| invalid_request(error.to_string()))?;
    create_cat_after_auth(service.as_ref(), &workspace_id, request).await
}

async fn run_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    cat_action(state, service, workspace, cat, request, CatAction::Run).await
}

async fn suspend_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    cat_action(state, service, workspace, cat, request, CatAction::Suspend).await
}

async fn warm_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    cat_action(state, service, workspace, cat, request, CatAction::Warm).await
}

async fn cold_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    cat_action(state, service, workspace, cat, request, CatAction::Cold).await
}

async fn destroy_cat(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    cat_action(state, service, workspace, cat, request, CatAction::Destroy).await
}

async fn cat_action(
    state: AppState,
    service: Arc<dyn SemanticResourceApi>,
    workspace: String,
    cat: String,
    request: Request<Body>,
    action: CatAction,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let cat_slug = resource_slug(cat, "Cat")?;
    cat_action_after_auth(service.as_ref(), &workspace_id, cat_slug, action).await
}

async fn create_disk(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let request: CreateDiskRequest = parse_json(request).await?;
    request
        .validate()
        .map_err(|error| invalid_request(error.to_string()))?;
    create_disk_after_auth(service.as_ref(), &workspace_id, request).await
}

async fn attach_disk(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let disk_slug = resource_slug(disk, "PersistentDisk")?;
    let request: AttachDiskRequest = parse_json(request).await?;
    disk_response(
        service.attach_disk(&workspace_id, disk_slug, request).await,
        StatusCode::OK,
    )
}

async fn detach_disk(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let disk_slug = resource_slug(disk, "PersistentDisk")?;
    let request: DetachDiskRequest = parse_json(request).await?;
    disk_response(
        service.detach_disk(&workspace_id, disk_slug, request).await,
        StatusCode::OK,
    )
}

async fn destroy_disk(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    require_empty_body(request).await?;
    let disk_slug = resource_slug(disk, "PersistentDisk")?;
    disk_response(
        service.destroy_disk(&workspace_id, disk_slug).await,
        StatusCode::OK,
    )
}

async fn create_snapshot(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let request: CreateDiskSnapshotRequest = parse_json(request).await?;
    let result = service.create_snapshot(&workspace_id, request).await;
    let created = result
        .as_ref()
        .is_ok_and(|response| response.code == SemanticSuccessCode::SnapshotCreated);
    snapshot_response(
        result,
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
    )
}

async fn destroy_snapshot(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, snapshot)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let request: DestroyDiskSnapshotRequest = parse_json(request).await?;
    request
        .validate()
        .map_err(|error| invalid_request(error.to_string()))?;
    snapshot_response(
        service
            .destroy_snapshot(
                &workspace_id,
                resource_slug(snapshot, "DiskSnapshot")?,
                request,
            )
            .await,
        StatusCode::OK,
    )
}

async fn restore_snapshot(
    State(state): State<AppState>,
    Extension(service): Extension<Arc<dyn SemanticResourceApi>>,
    Path((workspace, snapshot)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SemanticHttpFailure> {
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_retired_headers(request.headers())?;
    reject_query(request.uri())?;
    let snapshot_slug = resource_slug(snapshot, "DiskSnapshot")?;
    let request: RestoreDiskSnapshotRequest = parse_json(request).await?;
    request
        .validate()
        .map_err(|error| invalid_request(error.to_string()))?;
    snapshot_response(
        service
            .restore_snapshot(&workspace_id, snapshot_slug, request)
            .await,
        StatusCode::OK,
    )
}

async fn create_cat_after_auth(
    service: &dyn SemanticResourceApi,
    workspace_id: &str,
    request: CreateCatRequest,
) -> Result<Response, SemanticHttpFailure> {
    let result = service.create_cat(workspace_id, request).await;
    let created = result
        .as_ref()
        .is_ok_and(|response| response.code == SemanticSuccessCode::CatCreated);
    cat_response(
        result,
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
    )
}

async fn cat_action_after_auth(
    service: &dyn SemanticResourceApi,
    workspace_id: &str,
    cat_slug: ResourceSlug,
    action: CatAction,
) -> Result<Response, SemanticHttpFailure> {
    cat_response(
        service.cat_action(workspace_id, cat_slug, action).await,
        StatusCode::OK,
    )
}

async fn create_disk_after_auth(
    service: &dyn SemanticResourceApi,
    workspace_id: &str,
    request: CreateDiskRequest,
) -> Result<Response, SemanticHttpFailure> {
    let result = service.create_disk(workspace_id, request).await;
    let created = result
        .as_ref()
        .is_ok_and(|response| response.code == SemanticSuccessCode::DiskCreated);
    disk_response(
        result,
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
    )
}

fn cat_response(
    result: Result<CatResponse, SemanticErrorBody>,
    status: StatusCode,
) -> Result<Response, SemanticHttpFailure> {
    let response = result.map_err(SemanticHttpFailure)?;
    response
        .cat
        .validate()
        .map_err(|error| internal_error(format!("service returned invalid Cat: {error}")))?;
    Ok(success_response(status, response))
}

fn disk_response(
    result: Result<DiskResponse, SemanticErrorBody>,
    status: StatusCode,
) -> Result<Response, SemanticHttpFailure> {
    let response = result.map_err(SemanticHttpFailure)?;
    response.disk.validate().map_err(|error| {
        internal_error(format!("service returned invalid PersistentDisk: {error}"))
    })?;
    Ok(success_response(status, response))
}

fn snapshot_response(
    result: Result<DiskSnapshotResponse, SemanticErrorBody>,
    status: StatusCode,
) -> Result<Response, SemanticHttpFailure> {
    let response = result.map_err(SemanticHttpFailure)?;
    response.validate().map_err(|error| {
        internal_error(format!("service returned invalid DiskSnapshot: {error}"))
    })?;
    Ok(success_response(status, response))
}

fn success_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn authenticated_workspace_id(
    state: &AppState,
    headers: &HeaderMap,
    workspace: &str,
) -> Result<String, SemanticHttpFailure> {
    check_workspace_auth(state, headers, workspace)
        .await
        .map(|scope| scope.workspace.id)
        .map_err(auth_failure)
}

fn auth_failure(Failure(error): Failure) -> SemanticHttpFailure {
    let code = match error.code {
        ErrorCode::Unauthenticated | ErrorCode::PermissionDenied | ErrorCode::NotFound => {
            SemanticErrorCode::Unauthorized
        }
        ErrorCode::InvalidArgument => SemanticErrorCode::InvalidRequest,
        ErrorCode::DeadlineExceeded => SemanticErrorCode::Timeout,
        ErrorCode::Unavailable => SemanticErrorCode::NodeUnavailable,
        _ => SemanticErrorCode::InternalError,
    };
    SemanticHttpFailure(SemanticErrorBody {
        code,
        message: error.message,
    })
}

fn reject_retired_headers(headers: &HeaderMap) -> Result<(), SemanticHttpFailure> {
    if headers.contains_key(IDEMPOTENCY_KEY) {
        return Err(invalid_request(
            "Idempotency-Key is not part of the semantic resource API",
        ));
    }
    Ok(())
}

fn reject_query(uri: &Uri) -> Result<(), SemanticHttpFailure> {
    if uri.query().is_some() {
        Err(invalid_request(
            "semantic resource mutation routes do not accept query parameters",
        ))
    } else {
        Ok(())
    }
}

async fn parse_json<T: DeserializeOwned>(request: Request<Body>) -> Result<T, SemanticHttpFailure> {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err(invalid_request("Content-Type must equal application/json"));
    }
    let body = to_bytes(request.into_body(), JSON_BODY_LIMIT)
        .await
        .map_err(|_| invalid_request("JSON request body exceeds 16384 bytes"))?;
    serde_json::from_slice(&body).map_err(|_| invalid_request("request body is malformed"))
}

async fn require_empty_body(request: Request<Body>) -> Result<(), SemanticHttpFailure> {
    if request.headers().contains_key(header::CONTENT_TYPE) {
        return Err(invalid_request(
            "this semantic action requires an empty body and no Content-Type",
        ));
    }
    let body = to_bytes(request.into_body(), 1)
        .await
        .map_err(|_| invalid_request("this semantic action requires an empty body"))?;
    if body.is_empty() {
        Ok(())
    } else {
        Err(invalid_request(
            "this semantic action requires an empty body",
        ))
    }
}

fn resource_slug(value: String, kind: &str) -> Result<ResourceSlug, SemanticHttpFailure> {
    ResourceSlug::new(value).ok_or_else(|| invalid_request(format!("{kind} slug is invalid")))
}

fn invalid_request(message: impl Into<String>) -> SemanticHttpFailure {
    SemanticHttpFailure(SemanticErrorBody {
        code: SemanticErrorCode::InvalidRequest,
        message: message.into(),
    })
}

fn internal_error(message: impl Into<String>) -> SemanticHttpFailure {
    SemanticHttpFailure(SemanticErrorBody {
        code: SemanticErrorCode::InternalError,
        message: message.into(),
    })
}

#[derive(Debug)]
struct SemanticHttpFailure(SemanticErrorBody);

impl IntoResponse for SemanticHttpFailure {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, Json(self.0)).into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::http::HeaderValue;
    use cats_api::runtime_reconciliation::Id;
    use cats_api::semantic_control::{
        CatView, DiskStatus, DiskView, NodeName, PersistentMountPath, SemanticStatus,
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        CreateCat(String, String),
        CatAction(String, String, CatAction),
        CreateDisk(String, String),
        Attach(String, String, String, String),
        Detach(String, String, String),
        DestroyDisk(String, String),
    }

    struct MockApi {
        calls: Mutex<Vec<Call>>,
    }

    impl MockApi {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl SemanticResourceApi for MockApi {
        fn list_cats<'a>(
            &'a self,
            _workspace_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Vec<CatView>, SemanticErrorBody>> {
            Box::pin(async {
                Ok(vec![
                    cat_response_fixture(
                        slug("web"),
                        SemanticStatus::Ok,
                        SemanticSuccessCode::CatCreated,
                    )
                    .cat,
                ])
            })
        }

        fn get_cat<'a>(
            &'a self,
            _workspace_id: &'a str,
            cat_slug: ResourceSlug,
        ) -> SemanticResourceFuture<'a, Result<CatView, SemanticErrorBody>> {
            Box::pin(async move {
                Ok(cat_response_fixture(
                    cat_slug,
                    SemanticStatus::Ok,
                    SemanticSuccessCode::CatCreated,
                )
                .cat)
            })
        }

        fn list_disks<'a>(
            &'a self,
            _workspace_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Vec<DiskView>, SemanticErrorBody>> {
            Box::pin(async {
                Ok(vec![
                    disk_response_fixture(
                        slug("data"),
                        SemanticStatus::Ok,
                        SemanticSuccessCode::DiskCreated,
                    )
                    .disk,
                ])
            })
        }

        fn get_disk<'a>(
            &'a self,
            _workspace_id: &'a str,
            disk_slug: ResourceSlug,
        ) -> SemanticResourceFuture<'a, Result<DiskView, SemanticErrorBody>> {
            Box::pin(async move {
                Ok(disk_response_fixture(
                    disk_slug,
                    SemanticStatus::Ok,
                    SemanticSuccessCode::DiskCreated,
                )
                .disk)
            })
        }

        fn create_cat<'a>(
            &'a self,
            workspace_id: &'a str,
            request: CreateCatRequest,
        ) -> SemanticResourceFuture<'a, Result<CatResponse, SemanticErrorBody>> {
            Box::pin(async move {
                self.calls.lock().expect("calls").push(Call::CreateCat(
                    workspace_id.to_owned(),
                    request.cat_slug.to_string(),
                ));
                Ok(cat_response_fixture(
                    request.cat_slug,
                    SemanticStatus::Ok,
                    SemanticSuccessCode::CatCreated,
                ))
            })
        }

        fn cat_action<'a>(
            &'a self,
            workspace_id: &'a str,
            cat_slug: ResourceSlug,
            action: CatAction,
        ) -> SemanticResourceFuture<'a, Result<CatResponse, SemanticErrorBody>> {
            Box::pin(async move {
                self.calls.lock().expect("calls").push(Call::CatAction(
                    workspace_id.to_owned(),
                    cat_slug.to_string(),
                    action,
                ));
                Ok(cat_response_fixture(
                    cat_slug,
                    SemanticStatus::AlreadyDone,
                    action_already_code(action),
                ))
            })
        }

        fn create_disk<'a>(
            &'a self,
            workspace_id: &'a str,
            request: CreateDiskRequest,
        ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>> {
            Box::pin(async move {
                self.calls.lock().expect("calls").push(Call::CreateDisk(
                    workspace_id.to_owned(),
                    request.disk_slug.to_string(),
                ));
                Ok(disk_response_fixture(
                    request.disk_slug,
                    SemanticStatus::Ok,
                    SemanticSuccessCode::DiskCreated,
                ))
            })
        }

        fn attach_disk<'a>(
            &'a self,
            workspace_id: &'a str,
            disk_slug: ResourceSlug,
            request: AttachDiskRequest,
        ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>> {
            Box::pin(async move {
                self.calls.lock().expect("calls").push(Call::Attach(
                    workspace_id.to_owned(),
                    disk_slug.to_string(),
                    request.cat_slug.to_string(),
                    request.mount_path.to_string(),
                ));
                Ok(disk_response_fixture(
                    disk_slug,
                    SemanticStatus::Ok,
                    SemanticSuccessCode::DiskAttached,
                ))
            })
        }

        fn detach_disk<'a>(
            &'a self,
            workspace_id: &'a str,
            disk_slug: ResourceSlug,
            request: DetachDiskRequest,
        ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>> {
            Box::pin(async move {
                self.calls.lock().expect("calls").push(Call::Detach(
                    workspace_id.to_owned(),
                    disk_slug.to_string(),
                    request.cat_slug.to_string(),
                ));
                Ok(disk_response_fixture(
                    disk_slug,
                    SemanticStatus::AlreadyDone,
                    SemanticSuccessCode::AlreadyDetached,
                ))
            })
        }

        fn destroy_disk<'a>(
            &'a self,
            workspace_id: &'a str,
            disk_slug: ResourceSlug,
        ) -> SemanticResourceFuture<'a, Result<DiskResponse, SemanticErrorBody>> {
            Box::pin(async move {
                self.calls.lock().expect("calls").push(Call::DestroyDisk(
                    workspace_id.to_owned(),
                    disk_slug.to_string(),
                ));
                Ok(disk_response_fixture(
                    disk_slug,
                    SemanticStatus::Ok,
                    SemanticSuccessCode::DiskDeleted,
                ))
            })
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).expect("ID")
    }

    fn slug(value: &str) -> ResourceSlug {
        ResourceSlug::new(value).expect("slug")
    }

    fn cat_response_fixture(
        cat_slug: ResourceSlug,
        status: SemanticStatus,
        code: SemanticSuccessCode,
    ) -> CatResponse {
        CatResponse {
            status,
            code,
            cat: CatView {
                cat_id: id("cat_01"),
                workspace_id: id("ws_01"),
                cat_slug,
                state: Some(cats_api::semantic_control::CatState::Running),
                current_action: None,
                node_id: Some(id("node_01")),
                node_name: Some(NodeName::new("node-one").expect("node name")),
                cpu: 2,
                memory_bytes: 1024,
                boot_image: "ubuntu".to_owned(),
                mounts: Vec::new(),
                last_error: None,
                created_at_unix_ms: 1,
                updated_at_unix_ms: 2,
                destroyed_at_unix_ms: None,
                current_action_started_at_unix_ms: None,
                last_running_at_unix_ms: Some(2),
            },
        }
    }

    fn disk_response_fixture(
        disk_slug: ResourceSlug,
        status: SemanticStatus,
        code: SemanticSuccessCode,
    ) -> DiskResponse {
        DiskResponse {
            status,
            code,
            disk: DiskView {
                disk_id: id("disk_01"),
                workspace_id: id("ws_01"),
                disk_slug,
                size_bytes: 1024,
                head_generation: None,
                status: DiskStatus::Normal,
                binding: None,
                created_at_unix_ms: 1,
                deleted_at_unix_ms: None,
            },
        }
    }

    fn action_already_code(action: CatAction) -> SemanticSuccessCode {
        match action {
            CatAction::Create => SemanticSuccessCode::AlreadyExists,
            CatAction::Run => SemanticSuccessCode::AlreadyRunning,
            CatAction::Suspend => SemanticSuccessCode::AlreadySuspended,
            CatAction::Warm => SemanticSuccessCode::AlreadyWarm,
            CatAction::Cold => SemanticSuccessCode::AlreadyCold,
            CatAction::Destroy => SemanticSuccessCode::AlreadyDestroyed,
        }
    }

    #[tokio::test]
    async fn authenticated_dispatch_uses_workspace_and_shared_dtos() {
        let api = MockApi::new();
        let create = CreateCatRequest {
            cat_slug: slug("web"),
            cpu: 2,
            memory_bytes: 1024,
            mounts: Vec::new(),
        };
        let response = create_cat_after_auth(&api, "ws_01", create)
            .await
            .expect("create Cat");
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = cat_action_after_auth(&api, "ws_01", slug("web"), CatAction::Warm)
            .await
            .expect("warm Cat");
        assert_eq!(response.status(), StatusCode::OK);

        let create = CreateDiskRequest {
            disk_slug: slug("data"),
            size_bytes: 1024,
        };
        let response = create_disk_after_auth(&api, "ws_01", create)
            .await
            .expect("create Disk");
        assert_eq!(response.status(), StatusCode::CREATED);

        assert_eq!(
            *api.calls.lock().expect("calls"),
            [
                Call::CreateCat("ws_01".to_owned(), "web".to_owned()),
                Call::CatAction("ws_01".to_owned(), "web".to_owned(), CatAction::Warm),
                Call::CreateDisk("ws_01".to_owned(), "data".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn disk_dispatch_carries_only_scenario_identity() {
        let api = MockApi::new();
        let attach = AttachDiskRequest {
            cat_slug: slug("web"),
            mount_path: PersistentMountPath::new("/data").expect("mount"),
        };
        disk_response(
            api.attach_disk("ws_01", slug("data"), attach).await,
            StatusCode::OK,
        )
        .expect("attach");
        let detach = DetachDiskRequest {
            cat_slug: slug("web"),
        };
        disk_response(
            api.detach_disk("ws_01", slug("data"), detach).await,
            StatusCode::OK,
        )
        .expect("detach");
        disk_response(
            api.destroy_disk("ws_01", slug("data")).await,
            StatusCode::OK,
        )
        .expect("destroy");

        assert_eq!(
            *api.calls.lock().expect("calls"),
            [
                Call::Attach(
                    "ws_01".to_owned(),
                    "data".to_owned(),
                    "web".to_owned(),
                    "/data".to_owned()
                ),
                Call::Detach("ws_01".to_owned(), "data".to_owned(), "web".to_owned()),
                Call::DestroyDisk("ws_01".to_owned(), "data".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn parser_rejects_retired_identity_fields_and_headers() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"cat_slug":"web","cpu":2,"memory_bytes":1024,"mounts":[],"request_id":"old"}"#,
            ))
            .expect("request");
        let error = parse_json::<CreateCatRequest>(request)
            .await
            .expect_err("request_id is not accepted");
        assert_eq!(error.0.code, SemanticErrorCode::InvalidRequest);

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"cat_slug":"web","cpu":2,"memory_bytes":1024,"mounts":[],"boot_image":"ubuntu"}"#,
            ))
            .expect("request");
        assert!(parse_json::<CreateCatRequest>(request).await.is_err());

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"disk_slug":"data","size_bytes":1024,"operation":"old"}"#,
            ))
            .expect("request");
        assert!(parse_json::<CreateDiskRequest>(request).await.is_err());

        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY, HeaderValue::from_static("old-key"));
        assert!(reject_retired_headers(&headers).is_err());
    }

    #[tokio::test]
    async fn semantic_failures_have_no_request_id_field() {
        let response = SemanticHttpFailure(SemanticErrorBody {
            code: SemanticErrorCode::Busy,
            message: "busy".to_owned(),
        })
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), 1024).await.expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("JSON"),
            serde_json::json!({"code":"busy","message":"busy"})
        );
    }

    #[test]
    fn route_fixture_has_only_documented_semantic_resources() {
        let _router: Router<AppState> = routes(Arc::new(MockApi::new()));
        let source = include_str!("semantic_resources.rs")
            .split_once("#[cfg(test)]")
            .expect("production boundary")
            .0;
        for (name, path) in [
            ("CATS_COLLECTION_PATH", CATS_COLLECTION_PATH),
            ("CAT_ITEM_PATH", CAT_ITEM_PATH),
            ("CAT_RUN_PATH", CAT_RUN_PATH),
            ("CAT_SUSPEND_PATH", CAT_SUSPEND_PATH),
            ("CAT_WARM_PATH", CAT_WARM_PATH),
            ("CAT_COLD_PATH", CAT_COLD_PATH),
            ("CAT_DESTROY_PATH", CAT_DESTROY_PATH),
            ("DISKS_COLLECTION_PATH", DISKS_COLLECTION_PATH),
            ("DISK_ITEM_PATH", DISK_ITEM_PATH),
            ("DISK_ATTACH_PATH", DISK_ATTACH_PATH),
            ("DISK_DETACH_PATH", DISK_DETACH_PATH),
            ("DISK_DESTROY_PATH", DISK_DESTROY_PATH),
        ] {
            assert!(source.contains(path), "path constant is missing: {path}");
            assert_eq!(
                source.matches(&format!(".route({name},")).count(),
                1,
                "route mismatch: {path}"
            );
        }
        for retired in ["Idempotency-Key", "request_id", "Operation"] {
            assert!(
                !source
                    .split_once("pub trait SemanticResourceApi")
                    .expect("service trait")
                    .1
                    .split_once("pub fn routes")
                    .expect("routes")
                    .0
                    .contains(retired),
                "retired protocol field leaked into service port: {retired}"
            );
        }
    }
}

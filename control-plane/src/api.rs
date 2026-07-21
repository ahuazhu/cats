//! Versioned HTTP API (arch doc §17). Mutations return `202 + Operation`;
//! `Idempotency-Key` retries replay the original operation; actions live
//! under `/actions/<verb>` (path-safe rendering of the `:verb` convention).

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::requests::*;
use cats_api::resources::*;

use crate::server::AppState;

pub struct Failure(pub ApiError);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ErrorBody {
            code: self.0.code,
            message: self.0.message,
            request_id: None,
        };
        (status, Json(body)).into_response()
    }
}

impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        Failure(e)
    }
}

type ApiResult<T> = std::result::Result<T, Failure>;

fn check_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == state.cfg.auth_token);
    if ok {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::Unauthenticated,
            "missing or invalid bearer token",
        )
        .into())
    }
}

fn idem_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn if_match(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"'))
        .and_then(|s| s.parse().ok())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/v1/projects/{project}/cats",
            post(create_cat).get(list_cats),
        )
        .route(
            "/v1/projects/{project}/cats/{cat}",
            get(get_cat).delete(delete_cat),
        )
        .route(
            "/v1/projects/{project}/cats/{cat}/actions/{verb}",
            post(cat_action),
        )
        .route("/v1/projects/{project}/cats/{cat}/exec", post(exec_cat))
        .route(
            "/v1/projects/{project}/cats/{cat}/endpoints",
            post(create_endpoint).get(list_endpoints),
        )
        .route(
            "/v1/projects/{project}/disks",
            post(create_disk).get(list_disks),
        )
        .route(
            "/v1/projects/{project}/disks/{disk}",
            get(get_disk).delete(delete_disk),
        )
        .route(
            "/v1/projects/{project}/disks/{disk}/actions/{verb}",
            post(disk_action),
        )
        .route(
            "/v1/projects/{project}/disks/{disk}/snapshots",
            post(create_snapshot).get(list_snapshots),
        )
        .route("/v1/operations/{id}", get(get_operation))
        .route("/v1/nodes/register", post(register_node))
        .route("/v1/nodes/heartbeat", post(heartbeat))
        .route("/v1/nodes/{id}/actions/cordon", post(cordon_node))
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/routes/resolve", get(resolve_route))
        .route("/v1/routes/wake", post(wake_route_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Cats
// ---------------------------------------------------------------------------

async fn create_cat(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateCatRequest>,
) -> ApiResult<Response> {
    check_auth(&state, &headers)?;
    if req.name.is_empty()
        || !req
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::invalid("cat name must be non-empty [a-z0-9-]").into());
    }
    let route = format!("POST /cats {project}/{}", req.name);
    if let Some(key) = idem_key(&headers) {
        if let Some(op_id) = state.store.idempotency_lookup(&key, &route)? {
            let op = state.store.get_operation(&op_id)?;
            let cat = state.store.must_get_cat_by_id(&op.resource_id)?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(CatOperationResponse { operation: op, cat }),
            )
                .into_response());
        }
    }
    let extra = req
        .disk
        .as_ref()
        .map(|d| (d.name.as_str(), d.size_bytes, d.mount_at.as_str()));
    let (cat, _disks, op) = state.store.create_cat(
        &project,
        &req.name,
        &req.image,
        req.cpus,
        req.memory_mib,
        req.root_size_bytes,
        extra,
    )?;
    if let Some(key) = idem_key(&headers) {
        state.store.idempotency_store(&key, &route, &op.id)?;
    }
    state.notify.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse { operation: op, cat }),
    )
        .into_response())
}

async fn list_cats(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Cat>>> {
    check_auth(&state, &headers)?;
    Ok(Json(ListResponse {
        items: state.store.list_cats(&project)?,
    }))
}

async fn get_cat(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Cat>> {
    check_auth(&state, &headers)?;
    Ok(Json(state.store.get_cat(&project, &cat)?))
}

async fn cat_action(
    State(state): State<AppState>,
    Path((project, cat, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_auth(&state, &headers)?;
    let cat = state.store.get_cat(&project, &cat)?;
    let desired = match verb.as_str() {
        "start" | "resume" => DesiredState::Running,
        "suspend" => DesiredState::Suspended,
        "warm" => DesiredState::Warm,
        "stop" => DesiredState::Cold,
        _ => return Err(ApiError::invalid(format!("unknown action {verb}")).into()),
    };
    let route = format!("POST /cats/{}/actions/{verb}", cat.id);
    if let Some(key) = idem_key(&headers) {
        if let Some(op_id) = state.store.idempotency_lookup(&key, &route)? {
            let op = state.store.get_operation(&op_id)?;
            let cat = state.store.must_get_cat_by_id(&cat.id)?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(CatOperationResponse { operation: op, cat }),
            )
                .into_response());
        }
    }
    let op =
        state
            .store
            .set_desired(&cat.id, desired, if_match(&headers), &format!("cat.{verb}"))?;
    if let Some(key) = idem_key(&headers) {
        state.store.idempotency_store(&key, &route, &op.id)?;
    }
    state.notify.notify_one();
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse { operation: op, cat }),
    )
        .into_response())
}

async fn delete_cat(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_auth(&state, &headers)?;
    let cat = state.store.get_cat(&project, &cat)?;
    let op = state.store.set_desired(
        &cat.id,
        DesiredState::Deleted,
        if_match(&headers),
        "cat.delete",
    )?;
    state.notify.notify_one();
    let cat_snapshot = state.store.must_get_cat_by_id(&cat.id)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse {
            operation: op,
            cat: cat_snapshot,
        }),
    )
        .into_response())
}

async fn exec_cat(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<ExecResponse>> {
    check_auth(&state, &headers)?;
    let cat = state.store.get_cat(&project, &cat)?;
    if req.command.is_empty() {
        return Err(ApiError::invalid("command must be a non-empty argv array").into());
    }
    // Shell/exec always wakes (arch doc §8.2).
    let cat = ensure_running(&state, cat).await?;
    let node = state
        .store
        .list_nodes()?
        .into_iter()
        .find(|n| Some(&n.id) == cat.node_id.as_ref())
        .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
    let url = format!(
        "{}/v1/cats/{}/exec",
        node.agent_url.trim_end_matches('/'),
        cat.id
    );
    let resp = state
        .controller
        .http
        .post(url)
        .bearer_auth(&state.cfg.auth_token)
        .json(&req)
        .send()
        .await
        .map_err(|e| ApiError::unavailable(format!("node agent unreachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::unavailable(format!("exec failed: {}", resp.status())).into());
    }
    let out: ExecResponse = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("bad exec response: {e}")))?;
    Ok(Json(out))
}

/// Wake a cat for exec/gateway traffic and wait until it reports Running.
pub async fn ensure_running(state: &AppState, cat: Cat) -> ApiResult<Cat> {
    if cat.observed_state == ObservedState::Running {
        return Ok(cat);
    }
    if cat.desired_state != DesiredState::Running {
        state
            .store
            .set_desired(&cat.id, DesiredState::Running, None, "cat.wake")?;
    }
    state.notify.notify_one();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let current = state.store.must_get_cat_by_id(&cat.id)?;
        match current.observed_state {
            ObservedState::Running => return Ok(current),
            ObservedState::Failed => {
                return Err(ApiError::unavailable("cat failed to start").into())
            }
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            return Err(ApiError::new(ErrorCode::DeadlineExceeded, "wake timed out").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// Disks
// ---------------------------------------------------------------------------

async fn create_disk(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateDiskRequest>,
) -> ApiResult<Json<Disk>> {
    check_auth(&state, &headers)?;
    if req.size_bytes == 0 || req.size_bytes > cats_api::chunk::MAX_VOLUME_BYTES {
        return Err(ApiError::invalid("disk size out of range").into());
    }
    let disk = state
        .store
        .create_disk(&project, &req.name, req.size_bytes)?;
    // Create the storage volume eagerly so snapshots/resize work pre-attach.
    let size = cats_api::chunk::round_up_to_chunk(req.size_bytes);
    match state.storage_meta.create_volume(&disk.volume_id, size) {
        Ok(()) | Err(cats_blockd::meta::MetaError::AlreadyExists(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    Ok(Json(disk))
}

async fn list_disks(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Disk>>> {
    check_auth(&state, &headers)?;
    Ok(Json(ListResponse {
        items: state.store.list_disks(&project)?,
    }))
}

async fn get_disk(
    State(state): State<AppState>,
    Path((project, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Disk>> {
    check_auth(&state, &headers)?;
    Ok(Json(state.store.get_disk(&project, &disk)?))
}

async fn delete_disk(
    State(state): State<AppState>,
    Path((project, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_auth(&state, &headers)?;
    let disk = state.store.get_disk(&project, &disk)?;
    if disk.kind == DiskKind::Root {
        return Err(ApiError::failed_precondition("root disks are deleted with their cat").into());
    }
    if disk.bound_cat_id.is_some() {
        return Err(ApiError::failed_precondition("disk must be Available (unmount first)").into());
    }
    match state.storage_meta.delete_volume(&disk.volume_id) {
        Ok(()) | Err(cats_blockd::meta::MetaError::NotFound(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    state.store.delete_disk_row(&disk.id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct DiskActionBody {
    #[serde(default)]
    cat_id: Option<String>,
    #[serde(default)]
    mount_at: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

async fn disk_action(
    State(state): State<AppState>,
    Path((project, disk, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<DiskActionBody>,
) -> ApiResult<Response> {
    check_auth(&state, &headers)?;
    let disk = state.store.get_disk(&project, &disk)?;
    match verb.as_str() {
        "mount" => {
            let cat_ref = body
                .cat_id
                .ok_or_else(|| ApiError::invalid("cat_id required"))?;
            let mount_at = body
                .mount_at
                .ok_or_else(|| ApiError::invalid("mount_at required"))?;
            let cat = state.store.get_cat(&project, &cat_ref)?;
            if disk.kind == DiskKind::Root {
                return Err(ApiError::failed_precondition("cannot mount a root disk").into());
            }
            let binding = state.store.bind_disk(&disk.id, &cat.id, &mount_at)?;
            // Hot attach when running; cold cats pick the disk up at start.
            if cat.observed_state == ObservedState::Running {
                if let Err(e) = hot_attach(&state, &cat, &disk, &binding.mount_path).await {
                    state.store.unbind_disk(&disk.id)?;
                    return Err(e);
                }
            }
            Ok(Json(binding).into_response())
        }
        "unmount" => {
            let Some(bound_cat) = disk.bound_cat_id.clone() else {
                return Err(ApiError::failed_precondition("disk is not mounted").into());
            };
            let cat = state.store.must_get_cat_by_id(&bound_cat)?;
            if cat.observed_state == ObservedState::Running {
                hot_detach(&state, &cat, &disk).await?;
            }
            match state.storage_meta.revoke_lease(&disk.volume_id) {
                Ok(()) | Err(cats_blockd::meta::MetaError::NotFound(_)) => {}
                Err(e) => return Err(ApiError::internal(e.to_string()).into()),
            }
            state.store.unbind_disk(&disk.id)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        "resize" => {
            let new_size = body
                .size_bytes
                .ok_or_else(|| ApiError::invalid("size_bytes required"))?;
            if disk.bound_cat_id.is_some() {
                return Err(ApiError::failed_precondition(
                    "v1 resize requires the disk to be Available",
                )
                .into());
            }
            if new_size < disk.size_bytes {
                return Err(ApiError::invalid("shrink is not supported").into());
            }
            let rounded = cats_api::chunk::round_up_to_chunk(new_size);
            state
                .storage_meta
                .resize_volume(&disk.volume_id, rounded)
                .map_err(|e| ApiError::failed_precondition(e.to_string()))?;
            state.store.set_disk_size(&disk.id, new_size)?;
            Ok(Json(state.store.get_disk(&project, &disk.id)?).into_response())
        }
        _ => Err(ApiError::invalid(format!("unknown disk action {verb}")).into()),
    }
}

async fn hot_attach(state: &AppState, cat: &Cat, disk: &Disk, mount_path: &str) -> ApiResult<()> {
    let node = state
        .store
        .list_nodes()?
        .into_iter()
        .find(|n| Some(&n.id) == cat.node_id.as_ref())
        .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
    let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
    match state.storage_meta.create_volume(&disk.volume_id, size) {
        Ok(()) | Err(cats_blockd::meta::MetaError::AlreadyExists(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    let job = cats_api::nodejob::NodeJob {
        job_id: cats_api::nodejob::job_id(&cat.id, cat.generation, &format!("attach_{}", disk.id)),
        cat_generation: cat.generation,
        action: cats_api::nodejob::NodeJobAction::AttachDisk {
            cat_id: cat.id.clone(),
            volume: cats_api::nodejob::VolumeGrant {
                disk_id: disk.id.clone(),
                volume_id: disk.volume_id.clone(),
                attachment_id: format!("att_{}_{}_{}", cat.id, disk.id, cat.generation),
                epoch: 0,
                size_bytes: size,
                mount_path: mount_path.to_string(),
            },
        },
    };
    dispatch_or_unavailable(state, &node.agent_url, &job).await
}

async fn hot_detach(state: &AppState, cat: &Cat, disk: &Disk) -> ApiResult<()> {
    let node = state
        .store
        .list_nodes()?
        .into_iter()
        .find(|n| Some(&n.id) == cat.node_id.as_ref())
        .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
    let job = cats_api::nodejob::NodeJob {
        job_id: cats_api::nodejob::job_id(&cat.id, cat.generation, &format!("detach_{}", disk.id)),
        cat_generation: cat.generation,
        action: cats_api::nodejob::NodeJobAction::DetachDisk {
            cat_id: cat.id.clone(),
            disk_id: disk.id.clone(),
        },
    };
    dispatch_or_unavailable(state, &node.agent_url, &job).await
}

async fn dispatch_or_unavailable(
    state: &AppState,
    agent_url: &str,
    job: &cats_api::nodejob::NodeJob,
) -> ApiResult<()> {
    let resp = state
        .controller
        .http
        .post(format!("{}/v1/jobs", agent_url.trim_end_matches('/')))
        .bearer_auth(&state.cfg.auth_token)
        .json(job)
        .send()
        .await
        .map_err(|e| ApiError::unavailable(format!("node agent unreachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::unavailable(format!("node agent returned {}", resp.status())).into());
    }
    let result: cats_api::nodejob::NodeJobResult = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if result.phase != cats_api::nodejob::JobPhase::Succeeded {
        return Err(
            ApiError::unavailable(result.error.unwrap_or_else(|| "job failed".into())).into(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

async fn create_snapshot(
    State(state): State<AppState>,
    Path((project, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Snapshot>> {
    check_auth(&state, &headers)?;
    let disk = state.store.get_disk(&project, &disk)?;
    let snap_id = crate::store::new_id(cats_api::ids::SNAPSHOT_PREFIX);
    let row = state
        .storage_meta
        .create_snapshot(&snap_id, &disk.volume_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(Snapshot {
        id: row.snapshot_id,
        disk_id: disk.id,
        generation: row.generation,
        root_hash_hex: row.root_hash.map(hex_lower).unwrap_or_default(),
        created_at_unix: crate::store::now_unix(),
    }))
}

fn hex_lower(h: [u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

async fn list_snapshots(
    State(state): State<AppState>,
    Path((project, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Snapshot>>> {
    check_auth(&state, &headers)?;
    let disk = state.store.get_disk(&project, &disk)?;
    let rows = state
        .storage_meta
        .list_snapshots(&disk.volume_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(ListResponse {
        items: rows
            .into_iter()
            .map(|r| Snapshot {
                id: r.snapshot_id,
                disk_id: disk.id.clone(),
                generation: r.generation,
                root_hash_hex: r.root_hash.map(hex_lower).unwrap_or_default(),
                created_at_unix: 0,
            })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Endpoints / routes
// ---------------------------------------------------------------------------

async fn create_endpoint(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<CreateEndpointRequest>,
) -> ApiResult<Json<EndpointResponse>> {
    check_auth(&state, &headers)?;
    let cat = state.store.get_cat(&project, &cat)?;
    let ep = state.store.create_endpoint(
        &cat,
        &req.name,
        req.target_port,
        &req.protocol,
        req.wake_policy,
    )?;
    // If the cat is already running, bind the route immediately.
    if let (ObservedState::Running, Some(node_id)) = (cat.observed_state, &cat.node_id) {
        if let Some(node) = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| &n.id == node_id)
        {
            state
                .store
                .publish_routes(&cat.id, &node.id, &node.gateway_url)?;
        }
    }
    Ok(Json(EndpointResponse { endpoint: ep }))
}

async fn list_endpoints(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Endpoint>>> {
    check_auth(&state, &headers)?;
    let cat = state.store.get_cat(&project, &cat)?;
    Ok(Json(ListResponse {
        items: state.store.endpoints_for_cat(&cat.id)?,
    }))
}

#[derive(serde::Deserialize)]
pub(crate) struct ResolveQuery {
    hostname: String,
}

#[derive(serde::Serialize)]
struct ResolveResponse {
    binding: RouteBinding,
    state: String,
    observed_state: ObservedState,
    node_agent_url: String,
}

async fn resolve_route(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<ResolveResponse>> {
    check_auth(&state, &headers)?;
    let (binding, route_state) = state.store.resolve_route(&q.hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    let node_agent_url = state
        .store
        .list_nodes()?
        .into_iter()
        .find(|n| n.id == binding.node_id)
        .map(|n| n.agent_url)
        .unwrap_or_default();
    Ok(Json(ResolveResponse {
        binding,
        state: route_state,
        observed_state: cat.observed_state,
        node_agent_url,
    }))
}

/// Gateway wake entry: waits until the cat backing `hostname` is running.
async fn wake_route(state: &AppState, hostname: &str) -> ApiResult<()> {
    let (binding, _) = state.store.resolve_route(hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    if binding.wake_policy == WakePolicy::NoWake && cat.observed_state != ObservedState::Running {
        return Err(ApiError::unavailable("endpoint does not wake on request").into());
    }
    ensure_running(state, cat).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterNodeRequest>,
) -> ApiResult<StatusCode> {
    check_auth(&state, &headers)?;
    state.store.register_node(
        &req.node_id,
        &req.agent_url,
        &req.gateway_url,
        req.cpus,
        req.memory_mib,
    )?;
    state.notify.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<StatusCode> {
    check_auth(&state, &headers)?;
    state.store.heartbeat_node(&req.node_id)?;
    // Drift detection: trust node reports for steady states at the same
    // generation; the reconciler drives any resulting divergence.
    for hb in &req.cats {
        if let Ok(cat) = state.store.must_get_cat_by_id(&hb.cat_id) {
            if cat.generation == hb.generation
                && cat.node_id.as_deref() == Some(req.node_id.as_str())
                && cat.observed_state != hb.state
                && matches!(
                    cat.observed_state,
                    ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
                )
            {
                state.store.set_observed(&cat.id, hb.state)?;
                state.notify.notify_one();
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn cordon_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_auth(&state, &headers)?;
    state.store.set_node_state(&id, NodeState::Cordoned)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Node>>> {
    check_auth(&state, &headers)?;
    Ok(Json(ListResponse {
        items: state.store.list_nodes()?,
    }))
}

/// Wake handler used by the gateway (`POST /v1/routes/wake?hostname=`).
async fn wake_route_handler(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_auth(&state, &headers)?;
    wake_route(&state, &q.hostname).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_operation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Operation>> {
    check_auth(&state, &headers)?;
    Ok(Json(state.store.get_operation(&id)?))
}

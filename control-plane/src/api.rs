//! Versioned HTTP API (arch doc §17). Mutations return `202 + Operation`;
//! `Idempotency-Key` retries replay the original operation; actions live
//! under `/actions/<verb>` (path-safe rendering of the `:verb` convention).

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

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
        let mut response = (status, Json(body)).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        Failure(e)
    }
}

type ApiResult<T> = std::result::Result<T, Failure>;

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

#[derive(Debug, Clone)]
enum Principal {
    Service,
    Administrator,
    User(crate::auth::AccessIdentity),
}

async fn bearer_principal(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<Principal>> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    if token == state.cfg.auth_token {
        return Ok(Some(Principal::Service));
    }
    if token == state.cfg.admin_token {
        return Ok(Some(Principal::Administrator));
    }
    let workos =
        state.cfg.workos.as_ref().ok_or_else(|| {
            ApiError::unauthenticated("missing or invalid authentication credential")
        })?;
    Ok(Some(Principal::User(
        workos.verify_access_token(token).await?,
    )))
}

fn auth_failure(authenticated: bool) -> Failure {
    if authenticated {
        ApiError::new(
            ErrorCode::PermissionDenied,
            "authentication credential is not allowed for this resource",
        )
        .into()
    } else {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "missing or invalid authentication credential",
        )
        .into()
    }
}

async fn check_authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if bearer_principal(state, headers).await?.is_some()
        || crate::auth::has_any_web_session(state, headers)
    {
        return Ok(());
    }
    Err(auth_failure(false))
}

async fn check_project_auth(state: &AppState, headers: &HeaderMap, project: &str) -> ApiResult<()> {
    let principal = bearer_principal(state, headers).await?;
    let bearer_allowed = match &principal {
        Some(Principal::Administrator) => true,
        Some(Principal::User(identity)) => identity.project.as_deref() == Some(project),
        Some(Principal::Service) | None => false,
    };
    if bearer_allowed || crate::auth::web_session_allows_project(state, headers, project) {
        return Ok(());
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers),
    ))
}

async fn check_admin_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let principal = bearer_principal(state, headers).await?;
    let bearer_allowed = match &principal {
        Some(Principal::Administrator) => true,
        Some(Principal::User(identity)) => state
            .cfg
            .workos
            .as_ref()
            .is_some_and(|workos| workos.is_fleet_administrator(identity)),
        Some(Principal::Service) | None => false,
    };
    if bearer_allowed || crate::auth::web_session_is_admin(state, headers) {
        return Ok(());
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers),
    ))
}

async fn check_service_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let principal = bearer_principal(state, headers).await?;
    if matches!(
        principal,
        Some(Principal::Service | Principal::Administrator)
    ) {
        return Ok(());
    }
    Err(auth_failure(principal.is_some()))
}

async fn require_cli_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<crate::auth::AccessIdentity> {
    match bearer_principal(state, headers).await? {
        Some(Principal::User(identity)) => Ok(identity),
        Some(_) => Err(auth_failure(true)),
        None => Err(auth_failure(false)),
    }
}

fn cordon_registered_node(state: &AppState, id: &str) -> ApiResult<()> {
    let node = state.store.get_node(id)?;
    if node.state == NodeState::Draining && !state.store.cats_on_node(id)?.is_empty() {
        return Err(ApiError::failed_precondition(
            "node drain is still in progress; use uncordon to cancel it",
        )
        .into());
    }
    state.store.set_node_state(id, NodeState::Cordoned)?;
    Ok(())
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
        .route("/", get(crate::ui::portal))
        .route("/zh-CN", get(crate::ui::zh_home_redirect))
        .route("/zh-CN/", get(crate::ui::zh_home))
        .route("/docs", get(crate::ui::docs_redirect))
        .route("/docs/", get(crate::ui::docs_index))
        .route("/docs/{slug}", get(crate::ui::docs_detail_redirect))
        .route("/docs/{slug}/", get(crate::ui::docs_detail))
        .route("/zh-CN/docs", get(crate::ui::zh_docs_redirect))
        .route("/zh-CN/docs/", get(crate::ui::zh_docs_index))
        .route(
            "/zh-CN/docs/{slug}",
            get(crate::ui::zh_docs_detail_redirect),
        )
        .route("/zh-CN/docs/{slug}/", get(crate::ui::zh_docs_detail))
        .route("/robots.txt", get(crate::ui::robots))
        .route("/sitemap.xml", get(crate::ui::sitemap))
        .route("/site.webmanifest", get(crate::ui::web_manifest))
        .route("/assets/public.css", get(crate::ui::public_styles))
        .route("/assets/cats-mark.svg", get(crate::ui::cats_mark))
        .route("/assets/cats-logo.svg", get(crate::ui::cats_logo))
        .route("/assets/cats-og.svg", get(crate::ui::cats_og))
        .route("/assets/cats-og.png", get(crate::ui::cats_og_png))
        .route("/user", get(crate::ui::user_console))
        .route("/user/", get(crate::ui::user_console))
        .route("/admin", get(crate::ui::admin_console))
        .route("/admin/", get(crate::ui::admin_console))
        .route("/ui/styles.css", get(crate::ui::styles))
        .route("/ui/i18n.js", get(crate::ui::i18n_script))
        .route("/ui/common.js", get(crate::ui::common_script))
        .route("/ui/user.js", get(crate::ui::user_script))
        .route("/ui/admin.js", get(crate::ui::admin_script))
        .route("/auth/config", get(crate::auth::config))
        .route("/auth/login", get(crate::auth::login))
        .route("/auth/callback", get(crate::auth::callback))
        .route("/auth/session", get(crate::auth::session))
        .route("/auth/logout", get(crate::auth::logout))
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/me", get(cli_me))
        .route("/v1/workspaces", get(list_workspaces))
        .route("/v1/auth/logout", post(cli_logout))
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
        .route("/v1/projects/{project}/cats/{cat}/shell", get(shell_cat))
        .route(
            "/v1/projects/{project}/cats/{cat}/auto-suspend",
            get(get_auto_suspend).put(update_auto_suspend),
        )
        .route("/v1/projects/{project}/cats/{cat}/work", get(get_cat_work))
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
        .route("/v1/projects/{project}/operations", get(list_operations))
        .route("/v1/nodes/register", post(register_node))
        .route("/v1/nodes/heartbeat", post(heartbeat))
        .route("/v1/nodes/work-status", post(node_work_status))
        .route("/v1/internal/work/acquire", post(acquire_work))
        .route("/v1/internal/work/release", post(release_work))
        .route("/v1/nodes/{id}/actions/cordon", post(cordon_node))
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/admin/nodes", get(admin_list_nodes))
        .route(
            "/v1/admin/nodes/{id}",
            get(admin_get_node).delete(admin_delete_node),
        )
        .route(
            "/v1/admin/nodes/{id}/actions/{verb}",
            post(admin_node_action),
        )
        .route("/v1/admin/monitoring", get(admin_monitoring))
        .route("/metrics", get(prometheus_metrics))
        .route("/v1/routes/resolve", get(resolve_route))
        .route("/v1/routes/wake", post(wake_route_handler))
        .fallback(crate::ui::not_found)
        .with_state(state)
}

async fn cli_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<cats_api::auth::MeResponse>> {
    let identity = require_cli_identity(&state, &headers).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    Ok(Json(workos.me(&identity).await?))
}

async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    let identity = require_cli_identity(&state, &headers).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    Ok(Json(ListResponse {
        items: workos.workspaces_for(&identity).await?,
    }))
}

async fn cli_logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let identity = require_cli_identity(&state, &headers).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    workos.revoke_cli_session(&identity).await?;
    Ok(StatusCode::NO_CONTENT)
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
    check_project_auth(&state, &headers, &project).await?;
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
        req.auto_suspend,
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
    check_project_auth(&state, &headers, &project).await?;
    Ok(Json(ListResponse {
        items: state.store.list_cats(&project)?,
    }))
}

async fn get_cat(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Cat>> {
    check_project_auth(&state, &headers, &project).await?;
    Ok(Json(state.store.get_cat(&project, &cat)?))
}

async fn cat_action(
    State(state): State<AppState>,
    Path((project, cat, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_project_auth(&state, &headers, &project).await?;
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
    check_project_auth(&state, &headers, &project).await?;
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
    check_project_auth(&state, &headers, &project).await?;
    let cat = state.store.get_cat(&project, &cat)?;
    if req.command.is_empty() {
        return Err(ApiError::invalid("command must be a non-empty argv array").into());
    }
    let owner = format!("exec_{}", uuid::Uuid::new_v4().simple());
    let cat_id = cat.id.clone();
    let ttl_ms = req.timeout_ms.unwrap_or(120_000).clamp(1_000, 3_600_000);
    let lease = state
        .store
        .acquire_work(&cat.id, WorkKind::Exec, &owner, "exec", ttl_ms)?;
    let result: ApiResult<ExecResponse> = async {
        let mut cat = cat;
        let mut retried_suspend_conflict = false;
        loop {
            // Shell/exec always wakes (arch doc §8.2). An exec that reaches
            // the node while its suspend gate is closing gets a transient
            // 409 and cancels that suspend. Wait for the control plane to
            // observe Running again, then retry the exec once.
            cat = ensure_running(&state, cat).await?;
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
            let status = resp.status();
            if status.is_success() {
                break resp
                    .json::<ExecResponse>()
                    .await
                    .map_err(|e| ApiError::internal(format!("bad exec response: {e}")).into());
            }
            if status == StatusCode::CONFLICT && !retried_suspend_conflict {
                retried_suspend_conflict = true;
                continue;
            }
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            let message = if detail.is_empty() {
                format!("exec failed: {status}")
            } else {
                format!("exec failed: {detail}")
            };
            break Err(ApiError::unavailable(message).into());
        }
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result.map(Json)
}

#[derive(Debug, Deserialize)]
struct ShellQuery {
    #[serde(default = "default_terminal_rows")]
    rows: u16,
    #[serde(default = "default_terminal_cols")]
    cols: u16,
}

fn default_terminal_rows() -> u16 {
    24
}

fn default_terminal_cols() -> u16 {
    80
}

async fn shell_cat(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    Query(query): Query<ShellQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    check_project_auth(&state, &headers, &project).await?;
    if !(1..=1_000).contains(&query.rows) || !(1..=1_000).contains(&query.cols) {
        return Err(ApiError::invalid("terminal dimensions must be in 1..=1000").into());
    }
    let cat = state.store.get_cat(&project, &cat)?;
    let owner = format!("shell_{}", uuid::Uuid::new_v4().simple());
    let lease = state
        .store
        .acquire_work(&cat.id, WorkKind::Exec, &owner, "shell", 120_000)?;
    state.notify.notify_one();
    let cat_id = cat.id.clone();

    let prepared = prepare_node_shell(&state, cat, query.rows, query.cols).await;
    let node_socket = match prepared {
        Ok(socket) => socket,
        Err(error) => {
            let _ = state.store.release_work(&lease.id);
            let _ = state.controller.maybe_auto_suspend(&cat_id);
            return Err(error);
        }
    };
    let cleanup_state = state.clone();
    Ok(ws
        .max_message_size(MAX_SHELL_MESSAGE_BYTES)
        .max_frame_size(MAX_SHELL_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            proxy_shell(
                socket,
                node_socket,
                cleanup_state.clone(),
                cat_id.clone(),
                owner,
            )
            .await;
            let _ = cleanup_state.store.release_work(&lease.id);
            let _ = cleanup_state.controller.maybe_auto_suspend(&cat_id);
        }))
}

async fn prepare_node_shell(
    state: &AppState,
    mut cat: Cat,
    rows: u16,
    cols: u16,
) -> ApiResult<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut retried_suspend_conflict = false;
    loop {
        cat = ensure_running(state, cat).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|node| Some(&node.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
        let mut url = reqwest::Url::parse(node.agent_url.trim_end_matches('/'))
            .map_err(|error| ApiError::internal(format!("invalid node agent URL: {error}")))?;
        url.set_scheme(match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => return Err(ApiError::internal("node agent URL must use http or https").into()),
        })
        .map_err(|_| ApiError::internal("invalid node WebSocket URL"))?;
        url.set_path(&format!("/v1/cats/{}/shell", cat.id));
        url.set_query(Some(&format!("rows={rows}&cols={cols}")));
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|error| ApiError::internal(format!("build node shell request: {error}")))?;
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", state.cfg.auth_token))
                .map_err(|_| ApiError::internal("invalid service authorization header"))?,
        );
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => return Ok(socket),
            Err(tokio_tungstenite::tungstenite::Error::Http(response))
                if response.status() == StatusCode::CONFLICT && !retried_suspend_conflict =>
            {
                retried_suspend_conflict = true;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => {
                return Err(
                    ApiError::unavailable(format!("node shell connection failed: {error}")).into(),
                )
            }
        }
    }
}

async fn proxy_shell(
    client: WebSocket,
    node: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    state: AppState,
    cat_id: String,
    owner: String,
) {
    let (mut client_sender, mut client_receiver) = client.split();
    let (mut node_sender, mut node_receiver) = node.split();
    let mut renewal = tokio::time::interval(Duration::from_secs(30));
    renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renewal.tick().await;

    loop {
        tokio::select! {
            incoming = client_receiver.next() => {
                let Some(Ok(message)) = incoming else { break };
                let message = match message {
                    Message::Text(text) => {
                        tokio_tungstenite::tungstenite::Message::Text(text.to_string().into())
                    }
                    Message::Binary(data) => tokio_tungstenite::tungstenite::Message::Binary(data),
                    Message::Ping(data) => tokio_tungstenite::tungstenite::Message::Ping(data),
                    Message::Pong(data) => tokio_tungstenite::tungstenite::Message::Pong(data),
                    Message::Close(_) => tokio_tungstenite::tungstenite::Message::Close(None),
                };
                if node_sender.send(message).await.is_err() {
                    break;
                }
            }
            outgoing = node_receiver.next() => {
                let Some(Ok(message)) = outgoing else { break };
                let message = match message {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        Message::Text(text.to_string().into())
                    }
                    tokio_tungstenite::tungstenite::Message::Binary(data) => Message::Binary(data),
                    tokio_tungstenite::tungstenite::Message::Ping(data) => Message::Ping(data),
                    tokio_tungstenite::tungstenite::Message::Pong(data) => Message::Pong(data),
                    tokio_tungstenite::tungstenite::Message::Close(_) => Message::Close(None),
                    tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
                };
                if client_sender.send(message).await.is_err() {
                    break;
                }
            }
            _ = renewal.tick() => {
                if let Err(error) = state.store.acquire_work(
                    &cat_id,
                    WorkKind::Exec,
                    &owner,
                    "shell",
                    120_000,
                ) {
                    tracing::warn!(cat_id, error = %error, "shell work lease renewal failed");
                    break;
                }
            }
        }
    }
    let _ = node_sender
        .send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await;
}

async fn get_auto_suspend(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AutoSuspendResponse>> {
    check_project_auth(&state, &headers, &project).await?;
    let cat = state.store.get_cat(&project, &cat)?;
    let work = state
        .store
        .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?;
    Ok(Json(AutoSuspendResponse { cat, work }))
}

async fn update_auto_suspend(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateAutoSuspendRequest>,
) -> ApiResult<Json<AutoSuspendResponse>> {
    check_project_auth(&state, &headers, &project).await?;
    let cat = state.store.get_cat(&project, &cat)?;
    let cat = state.store.set_auto_suspend(&cat.id, request.enabled)?;
    if request.enabled {
        state.controller.maybe_auto_suspend(&cat.id)?;
    }
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    let work = state
        .store
        .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?;
    Ok(Json(AutoSuspendResponse { cat, work }))
}

async fn get_cat_work(
    State(state): State<AppState>,
    Path((project, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<CatWorkStatus>> {
    check_project_auth(&state, &headers, &project).await?;
    let cat = state.store.get_cat(&project, &cat)?;
    Ok(Json(
        state
            .store
            .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?,
    ))
}

/// Wake a cat for exec/gateway traffic and wait until it reports Running.
pub async fn ensure_running(state: &AppState, cat: Cat) -> ApiResult<Cat> {
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    if cat.desired_state == DesiredState::Running && cat.observed_state == ObservedState::Running {
        return Ok(cat);
    }
    state.store.ensure_desired_running(&cat.id)?;
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
    check_project_auth(&state, &headers, &project).await?;
    if req.size_bytes == 0 || req.size_bytes > cats_api::chunk::MAX_VOLUME_BYTES {
        return Err(ApiError::invalid("disk size out of range").into());
    }
    let disk = state
        .store
        .create_disk(&project, &req.name, req.size_bytes)?;
    // Create the storage volume eagerly so snapshots/resize work pre-attach.
    let size = cats_api::chunk::round_up_to_chunk(req.size_bytes);
    match state.storage_meta.create_volume(&disk.volume_id, size) {
        Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    Ok(Json(disk))
}

async fn list_disks(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Disk>>> {
    check_project_auth(&state, &headers, &project).await?;
    Ok(Json(ListResponse {
        items: state.store.list_disks(&project)?,
    }))
}

async fn get_disk(
    State(state): State<AppState>,
    Path((project, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Disk>> {
    check_project_auth(&state, &headers, &project).await?;
    Ok(Json(state.store.get_disk(&project, &disk)?))
}

async fn delete_disk(
    State(state): State<AppState>,
    Path((project, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_project_auth(&state, &headers, &project).await?;
    let disk = state.store.get_disk(&project, &disk)?;
    if disk.kind == DiskKind::Root {
        return Err(ApiError::failed_precondition("root disks are deleted with their cat").into());
    }
    if disk.bound_cat_id.is_some() {
        return Err(ApiError::failed_precondition("disk must be Available (unmount first)").into());
    }
    match state.storage_meta.delete_volume(&disk.volume_id) {
        Ok(()) | Err(cats_storage::MetaError::NotFound(_)) => {}
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
    check_project_auth(&state, &headers, &project).await?;
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
                Ok(()) | Err(cats_storage::MetaError::NotFound(_)) => {}
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
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "disk_attach", 120_000)?;
    let cat_id = cat.id.clone();
    let result = async {
        let cat = ensure_running(state, cat.clone()).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
        match state.storage_meta.create_volume(&disk.volume_id, size) {
            Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
            Err(e) => return Err(ApiError::internal(e.to_string()).into()),
        }
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("attach_{}", disk.id),
            ),
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
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result
}

async fn hot_detach(state: &AppState, cat: &Cat, disk: &Disk) -> ApiResult<()> {
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "disk_detach", 120_000)?;
    let cat_id = cat.id.clone();
    let result = async {
        let cat = ensure_running(state, cat.clone()).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("detach_{}", disk.id),
            ),
            cat_generation: cat.generation,
            action: cats_api::nodejob::NodeJobAction::DetachDisk {
                cat_id: cat.id.clone(),
                disk_id: disk.id.clone(),
            },
        };
        dispatch_or_unavailable(state, &node.agent_url, &job).await
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result
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
    check_project_auth(&state, &headers, &project).await?;
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
    check_project_auth(&state, &headers, &project).await?;
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
    check_project_auth(&state, &headers, &project).await?;
    if req.name.is_empty()
        || req.name.len() > 24
        || !req
            .name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        || req.name.starts_with('-')
        || req.name.ends_with('-')
    {
        return Err(
            ApiError::invalid("endpoint name must be 1-24 lowercase [a-z0-9-] characters").into(),
        );
    }
    if req.target_port == 0 {
        return Err(ApiError::invalid("endpoint target_port must be non-zero").into());
    }
    if req.protocol != "http" {
        return Err(ApiError::invalid("only http endpoints are currently supported").into());
    }
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
    check_project_auth(&state, &headers, &project).await?;
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
    check_service_auth(&state, &headers).await?;
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
    check_service_auth(&state, &headers).await?;
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
    check_service_auth(&state, &headers).await?;
    state
        .store
        .heartbeat_node(&req.node_id, req.telemetry.as_ref())?;
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

async fn node_work_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NodeWorkStatusRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    let should_wake = state.store.ingest_guest_work(&request)?;
    if should_wake {
        state.notify.notify_one();
    } else {
        state.controller.maybe_auto_suspend(&request.cat_id)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn acquire_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AcquireWorkRequest>,
) -> ApiResult<Json<AcquireWorkResponse>> {
    check_service_auth(&state, &headers).await?;
    if request.kind == WorkKind::Guest {
        return Err(ApiError::invalid("guest work must come through the owning node").into());
    }
    let lease = state.store.acquire_work(
        &request.cat_id,
        request.kind,
        &request.owner_id,
        &request.label,
        request.ttl_ms,
    )?;
    Ok(Json(AcquireWorkResponse { lease }))
}

async fn release_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReleaseWorkRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    if let Some(cat_id) = state.store.release_work(&request.lease_id)? {
        state.controller.maybe_auto_suspend(&cat_id)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn cordon_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    cordon_registered_node(&state, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Node>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_nodes()?,
    }))
}

async fn admin_list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeSummary>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_node_summaries()?,
    }))
}

async fn admin_get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<NodeSummary>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(state.store.node_summary(&id)?))
}

async fn admin_node_action(
    State(state): State<AppState>,
    Path((id, verb)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let node = state.store.get_node(&id)?;
    let status = match verb.as_str() {
        "cordon" => {
            cordon_registered_node(&state, &id)?;
            StatusCode::OK
        }
        "uncordon" => {
            if node.state == NodeState::Lost {
                return Err(ApiError::failed_precondition(
                    "lost node must heartbeat or register before uncordon",
                )
                .into());
            }
            state.store.set_node_state(&id, NodeState::Ready)?;
            state.notify.notify_one();
            StatusCode::OK
        }
        "drain" => {
            if node.state == NodeState::Lost {
                return Err(ApiError::failed_precondition(
                    "lost nodes are fenced automatically and cannot be drained",
                )
                .into());
            }
            state.store.set_node_state(&id, NodeState::Draining)?;
            state.notify.notify_one();
            StatusCode::ACCEPTED
        }
        _ => return Err(ApiError::invalid(format!("unknown node action {verb}")).into()),
    };
    Ok((status, Json(state.store.node_summary(&id)?)).into_response())
}

async fn admin_delete_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    state.store.delete_node(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

fn monitoring_snapshot(state: &AppState) -> crate::store::Result<MonitoringOverview> {
    let mut cat_counts = CatStateCounts::default();
    for cat in state.store.list_all_cats()? {
        cat_counts.total += 1;
        match cat.observed_state {
            ObservedState::Running => cat_counts.running += 1,
            ObservedState::Suspended => cat_counts.suspended += 1,
            ObservedState::Warm => cat_counts.warm += 1,
            ObservedState::Cold => cat_counts.cold += 1,
            ObservedState::Failed | ObservedState::Unknown => cat_counts.failed_or_unknown += 1,
            _ => cat_counts.transitional += 1,
        }
    }

    let summaries = state.store.list_node_summaries()?;
    let mut node_counts = NodeStateCounts::default();
    let mut capacity = FleetCapacity::default();
    let mut usage = FleetUsage::default();
    let mut cpu_weighted_sum = 0.0;
    let mut cpu_weight = 0_u64;
    let mut logical_cpus = 0_u64;
    let mut memory_total = 0_u64;
    let mut memory_available = 0_u64;
    let mut memory_samples = 0_u64;
    let mut disk_total = 0_u64;
    let mut disk_available = 0_u64;
    let mut disk_samples = 0_u64;
    for summary in &summaries {
        node_counts.total += 1;
        match summary.node.state {
            NodeState::Ready => node_counts.ready += 1,
            NodeState::Cordoned => node_counts.cordoned += 1,
            NodeState::Draining => node_counts.draining += 1,
            NodeState::Lost => node_counts.lost += 1,
        }
        capacity.total_cpus += u64::from(summary.node.capacity.cpus);
        capacity.total_memory_mib += summary.node.capacity.memory_mib;
        capacity.assigned_cpus += u64::from(summary.assigned_cpus);
        capacity.assigned_memory_mib += summary.assigned_memory_mib;

        if summary.node.state == NodeState::Lost {
            continue;
        }
        let Some(telemetry) = &summary.node.telemetry else {
            continue;
        };
        if let Some(count) = telemetry.host_logical_cpus {
            logical_cpus += u64::from(count);
        }
        if let Some(percent) = telemetry.host_cpu_usage_percent {
            let weight = u64::from(
                telemetry
                    .host_logical_cpus
                    .unwrap_or(summary.node.capacity.cpus),
            );
            if weight > 0 {
                cpu_weighted_sum += percent.clamp(0.0, 100.0) * weight as f64;
                cpu_weight += weight;
            }
        }
        if let (Some(total), Some(available)) = (
            telemetry.host_memory_total_mib,
            telemetry.host_memory_available_mib,
        ) {
            memory_total = memory_total.saturating_add(total);
            memory_available = memory_available.saturating_add(available.min(total));
            memory_samples += 1;
        }
        if let (Some(total), Some(available)) = (
            telemetry.host_disk_total_bytes,
            telemetry.host_disk_available_bytes,
        ) {
            disk_total = disk_total.saturating_add(total);
            disk_available = disk_available.saturating_add(available.min(total));
            disk_samples += 1;
        }
    }
    if cpu_weight > 0 {
        usage.cpu_usage_percent = Some(cpu_weighted_sum / cpu_weight as f64);
    }
    if logical_cpus > 0 {
        usage.logical_cpus = Some(logical_cpus);
    }
    if memory_samples > 0 {
        usage.memory_total_mib = Some(memory_total);
        usage.memory_used_mib = Some(memory_total.saturating_sub(memory_available));
    }
    if disk_samples > 0 {
        usage.disk_total_bytes = Some(disk_total);
        usage.disk_used_bytes = Some(disk_total.saturating_sub(disk_available));
    }

    Ok(MonitoringOverview {
        generated_at_unix: crate::store::now_unix(),
        cats: cat_counts,
        nodes: node_counts,
        operations: state.store.operation_counts()?,
        capacity,
        usage,
    })
}

async fn admin_monitoring(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MonitoringOverview>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(monitoring_snapshot(&state)?))
}

async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let overview = monitoring_snapshot(&state)?;
    let mut body = String::new();
    macro_rules! metric {
        ($name:expr, $value:expr) => {
            body.push_str(&format!("{} {}\n", $name, $value));
        };
    }
    metric!("cats_control_plane_cats_total", overview.cats.total);
    metric!("cats_control_plane_cats_running", overview.cats.running);
    metric!("cats_control_plane_cats_suspended", overview.cats.suspended);
    metric!("cats_control_plane_cats_warm", overview.cats.warm);
    metric!("cats_control_plane_cats_cold", overview.cats.cold);
    metric!(
        "cats_control_plane_cats_transitional",
        overview.cats.transitional
    );
    metric!(
        "cats_control_plane_cats_failed_or_unknown",
        overview.cats.failed_or_unknown
    );
    metric!("cats_control_plane_nodes_ready", overview.nodes.ready);
    metric!("cats_control_plane_nodes_cordoned", overview.nodes.cordoned);
    metric!("cats_control_plane_nodes_draining", overview.nodes.draining);
    metric!("cats_control_plane_nodes_lost", overview.nodes.lost);
    metric!(
        "cats_control_plane_operations_pending",
        overview.operations.pending
    );
    metric!(
        "cats_control_plane_operations_running",
        overview.operations.running
    );
    metric!(
        "cats_control_plane_operations_succeeded",
        overview.operations.succeeded
    );
    metric!(
        "cats_control_plane_operations_failed",
        overview.operations.failed
    );
    metric!(
        "cats_control_plane_capacity_cpus",
        overview.capacity.total_cpus
    );
    metric!(
        "cats_control_plane_capacity_assigned_cpus",
        overview.capacity.assigned_cpus
    );
    metric!(
        "cats_control_plane_capacity_memory_mib",
        overview.capacity.total_memory_mib
    );
    metric!(
        "cats_control_plane_capacity_assigned_memory_mib",
        overview.capacity.assigned_memory_mib
    );
    if let Some(percent) = overview.usage.cpu_usage_percent {
        metric!("cats_control_plane_host_cpu_usage_percent", percent);
    }
    if let Some(logical_cpus) = overview.usage.logical_cpus {
        metric!("cats_control_plane_host_logical_cpus", logical_cpus);
    }
    if let Some(total) = overview.usage.memory_total_mib {
        metric!("cats_control_plane_host_memory_total_mib", total);
    }
    if let Some(used) = overview.usage.memory_used_mib {
        metric!("cats_control_plane_host_memory_used_mib", used);
    }
    if let Some(total) = overview.usage.disk_total_bytes {
        metric!("cats_control_plane_host_disk_total_bytes", total);
    }
    if let Some(used) = overview.usage.disk_used_bytes {
        metric!("cats_control_plane_host_disk_used_bytes", used);
    }
    for summary in state.store.list_node_summaries()? {
        let node_id = summary
            .node
            .id
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('"', "\\\"");
        metric!(
            format!("cats_node_heartbeat_age_seconds{{node_id=\"{node_id}\"}}"),
            summary.heartbeat_age_seconds
        );
        if let Some(telemetry) = summary.node.telemetry {
            metric!(
                format!("cats_node_observed_cats{{node_id=\"{node_id}\"}}"),
                telemetry.observed_cats
            );
            metric!(
                format!("cats_node_allocated_cpus{{node_id=\"{node_id}\"}}"),
                telemetry.allocated_cpus
            );
            metric!(
                format!("cats_node_allocated_memory_mib{{node_id=\"{node_id}\"}}"),
                telemetry.allocated_memory_mib
            );
            if let Some(logical_cpus) = telemetry.host_logical_cpus {
                metric!(
                    format!("cats_node_logical_cpus{{node_id=\"{node_id}\"}}"),
                    logical_cpus
                );
            }
            if let Some(percent) = telemetry.host_cpu_usage_percent {
                metric!(
                    format!("cats_node_cpu_usage_percent{{node_id=\"{node_id}\"}}"),
                    percent
                );
            }
            if let Some(load) = telemetry.load_average_1m {
                metric!(
                    format!("cats_node_load_average_1m{{node_id=\"{node_id}\"}}"),
                    load
                );
            }
            if let Some(available) = telemetry.host_memory_available_mib {
                metric!(
                    format!("cats_node_memory_available_mib{{node_id=\"{node_id}\"}}"),
                    available
                );
            }
            if let Some(total) = telemetry.host_memory_total_mib {
                metric!(
                    format!("cats_node_memory_total_mib{{node_id=\"{node_id}\"}}"),
                    total
                );
                if let Some(available) = telemetry.host_memory_available_mib {
                    metric!(
                        format!("cats_node_memory_used_mib{{node_id=\"{node_id}\"}}"),
                        total.saturating_sub(available.min(total))
                    );
                }
            }
            if let Some(available) = telemetry.host_disk_available_bytes {
                metric!(
                    format!("cats_node_disk_available_bytes{{node_id=\"{node_id}\"}}"),
                    available
                );
            }
            if let Some(total) = telemetry.host_disk_total_bytes {
                metric!(
                    format!("cats_node_disk_total_bytes{{node_id=\"{node_id}\"}}"),
                    total
                );
                if let Some(available) = telemetry.host_disk_available_bytes {
                    metric!(
                        format!("cats_node_disk_used_bytes{{node_id=\"{node_id}\"}}"),
                        total.saturating_sub(available.min(total))
                    );
                }
            }
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

/// Wake handler used by the gateway (`POST /v1/routes/wake?hostname=`).
async fn wake_route_handler(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    wake_route(&state, &q.hostname).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_operation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Operation>> {
    // Authenticate before looking up an opaque ID so unauthenticated callers
    // cannot use status differences to enumerate operations.
    check_authenticated(&state, &headers).await?;
    let operation = state.store.get_operation(&id)?;
    check_project_auth(&state, &headers, &operation.project).await?;
    Ok(Json(operation))
}

async fn list_operations(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Operation>>> {
    check_project_auth(&state, &headers, &project).await?;
    Ok(Json(ListResponse {
        items: state.store.list_operations(&project)?,
    }))
}

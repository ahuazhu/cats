//! Authenticated public Exec and interactive Shell routes.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, FromRequestParts, Path, Query, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cats_api::semantic_control::{ResourceSlug, SemanticErrorBody, SemanticErrorCode};
use cats_api::sessions::{
    ExecRequest, ShellClientControl, ShellServerControl, MAX_EXEC_JSON_BODY_BYTES,
    MAX_SHELL_DIMENSION, MAX_SHELL_MESSAGE_BYTES, MIN_SHELL_DIMENSION,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;

use super::{check_workspace_bearer_auth, Failure};
use crate::semantic_session::{
    error, NodedShell, SemanticNodedSessionClient, SessionAccessApi, SessionTarget,
    PUBLIC_SHELL_UNAVAILABLE_MESSAGE,
};
use crate::server::AppState;

pub const CAT_EXEC_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/exec";
pub const CAT_SHELL_PATH: &str = "/v1/workspaces/{workspace}/cats/{cat}/shell";

const WEBSOCKET_IO_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

struct RuntimeSessionTasksInner {
    shutdown: tokio::sync::watch::Sender<bool>,
    active: tokio::sync::watch::Sender<usize>,
}

#[derive(Clone)]
struct RuntimeSessionTasks {
    inner: Arc<RuntimeSessionTasksInner>,
}

impl RuntimeSessionTasks {
    fn new() -> Self {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let (active, _) = tokio::sync::watch::channel(0);
        Self {
            inner: Arc::new(RuntimeSessionTasksInner { shutdown, active }),
        }
    }

    fn begin_shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    fn is_shutdown(&self) -> bool {
        *self.inner.shutdown.borrow()
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.inner.shutdown.subscribe()
    }

    fn register(&self) -> Option<RuntimeSessionTaskGuard> {
        if self.is_shutdown() {
            return None;
        }
        self.inner.active.send_modify(|active| *active += 1);
        if self.is_shutdown() {
            self.inner.active.send_modify(|active| {
                *active = active.checked_sub(1).expect("registration incremented")
            });
            return None;
        }
        Some(RuntimeSessionTaskGuard {
            inner: Some(Arc::clone(&self.inner)),
        })
    }

    async fn drain(&self) -> Result<(), SessionHttpFailure> {
        let deadline = tokio::time::Instant::now() + SESSION_SHUTDOWN_DRAIN_TIMEOUT;
        let mut active = self.inner.active.subscribe();
        loop {
            if *active.borrow_and_update() == 0 {
                return Ok(());
            }
            if tokio::time::timeout_at(deadline, active.changed())
                .await
                .is_err()
            {
                return Err(SessionHttpFailure(error(
                    SemanticErrorCode::Timeout,
                    "active runtime sessions did not drain during Control shutdown",
                )));
            }
        }
    }
}

struct RuntimeSessionTaskGuard {
    inner: Option<Arc<RuntimeSessionTasksInner>>,
}

impl Drop for RuntimeSessionTaskGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.active.send_modify(|active| {
                *active = active
                    .checked_sub(1)
                    .expect("active runtime session task guard")
            });
        }
    }
}

#[derive(Clone)]
pub struct SemanticSessionHttpState {
    access: Arc<dyn SessionAccessApi>,
    noded: SemanticNodedSessionClient,
    runtime_tasks: RuntimeSessionTasks,
}

impl SemanticSessionHttpState {
    pub fn new(access: Arc<dyn SessionAccessApi>, noded: SemanticNodedSessionClient) -> Self {
        Self {
            access,
            noded,
            runtime_tasks: RuntimeSessionTasks::new(),
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.runtime_tasks.begin_shutdown();
    }

    pub(crate) async fn drain_shutdown(&self) -> anyhow::Result<()> {
        self.runtime_tasks
            .drain()
            .await
            .map_err(|error_value| anyhow::anyhow!(error_value.0.message))
    }

    fn ensure_accepting(&self) -> Result<(), SessionHttpFailure> {
        if self.runtime_tasks.is_shutdown() {
            Err(SessionHttpFailure(error(
                SemanticErrorCode::NodeUnavailable,
                "Control is shutting down",
            )))
        } else {
            Ok(())
        }
    }
}

pub fn routes(session: SemanticSessionHttpState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(CAT_EXEC_PATH, post(exec_cat))
        .route(CAT_SHELL_PATH, get(shell_cat))
        .layer(Extension(session))
}

async fn exec_cat(
    State(state): State<AppState>,
    Extension(session): Extension<SemanticSessionHttpState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SessionHttpFailure> {
    // Authentication intentionally precedes body parsing, lifecycle wake and
    // every Node connection. Only the immutable Workspace ID crosses the
    // public adapter boundary; the caller credential never does.
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_browser_origin(request.headers())?;
    session.ensure_accepting()?;
    // Register before consuming the request body. Shutdown must account for
    // every admitted Exec, including one blocked on an incomplete upload,
    // lifecycle wake or the single noded dispatch.
    let mut active_session = begin_runtime_session(&session, "Exec")?;
    reject_query(request.uri().query())?;
    let request: ExecRequest = tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut active_session.shutdown) => {
            return Err(runtime_shutdown_failure("reading the Exec request"));
        }
        result = parse_exec_json(request) => result?,
    };
    request
        .validate()
        .map_err(|error_value| invalid_request(error_value.to_string()))?;
    exec_after_auth(
        &session,
        &workspace_id,
        resource_slug(cat)?,
        request,
        active_session,
    )
    .await
}

async fn exec_after_auth(
    session: &SemanticSessionHttpState,
    workspace_id: &str,
    cat_slug: ResourceSlug,
    request: ExecRequest,
    mut active_session: ActiveRuntimeSession,
) -> Result<Response, SessionHttpFailure> {
    let target = prepare_runtime_target(
        session,
        workspace_id,
        cat_slug,
        &mut active_session.shutdown,
        "Exec",
    )
    .await?;
    // Exactly one dispatch. In particular, ambiguous timeout/response loss is
    // returned to the caller and never replayed here.
    let response = tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut active_session.shutdown) => {
            return Err(ambiguous_exec_shutdown_failure());
        }
        result = session.noded.exec(&target, &request) => {
            result.map_err(SessionHttpFailure)?
        }
    };
    let mut response = (StatusCode::OK, Json(response)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellQuery {
    #[serde(default = "default_shell_rows")]
    rows: u16,
    #[serde(default = "default_shell_cols")]
    cols: u16,
}

const fn default_shell_rows() -> u16 {
    24
}

const fn default_shell_cols() -> u16 {
    80
}

async fn shell_cat(
    State(state): State<AppState>,
    Extension(session): Extension<SemanticSessionHttpState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> Result<Response, SessionHttpFailure> {
    // Keep all fallible request parsing behind Bearer authorization. Axum's
    // ordinary Query/WebSocketUpgrade extractors would reject before entering
    // this handler and could therefore create a separate unauthenticated
    // response surface.
    let workspace_id = authenticated_workspace_id(&state, request.headers(), &workspace).await?;
    reject_browser_origin(request.headers())?;
    session.ensure_accepting()?;
    let (mut parts, _) = request.into_parts();
    let Query(query) = Query::<ShellQuery>::try_from_uri(&parts.uri)
        .map_err(|_| invalid_request("Shell query is malformed"))?;
    let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_| invalid_request("request is not a valid WebSocket upgrade"))?;
    if !(MIN_SHELL_DIMENSION..=MAX_SHELL_DIMENSION).contains(&query.rows)
        || !(MIN_SHELL_DIMENSION..=MAX_SHELL_DIMENSION).contains(&query.cols)
    {
        return Err(invalid_request(format!(
            "rows and cols must each be between {MIN_SHELL_DIMENSION} and {MAX_SHELL_DIMENSION}"
        )));
    }
    let cat_slug = resource_slug(cat)?;
    // Complete wake, the fresh placement read and the authenticated Node
    // handshake before accepting the public upgrade. Failures therefore keep
    // their ordinary semantic HTTP status instead of becoming an in-band PTY
    // error after a misleading 101 response.
    let mut active_session = begin_runtime_session(&session, "Shell")?;
    let target = prepare_runtime_target(
        &session,
        &workspace_id,
        cat_slug,
        &mut active_session.shutdown,
        "Shell",
    )
    .await?;
    let mut node = tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut active_session.shutdown) => {
            return Err(runtime_shutdown_failure("opening the Shell"));
        }
        result = session.noded.open_shell(&target, query.rows, query.cols) => {
            result.map_err(SessionHttpFailure)?
        }
    };
    if *active_session.shutdown.borrow() {
        bounded_node_close(&mut node).await;
        return Err(runtime_shutdown_failure("opening the Shell"));
    }
    Ok(upgrade
        .max_message_size(MAX_SHELL_MESSAGE_BYTES)
        .max_frame_size(MAX_SHELL_MESSAGE_BYTES)
        .on_upgrade(move |socket| serve_shell(socket, node, active_session)))
}

struct ActiveRuntimeSession {
    shutdown: tokio::sync::watch::Receiver<bool>,
    _task_guard: RuntimeSessionTaskGuard,
}

fn begin_runtime_session(
    session: &SemanticSessionHttpState,
    operation: &'static str,
) -> Result<ActiveRuntimeSession, SessionHttpFailure> {
    let Some(task_guard) = session.runtime_tasks.register() else {
        return Err(runtime_shutdown_failure(match operation {
            "Exec" => "opening the Exec",
            _ => "opening the Shell",
        }));
    };
    Ok(ActiveRuntimeSession {
        shutdown: session.runtime_tasks.subscribe(),
        _task_guard: task_guard,
    })
}

async fn prepare_runtime_target(
    session: &SemanticSessionHttpState,
    workspace_id: &str,
    cat_slug: ResourceSlug,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    operation: &'static str,
) -> Result<SessionTarget, SessionHttpFailure> {
    let target = tokio::select! {
        biased;
        _ = wait_for_shutdown(shutdown) => {
            return Err(runtime_shutdown_failure(match operation {
                "Exec" => "preparing the Exec",
                _ => "preparing the Shell",
            }));
        }
        result = session.access.prepare(workspace_id, cat_slug) => {
            result.map_err(SessionHttpFailure)?
        }
    };
    if *shutdown.borrow() {
        return Err(runtime_shutdown_failure(match operation {
            "Exec" => "preparing the Exec",
            _ => "preparing the Shell",
        }));
    }
    Ok(target)
}

async fn serve_shell(
    mut public: WebSocket,
    node: NodedShell,
    mut active_session: ActiveRuntimeSession,
) {
    let result = proxy_shell(&mut public, node, &mut active_session.shutdown).await;
    if let Err(error_body) = result {
        if !*active_session.shutdown.borrow() {
            send_shell_error(
                &mut public,
                error_body.message,
                &mut active_session.shutdown,
            )
            .await;
        }
        bounded_public_close(&mut public).await;
    }
}

async fn proxy_shell(
    public: &mut WebSocket,
    mut node: NodedShell,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), SemanticErrorBody> {
    let result = proxy_shell_frames(public, &mut node, shutdown).await;
    bounded_node_close(&mut node).await;
    if result.is_ok() {
        bounded_public_close(public).await;
    }
    result
}

async fn proxy_shell_frames(
    public: &mut WebSocket,
    node: &mut NodedShell,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), SemanticErrorBody> {
    loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => break,
            public_message = public.recv() => {
                let Some(public_message) = public_message else { break };
                let public_message = public_message.map_err(|error_value| {
                    error(SemanticErrorCode::NodeUnavailable, format!("public Shell transport failed: {error_value}"))
                })?;
                let Some(node_message) = public_to_node(public_message)? else { break };
                send_node(node, node_message, shutdown).await?;
            }
            node_message = node.next() => {
                let Some(node_message) = node_message else { break };
                let node_message = node_message.map_err(noded_shell_transport_error)?;
                let Some(public_message) = node_to_public(node_message)? else { break };
                send_public(public, public_message, shutdown).await?;
            }
        }
    }
    // The outer proxy closes both transports on every exit, including errors
    // and Control shutdown, so noded promptly tears down the Guest PTY.
    Ok(())
}

async fn wait_for_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

fn runtime_shutdown_failure(phase: &'static str) -> SessionHttpFailure {
    SessionHttpFailure(error(
        SemanticErrorCode::NodeUnavailable,
        format!("Control began shutdown while {phase}"),
    ))
}

fn ambiguous_exec_shutdown_failure() -> SessionHttpFailure {
    SessionHttpFailure(error(
        SemanticErrorCode::NodeUnavailable,
        "Control shutdown dropped the local noded Exec transport; the result is unknown and was not retried",
    ))
}

async fn send_node(
    node: &mut NodedShell,
    message: tungstenite::Message,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), SemanticErrorBody> {
    tokio::select! {
        biased;
        _ = wait_for_shutdown(shutdown) => Err(session_cancelled()),
        result = tokio::time::timeout(WEBSOCKET_IO_TIMEOUT, node.send(message)) => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error_value)) => Err(noded_shell_transport_error(error_value)),
                Err(_) => Err(noded_shell_transport_error("send timed out")),
            }
        }
    }
}

async fn send_public(
    public: &mut WebSocket,
    message: Message,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), SemanticErrorBody> {
    tokio::select! {
        biased;
        _ = wait_for_shutdown(shutdown) => Err(session_cancelled()),
        result = tokio::time::timeout(WEBSOCKET_IO_TIMEOUT, public.send(message)) => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error_value)) => Err(error(
                    SemanticErrorCode::NodeUnavailable,
                    format!("public Shell transport failed: {error_value}"),
                )),
                Err(_) => Err(error(
                    SemanticErrorCode::NodeUnavailable,
                    "public Shell send timed out",
                )),
            }
        }
    }
}

async fn bounded_public_close(public: &mut WebSocket) {
    let _ = tokio::time::timeout(WEBSOCKET_IO_TIMEOUT, public.send(Message::Close(None))).await;
}

async fn bounded_node_close(node: &mut NodedShell) {
    let _ = tokio::time::timeout(WEBSOCKET_IO_TIMEOUT, node.close(None)).await;
}

fn session_cancelled() -> SemanticErrorBody {
    error(
        SemanticErrorCode::ActionCancelled,
        "Shell proxy was cancelled during Control shutdown",
    )
}

fn noded_shell_transport_error(error_value: impl std::fmt::Display) -> SemanticErrorBody {
    tracing::warn!(error = %error_value, "noded Shell proxy transport failed");
    error(
        SemanticErrorCode::NodeUnavailable,
        "noded Shell session ended unexpectedly",
    )
}

fn public_to_node(message: Message) -> Result<Option<tungstenite::Message>, SemanticErrorBody> {
    Ok(match message {
        Message::Text(text) => {
            if text.len() > MAX_SHELL_MESSAGE_BYTES {
                return Err(invalid_session(
                    "Shell control frame exceeds the size limit",
                ));
            }
            let control: ShellClientControl = serde_json::from_str(text.as_str())
                .map_err(|_| invalid_session("malformed Shell control frame"))?;
            control
                .validate()
                .map_err(|error_value| invalid_session(error_value.to_string()))?;
            Some(tungstenite::Message::Text(text.as_str().into()))
        }
        Message::Binary(bytes) => {
            if bytes.len() > MAX_SHELL_MESSAGE_BYTES {
                return Err(invalid_session("Shell input frame exceeds the size limit"));
            }
            Some(tungstenite::Message::Binary(bytes))
        }
        Message::Ping(bytes) => Some(tungstenite::Message::Ping(bytes)),
        Message::Pong(bytes) => Some(tungstenite::Message::Pong(bytes)),
        Message::Close(_) => None,
    })
}

fn node_to_public(message: tungstenite::Message) -> Result<Option<Message>, SemanticErrorBody> {
    Ok(match message {
        tungstenite::Message::Text(text) => {
            if text.len() > MAX_SHELL_MESSAGE_BYTES {
                return Err(invalid_session(
                    "noded Shell control frame exceeds the size limit",
                ));
            }
            let control = serde_json::from_str::<ShellServerControl>(text.as_str())
                .map_err(|_| invalid_session("noded returned a malformed Shell control frame"))?;
            let public_text = match control {
                ShellServerControl::Error { .. } => {
                    tracing::warn!("noded Shell reported a private runtime error");
                    serde_json::to_string(&ShellServerControl::Error {
                        message: PUBLIC_SHELL_UNAVAILABLE_MESSAGE.to_owned(),
                    })
                    .map_err(|_| {
                        error(
                            SemanticErrorCode::InternalError,
                            "cannot encode the public Shell error frame",
                        )
                    })?
                }
                ShellServerControl::Exit { .. } => text.as_str().to_owned(),
            };
            Some(Message::Text(public_text.into()))
        }
        tungstenite::Message::Binary(bytes) => {
            if bytes.len() > MAX_SHELL_MESSAGE_BYTES {
                return Err(invalid_session(
                    "noded Shell output frame exceeds the size limit",
                ));
            }
            Some(Message::Binary(bytes))
        }
        tungstenite::Message::Ping(bytes) => Some(Message::Ping(bytes)),
        tungstenite::Message::Pong(bytes) => Some(Message::Pong(bytes)),
        tungstenite::Message::Close(_) => None,
        tungstenite::Message::Frame(_) => {
            return Err(invalid_session(
                "noded returned an unexpected raw WebSocket frame",
            ));
        }
    })
}

async fn send_shell_error(
    public: &mut WebSocket,
    message: String,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) {
    let control = ShellServerControl::Error { message };
    if let Ok(encoded) = serde_json::to_string(&control) {
        let _ = send_public(public, Message::Text(encoded.into()), shutdown).await;
    }
}

async fn authenticated_workspace_id(
    state: &AppState,
    headers: &HeaderMap,
    workspace: &str,
) -> Result<String, SessionHttpFailure> {
    require_bearer_credential(headers)?;
    check_workspace_bearer_auth(state, headers, workspace)
        .await
        .map(|scope| scope.workspace.id)
        .map_err(auth_failure)
}

fn require_bearer_credential(headers: &HeaderMap) -> Result<(), SessionHttpFailure> {
    if super::bearer_token(headers).is_some_and(|token| !token.is_empty()) {
        Ok(())
    } else {
        Err(SessionHttpFailure(error(
            SemanticErrorCode::Unauthorized,
            "an explicit Bearer credential is required",
        )))
    }
}

fn reject_browser_origin(headers: &HeaderMap) -> Result<(), SessionHttpFailure> {
    if headers.contains_key(header::ORIGIN) {
        Err(SessionHttpFailure(error(
            SemanticErrorCode::Unauthorized,
            "browser Origin requests are not accepted by runtime session endpoints",
        )))
    } else {
        Ok(())
    }
}

fn auth_failure(Failure(error_value): Failure) -> SessionHttpFailure {
    let code = match error_value.code {
        cats_api::error::ErrorCode::Unauthenticated
        | cats_api::error::ErrorCode::PermissionDenied
        | cats_api::error::ErrorCode::NotFound => SemanticErrorCode::Unauthorized,
        cats_api::error::ErrorCode::InvalidArgument => SemanticErrorCode::InvalidRequest,
        cats_api::error::ErrorCode::DeadlineExceeded => SemanticErrorCode::Timeout,
        cats_api::error::ErrorCode::Unavailable => SemanticErrorCode::NodeUnavailable,
        _ => SemanticErrorCode::InternalError,
    };
    SessionHttpFailure(error(code, error_value.message))
}

async fn parse_exec_json(request: Request<Body>) -> Result<ExecRequest, SessionHttpFailure> {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err(invalid_request("Content-Type must equal application/json"));
    }
    let body = to_bytes(request.into_body(), MAX_EXEC_JSON_BODY_BYTES)
        .await
        .map_err(|_| invalid_request("Exec request exceeds the body limit"))?;
    serde_json::from_slice(&body).map_err(|_| invalid_request("Exec request is malformed"))
}

fn resource_slug(value: String) -> Result<ResourceSlug, SessionHttpFailure> {
    ResourceSlug::new(value).ok_or_else(|| invalid_request("Cat slug is invalid"))
}

fn reject_query(query: Option<&str>) -> Result<(), SessionHttpFailure> {
    if query.is_some() {
        Err(invalid_request("Exec does not accept query parameters"))
    } else {
        Ok(())
    }
}

fn invalid_request(message: impl Into<String>) -> SessionHttpFailure {
    SessionHttpFailure(error(SemanticErrorCode::InvalidRequest, message))
}

fn invalid_session(message: impl Into<String>) -> SemanticErrorBody {
    error(SemanticErrorCode::InvalidRequest, message)
}

#[derive(Debug)]
struct SessionHttpFailure(SemanticErrorBody);

impl IntoResponse for SessionHttpFailure {
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
    use std::collections::BTreeMap;
    use std::future::pending;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::http::HeaderValue;
    use cats_api::sessions::ExecResponse;
    use futures_util::SinkExt as _;
    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn cookie_only_and_browser_origin_are_rejected_before_session_work() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("cats_session=sealed"),
        );
        let failure = require_bearer_credential(&headers).expect_err("cookie-only request");
        assert_eq!(failure.0.code, SemanticErrorCode::Unauthorized);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-token"),
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://hostile.example"),
        );
        require_bearer_credential(&headers).expect("explicit bearer");
        let failure = reject_browser_origin(&headers).expect_err("browser Origin");
        assert_eq!(failure.0.code, SemanticErrorCode::Unauthorized);
        let response = failure.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    #[tokio::test]
    async fn shutdown_rejects_new_shells_and_drains_registered_tasks() {
        let tasks = RuntimeSessionTasks::new();
        let guard = tasks.register().expect("register active runtime session");
        let mut shutdown = tasks.subscribe();
        tasks.begin_shutdown();
        assert!(*shutdown.borrow_and_update());
        assert!(tasks.register().is_none());

        let draining = tokio::spawn({
            let tasks = tasks.clone();
            async move { tasks.drain().await }
        });
        tokio::task::yield_now().await;
        assert!(!draining.is_finished());
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), draining)
            .await
            .expect("drain deadline")
            .expect("drain task")
            .expect("drain result");
    }

    #[tokio::test]
    async fn active_drop_before_first_changed_poll_is_not_lost() {
        let tasks = RuntimeSessionTasks::new();
        let guard = tasks.register().expect("register active runtime session");
        let mut active = tasks.inner.active.subscribe();
        assert_eq!(*active.borrow_and_update(), 1);

        // Construct no `changed()` future until after the guard is gone. A
        // Notify-based edge signal can be lost in exactly this interval;
        // watch retains the current zero and reports the unseen version.
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), active.changed())
            .await
            .expect("retained active-count change")
            .expect("active-count sender");
        assert_eq!(*active.borrow_and_update(), 0);
        tasks.drain().await.expect("drain zero active tasks");
    }

    #[tokio::test]
    async fn shutdown_cancels_blocked_prepare_before_drain_and_node_open() {
        struct PrepareDrop(Arc<AtomicBool>);

        impl Drop for PrepareDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        struct BarrierAccess {
            started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            dropped: Arc<AtomicBool>,
        }

        impl SessionAccessApi for BarrierAccess {
            fn prepare<'a>(
                &'a self,
                _workspace_id: &'a str,
                _cat_slug: ResourceSlug,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<SessionTarget, SemanticErrorBody>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    let _drop = PrepareDrop(Arc::clone(&self.dropped));
                    if let Some(started) = self.started.lock().expect("started").take() {
                        let _ = started.send(());
                    }
                    pending::<Result<SessionTarget, SemanticErrorBody>>().await
                })
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let prepare_dropped = Arc::new(AtomicBool::new(false));
        let open_called = Arc::new(AtomicBool::new(false));
        let session = SemanticSessionHttpState::new(
            Arc::new(BarrierAccess {
                started: std::sync::Mutex::new(Some(started_tx)),
                dropped: Arc::clone(&prepare_dropped),
            }),
            SemanticNodedSessionClient::new(
                cats_api::semantic_control::NodedServiceToken::new("x".repeat(32))
                    .expect("service token"),
            )
            .expect("noded client"),
        );
        let preparing = tokio::spawn({
            let session = session.clone();
            let open_called = Arc::clone(&open_called);
            async move {
                let mut active_session = begin_runtime_session(&session, "Exec")?;
                let result = prepare_runtime_target(
                    &session,
                    "ws_01",
                    ResourceSlug::new("web").expect("slug"),
                    &mut active_session.shutdown,
                    "Exec",
                )
                .await;
                if result.is_ok() {
                    open_called.store(true, Ordering::SeqCst);
                }
                result.map(|_| ())
            }
        });
        started_rx.await.expect("prepare started");

        session.begin_shutdown();
        let draining = tokio::spawn({
            let session = session.clone();
            async move { session.drain_shutdown().await }
        });
        tokio::time::timeout(Duration::from_secs(1), draining)
            .await
            .expect("shutdown drain deadline")
            .expect("shutdown drain task")
            .expect("shutdown drain");
        assert!(
            prepare_dropped.load(Ordering::SeqCst),
            "drain cannot finish before the in-flight prepare is cancelled"
        );
        assert!(preparing.await.expect("prepare task").is_err());
        assert!(!open_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_drops_local_dispatched_exec_transport_and_drains_once() {
        struct FixedAccess {
            target: SessionTarget,
            prepares: Arc<AtomicUsize>,
        }

        impl SessionAccessApi for FixedAccess {
            fn prepare<'a>(
                &'a self,
                _workspace_id: &'a str,
                _cat_slug: ResourceSlug,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<SessionTarget, SemanticErrorBody>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    self.prepares.fetch_add(1, Ordering::SeqCst);
                    Ok(self.target.clone())
                })
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw noded");
        let address = listener.local_addr().expect("raw noded address");
        let accepts = Arc::new(AtomicUsize::new(0));
        let server_accepts = Arc::clone(&accepts);
        let (dispatched_tx, dispatched_rx) = tokio::sync::oneshot::channel();
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept Exec transport");
            server_accepts.fetch_add(1, Ordering::SeqCst);
            let mut bytes = Vec::new();
            let expected_request_bytes = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read Exec request");
                assert!(read > 0, "Control closed before dispatching the Exec body");
                bytes.extend_from_slice(&chunk[..read]);
                let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                    continue;
                };
                let headers = std::str::from_utf8(&bytes[..header_end]).expect("HTTP headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("Content-Length"))
                    })
                    .expect("Exec Content-Length");
                break header_end + 4 + content_length;
            };
            while bytes.len() < expected_request_bytes {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read Exec body");
                assert!(read > 0, "Control closed during the Exec body");
                bytes.extend_from_slice(&chunk[..read]);
            }
            let _ = dispatched_tx.send(());

            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("shutdown must close Control's local noded transport")
                .expect("read noded EOF");
            assert_eq!(
                read, 0,
                "dropping Control's local request future must produce TCP EOF"
            );
            let _ = eof_tx.send(());

            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "ambiguous Exec must not be redispatched"
            );
        });

        let prepares = Arc::new(AtomicUsize::new(0));
        let target = SessionTarget {
            cat_id: cats_api::runtime_reconciliation::Id::new("cat_01").expect("Cat ID"),
            endpoint: cats_api::semantic_control::NodedControlEndpoint::new(format!(
                "http://{address}"
            ))
            .expect("noded endpoint"),
        };
        let session = SemanticSessionHttpState::new(
            Arc::new(FixedAccess {
                target,
                prepares: Arc::clone(&prepares),
            }),
            SemanticNodedSessionClient::new(
                cats_api::semantic_control::NodedServiceToken::new("x".repeat(32))
                    .expect("service token"),
            )
            .expect("noded client"),
        );
        let request = ExecRequest {
            command: vec!["sleep".to_owned(), "forever".to_owned()],
            timeout_ms: Some(60_000),
            env: Default::default(),
            stdin: Vec::new(),
        };
        let exec = tokio::spawn({
            let session = session.clone();
            async move {
                let active_session = begin_runtime_session(&session, "Exec")?;
                exec_after_auth(
                    &session,
                    "ws_01",
                    ResourceSlug::new("web").expect("slug"),
                    request,
                    active_session,
                )
                .await
            }
        });
        dispatched_rx.await.expect("Exec dispatch observed");

        session.begin_shutdown();
        let failure = exec
            .await
            .expect("Exec task")
            .expect_err("shutdown must cancel Exec")
            .0;
        tokio::time::timeout(Duration::from_secs(1), session.drain_shutdown())
            .await
            .expect("runtime session drain deadline")
            .expect("runtime session drain");
        eof_rx.await.expect("raw noded EOF");
        server.await.expect("raw noded server");

        assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
        assert!(failure.message.contains("result is unknown"));
        assert!(failure.message.contains("was not retried"));
        assert_eq!(prepares.load(Ordering::SeqCst), 1);
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn actual_routes_authenticate_bound_bodies_dispatch_once_and_upgrade_shell() {
        const ADMIN_TOKEN: &str = "session-route-admin-token";
        const SERVICE_TOKEN: &str = "session-route-service-token";
        const NODED_TOKEN: &str = "session-route-noded-token-000000";
        const WORKSPACE_ID: &str = "ws_session_routes";

        #[derive(Clone)]
        struct RouteNodedState {
            execs: Arc<AtomicUsize>,
            shells: Arc<AtomicUsize>,
            reject_exec: Arc<AtomicBool>,
            reject_shell: Arc<AtomicBool>,
            send_private_shell_error: Arc<AtomicBool>,
        }

        async fn noded_exec(
            State(state): State<RouteNodedState>,
            Json(_request): Json<ExecRequest>,
        ) -> Response {
            state.execs.fetch_add(1, Ordering::SeqCst);
            if state.reject_exec.load(Ordering::SeqCst) {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(error(
                        SemanticErrorCode::NodeUnavailable,
                        "connect /run/cats/vmm-4242.pid: Permission denied (os error 13)",
                    )),
                )
                    .into_response();
            }
            Json(ExecResponse {
                exit_code: 7,
                stdout: "route-ok".to_owned(),
                stderr: "exact".to_owned(),
            })
            .into_response()
        }

        async fn noded_shell(
            State(state): State<RouteNodedState>,
            upgrade: WebSocketUpgrade,
        ) -> Response {
            state.shells.fetch_add(1, Ordering::SeqCst);
            if state.reject_shell.load(Ordering::SeqCst) {
                return (
                    StatusCode::BAD_GATEWAY,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&error(
                        SemanticErrorCode::NodeUnavailable,
                        "connect /run/cats/vmm-4242.pid: Permission denied (os error 13)",
                    ))
                    .expect("semantic error JSON"),
                )
                    .into_response();
            }
            let send_private_shell_error = state.send_private_shell_error.load(Ordering::SeqCst);
            upgrade.on_upgrade(move |mut socket| async move {
                let control = if send_private_shell_error {
                    ShellServerControl::Error {
                        message: "vsock /run/cats/vmm-4242.pid: broken pipe (os error 32)"
                            .to_owned(),
                    }
                } else {
                    ShellServerControl::Exit { exit_code: 23 }
                };
                let encoded = serde_json::to_string(&control).expect("Shell control JSON");
                socket
                    .send(Message::Text(encoded.into()))
                    .await
                    .expect("send exact Exit");
                let _ = socket.close().await;
            })
        }

        struct RouteAccess {
            prepares: Arc<AtomicUsize>,
            target: SessionTarget,
        }

        impl SessionAccessApi for RouteAccess {
            fn prepare<'a>(
                &'a self,
                _workspace_id: &'a str,
                cat_slug: ResourceSlug,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<SessionTarget, SemanticErrorBody>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    self.prepares.fetch_add(1, Ordering::SeqCst);
                    if cat_slug.as_str() == "prepare-fail" {
                        return Err(error(
                            SemanticErrorCode::InvalidState,
                            "test prepare failure",
                        ));
                    }
                    Ok(self.target.clone())
                })
            }
        }

        let noded_state = RouteNodedState {
            execs: Arc::new(AtomicUsize::new(0)),
            shells: Arc::new(AtomicUsize::new(0)),
            reject_exec: Arc::new(AtomicBool::new(false)),
            reject_shell: Arc::new(AtomicBool::new(false)),
            send_private_shell_error: Arc::new(AtomicBool::new(false)),
        };
        let noded_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test noded");
        let noded_address = noded_listener.local_addr().expect("noded address");
        let noded_app = Router::new()
            .route("/v1/cats/{cat_id}/exec", post(noded_exec))
            .route("/v1/cats/{cat_id}/shell", get(noded_shell))
            .with_state(noded_state.clone());
        let noded_server = tokio::spawn(async move {
            axum::serve(noded_listener, noded_app)
                .await
                .expect("serve test noded");
        });

        let prepares = Arc::new(AtomicUsize::new(0));
        let sessions = SemanticSessionHttpState::new(
            Arc::new(RouteAccess {
                prepares: Arc::clone(&prepares),
                target: SessionTarget {
                    cat_id: cats_api::runtime_reconciliation::Id::new("cat_route").expect("Cat ID"),
                    endpoint: cats_api::semantic_control::NodedControlEndpoint::new(format!(
                        "http://{noded_address}"
                    ))
                    .expect("noded endpoint"),
                },
            }),
            SemanticNodedSessionClient::new(
                cats_api::semantic_control::NodedServiceToken::new(NODED_TOKEN)
                    .expect("noded token"),
            )
            .expect("session client"),
        );
        let directory = tempfile::tempdir().expect("temp directory");
        let usage = Arc::new(
            cats_metering::SqliteUsageStore::open(&directory.path().join("usage.db"))
                .expect("usage store"),
        );
        let dsn = crate::testsupport::isolated_control_store_url();
        let control = crate::server::spawn_with_sessions_for_test(
            crate::server::Config {
                listen: "127.0.0.1:0".to_owned(),
                control_store_dsn: crate::store::DsnSource::Literal(dsn),
                control_store_ca_file: None,
                usage_store: usage.clone(),
                credit_store: usage,
                image_blob: crate::testsupport::unavailable_image_blob(),
                default_boot_image: crate::testsupport::test_boot_image(),
                auth_token: SERVICE_TOKEN.to_owned(),
                noded_service_token: NODED_TOKEN.to_owned(),
                guest_runtime_profile_receipt:
                    crate::testsupport::test_guest_runtime_profile_receipt(),
                runtime_provisioner_trust_bundle:
                    crate::testsupport::test_runtime_provisioner_trust_bundle(),
                production_cutover_operator_trust_bundle:
                    crate::testsupport::test_production_cutover_operator_trust_bundle(),
                admin_token: ADMIN_TOKEN.to_owned(),
                workos: None,
                stripe: None,
                billing_enforcement_enabled: false,
            },
            sessions,
        )
        .await
        .expect("spawn Control test server");
        control
            .state
            .store
            .execute(|store| {
                store.with(|client| {
                    client.batch_execute(
                        "INSERT INTO accounts (
                            id,slug,display_name,kind,workos_organization_id,billing_account_id,
                            personal_owner_user_id,status,created_at
                         ) VALUES (
                            'acct_session_routes','session-routes','Session Routes','organization',
                            'org_session_routes','billing_session_routes',NULL,'active',1
                         );
                         INSERT INTO workspaces (
                            id,account_id,slug,display_name,is_default,created_at
                         ) VALUES (
                            'ws_session_routes','acct_session_routes','default','Default',TRUE,1
                         );",
                    )
                })
            })
            .await
            .expect("seed authenticated Workspace");

        let http = reqwest::Client::new();
        let exec_url = format!(
            "{}/v1/workspaces/{WORKSPACE_ID}/cats/web/exec",
            control.base_url()
        );
        let cookie_only = http
            .post(&exec_url)
            .header(header::COOKIE, "cats_session=sealed")
            .header(header::CONTENT_TYPE, "application/json")
            .body("{")
            .send()
            .await
            .expect("cookie-only request");
        assert_eq!(cookie_only.status(), StatusCode::UNAUTHORIZED);
        let hostile_origin = http
            .post(&exec_url)
            .bearer_auth(ADMIN_TOKEN)
            .header(header::ORIGIN, "https://hostile.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body("{")
            .send()
            .await
            .expect("hostile Origin request");
        assert_eq!(hostile_origin.status(), StatusCode::UNAUTHORIZED);
        let malformed_unauthenticated = http
            .post(&exec_url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(vec![b' '; MAX_EXEC_JSON_BODY_BYTES + 1])
            .send()
            .await
            .expect("unauthenticated oversized request");
        assert_eq!(malformed_unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(prepares.load(Ordering::SeqCst), 0);
        assert_eq!(noded_state.execs.load(Ordering::SeqCst), 0);
        assert_eq!(noded_state.shells.load(Ordering::SeqCst), 0);

        let exact_limit = http
            .post(&exec_url)
            .bearer_auth(ADMIN_TOKEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(vec![b' '; MAX_EXEC_JSON_BODY_BYTES])
            .send()
            .await
            .expect("exact-limit request");
        assert_eq!(exact_limit.status(), StatusCode::BAD_REQUEST);
        let exact_failure = exact_limit
            .json::<SemanticErrorBody>()
            .await
            .expect("exact-limit semantic error");
        assert!(exact_failure.message.contains("malformed"));
        let above_limit = http
            .post(&exec_url)
            .bearer_auth(ADMIN_TOKEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(vec![b' '; MAX_EXEC_JSON_BODY_BYTES + 1])
            .send()
            .await
            .expect("above-limit request");
        assert_eq!(above_limit.status(), StatusCode::BAD_REQUEST);
        let above_failure = above_limit
            .json::<SemanticErrorBody>()
            .await
            .expect("above-limit semantic error");
        assert!(above_failure.message.contains("body limit"));
        assert_eq!(prepares.load(Ordering::SeqCst), 0);
        assert_eq!(noded_state.execs.load(Ordering::SeqCst), 0);

        let request = ExecRequest {
            command: vec!["sh".to_owned(), "-c".to_owned(), "exit 7".to_owned()],
            timeout_ms: Some(1_000),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };
        let response = http
            .post(&exec_url)
            .bearer_auth(ADMIN_TOKEN)
            .json(&request)
            .send()
            .await
            .expect("authorized Exec");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<ExecResponse>().await.expect("Exec JSON"),
            ExecResponse {
                exit_code: 7,
                stdout: "route-ok".to_owned(),
                stderr: "exact".to_owned(),
            }
        );
        assert_eq!(prepares.load(Ordering::SeqCst), 1);
        assert_eq!(noded_state.execs.load(Ordering::SeqCst), 1);

        noded_state.reject_exec.store(true, Ordering::SeqCst);
        let private_exec_failure = http
            .post(&exec_url)
            .bearer_auth(ADMIN_TOKEN)
            .json(&request)
            .send()
            .await
            .expect("private noded Exec failure");
        assert_eq!(
            private_exec_failure.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let private_exec_failure = private_exec_failure
            .json::<SemanticErrorBody>()
            .await
            .expect("public semantic Exec failure");
        assert_eq!(
            private_exec_failure.code,
            SemanticErrorCode::NodeUnavailable
        );
        assert_eq!(
            private_exec_failure.message,
            crate::semantic_session::PUBLIC_EXEC_NODE_UNAVAILABLE_MESSAGE
        );
        assert!(private_exec_failure
            .message
            .contains("result may be unknown"));
        assert!(private_exec_failure
            .message
            .contains("must not be retried automatically"));
        assert!(!private_exec_failure.message.contains("/run/"));
        assert!(!private_exec_failure.message.contains("4242"));
        assert!(!private_exec_failure.message.contains("os error"));
        noded_state.reject_exec.store(false, Ordering::SeqCst);

        let prepare_failure_url = format!(
            "ws://{}/v1/workspaces/{WORKSPACE_ID}/cats/prepare-fail/shell",
            control.addr
        );
        let mut prepare_failure_request =
            tungstenite::client::IntoClientRequest::into_client_request(prepare_failure_url)
                .expect("prepare-failure WebSocket request");
        prepare_failure_request.headers_mut().insert(
            header::AUTHORIZATION,
            tungstenite::http::HeaderValue::from_str(&format!("Bearer {ADMIN_TOKEN}"))
                .expect("authorization"),
        );
        let prepare_failure = tokio_tungstenite::connect_async(prepare_failure_request)
            .await
            .expect_err("prepare failure must precede public 101");
        let tungstenite::Error::Http(response) = prepare_failure else {
            panic!("prepare failure must be an ordinary HTTP response")
        };
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(noded_state.shells.load(Ordering::SeqCst), 0);

        let shell_url = format!(
            "ws://{}/v1/workspaces/{WORKSPACE_ID}/cats/web/shell",
            control.addr
        );
        let mut shell_request =
            tungstenite::client::IntoClientRequest::into_client_request(shell_url.clone())
                .expect("Shell WebSocket request");
        shell_request.headers_mut().insert(
            header::AUTHORIZATION,
            tungstenite::http::HeaderValue::from_str(&format!("Bearer {ADMIN_TOKEN}"))
                .expect("authorization"),
        );
        let (mut shell, response) = tokio_tungstenite::connect_async(shell_request)
            .await
            .expect("public Shell 101");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let exit = shell
            .next()
            .await
            .expect("Shell Exit frame")
            .expect("valid Shell frame");
        let tungstenite::Message::Text(exit) = exit else {
            panic!("Shell Exit must remain a text control frame")
        };
        assert_eq!(
            serde_json::from_str::<ShellServerControl>(exit.as_str()).expect("Shell Exit JSON"),
            ShellServerControl::Exit { exit_code: 23 }
        );

        noded_state
            .send_private_shell_error
            .store(true, Ordering::SeqCst);
        let mut private_shell_error_request =
            tungstenite::client::IntoClientRequest::into_client_request(shell_url.clone())
                .expect("private Shell error request");
        private_shell_error_request.headers_mut().insert(
            header::AUTHORIZATION,
            tungstenite::http::HeaderValue::from_str(&format!("Bearer {ADMIN_TOKEN}"))
                .expect("authorization"),
        );
        let (mut private_shell, response) =
            tokio_tungstenite::connect_async(private_shell_error_request)
                .await
                .expect("public Shell 101 before private Node error");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let private_shell_error = private_shell
            .next()
            .await
            .expect("public Shell error frame")
            .expect("valid public Shell error frame");
        let tungstenite::Message::Text(private_shell_error) = private_shell_error else {
            panic!("public Shell error must remain a text control frame")
        };
        let private_shell_error =
            serde_json::from_str::<ShellServerControl>(private_shell_error.as_str())
                .expect("public Shell error JSON");
        assert_eq!(
            private_shell_error,
            ShellServerControl::Error {
                message: PUBLIC_SHELL_UNAVAILABLE_MESSAGE.to_owned(),
            }
        );
        let encoded = serde_json::to_string(&private_shell_error).expect("public Shell error JSON");
        assert!(!encoded.contains("/run/"));
        assert!(!encoded.contains("4242"));
        assert!(!encoded.contains("os error"));
        noded_state
            .send_private_shell_error
            .store(false, Ordering::SeqCst);

        noded_state.reject_shell.store(true, Ordering::SeqCst);
        let mut rejected_shell_request =
            tungstenite::client::IntoClientRequest::into_client_request(shell_url)
                .expect("rejected Shell request");
        rejected_shell_request.headers_mut().insert(
            header::AUTHORIZATION,
            tungstenite::http::HeaderValue::from_str(&format!("Bearer {ADMIN_TOKEN}"))
                .expect("authorization"),
        );
        let rejected_shell = tokio_tungstenite::connect_async(rejected_shell_request)
            .await
            .expect_err("noded failure must precede public 101");
        let tungstenite::Error::Http(response) = rejected_shell else {
            panic!("noded failure must be an ordinary HTTP response")
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let failure = serde_json::from_slice::<SemanticErrorBody>(
            response.body().as_deref().expect("semantic failure body"),
        )
        .expect("semantic failure JSON");
        assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
        assert_eq!(failure.message, PUBLIC_SHELL_UNAVAILABLE_MESSAGE);
        assert!(!failure.message.contains("/run/"));
        assert!(!failure.message.contains("4242"));
        assert!(!failure.message.contains("os error"));

        control.shutdown().await.expect("Control shutdown");
        noded_server.abort();
    }

    #[test]
    fn shell_dimensions_default_and_reject_out_of_range_values() {
        let defaults: ShellQuery = serde_json::from_value(serde_json::json!({})).expect("query");
        assert_eq!(defaults.rows, 24);
        assert_eq!(defaults.cols, 80);
        assert!(
            !(MIN_SHELL_DIMENSION..=MAX_SHELL_DIMENSION).contains(&0),
            "zero must remain outside the shared dimension contract"
        );
        assert!(
            !(MIN_SHELL_DIMENSION..=MAX_SHELL_DIMENSION)
                .contains(&MAX_SHELL_DIMENSION.saturating_add(1)),
            "oversized terminals must remain outside the shared contract"
        );
    }

    #[test]
    fn shell_proxy_validates_public_control_before_forwarding() {
        let valid = Message::Text(
            serde_json::to_string(&ShellClientControl::Resize { rows: 24, cols: 80 })
                .expect("JSON")
                .into(),
        );
        assert!(matches!(
            public_to_node(valid).expect("valid frame"),
            Some(tungstenite::Message::Text(_))
        ));

        let invalid = Message::Text(
            serde_json::to_string(&ShellClientControl::Resize { rows: 0, cols: 80 })
                .expect("JSON")
                .into(),
        );
        let failure = public_to_node(invalid).expect_err("invalid dimensions");
        assert_eq!(failure.code, SemanticErrorCode::InvalidRequest);

        let private_node_error = tungstenite::Message::Text(
            serde_json::to_string(&ShellServerControl::Error {
                message: "vsock /run/cats/vmm-4242.pid: broken pipe (os error 32)".to_owned(),
            })
            .expect("private Shell error JSON")
            .into(),
        );
        let public_error = node_to_public(private_node_error)
            .expect("valid private error frame")
            .expect("public error frame");
        let Message::Text(public_error) = public_error else {
            panic!("public Shell error must be a text frame")
        };
        assert_eq!(
            serde_json::from_str::<ShellServerControl>(public_error.as_str())
                .expect("public Shell error JSON"),
            ShellServerControl::Error {
                message: PUBLIC_SHELL_UNAVAILABLE_MESSAGE.to_owned(),
            }
        );
        assert!(!public_error.contains("/run/"));
        assert!(!public_error.contains("4242"));
        assert!(!public_error.contains("os error"));

        let maximum_public_binary = Message::Binary(vec![0x5a; MAX_SHELL_MESSAGE_BYTES].into());
        let forwarded = public_to_node(maximum_public_binary)
            .expect("maximum public Shell binary frame")
            .expect("forwarded public Shell binary frame");
        assert!(matches!(
            forwarded,
            tungstenite::Message::Binary(ref bytes) if bytes.len() == MAX_SHELL_MESSAGE_BYTES
        ));
        let oversized_public_binary =
            Message::Binary(vec![0x5a; MAX_SHELL_MESSAGE_BYTES + 1].into());
        let failure =
            public_to_node(oversized_public_binary).expect_err("oversized public binary frame");
        assert_eq!(failure.code, SemanticErrorCode::InvalidRequest);

        let maximum_node_binary =
            tungstenite::Message::Binary(vec![0x5a; MAX_SHELL_MESSAGE_BYTES].into());
        let forwarded = node_to_public(maximum_node_binary)
            .expect("maximum noded Shell binary frame")
            .expect("forwarded noded Shell binary frame");
        assert!(matches!(
            forwarded,
            Message::Binary(ref bytes) if bytes.len() == MAX_SHELL_MESSAGE_BYTES
        ));
        let oversized_node_binary =
            tungstenite::Message::Binary(vec![0x5a; MAX_SHELL_MESSAGE_BYTES + 1].into());
        let failure =
            node_to_public(oversized_node_binary).expect_err("oversized noded binary frame");
        assert_eq!(failure.code, SemanticErrorCode::InvalidRequest);
    }

    #[test]
    fn route_contract_keeps_auth_and_node_handshake_before_public_upgrade() {
        let source = include_str!("sessions.rs")
            .split_once("#[cfg(test)]")
            .expect("production source")
            .0;
        let shell = source
            .split_once("async fn shell_cat")
            .expect("Shell handler")
            .1
            .split_once("async fn serve_shell")
            .expect("Shell handler end")
            .0;
        let auth = shell.find("authenticated_workspace_id").expect("auth call");
        let origin = shell.find("reject_browser_origin").expect("Origin check");
        let query = shell
            .find("Query::<ShellQuery>::try_from_uri")
            .expect("query parse");
        let register = shell
            .find("begin_runtime_session")
            .expect("runtime session registration");
        let prepare = shell
            .find("prepare_runtime_target")
            .expect("registered prepare call");
        let connect = shell.find(".open_shell(").expect("Node handshake");
        let upgrade = shell.find(".on_upgrade(").expect("public upgrade");
        assert!(
            auth < origin
                && origin < query
                && query < register
                && register < prepare
                && prepare < connect
                && connect < upgrade
        );
        let exec = source
            .split_once("async fn exec_cat")
            .expect("Exec handler")
            .1
            .split_once("async fn exec_after_auth")
            .expect("Exec handler end")
            .0;
        let auth = exec.find("authenticated_workspace_id").expect("auth call");
        let origin = exec.find("reject_browser_origin").expect("Origin check");
        let register = exec
            .find("begin_runtime_session")
            .expect("runtime session registration");
        let body = exec.find("parse_exec_json").expect("body parse");
        let dispatch = exec.find("exec_after_auth").expect("dispatch call");
        assert!(auth < origin && origin < register && register < body && body < dispatch);
    }
}

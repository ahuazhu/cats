//! Node agent HTTP surface + registration/heartbeat loops.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use cats_api::guest::GuestShellFrame;
use cats_api::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, UsageMetric,
    MAX_USAGE_CHECKPOINTS_PER_REQUEST, MAX_USAGE_INGEST_BODY_BYTES,
};
use cats_api::nodejob::{JobPhase, NodeJob};
use cats_api::oci::{DeployOciRequest, OciDeployment};
use cats_api::requests::{
    ExecRequest, ExecResponse, NodeWorkStatusRequest, ProxyHttpRequest, ShellClientControl,
    ShellServerControl, MAX_SHELL_MESSAGE_BYTES,
};
use cats_api::resources::{CatResourceTelemetry, NodeTelemetry};
use cats_api::route_grant::{ROUTE_GRANT_REJECTION_EXPIRED, ROUTE_GRANT_REJECTION_HEADER};
use cats_metering::RuntimeMeterAccumulator;
use cats_storage::MetadataStore;

use crate::guest_client::GuestShell;
use crate::runtime::{
    allocated_tree_bytes, CatTelemetryTarget, GuestConn, NodeConfig, NodeRuntime, ProxyTarget,
    RuntimeActivityGuard, UsageFinalizer,
};
use crate::usage_spool::UsageSpool;

async fn watch_guest_work(
    client: reqwest::Client,
    cp: String,
    token: String,
    node_id: String,
    cat_id: String,
    generation: i64,
    conn: GuestConn,
) {
    let mut after_sequence = None;
    loop {
        let watch_conn = conn.clone();
        let status = tokio::task::spawn_blocking(move || {
            let mut guest = watch_conn.connect()?;
            guest.work_status(after_sequence, 1_000)
        })
        .await;
        let status = match status {
            Ok(Ok(status)) => status,
            _ => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        after_sequence = Some(status.lease_sequence);
        let request = NodeWorkStatusRequest {
            node_id: node_id.clone(),
            cat_id: cat_id.clone(),
            generation,
            guest_source_epoch: status.source_epoch,
            guest_lease_sequence: status.lease_sequence,
            leases: status.leases,
        };
        let response = client
            .post(format!("{cp}/v1/nodes/work-status"))
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await;
        if response.is_err() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub auth_token: String,
    /// Closed local Node identity, durable registration state, and signer.
    pub agent_registration: crate::agent_registration::AgentRegistrationConfig,
    /// Public-key verifier for control-plane signed Endpoint Route Grants.
    pub route_grant_verifier: Arc<crate::route_grant::RouteGrantVerifier>,
    /// Local telemetry sampling cadence. It no longer drives the removed
    /// `/v1/nodes/heartbeat` transport.
    pub heartbeat_ms: u64,
    pub node: NodeConfig,
    pub storage_meta: Arc<dyn MetadataStore>,
}

#[derive(Clone)]
pub struct NodeState {
    pub runtime: Arc<NodeRuntime>,
    pub cfg: Arc<ServerConfig>,
    client: reqwest::Client,
    usage_pipeline: Arc<UsageMeteringPipeline>,
    /// Already durable before any runtime gate or listener is opened.
    pub agent_session: Arc<cats_api::runtime_reconciliation::AgentSession>,
}

pub struct Handle {
    pub addr: std::net::SocketAddr,
    pub state: NodeState,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn shutdown(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn check_auth(cfg: &ServerConfig, headers: &HeaderMap) -> Result<(), StatusCode> {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == cfg.auth_token);
    if ok {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

impl NodeState {
    async fn deliver_pending_usage(&self) -> anyhow::Result<()> {
        deliver_usage_batches(
            &self.client,
            &format!(
                "{}/v1/internal/usage/checkpoints",
                self.cfg.control_plane_url.trim_end_matches('/')
            ),
            &self.cfg.auth_token,
            &self.cfg.node.node_id,
            &self.usage_pipeline.spool,
            &self.usage_pipeline.delivery,
        )
        .await
    }
}

/// Use half the server's explicit JSON limit. The budget covers the complete
/// serialized request, not just the checkpoint objects, and leaves room for
/// intermediary behavior that is stricter than the final Axum extractor.
const USAGE_REQUEST_TARGET_BYTES: usize = MAX_USAGE_INGEST_BODY_BYTES / 2;
const USAGE_DELIVERY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const USAGE_DELIVERY_MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Bound on how much of a rejection body is quoted into an error. Enough for
/// the control plane's structured message, short enough that remote input
/// cannot flood the journal.
const MAX_INGEST_ERROR_DETAIL_CHARS: usize = 512;

/// How often abandoned per-Cat runtime directories are reclaimed and recounted.
///
/// Slow on purpose. Every pass walks the state directory and probes a Unix
/// socket per abandoned Cat, and what it is chasing accumulates over days: the
/// host that motivated it had collected 49 directories, the oldest five over
/// five days old (issue #99). A tighter cadence would buy nothing but I/O.
const RUNTIME_RESIDUE_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// How often the uploader drains the spool when nothing nudges it.
///
/// Independent of the heartbeat interval on purpose: billing tolerates delay,
/// liveness does not, so the two cadences must not be the same knob.
const USAGE_DELIVERY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct UsageDeliveryState {
    request_budget_bytes: usize,
    /// A response timeout is a soft capacity signal, so it lowers this AIMD
    /// window without changing the hard serialized-byte budget. Keeping the
    /// two dimensions separate guarantees that a later, larger checkpoint can
    /// still be sent by itself.
    max_checkpoints_per_request: usize,
    consecutive_failures: u32,
    retry_not_before: Option<Instant>,
}

impl Default for UsageDeliveryState {
    fn default() -> Self {
        Self {
            request_budget_bytes: USAGE_REQUEST_TARGET_BYTES,
            max_checkpoints_per_request: MAX_USAGE_CHECKPOINTS_PER_REQUEST,
            consecutive_failures: 0,
            retry_not_before: None,
        }
    }
}

impl UsageDeliveryState {
    fn retry_delay(&self, now: Instant) -> Option<Duration> {
        self.retry_not_before
            .and_then(|deadline| deadline.checked_duration_since(now))
    }

    fn record_idle(&mut self) {
        self.consecutive_failures = 0;
        self.retry_not_before = None;
    }

    fn record_success(&mut self) {
        self.record_idle();
        if self.max_checkpoints_per_request < MAX_USAGE_CHECKPOINTS_PER_REQUEST {
            // Additive recovery avoids permanently pinning throughput to one
            // tiny request after a transient slow response. It also avoids
            // immediately returning to the exact oversized batch that just
            // timed out.
            let growth = (self.max_checkpoints_per_request / 8).max(1);
            self.max_checkpoints_per_request = self
                .max_checkpoints_per_request
                .saturating_add(growth)
                .min(MAX_USAGE_CHECKPOINTS_PER_REQUEST);
        }
    }

    fn record_failure(&mut self, now: Instant) -> Duration {
        let exponent = self.consecutive_failures.min(6);
        let multiplier = 1_u32 << exponent;
        let delay = USAGE_DELIVERY_INITIAL_BACKOFF
            .saturating_mul(multiplier)
            .min(USAGE_DELIVERY_MAX_BACKOFF);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_not_before = now.checked_add(delay);
        delay
    }

    fn shrink_after_payload_too_large(
        &mut self,
        node_id: &str,
        rejected: &[CatUsageCheckpoint],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            rejected.len() > 1,
            "control plane rejected one usage checkpoint as payload too large; the queue head was retained"
        );
        let smaller_count = rejected.len() / 2;
        let smaller = IngestUsageCheckpointsRequest {
            node_id: node_id.to_string(),
            checkpoints: rejected[..smaller_count].to_vec(),
        };
        let smaller_bytes = serde_json::to_vec(&smaller)?.len();
        anyhow::ensure!(
            smaller_bytes < self.request_budget_bytes,
            "usage request split did not reduce the request budget"
        );
        self.request_budget_bytes = smaller_bytes;
        Ok(())
    }

    fn shrink_after_timeout(&mut self, rejected: &[CatUsageCheckpoint]) -> bool {
        if rejected.len() <= 1 {
            return false;
        }
        self.max_checkpoints_per_request = (rejected.len() / 2).max(1);
        true
    }
}

async fn deliver_usage_batches(
    client: &reqwest::Client,
    endpoint: &str,
    auth_token: &str,
    node_id: &str,
    spool: &UsageSpool,
    delivery: &tokio::sync::Mutex<UsageDeliveryState>,
) -> anyhow::Result<()> {
    // Every periodic or lifecycle-triggered uploader wakeup shares one ordered
    // delivery lane. Holding an async mutex across the request is intentional;
    // a std mutex is not held across await, and later batches cannot overtake
    // earlier ones.
    let mut delivery = delivery.lock().await;
    if spool.is_empty()? {
        delivery.record_idle();
        return Ok(());
    }
    if let Some(delay) = delivery.retry_delay(Instant::now()) {
        anyhow::bail!(
            "usage delivery is backing off for another {} ms",
            delay.as_millis()
        );
    }

    loop {
        let pending_checkpoints = match spool.peek_request_batch(
            node_id,
            delivery.max_checkpoints_per_request,
            delivery.request_budget_bytes,
        ) {
            Ok(checkpoints) => checkpoints,
            Err(error) => {
                let delay = delivery.record_failure(Instant::now());
                return Err(error).context(format!(
                    "build bounded usage request; retrying after {} ms",
                    delay.as_millis()
                ));
            }
        };
        if pending_checkpoints.is_empty() {
            delivery.record_idle();
            return Ok(());
        }
        let request = IngestUsageCheckpointsRequest {
            node_id: node_id.to_string(),
            checkpoints: pending_checkpoints.clone(),
        };
        let request_json = serde_json::to_vec(&request)?;
        anyhow::ensure!(
            request_json.len() <= delivery.request_budget_bytes,
            "usage request serialized to {} bytes above its {}-byte budget",
            request_json.len(),
            delivery.request_budget_bytes
        );
        let response = match client
            .post(endpoint)
            .bearer_auth(auth_token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(request_json)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                // A response timeout after connecting is often a batch-size
                // signal: the server accepted the request but could not durably
                // ingest it inside our deadline. Retain the whole prefix and
                // halve only the next wire request. Connect timeouts instead
                // describe reachability and cannot be improved by splitting.
                // The response can be lost after a successful commit, so this
                // retry remains safe only because ingestion deduplicates the
                // stable checkpoint event IDs.
                let shrunk = error.is_timeout()
                    && !error.is_connect()
                    && delivery.shrink_after_timeout(&pending_checkpoints);
                let delay = delivery.record_failure(Instant::now());
                let capacity_detail = if shrunk {
                    format!(
                        "; reduced the next batch to at most {} checkpoints",
                        delivery.max_checkpoints_per_request
                    )
                } else {
                    String::new()
                };
                return Err(error).context(format!(
                    "send durable usage checkpoints{capacity_detail}; retrying after {} ms",
                    delay.as_millis(),
                ));
            }
        };
        if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
            if pending_checkpoints.len() == 1 {
                let delay = delivery.record_failure(Instant::now());
                anyhow::bail!(
                    "control plane rejected one usage checkpoint as payload too large; the queue head was retained and will retry after {} ms",
                    delay.as_millis()
                );
            }
            delivery.shrink_after_payload_too_large(node_id, &pending_checkpoints)?;
            continue;
        }
        if !response.status().is_success() {
            let status = response.status();
            let shrunk = matches!(
                status,
                StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT
            ) && delivery.shrink_after_timeout(&pending_checkpoints);
            // Carry the control plane's reason. It names the offending
            // checkpoint and what is wrong with it, which is the difference
            // between "the batch is rejected" and knowing that one specific Cat
            // changed owner. Checkpoints carry no credentials, so the body is
            // safe to log; bound it anyway because it is remote input.
            let detail = response.text().await.unwrap_or_default();
            let detail = detail.trim();
            let detail: String = detail.chars().take(MAX_INGEST_ERROR_DETAIL_CHARS).collect();
            let delay = delivery.record_failure(Instant::now());
            let capacity_detail = if shrunk {
                format!(
                    "; reduced the next batch to at most {} checkpoints",
                    delivery.max_checkpoints_per_request
                )
            } else {
                String::new()
            };
            if detail.is_empty() {
                anyhow::bail!(
                    "usage ingestion returned {status}{capacity_detail}; retrying after {} ms",
                    delay.as_millis()
                );
            }
            anyhow::bail!(
                "usage ingestion returned {status}: {detail}{capacity_detail}; retrying after {} ms",
                delay.as_millis()
            );
        }

        let event_ids = pending_checkpoints
            .iter()
            .map(|checkpoint| checkpoint.event_id.clone())
            .collect::<Vec<_>>();
        spool.acknowledge(&event_ids)?;
        delivery.record_success();
    }
}

async fn handle_job(
    State(state): State<NodeState>,
    headers: HeaderMap,
    Json(job): Json<NodeJob>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || runtime.execute(job)).await;
    match result {
        Ok(res) if res.phase == JobPhase::Succeeded => {
            // A lifecycle result is not withheld for usage delivery. The
            // durable outbox is what makes a final checkpoint survive, not the
            // upload: `runtime.execute` has already persisted it, and ADR-0011
            // designs delivery to replay after the resource is deleted. Waiting
            // here added no durability and made an upload outage a lifecycle
            // outage -- a blocked stop could not converge, which kept a Cat's
            // claim alive and, through it, held its Host in recovery limbo.
            //
            // Nudge the uploader so a final checkpoint still leaves promptly on
            // the happy path, without making this response depend on it.
            state.usage_pipeline.wake_delivery();
            Json(res).into_response()
        }
        Ok(res) => Json(res).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_exec(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || {
        runtime.exec_with_input(&cat_id, req.command, req.env, req.stdin)
    })
    .await;
    match result {
        Ok(Ok((exit_code, stdout, stderr))) => Json(ExecResponse {
            exit_code,
            stdout,
            stderr,
        })
        .into_response(),
        Ok(Err(e)) if crate::runtime::is_activity_changed(&e) => {
            (StatusCode::CONFLICT, format!("{e:#}")).into_response()
        }
        Ok(Err(e)) => (StatusCode::SERVICE_UNAVAILABLE, format!("{e:#}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_deploy_oci(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DeployOciRequest>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || runtime.deploy_oci(&cat_id, request)).await;
    match result {
        Ok(Ok(deployment)) => Json::<OciDeployment>(deployment).into_response(),
        Ok(Err(error)) if crate::runtime::is_activity_changed(&error) => {
            (StatusCode::CONFLICT, format!("{error:#}")).into_response()
        }
        Ok(Err(error)) => (StatusCode::SERVICE_UNAVAILABLE, format!("{error:#}")).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
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

async fn handle_shell(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    Query(query): Query<ShellQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    if !(1..=1_000).contains(&query.rows) || !(1..=1_000).contains(&query.cols) {
        return (StatusCode::BAD_REQUEST, "invalid terminal dimensions").into_response();
    }
    let runtime = state.runtime.clone();
    let opened =
        tokio::task::spawn_blocking(move || runtime.open_shell(&cat_id, query.rows, query.cols))
            .await;
    match opened {
        Ok(Ok((guest, activity_guard))) => ws
            .max_message_size(MAX_SHELL_MESSAGE_BYTES)
            .max_frame_size(MAX_SHELL_MESSAGE_BYTES)
            .on_upgrade(move |socket| bridge_shell(socket, guest, activity_guard)),
        Ok(Err(error)) if crate::runtime::is_activity_changed(&error) => {
            (StatusCode::CONFLICT, format!("{error:#}")).into_response()
        }
        Ok(Err(error)) => (StatusCode::SERVICE_UNAVAILABLE, format!("{error:#}")).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn bridge_shell(socket: WebSocket, guest: GuestShell, _activity_guard: RuntimeActivityGuard) {
    let mut guest_reader = match guest.try_clone() {
        Ok(reader) => reader,
        Err(error) => {
            tracing::warn!(error = %error, "clone guest shell stream failed");
            return;
        }
    };
    let mut guest_writer = guest;
    let (to_guest_tx, mut to_guest_rx) = tokio::sync::mpsc::channel::<GuestShellFrame>(32);
    let (from_guest_tx, mut from_guest_rx) = tokio::sync::mpsc::channel::<GuestShellFrame>(32);
    let writer_task = tokio::task::spawn_blocking(move || {
        while let Some(frame) = to_guest_rx.blocking_recv() {
            if guest_writer.send(&frame).is_err() {
                break;
            }
            if frame == GuestShellFrame::Close {
                break;
            }
        }
    });
    let reader_task = tokio::task::spawn_blocking(move || {
        while let Ok(frame) = guest_reader.recv() {
            let terminal = matches!(frame, GuestShellFrame::Exit { .. });
            if from_guest_tx.blocking_send(frame).is_err() || terminal {
                break;
            }
        }
    });

    let (mut ws_sender, mut ws_receiver) = socket.split();
    let mut terminal = false;
    while !terminal {
        tokio::select! {
            incoming = ws_receiver.next() => {
                let Some(Ok(message)) = incoming else { break };
                let frame = match message {
                    Message::Binary(data) => Some(GuestShellFrame::Input { data: data.to_vec() }),
                    Message::Text(text) => match serde_json::from_str::<ShellClientControl>(text.as_str()) {
                        Ok(ShellClientControl::Resize { rows, cols }) => {
                            Some(GuestShellFrame::Resize { rows, cols })
                        }
                        Ok(ShellClientControl::Close) => {
                            terminal = true;
                            Some(GuestShellFrame::Close)
                        }
                        Err(_) => {
                            let control = ShellServerControl::Error {
                                message: "invalid shell control frame".to_string(),
                            };
                            let _ = ws_sender.send(Message::Text(serde_json::to_string(&control).unwrap().into())).await;
                            terminal = true;
                            Some(GuestShellFrame::Close)
                        }
                    },
                    Message::Ping(data) => {
                        if ws_sender.send(Message::Pong(data)).await.is_err() {
                            terminal = true;
                        }
                        None
                    }
                    Message::Pong(_) => None,
                    Message::Close(_) => {
                        terminal = true;
                        Some(GuestShellFrame::Close)
                    }
                };
                if let Some(frame) = frame {
                    if to_guest_tx.send(frame).await.is_err() {
                        break;
                    }
                }
            }
            outgoing = from_guest_rx.recv() => {
                let Some(frame) = outgoing else { break };
                let message = match frame {
                    GuestShellFrame::Output { data } => Message::Binary(data.into()),
                    GuestShellFrame::Exit { exit_code } => {
                        terminal = true;
                        Message::Text(serde_json::to_string(&ShellServerControl::Exit { exit_code }).unwrap().into())
                    }
                    _ => {
                        terminal = true;
                        Message::Text(serde_json::to_string(&ShellServerControl::Error {
                            message: "invalid frame from guest shell".to_string(),
                        }).unwrap().into())
                    }
                };
                if ws_sender.send(message).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = to_guest_tx.send(GuestShellFrame::Close).await;
    drop(to_guest_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), reader_task).await;
}

/// Gateway hop. 409 means the Cat is not active on this node (stale route:
/// the gateway must re-resolve); guest network/service failures are 502.
fn route_grant_rejection_response(
    error: crate::route_grant::RouteGrantVerificationError,
) -> Response {
    if error.is_expired() {
        return (
            StatusCode::CONFLICT,
            [(ROUTE_GRANT_REJECTION_HEADER, ROUTE_GRANT_REJECTION_EXPIRED)],
            format!("invalid route grant: {error:#}"),
        )
            .into_response();
    }
    (
        StatusCode::CONFLICT,
        format!("invalid route grant: {error:#}"),
    )
        .into_response()
}

async fn handle_proxy(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProxyHttpRequest>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let claims = match state.cfg.route_grant_verifier.verify(
        &request.route_grant,
        crate::route_grant::ExpectedRouteGrant {
            hostname: &request.hostname,
            cat_id: &cat_id,
            node_id: &state.cfg.node.node_id,
            route_epoch: request.route_epoch,
            target_port: request.target_port,
        },
    ) {
        Ok(claims) => claims,
        Err(error) => return route_grant_rejection_response(error),
    };
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || {
        runtime.proxy_http(&cat_id, claims.cat_generation, &request)
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => {
            let message = format!("{error:#}");
            let status = if message.contains("cat is not active on this node") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_GATEWAY
            };
            (status, message).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ProxyWebSocketQuery {
    target_port: u16,
    route_epoch: i64,
    hostname: String,
    path: String,
}

trait ProxyIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyIo for T {}
type BoxProxyIo = Box<dyn ProxyIo>;
type GuestWebSocket = tokio_tungstenite::WebSocketStream<BoxProxyIo>;

async fn handle_proxy_websocket(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    Query(query): Query<ProxyWebSocketQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let route_grant = match headers
        .get("x-cats-route-grant")
        .and_then(|value| value.to_str().ok())
    {
        Some(route_grant) => route_grant,
        None => return (StatusCode::CONFLICT, "missing Endpoint Route Grant").into_response(),
    };
    let claims = match state.cfg.route_grant_verifier.verify(
        route_grant,
        crate::route_grant::ExpectedRouteGrant {
            hostname: &query.hostname,
            cat_id: &cat_id,
            node_id: &state.cfg.node.node_id,
            route_epoch: query.route_epoch,
            target_port: query.target_port,
        },
    ) {
        Ok(claims) => claims,
        Err(error) => return route_grant_rejection_response(error),
    };
    let forwarded = match decode_forwarded_headers(&headers) {
        Ok(headers) => headers,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let runtime = state.runtime.clone();
    let target_port = query.target_port;
    let opened = tokio::task::spawn_blocking(move || {
        runtime.open_proxy_target(&cat_id, claims.cat_generation, target_port)
    })
    .await;
    let (target, activity_guard) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(error)) => {
            let message = format!("{error:#}");
            let status = if message.contains("cat is not active on this node") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_GATEWAY
            };
            return (status, message).into_response();
        }
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    };
    let guest = match connect_guest_websocket(target, &query.path, forwarded).await {
        Ok(guest) => guest,
        Err(error) => return (StatusCode::BAD_GATEWAY, format!("{error:#}")).into_response(),
    };
    let selected_protocol = guest
        .1
        .headers()
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let upgrade = if let Some(protocol) = selected_protocol {
        ws.protocols([protocol])
    } else {
        ws
    };
    upgrade.on_upgrade(move |socket| bridge_endpoint_websocket(socket, guest.0, activity_guard))
}

fn decode_forwarded_headers(headers: &HeaderMap) -> Result<Vec<(String, String)>, String> {
    let encoded = headers
        .get("x-cats-forwarded-headers")
        .ok_or_else(|| "missing forwarded headers".to_string())?
        .to_str()
        .map_err(|_| "forwarded headers are not text".to_string())?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "forwarded headers are not valid base64".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "forwarded headers are not valid JSON".to_string())
}

async fn connect_guest_websocket(
    target: ProxyTarget,
    path: &str,
    forwarded: Vec<(String, String)>,
) -> anyhow::Result<(GuestWebSocket, axum::http::Response<Option<Vec<u8>>>)> {
    let request = build_guest_websocket_request(path, forwarded)?;
    let stream: BoxProxyIo = match target {
        ProxyTarget::Unix(path) => Box::new(
            tokio::net::UnixStream::connect(path)
                .await
                .context("connect guest WebSocket Unix socket")?,
        ),
        ProxyTarget::Tcp(address) => Box::new(
            tokio::net::TcpStream::connect(address)
                .await
                .with_context(|| format!("connect guest WebSocket {address}"))?,
        ),
    };
    tokio_tungstenite::client_async(request, stream)
        .await
        .context("guest WebSocket handshake")
}

fn build_guest_websocket_request(
    path: &str,
    forwarded: Vec<(String, String)>,
) -> anyhow::Result<axum::http::Request<()>> {
    anyhow::ensure!(path.starts_with('/'), "invalid WebSocket request path");
    let mut request = format!("ws://guest{path}")
        .into_client_request()
        .context("build guest WebSocket request")?;
    if let Some((_, host)) = forwarded
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-host"))
    {
        request.headers_mut().insert(
            header::HOST,
            HeaderValue::try_from(host).context("invalid forwarded host")?,
        );
    }
    for (name, value) in forwarded {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("sec-websocket-key")
            || name.eq_ignore_ascii_case("sec-websocket-version")
            || name.eq_ignore_ascii_case("sec-websocket-accept")
            || name.eq_ignore_ascii_case("sec-websocket-extensions")
        {
            continue;
        }
        let name = HeaderName::try_from(name).context("invalid forwarded header name")?;
        let value = HeaderValue::try_from(value).context("invalid forwarded header value")?;
        request.headers_mut().append(name, value);
    }
    Ok(request)
}

async fn bridge_endpoint_websocket(
    socket: WebSocket,
    guest: GuestWebSocket,
    _activity_guard: RuntimeActivityGuard,
) {
    let (mut client_sender, mut client_receiver) = socket.split();
    let (mut guest_sender, mut guest_receiver) = guest.split();
    loop {
        tokio::select! {
            incoming = client_receiver.next() => {
                let Some(Ok(message)) = incoming else { break };
                let message = match message {
                    Message::Text(data) => tokio_tungstenite::tungstenite::Message::Text(data.to_string().into()),
                    Message::Binary(data) => tokio_tungstenite::tungstenite::Message::Binary(data),
                    Message::Ping(data) => tokio_tungstenite::tungstenite::Message::Ping(data),
                    Message::Pong(data) => tokio_tungstenite::tungstenite::Message::Pong(data),
                    Message::Close(_) => tokio_tungstenite::tungstenite::Message::Close(None),
                };
                if guest_sender.send(message).await.is_err() {
                    break;
                }
            }
            outgoing = guest_receiver.next() => {
                let Some(Ok(message)) = outgoing else { break };
                let message = match message {
                    tokio_tungstenite::tungstenite::Message::Text(data) => Message::Text(data.to_string().into()),
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
        }
    }
    let _ = guest_sender
        .send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await;
}

pub fn router(state: NodeState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/jobs", post(handle_job))
        .route("/v1/cats/{id}/exec", post(handle_exec))
        .route("/v1/cats/{id}/oci-deployments", post(handle_deploy_oci))
        .route("/v1/cats/{id}/shell", get(handle_shell))
        .route("/v1/cats/{id}/proxy", post(handle_proxy))
        .route("/v1/cats/{id}/proxy-websocket", get(handle_proxy_websocket))
        .with_state(state)
}

#[cfg(test)]
mod proxy_websocket_tests {
    use super::build_guest_websocket_request;

    #[test]
    fn guest_handshake_uses_the_trusted_public_host() {
        let request = build_guest_websocket_request(
            "/socket?token=one",
            vec![
                (
                    "x-forwarded-host".to_string(),
                    "preview-123.cats.run".to_string(),
                ),
                (
                    "origin".to_string(),
                    "https://preview-123.cats.run".to_string(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(request.uri().path_and_query().unwrap(), "/socket?token=one");
        assert_eq!(request.headers()["host"], "preview-123.cats.run");
        assert_eq!(request.headers()["origin"], "https://preview-123.cats.run");
    }
}

#[cfg(test)]
mod usage_delivery_tests {
    use super::{deliver_usage_batches, UsageDeliveryState};
    use crate::usage_spool::UsageSpool;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use cats_api::metering::{CatUsageCheckpoint, IngestUsageCheckpointsRequest, UsageMetric};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[derive(Clone, Default)]
    struct MockIngestion {
        responses: Arc<Mutex<VecDeque<StatusCode>>>,
        requests: Arc<Mutex<Vec<Vec<String>>>>,
    }

    #[derive(Clone)]
    struct TimeoutSensitiveIngestion {
        max_checkpoints: usize,
        requests: Arc<Mutex<Vec<Vec<String>>>>,
        accepted: Arc<Mutex<Vec<String>>>,
    }

    async fn ingest(State(state): State<MockIngestion>, body: Bytes) -> StatusCode {
        let request: IngestUsageCheckpointsRequest = serde_json::from_slice(&body).unwrap();
        state.requests.lock().unwrap().push(
            request
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.event_id.clone())
                .collect(),
        );
        state
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(StatusCode::OK)
    }

    async fn ingest_with_size_dependent_timeout(
        State(state): State<TimeoutSensitiveIngestion>,
        body: Bytes,
    ) -> StatusCode {
        let request: IngestUsageCheckpointsRequest = serde_json::from_slice(&body).unwrap();
        let event_ids = request
            .checkpoints
            .iter()
            .map(|checkpoint| checkpoint.event_id.clone())
            .collect::<Vec<_>>();
        state.requests.lock().unwrap().push(event_ids.clone());
        if event_ids.len() > state.max_checkpoints {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        } else {
            state.accepted.lock().unwrap().extend(event_ids);
        }
        StatusCode::OK
    }

    /// Answers every request with one status and one body, for asserting what
    /// a rejection reason turns into on the node side.
    async fn spawn_rejecting_mock(
        status: StatusCode,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/", post(move || async move { (status, body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/"), server)
    }

    async fn spawn_mock(
        responses: impl IntoIterator<Item = StatusCode>,
    ) -> (String, MockIngestion, tokio::task::JoinHandle<()>) {
        let state = MockIngestion::default();
        state.responses.lock().unwrap().extend(responses);
        let app = Router::new()
            .route("/", post(ingest))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/"), state, server)
    }

    async fn spawn_timeout_sensitive_mock(
        max_checkpoints: usize,
    ) -> (
        String,
        TimeoutSensitiveIngestion,
        tokio::task::JoinHandle<()>,
    ) {
        let state = TimeoutSensitiveIngestion {
            max_checkpoints,
            requests: Arc::new(Mutex::new(Vec::new())),
            accepted: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route("/", post(ingest_with_size_dependent_timeout))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/"), state, server)
    }

    fn checkpoint(sequence: u64) -> CatUsageCheckpoint {
        CatUsageCheckpoint {
            event_id: format!("event-{sequence:02}"),
            source_id: "node/node-a/cat/cat-a".to_string(),
            source_epoch: "epoch-a".to_string(),
            sequence,
            observed_at_unix_ms: 1_000 + i64::try_from(sequence).unwrap(),
            cat_id: "cat-a".to_string(),
            cat_generation: 1,
            metric: UsageMetric::CpuUsec,
            cumulative_quantity: u128::from(sequence),
        }
    }

    fn spool_with(checkpoints: &[CatUsageCheckpoint]) -> (tempfile::TempDir, UsageSpool) {
        let directory = tempfile::tempdir().unwrap();
        let spool = UsageSpool::open(&directory.path().join("usage-spool.sqlite3")).unwrap();
        spool.enqueue(checkpoints).unwrap();
        (directory, spool)
    }

    #[tokio::test]
    async fn payload_too_large_retries_smaller_prefixes_without_replaying_the_large_batch() {
        let checkpoints = (0..8).map(checkpoint).collect::<Vec<_>>();
        let (_directory, spool) = spool_with(&checkpoints);
        let (endpoint, mock, server) = spawn_mock([StatusCode::PAYLOAD_TOO_LARGE]).await;
        let delivery = tokio::sync::Mutex::new(UsageDeliveryState::default());

        deliver_usage_batches(
            &reqwest::Client::new(),
            &endpoint,
            "token",
            "node-a",
            &spool,
            &delivery,
        )
        .await
        .unwrap();

        assert!(spool.is_empty().unwrap());
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.iter().map(Vec::len).collect::<Vec<_>>(), [8, 4, 4]);
        assert_eq!(
            requests[1],
            checkpoints[..4]
                .iter()
                .map(|c| c.event_id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            requests[2],
            checkpoints[4..]
                .iter()
                .map(|c| c.event_id.clone())
                .collect::<Vec<_>>()
        );
        server.abort();
    }

    #[tokio::test]
    async fn request_timeout_shrinks_batches_until_the_ordered_spool_recovers() {
        let checkpoints = (0..8).map(checkpoint).collect::<Vec<_>>();
        let expected = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.event_id.clone())
            .collect::<Vec<_>>();
        let (_directory, spool) = spool_with(&checkpoints);
        let (endpoint, mock, server) = spawn_timeout_sensitive_mock(2).await;
        let delivery = tokio::sync::Mutex::new(UsageDeliveryState::default());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();

        for _ in 0..12 {
            let _ = deliver_usage_batches(&client, &endpoint, "token", "node-a", &spool, &delivery)
                .await;
            if spool.is_empty().unwrap() {
                break;
            }
            delivery.lock().await.retry_not_before = Some(Instant::now());
        }

        assert!(
            spool.is_empty().unwrap(),
            "a size-dependent timeout must not wedge the queue head"
        );
        assert_eq!(
            *mock.accepted.lock().unwrap(),
            expected,
            "only accepted consecutive prefixes may be acknowledged"
        );
        let request_sizes = mock
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>();
        assert_eq!(request_sizes.first(), Some(&8));
        assert!(
            request_sizes.windows(2).any(|sizes| sizes[1] < sizes[0]),
            "a timeout must reduce a later request: {request_sizes:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn gateway_timeout_shrinks_the_next_batch_without_acknowledging_the_failed_one() {
        let checkpoints = (0..4).map(checkpoint).collect::<Vec<_>>();
        let (_directory, spool) = spool_with(&checkpoints);
        let (endpoint, mock, server) =
            spawn_mock([StatusCode::GATEWAY_TIMEOUT, StatusCode::OK, StatusCode::OK]).await;
        let delivery = tokio::sync::Mutex::new(UsageDeliveryState::default());
        let client = reqwest::Client::new();

        let error = deliver_usage_batches(&client, &endpoint, "token", "node-a", &spool, &delivery)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("504 Gateway Timeout"));
        assert_eq!(spool.len().unwrap(), 4);
        delivery.lock().await.retry_not_before = Some(Instant::now());

        deliver_usage_batches(&client, &endpoint, "token", "node-a", &spool, &delivery)
            .await
            .unwrap();

        assert!(spool.is_empty().unwrap());
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.iter().map(Vec::len).collect::<Vec<_>>(), [4, 2, 2]);
        assert_eq!(
            requests[0],
            checkpoints
                .iter()
                .map(|c| c.event_id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(requests[1], requests[0][..2]);
        assert_eq!(requests[2], requests[0][2..]);
        server.abort();
    }

    #[tokio::test]
    async fn bad_gateway_does_not_ack_and_retries_the_same_order_after_backoff() {
        let checkpoints = (0..3).map(checkpoint).collect::<Vec<_>>();
        let (_directory, spool) = spool_with(&checkpoints);
        let (endpoint, mock, server) = spawn_mock([StatusCode::BAD_GATEWAY, StatusCode::OK]).await;
        let delivery = tokio::sync::Mutex::new(UsageDeliveryState::default());
        let client = reqwest::Client::new();

        let error = deliver_usage_batches(&client, &endpoint, "token", "node-a", &spool, &delivery)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("502 Bad Gateway"));
        assert_eq!(spool.len().unwrap(), 3);

        let backed_off =
            deliver_usage_batches(&client, &endpoint, "token", "node-a", &spool, &delivery)
                .await
                .unwrap_err();
        assert!(backed_off.to_string().contains("backing off"));
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        {
            let mut state = delivery.lock().await;
            state.retry_not_before = Some(Instant::now());
        }

        deliver_usage_batches(&client, &endpoint, "token", "node-a", &spool, &delivery)
            .await
            .unwrap();
        assert!(spool.is_empty().unwrap());
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        server.abort();
    }

    #[tokio::test]
    async fn single_checkpoint_rejected_as_too_large_stays_at_the_queue_head() {
        let (_directory, spool) = spool_with(&[checkpoint(0)]);
        let (endpoint, mock, server) = spawn_mock([StatusCode::PAYLOAD_TOO_LARGE]).await;
        let delivery = tokio::sync::Mutex::new(UsageDeliveryState::default());

        let error = deliver_usage_batches(
            &reqwest::Client::new(),
            &endpoint,
            "token",
            "node-a",
            &spool,
            &delivery,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("queue head was retained"));
        assert_eq!(spool.len().unwrap(), 1);
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        server.abort();
    }

    /// A rejection must say what was rejected and why.
    ///
    /// The status alone was logged and the response body discarded, so a
    /// poisoned batch read as a bare "returned 409 Conflict" -- which named
    /// neither the offending checkpoint nor the reason, and left diagnosis to
    /// guesswork against a live cluster.
    #[tokio::test]
    async fn a_rejection_carries_the_control_planes_reason() {
        let (_directory, spool) = spool_with(&[checkpoint(0)]);
        let (endpoint, server) = spawn_rejecting_mock(
            StatusCode::CONFLICT,
            r#"{"code":"conflict","message":"node node-a does not own Cat cat-a"}"#,
        )
        .await;
        let delivery = tokio::sync::Mutex::new(UsageDeliveryState::default());

        let error = deliver_usage_batches(
            &reqwest::Client::new(),
            &endpoint,
            "token",
            "node-a",
            &spool,
            &delivery,
        )
        .await
        .unwrap_err();
        let reported = format!("{error:#}");
        assert!(
            reported.contains("does not own Cat cat-a"),
            "the reason must reach the operator, got: {reported}"
        );
        assert!(reported.contains("409"), "the status is still useful");
        // A rejected batch is retained: discarding usage is a separate,
        // deliberate decision and must never be a side effect of a bad reply.
        assert_eq!(spool.len().unwrap(), 1);
        server.abort();
    }
}

#[derive(Clone, Copy)]
struct CpuTimes {
    total: u64,
    idle: u64,
}

fn parse_cpu_times(contents: &str) -> Option<CpuTimes> {
    let mut fields = contents
        .lines()
        .find(|line| line.starts_with("cpu "))?
        .split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let values = fields
        .take(8)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }
    let total = values.iter().copied().sum();
    let idle = values[3].saturating_add(values.get(4).copied().unwrap_or(0));
    Some(CpuTimes { total, idle })
}

fn cpu_usage_percent(previous: CpuTimes, current: CpuTimes) -> Option<f64> {
    let total = current.total.checked_sub(previous.total)?;
    if total == 0 {
        return None;
    }
    let idle = current.idle.saturating_sub(previous.idle).min(total);
    Some((((total - idle) as f64 / total as f64) * 100.0).clamp(0.0, 100.0))
}

fn process_cpu_usage_cores(
    previous_ticks: u64,
    current_ticks: u64,
    host_interval_ticks: u64,
    logical_cpus: u32,
) -> Option<f64> {
    if host_interval_ticks == 0 || logical_cpus == 0 {
        return None;
    }
    let process_delta = current_ticks.checked_sub(previous_ticks)?;
    Some(process_delta as f64 / host_interval_ticks as f64 * f64::from(logical_cpus))
}

fn parse_memory_mib(contents: &str) -> (Option<u64>, Option<u64>) {
    let mut total = None;
    let mut available = None;
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next();
        let value = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .map(|kib| kib / 1024);
        match key {
            Some("MemTotal:") => total = value,
            Some("MemAvailable:") => available = value,
            _ => {}
        }
    }
    (total, available)
}

fn filesystem_capacity(path: &FsPath) -> Option<(u64, u64)> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stats = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a valid NUL-terminated C string and `stats` points to
    // writable storage for one `statvfs` value. A zero return initializes it.
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: statvfs returned zero, so it initialized the output structure.
    let stats = unsafe { stats.assume_init() };
    let block_size = stats.f_frsize;
    // The statvfs block counters are 32-bit on some platforms and 64-bit on
    // others, so the cast is redundant on Linux but required elsewhere.
    #[allow(clippy::unnecessary_cast)]
    Some((
        (stats.f_blocks as u64).saturating_mul(block_size),
        (stats.f_bavail as u64).saturating_mul(block_size),
    ))
}

fn parse_process_cpu_ticks(contents: &str) -> Option<u64> {
    // `/proc/<pid>/stat` wraps comm in parentheses and it may contain spaces.
    // Fields after the final ')' start at process-state (field 3); utime and
    // stime are fields 14 and 15.
    let fields: Vec<&str> = contents
        .get(contents.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    let user = fields.get(11)?.parse::<u64>().ok()?;
    let system = fields.get(12)?.parse::<u64>().ok()?;
    Some(user.saturating_add(system))
}

fn parse_process_rss_bytes(contents: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "VmRSS:" {
            return None;
        }
        fields
            .next()?
            .parse::<u64>()
            .ok()
            .map(|kib| kib.saturating_mul(1024))
    })
}

fn process_usage(process_ids: &[u32]) -> (Option<u64>, Option<u64>) {
    if process_ids.is_empty() {
        return (Some(0), Some(0));
    }
    let mut cpu_ticks = 0_u64;
    let mut rss_bytes = 0_u64;
    for process_id in process_ids {
        let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat"))
            .ok()
            .and_then(|contents| parse_process_cpu_ticks(&contents));
        let rss = std::fs::read_to_string(format!("/proc/{process_id}/status"))
            .ok()
            .and_then(|contents| parse_process_rss_bytes(&contents));
        let (Some(stat), Some(rss)) = (stat, rss) else {
            return (None, None);
        };
        cpu_ticks = cpu_ticks.saturating_add(stat);
        rss_bytes = rss_bytes.saturating_add(rss);
    }
    (Some(cpu_ticks), Some(rss_bytes))
}

fn parse_cgroup_cpu_usage_usec(contents: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "usage_usec" {
            return None;
        }
        fields.next()?.parse().ok()
    })
}

fn read_cgroup_usage(path: &FsPath) -> Option<(u64, u64)> {
    let cpu_usage_usec = std::fs::read_to_string(path.join("cpu.stat"))
        .ok()
        .and_then(|contents| parse_cgroup_cpu_usage_usec(&contents))?;
    let memory_current_bytes = std::fs::read_to_string(path.join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some((cpu_usage_usec, memory_current_bytes))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

struct CatCpuSample {
    process_ids: Vec<u32>,
    cpu_ticks: u64,
}

struct CatDiskSample {
    sampled_at: Instant,
    used_bytes: u64,
}

struct CatMeterSample {
    source_epoch: String,
    generation: i64,
    accumulator: RuntimeMeterAccumulator,
    last_checkpoint_at: Option<Instant>,
    failed: bool,
}

struct HostTelemetrySampler {
    node_id: String,
    previous_cpu: Option<CpuTimes>,
    previous_cat_cpu: HashMap<String, CatCpuSample>,
    cat_disk_samples: HashMap<String, CatDiskSample>,
    cat_meter_samples: HashMap<String, CatMeterSample>,
    /// Last finalized epoch per Cat. A heartbeat can capture its target
    /// immediately before a lifecycle transition; rejecting that stale target
    /// prevents it from reopening a retired billing stream.
    retired_meter_epochs: HashMap<String, String>,
    disk_path: PathBuf,
}

impl HostTelemetrySampler {
    fn new(node_id: String, disk_path: PathBuf) -> Self {
        Self {
            node_id,
            previous_cpu: std::fs::read_to_string("/proc/stat")
                .ok()
                .and_then(|contents| parse_cpu_times(&contents)),
            previous_cat_cpu: HashMap::new(),
            cat_disk_samples: HashMap::new(),
            cat_meter_samples: HashMap::new(),
            retired_meter_epochs: HashMap::new(),
            disk_path,
        }
    }

    fn sample(
        &mut self,
        mut telemetry: NodeTelemetry,
        targets: Vec<CatTelemetryTarget>,
    ) -> (NodeTelemetry, Vec<CatUsageCheckpoint>) {
        let logical_cpus = std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok());
        telemetry.host_logical_cpus = logical_cpus;
        telemetry.load_average_1m = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|contents| contents.split_whitespace().next()?.parse().ok());

        let current_cpu = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|contents| parse_cpu_times(&contents));
        let host_interval_ticks =
            self.previous_cpu
                .zip(current_cpu)
                .and_then(|(previous, current)| {
                    current
                        .total
                        .checked_sub(previous.total)
                        .filter(|value| *value > 0)
                });
        if let Some(current) = current_cpu {
            telemetry.host_cpu_usage_percent = self
                .previous_cpu
                .and_then(|previous| cpu_usage_percent(previous, current));
            self.previous_cpu = Some(current);
        }

        if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
            (
                telemetry.host_memory_total_mib,
                telemetry.host_memory_available_mib,
            ) = parse_memory_mib(&contents);
        }
        if let Some((total, available)) = filesystem_capacity(&self.disk_path) {
            telemetry.host_disk_total_bytes = Some(total);
            telemetry.host_disk_available_bytes = Some(available);
        }

        let now = Instant::now();
        let observed_at_unix_ms = now_unix_ms();
        let mut usage_checkpoints = Vec::new();
        for target in &targets {
            match self.sample_usage_target(target, now, observed_at_unix_ms, false) {
                Ok(checkpoints) => usage_checkpoints.extend(checkpoints),
                Err(error) => {
                    tracing::error!(
                        cat = %target.cat_id,
                        error = format!("{error:#}"),
                        "authoritative billing sample failed closed until a new runtime epoch"
                    );
                }
            }
        }
        let mut current_cat_cpu = HashMap::new();
        telemetry.cat_resources = targets
            .into_iter()
            .map(|mut target| {
                target.process_ids.sort_unstable();
                let (cpu_ticks, memory_rss_bytes) = process_usage(&target.process_ids);
                let cpu_usage_cores = cpu_ticks.and_then(|ticks| {
                    let previous = self.previous_cat_cpu.get(&target.cat_id)?;
                    if previous.process_ids != target.process_ids {
                        return None;
                    }
                    let host_delta = host_interval_ticks?;
                    process_cpu_usage_cores(previous.cpu_ticks, ticks, host_delta, logical_cpus?)
                });
                if let Some(ticks) = cpu_ticks {
                    current_cat_cpu.insert(
                        target.cat_id.clone(),
                        CatCpuSample {
                            process_ids: target.process_ids,
                            cpu_ticks: ticks,
                        },
                    );
                }

                let host_disk_used_bytes = match self.cat_disk_samples.get(&target.cat_id) {
                    Some(sample)
                        if now.duration_since(sample.sampled_at) < Duration::from_secs(5) =>
                    {
                        Some(sample.used_bytes)
                    }
                    _ => allocated_tree_bytes(&target.runtime_dir).inspect(|used_bytes| {
                        self.cat_disk_samples.insert(
                            target.cat_id.clone(),
                            CatDiskSample {
                                sampled_at: now,
                                used_bytes: *used_bytes,
                            },
                        );
                    }),
                };
                CatResourceTelemetry {
                    cat_id: target.cat_id,
                    cpu_usage_cores,
                    memory_rss_bytes,
                    host_disk_used_bytes,
                    disk_durability: target.disk_durability,
                }
            })
            .collect();
        self.previous_cat_cpu = current_cat_cpu;
        self.cat_disk_samples.retain(|cat_id, _| {
            telemetry
                .cat_resources
                .iter()
                .any(|item| &item.cat_id == cat_id)
        });
        // A lifecycle job removes its runtime from the supervisor map while it
        // performs finalization and teardown. A concurrent heartbeat can
        // therefore observe the Cat as temporarily absent even though a
        // failed teardown will put the same runtime and source epoch back.
        // Dropping either entry here would reopen that epoch at sequence zero.
        // Finalization removes the live accumulator explicitly; a later,
        // genuinely new epoch replaces the retired marker below.
        (telemetry, usage_checkpoints)
    }

    fn finalize(&mut self, target: &CatTelemetryTarget) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
        let checkpoints = self.sample_usage_target(target, Instant::now(), now_unix_ms(), true)?;
        if let Some(metering) = &target.metering {
            self.retired_meter_epochs
                .insert(target.cat_id.clone(), metering.source_epoch.clone());
        }
        self.cat_meter_samples.remove(&target.cat_id);
        Ok(checkpoints)
    }

    fn sample_usage_target(
        &mut self,
        target: &CatTelemetryTarget,
        now: Instant,
        observed_at_unix_ms: i64,
        force_checkpoint: bool,
    ) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
        let Some(metering) = &target.metering else {
            return Ok(Vec::new());
        };
        if let Some(retired_epoch) = self.retired_meter_epochs.get(&target.cat_id) {
            if retired_epoch == &metering.source_epoch {
                return Ok(Vec::new());
            }
            self.retired_meter_epochs.remove(&target.cat_id);
        }
        let replace = self
            .cat_meter_samples
            .get(&target.cat_id)
            .is_none_or(|sample| {
                sample.source_epoch != metering.source_epoch
                    || sample.generation != target.generation
            });
        if replace {
            let accumulator = RuntimeMeterAccumulator::new(
                format!("node/{}/cat/{}", self.node_id, target.cat_id),
                metering.source_epoch.clone(),
                target.cat_id.clone(),
                target.generation,
            )?;
            self.cat_meter_samples.insert(
                target.cat_id.clone(),
                CatMeterSample {
                    source_epoch: metering.source_epoch.clone(),
                    generation: target.generation,
                    accumulator,
                    last_checkpoint_at: None,
                    failed: false,
                },
            );
        }
        let sample = self
            .cat_meter_samples
            .get_mut(&target.cat_id)
            .context("meter sample disappeared during observation")?;
        if sample.failed {
            bail!("meter sample previously failed");
        }
        let Some((cpu_usage_usec, memory_current_bytes)) = read_cgroup_usage(&metering.cgroup_path)
        else {
            sample.failed = true;
            bail!(
                "authoritative cgroup sample unavailable at {}",
                metering.cgroup_path.display()
            );
        };
        if sample
            .accumulator
            .last_observed_at_unix_ms()
            .is_none_or(|last| observed_at_unix_ms > last)
        {
            if let Err(error) = sample.accumulator.observe(
                observed_at_unix_ms,
                cpu_usage_usec,
                memory_current_bytes,
            ) {
                sample.failed = true;
                return Err(error.into());
            }
        }
        let due = force_checkpoint
            || sample
                .last_checkpoint_at
                .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10));
        if !due {
            return Ok(Vec::new());
        }
        match sample.accumulator.checkpoint() {
            Ok(checkpoints) => {
                sample.last_checkpoint_at = Some(now);
                Ok(checkpoints.into())
            }
            Err(error) => {
                sample.failed = true;
                Err(error.into())
            }
        }
    }
}

struct UsageMeteringPipeline {
    sampler: Mutex<HostTelemetrySampler>,
    spool: UsageSpool,
    unspooled: Mutex<Vec<CatUsageCheckpoint>>,
    delivery: tokio::sync::Mutex<UsageDeliveryState>,
    /// Asks the uploader to attempt a drain now instead of at its next tick.
    ///
    /// A hint, never a dependency: nothing waits on the result, so a caller can
    /// nudge delivery without inheriting its latency or its failures.
    delivery_wake: tokio::sync::Notify,
}

impl UsageMeteringPipeline {
    fn open(node_id: String, state_dir: PathBuf) -> anyhow::Result<Self> {
        let spool = UsageSpool::open(&state_dir.join("usage-spool.sqlite3"))?;
        Ok(Self {
            sampler: Mutex::new(HostTelemetrySampler::new(node_id, state_dir)),
            spool,
            unspooled: Mutex::new(Vec::new()),
            delivery: tokio::sync::Mutex::new(UsageDeliveryState::default()),
            delivery_wake: tokio::sync::Notify::new(),
        })
    }

    fn wake_delivery(&self) {
        self.delivery_wake.notify_one();
    }

    fn sample(
        &self,
        telemetry: NodeTelemetry,
        targets: Vec<CatTelemetryTarget>,
    ) -> (NodeTelemetry, anyhow::Result<()>) {
        let (telemetry, checkpoints) = self.sampler.lock().unwrap().sample(telemetry, targets);
        (telemetry, self.persist(checkpoints))
    }

    fn persist(&self, checkpoints: Vec<CatUsageCheckpoint>) -> anyhow::Result<()> {
        let mut unspooled = self.unspooled.lock().unwrap();
        unspooled.extend(checkpoints);
        if unspooled.len() > 20_000 {
            *unspooled = compact_pending_checkpoints(std::mem::take(&mut *unspooled));
        }
        self.spool.enqueue(&unspooled)?;
        unspooled.clear();
        Ok(())
    }
}

impl UsageFinalizer for UsageMeteringPipeline {
    fn finalize(&self, target: CatTelemetryTarget) -> anyhow::Result<()> {
        let checkpoints = self.sampler.lock().unwrap().finalize(&target)?;
        self.persist(checkpoints)
    }
}

fn compact_pending_checkpoints(checkpoints: Vec<CatUsageCheckpoint>) -> Vec<CatUsageCheckpoint> {
    let mut streams =
        HashMap::<(String, String, UsageMetric), (CatUsageCheckpoint, CatUsageCheckpoint)>::new();
    for checkpoint in checkpoints {
        let key = (
            checkpoint.source_id.clone(),
            checkpoint.source_epoch.clone(),
            checkpoint.metric,
        );
        streams
            .entry(key)
            .and_modify(|(first, last)| {
                if checkpoint.sequence < first.sequence {
                    *first = checkpoint.clone();
                }
                if checkpoint.sequence > last.sequence {
                    *last = checkpoint.clone();
                }
            })
            .or_insert_with(|| (checkpoint.clone(), checkpoint));
    }
    let mut compacted = Vec::with_capacity(streams.len() * 2);
    for (_, (first, last)) in streams {
        let one = first.event_id == last.event_id;
        compacted.push(first);
        if !one {
            compacted.push(last);
        }
    }
    compacted.sort_by(|left, right| {
        (
            left.observed_at_unix_ms,
            left.source_id.as_str(),
            left.source_epoch.as_str(),
            left.metric.slug(),
            left.sequence,
        )
            .cmp(&(
                right.observed_at_unix_ms,
                right.source_id.as_str(),
                right.source_epoch.as_str(),
                right.metric.slug(),
                right.sequence,
            ))
    });
    compacted
}

/// One operator-readable line naming every Cat adoption refused, and why.
fn residue_summary(residue: &[(String, String)]) -> String {
    if residue.is_empty() {
        return "none".to_string();
    }
    residue
        .iter()
        .map(|(cat_id, reason)| format!("{cat_id}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn sample_usage(state: &NodeState, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let (_, persisted) = state
            .usage_pipeline
            .sample(state.runtime.telemetry(), state.runtime.telemetry_targets());
        if let Err(error) = persisted {
            tracing::error!(
                %error,
                "usage checkpoints are not durable; billing remains failed closed"
            );
        }
    }
}

/// Start the Node only after its exact pending registration has produced a
/// validated and durable AgentSession. No runtime gate or listener opens first.
pub async fn spawn(cfg: ServerConfig) -> anyhow::Result<Handle> {
    anyhow::ensure!(cfg.heartbeat_ms > 0, "heartbeat interval must be positive");
    anyhow::ensure!(
        cfg.node.metering_cgroup_root.is_none() || cfg.heartbeat_ms <= 1_000,
        "authoritative billing requires a heartbeat/sample interval of at most 1000ms"
    );
    anyhow::ensure!(
        cfg.node.node_id == cfg.agent_registration.identity().node_id.as_str(),
        "Node runtime identity does not match the installed NodeIdentity"
    );
    anyhow::ensure!(
        cfg.node.state_dir == cfg.agent_registration.state_path(),
        "Node runtime state path does not match the installed NodeIdentity"
    );
    let agent_session = Arc::new(
        cfg.agent_registration
            .register_until_session(&cfg.control_plane_url)
            .await
            .context("establish durable Agent session")?,
    );
    crate::runtime::initialize_metering_cgroup(&cfg.node)?;
    let usage_pipeline = Arc::new(UsageMeteringPipeline::open(
        cfg.node.node_id.clone(),
        cfg.node.state_dir.clone(),
    )?);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let cfg = Arc::new(cfg);
    let runtime =
        Arc::new(NodeRuntime::new(cfg.node.clone())?.with_usage_finalizer(usage_pipeline.clone()));

    // Rebuild the V1 local inventory before serving anything and before
    // announcing this node. The control plane recovers a Lost node only
    // from a heartbeat carrying every non-deleting claim at its claimed
    // generation, so the first heartbeat has to already know what this node is
    // running. Adoption probes /proc, Unix sockets and directories, so it runs
    // off the async executor.
    let adopting = runtime.clone();
    let adoption = tokio::task::spawn_blocking(move || adopting.adopt_from_ledger())
        .await
        .context("scan the node runtime ledger")?;
    tracing::info!(
        node = %cfg.node.node_id,
        adopted = adoption.adopted.len(),
        residue = adoption.residue.len(),
        not_adopted = %residue_summary(&adoption.residue),
        "rebuilt the node runtime inventory from the ledger"
    );

    // Then reclaim what is provably dead, still before the agent is reachable
    // and can be given a StartCat: allocation is the next thing to touch these
    // devices, and one the kernel still has connected to a dead server cannot
    // serve a Guest (issue #79). Deliberately after adoption -- what this node
    // is still running is decided there, and the sweep should never be in a
    // position to disconnect a device belonging to a Cat just proven alive.
    // Runs `nbd-client` and waits for the kernel to settle, so like the scan
    // above it stays off the async executor.
    let sweeping = runtime.clone();
    tokio::task::spawn_blocking(move || sweeping.reclaim_leaked_block_devices())
        .await
        .context("sweep leaked kernel NBD devices")?;

    // Same shape for the per-Cat runtime directories, and for the same reason:
    // nothing reclaimed them, so the local medium only filled (issue #99). Also
    // after adoption -- what this node still supervises is decided there, and
    // the sweep must never be in a position to delete state belonging to a Cat
    // just proven alive.
    let residue_sweeping = runtime.clone();
    tokio::task::spawn_blocking(move || residue_sweeping.sweep_runtime_residue())
        .await
        .context("sweep abandoned per-Cat runtime directories")?;

    let state = NodeState {
        runtime: runtime.clone(),
        cfg: cfg.clone(),
        client: client.clone(),
        usage_pipeline: usage_pipeline.clone(),
        agent_session,
    };

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = router(state.clone());
    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("node agent server exited: {e}");
        }
    });

    let cp = cfg.control_plane_url.trim_end_matches('/').to_string();
    let token = cfg.auth_token.clone();

    let sampling_state = state.clone();
    let sampling_interval = Duration::from_millis(cfg.heartbeat_ms);
    let telemetry_sampler =
        tokio::spawn(async move { sample_usage(&sampling_state, sampling_interval).await });

    // Usage upload: its own channel, best effort. It may be slow, it may fail,
    // it may back off for a minute -- none of that is allowed to reach liveness
    // or a lifecycle result. Durability comes from the spool it drains, so a
    // deferred upload costs delay, not data. One task keeps deliveries ordered,
    // which is the only reason the old shared lane existed.
    let usage_state = state.clone();
    let usage_uploader = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = usage_state.usage_pipeline.delivery_wake.notified() => {}
                _ = tokio::time::sleep(USAGE_DELIVERY_INTERVAL) => {}
            }
            if let Err(error) = usage_state.deliver_pending_usage().await {
                // Alternate Display prints the whole context chain. Plain `%error`
                // shows only the outermost `.context(...)`, which hid the actual
                // transport or status failure behind "send durable usage
                // checkpoints" and made this undiagnosable from logs alone.
                tracing::warn!(
                    error = format!("{error:#}"),
                    "durable usage checkpoint delivery deferred"
                );
            }
        }
    });

    // Runtime-directory residue: reclaim, then report what had to stay. A
    // teardown fails while the agent is up, not only across a restart, so a
    // boot-only sweep would hold those bytes until someone restarted the agent
    // -- and the telemetry behind it would age into fiction meanwhile.
    let residue_state = state.clone();
    let residue_sweeper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(RUNTIME_RESIDUE_SWEEP_INTERVAL).await;
            let runtime = residue_state.runtime.clone();
            // Walks the state directory and probes Unix sockets, so it stays
            // off the async executor like every other filesystem pass here.
            if let Err(error) =
                tokio::task::spawn_blocking(move || runtime.sweep_runtime_residue()).await
            {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "runtime-directory sweep did not run"
                );
            }
        }
    });

    // One long-poll watcher per Running Cat. Lease changes are pushed to the
    // control plane immediately; the 1s timeout refreshes source freshness
    // and repairs a lost event without high-rate polling.
    let watch_state = state.clone();
    let watch_client = client.clone();
    let watch_cp = cp.clone();
    let watch_token = token.clone();
    let watch_node_id = cfg.node.node_id.clone();
    let activity_watchers = tokio::spawn(async move {
        let mut watchers: HashMap<(String, i64), tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            let targets = watch_state.runtime.activity_targets();
            let wanted: HashSet<(String, i64)> = targets
                .iter()
                .map(|(cat_id, generation, _)| (cat_id.clone(), *generation))
                .collect();
            watchers.retain(|key, task| {
                if wanted.contains(key) {
                    true
                } else {
                    task.abort();
                    false
                }
            });
            for (cat_id, generation, conn) in targets {
                let key = (cat_id.clone(), generation);
                watchers.entry(key).or_insert_with(|| {
                    tokio::spawn(watch_guest_work(
                        watch_client.clone(),
                        watch_cp.clone(),
                        watch_token.clone(),
                        watch_node_id.clone(),
                        cat_id,
                        generation,
                        conn,
                    ))
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    Ok(Handle {
        addr,
        state,
        tasks: vec![
            server,
            telemetry_sampler,
            usage_uploader,
            residue_sweeper,
            activity_watchers,
        ],
    })
}

#[cfg(test)]
mod route_grant_rejection_tests {
    use super::*;

    #[test]
    fn natural_expiry_is_machine_readable_but_other_rejections_are_not() {
        let expired = route_grant_rejection_response(
            crate::route_grant::RouteGrantVerificationError::Expired,
        );
        assert_eq!(expired.status(), StatusCode::CONFLICT);
        assert_eq!(
            expired.headers().get(ROUTE_GRANT_REJECTION_HEADER).unwrap(),
            ROUTE_GRANT_REJECTION_EXPIRED
        );

        let invalid = route_grant_rejection_response(
            crate::route_grant::RouteGrantVerificationError::Invalid(anyhow::anyhow!(
                "signature mismatch"
            )),
        );
        assert_eq!(invalid.status(), StatusCode::CONFLICT);
        assert!(invalid
            .headers()
            .get(ROUTE_GRANT_REJECTION_HEADER)
            .is_none());
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::{
        compact_pending_checkpoints, cpu_usage_percent, filesystem_capacity, now_unix_ms,
        parse_cgroup_cpu_usage_usec, parse_cpu_times, parse_memory_mib, parse_process_cpu_ticks,
        parse_process_rss_bytes, process_cpu_usage_cores, read_cgroup_usage, HostTelemetrySampler,
    };
    use crate::runtime::{CatMeteringTarget, CatTelemetryTarget};
    use cats_api::metering::{CatUsageCheckpoint, UsageMetric};
    use cats_api::resources::NodeTelemetry;
    use cats_metering::deterministic_event_id;
    use std::time::Instant;

    #[test]
    fn parses_cpu_and_calculates_interval_usage() {
        let previous = parse_cpu_times("cpu  100 0 50 800 50 0 0 0 0 0\n").unwrap();
        let current = parse_cpu_times("cpu  130 0 70 850 50 0 0 0 0 0\n").unwrap();
        let usage = cpu_usage_percent(previous, current).unwrap();
        assert!((usage - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parses_linux_memory_values_as_mib() {
        let (total, available) = parse_memory_mib(
            "MemTotal:       197659444 kB\nMemFree: 100 kB\nMemAvailable: 70158328 kB\n",
        );
        assert_eq!(total, Some(193_026));
        assert_eq!(available, Some(68_513));
    }

    #[test]
    fn calculates_process_cpu_as_consumed_logical_cores() {
        let cores = process_cpu_usage_cores(100, 150, 400, 8).unwrap();
        assert!((cores - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reads_capacity_for_an_existing_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let (total, available) = filesystem_capacity(temp.path()).unwrap();
        assert!(total > 0);
        assert!(available <= total);
    }

    #[test]
    fn parses_process_cpu_and_rss() {
        let stat = "123 (cloud hypervisor) S 1 2 3 4 5 6 7 8 9 10 20 7 0 0 0";
        assert_eq!(parse_process_cpu_ticks(stat), Some(27));
        assert_eq!(
            parse_process_rss_bytes("Name:\tcloud-hypervisor\nVmRSS:\t  1234 kB\n"),
            Some(1_263_616)
        );
    }

    #[test]
    fn reads_authoritative_cgroup_v2_cpu_and_memory_counters() {
        assert_eq!(
            parse_cgroup_cpu_usage_usec("usage_usec 12345\nuser_usec 10000\nsystem_usec 2345\n"),
            Some(12_345)
        );
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("cpu.stat"),
            "usage_usec 12345\nuser_usec 10000\nsystem_usec 2345\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("memory.current"), "987654\n").unwrap();
        assert_eq!(read_cgroup_usage(temp.path()), Some((12_345, 987_654)));
    }

    #[test]
    fn pending_checkpoint_compaction_keeps_baseline_and_latest_cumulative_value() {
        let checkpoints = (0..3)
            .map(|sequence| {
                let mut checkpoint = CatUsageCheckpoint {
                    event_id: String::new(),
                    source_id: "node/node-a/cat/cat-a".to_string(),
                    source_epoch: "epoch-a".to_string(),
                    sequence,
                    observed_at_unix_ms: 1_000 + i64::try_from(sequence).unwrap() * 10_000,
                    cat_id: "cat-a".to_string(),
                    cat_generation: 1,
                    metric: UsageMetric::CpuUsec,
                    cumulative_quantity: u128::from(sequence) * 100,
                };
                checkpoint.event_id = deterministic_event_id(&checkpoint);
                checkpoint
            })
            .collect();
        let compacted = compact_pending_checkpoints(checkpoints);
        assert_eq!(compacted.len(), 2);
        assert_eq!(compacted[0].sequence, 0);
        assert_eq!(compacted[1].sequence, 2);
    }

    #[test]
    fn lifecycle_finalization_emits_and_retires_the_latest_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let cgroup = temp.path().join("metering");
        std::fs::create_dir(&cgroup).unwrap();
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 100\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "1000\n").unwrap();
        let target = CatTelemetryTarget {
            cat_id: "cat-a".to_string(),
            generation: 1,
            process_ids: Vec::new(),
            runtime_dir: temp.path().to_path_buf(),
            metering: Some(CatMeteringTarget {
                cgroup_path: cgroup.clone(),
                source_epoch: "epoch-a".to_string(),
            }),
            disk_durability: Vec::new(),
        };
        let mut sampler =
            HostTelemetrySampler::new("node-a".to_string(), temp.path().to_path_buf());
        let baseline = sampler
            .sample_usage_target(&target, Instant::now(), now_unix_ms(), false)
            .unwrap();
        assert_eq!(baseline.len(), 2);
        assert!(baseline.iter().all(|checkpoint| checkpoint.sequence == 0));

        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 200\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "2000\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let final_checkpoints = sampler.finalize(&target).unwrap();
        assert_eq!(final_checkpoints.len(), 2);
        assert!(final_checkpoints
            .iter()
            .all(|checkpoint| checkpoint.sequence == 1));
        assert_eq!(
            final_checkpoints
                .iter()
                .find(|checkpoint| checkpoint.metric == UsageMetric::CpuUsec)
                .unwrap()
                .cumulative_quantity,
            200
        );
        assert!(!sampler.cat_meter_samples.contains_key("cat-a"));

        // A heartbeat that captured the old target before finalization must
        // not reopen the retired epoch or emit post-Warm usage.
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 300\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "3000\n").unwrap();
        let stale = sampler
            .sample_usage_target(&target, Instant::now(), now_unix_ms(), false)
            .unwrap();
        assert!(stale.is_empty());
        assert!(!sampler.cat_meter_samples.contains_key("cat-a"));

        // A restore creates a fresh epoch and is sampled normally.
        let mut restored = target.clone();
        restored.generation = 2;
        restored.metering.as_mut().unwrap().source_epoch = "epoch-b".to_string();
        let restored_baseline = sampler
            .sample_usage_target(&restored, Instant::now(), now_unix_ms(), false)
            .unwrap();
        assert_eq!(restored_baseline.len(), 2);
        assert!(restored_baseline
            .iter()
            .all(|checkpoint| checkpoint.sequence == 0));
    }

    #[test]
    fn transient_runtime_absence_does_not_reopen_a_metering_epoch() {
        let temp = tempfile::tempdir().unwrap();
        let cgroup = temp.path().join("metering");
        std::fs::create_dir(&cgroup).unwrap();
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 100\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "1000\n").unwrap();
        let target = CatTelemetryTarget {
            cat_id: "cat-a".to_string(),
            generation: 1,
            process_ids: Vec::new(),
            runtime_dir: temp.path().to_path_buf(),
            metering: Some(CatMeteringTarget {
                cgroup_path: cgroup.clone(),
                source_epoch: "epoch-a".to_string(),
            }),
            disk_durability: Vec::new(),
        };
        let mut sampler =
            HostTelemetrySampler::new("node-a".to_string(), temp.path().to_path_buf());
        let baseline = sampler
            .sample_usage_target(&target, Instant::now(), now_unix_ms(), false)
            .unwrap();
        assert!(baseline.iter().all(|checkpoint| checkpoint.sequence == 0));

        // stop_cat removes a runtime before finalizing it. A heartbeat can
        // sample the empty supervisor map in that window.
        let _ = sampler.sample(NodeTelemetry::default(), Vec::new());

        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 200\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "2000\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let final_checkpoints = sampler.finalize(&target).unwrap();
        assert!(final_checkpoints
            .iter()
            .all(|checkpoint| checkpoint.sequence == 1));

        // A failed teardown may reinsert the same runtime. Even another empty
        // heartbeat must not erase the retired-epoch fence.
        let _ = sampler.sample(NodeTelemetry::default(), Vec::new());
        let stale = sampler
            .sample_usage_target(&target, Instant::now(), now_unix_ms(), false)
            .unwrap();
        assert!(stale.is_empty());
    }
}

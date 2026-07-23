//! Node agent HTTP surface + registration/heartbeat loops.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};

use cats_api::guest::GuestShellFrame;
use cats_api::nodejob::NodeJob;
use cats_api::requests::{
    ExecRequest, ExecResponse, HeartbeatCat, HeartbeatRequest, NodeWorkStatusRequest,
    ProxyHttpRequest, RegisterNodeRequest, ShellClientControl, ShellServerControl,
    MAX_SHELL_MESSAGE_BYTES,
};
use cats_api::resources::NodeTelemetry;
use cats_storage::MetadataStore;

use crate::guest_client::GuestShell;
use crate::runtime::{GuestConn, NodeConfig, NodeRuntime, RuntimeActivityGuard};

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
    /// URL other components use to reach this node. Required when `listen`
    /// uses a wildcard address such as `0.0.0.0:7301`.
    pub advertise_url: Option<String>,
    pub control_plane_url: String,
    pub auth_token: String,
    pub gateway_url: String,
    pub cpus: u32,
    pub memory_mib: u64,
    pub heartbeat_ms: u64,
    pub node: NodeConfig,
    pub storage_meta: Arc<dyn MetadataStore>,
}

#[derive(Clone)]
pub struct NodeState {
    pub runtime: Arc<NodeRuntime>,
    pub cfg: Arc<ServerConfig>,
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
    let result = tokio::task::spawn_blocking(move || runtime.exec(&cat_id, req.command)).await;
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
async fn handle_proxy(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProxyHttpRequest>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || runtime.proxy_http(&cat_id, &request)).await;
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

pub fn router(state: NodeState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/jobs", post(handle_job))
        .route("/v1/cats/{id}/exec", post(handle_exec))
        .route("/v1/cats/{id}/shell", get(handle_shell))
        .route("/v1/cats/{id}/proxy", post(handle_proxy))
        .with_state(state)
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
    Some((
        (stats.f_blocks as u64).saturating_mul(block_size),
        (stats.f_bavail as u64).saturating_mul(block_size),
    ))
}

struct HostTelemetrySampler {
    previous_cpu: Option<CpuTimes>,
    disk_path: PathBuf,
}

impl HostTelemetrySampler {
    fn new(disk_path: PathBuf) -> Self {
        Self {
            previous_cpu: std::fs::read_to_string("/proc/stat")
                .ok()
                .and_then(|contents| parse_cpu_times(&contents)),
            disk_path,
        }
    }

    fn sample(&mut self, mut telemetry: NodeTelemetry) -> NodeTelemetry {
        telemetry.host_logical_cpus = std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok());
        telemetry.load_average_1m = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|contents| contents.split_whitespace().next()?.parse().ok());

        if let Some(current) = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|contents| parse_cpu_times(&contents))
        {
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
        telemetry
    }
}

/// Start the node agent: HTTP server + registration + heartbeat loop.
pub async fn spawn(cfg: ServerConfig) -> anyhow::Result<Handle> {
    std::fs::create_dir_all(&cfg.node.state_dir)?;
    let cfg = Arc::new(cfg);
    let runtime = Arc::new(NodeRuntime::new(cfg.node.clone(), cfg.storage_meta.clone()));
    let state = NodeState {
        runtime: runtime.clone(),
        cfg: cfg.clone(),
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

    // Register with the control plane (retry until it is reachable).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let agent_url = cfg
        .advertise_url
        .clone()
        .unwrap_or_else(|| format!("http://{addr}"));
    anyhow::ensure!(
        reqwest::Url::parse(&agent_url).is_ok_and(|url| matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && !url.cannot_be_a_base()),
        "node advertise URL must be an absolute HTTP(S) URL"
    );
    let register = RegisterNodeRequest {
        node_id: cfg.node.node_id.clone(),
        agent_url,
        gateway_url: cfg.gateway_url.clone(),
        cpus: cfg.cpus,
        memory_mib: cfg.memory_mib,
    };
    let cp = cfg.control_plane_url.trim_end_matches('/').to_string();
    let token = cfg.auth_token.clone();
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let resp = client
                .post(format!("{cp}/v1/nodes/register"))
                .bearer_auth(&token)
                .json(&register)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => break,
                _ if std::time::Instant::now() > deadline => {
                    anyhow::bail!("could not register with control plane at {cp}")
                }
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
    tracing::info!(node = %cfg.node.node_id, %addr, "node agent registered");

    // Heartbeat loop.
    let hb_state = state.clone();
    let hb_client = client.clone();
    let hb_cp = cp.clone();
    let hb_token = token.clone();
    let interval = Duration::from_millis(cfg.heartbeat_ms);
    let mut telemetry_sampler = HostTelemetrySampler::new(cfg.node.state_dir.clone());
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let cats: Vec<HeartbeatCat> = hb_state
                .runtime
                .snapshot()
                .into_iter()
                .map(|(cat_id, generation, state)| HeartbeatCat {
                    cat_id,
                    generation,
                    state,
                })
                .collect();
            let _ = hb_client
                .post(format!("{hb_cp}/v1/nodes/heartbeat"))
                .bearer_auth(&hb_token)
                .json(&HeartbeatRequest {
                    node_id: hb_state.cfg.node.node_id.clone(),
                    cats,
                    telemetry: Some(telemetry_sampler.sample(hb_state.runtime.telemetry())),
                })
                .send()
                .await;
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
        tasks: vec![server, heartbeat, activity_watchers],
    })
}

#[cfg(test)]
mod telemetry_tests {
    use super::{cpu_usage_percent, filesystem_capacity, parse_cpu_times, parse_memory_mib};

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
    fn reads_capacity_for_an_existing_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let (total, available) = filesystem_capacity(temp.path()).unwrap();
        assert!(total > 0);
        assert!(available <= total);
    }
}

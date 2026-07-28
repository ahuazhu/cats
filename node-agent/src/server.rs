//! Node agent HTTP surface + registration/heartbeat loops.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};

use cats_api::guest::GuestShellFrame;
use cats_api::metering::{CatUsageCheckpoint, IngestUsageCheckpointsRequest, UsageMetric};
use cats_api::nodejob::{JobPhase, NodeJob, NodeJobResult};
use cats_api::requests::{
    ExecRequest, ExecResponse, HeartbeatCat, HeartbeatRequest, NodeWorkStatusRequest,
    ProxyHttpRequest, RegisterNodeRequest, ShellClientControl, ShellServerControl,
    MAX_SHELL_MESSAGE_BYTES,
};
use cats_api::resources::{CatResourceTelemetry, NodeTelemetry};
use cats_metering::RuntimeMeterAccumulator;
use cats_storage::MetadataStore;

use crate::guest_client::GuestShell;
use crate::runtime::{
    CatTelemetryTarget, GuestConn, NodeConfig, NodeRuntime, RuntimeActivityGuard, UsageFinalizer,
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
    client: reqwest::Client,
    usage_pipeline: Arc<UsageMeteringPipeline>,
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
        loop {
            let pending_checkpoints = self.usage_pipeline.spool.peek(10_000)?;
            if pending_checkpoints.is_empty() {
                return Ok(());
            }
            let request = IngestUsageCheckpointsRequest {
                node_id: self.cfg.node.node_id.clone(),
                checkpoints: pending_checkpoints.clone(),
            };
            let response = self
                .client
                .post(format!(
                    "{}/v1/internal/usage/checkpoints",
                    self.cfg.control_plane_url.trim_end_matches('/')
                ))
                .bearer_auth(&self.cfg.auth_token)
                .json(&request)
                .send()
                .await
                .context("send durable usage checkpoints")?;
            anyhow::ensure!(
                response.status().is_success(),
                "usage ingestion returned {}",
                response.status()
            );
            let event_ids = pending_checkpoints
                .iter()
                .map(|checkpoint| checkpoint.event_id.clone())
                .collect::<Vec<_>>();
            self.usage_pipeline.spool.acknowledge(&event_ids)?;
        }
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
            if let Err(error) = state.deliver_pending_usage().await {
                tracing::error!(
                    job = %res.job_id,
                    %error,
                    "lifecycle result withheld until final usage checkpoints are acknowledged"
                );
                Json(NodeJobResult::fail(
                    res.job_id,
                    res.observed_state,
                    format!("final usage delivery failed: {error:#}"),
                    true,
                ))
                .into_response()
            } else {
                Json(res).into_response()
            }
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

fn allocated_tree_bytes(path: &FsPath) -> Option<u64> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    let mut total = metadata.blocks().saturating_mul(512);
    if metadata.file_type().is_dir() {
        for entry in std::fs::read_dir(path).ok()? {
            total = total.saturating_add(allocated_tree_bytes(&entry.ok()?.path())?);
        }
    }
    Some(total)
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
                        %error,
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
        self.cat_meter_samples.retain(|cat_id, _| {
            telemetry
                .cat_resources
                .iter()
                .any(|item| &item.cat_id == cat_id)
        });
        self.retired_meter_epochs.retain(|cat_id, _| {
            telemetry
                .cat_resources
                .iter()
                .any(|item| &item.cat_id == cat_id)
        });
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
        if self
            .retired_meter_epochs
            .get(&target.cat_id)
            .is_some_and(|epoch| epoch == &metering.source_epoch)
        {
            return Ok(Vec::new());
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
}

impl UsageMeteringPipeline {
    fn open(node_id: String, state_dir: PathBuf) -> anyhow::Result<Self> {
        let spool = UsageSpool::open(&state_dir.join("usage-spool.sqlite3"))?;
        Ok(Self {
            sampler: Mutex::new(HostTelemetrySampler::new(node_id, state_dir)),
            spool,
            unspooled: Mutex::new(Vec::new()),
        })
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

/// Start the node agent: HTTP server + registration + heartbeat loop.
pub async fn spawn(cfg: ServerConfig) -> anyhow::Result<Handle> {
    anyhow::ensure!(cfg.heartbeat_ms > 0, "heartbeat interval must be positive");
    anyhow::ensure!(
        cfg.node.metering_cgroup_root.is_none() || cfg.heartbeat_ms <= 1_000,
        "authoritative billing requires a heartbeat/sample interval of at most 1000ms"
    );
    crate::runtime::initialize_metering_cgroup(&cfg.node)?;
    std::fs::create_dir_all(&cfg.node.state_dir)?;
    let usage_pipeline = Arc::new(UsageMeteringPipeline::open(
        cfg.node.node_id.clone(),
        cfg.node.state_dir.clone(),
    )?);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let cfg = Arc::new(cfg);
    let runtime = Arc::new(
        NodeRuntime::new(cfg.node.clone())
            .with_usage_finalizer(usage_pipeline.clone()),
    );
    let state = NodeState {
        runtime: runtime.clone(),
        cfg: cfg.clone(),
        client: client.clone(),
        usage_pipeline: usage_pipeline.clone(),
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
    let hb_usage_pipeline = usage_pipeline.clone();
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
            let (telemetry, persisted) = hb_usage_pipeline.sample(
                hb_state.runtime.telemetry(),
                hb_state.runtime.telemetry_targets(),
            );
            if let Err(error) = persisted {
                tracing::error!(
                    %error,
                    "usage checkpoints are not durable; billing remains failed closed"
                );
            }
            let _ = hb_client
                .post(format!("{hb_cp}/v1/nodes/heartbeat"))
                .bearer_auth(&hb_token)
                .json(&HeartbeatRequest {
                    node_id: hb_state.cfg.node.node_id.clone(),
                    cats,
                    telemetry: Some(telemetry),
                })
                .send()
                .await;
            if let Err(error) = hb_state.deliver_pending_usage().await {
                tracing::warn!(%error, "durable usage checkpoint delivery deferred");
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
        tasks: vec![server, heartbeat, activity_watchers],
    })
}

#[cfg(test)]
mod telemetry_tests {
    use super::{
        allocated_tree_bytes, compact_pending_checkpoints, cpu_usage_percent, filesystem_capacity,
        now_unix_ms, parse_cgroup_cpu_usage_usec, parse_cpu_times, parse_memory_mib,
        parse_process_cpu_ticks, parse_process_rss_bytes, process_cpu_usage_cores,
        read_cgroup_usage, HostTelemetrySampler,
    };
    use crate::runtime::{CatMeteringTarget, CatTelemetryTarget};
    use cats_api::metering::{CatUsageCheckpoint, UsageMetric};
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
    fn measures_allocated_runtime_tree_without_following_symlinks() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("cache")).unwrap();
        let mut file = std::fs::File::create(temp.path().join("cache/chunk")).unwrap();
        file.write_all(&vec![1_u8; 8192]).unwrap();
        std::os::unix::fs::symlink(temp.path().join("cache"), temp.path().join("cache-link"))
            .unwrap();
        let used = allocated_tree_bytes(temp.path()).unwrap();
        assert!(used >= 8192);
        assert!(used < 32 * 1024 * 1024);
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
}

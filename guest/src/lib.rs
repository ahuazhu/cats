//! Cats guest agent.
//!
//! In production this process is PID-1-adjacent inside the guest. Host control
//! uses the length-prefixed JSON protocol over AF_VSOCK; Guest user programs
//! use HTTP/1.1 on `/run/cats/runtime.sock`. Under the FakeVmm it is an
//! ordinary host process with isolated Unix sockets, and its "virtio disks"
//! are NBD connections to per-attachment `cats-blockd` sockets — so every
//! block byte still flows through the real storage engine.
//!
//! Identity: `boot_id` is created fresh at cold boot and restored from the
//! state file on Warm restore. This is the same correctness oracle the
//! 2026-07-21 experiments used (`boot_id_preserved` / `boot_id_changed`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use cats_api::guest::{
    AcquireGuestWorkLeaseRequest, GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody,
    GuestRuntimeApiError, GuestRuntimeApiErrorResponse, GuestWorkLease, GuestWorkStatus,
    RenewGuestWorkLeaseRequest, GUEST_WORK_LEASES_PATH, MAX_FRAME_BYTES, MAX_WORK_LEASES,
    MAX_WORK_LEASE_TTL_MS,
};
use cats_blockd::nbd::NbdClient;

// ---------------------------------------------------------------------------
// Framing: u32 big-endian length + JSON body.
// ---------------------------------------------------------------------------

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(|_| std::io::Error::other("oversized frame"))?;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("oversized frame"));
    }
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_frame<R: Read, T: for<'a> Deserialize<'a>>(r: &mut R) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("oversized frame"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(std::io::Error::other)
}

// ---------------------------------------------------------------------------
// Guest runtime HTTP/1.1 over Unix socket.
// ---------------------------------------------------------------------------

const MAX_WORK_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_WORK_HTTP_BODY_BYTES: usize = 64 * 1024;

struct WorkHttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct WorkHttpResponse {
    status: u16,
    reason: &'static str,
    content_type: Option<&'static str>,
    body: Vec<u8>,
    location: Option<String>,
}

impl WorkHttpResponse {
    fn json<T: Serialize>(status: u16, reason: &'static str, value: &T) -> Self {
        Self {
            status,
            reason,
            content_type: Some("application/json"),
            body: serde_json::to_vec(value).expect("Guest runtime response is JSON serializable"),
            location: None,
        }
    }

    fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            content_type: None,
            body: Vec::new(),
            location: None,
        }
    }

    fn error(status: u16, reason: &'static str, code: &str, message: impl Into<String>) -> Self {
        Self::json(
            status,
            reason,
            &GuestRuntimeApiErrorResponse {
                error: GuestRuntimeApiError {
                    code: code.into(),
                    message: message.into(),
                },
            },
        )
    }

    fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    fn write_to(&self, stream: &mut impl Write) -> std::io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\n",
            self.status,
            self.reason,
            self.body.len()
        )?;
        if let Some(content_type) = self.content_type {
            write!(stream, "content-type: {content_type}\r\n")?;
        }
        if let Some(location) = &self.location {
            write!(stream, "location: {location}\r\n")?;
        }
        write!(stream, "\r\n")?;
        stream.write_all(&self.body)?;
        stream.flush()
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_work_http_request(
    stream: &mut impl Read,
) -> std::result::Result<WorkHttpRequest, WorkHttpResponse> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = header_end(&bytes) {
            break end;
        }
        if bytes.len() >= MAX_WORK_HTTP_HEADER_BYTES {
            return Err(WorkHttpResponse::error(
                431,
                "Request Header Fields Too Large",
                "headers_too_large",
                "HTTP headers exceed 16 KiB",
            ));
        }
        let read = stream.read(&mut chunk).map_err(|error| {
            WorkHttpResponse::error(400, "Bad Request", "read_failed", error.to_string())
        })?;
        if read == 0 {
            return Err(WorkHttpResponse::error(
                400,
                "Bad Request",
                "incomplete_headers",
                "connection closed before the HTTP headers completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    if end > MAX_WORK_HTTP_HEADER_BYTES {
        return Err(WorkHttpResponse::error(
            431,
            "Request Header Fields Too Large",
            "headers_too_large",
            "HTTP headers exceed 16 KiB",
        ));
    }

    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| {
        WorkHttpResponse::error(
            400,
            "Bad Request",
            "invalid_headers",
            "HTTP headers must be UTF-8/ASCII",
        )
    })?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let path = request_parts.next().unwrap_or_default().to_string();
    let version = request_parts.next().unwrap_or_default();
    if method.is_empty()
        || path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || request_parts.next().is_some()
    {
        return Err(WorkHttpResponse::error(
            400,
            "Bad Request",
            "invalid_request_line",
            "expected METHOD PATH HTTP/1.1",
        ));
    }

    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(WorkHttpResponse::error(
                400,
                "Bad Request",
                "invalid_header",
                "HTTP header is missing ':'",
            ));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(WorkHttpResponse::error(
                400,
                "Bad Request",
                "unsupported_transfer_encoding",
                "chunked request bodies are not supported on the local runtime socket",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(WorkHttpResponse::error(
                    400,
                    "Bad Request",
                    "duplicate_content_length",
                    "Content-Length may appear only once",
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                WorkHttpResponse::error(
                    400,
                    "Bad Request",
                    "invalid_content_length",
                    "Content-Length must be a non-negative integer",
                )
            })?);
        }
    }

    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_WORK_HTTP_BODY_BYTES {
        return Err(WorkHttpResponse::error(
            413,
            "Content Too Large",
            "body_too_large",
            "HTTP body exceeds 64 KiB",
        ));
    }
    let body_start = end + 4;
    while bytes.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut chunk).map_err(|error| {
            WorkHttpResponse::error(400, "Bad Request", "read_failed", error.to_string())
        })?;
        if read == 0 {
            return Err(WorkHttpResponse::error(
                400,
                "Bad Request",
                "incomplete_body",
                "connection closed before Content-Length bytes arrived",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }

    Ok(WorkHttpRequest {
        method,
        path,
        body: bytes[body_start..body_start + content_length].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Disk map: written by the node agent, re-read on every block operation so
// hot attach/detach need no push channel.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMapEntry {
    pub socket: PathBuf,
    pub mount_path: String,
}

pub type DiskMap = HashMap<String, DiskMapEntry>;

fn load_disk_map(path: &Path) -> DiskMap {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Saved state (Warm snapshot carrier)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct SavedState {
    boot_id: String,
    counter: u64,
}

/// How this agent is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestMode {
    /// FakeVmm: a host process; "virtio disks" are NBD connections listed in
    /// the node-maintained disk map; boot identity is synthesized (and
    /// restored from the Warm state file).
    Fake,
    /// A real VM: boot identity is the kernel's per-boot UUID (preserved by
    /// VMM snapshot/restore, changed by cold boot — the experiments'
    /// oracle); syncfs is the real syscall; the kernel owns the disks, so
    /// block-level ops are not served here.
    Vm,
}

pub struct GuestAgent {
    mode: GuestMode,
    boot_id: String,
    started: Instant,
    disk_map_path: PathBuf,
    /// Monotonic counter surviving Warm (proves process-state continuity).
    counter: AtomicU64,
    volumes: Mutex<HashMap<String, NbdClient>>,
    work: WorkRegistry,
}

struct WorkLeaseEntry {
    id: String,
    label: String,
    expires_at: Instant,
}

struct WorkInner {
    source_epoch: String,
    lease_sequence: u64,
    quiescing: bool,
    leases: HashMap<String, WorkLeaseEntry>,
}

struct WorkRegistry {
    inner: Mutex<WorkInner>,
    changed: Condvar,
}

#[derive(Debug, thiserror::Error)]
enum WorkRegistryError {
    #[error("{0}")]
    Invalid(String),
    #[error("activity_changed: Cat is preparing to suspend; retry")]
    ActivityChanged,
    #[error("work lease {0} not found")]
    NotFound(String),
    #[error("too many work leases")]
    Capacity,
}

impl WorkRegistry {
    fn new() -> Self {
        Self {
            inner: Mutex::new(WorkInner {
                source_epoch: uuid::Uuid::new_v4().simple().to_string(),
                lease_sequence: 0,
                quiescing: false,
                leases: HashMap::new(),
            }),
            changed: Condvar::new(),
        }
    }

    fn prune(inner: &mut WorkInner) -> bool {
        let before = inner.leases.len();
        let now = Instant::now();
        inner.leases.retain(|_, lease| lease.expires_at > now);
        if inner.leases.len() != before {
            inner.lease_sequence = inner.lease_sequence.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn status_of(inner: &WorkInner) -> GuestWorkStatus {
        let now = Instant::now();
        let mut leases: Vec<GuestWorkLease> = inner
            .leases
            .values()
            .map(|lease| GuestWorkLease {
                id: lease.id.clone(),
                label: lease.label.clone(),
                remaining_ttl_ms: lease
                    .expires_at
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64,
            })
            .collect();
        leases.sort_by(|a, b| a.id.cmp(&b.id));
        GuestWorkStatus {
            source_epoch: inner.source_epoch.clone(),
            lease_sequence: inner.lease_sequence,
            quiescing: inner.quiescing,
            leases,
        }
    }

    fn status(&self, after_sequence: Option<u64>, wait_timeout_ms: u64) -> GuestWorkStatus {
        let max_wait = Duration::from_millis(wait_timeout_ms.min(30_000));
        let deadline = Instant::now() + max_wait;
        let mut inner = self.inner.lock().unwrap();
        if Self::prune(&mut inner) {
            self.changed.notify_all();
        }
        while after_sequence == Some(inner.lease_sequence) && Instant::now() < deadline {
            let until_expiry = inner
                .leases
                .values()
                .map(|lease| lease.expires_at.saturating_duration_since(Instant::now()))
                .min()
                .unwrap_or_else(|| deadline.saturating_duration_since(Instant::now()));
            let wait = until_expiry
                .min(deadline.saturating_duration_since(Instant::now()))
                .max(Duration::from_millis(1));
            let (next, _) = self.changed.wait_timeout(inner, wait).unwrap();
            inner = next;
            if Self::prune(&mut inner) {
                self.changed.notify_all();
            }
        }
        Self::status_of(&inner)
    }

    fn acquire(
        &self,
        label: String,
        ttl_ms: u64,
    ) -> std::result::Result<GuestWorkLease, WorkRegistryError> {
        validate_label(&label)?;
        validate_ttl(ttl_ms)?;
        let mut inner = self.inner.lock().unwrap();
        Self::prune(&mut inner);
        if inner.quiescing {
            inner.lease_sequence = inner.lease_sequence.saturating_add(1);
            self.changed.notify_all();
            return Err(WorkRegistryError::ActivityChanged);
        }
        if inner.leases.len() >= MAX_WORK_LEASES {
            return Err(WorkRegistryError::Capacity);
        }
        let id = format!("work_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        inner.leases.insert(
            id.clone(),
            WorkLeaseEntry {
                id: id.clone(),
                label,
                expires_at: Instant::now() + Duration::from_millis(ttl_ms),
            },
        );
        inner.lease_sequence = inner.lease_sequence.saturating_add(1);
        let lease = Self::status_of(&inner)
            .leases
            .into_iter()
            .find(|lease| lease.id == id)
            .expect("inserted work lease");
        self.changed.notify_all();
        Ok(lease)
    }

    fn renew(
        &self,
        lease_id: &str,
        ttl_ms: u64,
    ) -> std::result::Result<GuestWorkLease, WorkRegistryError> {
        validate_ttl(ttl_ms)?;
        let mut inner = self.inner.lock().unwrap();
        Self::prune(&mut inner);
        if inner.quiescing {
            inner.lease_sequence = inner.lease_sequence.saturating_add(1);
            self.changed.notify_all();
            return Err(WorkRegistryError::ActivityChanged);
        }
        let lease = inner
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| WorkRegistryError::NotFound(lease_id.to_string()))?;
        lease.expires_at = Instant::now() + Duration::from_millis(ttl_ms);
        inner.lease_sequence = inner.lease_sequence.saturating_add(1);
        let renewed = Self::status_of(&inner)
            .leases
            .into_iter()
            .find(|lease| lease.id == lease_id)
            .expect("renewed work lease");
        self.changed.notify_all();
        Ok(renewed)
    }

    fn release(&self, lease_id: &str) -> std::result::Result<(), WorkRegistryError> {
        let mut inner = self.inner.lock().unwrap();
        Self::prune(&mut inner);
        if inner.leases.remove(lease_id).is_some() {
            inner.lease_sequence = inner.lease_sequence.saturating_add(1);
            self.changed.notify_all();
        }
        // DELETE is idempotent: an expired, already released, or pre-restart
        // lease is already in the caller's desired state.
        Ok(())
    }

    fn prepare_suspend(
        &self,
        expected_sequence: u64,
    ) -> std::result::Result<(String, u64), WorkRegistryError> {
        let mut inner = self.inner.lock().unwrap();
        Self::prune(&mut inner);
        if inner.lease_sequence != expected_sequence || !inner.leases.is_empty() {
            return Err(WorkRegistryError::ActivityChanged);
        }
        inner.quiescing = true;
        Ok((inner.source_epoch.clone(), inner.lease_sequence))
    }

    fn abort_suspend(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.quiescing = false;
        self.changed.notify_all();
    }
}

fn validate_label(label: &str) -> std::result::Result<(), WorkRegistryError> {
    if label.is_empty() {
        return Err(WorkRegistryError::Invalid(
            "work label must not be empty".into(),
        ));
    }
    if label.len() > 64 {
        return Err(WorkRegistryError::Invalid(
            "work label exceeds 64 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_ttl(ttl_ms: u64) -> std::result::Result<(), WorkRegistryError> {
    if ttl_ms == 0 {
        return Err(WorkRegistryError::Invalid(
            "work TTL must be positive".into(),
        ));
    }
    if ttl_ms > MAX_WORK_LEASE_TTL_MS {
        return Err(WorkRegistryError::Invalid(
            "work TTL exceeds the maximum".into(),
        ));
    }
    Ok(())
}

fn kernel_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().replace('-', ""))
}

impl GuestAgent {
    pub fn new(disk_map_path: PathBuf, state_file: Option<&Path>) -> Self {
        Self::with_mode(GuestMode::Fake, disk_map_path, state_file)
    }

    pub fn with_mode(mode: GuestMode, disk_map_path: PathBuf, state_file: Option<&Path>) -> Self {
        let restored: Option<SavedState> = state_file
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok());
        let (boot_id, counter) = match (&mode, restored) {
            (GuestMode::Vm, _) => (
                kernel_boot_id().unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()),
                0,
            ),
            (GuestMode::Fake, Some(s)) => (s.boot_id, s.counter),
            (GuestMode::Fake, None) => (uuid::Uuid::new_v4().simple().to_string(), 0),
        };
        Self {
            mode,
            boot_id,
            started: Instant::now(),
            disk_map_path,
            counter: AtomicU64::new(counter),
            volumes: Mutex::new(HashMap::new()),
            work: WorkRegistry::new(),
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    fn with_volume<T>(
        &self,
        disk_id: &str,
        f: impl FnOnce(&mut NbdClient) -> Result<T>,
    ) -> Result<T> {
        let map = load_disk_map(&self.disk_map_path);
        let entry = map
            .get(disk_id)
            .with_context(|| format!("disk {disk_id} is not attached"))?
            .clone();
        let mut volumes = self.volumes.lock().unwrap();
        if !volumes.contains_key(disk_id) {
            let client = NbdClient::connect_unix(&entry.socket)
                .with_context(|| format!("connect volume {disk_id}"))?;
            volumes.insert(disk_id.to_string(), client);
        }
        let client = volumes.get_mut(disk_id).expect("just inserted");
        let out = f(client);
        if out.is_err() {
            // Drop a broken connection so the next call reconnects.
            volumes.remove(disk_id);
        }
        out
    }

    fn drop_missing_volumes(&self) {
        let map = load_disk_map(&self.disk_map_path);
        self.volumes
            .lock()
            .unwrap()
            .retain(|k, _| map.contains_key(k));
    }

    pub fn handle(&self, req: GuestRequestBody) -> GuestResponseBody {
        match self.try_handle(req) {
            Ok(resp) => resp,
            Err(e) => GuestResponseBody::Error {
                message: format!("{e:#}"),
            },
        }
    }

    fn require_fake(&self, op: &str) -> Result<()> {
        if self.mode != GuestMode::Fake {
            anyhow::bail!(
                "{op} is only served by the fake guest (real disks belong to the kernel)"
            );
        }
        Ok(())
    }

    fn try_handle(&self, req: GuestRequestBody) -> Result<GuestResponseBody> {
        match req {
            GuestRequestBody::Health => {
                self.counter.fetch_add(1, Ordering::SeqCst);
                let disks = match self.mode {
                    GuestMode::Fake => load_disk_map(&self.disk_map_path).keys().cloned().collect(),
                    GuestMode::Vm => list_block_devices(),
                };
                Ok(GuestResponseBody::Health {
                    boot_id: self.boot_id.clone(),
                    uptime_ms: self.started.elapsed().as_millis() as u64,
                    disks,
                })
            }
            GuestRequestBody::WorkStatus {
                after_sequence,
                wait_timeout_ms,
            } => Ok(GuestResponseBody::WorkStatus {
                status: self.work.status(after_sequence, wait_timeout_ms),
            }),
            GuestRequestBody::PrepareSuspend {
                expected_lease_sequence,
            } => {
                let (source_epoch, lease_sequence) =
                    self.work.prepare_suspend(expected_lease_sequence)?;
                Ok(GuestResponseBody::SuspendPrepared {
                    source_epoch,
                    lease_sequence,
                })
            }
            GuestRequestBody::AbortSuspend => {
                self.work.abort_suspend();
                Ok(GuestResponseBody::Ok)
            }
            GuestRequestBody::Exec {
                command,
                timeout_ms: _,
            } => {
                let (argv0, rest) = command
                    .split_first()
                    .context("command must be a non-empty argv array")?;
                let out = match std::process::Command::new(argv0).args(rest).output() {
                    Ok(out) => out,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(GuestResponseBody::Exec {
                            exit_code: 127,
                            stdout: String::new(),
                            stderr: format!("{argv0}: command not found\n"),
                        });
                    }
                    Err(error) => return Err(error).with_context(|| format!("spawn {argv0}")),
                };
                Ok(GuestResponseBody::Exec {
                    exit_code: out.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                })
            }
            GuestRequestBody::Syncfs => {
                if self.mode == GuestMode::Vm {
                    real_syncfs()?;
                    return Ok(GuestResponseBody::Ok);
                }
                self.drop_missing_volumes();
                let ids: Vec<String> = load_disk_map(&self.disk_map_path).keys().cloned().collect();
                for id in ids {
                    self.with_volume(&id, |c| Ok(c.flush()?))?;
                }
                Ok(GuestResponseBody::Ok)
            }
            GuestRequestBody::ReadBlock {
                disk_id,
                offset,
                len,
            } => {
                self.require_fake("read_block")?;
                let data = self.with_volume(&disk_id, |c| Ok(c.read(offset, len)?))?;
                Ok(GuestResponseBody::Data {
                    data_hex: hex::encode(data),
                })
            }
            GuestRequestBody::WriteBlock {
                disk_id,
                offset,
                data_hex,
            } => {
                self.require_fake("write_block")?;
                let data = hex::decode(&data_hex).context("data_hex is not valid hex")?;
                self.with_volume(&disk_id, |c| Ok(c.write(offset, &data)?))?;
                self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(GuestResponseBody::Ok)
            }
            GuestRequestBody::FlushDisk { disk_id } => {
                if self.mode == GuestMode::Vm {
                    // The kernel owns the disks; syncfs is the durable point.
                    real_syncfs()?;
                    return Ok(GuestResponseBody::Ok);
                }
                self.with_volume(&disk_id, |c| Ok(c.flush()?))?;
                Ok(GuestResponseBody::Ok)
            }
            GuestRequestBody::SaveState { path } => {
                self.require_fake("save_state")?;
                let state = SavedState {
                    boot_id: self.boot_id.clone(),
                    counter: self.counter.load(Ordering::SeqCst),
                };
                let tmp = PathBuf::from(format!("{path}.tmp"));
                std::fs::write(&tmp, serde_json::to_vec(&state)?)?;
                std::fs::rename(&tmp, &path)?;
                Ok(GuestResponseBody::Ok)
            }
            GuestRequestBody::Shutdown => {
                tracing::info!("guest agent shutting down");
                std::process::exit(0);
            }
        }
    }

    fn work_registry_error(error: WorkRegistryError) -> WorkHttpResponse {
        match error {
            WorkRegistryError::Invalid(message) => {
                WorkHttpResponse::error(400, "Bad Request", "invalid_request", message)
            }
            WorkRegistryError::ActivityChanged => WorkHttpResponse::error(
                409,
                "Conflict",
                "activity_changed",
                "Cat is preparing to suspend; retry after it remains Running",
            ),
            WorkRegistryError::NotFound(lease_id) => WorkHttpResponse::error(
                404,
                "Not Found",
                "lease_not_found",
                format!("work lease {lease_id} was not found"),
            ),
            WorkRegistryError::Capacity => WorkHttpResponse::error(
                429,
                "Too Many Requests",
                "too_many_leases",
                format!("a Guest may hold at most {MAX_WORK_LEASES} work leases"),
            ),
        }
    }

    fn parse_work_json<T: for<'de> Deserialize<'de>>(
        body: &[u8],
    ) -> std::result::Result<T, WorkHttpResponse> {
        serde_json::from_slice(body).map_err(|error| {
            WorkHttpResponse::error(
                400,
                "Bad Request",
                "invalid_json",
                format!("invalid JSON request body: {error}"),
            )
        })
    }

    fn handle_work_http(&self, request: WorkHttpRequest) -> WorkHttpResponse {
        if request.path == GUEST_WORK_LEASES_PATH {
            return match request.method.as_str() {
                "GET" => WorkHttpResponse::json(200, "OK", &self.work.status(None, 0)),
                "POST" => {
                    let body: AcquireGuestWorkLeaseRequest =
                        match Self::parse_work_json(&request.body) {
                            Ok(body) => body,
                            Err(response) => return response,
                        };
                    match self.work.acquire(body.label, body.ttl_ms) {
                        Ok(lease) => WorkHttpResponse::json(201, "Created", &lease)
                            .with_location(format!("{GUEST_WORK_LEASES_PATH}/{}", lease.id)),
                        Err(error) => Self::work_registry_error(error),
                    }
                }
                _ => WorkHttpResponse::error(
                    405,
                    "Method Not Allowed",
                    "method_not_allowed",
                    "use GET or POST on /v1/work-leases",
                ),
            };
        }

        let Some(lease_id) = request
            .path
            .strip_prefix(&format!("{GUEST_WORK_LEASES_PATH}/"))
            .filter(|lease_id| !lease_id.is_empty() && !lease_id.contains('/'))
        else {
            return WorkHttpResponse::error(
                404,
                "Not Found",
                "not_found",
                "unknown Guest runtime API route",
            );
        };
        match request.method.as_str() {
            "PUT" => {
                let body: RenewGuestWorkLeaseRequest = match Self::parse_work_json(&request.body) {
                    Ok(body) => body,
                    Err(response) => return response,
                };
                match self.work.renew(lease_id, body.ttl_ms) {
                    Ok(lease) => WorkHttpResponse::json(200, "OK", &lease),
                    Err(error) => Self::work_registry_error(error),
                }
            }
            "DELETE" => match self.work.release(lease_id) {
                Ok(()) => WorkHttpResponse::empty(204, "No Content"),
                Err(error) => Self::work_registry_error(error),
            },
            _ => WorkHttpResponse::error(
                405,
                "Method Not Allowed",
                "method_not_allowed",
                "use PUT or DELETE on /v1/work-leases/{lease_id}",
            ),
        }
    }

    fn serve_work_stream(&self, mut stream: std::os::unix::net::UnixStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let response = match read_work_http_request(&mut stream) {
            Ok(request) => self.handle_work_http(request),
            Err(response) => response,
        };
        let _ = response.write_to(&mut stream);
    }

    /// Serve the open Guest-local work API as HTTP/1.1 over a Unix socket.
    /// Each connection handles one request and closes, which is compatible
    /// with curl and language HTTP clients that support Unix sockets. No Cat
    /// id, platform credential, Cats SDK, or TCP port crosses this boundary.
    pub fn serve_runtime_http(self: &std::sync::Arc<Self>, listener: UnixListener) {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { return };
            let agent = self.clone();
            std::thread::spawn(move || agent.serve_work_stream(stream));
        }
    }

    /// Serve the control socket until the process is killed. One thread per
    /// connection so health checks are never blocked behind a long exec.
    pub fn serve_control(self: &std::sync::Arc<Self>, listener: UnixListener) {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { return };
            self.serve_control_stream(stream);
        }
    }

    fn serve_control_stream(
        self: &std::sync::Arc<Self>,
        mut stream: std::os::unix::net::UnixStream,
    ) {
        let agent = self.clone();
        std::thread::spawn(move || {
            while let Ok(req) = read_frame::<_, GuestRequest>(&mut stream) {
                let resp = GuestResponse {
                    id: req.id,
                    body: agent.handle(req.body),
                };
                if write_frame(&mut stream, &resp).is_err() {
                    break;
                }
            }
        });
    }

    /// Serve AF_VSOCK without asking `UnixListener` to decode the peer
    /// address. Its `accept` path expects `sockaddr_un` and rejects an
    /// otherwise valid `sockaddr_vm`; accepting with a null address keeps the
    /// resulting stream fully usable for read/write framing.
    #[cfg(target_os = "linux")]
    pub fn serve_vsock_control(self: &std::sync::Arc<Self>, listener: VsockListener) -> Result<()> {
        loop {
            let stream = listener.accept()?;
            self.serve_control_stream(stream);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn serve_vsock_control(
        self: &std::sync::Arc<Self>,
        _listener: VsockListener,
    ) -> Result<()> {
        anyhow::bail!("vsock is only available on linux")
    }

    /// Minimal HTTP/1.1 web service over a unix socket: the "user workload"
    /// behind endpoints in dev/tests.
    pub fn serve_web(&self, listener: UnixListener) {
        let hits = AtomicU64::new(0);
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { return };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0u8; 4096];
            let n = match stream.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            let head = String::from_utf8_lossy(&buf[..n]);
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let hit = hits.fetch_add(1, Ordering::SeqCst) + 1;
            let body = format!("cat boot_id={} path={} hits={}\n", self.boot_id, path, hit);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    }
}

fn list_block_devices() -> Vec<String> {
    std::fs::read_dir("/sys/block")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("vd"))
                .collect()
        })
        .unwrap_or_default()
}

/// Flush every mounted filesystem (real VM mode durable point).
#[cfg(target_os = "linux")]
fn real_syncfs() -> Result<()> {
    // sync(2) flushes all filesystems; simple and sufficient for V1.
    // SAFETY: `sync` takes no pointers or arguments and has no Rust-side
    // memory-safety preconditions.
    unsafe { libc::sync() };
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn real_syncfs() -> Result<()> {
    anyhow::bail!("vm mode requires linux")
}

/// AF_VSOCK listener (real guests only). Accepted connections are handed to
/// the same frame loop as unix sockets.
#[cfg(target_os = "linux")]
pub struct VsockListener(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl VsockListener {
    fn accept(&self) -> Result<std::os::unix::net::UnixStream> {
        use std::os::fd::{AsRawFd, FromRawFd};
        loop {
            // SAFETY: the listener owns a valid AF_VSOCK descriptor; null
            // address pointers are explicitly allowed, and no pointer is
            // retained after `accept4` returns.
            let fd = unsafe {
                libc::accept4(
                    self.0.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if fd >= 0 {
                // SAFETY: a successful `accept4` returns a fresh owned stream
                // descriptor, transferred exactly once to `UnixStream` as a
                // generic owning stream-fd wrapper.
                return Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) });
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                anyhow::bail!("vsock accept: {error}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn bind_vsock(port: u32) -> Result<VsockListener> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: `socket` receives constant address/protocol values and returns
    // either a new owned descriptor or a negative error sentinel.
    let raw_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    anyhow::ensure!(
        raw_fd >= 0,
        "vsock socket: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `raw_fd` was just returned by `socket`, is non-negative, and is
    // transferred exactly once into `OwnedFd`; every later error closes it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    // SAFETY: zero is a valid initial representation for `sockaddr_vm`; all
    // fields required by AF_VSOCK are populated immediately below.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = port;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    // SAFETY: the pointer and length describe the live `addr` value, and the
    // owned socket descriptor stays valid for the call.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    anyhow::ensure!(rc == 0, "vsock bind: {}", std::io::Error::last_os_error());
    // SAFETY: `fd` remains a valid socket descriptor and `listen` retains no
    // Rust references.
    let rc = unsafe { libc::listen(fd.as_raw_fd(), 16) };
    anyhow::ensure!(rc == 0, "vsock listen: {}", std::io::Error::last_os_error());
    Ok(VsockListener(fd))
}

#[cfg(not(target_os = "linux"))]
pub struct VsockListener;

#[cfg(not(target_os = "linux"))]
pub fn bind_vsock(_port: u32) -> Result<VsockListener> {
    anyhow::bail!("vsock is only available on linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let req = GuestRequest {
            id: 7,
            body: GuestRequestBody::Health,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let back: GuestRequest = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(back.id, 7);
        assert!(matches!(back.body, GuestRequestBody::Health));
    }

    #[test]
    fn health_exec_and_state_save_restore() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("disks.json");
        std::fs::write(&map_path, b"{}").unwrap();
        let agent = GuestAgent::new(map_path.clone(), None);
        let boot_id = agent.boot_id().to_string();

        match agent.handle(GuestRequestBody::Health) {
            GuestResponseBody::Health {
                boot_id: b, disks, ..
            } => {
                assert_eq!(b, boot_id);
                assert!(disks.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
        match agent.handle(GuestRequestBody::Exec {
            command: vec!["echo".into(), "hello".into()],
            timeout_ms: None,
        }) {
            GuestResponseBody::Exec {
                exit_code, stdout, ..
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim(), "hello");
            }
            other => panic!("unexpected {other:?}"),
        }
        match agent.handle(GuestRequestBody::Exec {
            command: vec!["/definitely/not/a/cats-command".into()],
            timeout_ms: None,
        }) {
            GuestResponseBody::Exec {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(exit_code, 127);
                assert!(stdout.is_empty());
                assert_eq!(
                    stderr,
                    "/definitely/not/a/cats-command: command not found\n"
                );
            }
            other => panic!("unexpected {other:?}"),
        }

        // Save state, then "restore" into a new agent: boot_id survives.
        let state = dir.path().join("state.json");
        agent.handle(GuestRequestBody::SaveState {
            path: state.display().to_string(),
        });
        let restored = GuestAgent::new(map_path, Some(&state));
        assert_eq!(restored.boot_id(), boot_id);

        // Unknown disk errors cleanly.
        match agent.handle(GuestRequestBody::ReadBlock {
            disk_id: "missing".into(),
            offset: 0,
            len: 16,
        }) {
            GuestResponseBody::Error { message } => assert!(message.contains("not attached")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn user_work_lease_is_the_guest_suspend_fence() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("disks.json");
        std::fs::write(&map_path, b"{}").unwrap();
        let agent = GuestAgent::new(map_path, None);

        let lease = agent.work.acquire("training-step".into(), 5_000).unwrap();
        let active = agent.work.status(None, 0);
        assert_eq!(active.leases.len(), 1);
        assert!(matches!(
            agent.handle(GuestRequestBody::PrepareSuspend {
                expected_lease_sequence: active.lease_sequence,
            }),
            GuestResponseBody::Error { .. }
        ));

        agent.work.release(&lease.id).unwrap();
        let idle = agent.work.status(None, 0);
        assert!(idle.leases.is_empty());
        assert!(matches!(
            agent.handle(GuestRequestBody::PrepareSuspend {
                expected_lease_sequence: idle.lease_sequence,
            }),
            GuestResponseBody::SuspendPrepared { .. }
        ));

        // New work cannot slip through the quiesce window. Its failed
        // admission still changes the sequence, forcing the Node to abort.
        assert!(matches!(
            agent.work.acquire("racing-step".into(), 5_000),
            Err(WorkRegistryError::ActivityChanged)
        ));
        let raced = agent.work.status(None, 0);
        assert!(raced.lease_sequence > idle.lease_sequence);
        assert!(raced.quiescing);

        assert!(matches!(
            agent.handle(GuestRequestBody::AbortSuspend),
            GuestResponseBody::Ok
        ));
        assert!(agent.work.acquire("retry-step".into(), 5_000).is_ok());
    }

    #[test]
    fn expired_user_work_lease_disappears_without_polling_delay() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("disks.json");
        std::fs::write(&map_path, b"{}").unwrap();
        let agent = GuestAgent::new(map_path, None);
        agent.work.acquire("short".into(), 10).unwrap();
        let active = agent.work.status(None, 0);
        let idle = agent.work.status(Some(active.lease_sequence), 1_000);
        assert!(idle.leases.is_empty());
        assert!(idle.lease_sequence > active.lease_sequence);
    }

    #[test]
    fn guest_runtime_work_api_is_http_over_unix_stream() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("disks.json");
        std::fs::write(&map_path, b"{}").unwrap();
        let agent = std::sync::Arc::new(GuestAgent::new(map_path, None));
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let serving = agent.clone();
        let worker = std::thread::spawn(move || serving.serve_work_stream(server));
        let body = br#"{"label":"compile","ttl_ms":5000}"#;
        write!(
            client,
            "POST {GUEST_WORK_LEASES_PATH} HTTP/1.1\r\nhost: cats-runtime\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        client.write_all(body).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        worker.join().unwrap();

        let split = header_end(&response).unwrap();
        let head = std::str::from_utf8(&response[..split]).unwrap();
        assert!(head.starts_with("HTTP/1.1 201 Created\r\n"));
        assert!(head.contains("content-type: application/json\r\n"));
        let lease: GuestWorkLease = serde_json::from_slice(&response[split + 4..]).unwrap();
        assert_eq!(lease.label, "compile");
        assert_eq!(agent.work.status(None, 0).leases.len(), 1);
    }

    #[test]
    fn guest_runtime_http_covers_renew_list_idempotent_delete_and_quiesce() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("disks.json");
        std::fs::write(&map_path, b"{}").unwrap();
        let agent = GuestAgent::new(map_path, None);

        let created = agent.handle_work_http(WorkHttpRequest {
            method: "POST".into(),
            path: GUEST_WORK_LEASES_PATH.into(),
            body: br#"{"label":"queue-drain"}"#.to_vec(),
        });
        assert_eq!(created.status, 201);
        let lease: GuestWorkLease = serde_json::from_slice(&created.body).unwrap();
        assert!(lease.remaining_ttl_ms > 0);

        let renewed = agent.handle_work_http(WorkHttpRequest {
            method: "PUT".into(),
            path: format!("{GUEST_WORK_LEASES_PATH}/{}", lease.id),
            body: br#"{"ttl_ms":10000}"#.to_vec(),
        });
        assert_eq!(renewed.status, 200);
        let renewed: GuestWorkLease = serde_json::from_slice(&renewed.body).unwrap();
        assert!(renewed.remaining_ttl_ms > 5_000);

        let listed = agent.handle_work_http(WorkHttpRequest {
            method: "GET".into(),
            path: GUEST_WORK_LEASES_PATH.into(),
            body: Vec::new(),
        });
        let status: GuestWorkStatus = serde_json::from_slice(&listed.body).unwrap();
        assert_eq!(status.leases.len(), 1);

        for _ in 0..2 {
            let released = agent.handle_work_http(WorkHttpRequest {
                method: "DELETE".into(),
                path: format!("{GUEST_WORK_LEASES_PATH}/{}", lease.id),
                body: Vec::new(),
            });
            assert_eq!(released.status, 204);
        }

        let idle = agent.work.status(None, 0);
        agent.work.prepare_suspend(idle.lease_sequence).unwrap();
        let rejected = agent.handle_work_http(WorkHttpRequest {
            method: "POST".into(),
            path: GUEST_WORK_LEASES_PATH.into(),
            body: br#"{"label":"racing-work"}"#.to_vec(),
        });
        assert_eq!(rejected.status, 409);
        let error: GuestRuntimeApiErrorResponse = serde_json::from_slice(&rejected.body).unwrap();
        assert_eq!(error.error.code, "activity_changed");
    }
}

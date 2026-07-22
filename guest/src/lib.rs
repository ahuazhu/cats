//! Cats guest agent.
//!
//! In production this process is PID-1-adjacent inside the guest and speaks
//! the length-prefixed JSON protocol over AF_VSOCK. Under the FakeVmm it is
//! an ordinary host process speaking the same protocol over a unix socket,
//! and its "virtio disks" are NBD connections to per-attachment
//! `cats-blockd` sockets — so every block byte still flows through the real
//! storage engine.
//!
//! Identity: `boot_id` is created fresh at cold boot and restored from the
//! state file on Warm restore. This is the same correctness oracle the
//! 2026-07-21 experiments used (`boot_id_preserved` / `boot_id_changed`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use cats_api::guest::{
    GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody, MAX_FRAME_BYTES,
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
            GuestRequestBody::Exec {
                command,
                timeout_ms: _,
            } => {
                let (argv0, rest) = command
                    .split_first()
                    .context("command must be a non-empty argv array")?;
                let out = std::process::Command::new(argv0)
                    .args(rest)
                    .output()
                    .with_context(|| format!("spawn {argv0}"))?;
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
}

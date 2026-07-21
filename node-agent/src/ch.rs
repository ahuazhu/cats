//! Cloud Hypervisor integration (the real-VMM half of the runtime seam).
//!
//! Phase A data path (correctness-first, per ADR-0001 ordering):
//!
//! ```text
//! guest virtio-blk -> CH built-in block backend -> /dev/nbdN (kernel NBD
//! client) -> cats-blockd NBD server -> ChunkEngine -> S3/File blobstore
//! ```
//!
//! The kernel NBD hop reuses the fully crash-tested NBD frontend; a native
//! vhost-user-blk backend is the later performance milestone and does not
//! change any commit semantics. Guest control runs over CH hybrid vsock.
//! Warm uses `vm.snapshot` / `--restore` (the mechanism validated in the
//! 2026-07-21 experiments) with the snapshot on local disk.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use cats_blockd::nbd::NbdClient;

/// Guest-agent vsock port (must match the guest image's init script).
pub const GUEST_VSOCK_PORT: u32 = 5000;

#[derive(Debug, Clone)]
pub struct ChConfig {
    pub ch_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    /// Kernel command line; `root=/dev/vda` etc.
    pub cmdline: String,
    /// Raw image written into generation-0 root volumes (golden root).
    pub seed_image: Option<PathBuf>,
    pub nbd_client_bin: PathBuf,
    /// How many /dev/nbdN devices exist (modprobe nbd nbds_max=...).
    pub nbd_devices: u32,
}

/// Per-cat runtime state that only exists in CH mode.
#[derive(Debug, Default)]
pub struct ChRuntime {
    pub api_sock: PathBuf,
    pub vsock_sock: PathBuf,
    /// disk_id -> /dev/nbdN (order matters for restore).
    pub nbd: HashMap<String, String>,
    pub snapshot_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// CH API socket: minimal HTTP/1.1 over a unix stream.
// ---------------------------------------------------------------------------

pub fn ch_api(sock: &Path, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
    let mut stream = UnixStream::connect(sock)
        .with_context(|| format!("connect CH api socket {}", sock.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let status: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .context("malformed CH api response")?;
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, payload))
}

pub fn ch_api_ok(sock: &Path, method: &str, path: &str, body: Option<&str>) -> Result<()> {
    let (status, payload) = ch_api(sock, method, path, body)?;
    if !(200..300).contains(&status) {
        bail!("CH {method} {path} -> {status}: {payload}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kernel NBD attach/detach
// ---------------------------------------------------------------------------

fn nbd_lock() -> Result<std::fs::File> {
    let lock_path = std::env::temp_dir().join("cats-nbd.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    let rc = unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
    anyhow::ensure!(rc == 0, "flock nbd allocation lock failed");
    Ok(file)
}

fn nbd_device_busy(n: u32) -> bool {
    // A connected NBD device exposes a `pid` attribute.
    Path::new(&format!("/sys/block/nbd{n}/pid")).exists()
}

/// Attach the blockd unix socket to a specific or any free /dev/nbdN.
pub fn nbd_attach(
    cfg: &ChConfig,
    blockd_socket: &Path,
    want_device: Option<&str>,
) -> Result<String> {
    let _lock = nbd_lock()?;
    let candidates: Vec<String> = match want_device {
        Some(dev) => vec![dev.to_string()],
        None => (0..cfg.nbd_devices)
            .map(|n| format!("/dev/nbd{n}"))
            .collect(),
    };
    for dev in candidates {
        let n: u32 = dev
            .trim_start_matches("/dev/nbd")
            .parse()
            .unwrap_or(u32::MAX);
        if n == u32::MAX || nbd_device_busy(n) {
            if want_device.is_some() {
                bail!("required NBD device {dev} is busy");
            }
            continue;
        }
        let out = Command::new(&cfg.nbd_client_bin)
            .arg("-unix")
            .arg(blockd_socket)
            .arg(&dev)
            .args(["-b", "512", "-N", ""])
            .output()
            .context("run nbd-client")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if want_device.is_some() {
                bail!("nbd-client {dev} failed: {err}");
            }
            tracing::warn!("nbd-client {dev} failed, trying next: {err}");
            continue;
        }
        // Wait until the kernel reports a non-zero size.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let size: u64 = std::fs::read_to_string(format!("/sys/block/nbd{n}/size"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            if size > 0 {
                return Ok(dev);
            }
            if Instant::now() > deadline {
                bail!("{dev} attached but never reported a size");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    bail!("no free /dev/nbdN device (raise --ch-nbd-devices / nbds_max)")
}

pub fn nbd_detach(cfg: &ChConfig, dev: &str) {
    let _ = Command::new(&cfg.nbd_client_bin).args(["-d", dev]).output();
}

// ---------------------------------------------------------------------------
// Golden-root seeding: stream a raw image into a fresh volume through the
// userspace NBD client (skipping all-zero blocks: the volume is sparse).
// ---------------------------------------------------------------------------

pub fn seed_volume(blockd_socket: &Path, image: &Path) -> Result<()> {
    const STEP: usize = 1 << 20;
    let data =
        std::fs::read(image).with_context(|| format!("read seed image {}", image.display()))?;
    let mut client = NbdClient::connect_unix(blockd_socket)?;
    anyhow::ensure!(
        client.size() >= data.len() as u64,
        "volume ({}) smaller than seed image ({})",
        client.size(),
        data.len()
    );
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + STEP).min(data.len());
        let chunk = &data[off..end];
        if !chunk.iter().all(|&b| b == 0) {
            client.write(off as u64, chunk)?;
        }
        off = end;
    }
    client.flush()?;
    client.disconnect()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// VMM process control
// ---------------------------------------------------------------------------

pub struct ChSpawn<'a> {
    pub cfg: &'a ChConfig,
    pub api_sock: &'a Path,
    pub vsock_sock: &'a Path,
    pub serial_log: &'a Path,
    pub cpus: u32,
    pub memory_mib: u64,
    /// Root first; kernel names them vda, vdb, ... in order.
    pub disks: &'a [String],
    /// Restore from this snapshot directory instead of a fresh boot.
    pub restore_from: Option<&'a Path>,
}

pub fn spawn_vmm(s: &ChSpawn<'_>) -> Result<Child> {
    let _ = std::fs::remove_file(s.api_sock);
    let mut cmd = Command::new(&s.cfg.ch_bin);
    cmd.arg("--api-socket").arg(s.api_sock);
    match s.restore_from {
        Some(dir) => {
            cmd.arg("--restore")
                .arg(format!("source_url=file://{}", dir.display()));
        }
        None => {
            cmd.arg("--kernel").arg(&s.cfg.kernel);
            if let Some(initrd) = &s.cfg.initramfs {
                cmd.arg("--initramfs").arg(initrd);
            }
            cmd.arg("--cmdline").arg(&s.cfg.cmdline);
            cmd.arg("--cpus").arg(format!("boot={}", s.cpus.max(1)));
            cmd.arg("--memory")
                .arg(format!("size={}M", s.memory_mib.max(128)));
            cmd.arg("--vsock")
                .arg(format!("cid=3,socket={}", s.vsock_sock.display()));
            let mut disk_args: Vec<String> = s.disks.iter().map(|d| format!("path={d}")).collect();
            cmd.arg("--disk").args(disk_args.drain(..));
            cmd.arg("--serial")
                .arg(format!("file={}", s.serial_log.display()));
            cmd.arg("--console").arg("off");
        }
    }
    let log =
        std::fs::File::create(s.serial_log.with_file_name("vmm.log")).context("create vmm log")?;
    cmd.stdout(Stdio::null()).stderr(log);
    cmd.spawn().context("spawn cloud-hypervisor")
}

pub fn wait_api_ready(api_sock: &Path, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if ch_api(api_sock, "GET", "/api/v1/vm.ping", None).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("cloud-hypervisor exited during startup: {status}");
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for CH api socket");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn pause(api_sock: &Path) -> Result<()> {
    ch_api_ok(api_sock, "PUT", "/api/v1/vm.pause", None)
}

pub fn resume(api_sock: &Path) -> Result<()> {
    ch_api_ok(api_sock, "PUT", "/api/v1/vm.resume", None)
}

pub fn snapshot(api_sock: &Path, dest_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dest_dir)?;
    let body = serde_json::json!({
        "destination_url": format!("file://{}", dest_dir.display())
    })
    .to_string();
    ch_api_ok(api_sock, "PUT", "/api/v1/vm.snapshot", Some(&body))
}

pub fn shutdown_vmm(api_sock: &Path, child: &mut Child) {
    let _ = ch_api_ok(api_sock, "PUT", "/api/v1/vmm.shutdown", None);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

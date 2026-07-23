//! Cloud Hypervisor integration (the real-VMM half of the runtime seam).
//!
//! Phase A data path (correctness-first, per ADR-0001 ordering):
//!
//! ```text
//! guest virtio-blk -> CH built-in block backend -> /dev/nbdN (kernel NBD
//! client) -> cats-blockd NBD server -> ChunkEngine -> storage adapters
//! ```
//!
//! The kernel NBD hop reuses the fully crash-tested NBD frontend; a native
//! vhost-user-blk backend is the later performance milestone and does not
//! change any commit semantics. Guest control runs over CH hybrid vsock.
//! Warm uses `vm.snapshot` / `--restore` (the mechanism validated in the
//! 2026-07-21 experiments) with the snapshot on local disk.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
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
    /// Optional private /16 used for per-Cat tap networks (for example
    /// `10.240.0.0/16`). Host NAT is installed by the deployment scripts.
    pub network_cidr: Option<String>,
    pub ip_bin: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChNetwork {
    pub tap: String,
    pub mac: String,
    pub host_ip: String,
    pub guest_ip: String,
}

/// Per-cat runtime state that only exists in CH mode.
#[derive(Debug, Default, Clone)]
pub struct ChRuntime {
    pub api_sock: PathBuf,
    pub vsock_sock: PathBuf,
    /// disk_id -> /dev/nbdN (order matters for restore).
    pub nbd: HashMap<String, String>,
    pub snapshot_dir: Option<PathBuf>,
    /// Kept while Warm because the restored VMM reconnects to the same tap.
    pub network: Option<ChNetwork>,
}

fn stable_hash(value: &str) -> u64 {
    // FNV-1a: deterministic across processes and Rust releases, unlike
    // DefaultHasher. The slot only controls local addressing, never identity.
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn network_for(cidr: &str, cat_id: &str) -> Result<ChNetwork> {
    let (base, prefix) = cidr
        .split_once('/')
        .context("--ch-network-cidr must include /16")?;
    anyhow::ensure!(prefix == "16", "--ch-network-cidr must be a /16");
    let base: std::net::Ipv4Addr = base.parse().context("invalid --ch-network-cidr")?;
    let octets = base.octets();
    anyhow::ensure!(
        octets[2] == 0 && octets[3] == 0,
        "--ch-network-cidr must be aligned to a /16"
    );

    let hash = stable_hash(cat_id);
    // 16,383 non-overlapping /30s. Slot zero is intentionally unused.
    let offset = ((hash % 16_383) + 1) as u16 * 4;
    let third = (offset >> 8) as u8;
    let fourth = (offset & 0xff) as u8;
    let host_ip = format!("{}.{}.{}.{}/30", octets[0], octets[1], third, fourth + 1);
    let guest_ip = format!("{}.{}.{}.{}/30", octets[0], octets[1], third, fourth + 2);
    Ok(ChNetwork {
        tap: format!("cat{:011x}", hash & 0x7ff_ffff_ffff),
        // cats-init derives its address from these final two octets.
        mac: format!(
            "02:ca:{:02x}:{:02x}:{third:02x}:{:02x}",
            octets[0],
            octets[1],
            fourth + 2
        ),
        host_ip,
        guest_ip,
    })
}

fn ip_status(ip_bin: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new(ip_bin)
        .args(args)
        .output()
        .with_context(|| format!("run {} {}", ip_bin.display(), args.join(" ")))?;
    anyhow::ensure!(
        output.status.success(),
        "{} {} failed: {}",
        ip_bin.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

pub fn prepare_network(cfg: &ChConfig, cat_id: &str) -> Result<Option<ChNetwork>> {
    let Some(cidr) = cfg.network_cidr.as_deref() else {
        return Ok(None);
    };
    let network = network_for(cidr, cat_id)?;
    let _ = Command::new(&cfg.ip_bin)
        .args(["link", "delete", "dev", &network.tap])
        .output();
    let addresses = Command::new(&cfg.ip_bin)
        .args(["-o", "-4", "addr", "show"])
        .output()
        .with_context(|| format!("run {} -o -4 addr show", cfg.ip_bin.display()))?;
    anyhow::ensure!(
        addresses.status.success(),
        "{} -o -4 addr show failed: {}",
        cfg.ip_bin.display(),
        String::from_utf8_lossy(&addresses.stderr).trim()
    );
    let assigned = String::from_utf8_lossy(&addresses.stdout);
    anyhow::ensure!(
        !assigned.contains(&format!("inet {}", network.host_ip)),
        "Cat network address collision for {}",
        network.host_ip
    );
    ip_status(
        &cfg.ip_bin,
        &["tuntap", "add", "dev", &network.tap, "mode", "tap"],
    )?;
    if let Err(error) = (|| {
        ip_status(
            &cfg.ip_bin,
            &["addr", "add", &network.host_ip, "dev", &network.tap],
        )?;
        ip_status(&cfg.ip_bin, &["link", "set", "dev", &network.tap, "up"])
    })() {
        remove_network(cfg, &network);
        return Err(error);
    }
    Ok(Some(network))
}

pub fn remove_network(cfg: &ChConfig, network: &ChNetwork) {
    let _ = Command::new(&cfg.ip_bin)
        .args(["link", "delete", "dev", &network.tap])
        .output();
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

    // Cloud Hypervisor keeps its API connections alive even when the client
    // asks for `Connection: close`. Read the HTTP message according to its
    // Content-Length instead of waiting for EOF (which otherwise turns every
    // successful API call into a read timeout).
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .context("malformed CH api response")?;

    let mut content_length = None;
    let mut header_bytes = status_line.len();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        anyhow::ensure!(read > 0, "truncated CH api response headers");
        header_bytes += read;
        anyhow::ensure!(
            header_bytes <= 64 * 1024,
            "oversized CH api response headers"
        );
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .context("invalid CH api Content-Length")?,
                );
            }
        }
    }

    let mut payload = vec![0; content_length.unwrap_or(0)];
    reader.read_exact(&mut payload)?;
    let payload = String::from_utf8(payload).context("CH api response body is not UTF-8")?;
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
    // SAFETY: `file` owns a valid open descriptor for the duration of this
    // call, and `flock` does not retain the descriptor pointer.
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
    pub network: Option<&'a ChNetwork>,
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
            if let Some(network) = s.network {
                cmd.arg("--net")
                    .arg(format!("tap={},mac={}", network.tap, network.mac));
            }
            // image_type=raw is required: CH v53 otherwise auto-detects raw
            // and enables a sector-0 write protection that fails ext4 writes.
            let mut disk_args: Vec<String> = s
                .disks
                .iter()
                .map(|d| format!("path={d},image_type=raw"))
                .collect();
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
        // vmm.ping (not vm.ping): confirms the VMM HTTP thread is serving.
        if let Ok((status, _)) = ch_api(api_sock, "GET", "/api/v1/vmm.ping", None) {
            if (200..300).contains(&status) {
                return Ok(());
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    #[test]
    fn cat_network_is_stable_and_encodes_guest_address_in_mac() {
        let first = network_for("10.240.0.0/16", "cat_60e825c8c6cd").unwrap();
        let second = network_for("10.240.0.0/16", "cat_60e825c8c6cd").unwrap();
        assert_eq!(first, second);
        assert!(first.tap.len() <= 15);
        let ip = first.guest_ip.trim_end_matches("/30");
        let octets: Vec<u8> = ip.split('.').map(|part| part.parse().unwrap()).collect();
        assert!(first.mac.ends_with(&format!(
            "{:02x}:{:02x}:{:02x}:{:02x}",
            octets[0], octets[1], octets[2], octets[3]
        )));
    }

    #[test]
    fn cat_network_rejects_non_16_or_unaligned_cidr() {
        assert!(network_for("10.240.0.0/24", "cat").is_err());
        assert!(network_for("10.240.1.0/16", "cat").is_err());
    }

    #[test]
    fn ch_api_uses_content_length_without_waiting_for_eof() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ch-api.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let count = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..count]).contains("/api/v1/vmm.ping"));
            stream
                .write_all(
                    b"HTTP/1.1 200 \r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
                )
                .unwrap();
            // Reproduce CH v53: keep the connection open after the complete
            // response. The client must still return immediately.
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });

        let (status, body) = ch_api(&sock, "GET", "/api/v1/vmm.ping", None).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, r#"{"ok":true}"#);
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }
}

//! Cloud Hypervisor integration (the real-VMM half of the runtime seam).
//!
//! Two Guest block data paths, selected by [`ChConfig::block_path`]:
//!
//! ```text
//! kernel-nbd (Phase A, the correctness-first path of ADR-0001):
//!   guest virtio-blk -> CH built-in block backend -> /dev/nbdN (kernel NBD
//!   client) -> cats-blockd NBD server -> ChunkEngine -> storage adapters
//!
//! vhost-user (ADR-0015):
//!   guest virtio-blk -> CH vhost-user-blk client -> cats-blockd vhost-user
//!   backend -> ChunkEngine -> storage adapters
//! ```
//!
//! Both frontends drive the same engine and the same commit protocol, so the
//! choice is a performance/operational one, not a correctness one: the kernel
//! NBD hop needs `nbd-client` plus a `/dev/nbdN` device per disk, while
//! vhost-user needs shared Guest memory (already required here for
//! `MADV_PAGEOUT`) and no host block device at all. Guest control runs over CH
//! hybrid vsock.
//! Warm uses `vm.snapshot` / `--restore` (the mechanism validated in the
//! 2026-07-21 experiments) with the snapshot on local disk. Suspended uses a
//! per-Cat, file-backed memory zone and process_madvise(MADV_PAGEOUT), so it
//! reclaims Guest RAM without depending on host swap.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::proc::ProcHandle;

/// Guest-agent vsock port (must match the guest image's init script).
pub const GUEST_VSOCK_PORT: u32 = 5000;
/// Named, per-Cat RAM backing kept under the Cat's host-local runtime.
pub const GUEST_MEMORY_FILE: &str = "guest-memory.bin";
const MIB: u64 = 1024 * 1024;

/// Which frontend of `cats-blockd` the Guest's virtio-blk devices are served by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockPath {
    /// Phase A: `nbd-client` binds the backend to `/dev/nbdN` and Cloud
    /// Hypervisor's built-in block backend serves the Guest from that device.
    #[default]
    KernelNbd,
    /// Cloud Hypervisor talks vhost-user-blk directly to `cats-blockd`.
    VhostUser,
}

impl BlockPath {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "kernel-nbd" => Ok(Self::KernelNbd),
            "vhost-user" => Ok(Self::VhostUser),
            other => bail!("unknown block path {other} (expected kernel-nbd|vhost-user)"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::KernelNbd => "kernel-nbd",
            Self::VhostUser => "vhost-user",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChConfig {
    /// Open the kernel-NBD block device with O_DIRECT, bypassing the host page
    /// cache. Only meaningful on [`BlockPath::KernelNbd`]; the vhost-user path
    /// never had a host-side cache to bypass.
    pub block_direct: bool,
    pub ch_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    /// Kernel command line; `root=/dev/vda` etc.
    pub cmdline: String,
    /// Golden root: the raw image a generation-0 root volume is provisioned from.
    /// Published once per digest and then referenced, not copied (ADR-0017), so
    /// this is passed to `cats-blockd` rather than streamed through a frontend.
    pub seed_image: Option<PathBuf>,
    pub block_path: BlockPath,
    /// Upper bound on virtio-blk queues per disk on the vhost-user path; the
    /// effective count is [`vhost_user_queues_for`], because Cloud Hypervisor
    /// rejects a queue count above the Cat's boot vCPUs. One worker thread per
    /// queue in `cats-blockd`, so this bounds per-disk request concurrency.
    pub vhost_user_queues: usize,
    /// Depth of each virtio-blk queue (power of two).
    pub vhost_user_queue_size: u16,
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
    /// Sparse file-backed Guest RAM. It survives Suspended/Warm and is
    /// removed with the rest of the Cat runtime when the Cat becomes Cold.
    pub memory_file: PathBuf,
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
        // The Guest's early cats-network service derives its address from
        // these final two octets before Guest Agent readiness.
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
// VMM process control
// ---------------------------------------------------------------------------

/// `--disk` argument for a host block device or file.
///
/// `image_type=raw` is required: CH v53 otherwise auto-detects raw and enables a
/// sector-0 write protection that fails ext4 writes.
pub fn file_disk_arg(path: &str, direct: bool) -> String {
    // `direct=on` makes Cloud Hypervisor open the device with O_DIRECT, so the
    // host page cache stops acking Guest writes before the engine has seen them.
    // Off (CH's default) is faster on paper and the write is not durable yet;
    // on is slower and honest. It is also the only way to compare this path with
    // vhost-user, which has no such cache -- without it every write number is a
    // page-cache measurement (see ADR-0015).
    let direct = if direct { "on" } else { "off" };
    format!("path={path},image_type=raw,direct={direct}")
}

/// Effective virtio-blk queue count for one Cat.
///
/// Cloud Hypervisor validates `num_queues <= boot vCPUs` and refuses to start
/// otherwise (`TooManyQueues`), so the node-level maximum has to be clamped per
/// Cat. The Guest driver maps queues to vCPUs anyway, so more queues than vCPUs
/// would buy nothing.
pub fn vhost_user_queues_for(cfg: &ChConfig, cpus: u32) -> usize {
    cfg.vhost_user_queues.clamp(1, cpus.max(1) as usize)
}

/// `--disk` argument for a `cats-blockd` vhost-user-blk backend.
///
/// `num_queues` and `queue_size` must match what the backend was started with:
/// the VMM configures exactly the queues it is told about, and a mismatch shows
/// up as a Guest device that never completes a request.
pub fn vhost_user_disk_arg(socket: &Path, num_queues: usize, queue_size: u16) -> Result<String> {
    let socket = socket
        .to_str()
        .context("vhost-user socket path is not UTF-8")?;
    anyhow::ensure!(
        !socket.contains(','),
        "vhost-user socket path cannot contain a comma"
    );
    Ok(format!(
        "vhost_user=on,socket={socket},num_queues={num_queues},queue_size={queue_size}"
    ))
}

pub struct ChSpawn<'a> {
    pub cfg: &'a ChConfig,
    pub api_sock: &'a Path,
    pub vsock_sock: &'a Path,
    pub serial_log: &'a Path,
    pub cpus: u32,
    pub memory_mib: u64,
    /// Required for a fresh boot. Snapshot restore reopens the path recorded
    /// in the Cloud Hypervisor snapshot.
    pub memory_file: Option<&'a Path>,
    /// Fully formed `--disk` arguments, root first: the kernel names them vda,
    /// vdb, ... in order. Build them with [`file_disk_arg`] or
    /// [`vhost_user_disk_arg`].
    pub disks: &'a [String],
    /// Restore from this snapshot directory instead of a fresh boot.
    pub restore_from: Option<&'a Path>,
    pub network: Option<&'a ChNetwork>,
}

pub fn spawn_vmm(s: &ChSpawn<'_>) -> Result<Child> {
    let _ = std::fs::remove_file(s.api_sock);
    let _ = std::fs::remove_file(s.vsock_sock);
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
            let memory_file = s
                .memory_file
                .context("fresh Cloud Hypervisor boot requires a memory backing file")?;
            anyhow::ensure!(
                !memory_file.as_os_str().to_string_lossy().contains(','),
                "memory backing path cannot contain a comma"
            );
            // A named MAP_SHARED memory zone is required for MADV_PAGEOUT to
            // write dirty Guest pages to local NVMe on hosts without swap. It
            // is also what makes vhost-user possible: the backend has to be able
            // to map the Guest's virtqueues and payload pages.
            cmd.arg("--memory").arg("size=0");
            cmd.arg("--memory-zone").arg(format!(
                "id=cat-ram,size={}M,file={},shared=on",
                s.memory_mib.max(128),
                memory_file.display()
            ));
            cmd.arg("--vsock")
                .arg(format!("cid=3,socket={}", s.vsock_sock.display()));
            if let Some(network) = s.network {
                cmd.arg("--net")
                    .arg(format!("tap={},mac={}", network.tap, network.mac));
            }
            cmd.arg("--disk").args(s.disks);
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

/// Create a zero-filled sparse RAM backing. Sparse allocation avoids charging
/// untouched Guest pages to local NVMe; MADV_PAGEOUT allocates only pages that
/// the Guest actually dirtied.
pub fn prepare_memory_backing(path: &Path, memory_mib: u64) -> Result<()> {
    let bytes = memory_mib
        .max(128)
        .checked_mul(MIB)
        .context("Guest memory size overflow")?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create Guest memory backing {}", path.display()))?;
    file.set_len(bytes)
        .with_context(|| format!("size Guest memory backing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Make file-backed Guest RAM durable before exiting the VMM for Warm.
pub fn sync_memory_backing(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open Guest memory backing {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync Guest memory backing {}", path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageOutStats {
    pub ranges: usize,
    pub bytes_advised: u64,
    pub rss_before_bytes: u64,
    pub rss_after_bytes: u64,
}

#[cfg(any(target_os = "linux", test))]
fn parse_backing_ranges(maps: &str, backing: &Path) -> Result<Vec<(usize, usize)>> {
    let expected = backing
        .to_str()
        .context("Guest memory backing path is not UTF-8")?;
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(perms) = fields.next() else {
            continue;
        };
        let _offset = fields.next();
        let _device = fields.next();
        let _inode = fields.next();
        let path = fields.collect::<Vec<_>>().join(" ");
        if path.is_empty() {
            continue;
        }
        if path != expected || !perms.starts_with("rw") {
            continue;
        }
        let (start, end) = range
            .split_once('-')
            .context("malformed process memory range")?;
        let start = usize::from_str_radix(start, 16).context("invalid memory range start")?;
        let end = usize::from_str_radix(end, 16).context("invalid memory range end")?;
        anyhow::ensure!(end > start, "empty process memory range");
        ranges.push((start, end));
    }
    Ok(ranges)
}

#[cfg(target_os = "linux")]
fn process_rss_bytes(pid: u32) -> Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("read status for VMM pid {pid}"))?;
    let rss_kib = status
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("VmRSS:")?.trim();
            value.split_whitespace().next()?.parse::<u64>().ok()
        })
        .context("VMM status did not contain VmRSS")?;
    rss_kib.checked_mul(1024).context("VMM RSS overflow")
}

/// One `MADV_PAGEOUT` walk of `[start, end)`, returning the bytes advised.
///
/// The kernel reports partial progress, so this loops until the range is
/// covered. Each call is capped at 1 GiB per iovec to match the validated
/// reference helper rather than handing the kernel an unbounded length.
#[cfg(target_os = "linux")]
fn advise_pageout(pidfd: std::os::fd::RawFd, pid: u32, start: usize, end: usize) -> Result<u64> {
    const MAX_IOV_BYTES: usize = 1 << 30;
    let mut advised_total = 0u64;
    let mut cursor = start;
    while cursor < end {
        let len = (end - cursor).min(MAX_IOV_BYTES);
        let mut iov = libc::iovec {
            iov_base: cursor as *mut libc::c_void,
            iov_len: len,
        };
        // SAFETY: process_madvise interprets the iovec addresses in the pidfd
        // target. The VMM is paused and remains our supervised child.
        let advised = unsafe {
            libc::syscall(
                libc::SYS_process_madvise,
                pidfd,
                &mut iov as *mut libc::iovec,
                1usize,
                libc::MADV_PAGEOUT,
                0u32,
            )
        };
        if advised < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("MADV_PAGEOUT VMM pid {pid}"));
        }
        anyhow::ensure!(advised > 0, "MADV_PAGEOUT made no progress");
        let advised = advised as usize;
        anyhow::ensure!(
            advised <= len,
            "MADV_PAGEOUT returned an invalid byte count"
        );
        cursor += advised;
        advised_total = advised_total
            .checked_add(advised as u64)
            .context("page-out byte count overflow")?;
    }
    Ok(advised_total)
}

#[cfg(target_os = "linux")]
pub fn page_out_memory(pid: u32, backing: &Path) -> Result<PageOutStats> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("read memory maps for VMM pid {pid}"))?;
    let ranges = parse_backing_ranges(&maps, backing)?;
    anyhow::ensure!(
        !ranges.is_empty(),
        "VMM does not map expected Guest memory backing {}",
        backing.display()
    );

    // SAFETY: pidfd_open returns a new owned fd on success.
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw_pidfd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("pidfd_open VMM pid {pid}"));
    }
    // SAFETY: raw_pidfd was returned as a new descriptor above.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd as i32) };

    let rss_before_bytes = process_rss_bytes(pid)?;
    let mut bytes_advised = 0u64;
    for (start, end) in &ranges {
        bytes_advised = bytes_advised
            .checked_add(advise_pageout(pidfd.as_raw_fd(), pid, *start, *end)?)
            .context("page-out byte count overflow")?;
    }
    // Flush the file-backed zone so the pages the first pass left dirty become
    // clean and therefore reclaimable. Without this the second pass has
    // nothing new to drop.
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe { libc::sync() };
    // Second pass: reclaims the now-clean pages where the mapping topology
    // permits it. The 2026-07-21 reclaim ratios (97.7-98.5% of Guest RAM)
    // were measured with both passes, so a single pass does not reproduce
    // the validated Suspended footprint. Byte counts from this pass are not
    // added to `bytes_advised`, which reports the range walked once.
    for (start, end) in &ranges {
        advise_pageout(pidfd.as_raw_fd(), pid, *start, *end)?;
    }
    let rss_after_bytes = process_rss_bytes(pid)?;
    Ok(PageOutStats {
        ranges: ranges.len(),
        bytes_advised,
        rss_before_bytes,
        rss_after_bytes,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn page_out_memory(_pid: u32, _backing: &Path) -> Result<PageOutStats> {
    bail!("Guest memory page-out requires Linux")
}

pub(crate) fn wait_api_ready(api_sock: &Path, vmm: &mut ProcHandle) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        // vmm.ping (not vm.ping): confirms the VMM HTTP thread is serving.
        if let Ok((status, _)) = ch_api(api_sock, "GET", "/api/v1/vmm.ping", None) {
            if (200..300).contains(&status) {
                return Ok(());
            }
        }
        if vmm.exited()? {
            bail!("cloud-hypervisor exited during startup");
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for CH api socket");
        }
        std::thread::sleep(Duration::from_millis(10));
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

pub(crate) fn shutdown_vmm(api_sock: &Path, vmm: &mut ProcHandle) {
    let _ = ch_api_ok(api_sock, "PUT", "/api/v1/vmm.shutdown", None);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        // A probe that fails is not evidence of an exit; keep waiting.
        if vmm.exited().unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    vmm.kill_and_reap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    #[test]
    fn block_path_round_trips_and_rejects_unknown_values() {
        for path in [BlockPath::KernelNbd, BlockPath::VhostUser] {
            assert_eq!(BlockPath::parse(path.as_str()).unwrap(), path);
        }
        assert!(BlockPath::parse("vhost_user").is_err());
        // The Phase A path stays the default until the vhost-user path passes a
        // real-VMM acceptance run (ADR-0015).
        assert_eq!(BlockPath::default(), BlockPath::KernelNbd);
    }

    #[test]
    fn queue_count_never_exceeds_the_cats_vcpus() {
        let mut cfg = ChConfig {
            block_direct: false,
            ch_bin: PathBuf::from("ch"),
            kernel: PathBuf::from("vmlinuz"),
            initramfs: None,
            cmdline: String::new(),
            seed_image: None,
            block_path: BlockPath::VhostUser,
            vhost_user_queues: 4,
            vhost_user_queue_size: 256,
            nbd_client_bin: PathBuf::from("nbd-client"),
            nbd_devices: 8,
            network_cidr: None,
            ip_bin: PathBuf::from("ip"),
        };
        // Cloud Hypervisor rejects num_queues > boot vCPUs, so a 1-vCPU Cat on a
        // node configured for 4 queues must still start.
        assert_eq!(vhost_user_queues_for(&cfg, 1), 1);
        assert_eq!(vhost_user_queues_for(&cfg, 2), 2);
        assert_eq!(vhost_user_queues_for(&cfg, 8), 4);
        // A zero vCPU count cannot happen, but must not produce zero queues.
        assert_eq!(vhost_user_queues_for(&cfg, 0), 1);
        cfg.vhost_user_queues = 1;
        assert_eq!(vhost_user_queues_for(&cfg, 16), 1);
    }

    #[test]
    fn disk_arguments_describe_both_block_paths() {
        assert_eq!(
            file_disk_arg("/dev/nbd3", false),
            "path=/dev/nbd3,image_type=raw,direct=off",
            "image_type is required for CH v53 raw disks"
        );
        // direct=on is what makes a kernel-nbd measurement comparable with
        // vhost-user: without it the host page cache acks writes the engine has
        // not seen (ADR-0015).
        assert_eq!(
            file_disk_arg("/dev/nbd3", true),
            "path=/dev/nbd3,image_type=raw,direct=on"
        );
        assert_eq!(
            vhost_user_disk_arg(Path::new("/tmp/cats-sock/abc.sock"), 4, 256).unwrap(),
            "vhost_user=on,socket=/tmp/cats-sock/abc.sock,num_queues=4,queue_size=256"
        );
        // A comma would silently split into another CH disk option.
        assert!(vhost_user_disk_arg(Path::new("/tmp/a,b.sock"), 1, 256).is_err());
    }

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
    fn memory_backing_is_sparse_sized_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GUEST_MEMORY_FILE);
        prepare_memory_backing(&path, 256).unwrap();
        let metadata = path.metadata().unwrap();
        assert_eq!(metadata.len(), 256 * MIB);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn backing_range_parser_selects_only_writable_exact_file_mappings() {
        let maps = "\
1000-2000 rw-s 00000000 08:01 1 /var/lib/cats/cat/guest-memory.bin\n\
2000-3000 r--s 00001000 08:01 1 /var/lib/cats/cat/guest-memory.bin\n\
3000-5000 rw-s 00002000 08:01 1 /var/lib/cats/cat/guest-memory.bin\n\
5000-6000 rw-p 00000000 00:00 0 [heap]\n";
        assert_eq!(
            parse_backing_ranges(maps, Path::new("/var/lib/cats/cat/guest-memory.bin")).unwrap(),
            vec![(0x1000, 0x2000), (0x3000, 0x5000)]
        );
    }

    #[test]
    fn fresh_vmm_uses_shared_file_backed_memory_zone() {
        let dir = tempfile::tempdir().unwrap();
        let args_path = dir.path().join("args");
        let fake_ch = dir.path().join("cloud-hypervisor");
        std::fs::write(
            &fake_ch,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                args_path.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ch, std::fs::Permissions::from_mode(0o755)).unwrap();
        let kernel = dir.path().join("vmlinuz");
        std::fs::write(&kernel, []).unwrap();
        let memory_file = dir.path().join(GUEST_MEMORY_FILE);
        prepare_memory_backing(&memory_file, 256).unwrap();
        let cfg = ChConfig {
            block_direct: false,
            ch_bin: fake_ch,
            kernel,
            initramfs: None,
            cmdline: "console=ttyS0".into(),
            seed_image: None,
            block_path: BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin: PathBuf::from("nbd-client"),
            nbd_devices: 8,
            network_cidr: None,
            ip_bin: PathBuf::from("ip"),
        };
        let serial = dir.path().join("serial.log");
        let mut child = spawn_vmm(&ChSpawn {
            cfg: &cfg,
            api_sock: &dir.path().join("api.sock"),
            vsock_sock: &dir.path().join("vsock.sock"),
            serial_log: &serial,
            cpus: 2,
            memory_mib: 256,
            memory_file: Some(&memory_file),
            disks: &[],
            restore_from: None,
            network: None,
        })
        .unwrap();
        assert!(child.wait().unwrap().success());
        let args = std::fs::read_to_string(args_path).unwrap();
        assert!(args.contains("--memory\nsize=0\n"));
        assert!(args.contains(&format!(
            "--memory-zone\nid=cat-ram,size=256M,file={},shared=on\n",
            memory_file.display()
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn page_out_preserves_shared_backing_contents() {
        use std::os::fd::AsRawFd;

        const LEN: usize = 32 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let memory_file = dir.path().join(GUEST_MEMORY_FILE);
        prepare_memory_backing(&memory_file, 32).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&memory_file)
            .unwrap();
        // SAFETY: the test owns this file and unmaps the returned mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        for offset in (0..LEN).step_by(4096) {
            // SAFETY: every offset is within the mapping above.
            unsafe { (mapping.cast::<u8>().add(offset)).write_volatile(0x5a) };
        }

        let stats = match page_out_memory(std::process::id(), &memory_file) {
            Ok(stats) => stats,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    .is_some_and(|code| code == libc::ENOSYS || code == libc::EPERM) =>
            {
                // Some container runtimes block pidfd/process_madvise. The
                // production worker capability is checked separately.
                // SAFETY: mapping and length are owned by this test.
                assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
                return;
            }
            Err(error) => panic!("page-out probe failed: {error:#}"),
        };
        assert!(stats.bytes_advised >= LEN as u64);
        for offset in [0, LEN / 2, LEN - 4096] {
            // SAFETY: these offsets are within the mapping and may refault the
            // page from the backing file after MADV_PAGEOUT.
            let byte = unsafe { (mapping.cast::<u8>().add(offset)).read_volatile() };
            assert_eq!(byte, 0x5a);
        }
        // SAFETY: mapping and length are the values returned to this test.
        assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
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

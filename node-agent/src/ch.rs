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

/// Where the kernel publishes per-device NBD state, and where process liveness
/// is read from.
///
/// Fixed in production. It is a value rather than a constant only so the scan
/// and the reclaim sweep can be exercised against a fixture on a host that has
/// no nbd driver.
#[derive(Debug, Clone)]
struct NbdSysfs {
    sys_block: PathBuf,
    proc_root: PathBuf,
}

impl Default for NbdSysfs {
    fn default() -> Self {
        Self {
            sys_block: PathBuf::from("/sys/block"),
            proc_root: PathBuf::from("/proc"),
        }
    }
}

/// What the kernel currently holds on one `/dev/nbdN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NbdDeviceState {
    /// No server and no capacity: allocatable.
    Free,
    /// A live process is serving the device.
    Serving { pid: i32 },
    /// The kernel still has the device connected, but nothing is serving it.
    ///
    /// The slot is spent: it can never be allocated and, on a device attached
    /// the way an older node agent attached them, nothing but an explicit
    /// disconnect gets it back. 27 of a 64-device pool were in this state on
    /// `metal-1` on 2026-08-04, and nothing reported the number.
    ///
    /// I/O to such a device fails rather than hangs — a measured `EIO` in
    /// every mode tried (`experiments/nbd-attach-mode-20260804/`). That run
    /// did not reproduce the uninterruptible-sleep stalls seen during the
    /// incident, so treat those as observed alongside pool exhaustion, not as
    /// demonstrated to follow from touching one of these.
    Leaked { pid: Option<i32> },
}

/// Attach through the classic ioctl interface instead of `nbd-client`'s
/// default netlink one.
///
/// This is what makes a leaked device both rare and recognizable, measured on
/// Linux 6.17 with nbd-client 3.26.1 against a real `cats-blockd`
/// (`experiments/nbd-attach-mode-20260804/`):
///
/// * Netlink leaves no process behind. `/sys/block/nbdN/pid` names the
///   nbd-client that configured the device and then exited, so it is a dead
///   pid on a perfectly healthy device -- a leaked device and a working one
///   are byte-for-byte identical in sysfs, and no scan can tell them apart.
///   Worse, nothing ever reclaims one: with no resident client the kernel
///   holds the configuration open waiting for a reconnect that never comes,
///   and the device stays connected even after its last opener closes.
/// * ioctl keeps one `nbd-client` resident per device. When the server dies
///   the client's ioctl returns and it clears the socket, so the usual case
///   reclaims itself. When something still holds the device open -- Cloud
///   Hypervisor, in production -- the device is left with a *dead* recorded
///   pid and a non-zero size, which is exactly the state
///   [`NbdDeviceState::Leaked`] recognizes.
///
/// The trade-off, same run: sequential O_DIRECT writes are a wash (36.0/36.1
/// vs 36.0/33.4 MB/s), 4 KiB random writes measured 7-12% lower under ioctl
/// (55.0/51.7 vs 59.2/58.6 MiB/s over two rounds each). That is a debug build
/// against a file-backed object store, so it bounds nothing in production; see
/// ADR-0015 for why this is a question about the kernel-NBD default at all.
const NBD_IOCTL_MODE: &str = "-nonetlink";

/// A leaked device is disconnected before the node agent registers, so the
/// sweep must not be the reason a host stays out of service. All of them are
/// disconnected concurrently and share this deadline.
const NBD_RECLAIM_TIMEOUT: Duration = Duration::from_secs(30);
/// The kernel clears `pid` and resets the capacity from the disconnect ioctl,
/// not necessarily before `nbd-client` has exited.
const NBD_SETTLE_TIMEOUT: Duration = Duration::from_secs(2);

fn nbd_attribute(sysfs: &NbdSysfs, n: u32, name: &str) -> Option<String> {
    std::fs::read_to_string(sysfs.sys_block.join(format!("nbd{n}")).join(name))
        .ok()
        .map(|value| value.trim().to_string())
}

fn nbd_device_state_of(sysfs: &NbdSysfs, n: u32) -> NbdDeviceState {
    // A connected NBD device exposes a `pid` attribute naming the task that
    // serves it, and a non-zero `size`. Both are driver attributes: reading
    // them costs no I/O to the device at all (measured at 1-2 ms against
    // leaked devices), which is what makes this scan cheap enough to run on
    // the heartbeat and safe to point at devices nothing is serving.
    // This only discriminates because the attach uses [`NBD_IOCTL_MODE`]: the
    // recorded pid is then a resident `nbd-client`, alive for exactly as long
    // as the device is served. Under nbd-client's default netlink mode the
    // recorded pid is dead on healthy devices too, and every judgement below
    // would be a false positive.
    let pid = nbd_attribute(sysfs, n, "pid").and_then(|pid| pid.parse::<i32>().ok());
    match pid {
        // A live pid is trusted. Proving it is still the *same* process that
        // attached needs the recorded process identity (start ticks), which
        // the node agent does not persist today; without it, pid reuse can
        // only make this scan leave a leaked device alone, never disconnect a
        // live one.
        Some(pid) if pid > 0 && sysfs.proc_root.join(pid.to_string()).is_dir() => {
            NbdDeviceState::Serving { pid }
        }
        Some(pid) => NbdDeviceState::Leaked { pid: Some(pid) },
        // No serving task, but the kernel still reports a capacity: the device
        // is half torn down, and just as unusable.
        None => {
            let sectors = nbd_attribute(sysfs, n, "size")
                .and_then(|size| size.parse::<u64>().ok())
                .unwrap_or(0);
            if sectors > 0 {
                NbdDeviceState::Leaked { pid: None }
            } else {
                NbdDeviceState::Free
            }
        }
    }
}

/// Whether a live process still has `/dev/nbdN` open.
///
/// The guard on every disconnect this module issues. A device attached by an
/// older node agent — before [`NBD_IOCTL_MODE`] — records a dead pid even when
/// it is healthy and serving a Cat, so on the first boot after that change the
/// sweep would otherwise pull the disk out from under a running Guest. Nothing
/// in sysfs distinguishes those two, but an open file descriptor does: Cloud
/// Hypervisor holds the device for as long as the Cat runs, and a genuinely
/// leaked device is held by nobody.
///
/// Conservative in the safe direction. A leaked device that some orphan still
/// holds open is left alone and stays visible in the leak count until that
/// process goes; a device in use is never disconnected.
fn nbd_device_is_open(sysfs: &NbdSysfs, n: u32) -> bool {
    let device = PathBuf::from(format!("/dev/nbd{n}"));
    let Ok(entries) = std::fs::read_dir(&sysfs.proc_root) else {
        // Without /proc there is no way to prove the device is unused, and an
        // unprovable disconnect is not one worth issuing.
        return true;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_digit())
        {
            continue;
        }
        let Ok(descriptors) = std::fs::read_dir(entry.path().join("fd")) else {
            // A process that exited mid-scan, or one this agent may not look
            // into. Neither can be holding a device open on our behalf.
            continue;
        };
        for descriptor in descriptors.flatten() {
            if std::fs::read_link(descriptor.path()).is_ok_and(|target| target == device) {
                return true;
            }
        }
    }
    false
}

fn leaked_nbd_devices_of(sysfs: &NbdSysfs, devices: u32) -> Vec<u32> {
    (0..devices)
        .filter(|n| {
            matches!(
                nbd_device_state_of(sysfs, *n),
                NbdDeviceState::Leaked { .. }
            )
        })
        .collect()
}

/// How many devices in the pool the kernel holds connected with no server
/// behind them.
///
/// Cheap enough for the heartbeat: two attribute reads per device. Nothing
/// reported this count before, so a pool that was two thirds leaked looked
/// exactly like a pool that was two thirds busy (issue #79).
pub fn leaked_nbd_device_count(cfg: &ChConfig) -> u64 {
    leaked_nbd_devices_of(&NbdSysfs::default(), cfg.nbd_devices).len() as u64
}

/// What one reclaim sweep managed to disconnect.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NbdReclaim {
    pub reclaimed: Vec<String>,
    /// Still connected after the sweep asked for a disconnect, usually
    /// because something still holds the device open. Excluded from
    /// allocation until it settles.
    pub unreclaimed: Vec<String>,
}

/// Disconnect every device the kernel holds connected to a server that is gone.
///
/// The node agent runs this at boot, before it registers and can be given a
/// `StartCat`. A blockd killed without a teardown — which one `systemctl stop`
/// of the worker does to every blockd in the unit cgroup — leaves its device
/// behind, and nothing else ever reclaims it, so without this pass the pool
/// only shrinks (issue #79).
pub fn reclaim_leaked_nbd_devices(cfg: &ChConfig) -> Result<NbdReclaim> {
    let sysfs = NbdSysfs::default();
    let _lock = nbd_lock()?;
    Ok(reclaim_leaked_nbd_devices_of(cfg, &sysfs))
}

fn reclaim_leaked_nbd_devices_of(cfg: &ChConfig, sysfs: &NbdSysfs) -> NbdReclaim {
    let mut report = NbdReclaim::default();
    let leaked = leaked_nbd_devices_of(sysfs, cfg.nbd_devices);
    if leaked.is_empty() {
        return report;
    }
    tracing::warn!(
        leaked = leaked.len(),
        pool = cfg.nbd_devices,
        "reclaiming kernel NBD devices left connected to a dead server"
    );
    // Disconnect concurrently: `nbd-client -d` has always returned promptly in
    // practice (all 27 devices of the 2026-08-04 incident disconnected
    // cleanly), but one that does not must not hold up the whole node.
    let mut pending: Vec<(u32, String, Option<Child>)> = Vec::new();
    for n in leaked {
        let dev = format!("/dev/nbd{n}");
        if nbd_device_is_open(sysfs, n) {
            tracing::warn!(
                device = %dev,
                "leaving a leaked NBD device alone: a live process still has it open"
            );
            report.unreclaimed.push(dev);
            continue;
        }
        match Command::new(&cfg.nbd_client_bin)
            .args(["-d", &dev])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => pending.push((n, dev, Some(child))),
            Err(error) => {
                tracing::error!(device = %dev, %error, "could not run nbd-client");
                pending.push((n, dev, None));
            }
        }
    }
    let deadline = Instant::now() + NBD_RECLAIM_TIMEOUT;
    for (n, dev, child) in &mut pending {
        if let Some(child) = child {
            wait_for_exit(child, deadline);
        }
        if wait_until_free(sysfs, *n, deadline) {
            report.reclaimed.push(std::mem::take(dev));
        } else {
            report.unreclaimed.push(std::mem::take(dev));
        }
    }
    report
}

/// Wait for a child until `deadline` and then stop waiting on it.
///
/// A `nbd-client -d` that is itself stuck in the kernel cannot be killed, so
/// abandoning it is all the deadline can do; it is reaped by the next wait if
/// it ever finishes.
fn wait_for_exit(child: &mut Child, deadline: Instant) {
    loop {
        match child.try_wait() {
            Ok(None) => {}
            _ => return,
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_until_free(sysfs: &NbdSysfs, n: u32, deadline: Instant) -> bool {
    let deadline = deadline.min(Instant::now() + NBD_SETTLE_TIMEOUT);
    loop {
        if nbd_device_state_of(sysfs, n) == NbdDeviceState::Free {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Disconnect one leaked device and report whether the kernel let go of it.
///
/// A `false` here does not mean the disconnect was refused: a device someone
/// still holds open keeps its attributes until the last opener closes
/// (measured: cleared 200 ms after the holder exited). Either way it is not
/// safe to allocate, which is all the caller asks.
fn reclaim_nbd_device(cfg: &ChConfig, sysfs: &NbdSysfs, n: u32) -> bool {
    if nbd_device_is_open(sysfs, n) {
        return false;
    }
    nbd_detach(cfg, &format!("/dev/nbd{n}"));
    wait_until_free(sysfs, n, Instant::now() + NBD_SETTLE_TIMEOUT)
}

/// Attach the blockd unix socket to a specific or any free /dev/nbdN.
pub fn nbd_attach(
    cfg: &ChConfig,
    blockd_socket: &Path,
    want_device: Option<&str>,
) -> Result<String> {
    let sysfs = NbdSysfs::default();
    let _lock = nbd_lock()?;
    let candidates: Vec<String> = match want_device {
        Some(dev) => vec![dev.to_string()],
        None => (0..cfg.nbd_devices)
            .map(|n| format!("/dev/nbd{n}"))
            .collect(),
    };
    let mut serving = 0;
    let mut unreclaimable = 0;
    for dev in candidates {
        let Ok(n) = dev.trim_start_matches("/dev/nbd").parse::<u32>() else {
            bail!("required NBD device {dev} is not a kernel NBD device");
        };
        match nbd_device_state_of(&sysfs, n) {
            NbdDeviceState::Free => {}
            NbdDeviceState::Serving { pid } => {
                if want_device.is_some() {
                    bail!("required NBD device {dev} is busy (served by pid {pid})");
                }
                serving += 1;
                continue;
            }
            // Never hand a Cat a device the kernel still has connected to a
            // dead server: its I/O fails, so the Guest would come up with a
            // broken root disk. Reclaiming here also returns the slot to the
            // pool instead of losing it until the next boot.
            NbdDeviceState::Leaked { pid } => {
                tracing::warn!(
                    device = %dev,
                    leaked_pid = ?pid,
                    "reclaiming a kernel NBD device left connected to a dead server"
                );
                if !reclaim_nbd_device(cfg, &sysfs, n) {
                    tracing::error!(device = %dev, "leaked NBD device is still connected after a disconnect; something is holding it open");
                    if want_device.is_some() {
                        bail!("required NBD device {dev} is leaked and is still connected");
                    }
                    unreclaimable += 1;
                    continue;
                }
            }
        }
        let out = Command::new(&cfg.nbd_client_bin)
            .arg(NBD_IOCTL_MODE)
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
            let size: u64 = nbd_attribute(&sysfs, n, "size")
                .and_then(|size| size.parse().ok())
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
    bail!(
        "no free /dev/nbdN device in a pool of {} ({serving} busy, {unreclaimable} leaked and \
         still connected); raise --ch-nbd-devices / nbds_max",
        cfg.nbd_devices
    )
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

    /// A stand-in for `/sys/block` and `/proc`, so the leak scan can be
    /// exercised on a host that has no nbd driver.
    struct FakeSysfs {
        _dir: tempfile::TempDir,
        sysfs: NbdSysfs,
    }

    impl FakeSysfs {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let sysfs = NbdSysfs {
                sys_block: dir.path().join("sys-block"),
                proc_root: dir.path().join("proc"),
            };
            std::fs::create_dir_all(&sysfs.sys_block).unwrap();
            std::fs::create_dir_all(&sysfs.proc_root).unwrap();
            Self { _dir: dir, sysfs }
        }

        fn device(&self, n: u32) -> PathBuf {
            let dir = self.sysfs.sys_block.join(format!("nbd{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// The kernel's view of a connected device: a serving task and a size.
        fn connected(&self, n: u32, pid: i32) {
            let dir = self.device(n);
            std::fs::write(dir.join("pid"), format!("{pid}\n")).unwrap();
            std::fs::write(dir.join("size"), "2097152\n").unwrap();
        }

        /// Connected with no serving task at all: the half-torn-down shape.
        fn sized_without_a_server(&self, n: u32) {
            std::fs::write(self.device(n).join("size"), "2097152\n").unwrap();
        }

        fn free(&self, n: u32) {
            std::fs::write(self.device(n).join("size"), "0\n").unwrap();
        }

        fn live_process(&self, pid: i32) {
            std::fs::create_dir_all(self.sysfs.proc_root.join(pid.to_string())).unwrap();
        }
    }

    fn probe_config(nbd_client_bin: PathBuf, nbd_devices: u32) -> ChConfig {
        ChConfig {
            block_direct: false,
            ch_bin: PathBuf::from("ch"),
            kernel: PathBuf::from("vmlinuz"),
            initramfs: None,
            cmdline: String::new(),
            seed_image: None,
            block_path: BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin,
            nbd_devices,
            network_cidr: None,
            ip_bin: PathBuf::from("ip"),
        }
    }

    /// The pool has three ways of not being free, and only one of them is a
    /// device someone is actually using.
    ///
    /// The old check asked only whether `pid` existed, which called a dead
    /// server "busy" (so the slot was never reused) and called a device with a
    /// size but no server "free" (so it was handed to the next Cat, whose disk
    /// then answered every request with an error).
    #[test]
    fn a_device_is_free_only_when_nothing_holds_it() {
        let fake = FakeSysfs::new();
        let live = std::process::id() as i32;
        fake.live_process(live);
        fake.connected(0, live);
        fake.connected(1, 4_194_303);
        fake.sized_without_a_server(2);
        fake.free(3);

        assert_eq!(
            nbd_device_state_of(&fake.sysfs, 0),
            NbdDeviceState::Serving { pid: live }
        );
        assert_eq!(
            nbd_device_state_of(&fake.sysfs, 1),
            NbdDeviceState::Leaked {
                pid: Some(4_194_303)
            },
            "a recorded pid that is gone is the leak, not a busy device"
        );
        assert_eq!(
            nbd_device_state_of(&fake.sysfs, 2),
            NbdDeviceState::Leaked { pid: None },
            "a size with no serving task is just as unusable"
        );
        assert_eq!(nbd_device_state_of(&fake.sysfs, 3), NbdDeviceState::Free);
        assert_eq!(leaked_nbd_devices_of(&fake.sysfs, 4), vec![1, 2]);
    }

    /// The boot sweep disconnects every leaked device, leaves live ones alone,
    /// and reports honestly the ones the kernel would not let go of.
    #[test]
    fn the_sweep_reclaims_the_leaked_devices_and_nothing_else() {
        let fake = FakeSysfs::new();
        let live = std::process::id() as i32;
        fake.live_process(live);
        fake.connected(0, live);
        fake.connected(1, 4_194_301);
        fake.free(2);
        fake.sized_without_a_server(3);

        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let fake_client = dir.path().join("nbd-client");
        // Stands in for the kernel letting go: clear the attributes the real
        // disconnect clears. Device 3 is left connected on purpose, to prove a
        // device that will not disconnect is reported rather than assumed
        // reclaimed.
        std::fs::write(
            &fake_client,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nn=${{2#/dev/nbd}}\n\
                 [ \"$n\" = 3 ] && exit 1\nrm -f '{}'/nbd$n/pid\nprintf '0\\n' > '{}'/nbd$n/size\n",
                calls.display(),
                fake.sysfs.sys_block.display(),
                fake.sysfs.sys_block.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_client, std::fs::Permissions::from_mode(0o755)).unwrap();

        let report = reclaim_leaked_nbd_devices_of(&probe_config(fake_client, 4), &fake.sysfs);
        assert_eq!(report.reclaimed, vec!["/dev/nbd1".to_string()]);
        assert_eq!(report.unreclaimed, vec!["/dev/nbd3".to_string()]);

        let calls = std::fs::read_to_string(&calls).unwrap();
        // Sorted: the disconnects are deliberately issued concurrently, so
        // which one lands in the log first is not part of the contract.
        let mut called: Vec<&str> = calls.lines().collect();
        called.sort_unstable();
        assert_eq!(
            called,
            vec!["-d /dev/nbd1", "-d /dev/nbd3"],
            "the device a live process serves, and the free one, must not be touched"
        );
        assert_eq!(
            nbd_device_state_of(&fake.sysfs, 0),
            NbdDeviceState::Serving { pid: live }
        );
    }

    /// A device a live process still has open is never disconnected, however
    /// leaked it looks.
    ///
    /// This is what makes the first boot after [`NBD_IOCTL_MODE`] safe. A
    /// device attached by the previous, netlink-based code records a dead pid
    /// even while it is healthily serving a Cat, so sysfs alone cannot tell it
    /// from a leak — but Cloud Hypervisor is holding it open, and a real leak
    /// is held by nobody.
    #[test]
    fn a_device_someone_still_has_open_is_never_disconnected() {
        let fake = FakeSysfs::new();
        fake.connected(0, 4_194_299);
        fake.connected(1, 4_194_298);
        // /proc/<pid>/fd/7 -> /dev/nbd0, the shape of a VMM holding a disk.
        let holder = fake.sysfs.proc_root.join("4242").join("fd");
        std::fs::create_dir_all(&holder).unwrap();
        std::os::unix::fs::symlink("/dev/nbd0", holder.join("7")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let fake_client = dir.path().join("nbd-client");
        std::fs::write(
            &fake_client,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nn=${{2#/dev/nbd}}\n\
                 rm -f '{}'/nbd$n/pid\nprintf '0\\n' > '{}'/nbd$n/size\n",
                calls.display(),
                fake.sysfs.sys_block.display(),
                fake.sysfs.sys_block.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_client, std::fs::Permissions::from_mode(0o755)).unwrap();

        let report = reclaim_leaked_nbd_devices_of(&probe_config(fake_client, 2), &fake.sysfs);
        assert_eq!(report.reclaimed, vec!["/dev/nbd1".to_string()]);
        assert_eq!(
            report.unreclaimed,
            vec!["/dev/nbd0".to_string()],
            "held open, so left alone and still reported"
        );
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap().trim(),
            "-d /dev/nbd1",
            "the held device must never be handed to nbd-client -d"
        );
    }

    /// A pool with nothing leaked must not run `nbd-client` at all: every node
    /// runs this sweep at boot, including nodes on the vhost-user path that
    /// may not have the binary installed.
    #[test]
    fn a_clean_pool_runs_no_disconnects() {
        let fake = FakeSysfs::new();
        fake.free(0);
        fake.free(1);
        let cfg = probe_config(PathBuf::from("/nonexistent/nbd-client"), 2);
        assert_eq!(
            reclaim_leaked_nbd_devices_of(&cfg, &fake.sysfs),
            NbdReclaim::default()
        );
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

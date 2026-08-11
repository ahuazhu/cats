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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use cats_api::runtime_reconciliation::{
    IsolatedIpv4Kind, NetworkConfig, RandomId128, RuntimeNetworkIdentity,
};

use crate::proc::ProcHandle;
use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimePhysicalReadContext};

/// Guest-agent vsock port (must match the guest image's init script).
pub const GUEST_VSOCK_PORT: u32 = 5000;
/// Named, per-Cat RAM backing kept under the Cat's host-local runtime.
pub const GUEST_MEMORY_FILE: &str = "guest-memory.bin";
const MIB: u64 = 1024 * 1024;
const IP_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);
const IP_COMMAND_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const STANDALONE_IP_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Fixed launcher selected by the installed Node configuration. The
    /// StartRuntime checkpoint records and hashes this exact executable; it is
    /// never inferred from the Agent executable or from PATH.
    pub vmm_launcher_bin: PathBuf,
    pub ch_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    /// Production carries the release manifest projection and reopens/hashes
    /// the exact boot bytes for every fresh launch. `None` exists only for
    /// test and historical experiment constructors that do not use the
    /// production installed release paths.
    pub boot_contract: Option<cats_api::runtime_artifacts::GuestRuntimeBootContract>,
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
    pub ip_bin: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChNetwork {
    pub tap: String,
    /// Host-physical fencing token. It is fresh and deliberately has no input
    /// relationship to Cat or Network identity.
    pub ownership_token: RandomId128,
    /// Exact Desired authority consumed by this tap and VMM launch.
    pub config: NetworkConfig,
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

fn validate_desired_network(desired: &NetworkConfig) -> Result<()> {
    anyhow::ensure!(
        desired.kind == IsolatedIpv4Kind::IsolatedIpv4,
        "Desired network kind is not isolated_ipv4"
    );
    anyhow::ensure!(
        desired.prefix_length == 30,
        "Desired isolated IPv4 prefix must be /30"
    );
    let guest: std::net::Ipv4Addr = desired
        .guest_ipv4
        .as_str()
        .parse()
        .context("Desired guest IPv4 is invalid")?;
    let gateway: std::net::Ipv4Addr = desired
        .gateway_ipv4
        .as_str()
        .parse()
        .context("Desired gateway IPv4 is invalid")?;
    let guest_bits = u32::from(guest);
    let gateway_bits = u32::from(gateway);
    anyhow::ensure!(
        guest_bits & !3 == gateway_bits & !3 && guest_bits & 3 == 2 && gateway_bits & 3 == 1,
        "Desired guest and gateway IPv4 do not name the host/guest pair of one /30"
    );
    let octets = guest.octets();
    let expected_mac = format!(
        "02:ca:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3]
    );
    anyhow::ensure!(
        desired.guest_mac.as_str() == expected_mac,
        "Desired guest MAC does not encode its exact guest IPv4"
    );
    Ok(())
}

fn bind_desired_network(
    desired: &NetworkConfig,
    tap: String,
    ownership_token: RandomId128,
) -> Result<ChNetwork> {
    validate_desired_network(desired)?;
    anyhow::ensure!(
        (4..=15).contains(&tap.len())
            && tap.starts_with("cat")
            && tap
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
        "Host tap name must be cat-prefixed lowercase ASCII within 15 bytes"
    );
    Ok(ChNetwork {
        tap,
        ownership_token,
        config: desired.clone(),
    })
}

/// Revalidates a checkpointed Host-physical tuple without touching Host
/// state. The signed Desired adapter calls this immediately after every
/// descriptor-relative checkpoint read, before the tuple can reach `ip` or a
/// VMM launch.
pub(crate) fn validate_network_plan(network: &ChNetwork) -> Result<()> {
    let checked = bind_desired_network(
        &network.config,
        network.tap.clone(),
        network.ownership_token.clone(),
    )?;
    anyhow::ensure!(
        checked == *network,
        "checkpointed Host network tuple is invalid"
    );
    Ok(())
}

/// A newly-created TAP that is still tied to its clone descriptor.
///
/// Until `publish` succeeds, dropping this value is the only cleanup action:
/// Linux removes the non-persistent interface when the descriptor closes, so
/// an error path never has to guess ownership from a reusable name or ifindex.
pub(crate) trait PendingTap: Send {
    fn publish(self: Box<Self>) -> Result<()>;
}

/// The narrow physical TAP creation seam used by the network state machine.
/// Tests inject a descriptor-lifetime fake; production has no command-line
/// fallback for this security-sensitive create/publish transition.
pub(crate) trait TapCreatePort: Send + Sync + 'static {
    fn create_nonpersistent(&self, tap_name: &str) -> Result<Box<dyn PendingTap>>;
}

pub(crate) struct PlatformTapCreatePort;

#[cfg(target_os = "linux")]
struct LinuxPendingTap {
    descriptor: File,
}

#[cfg(target_os = "linux")]
impl PendingTap for LinuxPendingTap {
    fn publish(self: Box<Self>) -> Result<()> {
        // TUNSETPERSIST consumes an integer value, despite its `_IOW<int>`
        // encoding. On failure `self` still drops and closes the clone fd, so
        // the unpublished TAP is removed by the kernel.
        // SAFETY: `descriptor` is a live `/dev/net/tun` clone descriptor and
        // this ioctl retains neither the fd nor any Rust memory.
        let result = unsafe {
            libc::ioctl(
                self.descriptor.as_raw_fd(),
                libc::TUNSETPERSIST,
                1 as libc::c_int,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error()).context("publish Linux TAP with TUNSETPERSIST")
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_tap_request(tap_name: &str) -> Result<libc::ifreq> {
    let name = tap_name.as_bytes();
    anyhow::ensure!(
        name.len() < libc::IFNAMSIZ,
        "Linux TAP name exceeds IFNAMSIZ"
    );
    // SAFETY: `ifreq` is a C plain-data request whose all-zero representation
    // is the required starting state before setting its name and flag union.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, source) in request.ifr_name.iter_mut().zip(name.iter().copied()) {
        *target = source as libc::c_char;
    }
    request.ifr_ifru.ifru_flags =
        (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
    Ok(request)
}

#[cfg(target_os = "linux")]
impl TapCreatePort for PlatformTapCreatePort {
    fn create_nonpersistent(&self, tap_name: &str) -> Result<Box<dyn PendingTap>> {
        let descriptor = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/net/tun")
            .context("open Linux /dev/net/tun clone device")?;
        let mut request = linux_tap_request(tap_name)?;
        // SAFETY: the fd is a live TUN clone descriptor and `request` is a
        // correctly-sized writable ifreq that remains live for this call.
        let result = unsafe { libc::ioctl(descriptor.as_raw_fd(), libc::TUNSETIFF, &mut request) };
        if result < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("create exclusive non-persistent Linux TAP {tap_name}"));
        }
        let actual_name_end = request
            .ifr_name
            .iter()
            .position(|byte| *byte == 0)
            .context("Linux TUNSETIFF returned a non-terminated interface name")?;
        let actual_name = request.ifr_name[..actual_name_end]
            .iter()
            .map(|byte| byte.to_ne_bytes()[0])
            .collect::<Vec<_>>();
        anyhow::ensure!(
            actual_name == tap_name.as_bytes(),
            "Linux TUNSETIFF returned a different TAP name"
        );
        Ok(Box::new(LinuxPendingTap { descriptor }))
    }
}

#[cfg(not(target_os = "linux"))]
impl TapCreatePort for PlatformTapCreatePort {
    fn create_nonpersistent(&self, _tap_name: &str) -> Result<Box<dyn PendingTap>> {
        anyhow::bail!("exclusive non-persistent TAP creation requires Linux /dev/net/tun")
    }
}

enum IpCommandContext<'a> {
    Desired(&'a RuntimeDesiredEffectContext),
    Physical(&'a dyn RuntimePhysicalReadContext),
    Standalone { deadline: Instant },
}

impl IpCommandContext<'_> {
    fn deadline(&self) -> Instant {
        match self {
            Self::Desired(context) => context.deadline(),
            Self::Physical(context) => context.deadline(),
            Self::Standalone { deadline } => *deadline,
        }
    }

    fn check_active(&self) -> Result<()> {
        match self {
            Self::Desired(context) => context.check_active(),
            Self::Physical(context) => context.check_active(),
            Self::Standalone { deadline } => {
                anyhow::ensure!(
                    Instant::now() < *deadline,
                    "Host ip command deadline expired"
                );
                Ok(())
            }
        }
    }
}

struct IpCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: `fd` is owned by a live Child pipe for the duration of both
    // fcntl calls. F_GETFL does not modify memory and F_SETFL receives the
    // flags returned for that same descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see above; adding O_NONBLOCK preserves every existing flag.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain_ip_stream(
    stream: &mut impl Read,
    bytes: &mut Vec<u8>,
    eof: &mut bool,
    stream_name: &str,
) -> Result<()> {
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(read) => {
                anyhow::ensure!(
                    bytes.len().saturating_add(read) <= IP_COMMAND_OUTPUT_MAX_BYTES,
                    "Host ip {stream_name} exceeded {IP_COMMAND_OUTPUT_MAX_BYTES} bytes"
                );
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context(format!("read Host ip {stream_name}")),
        }
    }
}

fn kill_and_reap_ip(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .context("poll Host ip before termination")?
        .is_none()
    {
        child
            .kill()
            .context("kill Host ip after cancellation or deadline")?;
    }
    child
        .wait()
        .context("reap Host ip after cancellation or deadline")?;
    Ok(())
}

fn run_ip_command(
    context: &IpCommandContext<'_>,
    ip_bin: &Path,
    args: &[&str],
) -> Result<IpCommandOutput> {
    context.check_active()?;
    let command = format!("{} {}", ip_bin.display(), args.join(" "));
    let mut child = Command::new(ip_bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {command}"))?;
    let pipes = (|| {
        let stdout = child
            .stdout
            .take()
            .context("Host ip stdout pipe was not created")?;
        let stderr = child
            .stderr
            .take()
            .context("Host ip stderr pipe was not created")?;
        set_nonblocking(stdout.as_raw_fd()).context("make Host ip stdout nonblocking")?;
        set_nonblocking(stderr.as_raw_fd()).context("make Host ip stderr nonblocking")?;
        Ok::<_, anyhow::Error>((stdout, stderr))
    })();
    let (mut stdout, mut stderr) = match pipes {
        Ok(pipes) => pipes,
        Err(error) => {
            return match kill_and_reap_ip(&mut child) {
                Ok(()) => Err(error).with_context(|| format!("set up {command}")),
                Err(cleanup) => Err(error).with_context(|| {
                    format!("set up {command}; additionally failed to terminate child: {cleanup:#}")
                }),
            };
        }
    };

    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let result = (|| -> Result<IpCommandOutput> {
        let mut status = None;
        loop {
            drain_ip_stream(&mut stdout, &mut stdout_bytes, &mut stdout_eof, "stdout")?;
            drain_ip_stream(&mut stderr, &mut stderr_bytes, &mut stderr_eof, "stderr")?;
            if status.is_none() {
                status = child
                    .try_wait()
                    .with_context(|| format!("poll {command}"))?;
            }
            if let Some(status) = status {
                if stdout_eof && stderr_eof {
                    context.check_active()?;
                    return Ok(IpCommandOutput {
                        status,
                        stdout: stdout_bytes,
                        stderr: stderr_bytes,
                    });
                }
            }

            context.check_active()?;
            let remaining = context.deadline().saturating_duration_since(Instant::now());
            std::thread::sleep(IP_COMMAND_POLL_INTERVAL.min(remaining));
        }
    })();

    match result {
        Ok(output) => Ok(output),
        Err(error) => match kill_and_reap_ip(&mut child) {
            Ok(()) => Err(error).with_context(|| format!("run {command}")),
            Err(cleanup) => Err(error).with_context(|| {
                format!("run {command}; additionally failed to terminate child: {cleanup:#}")
            }),
        },
    }
}

fn ip_status(context: &IpCommandContext<'_>, ip_bin: &Path, args: &[&str]) -> Result<()> {
    let output = run_ip_command(context, ip_bin, args)?;
    anyhow::ensure!(
        output.status.success(),
        "{} {} failed: {}",
        ip_bin.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Produce the complete Host-physical tuple without touching Host state.
/// The caller must durably checkpoint the return value before calling
/// [`prepare_network`]. A checkpoint replay must reuse this exact value.
pub fn plan_network(desired: &NetworkConfig) -> Result<ChNetwork> {
    plan_network_with_random(desired, || {
        RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .context("generate Host network identity entropy")
    })
}

fn plan_network_with_random(
    desired: &NetworkConfig,
    mut random: impl FnMut() -> Result<RandomId128>,
) -> Result<ChNetwork> {
    validate_desired_network(desired)?;
    // The Linux-visible name is not an authority token.  Mint it from a
    // separate CSPRNG sample so publishing the name does not disclose any
    // prefix of the provider-private ownership capability.
    let tap_entropy = random()?;
    let ownership_token = random()?;
    anyhow::ensure!(
        tap_entropy != ownership_token,
        "Host TAP name entropy collided with its ownership token"
    );
    bind_desired_network(
        desired,
        format!("cat{}", &tap_entropy.as_str()[..11]),
        ownership_token,
    )
}

fn network_alias(network: &ChNetwork) -> String {
    format!(
        "cats-network:{}:{}",
        network.config.network_id, network.ownership_token
    )
}

fn host_cidr(network: &ChNetwork) -> String {
    format!(
        "{}/{}",
        network.config.gateway_ipv4.as_str(),
        network.config.prefix_length
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Cidr {
    address: Ipv4Addr,
    prefix_length: u8,
}

impl Ipv4Cidr {
    fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value
            .split_once('/')
            .context("IPv4 address is missing its prefix length")?;
        anyhow::ensure!(!prefix.contains('/'), "IPv4 address has multiple prefixes");
        let address = address.parse().context("IPv4 address is invalid")?;
        let prefix_length: u8 = prefix.parse().context("IPv4 prefix length is invalid")?;
        anyhow::ensure!(prefix_length <= 32, "IPv4 prefix length exceeds 32");
        Ok(Self {
            address,
            prefix_length,
        })
    }

    fn display(self) -> String {
        format!("{}/{}", self.address, self.prefix_length)
    }

    fn overlaps(self, other: Self) -> bool {
        let (self_start, self_end) = self.range();
        let (other_start, other_end) = other.range();
        self_start <= other_end && other_start <= self_end
    }

    fn range(self) -> (u32, u32) {
        let mask = if self.prefix_length == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix_length))
        };
        let start = u32::from(self.address) & mask;
        (start, start | !mask)
    }
}

pub(crate) fn network_configs_overlap(left: &NetworkConfig, right: &NetworkConfig) -> Result<bool> {
    validate_desired_network(left)?;
    validate_desired_network(right)?;
    let left = Ipv4Cidr::parse(&format!(
        "{}/{}",
        left.gateway_ipv4.as_str(),
        left.prefix_length
    ))?;
    let right = Ipv4Cidr::parse(&format!(
        "{}/{}",
        right.gateway_ipv4.as_str(),
        right.prefix_length
    ))?;
    Ok(left.overlaps(right))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostIpv4Address {
    interface: String,
    cidr: Ipv4Cidr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostNetworkLinkSnapshot {
    ifindex: u32,
    is_tap: bool,
    is_up: bool,
    alias: Option<String>,
    ipv4: Vec<Ipv4Cidr>,
}

/// One bounded, stable view of every Host link and IPv4 address relevant to
/// a checkpoint-first TAP reservation. The fields stay private so a caller
/// cannot turn a link name or an alias string into provider evidence without
/// applying the validation methods below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostNetworkSnapshot {
    links: BTreeMap<String, HostNetworkLinkSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservedHostNetworkState {
    Absent,
    Exact,
}

#[derive(serde::Deserialize)]
struct IpJsonLink {
    ifindex: u32,
    ifname: String,
    flags: Vec<String>,
    #[serde(default)]
    ifalias: Option<String>,
    #[serde(default)]
    linkinfo: Option<IpJsonLinkInfo>,
}

#[derive(serde::Deserialize)]
struct IpJsonLinkInfo {
    info_kind: String,
    #[serde(default)]
    info_data: Option<IpJsonTunInfo>,
}

#[derive(serde::Deserialize)]
struct IpJsonTunInfo {
    #[serde(rename = "type")]
    interface_type: Option<String>,
}

#[derive(serde::Deserialize)]
struct IpJsonAddressLink {
    ifindex: u32,
    ifname: String,
    #[serde(default)]
    addr_info: Vec<IpJsonAddress>,
}

#[derive(serde::Deserialize)]
struct IpJsonAddress {
    family: String,
    local: String,
    prefixlen: u8,
}

impl HostNetworkSnapshot {
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self {
            links: BTreeMap::new(),
        }
    }

    fn managed_networks(
        &self,
    ) -> Result<BTreeMap<String, (cats_api::runtime_reconciliation::Id, RandomId128, Ipv4Cidr)>>
    {
        let mut managed = BTreeMap::new();
        let mut network_ids = BTreeSet::new();
        let mut ownership_tokens = BTreeSet::new();
        for (name, link) in &self.links {
            let managed_name = is_managed_tap_name(name);
            let alias = link.alias.as_deref();
            let cats_alias = alias.is_some_and(|alias| alias.starts_with("cats-network"));
            anyhow::ensure!(
                managed_name == cats_alias,
                "Host link {name} has an incomplete Cats network identity"
            );
            if !cats_alias {
                continue;
            }
            let (network_id, ownership_token) =
                parse_network_alias(alias.expect("cats_alias proves an alias is present"))?;
            anyhow::ensure!(
                link.is_tap && link.is_up && link.ipv4.len() == 1,
                "managed Host network {name} is not one exact up TAP with one IPv4 address"
            );
            anyhow::ensure!(
                network_ids.insert(network_id.clone()),
                "Host network identity {network_id} is present more than once"
            );
            anyhow::ensure!(
                ownership_tokens.insert(ownership_token.clone()),
                "Host network ownership token is present more than once"
            );
            managed.insert(name.clone(), (network_id, ownership_token, link.ipv4[0]));
        }
        Ok(managed)
    }

    /// Require every physical Cats TAP to be the exact projection of one
    /// durable network reservation. A reservation may legitimately be absent
    /// before its later create effect, but a physical managed TAP without a
    /// checkpoint must never be treated as harmless Host background state.
    pub(crate) fn ensure_managed_networks_are_reserved<'a>(
        &self,
        reserved: impl IntoIterator<Item = &'a RuntimeNetworkIdentity>,
    ) -> Result<()> {
        let mut durable = BTreeMap::new();
        for identity in reserved {
            let network = ChNetwork {
                tap: identity.tap_name.as_str().to_owned(),
                ownership_token: identity.ownership_token.clone(),
                config: identity.network_config.clone(),
            };
            validate_network_plan(&network)?;
            anyhow::ensure!(
                durable.insert(network.tap.clone(), network).is_none(),
                "durable Host network reservations repeat one TAP name"
            );
        }
        for (tap_name, (network_id, ownership_token, address)) in self.managed_networks()? {
            let expected = durable
                .get(&tap_name)
                .context("physical Cats TAP lacks a durable reservation")?;
            anyhow::ensure!(
                expected.config.network_id.as_str() == network_id.as_str()
                    && expected.ownership_token.as_str() == ownership_token.as_str()
                    && Ipv4Cidr::parse(&host_cidr(expected))? == address,
                "physical Cats TAP differs from its durable reservation"
            );
        }
        Ok(())
    }

    /// Close every durable reservation against the complete Host IPv4 set.
    /// Its own exact TAP/address is the sole allowed overlap; an absent
    /// reservation therefore conflicts with any physical owner of its range.
    pub(crate) fn ensure_reserved_network_ranges<'a>(
        &self,
        reserved: impl IntoIterator<Item = &'a RuntimeNetworkIdentity>,
    ) -> Result<()> {
        let reserved = reserved.into_iter().collect::<Vec<_>>();
        for identity in &reserved {
            let expected = ChNetwork {
                tap: identity.tap_name.as_str().to_owned(),
                ownership_token: identity.ownership_token.clone(),
                config: identity.network_config.clone(),
            };
            validate_network_plan(&expected)?;
            let desired = Ipv4Cidr::parse(&host_cidr(&expected))?;
            for (name, link) in &self.links {
                for address in &link.ipv4 {
                    if name == &expected.tap && address == &desired {
                        continue;
                    }
                    anyhow::ensure!(
                        !address.overlaps(desired),
                        "durable Host network range {} overlaps {} on {name}",
                        desired.display(),
                        address.display()
                    );
                }
            }
        }
        Ok(())
    }

    /// Prove that a fresh random reservation does not reuse a Host link,
    /// network identity, ownership token, or overlapping IPv4 range. Existing
    /// managed links must themselves be well-formed TAPs so a foreign alias
    /// cannot be ignored merely because the candidate chose another name.
    pub(crate) fn ensure_candidate_available(&self, network: &ChNetwork) -> Result<()> {
        validate_network_plan(network)?;
        let desired = Ipv4Cidr::parse(&host_cidr(network))?;
        let managed = self.managed_networks()?;
        for (name, link) in &self.links {
            if name == &network.tap {
                anyhow::bail!("checkpointed Host tap name {name} already exists")
            }
            if let Some((network_id, ownership_token, _)) = managed.get(name) {
                anyhow::ensure!(
                    network_id != &network.config.network_id,
                    "Host network identity {} is already present on {name}",
                    network.config.network_id
                );
                anyhow::ensure!(
                    ownership_token != &network.ownership_token,
                    "Host network ownership token is already present on {name}"
                );
            }
            for address in &link.ipv4 {
                anyhow::ensure!(
                    !address.overlaps(desired),
                    "checkpointed Host network range {} overlaps {} on {name}",
                    desired.display(),
                    address.display()
                );
            }
        }
        Ok(())
    }

    /// Classify one durable reservation from this complete snapshot.  A
    /// present name is exact only when TAP kind, link state, alias authority,
    /// ifindex/address join and IPv4 tuple all match.  Partial or foreign
    /// state is an error, never an adoptable absence.
    pub(crate) fn reserved_network_state(
        &self,
        identity: &RuntimeNetworkIdentity,
    ) -> Result<ReservedHostNetworkState> {
        let expected = ChNetwork {
            tap: identity.tap_name.as_str().to_owned(),
            ownership_token: identity.ownership_token.clone(),
            config: identity.network_config.clone(),
        };
        validate_network_plan(&expected)?;
        let Some(link) = self.links.get(&expected.tap) else {
            return Ok(ReservedHostNetworkState::Absent);
        };
        anyhow::ensure!(
            link.is_tap
                && link.is_up
                && link.alias.as_deref() == Some(network_alias(&expected).as_str())
                && link.ipv4 == [Ipv4Cidr::parse(&host_cidr(&expected))?],
            "durable Host network reservation is present with partial or foreign state"
        );
        Ok(ReservedHostNetworkState::Exact)
    }

    pub(crate) fn unchanged_except_reserved_tap(
        &self,
        after: &Self,
        identity: &RuntimeNetworkIdentity,
    ) -> bool {
        self.links
            .iter()
            .filter(|(name, _)| name.as_str() != identity.tap_name.as_str())
            .eq(after
                .links
                .iter()
                .filter(|(name, _)| name.as_str() != identity.tap_name.as_str()))
    }
}

fn is_managed_tap_name(name: &str) -> bool {
    (4..=15).contains(&name.len())
        && name.starts_with("cat")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn parse_network_alias(alias: &str) -> Result<(cats_api::runtime_reconciliation::Id, RandomId128)> {
    let fields = alias
        .strip_prefix("cats-network:")
        .context("Host network alias is outside the Cats namespace")?;
    let (network_id, ownership_token) = fields
        .rsplit_once(':')
        .context("Cats Host network alias lacks ownership token")?;
    anyhow::ensure!(
        !network_id.is_empty(),
        "Cats Host network alias lacks network ID"
    );
    Ok((
        cats_api::runtime_reconciliation::Id::new(network_id.to_owned())
            .context("Cats Host network alias has invalid network ID")?,
        RandomId128::new(ownership_token.to_owned())
            .context("Cats Host network alias has invalid ownership token")?,
    ))
}

fn parse_ip_link_snapshot(bytes: &[u8]) -> Result<BTreeMap<String, HostNetworkLinkSnapshot>> {
    let records: Vec<IpJsonLink> =
        serde_json::from_slice(bytes).context("decode Host ip JSON link inventory")?;
    anyhow::ensure!(
        records.len() <= 131_072,
        "Host link inventory exceeds the closed entry bound"
    );
    let mut links = BTreeMap::new();
    let mut indexes = BTreeSet::new();
    for record in records {
        anyhow::ensure!(record.ifindex > 0, "Host link has zero ifindex");
        anyhow::ensure!(
            !record.ifname.is_empty()
                && record.ifname.len() < libc::IFNAMSIZ
                && !record.ifname.contains('@'),
            "Host link inventory has an invalid interface name"
        );
        anyhow::ensure!(
            indexes.insert(record.ifindex),
            "Host link inventory repeats ifindex {}",
            record.ifindex
        );
        if let Some(alias) = &record.ifalias {
            anyhow::ensure!(
                !alias.is_empty() && alias.len() <= 256,
                "Host link alias is empty or exceeds 256 bytes"
            );
        }
        let is_tap = record.linkinfo.as_ref().is_some_and(|linkinfo| {
            linkinfo.info_kind == "tun"
                && linkinfo
                    .info_data
                    .as_ref()
                    .and_then(|data| data.interface_type.as_deref())
                    == Some("tap")
        });
        let is_up = record.flags.iter().any(|flag| flag == "UP");
        anyhow::ensure!(
            links
                .insert(
                    record.ifname,
                    HostNetworkLinkSnapshot {
                        ifindex: record.ifindex,
                        is_tap,
                        is_up,
                        alias: record.ifalias,
                        ipv4: Vec::new(),
                    },
                )
                .is_none(),
            "Host link inventory repeats an interface name"
        );
    }
    Ok(links)
}

fn add_ip_address_snapshot(
    links: &mut BTreeMap<String, HostNetworkLinkSnapshot>,
    bytes: &[u8],
) -> Result<()> {
    let records: Vec<IpJsonAddressLink> =
        serde_json::from_slice(bytes).context("decode Host ip JSON IPv4 inventory")?;
    anyhow::ensure!(
        records.len() <= 131_072,
        "Host IPv4 inventory exceeds the closed entry bound"
    );
    let mut address_records = BTreeSet::new();
    for record in records {
        anyhow::ensure!(
            address_records.insert((record.ifindex, record.ifname.clone())),
            "Host IPv4 inventory repeats one interface"
        );
        let link = links
            .get_mut(&record.ifname)
            .context("Host IPv4 inventory names an absent link")?;
        anyhow::ensure!(
            link.ifindex == record.ifindex,
            "Host IPv4 inventory changed interface identity"
        );
        let mut addresses = Vec::new();
        for address in record.addr_info {
            anyhow::ensure!(
                address.family == "inet",
                "Host IPv4 inventory contains a non-IPv4 address"
            );
            addresses.push(Ipv4Cidr::parse(&format!(
                "{}/{}",
                address.local, address.prefixlen
            ))?);
        }
        addresses.sort_by_key(|address| (u32::from(address.address), address.prefix_length));
        anyhow::ensure!(
            addresses.windows(2).all(|pair| pair[0] != pair[1]),
            "Host IPv4 inventory repeats one address"
        );
        link.ipv4 = addresses;
    }
    Ok(())
}

fn host_network_snapshot_once(
    ip_bin: &Path,
    context: &IpCommandContext<'_>,
) -> Result<HostNetworkSnapshot> {
    let links = run_ip_command(context, ip_bin, &["-j", "-d", "link", "show"])?;
    anyhow::ensure!(
        links.status.success(),
        "{} JSON link inventory failed: {}",
        ip_bin.display(),
        String::from_utf8_lossy(&links.stderr).trim()
    );
    let addresses = run_ip_command(context, ip_bin, &["-j", "-4", "address", "show"])?;
    anyhow::ensure!(
        addresses.status.success(),
        "{} JSON IPv4 inventory failed: {}",
        ip_bin.display(),
        String::from_utf8_lossy(&addresses.stderr).trim()
    );
    let mut links = parse_ip_link_snapshot(&links.stdout)?;
    add_ip_address_snapshot(&mut links, &addresses.stdout)?;
    Ok(HostNetworkSnapshot { links })
}

/// Read the complete Host link/address set twice and accept it only when the
/// two independent command snapshots are byte-semantically equal. This does
/// not claim atomicity against arbitrary root mutation; it detects the
/// ordinary rename/recreate/address windows and is always bracketed by the
/// Node-global network allocation lock for checkpoint/effect use.
pub(crate) fn inspect_host_network_snapshot(
    ip_bin: &Path,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<HostNetworkSnapshot> {
    anyhow::ensure!(ip_bin.is_absolute(), "Host ip binary must be absolute");
    let context = IpCommandContext::Physical(context);
    let before = host_network_snapshot_once(ip_bin, &context)?;
    let after = host_network_snapshot_once(ip_bin, &context)?;
    anyhow::ensure!(
        before == after,
        "Host network inventory changed during the bounded physical scan"
    );
    Ok(after)
}

fn ipv4_addresses(output: &[u8]) -> Result<Vec<HostIpv4Address>> {
    let text = std::str::from_utf8(output).context("Host ip address output is not UTF-8")?;
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    for (index, line) in text.lines().enumerate() {
        anyhow::ensure!(!line.trim().is_empty(), "Host ip output has an empty line");
        let mut fields = line.split_ascii_whitespace();
        let ordinal = fields
            .next()
            .and_then(|field| field.strip_suffix(':'))
            .with_context(|| format!("Host ip line {} has no interface index", index + 1))?;
        ordinal.parse::<u32>().with_context(|| {
            format!("Host ip line {} has an invalid interface index", index + 1)
        })?;
        let interface = fields
            .next()
            .with_context(|| format!("Host ip line {} has no interface name", index + 1))?;
        anyhow::ensure!(
            !interface.is_empty(),
            "Host ip line {} has an empty interface name",
            index + 1
        );
        anyhow::ensure!(
            fields.next() == Some("inet"),
            "Host ip line {} has no IPv4 address marker",
            index + 1
        );
        let cidr_text = fields
            .next()
            .with_context(|| format!("Host ip line {} has no IPv4 CIDR", index + 1))?;
        anyhow::ensure!(
            !fields.any(|field| field == "inet"),
            "Host ip line {} has multiple IPv4 address markers",
            index + 1
        );
        let cidr = Ipv4Cidr::parse(cidr_text)
            .with_context(|| format!("parse Host ip line {} IPv4 CIDR", index + 1))?;
        anyhow::ensure!(
            seen.insert(cidr.address),
            "Host ip output repeats IPv4 address {}",
            cidr.address
        );
        addresses.push(HostIpv4Address {
            interface: interface.to_owned(),
            cidr,
        });
    }
    Ok(addresses)
}

/// Return false only when the exact tap name is absent. A present tap with a
/// different/missing token is foreign residue and must fail closed.
fn exact_network_exists(
    cfg: &ChConfig,
    network: &ChNetwork,
    context: &IpCommandContext<'_>,
) -> Result<bool> {
    let output = run_ip_command(
        context,
        &cfg.ip_bin,
        &["-d", "link", "show", "dev", &network.tap],
    )
    .with_context(|| format!("inspect Host tap {}", network.tap))?;
    if !output.status.success() {
        return Ok(false);
    }
    let expected = network_alias(network);
    anyhow::ensure!(
        String::from_utf8_lossy(&output.stdout)
            .split_ascii_whitespace()
            .any(|field| field == expected),
        "Host tap {} exists with a different or missing ownership token",
        network.tap
    );
    Ok(true)
}

fn ensure_host_cidr_available(
    ip_bin: &Path,
    desired: Ipv4Cidr,
    adopted_tap: Option<&str>,
    context: &IpCommandContext<'_>,
) -> Result<()> {
    let addresses = run_ip_command(context, ip_bin, &["-o", "-4", "addr", "show"])
        .with_context(|| format!("run {} -o -4 addr show", ip_bin.display()))?;
    anyhow::ensure!(
        addresses.status.success(),
        "{} -o -4 addr show failed: {}",
        ip_bin.display(),
        String::from_utf8_lossy(&addresses.stderr).trim()
    );
    let addresses = ipv4_addresses(&addresses.stdout)?;
    let mut adopted_seen = false;
    for address in addresses {
        if !address.cidr.overlaps(desired) {
            continue;
        }
        if adopted_tap == Some(address.interface.as_str()) && address.cidr == desired {
            anyhow::ensure!(
                !adopted_seen,
                "Host ip output repeats adopted tap {0}",
                address.interface
            );
            adopted_seen = true;
            continue;
        }
        anyhow::bail!(
            "Cat network address collision: desired {} overlaps {} on {}",
            desired.display(),
            address.cidr.display(),
            address.interface
        );
    }
    if let Some(tap) = adopted_tap {
        anyhow::ensure!(
            adopted_seen,
            "adopted Host tap {tap} disappeared from the global IPv4 inventory"
        );
    }
    Ok(())
}

/// Create or adopt only the exact tuple that the caller already checkpointed.
/// An existing same-token tap is completed idempotently; a same-name tap with
/// any other token or address is rejected without mutation.
pub fn prepare_network(
    cfg: &ChConfig,
    network: &ChNetwork,
    effect_context: &RuntimeDesiredEffectContext,
) -> Result<()> {
    prepare_network_with_tap_port(cfg, network, effect_context, &PlatformTapCreatePort)
}

pub(crate) fn prepare_network_with_tap_port(
    cfg: &ChConfig,
    network: &ChNetwork,
    effect_context: &RuntimeDesiredEffectContext,
    tap_create: &dyn TapCreatePort,
) -> Result<()> {
    validate_network_plan(network)?;
    let host_cidr = host_cidr(network);
    let desired_cidr = Ipv4Cidr::parse(&host_cidr).context("parse checkpointed Host IPv4 CIDR")?;
    let context = IpCommandContext::Desired(effect_context);

    if exact_network_exists(cfg, network, &context)? {
        let addresses = run_ip_command(
            &context,
            &cfg.ip_bin,
            &["-o", "-4", "addr", "show", "dev", &network.tap],
        )
        .with_context(|| format!("inspect IPv4 addresses on Host tap {}", network.tap))?;
        anyhow::ensure!(
            addresses.status.success(),
            "inspect IPv4 addresses on Host tap {}: {}",
            network.tap,
            String::from_utf8_lossy(&addresses.stderr).trim()
        );
        let assigned = ipv4_addresses(&addresses.stdout)?;
        if assigned.is_empty() {
            ensure_host_cidr_available(&cfg.ip_bin, desired_cidr, None, &context)?;
            ip_status(
                &context,
                &cfg.ip_bin,
                &["addr", "add", &host_cidr, "dev", &network.tap],
            )?;
        } else {
            anyhow::ensure!(
                assigned.len() == 1 && assigned[0].cidr == desired_cidr,
                "Host tap {} has an address other than exact checkpointed {host_cidr}",
                network.tap
            );
            ensure_host_cidr_available(&cfg.ip_bin, desired_cidr, Some(&network.tap), &context)?;
        }
        return ip_status(
            &context,
            &cfg.ip_bin,
            &["link", "set", "dev", &network.tap, "up"],
        );
    }

    ensure_host_cidr_available(&cfg.ip_bin, desired_cidr, None, &context)?;
    let pending_tap = tap_create
        .create_nonpersistent(&network.tap)
        .with_context(|| format!("create unpublished Host tap {}", network.tap))?;
    (|| {
        ip_status(
            &context,
            &cfg.ip_bin,
            &[
                "link",
                "set",
                "dev",
                &network.tap,
                "alias",
                &network_alias(network),
            ],
        )?;
        ip_status(
            &context,
            &cfg.ip_bin,
            &["addr", "add", &host_cidr, "dev", &network.tap],
        )?;
        ip_status(
            &context,
            &cfg.ip_bin,
            &["link", "set", "dev", &network.tap, "up"],
        )?;
        // This is the publication boundary. Every earlier failure,
        // cancellation or process exit closes `pending_tap`, so Linux removes
        // the exact unpublished interface without a name-based delete.
        context.check_active()?;
        pending_tap
            .publish()
            .with_context(|| format!("publish configured Host tap {}", network.tap))
    })()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkCreateAttempt {
    Published,
    DefinitelyNotPublished,
    PublicationOutcomeUnknown,
}

/// Create only from a caller-retained complete absence proof. This primitive
/// never adopts or completes an existing interface: `TUNSETIFF|TUN_EXCL` is
/// the sole name claim, and every pre-publication path drops the clone fd.
/// Once creation is attempted, the closed outcome deliberately contains no
/// retry instruction; the reconciler must Refresh and obtain a new scan.
pub(crate) fn create_network_from_sealed_absence_with_tap_port(
    ip_bin: &Path,
    network: &ChNetwork,
    effect_context: &RuntimeDesiredEffectContext,
    tap_create: &dyn TapCreatePort,
) -> Result<NetworkCreateAttempt> {
    anyhow::ensure!(ip_bin.is_absolute(), "Host ip binary must be absolute");
    validate_network_plan(network)?;
    let host_cidr = host_cidr(network);
    let desired_cidr = Ipv4Cidr::parse(&host_cidr).context("parse checkpointed Host IPv4 CIDR")?;
    let context = IpCommandContext::Desired(effect_context);
    ensure_host_cidr_available(ip_bin, desired_cidr, None, &context)?;
    context.check_active()?;

    let pending_tap = match tap_create.create_nonpersistent(&network.tap) {
        Ok(pending) => pending,
        Err(_) => return Ok(NetworkCreateAttempt::DefinitelyNotPublished),
    };
    let configured = (|| {
        ip_status(
            &context,
            ip_bin,
            &[
                "link",
                "set",
                "dev",
                &network.tap,
                "alias",
                &network_alias(network),
            ],
        )?;
        ip_status(
            &context,
            ip_bin,
            &["addr", "add", &host_cidr, "dev", &network.tap],
        )?;
        ip_status(
            &context,
            ip_bin,
            &["link", "set", "dev", &network.tap, "up"],
        )?;
        context.check_active()
    })();
    if configured.is_err() {
        drop(pending_tap);
        return Ok(NetworkCreateAttempt::DefinitelyNotPublished);
    }
    match pending_tap.publish() {
        Ok(()) => Ok(NetworkCreateAttempt::Published),
        Err(_) => Ok(NetworkCreateAttempt::PublicationOutcomeUnknown),
    }
}

pub fn remove_network(cfg: &ChConfig, network: &ChNetwork) -> Result<()> {
    let context = IpCommandContext::Standalone {
        deadline: Instant::now() + STANDALONE_IP_COMMAND_TIMEOUT,
    };
    if exact_network_exists(cfg, network, &context)? {
        ip_status(
            &context,
            &cfg.ip_bin,
            &["link", "delete", "dev", &network.tap],
        )?;
    }
    Ok(())
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
    effective_vhost_user_queues(cfg.vhost_user_queues, cpus)
}

/// Shared projection used when the signed Runtime composer freezes only the
/// vhost fields it needs instead of retaining the wider VMM configuration.
pub(crate) fn effective_vhost_user_queues(maximum_queues: usize, cpus: u32) -> usize {
    maximum_queues.clamp(1, cpus.max(1) as usize)
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
    let verified_boot = if s.restore_from.is_none() {
        s.cfg
            .boot_contract
            .as_ref()
            .map(|contract| {
                cats_api::runtime_artifacts::open_verified_guest_runtime_launch(
                    contract,
                    &s.cfg.kernel,
                    s.cfg.initramfs.as_deref(),
                )
                .context("revalidate installed Guest boot bytes for VMM launch")
            })
            .transpose()?
    } else {
        None
    };
    if let Some(verified) = &verified_boot {
        make_inheritable(verified.kernel())?;
        if let Some(initramfs) = verified.initramfs() {
            make_inheritable(initramfs)?;
        }
    }
    match s.restore_from {
        Some(dir) => {
            cmd.arg("--restore")
                .arg(format!("source_url=file://{}", dir.display()));
        }
        None => {
            if let Some(verified) = &verified_boot {
                cmd.arg("--kernel")
                    .arg(inherited_fd_path(verified.kernel()));
                if let Some(initramfs) = verified.initramfs() {
                    cmd.arg("--initramfs").arg(inherited_fd_path(initramfs));
                }
            } else {
                cmd.arg("--kernel").arg(&s.cfg.kernel);
                if let Some(initrd) = &s.cfg.initramfs {
                    cmd.arg("--initramfs").arg(initrd);
                }
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
                cmd.arg("--net").arg(format!(
                    "tap={},mac={}",
                    network.tap,
                    network.config.guest_mac.as_str()
                ));
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

fn inherited_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn make_inheritable(file: &File) -> Result<()> {
    // SAFETY: `file` owns a live descriptor. F_GETFD/F_SETFD operate only on
    // that descriptor and do not access Rust memory. Clearing CLOEXEC is
    // deliberate: Cloud Hypervisor opens `/proc/self/fd/<n>` after exec.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    anyhow::ensure!(flags >= 0, "read Guest boot descriptor flags");
    // SAFETY: the same live descriptor invariant applies to this F_SETFD
    // operation; no pointer or Rust memory is passed to libc.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    anyhow::ensure!(result == 0, "make Guest boot descriptor inheritable");
    Ok(())
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
    use std::sync::{mpsc, Arc, Mutex};

    #[derive(Debug, Clone, Copy)]
    enum FakePublishBehavior {
        Succeed,
        ReturnError,
        PanicBeforePublish,
    }

    #[derive(Default)]
    struct FakeTapEvents {
        creates: usize,
        publishes: usize,
        unpublished_drops: usize,
    }

    struct MarkerTapCreatePort {
        link: PathBuf,
        behavior: FakePublishBehavior,
        cancel_after_create: Option<RuntimeDesiredEffectContext>,
        events: Arc<Mutex<FakeTapEvents>>,
    }

    impl MarkerTapCreatePort {
        fn new(link: PathBuf) -> Self {
            Self {
                link,
                behavior: FakePublishBehavior::Succeed,
                cancel_after_create: None,
                events: Arc::new(Mutex::new(FakeTapEvents::default())),
            }
        }
    }

    struct MarkerPendingTap {
        link: PathBuf,
        behavior: FakePublishBehavior,
        events: Arc<Mutex<FakeTapEvents>>,
        published: bool,
    }

    impl PendingTap for MarkerPendingTap {
        fn publish(mut self: Box<Self>) -> Result<()> {
            if matches!(self.behavior, FakePublishBehavior::PanicBeforePublish) {
                panic!("injected process crash before TAP publish");
            }
            if matches!(self.behavior, FakePublishBehavior::ReturnError) {
                anyhow::bail!("injected TAP publication response loss")
            }
            self.events.lock().unwrap().publishes += 1;
            self.published = true;
            Ok(())
        }
    }

    impl Drop for MarkerPendingTap {
        fn drop(&mut self) {
            if !self.published {
                let _ = std::fs::remove_file(&self.link);
                self.events.lock().unwrap().unpublished_drops += 1;
            }
        }
    }

    impl TapCreatePort for MarkerTapCreatePort {
        fn create_nonpersistent(&self, _tap_name: &str) -> Result<Box<dyn PendingTap>> {
            anyhow::ensure!(!self.link.exists(), "fake exclusive TAP already exists");
            std::fs::write(&self.link, [])?;
            self.events.lock().unwrap().creates += 1;
            if let Some(context) = &self.cancel_after_create {
                context.cancel_for_test();
            }
            Ok(Box::new(MarkerPendingTap {
                link: self.link.clone(),
                behavior: self.behavior,
                events: Arc::clone(&self.events),
                published: false,
            }))
        }
    }

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
            vmm_launcher_bin: PathBuf::from("cats-vmm-launcher"),
            ch_bin: PathBuf::from("ch"),
            kernel: PathBuf::from("vmlinuz"),
            initramfs: None,
            boot_contract: None,
            cmdline: String::new(),
            seed_image: None,
            block_path: BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin,
            nbd_devices,
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
            vmm_launcher_bin: PathBuf::from("cats-vmm-launcher"),
            ch_bin: PathBuf::from("ch"),
            kernel: PathBuf::from("vmlinuz"),
            initramfs: None,
            boot_contract: None,
            cmdline: String::new(),
            seed_image: None,
            block_path: BlockPath::VhostUser,
            vhost_user_queues: 4,
            vhost_user_queue_size: 256,
            nbd_client_bin: PathBuf::from("nbd-client"),
            nbd_devices: 8,
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

    fn desired_network() -> NetworkConfig {
        use cats_api::runtime_reconciliation::{Id, Ipv4Address, MacAddress};

        NetworkConfig {
            kind: IsolatedIpv4Kind::IsolatedIpv4,
            network_id: Id::new("net_77777777777777777777777777777777").unwrap(),
            guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
            guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
            prefix_length: 30,
            gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
        }
    }

    fn network_snapshot(
        links: serde_json::Value,
        addresses: serde_json::Value,
    ) -> Result<HostNetworkSnapshot> {
        let mut links = parse_ip_link_snapshot(&serde_json::to_vec(&links).unwrap())?;
        add_ip_address_snapshot(&mut links, &serde_json::to_vec(&addresses).unwrap())?;
        Ok(HostNetworkSnapshot { links })
    }

    fn incumbent_network() -> RuntimeNetworkIdentity {
        use cats_api::runtime_reconciliation::{Id, Ipv4Address, MacAddress};

        RuntimeNetworkIdentity {
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: Id::new("net_old").unwrap(),
                guest_mac: MacAddress::new("02:ca:0a:f0:00:02").unwrap(),
                guest_ipv4: Ipv4Address::new("10.240.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.240.0.1").unwrap(),
            },
            tap_name: Id::new("catold000001").unwrap(),
            ownership_token: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
        }
    }

    fn incumbent_link_json(alias: &str, address: &str) -> (serde_json::Value, serde_json::Value) {
        (
            serde_json::json!([
                {
                    "ifindex": 1,
                    "ifname": "lo",
                    "flags": ["LOOPBACK", "UP"]
                },
                {
                    "ifindex": 17,
                    "ifname": "catold000001",
                    "flags": ["BROADCAST", "UP"],
                    "ifalias": alias,
                    "linkinfo": {
                        "info_kind": "tun",
                        "info_data": { "type": "tap" }
                    }
                }
            ]),
            serde_json::json!([
                {
                    "ifindex": 1,
                    "ifname": "lo",
                    "addr_info": [
                        { "family": "inet", "local": "127.0.0.1", "prefixlen": 8 }
                    ]
                },
                {
                    "ifindex": 17,
                    "ifname": "catold000001",
                    "addr_info": [
                        { "family": "inet", "local": address, "prefixlen": 30 }
                    ]
                }
            ]),
        )
    }

    #[test]
    fn host_network_snapshot_closes_managed_aliases_and_candidate_collisions() {
        let incumbent = incumbent_network();
        let alias = format!(
            "cats-network:{}:{}",
            incumbent.network_config.network_id, incumbent.ownership_token
        );
        let (links, addresses) = incumbent_link_json(&alias, "10.240.0.1");
        let snapshot = network_snapshot(links, addresses).unwrap();
        snapshot
            .ensure_managed_networks_are_reserved([&incumbent])
            .unwrap();

        let candidate = bind_desired_network(
            &desired_network(),
            "catnew000001".to_owned(),
            RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        )
        .unwrap();
        snapshot.ensure_candidate_available(&candidate).unwrap();

        for conflicting in [
            ChNetwork {
                tap: incumbent.tap_name.as_str().to_owned(),
                ..candidate.clone()
            },
            ChNetwork {
                config: NetworkConfig {
                    network_id: incumbent.network_config.network_id.clone(),
                    ..candidate.config.clone()
                },
                ..candidate.clone()
            },
            ChNetwork {
                ownership_token: incumbent.ownership_token.clone(),
                ..candidate.clone()
            },
        ] {
            assert!(snapshot.ensure_candidate_available(&conflicting).is_err());
        }

        let overlap = bind_desired_network(
            &NetworkConfig {
                network_id: cats_api::runtime_reconciliation::Id::new("net_overlap").unwrap(),
                guest_mac: cats_api::runtime_reconciliation::MacAddress::new("02:ca:0a:f0:00:02")
                    .unwrap(),
                guest_ipv4: cats_api::runtime_reconciliation::Ipv4Address::new("10.240.0.2")
                    .unwrap(),
                gateway_ipv4: cats_api::runtime_reconciliation::Ipv4Address::new("10.240.0.1")
                    .unwrap(),
                ..desired_network()
            },
            "catnew000002".to_owned(),
            RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
        )
        .unwrap();
        assert!(snapshot.ensure_candidate_available(&overlap).is_err());
    }

    #[test]
    fn host_network_snapshot_rejects_missing_corrupt_or_unbound_managed_identity() {
        let incumbent = incumbent_network();
        let alias = format!(
            "cats-network:{}:{}",
            incumbent.network_config.network_id, incumbent.ownership_token
        );

        let (mut links, addresses) = incumbent_link_json(&alias, "10.240.0.1");
        links[1].as_object_mut().unwrap().remove("ifalias");
        let missing = network_snapshot(links, addresses).unwrap();
        assert!(missing
            .ensure_candidate_available(&plan_network(&desired_network()).unwrap())
            .is_err());

        let (mut links, addresses) = incumbent_link_json("cats-network:broken", "10.240.0.1");
        links[1]["ifname"] = serde_json::json!("catold000001");
        let corrupt = network_snapshot(links, addresses).unwrap();
        assert!(corrupt
            .ensure_candidate_available(&plan_network(&desired_network()).unwrap())
            .is_err());

        let (links, addresses) = incumbent_link_json(&alias, "10.240.0.1");
        let unbound = network_snapshot(links, addresses).unwrap();
        assert!(unbound.ensure_managed_networks_are_reserved([]).is_err());

        let (links, addresses) = incumbent_link_json(&alias, "10.240.0.5");
        let wrong_address = network_snapshot(links, addresses).unwrap();
        assert!(wrong_address
            .ensure_managed_networks_are_reserved([&incumbent])
            .is_err());
    }

    #[test]
    fn host_network_snapshot_rejects_duplicate_managed_network_or_token() {
        let incumbent = incumbent_network();
        let alias = format!(
            "cats-network:{}:{}",
            incumbent.network_config.network_id, incumbent.ownership_token
        );
        let (mut links, mut addresses) = incumbent_link_json(&alias, "10.240.0.1");
        links.as_array_mut().unwrap().push(serde_json::json!({
            "ifindex": 18,
            "ifname": "catold000002",
            "flags": ["UP"],
            "ifalias": alias,
            "linkinfo": {
                "info_kind": "tun",
                "info_data": { "type": "tap" }
            }
        }));
        addresses.as_array_mut().unwrap().push(serde_json::json!({
            "ifindex": 18,
            "ifname": "catold000002",
            "addr_info": [
                { "family": "inet", "local": "10.240.0.9", "prefixlen": 30 }
            ]
        }));
        let duplicate = network_snapshot(links, addresses).unwrap();
        assert!(duplicate
            .ensure_candidate_available(&plan_network(&desired_network()).unwrap())
            .is_err());
    }

    fn desired_effect_context(path: &Path) -> RuntimeDesiredEffectContext {
        RuntimeDesiredEffectContext::for_test(
            crate::state_directory::StateDirectory::unanchored(path.to_path_buf()),
            Instant::now() + Duration::from_secs(10),
        )
    }

    #[test]
    fn exact_desired_network_is_retained_without_cat_or_cidr_derivation() {
        use cats_api::runtime_reconciliation::{Ipv4Address, MacAddress};

        let desired = desired_network();
        let ownership = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let network =
            bind_desired_network(&desired, "catphysical01".into(), ownership.clone()).unwrap();
        assert_eq!(network.config, desired);
        assert_eq!(network.ownership_token, ownership);
        assert_eq!(network.tap, "catphysical01");

        for changed in [
            NetworkConfig {
                prefix_length: 29,
                ..desired.clone()
            },
            NetworkConfig {
                gateway_ipv4: Ipv4Address::new("10.240.0.4").unwrap(),
                ..desired.clone()
            },
            NetworkConfig {
                guest_mac: MacAddress::new("02:ca:0a:f0:00:07").unwrap(),
                ..desired.clone()
            },
        ] {
            assert!(
                bind_desired_network(&changed, "catphysical01".into(), ownership.clone()).is_err()
            );
        }

        let first = plan_network(&desired).unwrap();
        let second = plan_network(&desired).unwrap();
        assert_eq!(first.config, desired);
        assert_eq!(second.config, desired);
        assert_ne!(first.ownership_token, second.ownership_token);
        assert_ne!(first.tap, second.tap);
    }

    #[test]
    fn network_plan_mints_independent_name_and_authority_samples() {
        let samples = [
            RandomId128::new("11111111111aaaaaaaaaaaaaaaaaaaaa").unwrap(),
            RandomId128::new("22222222222bbbbbbbbbbbbbbbbbbbbb").unwrap(),
        ];
        let mut samples = samples.into_iter();
        let planned = plan_network_with_random(&desired_network(), || {
            samples.next().context("test random sample exhausted")
        })
        .unwrap();

        assert_eq!(planned.tap, "cat11111111111");
        assert_eq!(
            planned.ownership_token,
            RandomId128::new("22222222222bbbbbbbbbbbbbbbbbbbbb").unwrap()
        );
        assert_ne!(
            &planned.tap[3..],
            &planned.ownership_token.as_str()[..11],
            "published TAP name leaked the ownership-token prefix"
        );
        assert!(samples.next().is_none());
    }

    #[test]
    fn network_alias_round_trips_colon_bearing_network_id() {
        let config = NetworkConfig {
            network_id: cats_api::runtime_reconciliation::Id::new("tenant:segment:42").unwrap(),
            ..desired_network()
        };
        let network = bind_desired_network(
            &config,
            "catphysical01".into(),
            RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        )
        .unwrap();

        let parsed = parse_network_alias(&network_alias(&network)).unwrap();
        assert_eq!(parsed.0, config.network_id);
        assert_eq!(parsed.1, network.ownership_token);
    }

    #[test]
    fn checkpointed_network_plan_precedes_effect_and_replays_exact_token() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("ip.log");
        let link = dir.path().join("link");
        let alias = dir.path().join("alias");
        let address = dir.path().join("address");
        let fake_ip = dir.path().join("ip");
        let planned = plan_network(&desired_network()).unwrap();
        std::fs::write(
            &fake_ip,
            format!(
                "#!/bin/sh\n\
printf '%s\\n' \"$*\" >> '{log}'\n\
if [ \"$1\" = '-d' ]; then\n\
  if [ -f '{link}' ]; then printf '1: tap0 alias %s\\n' \"$(cat '{alias}' 2>/dev/null)\"; exit 0; fi\n\
  exit 1\n\
fi\n\
if [ \"$1\" = '-o' ] && [ \"$5\" = 'dev' ]; then\n\
  if [ -f '{address}' ]; then printf '1: {tap} inet %s scope global\\n' \"$(cat '{address}')\"; fi\n\
  exit 0\n\
fi\n\
if [ \"$1\" = '-o' ]; then\n\
  if [ -f '{link}' ] && [ -f '{address}' ]; then printf '1: {tap} inet %s scope global\\n' \"$(cat '{address}')\"; fi\n\
  exit 0\n\
fi\n\
if [ \"$1\" = 'tuntap' ]; then : > '{link}'; exit 0; fi\n\
if [ \"$1\" = 'link' ] && [ \"$2\" = 'set' ] && [ \"$5\" = 'alias' ]; then printf '%s' \"$6\" > '{alias}'; exit 0; fi\n\
if [ \"$1\" = 'addr' ]; then printf '%s' \"$3\" > '{address}'; exit 0; fi\n\
if [ \"$1\" = 'link' ] && [ \"$2\" = 'set' ]; then exit 0; fi\n\
if [ \"$1\" = 'link' ] && [ \"$2\" = 'delete' ]; then rm -f '{link}' '{alias}' '{address}'; exit 0; fi\n\
exit 97\n",
                log = log.display(),
                link = link.display(),
                alias = alias.display(),
                address = address.display(),
                tap = planned.tap.as_str(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!log.exists(), "zero-effect plan unexpectedly executed ip");
        let checkpoint = dir.path().join("network.json");
        let mut file = File::create(&checkpoint).unwrap();
        file.write_all(&serde_json::to_vec(&planned).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        assert!(!log.exists(), "durable checkpoint unexpectedly executed ip");
        let replayed: ChNetwork =
            serde_json::from_slice(&std::fs::read(checkpoint).unwrap()).unwrap();

        let mut cfg = probe_config(dir.path().join("nbd-client"), 8);
        cfg.ip_bin = fake_ip;
        let context = desired_effect_context(dir.path());
        let tap_create = MarkerTapCreatePort::new(link.clone());
        let tap_events = Arc::clone(&tap_create.events);
        prepare_network_with_tap_port(&cfg, &replayed, &context, &tap_create).unwrap();
        assert_eq!(std::fs::read_to_string(&address).unwrap(), "10.240.0.5/30");
        assert_eq!(
            std::fs::read_to_string(&alias).unwrap(),
            network_alias(&replayed)
        );

        // Crash after the token-bearing tap exists but before its address is
        // complete: the durable tuple is adopted and completed, not replanned.
        std::fs::remove_file(&address).unwrap();
        prepare_network_with_tap_port(&cfg, &replayed, &context, &tap_create).unwrap();
        assert_eq!(std::fs::read_to_string(&address).unwrap(), "10.240.0.5/30");

        let foreign = ChNetwork {
            ownership_token: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            ..replayed.clone()
        };
        assert!(prepare_network_with_tap_port(&cfg, &foreign, &context, &tap_create).is_err());
        assert!(remove_network(&cfg, &foreign).is_err());
        assert!(link.exists(), "foreign-token cleanup deleted the owned tap");
        let events = tap_events.lock().unwrap();
        assert_eq!(events.creates, 1);
        assert_eq!(events.publishes, 1);
        assert_eq!(events.unpublished_drops, 0);
        drop(events);
        remove_network(&cfg, &replayed).unwrap();
        assert!(!link.exists());
    }

    #[test]
    fn cancellation_after_nonpersistent_tap_create_drops_it_without_name_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("tap-live");
        let mutation = dir.path().join("mutation");
        let log = dir.path().join("ip.log");
        let fake_ip = dir.path().join("ip");
        std::fs::write(
            &fake_ip,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n\
if [ \"$1\" = '-d' ]; then exit 1; fi\n\
if [ \"$1\" = '-o' ]; then exit 0; fi\n\
: > '{mutation}'\n\
exit 0\n",
                log = log.display(),
                mutation = mutation.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = probe_config(dir.path().join("nbd-client"), 8);
        cfg.ip_bin = fake_ip;
        let network = plan_network(&desired_network()).unwrap();
        let context = desired_effect_context(dir.path());
        let mut tap_create = MarkerTapCreatePort::new(link.clone());
        tap_create.cancel_after_create = Some(context.clone());
        let events = Arc::clone(&tap_create.events);

        let error = prepare_network_with_tap_port(&cfg, &network, &context, &tap_create)
            .expect_err("cancelled unpublished TAP was accepted");
        assert!(format!("{error:#}").contains("cancelled"));
        assert!(!link.exists(), "cancelled pending TAP remained visible");
        assert!(
            !mutation.exists(),
            "cancelled state machine mutated the TAP"
        );
        assert!(
            !std::fs::read_to_string(log)
                .unwrap()
                .contains("link delete"),
            "cancellation guessed cleanup from the TAP name"
        );
        let events = events.lock().unwrap();
        assert_eq!(events.creates, 1);
        assert_eq!(events.publishes, 0);
        assert_eq!(events.unpublished_drops, 1);
    }

    #[test]
    fn sealed_absence_create_has_closed_publish_and_response_loss_outcomes() {
        for (behavior, cancel, expected, remains) in [
            (
                FakePublishBehavior::Succeed,
                false,
                NetworkCreateAttempt::Published,
                true,
            ),
            (
                FakePublishBehavior::Succeed,
                true,
                NetworkCreateAttempt::DefinitelyNotPublished,
                false,
            ),
            (
                FakePublishBehavior::ReturnError,
                false,
                NetworkCreateAttempt::PublicationOutcomeUnknown,
                false,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let link = dir.path().join("tap-live");
            let log = dir.path().join("ip.log");
            let fake_ip = dir.path().join("ip");
            std::fs::write(
                &fake_ip,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n\
if [ \"$1\" = '-o' ]; then exit 0; fi\n\
exit 0\n",
                    log = log.display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();
            let network = plan_network(&desired_network()).unwrap();
            let context = desired_effect_context(dir.path());
            let mut tap_create = MarkerTapCreatePort::new(link.clone());
            tap_create.behavior = behavior;
            if cancel {
                tap_create.cancel_after_create = Some(context.clone());
            }
            let events = Arc::clone(&tap_create.events);

            assert_eq!(
                create_network_from_sealed_absence_with_tap_port(
                    &fake_ip,
                    &network,
                    &context,
                    &tap_create,
                )
                .unwrap(),
                expected
            );
            assert_eq!(link.exists(), remains);
            assert!(!std::fs::read_to_string(log)
                .unwrap()
                .contains("link delete"));
            let events = events.lock().unwrap();
            assert_eq!(events.creates, 1);
            assert_eq!(
                events.publishes,
                usize::from(expected == NetworkCreateAttempt::Published)
            );
            assert_eq!(events.unpublished_drops, usize::from(!remains));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN, CAP_NET_ADMIN, and /dev/net/tun"]
    fn real_linux_scoped_tap_is_published_and_exact_in_a_private_network_namespace() {
        let ip = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.is_file())
            .expect("install iproute2 for the scoped TAP test");
        assert!(Path::new("/dev/net/tun").exists(), "/dev/net/tun is absent");
        // SAFETY: unshare changes only this test thread's network namespace.
        // The ignored test is run in a disposable privileged Linux process;
        // the namespace (and its persistent TAP) is destroyed with the thread.
        let result = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        assert_eq!(
            result,
            0,
            "unshare(CLONE_NEWNET): {}",
            io::Error::last_os_error()
        );

        let state = tempfile::tempdir().unwrap();
        let context = desired_effect_context(state.path());
        let network = plan_network(&desired_network()).unwrap();
        assert_eq!(
            create_network_from_sealed_absence_with_tap_port(
                &ip,
                &network,
                &context,
                &PlatformTapCreatePort,
            )
            .unwrap(),
            NetworkCreateAttempt::Published
        );
        let identity = RuntimeNetworkIdentity {
            network_config: network.config.clone(),
            tap_name: cats_api::runtime_reconciliation::Id::new(network.tap.clone()).unwrap(),
            ownership_token: network.ownership_token.clone(),
        };
        assert_eq!(
            inspect_host_network_snapshot(&ip, &context)
                .unwrap()
                .reserved_network_state(&identity)
                .unwrap(),
            ReservedHostNetworkState::Exact
        );
    }

    #[test]
    fn crash_before_publish_drops_nonpersistent_tap_without_name_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("tap-live");
        let log = dir.path().join("ip.log");
        let fake_ip = dir.path().join("ip");
        std::fs::write(
            &fake_ip,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n\
if [ \"$1\" = '-d' ]; then exit 1; fi\n\
if [ \"$1\" = '-o' ]; then exit 0; fi\n\
exit 0\n",
                log = log.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = probe_config(dir.path().join("nbd-client"), 8);
        cfg.ip_bin = fake_ip;
        let network = plan_network(&desired_network()).unwrap();
        let context = desired_effect_context(dir.path());
        let mut tap_create = MarkerTapCreatePort::new(link.clone());
        tap_create.behavior = FakePublishBehavior::PanicBeforePublish;
        let events = Arc::clone(&tap_create.events);

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepare_network_with_tap_port(&cfg, &network, &context, &tap_create)
        }));
        assert!(
            crashed.is_err(),
            "injected pre-publish crash did not unwind"
        );
        assert!(!link.exists(), "crashed pending TAP remained visible");
        assert!(
            !std::fs::read_to_string(log)
                .unwrap()
                .contains("link delete"),
            "crash recovery guessed cleanup from the TAP name"
        );
        let events = events.lock().unwrap();
        assert_eq!(events.creates, 1);
        assert_eq!(events.publishes, 0);
        assert_eq!(events.unpublished_drops, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_request_is_exclusive_nonpersistent_tap_without_packet_info() {
        let request = linux_tap_request("catphysical01").unwrap();
        let name_end = request.ifr_name.iter().position(|byte| *byte == 0).unwrap();
        let name = request.ifr_name[..name_end]
            .iter()
            .map(|byte| byte.to_ne_bytes()[0])
            .collect::<Vec<_>>();
        assert_eq!(name, b"catphysical01");
        // SAFETY: linux_tap_request initialized this union variant and no
        // other variant has been written since.
        let flags = unsafe { request.ifr_ifru.ifru_flags } as libc::c_int & 0xffff;
        assert_eq!(flags, libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL);
        assert_eq!(flags & libc::IFF_PERSIST, 0);
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
            vmm_launcher_bin: dir.path().join("cats-vmm-launcher"),
            ch_bin: fake_ch,
            kernel,
            initramfs: None,
            boot_contract: None,
            cmdline: "console=ttyS0".into(),
            seed_image: None,
            block_path: BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin: PathBuf::from("nbd-client"),
            nbd_devices: 8,
            ip_bin: PathBuf::from("ip"),
        };
        let serial = dir.path().join("serial.log");
        let network = plan_network(&desired_network()).unwrap();
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
            network: Some(&network),
        })
        .unwrap();
        assert!(child.wait().unwrap().success());
        let args = std::fs::read_to_string(args_path).unwrap();
        assert!(args.contains("--memory\nsize=0\n"));
        assert!(args.contains(&format!(
            "--memory-zone\nid=cat-ram,size=256M,file={},shared=on\n",
            memory_file.display()
        )));
        assert!(args.contains(&format!(
            "--net\ntap={},mac={}\n",
            network.tap,
            network.config.guest_mac.as_str()
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

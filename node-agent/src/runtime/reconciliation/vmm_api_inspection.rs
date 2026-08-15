//! Descriptor-retained Cloud Hypervisor v53 API/socket inspection.
//!
//! `vm.info` does not contain Cats volume lineage, artifact digests or the
//! Host-side IP configuration.  This adapter therefore proves only the facts
//! Cloud Hypervisor can physically report: process PID, VCPU/RAM shape, fixed
//! payload paths, Guest CID, TAP/MAC and the ordered block frontend list.  The
//! caller must join this private proof to the exact checkpoint, artifacts,
//! TAP and prepared-device proofs before publishing public evidence.

use std::collections::BTreeSet;

#[cfg(target_os = "linux")]
use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    HostPath, PrepareDeviceFrontend, ProcessState, RuntimeCheckpoint, RuntimeLaunchIdentity,
};
use serde::Deserialize;

use crate::runtime_spine::RuntimePhysicalReadContext;
#[cfg(target_os = "linux")]
use crate::vmm_launcher::VMM_API_LISTENER_FD;

use super::retained_runtime_launch::RetainedRuntimeLaunchAuthority;

const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_PING_TEXT_BYTES: usize = 1024;
const MAX_PING_FEATURES: usize = 128;
const MAX_PING_FEATURE_BYTES: usize = 256;

const CH_KERNEL_FD_PATH: &str = "/proc/self/fd/66";
const CH_INITRAMFS_FD_PATH: &str = "/proc/self/fd/67";
const CH_MEMORY_FD_PATH: &str = "/proc/self/fd/68";
const CH_SERIAL_FD_PATH: &str = "/proc/self/fd/69";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum VmmApiInspection {
    Exact(Box<ExactVmmApiProof>),
    Unavailable(VmmApiUnavailable),
    Conflict(VmmApiConflict),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VmmApiUnavailable {
    UnsupportedPlatform,
    SocketAbsentOrUnreadable,
    ApiTransportOrDeadline,
    ProcessTableUnreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VmmApiConflict {
    SocketIdentity,
    SocketOwnership,
    ApiPeer,
    HttpProtocol,
    VmmPing,
    VmInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VmmApiExpectation {
    process_id: u32,
    api_socket_path: HostPath,
    vsock_socket_path: HostPath,
    vcpus: u32,
    memory_bytes: u64,
    kernel_cmdline: String,
    has_initramfs: bool,
    guest_cid: u32,
    tap_name: String,
    guest_mac: String,
    disks: Vec<VmmApiDiskExpectation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VmmApiDiskExpectation {
    KernelNbd {
        path: String,
        direct: bool,
        serial: String,
    },
    VhostUserBlk {
        socket: String,
        queues: usize,
        queue_size: u16,
        serial: String,
    },
}

impl VmmApiExpectation {
    pub(super) fn from_checkpoint(
        checkpoint: &RuntimeCheckpoint,
        process_id: u32,
    ) -> anyhow::Result<Self> {
        let launch = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        Self::from_launch_identity(launch.identity(), process_id)
    }

    pub(super) fn from_launch_identity(
        launch: &RuntimeLaunchIdentity,
        process_id: u32,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(process_id > 0, "VMM API expectation has a zero process ID");
        let disks = launch
            .devices
            .iter()
            .map(|device| match &device.frontend {
                PrepareDeviceFrontend::KernelNbd {
                    device_path,
                    direct,
                    ..
                } => VmmApiDiskExpectation::KernelNbd {
                    path: device_path.as_str().to_owned(),
                    direct: *direct,
                    serial: device.guest_device.serial.as_str().to_owned(),
                },
                PrepareDeviceFrontend::VhostUserBlk {
                    socket_path,
                    queues,
                    queue_size,
                } => VmmApiDiskExpectation::VhostUserBlk {
                    socket: socket_path.as_str().to_owned(),
                    queues: usize::from(*queues),
                    queue_size: *queue_size,
                    serial: device.guest_device.serial.as_str().to_owned(),
                },
            })
            .collect();
        Ok(Self {
            process_id,
            api_socket_path: launch.api_socket_path.clone(),
            vsock_socket_path: launch.vsock_socket_path.clone(),
            vcpus: launch.vcpus,
            memory_bytes: launch.memory_bytes,
            kernel_cmdline: launch.boot.kernel_cmdline.as_str().to_owned(),
            has_initramfs: launch.boot.initramfs.is_some(),
            guest_cid: launch.guest_cid,
            tap_name: launch.network.tap_name.as_str().to_owned(),
            guest_mac: launch.network.network_config.guest_mac.as_str().to_owned(),
            disks,
        })
    }

    pub(super) fn process_id(&self) -> u32 {
        self.process_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VmmPingEvidence {
    build_version: String,
    version: String,
    features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VmmInfoEvidence {
    state: ProcessState,
    vcpus: u32,
    memory_bytes: u64,
    guest_cid: u32,
    tap_name: String,
    guest_mac: String,
    host_mac: String,
    disk_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExactVmmApiProof {
    expected: VmmApiExpectation,
    ping: VmmPingEvidence,
    info: VmmInfoEvidence,
    #[cfg(target_os = "linux")]
    api_socket: RetainedVmmSocket,
    #[cfg(target_os = "linux")]
    vsock_socket: RetainedVmmSocket,
}

impl ExactVmmApiProof {
    pub(super) fn ping(&self) -> &VmmPingEvidence {
        &self.ping
    }

    pub(super) fn info(&self) -> &VmmInfoEvidence {
        &self.info
    }

    pub(super) fn process_state(&self) -> ProcessState {
        self.info.state
    }

    pub(super) fn assert_current(
        &self,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = context;
            anyhow::bail!("VMM API proof is unavailable on this platform")
        }
        #[cfg(target_os = "linux")]
        {
            self.api_socket
                .path
                .assert_current()
                .context("revalidate retained VMM API socket")?;
            self.vsock_socket
                .path
                .assert_current()
                .context("revalidate retained VMM vsock socket")?;
            match inspect_vmm_api(&self.expected, context)? {
                VmmApiInspection::Exact(current)
                    if current.ping == self.ping
                        && current.info == self.info
                        && current.api_socket.identity == self.api_socket.identity
                        && current.vsock_socket.identity == self.vsock_socket.identity =>
                {
                    self.api_socket
                        .path
                        .assert_current()
                        .context("revalidate original VMM API socket proof")?;
                    self.vsock_socket
                        .path
                        .assert_current()
                        .context("revalidate original VMM vsock socket proof")?;
                    Ok(())
                }
                VmmApiInspection::Exact(_)
                | VmmApiInspection::Conflict(_)
                | VmmApiInspection::Unavailable(_) => {
                    anyhow::bail!("VMM API/socket proof changed after full inventory")
                }
            }
        }
    }
}

pub(super) fn inspect_vmm_api(
    expected: &VmmApiExpectation,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<VmmApiInspection> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (expected, context);
        Ok(VmmApiInspection::Unavailable(
            VmmApiUnavailable::UnsupportedPlatform,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        linux::inspect(expected, context)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmmPingWire {
    build_version: String,
    version: String,
    pid: i64,
    features: Vec<String>,
}

impl VmmPingWire {
    fn exact(self, expected_process_id: u32) -> Option<VmmPingEvidence> {
        let valid_text = |text: &str, maximum: usize| {
            !text.is_empty()
                && text.len() <= maximum
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        };
        if self.pid != i64::from(expected_process_id)
            || !valid_text(&self.build_version, MAX_PING_TEXT_BYTES)
            || !valid_text(&self.version, MAX_PING_TEXT_BYTES)
            || self.features.len() > MAX_PING_FEATURES
            || self
                .features
                .iter()
                .any(|feature| !valid_text(feature, MAX_PING_FEATURE_BYTES))
            || self.features.iter().collect::<BTreeSet<_>>().len() != self.features.len()
        {
            return None;
        }
        Some(VmmPingEvidence {
            build_version: self.build_version,
            version: self.version,
            features: self.features,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmInfoWire {
    config: VmConfigWire,
    state: VmStateWire,
    memory_actual_size: u64,
    #[serde(default)]
    device_tree: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum VmStateWire {
    Created,
    Running,
    Shutdown,
    Paused,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmConfigWire {
    cpus: CpusConfigWire,
    memory: MemoryConfigWire,
    payload: Option<PayloadConfigWire>,
    #[serde(default)]
    rate_limit_groups: Option<serde_json::Value>,
    #[serde(default)]
    disks: Option<Vec<DiskConfigWire>>,
    #[serde(default)]
    net: Option<Vec<NetConfigWire>>,
    rng: RngConfigWire,
    #[serde(default)]
    balloon: Option<serde_json::Value>,
    #[serde(default)]
    generic_vhost_user: Option<serde_json::Value>,
    #[serde(default)]
    fs: Option<serde_json::Value>,
    #[serde(default)]
    pmem: Option<serde_json::Value>,
    serial: SerialConfigWire,
    console: ConsoleConfigWire,
    #[serde(default)]
    debug_console: Option<DebugConsoleConfigWire>,
    #[serde(default)]
    devices: Option<serde_json::Value>,
    #[serde(default)]
    user_devices: Option<serde_json::Value>,
    #[serde(default)]
    vdpa: Option<serde_json::Value>,
    #[serde(default)]
    vsock: Option<VsockConfigWire>,
    #[serde(default)]
    pvmemcontrol: Option<serde_json::Value>,
    pvpanic: bool,
    iommu: bool,
    #[serde(default)]
    numa: Option<serde_json::Value>,
    watchdog: bool,
    #[serde(default)]
    rtc: Option<serde_json::Value>,
    #[serde(default)]
    gdb: Option<bool>,
    #[serde(default)]
    pci_segments: Option<serde_json::Value>,
    #[serde(default)]
    platform: Option<serde_json::Value>,
    #[serde(default)]
    tpm: Option<serde_json::Value>,
    landlock_enable: bool,
    #[serde(default)]
    landlock_rules: Option<serde_json::Value>,
    #[serde(default)]
    ivshmem: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpusConfigWire {
    boot_vcpus: u32,
    max_vcpus: u32,
    #[serde(default)]
    topology: Option<serde_json::Value>,
    kvm_hyperv: bool,
    max_phys_bits: u8,
    #[serde(default)]
    affinity: Option<serde_json::Value>,
    features: CpuFeaturesWire,
    nested: bool,
    core_scheduling: String,
    profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpuFeaturesWire {
    #[serde(default)]
    amx: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryConfigWire {
    size: u64,
    mergeable: bool,
    hotplug_method: String,
    #[serde(default)]
    hotplug_size: Option<u64>,
    #[serde(default)]
    hotplugged_size: Option<u64>,
    shared: bool,
    hugepages: bool,
    #[serde(default)]
    hugepage_size: Option<u64>,
    prefault: bool,
    reserve: bool,
    #[serde(default)]
    zones: Option<Vec<MemoryZoneConfigWire>>,
    thp: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryZoneConfigWire {
    id: String,
    size: u64,
    #[serde(default)]
    file: Option<String>,
    shared: bool,
    hugepages: bool,
    #[serde(default)]
    hugepage_size: Option<u64>,
    #[serde(default)]
    host_numa_node: Option<u32>,
    #[serde(default)]
    hotplug_size: Option<u64>,
    #[serde(default)]
    hotplugged_size: Option<u64>,
    prefault: bool,
    reserve: bool,
    mergeable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadConfigWire {
    #[serde(default)]
    firmware: Option<String>,
    #[serde(default)]
    kernel: Option<String>,
    #[serde(default)]
    cmdline: Option<String>,
    #[serde(default)]
    initramfs: Option<String>,
    #[serde(default)]
    igvm: Option<String>,
    #[serde(default)]
    host_data: Option<String>,
    #[serde(default)]
    fw_cfg_config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskConfigWire {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    iommu: bool,
    pci_segment: u16,
    #[serde(default)]
    pci_device_id: Option<u8>,
    #[serde(default)]
    path: Option<String>,
    readonly: bool,
    direct: bool,
    num_queues: usize,
    queue_size: u16,
    vhost_user: bool,
    #[serde(default)]
    vhost_socket: Option<String>,
    #[serde(default)]
    rate_limit_group: Option<String>,
    #[serde(default)]
    rate_limiter_config: Option<serde_json::Value>,
    disable_io_uring: bool,
    disable_aio: bool,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    queue_affinity: Option<serde_json::Value>,
    backing_files: bool,
    sparse: bool,
    image_type: String,
    lock_granularity: String,
}

impl DiskConfigWire {
    fn exact(&self, index: usize, expected: &VmmApiDiskExpectation) -> bool {
        let expected_id = format!("_disk{index}");
        let common = self.id.as_deref() == Some(expected_id.as_str())
            && !self.iommu
            && self.pci_segment == 0
            && self.pci_device_id.is_none()
            && !self.readonly
            && self.rate_limit_group.is_none()
            && self.rate_limiter_config.is_none()
            && !self.disable_io_uring
            && !self.disable_aio
            && self.queue_affinity.is_none()
            && !self.backing_files
            && self.sparse
            && self.lock_granularity == "ByteRange";
        common
            && match expected {
                VmmApiDiskExpectation::KernelNbd {
                    path,
                    direct,
                    serial,
                } => {
                    self.path.as_deref() == Some(path)
                        && self.direct == *direct
                        && self.serial.as_deref() == Some(serial)
                        && self.num_queues == 1
                        && self.queue_size == 128
                        && !self.vhost_user
                        && self.vhost_socket.is_none()
                        && self.image_type == "Raw"
                }
                VmmApiDiskExpectation::VhostUserBlk {
                    socket,
                    queues,
                    queue_size,
                    serial,
                } => {
                    self.path.is_none()
                        && !self.direct
                        && self.serial.as_deref() == Some(serial)
                        && self.num_queues == *queues
                        && self.queue_size == *queue_size
                        && self.vhost_user
                        && self.vhost_socket.as_deref() == Some(socket)
                        && self.image_type == "Unknown"
                }
            }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetConfigWire {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    iommu: bool,
    pci_segment: u16,
    #[serde(default)]
    pci_device_id: Option<u8>,
    #[serde(default)]
    tap: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    mask: Option<String>,
    mac: String,
    #[serde(default)]
    host_mac: Option<String>,
    #[serde(default)]
    mtu: Option<u16>,
    num_queues: usize,
    queue_size: u16,
    vhost_user: bool,
    #[serde(default)]
    vhost_socket: Option<String>,
    vhost_mode: String,
    #[serde(default)]
    fds: Option<Vec<i32>>,
    #[serde(default)]
    rate_limiter_config: Option<serde_json::Value>,
    offload_tso: bool,
    offload_ufo: bool,
    offload_csum: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RngConfigWire {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    iommu: bool,
    pci_segment: u16,
    #[serde(default)]
    pci_device_id: Option<u8>,
    src: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SerialConfigWire {
    #[serde(default)]
    file: Option<String>,
    mode: String,
    #[serde(default)]
    socket: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsoleConfigWire {
    #[serde(default)]
    file: Option<String>,
    mode: String,
    #[serde(default)]
    socket: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    iommu: bool,
    pci_segment: u16,
    #[serde(default)]
    pci_device_id: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugConsoleConfigWire {
    #[serde(default)]
    file: Option<String>,
    mode: String,
    #[serde(default)]
    iobase: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VsockConfigWire {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    iommu: bool,
    pci_segment: u16,
    #[serde(default)]
    pci_device_id: Option<u8>,
    cid: u32,
    socket: String,
}

impl VmInfoWire {
    fn exact(self, expected: &VmmApiExpectation) -> Option<VmmInfoEvidence> {
        let state = match self.state {
            VmStateWire::Running => ProcessState::Running,
            VmStateWire::Paused => ProcessState::Paused,
            VmStateWire::Created | VmStateWire::Shutdown => return None,
        };
        if self.memory_actual_size != expected.memory_bytes {
            return None;
        }
        let host_mac = self.config.exact(expected)?;
        // `device_tree` is an implementation topology, not an independent
        // launch request. Its bytes are bounded by the HTTP body cap; every
        // configurable device family is closed below through `VmConfig`.
        let _ = self.device_tree;
        Some(VmmInfoEvidence {
            state,
            vcpus: expected.vcpus,
            memory_bytes: expected.memory_bytes,
            guest_cid: expected.guest_cid,
            tap_name: expected.tap_name.clone(),
            guest_mac: expected.guest_mac.clone(),
            host_mac,
            disk_count: expected.disks.len(),
        })
    }
}

impl VmConfigWire {
    fn exact(&self, expected: &VmmApiExpectation) -> Option<String> {
        let cpus = &self.cpus;
        let cpu_exact = cpus.boot_vcpus == expected.vcpus
            && cpus.max_vcpus == expected.vcpus
            && cpus.topology.is_none()
            && !cpus.kvm_hyperv
            && cpus.max_phys_bits == 46
            && cpus.affinity.is_none()
            && !cpus.features.amx
            && cpus.nested
            && cpus.core_scheduling == "Vm"
            && cpus.profile == "Host";
        let zones = self.memory.zones.as_deref()?;
        let memory_exact = self.memory.size == 0
            && !self.memory.mergeable
            && self.memory.hotplug_method == "Acpi"
            && self.memory.hotplug_size.is_none()
            && self.memory.hotplugged_size.is_none()
            && !self.memory.shared
            && !self.memory.hugepages
            && self.memory.hugepage_size.is_none()
            && !self.memory.prefault
            && !self.memory.reserve
            && self.memory.thp
            && matches!(zones, [zone] if zone.exact(expected.memory_bytes));
        let payload_exact = self
            .payload
            .as_ref()
            .is_some_and(|payload| payload.exact(expected));
        let disks_exact = self.disks.as_deref().is_some_and(|disks| {
            disks.len() == expected.disks.len()
                && disks
                    .iter()
                    .zip(&expected.disks)
                    .enumerate()
                    .all(|(index, (actual, expected))| actual.exact(index, expected))
        });
        let net_exact = matches!(
            self.net.as_deref(),
            Some([net]) if net.exact(expected)
        );
        let vsock_exact = self
            .vsock
            .as_ref()
            .is_some_and(|vsock| vsock.exact(expected));
        // Cats' production Cloud Hypervisor artifact is the pinned x86_64
        // static build installed by `deploy/aws/metal/install-worker.sh`.
        // Keep that wire shape fixed even when these parser tests compile on
        // an aarch64 development host.
        let debug_console_exact = self
            .debug_console
            .as_ref()
            .is_some_and(DebugConsoleConfigWire::is_default);
        let exact = cpu_exact
            && memory_exact
            && payload_exact
            && disks_exact
            && net_exact
            && vsock_exact
            && self.rate_limit_groups.is_none()
            && self.rng.is_default()
            && self.balloon.is_none()
            && self.generic_vhost_user.is_none()
            && self.fs.is_none()
            && self.pmem.is_none()
            && self.serial.is_exact()
            && self.console.is_default()
            && debug_console_exact
            && self.devices.is_none()
            && self.user_devices.is_none()
            && self.vdpa.is_none()
            && self.pvmemcontrol.is_none()
            && !self.pvpanic
            && !self.iommu
            && self.numa.is_none()
            && !self.watchdog
            && self.rtc.is_none()
            && self.gdb.is_none_or(|gdb| !gdb)
            && self.pci_segments.is_none()
            && self.platform.is_none()
            && self.tpm.is_none()
            && !self.landlock_enable
            && self.landlock_rules.is_none()
            && self.ivshmem.is_none();
        if exact {
            self.net
                .as_deref()
                .and_then(|net| net.first())
                .and_then(|net| net.host_mac.clone())
        } else {
            None
        }
    }
}

impl MemoryZoneConfigWire {
    fn exact(&self, memory_bytes: u64) -> bool {
        self.id == "cat-ram"
            && self.size == memory_bytes
            && self.file.as_deref() == Some(CH_MEMORY_FD_PATH)
            && self.shared
            && !self.hugepages
            && self.hugepage_size.is_none()
            && self.host_numa_node.is_none()
            && self.hotplug_size.is_none()
            && self.hotplugged_size.is_none()
            && !self.prefault
            && !self.reserve
            && !self.mergeable
    }
}

impl PayloadConfigWire {
    fn exact(&self, expected: &VmmApiExpectation) -> bool {
        self.firmware.is_none()
            && self.kernel.as_deref() == Some(CH_KERNEL_FD_PATH)
            && self.cmdline.as_deref() == Some(expected.kernel_cmdline.as_str())
            && self.initramfs.as_deref() == expected.has_initramfs.then_some(CH_INITRAMFS_FD_PATH)
            && self.igvm.is_none()
            && self.host_data.is_none()
            && self.fw_cfg_config.is_none()
    }
}

impl NetConfigWire {
    fn exact(&self, expected: &VmmApiExpectation) -> bool {
        let expected_id = format!("_net{}", expected.disks.len());
        self.id.as_deref() == Some(expected_id.as_str())
            && !self.iommu
            && self.pci_segment == 0
            && self.pci_device_id.is_none()
            && self.tap.as_deref() == Some(expected.tap_name.as_str())
            && self.ip.is_none()
            && self.mask.is_none()
            && self.mac == expected.guest_mac
            && self.host_mac.as_deref().is_some_and(canonical_mac)
            && self.mtu.is_none()
            && self.num_queues == 2
            && self.queue_size == 256
            && !self.vhost_user
            && self.vhost_socket.is_none()
            && self.vhost_mode == "Client"
            && self.fds.is_none()
            && self.rate_limiter_config.is_none()
            && self.offload_tso
            && self.offload_ufo
            && self.offload_csum
    }
}

impl RngConfigWire {
    fn is_default(&self) -> bool {
        self.id.is_none()
            && !self.iommu
            && self.pci_segment == 0
            && self.pci_device_id.is_none()
            && self.src == "/dev/urandom"
    }
}

impl SerialConfigWire {
    fn is_exact(&self) -> bool {
        self.file.as_deref() == Some(CH_SERIAL_FD_PATH)
            && self.mode == "File"
            && self.socket.is_none()
    }
}

impl ConsoleConfigWire {
    fn is_default(&self) -> bool {
        self.file.is_none()
            && self.mode == "Off"
            && self.socket.is_none()
            && self.id.is_none()
            && !self.iommu
            && self.pci_segment == 0
            && self.pci_device_id.is_none()
    }
}

impl DebugConsoleConfigWire {
    fn is_default(&self) -> bool {
        self.file.is_none() && self.mode == "Off" && self.iobase == Some(0xe9)
    }
}

impl VsockConfigWire {
    fn exact(&self, expected: &VmmApiExpectation) -> bool {
        let expected_id = format!("_vsock{}", expected.disks.len() + 1);
        self.id.as_deref() == Some(expected_id.as_str())
            && !self.iommu
            && self.pci_segment == 0
            && self.pci_device_id.is_none()
            && self.cid == expected.guest_cid
            && self.socket == expected.vsock_socket_path.as_str()
    }
}

fn canonical_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 2 | 5 | 8 | 11 | 14) {
                byte == b':'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{CString, OsString};
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Component, Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use anyhow::Context as _;

    use super::*;

    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const PROC_NET_UNIX_MAX_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_PROC_ENTRIES: usize = 131_072;
    const MAX_PROCESS_DESCRIPTORS: usize = 4_096;
    const MAX_TOTAL_DESCRIPTORS: usize = 262_144;

    pub(super) fn inspect(
        expected: &VmmApiExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<VmmApiInspection> {
        context.check_active()?;
        let process_metadata = match std::fs::metadata(format!("/proc/{}", expected.process_id)) {
            Ok(metadata) if metadata.is_dir() => metadata,
            Ok(_) => return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketOwnership)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(VmmApiInspection::Unavailable(
                    VmmApiUnavailable::SocketAbsentOrUnreadable,
                ))
            }
            Err(_) => {
                return Ok(VmmApiInspection::Unavailable(
                    VmmApiUnavailable::ProcessTableUnreadable,
                ))
            }
        };
        let expected_user = process_metadata.uid();
        let expected_group = process_metadata.gid();
        let api_path = match RetainedSocketPath::open(
            &expected.api_socket_path,
            expected_user,
            expected_group,
        )? {
            PathInspection::Exact(path) => path,
            PathInspection::Unavailable => {
                return Ok(VmmApiInspection::Unavailable(
                    VmmApiUnavailable::SocketAbsentOrUnreadable,
                ))
            }
            PathInspection::Conflict => {
                return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketIdentity))
            }
        };
        let vsock_path = match RetainedSocketPath::open(
            &expected.vsock_socket_path,
            expected_user,
            expected_group,
        )? {
            PathInspection::Exact(path) => path,
            PathInspection::Unavailable => {
                return Ok(VmmApiInspection::Unavailable(
                    VmmApiUnavailable::SocketAbsentOrUnreadable,
                ))
            }
            PathInspection::Conflict => {
                return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketIdentity))
            }
        };
        if api_path.identity == vsock_path.identity {
            return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketIdentity));
        }
        let before =
            match inspect_listener_pair(&expected.vsock_socket_path, expected.process_id, context)?
            {
                PairInspection::Exact(pair) => pair,
                PairInspection::Unavailable => {
                    return Ok(VmmApiInspection::Unavailable(
                        VmmApiUnavailable::ProcessTableUnreadable,
                    ))
                }
                PairInspection::Conflict => {
                    return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketOwnership))
                }
            };

        let ping_body = match get_api_json(
            &expected.api_socket_path,
            "/api/v1/vmm.ping",
            expected.process_id,
            context,
        )? {
            ApiRead::Exact(body) => body,
            ApiRead::Unavailable => {
                return Ok(VmmApiInspection::Unavailable(
                    VmmApiUnavailable::ApiTransportOrDeadline,
                ))
            }
            ApiRead::Conflict(conflict) => return Ok(VmmApiInspection::Conflict(conflict)),
        };
        let ping = match serde_json::from_slice::<VmmPingWire>(&ping_body)
            .ok()
            .and_then(|ping| ping.exact(expected.process_id))
        {
            Some(ping) => ping,
            None => return Ok(VmmApiInspection::Conflict(VmmApiConflict::VmmPing)),
        };
        let info_body = match get_api_json(
            &expected.api_socket_path,
            "/api/v1/vm.info",
            expected.process_id,
            context,
        )? {
            ApiRead::Exact(body) => body,
            ApiRead::Unavailable => {
                return Ok(VmmApiInspection::Unavailable(
                    VmmApiUnavailable::ApiTransportOrDeadline,
                ))
            }
            ApiRead::Conflict(conflict) => return Ok(VmmApiInspection::Conflict(conflict)),
        };
        let info = match serde_json::from_slice::<VmInfoWire>(&info_body)
            .ok()
            .and_then(|info| info.exact(expected))
        {
            Some(info) => info,
            None => return Ok(VmmApiInspection::Conflict(VmmApiConflict::VmInfo)),
        };
        if api_path.assert_current().is_err() || vsock_path.assert_current().is_err() {
            return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketIdentity));
        }
        let after =
            match inspect_listener_pair(&expected.vsock_socket_path, expected.process_id, context)?
            {
                PairInspection::Exact(pair) => pair,
                PairInspection::Unavailable => {
                    return Ok(VmmApiInspection::Unavailable(
                        VmmApiUnavailable::ProcessTableUnreadable,
                    ))
                }
                PairInspection::Conflict => {
                    return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketOwnership))
                }
            };
        if before != after {
            return Ok(VmmApiInspection::Conflict(VmmApiConflict::SocketIdentity));
        }
        context.check_active()?;
        Ok(VmmApiInspection::Exact(Box::new(ExactVmmApiProof {
            expected: expected.clone(),
            ping,
            info,
            api_socket: RetainedVmmSocket {
                identity: SocketIdentity {
                    path: api_path.identity,
                    kernel_inode: before[0],
                },
                path: Arc::new(api_path),
            },
            vsock_socket: RetainedVmmSocket {
                identity: SocketIdentity {
                    path: vsock_path.identity,
                    kernel_inode: before[1],
                },
                path: Arc::new(vsock_path),
            },
        })))
    }

    #[derive(Debug, Clone)]
    pub(super) struct RetainedVmmSocket {
        pub(super) identity: SocketIdentity,
        pub(super) path: Arc<RetainedSocketPath>,
    }

    impl PartialEq for RetainedVmmSocket {
        fn eq(&self, other: &Self) -> bool {
            self.identity == other.identity
        }
    }

    impl Eq for RetainedVmmSocket {}

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct SocketIdentity {
        path: PathIdentity,
        kernel_inode: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PathIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        links: u64,
        user: u32,
        group: u32,
    }

    #[derive(Clone)]
    struct RetainedPathComponent {
        name: OsString,
        descriptor: Arc<File>,
        identity: PathIdentity,
    }

    impl std::fmt::Debug for RetainedPathComponent {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("RetainedPathComponent")
                .field("name", &self.name)
                .field("identity", &self.identity)
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone)]
    pub(super) struct RetainedSocketPath {
        absolute_path: PathBuf,
        root: Arc<File>,
        root_identity: PathIdentity,
        directories: Vec<RetainedPathComponent>,
        leaf_name: OsString,
        leaf: Arc<File>,
        identity: PathIdentity,
    }

    impl std::fmt::Debug for RetainedSocketPath {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("RetainedSocketPath")
                .field("absolute_path", &self.absolute_path)
                .field("root_identity", &self.root_identity)
                .field("directories", &self.directories)
                .field("leaf_name", &self.leaf_name)
                .field("identity", &self.identity)
                .finish_non_exhaustive()
        }
    }

    enum PathInspection {
        Exact(RetainedSocketPath),
        Unavailable,
        Conflict,
    }

    impl RetainedSocketPath {
        fn open(
            socket: &HostPath,
            expected_user: u32,
            expected_group: u32,
        ) -> anyhow::Result<PathInspection> {
            let path = Path::new(socket.as_str());
            if !path.is_absolute() {
                return Ok(PathInspection::Conflict);
            }
            let mut components = Vec::new();
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(component) => components.push(component.to_owned()),
                    Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                        return Ok(PathInspection::Conflict)
                    }
                }
            }
            if components.is_empty() {
                return Ok(PathInspection::Conflict);
            }
            let root = match open_absolute_root() {
                Ok(root) => Arc::new(root),
                Err(_) => return Ok(PathInspection::Unavailable),
            };
            let root_identity = path_identity(
                &root
                    .metadata()
                    .context("stat retained VMM socket filesystem root")?,
            );
            let mut current = root.try_clone()?;
            let mut directories = Vec::with_capacity(components.len().saturating_sub(1));
            for component in &components[..components.len() - 1] {
                let descriptor = match open_component(
                    &current,
                    component,
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                ) {
                    Ok(descriptor) => descriptor,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(PathInspection::Unavailable)
                    }
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EINVAL)
                        ) =>
                    {
                        return Ok(PathInspection::Conflict)
                    }
                    Err(_) => return Ok(PathInspection::Unavailable),
                };
                let identity = path_identity(
                    &descriptor
                        .metadata()
                        .context("stat retained VMM socket parent")?,
                );
                current = descriptor.try_clone()?;
                directories.push(RetainedPathComponent {
                    name: component.clone(),
                    descriptor: Arc::new(descriptor),
                    identity,
                });
            }
            let leaf_name = components
                .last()
                .expect("nonempty absolute socket path")
                .clone();
            let leaf = match open_component(
                &current,
                &leaf_name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            ) {
                Ok(leaf) => Arc::new(leaf),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(PathInspection::Unavailable)
                }
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EINVAL)
                    ) =>
                {
                    return Ok(PathInspection::Conflict)
                }
                Err(_) => return Ok(PathInspection::Unavailable),
            };
            let metadata = leaf.metadata().context("stat retained VMM socket")?;
            let identity = path_identity(&metadata);
            if !metadata.file_type().is_socket()
                || identity.links != 1
                || identity.mode & 0o7777 != 0o700
                || identity.user != expected_user
                || identity.group != expected_group
            {
                return Ok(PathInspection::Conflict);
            }
            let retained = Self {
                absolute_path: path.to_path_buf(),
                root,
                root_identity,
                directories,
                leaf_name,
                leaf,
                identity,
            };
            if retained.assert_current().is_err() {
                return Ok(PathInspection::Conflict);
            }
            Ok(PathInspection::Exact(retained))
        }

        pub(super) fn assert_current(&self) -> anyhow::Result<()> {
            anyhow::ensure!(
                path_identity(&self.root.metadata().context("re-stat VMM socket root")?)
                    == self.root_identity,
                "retained VMM socket root identity changed"
            );
            let lexical_root = open_absolute_root().context("reopen VMM socket root")?;
            anyhow::ensure!(
                path_identity(
                    &lexical_root
                        .metadata()
                        .context("stat reopened VMM socket root")?
                ) == self.root_identity,
                "VMM socket root path no longer names the retained root"
            );
            let mut current = self.root.try_clone()?;
            for directory in &self.directories {
                anyhow::ensure!(
                    path_identity(
                        &directory
                            .descriptor
                            .metadata()
                            .context("re-stat retained VMM socket parent")?
                    ) == directory.identity,
                    "retained VMM socket parent identity changed"
                );
                let reopened = open_component(
                    &current,
                    &directory.name,
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .context("reopen VMM socket parent")?;
                anyhow::ensure!(
                    path_identity(
                        &reopened
                            .metadata()
                            .context("stat reopened VMM socket parent")?
                    ) == directory.identity,
                    "VMM socket parent path no longer names retained directory"
                );
                current = reopened;
            }
            anyhow::ensure!(
                path_identity(
                    &self
                        .leaf
                        .metadata()
                        .context("re-stat retained VMM socket")?
                ) == self.identity,
                "retained VMM socket identity changed"
            );
            let reopened = open_component(
                &current,
                &self.leaf_name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .context("reopen VMM socket leaf")?;
            anyhow::ensure!(
                path_identity(
                    &reopened
                        .metadata()
                        .context("stat reopened VMM socket leaf")?
                ) == self.identity,
                "VMM socket path no longer names retained inode"
            );
            Ok(())
        }
    }

    fn open_absolute_root() -> io::Result<File> {
        let root = CString::new("/").expect("root path contains no NUL");
        // SAFETY: the root CString is valid for this call and a successful
        // descriptor moves exactly once into File.
        let descriptor = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn open_component(parent: &File, component: &std::ffi::OsStr, flags: i32) -> io::Result<File> {
        let component = CString::new(component.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: parent is a live directory descriptor, component is
        // NUL-terminated, and a successful fd moves once into File.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn path_identity(metadata: &std::fs::Metadata) -> PathIdentity {
        PathIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            user: metadata.uid(),
            group: metadata.gid(),
        }
    }

    pub(super) enum PairInspection {
        Exact([u64; 2]),
        Unavailable,
        Conflict,
    }

    pub(super) fn inspect_listener_pair(
        vsock_path: &HostPath,
        expected_process_id: u32,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<PairInspection> {
        context.check_active()?;
        let api_inode = match inspect_api_listener_descriptor(expected_process_id)? {
            DescriptorInspection::Exact(inode) => inode,
            DescriptorInspection::Unavailable => return Ok(PairInspection::Unavailable),
            DescriptorInspection::Conflict => return Ok(PairInspection::Conflict),
        };
        let file = match File::open("/proc/net/unix") {
            Ok(file) => file,
            Err(_) => return Ok(PairInspection::Unavailable),
        };
        let mut bytes = Vec::new();
        file.take(PROC_NET_UNIX_MAX_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .context("read VMM /proc/net/unix")?;
        context.check_active()?;
        if bytes.len() as u64 > PROC_NET_UNIX_MAX_BYTES {
            return Ok(PairInspection::Conflict);
        }
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => return Ok(PairInspection::Conflict),
        };
        let mut matching_api = Vec::new();
        let mut matching_vsock = Vec::new();
        for line in text.lines().skip(1) {
            let Some(fields) = parse_proc_net_unix_line(line) else {
                continue;
            };
            let is_api = fields.inode == api_inode;
            let is_vsock = fields.path == Some(vsock_path.as_str());
            if is_api || is_vsock {
                if fields.flags != "00010000"
                    || fields.socket_type != "0001"
                    || fields.state != "01"
                {
                    return Ok(PairInspection::Conflict);
                }
                if is_api {
                    matching_api.push(fields.inode);
                }
                if is_vsock {
                    matching_vsock.push(fields.inode);
                }
            }
        }
        let pair = match (matching_api.as_slice(), matching_vsock.as_slice()) {
            ([api], [vsock]) if api != vsock => [*api, *vsock],
            ([], _) | (_, []) => return Ok(PairInspection::Unavailable),
            _ => return Ok(PairInspection::Conflict),
        };
        match inspect_fd_owners(pair, expected_process_id, context)? {
            OwnerInspection::Exact => Ok(PairInspection::Exact(pair)),
            OwnerInspection::Unavailable => Ok(PairInspection::Unavailable),
            OwnerInspection::Conflict => Ok(PairInspection::Conflict),
        }
    }

    enum DescriptorInspection {
        Exact(u64),
        Unavailable,
        Conflict,
    }

    fn inspect_api_listener_descriptor(
        expected_process_id: u32,
    ) -> anyhow::Result<DescriptorInspection> {
        let descriptor_path = format!("/proc/{expected_process_id}/fd/{VMM_API_LISTENER_FD}");
        let target = match std::fs::read_link(&descriptor_path) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(DescriptorInspection::Unavailable)
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(DescriptorInspection::Unavailable)
            }
            Err(_) => return Ok(DescriptorInspection::Conflict),
        };
        let bytes = target.as_os_str().as_bytes();
        let Some(payload) = bytes
            .strip_prefix(b"socket:[")
            .and_then(|bytes| bytes.strip_suffix(b"]"))
        else {
            return Ok(DescriptorInspection::Conflict);
        };
        let inode = match std::str::from_utf8(payload)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|inode| *inode > 0)
        {
            Some(inode) => inode,
            None => return Ok(DescriptorInspection::Conflict),
        };
        Ok(DescriptorInspection::Exact(inode))
    }

    struct ProcNetUnixLine<'a> {
        flags: &'a str,
        socket_type: &'a str,
        state: &'a str,
        inode: u64,
        path: Option<&'a str>,
    }

    fn parse_proc_net_unix_line(line: &str) -> Option<ProcNetUnixLine<'_>> {
        fn next_field<'a>(line: &'a str, offset: &mut usize) -> Option<&'a str> {
            while line
                .as_bytes()
                .get(*offset)
                .is_some_and(u8::is_ascii_whitespace)
            {
                *offset += 1;
            }
            let start = *offset;
            while line
                .as_bytes()
                .get(*offset)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                *offset += 1;
            }
            (*offset > start).then(|| &line[start..*offset])
        }

        let mut offset = 0;
        let _number = next_field(line, &mut offset)?;
        let _references = next_field(line, &mut offset)?;
        let _protocol = next_field(line, &mut offset)?;
        let flags = next_field(line, &mut offset)?;
        let socket_type = next_field(line, &mut offset)?;
        let state = next_field(line, &mut offset)?;
        let inode = next_field(line, &mut offset)?.parse::<u64>().ok()?;
        while line
            .as_bytes()
            .get(offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            offset += 1;
        }
        let path = line.get(offset..).filter(|path| !path.is_empty());
        Some(ProcNetUnixLine {
            flags,
            socket_type,
            state,
            inode,
            path,
        })
    }

    enum OwnerInspection {
        Exact,
        Unavailable,
        Conflict,
    }

    fn inspect_fd_owners(
        inodes: [u64; 2],
        expected_process_id: u32,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<OwnerInspection> {
        let targets = [
            OsString::from_vec(format!("socket:[{}]", inodes[0]).into_bytes()),
            OsString::from_vec(format!("socket:[{}]", inodes[1]).into_bytes()),
        ];
        let processes = match std::fs::read_dir("/proc") {
            Ok(processes) => processes,
            Err(_) => return Ok(OwnerInspection::Unavailable),
        };
        let mut process_entries = 0_usize;
        let mut total_descriptors = 0_usize;
        let mut expected_counts = [0_usize; 2];
        let mut foreign = [false; 2];
        for process in processes {
            context.check_active()?;
            process_entries = process_entries.saturating_add(1);
            if process_entries > MAX_PROC_ENTRIES {
                return Ok(OwnerInspection::Conflict);
            }
            let process = match process {
                Ok(process) => process,
                Err(_) => return Ok(OwnerInspection::Unavailable),
            };
            let Some(process_id) = process
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .filter(|process_id| *process_id > 0)
            else {
                continue;
            };
            let descriptors = match std::fs::read_dir(process.path().join("fd")) {
                Ok(descriptors) => descriptors,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return Ok(OwnerInspection::Unavailable)
                }
                Err(_) => return Ok(OwnerInspection::Unavailable),
            };
            let mut process_descriptors = 0_usize;
            for descriptor in descriptors {
                context.check_active()?;
                process_descriptors = process_descriptors.saturating_add(1);
                total_descriptors = total_descriptors.saturating_add(1);
                if process_descriptors > MAX_PROCESS_DESCRIPTORS
                    || total_descriptors > MAX_TOTAL_DESCRIPTORS
                {
                    return Ok(OwnerInspection::Conflict);
                }
                let descriptor = match descriptor {
                    Ok(descriptor) => descriptor,
                    Err(_) => return Ok(OwnerInspection::Unavailable),
                };
                let descriptor_number = match descriptor
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<i32>().ok())
                    .filter(|descriptor| *descriptor >= 0)
                {
                    Some(descriptor) => descriptor,
                    None => return Ok(OwnerInspection::Conflict),
                };
                match std::fs::read_link(descriptor.path()) {
                    Ok(target) => {
                        for (index, expected) in targets.iter().enumerate() {
                            if target.as_os_str() == expected {
                                let exact_owner = process_id == expected_process_id
                                    && (index != 0 || descriptor_number == VMM_API_LISTENER_FD);
                                if exact_owner {
                                    expected_counts[index] =
                                        expected_counts[index].saturating_add(1);
                                } else {
                                    foreign[index] = true;
                                }
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        return Ok(OwnerInspection::Unavailable)
                    }
                    Err(_) => return Ok(OwnerInspection::Unavailable),
                }
            }
        }
        Ok(if expected_counts == [1, 1] && foreign == [false, false] {
            OwnerInspection::Exact
        } else {
            OwnerInspection::Conflict
        })
    }

    enum ApiRead {
        Exact(Vec<u8>),
        Unavailable,
        Conflict(VmmApiConflict),
    }

    fn get_api_json(
        socket: &HostPath,
        request_path: &str,
        expected_process_id: u32,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ApiRead> {
        let mut stream = match connect_nonblocking(socket, context)? {
            Some(stream) => stream,
            None => return Ok(ApiRead::Unavailable),
        };
        if peer_process_id(stream.as_raw_fd()) != Some(expected_process_id) {
            return Ok(ApiRead::Conflict(VmmApiConflict::ApiPeer));
        }
        let request = format!(
            "GET {request_path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        if !write_all_before(&mut stream, request.as_bytes(), context)? {
            return Ok(ApiRead::Unavailable);
        }
        read_http_response(&mut stream, context)
    }

    fn connect_nonblocking(
        socket: &HostPath,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<Option<UnixStream>> {
        context.check_active()?;
        let bytes = socket.as_str().as_bytes();
        if bytes.is_empty() || bytes.len() >= 108 || bytes.contains(&0) {
            return Ok(None);
        }
        // SAFETY: socket returns a fresh descriptor and retains no Rust data.
        let descriptor = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if descriptor < 0 {
            return Ok(None);
        }
        // SAFETY: zeroed sockaddr_un is valid initialization; family/path are
        // filled below before the kernel reads it.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, source) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
            *target = source as libc::c_char;
        }
        let length = (size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
        // SAFETY: descriptor/address are live for this call and not retained.
        let connected = unsafe {
            libc::connect(
                descriptor,
                (&raw const address).cast::<libc::sockaddr>(),
                length,
            )
        };
        if connected != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS)
                || !poll_before(descriptor, libc::POLLOUT, context)?
                || socket_error(descriptor) != Some(0)
            {
                // SAFETY: descriptor ownership has not moved.
                unsafe { libc::close(descriptor) };
                return Ok(None);
            }
        }
        // SAFETY: ownership of the connected descriptor moves into UnixStream.
        Ok(Some(unsafe { UnixStream::from_raw_fd(descriptor) }))
    }

    fn peer_process_id(descriptor: i32) -> Option<u32> {
        // SAFETY: zeroed ucred is valid initialization and getsockopt writes
        // the complete structure before fields are read.
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: credentials/length are writable and valid for getsockopt.
        let result = unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut credentials).cast(),
                &raw mut length,
            )
        };
        (result == 0 && length as usize == size_of::<libc::ucred>() && credentials.pid > 0)
            .then_some(credentials.pid as u32)
    }

    fn socket_error(descriptor: i32) -> Option<i32> {
        let mut error = 0_i32;
        let mut length = size_of::<i32>() as libc::socklen_t;
        // SAFETY: error/length are writable and valid for getsockopt.
        let result = unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut error).cast(),
                &raw mut length,
            )
        };
        (result == 0 && length as usize == size_of::<i32>()).then_some(error)
    }

    fn poll_before(
        descriptor: i32,
        events: i16,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<bool> {
        loop {
            context.check_active()?;
            let remaining = context.deadline().saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let timeout =
                i32::try_from(POLL_INTERVAL.min(remaining).as_millis().max(1)).unwrap_or(1);
            let mut poll = libc::pollfd {
                fd: descriptor,
                events,
                revents: 0,
            };
            // SAFETY: poll points to one initialized pollfd for the call.
            let result = unsafe { libc::poll(&raw mut poll, 1, timeout) };
            if result > 0 {
                return Ok(poll.revents & events != 0);
            }
            if result == 0 {
                continue;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Ok(false);
            }
        }
    }

    fn write_all_before(
        stream: &mut UnixStream,
        mut bytes: &[u8],
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<bool> {
        while !bytes.is_empty() {
            context.check_active()?;
            match stream.write(bytes) {
                Ok(0) => return Ok(false),
                Ok(written) => bytes = &bytes[written..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !poll_before(stream.as_raw_fd(), libc::POLLOUT, context)? {
                        return Ok(false);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Ok(false),
            }
        }
        Ok(true)
    }

    fn read_http_response(
        stream: &mut UnixStream,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ApiRead> {
        let mut bytes = Vec::new();
        let header_end = loop {
            if let Some(offset) = find_bytes(&bytes, b"\r\n\r\n") {
                break offset + 4;
            }
            if bytes.len() >= MAX_HTTP_HEADER_BYTES {
                return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
            }
            match read_more(stream, &mut bytes, MAX_HTTP_HEADER_BYTES, context)? {
                ReadProgress::Read => {}
                ReadProgress::Eof => return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol)),
                ReadProgress::Unavailable => return Ok(ApiRead::Unavailable),
            }
        };
        let header = match std::str::from_utf8(&bytes[..header_end]) {
            Ok(header) => header,
            Err(_) => return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol)),
        };
        let mut lines = header[..header.len() - 4].split("\r\n");
        let Some(status) = lines.next() else {
            return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
        };
        // Cloud Hypervisor's micro_http response may leave the reason phrase
        // empty (`HTTP/1.1 200 `). HTTP status identity is the version/code;
        // accept zero or more bounded ASCII reason words.
        let mut status_fields = status.split_whitespace();
        if status_fields.next() != Some("HTTP/1.1")
            || status_fields.next() != Some("200")
            || status_fields.any(|field| {
                !field
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            })
        {
            return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
        }
        let mut content_length = None;
        for line in lines {
            if line.starts_with(' ') || line.starts_with('\t') {
                return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
            }
            let Some((name, value)) = line.split_once(':') else {
                return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
            };
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
            }
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
                }
                content_length = value.trim().parse::<usize>().ok();
                if content_length.is_none() {
                    return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
                }
            }
        }
        let Some(content_length) = content_length.filter(|length| *length <= MAX_HTTP_BODY_BYTES)
        else {
            return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
        };
        let total = match header_end.checked_add(content_length) {
            Some(total) => total,
            None => return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol)),
        };
        if bytes.len() > total {
            return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol));
        }
        while bytes.len() < total {
            match read_more(stream, &mut bytes, total, context)? {
                ReadProgress::Read => {}
                ReadProgress::Eof => return Ok(ApiRead::Conflict(VmmApiConflict::HttpProtocol)),
                ReadProgress::Unavailable => return Ok(ApiRead::Unavailable),
            }
        }
        Ok(ApiRead::Exact(bytes[header_end..].to_vec()))
    }

    enum ReadProgress {
        Read,
        Eof,
        Unavailable,
    }

    fn read_more(
        stream: &mut UnixStream,
        bytes: &mut Vec<u8>,
        maximum: usize,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ReadProgress> {
        context.check_active()?;
        let remaining = maximum.saturating_sub(bytes.len());
        if remaining == 0 {
            return Ok(ReadProgress::Eof);
        }
        let mut buffer = [0_u8; 8192];
        let read_limit = remaining.min(buffer.len());
        match stream.read(&mut buffer[..read_limit]) {
            Ok(0) => Ok(ReadProgress::Eof),
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                Ok(ReadProgress::Read)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if poll_before(stream.as_raw_fd(), libc::POLLIN, context)? {
                    Ok(ReadProgress::Read)
                } else {
                    Ok(ReadProgress::Unavailable)
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(ReadProgress::Read),
            Err(_) => Ok(ReadProgress::Unavailable),
        }
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

#[cfg(target_os = "linux")]
use linux::RetainedVmmSocket;

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs::File;
    #[cfg(target_os = "linux")]
    use std::io::Read as _;
    #[cfg(target_os = "linux")]
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixListener;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::decode_runtime_checkpoint;

    use super::*;

    fn expectation() -> VmmApiExpectation {
        let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        VmmApiExpectation::from_checkpoint(&checkpoint, 4242).unwrap()
    }

    fn exact_ping() -> Vec<u8> {
        br#"{"build_version":"v53.0","version":"53.0","pid":4242,"features":["io_uring"]}"#.to_vec()
    }

    fn exact_vm_info() -> Vec<u8> {
        let expected = expectation();
        let [VmmApiDiskExpectation::VhostUserBlk { socket, .. }] = expected.disks.as_slice() else {
            panic!("test checkpoint must contain exactly one vhost-user-blk device")
        };
        const VHOST_SOCKET_PLACEHOLDER: &str = "__EXPECTED_VHOST_SOCKET__";
        let template = r#"{
          "config": {
            "cpus": {"boot_vcpus":2,"max_vcpus":2,"kvm_hyperv":false,"max_phys_bits":46,"features":{"amx":false},"nested":true,"core_scheduling":"Vm","profile":"Host"},
            "memory": {"size":0,"mergeable":false,"hotplug_method":"Acpi","shared":false,"hugepages":false,"prefault":false,"reserve":false,"zones":[{"id":"cat-ram","size":2147483648,"file":"/proc/self/fd/68","shared":true,"hugepages":false,"prefault":false,"reserve":false,"mergeable":false}],"thp":true},
            "payload": {"kernel":"/proc/self/fd/66","cmdline":"console=ttyS0 root=/dev/vda rw clocksource=kvm-clock","initramfs":"/proc/self/fd/67"},
            "disks": [{"id":"_disk0","pci_segment":0,"readonly":false,"direct":false,"num_queues":2,"queue_size":256,"vhost_user":true,"vhost_socket":"__EXPECTED_VHOST_SOCKET__","disable_io_uring":false,"disable_aio":false,"serial":"cats-root","backing_files":false,"sparse":true,"image_type":"Unknown","lock_granularity":"ByteRange"}],
            "net": [{"id":"_net1","pci_segment":0,"tap":"cats0001","mac":"02:ca:0a:f0:00:06","host_mac":"02:00:00:00:00:01","num_queues":2,"queue_size":256,"vhost_user":false,"vhost_mode":"Client","offload_tso":true,"offload_ufo":true,"offload_csum":true}],
            "rng": {"pci_segment":0,"src":"/dev/urandom"},
            "serial": {"file":"/proc/self/fd/69","mode":"File"},
            "console": {"mode":"Off","pci_segment":0},
            "debug_console": {"mode":"Off","iobase":233},
            "vsock": {"id":"_vsock2","pci_segment":0,"cid":3,"socket":"/run/cats/cat_01/vmm-vsock.sock"},
            "pvpanic":false,"iommu":false,"watchdog":false,"landlock_enable":false
          },
          "state":"Running",
          "memory_actual_size":2147483648,
          "device_tree":{}
        }"#;
        assert_eq!(template.matches(VHOST_SOCKET_PLACEHOLDER).count(), 1);
        template
            .replace(VHOST_SOCKET_PLACEHOLDER, socket)
            .into_bytes()
    }

    #[test]
    fn v53_ping_binds_the_exact_main_pid_and_rejects_extra_fields() {
        let ping = serde_json::from_slice::<VmmPingWire>(&exact_ping()).unwrap();
        assert!(ping.exact(4242).is_some());
        assert!(serde_json::from_slice::<VmmPingWire>(
            br#"{"build_version":"v53.0","version":"53.0","pid":4243,"features":[],"extra":true}"#
        )
        .is_err());
    }

    #[test]
    fn v53_vm_info_closes_memory_zone_cid_tap_and_ordered_devices() {
        let expected = expectation();
        let info = serde_json::from_slice::<VmInfoWire>(&exact_vm_info()).unwrap();
        assert!(info.exact(&expected).is_some());

        let mut wrong = serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        wrong["config"]["vsock"]["cid"] = serde_json::json!(4);
        assert!(serde_json::from_value::<VmInfoWire>(wrong)
            .unwrap()
            .exact(&expected)
            .is_none());

        let mut wrong_serial =
            serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        wrong_serial["config"]["disks"][0]["serial"] = serde_json::json!("foreign-root");
        assert!(serde_json::from_value::<VmInfoWire>(wrong_serial)
            .unwrap()
            .exact(&expected)
            .is_none());

        let mut missing_serial =
            serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        missing_serial["config"]["disks"][0]
            .as_object_mut()
            .unwrap()
            .remove("serial");
        assert!(serde_json::from_value::<VmInfoWire>(missing_serial)
            .unwrap()
            .exact(&expected)
            .is_none());
    }

    #[test]
    fn v53_vm_info_preserves_running_vs_paused_as_physical_evidence() {
        let expected = expectation();
        let running = serde_json::from_slice::<VmInfoWire>(&exact_vm_info())
            .unwrap()
            .exact(&expected)
            .unwrap();
        assert_eq!(running.state, ProcessState::Running);

        let mut paused = serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        paused["state"] = serde_json::json!("Paused");
        let paused = serde_json::from_value::<VmInfoWire>(paused)
            .unwrap()
            .exact(&expected)
            .unwrap();
        assert_eq!(paused.state, ProcessState::Paused);

        let mut created = serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        created["state"] = serde_json::json!("Created");
        assert!(serde_json::from_value::<VmInfoWire>(created)
            .unwrap()
            .exact(&expected)
            .is_none());
    }

    #[test]
    fn v53_vm_info_rejects_extra_device_families_and_unknown_device_fields() {
        let expected = expectation();
        let mut extra_family =
            serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        extra_family["config"]["fs"] = serde_json::json!([{"tag":"foreign"}]);
        assert!(serde_json::from_value::<VmInfoWire>(extra_family)
            .unwrap()
            .exact(&expected)
            .is_none());

        let mut extra_field =
            serde_json::from_slice::<serde_json::Value>(&exact_vm_info()).unwrap();
        extra_field["config"]["disks"][0]["foreign"] = serde_json::json!(true);
        assert!(serde_json::from_value::<VmInfoWire>(extra_field).is_err());
    }

    #[test]
    fn response_and_ping_bounds_are_hard() {
        assert_eq!(MAX_HTTP_HEADER_BYTES, 64 * 1024);
        assert_eq!(MAX_HTTP_BODY_BYTES, 2 * 1024 * 1024);
        let oversized = serde_json::json!({
            "build_version": "v53.0",
            "version": "x".repeat(MAX_PING_TEXT_BYTES + 1),
            "pid": 4242,
            "features": []
        });
        assert!(serde_json::from_value::<VmmPingWire>(oversized)
            .unwrap()
            .exact(4242)
            .is_none());
    }

    #[cfg(target_os = "linux")]
    struct TestPhysicalContext {
        deadline: Instant,
    }

    #[cfg(target_os = "linux")]
    impl RuntimePhysicalReadContext for TestPhysicalContext {
        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn check_active(&self) -> anyhow::Result<()> {
            anyhow::ensure!(Instant::now() < self.deadline, "test deadline expired");
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn close_unrelated_fds_after_fork(mut retained: [libc::c_int; 5]) -> bool {
        // This child deliberately waits without exec. Close every descriptor
        // inherited from the parallel Rust test runner so it cannot retain an
        // unrelated checkpoint or attachment flock after that test's parent
        // thread drops its owner. Sorting a fixed stack array does not touch
        // allocator or synchronization state inherited across fork.
        retained.sort_unstable();
        let mut first = 3_u32;
        for descriptor in retained {
            if descriptor < 3 {
                continue;
            }
            let descriptor = descriptor as u32;
            if descriptor < first {
                continue;
            }
            if first < descriptor
                // SAFETY: this is the post-fork child and the retained values
                // above are the only descriptors it needs before `_exit`.
                && unsafe { libc::close_range(first, descriptor - 1, 0) } != 0
            {
                return false;
            }
            first = descriptor.saturating_add(1);
        }
        first == u32::MAX
            // SAFETY: same invariant as the bounded ranges above.
            || unsafe { libc::close_range(first, u32::MAX, 0) } == 0
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd71_and_sole_holder_are_both_required_for_api_identity() {
        // The sole-holder proof inspects foreign process descriptors, which
        // the unprivileged native build-host sandbox cannot do; the Docker
        // and metal root gates execute the full matrix.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: process holder proofs require the root gates");
            return;
        }
        for duplicate_api_holder in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let api_path = temporary.path().join("api.sock");
            let vsock_path = temporary.path().join("vsock.sock");
            let api = UnixListener::bind(&api_path).unwrap();
            let vsock = UnixListener::bind(&vsock_path).unwrap();
            std::fs::set_permissions(&api_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&vsock_path, std::fs::Permissions::from_mode(0o700)).unwrap();

            let mut ready = [0_i32; 2];
            let mut stop = [0_i32; 2];
            assert_eq!(
                // SAFETY: the array provides storage for exactly two fresh pipe
                // descriptors. Each endpoint is transferred or closed once below.
                unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            assert_eq!(
                // SAFETY: same invariant as the ready pipe.
                unsafe { libc::pipe2(stop.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            // SAFETY: the child branch uses only inherited descriptors and
            // async-signal-safe syscalls, then exits without running Rust
            // destructors. The parent owns normal Rust cleanup.
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                // SAFETY: these are the unused inherited pipe endpoints.
                unsafe {
                    libc::close(ready[0]);
                    libc::close(stop[1]);
                }
                let api_source = api.as_raw_fd();
                if api_source != VMM_API_LISTENER_FD
                    // SAFETY: dup3 atomically installs the inherited listener
                    // at the frozen provider-private descriptor number.
                    && unsafe { libc::dup3(api_source, VMM_API_LISTENER_FD, 0) } < 0
                {
                    // SAFETY: the child cannot safely unwind after fork.
                    unsafe { libc::_exit(91) };
                }
                if api_source != VMM_API_LISTENER_FD {
                    // SAFETY: fd71 now owns the only required API reference.
                    unsafe { libc::close(api_source) };
                }
                let duplicate_holder = if duplicate_api_holder {
                    // SAFETY: this intentionally creates a second holder for
                    // the negative half of the test.
                    let descriptor =
                        unsafe { libc::fcntl(VMM_API_LISTENER_FD, libc::F_DUPFD_CLOEXEC, 100) };
                    if descriptor < 0 {
                        // SAFETY: the child cannot safely unwind after fork.
                        unsafe { libc::_exit(92) };
                    }
                    descriptor
                } else {
                    -1
                };
                // SAFETY: the fixed stack-only helper retains exactly the two
                // socket holders, the synchronization pipes, fd71 and the
                // intentional negative duplicate while closing inherited
                // test-runner state before the child announces readiness.
                if !unsafe {
                    close_unrelated_fds_after_fork([
                        VMM_API_LISTENER_FD,
                        vsock.as_raw_fd(),
                        ready[1],
                        stop[0],
                        duplicate_holder,
                    ])
                } {
                    // SAFETY: the child cannot safely unwind after fork.
                    unsafe { libc::_exit(94) };
                }
                let byte = [1_u8];
                // SAFETY: the pipe endpoints and one-byte buffers are valid.
                if unsafe { libc::write(ready[1], byte.as_ptr().cast(), 1) } != 1 {
                    // SAFETY: the child cannot safely unwind after fork.
                    unsafe { libc::_exit(93) };
                }
                let mut command = [0_u8];
                // SAFETY: block until the parent completes the bounded scan.
                let _ = unsafe { libc::read(stop[0], command.as_mut_ptr().cast(), 1) };
                // SAFETY: the child must exit without running inherited Rust
                // destructors after fork.
                unsafe { libc::_exit(0) };
            }

            // SAFETY: these are the unused parent endpoints.
            unsafe {
                libc::close(ready[1]);
                libc::close(stop[0]);
            }
            drop(api);
            drop(vsock);
            // SAFETY: ownership of the two retained parent pipe endpoints is
            // transferred exactly once to File.
            let mut ready_reader = unsafe { File::from_raw_fd(ready[0]) };
            // SAFETY: this is the other retained parent endpoint and is
            // transferred exactly once to File.
            let stop_writer = unsafe { File::from_raw_fd(stop[1]) };
            let mut byte = [0_u8];
            ready_reader.read_exact(&mut byte).unwrap();

            let context = TestPhysicalContext {
                deadline: Instant::now() + Duration::from_secs(5),
            };
            let inspection = linux::inspect_listener_pair(
                &HostPath::new(vsock_path.to_string_lossy().into_owned()).unwrap(),
                child as u32,
                &context,
            )
            .unwrap();

            assert_eq!(
                // SAFETY: the descriptor and one-byte buffer are valid; this
                // write releases the exact child.
                unsafe { libc::write(stop_writer.as_raw_fd(), byte.as_ptr().cast(), 1) },
                1
            );
            let mut status = 0_i32;
            assert_eq!(
                // SAFETY: `child` is the exact live fork result and `status`
                // is writable for the complete waitpid call.
                unsafe { libc::waitpid(child, &raw mut status, 0) },
                child
            );
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);

            if duplicate_api_holder {
                assert!(matches!(inspection, linux::PairInspection::Conflict));
            } else {
                assert!(matches!(inspection, linux::PairInspection::Exact(_)));
            }
        }
    }
}

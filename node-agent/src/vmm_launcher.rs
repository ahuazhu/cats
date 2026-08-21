//! Closed process boundary used to exec one journaled Cloud Hypervisor launch.
//!
//! The lifecycle executor first fsyncs one [`AtomicVmmLaunchSpec`]. A transient
//! Cat-scoped service then passes that exact spec plus the installed VMM/boot
//! artifacts as named descriptors. The launcher validates every descriptor,
//! creates attempt-owned sockets/RAM/logs with no-replace semantics, clears its
//! inherited environment and finally replaces itself with Cloud Hypervisor.
//! It has no access to lifecycle Desired state or a second reconciliation
//! ledger, so it cannot invent or refresh launch authority after the journal
//! step has become durable.

use std::ffi::OsString;
use std::path::Path;

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    AcquireOrigin, ContractVersion, DiskKind, Durability, GuestDeviceIdentity, HostPath, Id,
    PrepareDeviceFrontend, PreparedDeviceInput, RandomId128, RuntimeLaunchArtifact,
    RuntimeLaunchIdentity, RuntimeNetworkIdentity, Sha256Digest, VmmBootProvenance,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::ch::{file_disk_arg_with_serial, vhost_user_disk_arg_with_serial};

pub const VMM_LAUNCHER_CONTRACT_ARGUMENT: &str = "--contract-version=1";
pub const VMM_PROCESS_TOKEN_ENVIRONMENT: &str = "CATS_VMM_PROCESS_IDENTITY_TOKEN";
pub const RUNTIME_INCARNATION_ENVIRONMENT: &str = "CATS_RUNTIME_INCARNATION";
pub const ATOMIC_VMM_LAUNCH_SPEC_FD_NAME: &str = "cats-atomic-vmm-launch-spec-v1";

const ATOMIC_VMM_LAUNCH_SPEC_DOMAIN: &[u8] = b"cats.atomic-lifecycle.vmm-launch-spec.v1";
const ATOMIC_VMM_LAUNCH_SPEC_MAX_BYTES: usize = 128 * 1024;
const ATOMIC_VMM_LAUNCH_SPEC_VERSION: ContractVersion = ContractVersion::V1;
const INSTALLED_VMM_SOCKET_ROOT: &str = "/run/cats/vmm-v1";
const INSTALLED_VMM_LAUNCH_NAMESPACE: &str = "vmm-launch-v1";

/// Provider-private Cloud Hypervisor API listener descriptor.  It is outside
/// systemd's activation range and the frozen artifact/RAM/log descriptor set.
/// The VMM inspector treats `/proc/<MainPID>/fd/71` as part of exact process
/// identity; this number is not a Runtime wire field.
pub const VMM_API_LISTENER_FD: i32 = 71;

const MIB: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const VMM_FD_NAME: &str = "cats-vmm-v1";
#[cfg(target_os = "linux")]
const KERNEL_FD_NAME: &str = "cats-kernel-v1";
#[cfg(target_os = "linux")]
const INITRAMFS_FD_NAME: &str = "cats-initramfs-v1";

// These are deliberately outside systemd's activation range.  They are part
// of the provider-private V1 launch/inspection contract, not wire fields.
#[cfg(target_os = "linux")]
const ATOMIC_VMM_LAUNCH_SPEC_FD: i32 = 64;
#[cfg(target_os = "linux")]
const VMM_FD: i32 = 65;
const KERNEL_FD: i32 = 66;
const INITRAMFS_FD: i32 = 67;
const MEMORY_FD: i32 = 68;
const SERIAL_LOG_FD: i32 = 69;
#[cfg(target_os = "linux")]
const VMM_LOG_FD: i32 = 70;

/// Exact identity of a retained Warm memory backing. The Warm terminal bundle
/// records this proof before the old VMM exits; Start must carry it unchanged
/// into the durable launch spec before the launcher may reopen the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVmmMemoryFileIdentity {
    pub path: HostPath,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub content_sha256: Sha256Digest,
}

/// Snapshot-visible identity of one disk in the retained Warm VMM.
///
/// A same-Node Warm Start may launch replacement blockd processes under new
/// process identities, but it may not change the disk lineage, Guest slot,
/// frontend endpoint, or frontend ownership token encoded in the Cloud
/// Hypervisor snapshot. Keeping that projection separate from
/// [`PreparedDeviceInput`] makes the intentionally replaceable serving
/// process/authorization receipts and the post-snapshot authority head
/// explicit omissions. The latter may advance while Warm drains `L` to `R`;
/// its exact current value is checked by the separate Volume authority path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVmmWarmRestoreDeviceIdentity {
    volume_intent_id: Id,
    disk_id: Id,
    volume_id: Id,
    disk_kind: DiskKind,
    attachment_id: Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    acquire_origin: AcquireOrigin,
    size_bytes: u64,
    durability: Durability,
    guest_device: GuestDeviceIdentity,
    ownership_token: RandomId128,
    frontend: PrepareDeviceFrontend,
}

impl From<&PreparedDeviceInput> for AtomicVmmWarmRestoreDeviceIdentity {
    fn from(device: &PreparedDeviceInput) -> Self {
        Self {
            volume_intent_id: device.volume_intent_id.clone(),
            disk_id: device.disk_id.clone(),
            volume_id: device.volume_id.clone(),
            disk_kind: device.disk_kind,
            attachment_id: device.attachment_id.clone(),
            attachment_epoch: device.attachment_epoch,
            acquire_origin: device.acquire_origin.clone(),
            size_bytes: device.size_bytes,
            durability: device.durability,
            guest_device: device.guest_device.clone(),
            ownership_token: device.ownership_token.clone(),
            frontend: device.frontend.clone(),
        }
    }
}

/// Exact immutable launch configuration captured by a retained Warm source.
///
/// Cloud Hypervisor's restore command does not repeat the normal boot/device
/// CLI. The launcher therefore carries this source projection in the durable
/// spec and compares the newly attributed runtime against it before opening
/// any socket or file. A conflict is an error in `WarmRestore`; callers must
/// not retry it as [`AtomicVmmLaunchMode::Fresh`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVmmWarmRestoreSourceIdentity {
    source_runtime_incarnation: RandomId128,
    boot: Box<VmmBootProvenance>,
    vcpus: u32,
    memory_bytes: u64,
    boot_image_digest: Sha256Digest,
    guest_config_digest: Sha256Digest,
    vsock_socket_path: HostPath,
    guest_cid: u32,
    memory_file_path: HostPath,
    network: Box<RuntimeNetworkIdentity>,
    devices: Vec<AtomicVmmWarmRestoreDeviceIdentity>,
}

impl AtomicVmmWarmRestoreSourceIdentity {
    /// Freeze the snapshot-visible projection of an already descriptor-
    /// verified installed runtime. The returned identity is carried into the
    /// journaled launch spec; validation later compares every member against
    /// the requested restored runtime.
    pub fn from_launch(source: &RuntimeLaunchIdentity) -> Self {
        Self {
            source_runtime_incarnation: source.runtime_incarnation.clone(),
            boot: source.boot.clone(),
            vcpus: source.vcpus,
            memory_bytes: source.memory_bytes,
            boot_image_digest: source.boot_image_digest.clone(),
            guest_config_digest: source.guest_config_digest.clone(),
            vsock_socket_path: source.vsock_socket_path.clone(),
            guest_cid: source.guest_cid,
            memory_file_path: source.memory_file_path.clone(),
            network: source.network.clone(),
            devices: source
                .devices
                .iter()
                .map(AtomicVmmWarmRestoreDeviceIdentity::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicVmmLaunchMode {
    Fresh,
    WarmRestore {
        snapshot_directory: HostPath,
        memory_file: AtomicVmmMemoryFileIdentity,
        source: Box<AtomicVmmWarmRestoreSourceIdentity>,
    },
}

/// The only production launch authority accepted by `cats-vmm-launcher`.
/// Every field is chosen by the side-effect-free Start planner and the full
/// canonical bytes are fsynced in the sole lifecycle journal before systemd
/// submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVmmLaunchSpec {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cat_id: Id,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub platform_plan_digest: Sha256Digest,
    pub state_directory: HostPath,
    pub launch: Box<RuntimeLaunchIdentity>,
    pub mode: AtomicVmmLaunchMode,
    pub spec_digest: Sha256Digest,
}

impl AtomicVmmLaunchSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: Id,
        cat_id: Id,
        operation_id: Id,
        request_fingerprint: Sha256Digest,
        platform_plan_digest: Sha256Digest,
        state_directory: HostPath,
        launch: RuntimeLaunchIdentity,
        mode: AtomicVmmLaunchMode,
    ) -> Result<Self> {
        let mut spec = Self {
            version: ATOMIC_VMM_LAUNCH_SPEC_VERSION,
            node_id,
            cat_id,
            operation_id,
            request_fingerprint,
            platform_plan_digest,
            state_directory,
            launch: Box::new(launch),
            mode,
            spec_digest: zero_digest(),
        };
        spec.spec_digest = atomic_vmm_launch_spec_digest(&spec)?;
        validate_atomic_vmm_launch_spec(&spec)?;
        Ok(spec)
    }
}

pub fn encode_atomic_vmm_launch_spec(spec: &AtomicVmmLaunchSpec) -> Result<Vec<u8>> {
    validate_atomic_vmm_launch_spec(spec)?;
    let bytes = serde_json::to_vec(spec).context("encode atomic VMM launch spec")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= ATOMIC_VMM_LAUNCH_SPEC_MAX_BYTES,
        "atomic VMM launch spec exceeds its wire bound"
    );
    Ok(bytes)
}

pub fn decode_atomic_vmm_launch_spec(bytes: &[u8]) -> Result<AtomicVmmLaunchSpec> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= ATOMIC_VMM_LAUNCH_SPEC_MAX_BYTES,
        "atomic VMM launch spec has an invalid wire length"
    );
    let spec: AtomicVmmLaunchSpec =
        serde_json::from_slice(bytes).context("decode atomic VMM launch spec")?;
    anyhow::ensure!(
        serde_json::to_vec(&spec)? == bytes,
        "atomic VMM launch spec is not canonical JSON"
    );
    validate_atomic_vmm_launch_spec(&spec)?;
    Ok(spec)
}

fn validate_atomic_vmm_launch_spec(spec: &AtomicVmmLaunchSpec) -> Result<()> {
    let launch = spec.launch.as_ref();
    let state_directory = Path::new(spec.state_directory.as_str());
    let expected_launch_root = state_directory
        .join(INSTALLED_VMM_LAUNCH_NAMESPACE)
        .join(format!("p-{}", launch.runtime_incarnation.as_str()));
    let expected_socket_root = Path::new(INSTALLED_VMM_SOCKET_ROOT)
        .join(format!("p-{}", launch.runtime_incarnation.as_str()));
    anyhow::ensure!(
        spec.version == ATOMIC_VMM_LAUNCH_SPEC_VERSION
            && atomic_vmm_launch_spec_digest(spec)? == spec.spec_digest
            && state_directory.is_absolute()
            && Path::new(launch.api_socket_path.as_str()).parent()
                == Some(expected_socket_root.as_path())
            && Path::new(launch.serial_log_path.as_str()).parent()
                == Some(expected_launch_root.as_path())
            && Path::new(launch.vmm_log_path.as_str()).parent()
                == Some(expected_launch_root.as_path()),
        "atomic VMM launch spec changed its installed path or identity binding"
    );
    match &spec.mode {
        AtomicVmmLaunchMode::Fresh => anyhow::ensure!(
            Path::new(launch.vsock_socket_path.as_str()).parent()
                == Some(expected_socket_root.as_path())
                && Path::new(launch.memory_file_path.as_str()).parent()
                    == Some(expected_launch_root.as_path()),
            "fresh atomic VMM socket or memory path escaped its launch namespace"
        ),
        AtomicVmmLaunchMode::WarmRestore {
            snapshot_directory,
            memory_file,
            source,
        } => validate_warm_restore_binding(
            state_directory,
            launch,
            snapshot_directory,
            memory_file,
            source,
        )?,
    }
    let _ = cloud_hypervisor_arguments_for_launch(launch, &spec.mode)?;
    Ok(())
}

fn validate_warm_restore_binding(
    state_directory: &Path,
    launch: &RuntimeLaunchIdentity,
    snapshot_directory: &HostPath,
    memory_file: &AtomicVmmMemoryFileIdentity,
    source: &AtomicVmmWarmRestoreSourceIdentity,
) -> Result<()> {
    let expected_source_launch_root = state_directory
        .join(INSTALLED_VMM_LAUNCH_NAMESPACE)
        .join(format!("p-{}", source.source_runtime_incarnation.as_str()));
    let expected_source_socket_root = Path::new(INSTALLED_VMM_SOCKET_ROOT)
        .join(format!("p-{}", source.source_runtime_incarnation.as_str()));
    let restored_devices = launch
        .devices
        .iter()
        .map(AtomicVmmWarmRestoreDeviceIdentity::from)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        Path::new(snapshot_directory.as_str()).is_absolute()
            && Path::new(snapshot_directory.as_str()).starts_with(state_directory)
            && Path::new(snapshot_directory.as_str()) != state_directory
            && launch.runtime_incarnation != source.source_runtime_incarnation
            && launch.boot == source.boot
            && launch.vcpus == source.vcpus
            && launch.memory_bytes == source.memory_bytes
            && launch.boot_image_digest == source.boot_image_digest
            && launch.guest_config_digest == source.guest_config_digest
            && launch.vsock_socket_path == source.vsock_socket_path
            && launch.guest_cid == source.guest_cid
            && launch.memory_file_path == source.memory_file_path
            && launch.network == source.network
            && restored_devices == source.devices
            && Path::new(source.vsock_socket_path.as_str()).parent()
                == Some(expected_source_socket_root.as_path())
            && Path::new(source.memory_file_path.as_str()).parent()
                == Some(expected_source_launch_root.as_path())
            && memory_file.path == source.memory_file_path
            && memory_file.path == launch.memory_file_path
            && memory_file.length == source.memory_bytes
            && memory_file.length == launch.memory_bytes
            && memory_file.device > 0
            && memory_file.inode > 0,
        "Warm atomic VMM restore changed its exact source, snapshot, or transferred memory proof"
    );
    Ok(())
}

fn atomic_vmm_launch_spec_digest(spec: &AtomicVmmLaunchSpec) -> Result<Sha256Digest> {
    let mut preimage = spec.clone();
    preimage.spec_digest = zero_digest();
    let bytes = serde_json::to_vec(&preimage).context("encode atomic VMM launch digest")?;
    let mut hasher = Sha256::new();
    hasher.update(ATOMIC_VMM_LAUNCH_SPEC_DOMAIN);
    hasher.update([0]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn zero_digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0; 32])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmLauncherPlan {
    spec: AtomicVmmLaunchSpec,
    cloud_hypervisor_arguments: Vec<OsString>,
}

impl VmmLauncherPlan {
    pub fn from_spec(spec: AtomicVmmLaunchSpec) -> Result<Self> {
        validate_atomic_vmm_launch_spec(&spec)?;
        let cloud_hypervisor_arguments =
            cloud_hypervisor_arguments_for_launch(&spec.launch, &spec.mode)?;
        Ok(Self {
            spec,
            cloud_hypervisor_arguments,
        })
    }

    pub fn spec(&self) -> &AtomicVmmLaunchSpec {
        &self.spec
    }

    pub fn cloud_hypervisor_arguments(&self) -> &[OsString] {
        &self.cloud_hypervisor_arguments
    }

    pub fn vmm_executable(&self) -> &RuntimeLaunchArtifact {
        &self.spec.launch.boot.vmm_executable
    }
}

pub(crate) fn cloud_hypervisor_arguments_for_launch(
    launch: &RuntimeLaunchIdentity,
    mode: &AtomicVmmLaunchMode,
) -> Result<Vec<OsString>> {
    let RuntimeLaunchIdentity {
        boot,
        process_identity_token,
        vcpus,
        memory_bytes,
        vsock_socket_path,
        guest_cid,
        memory_file_path,
        serial_log_path,
        vmm_log_path,
        network,
        devices,
        ..
    } = launch;
    anyhow::ensure!(
        *vcpus > 0,
        "StartRuntime VMM launch requires at least one vCPU"
    );
    anyhow::ensure!(
        *memory_bytes >= 128 * MIB && *memory_bytes % MIB == 0,
        "StartRuntime memory must be at least 128 MiB and MiB-aligned"
    );
    anyhow::ensure!(
        (3..=u32::MAX - 1).contains(guest_cid),
        "StartRuntime Guest CID is outside the allocatable range"
    );
    anyhow::ensure!(
        !vsock_socket_path.as_str().contains(','),
        "vsock socket path contains a Cloud Hypervisor separator"
    );
    let launch_file_paths = [
        Path::new(memory_file_path.as_str()),
        Path::new(serial_log_path.as_str()),
        Path::new(vmm_log_path.as_str()),
    ];
    anyhow::ensure!(
        launch_file_parents_are_equal_or_disjoint(&launch_file_paths),
        "VMM launch file parents are nested"
    );

    let mut arguments = vec![
        OsString::from("--api-socket"),
        OsString::from(format!("fd={VMM_API_LISTENER_FD}")),
    ];
    if let AtomicVmmLaunchMode::WarmRestore {
        snapshot_directory, ..
    } = mode
    {
        arguments.push(OsString::from("--restore"));
        arguments.push(OsString::from(format!(
            "source_url=file://{}",
            snapshot_directory.as_str()
        )));
        return Ok(arguments);
    }
    arguments.push(OsString::from("--kernel"));
    arguments.push(fixed_fd_path(KERNEL_FD));
    if boot.initramfs.is_some() {
        arguments.push(OsString::from("--initramfs"));
        arguments.push(fixed_fd_path(INITRAMFS_FD));
    }
    arguments.extend([
        OsString::from("--cmdline"),
        OsString::from(boot.kernel_cmdline.as_str()),
        OsString::from("--cpus"),
        OsString::from(format!("boot={vcpus}")),
        OsString::from("--memory"),
        OsString::from("size=0"),
        OsString::from("--memory-zone"),
        OsString::from(format!(
            "id=cat-ram,size={}M,file={},shared=on",
            memory_bytes / MIB,
            fixed_fd_path(MEMORY_FD).to_string_lossy()
        )),
        OsString::from("--vsock"),
        OsString::from(format!(
            "cid={guest_cid},socket={}",
            vsock_socket_path.as_str()
        )),
        OsString::from("--net"),
        OsString::from(format!(
            "tap={},mac={}",
            network.tap_name.as_str(),
            network.network_config.guest_mac.as_str()
        )),
    ]);
    for device in devices {
        let disk = match &device.frontend {
            PrepareDeviceFrontend::KernelNbd {
                device_path,
                direct,
                ..
            } => {
                anyhow::ensure!(
                    !device_path.as_str().contains(','),
                    "kernel-NBD device path contains a Cloud Hypervisor separator"
                );
                file_disk_arg_with_serial(
                    device_path.as_str(),
                    *direct,
                    device.guest_device.serial.as_str(),
                )?
            }
            PrepareDeviceFrontend::VhostUserBlk {
                socket_path,
                queues,
                queue_size,
            } => vhost_user_disk_arg_with_serial(
                Path::new(socket_path.as_str()),
                usize::from(*queues),
                *queue_size,
                device.guest_device.serial.as_str(),
            )?,
        };
        arguments.push(OsString::from("--disk"));
        arguments.push(OsString::from(disk));
    }
    arguments.extend([
        OsString::from("--serial"),
        OsString::from(format!(
            "file={}",
            fixed_fd_path(SERIAL_LOG_FD).to_string_lossy()
        )),
        OsString::from("--console"),
        OsString::from("off"),
    ]);
    anyhow::ensure!(
        !process_identity_token.as_str().is_empty(),
        "StartRuntime process token is empty"
    );
    Ok(arguments)
}

fn fixed_fd_path(fd: i32) -> OsString {
    OsString::from(format!("/proc/self/fd/{fd}"))
}

fn launch_file_parents_are_equal_or_disjoint(paths: &[&Path]) -> bool {
    for (index, left) in paths.iter().enumerate() {
        let Some(left_parent) = left.parent() else {
            return false;
        };
        for right in &paths[index + 1..] {
            let Some(right_parent) = right.parent() else {
                return false;
            };
            if left_parent != right_parent
                && (left_parent.starts_with(right_parent) || right_parent.starts_with(left_parent))
            {
                return false;
            }
        }
    }
    true
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::ffi::{CStr, CString, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd as _, RawFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::{
        FileExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
    };
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};

    use anyhow::{Context as _, Result};
    use cats_api::runtime_reconciliation::{RuntimeLaunchArtifact, Sha256Digest};
    use sha2::{Digest as _, Sha256};

    use super::{
        decode_atomic_vmm_launch_spec, fixed_fd_path, AtomicVmmLaunchMode,
        AtomicVmmMemoryFileIdentity, VmmLauncherPlan, ATOMIC_VMM_LAUNCH_SPEC_FD,
        ATOMIC_VMM_LAUNCH_SPEC_FD_NAME, ATOMIC_VMM_LAUNCH_SPEC_MAX_BYTES, INITRAMFS_FD,
        INITRAMFS_FD_NAME, KERNEL_FD, KERNEL_FD_NAME, MEMORY_FD, RUNTIME_INCARNATION_ENVIRONMENT,
        SERIAL_LOG_FD, VMM_API_LISTENER_FD, VMM_FD, VMM_FD_NAME, VMM_LOG_FD,
        VMM_PROCESS_TOKEN_ENVIRONMENT,
    };

    const HASH_BUFFER_BYTES: usize = 1024 * 1024;

    pub(super) fn run() -> Result<()> {
        let mut arguments = std::env::args_os();
        let _program = arguments.next().context("VMM launcher argv is empty")?;
        anyhow::ensure!(
            arguments.next().as_deref()
                == Some(std::ffi::OsStr::new(super::VMM_LAUNCHER_CONTRACT_ARGUMENT))
                && arguments.next().is_none(),
            "VMM launcher requires the exact V1 contract argument"
        );

        let mut open_files = SystemdOpenFiles::take_from_environment()?;
        let spec_file = open_files.take(ATOMIC_VMM_LAUNCH_SPEC_FD_NAME)?;
        let spec_bytes = read_bounded_launch_spec(&spec_file)?;
        let plan = VmmLauncherPlan::from_spec(decode_atomic_vmm_launch_spec(&spec_bytes)?)?;
        let launch = plan.spec().launch.as_ref();
        let launcher_executable = launch.launcher_executable.as_ref();
        let boot = launch.boot.as_ref();
        let runtime_incarnation = &launch.runtime_incarnation;
        let process_identity_token = &launch.process_identity_token;
        let memory_bytes = launch.memory_bytes;
        let api_socket_path = &launch.api_socket_path;
        let vsock_socket_path = &launch.vsock_socket_path;
        let memory_file_path = &launch.memory_file_path;
        let serial_log_path = &launch.serial_log_path;
        let vmm_log_path = &launch.vmm_log_path;

        validate_bound_environment(
            runtime_incarnation.as_str(),
            process_identity_token.as_str(),
        )?;
        validate_current_executable(launcher_executable)?;
        let vmm = open_files.take(VMM_FD_NAME)?;
        validate_artifact(&vmm, &boot.vmm_executable, 0o755)?;
        let kernel = open_files.take(KERNEL_FD_NAME)?;
        validate_artifact(&kernel, &boot.kernel, 0o644)?;
        let initramfs = match &boot.initramfs {
            Some(expected) => {
                let file = open_files.take(INITRAMFS_FD_NAME)?;
                validate_artifact(&file, expected, 0o644)?;
                Some(file)
            }
            None => None,
        };
        open_files.ensure_empty()?;

        let api_listener = OwnedApiListener::bind(Path::new(api_socket_path.as_str()))?;
        let vsock_parent = CheckedParent::open(Path::new(vsock_socket_path.as_str()))?;
        vsock_parent.ensure_absent()?;
        let (memory, serial_log, vmm_log) = match &plan.spec().mode {
            AtomicVmmLaunchMode::Fresh => {
                let [memory, serial_log, vmm_log] = OwnedLaunchFile::create_batch([
                    (Path::new(memory_file_path.as_str()), memory_bytes),
                    (Path::new(serial_log_path.as_str()), 0),
                    (Path::new(vmm_log_path.as_str()), 0),
                ])?;
                (LaunchMemoryFile::Fresh(memory), serial_log, vmm_log)
            }
            AtomicVmmLaunchMode::WarmRestore { memory_file, .. } => {
                let [serial_log, vmm_log] = OwnedLaunchFile::create_batch([
                    (Path::new(serial_log_path.as_str()), 0),
                    (Path::new(vmm_log_path.as_str()), 0),
                ])?;
                (
                    LaunchMemoryFile::Warm(RetainedWarmMemoryFile::open(memory_file)?),
                    serial_log,
                    vmm_log,
                )
            }
        };

        // Close replacement and late-socket windows after all exclusive files
        // exist but before the process boundary linearizes at exec.
        validate_current_executable(launcher_executable)?;
        validate_artifact(&vmm, &boot.vmm_executable, 0o755)?;
        validate_artifact(&kernel, &boot.kernel, 0o644)?;
        if let (Some(file), Some(expected)) = (&initramfs, &boot.initramfs) {
            validate_artifact(file, expected, 0o644)?;
        }
        api_listener.assert_current()?;
        vsock_parent.assert_current_and_absent()?;
        memory.assert_current()?;
        serial_log.assert_current(0)?;
        vmm_log.assert_current(0)?;

        install_fixed_fd(&spec_file, ATOMIC_VMM_LAUNCH_SPEC_FD)?;
        install_fixed_fd(&vmm, VMM_FD)?;
        install_fixed_fd(&kernel, KERNEL_FD)?;
        if let Some(initramfs) = &initramfs {
            install_fixed_fd(initramfs, INITRAMFS_FD)?;
        }
        install_fixed_fd(memory.file(), MEMORY_FD)?;
        install_fixed_fd(&serial_log.file, SERIAL_LOG_FD)?;
        install_fixed_fd(&vmm_log.file, VMM_LOG_FD)?;
        install_fixed_fd(api_listener.listener(), VMM_API_LISTENER_FD)?;

        let stderr_fd = duplicate_fd(VMM_LOG_FD)?;
        // SAFETY: `duplicate_fd` returned a new descriptor owned by this File.
        let stderr = unsafe { File::from_raw_fd(stderr_fd) };
        let mut command = Command::new(fixed_fd_path(VMM_FD));
        command
            .arg0(OsString::from(plan.vmm_executable().path.as_str()))
            .args(plan.cloud_hypervisor_arguments())
            .env_clear()
            .env(
                VMM_PROCESS_TOKEN_ENVIRONMENT,
                process_identity_token.as_str(),
            )
            .env(
                RUNTIME_INCARNATION_ENVIRONMENT,
                runtime_incarnation.as_str(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .current_dir("/");
        // Bracket descriptor installation and command construction with one
        // final lexical proof immediately before exec.  The fixed descriptors
        // remain the launch authority, while these checks ensure the
        // journaled canonical paths still name those same files.
        api_listener.assert_current()?;
        vsock_parent.assert_current_and_absent()?;
        memory.assert_current()?;
        serial_log.assert_current(0)?;
        vmm_log.assert_current(0)?;
        let error = command.exec();
        Err(error).context("exec exact Cloud Hypervisor descriptor")
    }

    struct SystemdOpenFiles {
        files: BTreeMap<String, File>,
    }

    impl SystemdOpenFiles {
        fn take_from_environment() -> Result<Self> {
            let current_pid = std::process::id();
            let listen_pid = std::env::var("LISTEN_PID")
                .context("systemd did not pass LISTEN_PID")?
                .parse::<u32>()
                .context("LISTEN_PID is not a u32")?;
            anyhow::ensure!(listen_pid == current_pid, "LISTEN_PID is not this launcher");
            let count = std::env::var("LISTEN_FDS")
                .context("systemd did not pass LISTEN_FDS")?
                .parse::<usize>()
                .context("LISTEN_FDS is not a usize")?;
            anyhow::ensure!(
                (3..=4).contains(&count),
                "unexpected systemd open-file count"
            );
            let names = std::env::var("LISTEN_FDNAMES")
                .context("systemd did not pass LISTEN_FDNAMES")?
                .split(':')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                names.len() == count,
                "systemd open-file names do not match FDs"
            );
            let mut files = BTreeMap::new();
            for (offset, name) in names.into_iter().enumerate() {
                anyhow::ensure!(!name.is_empty(), "systemd passed an empty FD name");
                let fd = 3_i32
                    .checked_add(i32::try_from(offset).context("activation FD offset overflow")?)
                    .context("activation FD overflow")?;
                // SAFETY: systemd transfers ownership of LISTEN_FDS descriptors
                // beginning at 3 to this process exactly once.
                let file = unsafe { File::from_raw_fd(fd) };
                set_close_on_exec(&file)?;
                anyhow::ensure!(
                    files.insert(name, file).is_none(),
                    "duplicate systemd FD name"
                );
            }
            Ok(Self { files })
        }

        fn take(&mut self, name: &str) -> Result<File> {
            self.files
                .remove(name)
                .with_context(|| format!("systemd did not pass {name}"))
        }

        fn ensure_empty(&self) -> Result<()> {
            anyhow::ensure!(self.files.is_empty(), "systemd passed an unknown open file");
            Ok(())
        }
    }

    fn set_close_on_exec(file: &File) -> Result<()> {
        // SAFETY: F_GETFD only reads flags from this live owned descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error())
                .context("read systemd open-file descriptor flags");
        }
        // SAFETY: F_SETFD changes only the flags of this live owned
        // descriptor.  The fixed 64+ launch descriptors are installed later
        // without CLOEXEC; these original activation descriptors must not
        // leak through the launcher-to-VMM exec.
        let result =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if result < 0 {
            Err(io::Error::last_os_error()).context("set CLOEXEC on systemd open-file descriptor")
        } else {
            Ok(())
        }
    }

    fn read_bounded_launch_spec(file: &File) -> Result<Vec<u8>> {
        let metadata = file.metadata().context("stat atomic VMM launch spec FD")?;
        ensure_regular_root_file(&metadata, 0o600)?;
        let length = usize::try_from(metadata.len()).context("launch spec length exceeds usize")?;
        anyhow::ensure!(
            (1..=ATOMIC_VMM_LAUNCH_SPEC_MAX_BYTES).contains(&length),
            "atomic VMM launch spec length is outside the wire bound"
        );
        let mut bytes = vec![0_u8; length];
        read_exact_at(file, &mut bytes)?;
        let mut extra = [0_u8; 1];
        anyhow::ensure!(
            file.read_at(&mut extra, length as u64)
                .context("probe atomic VMM launch spec EOF")?
                == 0,
            "atomic VMM launch spec grew while it was read"
        );
        let after = file
            .metadata()
            .context("re-stat atomic VMM launch spec FD")?;
        anyhow::ensure!(
            same_stable_file(&metadata, &after),
            "atomic VMM launch spec changed"
        );
        Ok(bytes)
    }

    fn validate_bound_environment(incarnation: &str, token: &str) -> Result<()> {
        anyhow::ensure!(
            std::env::var(RUNTIME_INCARNATION_ENVIRONMENT).as_deref() == Ok(incarnation),
            "launcher incarnation environment is not checkpoint-exact"
        );
        anyhow::ensure!(
            std::env::var(VMM_PROCESS_TOKEN_ENVIRONMENT).as_deref() == Ok(token),
            "launcher process-token environment is not checkpoint-exact"
        );
        for (name, _) in std::env::vars_os() {
            if let Some(name) = name.to_str() {
                anyhow::ensure!(
                    !name.starts_with("CATS_")
                        || name == RUNTIME_INCARNATION_ENVIRONMENT
                        || name == VMM_PROCESS_TOKEN_ENVIRONMENT,
                    "launcher inherited an unexpected CATS environment variable"
                );
            }
        }
        Ok(())
    }

    fn validate_current_executable(expected: &RuntimeLaunchArtifact) -> Result<()> {
        let current = std::fs::read_link("/proc/self/exe").context("read launcher executable")?;
        anyhow::ensure!(
            current == Path::new(expected.path.as_str()),
            "launcher executable pathname is not checkpoint-exact"
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")
            .context("open launcher executable")?;
        validate_artifact(&file, expected, 0o755)
    }

    fn validate_artifact(file: &File, expected: &RuntimeLaunchArtifact, mode: u32) -> Result<()> {
        let metadata = file.metadata().context("stat VMM launch artifact FD")?;
        ensure_regular_root_file(&metadata, mode)?;
        anyhow::ensure!(
            metadata.len() == expected.length.get(),
            "VMM launch artifact length changed"
        );
        let digest = hash_exact(file, metadata.len())?;
        anyhow::ensure!(
            digest == expected.content_sha256,
            "VMM launch artifact digest changed"
        );
        let after = file.metadata().context("re-stat VMM launch artifact FD")?;
        anyhow::ensure!(
            same_stable_file(&metadata, &after),
            "VMM launch artifact changed"
        );
        Ok(())
    }

    fn hash_exact(file: &File, length: u64) -> Result<Sha256Digest> {
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
        while offset < length {
            let remaining = usize::try_from((length - offset).min(HASH_BUFFER_BYTES as u64))
                .context("artifact hash chunk exceeds usize")?;
            let read = file
                .read_at(&mut buffer[..remaining], offset)
                .context("read VMM launch artifact")?;
            anyhow::ensure!(read > 0, "VMM launch artifact ended early");
            hasher.update(&buffer[..read]);
            offset = offset
                .checked_add(read as u64)
                .context("artifact hash offset overflow")?;
        }
        let mut extra = [0_u8; 1];
        anyhow::ensure!(
            file.read_at(&mut extra, length)
                .context("probe VMM launch artifact EOF")?
                == 0,
            "VMM launch artifact grew while it was hashed"
        );
        Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
    }

    fn read_exact_at(file: &File, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let read = file
                .read_at(&mut bytes[offset..], offset as u64)
                .context("read exact launcher checkpoint")?;
            anyhow::ensure!(read > 0, "launcher checkpoint ended early");
            offset = offset
                .checked_add(read)
                .context("checkpoint offset overflow")?;
        }
        Ok(())
    }

    fn ensure_regular_root_file(metadata: &std::fs::Metadata, mode: u32) -> Result<()> {
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "launch FD is not a regular file"
        );
        anyhow::ensure!(metadata.nlink() == 1, "launch FD is not single-link");
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.gid() == 0,
            "launch FD is not root-owned"
        );
        anyhow::ensure!(
            metadata.mode() & 0o7777 == mode,
            "launch FD mode is not exact"
        );
        Ok(())
    }

    fn same_stable_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
            && left.nlink() == right.nlink()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }

    struct CheckedParent {
        path: PathBuf,
        directories: DirectoryChain,
        basename: CString,
    }

    impl CheckedParent {
        fn open(path: &Path) -> Result<Self> {
            anyhow::ensure!(path.is_absolute(), "launch resource path is not absolute");
            let basename = path
                .file_name()
                .context("launch resource path has no basename")?;
            let basename = CString::new(basename.as_bytes())
                .context("launch resource basename contains NUL")?;
            let parent = path
                .parent()
                .context("launch resource path has no parent")?;
            let directories = open_directory_chain(parent)?;
            Ok(Self {
                path: path.to_path_buf(),
                directories,
                basename,
            })
        }

        fn descriptor(&self) -> &File {
            self.directories.leaf()
        }

        fn ensure_absent(&self) -> Result<()> {
            match stat_at(self.descriptor(), &self.basename) {
                Ok(_) => anyhow::bail!("launch resource already exists: {}", self.path.display()),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                Err(error) => Err(error).context("inspect launch resource path"),
            }
        }

        fn assert_current(&self) -> Result<Self> {
            let current = Self::open(&self.path)?;
            anyhow::ensure!(
                self.directories.retained_matches(&current.directories)?,
                "launch resource ancestor chain changed"
            );
            Ok(current)
        }

        fn freeze_after_batch(&self) -> Result<Self> {
            let current = Self::open(&self.path)?;
            anyhow::ensure!(
                self.directories
                    .retained_matches_after_batch(&current.directories)?,
                "launch resource ancestor changed while its file batch was created"
            );
            Ok(current)
        }

        fn assert_current_and_absent(&self) -> Result<()> {
            let current = self.assert_current()?;
            self.ensure_absent()?;
            current.ensure_absent()
        }
    }

    struct OwnedApiListener {
        parent: CheckedParent,
        listener: UnixListener,
        device: u64,
        inode: u64,
    }

    impl OwnedApiListener {
        fn bind(path: &Path) -> Result<Self> {
            let parent = CheckedParent::open(path)?;
            parent.ensure_absent()?;
            // Binding through the retained parent descriptor closes the
            // ancestor-replacement window inherent in a lexical Unix path.
            let descriptor_path = PathBuf::from(format!(
                "/proc/self/fd/{}/{}",
                parent.descriptor().as_raw_fd(),
                parent.basename.to_string_lossy()
            ));
            let listener = UnixListener::bind(&descriptor_path)
                .context("bind exclusive atomic VMM API listener")?;
            // The transient service contract fixes UMask=0077. Validation
            // below rejects a launcher reached through any weaker context.
            let current_parent = parent.freeze_after_batch()?;
            let retained = stat_at(parent.descriptor(), &parent.basename)
                .context("inspect retained atomic VMM API socket")?;
            let current = stat_at(current_parent.descriptor(), &current_parent.basename)
                .context("reopen atomic VMM API socket")?;
            ensure_owned_socket(&retained)?;
            anyhow::ensure!(
                same_stable_file(&retained, &current),
                "atomic VMM API socket pathname changed after bind"
            );
            Ok(Self {
                parent: current_parent,
                listener,
                device: retained.dev(),
                inode: retained.ino(),
            })
        }

        fn listener(&self) -> &UnixListener {
            &self.listener
        }

        fn assert_current(&self) -> Result<()> {
            let retained = stat_at(self.parent.descriptor(), &self.parent.basename)
                .context("reinspect retained atomic VMM API socket")?;
            let current_parent = self.parent.assert_current()?;
            let current = stat_at(current_parent.descriptor(), &current_parent.basename)
                .context("reopen current atomic VMM API socket")?;
            ensure_owned_socket(&retained)?;
            anyhow::ensure!(
                retained.dev() == self.device
                    && retained.ino() == self.inode
                    && same_stable_file(&retained, &current),
                "atomic VMM API socket identity changed"
            );
            Ok(())
        }
    }

    fn ensure_owned_socket(metadata: &std::fs::Metadata) -> Result<()> {
        anyhow::ensure!(
            metadata.file_type().is_socket()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o700,
            "atomic VMM API listener has unsafe type, owner, or mode"
        );
        Ok(())
    }

    struct OwnedLaunchFile {
        parent: CheckedParent,
        file: File,
        device: u64,
        inode: u64,
    }

    impl OwnedLaunchFile {
        #[cfg(test)]
        fn create(path: &Path) -> Result<Self> {
            let [owned] = Self::create_batch([(path, 0)])?;
            Ok(owned)
        }

        fn create_batch<const N: usize>(requests: [(&Path, u64); N]) -> Result<[Self; N]> {
            Self::create_batch_inner(requests, || Ok(()))
        }

        #[cfg(test)]
        fn create_batch_with_before_freeze<const N: usize>(
            requests: [(&Path, u64); N],
            before_freeze: impl FnOnce() -> Result<()>,
        ) -> Result<[Self; N]> {
            Self::create_batch_inner(requests, before_freeze)
        }

        fn create_batch_inner<const N: usize>(
            requests: [(&Path, u64); N],
            before_freeze: impl FnOnce() -> Result<()>,
        ) -> Result<[Self; N]> {
            for (index, (path, _)) in requests.iter().enumerate() {
                anyhow::ensure!(
                    !requests[..index]
                        .iter()
                        .any(|(other_path, _)| other_path == path),
                    "VMM launch file batch contains a duplicate path"
                );
            }
            let request_paths = requests.iter().map(|(path, _)| *path).collect::<Vec<_>>();
            anyhow::ensure!(
                super::launch_file_parents_are_equal_or_disjoint(&request_paths),
                "VMM launch file parents are nested"
            );

            // Resolve every canonical parent and prove every leaf absent before
            // the first no-replace create. The batch's own sibling creates may
            // then update a shared parent, so all parent baselines are frozen
            // only after the complete known set exists.
            let mut prepared = Vec::with_capacity(N);
            for (path, expected_length) in requests {
                let parent = CheckedParent::open(path)?;
                parent.ensure_absent()?;
                prepared.push((parent, expected_length));
            }
            let mut created = Vec::with_capacity(N);
            for (parent, expected_length) in prepared {
                // SAFETY: `parent` is a retained directory descriptor and
                // `basename` is NUL-free. O_EXCL/O_NOFOLLOW prevent replacement
                // or symlink adoption at the leaf.
                let fd = unsafe {
                    libc::openat(
                        parent.descriptor().as_raw_fd(),
                        parent.basename.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error())
                        .context("create exclusive VMM launch file");
                }
                // SAFETY: successful openat returned one newly-owned descriptor.
                let file = unsafe { File::from_raw_fd(fd) };
                file.set_len(expected_length)
                    .context("size exclusive VMM launch file")?;
                let baseline = file.metadata().context("stat exclusive VMM launch file")?;
                ensure_owned_launch_file(&baseline, expected_length)?;
                created.push((parent, file, baseline, expected_length));
            }
            before_freeze()?;

            let mut owned = Vec::with_capacity(N);
            for (parent, file, baseline, _expected_length) in created {
                let current_parent = parent.freeze_after_batch()?;
                let retained_path = stat_at(parent.descriptor(), &parent.basename)
                    .context("reinspect newly-created VMM launch file")?;
                let current_path = stat_at(current_parent.descriptor(), &current_parent.basename)
                    .context("reopen newly-created VMM launch file")?;
                let after = file
                    .metadata()
                    .context("re-stat exclusive VMM launch file")?;
                anyhow::ensure!(
                    same_stable_file(&baseline, &after)
                        && same_stable_file(&baseline, &retained_path)
                        && same_stable_file(&baseline, &current_path),
                    "new VMM launch file pathname or contents changed"
                );
                owned.push(Self {
                    parent: current_parent,
                    file,
                    device: baseline.dev(),
                    inode: baseline.ino(),
                });
            }

            for (file, (_, expected_length)) in owned.iter().zip(requests.iter()) {
                file.assert_current(*expected_length)?;
            }
            owned
                .try_into()
                .map_err(|_| anyhow::anyhow!("VMM launch file batch length changed"))
        }

        fn assert_current(&self, expected_length: u64) -> Result<()> {
            let before = self
                .file
                .metadata()
                .context("stat retained VMM launch file")?;
            ensure_owned_launch_file(&before, expected_length)?;
            anyhow::ensure!(
                before.dev() == self.device && before.ino() == self.inode,
                "retained VMM launch file identity changed"
            );
            let retained_path = stat_at(self.parent.descriptor(), &self.parent.basename)
                .context("reinspect retained VMM launch file path")?;
            let current_parent = self.parent.assert_current()?;
            let current_path = stat_at(current_parent.descriptor(), &current_parent.basename)
                .context("reopen current VMM launch file path")?;
            let after = self
                .file
                .metadata()
                .context("re-stat retained VMM launch file")?;
            anyhow::ensure!(
                same_stable_file(&before, &after)
                    && same_stable_file(&before, &retained_path)
                    && same_stable_file(&before, &current_path),
                "VMM launch file pathname or contents changed"
            );
            Ok(())
        }
    }

    enum LaunchMemoryFile {
        Fresh(OwnedLaunchFile),
        Warm(RetainedWarmMemoryFile),
    }

    impl LaunchMemoryFile {
        fn file(&self) -> &File {
            match self {
                Self::Fresh(file) => &file.file,
                Self::Warm(file) => &file.file,
            }
        }

        fn assert_current(&self) -> Result<()> {
            match self {
                Self::Fresh(file) => {
                    let length = file.file.metadata()?.len();
                    file.assert_current(length)
                }
                Self::Warm(file) => file.assert_current(),
            }
        }
    }

    struct RetainedWarmMemoryFile {
        expected: AtomicVmmMemoryFileIdentity,
        parent: CheckedParent,
        file: File,
    }

    impl RetainedWarmMemoryFile {
        fn open(expected: &AtomicVmmMemoryFileIdentity) -> Result<Self> {
            let parent = CheckedParent::open(Path::new(expected.path.as_str()))?;
            // SAFETY: parent is a retained directory and basename is NUL-free;
            // O_NOFOLLOW prevents adopting a symlink as the transferred RAM.
            let fd = unsafe {
                libc::openat(
                    parent.descriptor().as_raw_fd(),
                    parent.basename.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error())
                    .context("open exact transferred Warm memory file");
            }
            // SAFETY: successful openat returned one newly-owned descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            let retained = Self {
                expected: expected.clone(),
                parent,
                file,
            };
            retained.assert_current()?;
            Ok(retained)
        }

        fn assert_current(&self) -> Result<()> {
            let before = self
                .file
                .metadata()
                .context("stat transferred Warm memory")?;
            ensure_owned_launch_file(&before, self.expected.length)?;
            anyhow::ensure!(
                before.dev() == self.expected.device
                    && before.ino() == self.expected.inode
                    && hash_exact(&self.file, self.expected.length)?
                        == self.expected.content_sha256,
                "transferred Warm memory identity or digest changed"
            );
            let retained_path = stat_at(self.parent.descriptor(), &self.parent.basename)
                .context("reinspect transferred Warm memory pathname")?;
            let current_parent = self.parent.assert_current()?;
            let current_path = stat_at(current_parent.descriptor(), &current_parent.basename)
                .context("reopen transferred Warm memory pathname")?;
            let after = self
                .file
                .metadata()
                .context("re-stat transferred Warm memory")?;
            anyhow::ensure!(
                same_stable_file(&before, &after)
                    && same_stable_file(&before, &retained_path)
                    && same_stable_file(&before, &current_path),
                "transferred Warm memory pathname changed"
            );
            Ok(())
        }
    }

    fn ensure_owned_launch_file(metadata: &std::fs::Metadata, expected_length: u64) -> Result<()> {
        ensure_regular_root_file(metadata, 0o600)?;
        anyhow::ensure!(
            metadata.len() == expected_length,
            "VMM launch file length changed"
        );
        Ok(())
    }

    // Intentionally no Drop unlink: a check-then-unlink cleanup can delete a
    // foreign pathname replacement.  Any failed or ambiguous launch leaves
    // its no-replace file for checkpoint-aware fresh-full recovery.

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    impl DirectoryIdentity {
        fn from(metadata: &std::fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }

        fn same_node_and_policy(&self, other: &Self) -> bool {
            self.device == other.device
                && self.inode == other.inode
                && self.mode == other.mode
                && self.uid == other.uid
                && self.gid == other.gid
                && self.links == other.links
        }
    }

    struct RetainedDirectory {
        descriptor: File,
        identity: DirectoryIdentity,
    }

    struct DirectoryChain {
        directories: Vec<RetainedDirectory>,
    }

    impl DirectoryChain {
        fn leaf(&self) -> &File {
            &self
                .directories
                .last()
                .expect("absolute paths retain at least the root directory")
                .descriptor
        }

        fn retained_matches(&self, current: &Self) -> Result<bool> {
            if self.directories.len() != current.directories.len() {
                return Ok(false);
            }
            let last = self.directories.len().saturating_sub(1);
            for (index, (retained, reopened)) in self
                .directories
                .iter()
                .zip(&current.directories)
                .enumerate()
            {
                let retained_metadata = retained
                    .descriptor
                    .metadata()
                    .context("reinspect retained launch ancestor")?;
                ensure_safe_directory(&retained_metadata)?;
                let retained_current = DirectoryIdentity::from(&retained_metadata);
                // Shared ancestors such as /run and /var/lib legitimately
                // change when another Cat creates a disjoint sibling. Their
                // pathname, inode, owner and policy must remain exact, while
                // only the launch file's private parent is timestamp-frozen to
                // catch move-away/back and unexpected sibling mutations.
                let matches = if index == last {
                    retained_current == retained.identity && retained.identity == reopened.identity
                } else {
                    retained_current.same_node_and_policy(&retained.identity)
                        && retained.identity.same_node_and_policy(&reopened.identity)
                };
                if !matches {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn retained_matches_after_batch(&self, current: &Self) -> Result<bool> {
            if self.directories.len() != current.directories.len() {
                return Ok(false);
            }
            let last = self.directories.len().saturating_sub(1);
            for (index, (retained, reopened)) in self
                .directories
                .iter()
                .zip(&current.directories)
                .enumerate()
            {
                let retained_metadata = retained
                    .descriptor
                    .metadata()
                    .context("reinspect launch ancestor after file batch")?;
                ensure_safe_directory(&retained_metadata)?;
                let retained_current = DirectoryIdentity::from(&retained_metadata);
                if index == last {
                    if !retained_current.same_node_and_policy(&retained.identity)
                        || retained_current != reopened.identity
                    {
                        return Ok(false);
                    }
                } else if !retained_current.same_node_and_policy(&retained.identity)
                    || !retained.identity.same_node_and_policy(&reopened.identity)
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    fn open_directory_chain(path: &Path) -> Result<DirectoryChain> {
        // SAFETY: fixed NUL-terminated path and flags; returned descriptor is
        // immediately owned by File on success.
        let root_fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(io::Error::last_os_error()).context("open launch root directory");
        }
        // SAFETY: successful open returned one owned descriptor.
        let mut current = unsafe { File::from_raw_fd(root_fd) };
        let root_metadata = current.metadata().context("stat launch root directory")?;
        ensure_safe_directory(&root_metadata)?;
        let mut directories = vec![RetainedDirectory {
            descriptor: current,
            identity: DirectoryIdentity::from(&root_metadata),
        }];
        for component in path.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes())
                        .context("launch directory component contains NUL")?;
                    // SAFETY: current is a retained directory, and name is a
                    // checked relative component with no NUL.
                    let fd = unsafe {
                        libc::openat(
                            directories
                                .last()
                                .expect("root is retained")
                                .descriptor
                                .as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error())
                            .context("open launch directory component");
                    }
                    // SAFETY: successful openat returned one owned descriptor.
                    current = unsafe { File::from_raw_fd(fd) };
                    let metadata = current
                        .metadata()
                        .context("stat launch directory component")?;
                    ensure_safe_directory(&metadata)?;
                    directories.push(RetainedDirectory {
                        descriptor: current,
                        identity: DirectoryIdentity::from(&metadata),
                    });
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    anyhow::bail!("launch resource path is not canonical")
                }
            }
        }
        Ok(DirectoryChain { directories })
    }

    fn ensure_safe_directory(metadata: &std::fs::Metadata) -> Result<()> {
        anyhow::ensure!(
            metadata.file_type().is_dir(),
            "launch ancestor is not a directory"
        );
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.gid() == 0,
            "launch ancestor is not root-owned"
        );
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "launch ancestor is writable by group/other"
        );
        Ok(())
    }

    fn stat_at(parent: &File, name: &CStr) -> io::Result<std::fs::Metadata> {
        let path = PathBuf::from(OsString::from_vec(name.to_bytes().to_vec()));
        // `/proc/self/fd/<n>/<name>` follows the retained parent descriptor;
        // symlink_metadata keeps the leaf no-follow for identity checks.
        std::fs::symlink_metadata(
            PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(path),
        )
    }

    fn install_fixed_fd(file: &impl AsRawFd, target: RawFd) -> Result<()> {
        if file.as_raw_fd() != target {
            // SAFETY: both integers are descriptors; dup3 atomically replaces
            // the target and creates a non-CLOEXEC duplicate on success.
            let result = unsafe { libc::dup3(file.as_raw_fd(), target, 0) };
            if result < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("install fixed VMM descriptor {target}"));
            }
        } else {
            // SAFETY: fcntl operates only on this live descriptor.
            let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
            if flags < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("read VMM descriptor flags {target}"));
            }
            // SAFETY: F_SETFD changes only the flags of the live fixed target.
            let result = unsafe { libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            if result < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("clear CLOEXEC on VMM descriptor {target}"));
            }
        }
        Ok(())
    }

    fn duplicate_fd(fd: RawFd) -> Result<RawFd> {
        // SAFETY: F_DUPFD_CLOEXEC duplicates one live descriptor and returns a
        // new independently-owned descriptor.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            Err(io::Error::last_os_error()).context("duplicate VMM log descriptor")
        } else {
            Ok(duplicate)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        use cats_api::runtime_reconciliation::HostPath;

        use super::*;

        fn running_as_root() -> bool {
            // SAFETY: geteuid has no pointer arguments or side effects.
            unsafe { libc::geteuid() == 0 }
        }

        fn launch_path() -> (tempfile::TempDir, PathBuf) {
            let root = tempfile::Builder::new()
                .prefix("cats-vmm-launcher-")
                .tempdir_in("/run")
                .unwrap();
            let parent = root.path().join("cat/runtime");
            std::fs::create_dir_all(&parent).unwrap();
            (root, parent.join("launch.file"))
        }

        #[test]
        fn systemd_open_file_descriptors_are_made_close_on_exec() {
            let file = tempfile::tempfile().unwrap();
            // SAFETY: F_GETFD reads flags from the live test descriptor.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            // SAFETY: F_SETFD changes only this live test descriptor.
            let result =
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            assert!(result >= 0);

            set_close_on_exec(&file).unwrap();

            // SAFETY: F_GETFD reads flags from the live test descriptor.
            let after = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(after & libc::FD_CLOEXEC != 0);
        }

        #[test]
        fn transferred_warm_memory_reopens_exact_inode_and_rejects_path_replacement() {
            if !running_as_root() {
                return;
            }
            let (_root, path) = launch_path();
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&[0x5a; 4096]).unwrap();
            file.sync_all().unwrap();
            let metadata = file.metadata().unwrap();
            let expected = AtomicVmmMemoryFileIdentity {
                path: HostPath::new(path.to_string_lossy().into_owned()).unwrap(),
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                content_sha256: hash_exact(&file, metadata.len()).unwrap(),
            };
            drop(file);

            let mut wrong_inode = expected.clone();
            wrong_inode.inode = wrong_inode.inode.checked_add(1).unwrap();
            assert!(RetainedWarmMemoryFile::open(&wrong_inode).is_err());

            let retained = RetainedWarmMemoryFile::open(&expected).unwrap();
            retained.assert_current().unwrap();

            let moved = path.with_extension("moved");
            std::fs::rename(&path, &moved).unwrap();
            let mut replacement = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            replacement.write_all(&[0x5a; 4096]).unwrap();
            replacement.sync_all().unwrap();

            assert!(retained.assert_current().is_err());
        }

        #[test]
        fn launch_file_rejects_leaf_replacement_and_never_unlinks_it_on_drop() {
            if !running_as_root() {
                return;
            }
            let (_root, path) = launch_path();
            let owned = OwnedLaunchFile::create(&path).unwrap();
            owned.assert_current(0).unwrap();
            let moved = path.with_extension("moved");
            std::fs::rename(&path, &moved).unwrap();
            let mut replacement = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            replacement.write_all(b"foreign").unwrap();
            replacement.sync_all().unwrap();

            assert!(owned.assert_current(0).is_err());
            drop(owned);
            assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        }

        #[test]
        fn launch_file_rejects_an_ancestor_move_away_and_back() {
            if !running_as_root() {
                return;
            }
            let (root, path) = launch_path();
            let owned = OwnedLaunchFile::create(&path).unwrap();
            owned.assert_current(0).unwrap();
            let ancestor = path.parent().unwrap();
            let moved = root.path().join("moved-runtime");
            std::fs::rename(ancestor, &moved).unwrap();
            std::fs::write(moved.join("aba-marker"), b"changed").unwrap();
            std::fs::remove_file(moved.join("aba-marker")).unwrap();
            std::fs::rename(&moved, ancestor).unwrap();

            assert!(owned.assert_current(0).is_err());
        }

        #[test]
        fn launch_file_allows_disjoint_shared_ancestor_sibling_churn() {
            if !running_as_root() {
                return;
            }
            let (_root, path) = launch_path();
            let owned = OwnedLaunchFile::create(&path).unwrap();
            let sibling = tempfile::Builder::new()
                .prefix("cats-vmm-unrelated-")
                .tempdir_in("/run")
                .unwrap();
            drop(sibling);

            owned.assert_current(0).unwrap();
        }

        #[test]
        fn launch_file_batch_freezes_one_shared_parent_after_all_owned_creates() {
            if !running_as_root() {
                return;
            }
            let (root, path) = launch_path();
            let parent = path.parent().unwrap();
            let memory_path = parent.join("memory.bin");
            let serial_log_path = parent.join("serial.log");
            let vmm_log_path = parent.join("vmm.log");
            let [memory, serial_log, vmm_log] = OwnedLaunchFile::create_batch([
                (memory_path.as_path(), 4096),
                (serial_log_path.as_path(), 0),
                (vmm_log_path.as_path(), 0),
            ])
            .unwrap();

            memory.assert_current(4096).unwrap();
            serial_log.assert_current(0).unwrap();
            vmm_log.assert_current(0).unwrap();

            let foreign_sibling = parent.join("foreign");
            std::fs::write(&foreign_sibling, b"changed").unwrap();
            std::fs::remove_file(&foreign_sibling).unwrap();
            assert!(memory.assert_current(4096).is_err());
            assert!(serial_log.assert_current(0).is_err());
            assert!(vmm_log.assert_current(0).is_err());
            drop(root);
        }

        #[test]
        fn launch_file_batch_rejects_nested_parents_before_any_create() {
            if !running_as_root() {
                return;
            }
            let (root, path) = launch_path();
            let runtime_parent = path.parent().unwrap();
            let cat_parent = runtime_parent.parent().unwrap();
            let memory_path = cat_parent.join("memory.bin");
            let serial_log_path = runtime_parent.join("serial.log");
            let vmm_log_path = runtime_parent.join("vmm.log");

            let error = OwnedLaunchFile::create_batch([
                (memory_path.as_path(), 4096),
                (serial_log_path.as_path(), 0),
                (vmm_log_path.as_path(), 0),
            ])
            .err()
            .expect("nested launch parents must fail before create");
            assert!(error.to_string().contains("parents are nested"));
            assert!(!memory_path.exists());
            assert!(!serial_log_path.exists());
            assert!(!vmm_log_path.exists());
            drop(root);
        }

        #[test]
        fn launch_file_batch_rejects_leaf_aba_before_parent_freeze() {
            if !running_as_root() {
                return;
            }
            let (_root, path) = launch_path();
            let parent = path.parent().unwrap();
            let memory_path = parent.join("memory.bin");
            let moved_memory_path = parent.join("memory.moved");
            let serial_log_path = parent.join("serial.log");
            let vmm_log_path = parent.join("vmm.log");
            let _error = OwnedLaunchFile::create_batch_with_before_freeze(
                [
                    (memory_path.as_path(), 4096),
                    (serial_log_path.as_path(), 0),
                    (vmm_log_path.as_path(), 0),
                ],
                || {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    std::fs::rename(&memory_path, &moved_memory_path)?;
                    let mut moved = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&moved_memory_path)?;
                    moved.write_all(b"foreign")?;
                    moved.sync_all()?;
                    std::fs::rename(&moved_memory_path, &memory_path)?;
                    Ok(())
                },
            )
            .err()
            .expect("leaf ABA before parent freeze must fail");

            // The injected closure completed (the moved leaf is absent) and
            // all three exclusive creates happened. Any error from the
            // subsequent descriptor/path freeze is therefore the required
            // fail-closed ABA outcome; its anyhow context is not an ABI.
            assert!(memory_path.exists());
            assert!(serial_log_path.exists());
            assert!(vmm_log_path.exists());
            assert!(!moved_memory_path.exists());
        }
    }
}

pub fn run() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("cats-vmm-launcher requires Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::{
        AsciiText, DirectAuthorizedAttachmentIdentity, DirectAuthorizedAttachmentPurpose,
        FenceEpoch, Generation, Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig,
        RemoteHead, ServingAuthorityProvenance, ServingBlockdIdentity, WireU64,
    };

    const TEST_MEMORY_BYTES: u64 = 256 * MIB;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test Id")
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).expect("valid random identity")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn wire(value: u64) -> WireU64 {
        WireU64::new(value).expect("positive wire integer")
    }

    fn host_path(value: impl Into<String>) -> HostPath {
        HostPath::new(value.into()).expect("valid absolute Host path")
    }

    fn artifact(path: &str, byte: u8) -> RuntimeLaunchArtifact {
        RuntimeLaunchArtifact {
            path: host_path(path),
            length: wire(4096),
            content_sha256: digest(byte),
        }
    }

    fn launch_root(incarnation: &RandomId128) -> String {
        format!(
            "/var/lib/cats/{INSTALLED_VMM_LAUNCH_NAMESPACE}/p-{}",
            incarnation.as_str()
        )
    }

    fn socket_root(incarnation: &RandomId128) -> String {
        format!("{INSTALLED_VMM_SOCKET_ROOT}/p-{}", incarnation.as_str())
    }

    fn source_launch() -> RuntimeLaunchIdentity {
        let incarnation = random(1);
        let ownership_token = random(10);
        RuntimeLaunchIdentity {
            runtime_incarnation: incarnation.clone(),
            scope_id: id("cats_vmm_source"),
            launcher_executable: Box::new(artifact("/usr/libexec/cats-vmm-launcher", 2)),
            boot: Box::new(VmmBootProvenance {
                vmm_executable: artifact("/usr/bin/cloud-hypervisor", 3),
                kernel: artifact("/usr/lib/cats/vmlinux", 4),
                initramfs: Some(artifact("/usr/lib/cats/initramfs", 5)),
                kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda")
                    .expect("valid kernel command line"),
            }),
            process_identity_token: random(6),
            vcpus: 2,
            memory_bytes: TEST_MEMORY_BYTES,
            boot_image_digest: digest(7),
            guest_config_digest: digest(8),
            api_socket_path: host_path(format!("{}/api.sock", socket_root(&incarnation))),
            vsock_socket_path: host_path(format!("{}/vsock.sock", socket_root(&incarnation))),
            guest_cid: 7,
            memory_file_path: host_path(format!("{}/memory.bin", launch_root(&incarnation))),
            serial_log_path: host_path(format!("{}/serial.log", launch_root(&incarnation))),
            vmm_log_path: host_path(format!("{}/vmm.log", launch_root(&incarnation))),
            network: Box::new(RuntimeNetworkIdentity {
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("network_warm"),
                    guest_mac: MacAddress::new("02:ca:fe:00:00:07").expect("valid Guest MAC"),
                    guest_ipv4: Ipv4Address::new("10.20.0.2").expect("valid Guest IPv4"),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.20.0.1").expect("valid gateway IPv4"),
                },
                tap_name: id("tap_warm"),
                ownership_token: random(9),
            }),
            devices: vec![PreparedDeviceInput {
                volume_intent_id: id("volume_intent_root"),
                disk_id: id("disk_root"),
                volume_id: id("volume_root"),
                disk_kind: DiskKind::Root,
                attachment_id: id("attachment_root"),
                attachment_epoch: FenceEpoch::new(3).expect("positive attachment epoch"),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: random(11),
                },
                expected_head: RemoteHead {
                    generation: Generation::new(4).expect("positive generation"),
                    root_hash: Some(digest(12)),
                    root_object_id: Some(
                        AsciiText::new("root_object_4").expect("valid root object Id"),
                    ),
                },
                size_bytes: 4 * 1024 * 1024 * 1024,
                durability: Durability::Strict,
                guest_device: GuestDeviceIdentity {
                    serial: id("cats_root"),
                    slot: 0,
                },
                ownership_token: ownership_token.clone(),
                serving_authority: Box::new(
                    ServingAuthorityProvenance::DirectAuthorizedAttachment {
                        authorization: DirectAuthorizedAttachmentIdentity {
                            path: host_path("/var/lib/cats/source-authority.json"),
                            device: wire(21),
                            inode: wire(22),
                            length: wire(23),
                            content_sha256: digest(13),
                        },
                        purpose: DirectAuthorizedAttachmentPurpose::ExistingRoot,
                    },
                ),
                serving_process: ServingBlockdIdentity {
                    scope_id: id("cats_blockd_source"),
                    control_socket_path: host_path(format!(
                        "/run/cats/blockd-v1/d-{}/ctl.sock",
                        ownership_token.as_str()
                    )),
                    data_directory: host_path("/var/lib/cats/source-lineage"),
                    executable_path: host_path("/usr/bin/cats-blockd"),
                    process_identity_token: random(14),
                },
                frontend: PrepareDeviceFrontend::VhostUserBlk {
                    socket_path: host_path(format!(
                        "/run/cats/blockd-v1/d-{}/io.sock",
                        ownership_token.as_str()
                    )),
                    queues: 2,
                    queue_size: 256,
                },
            }],
        }
    }

    fn restored_launch(source: &RuntimeLaunchIdentity) -> RuntimeLaunchIdentity {
        let incarnation = random(20);
        let mut launch = source.clone();
        launch.runtime_incarnation = incarnation.clone();
        launch.scope_id = id("cats_vmm_restored");
        launch.process_identity_token = random(21);
        launch.api_socket_path = host_path(format!("{}/api.sock", socket_root(&incarnation)));
        launch.serial_log_path = host_path(format!("{}/serial.log", launch_root(&incarnation)));
        launch.vmm_log_path = host_path(format!("{}/vmm.log", launch_root(&incarnation)));
        let device = launch
            .devices
            .first_mut()
            .expect("fixture retains its Root device");
        // Warm drain may advance the current remote head after the source VMM
        // launch. Volume authority, not the CH snapshot, authenticates it.
        device.expected_head = RemoteHead {
            generation: Generation::new(5).expect("positive advanced generation"),
            root_hash: Some(digest(21)),
            root_object_id: Some(
                AsciiText::new("root_object_5").expect("valid advanced root object Id"),
            ),
        };
        *device.serving_authority = ServingAuthorityProvenance::DirectAuthorizedAttachment {
            authorization: DirectAuthorizedAttachmentIdentity {
                path: host_path("/var/lib/cats/restored-authority.json"),
                device: wire(31),
                inode: wire(32),
                length: wire(33),
                content_sha256: digest(22),
            },
            purpose: DirectAuthorizedAttachmentPurpose::ExistingRoot,
        };
        device.serving_process.scope_id = id("cats_blockd_restored");
        device.serving_process.process_identity_token = random(23);
        launch
    }

    fn warm_mode(source: &RuntimeLaunchIdentity) -> AtomicVmmLaunchMode {
        AtomicVmmLaunchMode::WarmRestore {
            snapshot_directory: host_path(
                "/var/lib/cats/atomic-warm-snapshots-v1/operation/snapshot",
            ),
            memory_file: AtomicVmmMemoryFileIdentity {
                path: source.memory_file_path.clone(),
                device: 41,
                inode: 42,
                length: source.memory_bytes,
                content_sha256: digest(24),
            },
            source: Box::new(AtomicVmmWarmRestoreSourceIdentity::from_launch(source)),
        }
    }

    fn spec(
        launch: RuntimeLaunchIdentity,
        mode: AtomicVmmLaunchMode,
    ) -> Result<AtomicVmmLaunchSpec> {
        AtomicVmmLaunchSpec::new(
            id("node_a"),
            id("cat_a"),
            id("operation_a"),
            digest(30),
            digest(31),
            host_path("/var/lib/cats"),
            launch,
            mode,
        )
    }

    #[test]
    fn fresh_atomic_launch_builds_the_frozen_cloud_hypervisor_argv() {
        let launch = source_launch();
        let socket_path = match &launch.devices[0].frontend {
            PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path.clone(),
            PrepareDeviceFrontend::KernelNbd { .. } => unreachable!(),
        };
        let expected_disk = format!(
            "vhost_user=on,socket={},num_queues=2,queue_size=256,serial=cats_root",
            socket_path.as_str()
        );
        let plan = VmmLauncherPlan::from_spec(spec(launch, AtomicVmmLaunchMode::Fresh).unwrap())
            .expect("valid fresh atomic launch");
        let arguments = plan
            .cloud_hypervisor_arguments()
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments[0..4],
            ["--api-socket", "fd=71", "--kernel", "/proc/self/fd/66"]
        );
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--initramfs", "/proc/self/fd/67"]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--cpus", "boot=2"]));
        assert!(arguments.windows(2).any(|pair| pair
            == [
                "--memory-zone",
                "id=cat-ram,size=256M,file=/proc/self/fd/68,shared=on"
            ]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--net", "tap=tap_warm,mac=02:ca:fe:00:00:07"]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--disk", expected_disk.as_str()]));
        assert_eq!(
            &arguments[arguments.len() - 4..],
            ["--serial", "file=/proc/self/fd/69", "--console", "off"]
        );
    }

    #[test]
    fn warm_restore_accepts_exact_source_and_only_emits_restore_arguments() {
        let source = source_launch();
        let launch = restored_launch(&source);
        let expected_vsock = source.vsock_socket_path.clone();
        let expected_cid = source.guest_cid;
        let expected_network = source.network.clone();
        let expected_devices = source
            .devices
            .iter()
            .map(AtomicVmmWarmRestoreDeviceIdentity::from)
            .collect::<Vec<_>>();
        let plan = VmmLauncherPlan::from_spec(
            spec(launch, warm_mode(&source)).expect("exact Warm source is valid"),
        )
        .expect("valid Warm launcher plan");

        assert_eq!(plan.spec().launch.vsock_socket_path, expected_vsock);
        assert_eq!(plan.spec().launch.guest_cid, expected_cid);
        assert_eq!(plan.spec().launch.network, expected_network);
        assert_eq!(
            plan.spec()
                .launch
                .devices
                .iter()
                .map(AtomicVmmWarmRestoreDeviceIdentity::from)
                .collect::<Vec<_>>(),
            expected_devices
        );
        let arguments = plan
            .cloud_hypervisor_arguments()
            .iter()
            .map(|value| value.to_str().expect("UTF-8 fixture argument"))
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            [
                "--api-socket",
                "fd=71",
                "--restore",
                "source_url=file:///var/lib/cats/atomic-warm-snapshots-v1/operation/snapshot"
            ]
        );

        let encoded = encode_atomic_vmm_launch_spec(plan.spec()).expect("encode exact Warm spec");
        assert_eq!(
            decode_atomic_vmm_launch_spec(&encoded).expect("decode exact Warm spec"),
            *plan.spec()
        );
    }

    #[test]
    fn warm_restore_rejects_transport_network_and_device_drift_without_fresh_fallback() {
        let source = source_launch();

        let mut changed_cid = restored_launch(&source);
        changed_cid.guest_cid += 1;
        assert!(spec(changed_cid, warm_mode(&source)).is_err());

        let mut changed_vsock = restored_launch(&source);
        changed_vsock.vsock_socket_path = host_path(format!(
            "{}/other-vsock.sock",
            socket_root(&source.runtime_incarnation)
        ));
        assert!(spec(changed_vsock, warm_mode(&source)).is_err());

        let mut changed_network = restored_launch(&source);
        changed_network.network.ownership_token = random(40);
        assert!(spec(changed_network, warm_mode(&source)).is_err());

        let mut changed_owner = restored_launch(&source);
        changed_owner.devices[0].ownership_token = random(41);
        assert!(spec(changed_owner, warm_mode(&source)).is_err());

        let mut changed_frontend = restored_launch(&source);
        changed_frontend.devices[0].frontend = PrepareDeviceFrontend::KernelNbd {
            listener_socket_path: host_path("/run/cats/blockd-v1/d-test/io.sock"),
            device_path: host_path("/dev/nbd7"),
            direct: true,
        };
        assert!(spec(changed_frontend, warm_mode(&source)).is_err());
    }

    #[test]
    fn warm_restore_requires_exact_transferred_memory_path_and_size() {
        let source = source_launch();
        let launch = restored_launch(&source);
        let mut wrong_path = warm_mode(&source);
        let AtomicVmmLaunchMode::WarmRestore { memory_file, .. } = &mut wrong_path else {
            unreachable!()
        };
        memory_file.path = host_path(format!(
            "{}/replacement-memory.bin",
            launch_root(&source.runtime_incarnation)
        ));
        assert!(spec(launch.clone(), wrong_path).is_err());

        let mut wrong_size = warm_mode(&source);
        let AtomicVmmLaunchMode::WarmRestore { memory_file, .. } = &mut wrong_size else {
            unreachable!()
        };
        memory_file.length -= MIB;
        assert!(spec(launch, wrong_size).is_err());
    }

    #[test]
    fn fresh_launch_rejects_a_retained_source_vsock_path() {
        let source = source_launch();
        let launch = restored_launch(&source);
        let error = spec(launch, AtomicVmmLaunchMode::Fresh)
            .expect_err("Fresh must not adopt a Warm source socket or memory namespace");
        assert!(error
            .to_string()
            .contains("fresh atomic VMM socket or memory path escaped"));
    }
}

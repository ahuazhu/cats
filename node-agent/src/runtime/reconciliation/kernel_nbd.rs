//! Exact provider-private inventory and reservation for the ADR-0015
//! kernel-NBD frontend.
//!
//! A `/dev/nbdN` path becomes part of a `PrepareDevice` checkpoint before the
//! attach effect. Two concurrent Cats must therefore serialize the sequence
//! "read every durable reservation -> prove the slot free -> fsync the new
//! checkpoint". [`KernelNbdAllocationPermit`] retains the Node-global flock
//! and one exact pool snapshot across that caller-owned checkpoint replace.
//! It does not attach or detach a device.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    HostPath, Id, ObservedDevice, OwnershipTokenEvidence, PrepareDeviceFrontend, RandomId128,
    ReconcileStep, RuntimeCheckpoint, WireU64,
};

use crate::runtime_spine::RuntimePhysicalReadContext;
use crate::state_directory::StateDirectory;

use super::checkpoint::{FileCheckpointStore, StoredCheckpoint};

const ALLOCATION_LOCK_BASENAME: &str = "kernel-nbd-allocation.lock";
const MAX_SYSFS_ATTRIBUTE_BYTES: u64 = 64;
const MAX_PROC_STAT_BYTES: u64 = 64 * 1024;
const MAX_PROC_CMDLINE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct KernelNbdInventoryConfig {
    state_directory: StateDirectory,
    sys_block_root: PathBuf,
    proc_root: PathBuf,
    nbd_client_binary: PathBuf,
    device_count: u32,
}

impl KernelNbdInventoryConfig {
    pub(crate) fn installed(
        state_directory: StateDirectory,
        nbd_client_binary: PathBuf,
        device_count: u32,
    ) -> Result<Self> {
        anyhow::ensure!(cfg!(target_os = "linux"), "kernel NBD requires Linux");
        anyhow::ensure!(
            nbd_client_binary.is_absolute(),
            "kernel-NBD client binary must be absolute"
        );
        anyhow::ensure!(device_count > 0, "kernel-NBD pool must not be empty");
        Ok(Self {
            state_directory,
            sys_block_root: PathBuf::from("/sys/block"),
            proc_root: PathBuf::from("/proc"),
            nbd_client_binary,
            device_count,
        })
    }

    #[cfg(test)]
    fn fixture(
        state_directory: StateDirectory,
        sys_block_root: PathBuf,
        proc_root: PathBuf,
        nbd_client_binary: PathBuf,
        device_count: u32,
    ) -> Self {
        Self {
            state_directory,
            sys_block_root,
            proc_root,
            nbd_client_binary,
            device_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdClientIdentity {
    pub(crate) process_id: u32,
    pub(crate) process_start_time_ticks: WireU64,
    pub(crate) executable_path: HostPath,
    pub(crate) listener_socket_path: HostPath,
    pub(crate) device_path: HostPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KernelNbdSlotState {
    Free,
    Serving(KernelNbdClientIdentity),
    /// The kernel still reports a configured device but no exact live client.
    /// This is never allocatable; a separately checkpointed cleanup effect is
    /// required before it can become `Free`.
    Leaked {
        recorded_process_id: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdPoolSnapshot {
    slots: BTreeMap<HostPath, KernelNbdSlotState>,
    // BTreeMap's lexical path order places nbd10 before nbd2. Retain the
    // configured numeric order so allocation is stable by device index.
    ordered_paths: Vec<HostPath>,
}

impl KernelNbdPoolSnapshot {
    pub(crate) fn slots(&self) -> &BTreeMap<HostPath, KernelNbdSlotState> {
        &self.slots
    }

    pub(crate) fn state(&self, path: &HostPath) -> Option<&KernelNbdSlotState> {
        self.slots.get(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdReservation {
    pub(crate) cat_id: Id,
    pub(crate) volume_id: Id,
    pub(crate) device_path: HostPath,
    pub(crate) ownership_token: RandomId128,
}

/// Durable reservations reconstructed from every Runtime checkpoint in the
/// same descriptor-stable checkpoint-directory snapshot. The caller must not
/// build this from Desired alone or from one Cat point-read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KernelNbdReservations {
    by_device: BTreeMap<HostPath, KernelNbdReservation>,
    by_identity: BTreeMap<KernelNbdReservationIdentity, HostPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KernelNbdReservationIdentity {
    cat_id: Id,
    volume_id: Id,
    ownership_token: RandomId128,
}

impl KernelNbdReservations {
    pub(crate) fn from_checkpoints<'a>(
        checkpoints: impl IntoIterator<Item = &'a RuntimeCheckpoint>,
    ) -> Result<Self> {
        let mut reservations = Self::default();
        for checkpoint in checkpoints {
            if let ReconcileStep::PrepareDevice {
                volume_id,
                ownership_token,
                frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
                ..
            } = &checkpoint.step
            {
                reservations.insert(KernelNbdReservation {
                    cat_id: checkpoint.cat_id.clone(),
                    volume_id: volume_id.clone(),
                    device_path: device_path.clone(),
                    ownership_token: ownership_token.clone(),
                })?;
            }
            for volume in &checkpoint.volumes {
                for device in &volume.devices {
                    let ObservedDevice::KernelNbd {
                        device_path,
                        ownership_token,
                        ..
                    } = device
                    else {
                        continue;
                    };
                    let OwnershipTokenEvidence::Valid { ownership_token } = ownership_token else {
                        anyhow::bail!(
                            "durable kernel-NBD reservation has no valid ownership token"
                        );
                    };
                    reservations.insert(KernelNbdReservation {
                        cat_id: checkpoint.cat_id.clone(),
                        volume_id: volume.volume_id.clone(),
                        device_path: device_path.clone(),
                        ownership_token: ownership_token.clone(),
                    })?;
                }
            }
        }
        Ok(reservations)
    }

    fn insert(&mut self, candidate: KernelNbdReservation) -> Result<()> {
        let identity = KernelNbdReservationIdentity {
            cat_id: candidate.cat_id.clone(),
            volume_id: candidate.volume_id.clone(),
            ownership_token: candidate.ownership_token.clone(),
        };
        if let Some(existing_path) = self.by_identity.get(&identity) {
            anyhow::ensure!(
                existing_path == &candidate.device_path,
                "kernel-NBD reservation identity names conflicting devices"
            );
        }
        if let Some(existing) = self.by_device.get(&candidate.device_path) {
            anyhow::ensure!(
                existing == &candidate,
                "kernel-NBD device is durably reserved by conflicting identities"
            );
            return Ok(());
        }
        self.by_identity
            .insert(identity, candidate.device_path.clone());
        self.by_device
            .insert(candidate.device_path.clone(), candidate);
        Ok(())
    }

    pub(crate) fn by_device(&self) -> &BTreeMap<HostPath, KernelNbdReservation> {
        &self.by_device
    }
}

/// Held across the final durable-reservation index read and the caller's
/// atomic checkpoint replace. Dropping it releases only the allocation lock;
/// it never changes a kernel device.
#[derive(Debug)]
pub(crate) struct KernelNbdAllocationPermit {
    _allocation_lock: File,
    snapshot: KernelNbdPoolSnapshot,
}

impl KernelNbdAllocationPermit {
    pub(crate) fn snapshot(&self) -> &KernelNbdPoolSnapshot {
        &self.snapshot
    }

    /// Choose the lowest configured slot that is both physically free and not
    /// named by any durable checkpoint. The caller must fsync its new
    /// `PrepareDevice` checkpoint before this permit is dropped.
    fn select_free(&self, reservations: &KernelNbdReservations) -> Result<HostPath> {
        for path in reservations.by_device.keys() {
            anyhow::ensure!(
                self.snapshot.slots.contains_key(path),
                "durable kernel-NBD reservation names a device outside the configured pool"
            );
        }
        for path in &self.snapshot.ordered_paths {
            let state = self
                .snapshot
                .state(path)
                .expect("ordered kernel-NBD path is present in the same snapshot");
            if matches!(state, KernelNbdSlotState::Free)
                && !reservations.by_device.contains_key(path)
            {
                return Ok(path.clone());
            }
        }
        anyhow::bail!("no physically free, unreserved kernel-NBD device remains")
    }

    pub(crate) fn require_free(&self, device_path: &HostPath) -> Result<()> {
        anyhow::ensure!(
            matches!(
                self.snapshot.state(device_path),
                Some(KernelNbdSlotState::Free)
            ),
            "checkpointed kernel-NBD device is not physically free"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KernelNbdInventoryPort {
    config: KernelNbdInventoryConfig,
}

impl KernelNbdInventoryPort {
    pub(crate) fn new(config: KernelNbdInventoryConfig) -> Self {
        Self { config }
    }

    /// Acquire the Node-global allocator and inspect every configured slot.
    /// The callback that persists the reservation runs later while the
    /// returned permit still owns this lock.
    pub(crate) fn lock_and_inspect(
        &self,
        context: &dyn RuntimePhysicalReadContext,
    ) -> Result<KernelNbdAllocationPermit> {
        context.check_active()?;
        let allocation_lock = open_allocation_lock(&self.config.state_directory)?;
        lock_exclusive_nonblocking(&allocation_lock)?;
        let snapshot = inspect_pool(&self.config, context)?;
        context.check_active()?;
        Ok(KernelNbdAllocationPermit {
            _allocation_lock: allocation_lock,
            snapshot,
        })
    }

    /// Serialize the complete durable-reservation read, deterministic free
    /// slot choice, and an actual [`FileCheckpointStore`] replacement.
    /// `read_reservations` must enumerate the descriptor-stable checkpoint
    /// namespace; a cached inventory projection is intentionally not accepted
    /// here. Returning a generic callback result would let a caller drop this
    /// permit before it had durably published the reservation, so this API
    /// deliberately returns only a [`StoredCheckpoint`].
    pub(crate) fn reserve_and_replace(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        read_reservations: impl FnOnce() -> Result<KernelNbdReservations>,
        store: &FileCheckpointStore,
        predecessor: &StoredCheckpoint,
        build_checkpoint: impl FnOnce(HostPath) -> Result<RuntimeCheckpoint>,
    ) -> Result<StoredCheckpoint> {
        let permit = self.lock_and_inspect(context)?;
        context.check_active()?;
        let reservations = read_reservations()?;
        context.check_active()?;
        let selected = permit.select_free(&reservations)?;
        let replacement = build_checkpoint(selected)?;
        context.check_active()?;
        // `permit` remains live through FileCheckpointStore's file and parent
        // directory fsync barriers and is dropped only after publication.
        store
            .replace(predecessor, &replacement)
            .context("persist kernel-NBD reservation checkpoint")
    }
}

fn inspect_pool(
    config: &KernelNbdInventoryConfig,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<KernelNbdPoolSnapshot> {
    let mut slots = BTreeMap::new();
    let mut ordered_paths = Vec::with_capacity(config.device_count as usize);
    for index in 0..config.device_count {
        context.check_active()?;
        let device_path = HostPath::new(format!("/dev/nbd{index}"))
            .expect("fixed kernel-NBD path is a canonical HostPath");
        let state = inspect_slot(config, index, &device_path, context)
            .with_context(|| format!("inspect exact kernel-NBD slot /dev/nbd{index}"))?;
        slots.insert(device_path.clone(), state);
        ordered_paths.push(device_path);
    }
    context.check_active()?;
    Ok(KernelNbdPoolSnapshot {
        slots,
        ordered_paths,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelTuple {
    process_id: Option<u32>,
    size_sectors: u64,
}

fn inspect_slot(
    config: &KernelNbdInventoryConfig,
    index: u32,
    device_path: &HostPath,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<KernelNbdSlotState> {
    let slot = config.sys_block_root.join(format!("nbd{index}"));
    let before = read_kernel_tuple(&slot, context)?;
    let state = match before {
        KernelTuple {
            process_id: None,
            size_sectors: 0,
        } => KernelNbdSlotState::Free,
        KernelTuple {
            process_id,
            size_sectors,
        } if size_sectors > 0 => match process_id {
            Some(process_id) => {
                match sample_exact_client(config, process_id, device_path, context)? {
                    Some(identity) => KernelNbdSlotState::Serving(identity),
                    None => KernelNbdSlotState::Leaked {
                        recorded_process_id: Some(process_id),
                    },
                }
            }
            None => KernelNbdSlotState::Leaked {
                recorded_process_id: None,
            },
        },
        KernelTuple {
            process_id: Some(_),
            size_sectors: 0,
        } => anyhow::bail!("kernel-NBD slot has a client pid but zero capacity"),
        _ => unreachable!("kernel-NBD size cases are exhaustive"),
    };
    context.check_active()?;
    let after = read_kernel_tuple(&slot, context)?;
    anyhow::ensure!(before == after, "kernel-NBD slot changed during inspection");
    if let KernelNbdSlotState::Serving(identity) = &state {
        let repeated = sample_exact_client(config, identity.process_id, device_path, context)?;
        anyhow::ensure!(
            repeated.as_ref() == Some(identity),
            "kernel-NBD client changed during inspection"
        );
    }
    Ok(state)
}

fn read_kernel_tuple(slot: &Path, context: &dyn RuntimePhysicalReadContext) -> Result<KernelTuple> {
    let pid = read_optional_bounded(&slot.join("pid"), MAX_SYSFS_ATTRIBUTE_BYTES, context)?;
    let process_id = match pid {
        None => None,
        Some(bytes) => {
            let text = std::str::from_utf8(&bytes).context("kernel-NBD pid is not UTF-8")?;
            let value = text
                .trim()
                .parse::<u32>()
                .context("kernel-NBD pid is not a u32")?;
            (value > 0).then_some(value)
        }
    };
    let size = read_required_bounded(&slot.join("size"), MAX_SYSFS_ATTRIBUTE_BYTES, context)?;
    let size = std::str::from_utf8(&size)
        .context("kernel-NBD size is not UTF-8")?
        .trim()
        .parse::<u64>()
        .context("kernel-NBD size is not a u64")?;
    Ok(KernelTuple {
        process_id,
        size_sectors: size,
    })
}

fn sample_exact_client(
    config: &KernelNbdInventoryConfig,
    process_id: u32,
    device_path: &HostPath,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<Option<KernelNbdClientIdentity>> {
    let process = config.proc_root.join(process_id.to_string());
    let process_metadata = match std::fs::metadata(&process) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context("inspect kernel-NBD client process"),
    };
    anyhow::ensure!(
        process_metadata.is_dir() && process_metadata.uid() == effective_user_id(),
        "kernel-NBD slot is served by a foreign process owner"
    );
    let stat = match read_optional_bounded(&process.join("stat"), MAX_PROC_STAT_BYTES, context)? {
        Some(stat) => stat,
        None => return Ok(None),
    };
    let stat = std::str::from_utf8(&stat).context("kernel-NBD client stat is not UTF-8")?;
    let (_, after_comm) = stat
        .rsplit_once(')')
        .context("kernel-NBD client stat has no command terminator")?;
    let start_time_ticks = after_comm
        .split_whitespace()
        .nth(19)
        .context("kernel-NBD client stat omits start time")?
        .parse::<u64>()
        .context("kernel-NBD client start time is not a u64")?;
    let start_time_ticks = WireU64::new(start_time_ticks)
        .filter(|value| value.get() > 0)
        .context("kernel-NBD client start time is zero")?;
    context.check_active()?;
    let executable = match std::fs::read_link(process.join("exe")) {
        Ok(executable) => executable,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context("read kernel-NBD client executable"),
    };
    anyhow::ensure!(
        executable == config.nbd_client_binary,
        "kernel-NBD slot is served by a foreign executable"
    );
    let command_line =
        read_required_bounded(&process.join("cmdline"), MAX_PROC_CMDLINE_BYTES, context)?;
    let arguments = parse_nul_arguments(&command_line)?;
    let expected_device = OsString::from(device_path.as_str());
    anyhow::ensure!(
        arguments.len() == 9
            && Path::new(&arguments[0]) == config.nbd_client_binary
            && arguments[1] == NBD_IOCTL_MODE
            && arguments[2] == "-unix"
            && arguments[4] == expected_device
            && arguments[5] == "-b"
            && arguments[6] == "512"
            && arguments[7] == "-N"
            && arguments[8].is_empty(),
        "kernel-NBD client argv is not the frozen ioctl invocation"
    );
    let socket = Path::new(&arguments[3]);
    let listener_socket_path = HostPath::new(
        socket
            .to_str()
            .context("kernel-NBD listener socket path is not UTF-8")?
            .to_owned(),
    )
    .context("kernel-NBD listener socket is not a canonical HostPath")?;
    let executable_path = HostPath::new(
        executable
            .to_str()
            .context("kernel-NBD executable path is not UTF-8")?
            .to_owned(),
    )
    .context("kernel-NBD executable is not a canonical HostPath")?;
    Ok(Some(KernelNbdClientIdentity {
        process_id,
        process_start_time_ticks: start_time_ticks,
        executable_path,
        listener_socket_path,
        device_path: device_path.clone(),
    }))
}

const NBD_IOCTL_MODE: &str = "-nonetlink";

fn parse_nul_arguments(bytes: &[u8]) -> Result<Vec<OsString>> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.last() == Some(&0),
        "kernel-NBD client argv is not NUL terminated"
    );
    Ok(bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(|argument| OsString::from_vec(argument.to_vec()))
        .collect())
}

fn read_optional_bounded(
    path: &Path,
    cap: u64,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<Option<Vec<u8>>> {
    context.check_active()?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).with_context(|| format!("open {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    context.check_active()?;
    anyhow::ensure!(
        bytes.len() as u64 <= cap,
        "{} exceeds byte cap",
        path.display()
    );
    Ok(Some(bytes))
}

fn read_required_bounded(
    path: &Path,
    cap: u64,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<Vec<u8>> {
    read_optional_bounded(path, cap, context)?
        .with_context(|| format!("required kernel-NBD input {} is absent", path.display()))
}

fn open_allocation_lock(state_directory: &StateDirectory) -> Result<File> {
    let directory = state_directory
        .try_clone_directory()
        .context("open retained Node state directory for kernel-NBD allocation")?;
    let name = CString::new(ALLOCATION_LOCK_BASENAME).expect("fixed basename has no NUL");
    let file = open_at(
        &directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0o600,
    )
    .context("open kernel-NBD allocation lock")?;
    let metadata = file
        .metadata()
        .context("inspect kernel-NBD allocation lock")?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.uid() == effective_user_id()
            && metadata.gid() == effective_group_id(),
        "kernel-NBD allocation lock has unsafe metadata"
    );
    Ok(file)
}

fn lock_exclusive_nonblocking(file: &File) -> Result<()> {
    loop {
        // SAFETY: `file` owns a live descriptor and `flock` retains no Rust
        // pointer or ownership after the call returns.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if source.raw_os_error() == Some(libc::EWOULDBLOCK)
            || source.raw_os_error() == Some(libc::EAGAIN)
        {
            anyhow::bail!("kernel-NBD allocation is already active")
        }
        return Err(source).context("lock kernel-NBD allocator");
    }
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: both descriptors/strings are live for the duration of `openat`;
    // the returned descriptor, when nonnegative, is newly owned by this call.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `openat` returned one fresh descriptor which is now
    // transferred to `File` exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no arguments and retains no state.
    unsafe { libc::geteuid() }
}

fn effective_group_id() -> u32 {
    // SAFETY: `getegid` has no arguments and retains no state.
    unsafe { libc::getegid() }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        AcquireOrigin, ContractVersion, Durability, FenceEpoch, Generation, GuestDeviceIdentity,
        GuestTransportEvidence, LifecycleAdmission, RemoteHead, RequireIdleCheckpoint, Revision,
        ServingAuthorityProvenance, ServingBlockdIdentity, WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use super::*;

    #[derive(Debug)]
    struct TestContext {
        deadline: Instant,
    }

    impl TestContext {
        fn active() -> Self {
            Self {
                deadline: Instant::now() + Duration::from_secs(5),
            }
        }
    }

    impl RuntimePhysicalReadContext for TestContext {
        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn check_active(&self) -> Result<()> {
            anyhow::ensure!(Instant::now() < self.deadline, "test deadline expired");
            Ok(())
        }
    }

    struct Fixture {
        _temp: TempDir,
        state: PathBuf,
        sys: PathBuf,
        proc: PathBuf,
        client: PathBuf,
    }

    impl Fixture {
        fn new(slots: u32) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let state = temp.path().join("state");
            let sys = temp.path().join("sys-block");
            let proc = temp.path().join("proc");
            let client = temp.path().join("nbd-client");
            fs::create_dir(&state).unwrap();
            fs::create_dir(&sys).unwrap();
            fs::create_dir(&proc).unwrap();
            fs::write(&client, b"fixture").unwrap();
            for index in 0..slots {
                let slot = sys.join(format!("nbd{index}"));
                fs::create_dir(&slot).unwrap();
                fs::write(slot.join("size"), b"0\n").unwrap();
            }
            Self {
                _temp: temp,
                state,
                sys,
                proc,
                client,
            }
        }

        fn config(&self, slots: u32) -> KernelNbdInventoryConfig {
            KernelNbdInventoryConfig::fixture(
                StateDirectory::unanchored(self.state.clone()),
                self.sys.clone(),
                self.proc.clone(),
                self.client.clone(),
                slots,
            )
        }

        fn serving(&self, index: u32, pid: u32, socket: &str) {
            let slot = self.sys.join(format!("nbd{index}"));
            fs::write(slot.join("pid"), format!("{pid}\n")).unwrap();
            fs::write(slot.join("size"), b"8192\n").unwrap();
            let process = self.proc.join(pid.to_string());
            fs::create_dir(&process).unwrap();
            let mut fields = vec!["S".to_owned()];
            fields.extend((0..18).map(|_| "0".to_owned()));
            fields.push("700".to_owned());
            fields.extend((0..4).map(|_| "0".to_owned()));
            fs::write(
                process.join("stat"),
                format!("{pid} (nbd-client) {}\n", fields.join(" ")),
            )
            .unwrap();
            symlink(&self.client, process.join("exe")).unwrap();
            let device = format!("/dev/nbd{index}");
            let argv = [
                self.client.as_os_str().as_bytes(),
                b"-nonetlink",
                b"-unix",
                socket.as_bytes(),
                device.as_bytes(),
                b"-b",
                b"512",
                b"-N",
                b"",
            ];
            let mut bytes = Vec::new();
            for argument in argv {
                bytes.extend_from_slice(argument);
                bytes.push(0);
            }
            fs::write(process.join("cmdline"), bytes).unwrap();
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(byte: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(byte, 32).collect::<String>()).unwrap()
    }

    fn host(value: &str) -> HostPath {
        HostPath::new(value.to_owned()).unwrap()
    }

    fn checkpoint(cat: &str, volume: &str, device: &str, token: char) -> RuntimeCheckpoint {
        RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: id(cat),
            node_id: id("node_a"),
            placement_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            spec_digest: cats_api::runtime_reconciliation::Sha256Digest::new(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .unwrap(),
            runtime_incarnation: None,
            stable_state: None,
            step: ReconcileStep::PrepareDevice {
                volume_id: id(volume),
                attachment_id: id("att_a"),
                attachment_epoch: FenceEpoch::new(1).unwrap(),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: random('2'),
                },
                expected_head: RemoteHead {
                    generation: Generation::new(1).unwrap(),
                    root_hash: Some(
                        cats_api::runtime_reconciliation::Sha256Digest::new(format!(
                            "sha256:{}",
                            "3".repeat(64)
                        ))
                        .unwrap(),
                    ),
                    root_object_id: Some(
                        cats_api::runtime_reconciliation::AsciiText::new("root/1").unwrap(),
                    ),
                },
                size_bytes: 4096,
                durability: Durability::Strict,
                guest_device: GuestDeviceIdentity {
                    serial: id("cats-root"),
                    slot: 0,
                },
                ownership_token: random(token),
                serving_authority: Box::new(
                    ServingAuthorityProvenance::DirectAuthorizedAttachment {
                        authorization: cats_api::runtime_reconciliation::DirectAuthorizedAttachmentIdentity {
                            path: host("/var/lib/cats/authorized-serving.json"),
                            device: WireU64::new(1).unwrap(),
                            inode: WireU64::new(2).unwrap(),
                            length: WireU64::new(3).unwrap(),
                            content_sha256: cats_api::runtime_reconciliation::Sha256Digest::new(
                                format!("sha256:{}", "4".repeat(64)),
                            )
                            .unwrap(),
                        },
                        purpose: cats_api::runtime_reconciliation::DirectAuthorizedAttachmentPurpose::ExistingRoot,
                    },
                ),
                serving_process: ServingBlockdIdentity {
                    scope_id: id("cats-serving.service"),
                    control_socket_path: host("/run/cats/control.sock"),
                    data_directory: host("/var/lib/cats/data"),
                    executable_path: host("/usr/bin/cats-blockd"),
                    process_identity_token: random('5'),
                },
                frontend: PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path: host("/run/cats/nbd.sock"),
                    device_path: host(device),
                },
            },
            require_idle: RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(1).unwrap(),
            processes: Vec::new(),
            volumes: Vec::new(),
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
        }
    }

    #[test]
    fn locked_scan_distinguishes_free_serving_and_leaked_and_selects_unreserved() {
        let fixture = Fixture::new(12);
        fixture.serving(1, 42, "/run/cats/a.sock");
        fs::write(fixture.sys.join("nbd2/size"), b"4096\n").unwrap();
        let port = KernelNbdInventoryPort::new(fixture.config(12));
        let permit = port.lock_and_inspect(&TestContext::active()).unwrap();
        assert_eq!(
            permit.snapshot().state(&host("/dev/nbd0")),
            Some(&KernelNbdSlotState::Free)
        );
        let KernelNbdSlotState::Serving(identity) =
            permit.snapshot().state(&host("/dev/nbd1")).unwrap()
        else {
            panic!("nbd1 must be exact serving")
        };
        assert_eq!(identity.process_id, 42);
        assert_eq!(identity.listener_socket_path, host("/run/cats/a.sock"));
        assert_eq!(
            permit.snapshot().state(&host("/dev/nbd2")),
            Some(&KernelNbdSlotState::Leaked {
                recorded_process_id: None
            })
        );
        let reservations = KernelNbdReservations::from_checkpoints([&checkpoint(
            "cat_a",
            "vol_a",
            "/dev/nbd0",
            '6',
        )])
        .unwrap();
        assert_eq!(
            permit.select_free(&reservations).unwrap(),
            host("/dev/nbd3")
        );
    }

    #[test]
    fn allocation_flock_excludes_a_second_selector_through_checkpoint_fsync() {
        let fixture = Fixture::new(2);
        let first = KernelNbdInventoryPort::new(fixture.config(2));
        let second = KernelNbdInventoryPort::new(fixture.config(2));
        let checkpoint_directory = fixture.state.join("checkpoints");
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let persisted = first
            .reserve_and_replace(
                &TestContext::active(),
                || KernelNbdReservations::from_checkpoints([predecessor.checkpoint()]),
                &store,
                &predecessor,
                |selected| {
                    let error = second.lock_and_inspect(&TestContext::active()).unwrap_err();
                    assert!(error.to_string().contains("already active"), "{error:#}");
                    let mut replacement = predecessor.checkpoint().clone();
                    let ReconcileStep::PrepareDevice {
                        frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
                        ..
                    } = &mut replacement.step
                    else {
                        panic!("fixture must be a kernel-NBD PrepareDevice checkpoint")
                    };
                    *device_path = selected;
                    Ok(replacement)
                },
            )
            .unwrap();
        let ReconcileStep::PrepareDevice {
            frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
            ..
        } = &persisted.checkpoint().step
        else {
            panic!("persisted checkpoint must remain PrepareDevice")
        };
        assert_eq!(device_path, &host("/dev/nbd0"));
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            persisted.checkpoint()
        );
        second.lock_and_inspect(&TestContext::active()).unwrap();
    }

    #[test]
    fn malformed_or_foreign_serving_identity_fails_closed() {
        let fixture = Fixture::new(1);
        fixture.serving(0, 42, "/run/cats/a.sock");
        fs::write(fixture.proc.join("42/cmdline"), b"foreign\0").unwrap();
        let port = KernelNbdInventoryPort::new(fixture.config(1));
        assert!(port.lock_and_inspect(&TestContext::active()).is_err());

        fs::write(fixture.sys.join("nbd0/pid"), b"42\n").unwrap();
        fs::write(fixture.sys.join("nbd0/size"), b"0\n").unwrap();
        assert!(port.lock_and_inspect(&TestContext::active()).is_err());
    }

    #[test]
    fn lock_metadata_and_reservation_conflicts_are_closed() {
        let fixture = Fixture::new(2);
        let lock = fixture.state.join(ALLOCATION_LOCK_BASENAME);
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        assert!(port.lock_and_inspect(&TestContext::active()).is_err());

        let first = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let second = checkpoint("cat_b", "vol_b", "/dev/nbd0", '7');
        assert!(KernelNbdReservations::from_checkpoints([&first, &second]).is_err());
        let same_identity_other_device = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        assert!(
            KernelNbdReservations::from_checkpoints([&first, &same_identity_other_device]).is_err()
        );

        let other = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(other.config(2));
        let outside = checkpoint("cat_c", "vol_c", "/dev/nbd9", '8');
        let reservations = KernelNbdReservations::from_checkpoints([&outside]).unwrap();
        let permit = port.lock_and_inspect(&TestContext::active()).unwrap();
        assert!(permit.select_free(&reservations).is_err());
    }
}

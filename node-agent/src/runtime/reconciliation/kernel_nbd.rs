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
use std::fs::{File, Metadata};
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

use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimePhysicalReadContext};
use crate::state_directory::StateDirectory;

use super::checkpoint::{FileCheckpointStore, StoredCheckpoint};
use super::clean_slate_probes::{
    snapshot_runtime_checkpoint_namespace, RuntimeCheckpointNamespaceSnapshot,
    CHECKPOINT_NAMESPACE, RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
};

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
    fn from_snapshot(snapshot: &RuntimeCheckpointNamespaceSnapshot) -> Result<Self> {
        Self::from_checkpoints(snapshot.iter_checkpoints())
    }

    fn from_checkpoints<'a>(
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
    state_root: File,
    allocation_lock: File,
    snapshot: KernelNbdPoolSnapshot,
}

impl KernelNbdAllocationPermit {
    fn state_root(&self) -> &File {
        &self.state_root
    }

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

    fn assert_current_allocation_lock(&self) -> Result<()> {
        let current = reopen_allocation_lock(&self.state_root)?;
        ensure_same_allocation_lock(&self.allocation_lock, &current)
    }

    fn assert_current_checkpoint_namespace(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        let current = reopen_checkpoint_namespace(&self.state_root)?;
        validate_checkpoint_namespace(&self.state_root, snapshot.retained_directory())?;
        validate_checkpoint_namespace(&self.state_root, store.retained_directory())?;
        ensure_same_directory(
            snapshot.retained_directory(),
            store.retained_directory(),
            "kernel-NBD snapshot and checkpoint store use different directories",
        )?;
        ensure_same_directory(
            snapshot.retained_directory(),
            &current,
            "kernel-NBD checkpoint namespace pathname changed during reservation",
        )
    }

    fn assert_current_publication_paths(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        self.assert_current_allocation_lock()?;
        self.assert_current_checkpoint_namespace(snapshot, store)
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
        let state_root = self
            .config
            .state_directory
            .try_clone_directory()
            .context("retain Node state root for kernel-NBD allocation")?;
        let allocation_lock = open_allocation_lock(&state_root)?;
        lock_exclusive_nonblocking(&allocation_lock)?;
        let permit = KernelNbdAllocationPermit {
            state_root,
            allocation_lock,
            snapshot: inspect_pool(&self.config, context)?,
        };
        permit.assert_current_allocation_lock()?;
        context.check_active()?;
        Ok(permit)
    }

    /// Serialize the complete durable-reservation read, deterministic free
    /// slot choice, and an actual [`FileCheckpointStore`] replacement.
    /// The accepted Desired Cat set and a fresh descriptor-stable checkpoint
    /// namespace are read while the allocator remains locked; a cached
    /// inventory projection is intentionally not accepted here. Returning a
    /// generic callback result would let a caller drop this permit before it
    /// had durably published the reservation, so this API deliberately returns
    /// only a [`StoredCheckpoint`].
    pub(crate) fn reserve_and_replace(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        predecessor: &StoredCheckpoint,
        build_checkpoint: impl FnOnce(HostPath) -> Result<RuntimeCheckpoint>,
    ) -> Result<StoredCheckpoint> {
        let permit = self.lock_and_inspect(context)?;
        context.check_active()?;
        let context_state_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Desired-effect state root for kernel-NBD reservation")?;
        ensure_same_directory(
            permit.state_root(),
            &context_state_root,
            "kernel-NBD Desired context and allocator use different directories",
        )?;
        let assigned_cats = context.accepted_full()?.assigned_cats()?;
        let snapshot = snapshot_runtime_checkpoint_namespace(
            permit.state_root(),
            context,
            assigned_cats,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?
        .context("kernel-NBD reservation requires a complete checkpoint namespace")?;
        permit.assert_current_publication_paths(&snapshot, store)?;
        anyhow::ensure!(
            snapshot.checkpoint(&predecessor.checkpoint().cat_id) == Some(predecessor.checkpoint()),
            "kernel-NBD predecessor is not the exact checkpoint-namespace value"
        );
        let reservations = KernelNbdReservations::from_snapshot(&snapshot)?;
        context.check_active()?;
        let selected = permit.select_free(&reservations)?;
        let replacement = build_checkpoint(selected)?;
        context.check_active()?;
        // The flock and namespace snapshots are descriptor-stable, but the
        // current state-root basenames could otherwise be renamed away and
        // recreated around the callback. Reopen both lexical paths before
        // publication so a reservation is never fsynced only into a detached
        // namespace or under a split allocation-lock domain.
        permit.assert_current_publication_paths(&snapshot, store)?;
        // `permit` remains live through FileCheckpointStore's file and parent
        // directory fsync barriers and is dropped only after publication.
        let persisted = store
            .replace(predecessor, &replacement)
            .context("persist kernel-NBD reservation checkpoint")?;
        // A same-uid Host-state mutator is outside the cooperating flock
        // protocol, but observing a post-publication lexical replacement must
        // still fail closed: the caller must not proceed to attach a device
        // from a checkpoint no longer reachable in the current namespace.
        permit.assert_current_publication_paths(&snapshot, store)?;
        Ok(persisted)
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

fn open_allocation_lock(directory: &File) -> Result<File> {
    let name = CString::new(ALLOCATION_LOCK_BASENAME).expect("fixed basename has no NUL");
    let file = open_at(
        directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0o600,
    )
    .context("open kernel-NBD allocation lock")?;
    validate_allocation_lock(&file)?;
    Ok(file)
}

fn reopen_allocation_lock(directory: &File) -> Result<File> {
    let name = CString::new(ALLOCATION_LOCK_BASENAME).expect("fixed basename has no NUL");
    let file = open_at(
        directory,
        &name,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .context("reopen current kernel-NBD allocation lock")?;
    validate_allocation_lock(&file)?;
    Ok(file)
}

fn validate_allocation_lock(file: &File) -> Result<Metadata> {
    let metadata = file
        .metadata()
        .context("inspect kernel-NBD allocation lock")?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.uid() == effective_user_id()
            && metadata.gid() == effective_group_id()
            && metadata.len() == 0,
        "kernel-NBD allocation lock has unsafe metadata"
    );
    Ok(metadata)
}

fn ensure_same_allocation_lock(left: &File, right: &File) -> Result<()> {
    let left = validate_allocation_lock(left)?;
    let right = validate_allocation_lock(right)?;
    anyhow::ensure!(
        left.dev() == right.dev() && left.ino() == right.ino(),
        "kernel-NBD allocation lock pathname changed while locked"
    );
    Ok(())
}

fn reopen_checkpoint_namespace(state_root: &File) -> Result<File> {
    let name = CString::new(CHECKPOINT_NAMESPACE).expect("fixed namespace has no NUL");
    let directory = open_at(
        state_root,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .context("reopen current kernel-NBD checkpoint namespace")?;
    validate_checkpoint_namespace(state_root, &directory)?;
    Ok(directory)
}

fn validate_checkpoint_namespace(state_root: &File, directory: &File) -> Result<Metadata> {
    let root = state_root
        .metadata()
        .context("inspect retained kernel-NBD state root")?;
    let metadata = directory
        .metadata()
        .context("inspect retained kernel-NBD checkpoint namespace")?;
    anyhow::ensure!(
        root.is_dir()
            && metadata.is_dir()
            && metadata.uid() == root.uid()
            && metadata.mode() & 0o022 == 0,
        "kernel-NBD checkpoint namespace has unsafe owner or mode"
    );
    Ok(metadata)
}

fn ensure_same_directory(left: &File, right: &File, mismatch: &'static str) -> Result<()> {
    let left = left
        .metadata()
        .context("inspect retained checkpoint namespace")?;
    let right = right
        .metadata()
        .context("inspect checkpoint store directory")?;
    anyhow::ensure!(
        left.is_dir() && right.is_dir() && left.dev() == right.dev() && left.ino() == right.ino(),
        mismatch
    );
    Ok(())
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
        AcquireOrigin, AdmissionInventoryAttestation, AgentSession, AssignedKind,
        AssignedPlacement, ContractVersion, DesiredReadSnapshot, DesiredRuntimeSpec, Durability,
        Epoch, FenceEpoch, Generation, GuestDeviceIdentity, GuestTransportEvidence, Ipv4Address,
        IsolatedIpv4Kind, LifecycleAdmission, MacAddress, NetworkConfig, NodeBootId,
        NodeObservation, RemoteHead, RequireIdleCheckpoint, Revision, RuntimeConfig, RuntimeTarget,
        RuntimeTransition, Sequence, ServingAuthorityProvenance, ServingBlockdIdentity,
        SessionBinding, Sha256Digest, UnixMillis, WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::RuntimeDesiredEffectAdmission;

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

    fn desired(cat: &str) -> DesiredRuntimeSpec {
        DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("ws_a"),
            cat_id: id(cat),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: id("node_a"),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            runtime: RuntimeConfig {
                vcpus: 1,
                memory_bytes: 1_073_741_824,
                boot_image_digest: Sha256Digest::from_bytes([8; 32]),
                guest_config_digest: Sha256Digest::from_bytes([9; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("net_a"),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: Vec::new(),
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([7; 32]),
        }
    }

    fn desired_effect_context(state: &Path, cats: &[&str]) -> RuntimeDesiredEffectContext {
        let node_boot_id = NodeBootId::new("a".repeat(32)).unwrap();
        let agent_instance_id = random('b');
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: id("node_a"),
            immutable_host_id: id("host_a"),
            node_boot_id: node_boot_id.clone(),
            agent_instance_id: agent_instance_id.clone(),
            agent_session_epoch: Epoch::new(1).unwrap(),
            registration_attempt_id: random('c'),
            guest_config_digest: Sha256Digest::from_bytes([6; 32]),
            lease_deadline_unix_ms: UnixMillis::new(2_000).unwrap(),
        };
        let binding = SessionBinding {
            node_id: session.node_id.clone(),
            node_boot_id: node_boot_id.clone(),
            agent_instance_id: agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
        };
        let read_position = Sequence::new(1).unwrap();
        let snapshot = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: binding,
            request_sequence: Sequence::new(1).unwrap(),
            read_position,
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(2_000).unwrap(),
            desired_specs: cats.iter().map(|cat| desired(cat)).collect(),
        };
        let inventory_digest = Sha256Digest::from_bytes([5; 32]);
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: random('d'),
            node_id: session.node_id.clone(),
            node_boot_id,
            agent_instance_id,
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(1).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            complete_inventory: true,
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest: Some(inventory_digest.clone()),
            inventory_read_position: Some(read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: Vec::new(),
            residue: Vec::new(),
        };
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest,
            inventory_read_position: read_position,
            accepted_at_unix_ms: UnixMillis::new(1_100).unwrap(),
        };
        let admission = RuntimeDesiredEffectAdmission::for_test(session, observation, attestation)
            .bind_assigned_cats_for_test(&snapshot);
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(state.to_path_buf()),
            Instant::now() + Duration::from_secs(5),
            admission,
        )
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
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let persisted = first
            .reserve_and_replace(&context, &store, &predecessor, |selected| {
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
            })
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
    fn reservation_rejects_checkpoint_namespace_rename_recreate_before_publication() {
        let fixture = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let detached_directory = fixture.state.join("checkpoints-detached");
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let target_name = format!("cat-{}.checkpoint.json", source.cat_id.as_str());
        let predecessor_bytes = fs::read(checkpoint_directory.join(&target_name)).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a"]);

        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |selected| {
                fs::rename(&checkpoint_directory, &detached_directory).unwrap();
                fs::create_dir(&checkpoint_directory).unwrap();
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
            })
            .unwrap_err();

        assert!(error.to_string().contains("pathname changed"), "{error:#}");
        assert!(!checkpoint_directory.join(&target_name).exists());
        assert_eq!(
            fs::read(detached_directory.join(&target_name)).unwrap(),
            predecessor_bytes
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
    }

    #[test]
    fn reservation_never_authorizes_attach_after_post_publish_namespace_replacement() {
        let fixture = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let detached_directory = fixture.state.join("checkpoints-post-publish-detached");
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let target_name = format!("cat-{}.checkpoint.json", source.cat_id.as_str());
        let hook_checkpoint_directory = checkpoint_directory.clone();
        let hook_detached_directory = detached_directory.clone();
        store.before_publish_once(move |_| {
            fs::rename(&hook_checkpoint_directory, &hook_detached_directory).unwrap();
            fs::create_dir(&hook_checkpoint_directory).unwrap();
        });
        let context = desired_effect_context(&fixture.state, &["cat_a"]);

        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |selected| {
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
            })
            .unwrap_err();

        assert!(error.to_string().contains("pathname changed"), "{error:#}");
        assert!(!checkpoint_directory.join(&target_name).exists());
        let detached = store.load().unwrap().unwrap();
        let ReconcileStep::PrepareDevice {
            frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
            ..
        } = &detached.checkpoint().step
        else {
            panic!("detached publication must remain PrepareDevice")
        };
        assert_eq!(device_path, &host("/dev/nbd0"));
        assert!(detached_directory.join(&target_name).exists());
    }

    #[test]
    fn reservation_rejects_allocation_lock_rename_recreate_before_publication() {
        let fixture = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let lock_path = fixture.state.join(ALLOCATION_LOCK_BASENAME);
        let detached_lock_path = fixture.state.join("kernel-nbd-allocation.detached");

        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |selected| {
                fs::rename(&lock_path, &detached_lock_path).unwrap();
                fs::write(&lock_path, b"").unwrap();
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
                let replacement_identity = fs::metadata(&lock_path).unwrap();
                let mut replacement = predecessor.checkpoint().clone();
                let ReconcileStep::PrepareDevice {
                    frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
                    ..
                } = &mut replacement.step
                else {
                    panic!("fixture must be a kernel-NBD PrepareDevice checkpoint")
                };
                *device_path = selected;
                assert_ne!(
                    replacement_identity.ino(),
                    fs::metadata(&detached_lock_path).unwrap().ino()
                );
                Ok(replacement)
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("allocation lock pathname changed"),
            "{error:#}"
        );
        assert!(detached_lock_path.exists());
        assert_eq!(fs::read(&lock_path).unwrap(), b"");
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
    }

    #[test]
    fn reservation_rejects_cross_root_store_and_stale_predecessor() {
        let fixture = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join("checkpoints"), &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();

        let other = tempfile::tempdir().unwrap();
        let other_state = other.path().join("state");
        fs::create_dir(&other_state).unwrap();
        let other_store =
            FileCheckpointStore::open(&other_state.join("checkpoints"), &source.cat_id).unwrap();
        let other_predecessor = other_store.create(&source).unwrap();

        let cross_root = desired_effect_context(&other_state, &["cat_a"]);
        let error = port
            .reserve_and_replace(&cross_root, &store, &predecessor, |_| {
                panic!("cross-root reservation must fail before checkpoint construction")
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("different directories"),
            "{error:#}"
        );

        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let error = port
            .reserve_and_replace(&context, &other_store, &other_predecessor, |_| {
                panic!("cross-store reservation must fail before checkpoint construction")
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("different directories"),
            "{error:#}"
        );

        let mut successor = source.clone();
        successor.updated_at_unix_ms = UnixMillis::new(2).unwrap();
        let successor = store.replace(&predecessor, &successor).unwrap();
        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |_| {
                panic!("stale predecessor must fail before checkpoint construction")
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not the exact checkpoint-namespace value"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            successor.checkpoint()
        );
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

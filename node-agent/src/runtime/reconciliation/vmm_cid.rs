//! Node-global, checkpoint-first Guest CID reservation for `StartRuntime`.
//!
//! The allocation flock covers one complete checkpoint namespace snapshot,
//! one exact live-VMM CID snapshot and the per-Cat checkpoint fsync.  This
//! module never starts a VMM; the next accepted full inventory owns that one
//! physical effect.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    GuestTransportEvidence, Id, RandomId128, ReconcileStep, RuntimeCheckpoint,
};

use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimePhysicalReadContext};
use crate::state_directory::StateDirectory;

use super::checkpoint::{revalidate_checkpoint_namespace, FileCheckpointStore, StoredCheckpoint};
use super::clean_slate_probes::{
    snapshot_runtime_checkpoint_namespace, RuntimeCheckpointNamespaceSnapshot,
    CHECKPOINT_NAMESPACE, RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
};

const VMM_ALLOCATION_LOCK_BASENAME: &str = "vmm-allocation.lock";
const FIRST_GUEST_CID: u32 = 3;
const LAST_GUEST_CID: u32 = u32::MAX - 1;
const MAX_ASSIGNED_CATS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VmmCidOwner {
    cat_id: Id,
    runtime_incarnation: RandomId128,
}

impl VmmCidOwner {
    pub(crate) fn new(cat_id: Id, runtime_incarnation: RandomId128) -> Self {
        Self {
            cat_id,
            runtime_incarnation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExactLiveVmmCid {
    owner: VmmCidOwner,
    guest_cid: u32,
}

impl ExactLiveVmmCid {
    pub(crate) fn new(owner: VmmCidOwner, guest_cid: u32) -> Result<Self> {
        ensure_guest_cid(guest_cid)?;
        Ok(Self { owner, guest_cid })
    }
}

/// Complete provider-private projection of one Node-global VMM scan.
///
/// A platform scanner may construct this only after rejecting every foreign,
/// malformed or ambiguous VMM.  The allocator compares two such snapshots
/// under the same flock before publishing a reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmmCidInventorySnapshot {
    exact: Vec<ExactLiveVmmCid>,
}

impl VmmCidInventorySnapshot {
    pub(crate) fn try_new(mut exact: Vec<ExactLiveVmmCid>) -> Result<Self> {
        anyhow::ensure!(
            exact.len() <= MAX_ASSIGNED_CATS,
            "live VMM CID inventory exceeds the assigned-Cat bound"
        );
        exact.sort();
        let mut by_owner = BTreeMap::<VmmCidOwner, u32>::new();
        let mut by_cid = BTreeMap::<u32, VmmCidOwner>::new();
        for entry in &exact {
            if let Some(existing) = by_owner.insert(entry.owner.clone(), entry.guest_cid) {
                anyhow::ensure!(
                    existing == entry.guest_cid,
                    "one live VMM identity reports more than one Guest CID"
                );
                anyhow::bail!("Node-global VMM scan duplicates one exact process")
            }
            if let Some(existing) = by_cid.insert(entry.guest_cid, entry.owner.clone()) {
                anyhow::ensure!(
                    existing == entry.owner,
                    "one Guest CID is used by multiple live VMMs"
                );
                anyhow::bail!("Node-global VMM scan duplicates one exact process")
            }
        }
        Ok(Self { exact })
    }

    fn validate_against(&self, reservations: &VmmCidReservations) -> Result<()> {
        for live in &self.exact {
            reservations.assert_contains(live)?;
        }
        Ok(())
    }
}

pub(crate) mod inventory_port_sealed {
    pub(crate) trait Sealed {}
}

pub(crate) trait VmmCidInventoryPort: inventory_port_sealed::Sealed + Send + Sync {
    fn inspect(&self, context: &RuntimeDesiredEffectContext) -> Result<VmmCidInventorySnapshot>;
}

/// Test-only live-CID projection from the exact accepted full-inventory
/// admission that opened this Desired effect batch.
///
/// The complete clean-slate scanner already rejected unavailable, malformed,
/// conflicting, duplicate and foreign managed processes before it could mint
/// `NodeGlobalManagedProcessAdmission`. Reopening `/proc`, systemd or public
/// Production uses the full Node-global process bridge, which reopens the same
/// admitted closed set under the CID allocation flock. Tests that exercise
/// the allocator in isolation use this projection after explicitly building a
/// sealed admission. A legitimately absent VMM contributes no live CID; a
/// missing admission fails rather than becoming an unproven empty inventory.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PlatformExactVmmCidInventoryPort;

#[cfg(test)]
impl inventory_port_sealed::Sealed for PlatformExactVmmCidInventoryPort {}

#[cfg(test)]
impl VmmCidInventoryPort for PlatformExactVmmCidInventoryPort {
    fn inspect(&self, context: &RuntimeDesiredEffectContext) -> Result<VmmCidInventorySnapshot> {
        context.check_active()?;
        let _node_global_effect = context.lock_node_global_effect()?;
        let accepted = context.accepted_full()?;
        let admission = context.node_global_process()?;
        anyhow::ensure!(
            admission.matches_observation(accepted.observation()),
            "VMM CID inventory admission is not bound to the accepted full observation"
        );
        let exact = admission
            .exact_vmm_proofs()
            .map(|proof| {
                let (cat_id, runtime_incarnation, guest_cid) = proof.guest_cid_identity();
                ExactLiveVmmCid::new(
                    VmmCidOwner::new(cat_id.clone(), runtime_incarnation.clone()),
                    guest_cid,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        context.check_active()?;
        VmmCidInventorySnapshot::try_new(exact)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmmCidReservation {
    owner: VmmCidOwner,
    guest_cid: u32,
}

#[derive(Debug, Clone, Default)]
struct VmmCidReservations {
    by_cid: BTreeMap<u32, VmmCidReservation>,
    by_owner: BTreeMap<VmmCidOwner, VmmCidReservation>,
}

impl VmmCidReservations {
    fn from_snapshot(snapshot: &RuntimeCheckpointNamespaceSnapshot) -> Result<Self> {
        let mut reservations = Self::default();
        for checkpoint in snapshot.iter_checkpoints() {
            reservations.collect_checkpoint(checkpoint)?;
        }
        anyhow::ensure!(
            reservations.by_owner.len() <= MAX_ASSIGNED_CATS,
            "durable VMM CID reservations exceed the assigned-Cat bound"
        );
        Ok(reservations)
    }

    fn collect_checkpoint(&mut self, checkpoint: &RuntimeCheckpoint) -> Result<()> {
        if let ReconcileStep::StartRuntime {
            runtime_incarnation,
            guest_cid,
            ..
        } = &checkpoint.step
        {
            anyhow::ensure!(
                checkpoint.runtime_incarnation.as_ref() == Some(runtime_incarnation),
                "StartRuntime CID reservation disagrees with its checkpoint incarnation"
            );
            self.insert(VmmCidReservation {
                owner: VmmCidOwner::new(checkpoint.cat_id.clone(), runtime_incarnation.clone()),
                guest_cid: *guest_cid,
            })?;
        }
        if let GuestTransportEvidence::VsockReady {
            runtime_incarnation,
            guest_cid,
            ..
        } = &checkpoint.guest_transport
        {
            anyhow::ensure!(
                checkpoint.runtime_incarnation.as_ref() == Some(runtime_incarnation),
                "Guest transport CID reservation disagrees with its checkpoint incarnation"
            );
            self.insert(VmmCidReservation {
                owner: VmmCidOwner::new(checkpoint.cat_id.clone(), runtime_incarnation.clone()),
                guest_cid: *guest_cid,
            })?;
        }
        Ok(())
    }

    fn insert(&mut self, reservation: VmmCidReservation) -> Result<()> {
        ensure_guest_cid(reservation.guest_cid)?;
        if let Some(existing) = self.by_cid.get(&reservation.guest_cid) {
            anyhow::ensure!(
                existing == &reservation,
                "Guest CID is reused by another durable Runtime"
            );
        }
        if let Some(existing) = self.by_owner.get(&reservation.owner) {
            anyhow::ensure!(
                existing == &reservation,
                "one Runtime incarnation reserves more than one Guest CID"
            );
        }
        self.by_cid
            .insert(reservation.guest_cid, reservation.clone());
        self.by_owner.insert(reservation.owner.clone(), reservation);
        Ok(())
    }

    fn assert_contains(&self, live: &ExactLiveVmmCid) -> Result<()> {
        let expected = VmmCidReservation {
            owner: live.owner.clone(),
            guest_cid: live.guest_cid,
        };
        anyhow::ensure!(
            self.by_cid.get(&live.guest_cid) == Some(&expected)
                && self.by_owner.get(&live.owner) == Some(&expected),
            "live VMM CID lacks one exact durable reservation"
        );
        Ok(())
    }

    fn select_free(&self) -> Result<u32> {
        anyhow::ensure!(
            self.by_cid.len() <= MAX_ASSIGNED_CATS,
            "VMM CID reservation count exceeds the assigned-Cat bound"
        );
        for offset in 0..=self.by_cid.len() {
            let offset = u32::try_from(offset).context("VMM CID candidate offset exceeds u32")?;
            let candidate = FIRST_GUEST_CID
                .checked_add(offset)
                .context("VMM CID candidate overflow")?;
            anyhow::ensure!(
                candidate <= LAST_GUEST_CID,
                "VMM CID candidate exceeds the closed range"
            );
            if !self.by_cid.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        anyhow::bail!("bounded VMM CID candidate set contains no free value")
    }
}

fn ensure_guest_cid(guest_cid: u32) -> Result<()> {
    anyhow::ensure!(
        (FIRST_GUEST_CID..=LAST_GUEST_CID).contains(&guest_cid),
        "Guest CID is reserved or VMADDR_CID_ANY"
    );
    Ok(())
}

#[derive(Debug)]
struct VmmCidAllocationPermit {
    state_root: File,
    lock: File,
    acquired_lock_metadata: VmmAllocationLockMetadata,
    lock_held: bool,
}

impl VmmCidAllocationPermit {
    fn assert_current_paths(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        anyhow::ensure!(self.lock_held, "VMM CID allocation lock was released");
        let reopened = open_vmm_allocation_lock(&self.state_root)?;
        self.assert_current_lock(&reopened)?;
        revalidate_checkpoint_namespace(
            &self.state_root,
            CHECKPOINT_NAMESPACE,
            &[snapshot.retained_directory(), store.retained_directory()],
        )
        .context("VMM CID checkpoint namespace changed")?;
        Ok(())
    }

    fn assert_current_lock(&self, reopened: &File) -> Result<()> {
        let retained = self
            .lock
            .metadata()
            .context("inspect retained VMM allocation lock")?;
        let reopened = reopened
            .metadata()
            .context("inspect reopened VMM allocation lock")?;
        anyhow::ensure!(
            VmmAllocationLockMetadata::from(&retained) == self.acquired_lock_metadata
                && VmmAllocationLockMetadata::from(&reopened) == self.acquired_lock_metadata,
            "VMM allocation lock changed since its flock was acquired"
        );
        Ok(())
    }

    fn unlock(&mut self) -> Result<()> {
        if !self.lock_held {
            return Ok(());
        }
        unlock_file(&self.lock).context("release Node-global VMM allocation lock")?;
        self.lock_held = false;
        Ok(())
    }

    fn release(mut self) -> Result<()> {
        self.unlock()
    }
}

impl Drop for VmmCidAllocationPermit {
    fn drop(&mut self) {
        // Explicit LOCK_UN is required because a forked pre-exec child may
        // temporarily retain this open-file description despite O_CLOEXEC.
        let _ = self.unlock();
    }
}

#[cfg(test)]
type AfterReplaceHook = Arc<dyn Fn(&RuntimeDesiredEffectContext) -> Result<()> + Send + Sync>;

pub(crate) struct VmmCidAllocationPort {
    state_directory: StateDirectory,
    inventory: Arc<dyn VmmCidInventoryPort>,
    #[cfg(test)]
    after_replace: Option<AfterReplaceHook>,
}

impl std::fmt::Debug for VmmCidAllocationPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VmmCidAllocationPort")
            .field("state_directory", &self.state_directory)
            .field("inventory", &"sealed")
            .finish()
    }
}

impl VmmCidAllocationPort {
    pub(crate) fn new(
        state_directory: StateDirectory,
        inventory: Arc<dyn VmmCidInventoryPort>,
    ) -> Self {
        Self {
            state_directory,
            inventory,
            #[cfg(test)]
            after_replace: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_after_replace(mut self, hook: AfterReplaceHook) -> Self {
        self.after_replace = Some(hook);
        self
    }

    fn lock(&self, context: &dyn RuntimePhysicalReadContext) -> Result<VmmCidAllocationPermit> {
        context.check_active()?;
        let state_root = self
            .state_directory
            .try_clone_directory()
            .context("retain Node state root for VMM CID allocation")?;
        let lock = open_vmm_allocation_lock(&state_root)?;
        lock_exclusive_nonblocking(&lock)?;
        let acquired_lock_metadata = VmmAllocationLockMetadata::from(
            &lock
                .metadata()
                .context("inspect acquired VMM allocation lock")?,
        );
        let permit = VmmCidAllocationPermit {
            state_root,
            lock,
            acquired_lock_metadata,
            lock_held: true,
        };
        let reopened = open_vmm_allocation_lock(&permit.state_root)?;
        permit.assert_current_lock(&reopened)?;
        context.check_active()?;
        Ok(permit)
    }

    pub(crate) fn reserve_and_replace(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        predecessor: &StoredCheckpoint,
        mut revalidate_authority: impl FnMut() -> Result<()>,
        build: impl FnOnce(u32) -> Result<RuntimeCheckpoint>,
    ) -> Result<StoredCheckpoint> {
        let permit = self.lock(context)?;
        let context_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Desired-effect state root for VMM CID reservation")?;
        ensure_same_file(
            &permit.state_root,
            &context_root,
            "VMM allocator and Desired effect use different state roots",
        )?;
        let assigned = context.accepted_full()?.assigned_cats()?;
        let snapshot = snapshot_runtime_checkpoint_namespace(
            &permit.state_root,
            context,
            assigned,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?
        .context("VMM CID reservation requires a complete checkpoint namespace")?;
        permit.assert_current_paths(&snapshot, store)?;
        anyhow::ensure!(
            snapshot.checkpoint(&predecessor.checkpoint().cat_id) == Some(predecessor.checkpoint()),
            "PrepareNetwork predecessor is not current in the complete namespace"
        );
        anyhow::ensure!(
            matches!(
                predecessor.checkpoint().step,
                ReconcileStep::PrepareNetwork { .. }
            ) && predecessor.checkpoint().runtime_incarnation.is_none(),
            "VMM CID reservation predecessor is not pre-launch PrepareNetwork"
        );
        let reservations = VmmCidReservations::from_snapshot(&snapshot)?;
        let physical_before = self.inventory.inspect(context)?;
        physical_before.validate_against(&reservations)?;
        let selected = reservations.select_free()?;
        // The accepted full scan is only the admission that opened this
        // batch. Reopen every external launch authority after taking the
        // Node-global CID flock, before constructing a successor from it.
        revalidate_authority()?;
        context.check_active()?;
        let replacement = build(selected)?;
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            guest_cid,
            ..
        } = &replacement.step
        else {
            anyhow::bail!("VMM CID allocator callback did not construct StartRuntime")
        };
        anyhow::ensure!(
            replacement.cat_id == predecessor.checkpoint().cat_id
                && replacement.runtime_incarnation.as_ref() == Some(runtime_incarnation)
                && *guest_cid == selected,
            "VMM CID allocator callback changed its selected CID or Runtime identity"
        );
        ensure_start_runtime_successor(predecessor.checkpoint(), &replacement)?;
        let mut prospective = reservations;
        prospective.insert(VmmCidReservation {
            owner: VmmCidOwner::new(replacement.cat_id.clone(), runtime_incarnation.clone()),
            guest_cid: selected,
        })?;
        let physical_after = self.inventory.inspect(context)?;
        anyhow::ensure!(
            physical_after == physical_before,
            "Node-global live VMM CID inventory changed before reservation publication"
        );
        physical_after.validate_against(&prospective)?;
        // Close the other side of the CID critical section. In particular,
        // an exact TAP, serving process, device, Volume lease or installed
        // launch artifact may not drift while the allocator was selecting a
        // CID and validating the complete live-VMM namespace.
        revalidate_authority()?;
        context.check_active()?;
        permit.assert_current_paths(&snapshot, store)?;
        let persisted = store
            .replace(predecessor, &replacement)
            .context("persist StartRuntime CID reservation checkpoint")?;
        #[cfg(test)]
        if let Some(hook) = &self.after_replace {
            hook(context)?;
        }
        permit.assert_current_paths(&snapshot, store)?;
        // Publication is durable even when cancellation wins its final race.
        // Return an error so this expired admission cannot be reported as a
        // successful effect; the next accepted full adopts the reservation.
        context.check_active()?;
        permit.release()?;
        Ok(persisted)
    }
}

fn ensure_start_runtime_successor(
    predecessor: &RuntimeCheckpoint,
    replacement: &RuntimeCheckpoint,
) -> Result<()> {
    let ReconcileStep::PrepareNetwork {
        network: predecessor_network,
        devices: predecessor_devices,
    } = &predecessor.step
    else {
        anyhow::bail!("VMM CID predecessor is not PrepareNetwork")
    };
    let ReconcileStep::StartRuntime {
        runtime_incarnation,
        network,
        devices,
        ..
    } = &replacement.step
    else {
        anyhow::bail!("VMM CID replacement is not StartRuntime")
    };
    anyhow::ensure!(
        replacement.version == predecessor.version
            && replacement.cat_id == predecessor.cat_id
            && replacement.node_id == predecessor.node_id
            && replacement.placement_epoch == predecessor.placement_epoch
            && replacement.desired_revision == predecessor.desired_revision
            && replacement.spec_digest == predecessor.spec_digest
            && predecessor.runtime_incarnation.is_none()
            && replacement.runtime_incarnation.as_ref() == Some(runtime_incarnation)
            && replacement.stable_state.is_none()
            && network.as_ref() == predecessor_network
            && devices == predecessor_devices
            && replacement.updated_at_unix_ms > predecessor.updated_at_unix_ms,
        "VMM CID replacement is not the exact monotonic PrepareNetwork successor"
    );
    Ok(())
}

fn open_vmm_allocation_lock(root: &File) -> Result<File> {
    let name = CString::new(VMM_ALLOCATION_LOCK_BASENAME)
        .expect("VMM allocation lock basename is static ASCII");
    // SAFETY: root is a retained directory and name is a live NUL-terminated
    // basename. A successful descriptor is immediately transferred to File.
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error()).context("open VMM allocation lock");
    }
    // SAFETY: openat returned one new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata().context("inspect VMM allocation lock")?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == effective_user_id()
            && metadata.mode() & 0o7777 == 0o600,
        "VMM allocation lock has unsafe metadata"
    );
    Ok(file)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VmmAllocationLockMetadata {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl VmmAllocationLockMetadata {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn lock_exclusive_nonblocking(file: &File) -> Result<()> {
    loop {
        // SAFETY: file is a live descriptor and flock retains no Rust memory.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(source).context("acquire Node-global VMM allocation lock");
    }
}

fn unlock_file(file: &File) -> Result<()> {
    loop {
        // SAFETY: file is a live descriptor and flock retains no Rust memory.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(source).context("unlock Node-global VMM allocation lock");
    }
}

fn ensure_same_file(first: &File, second: &File, message: &'static str) -> Result<()> {
    let first = first.metadata().context("inspect retained VMM file")?;
    let second = second.metadata().context("inspect reopened VMM file")?;
    anyhow::ensure!(
        first.dev() == second.dev()
            && first.ino() == second.ino()
            && first.uid() == second.uid()
            && first.gid() == second.gid()
            && first.mode() == second.mode()
            && first.nlink() == second.nlink(),
        "{message}"
    );
    Ok(())
}

fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no pointer arguments and reads process credentials.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, AdmissionInventoryAttestation,
        AgentSession, ContractVersion, DesiredReadSnapshot, Epoch, GuestBootId, HostPath,
        NodeBootId, NodeObservation, Sequence, SessionBinding, Sha256Digest, UnixMillis,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::RuntimeDesiredEffectAdmission;

    use super::*;

    const PREPARE_NETWORK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-prepare-network-checkpoint.json"
    ));
    const START_RUNTIME: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
    ));
    const DESIRED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-desired.json"
    ));

    fn random(byte: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(byte, 32).collect::<String>()).unwrap()
    }

    fn prepare_network() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(PREPARE_NETWORK).unwrap()
    }

    fn start_runtime() -> RuntimeCheckpoint {
        let mut checkpoint = decode_runtime_checkpoint(START_RUNTIME).unwrap();
        checkpoint.updated_at_unix_ms =
            UnixMillis::new(checkpoint.updated_at_unix_ms.get() + 1).unwrap();
        checkpoint
    }

    fn start_runtime_variant(
        cat_id: &str,
        incarnation_digit: char,
        process_token_digit: char,
        guest_cid: u32,
    ) -> RuntimeCheckpoint {
        let source = std::str::from_utf8(START_RUNTIME).unwrap();
        let source = source
            .replace("cat_01", cat_id)
            .replace(&"5".repeat(32), &incarnation_digit.to_string().repeat(32))
            .replace(&"6".repeat(32), &process_token_digit.to_string().repeat(32))
            .replace("\"guest_cid\":3", &format!("\"guest_cid\":{guest_cid}"));
        decode_runtime_checkpoint(source.as_bytes()).unwrap()
    }

    fn vmm_expectation(
        checkpoint: RuntimeCheckpoint,
    ) -> super::super::vmm_process::VmmProcessExpectation {
        let checkpoint_path = HostPath::new(format!(
            "/var/lib/cats/node/checkpoints/{}.json",
            checkpoint.cat_id.as_str()
        ))
        .unwrap();
        super::super::vmm_process::VmmProcessExpectation::from_checkpoint(checkpoint)
            .unwrap()
            .with_checkpoint_path(checkpoint_path)
            .unwrap()
    }

    fn context(state: &Path, cats: &[Id]) -> RuntimeDesiredEffectContext {
        let node_boot_id = NodeBootId::new("a".repeat(32)).unwrap();
        let agent_instance_id = random('b');
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: Id::new("node_a").unwrap(),
            immutable_host_id: Id::new("host_a").unwrap(),
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
        let desired = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: binding,
            request_sequence: Sequence::new(1).unwrap(),
            read_position,
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(2_000).unwrap(),
            desired_specs: cats
                .iter()
                .map(|cat_id| {
                    let mut desired = decode_desired_runtime_spec(DESIRED).unwrap();
                    desired.cat_id = cat_id.clone();
                    desired
                })
                .collect(),
        };
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
            inventory_digest: Some(Sha256Digest::from_bytes([5; 32])),
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
            inventory_digest: Sha256Digest::from_bytes([5; 32]),
            inventory_read_position: read_position,
            accepted_at_unix_ms: UnixMillis::new(1_100).unwrap(),
        };
        let admission = RuntimeDesiredEffectAdmission::for_test(session, observation, attestation)
            .bind_assigned_cats_for_test(&desired);
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(state.to_path_buf()),
            Instant::now() + Duration::from_secs(10),
            admission,
        )
    }

    fn platform_context(
        state: &Path,
        cats: &[Id],
        managed: super::super::root_provision_process::NodeGlobalManagedProcessAdmission,
    ) -> RuntimeDesiredEffectContext {
        let node_boot_id = NodeBootId::new("2".repeat(32)).unwrap();
        let agent_instance_id = random('3');
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: Id::new("node_test").unwrap(),
            immutable_host_id: Id::new("host_test").unwrap(),
            node_boot_id: node_boot_id.clone(),
            agent_instance_id: agent_instance_id.clone(),
            agent_session_epoch: Epoch::new(1).unwrap(),
            registration_attempt_id: random('e'),
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
        let desired = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: binding,
            request_sequence: Sequence::new(1).unwrap(),
            read_position,
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(2_000).unwrap(),
            desired_specs: cats
                .iter()
                .map(|cat_id| {
                    let mut desired = decode_desired_runtime_spec(DESIRED).unwrap();
                    desired.cat_id = cat_id.clone();
                    desired
                })
                .collect(),
        };
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: random('1'),
            node_id: session.node_id.clone(),
            node_boot_id,
            agent_instance_id,
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(1).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            complete_inventory: true,
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest: Some(Sha256Digest::from_bytes([4; 32])),
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
            inventory_digest: Sha256Digest::from_bytes([4; 32]),
            inventory_read_position: read_position,
            accepted_at_unix_ms: UnixMillis::new(1_100).unwrap(),
        };
        let admission = RuntimeDesiredEffectAdmission::for_test(session, observation, attestation)
            .bind_assigned_cats_for_test(&desired);
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(state.to_path_buf()),
            Instant::now() + Duration::from_secs(10),
            admission,
        )
        .with_node_global_process_for_test(managed)
    }

    #[derive(Debug)]
    struct FakeInventory {
        snapshots: Mutex<VecDeque<VmmCidInventorySnapshot>>,
    }

    impl FakeInventory {
        fn stable(snapshot: VmmCidInventorySnapshot) -> Self {
            Self {
                snapshots: Mutex::new(VecDeque::from([snapshot])),
            }
        }

        fn changing(snapshots: impl IntoIterator<Item = VmmCidInventorySnapshot>) -> Self {
            Self {
                snapshots: Mutex::new(snapshots.into_iter().collect()),
            }
        }
    }

    impl inventory_port_sealed::Sealed for FakeInventory {}

    impl VmmCidInventoryPort for FakeInventory {
        fn inspect(
            &self,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmCidInventorySnapshot> {
            context.check_active()?;
            let mut snapshots = self.snapshots.lock().unwrap();
            if snapshots.len() > 1 {
                return Ok(snapshots.pop_front().unwrap());
            }
            snapshots
                .front()
                .cloned()
                .context("fake VMM CID inventory is exhausted")
        }
    }

    #[test]
    fn platform_inventory_projects_sorted_exact_vmm_cids_from_one_admission() {
        let fixture = Fixture::new();
        let expected_b = vmm_expectation(start_runtime_variant("cat_02", 'e', 'f', 4));
        let expected_a = vmm_expectation(start_runtime_variant("cat_01", '5', '6', 3));
        let cat_b = expected_b.cat_id().clone();
        let cat_a = expected_a.cat_id().clone();
        let proof_b = expected_b
            .clone()
            .prove_exact_process(expected_b.exact_evidence_for_test(4_202))
            .unwrap();
        let proof_a = expected_a
            .clone()
            .prove_exact_process(expected_a.exact_evidence_for_test(4_201))
            .unwrap();
        let managed = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_vmms(
            BTreeMap::from([
                (cat_b.clone(), expected_b),
                (cat_a.clone(), expected_a),
            ]),
            BTreeMap::from([(cat_b.clone(), proof_b), (cat_a.clone(), proof_a)]),
        )
        .unwrap()
        .into_admission_for_test();
        let context = platform_context(&fixture.state, &[cat_b, cat_a], managed);

        let snapshot = PlatformExactVmmCidInventoryPort.inspect(&context).unwrap();

        assert_eq!(snapshot.exact.len(), 2);
        assert_eq!(snapshot.exact[0].owner.cat_id.as_str(), "cat_01");
        assert_eq!(
            snapshot.exact[0].owner.runtime_incarnation.as_str(),
            &"5".repeat(32)
        );
        assert_eq!(snapshot.exact[0].guest_cid, 3);
        assert_eq!(snapshot.exact[1].owner.cat_id.as_str(), "cat_02");
        assert_eq!(
            snapshot.exact[1].owner.runtime_incarnation.as_str(),
            &"e".repeat(32)
        );
        assert_eq!(snapshot.exact[1].guest_cid, 4);
    }

    #[test]
    fn platform_inventory_accepts_empty_only_from_scanner_sealed_absence() {
        let fixture = Fixture::new();
        let expected = vmm_expectation(start_runtime_variant("cat_01", '5', '6', 3));
        let cat_id = expected.cat_id().clone();
        let managed = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_vmms(BTreeMap::from([(cat_id.clone(), expected)]), BTreeMap::new())
        .unwrap()
        .into_admission_for_test();
        let context = platform_context(&fixture.state, &[cat_id], managed);

        let snapshot = PlatformExactVmmCidInventoryPort.inspect(&context).unwrap();

        assert!(snapshot.exact.is_empty());
    }

    #[test]
    fn platform_inventory_rejects_missing_or_unbound_global_admission() {
        let fixture = Fixture::new();
        let context = context(&fixture.state, &[]);
        assert!(PlatformExactVmmCidInventoryPort.inspect(&context).is_err());

        let managed = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .into_admission_for_test();
        let context = context.with_node_global_process_for_test(managed);
        assert!(PlatformExactVmmCidInventoryPort.inspect(&context).is_err());
    }

    struct Fixture {
        _temp: TempDir,
        state: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let state = temp.path().join("state");
            fs::create_dir(&state).unwrap();
            Self { _temp: temp, state }
        }

        fn store(&self, checkpoint: &RuntimeCheckpoint) -> FileCheckpointStore {
            FileCheckpointStore::open(&self.state.join(CHECKPOINT_NAMESPACE), &checkpoint.cat_id)
                .unwrap()
        }
    }

    struct TestPhysicalContext {
        deadline: Instant,
    }

    impl TestPhysicalContext {
        fn active() -> Self {
            Self {
                deadline: Instant::now() + Duration::from_secs(5),
            }
        }
    }

    impl RuntimePhysicalReadContext for TestPhysicalContext {
        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn check_active(&self) -> Result<()> {
            anyhow::ensure!(Instant::now() < self.deadline, "test deadline expired");
            Ok(())
        }
    }

    #[test]
    fn bounded_selector_uses_only_occupied_count_plus_one_candidates() {
        let mut reservations = VmmCidReservations::default();
        for offset in 0..MAX_ASSIGNED_CATS {
            reservations
                .insert(VmmCidReservation {
                    owner: VmmCidOwner::new(
                        Id::new(format!("cat_{offset}")).unwrap(),
                        RandomId128::new(format!("{:032x}", offset + 1)).unwrap(),
                    ),
                    guest_cid: FIRST_GUEST_CID + u32::try_from(offset).unwrap(),
                })
                .unwrap();
        }
        assert_eq!(
            reservations.select_free().unwrap(),
            FIRST_GUEST_CID + u32::try_from(MAX_ASSIGNED_CATS).unwrap()
        );
    }

    #[test]
    fn duplicate_durable_or_live_cids_are_rejected() {
        let owner_a = VmmCidOwner::new(Id::new("cat_a").unwrap(), random('a'));
        let owner_b = VmmCidOwner::new(Id::new("cat_b").unwrap(), random('b'));
        let mut reservations = VmmCidReservations::default();
        reservations
            .insert(VmmCidReservation {
                owner: owner_a.clone(),
                guest_cid: 3,
            })
            .unwrap();
        assert!(reservations
            .insert(VmmCidReservation {
                owner: owner_b.clone(),
                guest_cid: 3,
            })
            .is_err());
        assert!(VmmCidInventorySnapshot::try_new(vec![
            ExactLiveVmmCid::new(owner_a, 3).unwrap(),
            ExactLiveVmmCid::new(owner_b, 3).unwrap(),
        ])
        .is_err());
    }

    #[test]
    fn start_step_and_ready_guest_transport_join_one_exact_reservation() {
        let mut checkpoint = start_runtime();
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            guest_cid,
            ..
        } = &checkpoint.step
        else {
            unreachable!()
        };
        let owner = VmmCidOwner::new(checkpoint.cat_id.clone(), runtime_incarnation.clone());
        let cid = *guest_cid;
        checkpoint.guest_transport = GuestTransportEvidence::VsockReady {
            runtime_incarnation: runtime_incarnation.clone(),
            guest_cid: cid,
            guest_port: 5000,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_boot_id: GuestBootId::new("e".repeat(32)).unwrap(),
        };
        let mut reservations = VmmCidReservations::default();
        reservations.collect_checkpoint(&checkpoint).unwrap();
        assert_eq!(reservations.select_free().unwrap(), cid + 1);
        VmmCidInventorySnapshot::try_new(vec![ExactLiveVmmCid::new(owner, cid).unwrap()])
            .unwrap()
            .validate_against(&reservations)
            .unwrap();
    }

    #[test]
    fn reservation_persists_the_exact_selected_start_runtime_cid() {
        let fixture = Fixture::new();
        let predecessor_checkpoint = prepare_network();
        let store = fixture.store(&predecessor_checkpoint);
        let predecessor = store.create(&predecessor_checkpoint).unwrap();
        let inventory = Arc::new(FakeInventory::stable(
            VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
        ));
        let port =
            VmmCidAllocationPort::new(StateDirectory::unanchored(fixture.state.clone()), inventory);
        let persisted = port
            .reserve_and_replace(
                &context(
                    &fixture.state,
                    std::slice::from_ref(&predecessor_checkpoint.cat_id),
                ),
                &store,
                &predecessor,
                || Ok(()),
                |selected| {
                    let mut replacement = start_runtime();
                    let ReconcileStep::StartRuntime { guest_cid, .. } = &mut replacement.step
                    else {
                        unreachable!()
                    };
                    *guest_cid = selected;
                    Ok(replacement)
                },
            )
            .unwrap();
        let ReconcileStep::StartRuntime { guest_cid, .. } = persisted.checkpoint().step else {
            panic!("CID reservation did not publish StartRuntime")
        };
        assert_eq!(guest_cid, FIRST_GUEST_CID);
        port.lock(&TestPhysicalContext::active()).unwrap();
    }

    #[test]
    fn reservation_revalidates_external_authority_across_the_cid_critical_section() {
        let fixture = Fixture::new();
        let predecessor_checkpoint = prepare_network();
        let store = fixture.store(&predecessor_checkpoint);
        let predecessor = store.create(&predecessor_checkpoint).unwrap();
        let port = VmmCidAllocationPort::new(
            StateDirectory::unanchored(fixture.state.clone()),
            Arc::new(FakeInventory::stable(
                VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
            )),
        );
        let context = context(
            &fixture.state,
            std::slice::from_ref(&predecessor_checkpoint.cat_id),
        );
        let mut revalidations = 0;

        let error = port
            .reserve_and_replace(
                &context,
                &store,
                &predecessor,
                || {
                    revalidations += 1;
                    anyhow::ensure!(
                        revalidations == 1,
                        "injected launch authority drift before CID publication"
                    );
                    Ok(())
                },
                |_| Ok(start_runtime()),
            )
            .expect_err("drift after CID selection reached checkpoint publication");

        assert!(format!("{error:#}").contains("authority drift"));
        assert_eq!(revalidations, 2);
        let current = store.load().unwrap().unwrap();
        assert_eq!(current.checkpoint(), predecessor.checkpoint());
        assert_eq!(current.content_digest(), predecessor.content_digest());
        port.lock(&TestPhysicalContext::active()).unwrap();
    }

    #[test]
    fn cancellation_after_publication_returns_error_but_keeps_the_reservation() {
        let fixture = Fixture::new();
        let predecessor_checkpoint = prepare_network();
        let store = fixture.store(&predecessor_checkpoint);
        let predecessor = store.create(&predecessor_checkpoint).unwrap();
        let port = VmmCidAllocationPort::new(
            StateDirectory::unanchored(fixture.state.clone()),
            Arc::new(FakeInventory::stable(
                VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
            )),
        )
        .with_after_replace(Arc::new(|context| {
            context.cancel_for_test();
            Ok(())
        }));
        let context = context(
            &fixture.state,
            std::slice::from_ref(&predecessor_checkpoint.cat_id),
        );
        assert!(port
            .reserve_and_replace(
                &context,
                &store,
                &predecessor,
                || Ok(()),
                |selected| {
                    let mut replacement = start_runtime();
                    let ReconcileStep::StartRuntime { guest_cid, .. } = &mut replacement.step
                    else {
                        unreachable!()
                    };
                    *guest_cid = selected;
                    Ok(replacement)
                }
            )
            .is_err());
        let current = store.load().unwrap().unwrap();
        let ReconcileStep::StartRuntime { guest_cid, .. } = current.checkpoint().step else {
            panic!("published CID reservation was lost after cancellation")
        };
        assert_eq!(guest_cid, FIRST_GUEST_CID);
        port.lock(&TestPhysicalContext::active()).unwrap();
    }

    #[test]
    fn restored_lock_inode_cannot_hide_a_replacement_lock_domain_publication() {
        let fixture = Fixture::new();
        let checkpoint_a = prepare_network();
        let mut checkpoint_b = prepare_network();
        checkpoint_b.cat_id = Id::new("cat_b").unwrap();
        let store_a = fixture.store(&checkpoint_a);
        let store_b = fixture.store(&checkpoint_b);
        let predecessor_a = store_a.create(&checkpoint_a).unwrap();
        let predecessor_b = store_b.create(&checkpoint_b).unwrap();
        let port = VmmCidAllocationPort::new(
            StateDirectory::unanchored(fixture.state.clone()),
            Arc::new(FakeInventory::stable(
                VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
            )),
        );
        let state = fixture.state.clone();
        let lock_path = state.join(VMM_ALLOCATION_LOCK_BASENAME);
        let moved_lock_path = state.join("vmm-allocation.lock.moved");
        let result = port.reserve_and_replace(
            &context(
                &fixture.state,
                &[checkpoint_a.cat_id.clone(), checkpoint_b.cat_id.clone()],
            ),
            &store_a,
            &predecessor_a,
            || Ok(()),
            |selected| {
                fs::rename(&lock_path, &moved_lock_path).unwrap();
                // Force a generation change on the retained inode even on a
                // filesystem whose timestamp granularity hides the renames.
                fs::write(&moved_lock_path, b"generation-change").unwrap();
                File::options()
                    .write(true)
                    .open(&moved_lock_path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();

                let root = File::open(&state).unwrap();
                let replacement_lock = open_vmm_allocation_lock(&root).unwrap();
                lock_exclusive_nonblocking(&replacement_lock).unwrap();
                let mut replacement_b = start_runtime();
                replacement_b.cat_id = checkpoint_b.cat_id.clone();
                let ReconcileStep::StartRuntime { guest_cid, .. } = &mut replacement_b.step else {
                    unreachable!()
                };
                *guest_cid = selected;
                store_b.replace(&predecessor_b, &replacement_b).unwrap();
                unlock_file(&replacement_lock).unwrap();
                drop(replacement_lock);
                fs::remove_file(&lock_path).unwrap();
                fs::rename(&moved_lock_path, &lock_path).unwrap();

                let mut replacement_a = start_runtime();
                let ReconcileStep::StartRuntime { guest_cid, .. } = &mut replacement_a.step else {
                    unreachable!()
                };
                *guest_cid = selected;
                Ok(replacement_a)
            },
        );
        assert!(result.is_err());
        assert!(matches!(
            store_a.load().unwrap().unwrap().checkpoint().step,
            ReconcileStep::PrepareNetwork { .. }
        ));
        assert!(matches!(
            store_b.load().unwrap().unwrap().checkpoint().step,
            ReconcileStep::StartRuntime {
                guest_cid: FIRST_GUEST_CID,
                ..
            }
        ));
        port.lock(&TestPhysicalContext::active()).unwrap();
    }

    #[test]
    fn foreign_live_vmm_or_inventory_drift_publishes_nothing() {
        let fixture = Fixture::new();
        let predecessor_checkpoint = prepare_network();
        let store = fixture.store(&predecessor_checkpoint);
        let predecessor = store.create(&predecessor_checkpoint).unwrap();
        let foreign = ExactLiveVmmCid::new(
            VmmCidOwner::new(Id::new("cat_foreign").unwrap(), random('f')),
            3,
        )
        .unwrap();
        let port = VmmCidAllocationPort::new(
            StateDirectory::unanchored(fixture.state.clone()),
            Arc::new(FakeInventory::stable(
                VmmCidInventorySnapshot::try_new(vec![foreign]).unwrap(),
            )),
        );
        assert!(port
            .reserve_and_replace(
                &context(
                    &fixture.state,
                    std::slice::from_ref(&predecessor_checkpoint.cat_id)
                ),
                &store,
                &predecessor,
                || Ok(()),
                |_| Ok(start_runtime()),
            )
            .is_err());
        let current = store.load().unwrap().unwrap();
        assert_eq!(current.checkpoint(), predecessor.checkpoint());
        assert_eq!(current.content_digest(), predecessor.content_digest());

        let fixture = Fixture::new();
        let predecessor_checkpoint = prepare_network();
        let store = fixture.store(&predecessor_checkpoint);
        let predecessor = store.create(&predecessor_checkpoint).unwrap();
        let changed = ExactLiveVmmCid::new(
            VmmCidOwner::new(Id::new("cat_foreign").unwrap(), random('f')),
            4,
        )
        .unwrap();
        let port = VmmCidAllocationPort::new(
            StateDirectory::unanchored(fixture.state.clone()),
            Arc::new(FakeInventory::changing([
                VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
                VmmCidInventorySnapshot::try_new(vec![changed]).unwrap(),
            ])),
        );
        assert!(port
            .reserve_and_replace(
                &context(
                    &fixture.state,
                    std::slice::from_ref(&predecessor_checkpoint.cat_id)
                ),
                &store,
                &predecessor,
                || Ok(()),
                |_| Ok(start_runtime()),
            )
            .is_err());
        let current = store.load().unwrap().unwrap();
        assert_eq!(current.checkpoint(), predecessor.checkpoint());
        assert_eq!(current.content_digest(), predecessor.content_digest());
    }

    #[test]
    fn callback_cannot_ignore_or_change_the_selected_cid() {
        let fixture = Fixture::new();
        let predecessor_checkpoint = prepare_network();
        let store = fixture.store(&predecessor_checkpoint);
        let predecessor = store.create(&predecessor_checkpoint).unwrap();
        let inventory = Arc::new(FakeInventory::stable(
            VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
        ));
        let port =
            VmmCidAllocationPort::new(StateDirectory::unanchored(fixture.state.clone()), inventory);
        assert!(port
            .reserve_and_replace(
                &context(
                    &fixture.state,
                    std::slice::from_ref(&predecessor_checkpoint.cat_id)
                ),
                &store,
                &predecessor,
                || Ok(()),
                |_| {
                    let mut replacement = start_runtime();
                    let ReconcileStep::StartRuntime { guest_cid, .. } = &mut replacement.step
                    else {
                        unreachable!()
                    };
                    *guest_cid = 4;
                    Ok(replacement)
                },
            )
            .is_err());
        let current = store.load().unwrap().unwrap();
        assert_eq!(current.checkpoint(), predecessor.checkpoint());
        assert_eq!(current.content_digest(), predecessor.content_digest());
    }

    #[test]
    fn reserved_and_any_cids_are_never_constructible() {
        let owner = VmmCidOwner::new(Id::new("cat_a").unwrap(), random('a'));
        for cid in [0, 1, 2, u32::MAX] {
            assert!(ExactLiveVmmCid::new(owner.clone(), cid).is_err());
        }
        assert!(ExactLiveVmmCid::new(owner, LAST_GUEST_CID).is_ok());
    }

    #[test]
    fn allocation_drop_unlocks_an_inherited_open_file_description() {
        let fixture = Fixture::new();
        let port = VmmCidAllocationPort::new(
            StateDirectory::unanchored(fixture.state.clone()),
            Arc::new(FakeInventory::stable(
                VmmCidInventorySnapshot::try_new(Vec::new()).unwrap(),
            )),
        );
        let permit = port.lock(&TestPhysicalContext::active()).unwrap();
        // SAFETY: permit owns one live descriptor and a successful dup returns
        // a fresh descriptor owned by this test.
        let descriptor = unsafe { libc::dup(permit.lock.as_raw_fd()) };
        assert!(descriptor >= 0, "{}", io::Error::last_os_error());
        // SAFETY: successful dup transferred this descriptor exactly once.
        let inherited = unsafe { File::from_raw_fd(descriptor) };
        drop(permit);
        port.lock(&TestPhysicalContext::active()).unwrap();
        drop(inherited);
    }
}

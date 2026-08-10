//! Checkpoint-first reservation of one exact Host TAP identity.
//!
//! The reservation CAS is deliberately separate from TAP creation. It holds
//! a Node-global network allocation flock across a complete checkpoint
//! namespace read, a stable Host link/address snapshot, and the per-Cat
//! checkpoint fsync. A later accepted full inventory owns the one physical
//! create/adopt effect.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, CheckpointEvidence, Condition, DesiredRuntimeSpec, Id,
    LifecycleAdmission, ObservedDevice, OwnershipTokenEvidence, PrepareDeviceFrontend,
    PreparedDeviceInput, ProgressingReason, RandomId128, ReconcileStep, RuntimeCheckpoint,
    RuntimeNetworkIdentity, RuntimeTarget, RuntimeTransition, UnixMillis, WarmSnapshotEvidence,
};

use crate::ch::{inspect_host_network_snapshot, plan_network, ChNetwork};
use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimePhysicalReadContext,
};
use crate::state_directory::StateDirectory;

use super::checkpoint::{revalidate_checkpoint_namespace, FileCheckpointStore, StoredCheckpoint};
use super::clean_slate_probes::{
    snapshot_runtime_checkpoint_namespace, RuntimeCheckpointNamespaceSnapshot,
    CHECKPOINT_NAMESPACE, RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
};
use super::serving_handoff_effect::checkpoint_is_current_exact;

const NETWORK_ALLOCATION_LOCK_BASENAME: &str = "network-allocation.lock";

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkReservation {
    cat_id: Id,
    identity: RuntimeNetworkIdentity,
}

#[derive(Debug, Clone, Default)]
struct NetworkReservations {
    by_tap: BTreeMap<Id, NetworkReservation>,
    by_network: BTreeMap<Id, NetworkReservation>,
    by_token: BTreeMap<RandomId128, NetworkReservation>,
    occupied_tokens: BTreeMap<RandomId128, Id>,
}

impl NetworkReservations {
    fn from_snapshot(snapshot: &RuntimeCheckpointNamespaceSnapshot) -> Result<Self> {
        let mut reservations = Self::default();
        for checkpoint in snapshot.iter_checkpoints() {
            reservations.collect_checkpoint_tokens(checkpoint)?;
            match &checkpoint.step {
                ReconcileStep::PrepareNetwork { network, .. } => {
                    reservations.insert(NetworkReservation {
                        cat_id: checkpoint.cat_id.clone(),
                        identity: network.clone(),
                    })?;
                }
                ReconcileStep::StartRuntime { network, .. } => {
                    reservations.insert(NetworkReservation {
                        cat_id: checkpoint.cat_id.clone(),
                        identity: network.as_ref().clone(),
                    })?;
                }
                _ => {}
            }
            for observed in &checkpoint.networks {
                let OwnershipTokenEvidence::Valid { ownership_token } = &observed.ownership_token
                else {
                    anyhow::bail!("durable Host network projection lacks a valid ownership token")
                };
                reservations.insert(NetworkReservation {
                    cat_id: checkpoint.cat_id.clone(),
                    identity: RuntimeNetworkIdentity {
                        network_config: cats_api::runtime_reconciliation::NetworkConfig {
                            kind: observed.kind,
                            network_id: observed.network_id.clone(),
                            guest_mac: observed.guest_mac.clone(),
                            guest_ipv4: observed.guest_ipv4.clone(),
                            prefix_length: observed.prefix_length,
                            gateway_ipv4: observed.gateway_ipv4.clone(),
                        },
                        tap_name: observed.tap_name.clone(),
                        ownership_token: ownership_token.clone(),
                    },
                })?;
            }
        }
        Ok(reservations)
    }

    fn collect_checkpoint_tokens(&mut self, checkpoint: &RuntimeCheckpoint) -> Result<()> {
        let mut record = |token: &RandomId128| -> Result<()> {
            if let Some(existing_cat) = self.occupied_tokens.get(token) {
                anyhow::ensure!(
                    existing_cat == &checkpoint.cat_id,
                    "Runtime physical token is reused across Cats"
                );
            } else {
                self.occupied_tokens
                    .insert(token.clone(), checkpoint.cat_id.clone());
            }
            Ok(())
        };
        match &checkpoint.step {
            ReconcileStep::PrepareDevice {
                ownership_token,
                serving_process,
                ..
            } => {
                record(ownership_token)?;
                record(&serving_process.process_identity_token)?;
            }
            ReconcileStep::PrepareNetwork { network, devices } => {
                record(&network.ownership_token)?;
                for device in devices {
                    record(&device.ownership_token)?;
                    record(&device.serving_process.process_identity_token)?;
                }
            }
            ReconcileStep::StartRuntime {
                process_identity_token,
                network,
                devices,
                ..
            } => {
                record(process_identity_token)?;
                record(&network.ownership_token)?;
                for device in devices {
                    record(&device.ownership_token)?;
                    record(&device.serving_process.process_identity_token)?;
                }
            }
            _ => {}
        }
        for process in &checkpoint.processes {
            if let OwnershipTokenEvidence::Valid { ownership_token } = &process.ownership_token {
                record(ownership_token)?;
            }
        }
        for volume in &checkpoint.volumes {
            for device in &volume.devices {
                let ownership = match device {
                    ObservedDevice::KernelNbd {
                        ownership_token, ..
                    }
                    | ObservedDevice::VhostUserBlk {
                        ownership_token, ..
                    } => ownership_token,
                };
                if let OwnershipTokenEvidence::Valid { ownership_token } = ownership {
                    record(ownership_token)?;
                }
            }
        }
        Ok(())
    }

    fn insert(&mut self, candidate: NetworkReservation) -> Result<()> {
        for existing in [
            self.by_tap.get(&candidate.identity.tap_name),
            self.by_network
                .get(&candidate.identity.network_config.network_id),
            self.by_token.get(&candidate.identity.ownership_token),
        ]
        .into_iter()
        .flatten()
        {
            anyhow::ensure!(
                existing == &candidate,
                "Host network reservation conflicts with another durable identity"
            );
        }
        self.by_tap
            .insert(candidate.identity.tap_name.clone(), candidate.clone());
        self.by_network.insert(
            candidate.identity.network_config.network_id.clone(),
            candidate.clone(),
        );
        self.by_token.insert(
            candidate.identity.ownership_token.clone(),
            candidate.clone(),
        );
        self.occupied_tokens
            .entry(candidate.identity.ownership_token.clone())
            .or_insert(candidate.cat_id);
        Ok(())
    }

    fn assert_candidate_available(&self, candidate: &NetworkReservation) -> Result<()> {
        anyhow::ensure!(
            !self.by_tap.contains_key(&candidate.identity.tap_name),
            "fresh Host TAP name collides with a durable reservation"
        );
        anyhow::ensure!(
            !self
                .by_network
                .contains_key(&candidate.identity.network_config.network_id),
            "Desired network identity is already durably reserved"
        );
        anyhow::ensure!(
            !self
                .occupied_tokens
                .contains_key(&candidate.identity.ownership_token),
            "fresh Host network token collides with durable Runtime authority"
        );
        Ok(())
    }
}

#[derive(Debug)]
struct NetworkAllocationPermit {
    state_root: File,
    lock: File,
    lock_held: bool,
}

impl NetworkAllocationPermit {
    fn lock(&self) -> Result<&File> {
        anyhow::ensure!(
            self.lock_held,
            "network allocation permit was already released"
        );
        Ok(&self.lock)
    }

    fn assert_current_paths(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        let reopened = open_network_allocation_lock(&self.state_root)?;
        ensure_same_file(self.lock()?, &reopened, "network allocation lock changed")?;
        revalidate_checkpoint_namespace(
            &self.state_root,
            CHECKPOINT_NAMESPACE,
            &[snapshot.retained_directory(), store.retained_directory()],
        )
        .context("network reservation checkpoint namespace changed")?;
        Ok(())
    }

    fn unlock(&mut self) -> Result<()> {
        if !self.lock_held {
            return Ok(());
        }
        unlock_file(&self.lock).context("release Node-global network allocation lock")?;
        self.lock_held = false;
        Ok(())
    }

    fn release(mut self) -> Result<()> {
        self.unlock()
    }
}

impl Drop for NetworkAllocationPermit {
    fn drop(&mut self) {
        let _ = self.unlock();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NetworkAllocationPort {
    state_directory: StateDirectory,
    ip_binary: PathBuf,
}

impl NetworkAllocationPort {
    pub(crate) fn new(state_directory: StateDirectory, ip_binary: PathBuf) -> Result<Self> {
        anyhow::ensure!(ip_binary.is_absolute(), "Host ip binary must be absolute");
        Ok(Self {
            state_directory,
            ip_binary,
        })
    }

    fn lock(&self, context: &dyn RuntimePhysicalReadContext) -> Result<NetworkAllocationPermit> {
        context.check_active()?;
        let state_root = self
            .state_directory
            .try_clone_directory()
            .context("retain Node state root for network allocation")?;
        let lock = open_network_allocation_lock(&state_root)?;
        lock_exclusive_nonblocking(&lock)?;
        let permit = NetworkAllocationPermit {
            state_root,
            lock,
            lock_held: true,
        };
        let reopened = open_network_allocation_lock(&permit.state_root)?;
        ensure_same_file(permit.lock()?, &reopened, "network allocation lock changed")?;
        context.check_active()?;
        Ok(permit)
    }

    fn reserve_and_replace(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        predecessor: &StoredCheckpoint,
        network_config: &cats_api::runtime_reconciliation::NetworkConfig,
        mut revalidate_authority: impl FnMut() -> Result<()>,
        build: impl FnOnce(RuntimeNetworkIdentity) -> Result<RuntimeCheckpoint>,
    ) -> Result<StoredCheckpoint> {
        let permit = self.lock(context)?;
        let context_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Desired-effect state root for network reservation")?;
        ensure_same_file(
            &permit.state_root,
            &context_root,
            "network allocator and Desired effect use different state roots",
        )?;
        let assigned = context.accepted_full()?.assigned_cats()?;
        let snapshot = snapshot_runtime_checkpoint_namespace(
            &permit.state_root,
            context,
            assigned,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?
        .context("network reservation requires a complete checkpoint namespace")?;
        permit.assert_current_paths(&snapshot, store)?;
        anyhow::ensure!(
            snapshot.checkpoint(&predecessor.checkpoint().cat_id) == Some(predecessor.checkpoint()),
            "PrepareNetwork predecessor is not current in the complete namespace"
        );
        let reservations = NetworkReservations::from_snapshot(&snapshot)?;
        let planned = plan_network(network_config).context("plan fresh Host network identity")?;
        let identity = runtime_network_identity(&planned)?;
        let candidate = NetworkReservation {
            cat_id: predecessor.checkpoint().cat_id.clone(),
            identity: identity.clone(),
        };
        reservations.assert_candidate_available(&candidate)?;
        let physical = inspect_host_network_snapshot(&self.ip_binary, context)?;
        physical.ensure_managed_networks_are_reserved(
            reservations
                .by_tap
                .values()
                .map(|reservation| &reservation.identity),
        )?;
        physical.ensure_candidate_available(&planned)?;
        revalidate_authority()?;
        context.check_active()?;
        let replacement = build(identity.clone())?;
        let ReconcileStep::PrepareNetwork { network, .. } = &replacement.step else {
            anyhow::bail!("network allocator callback did not construct PrepareNetwork")
        };
        anyhow::ensure!(
            network == &identity && replacement.cat_id == predecessor.checkpoint().cat_id,
            "network allocator callback changed its selected identity or Cat"
        );
        let mut prospective = reservations;
        prospective.insert(candidate)?;
        let physical_after = inspect_host_network_snapshot(&self.ip_binary, context)?;
        anyhow::ensure!(
            physical_after == physical,
            "Host network inventory changed before reservation publication"
        );
        physical_after.ensure_managed_networks_are_reserved(
            prospective
                .by_tap
                .values()
                .map(|reservation| &reservation.identity),
        )?;
        physical_after.ensure_candidate_available(&planned)?;
        revalidate_authority()?;
        context.check_active()?;
        permit.assert_current_paths(&snapshot, store)?;
        let persisted = store
            .replace(predecessor, &replacement)
            .context("persist PrepareNetwork reservation checkpoint")?;
        permit.assert_current_paths(&snapshot, store)?;
        context.check_active()?;
        permit.release()?;
        Ok(persisted)
    }
}

pub(crate) struct PrepareNetworkReservationEffect {
    allocation: NetworkAllocationPort,
}

impl PrepareNetworkReservationEffect {
    pub(crate) fn new(state_directory: StateDirectory, ip_binary: PathBuf) -> Result<Self> {
        Ok(Self {
            allocation: NetworkAllocationPort::new(state_directory, ip_binary)?,
        })
    }

    /// Reserve the Host network only after the accepted full scan and sealed
    /// serving proof agree on one exact vhost-user device. Kernel-NBD remains
    /// with its independent attach admission and deliberately cannot reach
    /// this CAS from public device projection alone.
    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        let accepted = context.accepted_full()?;
        let mut runtimes = accepted
            .observation()
            .runtimes
            .iter()
            .filter(|runtime| runtime.cat_id == desired.cat_id);
        let Some(runtime) = runtimes.next() else {
            return Ok(None);
        };
        anyhow::ensure!(
            runtimes.next().is_none(),
            "PrepareNetwork admission duplicates one Cat"
        );
        let ReconcileStep::PrepareDevice { frontend, .. } = &runtime.step else {
            return Ok(None);
        };
        if !matches!(frontend, PrepareDeviceFrontend::VhostUserBlk { .. }) {
            return Ok(None);
        }
        if !checkpoint_is_current_exact(desired, runtime) {
            return Ok(None);
        }
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running
                && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
                && runtime.runtime_incarnation.is_none()
                && runtime.stable_state.is_none()
                && runtime.mounts.is_empty()
                && runtime.networks.is_empty()
                && matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
                && runtime.lifecycle_admission == LifecycleAdmission::Closed
                && runtime.routes.is_empty()
                && runtime.conditions
                    == [Condition::Progressing {
                        reason: ProgressingReason::ReconcileStep {
                            step: runtime.step.clone(),
                        },
                    }],
            "PrepareNetwork admission is not the exact closed pre-launch phase"
        );
        let Some((_expectation, Some(serving))) = context
            .node_global_process()?
            .serving_blockd(&desired.cat_id)
        else {
            anyhow::bail!("PrepareNetwork lacks exact provider-private serving proof")
        };
        let Some((volume_id, device)) = serving.vhost_device_projection() else {
            anyhow::bail!("PrepareNetwork serving proof is not vhost-user")
        };
        anyhow::ensure!(
            runtime.volumes.iter().any(|volume| {
                volume.volume_id == volume_id && volume.devices == [device.clone()]
            }),
            "PrepareNetwork public device projection changed after provider proof"
        );
        let listener = serving.listener_proof();
        listener.assert_current(context)?;

        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            anyhow::bail!("PrepareNetwork lacks a valid predecessor checkpoint")
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &checkpoint_directory,
            &desired.cat_id,
        )
        .context("open PrepareNetwork predecessor checkpoint")?;
        anyhow::ensure!(
            store.path() == Path::new(checkpoint_path.as_str()),
            "PrepareNetwork admission names another checkpoint path"
        );
        let Some(stored) = store.load().context("load PrepareNetwork predecessor")? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let prepared = prepared_device_input(stored.checkpoint())?;
        self.allocation.reserve_and_replace(
            context,
            &store,
            &stored,
            &desired.runtime.network_config,
            || listener.assert_current(context),
            |network| prepare_network_successor(&stored, network, prepared),
        )?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
}

fn prepared_device_input(checkpoint: &RuntimeCheckpoint) -> Result<PreparedDeviceInput> {
    let ReconcileStep::PrepareDevice {
        volume_intent_id,
        disk_id,
        volume_id,
        disk_kind,
        attachment_id,
        attachment_epoch,
        acquire_origin,
        expected_head,
        size_bytes,
        durability,
        guest_device,
        ownership_token,
        serving_authority,
        serving_process,
        frontend,
    } = &checkpoint.step
    else {
        anyhow::bail!("PrepareNetwork predecessor is not PrepareDevice")
    };
    Ok(PreparedDeviceInput {
        volume_intent_id: volume_intent_id.clone(),
        disk_id: disk_id.clone(),
        volume_id: volume_id.clone(),
        disk_kind: *disk_kind,
        attachment_id: attachment_id.clone(),
        attachment_epoch: *attachment_epoch,
        acquire_origin: acquire_origin.clone(),
        expected_head: expected_head.clone(),
        size_bytes: *size_bytes,
        durability: *durability,
        guest_device: guest_device.clone(),
        ownership_token: ownership_token.clone(),
        serving_authority: serving_authority.clone(),
        serving_process: serving_process.clone(),
        frontend: frontend.clone(),
    })
}

fn prepare_network_successor(
    predecessor: &StoredCheckpoint,
    network: RuntimeNetworkIdentity,
    device: PreparedDeviceInput,
) -> Result<RuntimeCheckpoint> {
    let mut checkpoint = predecessor.checkpoint().clone();
    checkpoint.step = ReconcileStep::PrepareNetwork {
        network,
        devices: vec![device],
    };
    checkpoint.updated_at_unix_ms = monotonic_wall_clock(predecessor)?;
    encode_runtime_checkpoint(&checkpoint)
        .context("constructed PrepareNetwork checkpoint is not canonical V1")?;
    Ok(checkpoint)
}

fn runtime_network_identity(network: &ChNetwork) -> Result<RuntimeNetworkIdentity> {
    Ok(RuntimeNetworkIdentity {
        network_config: network.config.clone(),
        tap_name: Id::new(network.tap.clone()).context("planned TAP name is not a wire Id")?,
        ownership_token: network.ownership_token.clone(),
    })
}

fn monotonic_wall_clock(stored: &StoredCheckpoint) -> Result<UnixMillis> {
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let wall_clock_ms = u64::try_from(wall_clock_ms).context("system time exceeds wire range")?;
    let minimum = stored
        .checkpoint()
        .updated_at_unix_ms
        .get()
        .checked_add(1)
        .context("PrepareNetwork checkpoint timestamp exhausted")?;
    UnixMillis::new(wall_clock_ms.max(minimum))
        .context("PrepareNetwork checkpoint timestamp is outside wire range")
}

fn open_network_allocation_lock(root: &File) -> Result<File> {
    let name = CString::new(NETWORK_ALLOCATION_LOCK_BASENAME)
        .expect("network allocation lock basename is static ASCII");
    // SAFETY: root is a retained directory and name is a live NUL-terminated
    // basename. On success this call returns a new owned descriptor.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open network allocation lock");
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().context("inspect network allocation lock")?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == effective_user_id()
            && metadata.mode() & 0o7777 == 0o600,
        "network allocation lock has unsafe metadata"
    );
    Ok(file)
}

fn lock_exclusive_nonblocking(file: &File) -> Result<()> {
    loop {
        // SAFETY: file is a live descriptor; flock retains no Rust memory.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(source).context("acquire Node-global network allocation lock");
    }
}

fn unlock_file(file: &File) -> Result<()> {
    loop {
        // SAFETY: file is a live descriptor; flock retains no Rust memory.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(source).context("unlock Node-global network allocation lock");
    }
}

fn ensure_same_file(first: &File, second: &File, message: &'static str) -> Result<()> {
    let first = first.metadata().context("inspect retained network file")?;
    let second = second.metadata().context("inspect reopened network file")?;
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
    // SAFETY: geteuid has no preconditions and reads process credentials.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, AdmissionInventoryAttestation,
        AgentSession, ContractVersion, DesiredReadSnapshot, DesiredRuntimeSpec, Epoch,
        NetworkConfig, NodeBootId, NodeObservation, RuntimeTarget, RuntimeTransition, Sequence,
        SessionBinding, Sha256Digest,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::RuntimeDesiredEffectAdmission;

    use super::*;

    const PREPARE_DEVICE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-prepare-device-checkpoint.json"
    ));
    const DESIRED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-desired.json"
    ));

    fn random(byte: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(byte, 32).collect::<String>()).unwrap()
    }

    fn fixed_predecessor() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(PREPARE_DEVICE).unwrap()
    }

    fn desired_for(cat_id: &Id) -> DesiredRuntimeSpec {
        let mut desired = decode_desired_runtime_spec(DESIRED).unwrap();
        desired.cat_id = cat_id.clone();
        desired.target = RuntimeTarget::Running;
        desired.transition = RuntimeTransition::CancelAndDrain;
        desired
    }

    fn desired_effect_context(state: &Path, cats: &[Id]) -> RuntimeDesiredEffectContext {
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
        let snapshot = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: binding,
            request_sequence: Sequence::new(1).unwrap(),
            read_position,
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(2_000).unwrap(),
            desired_specs: cats.iter().map(desired_for).collect(),
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
            Instant::now() + Duration::from_secs(10),
            admission,
        )
    }

    struct Fixture {
        _temp: TempDir,
        state: PathBuf,
        ip: PathBuf,
        marker: PathBuf,
        calls: PathBuf,
    }

    impl Fixture {
        fn empty() -> Self {
            Self::with_after_link(None)
        }

        fn with_after_link(link: Option<(&str, &str)>) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let state = temp.path().join("state");
            let ip = temp.path().join("ip");
            let marker = temp.path().join("after");
            let calls = temp.path().join("ip.calls");
            fs::create_dir(&state).unwrap();
            let (links, addresses) = match link {
                Some((alias, address)) => (
                    format!(
                        r#"[{{"ifindex":17,"ifname":"catold000001","flags":["UP"],"ifalias":"{alias}","linkinfo":{{"info_kind":"tun","info_data":{{"type":"tap"}}}}}}]"#
                    ),
                    format!(
                        r#"[{{"ifindex":17,"ifname":"catold000001","addr_info":[{{"family":"inet","local":"{address}","prefixlen":30}}]}}]"#
                    ),
                ),
                None => ("[]".to_owned(), "[]".to_owned()),
            };
            fs::write(
                &ip,
                format!(
                    "#!/bin/sh\n\
printf '%s\\n' \"$*\" >> '{calls}'\n\
if [ \"$2\" = '-d' ]; then\n\
  if [ -f '{marker}' ]; then printf '%s' '{links}'; else printf '[]'; fi\n\
  exit 0\n\
fi\n\
if [ \"$2\" = '-4' ]; then\n\
  if [ -f '{marker}' ]; then printf '%s' '{addresses}'; else printf '[]'; fi\n\
  exit 0\n\
fi\n\
exit 97\n",
                    calls = calls.display(),
                    marker = marker.display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&ip, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                _temp: temp,
                state,
                ip,
                marker,
                calls,
            }
        }

        fn port(&self) -> NetworkAllocationPort {
            NetworkAllocationPort::new(
                StateDirectory::unanchored(self.state.clone()),
                self.ip.clone(),
            )
            .unwrap()
        }

        fn store(&self, checkpoint: &RuntimeCheckpoint) -> FileCheckpointStore {
            FileCheckpointStore::open(&self.state.join(CHECKPOINT_NAMESPACE), &checkpoint.cat_id)
                .unwrap()
        }
    }

    struct InheritedNetworkLockChild {
        child: Child,
    }

    impl InheritedNetworkLockChild {
        fn spawn(permit: &NetworkAllocationPermit) -> Self {
            // SAFETY: permit owns one live descriptor and a successful dup
            // returns a fresh descriptor owned by this test.
            let descriptor = unsafe { libc::dup(permit.lock.as_raw_fd()) };
            assert!(descriptor >= 0, "{}", io::Error::last_os_error());
            // SAFETY: successful dup transferred this descriptor exactly once.
            let inherited = unsafe { File::from_raw_fd(descriptor) };
            let child = Command::new("/bin/sleep")
                .env_clear()
                .stdin(Stdio::from(inherited))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .arg("30")
                .spawn()
                .unwrap();
            Self { child }
        }
    }

    impl Drop for InheritedNetworkLockChild {
        fn drop(&mut self) {
            let _ = self.child.kill();
            self.child.wait().unwrap();
        }
    }

    fn reserve(
        fixture: &Fixture,
        store: &FileCheckpointStore,
        predecessor: &StoredCheckpoint,
        mutation: impl FnOnce(),
    ) -> Result<StoredCheckpoint> {
        let source = predecessor.checkpoint();
        let prepared = prepared_device_input(source).unwrap();
        let context = desired_effect_context(&fixture.state, std::slice::from_ref(&source.cat_id));
        fixture.port().reserve_and_replace(
            &context,
            store,
            predecessor,
            &desired_for(&source.cat_id).runtime.network_config,
            || Ok(()),
            |network| {
                mutation();
                prepare_network_successor(predecessor, network, prepared)
            },
        )
    }

    #[test]
    fn reservation_persists_one_exact_prepare_network_successor() {
        let fixture = Fixture::empty();
        let source = fixed_predecessor();
        let store = fixture.store(&source);
        let predecessor = store.create(&source).unwrap();
        let persisted = reserve(&fixture, &store, &predecessor, || {}).unwrap();
        let expected_device = prepared_device_input(&source).unwrap();
        let ReconcileStep::PrepareNetwork { network, devices } = &persisted.checkpoint().step
        else {
            panic!("reservation did not persist PrepareNetwork")
        };
        assert_eq!(
            network.network_config,
            desired_for(&source.cat_id).runtime.network_config
        );
        assert_eq!(devices, &[expected_device]);
        assert_eq!(persisted.checkpoint().runtime_incarnation, None);
        assert_eq!(persisted.checkpoint().stable_state, None);
        assert_eq!(
            persisted.checkpoint().lifecycle_admission,
            LifecycleAdmission::Closed
        );
        assert_eq!(
            fs::read_to_string(&fixture.calls).unwrap().lines().count(),
            8
        );
        fixture.port().lock(&TestPhysicalContext::active()).unwrap();
    }

    #[test]
    fn reservation_rejects_host_drift_before_checkpoint_publication() {
        let fixture = Fixture::with_after_link(Some(("foreign", "192.0.2.1")));
        let marker = fixture.marker.clone();
        let source = fixed_predecessor();
        let store = fixture.store(&source);
        let predecessor = store.create(&source).unwrap();
        let error = reserve(&fixture, &store, &predecessor, move || {
            fs::write(marker, b"changed").unwrap()
        })
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("inventory changed before reservation"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
    }

    #[test]
    fn reservation_rejects_unbound_physical_cats_tap_without_publication() {
        let source = fixed_predecessor();
        let incumbent = desired_for(&source.cat_id).runtime.network_config;
        let alias = format!("cats-network:{}:{}", incumbent.network_id, random('e'));
        let fixture = Fixture::with_after_link(Some((&alias, "10.240.0.5")));
        fs::write(&fixture.marker, b"present").unwrap();
        let store = fixture.store(&source);
        let predecessor = store.create(&source).unwrap();
        let error = reserve(&fixture, &store, &predecessor, || {
            panic!("unbound TAP must fail before build")
        })
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("lacks a durable reservation"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
    }

    #[test]
    fn reservation_rejects_checkpoint_namespace_rename_recreate() {
        let fixture = Fixture::empty();
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let detached = fixture.state.join("checkpoints-detached");
        let source = fixed_predecessor();
        let store = fixture.store(&source);
        let predecessor = store.create(&source).unwrap();
        let mutate_checkpoint_directory = checkpoint_directory.clone();
        let mutate_detached = detached.clone();
        let error = reserve(&fixture, &store, &predecessor, move || {
            fs::rename(&mutate_checkpoint_directory, &mutate_detached).unwrap();
            fs::create_dir(&mutate_checkpoint_directory).unwrap();
        })
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("namespace changed"),
            "{error:#}"
        );
        assert!(fs::read_dir(&checkpoint_directory)
            .unwrap()
            .next()
            .is_none());
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
        assert!(detached.exists());
    }

    #[test]
    fn network_reservations_reject_global_identity_and_token_reuse() {
        let first = NetworkReservation {
            cat_id: Id::new("cat_a").unwrap(),
            identity: RuntimeNetworkIdentity {
                network_config: desired_for(&Id::new("cat_a").unwrap())
                    .runtime
                    .network_config,
                tap_name: Id::new("cata00000001").unwrap(),
                ownership_token: random('a'),
            },
        };
        let mut reservations = NetworkReservations::default();
        reservations.insert(first.clone()).unwrap();
        for second in [
            NetworkReservation {
                cat_id: Id::new("cat_b").unwrap(),
                identity: RuntimeNetworkIdentity {
                    tap_name: first.identity.tap_name.clone(),
                    ownership_token: random('b'),
                    network_config: NetworkConfig {
                        network_id: Id::new("net_b").unwrap(),
                        ..first.identity.network_config.clone()
                    },
                },
            },
            NetworkReservation {
                cat_id: Id::new("cat_b").unwrap(),
                identity: RuntimeNetworkIdentity {
                    tap_name: Id::new("catb00000001").unwrap(),
                    ownership_token: first.identity.ownership_token.clone(),
                    network_config: NetworkConfig {
                        network_id: Id::new("net_b").unwrap(),
                        ..first.identity.network_config.clone()
                    },
                },
            },
        ] {
            assert!(reservations.insert(second).is_err());
        }
        reservations
            .occupied_tokens
            .insert(random('f'), Id::new("cat_z").unwrap());
        let fresh = NetworkReservation {
            cat_id: Id::new("cat_a").unwrap(),
            identity: RuntimeNetworkIdentity {
                tap_name: Id::new("cata00000002").unwrap(),
                ownership_token: random('f'),
                network_config: NetworkConfig {
                    network_id: Id::new("net_fresh").unwrap(),
                    ..first.identity.network_config
                },
            },
        };
        assert!(reservations.assert_candidate_available(&fresh).is_err());
    }

    #[derive(Debug)]
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
    fn allocation_drop_unlocks_an_open_file_description_inherited_across_exec() {
        let fixture = Fixture::empty();
        let port = fixture.port();
        let permit = port.lock(&TestPhysicalContext::active()).unwrap();
        let _inherited = InheritedNetworkLockChild::spawn(&permit);
        drop(permit);
        port.lock(&TestPhysicalContext::active()).unwrap();
    }
}

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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, CheckpointEvidence, DesiredRuntimeSpec, DiskKind, Epoch,
    GuestTransportEvidence, Id, LifecycleAdmission, LocalLineageState, NodeBootId, NodeObservation,
    ObservedDevice, ObservedDiskKind, ObservedNetwork, OwnershipTokenEvidence,
    PrepareDeviceFrontend, PreparedDeviceInput, RandomId128, ReconcileStep, RequireIdleCheckpoint,
    RuntimeCheckpoint, RuntimeLaunch, RuntimeNetworkIdentity, RuntimeTarget, RuntimeTransition,
    Sequence, Sha256Digest, UnixMillis, VolumeAccess, VolumeAuthorityEvidence, VolumeDisposition,
    WarmSnapshotEvidence,
};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::ch::{
    create_network_from_sealed_absence_with_tap_port, inspect_host_network_snapshot,
    network_configs_overlap, plan_network, ChNetwork, HostNetworkSnapshot, NetworkCreateAttempt,
    PlatformTapCreatePort, ReservedHostNetworkState, TapCreatePort,
};
use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
    RuntimeInventoryScanContext, RuntimePhysicalReadContext,
};
use crate::state_directory::StateDirectory;

use super::checkpoint::{revalidate_checkpoint_namespace, FileCheckpointStore, StoredCheckpoint};
use super::clean_slate_probes::{
    snapshot_runtime_checkpoint_namespace, RuntimeCheckpointNamespaceSnapshot,
    CHECKPOINT_NAMESPACE, RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
};
use super::inventory::{
    network_inventory_bridge_sealed, NetworkInventoryBridge, NetworkInventoryBridgeOutcome,
    RuntimeCheckpointInventoryEvidence,
};
pub(super) use super::prepare_device_retirement::prepared_device_set_is_exact;
use super::prepare_device_retirement::{
    prepare_device_base_admission_is_exact, prepared_device_input_is_exact,
    prepared_device_inputs_from_step, retirement_authority_lease_is_monotonic, unique_runtime,
};
use super::retained_runtime_launch::RetainedRuntimeLaunchAuthority;
use super::serving_blockd_process::{
    ExactServingBlockdProcessProof, ServingBlockdExpectation, ServingBlockdProcessGlobalPort,
    ServingBlockdProcessInspection,
};
use super::serving_handoff_effect::checkpoint_is_current_exact;
use super::signed_root_provision::signed_inventory_admission_is_exact_with_networks;

const NETWORK_ALLOCATION_LOCK_BASENAME: &str = "network-allocation.lock";

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkReservation {
    cat_id: Id,
    identity: RuntimeNetworkIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkInventoryEntry {
    reservation: NetworkReservation,
    state: ReservedHostNetworkState,
}

/// Provider-private result of one complete checkpoint/TAP scan.  The exact
/// physical snapshot and explicit absent/exact classification cannot be
/// reconstructed from the public `ObservedNetwork` vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeGlobalNetworkScanAdmission {
    entries: BTreeMap<Id, NetworkInventoryEntry>,
    physical: HostNetworkSnapshot,
}

/// The same sealed network inventory after binding to the exact full
/// observation accepted by Control. It is process-local and intentionally has
/// no wire decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeGlobalNetworkAdmission {
    observation_id: RandomId128,
    node_id: Id,
    node_boot_id: NodeBootId,
    agent_instance_id: RandomId128,
    agent_session_epoch: Epoch,
    inventory_epoch: Epoch,
    inventory_digest: Sha256Digest,
    inventory_read_position: Sequence,
    entries: BTreeMap<Id, NetworkInventoryEntry>,
    physical: HostNetworkSnapshot,
}

impl NodeGlobalNetworkScanAdmission {
    fn new(
        reservations: impl IntoIterator<Item = NetworkReservation>,
        physical: HostNetworkSnapshot,
    ) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for reservation in reservations {
            let state = physical.reserved_network_state(&reservation.identity)?;
            let cat_id = reservation.cat_id.clone();
            anyhow::ensure!(
                entries
                    .insert(cat_id, NetworkInventoryEntry { reservation, state })
                    .is_none(),
                "network inventory repeats one Cat reservation"
            );
        }
        Ok(Self { entries, physical })
    }

    pub(crate) fn network_projections(&self) -> BTreeMap<Id, Vec<ObservedNetwork>> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.state == ReservedHostNetworkState::Exact)
            .map(|(cat_id, entry)| {
                (
                    cat_id.clone(),
                    vec![observed_network(&entry.reservation.identity)],
                )
            })
            .collect()
    }

    pub(crate) fn has_exact_network(&self, cat_id: &Id, identity: &RuntimeNetworkIdentity) -> bool {
        self.entries.get(cat_id).is_some_and(|entry| {
            entry.reservation.identity == *identity
                && entry.state == ReservedHostNetworkState::Exact
        })
    }

    pub(crate) fn exact_network_is_present(
        &self,
        cat_id: &Id,
        identity: &RuntimeNetworkIdentity,
    ) -> Result<bool> {
        let entry = self
            .entries
            .get(cat_id)
            .context("Running scan lacks its retained network reservation")?;
        anyhow::ensure!(
            entry.reservation.identity == *identity,
            "Running scan network reservation changed its retained identity"
        );
        Ok(entry.state == ReservedHostNetworkState::Exact)
    }

    pub(crate) fn bind(self, observation: &NodeObservation) -> Result<NodeGlobalNetworkAdmission> {
        anyhow::ensure!(
            observation.complete_inventory,
            "Node-global network admission requires a complete observation"
        );
        let inventory_digest = observation
            .inventory_digest
            .clone()
            .context("Node-global network admission lacks inventory digest")?;
        let inventory_read_position = observation
            .inventory_read_position
            .context("Node-global network admission lacks inventory read position")?;
        let mut projections = self.network_projections();
        for runtime in &observation.runtimes {
            let expected = projections.remove(&runtime.cat_id).unwrap_or_default();
            anyhow::ensure!(
                runtime.networks == expected,
                "provider-private network proof conflicts with public projection"
            );
        }
        anyhow::ensure!(
            projections.is_empty()
                && self.entries.keys().all(|cat_id| observation
                    .runtimes
                    .iter()
                    .any(|runtime| &runtime.cat_id == cat_id)),
            "Node-global network admission names a Cat absent from inventory"
        );
        Ok(NodeGlobalNetworkAdmission {
            observation_id: observation.observation_id.clone(),
            node_id: observation.node_id.clone(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest,
            inventory_read_position,
            entries: self.entries,
            physical: self.physical,
        })
    }

    #[cfg(test)]
    pub(crate) fn absent_checkpoint_for_test(checkpoint: &RuntimeCheckpoint) -> Result<Self> {
        let network = checkpoint_network_identity(checkpoint)
            .context("test network admission requires retained network authority")?;
        Self::new(
            [NetworkReservation {
                cat_id: checkpoint.cat_id.clone(),
                identity: network.clone(),
            }],
            HostNetworkSnapshot::empty_for_test(),
        )
    }

    #[cfg(test)]
    pub(crate) fn exact_checkpoint_for_test(checkpoint: &RuntimeCheckpoint) -> Result<Self> {
        let network = checkpoint_network_identity(checkpoint)
            .context("test network admission requires retained network authority")?;
        Self::new(
            [NetworkReservation {
                cat_id: checkpoint.cat_id.clone(),
                identity: network.clone(),
            }],
            HostNetworkSnapshot::exact_for_test(network)?,
        )
    }
}

impl NodeGlobalNetworkAdmission {
    pub(crate) fn matches_observation(&self, observation: &NodeObservation) -> bool {
        observation.complete_inventory
            && self.observation_id == observation.observation_id
            && self.node_id == observation.node_id
            && self.node_boot_id == observation.node_boot_id
            && self.agent_instance_id == observation.agent_instance_id
            && self.agent_session_epoch == observation.agent_session_epoch
            && self.inventory_epoch == observation.inventory_epoch
            && observation.inventory_digest.as_ref() == Some(&self.inventory_digest)
            && observation.inventory_read_position == Some(self.inventory_read_position)
    }

    fn reservation(&self, cat_id: &Id) -> Option<&NetworkInventoryEntry> {
        self.entries.get(cat_id)
    }

    pub(crate) fn expected_networks(
        &self,
        cat_id: &Id,
        identity: &RuntimeNetworkIdentity,
    ) -> Option<Vec<ObservedNetwork>> {
        let entry = self.reservation(cat_id)?;
        if entry.reservation.identity != *identity {
            return None;
        }
        Some(match entry.state {
            ReservedHostNetworkState::Absent => Vec::new(),
            ReservedHostNetworkState::Exact => vec![observed_network(identity)],
        })
    }

    pub(crate) fn has_exact_network(&self, cat_id: &Id, identity: &RuntimeNetworkIdentity) -> bool {
        self.entries.get(cat_id).is_some_and(|entry| {
            entry.reservation.identity == *identity
                && entry.state == ReservedHostNetworkState::Exact
        })
    }
}

fn observed_network(identity: &RuntimeNetworkIdentity) -> ObservedNetwork {
    ObservedNetwork {
        kind: identity.network_config.kind,
        network_id: identity.network_config.network_id.clone(),
        guest_mac: identity.network_config.guest_mac.clone(),
        guest_ipv4: identity.network_config.guest_ipv4.clone(),
        prefix_length: identity.network_config.prefix_length,
        gateway_ipv4: identity.network_config.gateway_ipv4.clone(),
        tap_name: identity.tap_name.clone(),
        ownership_token: OwnershipTokenEvidence::Valid {
            ownership_token: identity.ownership_token.clone(),
        },
    }
}

fn checkpoint_network_identity(checkpoint: &RuntimeCheckpoint) -> Result<&RuntimeNetworkIdentity> {
    if let ReconcileStep::PrepareNetwork { network, .. } = &checkpoint.step {
        return Ok(network);
    }
    Ok(RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?
        .identity()
        .network
        .as_ref())
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
                _ if checkpoint.runtime_launch.identity().is_some() => {
                    let network = &checkpoint
                        .runtime_launch
                        .identity()
                        .expect("guarded retained launch")
                        .network;
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
        if let Some(launch) = checkpoint.runtime_launch.identity() {
            record(&launch.process_identity_token)?;
            record(&launch.network.ownership_token)?;
            for device in &launch.devices {
                record(&device.ownership_token)?;
                record(&device.serving_process.process_identity_token)?;
            }
        } else {
            match &checkpoint.step {
                ReconcileStep::PrepareDevice { devices } => {
                    for device in devices {
                        record(&device.ownership_token)?;
                        record(&device.serving_process.process_identity_token)?;
                    }
                }
                ReconcileStep::PrepareNetwork { network, devices } => {
                    record(&network.ownership_token)?;
                    for device in devices {
                        record(&device.ownership_token)?;
                        record(&device.serving_process.process_identity_token)?;
                    }
                }
                _ => {}
            }
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
        for existing in self.by_tap.values() {
            if existing != &candidate {
                anyhow::ensure!(
                    !network_configs_overlap(
                        &existing.identity.network_config,
                        &candidate.identity.network_config,
                    )?,
                    "Host network reservation overlaps another durable IPv4 range"
                );
            }
        }
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
        for existing in self.by_tap.values() {
            anyhow::ensure!(
                !network_configs_overlap(
                    &existing.identity.network_config,
                    &candidate.identity.network_config,
                )?,
                "fresh Host network reservation overlaps a durable IPv4 range"
            );
        }
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
    lock_identity: NetworkLockIdentity,
    lock_held: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkLockIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl NetworkLockIdentity {
    fn capture(file: &File) -> Result<Self> {
        let metadata = file
            .metadata()
            .context("capture network allocation lock identity")?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn assert_exact(self, file: &File) -> Result<()> {
        anyhow::ensure!(
            Self::capture(file)? == self,
            "network allocation lock changed from its acquisition identity"
        );
        Ok(())
    }
}

impl NetworkAllocationPermit {
    fn lock(&self) -> Result<&File> {
        anyhow::ensure!(
            self.lock_held,
            "network allocation permit was already released"
        );
        Ok(&self.lock)
    }

    fn assert_current_lock(&self) -> Result<()> {
        self.lock_identity.assert_exact(self.lock()?)?;
        let reopened = open_network_allocation_lock(&self.state_root)?;
        self.lock_identity.assert_exact(&reopened)
    }

    fn assert_current_paths(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        self.assert_current_lock()?;
        revalidate_checkpoint_namespace(
            &self.state_root,
            CHECKPOINT_NAMESPACE,
            &[snapshot.retained_directory(), store.retained_directory()],
        )
        .context("network reservation checkpoint namespace changed")?;
        Ok(())
    }

    fn assert_current_snapshot(&self, snapshot: &RuntimeCheckpointNamespaceSnapshot) -> Result<()> {
        self.assert_current_lock()?;
        let _reopened_namespace = revalidate_checkpoint_namespace(
            &self.state_root,
            CHECKPOINT_NAMESPACE,
            &[snapshot.retained_directory()],
        )
        .context("network inventory checkpoint namespace changed")?;
        Ok(())
    }

    fn assert_current_absent_namespace(&self) -> Result<()> {
        self.assert_current_lock()?;
        anyhow::ensure!(
            checkpoint_namespace_is_absent(&self.state_root)?,
            "network inventory checkpoint namespace appeared during scan"
        );
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
        let lock_identity = NetworkLockIdentity::capture(&lock)?;
        let permit = NetworkAllocationPermit {
            state_root,
            lock,
            lock_identity,
            lock_held: true,
        };
        permit.assert_current_lock()?;
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
        physical.ensure_reserved_network_ranges(
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
        physical_after.ensure_reserved_network_ranges(
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

    fn create_or_adopt_reserved(
        &self,
        context: &RuntimeDesiredEffectContext,
        admission: &NodeGlobalNetworkAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        tap_create: &dyn TapCreatePort,
        mut revalidate_authority: impl FnMut() -> Result<()>,
    ) -> Result<NetworkPhysicalRound> {
        let entry = admission
            .reservation(&stored.checkpoint().cat_id)
            .context("PrepareNetwork lacks its provider-private TAP reservation")?;
        let network = checkpoint_network_identity(stored.checkpoint())
            .context("physical network effect lacks retained network authority")?;
        anyhow::ensure!(
            &entry.reservation.identity == network,
            "provider-private TAP proof changed its durable reservation"
        );

        let permit = self.lock(context)?;
        let context_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Desired-effect state root for TAP create/adopt")?;
        ensure_same_file(
            &permit.state_root,
            &context_root,
            "network admission and Desired effect use different state roots",
        )?;
        let assigned = context.accepted_full()?.assigned_cats()?;
        let snapshot = snapshot_runtime_checkpoint_namespace(
            &permit.state_root,
            context,
            assigned,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?
        .context("TAP create/adopt requires a complete checkpoint namespace")?;
        permit.assert_current_paths(&snapshot, store)?;
        anyhow::ensure!(
            snapshot.checkpoint(&stored.checkpoint().cat_id) == Some(stored.checkpoint()),
            "PrepareNetwork checkpoint changed after accepted inventory"
        );
        let reservations = NetworkReservations::from_snapshot(&snapshot)?;
        anyhow::ensure!(
            reservations
                .by_tap
                .get(&network.tap_name)
                .is_some_and(|reservation| reservation == &entry.reservation),
            "complete checkpoint namespace changed the TAP reservation"
        );

        let inspect_closed = || -> Result<HostNetworkSnapshot> {
            let physical = inspect_host_network_snapshot(&self.ip_binary, context)?;
            physical.ensure_managed_networks_are_reserved(
                reservations
                    .by_tap
                    .values()
                    .map(|reservation| &reservation.identity),
            )?;
            physical.ensure_reserved_network_ranges(
                reservations
                    .by_tap
                    .values()
                    .map(|reservation| &reservation.identity),
            )?;
            Ok(physical)
        };
        let admitted_physical = inspect_closed()?;
        anyhow::ensure!(
            admitted_physical == admission.physical
                && admitted_physical.reserved_network_state(network)? == entry.state,
            "Host TAP inventory drifted after accepted full admission"
        );
        revalidate_authority()?;
        permit.assert_current_paths(&snapshot, store)?;
        let immediately_before = inspect_closed()?;
        anyhow::ensure!(
            immediately_before == admitted_physical,
            "Host TAP inventory changed before physical effect"
        );
        revalidate_authority()?;
        context.check_active()?;

        if entry.state == ReservedHostNetworkState::Exact {
            permit.assert_current_paths(&snapshot, store)?;
            permit.release()?;
            return Ok(NetworkPhysicalRound::AdoptedExact);
        }

        let planned = ChNetwork {
            tap: network.tap_name.as_str().to_owned(),
            ownership_token: network.ownership_token.clone(),
            config: network.network_config.clone(),
        };
        let attempt = create_network_from_sealed_absence_with_tap_port(
            &self.ip_binary,
            &planned,
            context,
            tap_create,
        )?;

        // A physical create was attempted. No error below may retain this
        // admission for a retry: the next full scan is the sole postcondition
        // oracle for success, response loss, cancellation or cleanup.
        let _postcondition = (|| -> Result<()> {
            let after = inspect_closed()?;
            anyhow::ensure!(
                admitted_physical.unchanged_except_reserved_tap(&after, network),
                "Host network inventory changed outside the attempted TAP"
            );
            let after_state = after.reserved_network_state(network)?;
            match attempt {
                NetworkCreateAttempt::Published => anyhow::ensure!(
                    after_state == ReservedHostNetworkState::Exact,
                    "published TAP is not exact"
                ),
                NetworkCreateAttempt::DefinitelyNotPublished => anyhow::ensure!(
                    after_state == ReservedHostNetworkState::Absent,
                    "definitively unpublished TAP remained visible"
                ),
                NetworkCreateAttempt::PublicationOutcomeUnknown => anyhow::ensure!(
                    matches!(
                        after_state,
                        ReservedHostNetworkState::Absent | ReservedHostNetworkState::Exact
                    ),
                    "ambiguous TAP publication left partial state"
                ),
            }
            permit.assert_current_paths(&snapshot, store)?;
            revalidate_authority()?;
            context.check_active()
        })();
        drop(permit);
        Ok(NetworkPhysicalRound::CreateAttempted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkPhysicalRound {
    AdoptedExact,
    CreateAttempted,
}

impl network_inventory_bridge_sealed::Sealed for NetworkAllocationPort {}

impl NetworkInventoryBridge for NetworkAllocationPort {
    fn inspect_all(
        &self,
        checkpoints: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
        context: &RuntimeInventoryScanContext,
    ) -> Result<NetworkInventoryBridgeOutcome> {
        let permit = self.lock(context)?;
        let assigned = context.assigned_cats()?;
        let snapshot = snapshot_runtime_checkpoint_namespace(
            &permit.state_root,
            context,
            &assigned,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?;
        let Some(snapshot) = snapshot else {
            if !checkpoints.is_empty() || !checkpoint_namespace_is_absent(&permit.state_root)? {
                permit.release()?;
                return Ok(NetworkInventoryBridgeOutcome::Unavailable);
            }
            permit.assert_current_absent_namespace()?;
            let physical = inspect_host_network_snapshot(&self.ip_binary, context)?;
            physical.ensure_managed_networks_are_reserved(std::iter::empty())?;
            physical.ensure_reserved_network_ranges(std::iter::empty())?;
            permit.assert_current_absent_namespace()?;
            let admission = NodeGlobalNetworkScanAdmission::new([], physical)?;
            permit.release()?;
            return Ok(NetworkInventoryBridgeOutcome::Complete(admission));
        };

        permit.assert_current_snapshot(&snapshot)?;
        anyhow::ensure!(
            snapshot.iter_checkpoints().len() == checkpoints.len()
                && checkpoints.iter().all(|(cat_id, evidence)| {
                    snapshot.checkpoint(cat_id) == Some(&evidence.checkpoint)
                }),
            "network bridge checkpoint snapshot differs from checkpoint inventory"
        );
        let reservations = NetworkReservations::from_snapshot(&snapshot)?;
        let physical = inspect_host_network_snapshot(&self.ip_binary, context)?;
        physical.ensure_managed_networks_are_reserved(
            reservations
                .by_tap
                .values()
                .map(|reservation| &reservation.identity),
        )?;
        physical.ensure_reserved_network_ranges(
            reservations
                .by_tap
                .values()
                .map(|reservation| &reservation.identity),
        )?;
        let admission =
            NodeGlobalNetworkScanAdmission::new(reservations.by_tap.into_values(), physical)?;
        permit.assert_current_snapshot(&snapshot)?;
        context.check_active()?;
        permit.release()?;
        Ok(NetworkInventoryBridgeOutcome::Complete(admission))
    }
}

pub(crate) struct PrepareNetworkReservationEffect {
    allocation: NetworkAllocationPort,
    authority: Arc<dyn VolumeDataAuthority>,
    serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
    tap_create: Arc<dyn TapCreatePort>,
}

struct AdmittedNetworkServing<'a> {
    expectation: &'a ServingBlockdExpectation,
    serving: &'a ExactServingBlockdProcessProof,
    first_authority: VolumeRecord,
    first_lease_expiry: UnixMillis,
}

impl PrepareNetworkReservationEffect {
    pub(crate) fn new(
        state_directory: StateDirectory,
        ip_binary: PathBuf,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
    ) -> Result<Self> {
        Ok(Self {
            allocation: NetworkAllocationPort::new(state_directory, ip_binary)?,
            authority,
            serving_process,
            tap_create: Arc::new(PlatformTapCreatePort),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_tap_create_for_test(mut self, tap_create: Arc<dyn TapCreatePort>) -> Self {
        self.tap_create = tap_create;
        self
    }

    /// Reopen the complete checkpoint/TAP namespace and prove that the
    /// persisted reservation is still the same exact physical TAP. This is a
    /// read-only boundary for the later StartRuntime CID critical section;
    /// an absent reservation is rejected and can never reach the create port.
    pub(crate) fn revalidate_exact_reserved(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
    ) -> Result<()> {
        let _node_global_effect = context.lock_node_global_effect()?;
        let accepted = context.accepted_full()?;
        let admission = context.node_global_network()?;
        anyhow::ensure!(
            admission.matches_observation(accepted.observation()),
            "StartRuntime network admission is not bound to the accepted full observation"
        );
        let entry = admission
            .reservation(&stored.checkpoint().cat_id)
            .context("StartRuntime lacks its provider-private TAP reservation")?;
        anyhow::ensure!(
            entry.state == ReservedHostNetworkState::Exact,
            "StartRuntime requires an exact physical TAP"
        );
        let round = self.allocation.create_or_adopt_reserved(
            context,
            admission,
            store,
            stored,
            self.tap_create.as_ref(),
            || Ok(()),
        )?;
        anyhow::ensure!(
            round == NetworkPhysicalRound::AdoptedExact,
            "StartRuntime network revalidation attempted a physical create"
        );
        Ok(())
    }

    /// Reserve the Host network only after the accepted full scan and sealed
    /// serving proof agree on one exact device. Kernel-NBD reaches this CAS
    /// only through its scanner-sealed physical client proof; a checkpoint or
    /// public device projection alone remains insufficient.
    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };
        if matches!(runtime.step, ReconcileStep::PrepareNetwork { .. }) {
            let _node_global_effect = context.lock_node_global_effect()?;
            return self.try_apply_physical(context, desired, runtime);
        }
        let ReconcileStep::PrepareDevice { devices } = &runtime.step else {
            return Ok(None);
        };
        if !prepare_device_base_admission_is_exact(accepted, desired, runtime) {
            return Ok(Some(local_contract_stop()));
        }
        let _node_global_effect = context.lock_node_global_effect()?;
        let process_admission = context.node_global_process()?;
        if process_admission.serving_blockd_count(&desired.cat_id) != devices.len() {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let mut admitted = Vec::with_capacity(devices.len());
        for prepared in devices {
            let Some((expectation, Some(serving))) =
                process_admission.serving_blockd(&desired.cat_id, &prepared.volume_id)
            else {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
            };
            if !expectation.matches_device_contract(&desired.cat_id, prepared) {
                return Ok(Some(local_contract_stop()));
            }
            let (volume_id, observed_device) = match &prepared.frontend {
                PrepareDeviceFrontend::VhostUserBlk { .. } => serving
                    .vhost_device_projection()
                    .context("PrepareNetwork serving proof is not vhost-user")?,
                PrepareDeviceFrontend::KernelNbd { .. } => {
                    let exact = context
                        .kernel_nbd_pool()?
                        .exact_device(&desired.cat_id, &prepared.volume_id)
                        .context("PrepareNetwork lacks exact kernel-NBD client proof")?;
                    anyhow::ensure!(
                        exact.listener().expectation() == expectation
                            && exact.matches_prepared_device(&desired.cat_id, prepared),
                        "PrepareNetwork kernel-NBD and serving proofs disagree"
                    );
                    exact.projection()
                }
            };
            if !prepare_network_volume_admission_is_exact(
                desired,
                runtime,
                prepared,
                &volume_id,
                Some(&observed_device),
            ) {
                return Ok(Some(local_contract_stop()));
            }
            let first_authority = self
                .authority
                .load_volume(expectation.volume_id())
                .context("load PrepareNetwork Volume authority")?;
            anyhow::ensure!(
                expectation.matches_current_authority(&first_authority),
                "PrepareNetwork Volume authority conflicts with serving admission"
            );
            let first_lease_expiry = first_authority
                .lease_expires_at
                .context("PrepareNetwork Volume authority lacks a serving lease")?;
            admitted.push(AdmittedNetworkServing {
                expectation,
                serving,
                first_authority,
                first_lease_expiry,
            });
        }
        if runtime.processes.len() != admitted.len()
            || !admitted.iter().all(|entry| {
                runtime
                    .processes
                    .iter()
                    .filter(|process| entry.serving.matches_public_process(process))
                    .count()
                    == 1
            })
        {
            return Ok(Some(local_contract_stop()));
        }

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
        let prepared = prepared_device_inputs(stored.checkpoint())?;
        self.allocation.reserve_and_replace(
            context,
            &store,
            &stored,
            &desired.runtime.network_config,
            || self.revalidate_serving_authorities(context, &admitted),
            |network| prepare_network_successor(&stored, network, prepared),
        )?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }

    fn try_apply_physical(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        runtime: &cats_api::runtime_reconciliation::ObservedRuntimeStatus,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        let accepted = context.accepted_full()?;
        let ReconcileStep::PrepareNetwork { network, devices } = &runtime.step else {
            unreachable!("caller selected PrepareNetwork")
        };
        if devices.is_empty() || !prepared_device_set_is_exact(desired, devices) {
            return Ok(Some(local_contract_stop()));
        }
        let network_admission = context.node_global_network()?;
        let Some(expected_networks) = network_admission.expected_networks(&desired.cat_id, network)
        else {
            return Ok(Some(local_contract_stop()));
        };
        if !signed_inventory_admission_is_exact_with_networks(
            accepted,
            desired,
            runtime,
            &expected_networks,
        ) || !checkpoint_is_current_exact(desired, runtime)
        {
            return Ok(Some(local_contract_stop()));
        }
        let process_admission = context.node_global_process()?;
        if process_admission.serving_blockd_count(&desired.cat_id) != devices.len() {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let mut serving_devices = Vec::with_capacity(devices.len());
        for device in devices {
            let Some((expectation, Some(serving))) =
                process_admission.serving_blockd(&desired.cat_id, &device.volume_id)
            else {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
            };
            if !expectation.matches_device_contract(&desired.cat_id, device) {
                return Ok(Some(local_contract_stop()));
            }
            let (volume_id, observed_device) = match &device.frontend {
                PrepareDeviceFrontend::VhostUserBlk { .. } => {
                    let Some(projection) = serving.vhost_device_projection() else {
                        return Ok(Some(local_contract_stop()));
                    };
                    projection
                }
                PrepareDeviceFrontend::KernelNbd { .. } => {
                    let exact = context
                        .kernel_nbd_pool()?
                        .exact_device(&desired.cat_id, &device.volume_id)
                        .context("PrepareNetwork lacks exact kernel-NBD client proof")?;
                    if exact.listener().expectation() != expectation
                        || !exact.matches_prepared_device(&desired.cat_id, device)
                    {
                        return Ok(Some(local_contract_stop()));
                    }
                    exact.projection()
                }
            };
            if !prepare_network_volume_admission_is_exact(
                desired,
                runtime,
                device,
                &volume_id,
                Some(&observed_device),
            ) {
                return Ok(Some(local_contract_stop()));
            }
            let first_authority = self
                .authority
                .load_volume(expectation.volume_id())
                .context("load TAP effect Volume authority")?;
            anyhow::ensure!(
                expectation.matches_current_authority(&first_authority),
                "TAP effect Volume authority conflicts with serving admission"
            );
            let first_lease_expiry = first_authority
                .lease_expires_at
                .context("TAP effect Volume authority lacks a serving lease")?;
            serving_devices.push(AdmittedNetworkServing {
                expectation,
                serving,
                first_authority,
                first_lease_expiry,
            });
        }
        if runtime.processes.len() != serving_devices.len()
            || !serving_devices.iter().all(|admitted| {
                runtime
                    .processes
                    .iter()
                    .filter(|process| admitted.serving.matches_public_process(process))
                    .count()
                    == 1
            })
        {
            return Ok(Some(local_contract_stop()));
        }

        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(local_contract_stop()));
        };
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )?;
        anyhow::ensure!(
            store.path() == Path::new(checkpoint_path.as_str()),
            "TAP effect admission names another checkpoint path"
        );
        let Some(stored) = store.load()? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let round = self.allocation.create_or_adopt_reserved(
            context,
            network_admission,
            &store,
            &stored,
            self.tap_create.as_ref(),
            || self.revalidate_serving_authorities(context, &serving_devices),
        )?;
        Ok(match round {
            // Exact TAP adoption is a read-only proof. Let the independent
            // StartRuntime reservation effect own this batch's sole CAS.
            NetworkPhysicalRound::AdoptedExact => None,
            NetworkPhysicalRound::CreateAttempted => {
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
        })
    }

    fn revalidate_serving_authority(
        &self,
        context: &RuntimeDesiredEffectContext,
        expected: &ServingBlockdExpectation,
        admitted: &ExactServingBlockdProcessProof,
        first_authority: &VolumeRecord,
        first_lease_expiry: UnixMillis,
    ) -> Result<()> {
        context.check_active()?;
        let inspection = self
            .serving_process
            .inspect_serving_exact_or_absent_after_node_global_sweep(expected, context)
            .context("reinspect PrepareNetwork serving authority across Node-global sweep")?;
        let ServingBlockdProcessInspection::Exact(current_process) = inspection else {
            anyhow::bail!("PrepareNetwork serving authority is no longer exact")
        };
        anyhow::ensure!(
            current_process.exactly_matches(expected)
                && current_process.as_ref() == admitted.evidence(),
            "PrepareNetwork serving process/status authority drifted"
        );
        let current_authority = self
            .authority
            .load_volume(expected.volume_id())
            .context("reread PrepareNetwork Volume authority")?;
        anyhow::ensure!(
            expected.matches_current_authority(&current_authority)
                && retirement_authority_lease_is_monotonic(
                    first_authority,
                    &current_authority,
                    first_lease_expiry,
                ),
            "PrepareNetwork Volume authority changed before checkpoint publication"
        );
        context.check_active()
    }

    fn revalidate_serving_authorities(
        &self,
        context: &RuntimeDesiredEffectContext,
        admitted: &[AdmittedNetworkServing<'_>],
    ) -> Result<()> {
        for entry in admitted {
            self.revalidate_serving_authority(
                context,
                entry.expectation,
                entry.serving,
                &entry.first_authority,
                entry.first_lease_expiry,
            )?;
        }
        Ok(())
    }
}

pub(super) fn prepare_network_volume_admission_is_exact(
    desired: &DesiredRuntimeSpec,
    runtime: &cats_api::runtime_reconciliation::ObservedRuntimeStatus,
    device: &PreparedDeviceInput,
    volume_id: &Id,
    observed_device: Option<&ObservedDevice>,
) -> bool {
    let Some(desired_volume) = desired
        .volumes
        .iter()
        .find(|intent| intent.volume_id == device.volume_id)
    else {
        return false;
    };
    let Some(observed_volume) = runtime
        .volumes
        .iter()
        .find(|volume| volume.volume_id == device.volume_id)
    else {
        return false;
    };
    let [lineage] = observed_volume.local_lineages.as_slice() else {
        return false;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed_volume.authority
    else {
        return false;
    };
    prepared_device_input_is_exact(device, desired, observed_volume)
        && desired.target == RuntimeTarget::Running
        && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        && desired_volume.access == VolumeAccess::ReadWriteOnce
        && matches!(desired_volume.disposition, VolumeDisposition::Retain)
        && device.volume_intent_id == desired_volume.volume_intent_id
        && device.disk_id == desired_volume.disk_id
        && device.volume_id == desired_volume.volume_id
        && device.volume_id == *volume_id
        && device.disk_kind == desired_volume.disk_kind
        && device.attachment_id == *attachment_id
        && device.attachment_epoch == *attachment_epoch
        && device.expected_head == *head
        && device.size_bytes == desired_volume.size_bytes
        && device.durability == desired_volume.durability
        && observed_volume.volume_intent_id.as_ref() == Some(&desired_volume.volume_intent_id)
        && observed_volume.disk_id.as_ref() == Some(&desired_volume.disk_id)
        && observed_volume.volume_id == desired_volume.volume_id
        && observed_volume.disk_kind
            == match desired_volume.disk_kind {
                DiskKind::Root => ObservedDiskKind::Root,
                DiskKind::Persistent => ObservedDiskKind::Persistent,
            }
        && observed_volume.size_bytes == Some(desired_volume.size_bytes)
        && observed_volume.durability == Some(desired_volume.durability)
        && observed_volume.devices.as_slice()
            == observed_device.map_or(&[][..], std::slice::from_ref)
        && lineage.attachment_id == *attachment_id
        && lineage.attachment_epoch == *attachment_epoch
        && lineage.acquire_origin == device.acquire_origin
        && lineage.node_id == desired.placement.node_id
        && lineage.placement_epoch == desired.placement.placement_epoch
        && lineage.local_durable_generation == head.generation
        && lineage.remote_durable_generation == head.generation
        && lineage.data_directory == device.serving_process.data_directory
        && lineage.pending_pack_count.get() == 0
        && !lineage.fenced
        && lineage.state == LocalLineageState::Active
}

fn local_contract_stop() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

pub(super) fn prepared_device_input(checkpoint: &RuntimeCheckpoint) -> Result<PreparedDeviceInput> {
    let devices = prepared_device_inputs(checkpoint)?;
    let [device] = devices.as_slice() else {
        anyhow::bail!("prepared-device projection requires exactly one device")
    };
    Ok(device.clone())
}

pub(super) fn prepared_device_inputs(
    checkpoint: &RuntimeCheckpoint,
) -> Result<Vec<PreparedDeviceInput>> {
    if let Some(identity) = checkpoint.runtime_launch.identity() {
        anyhow::ensure!(
            checkpoint.runtime_incarnation.as_ref() == Some(&identity.runtime_incarnation),
            "retained Runtime launch incarnation is not top-level exact"
        );
        anyhow::ensure!(
            !identity.devices.is_empty(),
            "retained Runtime launch must carry at least one prepared device"
        );
        return Ok(identity.devices.clone());
    }
    prepared_device_inputs_from_step(&checkpoint.step)
}

pub(super) fn prepare_device_checkpoint_view(
    checkpoint: &RuntimeCheckpoint,
) -> Result<RuntimeCheckpoint> {
    let devices = prepared_device_inputs(checkpoint)?;
    let mut root_handoff = devices.iter().filter(|device| {
        matches!(
            device.serving_authority.as_ref(),
            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
        )
    });
    root_handoff
        .next()
        .context("prepared-device projection lacks its Root handoff device")?;
    anyhow::ensure!(
        root_handoff.next().is_none(),
        "prepared-device projection contains duplicate Root handoff devices"
    );
    let mut prepared = checkpoint.clone();
    prepared.step = ReconcileStep::PrepareDevice { devices };
    // This is a canonical pre-launch reconstruction used only to rejoin the
    // immutable serving handoff after later phases replaced `step`. Never
    // carry live-VMM or Guest evidence backward into that reconstruction.
    prepared.runtime_incarnation = None;
    prepared.runtime_launch = RuntimeLaunch::Absent;
    prepared.stable_state = None;
    prepared.processes.clear();
    for volume in &mut prepared.volumes {
        volume.devices.clear();
    }
    prepared.mounts.clear();
    prepared.networks.clear();
    prepared.guest_transport = GuestTransportEvidence::Unavailable;
    prepared.warm_snapshot = WarmSnapshotEvidence::Absent;
    prepared.lifecycle_admission = LifecycleAdmission::Closed;
    prepared.route_gates.clear();
    prepared.require_idle = RequireIdleCheckpoint::NotApplicable;
    Ok(prepared)
}

fn prepare_network_successor(
    predecessor: &StoredCheckpoint,
    network: RuntimeNetworkIdentity,
    devices: Vec<PreparedDeviceInput>,
) -> Result<RuntimeCheckpoint> {
    let mut checkpoint = predecessor.checkpoint().clone();
    checkpoint.step = ReconcileStep::PrepareNetwork { network, devices };
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

fn checkpoint_namespace_is_absent(root: &File) -> Result<bool> {
    let name = CString::new(CHECKPOINT_NAMESPACE).expect("checkpoint namespace is static ASCII");
    // SAFETY: root is a retained directory and name is a live NUL-terminated
    // lexical basename. No symlink is followed and a successful fd is closed
    // below without escaping this probe.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: openat returned this owned descriptor and it is closed once.
        let directory = unsafe { File::from_raw_fd(fd) };
        drop(directory);
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(true)
    } else {
        Err(error).context("inspect absent checkpoint namespace for network inventory")
    }
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
    use std::cell::Cell;
    use std::fs;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, spec_digest,
        AdmissionInventoryAttestation, AgentSession, AppliedDesiredEvidence, CheckpointEvidence,
        Condition, ContractVersion, DesiredReadSnapshot, DesiredRuntimeSpec, Epoch,
        GuestTransportEvidence, HostPath, LifecycleAdmission, NetworkConfig, NodeBootId,
        NodeObservation, ObservedRuntimeStatus, ProgressingReason, RuntimeTarget,
        RuntimeTransition, Sequence, SessionBinding, Sha256Digest, VolumeAcquire,
        WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::RuntimeDesiredEffectAdmission;

    use super::*;

    const PREPARE_DEVICE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-prepare-device-checkpoint.json"
    ));
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
        desired_effect_context_for(state, cats.iter().map(desired_for).collect())
    }

    fn desired_effect_context_for(
        state: &Path,
        desired_specs: Vec<DesiredRuntimeSpec>,
    ) -> RuntimeDesiredEffectContext {
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
            desired_specs,
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

    #[test]
    fn prepared_device_set_rejects_a_missing_desired_volume_and_duplicate_device() {
        let checkpoint = fixed_predecessor();
        let prepared = prepared_device_input(&checkpoint).unwrap();
        let desired = desired_for(&checkpoint.cat_id);
        assert!(prepared_device_set_is_exact(
            &desired,
            std::slice::from_ref(&prepared)
        ));

        let mut desired_with_extra = desired.clone();
        let mut extra = desired_with_extra.volumes[0].clone();
        extra.volume_id = Id::new("vol_extra").unwrap();
        desired_with_extra.volumes.push(extra);
        assert!(!prepared_device_set_is_exact(
            &desired_with_extra,
            std::slice::from_ref(&prepared)
        ));
        assert!(!prepared_device_set_is_exact(
            &desired,
            &[prepared.clone(), prepared]
        ));
    }

    #[test]
    fn takeover_volume_remains_exact_through_prepare_network_and_start_runtime() {
        for encoded_checkpoint in [PREPARE_NETWORK, START_RUNTIME] {
            let mut checkpoint = decode_runtime_checkpoint(encoded_checkpoint).unwrap();
            let mut desired = desired_for(&checkpoint.cat_id);
            let authorization_id = Id::new("takeover_auth_root").unwrap();
            desired.volumes[0].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            checkpoint.spec_digest = desired.spec_digest.clone();

            let acquire_origin = cats_api::runtime_reconciliation::AcquireOrigin::Takeover {
                authorization_id: authorization_id.clone(),
            };
            match &mut checkpoint.step {
                ReconcileStep::PrepareNetwork { devices, .. }
                | ReconcileStep::StartRuntime { devices, .. } => {
                    devices[0].acquire_origin = acquire_origin.clone();
                }
                _ => panic!("fixture must be a downstream launch phase"),
            }
            if let RuntimeLaunch::Present(identity) = &mut checkpoint.runtime_launch {
                identity.devices[0].acquire_origin = acquire_origin.clone();
            }
            checkpoint.volumes[0].local_lineages[0].acquire_origin = acquire_origin;
            let device = match &checkpoint.step {
                ReconcileStep::PrepareNetwork { devices, .. }
                | ReconcileStep::StartRuntime { devices, .. } => devices[0].clone(),
                _ => unreachable!("phase was checked above"),
            };
            let observed_device = match &device.frontend {
                PrepareDeviceFrontend::KernelNbd { device_path, .. } => ObservedDevice::KernelNbd {
                    guest_device: device.guest_device.clone(),
                    device_path: device_path.clone(),
                    ownership_token: OwnershipTokenEvidence::Valid {
                        ownership_token: device.ownership_token.clone(),
                    },
                },
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => {
                    ObservedDevice::VhostUserBlk {
                        guest_device: device.guest_device.clone(),
                        socket_path: socket_path.clone(),
                        ownership_token: OwnershipTokenEvidence::Valid {
                            ownership_token: device.ownership_token.clone(),
                        },
                    }
                }
            };
            checkpoint.volumes[0].devices = vec![observed_device.clone()];
            assert!(prepared_device_set_is_exact(
                &desired,
                std::slice::from_ref(&device)
            ));

            let runtime = ObservedRuntimeStatus {
                cat_id: checkpoint.cat_id.clone(),
                applied_desired: Some(AppliedDesiredEvidence {
                    desired_revision: desired.desired_revision,
                    spec_digest: desired.spec_digest.clone(),
                    placement: desired.placement.clone(),
                    target: desired.target,
                }),
                runtime_incarnation: checkpoint.runtime_incarnation.clone(),
                stable_state: checkpoint.stable_state,
                step: checkpoint.step.clone(),
                checkpoint: CheckpointEvidence::Missing {
                    checkpoint_path: HostPath::new("/var/lib/cats/checkpoints/cat_01.json")
                        .unwrap(),
                },
                processes: Vec::new(),
                volumes: checkpoint.volumes.clone(),
                mounts: checkpoint.mounts.clone(),
                networks: checkpoint.networks.clone(),
                guest_transport: GuestTransportEvidence::Unavailable,
                warm_snapshot: WarmSnapshotEvidence::Absent,
                lifecycle_admission: LifecycleAdmission::Closed,
                routes: Vec::new(),
                platform_guards: 0,
                conditions: vec![Condition::Progressing {
                    reason: ProgressingReason::ReconcileStep {
                        step: checkpoint.step.clone(),
                    },
                }],
            };
            assert!(prepare_network_volume_admission_is_exact(
                &desired,
                &runtime,
                &device,
                &device.volume_id,
                Some(&observed_device),
            ));

            let mut wrong_desired_authorization = desired.clone();
            wrong_desired_authorization.volumes[0].acquire = VolumeAcquire::Takeover {
                authorization_id: Id::new("wrong_takeover_authorization").unwrap(),
            };
            wrong_desired_authorization.spec_digest =
                spec_digest(&wrong_desired_authorization).unwrap();
            assert!(!prepare_network_volume_admission_is_exact(
                &wrong_desired_authorization,
                &runtime,
                &device,
                &device.volume_id,
                Some(&observed_device),
            ));
            let mut wrong_origin = device.clone();
            wrong_origin.acquire_origin = cats_api::runtime_reconciliation::AcquireOrigin::Normal {
                transition_id: random('f'),
            };
            assert!(!prepare_network_volume_admission_is_exact(
                &desired,
                &runtime,
                &wrong_origin,
                &wrong_origin.volume_id,
                Some(&observed_device),
            ));
            let mut wrong_attachment = device.clone();
            wrong_attachment.attachment_id = Id::new("wrong_attachment").unwrap();
            assert!(!prepare_network_volume_admission_is_exact(
                &desired,
                &runtime,
                &wrong_attachment,
                &wrong_attachment.volume_id,
                Some(&observed_device),
            ));
            let mut wrong_epoch = device.clone();
            wrong_epoch.attachment_epoch = cats_api::runtime_reconciliation::FenceEpoch::new(
                wrong_epoch.attachment_epoch.get() + 1,
            )
            .unwrap();
            assert!(!prepare_network_volume_admission_is_exact(
                &desired,
                &runtime,
                &wrong_epoch,
                &wrong_epoch.volume_id,
                Some(&observed_device),
            ));
        }
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
                prepare_network_successor(predecessor, network, vec![prepared])
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
    fn reservation_rejects_network_lock_move_away_replacement_and_move_back_aba() {
        let fixture = Fixture::empty();
        let lock = fixture.state.join(NETWORK_ALLOCATION_LOCK_BASENAME);
        let detached = fixture.state.join("network-allocation-detached.lock");
        let replacement = fixture.state.join("network-allocation-replacement.lock");
        let source = fixed_predecessor();
        let store = fixture.store(&source);
        let predecessor = store.create(&source).unwrap();

        let error = reserve(&fixture, &store, &predecessor, || {
            fs::rename(&lock, &detached).unwrap();
            fs::write(&lock, []).unwrap();
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&lock, &replacement).unwrap();
            fs::rename(&detached, &lock).unwrap();
        })
        .expect_err("move-away/replacement/move-back lock ABA reached checkpoint CAS");
        assert!(
            format!("{error:#}").contains("acquisition identity"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
        assert!(replacement.exists());
    }

    #[test]
    fn reservation_closes_every_durable_range_before_build_or_cas() {
        let fixture = Fixture::with_after_link(Some(("foreign", "10.240.0.5")));
        let script = fs::read_to_string(&fixture.ip)
            .unwrap()
            .replace("catold000001", "foreign0");
        fs::write(&fixture.ip, script).unwrap();
        fs::write(&fixture.marker, b"present").unwrap();

        let source_a = fixed_predecessor();
        let desired_a = desired_for(&source_a.cat_id);
        let store_a = fixture.store(&source_a);
        let predecessor_a = store_a.create(&source_a).unwrap();
        let identity_a = RuntimeNetworkIdentity {
            network_config: desired_a.runtime.network_config.clone(),
            tap_name: Id::new("cata00000001").unwrap(),
            ownership_token: random('e'),
        };
        let prepared_a = prepared_device_input(&source_a).unwrap();
        let reserved_a =
            prepare_network_successor(&predecessor_a, identity_a, vec![prepared_a]).unwrap();
        store_a.replace(&predecessor_a, &reserved_a).unwrap();

        let cat_b = Id::new("cat_b").unwrap();
        let mut source_b = fixed_predecessor();
        source_b.cat_id = cat_b.clone();
        let ReconcileStep::PrepareDevice { devices } = &mut source_b.step else {
            panic!("fixture is not PrepareDevice")
        };
        devices[0].ownership_token = random('b');
        devices[0].serving_process.process_identity_token = random('c');
        let mut desired_b = desired_for(&cat_b);
        desired_b.runtime.network_config = NetworkConfig {
            network_id: Id::new("net_b").unwrap(),
            gateway_ipv4: cats_api::runtime_reconciliation::Ipv4Address::new("10.240.0.9").unwrap(),
            guest_ipv4: cats_api::runtime_reconciliation::Ipv4Address::new("10.240.0.10").unwrap(),
            guest_mac: cats_api::runtime_reconciliation::MacAddress::new("02:ca:0a:f0:00:0a")
                .unwrap(),
            ..desired_b.runtime.network_config.clone()
        };
        let store_b = fixture.store(&source_b);
        let predecessor_b = store_b.create(&source_b).unwrap();
        let prepared_b = prepared_device_input(&source_b).unwrap();
        let context =
            desired_effect_context_for(&fixture.state, vec![desired_a, desired_b.clone()]);
        let build_called = Cell::new(false);

        let error = fixture
            .port()
            .reserve_and_replace(
                &context,
                &store_b,
                &predecessor_b,
                &desired_b.runtime.network_config,
                || Ok(()),
                |network| {
                    build_called.set(true);
                    prepare_network_successor(&predecessor_b, network, vec![prepared_b])
                },
            )
            .expect_err("foreign owner of Cat A's durable range reached Cat B reservation CAS");
        assert!(
            format!("{error:#}").contains("durable Host network range"),
            "{error:#}"
        );
        assert!(
            !build_called.get(),
            "range conflict reached successor build"
        );
        assert_eq!(
            store_b.load().unwrap().unwrap().checkpoint(),
            predecessor_b.checkpoint()
        );
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
        let distinct_network = NetworkConfig {
            network_id: Id::new("net_b").unwrap(),
            gateway_ipv4: cats_api::runtime_reconciliation::Ipv4Address::new("10.240.0.9").unwrap(),
            guest_ipv4: cats_api::runtime_reconciliation::Ipv4Address::new("10.240.0.10").unwrap(),
            guest_mac: cats_api::runtime_reconciliation::MacAddress::new("02:ca:0a:f0:00:0a")
                .unwrap(),
            ..first.identity.network_config.clone()
        };
        let mut reservations = NetworkReservations::default();
        reservations.insert(first.clone()).unwrap();
        for second in [
            NetworkReservation {
                cat_id: Id::new("cat_b").unwrap(),
                identity: RuntimeNetworkIdentity {
                    tap_name: first.identity.tap_name.clone(),
                    ownership_token: random('b'),
                    network_config: distinct_network.clone(),
                },
            },
            NetworkReservation {
                cat_id: Id::new("cat_b").unwrap(),
                identity: RuntimeNetworkIdentity {
                    tap_name: Id::new("catb00000001").unwrap(),
                    ownership_token: first.identity.ownership_token.clone(),
                    network_config: distinct_network.clone(),
                },
            },
        ] {
            assert!(reservations.insert(second).is_err());
        }

        let overlapping_absent_reservation = NetworkReservation {
            cat_id: Id::new("cat_b").unwrap(),
            identity: RuntimeNetworkIdentity {
                tap_name: Id::new("catb00000002").unwrap(),
                ownership_token: random('d'),
                network_config: NetworkConfig {
                    network_id: Id::new("net_overlap").unwrap(),
                    ..first.identity.network_config.clone()
                },
            },
        };
        let overlap = reservations
            .insert(overlapping_absent_reservation)
            .expect_err("two durable absent TAP reservations overlapped");
        assert!(format!("{overlap:#}").contains("overlaps"));

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
                    ..distinct_network
                },
            },
        };
        assert!(reservations.assert_candidate_available(&fresh).is_err());
    }

    #[test]
    fn sealed_network_admission_binds_only_the_exact_full_observation() {
        let fixture = Fixture::empty();
        let context = desired_effect_context(&fixture.state, &[]);
        let observation = context.accepted_full().unwrap().observation().clone();
        let physical =
            inspect_host_network_snapshot(&fixture.ip, &TestPhysicalContext::active()).unwrap();
        let bound = NodeGlobalNetworkScanAdmission::new([], physical)
            .unwrap()
            .bind(&observation)
            .unwrap();
        let context = context.with_node_global_network_for_test(bound.clone());
        assert!(context
            .node_global_network()
            .unwrap()
            .matches_observation(&observation));

        let mut changed = observation;
        changed.inventory_epoch = Epoch::new(2).unwrap();
        assert!(!bound.matches_observation(&changed));
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

//! Exact provider-private inventory and reservation for the ADR-0015
//! kernel-NBD frontend.
//!
//! A `/dev/nbdN` path becomes part of a `PrepareDevice` checkpoint before the
//! attach effect and remains in every launch successor. Two concurrent Cats
//! must therefore serialize the sequence
//! "read every durable reservation -> prove the slot free -> fsync the new
//! checkpoint". [`KernelNbdAllocationPermit`] retains the Node-global flock
//! and one exact pool snapshot across that caller-owned checkpoint replace.
//! The sealed attach port reuses that same flock and strict inspector around
//! one fixed `nbd-client` submission. Detach and leak cleanup remain separate,
//! checkpoint-first effects.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, CheckpointEvidence, Epoch, FenceEpoch, GuestDeviceIdentity,
    HostPath, Id, NodeBootId, NodeObservation, ObservedDevice, OwnershipTokenEvidence,
    PrepareDeviceFrontend, PreparedDeviceInput, RandomId128, ReconcileStep, RuntimeCheckpoint,
    RuntimeTarget, RuntimeTransition, Sequence, Sha256Digest, WireU64,
};
use cats_storage::authority::VolumeDataAuthority;

use crate::runtime_spine::{
    effect_resource_owner_sealed, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason, RuntimeEffectResourceOwner, RuntimePhysicalReadContext,
};
use crate::state_directory::StateDirectory;

use super::authorized_blockd::AuthorizedBlockdStore;
use super::checkpoint::{
    revalidate_checkpoint_namespace, CurrentCheckpointGuard, FileCheckpointStore, StoredCheckpoint,
};
use super::clean_slate_probes::{
    snapshot_runtime_checkpoint_namespace, RuntimeCheckpointNamespaceSnapshot,
    CHECKPOINT_NAMESPACE, RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
};
use super::network::{prepare_network_volume_admission_is_exact, prepared_device_input};
use super::prepare_device_retirement::prepare_device_base_admission_is_exact;
use super::root_provision_process::NodeGlobalManagedProcessScanAdmission;
use super::serving_blockd_process::ServingBlockdListenerProof;
use super::serving_handoff::ServingHandoffStore;
use super::serving_handoff_effect::checkpoint_is_current_exact;
use super::signed_root_provision::signed_inventory_admission_is_exact_with_networks;

const ALLOCATION_LOCK_BASENAME: &str = "kernel-nbd-allocation.lock";
const MAX_SYSFS_ATTRIBUTE_BYTES: u64 = 64;
const MAX_PROC_STAT_BYTES: u64 = 64 * 1024;
const MAX_PROC_CMDLINE_BYTES: u64 = 64 * 1024;
const CLIENT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CLIENT_CLEANUP_GRACE: Duration = Duration::from_millis(50);
// V1 admits at most 1,024 Cats with 64 volumes each. A Host pool cannot need
// more slots than that closed product bound, and rejecting it here prevents a
// misconfigured u32-sized eager allocation before the first deadline probe.
const MAX_KERNEL_NBD_DEVICE_COUNT: u32 = 1_024 * 64;

pub(crate) mod attach_port_sealed {
    pub(crate) trait Sealed {}
}

pub(crate) mod retained_listener_sealed {
    pub(crate) trait Sealed {}
}

#[derive(Debug, Clone)]
pub(crate) struct KernelNbdInventoryConfig {
    state_directory: StateDirectory,
    sys_block_root: PathBuf,
    proc_root: PathBuf,
    nbd_client_binary: PathBuf,
    // `nbd-client` inherits this Node process identity. Freeze it with the
    // rest of the installed scanner configuration instead of reinterpreting a
    // later effective-uid change as exact provider evidence.
    client_process_user_id: u32,
    device_count: u32,
}

impl KernelNbdInventoryConfig {
    pub(crate) fn installed(
        state_directory: StateDirectory,
        nbd_client_binary: PathBuf,
        device_count: u32,
    ) -> Result<Self> {
        anyhow::ensure!(device_count > 0, "kernel-NBD pool must not be empty");
        anyhow::ensure!(
            device_count <= MAX_KERNEL_NBD_DEVICE_COUNT,
            "kernel-NBD pool exceeds the closed V1 device-count bound"
        );
        anyhow::ensure!(cfg!(target_os = "linux"), "kernel NBD requires Linux");
        anyhow::ensure!(
            nbd_client_binary.is_absolute(),
            "kernel-NBD client binary must be absolute"
        );
        let binary_text = nbd_client_binary
            .to_str()
            .context("kernel-NBD client binary path must be UTF-8")?;
        HostPath::new(binary_text.to_owned())
            .context("kernel-NBD client binary must be a canonical HostPath")?;
        Ok(Self {
            state_directory,
            sys_block_root: PathBuf::from("/sys/block"),
            proc_root: PathBuf::from("/proc"),
            nbd_client_binary,
            client_process_user_id: effective_user_id(),
            device_count,
        })
    }

    pub(crate) fn state_directory(&self) -> &StateDirectory {
        &self.state_directory
    }

    pub(crate) fn device_count(&self) -> u32 {
        self.device_count
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
            client_process_user_id: effective_user_id(),
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
    pub(crate) size_sectors: WireU64,
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
    /// This bounded sample could not distinguish free, serving or leaked.
    /// It is never allocatable and never authorizes a public projection.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdPoolSnapshot {
    slots: BTreeMap<HostPath, KernelNbdSlotState>,
    // BTreeMap's lexical path order places nbd10 before nbd2. Retain the
    // configured numeric order so allocation is stable by device index.
    ordered_paths: Vec<HostPath>,
}

impl KernelNbdPoolSnapshot {
    pub(crate) fn state(&self, path: &HostPath) -> Option<&KernelNbdSlotState> {
        self.slots.get(path)
    }

    /// Provider-private physical evidence for a later inventory join.  These
    /// identities deliberately contain no device ownership token; that token
    /// can only come from the independently verified serving-blockd status
    /// handshake.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (&HostPath, &KernelNbdSlotState)> {
        self.ordered_paths.iter().map(|path| {
            (
                path,
                self.slots
                    .get(path)
                    .expect("ordered kernel-NBD path is present in the same snapshot"),
            )
        })
    }
}

/// The exact durable reservation that authorizes one kernel-NBD client
/// submission.  Callers cannot fill these fields from Desired or inventory:
/// the only constructor below derives them from one decoded, digest-bound
/// [`StoredCheckpoint`], and the port compares that checkpoint again while
/// holding both the per-Cat writer guard and Node-global allocation flock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdAttachRequest {
    checkpoint_content_digest: Sha256Digest,
    cat_id: Id,
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    ownership_token: RandomId128,
    serving_process_identity_token: RandomId128,
    listener_socket_path: HostPath,
    device_path: HostPath,
    expected_size_sectors: WireU64,
}

impl KernelNbdAttachRequest {
    pub(crate) fn from_checkpoint(stored: &StoredCheckpoint) -> Result<Self> {
        let request = Self::from_runtime_checkpoint(stored.checkpoint())?;
        anyhow::ensure!(
            request.checkpoint_content_digest == *stored.content_digest(),
            "kernel-NBD stored checkpoint digest changed during request projection"
        );
        Ok(request)
    }

    fn from_runtime_checkpoint(checkpoint: &RuntimeCheckpoint) -> Result<Self> {
        let prepared = prepared_device_input(checkpoint)
            .context("kernel-NBD attach requires retained PrepareDevice authority")?;
        let PreparedDeviceInput {
            volume_id,
            attachment_id,
            attachment_epoch,
            size_bytes,
            ownership_token,
            serving_process,
            frontend,
            ..
        } = prepared;
        let PrepareDeviceFrontend::KernelNbd {
            listener_socket_path,
            device_path,
            ..
        } = frontend
        else {
            anyhow::bail!("kernel-NBD attach checkpoint selects another frontend")
        };
        anyhow::ensure!(
            size_bytes % 512 == 0,
            "kernel-NBD checkpoint size is not 512-byte aligned"
        );
        let expected_size_sectors = WireU64::new(size_bytes / 512)
            .filter(|sectors| sectors.get() > 0)
            .context("kernel-NBD checkpoint size has no positive sector capacity")?;
        Ok(Self {
            checkpoint_content_digest: checkpoint_content_digest(checkpoint)
                .context("digest kernel-NBD attach checkpoint")?,
            cat_id: checkpoint.cat_id.clone(),
            volume_id,
            attachment_id,
            attachment_epoch,
            ownership_token,
            serving_process_identity_token: serving_process.process_identity_token,
            listener_socket_path,
            device_path,
            expected_size_sectors,
        })
    }

    fn assert_listener_proof(
        &self,
        listener_socket_path: &HostPath,
        serving_process_identity_token: &RandomId128,
    ) -> Result<()> {
        anyhow::ensure!(
            listener_socket_path == &self.listener_socket_path
                && serving_process_identity_token == &self.serving_process_identity_token,
            "serving listener proof does not bind the checkpointed path and process token"
        );
        Ok(())
    }
}

/// Persisted device contract shared by `PrepareDevice` and every successor
/// checkpoint. Unlike public `ObservedDevice`, this retains the complete
/// attachment/process/frontend authority needed to join a physical client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdDeviceExpectation {
    cat_id: Id,
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    ownership_token: RandomId128,
    serving_process_identity_token: RandomId128,
    listener_socket_path: HostPath,
    device_path: HostPath,
    expected_size_sectors: WireU64,
    guest_device: GuestDeviceIdentity,
    prepared_device: PreparedDeviceInput,
}

impl KernelNbdDeviceExpectation {
    pub(super) fn from_prepare_device(checkpoint: &RuntimeCheckpoint) -> Result<Option<Self>> {
        if !matches!(checkpoint.step, ReconcileStep::PrepareDevice { .. }) {
            return Ok(None);
        }
        let prepared = super::network::prepared_device_input(checkpoint)?;
        Self::from_prepared_device(&checkpoint.cat_id, &prepared)
    }

    fn from_prepared_device(cat_id: &Id, prepared: &PreparedDeviceInput) -> Result<Option<Self>> {
        let PrepareDeviceFrontend::KernelNbd {
            listener_socket_path,
            device_path,
            ..
        } = &prepared.frontend
        else {
            return Ok(None);
        };
        anyhow::ensure!(
            prepared.size_bytes > 0 && prepared.size_bytes.is_multiple_of(512),
            "persisted kernel-NBD device size is not positive and 512-byte aligned"
        );
        let expected_size_sectors = WireU64::new(prepared.size_bytes / 512)
            .context("persisted kernel-NBD device capacity exceeds the wire range")?;
        anyhow::ensure!(
            prepared.serving_process.process_identity_token != prepared.ownership_token,
            "persisted kernel-NBD process and device tokens alias"
        );
        Ok(Some(Self {
            cat_id: cat_id.clone(),
            volume_id: prepared.volume_id.clone(),
            attachment_id: prepared.attachment_id.clone(),
            attachment_epoch: prepared.attachment_epoch,
            ownership_token: prepared.ownership_token.clone(),
            serving_process_identity_token: prepared.serving_process.process_identity_token.clone(),
            listener_socket_path: listener_socket_path.clone(),
            device_path: device_path.clone(),
            expected_size_sectors,
            guest_device: prepared.guest_device.clone(),
            prepared_device: prepared.clone(),
        }))
    }

    fn reservation(&self) -> KernelNbdReservation {
        KernelNbdReservation {
            cat_id: self.cat_id.clone(),
            volume_id: self.volume_id.clone(),
            device_path: self.device_path.clone(),
            ownership_token: self.ownership_token.clone(),
        }
    }

    fn matches_attach_request(&self, request: &KernelNbdAttachRequest) -> bool {
        self.cat_id == request.cat_id
            && self.volume_id == request.volume_id
            && self.attachment_id == request.attachment_id
            && self.attachment_epoch == request.attachment_epoch
            && self.ownership_token == request.ownership_token
            && self.serving_process_identity_token == request.serving_process_identity_token
            && self.listener_socket_path == request.listener_socket_path
            && self.device_path == request.device_path
            && self.expected_size_sectors == request.expected_size_sectors
    }

    fn matches_prepared_device(&self, cat_id: &Id, prepared: &PreparedDeviceInput) -> bool {
        self.cat_id == *cat_id && self.prepared_device == *prepared
    }

    fn observed_device(&self) -> ObservedDevice {
        ObservedDevice::KernelNbd {
            guest_device: self.guest_device.clone(),
            device_path: self.device_path.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: self.ownership_token.clone(),
            },
        }
    }
}

/// Exact public-device authority. Its constructor is private to the joint
/// scanner and requires both the strict client inspection and the independent
/// authorized-serving proof which minted the device token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactKernelNbdDeviceProof {
    expected: KernelNbdDeviceExpectation,
    client: KernelNbdClientIdentity,
    listener: ServingBlockdListenerProof,
}

impl ExactKernelNbdDeviceProof {
    fn new(
        expected: KernelNbdDeviceExpectation,
        client: KernelNbdClientIdentity,
        listener: ServingBlockdListenerProof,
    ) -> Result<Self> {
        anyhow::ensure!(
            client.listener_socket_path == expected.listener_socket_path
                && client.device_path == expected.device_path
                && client.size_sectors == expected.expected_size_sectors,
            "kernel-NBD client does not match its persisted device contract"
        );
        expected.assert_serving_listener(&listener)?;
        Ok(Self {
            expected,
            client,
            listener,
        })
    }

    pub(crate) fn projection(&self) -> (Id, ObservedDevice) {
        (
            self.expected.volume_id.clone(),
            self.expected.observed_device(),
        )
    }

    pub(crate) fn listener(&self) -> &ServingBlockdListenerProof {
        &self.listener
    }

    pub(crate) fn matches_prepared_device(
        &self,
        cat_id: &Id,
        prepared: &PreparedDeviceInput,
    ) -> bool {
        self.expected.matches_prepared_device(cat_id, prepared)
    }
}

impl KernelNbdDeviceExpectation {
    pub(super) fn assert_serving_listener(
        &self,
        listener: &ServingBlockdListenerProof,
    ) -> Result<()> {
        anyhow::ensure!(
            listener
                .expectation()
                .matches_device_contract(&self.cat_id, &self.prepared_device),
            "authorized-serving proof does not match the persisted kernel-NBD contract"
        );
        Ok(())
    }
}

/// Explicit state for one durable kernel-NBD reservation in a complete pool
/// scan. `Absent` may retain no listener when serving blockd itself is absent;
/// only `attachable_listener` below can authorize a submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KernelNbdDeviceScanState {
    Absent {
        expected: KernelNbdDeviceExpectation,
        listener: Option<ServingBlockdListenerProof>,
    },
    Exact(ExactKernelNbdDeviceProof),
    Leaked {
        expected: KernelNbdDeviceExpectation,
        recorded_process_id: Option<u32>,
    },
    Unavailable {
        expected: KernelNbdDeviceExpectation,
    },
}

/// Unbound provider-private output of one allocation-flock-protected full
/// checkpoint namespace and physical pool scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdPoolScanAdmission {
    devices_by_cat: BTreeMap<Id, KernelNbdDeviceScanState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KernelNbdPoolScanOutcome {
    Complete(KernelNbdPoolScanAdmission),
    Unavailable,
}

/// The same closed scan after binding the exact observation bytes accepted by
/// Control. It is process-local and cannot be reconstructed from checkpoint or
/// public `ObservedDevice` fields after restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelNbdPoolAdmission {
    observation_id: RandomId128,
    node_id: Id,
    node_boot_id: NodeBootId,
    agent_instance_id: RandomId128,
    agent_session_epoch: Epoch,
    inventory_epoch: Epoch,
    inventory_digest: Sha256Digest,
    inventory_read_position: Sequence,
    devices_by_cat: BTreeMap<Id, KernelNbdDeviceScanState>,
}

impl KernelNbdPoolScanAdmission {
    #[cfg(test)]
    fn expectation_for_test(checkpoint: &RuntimeCheckpoint) -> Result<KernelNbdDeviceExpectation> {
        let expected = match &checkpoint.step {
            ReconcileStep::PrepareNetwork { devices, .. }
            | ReconcileStep::StartRuntime { devices, .. } => {
                let [device] = devices.as_slice() else {
                    anyhow::bail!("test kernel-NBD admission requires one prepared device")
                };
                KernelNbdDeviceExpectation::from_prepared_device(&checkpoint.cat_id, device)?
            }
            _ => KernelNbdDeviceExpectation::from_prepare_device(checkpoint)?,
        };
        expected.context("test kernel-NBD admission requires a kernel-NBD prepared device")
    }

    #[cfg(test)]
    pub(super) fn absent_for_test(
        observation: &NodeObservation,
        checkpoint: &RuntimeCheckpoint,
        listener: ServingBlockdListenerProof,
    ) -> Result<KernelNbdPoolAdmission> {
        let expected = Self::expectation_for_test(checkpoint)?;
        expected.assert_serving_listener(&listener)?;
        Self {
            devices_by_cat: BTreeMap::from([(
                checkpoint.cat_id.clone(),
                KernelNbdDeviceScanState::Absent {
                    expected,
                    listener: Some(listener),
                },
            )]),
        }
        .bind(observation)
    }

    #[cfg(test)]
    pub(super) fn exact_for_test(
        observation: &NodeObservation,
        checkpoint: &RuntimeCheckpoint,
        listener: ServingBlockdListenerProof,
    ) -> Result<KernelNbdPoolAdmission> {
        let expected = Self::expectation_for_test(checkpoint)?;
        expected.assert_serving_listener(&listener)?;
        let client = KernelNbdClientIdentity {
            process_id: 47,
            process_start_time_ticks: WireU64::new(91)
                .context("test kernel-NBD process ticks are positive")?,
            executable_path: HostPath::new("/usr/bin/nbd-client")
                .context("test kernel-NBD executable path is canonical")?,
            listener_socket_path: expected.listener_socket_path.clone(),
            device_path: expected.device_path.clone(),
            size_sectors: expected.expected_size_sectors,
        };
        let proof = ExactKernelNbdDeviceProof::new(expected, client, listener)?;
        Self {
            devices_by_cat: BTreeMap::from([(
                checkpoint.cat_id.clone(),
                KernelNbdDeviceScanState::Exact(proof),
            )]),
        }
        .bind(observation)
    }

    pub(crate) fn has_unavailable_device(&self) -> bool {
        self.devices_by_cat
            .values()
            .any(|state| matches!(state, KernelNbdDeviceScanState::Unavailable { .. }))
    }

    pub(crate) fn device_projections(&self) -> BTreeMap<Id, (Id, ObservedDevice)> {
        self.devices_by_cat
            .iter()
            .filter_map(|(cat_id, state)| match state {
                KernelNbdDeviceScanState::Exact(proof) => {
                    Some((cat_id.clone(), proof.projection()))
                }
                KernelNbdDeviceScanState::Absent { .. }
                | KernelNbdDeviceScanState::Leaked { .. }
                | KernelNbdDeviceScanState::Unavailable { .. } => None,
            })
            .collect()
    }

    pub(crate) fn bind(self, observation: &NodeObservation) -> Result<KernelNbdPoolAdmission> {
        anyhow::ensure!(
            observation.complete_inventory,
            "kernel-NBD admission requires a complete observation"
        );
        let inventory_digest = observation
            .inventory_digest
            .clone()
            .context("kernel-NBD admission observation has no inventory digest")?;
        let inventory_read_position = observation
            .inventory_read_position
            .context("kernel-NBD admission observation has no read position")?;
        Ok(KernelNbdPoolAdmission {
            observation_id: observation.observation_id.clone(),
            node_id: observation.node_id.clone(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest,
            inventory_read_position,
            devices_by_cat: self.devices_by_cat,
        })
    }
}

impl KernelNbdPoolAdmission {
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

    pub(crate) fn device(&self, cat_id: &Id) -> Option<&KernelNbdDeviceScanState> {
        self.devices_by_cat.get(cat_id)
    }

    pub(crate) fn exact_device(&self, cat_id: &Id) -> Option<&ExactKernelNbdDeviceProof> {
        match self.device(cat_id) {
            Some(KernelNbdDeviceScanState::Exact(proof)) => Some(proof),
            _ => None,
        }
    }
}

/// Descriptor-stable identity of the listener owned by the exact serving
/// blockd incarnation. The socket device/inode are required in addition to
/// path and process token, so unlink/rebind and PID reuse cannot pass a
/// checkpoint-only join.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct RetainedKernelNbdListenerIdentity {
    pub(crate) listener_socket_path: HostPath,
    pub(crate) socket_device: WireU64,
    pub(crate) socket_inode: WireU64,
    pub(crate) serving_process_id: u32,
    pub(crate) serving_process_start_time_ticks: WireU64,
    pub(crate) serving_process_identity_token: RandomId128,
}

#[cfg(test)]
impl RetainedKernelNbdListenerIdentity {
    pub(crate) fn new(
        listener_socket_path: HostPath,
        socket_device: WireU64,
        socket_inode: WireU64,
        serving_process_id: u32,
        serving_process_start_time_ticks: WireU64,
        serving_process_identity_token: RandomId128,
    ) -> Result<Self> {
        anyhow::ensure!(
            socket_inode.get() > 0
                && serving_process_id > 0
                && serving_process_start_time_ticks.get() > 0,
            "retained kernel-NBD listener identity has a zero physical coordinate"
        );
        Ok(Self {
            listener_socket_path,
            socket_device,
            socket_inode,
            serving_process_id,
            serving_process_start_time_ticks,
            serving_process_identity_token,
        })
    }
}

/// Sealed retained listener capability supplied by the serving-blockd owner.
/// `assert_current` must reopen the lexical socket and revalidate the exact
/// retained descriptor/process identity. A path, bool, PID, or token alone
/// cannot implement this boundary.
pub(crate) trait RetainedKernelNbdListenerGuard:
    retained_listener_sealed::Sealed + Send + Sync
{
    /// Revalidate the retained descriptor chain, kernel socket inode, unique
    /// process holder and process incarnation against this exact checkpoint.
    /// Keeping the request and physical-read context inside this sealed call
    /// prevents a path/PID/token tuple from being used as a listener permit.
    fn assert_current_for(
        &self,
        request: &KernelNbdAttachRequest,
        context: &dyn RuntimePhysicalReadContext,
    ) -> Result<()>;
}

impl retained_listener_sealed::Sealed for ServingBlockdListenerProof {}

impl RetainedKernelNbdListenerGuard for ServingBlockdListenerProof {
    fn assert_current_for(
        &self,
        request: &KernelNbdAttachRequest,
        context: &dyn RuntimePhysicalReadContext,
    ) -> Result<()> {
        request.assert_listener_proof(self.listener_path(), self.process_identity_token())?;
        ServingBlockdListenerProof::assert_current(self, context)
    }
}

/// Result of exactly one client submission.  `OutcomeUnknown` is a terminal
/// result for this accepted effect batch: only a successor fresh full scan may
/// decide whether the client appeared.  It never authorizes an in-call retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KernelNbdAttachResult {
    Exact(KernelNbdClientIdentity),
    OutcomeUnknown,
    ConflictAfterSubmit(KernelNbdAttachConflict),
}

/// A physical conflict proved only after one client submission. Every variant
/// is terminal for the accepted effect batch: the caller must publish and
/// accept a successor full inventory before planning another effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KernelNbdAttachConflict {
    LiveClientIdentity,
    LeakedOrIncompleteAttachment { recorded_process_id: Option<u32> },
}

/// Sealed provider boundary for the one bounded kernel-NBD attach effect.
/// This foundation accepts only the serving owner's retained physical listener
/// guard and emits no public `ObservedDevice`; the later composition layer
/// still has to join the independent device token before projection.
pub(crate) trait KernelNbdAttachPort:
    attach_port_sealed::Sealed + Send + Sync + 'static
{
    fn attach_checkpointed(
        &self,
        request: &KernelNbdAttachRequest,
        listener: &dyn RetainedKernelNbdListenerGuard,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        context: &RuntimeDesiredEffectContext,
    ) -> Result<KernelNbdAttachResult>;
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
    by_ownership_token: BTreeMap<RandomId128, KernelNbdReservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KernelNbdReservationIdentity {
    cat_id: Id,
    volume_id: Id,
    ownership_token: RandomId128,
}

fn reservation_from_prepare_device(checkpoint: &RuntimeCheckpoint) -> Result<KernelNbdReservation> {
    let ReconcileStep::PrepareDevice {
        volume_id,
        ownership_token,
        frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("checkpoint is not a kernel-NBD PrepareDevice reservation");
    };
    Ok(KernelNbdReservation {
        cat_id: checkpoint.cat_id.clone(),
        volume_id: volume_id.clone(),
        device_path: device_path.clone(),
        ownership_token: ownership_token.clone(),
    })
}

fn reservation_from_prepared_device(
    cat_id: &Id,
    prepared: &PreparedDeviceInput,
) -> Option<KernelNbdReservation> {
    let PrepareDeviceFrontend::KernelNbd { device_path, .. } = &prepared.frontend else {
        return None;
    };
    Some(KernelNbdReservation {
        cat_id: cat_id.clone(),
        volume_id: prepared.volume_id.clone(),
        device_path: device_path.clone(),
        ownership_token: prepared.ownership_token.clone(),
    })
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
            reservations.insert_checkpoint(checkpoint)?;
        }
        Ok(reservations)
    }

    /// Rebuild the exact namespace state which will exist after one atomic
    /// per-Cat checkpoint replacement. Validating only the incumbent snapshot
    /// would let the newly generated device token or selected path collide at
    /// the publication boundary itself.
    fn after_replacing(
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        predecessor: &RuntimeCheckpoint,
        replacement: &RuntimeCheckpoint,
    ) -> Result<Self> {
        anyhow::ensure!(
            replacement.cat_id == predecessor.cat_id,
            "kernel-NBD reservation replacement changed its Cat identity"
        );
        let mut found_predecessor = false;
        let mut reservations = Self::default();
        for checkpoint in snapshot.iter_checkpoints() {
            if checkpoint.cat_id == predecessor.cat_id {
                anyhow::ensure!(
                    checkpoint == predecessor && !found_predecessor,
                    "kernel-NBD prospective reservation lacks its exact predecessor"
                );
                found_predecessor = true;
                reservations.insert_checkpoint(replacement)?;
            } else {
                reservations.insert_checkpoint(checkpoint)?;
            }
        }
        anyhow::ensure!(
            found_predecessor,
            "kernel-NBD prospective reservation omitted its predecessor Cat"
        );
        Ok(reservations)
    }

    fn insert_checkpoint(&mut self, checkpoint: &RuntimeCheckpoint) -> Result<()> {
        if let ReconcileStep::PrepareDevice {
            volume_id,
            ownership_token,
            frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
            ..
        } = &checkpoint.step
        {
            self.insert(KernelNbdReservation {
                cat_id: checkpoint.cat_id.clone(),
                volume_id: volume_id.clone(),
                device_path: device_path.clone(),
                ownership_token: ownership_token.clone(),
            })?;
        }
        if let ReconcileStep::PrepareNetwork { devices, .. }
        | ReconcileStep::StartRuntime { devices, .. } = &checkpoint.step
        {
            for reservation in devices
                .iter()
                .filter_map(|device| reservation_from_prepared_device(&checkpoint.cat_id, device))
            {
                self.insert(reservation)?;
            }
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
                    anyhow::bail!("durable kernel-NBD reservation has no valid ownership token");
                };
                self.insert(KernelNbdReservation {
                    cat_id: checkpoint.cat_id.clone(),
                    volume_id: volume.volume_id.clone(),
                    device_path: device_path.clone(),
                    ownership_token: ownership_token.clone(),
                })?;
            }
        }
        Ok(())
    }

    fn insert(&mut self, candidate: KernelNbdReservation) -> Result<()> {
        let identity = KernelNbdReservationIdentity {
            cat_id: candidate.cat_id.clone(),
            volume_id: candidate.volume_id.clone(),
            ownership_token: candidate.ownership_token.clone(),
        };
        if let Some(existing) = self.by_ownership_token.get(&candidate.ownership_token) {
            anyhow::ensure!(
                existing == &candidate,
                "kernel-NBD device ownership token is reused by conflicting identities"
            );
        }
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
        self.by_ownership_token
            .insert(candidate.ownership_token.clone(), candidate.clone());
        self.by_identity
            .insert(identity, candidate.device_path.clone());
        self.by_device
            .insert(candidate.device_path.clone(), candidate);
        Ok(())
    }

    fn assert_exact(&self, request: &KernelNbdAttachRequest) -> Result<()> {
        let expected = KernelNbdReservation {
            cat_id: request.cat_id.clone(),
            volume_id: request.volume_id.clone(),
            device_path: request.device_path.clone(),
            ownership_token: request.ownership_token.clone(),
        };
        self.assert_contains(
            &expected,
            "kernel-NBD attach lacks its exact durable reservation",
        )
    }

    fn assert_contains(
        &self,
        expected: &KernelNbdReservation,
        mismatch: &'static str,
    ) -> Result<()> {
        let identity = KernelNbdReservationIdentity {
            cat_id: expected.cat_id.clone(),
            volume_id: expected.volume_id.clone(),
            ownership_token: expected.ownership_token.clone(),
        };
        anyhow::ensure!(
            self.by_device.get(&expected.device_path) == Some(expected)
                && self.by_ownership_token.get(&expected.ownership_token) == Some(expected)
                && self.by_identity.get(&identity) == Some(&expected.device_path),
            mismatch
        );
        Ok(())
    }
}

/// Held across the final durable-reservation index read and the caller's
/// atomic checkpoint replace. Dropping it releases only the allocation lock;
/// it never changes a kernel device.
#[derive(Debug)]
pub(crate) struct KernelNbdAllocationPermit {
    state_root: File,
    allocation_lock: File,
    allocation_lock_held: bool,
    snapshot: KernelNbdPoolSnapshot,
    #[cfg(test)]
    injected_unlock_failures: usize,
}

impl KernelNbdAllocationPermit {
    fn state_root(&self) -> &File {
        &self.state_root
    }

    pub(crate) fn snapshot(&self) -> &KernelNbdPoolSnapshot {
        &self.snapshot
    }

    fn configured_index(&self, path: &HostPath) -> Result<u32> {
        self.snapshot
            .ordered_paths
            .iter()
            .position(|candidate| candidate == path)
            .and_then(|index| u32::try_from(index).ok())
            .context("kernel-NBD checkpoint names a device outside the configured pool")
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

    fn assert_current_allocation_lock(&self) -> Result<()> {
        let current = reopen_allocation_lock(&self.state_root)?;
        ensure_same_allocation_lock(&self.allocation_lock, &current)
    }

    fn assert_current_checkpoint_namespace(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        ensure_same_directory(
            snapshot.retained_directory(),
            store.retained_directory(),
            "kernel-NBD snapshot and checkpoint store use different directories",
        )?;
        revalidate_checkpoint_namespace(
            &self.state_root,
            CHECKPOINT_NAMESPACE,
            &[snapshot.retained_directory(), store.retained_directory()],
        )
        .context("kernel-NBD checkpoint namespace pathname changed during locked operation")
        .map(|_| ())
    }

    fn assert_current_scan_paths(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
    ) -> Result<()> {
        self.assert_current_allocation_lock()?;
        revalidate_checkpoint_namespace(
            &self.state_root,
            CHECKPOINT_NAMESPACE,
            &[snapshot.retained_directory()],
        )
        .context("kernel-NBD checkpoint namespace pathname changed during full pool scan")?;
        Ok(())
    }

    fn assert_current_publication_paths(
        &self,
        snapshot: &RuntimeCheckpointNamespaceSnapshot,
        store: &FileCheckpointStore,
    ) -> Result<()> {
        self.assert_current_allocation_lock()?;
        self.assert_current_checkpoint_namespace(snapshot, store)
    }

    /// Explicitly remove the flock from the shared open-file description
    /// before closing our descriptor. A forked child retains the same lock
    /// description until successful exec closes `O_CLOEXEC`; relying on close
    /// alone therefore leaks a short-lived lock after an exec failure.
    fn unlock_allocation_lock(&mut self) -> Result<()> {
        if !self.allocation_lock_held {
            return Ok(());
        }
        #[cfg(test)]
        if self.injected_unlock_failures > 0 {
            self.injected_unlock_failures -= 1;
            anyhow::bail!("injected kernel-NBD allocation unlock failure");
        }
        unlock_exclusive(&self.allocation_lock)?;
        self.allocation_lock_held = false;
        Ok(())
    }

    fn release(mut self) -> Result<()> {
        self.unlock_allocation_lock()
    }

    #[cfg(test)]
    fn inject_unlock_failures(&mut self, count: usize) {
        self.injected_unlock_failures = count;
    }
}

impl Drop for KernelNbdAllocationPermit {
    fn drop(&mut self) {
        // Drop cannot report an error. Retain fail-closed behavior by leaving
        // `allocation_lock_held` set until this last retry succeeds. If it
        // fails again, an inherited descriptor keeps the shared lock alive;
        // this path never returns a false success and never panics.
        let _ = self.unlock_allocation_lock();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KernelNbdInventoryPort {
    config: KernelNbdInventoryConfig,
    #[cfg(test)]
    injected_unlock_failures: usize,
}

impl KernelNbdInventoryPort {
    pub(crate) fn new(config: KernelNbdInventoryConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            injected_unlock_failures: 0,
        }
    }

    pub(crate) fn device_count(&self) -> u32 {
        self.config.device_count()
    }

    /// Reinspect the complete kernel-NBD pool under its allocation flock and
    /// prove that one accepted exact device is still the same client joined
    /// to the same persisted PrepareNetwork contract. This is read-only and
    /// is used immediately around the StartRuntime CID reservation CAS.
    pub(crate) fn revalidate_exact_device(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        admitted: &ExactKernelNbdDeviceProof,
    ) -> Result<()> {
        let permit = self.lock_and_inspect(context)?;
        let context_state_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Desired-effect state root for kernel-NBD revalidation")?;
        ensure_same_directory(
            permit.state_root(),
            &context_state_root,
            "kernel-NBD revalidation and Desired effect use different directories",
        )?;
        let assigned_cats = context.accepted_full()?.assigned_cats()?;
        let namespace = snapshot_runtime_checkpoint_namespace(
            permit.state_root(),
            context,
            assigned_cats,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?
        .context("kernel-NBD revalidation requires a complete checkpoint namespace")?;
        permit.assert_current_publication_paths(&namespace, store)?;
        anyhow::ensure!(
            namespace.checkpoint(&stored.checkpoint().cat_id) == Some(stored.checkpoint()),
            "kernel-NBD StartRuntime predecessor changed in the complete namespace"
        );
        let reservations = KernelNbdReservations::from_snapshot(&namespace)?;
        let expected = device_expectations_from_namespace(&namespace)?
            .into_values()
            .find(|expected| expected.cat_id == stored.checkpoint().cat_id)
            .context("PrepareNetwork lacks its exact kernel-NBD device expectation")?;
        anyhow::ensure!(
            admitted.expected == expected,
            "accepted kernel-NBD proof changed its persisted device expectation"
        );
        reservations.assert_contains(
            &expected.reservation(),
            "kernel-NBD StartRuntime expectation lacks its durable reservation",
        )?;
        permit.configured_index(&expected.device_path)?;
        anyhow::ensure!(
            matches!(
                permit.snapshot().state(&expected.device_path),
                Some(KernelNbdSlotState::Serving(client)) if client == &admitted.client
            ),
            "kernel-NBD client changed before StartRuntime reservation"
        );
        for (path, state) in permit.snapshot().iter() {
            if !reservations.by_device.contains_key(path) {
                anyhow::ensure!(
                    matches!(state, KernelNbdSlotState::Free),
                    "physical kernel-NBD slot has no exact durable reservation"
                );
            }
        }
        admitted.listener().assert_current(context)?;
        permit.assert_current_publication_paths(&namespace, store)?;
        context.check_active()?;
        permit
            .release()
            .context("unlock kernel-NBD allocator after StartRuntime revalidation")
    }

    #[cfg(test)]
    fn inject_unlock_failures(&mut self, count: usize) {
        self.injected_unlock_failures = count;
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
        // Install the explicit-unlock Drop guard immediately after flock
        // succeeds. Even an inventory error must not rely on close while a
        // concurrent fork may retain this open-file description.
        let mut permit = KernelNbdAllocationPermit {
            state_root,
            allocation_lock,
            allocation_lock_held: true,
            snapshot: KernelNbdPoolSnapshot {
                slots: BTreeMap::new(),
                ordered_paths: Vec::new(),
            },
            #[cfg(test)]
            injected_unlock_failures: self.injected_unlock_failures,
        };
        permit.snapshot = inspect_pool(&self.config, context)?;
        permit.assert_current_allocation_lock()?;
        context.check_active()?;
        Ok(permit)
    }

    /// Mint the scanner-only pool admission while one Node-global allocation
    /// flock covers both the complete checkpoint namespace and every physical
    /// slot. No public device is projected here unless the independent
    /// serving-blockd proof and strict client identity form one exact join.
    pub(crate) fn scan_complete_pool(
        &self,
        context: &crate::runtime_spine::RuntimeInventoryScanContext,
        managed_processes: &NodeGlobalManagedProcessScanAdmission,
    ) -> Result<KernelNbdPoolScanOutcome> {
        let permit = self.lock_and_inspect(context)?;
        let result = (|| {
            let assigned_cats = context.assigned_cats()?;
            let Some(namespace) = snapshot_runtime_checkpoint_namespace(
                permit.state_root(),
                context,
                &assigned_cats,
                RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
            )?
            else {
                return Ok(KernelNbdPoolScanOutcome::Unavailable);
            };
            permit.assert_current_scan_paths(&namespace)?;
            let reservations = KernelNbdReservations::from_snapshot(&namespace)?;
            let expectations = device_expectations_from_namespace(&namespace)?;

            for reservation in reservations.by_device.values() {
                permit.configured_index(&reservation.device_path)?;
                let expected = expectations.get(&reservation.device_path).context(
                    "durable kernel-NBD reservation lacks its persisted device contract",
                )?;
                reservations.assert_contains(
                    &expected.reservation(),
                    "persisted kernel-NBD device contract changed its durable reservation",
                )?;
            }
            anyhow::ensure!(
                expectations.len() == reservations.by_device.len(),
                "persisted kernel-NBD device contracts and durable reservations disagree"
            );

            let mut devices_by_cat = BTreeMap::new();
            for (device_path, slot) in permit.snapshot().iter() {
                let reservation = reservations.by_device.get(device_path);
                let expected = expectations.get(device_path);
                let (Some(reservation), Some(expected)) = (reservation, expected) else {
                    anyhow::ensure!(reservation.is_none() && expected.is_none());
                    match slot {
                        KernelNbdSlotState::Free => {}
                        KernelNbdSlotState::Unavailable => {
                            return Ok(KernelNbdPoolScanOutcome::Unavailable);
                        }
                        KernelNbdSlotState::Serving(_) | KernelNbdSlotState::Leaked { .. } => {
                            anyhow::bail!(
                                "physical kernel-NBD slot has no exact durable reservation"
                            )
                        }
                    }
                    continue;
                };
                anyhow::ensure!(
                    reservation == &expected.reservation(),
                    "kernel-NBD reservation and persisted device expectation conflict"
                );

                let listener = match managed_processes.serving_blockd(&expected.cat_id) {
                    Some((_serving_expected, Some(proof))) => {
                        let listener = proof.listener_proof();
                        expected.assert_serving_listener(&listener)?;
                        Some(listener)
                    }
                    Some((_, None)) | None => None,
                };
                let state = match (slot, listener) {
                    (KernelNbdSlotState::Free, listener) => KernelNbdDeviceScanState::Absent {
                        expected: expected.clone(),
                        listener,
                    },
                    (KernelNbdSlotState::Serving(client), Some(listener)) => {
                        match ExactKernelNbdDeviceProof::new(
                            expected.clone(),
                            client.clone(),
                            listener,
                        ) {
                            Ok(proof) => KernelNbdDeviceScanState::Exact(proof),
                            Err(_) => KernelNbdDeviceScanState::Leaked {
                                expected: expected.clone(),
                                recorded_process_id: Some(client.process_id),
                            },
                        }
                    }
                    (KernelNbdSlotState::Serving(client), None) => {
                        KernelNbdDeviceScanState::Leaked {
                            expected: expected.clone(),
                            recorded_process_id: Some(client.process_id),
                        }
                    }
                    (
                        KernelNbdSlotState::Leaked {
                            recorded_process_id,
                        },
                        _,
                    ) => KernelNbdDeviceScanState::Leaked {
                        expected: expected.clone(),
                        recorded_process_id: *recorded_process_id,
                    },
                    (KernelNbdSlotState::Unavailable, _) => KernelNbdDeviceScanState::Unavailable {
                        expected: expected.clone(),
                    },
                };
                anyhow::ensure!(
                    devices_by_cat
                        .insert(expected.cat_id.clone(), state)
                        .is_none(),
                    "kernel-NBD pool admission contains multiple devices for one V1 Cat"
                );
            }
            anyhow::ensure!(
                devices_by_cat.len() == expectations.len(),
                "kernel-NBD pool scan omitted a durable reservation"
            );
            permit.assert_current_scan_paths(&namespace)?;
            context.check_active()?;
            Ok(KernelNbdPoolScanOutcome::Complete(
                KernelNbdPoolScanAdmission { devices_by_cat },
            ))
        })();
        let released = permit
            .release()
            .context("unlock kernel-NBD allocator after complete pool scan");
        match (result, released) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(unlock)) => Err(error.context(format!(
                "kernel-NBD allocation unlock also failed: {unlock:#}"
            ))),
        }
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
        let replacement = build_checkpoint(selected.clone())?;
        let replacement_reservation = reservation_from_prepare_device(&replacement)
            .context("kernel-NBD replacement is not one exact PrepareDevice reservation")?;
        anyhow::ensure!(
            replacement_reservation.device_path == selected,
            "kernel-NBD replacement ignored the allocator-selected device"
        );
        let prospective = KernelNbdReservations::after_replacing(
            &snapshot,
            predecessor.checkpoint(),
            &replacement,
        )?;
        prospective.assert_contains(
            &replacement_reservation,
            "kernel-NBD replacement is not its exact prospective reservation",
        )?;
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
        // Publication may legitimately have crossed the caller's deadline or
        // cancellation boundary while the immutable temp, rename and parent
        // directory barriers completed. The durable reservation remains the
        // recovery source, but this stale admission must never receive a
        // success value that could authorize a second physical effect.
        context.check_active()?;
        permit
            .release()
            .context("unlock kernel-NBD allocator after reservation publication")?;
        Ok(persisted)
    }
}

fn device_expectations_from_namespace(
    namespace: &RuntimeCheckpointNamespaceSnapshot,
) -> Result<BTreeMap<HostPath, KernelNbdDeviceExpectation>> {
    let mut expectations = BTreeMap::new();
    for checkpoint in namespace.iter_checkpoints() {
        let prepared: Vec<&PreparedDeviceInput> = match &checkpoint.step {
            ReconcileStep::PrepareNetwork { devices, .. }
            | ReconcileStep::StartRuntime { devices, .. } => devices.iter().collect(),
            _ => Vec::new(),
        };
        let direct = KernelNbdDeviceExpectation::from_prepare_device(checkpoint)?;
        let candidates = direct.into_iter().chain(
            prepared
                .into_iter()
                .map(|device| {
                    KernelNbdDeviceExpectation::from_prepared_device(&checkpoint.cat_id, device)
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        for expected in candidates {
            let device_path = expected.device_path.clone();
            anyhow::ensure!(
                expectations.insert(device_path, expected).is_none(),
                "kernel-NBD persisted device contracts duplicate one physical path"
            );
        }
    }
    Ok(expectations)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelNbdClientPoll {
    Running,
    Exited { success: bool },
}

/// One child whose parent relationship still belongs to the Node runtime.
/// Implementations must make `poll` nonblocking; the installed adapter uses
/// `Child::try_wait`, which maps to a `waitpid(..., WNOHANG)`-style probe.
trait OwnedKernelNbdClient: Send {
    fn request_kill(&mut self) -> io::Result<()>;

    fn poll(&mut self) -> io::Result<KernelNbdClientPoll>;
}

struct PlatformOwnedKernelNbdClient {
    child: Child,
}

impl OwnedKernelNbdClient for PlatformOwnedKernelNbdClient {
    fn request_kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    fn poll(&mut self) -> io::Result<KernelNbdClientPoll> {
        match self.child.try_wait() {
            Ok(Some(status)) => Ok(KernelNbdClientPoll::Exited {
                success: status.success(),
            }),
            Ok(None) => Ok(KernelNbdClientPoll::Running),
            // The runtime registry is interested in retaining a waitable
            // parent relationship, not an exit status. If another process-wide
            // SIGCHLD owner already reaped it, ECHILD proves there is nothing
            // left for this registry to own or wait on.
            Err(source) if source.raw_os_error() == Some(libc::ECHILD) => {
                Ok(KernelNbdClientPoll::Exited { success: false })
            }
            Err(source) => Err(source),
        }
    }
}

/// Runtime-owned registry for a client which did not become waitable within
/// the attach effect's cleanup grace. No detached reaper is created: the
/// composition that owns the attach port must retain this owner, call
/// [`Self::poll_reap`] between batches, and must not declare its worker joined
/// until [`Self::shutdown_until`] succeeds. A deadline error leaves every
/// unresolved child in this registry so shutdown can be retried.
#[derive(Default)]
pub(crate) struct KernelNbdClientCleanupOwner {
    pending: Mutex<Vec<Box<dyn OwnedKernelNbdClient>>>,
}

impl std::fmt::Debug for KernelNbdClientCleanupOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelNbdClientCleanupOwner")
            .field("pending", &self.pending_count())
            .finish()
    }
}

impl KernelNbdClientCleanupOwner {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.lock_pending().len()
    }

    /// Nonblocking maintenance hook for the runtime owner. Successfully
    /// observed exits are reaped by the underlying `Child::try_wait` call.
    pub(crate) fn poll_reap(&self) -> Result<usize> {
        let mut pending = self.lock_pending();
        let mut index = 0;
        let mut reaped = 0;
        let mut first_error = None;
        while index < pending.len() {
            match pending[index].poll() {
                Ok(KernelNbdClientPoll::Running) => index += 1,
                Ok(KernelNbdClientPoll::Exited { .. }) => {
                    pending.swap_remove(index);
                    reaped += 1;
                }
                Err(source) => {
                    if first_error.is_none() {
                        first_error = Some(source);
                    }
                    // Keep this child but continue probing every later entry;
                    // one bad queue head must not starve reapable siblings.
                    index += 1;
                }
            }
        }
        drop(pending);
        if let Some(source) = first_error {
            Err(source).context("poll transferred kernel-NBD client cleanup")
        } else {
            Ok(reaped)
        }
    }

    /// Bounded worker-shutdown hook. It repeatedly requests termination and
    /// polls without a blocking wait. On deadline it returns an error while
    /// retaining the unresolved children; the runtime must keep this owner and
    /// retry rather than dropping an unowned reaper thread into the process.
    pub(crate) fn shutdown_until(&self, deadline: Instant) -> Result<()> {
        loop {
            {
                let mut pending = self.lock_pending();
                for client in pending.iter_mut() {
                    let _ = client.request_kill();
                }
            }
            self.poll_reap()?;
            let pending = self.pending_count();
            if pending == 0 {
                return Ok(());
            }
            let now = Instant::now();
            anyhow::ensure!(
                now < deadline,
                "{pending} owned kernel-NBD client cleanup(s) outlived the shutdown deadline"
            );
            std::thread::sleep(CLIENT_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
        }
    }

    fn transfer(&self, client: Box<dyn OwnedKernelNbdClient>) {
        self.lock_pending().push(client);
    }

    fn lock_pending(&self) -> MutexGuard<'_, Vec<Box<dyn OwnedKernelNbdClient>>> {
        // A panic must not discard owned children. Recover the inner registry
        // from poison so later runtime shutdown can still poll and reap them.
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl effect_resource_owner_sealed::Sealed for KernelNbdClientCleanupOwner {}

impl RuntimeEffectResourceOwner for KernelNbdClientCleanupOwner {
    fn poll(&self) -> Result<()> {
        self.poll_reap().map(|_| ())
    }

    fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    fn shutdown_until(&self, deadline: Instant) -> Result<()> {
        KernelNbdClientCleanupOwner::shutdown_until(self, deadline)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelNbdClientSubmission {
    Completed,
    OutcomeUnknown,
}

/// Closed boundary around process creation. `NotSubmitted` is permitted only
/// when no child was created and therefore no NBD ioctl can arrive later.
/// Once a child exists, every outcome is `Submitted`, including poll, kill,
/// cancellation and deadline failures.
#[derive(Debug)]
enum KernelNbdClientSubmitAttempt {
    NotSubmitted(anyhow::Error),
    Submitted(KernelNbdClientSubmission),
}

trait KernelNbdClientSubmitPort: Send + Sync + 'static {
    fn submit(
        &self,
        config: &KernelNbdInventoryConfig,
        request: &KernelNbdAttachRequest,
        context: &RuntimeDesiredEffectContext,
        cleanup_owner: &KernelNbdClientCleanupOwner,
    ) -> KernelNbdClientSubmitAttempt;
}

#[derive(Debug, Clone)]
struct ExactKernelNbdAttachPort<S> {
    inventory: KernelNbdInventoryPort,
    submitter: S,
    cleanup_owner: Arc<KernelNbdClientCleanupOwner>,
}

impl<S> ExactKernelNbdAttachPort<S> {
    fn with_cleanup_owner(
        config: KernelNbdInventoryConfig,
        submitter: S,
        cleanup_owner: Arc<KernelNbdClientCleanupOwner>,
    ) -> Self {
        Self {
            inventory: KernelNbdInventoryPort::new(config),
            submitter,
            cleanup_owner,
        }
    }

    #[cfg(test)]
    fn new(config: KernelNbdInventoryConfig, submitter: S) -> Self {
        Self::with_cleanup_owner(
            config,
            submitter,
            Arc::new(KernelNbdClientCleanupOwner::new()),
        )
    }
}

impl<S> attach_port_sealed::Sealed for ExactKernelNbdAttachPort<S> where S: KernelNbdClientSubmitPort
{}

impl<S> KernelNbdAttachPort for ExactKernelNbdAttachPort<S>
where
    S: KernelNbdClientSubmitPort,
{
    fn attach_checkpointed(
        &self,
        request: &KernelNbdAttachRequest,
        listener: &dyn RetainedKernelNbdListenerGuard,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        context: &RuntimeDesiredEffectContext,
    ) -> Result<KernelNbdAttachResult> {
        context.check_active()?;
        let checkpoint_request = KernelNbdAttachRequest::from_checkpoint(stored)?;
        anyhow::ensure!(
            request == &checkpoint_request,
            "kernel-NBD attach request differs from its exact stored checkpoint"
        );

        // The allocation lock is acquired before the per-Cat current-value
        // guard, matching reservation's lock order. It remains held across
        // the command and post-scan, so two cooperating attaches cannot both
        // observe one slot as Free.
        let permit = self.inventory.lock_and_inspect(context)?;
        let context_state_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Desired-effect state root for kernel-NBD attach")?;
        ensure_same_directory(
            permit.state_root(),
            &context_state_root,
            "kernel-NBD Desired context and attach port use different directories",
        )?;
        let assigned_cats = context.accepted_full()?.assigned_cats()?;
        let namespace = snapshot_runtime_checkpoint_namespace(
            permit.state_root(),
            context,
            assigned_cats,
            RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
        )?
        .context("kernel-NBD attach requires a complete checkpoint namespace")?;
        permit.assert_current_publication_paths(&namespace, store)?;
        anyhow::ensure!(
            namespace.checkpoint(&request.cat_id) == Some(stored.checkpoint()),
            "kernel-NBD attach checkpoint is not the exact namespace value"
        );
        let reservations = KernelNbdReservations::from_snapshot(&namespace)?;
        reservations.assert_exact(request)?;
        let device_index = permit.configured_index(&request.device_path)?;
        anyhow::ensure!(
            permit.snapshot().state(&request.device_path) == Some(&KernelNbdSlotState::Free),
            "kernel-NBD attach requires the reserved slot to be physically Free"
        );

        let current = store
            .assert_current(stored)
            .context("retain current checkpoint across kernel-NBD attach")?;
        store
            .revalidate_current(stored, &current)
            .context("revalidate current checkpoint before kernel-NBD attach")?;
        permit.assert_current_publication_paths(&namespace, store)?;
        assert_current_listener(request, listener, context)
            .context("revalidate retained serving listener before kernel-NBD attach")?;
        context.check_active()?;

        // A previously timed-out owned client may still be blocked before its
        // ioctl while sysfs remains Free. Settle the runtime-owned registry
        // under the same Node-global flock and conservatively block every new
        // attach until no late client can race this submission.
        self.cleanup_owner
            .poll_reap()
            .context("poll prior kernel-NBD client cleanup before attach")?;
        if self.cleanup_owner.pending_count() > 0 {
            // This accepted call cannot submit while an earlier owned child is
            // unsettled. An unlock failure is still terminally unknown rather
            // than authority to retry this batch.
            let _ = permit.release();
            return Ok(KernelNbdAttachResult::OutcomeUnknown);
        }
        context.check_active()?;

        let submission = match self.submitter.submit(
            &self.inventory.config,
            &checkpoint_request,
            context,
            &self.cleanup_owner,
        ) {
            KernelNbdClientSubmitAttempt::NotSubmitted(source) => {
                permit
                    .release()
                    .context("unlock kernel-NBD allocator after rejected submission")?;
                return Err(source);
            }
            KernelNbdClientSubmitAttempt::Submitted(submission) => submission,
        };

        // The helper below cannot return `Result`. Once process creation has
        // succeeded, every authority drift, physical inspection failure and
        // conflicting postcondition is a closed terminal result for this batch,
        // never an error that a caller could mistake for zero effect.
        let result = SubmittedKernelNbdAttach {
            submission,
            permit: &permit,
            namespace: &namespace,
            store,
            stored,
            current: &current,
            request,
            listener,
            device_index,
            context,
            config: &self.inventory.config,
        }
        .settle();
        // After process creation, even an unlock failure cannot be exposed as
        // a plain error: the client may already have performed its ioctl.
        if permit.release().is_err() {
            return Ok(KernelNbdAttachResult::OutcomeUnknown);
        }
        Ok(result)
    }
}

/// All evidence retained after process creation. Consuming this value through
/// [`Self::settle`] is the only post-submit exit path, and that path cannot
/// return a generic error.
struct SubmittedKernelNbdAttach<'a> {
    submission: KernelNbdClientSubmission,
    permit: &'a KernelNbdAllocationPermit,
    namespace: &'a RuntimeCheckpointNamespaceSnapshot,
    store: &'a FileCheckpointStore,
    stored: &'a StoredCheckpoint,
    current: &'a CurrentCheckpointGuard<'a>,
    request: &'a KernelNbdAttachRequest,
    listener: &'a dyn RetainedKernelNbdListenerGuard,
    device_index: u32,
    context: &'a RuntimeDesiredEffectContext,
    config: &'a KernelNbdInventoryConfig,
}

impl SubmittedKernelNbdAttach<'_> {
    fn settle(self) -> KernelNbdAttachResult {
        // Revalidate every retained authority even when the helper result or
        // cancellation boundary is ambiguous. A detached lock/checkpoint
        // namespace can never receive an Exact result.
        if self
            .permit
            .assert_current_publication_paths(self.namespace, self.store)
            .is_err()
            || self
                .store
                .revalidate_current(self.stored, self.current)
                .is_err()
            || assert_current_listener(self.request, self.listener, self.context).is_err()
        {
            return KernelNbdAttachResult::OutcomeUnknown;
        }
        if self.submission == KernelNbdClientSubmission::OutcomeUnknown
            || self.context.check_active().is_err()
        {
            return KernelNbdAttachResult::OutcomeUnknown;
        }

        // Use the identical strict inspector as the future full-inventory
        // adapter. It double-samples sysfs and process identity, and only a
        // non-zero-capacity client with exact executable and full frozen argv
        // can produce `Serving`.
        let post_scan = inspect_slot(
            self.config,
            self.device_index,
            &self.request.device_path,
            self.context,
        );
        if self
            .permit
            .assert_current_publication_paths(self.namespace, self.store)
            .is_err()
            || self
                .store
                .revalidate_current(self.stored, self.current)
                .is_err()
            || assert_current_listener(self.request, self.listener, self.context).is_err()
            || self.context.check_active().is_err()
        {
            return KernelNbdAttachResult::OutcomeUnknown;
        }
        match post_scan {
            Ok(KernelNbdSlotState::Serving(identity))
                if identity.listener_socket_path == self.request.listener_socket_path
                    && identity.device_path == self.request.device_path
                    && identity.size_sectors == self.request.expected_size_sectors =>
            {
                KernelNbdAttachResult::Exact(identity)
            }
            Ok(KernelNbdSlotState::Serving(_)) => KernelNbdAttachResult::ConflictAfterSubmit(
                KernelNbdAttachConflict::LiveClientIdentity,
            ),
            Ok(KernelNbdSlotState::Leaked {
                recorded_process_id,
            }) => KernelNbdAttachResult::ConflictAfterSubmit(
                KernelNbdAttachConflict::LeakedOrIncompleteAttachment {
                    recorded_process_id,
                },
            ),
            Ok(KernelNbdSlotState::Free | KernelNbdSlotState::Unavailable) | Err(_) => {
                KernelNbdAttachResult::OutcomeUnknown
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PlatformKernelNbdClientSubmitPort;

impl KernelNbdClientSubmitPort for PlatformKernelNbdClientSubmitPort {
    fn submit(
        &self,
        config: &KernelNbdInventoryConfig,
        request: &KernelNbdAttachRequest,
        context: &RuntimeDesiredEffectContext,
        cleanup_owner: &KernelNbdClientCleanupOwner,
    ) -> KernelNbdClientSubmitAttempt {
        run_bounded_nbd_client(
            kernel_nbd_client_command(config, request),
            context,
            cleanup_owner,
        )
    }
}

/// Installed sealed adapter. It remains deliberately uncomposed until the
/// serving-blockd listener proof is available to the higher layer.
#[derive(Debug, Clone)]
pub(crate) struct PlatformKernelNbdAttachPort {
    inner: ExactKernelNbdAttachPort<PlatformKernelNbdClientSubmitPort>,
}

impl PlatformKernelNbdAttachPort {
    pub(crate) fn new(
        config: KernelNbdInventoryConfig,
        cleanup_owner: Arc<KernelNbdClientCleanupOwner>,
    ) -> Self {
        Self {
            inner: ExactKernelNbdAttachPort::with_cleanup_owner(
                config,
                PlatformKernelNbdClientSubmitPort,
                cleanup_owner,
            ),
        }
    }
}

impl attach_port_sealed::Sealed for PlatformKernelNbdAttachPort {}

impl KernelNbdAttachPort for PlatformKernelNbdAttachPort {
    fn attach_checkpointed(
        &self,
        request: &KernelNbdAttachRequest,
        listener: &dyn RetainedKernelNbdListenerGuard,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        context: &RuntimeDesiredEffectContext,
    ) -> Result<KernelNbdAttachResult> {
        self.inner
            .attach_checkpointed(request, listener, store, stored, context)
    }
}

/// Production kernel-NBD effect for `PrepareDevice` and its retained
/// `PrepareNetwork` successor. The accepted pool admission decides only
/// whether this batch may attempt the effect; the sealed attach port still
/// performs a new allocation-flock-protected namespace/pool scan, checkpoint
/// guard and retained-listener revalidation at the submit edge.
pub(crate) struct KernelNbdAttachEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    attach: Arc<dyn KernelNbdAttachPort>,
}

impl KernelNbdAttachEffect {
    pub(crate) fn platform(
        authority: Arc<dyn VolumeDataAuthority>,
        config: KernelNbdInventoryConfig,
        cleanup_owner: Arc<KernelNbdClientCleanupOwner>,
    ) -> Self {
        Self {
            authority,
            attach: Arc::new(PlatformKernelNbdAttachPort::new(config, cleanup_owner)),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(
        authority: Arc<dyn VolumeDataAuthority>,
        attach: Arc<dyn KernelNbdAttachPort>,
    ) -> Self {
        Self { authority, attach }
    }

    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &cats_api::runtime_reconciliation::DesiredRuntimeSpec,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
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
            "kernel-NBD admission duplicates one Cat"
        );
        let prepare_network_device = match &runtime.step {
            ReconcileStep::PrepareDevice {
                frontend: PrepareDeviceFrontend::KernelNbd { .. },
                ..
            } => {
                if !prepare_device_base_admission_is_exact(accepted, desired, runtime) {
                    return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                        RuntimeDesiredEffectStopReason::LocalContract,
                    )));
                }
                None
            }
            ReconcileStep::PrepareNetwork { network, devices } => {
                let [device] = devices.as_slice() else {
                    return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                        RuntimeDesiredEffectStopReason::LocalContract,
                    )));
                };
                if !matches!(&device.frontend, PrepareDeviceFrontend::KernelNbd { .. }) {
                    return Ok(None);
                }
                let Some(expected_networks) = context
                    .node_global_network()?
                    .expected_networks(&desired.cat_id, network)
                else {
                    return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                        RuntimeDesiredEffectStopReason::LocalContract,
                    )));
                };
                if !signed_inventory_admission_is_exact_with_networks(
                    accepted,
                    desired,
                    runtime,
                    &expected_networks,
                ) || !checkpoint_is_current_exact(desired, runtime)
                {
                    return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                        RuntimeDesiredEffectStopReason::LocalContract,
                    )));
                }
                Some(device)
            }
            _ => return Ok(None),
        };
        let admission = context.kernel_nbd_pool()?;
        anyhow::ensure!(
            admission.matches_observation(accepted.observation()),
            "kernel-NBD pool admission is not bound to the accepted full observation"
        );
        if !checkpoint_is_current_exact(desired, runtime) {
            return Ok(None);
        }
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running
                && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
                && runtime.runtime_incarnation.is_none()
                && runtime.stable_state.is_none()
                && runtime.mounts.is_empty()
                && runtime.routes.is_empty(),
            "kernel-NBD attach is outside the closed pre-launch phase"
        );

        let state = admission
            .device(&desired.cat_id)
            .context("kernel-NBD accepted full lacks this Cat's durable reservation")?;
        let prepare_network_contract_is_exact = match (prepare_network_device, state) {
            (None, _) => true,
            (Some(device), KernelNbdDeviceScanState::Exact(proof)) => {
                let (volume_id, observed) = proof.projection();
                proof.matches_prepared_device(&desired.cat_id, device)
                    && prepare_network_volume_admission_is_exact(
                        desired,
                        runtime,
                        device,
                        &volume_id,
                        Some(&observed),
                    )
            }
            (
                Some(device),
                KernelNbdDeviceScanState::Absent { expected, .. }
                | KernelNbdDeviceScanState::Leaked { expected, .. }
                | KernelNbdDeviceScanState::Unavailable { expected, .. },
            ) => {
                expected.matches_prepared_device(&desired.cat_id, device)
                    && prepare_network_volume_admission_is_exact(
                        desired,
                        runtime,
                        device,
                        &expected.volume_id,
                        None,
                    )
            }
        };
        if !prepare_network_contract_is_exact {
            return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::LocalContract,
            )));
        }
        match state {
            KernelNbdDeviceScanState::Exact(proof) => {
                let (volume_id, projected) = proof.projection();
                anyhow::ensure!(
                    runtime.volumes.iter().any(|volume| {
                        volume.volume_id == volume_id && volume.devices == [projected.clone()]
                    }) && runtime
                        .volumes
                        .iter()
                        .filter(|volume| !volume.devices.is_empty())
                        .count()
                        == 1,
                    "public kernel-NBD device changed after exact provider proof"
                );
                proof.listener().assert_current(context)?;
                // A fresh exact full may fall through to the independent
                // PrepareNetwork reservation in this same dispatcher call.
                Ok(None)
            }
            KernelNbdDeviceScanState::Leaked { .. }
            | KernelNbdDeviceScanState::Unavailable { .. } => {
                Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
            KernelNbdDeviceScanState::Absent { listener: None, .. } => {
                // The preceding serving-process effect owns this admission.
                Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
            KernelNbdDeviceScanState::Absent {
                expected,
                listener: Some(listener),
            } => {
                anyhow::ensure!(
                    runtime
                        .volumes
                        .iter()
                        .all(|volume| volume.devices.is_empty()),
                    "absent kernel-NBD proof conflicts with a public device projection"
                );

                let CheckpointEvidence::Valid {
                    checkpoint_path,
                    content_digest,
                    ..
                } = &runtime.checkpoint
                else {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
                };
                let checkpoint_directory =
                    context.state_directory().path().join(CHECKPOINT_NAMESPACE);
                let store = FileCheckpointStore::open_preserving_checkpoint_temp(
                    &checkpoint_directory,
                    &desired.cat_id,
                )
                .context("open kernel-NBD attach checkpoint")?;
                anyhow::ensure!(
                    store.path() == Path::new(checkpoint_path.as_str()),
                    "kernel-NBD admission names another checkpoint path"
                );
                let Some(stored) = store.load().context("load kernel-NBD attach checkpoint")?
                else {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
                };
                if stored.content_digest() != content_digest
                    || stored.checkpoint().step != runtime.step
                {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
                }
                let request = KernelNbdAttachRequest::from_checkpoint(&stored)?;
                anyhow::ensure!(
                    expected.matches_attach_request(&request),
                    "kernel-NBD scanner admission changed from the current checkpoint"
                );

                let [desired_volume] = desired.volumes.as_slice() else {
                    anyhow::bail!("kernel-NBD V1 attach requires one Desired volume")
                };
                let current_authority = match self.authority.load_volume(&desired_volume.volume_id)
                {
                    Ok(authority) => authority,
                    Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
                };
                let retained = match AuthorizedBlockdStore::new(context.state_directory().clone())
                    .retain_prepare_device_handoff(stored.checkpoint(), desired)
                {
                    Ok(retained) => retained,
                    Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
                };
                let ready = match ServingHandoffStore::new(context.state_directory().clone())
                    .reopen_prepare_device_handoff(
                        stored.checkpoint(),
                        desired,
                        &current_authority,
                        retained,
                    ) {
                    Ok(ready) => ready,
                    Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
                };
                ready.assert_current(stored.checkpoint(), desired, &current_authority)?;
                context.check_active()?;

                let _result = self
                    .attach
                    .attach_checkpointed(&request, listener, &store, &stored, context)?;

                // Submission, response loss, conflict, cancellation and every
                // post-submit authority/descriptor drift share one terminal
                // outcome: discard this admission and require a new full scan.
                let postcondition_current = self
                    .authority
                    .load_volume(&desired_volume.volume_id)
                    .ok()
                    .is_some_and(|after| {
                        ready
                            .assert_current(stored.checkpoint(), desired, &after)
                            .is_ok()
                    });
                let _ = postcondition_current;
                Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
        }
    }
}

fn assert_current_listener(
    request: &KernelNbdAttachRequest,
    listener: &dyn RetainedKernelNbdListenerGuard,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<()> {
    listener.assert_current_for(request, context)
}

fn kernel_nbd_client_command(
    config: &KernelNbdInventoryConfig,
    request: &KernelNbdAttachRequest,
) -> Command {
    let mut command = Command::new(&config.nbd_client_binary);
    command
        .env_clear()
        .stdin(Stdio::null())
        // Client output is not authority and is deliberately discarded. A
        // zero-byte retention bound also prevents a daemonized descendant
        // from keeping a captured pipe (and therefore this effect) alive.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg(NBD_IOCTL_MODE)
        .arg("-unix")
        .arg(request.listener_socket_path.as_str())
        .arg(request.device_path.as_str())
        .args(["-b", "512", "-N", ""]);
    command
}

fn run_bounded_nbd_client(
    mut command: Command,
    context: &dyn RuntimePhysicalReadContext,
    cleanup_owner: &KernelNbdClientCleanupOwner,
) -> KernelNbdClientSubmitAttempt {
    if let Err(source) = context.check_active() {
        return KernelNbdClientSubmitAttempt::NotSubmitted(source);
    }
    let child = match command.spawn().context("spawn exact kernel-NBD client") {
        Ok(child) => child,
        Err(source) => return KernelNbdClientSubmitAttempt::NotSubmitted(source),
    };
    KernelNbdClientSubmitAttempt::Submitted(run_bounded_client_process(
        Box::new(PlatformOwnedKernelNbdClient { child }),
        context,
        cleanup_owner,
    ))
}

fn run_bounded_client_process(
    mut client: Box<dyn OwnedKernelNbdClient>,
    context: &dyn RuntimePhysicalReadContext,
    cleanup_owner: &KernelNbdClientCleanupOwner,
) -> KernelNbdClientSubmission {
    loop {
        match client.poll() {
            Ok(KernelNbdClientPoll::Exited { success }) => {
                return if success {
                    KernelNbdClientSubmission::Completed
                } else {
                    // The process existed, so a non-zero exit cannot prove
                    // that no ioctl reached the kernel. A successor fresh full
                    // scan must settle it.
                    KernelNbdClientSubmission::OutcomeUnknown
                };
            }
            Ok(KernelNbdClientPoll::Running) => {}
            Err(_) => {
                settle_or_transfer_owned_client(client, context, cleanup_owner);
                return KernelNbdClientSubmission::OutcomeUnknown;
            }
        }
        if context.check_active().is_err() {
            // Kill only this owned short-lived CLI process. An ioctl or a
            // daemonized client may already exist, so no detach or retry is
            // permitted in this admission batch.
            settle_or_transfer_owned_client(client, context, cleanup_owner);
            return KernelNbdClientSubmission::OutcomeUnknown;
        }
        let remaining = context.deadline().saturating_duration_since(Instant::now());
        std::thread::sleep(CLIENT_POLL_INTERVAL.min(remaining));
    }
}

fn settle_or_transfer_owned_client(
    mut client: Box<dyn OwnedKernelNbdClient>,
    context: &dyn RuntimePhysicalReadContext,
    cleanup_owner: &KernelNbdClientCleanupOwner,
) {
    // `kill(2)` itself is nonblocking. Do not call `Child::wait`: a client in
    // uninterruptible kernel sleep could make the effect and runtime shutdown
    // wait forever. Poll only through the smaller of a fixed cleanup grace and
    // the accepted effect deadline, then transfer the still-owned child.
    let _ = client.request_kill();
    let now = Instant::now();
    let grace_deadline = now
        .checked_add(CLIENT_CLEANUP_GRACE)
        .unwrap_or_else(|| context.deadline());
    let cleanup_deadline = context.deadline().min(grace_deadline);
    loop {
        match client.poll() {
            Ok(KernelNbdClientPoll::Exited { .. }) => return,
            Ok(KernelNbdClientPoll::Running) => {}
            Err(_) => {
                cleanup_owner.transfer(client);
                return;
            }
        }
        let now = Instant::now();
        if now >= cleanup_deadline {
            cleanup_owner.transfer(client);
            return;
        }
        std::thread::sleep(
            CLIENT_POLL_INTERVAL.min(cleanup_deadline.saturating_duration_since(now)),
        );
    }
}

fn inspect_pool(
    config: &KernelNbdInventoryConfig,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<KernelNbdPoolSnapshot> {
    let mut slots = BTreeMap::new();
    // Grow only after each slot's cancellation/deadline probe. Installed
    // configuration is capped above, while fixture callers still cannot force
    // one u32-sized allocation before the first probe.
    let mut ordered_paths = Vec::new();
    for index in 0..config.device_count {
        context.check_active()?;
        let device_path = HostPath::new(format!("/dev/nbd{index}"))
            .expect("fixed kernel-NBD path is a canonical HostPath");
        let state = inspect_slot(config, index, &device_path, context)
            .unwrap_or(KernelNbdSlotState::Unavailable);
        context
            .check_active()
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelNbdProcessCoordinate {
    device: u64,
    inode: u64,
    mode: u32,
    user_id: u32,
}

impl KernelNbdProcessCoordinate {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user_id: metadata.uid(),
        }
    }
}

/// One bounded `/proc/<pid>` sample. Stable negative identity evidence is a
/// non-allocatable slot state, not an unavailable read of every other device
/// in the pool. Retaining the sampled coordinates lets `inspect_slot` reject
/// a changed process coordinate, start time, executable or argv between its
/// two samples.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelNbdClientSample {
    Exact {
        process: KernelNbdProcessCoordinate,
        identity: KernelNbdClientIdentity,
    },
    NonExact(KernelNbdNonExactClientSample),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelNbdNonExactClientSample {
    ProcessAbsent,
    NotDirectory(KernelNbdProcessCoordinate),
    StatAbsent(KernelNbdProcessCoordinate),
    ForeignOwner {
        process: KernelNbdProcessCoordinate,
        start_time_ticks: WireU64,
    },
    ExecutableAbsent {
        process: KernelNbdProcessCoordinate,
        start_time_ticks: WireU64,
    },
    ForeignExecutable {
        process: KernelNbdProcessCoordinate,
        start_time_ticks: WireU64,
        executable: PathBuf,
    },
    ForeignArguments {
        process: KernelNbdProcessCoordinate,
        start_time_ticks: WireU64,
        executable: PathBuf,
        arguments: Vec<OsString>,
    },
}

fn inspect_slot(
    config: &KernelNbdInventoryConfig,
    index: u32,
    device_path: &HostPath,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<KernelNbdSlotState> {
    let slot = config.sys_block_root.join(format!("nbd{index}"));
    let before = read_kernel_tuple(&slot, context)?;
    let client_sample = match before {
        KernelTuple {
            process_id: Some(process_id),
            size_sectors,
        } if size_sectors > 0 => Some((
            process_id,
            sample_exact_client(config, process_id, device_path, size_sectors, context)?,
        )),
        KernelTuple {
            process_id: Some(_),
            size_sectors: 0,
        } => anyhow::bail!("kernel-NBD slot has a client pid but zero capacity"),
        _ => None,
    };
    context.check_active()?;
    let after = read_kernel_tuple(&slot, context)?;
    anyhow::ensure!(before == after, "kernel-NBD slot changed during inspection");
    if let Some((process_id, sample)) = client_sample {
        let repeated = sample_exact_client(
            config,
            process_id,
            device_path,
            before.size_sectors,
            context,
        )?;
        anyhow::ensure!(
            repeated == sample,
            "kernel-NBD client changed during inspection"
        );
        return Ok(match sample {
            KernelNbdClientSample::Exact { identity, .. } => KernelNbdSlotState::Serving(identity),
            KernelNbdClientSample::NonExact(_) => KernelNbdSlotState::Leaked {
                recorded_process_id: Some(process_id),
            },
        });
    }
    Ok(match before {
        KernelTuple {
            process_id: None,
            size_sectors: 0,
        } => KernelNbdSlotState::Free,
        KernelTuple {
            process_id: None,
            size_sectors,
        } if size_sectors > 0 => KernelNbdSlotState::Leaked {
            recorded_process_id: None,
        },
        _ => unreachable!("kernel-NBD tuple cases are exhaustive"),
    })
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
    size_sectors: u64,
    context: &dyn RuntimePhysicalReadContext,
) -> Result<KernelNbdClientSample> {
    let size_sectors = WireU64::new(size_sectors)
        .filter(|sectors| sectors.get() > 0)
        .context("kernel-NBD client has no representable positive sector capacity")?;
    let process = config.proc_root.join(process_id.to_string());
    let process_metadata = match std::fs::metadata(&process) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(KernelNbdClientSample::NonExact(
                KernelNbdNonExactClientSample::ProcessAbsent,
            ));
        }
        Err(source) => return Err(source).context("inspect kernel-NBD client process"),
    };
    let process_coordinate = KernelNbdProcessCoordinate::from_metadata(&process_metadata);
    if !process_metadata.is_dir() {
        return Ok(KernelNbdClientSample::NonExact(
            KernelNbdNonExactClientSample::NotDirectory(process_coordinate),
        ));
    }
    let stat = match read_optional_bounded(&process.join("stat"), MAX_PROC_STAT_BYTES, context)? {
        Some(stat) => stat,
        None => {
            return Ok(KernelNbdClientSample::NonExact(
                KernelNbdNonExactClientSample::StatAbsent(process_coordinate),
            ));
        }
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
    if process_metadata.uid() != config.client_process_user_id {
        return Ok(KernelNbdClientSample::NonExact(
            KernelNbdNonExactClientSample::ForeignOwner {
                process: process_coordinate,
                start_time_ticks,
            },
        ));
    }
    context.check_active()?;
    let executable = match std::fs::read_link(process.join("exe")) {
        Ok(executable) => executable,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(KernelNbdClientSample::NonExact(
                KernelNbdNonExactClientSample::ExecutableAbsent {
                    process: process_coordinate,
                    start_time_ticks,
                },
            ));
        }
        Err(source) => return Err(source).context("read kernel-NBD client executable"),
    };
    if executable != config.nbd_client_binary {
        return Ok(KernelNbdClientSample::NonExact(
            KernelNbdNonExactClientSample::ForeignExecutable {
                process: process_coordinate,
                start_time_ticks,
                executable,
            },
        ));
    }
    let command_line =
        read_required_bounded(&process.join("cmdline"), MAX_PROC_CMDLINE_BYTES, context)?;
    let arguments = parse_nul_arguments(&command_line)?;
    let expected_device = OsString::from(device_path.as_str());
    if !(arguments.len() == 9
        && Path::new(&arguments[0]) == config.nbd_client_binary
        && arguments[1] == NBD_IOCTL_MODE
        && arguments[2] == "-unix"
        && arguments[4] == expected_device
        && arguments[5] == "-b"
        && arguments[6] == "512"
        && arguments[7] == "-N"
        && arguments[8].is_empty())
    {
        return Ok(KernelNbdClientSample::NonExact(
            KernelNbdNonExactClientSample::ForeignArguments {
                process: process_coordinate,
                start_time_ticks,
                executable,
                arguments,
            },
        ));
    }
    let Some(listener_socket_text) = Path::new(&arguments[3]).to_str() else {
        return Ok(KernelNbdClientSample::NonExact(
            KernelNbdNonExactClientSample::ForeignArguments {
                process: process_coordinate,
                start_time_ticks,
                executable,
                arguments,
            },
        ));
    };
    let Some(listener_socket_path) = HostPath::new(listener_socket_text.to_owned()) else {
        return Ok(KernelNbdClientSample::NonExact(
            KernelNbdNonExactClientSample::ForeignArguments {
                process: process_coordinate,
                start_time_ticks,
                executable,
                arguments,
            },
        ));
    };
    let executable_path = HostPath::new(
        executable
            .to_str()
            .context("kernel-NBD executable path is not UTF-8")?
            .to_owned(),
    )
    .context("kernel-NBD executable is not a canonical HostPath")?;
    Ok(KernelNbdClientSample::Exact {
        process: process_coordinate,
        identity: KernelNbdClientIdentity {
            process_id,
            process_start_time_ticks: start_time_ticks,
            executable_path,
            listener_socket_path,
            device_path: device_path.clone(),
            size_sectors,
        },
    })
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

fn unlock_exclusive(file: &File) -> Result<()> {
    loop {
        // SAFETY: `file` owns a live descriptor and `flock` retains no Rust
        // pointer or ownership after the call returns.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(source).context("unlock kernel-NBD allocator");
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
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        AcquireOrigin, AdmissionInventoryAttestation, AgentSession, AssignedKind,
        AssignedPlacement, ContractVersion, DesiredReadSnapshot, DesiredRuntimeSpec, DiskKind,
        Durability, Epoch, FenceEpoch, Generation, GuestDeviceIdentity, GuestTransportEvidence,
        Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, MacAddress, NetworkConfig, NodeBootId,
        NodeObservation, RemoteHead, RequireIdleCheckpoint, Revision, RuntimeConfig, RuntimeTarget,
        RuntimeTransition, Sequence, ServingAuthorityProvenance, ServingBlockdIdentity,
        SessionBinding, Sha256Digest, UnixMillis, WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeInventoryScanContext, RuntimeSpineFullScan,
    };

    use super::super::checkpoint::runtime_checkpoint_path;

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
            install_serving_client(
                &self.sys,
                &self.proc,
                &self.client,
                index,
                pid,
                socket,
                &format!("/dev/nbd{index}"),
            );
        }
    }

    struct InheritedAllocationLockChild {
        child: Option<Child>,
    }

    impl InheritedAllocationLockChild {
        fn spawn(permit: &KernelNbdAllocationPermit) -> Self {
            // `dup` shares the exact open-file description carrying flock;
            // using it as stdin deliberately keeps that description open
            // across a successful exec, unlike the production CLOEXEC fd.
            // SAFETY: the permit owns a live descriptor and a successful dup
            // returns one fresh descriptor owned by this test.
            let descriptor = unsafe { libc::dup(permit.allocation_lock.as_raw_fd()) };
            assert!(descriptor >= 0, "{}", io::Error::last_os_error());
            // SAFETY: successful `dup` transferred this fresh descriptor to
            // the returned File exactly once.
            let inherited = unsafe { File::from_raw_fd(descriptor) };
            let child = Command::new("/bin/sleep")
                .env_clear()
                .stdin(Stdio::from(inherited))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .arg("30")
                .spawn()
                .unwrap();
            Self { child: Some(child) }
        }

        fn assert_running(&mut self) {
            assert!(self.child.as_mut().unwrap().try_wait().unwrap().is_none());
        }

        fn terminate(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                child.wait().unwrap();
            }
        }
    }

    impl Drop for InheritedAllocationLockChild {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    fn install_serving_client(
        sys: &Path,
        proc_root: &Path,
        client: &Path,
        index: u32,
        pid: u32,
        socket: &str,
        command_device: &str,
    ) {
        let slot = sys.join(format!("nbd{index}"));
        fs::write(slot.join("pid"), format!("{pid}\n")).unwrap();
        fs::write(slot.join("size"), b"8\n").unwrap();
        let process = proc_root.join(pid.to_string());
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
        symlink(client, process.join("exe")).unwrap();
        let argv: [&[u8]; 9] = [
            client.as_os_str().as_bytes(),
            b"-nonetlink",
            b"-unix",
            socket.as_bytes(),
            command_device.as_bytes(),
            b"-b",
            b"512",
            b"-N",
            b"",
        ];
        write_nul_arguments(&process.join("cmdline"), &argv);
    }

    fn write_nul_arguments(path: &Path, arguments: &[&[u8]]) {
        let mut bytes = Vec::new();
        for argument in arguments {
            bytes.extend_from_slice(argument);
            bytes.push(0);
        }
        fs::write(path, bytes).unwrap();
    }

    type SubmitAction = dyn Fn(
            &KernelNbdInventoryConfig,
            &KernelNbdAttachRequest,
            &RuntimeDesiredEffectContext,
        ) -> Result<KernelNbdClientSubmission>
        + Send
        + Sync;

    #[derive(Clone)]
    struct FakeSubmitter {
        calls: Arc<AtomicUsize>,
        action: Arc<SubmitAction>,
    }

    impl FakeSubmitter {
        fn new(
            action: impl Fn(
                    &KernelNbdInventoryConfig,
                    &KernelNbdAttachRequest,
                    &RuntimeDesiredEffectContext,
                ) -> Result<KernelNbdClientSubmission>
                + Send
                + Sync
                + 'static,
        ) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                action: Arc::new(action),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl KernelNbdClientSubmitPort for FakeSubmitter {
        fn submit(
            &self,
            config: &KernelNbdInventoryConfig,
            request: &KernelNbdAttachRequest,
            context: &RuntimeDesiredEffectContext,
            _cleanup_owner: &KernelNbdClientCleanupOwner,
        ) -> KernelNbdClientSubmitAttempt {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match (self.action)(config, request, context) {
                Ok(submission) => KernelNbdClientSubmitAttempt::Submitted(submission),
                Err(source) => KernelNbdClientSubmitAttempt::NotSubmitted(source),
            }
        }
    }

    struct StubbornOwnedClient {
        kill_requests: Arc<AtomicUsize>,
        allow_exit: Arc<AtomicBool>,
    }

    impl OwnedKernelNbdClient for StubbornOwnedClient {
        fn request_kill(&mut self) -> io::Result<()> {
            self.kill_requests.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn poll(&mut self) -> io::Result<KernelNbdClientPoll> {
            Ok(if self.allow_exit.load(Ordering::SeqCst) {
                KernelNbdClientPoll::Exited { success: false }
            } else {
                KernelNbdClientPoll::Running
            })
        }
    }

    struct PollErrorOwnedClient;

    impl OwnedKernelNbdClient for PollErrorOwnedClient {
        fn request_kill(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn poll(&mut self) -> io::Result<KernelNbdClientPoll> {
            Err(io::Error::other("injected cleanup poll failure"))
        }
    }

    #[derive(Clone)]
    struct StubbornClientSubmitter {
        client: Arc<Mutex<Option<Box<dyn OwnedKernelNbdClient>>>>,
        calls: Arc<AtomicUsize>,
        after_cleanup: Arc<dyn Fn() + Send + Sync>,
    }

    impl KernelNbdClientSubmitPort for StubbornClientSubmitter {
        fn submit(
            &self,
            _config: &KernelNbdInventoryConfig,
            _request: &KernelNbdAttachRequest,
            context: &RuntimeDesiredEffectContext,
            cleanup_owner: &KernelNbdClientCleanupOwner,
        ) -> KernelNbdClientSubmitAttempt {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call > 0 {
                (self.after_cleanup)();
                return KernelNbdClientSubmitAttempt::Submitted(
                    KernelNbdClientSubmission::Completed,
                );
            }
            let Some(client) = self
                .client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            else {
                return KernelNbdClientSubmitAttempt::NotSubmitted(anyhow::anyhow!(
                    "stubborn test client already submitted"
                ));
            };
            KernelNbdClientSubmitAttempt::Submitted(run_bounded_client_process(
                client,
                context,
                cleanup_owner,
            ))
        }
    }

    type ListenerAction = dyn Fn(usize, &RetainedKernelNbdListenerIdentity) -> Result<RetainedKernelNbdListenerIdentity>
        + Send
        + Sync;

    struct FakeListenerGuard {
        retained: RetainedKernelNbdListenerIdentity,
        calls: AtomicUsize,
        action: Arc<ListenerAction>,
    }

    impl FakeListenerGuard {
        fn fixed() -> Self {
            Self::new(|_, retained| Ok(retained.clone()))
        }

        fn new(
            action: impl Fn(
                    usize,
                    &RetainedKernelNbdListenerIdentity,
                ) -> Result<RetainedKernelNbdListenerIdentity>
                + Send
                + Sync
                + 'static,
        ) -> Self {
            Self {
                retained: RetainedKernelNbdListenerIdentity::new(
                    host("/run/cats/nbd.sock"),
                    WireU64::new(10).unwrap(),
                    WireU64::new(11).unwrap(),
                    400,
                    WireU64::new(401).unwrap(),
                    random('5'),
                )
                .unwrap(),
                calls: AtomicUsize::new(0),
                action: Arc::new(action),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl retained_listener_sealed::Sealed for FakeListenerGuard {}

    impl RetainedKernelNbdListenerGuard for FakeListenerGuard {
        fn assert_current_for(
            &self,
            request: &KernelNbdAttachRequest,
            context: &dyn RuntimePhysicalReadContext,
        ) -> Result<()> {
            context.check_active()?;
            request.assert_listener_proof(
                &self.retained.listener_socket_path,
                &self.retained.serving_process_identity_token,
            )?;
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            anyhow::ensure!(
                (self.action)(call, &self.retained)? == self.retained,
                "fake retained listener identity changed"
            );
            context.check_active()
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
                volume_intent_id: id(&format!("intent_{volume}")),
                disk_id: id(&format!("disk_{volume}")),
                volume_id: id(volume),
                disk_kind: DiskKind::Root,
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
                    direct: false,
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
        desired_effect_context_until(state, cats, Instant::now() + Duration::from_secs(5))
    }

    fn desired_effect_context_until(
        state: &Path,
        cats: &[&str],
        deadline: Instant,
    ) -> RuntimeDesiredEffectContext {
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
            deadline,
            admission,
        )
    }

    fn inventory_scan_context(cats: &[&str]) -> RuntimeInventoryScanContext {
        let node_boot_id = NodeBootId::new("a".repeat(32)).unwrap();
        let agent_instance_id = random('b');
        let session = SessionBinding {
            node_id: id("node_a"),
            node_boot_id,
            agent_instance_id,
            agent_session_epoch: Epoch::new(1).unwrap(),
        };
        RuntimeInventoryScanContext::for_test(
            RuntimeSpineFullScan {
                session: session.clone(),
                heartbeat_sequence: Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session,
                    request_sequence: Sequence::new(1).unwrap(),
                    read_position: Sequence::new(1).unwrap(),
                    issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
                    expires_at_unix_ms: UnixMillis::new(2_000).unwrap(),
                    desired_specs: cats.iter().map(|cat| desired(cat)).collect(),
                },
            },
            Instant::now() + Duration::from_secs(5),
        )
    }

    #[test]
    fn installed_config_rejects_an_unbounded_device_pool_before_allocation() {
        let temporary = TempDir::new().unwrap();
        let error = KernelNbdInventoryConfig::installed(
            StateDirectory::unanchored(temporary.path().to_path_buf()),
            PathBuf::from("/usr/bin/nbd-client"),
            u32::MAX,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("device-count bound"),
            "{error:#}"
        );
        assert!(!temporary.path().join(ALLOCATION_LOCK_BASENAME).exists());
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
    fn complete_pool_scan_preserves_absent_unavailable_and_unreserved_uncertainty() {
        let fixture = Fixture::new(2);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        store.create(&source).unwrap();
        let processes = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let port = KernelNbdInventoryPort::new(fixture.config(2));

        let KernelNbdPoolScanOutcome::Complete(absent) = port
            .scan_complete_pool(&inventory_scan_context(&["cat_a"]), &processes)
            .unwrap()
        else {
            panic!("free reserved slot must form an explicit Absent admission")
        };
        assert!(matches!(
            absent.devices_by_cat.get(&id("cat_a")),
            Some(KernelNbdDeviceScanState::Absent { listener: None, .. })
        ));
        assert!(absent.device_projections().is_empty());
        assert!(!absent.has_unavailable_device());

        fs::write(fixture.sys.join("nbd0/size"), b"not-a-number\n").unwrap();
        let KernelNbdPoolScanOutcome::Complete(unavailable) = port
            .scan_complete_pool(&inventory_scan_context(&["cat_a"]), &processes)
            .unwrap()
        else {
            panic!("reserved uncertain slot must retain its typed state")
        };
        assert!(matches!(
            unavailable.devices_by_cat.get(&id("cat_a")),
            Some(KernelNbdDeviceScanState::Unavailable { .. })
        ));
        assert!(unavailable.has_unavailable_device());

        fs::write(fixture.sys.join("nbd0/size"), b"0\n").unwrap();
        fs::write(fixture.sys.join("nbd1/size"), b"not-a-number\n").unwrap();
        assert!(matches!(
            port.scan_complete_pool(&inventory_scan_context(&["cat_a"]), &processes)
                .unwrap(),
            KernelNbdPoolScanOutcome::Unavailable
        ));
    }

    #[test]
    fn prepare_network_step_devices_remain_durable_reservations() {
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let expected = reservation_from_prepare_device(&source).unwrap();
        let mut successor = source.clone();
        successor.step = ReconcileStep::PrepareNetwork {
            network: cats_api::runtime_reconciliation::RuntimeNetworkIdentity {
                network_config: desired("cat_a").runtime.network_config,
                tap_name: id("cata00000001"),
                ownership_token: random('9'),
            },
            devices: vec![super::super::network::prepared_device_input(&source).unwrap()],
        };
        successor.volumes.clear();

        let reservations = KernelNbdReservations::from_checkpoints([&successor]).unwrap();
        reservations
            .assert_contains(
                &expected,
                "PrepareNetwork lost its persisted kernel-NBD reservation",
            )
            .unwrap();
    }

    #[test]
    fn persisted_device_expectation_binds_kernel_direct_mode() {
        let buffered = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let mut direct_checkpoint = buffered.clone();
        let ReconcileStep::PrepareDevice {
            frontend:
                PrepareDeviceFrontend::KernelNbd {
                    direct: direct_mode,
                    ..
                },
            ..
        } = &mut direct_checkpoint.step
        else {
            unreachable!()
        };
        *direct_mode = true;

        let buffered = KernelNbdDeviceExpectation::from_prepare_device(&buffered)
            .unwrap()
            .unwrap();
        let direct = KernelNbdDeviceExpectation::from_prepare_device(&direct_checkpoint)
            .unwrap()
            .unwrap();
        assert_ne!(
            buffered, direct,
            "listener admission must not erase the persisted direct mode"
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
    fn allocation_permit_drop_unlocks_an_open_file_description_inherited_across_exec() {
        let fixture = Fixture::new(1);
        let first = KernelNbdInventoryPort::new(fixture.config(1));
        let second = KernelNbdInventoryPort::new(fixture.config(1));
        let permit = first.lock_and_inspect(&TestContext::active()).unwrap();
        let mut inherited = InheritedAllocationLockChild::spawn(&permit);
        inherited.assert_running();

        drop(permit);

        let reacquired = second.lock_and_inspect(&TestContext::active()).unwrap();
        inherited.assert_running();
        drop(reacquired);
    }

    #[test]
    fn allocation_unlock_failure_is_closed_and_drop_never_panics() {
        let fixture = Fixture::new(1);
        let first = KernelNbdInventoryPort::new(fixture.config(1));
        let second = KernelNbdInventoryPort::new(fixture.config(1));
        let mut permit = first.lock_and_inspect(&TestContext::active()).unwrap();
        let mut inherited = InheritedAllocationLockChild::spawn(&permit);
        // Fail both the reporting release and Drop's last retry. The child is
        // then the sole descriptor retaining the still-locked description.
        permit.inject_unlock_failures(2);

        let release = std::panic::catch_unwind(AssertUnwindSafe(|| permit.release()));

        assert!(release.is_ok(), "allocation permit Drop must never panic");
        assert!(release.unwrap().is_err(), "unlock failure must not succeed");
        inherited.assert_running();
        let error = second.lock_and_inspect(&TestContext::active()).unwrap_err();
        assert!(error.to_string().contains("already active"), "{error:#}");

        inherited.terminate();
        second.lock_and_inspect(&TestContext::active()).unwrap();
    }

    #[test]
    fn reservation_rejects_non_exact_replacement_without_publication() {
        let fixture = Fixture::new(3);
        let port = KernelNbdInventoryPort::new(fixture.config(3));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let incumbent = checkpoint("cat_b", "vol_b", "/dev/nbd0", '7');
        let incumbent_store =
            FileCheckpointStore::open(&checkpoint_directory, &incumbent.cat_id).unwrap();
        let _incumbent = incumbent_store.create(&incumbent).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a", "cat_b"]);

        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |_| {
                Ok(predecessor.checkpoint().clone())
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("ignored the allocator-selected"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );

        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |_| {
                let mut replacement = predecessor.checkpoint().clone();
                let ReconcileStep::PrepareDevice { frontend, .. } = &mut replacement.step else {
                    panic!("fixture must be a PrepareDevice checkpoint")
                };
                *frontend = PrepareDeviceFrontend::VhostUserBlk {
                    socket_path: host("/run/cats/vhost.sock"),
                    queues: 1,
                    queue_size: 128,
                };
                Ok(replacement)
            })
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("not a kernel-NBD PrepareDevice reservation"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
    }

    #[test]
    fn reservation_rejects_prospective_global_token_collision_without_publication() {
        let fixture = Fixture::new(3);
        let port = KernelNbdInventoryPort::new(fixture.config(3));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let incumbent = checkpoint("cat_b", "vol_b", "/dev/nbd0", '7');
        let incumbent_store =
            FileCheckpointStore::open(&checkpoint_directory, &incumbent.cat_id).unwrap();
        let _incumbent = incumbent_store.create(&incumbent).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a", "cat_b"]);

        let error = port
            .reserve_and_replace(&context, &store, &predecessor, |selected| {
                let mut replacement = predecessor.checkpoint().clone();
                let ReconcileStep::PrepareDevice {
                    ownership_token,
                    frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
                    ..
                } = &mut replacement.step
                else {
                    panic!("fixture must be a kernel-NBD PrepareDevice checkpoint")
                };
                *ownership_token = random('7');
                *device_path = selected;
                Ok(replacement)
            })
            .unwrap_err();

        assert!(
            error.to_string().contains("ownership token is reused"),
            "{error:#}"
        );
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
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
    fn reservation_never_returns_success_after_publication_cancellation() {
        let fixture = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let cancellation = context.clone();
        store.before_publish_once(move |_| cancellation.cancel_for_test());

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

        assert!(error.to_string().contains("cancelled"), "{error:#}");
        let persisted = store.load().unwrap().unwrap();
        let ReconcileStep::PrepareDevice {
            frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
            ..
        } = &persisted.checkpoint().step
        else {
            panic!("durable cancellation recovery must remain PrepareDevice")
        };
        assert_eq!(device_path, &host("/dev/nbd0"));
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
    fn reservation_never_authorizes_attach_after_post_publish_lock_replacement() {
        let fixture = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(fixture.config(2));
        let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd1", '6');
        let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
        let predecessor = store.create(&source).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let lock_path = fixture.state.join(ALLOCATION_LOCK_BASENAME);
        let detached_lock_path = fixture
            .state
            .join("kernel-nbd-allocation-post-publish.detached");
        let hook_lock_path = lock_path.clone();
        let hook_detached_lock_path = detached_lock_path.clone();
        store.before_publish_once(move |_| {
            fs::rename(&hook_lock_path, &hook_detached_lock_path).unwrap();
            fs::write(&hook_lock_path, b"").unwrap();
            fs::set_permissions(&hook_lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        });

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

        assert!(
            error
                .to_string()
                .contains("allocation lock pathname changed"),
            "{error:#}"
        );
        assert!(detached_lock_path.exists());
        assert_eq!(fs::read(&lock_path).unwrap(), b"");
        let persisted = store.load().unwrap().unwrap();
        let ReconcileStep::PrepareDevice {
            frontend: PrepareDeviceFrontend::KernelNbd { device_path, .. },
            ..
        } = &persisted.checkpoint().step
        else {
            panic!("detached allocation domain publication must remain PrepareDevice")
        };
        assert_eq!(device_path, &host("/dev/nbd0"));
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
    fn stable_foreign_clients_are_leaked_without_hiding_a_later_free_slot() {
        #[derive(Debug, Clone, Copy)]
        enum ForeignClient {
            Owner,
            NonDirectory,
            Executable,
            Arguments,
            RelativeListener,
            NonUtf8Listener,
        }

        for foreign in [
            ForeignClient::Owner,
            ForeignClient::NonDirectory,
            ForeignClient::Executable,
            ForeignClient::Arguments,
            ForeignClient::RelativeListener,
            ForeignClient::NonUtf8Listener,
        ] {
            let fixture = Fixture::new(3);
            fixture.serving(0, 42, "/run/cats/a.sock");
            let process = fixture.proc.join("42");
            match foreign {
                ForeignClient::Owner => {}
                ForeignClient::NonDirectory => {
                    fs::remove_dir_all(&process).unwrap();
                    fs::write(&process, b"not a proc directory").unwrap();
                }
                ForeignClient::Executable => {
                    let foreign_executable = fixture.state.join("foreign-nbd-client");
                    fs::write(&foreign_executable, b"foreign").unwrap();
                    fs::remove_file(process.join("exe")).unwrap();
                    symlink(foreign_executable, process.join("exe")).unwrap();
                }
                ForeignClient::Arguments => {
                    let arguments: [&[u8]; 9] = [
                        fixture.client.as_os_str().as_bytes(),
                        b"-nonetlink",
                        b"-unix",
                        b"/run/cats/a.sock",
                        b"/dev/nbd0",
                        b"-b",
                        b"4096",
                        b"-N",
                        b"",
                    ];
                    write_nul_arguments(&process.join("cmdline"), &arguments);
                }
                ForeignClient::RelativeListener | ForeignClient::NonUtf8Listener => {
                    let listener: &[u8] = match foreign {
                        ForeignClient::RelativeListener => b"relative.sock",
                        ForeignClient::NonUtf8Listener => b"/run/cats/\xff.sock",
                        _ => unreachable!(),
                    };
                    let arguments: [&[u8]; 9] = [
                        fixture.client.as_os_str().as_bytes(),
                        b"-nonetlink",
                        b"-unix",
                        listener,
                        b"/dev/nbd0",
                        b"-b",
                        b"512",
                        b"-N",
                        b"",
                    ];
                    write_nul_arguments(&process.join("cmdline"), &arguments);
                }
            }

            let mut config = fixture.config(3);
            if matches!(foreign, ForeignClient::Owner) {
                config.client_process_user_id = if effective_user_id() == 0 { 1 } else { 0 };
            }
            let port = KernelNbdInventoryPort::new(config);
            let permit = port.lock_and_inspect(&TestContext::active()).unwrap();
            assert_eq!(
                permit.snapshot().state(&host("/dev/nbd0")),
                Some(&KernelNbdSlotState::Leaked {
                    recorded_process_id: Some(42),
                }),
                "{foreign:?}"
            );
            assert_eq!(
                permit
                    .select_free(&KernelNbdReservations::default())
                    .unwrap(),
                host("/dev/nbd1"),
                "{foreign:?}"
            );
        }
    }

    #[test]
    fn malformed_unavailable_or_half_configured_inputs_are_explicitly_unavailable() {
        let cases: [fn(&Fixture); 4] = [
            |fixture| fs::write(fixture.sys.join("nbd0/size"), b"not-a-number\n").unwrap(),
            |fixture| fs::write(fixture.sys.join("nbd0/size"), vec![b'1'; 65]).unwrap(),
            |fixture| {
                fs::write(fixture.sys.join("nbd0/pid"), b"42\n").unwrap();
                fs::write(fixture.sys.join("nbd0/size"), b"0\n").unwrap();
            },
            |fixture| {
                fixture.serving(0, 42, "/run/cats/a.sock");
                let stat = fixture.proc.join("42/stat");
                fs::remove_file(&stat).unwrap();
                fs::create_dir(&stat).unwrap();
            },
        ];
        for arrange in cases {
            let fixture = Fixture::new(3);
            arrange(&fixture);
            let port = KernelNbdInventoryPort::new(fixture.config(3));
            let permit = port.lock_and_inspect(&TestContext::active()).unwrap();
            assert_eq!(
                permit.snapshot().state(&host("/dev/nbd0")),
                Some(&KernelNbdSlotState::Unavailable)
            );
            assert_eq!(
                permit
                    .select_free(&KernelNbdReservations::default())
                    .unwrap(),
                host("/dev/nbd1")
            );
        }
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
        let same_token_other_cat = checkpoint("cat_b", "vol_b", "/dev/nbd1", '6');
        let error =
            KernelNbdReservations::from_checkpoints([&first, &same_token_other_cat]).unwrap_err();
        assert!(
            error.to_string().contains("ownership token is reused"),
            "{error:#}"
        );
        let same_token_other_volume = checkpoint("cat_a", "vol_b", "/dev/nbd1", '6');
        let error = KernelNbdReservations::from_checkpoints([&first, &same_token_other_volume])
            .unwrap_err();
        assert!(
            error.to_string().contains("ownership token is reused"),
            "{error:#}"
        );

        let other = Fixture::new(2);
        let port = KernelNbdInventoryPort::new(other.config(2));
        let outside = checkpoint("cat_c", "vol_c", "/dev/nbd9", '8');
        let reservations = KernelNbdReservations::from_checkpoints([&outside]).unwrap();
        let permit = port.lock_and_inspect(&TestContext::active()).unwrap();
        assert!(permit.select_free(&reservations).is_err());
    }

    #[test]
    fn attach_transitions_one_reserved_free_slot_to_exact_provider_evidence() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let sys = fixture.sys.clone();
        let proc_root = fixture.proc.clone();
        let client = fixture.client.clone();
        let submitter = FakeSubmitter::new(move |_, request, _| {
            assert_eq!(request.listener_socket_path, host("/run/cats/nbd.sock"));
            assert_eq!(request.device_path, host("/dev/nbd0"));
            install_serving_client(
                &sys,
                &proc_root,
                &client,
                0,
                42,
                "/run/cats/nbd.sock",
                "/dev/nbd0",
            );
            Ok(KernelNbdClientSubmission::Completed)
        });
        let calls = submitter.clone();
        let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let listener = FakeListenerGuard::fixed();

        let result = port
            .attach_checkpointed(&request, &listener, &store, &stored, &context)
            .unwrap();
        let KernelNbdAttachResult::Exact(identity) = result else {
            panic!("free-to-serving attach must return exact physical evidence")
        };
        assert_eq!(identity.process_id, 42);
        assert_eq!(
            identity.process_start_time_ticks,
            WireU64::new(700).unwrap()
        );
        assert_eq!(identity.listener_socket_path, host("/run/cats/nbd.sock"));
        assert_eq!(identity.device_path, host("/dev/nbd0"));
        assert_eq!(identity.size_sectors, WireU64::new(8).unwrap());
        assert_eq!(calls.calls(), 1);
        assert_eq!(listener.calls(), 3);

        // The inventory-facing API sees the same tokenless provider identity,
        // not an effect-private approximation.
        let inventory = KernelNbdInventoryPort::new(fixture.config(1));
        let snapshot = inventory.lock_and_inspect(&TestContext::active()).unwrap();
        let collected = snapshot.snapshot().iter().collect::<Vec<_>>();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, &host("/dev/nbd0"));
        assert_eq!(collected[0].1, &KernelNbdSlotState::Serving(identity));
    }

    #[test]
    fn post_submit_unlock_failure_is_unknown_and_never_resubmitted() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let sys = fixture.sys.clone();
        let proc_root = fixture.proc.clone();
        let client = fixture.client.clone();
        let submitter = FakeSubmitter::new(move |_, _, _| {
            install_serving_client(
                &sys,
                &proc_root,
                &client,
                0,
                47,
                "/run/cats/nbd.sock",
                "/dev/nbd0",
            );
            Ok(KernelNbdClientSubmission::Completed)
        });
        let calls = submitter.clone();
        let mut port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
        // Exercise both the reporting unlock and Drop's non-panicking retry.
        port.inventory.inject_unlock_failures(2);
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let listener = FakeListenerGuard::fixed();

        assert_eq!(
            port.attach_checkpointed(&request, &listener, &store, &stored, &context)
                .unwrap(),
            KernelNbdAttachResult::OutcomeUnknown
        );
        assert_eq!(calls.calls(), 1);
    }

    #[test]
    fn response_loss_and_cancellation_are_unknown_and_never_resubmitted() {
        for cancel in [false, true] {
            let fixture = Fixture::new(1);
            let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
            let store = FileCheckpointStore::open(
                &fixture.state.join(CHECKPOINT_NAMESPACE),
                &source.cat_id,
            )
            .unwrap();
            let stored = store.create(&source).unwrap();
            let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
            let sys = fixture.sys.clone();
            let proc_root = fixture.proc.clone();
            let client = fixture.client.clone();
            let submitter = FakeSubmitter::new(move |_, _, context| {
                install_serving_client(
                    &sys,
                    &proc_root,
                    &client,
                    0,
                    43,
                    "/run/cats/nbd.sock",
                    "/dev/nbd0",
                );
                if cancel {
                    context.cancel_for_test();
                    Ok(KernelNbdClientSubmission::Completed)
                } else {
                    Ok(KernelNbdClientSubmission::OutcomeUnknown)
                }
            });
            let calls = submitter.clone();
            let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
            let context = desired_effect_context(&fixture.state, &["cat_a"]);
            let listener = FakeListenerGuard::fixed();

            assert_eq!(
                port.attach_checkpointed(&request, &listener, &store, &stored, &context)
                    .unwrap(),
                KernelNbdAttachResult::OutcomeUnknown
            );
            assert_eq!(calls.calls(), 1);

            // A new read context can settle the exact late result; the stale
            // effect call itself deliberately did not adopt it.
            let inventory = KernelNbdInventoryPort::new(fixture.config(1));
            let permit = inventory.lock_and_inspect(&TestContext::active()).unwrap();
            assert!(matches!(
                permit.snapshot().state(&host("/dev/nbd0")),
                Some(KernelNbdSlotState::Serving(_))
            ));
        }
    }

    #[test]
    fn pre_submit_spawn_failure_is_the_only_plain_attach_error_after_admission() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        fs::remove_file(&fixture.client).unwrap();
        let port =
            ExactKernelNbdAttachPort::new(fixture.config(1), PlatformKernelNbdClientSubmitPort);
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let listener = FakeListenerGuard::fixed();

        let error = port
            .attach_checkpointed(&request, &listener, &store, &stored, &context)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("spawn exact kernel-NBD client"),
            "{error:#}"
        );
        assert_eq!(listener.calls(), 1);
        let inventory = KernelNbdInventoryPort::new(fixture.config(1));
        let permit = inventory.lock_and_inspect(&TestContext::active()).unwrap();
        assert_eq!(
            permit.snapshot().state(&host("/dev/nbd0")),
            Some(&KernelNbdSlotState::Free)
        );
    }

    #[test]
    fn attach_rejects_busy_foreign_leaked_and_half_configured_slots_before_submit() {
        let cases: [fn(&Fixture); 4] = [
            |fixture| fixture.serving(0, 44, "/run/cats/nbd.sock"),
            |fixture| {
                fixture.serving(0, 45, "/run/cats/nbd.sock");
                fs::write(fixture.proc.join("45/cmdline"), b"foreign\0").unwrap();
            },
            |fixture| {
                fs::write(fixture.sys.join("nbd0/size"), b"8192\n").unwrap();
            },
            |fixture| {
                fs::write(fixture.sys.join("nbd0/pid"), b"46\n").unwrap();
            },
        ];
        for arrange in cases {
            let fixture = Fixture::new(1);
            arrange(&fixture);
            let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
            let store = FileCheckpointStore::open(
                &fixture.state.join(CHECKPOINT_NAMESPACE),
                &source.cat_id,
            )
            .unwrap();
            let stored = store.create(&source).unwrap();
            let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
            let submitter = FakeSubmitter::new(|_, _, _| {
                panic!("a non-Free slot must fail before client submission")
            });
            let calls = submitter.clone();
            let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
            let context = desired_effect_context(&fixture.state, &["cat_a"]);
            let listener = FakeListenerGuard::fixed();

            assert!(port
                .attach_checkpointed(&request, &listener, &store, &stored, &context)
                .is_err());
            assert_eq!(calls.calls(), 0);
        }
    }

    #[test]
    fn attach_post_scan_rejects_listener_device_size_and_half_state_drift() {
        #[derive(Clone, Copy)]
        enum Drift {
            Listener,
            Device,
            Size,
            Leaked,
            Half,
        }
        for drift in [
            Drift::Listener,
            Drift::Device,
            Drift::Size,
            Drift::Leaked,
            Drift::Half,
        ] {
            let fixture = Fixture::new(1);
            let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
            let store = FileCheckpointStore::open(
                &fixture.state.join(CHECKPOINT_NAMESPACE),
                &source.cat_id,
            )
            .unwrap();
            let stored = store.create(&source).unwrap();
            let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
            let sys = fixture.sys.clone();
            let proc_root = fixture.proc.clone();
            let client = fixture.client.clone();
            let submitter = FakeSubmitter::new(move |_, _, _| {
                match drift {
                    Drift::Listener => install_serving_client(
                        &sys,
                        &proc_root,
                        &client,
                        0,
                        47,
                        "/run/cats/other.sock",
                        "/dev/nbd0",
                    ),
                    Drift::Device => install_serving_client(
                        &sys,
                        &proc_root,
                        &client,
                        0,
                        47,
                        "/run/cats/nbd.sock",
                        "/dev/nbd1",
                    ),
                    Drift::Size => {
                        install_serving_client(
                            &sys,
                            &proc_root,
                            &client,
                            0,
                            47,
                            "/run/cats/nbd.sock",
                            "/dev/nbd0",
                        );
                        fs::write(sys.join("nbd0/size"), b"16\n").unwrap();
                    }
                    Drift::Leaked => {
                        fs::write(sys.join("nbd0/size"), b"8192\n").unwrap();
                    }
                    Drift::Half => {
                        fs::write(sys.join("nbd0/pid"), b"47\n").unwrap();
                    }
                }
                Ok(KernelNbdClientSubmission::Completed)
            });
            let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
            let context = desired_effect_context(&fixture.state, &["cat_a"]);
            let listener = FakeListenerGuard::fixed();

            let result = port
                .attach_checkpointed(&request, &listener, &store, &stored, &context)
                .unwrap();
            let expected = match drift {
                Drift::Listener | Drift::Size => KernelNbdAttachResult::ConflictAfterSubmit(
                    KernelNbdAttachConflict::LiveClientIdentity,
                ),
                Drift::Leaked => KernelNbdAttachResult::ConflictAfterSubmit(
                    KernelNbdAttachConflict::LeakedOrIncompleteAttachment {
                        recorded_process_id: None,
                    },
                ),
                Drift::Device => KernelNbdAttachResult::ConflictAfterSubmit(
                    KernelNbdAttachConflict::LeakedOrIncompleteAttachment {
                        recorded_process_id: Some(47),
                    },
                ),
                Drift::Half => KernelNbdAttachResult::OutcomeUnknown,
            };
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn attach_rejects_unaligned_checkpoint_capacity_before_any_physical_read() {
        let fixture = Fixture::new(1);
        let mut source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let ReconcileStep::PrepareDevice { size_bytes, .. } = &mut source.step else {
            unreachable!()
        };
        *size_bytes = 513;
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();

        let error = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap_err();
        assert!(error.to_string().contains("512-byte aligned"), "{error:#}");
        assert!(!fixture.state.join(ALLOCATION_LOCK_BASENAME).exists());
    }

    #[test]
    fn retained_listener_rebind_after_submit_can_never_return_exact() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let listener = FakeListenerGuard::new(|call, retained| {
            let mut current = retained.clone();
            if call > 1 {
                current.socket_inode = WireU64::new(12).unwrap();
            }
            Ok(current)
        });
        let sys = fixture.sys.clone();
        let proc_root = fixture.proc.clone();
        let client = fixture.client.clone();
        let submitter = FakeSubmitter::new(move |_, _, _| {
            install_serving_client(
                &sys,
                &proc_root,
                &client,
                0,
                49,
                "/run/cats/nbd.sock",
                "/dev/nbd0",
            );
            Ok(KernelNbdClientSubmission::Completed)
        });
        let calls = submitter.clone();
        let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
        let context = desired_effect_context(&fixture.state, &["cat_a"]);

        let result = port
            .attach_checkpointed(&request, &listener, &store, &stored, &context)
            .unwrap();
        assert_eq!(result, KernelNbdAttachResult::OutcomeUnknown);
        assert_eq!(calls.calls(), 1);
        assert_eq!(listener.calls(), 2);
    }

    #[test]
    fn retained_listener_drift_before_submit_has_zero_client_effect() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let listener = FakeListenerGuard::new(|_, retained| {
            let mut current = retained.clone();
            current.socket_inode = WireU64::new(12).unwrap();
            Ok(current)
        });
        let submitter = FakeSubmitter::new(|_, _, _| {
            panic!("listener drift must fail before nbd-client submission")
        });
        let calls = submitter.clone();
        let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
        let context = desired_effect_context(&fixture.state, &["cat_a"]);

        let error = port
            .attach_checkpointed(&request, &listener, &store, &stored, &context)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("fake retained listener identity changed"),
            "{error:#}"
        );
        assert_eq!(calls.calls(), 0);
        assert_eq!(listener.calls(), 1);
    }

    #[test]
    fn attach_revalidates_checkpoint_value_namespace_and_allocation_lock_after_submit() {
        enum Drift {
            CheckpointValue,
            Namespace,
            AllocationLock,
        }
        for drift in [
            Drift::CheckpointValue,
            Drift::Namespace,
            Drift::AllocationLock,
        ] {
            let fixture = Fixture::new(1);
            let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
            let checkpoint_directory = fixture.state.join(CHECKPOINT_NAMESPACE);
            let store = FileCheckpointStore::open(&checkpoint_directory, &source.cat_id).unwrap();
            let stored = store.create(&source).unwrap();
            let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
            let state = fixture.state.clone();
            let checkpoint_directory_for_hook = checkpoint_directory.clone();
            let source_for_hook = source.clone();
            let submitter = FakeSubmitter::new(move |_, _, _| {
                match drift {
                    Drift::CheckpointValue => {
                        let mut changed = source_for_hook.clone();
                        let ReconcileStep::PrepareDevice {
                            frontend:
                                PrepareDeviceFrontend::KernelNbd {
                                    listener_socket_path,
                                    ..
                                },
                            ..
                        } = &mut changed.step
                        else {
                            unreachable!()
                        };
                        *listener_socket_path = host("/run/cats/drifted.sock");
                        let bytes =
                            cats_api::runtime_reconciliation::encode_runtime_checkpoint(&changed)
                                .unwrap();
                        fs::write(
                            runtime_checkpoint_path(
                                &checkpoint_directory_for_hook,
                                &source_for_hook.cat_id,
                            ),
                            bytes,
                        )
                        .unwrap();
                    }
                    Drift::Namespace => {
                        let detached = state.join("checkpoints-detached-during-attach");
                        fs::rename(&checkpoint_directory_for_hook, detached).unwrap();
                        fs::create_dir(&checkpoint_directory_for_hook).unwrap();
                    }
                    Drift::AllocationLock => {
                        let lock = state.join(ALLOCATION_LOCK_BASENAME);
                        let detached = state.join("kernel-nbd-allocation-during-attach.detached");
                        fs::rename(&lock, detached).unwrap();
                        fs::write(&lock, b"").unwrap();
                        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                }
                Ok(KernelNbdClientSubmission::Completed)
            });
            let port = ExactKernelNbdAttachPort::new(fixture.config(1), submitter);
            let context = desired_effect_context(&fixture.state, &["cat_a"]);
            let listener = FakeListenerGuard::fixed();

            assert_eq!(
                port.attach_checkpointed(&request, &listener, &store, &stored, &context)
                    .unwrap(),
                KernelNbdAttachResult::OutcomeUnknown
            );
        }
    }

    #[test]
    fn two_attach_ports_serialize_under_the_same_allocation_flock() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store = Arc::new(
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap(),
        );
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let context = desired_effect_context(&fixture.state, &["cat_a"]);
        let second_submitter = FakeSubmitter::new(|_, _, _| {
            panic!("the second attach must not pass the shared allocation flock")
        });
        let second_calls = second_submitter.clone();
        let second = Arc::new(ExactKernelNbdAttachPort::new(
            fixture.config(1),
            second_submitter,
        ));
        let second_store = Arc::clone(&store);
        let second_stored = stored.clone();
        let second_request = request.clone();
        let second_context = context.clone();
        let second_listener = Arc::new(FakeListenerGuard::fixed());
        let sys = fixture.sys.clone();
        let proc_root = fixture.proc.clone();
        let client = fixture.client.clone();
        let first_submitter = FakeSubmitter::new(move |_, _, _| {
            let error = second
                .attach_checkpointed(
                    &second_request,
                    second_listener.as_ref(),
                    &second_store,
                    &second_stored,
                    &second_context,
                )
                .unwrap_err();
            assert!(error.to_string().contains("already active"), "{error:#}");
            install_serving_client(
                &sys,
                &proc_root,
                &client,
                0,
                48,
                "/run/cats/nbd.sock",
                "/dev/nbd0",
            );
            Ok(KernelNbdClientSubmission::Completed)
        });
        let first = ExactKernelNbdAttachPort::new(fixture.config(1), first_submitter);
        let first_listener = FakeListenerGuard::fixed();

        assert!(matches!(
            first
                .attach_checkpointed(&request, &first_listener, &store, &stored, &context)
                .unwrap(),
            KernelNbdAttachResult::Exact(_)
        ));
        assert_eq!(second_calls.calls(), 0);
    }

    #[test]
    fn platform_submitter_uses_frozen_argv_empty_environment_and_bounded_io() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        fs::write(
            &fixture.client,
            br#"#!/bin/sh
if [ "${CARGO_MANIFEST_DIR+x}" = x ]; then exit 90; fi
if [ "$#" -ne 8 ]; then exit 91; fi
if [ "$1" != "-nonetlink" ] || [ "$2" != "-unix" ]; then exit 92; fi
if [ "$3" != "/run/cats/nbd.sock" ] || [ "$4" != "/dev/nbd0" ]; then exit 93; fi
if [ "$5" != "-b" ] || [ "$6" != "512" ] || [ "$7" != "-N" ]; then exit 94; fi
if [ -n "$8" ]; then exit 95; fi
printf ignored-output
printf ignored-error >&2
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&fixture.client, fs::Permissions::from_mode(0o700)).unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            StateDirectory::unanchored(fixture.state.clone()),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(
            PlatformKernelNbdClientSubmitPort.submit(
                &fixture.config(1),
                &request,
                &context,
                &KernelNbdClientCleanupOwner::new(),
            ),
            KernelNbdClientSubmitAttempt::Submitted(KernelNbdClientSubmission::Completed)
        ));
    }

    #[test]
    fn platform_submitter_cancels_one_attempt_as_unknown_without_retry() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let pid_file = fixture.state.join("nbd-client.pid");
        fs::write(
            &fixture.client,
            format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nwhile :; do :; done\n",
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fixture.client, fs::Permissions::from_mode(0o700)).unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            StateDirectory::unanchored(fixture.state.clone()),
            Instant::now() + Duration::from_secs(2),
        );
        let cancellation = context.clone();
        let cancel_pid_file = pid_file.clone();
        let canceller = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !cancel_pid_file.exists() {
                assert!(Instant::now() < deadline, "kernel-NBD client did not start");
                std::thread::sleep(Duration::from_millis(2));
            }
            cancellation.cancel_for_test();
        });
        let started = Instant::now();
        let cleanup_owner = KernelNbdClientCleanupOwner::new();
        assert!(matches!(
            PlatformKernelNbdClientSubmitPort.submit(
                &fixture.config(1),
                &request,
                &context,
                &cleanup_owner,
            ),
            KernelNbdClientSubmitAttempt::Submitted(KernelNbdClientSubmission::OutcomeUnknown)
        ));
        canceller.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        let pid: libc::pid_t = fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let mut status = 0;
        // SAFETY: the exact child wrote this pid and the status pointer is
        // valid. ECHILD proves the shared owned-child cleanup already reaped
        // it before the cancelled submit call returned.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        assert_eq!(waited, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(cleanup_owner.pending_count(), 0);
    }

    #[test]
    fn attach_deadline_transfers_a_stubborn_owned_child_for_later_runtime_reap() {
        let fixture = Fixture::new(1);
        let source = checkpoint("cat_a", "vol_a", "/dev/nbd0", '6');
        let store =
            FileCheckpointStore::open(&fixture.state.join(CHECKPOINT_NAMESPACE), &source.cat_id)
                .unwrap();
        let stored = store.create(&source).unwrap();
        let request = KernelNbdAttachRequest::from_checkpoint(&stored).unwrap();
        let kill_requests = Arc::new(AtomicUsize::new(0));
        let allow_exit = Arc::new(AtomicBool::new(false));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let sys = fixture.sys.clone();
        let proc_root = fixture.proc.clone();
        let client_binary = fixture.client.clone();
        let submitter = StubbornClientSubmitter {
            client: Arc::new(Mutex::new(Some(Box::new(StubbornOwnedClient {
                kill_requests: Arc::clone(&kill_requests),
                allow_exit: Arc::clone(&allow_exit),
            })))),
            calls: Arc::clone(&submit_calls),
            after_cleanup: Arc::new(move || {
                install_serving_client(
                    &sys,
                    &proc_root,
                    &client_binary,
                    0,
                    50,
                    "/run/cats/nbd.sock",
                    "/dev/nbd0",
                );
            }),
        };
        let cleanup_owner = Arc::new(KernelNbdClientCleanupOwner::new());
        let port = ExactKernelNbdAttachPort::with_cleanup_owner(
            fixture.config(1),
            submitter,
            Arc::clone(&cleanup_owner),
        );
        let deadline = Instant::now() + Duration::from_millis(200);
        let context = desired_effect_context_until(&fixture.state, &["cat_a"], deadline);
        let listener = FakeListenerGuard::fixed();

        let result = port
            .attach_checkpointed(&request, &listener, &store, &stored, &context)
            .unwrap();
        assert_eq!(result, KernelNbdAttachResult::OutcomeUnknown);
        assert!(Instant::now() < deadline + Duration::from_millis(250));
        assert!(kill_requests.load(Ordering::SeqCst) >= 1);
        assert_eq!(submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cleanup_owner.pending_count(), 1);
        let shutdown_error = cleanup_owner.shutdown_until(Instant::now()).unwrap_err();
        assert!(
            shutdown_error.to_string().contains("shutdown deadline"),
            "{shutdown_error:#}"
        );
        assert_eq!(cleanup_owner.pending_count(), 1);

        // A fresh batch still sees a Free sysfs slot, but the sealed port must
        // not start a second client while the first may reach its ioctl late.
        let second_context = desired_effect_context(&fixture.state, &["cat_a"]);
        assert_eq!(
            port.attach_checkpointed(&request, &listener, &store, &stored, &second_context,)
                .unwrap(),
            KernelNbdAttachResult::OutcomeUnknown
        );
        assert_eq!(submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cleanup_owner.pending_count(), 1);

        // Once the owner can reap the first child, the next batch performs the
        // second (and only second) submit and its exact post-scan may close.
        allow_exit.store(true, Ordering::SeqCst);
        let third_context = desired_effect_context(&fixture.state, &["cat_a"]);
        assert!(matches!(
            port.attach_checkpointed(&request, &listener, &store, &stored, &third_context,)
                .unwrap(),
            KernelNbdAttachResult::Exact(_)
        ));
        assert_eq!(submit_calls.load(Ordering::SeqCst), 2);
        assert_eq!(cleanup_owner.pending_count(), 0);
        cleanup_owner
            .shutdown_until(Instant::now() + Duration::from_millis(10))
            .unwrap();
    }

    #[test]
    fn cleanup_poll_error_retains_only_that_child_and_does_not_starve_later_reaps() {
        let cleanup_owner = KernelNbdClientCleanupOwner::new();
        cleanup_owner.transfer(Box::new(PollErrorOwnedClient));
        cleanup_owner.transfer(Box::new(StubbornOwnedClient {
            kill_requests: Arc::new(AtomicUsize::new(0)),
            allow_exit: Arc::new(AtomicBool::new(true)),
        }));

        let error = cleanup_owner.poll_reap().unwrap_err();
        assert!(
            format!("{error:#}").contains("injected cleanup poll failure"),
            "{error:#}"
        );
        assert_eq!(cleanup_owner.pending_count(), 1);
    }
}

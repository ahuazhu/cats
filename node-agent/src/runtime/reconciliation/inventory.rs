//! First-slice full inventory boundary.
//!
//! This can establish the first A20 attestation only after every Runtime §6
//! physical source proves that its managed namespace is empty, while the
//! metadata source may return exact authority facts for Desired-bound root
//! Volumes. It never adopts or translates the legacy runtime ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, sort_node_residue_canonically, AppliedDesiredEvidence,
    CheckpointEvidence, Condition, ControlHandshakeEvidence, DesiredRuntimeSpec,
    GuestTransportEvidence, HostPath, Id, InventorySource, LastVolumeTransition,
    LifecycleAdmission, LocalLineageState, LocalVolumeLineage, NodeResidue, ObservedDevice,
    ObservedRuntimeStatus, ObservedVolume, OwnershipTokenEvidence, ProcessEvidence, ProcessRole,
    ProcessState, ProgressingReason, ReadyReason, ReconcileStep, RequireIdleCheckpoint,
    RuntimeCheckpoint, RuntimeTarget, Sha256Digest, StableState, UnixMillis, VolumeAdminState,
    VolumeAuthorityEvidence, WarmSnapshotEvidence, WireU64, NODE_OBSERVATION_MAX_RESIDUE_ITEMS,
};
#[cfg(feature = "proposed-node-residue-reclamation")]
use cats_api::runtime_reconciliation::{
    residue_acquisition_digest, DataDirectoryRetentionReason, ResidueDataDirectoryLineage,
    ResidueLineageEvidence,
};
use cats_storage::{
    authority::{
        remote_head_is_same_or_later, validate_authorized_serving_attachment,
        validate_authorized_serving_record, validate_volume_record, AuthorizedServingAcquire,
        VolumeRecord,
    },
    BlobStore,
};
use thiserror::Error;

use crate::route_grant_v2::RouteGrantV2Verifier;
use crate::runtime_spine::{
    CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeInventoryKeyRing,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
};

use super::{
    admission_registry::AdmissionCellRegistry,
    classify_current_endpoint_route_retirement, classify_current_global_route_retirement,
    classify_superseded_route_retirement,
    guest_ready::{GuestReadyTransportPort, PlatformGuestReadyTransportPort},
    kernel_nbd::{KernelNbdInventoryPort, KernelNbdPoolScanOutcome, KernelNbdProcessAllowances},
    lifecycle_steps::{
        cold_membership_detach_cleanup_checkpoint_is_supported,
        cold_membership_detach_cleanup_is_supported, cold_membership_rebind_is_supported,
        current_cold_checkpoint_postcondition_is_exact,
    },
    network::{
        prepare_device_checkpoint_view, prepared_device_inputs, NodeGlobalNetworkScanAdmission,
    },
    prepare_device_retirement::{
        prepared_device_input_is_exact, prepared_device_input_matches_retained_lifecycle,
    },
    probe_exact_guest_mounted_set,
    retained_runtime_launch::RetainedRuntimeLaunchAuthority,
    root_provision_process::{
        ManagedServingKey, NodeGlobalManagedProcessScanAdmission,
        RetainedRootProvisionProcessAttempt, RootProvisionAuthoritySnapshot,
        RootProvisionProcessExpectation, StopReceiptSocketAdmission,
        TargetControlProcessLaunchIdentity,
    },
    running_admission::{classify_running_tail_phase, RunningTailScanAdmission},
    running_launch_authority::{
        validate_retained_running_close_scan_exact_set, validate_retained_running_scan_exact_set,
    },
    runtime_checkpoint_path, sealed_running_predecessor,
    signed_running::{
        expected_provision_heads, multi_acquire_checkpoint_is_bound, provision_checkpoint_is_bound,
        request_matches_volume, superseded_checkpoint_has_supported_replan, ProvisionHeadRead,
    },
    AuthorizedBlockdCheckpoint,
};

const REQUIRED_SOURCES: [InventorySource; 11] = [
    InventorySource::Checkpoint,
    InventorySource::Systemd,
    InventorySource::Process,
    InventorySource::ControlSocket,
    InventorySource::BlockFrontend,
    InventorySource::Network,
    InventorySource::DataDirectory,
    InventorySource::PendingPack,
    InventorySource::WarmSnapshot,
    InventorySource::MetadataStore,
    InventorySource::GuestMount,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryAbsence {
    Empty,
    /// A complete source enumeration containing physical resources which do
    /// not belong to an accepted runtime.  Residue is observation, not an
    /// absence proof and never authorizes scanner-side cleanup.
    Residue(Vec<NodeResidue>),
    RuntimeCheckpoints(BTreeMap<Id, RuntimeCheckpointInventoryEvidence>),
    RuntimeCheckpointsWithResidue {
        checkpoints: BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
        residue: Vec<NodeResidue>,
    },
    /// Canonical assigned checkpoint files which were readable but could not
    /// be decoded or bound to that filename's exact Desired. They belong to
    /// the Cat projection, never to top-level residue at the same path.
    RuntimeCheckpointsWithCorrupt {
        checkpoints: BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
        corrupt_checkpoints: BTreeMap<Id, Sha256Digest>,
        residue: Vec<NodeResidue>,
    },
    AuthorizedBlockd(BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>),
    AuthorizedBlockdWithResidue {
        blockds: BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
        residue: Vec<NodeResidue>,
    },
    /// The metadata source contains exactly the Desired-bound volume facts
    /// supplied here and no discovered local-only candidate. These are not
    /// physical residue: a newly assigned Cat must be able to report its
    /// authoritative root before its first local effect exists.
    DesiredVolumes(BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>),
    Unavailable,
}

/// Read-only classification of a syntactically valid per-Cat checkpoint
/// against the exact Desired snapshot which bounded this inventory scan.
///
/// A superseded checkpoint is physical evidence, not an unavailable source.
/// Keeping the complete old checkpoint lets the effect planner distinguish a
/// pre-effect journal from an already-authorized old attachment without ever
/// rewriting or deleting either one in the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredCheckpointBinding {
    Current,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCheckpointInventoryEvidence {
    pub checkpoint: RuntimeCheckpoint,
    pub binding: DesiredCheckpointBinding,
    /// The checkpoint scanner decoded and exactly validated a durable local
    /// marker for a closed A22 cleanup rejection. The marker itself stays a
    /// provider-private filesystem contract and is never projected to wire.
    pub definite_release_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedBlockdControlState {
    NotStarted,
    ExactControlOnlyEmpty,
    /// A durable `CleanupRelease::Volume` remains current and the immutable
    /// launch checkpoint is the final local restart anchor. Some earlier
    /// descriptor-relative unlinks may already have completed.
    #[cfg(feature = "proposed-node-residue-reclamation")]
    ReclaimInProgress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBlockdInventoryEvidence {
    pub data_directory: HostPath,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub allocated_bytes: WireU64,
    pub checkpoint: AuthorizedBlockdCheckpoint,
    pub binding: DesiredCheckpointBinding,
    /// Closed provider-private evidence. This is deliberately not projected
    /// to the Runtime inventory wire: it only prevents a process handshake
    /// from outrunning the engine files it claims to represent.
    pub control_state: AuthorizedBlockdControlState,
    /// Exact old control-only process identity retained by a validated
    /// `PrepareDevice.after_root_provision` handoff. This keeps the live old
    /// process in the Node-global allowlist until a later one-effect stop.
    pub(crate) retained_root_process: Option<RetainedRootProvisionProcessAttempt>,
    /// Present only when the full scanner validated the exact immutable
    /// target-control artifact. It expands target-phase inspection to the
    /// closed blank-or-wrapper argv union without projecting that private
    /// artifact onto the public Runtime wire.
    pub(crate) target_control_launch: Option<TargetControlProcessLaunchIdentity>,
    /// Typed stale control socket retained by an exact durable stop receipt.
    /// It is an additional allowlist member only while the corresponding
    /// RootControl expectation is physically absent.
    pub(crate) stop_receipt_socket: Option<StopReceiptSocketAdmission>,
    /// Descriptor chain retained by the DataDirectory scanner. Public
    /// observations cannot construct or reopen this provider-private delete
    /// admission.
    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub(crate) reclaim: Arc<super::residue_reclaim::RetainedDataDirectory>,
}

/// Provider-private authority evidence retained until the local attachment
/// has been checked against the complete fresh record. Only `observed` is
/// projected onto the frozen Runtime inventory wire contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityVolumeInventoryEvidence {
    pub observed: ObservedVolume,
    pub record: VolumeRecord,
}

/// One read-only proof for exactly one member of the Runtime inventory-source
/// closed set. `Err` means detected residue/collision/corruption, not ordinary
/// source downtime; implementations use `Unavailable` for the latter. Every
/// concrete probe must pass `context.deadline()` to its filesystem, socket,
/// process or metadata I/O and return promptly after cancellation.
pub trait InventoryAbsenceProbe:
    super::inventory_probe_sealed::Sealed + Send + Sync + 'static
{
    fn source(&self) -> InventorySource;
    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence>;
}

pub(crate) mod root_process_inventory_bridge_sealed {
    pub(crate) trait Sealed {}
}

#[derive(Debug)]
pub(crate) enum RootProcessInventoryBridgeOutcome {
    Complete(NodeGlobalManagedProcessScanAdmission),
    CompleteWithResidue {
        admission: NodeGlobalManagedProcessScanAdmission,
        systemd: Vec<NodeResidue>,
        processes: Vec<NodeResidue>,
        control_sockets: Vec<NodeResidue>,
    },
    Unavailable {
        /// Per-Cat exact Running negatives learned before a later member of
        /// the closed process scan became unavailable. These are safe only
        /// for fail-closing local admission; they never complete inventory.
        exact_running_negative_cats: BTreeSet<Id>,
    },
}

/// Joint Systemd/process/control-socket inspection. It consumes expectations
/// derived from the already-complete checkpoint, data-directory and authority
/// sources, and is the only path that may project a verified process.
pub(crate) trait RootProcessInventoryBridge:
    root_process_inventory_bridge_sealed::Sealed + Send + Sync + 'static
{
    fn executable_path(&self) -> &HostPath;

    fn serving_expectation(
        &self,
        checkpoint: &RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
        blockd: &AuthorizedBlockdInventoryEvidence,
        authority: &VolumeRecord,
    ) -> anyhow::Result<super::serving_blockd_process::ServingBlockdExpectation>;

    fn inspect_all(
        &self,
        root_expected: BTreeMap<Id, RootProvisionProcessExpectation>,
        serving_expected: BTreeMap<
            ManagedServingKey,
            super::serving_blockd_process::ServingBlockdExpectation,
        >,
        vmm_expected: BTreeMap<Id, super::vmm_process::VmmProcessExpectation>,
        stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RootProcessInventoryBridgeOutcome>;

    fn inspect_all_with_additional_managed_units(
        &self,
        root_expected: BTreeMap<Id, RootProvisionProcessExpectation>,
        serving_expected: BTreeMap<
            ManagedServingKey,
            super::serving_blockd_process::ServingBlockdExpectation,
        >,
        vmm_expected: BTreeMap<Id, super::vmm_process::VmmProcessExpectation>,
        stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
        additional_managed_units: BTreeSet<Id>,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RootProcessInventoryBridgeOutcome> {
        let outcome = self.inspect_all(
            root_expected,
            serving_expected,
            vmm_expected,
            stop_receipt_sockets,
            context,
        )?;
        Ok(match outcome {
            RootProcessInventoryBridgeOutcome::Complete(admission) => {
                RootProcessInventoryBridgeOutcome::Complete(
                    admission.with_additional_managed_units(additional_managed_units)?,
                )
            }
            RootProcessInventoryBridgeOutcome::CompleteWithResidue {
                admission,
                systemd,
                processes,
                control_sockets,
            } => RootProcessInventoryBridgeOutcome::CompleteWithResidue {
                admission: admission.with_additional_managed_units(additional_managed_units)?,
                systemd,
                processes,
                control_sockets,
            },
            unavailable @ RootProcessInventoryBridgeOutcome::Unavailable { .. } => unavailable,
        })
    }
}

pub(crate) mod network_inventory_bridge_sealed {
    pub(crate) trait Sealed {}
}

#[derive(Debug)]
pub(crate) enum NetworkInventoryBridgeOutcome {
    Complete(NodeGlobalNetworkScanAdmission),
    CompleteWithResidue {
        admission: NodeGlobalNetworkScanAdmission,
        residue: Vec<NodeResidue>,
    },
    Unavailable,
}

/// Joint durable-reservation and complete Host link/address inspection.  The
/// bridge is the only scanner path allowed to project a managed TAP.
pub(crate) trait NetworkInventoryBridge:
    network_inventory_bridge_sealed::Sealed + Send + Sync + 'static
{
    fn inspect_all(
        &self,
        checkpoints: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<NetworkInventoryBridgeOutcome>;
}

pub(crate) mod runtime_inventory_key_ring_reader_sealed {
    pub(crate) trait Sealed {}
}

/// One bounded read of the Node's actually loaded Route v2 verifier ring. The
/// scanner calls this port at most once per full scan and never substitutes
/// filesystem candidates for the in-process authorization fact.
pub(crate) trait RuntimeInventoryKeyRingReader:
    runtime_inventory_key_ring_reader_sealed::Sealed + Send + Sync + 'static
{
    fn read(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryKeyRing>;
}

#[derive(Debug)]
pub(crate) struct ActiveRuntimeInventoryKeyRingReader {
    verifier: Arc<RouteGrantV2Verifier>,
}

impl ActiveRuntimeInventoryKeyRingReader {
    pub(crate) fn new(verifier: Arc<RouteGrantV2Verifier>) -> Self {
        Self { verifier }
    }
}

impl runtime_inventory_key_ring_reader_sealed::Sealed for ActiveRuntimeInventoryKeyRingReader {}

impl RuntimeInventoryKeyRingReader for ActiveRuntimeInventoryKeyRingReader {
    fn read(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryKeyRing> {
        context.check_active()?;
        let ring = self
            .verifier
            .current_ring()
            .context("read the active Route Grant v2 verifier ring")?;
        context.check_active()?;
        Ok(RuntimeInventoryKeyRing::Loaded {
            version: ring.version(),
            digest: ring.digest().clone(),
            kids: ring.loaded_kids().to_vec(),
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InventoryProbeSetError {
    #[error("inventory absence probe is duplicated for {0:?}")]
    Duplicate(InventorySource),
    #[error("inventory absence probe is missing for {0:?}")]
    Missing(InventorySource),
}

pub struct CleanSlateInventoryScanner {
    checkpoint_directory: PathBuf,
    probes: Vec<Arc<dyn InventoryAbsenceProbe>>,
    blob: Option<Arc<dyn BlobStore>>,
    root_process_bridge: Option<Arc<dyn RootProcessInventoryBridge>>,
    network_bridge: Option<Arc<dyn NetworkInventoryBridge>>,
    kernel_nbd_port: Option<KernelNbdInventoryPort>,
    key_ring_reader: Option<Arc<dyn RuntimeInventoryKeyRingReader>>,
    running_admission_registry: Option<Arc<AdmissionCellRegistry>>,
    guest_ready: Option<Arc<dyn GuestReadyTransportPort>>,
}

impl crate::runtime_spine::inventory_scanner_sealed::Sealed for CleanSlateInventoryScanner {}

impl std::fmt::Debug for CleanSlateInventoryScanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CleanSlateInventoryScanner")
            .field("checkpoint_directory", &self.checkpoint_directory)
            .field(
                "sources",
                &self
                    .probes
                    .iter()
                    .map(|probe| probe.source())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl CleanSlateInventoryScanner {
    pub fn new(
        checkpoint_directory: PathBuf,
        mut probes: Vec<Arc<dyn InventoryAbsenceProbe>>,
    ) -> Result<Self, InventoryProbeSetError> {
        probes.sort_by_key(|probe| probe.source());
        let mut found = BTreeSet::new();
        for probe in &probes {
            if !found.insert(probe.source()) {
                return Err(InventoryProbeSetError::Duplicate(probe.source()));
            }
        }
        for source in REQUIRED_SOURCES {
            if !found.contains(&source) {
                return Err(InventoryProbeSetError::Missing(source));
            }
        }
        Ok(Self {
            checkpoint_directory,
            probes,
            blob: None,
            root_process_bridge: None,
            network_bridge: None,
            kernel_nbd_port: None,
            key_ring_reader: None,
            running_admission_registry: None,
            guest_ready: None,
        })
    }

    pub(crate) fn new_with_blob(
        checkpoint_directory: PathBuf,
        probes: Vec<Arc<dyn InventoryAbsenceProbe>>,
        blob: Arc<dyn BlobStore>,
    ) -> Result<Self, InventoryProbeSetError> {
        let mut scanner = Self::new(checkpoint_directory, probes)?;
        scanner.blob = Some(blob);
        Ok(scanner)
    }

    pub(crate) fn new_with_blob_and_root_process_bridge(
        checkpoint_directory: PathBuf,
        probes: Vec<Arc<dyn InventoryAbsenceProbe>>,
        blob: Arc<dyn BlobStore>,
        bridge: Arc<dyn RootProcessInventoryBridge>,
    ) -> Result<Self, InventoryProbeSetError> {
        let mut scanner = Self::new_with_blob(checkpoint_directory, probes, blob)?;
        scanner.root_process_bridge = Some(bridge);
        Ok(scanner)
    }

    pub(crate) fn with_key_ring_reader(
        mut self,
        reader: Arc<dyn RuntimeInventoryKeyRingReader>,
    ) -> Self {
        self.key_ring_reader = Some(reader);
        self
    }

    pub(crate) fn with_network_bridge(mut self, bridge: Arc<dyn NetworkInventoryBridge>) -> Self {
        self.network_bridge = Some(bridge);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_root_process_bridge_for_test(
        mut self,
        bridge: Arc<dyn RootProcessInventoryBridge>,
    ) -> Self {
        self.root_process_bridge = Some(bridge);
        self
    }

    pub(crate) fn with_kernel_nbd_pool(mut self, port: KernelNbdInventoryPort) -> Self {
        self.kernel_nbd_port = Some(port);
        self
    }

    pub(crate) fn with_running_tail(mut self, registry: Arc<AdmissionCellRegistry>) -> Self {
        self.running_admission_registry = Some(registry);
        self.guest_ready = Some(Arc::new(PlatformGuestReadyTransportPort));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_running_tail_transport_for_test(
        mut self,
        registry: Arc<AdmissionCellRegistry>,
        guest_ready: Arc<dyn GuestReadyTransportPort>,
    ) -> Self {
        self.running_admission_registry = Some(registry);
        self.guest_ready = Some(guest_ready);
        self
    }
}

struct InventoryProbeAggregation {
    unavailable_sources: Vec<InventorySource>,
    residue_sources: BTreeSet<InventorySource>,
    volumes_by_cat: BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
    checkpoints_by_cat: BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    corrupt_checkpoints_by_cat: BTreeMap<Id, Sha256Digest>,
    blockd_by_cat: BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    residue: Vec<NodeResidue>,
    coverage: InventoryCoverageAggregator,
}

impl InventoryProbeAggregation {
    fn new() -> Self {
        Self {
            unavailable_sources: Vec::new(),
            residue_sources: BTreeSet::new(),
            volumes_by_cat: BTreeMap::new(),
            checkpoints_by_cat: BTreeMap::new(),
            corrupt_checkpoints_by_cat: BTreeMap::new(),
            blockd_by_cat: BTreeMap::new(),
            residue: Vec::new(),
            coverage: InventoryCoverageAggregator::new(),
        }
    }
}

fn append_residue_or_mark_incomplete(
    aggregate: &mut InventoryProbeAggregation,
    source: InventorySource,
    mut residue: Vec<NodeResidue>,
) {
    if residue.is_empty() {
        return;
    }
    if aggregate
        .residue
        .len()
        .checked_add(residue.len())
        .is_none_or(|total| total > NODE_OBSERVATION_MAX_RESIDUE_ITEMS)
    {
        if !aggregate.unavailable_sources.contains(&source) {
            aggregate.unavailable_sources.push(source);
        }
        return;
    }
    aggregate.residue_sources.insert(source);
    aggregate.residue.append(&mut residue);
}

fn incomplete_inventory(
    mut unavailable_sources: Vec<InventorySource>,
    exact_physical_negative_cats: BTreeSet<Id>,
) -> RuntimeInventoryScanOutcome {
    unavailable_sources.sort();
    unavailable_sources.dedup();
    RuntimeInventoryScanOutcome::Incomplete {
        unavailable_sources,
        exact_physical_negative_cats,
    }
}

fn inspect_inventory_probe(
    probe: &Arc<dyn InventoryAbsenceProbe>,
    context: &RuntimeInventoryScanContext,
    aggregate: &mut InventoryProbeAggregation,
) -> anyhow::Result<()> {
    context
        .remaining()
        .with_context(|| format!("clean-slate inventory stopped before {:?}", probe.source()))?;
    match probe
        .prove_absent(context)
        .with_context(|| format!("prove {:?} inventory is absent", probe.source()))?
    {
        InventoryAbsence::Empty => {}
        InventoryAbsence::Residue(residue) => {
            append_residue_or_mark_incomplete(aggregate, probe.source(), residue)
        }
        InventoryAbsence::RuntimeCheckpoints(checkpoints) => {
            anyhow::ensure!(
                probe.source() == InventorySource::Checkpoint,
                "only the checkpoint source may report Runtime checkpoints"
            );
            for (cat_id, checkpoint) in checkpoints {
                anyhow::ensure!(
                    aggregate
                        .checkpoints_by_cat
                        .insert(cat_id, checkpoint)
                        .is_none(),
                    "checkpoint inventory duplicated one Cat"
                );
            }
        }
        InventoryAbsence::RuntimeCheckpointsWithResidue {
            checkpoints,
            residue,
        } => {
            anyhow::ensure!(
                probe.source() == InventorySource::Checkpoint,
                "only the checkpoint source may report Runtime checkpoints"
            );
            for (cat_id, checkpoint) in checkpoints {
                anyhow::ensure!(
                    aggregate
                        .checkpoints_by_cat
                        .insert(cat_id, checkpoint)
                        .is_none(),
                    "checkpoint inventory duplicated one Cat"
                );
            }
            append_residue_or_mark_incomplete(aggregate, probe.source(), residue);
        }
        InventoryAbsence::RuntimeCheckpointsWithCorrupt {
            checkpoints,
            corrupt_checkpoints,
            residue,
        } => {
            anyhow::ensure!(
                probe.source() == InventorySource::Checkpoint,
                "only the checkpoint source may report Runtime checkpoints"
            );
            for (cat_id, checkpoint) in checkpoints {
                anyhow::ensure!(
                    aggregate
                        .checkpoints_by_cat
                        .insert(cat_id, checkpoint)
                        .is_none(),
                    "checkpoint inventory duplicated one Cat"
                );
            }
            for (cat_id, digest) in corrupt_checkpoints {
                anyhow::ensure!(
                    !aggregate.checkpoints_by_cat.contains_key(&cat_id)
                        && aggregate
                            .corrupt_checkpoints_by_cat
                            .insert(cat_id, digest)
                            .is_none(),
                    "checkpoint inventory duplicated one Cat"
                );
            }
            append_residue_or_mark_incomplete(aggregate, probe.source(), residue);
        }
        InventoryAbsence::AuthorizedBlockd(blockds) => {
            anyhow::ensure!(
                probe.source() == InventorySource::DataDirectory,
                "only the data-directory source may report authorized blockd lineage"
            );
            for (cat_id, by_volume) in blockds {
                let target = aggregate.blockd_by_cat.entry(cat_id.clone()).or_default();
                for (volume_id, blockd) in by_volume {
                    anyhow::ensure!(
                        blockd.checkpoint.desired.cat_id == cat_id
                            && blockd.checkpoint.attachment.identity.volume_id == volume_id,
                        "data-directory inventory is indexed by another Cat or Volume"
                    );
                    anyhow::ensure!(
                        target.insert(volume_id, blockd).is_none(),
                        "data-directory inventory duplicated one Cat/Volume"
                    );
                }
            }
        }
        InventoryAbsence::AuthorizedBlockdWithResidue { blockds, residue } => {
            anyhow::ensure!(
                probe.source() == InventorySource::DataDirectory,
                "only the data-directory source may report authorized blockd lineage"
            );
            for (cat_id, by_volume) in blockds {
                let target = aggregate.blockd_by_cat.entry(cat_id.clone()).or_default();
                for (volume_id, blockd) in by_volume {
                    anyhow::ensure!(
                        blockd.checkpoint.desired.cat_id == cat_id
                            && blockd.checkpoint.attachment.identity.volume_id == volume_id,
                        "data-directory inventory is indexed by another Cat or Volume"
                    );
                    anyhow::ensure!(
                        target.insert(volume_id, blockd).is_none(),
                        "data-directory inventory duplicated one Cat/Volume"
                    );
                }
            }
            append_residue_or_mark_incomplete(aggregate, probe.source(), residue);
        }
        InventoryAbsence::DesiredVolumes(observed) => {
            anyhow::ensure!(
                probe.source() == InventorySource::MetadataStore,
                "only the metadata source may report Desired volume facts"
            );
            for (cat_id, volumes) in observed {
                anyhow::ensure!(
                    aggregate.volumes_by_cat.insert(cat_id, volumes).is_none(),
                    "metadata inventory duplicated one Cat"
                );
            }
        }
        InventoryAbsence::Unavailable => aggregate.unavailable_sources.push(probe.source()),
    }
    context
        .remaining()
        .with_context(|| format!("clean-slate inventory stopped after {:?}", probe.source()))?;
    aggregate.coverage.record(probe.source())?;
    Ok(())
}

impl RuntimeInventoryScanner for CleanSlateInventoryScanner {
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
        let mut aggregate = InventoryProbeAggregation::new();
        let mut processes_by_cat = BTreeMap::new();
        let mut serving_devices_by_cat = BTreeMap::new();
        let mut serving_status_by_cat = BTreeMap::new();
        let mut networks_by_cat = BTreeMap::new();
        let mut node_global_process_admission = None;
        let mut node_global_network_admission = None;
        let mut kernel_nbd_pool_admission = None;
        let mut kernel_nbd_process_allowances = KernelNbdProcessAllowances::default();
        let mut kernel_nbd_pre_scan_available = true;
        let mut exact_physical_negative_cats = BTreeSet::new();
        if let Some(bridge) = &self.root_process_bridge {
            // The process expectation cannot be derived until all three data
            // authorities have completed. Read each prerequisite exactly
            // once, then inspect the three physical process sources jointly.
            for source in [
                InventorySource::Checkpoint,
                InventorySource::DataDirectory,
                InventorySource::MetadataStore,
            ] {
                let probe = self
                    .probes
                    .iter()
                    .find(|probe| probe.source() == source)
                    .expect("probe-set validation established every source");
                inspect_inventory_probe(probe, &context, &mut aggregate)?;
            }
            if !aggregate.unavailable_sources.is_empty() {
                return Ok(incomplete_inventory(
                    aggregate.unavailable_sources,
                    exact_physical_negative_cats,
                ));
            }

            if let Some(kernel_nbd) = &self.kernel_nbd_port {
                kernel_nbd_process_allowances = match kernel_nbd.scan_process_allowances(&context) {
                    Ok(allowances) => allowances,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            proof = "kernel-NBD process allowances",
                            "kernel-NBD pre-scan is unavailable"
                        );
                        aggregate
                            .unavailable_sources
                            .push(InventorySource::BlockFrontend);
                        kernel_nbd_pre_scan_available = false;
                        KernelNbdProcessAllowances::default()
                    }
                };
            }

            let root_expected = root_process_expectations(
                &context,
                &self.checkpoint_directory,
                self.blob.as_deref(),
                bridge.executable_path(),
                &aggregate.checkpoints_by_cat,
                &aggregate.blockd_by_cat,
                &aggregate.volumes_by_cat,
            )?;
            let serving_expected = serving_process_expectations_with_registry(
                &context,
                bridge.as_ref(),
                &aggregate.checkpoints_by_cat,
                &aggregate.blockd_by_cat,
                &aggregate.volumes_by_cat,
                self.running_admission_registry.as_deref(),
            )?;
            let vmm_expected = vmm_process_expectations(
                &self.checkpoint_directory,
                &aggregate.checkpoints_by_cat,
            )?;
            let stop_receipt_sockets = aggregate.blockd_by_cat.iter().try_fold(
                BTreeMap::new(),
                |mut sockets, (cat_id, by_volume)| {
                    for evidence in by_volume.values() {
                        if let Some(socket) = evidence.stop_receipt_socket.clone() {
                            anyhow::ensure!(
                                sockets.insert(cat_id.clone(), socket).is_none(),
                                "one Cat retains duplicate Root stop-receipt sockets"
                            );
                        }
                    }
                    Ok::<_, anyhow::Error>(sockets)
                },
            )?;
            context
                .remaining()
                .context("root-process inventory bridge deadline expired before inspection")?;
            match bridge.inspect_all_with_additional_managed_units(
                root_expected,
                serving_expected,
                vmm_expected,
                stop_receipt_sockets,
                kernel_nbd_process_allowances.unit_ids(),
                &context,
            )? {
                RootProcessInventoryBridgeOutcome::Complete(admission) => {
                    exact_physical_negative_cats = admission.exact_running_negative_cats();
                    processes_by_cat = admission.process_projections();
                    serving_devices_by_cat = admission.vhost_device_projections();
                    serving_status_by_cat = admission.serving_status_projections();
                    node_global_process_admission = Some(admission);
                }
                RootProcessInventoryBridgeOutcome::CompleteWithResidue {
                    admission,
                    systemd,
                    processes,
                    control_sockets,
                } => {
                    exact_physical_negative_cats = admission.exact_running_negative_cats();
                    processes_by_cat = admission.process_projections();
                    serving_devices_by_cat = admission.vhost_device_projections();
                    serving_status_by_cat = admission.serving_status_projections();
                    node_global_process_admission = Some(admission);
                    append_residue_or_mark_incomplete(
                        &mut aggregate,
                        InventorySource::Systemd,
                        systemd,
                    );
                    append_residue_or_mark_incomplete(
                        &mut aggregate,
                        InventorySource::Process,
                        processes,
                    );
                    append_residue_or_mark_incomplete(
                        &mut aggregate,
                        InventorySource::ControlSocket,
                        control_sockets,
                    );
                }
                RootProcessInventoryBridgeOutcome::Unavailable {
                    exact_running_negative_cats,
                } => {
                    exact_physical_negative_cats = exact_running_negative_cats;
                    aggregate.unavailable_sources.extend([
                        InventorySource::Systemd,
                        InventorySource::Process,
                        InventorySource::ControlSocket,
                    ]);
                }
            }
            if context.remaining().is_err() {
                aggregate.unavailable_sources.extend([
                    InventorySource::Systemd,
                    InventorySource::Process,
                    InventorySource::ControlSocket,
                ]);
                return Ok(incomplete_inventory(
                    aggregate.unavailable_sources,
                    exact_physical_negative_cats,
                ));
            }
            if kernel_nbd_pre_scan_available {
                if let (Some(kernel_nbd), Some(managed_processes)) = (
                    self.kernel_nbd_port.as_ref(),
                    node_global_process_admission.as_ref(),
                ) {
                    match kernel_nbd.scan_complete_pool_with_allowances(
                        &context,
                        managed_processes,
                        &kernel_nbd_process_allowances,
                    )? {
                        KernelNbdPoolScanOutcome::Complete(admission) => {
                            if admission.has_unavailable_device() {
                                aggregate
                                    .unavailable_sources
                                    .push(InventorySource::BlockFrontend);
                            }
                            for (cat_id, projections) in admission.device_projections() {
                                for (volume_id, device) in projections {
                                    anyhow::ensure!(
                                        serving_devices_by_cat
                                            .entry(cat_id.clone())
                                            .or_default()
                                            .insert(volume_id, device)
                                            .is_none(),
                                        "managed frontend scan projects two devices for one Volume"
                                    );
                                }
                            }
                            kernel_nbd_pool_admission = Some(admission);
                        }
                        KernelNbdPoolScanOutcome::CompleteWithResidue { admission, residue } => {
                            debug_assert!(!admission.has_unavailable_device());
                            for (cat_id, projections) in admission.device_projections() {
                                for (volume_id, device) in projections {
                                    anyhow::ensure!(
                                        serving_devices_by_cat
                                            .entry(cat_id.clone())
                                            .or_default()
                                            .insert(volume_id, device)
                                            .is_none(),
                                        "managed frontend scan projects two devices for one Volume"
                                    );
                                }
                            }
                            kernel_nbd_pool_admission = Some(admission);
                            append_residue_or_mark_incomplete(
                                &mut aggregate,
                                InventorySource::BlockFrontend,
                                residue,
                            );
                        }
                        KernelNbdPoolScanOutcome::Unavailable => {
                            aggregate
                                .unavailable_sources
                                .push(InventorySource::BlockFrontend);
                        }
                    }
                } else if self.kernel_nbd_port.is_some() {
                    // A failed process bridge has already made this scan
                    // incomplete. Kernel-NBD proof is a join with that exact
                    // same-pass admission, so touching the pool cannot restore
                    // completeness and must not replace an earlier exact VMM
                    // negative with a scanner error.
                    aggregate
                        .unavailable_sources
                        .push(InventorySource::BlockFrontend);
                }
            }
            if processes_by_cat.keys().any(|cat_id| {
                !matches!(
                    aggregate
                        .blockd_by_cat
                        .get(cat_id)
                        .filter(|by_volume| !by_volume.is_empty())
                        .map(|by_volume| by_volume.values().all(|blockd| {
                            blockd.control_state
                                == AuthorizedBlockdControlState::ExactControlOnlyEmpty
                        })),
                    Some(true)
                )
            }) {
                // A verified process is one half of a joint physical fact. If
                // the same scan did not also prove the exact empty control-only
                // engine state, keep every involved source unavailable and do
                // not let the proof reach wire projection.
                return Ok(incomplete_inventory(
                    vec![
                        InventorySource::Systemd,
                        InventorySource::Process,
                        InventorySource::ControlSocket,
                        InventorySource::DataDirectory,
                    ],
                    exact_physical_negative_cats,
                ));
            }
            for source in [
                InventorySource::Systemd,
                InventorySource::Process,
                InventorySource::ControlSocket,
            ] {
                aggregate.coverage.record(source)?;
            }
            for probe in &self.probes {
                if matches!(
                    probe.source(),
                    InventorySource::Checkpoint
                        | InventorySource::DataDirectory
                        | InventorySource::MetadataStore
                        | InventorySource::Systemd
                        | InventorySource::Process
                        | InventorySource::ControlSocket
                ) {
                    continue;
                }
                inspect_inventory_probe(probe, &context, &mut aggregate)?;
            }
        } else {
            for probe in &self.probes {
                inspect_inventory_probe(probe, &context, &mut aggregate)?;
            }
        }
        if let Some(bridge) = &self.network_bridge {
            context
                .remaining()
                .context("network inventory bridge deadline expired before inspection")?;
            match bridge.inspect_all(&aggregate.checkpoints_by_cat, &context)? {
                NetworkInventoryBridgeOutcome::Complete(admission) => {
                    networks_by_cat = admission.network_projections();
                    node_global_network_admission = Some(admission);
                }
                NetworkInventoryBridgeOutcome::CompleteWithResidue { admission, residue } => {
                    networks_by_cat = admission.network_projections();
                    node_global_network_admission = Some(admission);
                    append_residue_or_mark_incomplete(
                        &mut aggregate,
                        InventorySource::Network,
                        residue,
                    );
                }
                NetworkInventoryBridgeOutcome::Unavailable => {
                    aggregate.unavailable_sources.push(InventorySource::Network);
                }
            }
            context
                .remaining()
                .context("network inventory bridge deadline expired after inspection")?;
        }
        if !aggregate.unavailable_sources.is_empty() {
            return Ok(incomplete_inventory(
                aggregate.unavailable_sources,
                exact_physical_negative_cats,
            ));
        }

        let mut running_tail_admission = None;
        if let (Some(registry), Some(guest_ready), Some(processes), Some(networks)) = (
            self.running_admission_registry.as_ref(),
            self.guest_ready.as_ref(),
            node_global_process_admission.as_ref(),
            node_global_network_admission.as_ref(),
        ) {
            let mut tail = RunningTailScanAdmission::empty();
            for desired in &context.coordinates().desired.desired_specs {
                let Some(checkpoint_evidence) = aggregate.checkpoints_by_cat.get(&desired.cat_id)
                else {
                    continue;
                };
                if checkpoint_evidence
                    .checkpoint
                    .runtime_launch
                    .identity()
                    .is_none()
                {
                    continue;
                }
                let checkpoint = &checkpoint_evidence.checkpoint;
                validate_scanned_checkpoint(
                    desired,
                    checkpoint,
                    checkpoint_evidence.binding,
                    aggregate.blockd_by_cat.get(&desired.cat_id),
                    &self.checkpoint_directory,
                    self.blob.as_deref(),
                    context.deadline(),
                )?;
                let session = registry
                    .existing_session(&desired.cat_id)
                    .context("observe the process-owned Running admission cell")?;
                let observed_cell = session.as_ref().map(|session| session.cell().observe());
                let launch_predecessor = sealed_running_predecessor(
                    checkpoint,
                    aggregate.blockd_by_cat.get(&desired.cat_id),
                )?;
                let gate_predecessor = session
                    .as_ref()
                    .and_then(|session| session.sealed_running_desired());
                let stored_edge_allows_live =
                    match (session.as_ref(), observed_cell.as_ref(), &checkpoint.step) {
                        (
                            Some(session),
                            Some(cell),
                            ReconcileStep::CloseGate { endpoint_id, .. },
                        )
                        | (
                            Some(session),
                            Some(cell),
                            ReconcileStep::InstallGate { endpoint_id, .. },
                        ) => session
                            .checkpoint_store()
                            .endpoint_effect_edge_allows_live(endpoint_id, cell.snapshot())?,
                        _ => false,
                    };
                let retirement_mode = match (&session, &observed_cell) {
                    (Some(_), Some(cell)) => {
                        let mut mode = classify_superseded_route_retirement(
                            desired,
                            checkpoint,
                            checkpoint_evidence.binding,
                            gate_predecessor.as_ref(),
                            cell,
                        )?;
                        if mode.is_none() {
                            mode = classify_current_endpoint_route_retirement(
                                desired,
                                checkpoint,
                                checkpoint_evidence.binding,
                                gate_predecessor.as_ref(),
                                cell,
                                stored_edge_allows_live,
                            )?;
                        }
                        if mode.is_none() {
                            mode = classify_current_global_route_retirement(
                                desired,
                                checkpoint,
                                checkpoint_evidence.binding,
                                cell,
                            )?;
                        }
                        mode
                    }
                    _ => None,
                };
                if let (Some(session), Some(cell), Some(mut mode)) =
                    (session.as_ref(), observed_cell.as_ref(), retirement_mode)
                {
                    let physical = if mode == super::RouteRetirementMode::EndpointOnly {
                        let physical_desired =
                            if checkpoint_evidence.binding == DesiredCheckpointBinding::Current {
                                desired
                            } else {
                                gate_predecessor.as_ref().context(
                                "Endpoint-only route retirement lacks its sealed live-gate Desired",
                            )?
                            };
                        match validate_retained_running_scan_exact_set(
                            physical_desired,
                            checkpoint,
                            aggregate
                                .volumes_by_cat
                                .get(&desired.cat_id)
                                .map_or(&[], Vec::as_slice),
                            processes,
                            networks,
                            kernel_nbd_pool_admission.as_ref(),
                        )? {
                            Some(vmm) => match probe_exact_guest_mounted_set(
                                guest_ready.as_ref(),
                                &context,
                                physical_desired,
                                checkpoint,
                                vmm,
                            ) {
                                Ok(mounted) => Some((vmm.clone(), mounted)),
                                Err(_) => {
                                    context.check_active()?;
                                    mode = super::RouteRetirementMode::GlobalPhysicalNegative;
                                    None
                                }
                            },
                            None => {
                                mode = super::RouteRetirementMode::GlobalPhysicalNegative;
                                None
                            }
                        }
                    } else if mode == super::RouteRetirementMode::GlobalDesired
                        && matches!(
                            checkpoint.require_idle,
                            cats_api::runtime_reconciliation::RequireIdleCheckpoint::Busy {
                                gate_closed: false,
                                ..
                            }
                        )
                    {
                        let sealed_running = gate_predecessor.as_ref().context(
                            "Busy/Open route retirement lacks its sealed Running source",
                        )?;
                        let physical_is_exact =
                            match validate_retained_running_close_scan_exact_set(
                                sealed_running,
                                desired,
                                checkpoint,
                                aggregate
                                    .volumes_by_cat
                                    .get(&desired.cat_id)
                                    .map_or(&[], Vec::as_slice),
                                processes,
                                networks,
                                kernel_nbd_pool_admission.as_ref(),
                            )? {
                                Some(vmm) => match probe_exact_guest_mounted_set(
                                    guest_ready.as_ref(),
                                    &context,
                                    sealed_running,
                                    checkpoint,
                                    vmm,
                                ) {
                                    Ok(_) => true,
                                    Err(_) => {
                                        context.check_active()?;
                                        false
                                    }
                                },
                                None => false,
                            };
                        if !physical_is_exact {
                            mode = super::RouteRetirementMode::GlobalPhysicalNegative;
                        }
                        None
                    } else {
                        None
                    };
                    tail.insert_route_retirement(
                        desired,
                        checkpoint,
                        checkpoint_evidence.binding,
                        checkpoint_content_digest(checkpoint)
                            .context("digest route-retirement checkpoint")?,
                        gate_predecessor,
                        Some(launch_predecessor),
                        session.generation(),
                        cell.clone(),
                        mode,
                        physical,
                    )?;
                    continue;
                }
                if desired.target != RuntimeTarget::Running
                    || checkpoint_evidence.binding != DesiredCheckpointBinding::Current
                {
                    continue;
                }
                // This gate applies only to current Running Ready/Install
                // authority. Superseded/global-negative route retirement must
                // be classified before reaching this branch so an early
                // filesystem phase cannot suppress close/drain convergence.
                if !classify_running_tail_phase(desired, checkpoint)?.permits_physical_proof() {
                    continue;
                }
                let Some(vmm) = validate_retained_running_scan_exact_set(
                    desired,
                    checkpoint,
                    aggregate
                        .volumes_by_cat
                        .get(&desired.cat_id)
                        .map_or(&[], Vec::as_slice),
                    processes,
                    networks,
                    kernel_nbd_pool_admission.as_ref(),
                )?
                else {
                    if let (Some(session), Some(cell)) = (session.as_ref(), observed_cell.as_ref())
                    {
                        tail.insert_route_retirement(
                            desired,
                            checkpoint,
                            checkpoint_evidence.binding,
                            checkpoint_content_digest(checkpoint)
                                .context("digest physically-negative Running checkpoint")?,
                            gate_predecessor.clone(),
                            Some(launch_predecessor.clone()),
                            session.generation(),
                            cell.clone(),
                            super::RouteRetirementMode::GlobalPhysicalNegative,
                            None,
                        )?;
                    }
                    continue;
                };
                let vmm = vmm.clone();
                let guest_ready = match probe_exact_guest_mounted_set(
                    guest_ready.as_ref(),
                    &context,
                    desired,
                    checkpoint,
                    &vmm,
                ) {
                    Ok(evidence) => evidence,
                    Err(_) => {
                        // A booting Guest or an earlier Format/Mount phase is
                        // an exact closed observation. If a process-local cell
                        // nevertheless exists, its routes remain observable
                        // and a close-only sidecar owns dispatch; complete
                        // negative physical evidence can never coexist with a
                        // publicly absent but actually Active route.
                        context.check_active()?;
                        if let (Some(session), Some(cell)) =
                            (session.as_ref(), observed_cell.as_ref())
                        {
                            tail.insert_route_retirement(
                                desired,
                                checkpoint,
                                checkpoint_evidence.binding,
                                checkpoint_content_digest(checkpoint)
                                    .context("digest Guest-negative Running checkpoint")?,
                                gate_predecessor.clone(),
                                Some(launch_predecessor.clone()),
                                session.generation(),
                                cell.clone(),
                                super::RouteRetirementMode::GlobalPhysicalNegative,
                                None,
                            )?;
                        }
                        continue;
                    }
                };
                tail.insert_exact(
                    launch_predecessor,
                    desired,
                    checkpoint,
                    checkpoint_content_digest(checkpoint)
                        .context("digest Running-tail checkpoint")?,
                    vmm,
                    guest_ready,
                    observed_cell,
                )?;
            }
            if !tail.is_empty() {
                running_tail_admission = Some(tail);
            }
        }

        let key_ring = match &self.key_ring_reader {
            Some(reader) => reader.read(&context)?,
            None => RuntimeInventoryKeyRing::Unavailable,
        };
        context.check_active()?;
        let observed_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time precedes the Unix epoch")?
            .as_millis();
        let observed_at_unix_ms = u64::try_from(observed_at_unix_ms)
            .ok()
            .and_then(UnixMillis::new)
            .context("system time does not fit UnixMillis")?;
        let coverage = aggregate.coverage.finish()?;
        let inventory_epoch = context.coordinates().inventory_epoch;
        let projection = InventoryProjectionContext {
            checkpoint_directory: &self.checkpoint_directory,
            blob: self.blob.as_deref(),
            deadline: context.deadline(),
        };
        #[cfg(feature = "proposed-node-residue-reclamation")]
        let mut data_directory_reclaim_admission =
            super::DataDirectoryReclaimScanAdmission::default();
        #[cfg(feature = "proposed-node-residue-reclamation")]
        let reclaim_sources_are_closed = aggregate.residue.is_empty();
        let mut runtimes = context
            .coordinates()
            .desired
            .desired_specs
            .iter()
            .map(|desired| {
                let checkpoint = RuntimeCheckpointProjectionInput::from_parts(
                    aggregate.checkpoints_by_cat.remove(&desired.cat_id),
                    aggregate.corrupt_checkpoints_by_cat.remove(&desired.cat_id),
                )?;
                let blockds = aggregate
                    .blockd_by_cat
                    .remove(&desired.cat_id)
                    .unwrap_or_default();
                let mut runtime = runtime_from_inventory(
                    desired,
                    inventory_epoch,
                    &projection,
                    aggregate
                        .volumes_by_cat
                        .remove(&desired.cat_id)
                        .unwrap_or_default(),
                    checkpoint,
                    blockds.clone(),
                    RuntimeManagedProjection {
                        processes: processes_by_cat.remove(&desired.cat_id).unwrap_or_default(),
                        serving_devices: serving_devices_by_cat
                            .remove(&desired.cat_id)
                            .unwrap_or_default(),
                        serving_status: serving_status_by_cat
                            .remove(&desired.cat_id)
                            .unwrap_or_default(),
                        networks: networks_by_cat.remove(&desired.cat_id).unwrap_or_default(),
                    },
                )?;
                #[cfg(feature = "proposed-node-residue-reclamation")]
                if reclaim_sources_are_closed {
                    project_exact_released_data_directory(
                        desired,
                        &mut runtime,
                        &blockds,
                        &mut aggregate.residue,
                        &mut data_directory_reclaim_admission,
                    )?;
                }
                Ok(runtime)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(tail) = &running_tail_admission {
            for runtime in &mut runtimes {
                tail.project_runtime(runtime)?;
            }
        }
        canonicalize_residue(&mut aggregate.residue)?;
        anyhow::ensure!(
            aggregate.volumes_by_cat.is_empty()
                && aggregate.checkpoints_by_cat.is_empty()
                && aggregate.corrupt_checkpoints_by_cat.is_empty()
                && aggregate.blockd_by_cat.is_empty()
                && processes_by_cat.is_empty()
                && serving_devices_by_cat.is_empty()
                && serving_status_by_cat.is_empty()
                && networks_by_cat.is_empty(),
            "inventory named a Cat outside Desired"
        );

        let inventory = CompleteRuntimeInventory::from_validated_coverage(
            coverage,
            observed_at_unix_ms,
            key_ring,
            runtimes,
            aggregate.residue,
            aggregate.residue_sources,
        )
        .with_node_global_process_admission(node_global_process_admission)
        .with_node_global_network_admission(node_global_network_admission)
        .with_kernel_nbd_pool_admission(kernel_nbd_pool_admission)
        .with_running_tail_admission(running_tail_admission);
        #[cfg(feature = "proposed-node-residue-reclamation")]
        let inventory = inventory.with_data_directory_reclaim_admission(
            (!data_directory_reclaim_admission.is_empty())
                .then_some(data_directory_reclaim_admission),
        );
        Ok(RuntimeInventoryScanOutcome::Complete(Box::new(inventory)))
    }
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn project_exact_released_data_directory(
    desired: &DesiredRuntimeSpec,
    runtime: &mut ObservedRuntimeStatus,
    blockds: &BTreeMap<Id, AuthorizedBlockdInventoryEvidence>,
    residue: &mut Vec<NodeResidue>,
    admission: &mut super::DataDirectoryReclaimScanAdmission,
) -> anyhow::Result<()> {
    if !matches!(desired.target, RuntimeTarget::Cold | RuntimeTarget::Deleted) {
        return Ok(());
    }
    let ReconcileStep::CleanupRelease { cleanup } = &runtime.step else {
        return Ok(());
    };
    let (
        cats_api::runtime_reconciliation::CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return Ok(());
    };
    if !runtime.processes.is_empty()
        || !runtime.mounts.is_empty()
        || !runtime.networks.is_empty()
        || !matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        || !matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
    {
        return Ok(());
    }
    let Some(blockd) = blockds.get(volume_id) else {
        return Ok(());
    };
    let current_intent = desired
        .volumes
        .iter()
        .find(|intent| intent.volume_id == *volume_id);
    let detached_intent = current_intent.is_none().then(|| {
        blockd.checkpoint.desired.volumes.iter().find(|intent| {
            intent.volume_id == *volume_id
                && intent.disk_kind == cats_api::runtime_reconciliation::DiskKind::Persistent
                && intent.attachment_id == *attachment_id
        })
    });
    let Some(intent) = current_intent.or_else(|| detached_intent.flatten()) else {
        return Ok(());
    };
    let detached_membership_cleanup = current_intent.is_none()
        && matches!(
            replay.disposition,
            cats_api::runtime_reconciliation::VolumeDisposition::DetachRetained
        )
        && matches!(
            &runtime.checkpoint,
            CheckpointEvidence::Valid {
                desired_revision,
                spec_digest,
                ..
            } if desired_revision < &desired.desired_revision
                && spec_digest != &desired.spec_digest
        )
        && runtime.volumes.len() == desired.volumes.len().saturating_add(1)
        && !desired
            .volumes
            .iter()
            .any(|candidate| candidate.volume_id == *volume_id);
    if current_intent.is_none() && !detached_membership_cleanup {
        return Ok(());
    }
    let Some(volume) = runtime
        .volumes
        .iter_mut()
        .find(|volume| volume.volume_id == *volume_id)
    else {
        return Ok(());
    };
    let VolumeAuthorityEvidence::Unowned {
        attachment_epoch: released_epoch,
        head: release_head,
    } = &volume.authority
    else {
        return Ok(());
    };
    let [lineage] = volume.local_lineages.as_slice() else {
        return Ok(());
    };
    let attachment = &blockd.checkpoint.attachment;
    if volume.devices.is_empty()
        && attachment_id == &attachment.identity.attachment_id
        && *attachment_epoch == attachment.identity.attachment_epoch
        && attachment_epoch
            .get()
            .checked_add(1)
            .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
            == Some(*released_epoch)
        && release_head.generation == replay.generation
        && lineage.attachment_id == *attachment_id
        && lineage.attachment_epoch == *attachment_epoch
        && lineage.data_directory == blockd.data_directory
        && lineage.local_durable_generation == lineage.remote_durable_generation
        && lineage.pending_pack_count.get() == 0
        && lineage.fenced
        && lineage.state == LocalLineageState::Released
    {
        let exact = ResidueDataDirectoryLineage {
            workspace_id: desired.workspace_id.clone(),
            cat_id: desired.cat_id.clone(),
            disk_id: intent.disk_id.clone(),
            disk_kind: intent.disk_kind,
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: *attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            node_id: attachment.identity.node_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            placement_epoch: attachment.identity.placement_epoch,
            acquisition: attachment.acquire.clone(),
            acquisition_digest: residue_acquisition_digest(&attachment.acquire)?,
            local_durable_generation: lineage.local_durable_generation,
            remote_durable_generation: lineage.remote_durable_generation,
            remote_head: release_head.clone(),
            pending_pack_count: lineage.pending_pack_count,
            fenced: true,
        };
        let observed = NodeResidue::DataDirectory {
            cat_id_hint: Some(desired.cat_id.clone()),
            disk_id_hint: Some(intent.disk_id.clone()),
            volume_id_hint: Some(volume_id.clone()),
            data_directory: blockd.data_directory.clone(),
            allocated_bytes: blockd.allocated_bytes,
            retention_reason: DataDirectoryRetentionReason::ExactReclaimPending,
            ownership_token: cats_api::runtime_reconciliation::OwnershipTokenEvidence::Missing,
            lineage: ResidueLineageEvidence::Readable {
                lineage: Box::new(exact),
            },
        };
        admission.insert(
            desired.cat_id.clone(),
            volume_id.clone(),
            observed.clone(),
            Arc::clone(&blockd.reclaim),
        )?;
        residue.push(observed);
        volume.local_lineages.clear();
    }
    Ok(())
}

fn canonicalize_residue(residue: &mut [NodeResidue]) -> anyhow::Result<()> {
    sort_node_residue_canonically(residue);
    anyhow::ensure!(
        residue.windows(2).all(|pair| pair[0] != pair[1]),
        "inventory duplicated one Node residue"
    );
    Ok(())
}

pub(super) fn vmm_process_expectations(
    checkpoint_directory: &std::path::Path,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
) -> anyhow::Result<BTreeMap<Id, super::vmm_process::VmmProcessExpectation>> {
    // A superseded retained Running launch stays an owned process until its
    // shared AdmissionCell has been closed and retirement can proceed.
    vmm_process_expectations_inner(checkpoint_directory, checkpoints_by_cat, true)
}

#[cfg(target_os = "linux")]
pub(super) fn recovery_vmm_process_expectations(
    checkpoint_directory: &std::path::Path,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
) -> anyhow::Result<BTreeMap<Id, super::vmm_process::VmmProcessExpectation>> {
    vmm_process_expectations_inner(checkpoint_directory, checkpoints_by_cat, true)
}

fn vmm_process_expectations_inner(
    checkpoint_directory: &std::path::Path,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    include_superseded: bool,
) -> anyhow::Result<BTreeMap<Id, super::vmm_process::VmmProcessExpectation>> {
    let mut expected = BTreeMap::new();
    for (cat_id, evidence) in checkpoints_by_cat {
        if (!include_superseded && evidence.binding != DesiredCheckpointBinding::Current)
            || evidence.checkpoint.runtime_launch.identity().is_none()
        {
            continue;
        }
        let checkpoint_path = HostPath::new(
            runtime_checkpoint_path(checkpoint_directory, cat_id)
                .to_string_lossy()
                .into_owned(),
        )
        .context("retained-launch checkpoint path is not canonical")?;
        let expectation = super::vmm_process::VmmProcessExpectation::from_checkpoint(
            evidence.checkpoint.clone(),
        )?
        .with_checkpoint_path(checkpoint_path)?;
        anyhow::ensure!(
            expected.insert(cat_id.clone(), expectation).is_none(),
            "VMM process expectation duplicated one Cat"
        );
    }
    Ok(expected)
}

pub(super) fn root_process_expectations(
    context: &RuntimeInventoryScanContext,
    checkpoint_directory: &std::path::Path,
    blob: Option<&dyn BlobStore>,
    executable_path: &HostPath,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
) -> anyhow::Result<BTreeMap<Id, RootProvisionProcessExpectation>> {
    let projection = InventoryProjectionContext {
        checkpoint_directory,
        blob,
        deadline: context.deadline(),
    };
    root_process_expectations_inner(
        context,
        &projection,
        executable_path,
        checkpoints_by_cat,
        blockd_by_cat,
        volumes_by_cat,
        true,
    )
}

#[cfg(target_os = "linux")]
pub(super) fn recovery_root_process_expectations(
    context: &RuntimeInventoryScanContext,
    checkpoint_directory: &std::path::Path,
    blob: Option<&dyn BlobStore>,
    executable_path: &HostPath,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
) -> anyhow::Result<BTreeMap<Id, RootProvisionProcessExpectation>> {
    let projection = InventoryProjectionContext {
        checkpoint_directory,
        blob,
        deadline: context.deadline(),
    };
    root_process_expectations_inner(
        context,
        &projection,
        executable_path,
        checkpoints_by_cat,
        blockd_by_cat,
        volumes_by_cat,
        true,
    )
}

fn root_process_expectations_inner(
    context: &RuntimeInventoryScanContext,
    projection: &InventoryProjectionContext<'_>,
    executable_path: &HostPath,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
    include_superseded: bool,
) -> anyhow::Result<BTreeMap<Id, RootProvisionProcessExpectation>> {
    let mut expected = BTreeMap::new();
    for desired in &context.coordinates().desired.desired_specs {
        let Some(checkpoint) = checkpoints_by_cat.get(&desired.cat_id) else {
            continue;
        };
        if !include_superseded && checkpoint.binding != DesiredCheckpointBinding::Current {
            continue;
        }
        let needs_root_process_bridge = match &checkpoint.checkpoint.step {
            ReconcileStep::ProvisionRootImage { .. } => true,
            ReconcileStep::PrepareDevice { devices } => devices.iter().any(|device| matches!(
                device.serving_authority.as_ref(),
                cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
            )),
            ReconcileStep::PrepareNetwork { .. } => true,
            _ => false,
        };
        if !needs_root_process_bridge {
            continue;
        }
        let blockds = blockd_by_cat
            .get(&desired.cat_id)
            .context("root-provision checkpoint lacks AuthorizedBlockd lineage")?;
        let mut roots = blockds.values().filter(|blockd| {
            blockd.checkpoint.volume.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root
        });
        let blockd = roots
            .next()
            .context("root-provision checkpoint lacks Root AuthorizedBlockd lineage")?;
        anyhow::ensure!(
            roots.next().is_none(),
            "root-provision checkpoint has duplicate Root AuthorizedBlockd lineage"
        );
        anyhow::ensure!(
            blockd.binding == checkpoint.binding,
            "root-provision checkpoint and AuthorizedBlockd binding disagree"
        );
        validate_scanned_checkpoint(
            desired,
            &checkpoint.checkpoint,
            checkpoint.binding,
            Some(blockds),
            projection.checkpoint_directory,
            projection.blob,
            projection.deadline,
        )?;
        if let Some(retained) = &blockd.retained_root_process {
            anyhow::ensure!(
                matches!(
                    checkpoint.checkpoint.step,
                    ReconcileStep::PrepareDevice { .. } | ReconcileStep::PrepareNetwork { .. }
                ),
                "retained Root process projection is outside a prepared-device phase"
            );
            let prepared_checkpoint = prepare_device_checkpoint_view(&checkpoint.checkpoint)?;
            let expectation_desired = if checkpoint.binding == DesiredCheckpointBinding::Current {
                desired
            } else {
                &blockd.checkpoint.desired
            };
            let expectation = RootProvisionProcessExpectation::from_retained_prepare_device(
                &prepared_checkpoint,
                expectation_desired,
                retained,
            )?;
            anyhow::ensure!(
                blockd.target_control_launch.as_ref() == Some(&retained.target_control_launch),
                "retained Root process changed its target-control launch identity"
            );
            anyhow::ensure!(
                expected
                    .insert(desired.cat_id.clone(), expectation)
                    .is_none(),
                "root-provision process expectation duplicated one Cat"
            );
            continue;
        }
        if !matches!(
            checkpoint.checkpoint.step,
            ReconcileStep::ProvisionRootImage { .. }
        ) {
            continue;
        }
        let attachment = blockd.checkpoint.attachment.clone();
        let volume = volumes_by_cat
            .get(&desired.cat_id)
            .and_then(|volumes| {
                volumes
                    .iter()
                    .find(|volume| volume.record.volume_id == attachment.identity.volume_id)
            })
            .context("root-provision process lacks its raw authority VolumeRecord")?;
        let mut expectation = RootProvisionProcessExpectation::from_checkpoint(
            &checkpoint.checkpoint,
            RootProvisionAuthoritySnapshot {
                attachment,
                volume: &volume.record,
            },
            executable_path.clone(),
        )?;
        if let Some(target) = &blockd.target_control_launch {
            expectation = expectation.with_target_control_launch(target.clone())?;
        }
        anyhow::ensure!(
            expected
                .insert(desired.cat_id.clone(), expectation)
                .is_none(),
            "root-provision process expectation duplicated one Cat"
        );
    }
    Ok(expected)
}

#[cfg(test)]
pub(super) fn serving_process_expectations(
    context: &RuntimeInventoryScanContext,
    bridge: &dyn RootProcessInventoryBridge,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
) -> anyhow::Result<
    BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdExpectation>,
> {
    serving_process_expectations_inner(
        context,
        bridge,
        checkpoints_by_cat,
        blockd_by_cat,
        volumes_by_cat,
        true,
        None,
    )
}

fn serving_process_expectations_with_registry(
    context: &RuntimeInventoryScanContext,
    bridge: &dyn RootProcessInventoryBridge,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
    registry: Option<&AdmissionCellRegistry>,
) -> anyhow::Result<
    BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdExpectation>,
> {
    serving_process_expectations_inner(
        context,
        bridge,
        checkpoints_by_cat,
        blockd_by_cat,
        volumes_by_cat,
        true,
        registry,
    )
}

#[cfg(target_os = "linux")]
pub(super) fn recovery_serving_process_expectations(
    context: &RuntimeInventoryScanContext,
    bridge: &dyn RootProcessInventoryBridge,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
) -> anyhow::Result<
    BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdExpectation>,
> {
    serving_process_expectations_inner(
        context,
        bridge,
        checkpoints_by_cat,
        blockd_by_cat,
        volumes_by_cat,
        true,
        None,
    )
}

fn serving_process_expectations_inner(
    context: &RuntimeInventoryScanContext,
    bridge: &dyn RootProcessInventoryBridge,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
    include_superseded: bool,
    registry: Option<&AdmissionCellRegistry>,
) -> anyhow::Result<
    BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdExpectation>,
> {
    let mut expected = BTreeMap::new();
    for desired in &context.coordinates().desired.desired_specs {
        let Some(checkpoint) = checkpoints_by_cat.get(&desired.cat_id) else {
            continue;
        };
        if (!include_superseded && checkpoint.binding != DesiredCheckpointBinding::Current)
            || !(matches!(
                checkpoint.checkpoint.step,
                ReconcileStep::PrepareDevice { .. } | ReconcileStep::PrepareNetwork { .. }
            ) || checkpoint.checkpoint.runtime_launch.identity().is_some())
        {
            continue;
        }
        let devices = prepared_device_inputs(&checkpoint.checkpoint)?;
        let blockds = blockd_by_cat
            .get(&desired.cat_id)
            .context("prepared-device checkpoint lacks AuthorizedBlockd inventory")?;
        anyhow::ensure!(
            blockds.len() == devices.len(),
            "prepared-device checkpoint and AuthorizedBlockd inventory differ in exact size"
        );
        let physical_desired = blockds
            .values()
            .next()
            .context("prepared-device checkpoint lacks immutable physical Desired")?
            .checkpoint
            .desired
            .clone();
        let current_running_gate = checkpoint.binding == DesiredCheckpointBinding::Current
            && desired.target == RuntimeTarget::Running
            && !matches!(
                checkpoint.checkpoint.step,
                ReconcileStep::CloseAdmission { .. }
            );
        let session = registry
            .map(|registry| registry.existing_session(&desired.cat_id))
            .transpose()?
            .flatten();
        let gate_desired = if current_running_gate {
            desired.clone()
        } else if let Some(session) = session {
            let sealed = session
                .sealed_running_desired()
                .context("retained route process expectation lacks its sealed live-gate Desired")?;
            if checkpoint.binding == DesiredCheckpointBinding::Superseded {
                anyhow::ensure!(
                    checkpoint.checkpoint.desired_revision == sealed.desired_revision
                        && checkpoint.checkpoint.spec_digest == sealed.spec_digest
                        && checkpoint.checkpoint.node_id == sealed.placement.node_id
                        && checkpoint.checkpoint.placement_epoch
                            == sealed.placement.placement_epoch,
                    "superseded process expectation does not bind its sealed live-gate Desired"
                );
            } else {
                anyhow::ensure!(
                    matches!(
                        checkpoint.checkpoint.step,
                        ReconcileStep::CloseAdmission { .. }
                    ),
                    "current process expectation differs from its sealed gate outside CloseAdmission"
                );
            }
            sealed
        } else {
            // A fresh Agent owns no prior process-local admission. Immutable
            // launch provenance can identify the old process for cleanup but
            // can never recreate process-local route admission.
            physical_desired.clone()
        };
        super::authorized_blockd::validate_running_physical_desired_successor(
            &physical_desired,
            &gate_desired,
        )?;
        let expected_blockd_binding = if physical_desired == *desired {
            DesiredCheckpointBinding::Current
        } else {
            DesiredCheckpointBinding::Superseded
        };
        anyhow::ensure!(
            blockds.values().all(|blockd| {
                blockd.checkpoint.desired == physical_desired
                    && blockd.binding == expected_blockd_binding
            }),
            "prepared-device AuthorizedBlockd set does not share one exact physical Desired"
        );
        for prepared in devices {
            let blockd = blockds
                .get(&prepared.volume_id)
                .context("prepared device lacks its AuthorizedBlockd lineage")?;
            let authority = volumes_by_cat
                .get(&desired.cat_id)
                .and_then(|volumes| {
                    volumes
                        .iter()
                        .find(|volume| volume.record.volume_id == prepared.volume_id)
                })
                .context("serving blockd process lacks its raw authority VolumeRecord")?;
            let expectation = bridge.serving_expectation(
                &checkpoint.checkpoint,
                &physical_desired,
                &gate_desired,
                &prepared,
                blockd,
                &authority.record,
            )?;
            let key = ManagedServingKey::new(desired.cat_id.clone(), prepared.volume_id.clone());
            anyhow::ensure!(
                expected.insert(key, expectation).is_none(),
                "serving blockd process expectation duplicated one Cat/Volume"
            );
        }
    }
    Ok(expected)
}

struct InventoryProjectionContext<'a> {
    checkpoint_directory: &'a std::path::Path,
    blob: Option<&'a dyn BlobStore>,
    deadline: std::time::Instant,
}

struct RuntimeManagedProjection {
    processes: Vec<ProcessEvidence>,
    serving_devices: BTreeMap<Id, ObservedDevice>,
    serving_status: BTreeMap<Id, cats_api::blockd::DurabilityStatus>,
    networks: Vec<cats_api::runtime_reconciliation::ObservedNetwork>,
}

enum RuntimeCheckpointProjectionInput {
    Missing,
    Valid(Box<RuntimeCheckpointInventoryEvidence>),
    Corrupt(Sha256Digest),
}

impl RuntimeCheckpointProjectionInput {
    fn from_parts(
        checkpoint: Option<RuntimeCheckpointInventoryEvidence>,
        corrupt_digest: Option<Sha256Digest>,
    ) -> anyhow::Result<Self> {
        match (checkpoint, corrupt_digest) {
            (None, None) => Ok(Self::Missing),
            (Some(checkpoint), None) => Ok(Self::Valid(Box::new(checkpoint))),
            (None, Some(digest)) => Ok(Self::Corrupt(digest)),
            (Some(_), Some(_)) => anyhow::bail!("checkpoint inventory duplicated one Cat"),
        }
    }
}

fn runtime_from_inventory(
    desired: &DesiredRuntimeSpec,
    inventory_epoch: cats_api::runtime_reconciliation::Epoch,
    projection: &InventoryProjectionContext<'_>,
    mut volume_evidence: Vec<AuthorityVolumeInventoryEvidence>,
    checkpoint_input: RuntimeCheckpointProjectionInput,
    blockds: BTreeMap<Id, AuthorizedBlockdInventoryEvidence>,
    mut managed: RuntimeManagedProjection,
) -> anyhow::Result<ObservedRuntimeStatus> {
    let (checkpoint, corrupt_checkpoint_digest) = match checkpoint_input {
        RuntimeCheckpointProjectionInput::Missing => (None, None),
        RuntimeCheckpointProjectionInput::Valid(checkpoint) => (Some(*checkpoint), None),
        RuntimeCheckpointProjectionInput::Corrupt(digest) => (None, Some(digest)),
    };
    let corrupt_checkpoint_present = corrupt_checkpoint_digest.is_some();
    let checkpoint_path = runtime_checkpoint_path(projection.checkpoint_directory, &desired.cat_id);
    let checkpoint_path = HostPath::new(
        checkpoint_path
            .to_str()
            .context("checkpoint path is not UTF-8")?
            .to_owned(),
    )
    .ok_or_else(|| anyhow::anyhow!("checkpoint path is not a valid HostPath"))?;

    for blockd in blockds.values() {
        if checkpoint.is_none() {
            anyhow::ensure!(
                corrupt_checkpoint_present
                    && blockd.binding == DesiredCheckpointBinding::Current
                    && blockd.checkpoint.desired == *desired,
                "local blockd lineage without a valid Runtime checkpoint is not exact current-Cat evidence"
            );
            let attachment = &blockd.checkpoint.attachment;
            let volume_evidence = volume_evidence
                .iter_mut()
                .find(|volume| volume.observed.volume_id == attachment.identity.volume_id)
                .context("authorized blockd lineage lacks its authority Volume")?;
            validate_authorized_serving_record(&volume_evidence.record, attachment, None)
                .context("corrupt-checkpoint Cat has non-exact local blockd lineage")?;
            let volume = &mut volume_evidence.observed;
            anyhow::ensure!(
                matches!(
                    &volume.authority,
                    VolumeAuthorityEvidence::Owned {
                        attachment_id,
                        attachment_epoch,
                        head,
                    } if attachment_id == &attachment.identity.attachment_id
                        && *attachment_epoch == attachment.identity.attachment_epoch
                        && head == &attachment.head
                ) && volume.local_lineages.is_empty()
                    && managed
                        .serving_status
                        .remove(&attachment.identity.volume_id)
                        .is_none(),
                "corrupt-checkpoint Cat cannot attribute a live or conflicting blockd lineage"
            );
            volume.local_lineages.push(LocalVolumeLineage {
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                acquire_origin: attachment.identity.acquire_origin.clone(),
                node_id: attachment.identity.node_id.clone(),
                placement_epoch: attachment.identity.placement_epoch,
                local_durable_generation: attachment.head.generation,
                remote_durable_generation: attachment.head.generation,
                data_directory: blockd.data_directory.clone(),
                pending_pack_count: WireU64::new(0).expect("zero fits WireU64"),
                fenced: false,
                state: LocalLineageState::Active,
            });
            continue;
        }
        anyhow::ensure!(
            checkpoint.is_some(),
            "authorized blockd lineage lacks its Runtime checkpoint"
        );
        let attachment = &blockd.checkpoint.attachment;
        let volume_evidence = volume_evidence
            .iter_mut()
            .find(|volume| volume.observed.volume_id == attachment.identity.volume_id)
            .context("authorized blockd lineage lacks its authority Volume")?;
        let volume = &mut volume_evidence.observed;
        let authority_record = &volume_evidence.record;
        let checkpoint_binding = checkpoint.as_ref().expect("presence checked above").binding;
        let runtime_checkpoint = &checkpoint
            .as_ref()
            .expect("presence checked above")
            .checkpoint;
        if matches!(
            runtime_checkpoint.step,
            ReconcileStep::AcquireVolume { .. } | ReconcileStep::ProvisionRootImage { .. }
        ) && runtime_checkpoint
            .volumes
            .iter()
            .find(|volume| volume.volume_id == attachment.identity.volume_id)
            .is_some_and(|volume| !volume.local_lineages.is_empty())
        {
            anyhow::ensure!(
                checkpoint_prepared_volume_matches_blockd(runtime_checkpoint, blockd),
                "checkpoint prepared Volume conflicts with its actual AuthorizedBlockd artifact"
            );
        }
        let historical_takeover_r0_is_closed =
            takeover_historical_r0_is_closed(runtime_checkpoint, attachment, authority_record);
        let authoritative_head_is_adoptable = match (&runtime_checkpoint.step, &volume.authority) {
            (
                ReconcileStep::ProvisionRootImage {
                    volume_id,
                    expected_blank_head,
                    expected_provisioned_head,
                    ..
                },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) if volume_id == &volume.volume_id => {
                head == expected_blank_head || head == expected_provisioned_head
            }
            (
                ReconcileStep::CleanupRelease { cleanup },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) if matches!(
                &cleanup.target,
                cats_api::runtime_reconciliation::CleanupTarget::Volume { volume_id, .. }
                    if volume_id == &volume.volume_id
            ) =>
            {
                cleanup
                    .volume_release
                    .as_ref()
                    .is_some_and(|release| release.generation == head.generation)
            }
            // The serving writer under this same grant may already have
            // published past the checkpointed head; a later durable write
            // advances it, while a same-generation tuple must stay byte-exact.
            (
                ReconcileStep::PrepareDevice { devices },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) => devices
                .iter()
                .find(|device| device.volume_id == volume.volume_id)
                .is_some_and(|device| remote_head_is_same_or_later(head, &device.expected_head)),
            (
                ReconcileStep::PrepareNetwork { devices, .. },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) => devices
                .iter()
                .find(|device| device.volume_id == volume.volume_id)
                .is_some_and(|device| remote_head_is_same_or_later(head, &device.expected_head)),
            (ReconcileStep::Quarantined, VolumeAuthorityEvidence::Owned { head, .. }) => {
                runtime_checkpoint.volumes.iter().any(|checkpoint_volume| {
                    checkpoint_volume.volume_id == volume.volume_id
                        && matches!(
                                &checkpoint_volume.authority,
                                VolumeAuthorityEvidence::Owned {
                                    head: checkpoint_head,
                                    ..
                                } if checkpoint_head == head
                        )
                })
            }
            (_, VolumeAuthorityEvidence::Owned { head, .. })
                if runtime_checkpoint.runtime_launch.identity().is_some() =>
            {
                runtime_checkpoint
                    .runtime_launch
                    .identity()
                    .and_then(|launch| {
                        launch
                            .devices
                            .iter()
                            .find(|device| device.volume_id == volume.volume_id)
                    })
                    .is_some_and(|device| {
                        // Root provisioning deliberately leaves the immutable
                        // acquire artifact at its blank head.  The retained
                        // launch vector is the first authority that binds the
                        // provisioned Root head and every Persistent head. A
                        // later durable write may advance that head, while a
                        // same-generation tuple must remain byte-exact.
                        launched_head_chain_is_monotonic(
                            &attachment.head,
                            &device.expected_head,
                            head,
                        )
                    })
            }
            (
                ReconcileStep::AcquireVolume {
                    request:
                        cats_api::runtime_reconciliation::VolumeAcquireRequest::Takeover {
                            authorization_id,
                        },
                },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) if matches!(
                &attachment.acquire,
                AuthorizedServingAcquire::Takeover { authorization, .. }
                    if &authorization.authorization_id == authorization_id
            ) =>
            {
                // A consumed Takeover can be recovered after its immutable R0
                // publication was lost even when the same fenced owner has
                // already renewed or advanced its head.  This exception is
                // scoped to the checkpoint's exact current Takeover target.
                // Previously prepared siblings and Normal artifacts remain
                // byte-exact, so a stale Acquire checkpoint cannot adopt an
                // unexplained authority advance.
                remote_head_is_same_or_later(head, &attachment.head)
            }
            (_, VolumeAuthorityEvidence::Owned { head, .. }) => head == &attachment.head,
            (
                ReconcileStep::CleanupRelease { cleanup },
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch,
                    head,
                },
            ) => {
                cleanup_release_matches_released_authority(
                    cleanup,
                    attachment,
                    *attachment_epoch,
                    head,
                ) || cold_membership_cleanup_matches_released_attachment(
                    desired,
                    runtime_checkpoint,
                    attachment,
                    *attachment_epoch,
                    head,
                )
            }
            (
                ReconcileStep::Stable {
                    state: StableState::Cold,
                },
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch,
                    head,
                },
            ) => stable_cold_checkpoint_matches_released_attachment(
                runtime_checkpoint,
                attachment,
                *attachment_epoch,
                head,
            ),
            (ReconcileStep::Quarantined, VolumeAuthorityEvidence::Unowned { .. }) => true,
            _ => false,
        };
        let retained_running_physical_launch =
            runtime_checkpoint.runtime_launch.identity().is_some()
                && super::authorized_blockd::validate_running_physical_desired_successor(
                    &blockd.checkpoint.desired,
                    desired,
                )
                .is_ok();
        let mixed_binding_is_closed = checkpoint_binding == DesiredCheckpointBinding::Current
            && blockd.binding == DesiredCheckpointBinding::Superseded
            && (current_checkpoint_adopts_blockd(runtime_checkpoint, attachment)
                || retained_running_physical_launch);
        anyhow::ensure!(
            blockd.binding == checkpoint_binding || mixed_binding_is_closed,
            "Runtime and authorized blockd checkpoint bindings disagree"
        );
        let current_attachment_is_exact = authority_owner_or_exact_release_matches(
            &volume.authority,
            desired,
            runtime_checkpoint,
            attachment,
        ) && authority_record_matches_local_attachment(
            authority_record,
            desired,
            runtime_checkpoint,
            attachment,
        ) && authoritative_head_is_adoptable;
        anyhow::ensure!(
            volume.volume_id == attachment.identity.volume_id
                && (current_attachment_is_exact || historical_takeover_r0_is_closed)
                && volume.local_lineages.is_empty(),
            "authorized blockd lineage conflicts with Volume authority"
        );
        let released = matches!(volume.authority, VolumeAuthorityEvidence::Unowned { .. });
        let closed_lineage = released || historical_takeover_r0_is_closed;
        let authority_generation = match &volume.authority {
            VolumeAuthorityEvidence::Owned { head, .. }
            | VolumeAuthorityEvidence::Unowned { head, .. } => head.generation,
            _ => unreachable!("owned or exact released authority was checked above"),
        };
        let status = managed
            .serving_status
            .remove(&attachment.identity.volume_id);
        anyhow::ensure!(
            !closed_lineage || status.is_none(),
            "closed authorized lineage still has an exact serving process"
        );
        let (local_generation, remote_generation, pending_pack_count, fenced) = match status {
            Some(status) => {
                let local = u64::try_from(status.local_durable_generation)
                    .ok()
                    .and_then(cats_api::runtime_reconciliation::Generation::new)
                    .context("serving local generation is outside the wire range")?;
                let remote = u64::try_from(status.remote_durable_generation)
                    .ok()
                    .and_then(cats_api::runtime_reconciliation::Generation::new)
                    .context("serving remote generation is outside the wire range")?;
                anyhow::ensure!(
                    remote == authority_generation && local >= remote && !status.fenced,
                    "serving durability watermarks conflict with current Volume authority"
                );
                (
                    local,
                    remote,
                    WireU64::new(
                        u64::try_from(status.unpublished_generations)
                            .context("serving pending pack count exceeds WireU64")?,
                    )
                    .context("serving pending pack count exceeds WireU64")?,
                    false,
                )
            }
            None => (
                if historical_takeover_r0_is_closed {
                    attachment.head.generation
                } else {
                    authority_generation
                },
                if historical_takeover_r0_is_closed {
                    attachment.head.generation
                } else {
                    authority_generation
                },
                WireU64::new(0).expect("zero fits WireU64"),
                closed_lineage,
            ),
        };
        volume.local_lineages.push(LocalVolumeLineage {
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            node_id: attachment.identity.node_id.clone(),
            placement_epoch: attachment.identity.placement_epoch,
            // A live serving proof contributes its actual blockd durability
            // watermarks. Immutable pre-serving lineage remains closed at the
            // independently loaded metadata head.
            local_durable_generation: local_generation,
            remote_durable_generation: remote_generation,
            data_directory: blockd.data_directory.clone(),
            pending_pack_count,
            fenced,
            state: if closed_lineage {
                LocalLineageState::Released
            } else {
                LocalLineageState::Active
            },
        });
    }
    anyhow::ensure!(
        managed.serving_status.is_empty(),
        "exact serving status lacks its AuthorizedBlockd lineage"
    );

    let mut volumes: Vec<ObservedVolume> = volume_evidence
        .into_iter()
        .map(|evidence| evidence.observed)
        .collect();
    for (volume_id, device) in managed.serving_devices {
        let volume = volumes
            .iter_mut()
            .find(|volume| volume.volume_id == volume_id)
            .context("serving vhost device lacks its observed Volume")?;
        anyhow::ensure!(
            volume.devices.is_empty(),
            "serving vhost device conflicts with another frontend projection"
        );
        volume.devices.push(device);
    }
    let unsupported_superseded = checkpoint.as_ref().is_some_and(|evidence| {
        evidence.binding == DesiredCheckpointBinding::Superseded
            && !superseded_checkpoint_has_supported_replan(desired, &evidence.checkpoint, &volumes)
            && !cold_membership_rebind_is_supported(desired, &evidence.checkpoint, &volumes)
            && !cold_membership_detach_cleanup_is_supported(desired, &evidence.checkpoint, &volumes)
    });
    let stable_cold_checkpoint = checkpoint.as_ref().is_some_and(|evidence| {
        matches!(
            evidence.checkpoint.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        )
    });
    let current_cold_postcondition_exact = checkpoint.as_ref().is_some_and(|evidence| {
        evidence.binding == DesiredCheckpointBinding::Current
            && current_cold_checkpoint_postcondition_is_exact(
                desired,
                &evidence.checkpoint,
                &volumes,
            )
            && managed.processes.is_empty()
            && managed.networks.is_empty()
    });
    let current_cold_postcondition_mismatch = checkpoint.as_ref().is_some_and(|evidence| {
        evidence.binding == DesiredCheckpointBinding::Current
            && matches!(
                evidence.checkpoint.step,
                ReconcileStep::Stable {
                    state: StableState::Cold
                }
            )
            && !current_cold_postcondition_exact
    });
    let definite_release_rejected = checkpoint
        .as_ref()
        .is_some_and(|evidence| evidence.definite_release_rejected);
    let closed_takeover_history = !stable_cold_checkpoint
        && volumes.iter().any(|volume| {
            volume.local_lineages.iter().any(|lineage| {
                lineage.state == LocalLineageState::Released
                    && matches!(
                        lineage.acquire_origin,
                        cats_api::runtime_reconciliation::AcquireOrigin::Takeover { .. }
                    )
            })
        });
    let (step, checkpoint_evidence, runtime_incarnation, stable_state, lifecycle_admission) =
        match checkpoint {
            Some(inventory_checkpoint) => {
                let checkpoint_binding = inventory_checkpoint.binding;
                let checkpoint = inventory_checkpoint.checkpoint;
                validate_scanned_checkpoint(
                    desired,
                    &checkpoint,
                    inventory_checkpoint.binding,
                    (!blockds.is_empty()).then_some(&blockds),
                    projection.checkpoint_directory,
                    projection.blob,
                    projection.deadline,
                )?;
                let evidence = CheckpointEvidence::Valid {
                    checkpoint_path,
                    content_digest: checkpoint_content_digest(&checkpoint)
                        .context("digest scanned Runtime checkpoint")?,
                    version: checkpoint.version,
                    cat_id: checkpoint.cat_id.clone(),
                    node_id: checkpoint.node_id.clone(),
                    desired_revision: checkpoint.desired_revision,
                    spec_digest: checkpoint.spec_digest.clone(),
                    placement_epoch: checkpoint.placement_epoch,
                    runtime_incarnation: checkpoint.runtime_incarnation.clone(),
                    runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
                    stable_state: checkpoint.stable_state,
                    step: Box::new(checkpoint.step.clone()),
                    require_idle: Box::new(checkpoint.require_idle.clone()),
                    updated_at_unix_ms: checkpoint.updated_at_unix_ms,
                };
                let projected_stable_state = if matches!(
                    &checkpoint.step,
                    ReconcileStep::Stable {
                        state: StableState::Cold
                    }
                ) {
                    current_cold_postcondition_exact.then_some(StableState::Cold)
                } else {
                    checkpoint.stable_state
                };
                (
                    checkpoint.step,
                    evidence,
                    checkpoint.runtime_incarnation,
                    projected_stable_state,
                    if checkpoint_binding == DesiredCheckpointBinding::Superseded {
                        LifecycleAdmission::Closed
                    } else {
                        checkpoint.lifecycle_admission
                    },
                )
            }
            None if corrupt_checkpoint_digest.is_some() => (
                ReconcileStep::InspectInventory { inventory_epoch },
                CheckpointEvidence::Corrupt {
                    checkpoint_path,
                    raw_content_digest: corrupt_checkpoint_digest
                        .expect("branch established corrupt checkpoint evidence"),
                },
                None,
                None,
                LifecycleAdmission::Closed,
            ),
            None => {
                anyhow::ensure!(
                    blockds.is_empty(),
                    "local lineage cannot exist without a Runtime checkpoint"
                );
                let step = ReconcileStep::InspectInventory { inventory_epoch };
                (
                    step,
                    CheckpointEvidence::Missing { checkpoint_path },
                    None,
                    None,
                    LifecycleAdmission::Closed,
                )
            }
        };

    let frozen_contract_stop = matches!(&step, ReconcileStep::Quarantined)
        || corrupt_checkpoint_present
        || unsupported_superseded
        || current_cold_postcondition_mismatch
        || definite_release_rejected
        || closed_takeover_history
        || (matches!(&step, ReconcileStep::CleanupRelease { .. })
            && volumes.iter().any(|volume| {
                matches!(&volume.authority, VolumeAuthorityEvidence::Unowned { .. })
            }));
    let conditions = if current_cold_postcondition_exact {
        vec![Condition::Ready {
            reason: ReadyReason::PostconditionSatisfied {
                target: RuntimeTarget::Cold,
            },
        }]
    } else if frozen_contract_stop {
        // A superseded checkpoint and a completed release are still exact
        // physical evidence, but neither is itself a terminal typed reason.
        // V1's persisted Quarantined step also lacks the reason required by
        // `Condition::Quarantined`. Keep these states closed and conditionless
        // instead of claiming progress or inventing a Control-settling fact.
        Vec::new()
    } else {
        vec![Condition::Progressing {
            reason: ProgressingReason::ReconcileStep { step: step.clone() },
        }]
    };

    Ok(ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        }),
        runtime_incarnation,
        stable_state,
        step: step.clone(),
        checkpoint: checkpoint_evidence,
        processes: managed.processes,
        volumes,
        mounts: Vec::new(),
        networks: managed.networks,
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission,
        routes: Vec::new(),
        platform_guards: 0,
        conditions,
    })
}

fn authority_record_matches_local_attachment(
    record: &VolumeRecord,
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
    if record.lease_owner.is_none() {
        let stable_cold_release = matches!(
            checkpoint.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        ) && stable_cold_checkpoint_matches_released_attachment(
            checkpoint,
            attachment,
            record.lease_epoch,
            &record.head,
        ) && matches!(
            &record.last_transition,
            Some(LastVolumeTransition::Release { request, result })
                if request.volume_id == attachment.identity.volume_id
                    && request.attachment_id == attachment.identity.attachment_id
                    && request.expected_epoch == attachment.identity.attachment_epoch
                    && result.volume_id == attachment.identity.volume_id
                    && result.released_attachment_id == attachment.identity.attachment_id
                    && result.resulting_epoch == record.lease_epoch
                    && result.resulting_head == record.head
        );
        // Released local bytes may remain only behind an exact cleanup, a
        // durable closed quarantine, or the exact fenced R == L lineage of a
        // Stable Cold checkpoint. The latter remains cache, never an owner.
        let cold_membership_detach_release =
            cold_membership_detach_cleanup_checkpoint_is_supported(desired, checkpoint)
                && checkpoint.volumes.iter().any(|volume| {
                    volume.volume_id == attachment.identity.volume_id
                        && cold_checkpoint_volume_matches_released_attachment(
                            volume,
                            attachment,
                            record.lease_epoch,
                            &record.head,
                        )
                })
                && volume_record_has_exact_release(record, attachment);
        return validate_volume_record(record).is_ok()
            && validate_authorized_serving_attachment(attachment).is_ok()
            && record.volume_id == attachment.identity.volume_id
            && record.size_bytes == attachment.size_bytes
            && record.durability == attachment.durability
            && matches!(record.admin_state, VolumeAdminState::Active)
            && record.lease_expires_at.is_none()
            && (matches!(
                checkpoint.step,
                ReconcileStep::CleanupRelease { .. } | ReconcileStep::Quarantined
            ) || stable_cold_release)
            && (!cold_membership_detach_cleanup_checkpoint_is_supported(desired, checkpoint)
                || cold_membership_detach_release);
    }

    validate_volume_record(record).is_ok()
        && validate_authorized_serving_attachment(attachment).is_ok()
        && record.volume_id == attachment.identity.volume_id
        && record.size_bytes == attachment.size_bytes
        && record.durability == attachment.durability
        && matches!(
            record.admin_state,
            cats_api::runtime_reconciliation::VolumeAdminState::Active
        )
        && record.lease_owner.as_ref() == Some(&attachment.identity.attachment_id)
        && record.lease_epoch == attachment.identity.attachment_epoch
        && record
            .lease_expires_at
            .is_some_and(|expiry| expiry >= attachment.lease_expires_at)
        && remote_head_is_same_or_later(&record.head, &attachment.head)
        && record.last_transition == Some(attachment.expected_last_transition())
}

fn volume_record_has_exact_release(
    record: &VolumeRecord,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
    matches!(
        &record.last_transition,
        Some(LastVolumeTransition::Release { request, result })
            if request.volume_id == attachment.identity.volume_id
                && request.attachment_id == attachment.identity.attachment_id
                && request.expected_epoch == attachment.identity.attachment_epoch
                && result.volume_id == attachment.identity.volume_id
                && result.transition_id == request.transition_id
                && result.released_attachment_id == attachment.identity.attachment_id
                && result.resulting_epoch == record.lease_epoch
                && result.resulting_head == record.head
    )
}

pub(crate) fn checkpoint_prepared_volume_matches_blockd(
    checkpoint: &RuntimeCheckpoint,
    blockd: &AuthorizedBlockdInventoryEvidence,
) -> bool {
    let attachment = &blockd.checkpoint.attachment;
    let Some(volume) = checkpoint
        .volumes
        .iter()
        .find(|volume| volume.volume_id == attachment.identity.volume_id)
    else {
        return false;
    };
    let [lineage] = volume.local_lineages.as_slice() else {
        return false;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head: checkpoint_head,
    } = &volume.authority
    else {
        return false;
    };
    let head_is_exact = match &checkpoint.step {
        ReconcileStep::ProvisionRootImage {
            volume_id,
            expected_blank_head,
            expected_provisioned_head,
            ..
        } if volume_id == &volume.volume_id => {
            // The immutable acquire artifact remains at the blank Root head.
            // A rebound Provision checkpoint may already carry the exact
            // completed target head; that one scoped transition is durable in
            // the step itself and must not be applied to Persistent siblings.
            attachment.head == *expected_blank_head
                && (checkpoint_head == expected_blank_head
                    || checkpoint_head == expected_provisioned_head)
        }
        _ => checkpoint_head == &attachment.head,
    };
    volume.size_bytes == Some(attachment.size_bytes)
        && volume.durability == Some(attachment.durability)
        && attachment_id == &attachment.identity.attachment_id
        && *attachment_epoch == attachment.identity.attachment_epoch
        && head_is_exact
        && lineage.attachment_id == attachment.identity.attachment_id
        && lineage.attachment_epoch == attachment.identity.attachment_epoch
        && lineage.acquire_origin == attachment.identity.acquire_origin
        && lineage.node_id == attachment.identity.node_id
        && lineage.placement_epoch == attachment.identity.placement_epoch
        && lineage.local_durable_generation == checkpoint_head.generation
        && lineage.remote_durable_generation == checkpoint_head.generation
        && lineage.data_directory == blockd.data_directory
        && lineage.pending_pack_count.get() == 0
        && !lineage.fenced
        && lineage.state == LocalLineageState::Active
        && volume.devices.is_empty()
}

/// A lost local publication may be recovered only after the consumed
/// takeover has already been closed by a later authority transition.  The
/// immutable local artifact remains the exact historical R0 grant; it must
/// never be rewritten from the current point read.  This narrow join admits
/// that artifact only as a fenced/released lineage so the Desired effect can
/// deterministically invalidate the spent takeover intent.  Ordinary current
/// attachments continue through `authority_record_matches_local_attachment`.
fn takeover_historical_r0_is_closed(
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
    current: &VolumeRecord,
) -> bool {
    let AuthorizedServingAcquire::Takeover {
        authorization,
        receipt,
    } = &attachment.acquire
    else {
        return false;
    };
    let checkpoint_volume = checkpoint
        .volumes
        .iter()
        .find(|volume| volume.volume_id == attachment.identity.volume_id);
    let current_publication_target = matches!(
        &checkpoint.step,
        ReconcileStep::AcquireVolume {
            request:
                cats_api::runtime_reconciliation::VolumeAcquireRequest::Takeover {
                    authorization_id,
                },
        } if authorization_id == &authorization.authorization_id
    ) && checkpoint_volume.is_some_and(|volume| {
        volume.local_lineages.is_empty()
            && matches!(
                &volume.authority,
                VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    head,
                } if attachment_id == &authorization.expected_attachment_id
                    && *attachment_epoch == authorization.expected_epoch
                    // The durable checkpoint is the pre-A22 predecessor. A
                    // Takeover preserves that locked head, so it must equal
                    // the Control-signed primary receipt even when current
                    // authority is a later closed successor. Monotonicity is
                    // reserved for current-vs-primary below; accepting an
                    // older checkpoint head here would let unrelated durable
                    // bytes borrow an otherwise valid receipt and R0.
                    && head == &receipt.resulting_head
            )
    });
    let previously_adopted_sibling = checkpoint_volume.is_some_and(|volume| {
        matches!(
            &volume.authority,
            VolumeAuthorityEvidence::Owned {
                attachment_id,
                attachment_epoch,
                head,
            } if attachment_id == &attachment.identity.attachment_id
                && *attachment_epoch == attachment.identity.attachment_epoch
                && head == &attachment.head
        ) && matches!(
            volume.local_lineages.as_slice(),
            [lineage]
                if lineage.attachment_id == attachment.identity.attachment_id
                    && lineage.attachment_epoch == attachment.identity.attachment_epoch
                    && lineage.acquire_origin == attachment.identity.acquire_origin
                    && lineage.node_id == attachment.identity.node_id
                    && lineage.placement_epoch == attachment.identity.placement_epoch
        )
    });
    if validate_volume_record(current).is_err()
        || current.volume_id != attachment.identity.volume_id
        || current.size_bytes != attachment.size_bytes
        || current.durability != attachment.durability
        || !matches!(current.admin_state, VolumeAdminState::Active)
        || (!current_publication_target && !previously_adopted_sibling)
        || authorization.authorization_id != receipt.authorization_id
        || receipt.volume_id != attachment.identity.volume_id
        || receipt.new_attachment_id != attachment.identity.attachment_id
        || receipt.resulting_epoch != attachment.identity.attachment_epoch
        || receipt.resulting_head != attachment.head
        || !remote_head_is_same_or_later(&current.head, &receipt.resulting_head)
    {
        return false;
    }

    match current.last_transition.as_ref() {
        Some(LastVolumeTransition::Release { request, result }) => {
            request.volume_id == receipt.volume_id
                && request.attachment_id == receipt.new_attachment_id
                && request.expected_epoch == receipt.resulting_epoch
                && result.volume_id == receipt.volume_id
                && result.released_attachment_id == receipt.new_attachment_id
                && receipt
                    .resulting_epoch
                    .get()
                    .checked_add(1)
                    .is_some_and(|next| next == result.resulting_epoch.get())
                && current.lease_owner.is_none()
                && current.lease_epoch == result.resulting_epoch
                && current.lease_expires_at.is_none()
                && remote_head_is_same_or_later(&result.resulting_head, &receipt.resulting_head)
        }
        Some(LastVolumeTransition::NormalAcquire { request, result }) => {
            request.volume_id == receipt.volume_id
                && request.expected_unowned_epoch > receipt.resulting_epoch
                && result.volume_id == receipt.volume_id
                && current.lease_owner.as_ref() == Some(&result.attachment_id)
                && current.lease_epoch == result.resulting_epoch
                && remote_head_is_same_or_later(&result.resulting_head, &receipt.resulting_head)
        }
        // A different takeover or disposable-delete marker is not thick
        // enough by itself: its direct authorization lives only in the signed
        // A19 evidence bundle. Publication recovery consumes that fresh proof
        // as an immediate Desired replan and never leaves such a state for the
        // scanner to infer from a larger epoch/another text ID.
        Some(LastVolumeTransition::Takeover { .. }) => false,
        Some(
            LastVolumeTransition::BeginDelete { .. }
            | LastVolumeTransition::BeginDisposableDelete { .. },
        )
        | None => false,
    }
}

fn launched_head_chain_is_monotonic(
    attachment_head: &cats_api::runtime_reconciliation::RemoteHead,
    launch_head: &cats_api::runtime_reconciliation::RemoteHead,
    current_head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    remote_head_is_same_or_later(launch_head, attachment_head)
        && remote_head_is_same_or_later(current_head, launch_head)
        && remote_head_is_same_or_later(current_head, attachment_head)
}

fn current_checkpoint_adopts_blockd(
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
    if checkpoint
        .runtime_launch
        .identity()
        .and_then(|launch| {
            launch
                .devices
                .iter()
                .find(|device| device.volume_id == attachment.identity.volume_id)
        })
        .is_some_and(|device| {
            device.attachment_id == attachment.identity.attachment_id
                && device.attachment_epoch == attachment.identity.attachment_epoch
                && device.acquire_origin == attachment.identity.acquire_origin
                && device.size_bytes == attachment.size_bytes
                && device.durability == attachment.durability
                && remote_head_is_same_or_later(&device.expected_head, &attachment.head)
        })
    {
        // Later lifecycle checkpoints deliberately carry the immutable
        // Running launch while their top-level Desired coordinates advance.
        // That launch is the durable adoption edge for the older physical
        // AuthorizedBlockd artifact; validate_scanned_checkpoint separately
        // joins its complete device set and sealed Desired predecessor.
        return true;
    }
    match &checkpoint.step {
        ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            ..
        } => {
            volume_id == &attachment.identity.volume_id
                && attachment_id == &attachment.identity.attachment_id
                && *attachment_epoch == attachment.identity.attachment_epoch
        }
        ReconcileStep::CleanupRelease { cleanup } => matches!(
            &cleanup.target,
            cats_api::runtime_reconciliation::CleanupTarget::Volume {
                volume_id,
                attachment_id,
                attachment_epoch,
            } if volume_id == &attachment.identity.volume_id
                && attachment_id == &attachment.identity.attachment_id
                && *attachment_epoch == attachment.identity.attachment_epoch
        ),
        ReconcileStep::Quarantined => checkpoint.volumes.iter().any(|volume| {
            volume.volume_id == attachment.identity.volume_id
                && volume.local_lineages.iter().any(|lineage| {
                    lineage.attachment_id == attachment.identity.attachment_id
                        && lineage.attachment_epoch == attachment.identity.attachment_epoch
                        && lineage.acquire_origin == attachment.identity.acquire_origin
                        && lineage.node_id == attachment.identity.node_id
                        && lineage.placement_epoch == attachment.identity.placement_epoch
                })
        }),
        ReconcileStep::Stable {
            state: StableState::Cold,
        } => checkpoint.volumes.iter().any(|volume| {
            volume.volume_id == attachment.identity.volume_id
                && volume.local_lineages.iter().any(|lineage| {
                    lineage.attachment_id == attachment.identity.attachment_id
                        && lineage.attachment_epoch == attachment.identity.attachment_epoch
                        && lineage.acquire_origin == attachment.identity.acquire_origin
                        && lineage.node_id == attachment.identity.node_id
                        && lineage.placement_epoch == attachment.identity.placement_epoch
                        && lineage.state == LocalLineageState::Released
                        && lineage.fenced
                })
        }),
        _ => false,
    }
}

#[cfg(test)]
pub(super) fn current_checkpoint_adopts_blockd_for_test(
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
    current_checkpoint_adopts_blockd(checkpoint, attachment)
}

fn authority_owner_or_exact_release_matches(
    authority: &VolumeAuthorityEvidence,
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
    match authority {
        VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            ..
        } => {
            attachment_id == &attachment.identity.attachment_id
                && *attachment_epoch == attachment.identity.attachment_epoch
        }
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        } => match &checkpoint.step {
            ReconcileStep::CleanupRelease { cleanup } => {
                cleanup_release_matches_released_authority(
                    cleanup,
                    attachment,
                    *attachment_epoch,
                    head,
                ) || cold_membership_cleanup_matches_released_attachment(
                    desired,
                    checkpoint,
                    attachment,
                    *attachment_epoch,
                    head,
                )
            }
            ReconcileStep::Quarantined => checkpoint.volumes.iter().any(|volume| {
                matches!(
                    &volume.authority,
                    VolumeAuthorityEvidence::Unowned {
                        attachment_epoch: checkpoint_epoch,
                        head: checkpoint_head,
                    } if checkpoint_epoch == attachment_epoch && checkpoint_head == head
                )
            }),
            ReconcileStep::Stable {
                state: StableState::Cold,
            } => stable_cold_checkpoint_matches_released_attachment(
                checkpoint,
                attachment,
                *attachment_epoch,
                head,
            ),
            _ => false,
        },
        _ => false,
    }
}

fn cleanup_release_matches_released_authority(
    cleanup: &cats_api::runtime_reconciliation::CleanupRelease,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
    resulting_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    let (
        cats_api::runtime_reconciliation::CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return false;
    };
    attachment_epoch
        .get()
        .checked_add(1)
        .is_some_and(|next| next == resulting_epoch.get())
        && volume_id == &attachment.identity.volume_id
        && attachment_id == &attachment.identity.attachment_id
        && *attachment_epoch == attachment.identity.attachment_epoch
        && replay.generation == head.generation
}

fn cold_membership_cleanup_matches_released_attachment(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
    resulting_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    cold_membership_detach_cleanup_checkpoint_is_supported(desired, checkpoint)
        && checkpoint
            .volumes
            .iter()
            .filter(|volume| volume.volume_id == attachment.identity.volume_id)
            .collect::<Vec<_>>()
            .as_slice()
            .first()
            .is_some_and(|volume| {
                checkpoint
                    .volumes
                    .iter()
                    .filter(|candidate| candidate.volume_id == volume.volume_id)
                    .count()
                    == 1
                    && cold_checkpoint_volume_matches_released_attachment(
                        volume,
                        attachment,
                        resulting_epoch,
                        head,
                    )
            })
}

fn stable_cold_checkpoint_matches_released_attachment(
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
    resulting_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    if checkpoint.stable_state != Some(StableState::Cold)
        || !matches!(
            checkpoint.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        )
        || attachment
            .identity
            .attachment_epoch
            .get()
            .checked_add(1)
            .is_none_or(|next| next != resulting_epoch.get())
        || !remote_head_is_same_or_later(head, &attachment.head)
    {
        return false;
    }
    let mut matching = checkpoint
        .volumes
        .iter()
        .filter(|volume| volume.volume_id == attachment.identity.volume_id);
    let Some(volume) = matching.next() else {
        return false;
    };
    if matching.next().is_some() {
        return false;
    }
    cold_checkpoint_volume_matches_released_attachment(volume, attachment, resulting_epoch, head)
}

fn cold_checkpoint_volume_matches_released_attachment(
    volume: &ObservedVolume,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
    resulting_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    let [lineage] = volume.local_lineages.as_slice() else {
        return false;
    };
    matches!(
        &volume.authority,
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head: checkpoint_head,
        } if *attachment_epoch == resulting_epoch && checkpoint_head == head
    ) && lineage.attachment_id == attachment.identity.attachment_id
        && lineage.attachment_epoch == attachment.identity.attachment_epoch
        && lineage.acquire_origin == attachment.identity.acquire_origin
        && lineage.node_id == attachment.identity.node_id
        && lineage.placement_epoch == attachment.identity.placement_epoch
        && lineage.local_durable_generation == head.generation
        && lineage.remote_durable_generation == head.generation
        && lineage.pending_pack_count.get() == 0
        && lineage.fenced
        && lineage.state == LocalLineageState::Released
        && volume.devices.is_empty()
}

/// Sidecar-free structural gate used before a previous-boot VMM receipt may
/// be selected. The later recovery-global sweep still joins blockd, metadata
/// and BlobStore evidence through [`validate_scanned_checkpoint`]; this first
/// layer prevents copied top-level digest coordinates from blessing drifted
/// device, network, incarnation or managed-path contents.
#[cfg(target_os = "linux")]
pub(super) fn validate_checkpoint_recovery_structure(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    binding: DesiredCheckpointBinding,
    state_directory: &crate::state_directory::StateDirectory,
    socket_root: &super::vmm_socket_namespace::ManagedVmmSocketRoot,
) -> anyhow::Result<()> {
    let unique_guest_slots = desired
        .volumes
        .iter()
        .map(|intent| intent.guest_device.slot)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        unique_guest_slots.len() == desired.volumes.len()
            && desired
                .volumes
                .iter()
                .enumerate()
                .all(|(index, intent)| usize::from(intent.guest_device.slot) == index),
        "Runtime recovery Desired volume slots are not canonical and unique"
    );
    let binding_is_valid = match binding {
        DesiredCheckpointBinding::Current => {
            checkpoint.desired_revision == desired.desired_revision
                && checkpoint.spec_digest == desired.spec_digest
                && checkpoint.placement_epoch == desired.placement.placement_epoch
        }
        DesiredCheckpointBinding::Superseded => {
            checkpoint.desired_revision < desired.desired_revision
                && checkpoint.placement_epoch <= desired.placement.placement_epoch
        }
    };
    anyhow::ensure!(
        checkpoint.version == cats_api::runtime_reconciliation::ContractVersion::V1
            && checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && binding_is_valid
            && scanned_checkpoint_phase_envelope_is_valid(checkpoint)
            && checkpoint_process_projections_match_retained_launch(checkpoint)
            && checkpoint.mounts.is_empty()
            && matches!(
                checkpoint.guest_transport,
                GuestTransportEvidence::Unavailable
            )
            && matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent),
        "Runtime recovery checkpoint does not bind the current Desired phase envelope"
    );

    if let ReconcileStep::AcquireVolume { request } = &checkpoint.step {
        if binding == DesiredCheckpointBinding::Superseded {
            validate_superseded_acquire_checkpoint(checkpoint, request)?;
            return Ok(());
        }
        anyhow::ensure!(
            multi_acquire_checkpoint_is_bound(checkpoint, desired, state_directory.path()),
            "Acquire recovery checkpoint does not bind the complete Desired volume set"
        );
        return Ok(());
    }

    if let ReconcileStep::ProvisionRootImage {
        expected_blank_head,
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    {
        let mut roots = desired
            .volumes
            .iter()
            .filter(|intent| intent.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root);
        let intent = roots
            .next()
            .context("provision recovery checkpoint lacks its Root Volume")?;
        anyhow::ensure!(
            roots.next().is_none(),
            "provision recovery checkpoint repeats the Root Volume"
        );
        let rebound;
        let structural = if binding == DesiredCheckpointBinding::Current {
            checkpoint
        } else {
            // Rebind only the top-level Desired coordinates for the pure
            // structural validator. Every retained lineage, managed path,
            // authority identity and phase field remains the predecessor's
            // physical value and must independently match current Desired.
            rebound = {
                let mut checkpoint = checkpoint.clone();
                checkpoint.desired_revision = desired.desired_revision;
                checkpoint.spec_digest = desired.spec_digest.clone();
                checkpoint.placement_epoch = desired.placement.placement_epoch;
                checkpoint
            };
            &rebound
        };
        anyhow::ensure!(
            provision_checkpoint_is_bound(
                structural,
                desired,
                intent,
                state_directory.path(),
                expected_blank_head,
                expected_provisioned_head,
            ),
            "provision recovery checkpoint has drifted managed paths or lineage"
        );
        return Ok(());
    }

    if matches!(
        checkpoint.step,
        ReconcileStep::PrepareDevice { .. } | ReconcileStep::PrepareNetwork { .. }
    ) || checkpoint.runtime_launch.identity().is_some()
    {
        let devices = prepared_device_inputs(checkpoint)?;
        anyhow::ensure!(
            super::network::prepared_device_set_is_exact(desired, &devices),
            "Runtime recovery checkpoint does not cover the exact Desired device set"
        );
        for device in devices {
            let observed = checkpoint
                .volumes
                .iter()
                .find(|volume| volume.volume_id == device.volume_id)
                .context("Runtime recovery device lacks its observed Volume")?;
            anyhow::ensure!(
                prepared_device_input_is_exact(&device, desired, observed),
                "Runtime recovery device does not bind the exact Desired Volume"
            );
        }
    }
    if let ReconcileStep::PrepareNetwork { network, .. } = &checkpoint.step {
        anyhow::ensure!(
            network.network_config == desired.runtime.network_config,
            "Runtime recovery checkpoint does not bind the exact Desired network"
        );
    }
    if let Some(launch) = checkpoint.runtime_launch.identity() {
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running
                && launch.vcpus == desired.runtime.vcpus
                && launch.memory_bytes == desired.runtime.memory_bytes
                && launch.boot_image_digest == desired.runtime.boot_image_digest
                && launch.guest_config_digest == desired.runtime.guest_config_digest
                && launch.network.network_config == desired.runtime.network_config,
            "Runtime recovery launch does not bind the exact Desired runtime"
        );
        let recovered =
            super::vmm_socket_namespace::vmm_state_directory_from_checkpoint(checkpoint)?;
        anyhow::ensure!(
            recovered.path() == state_directory.path(),
            "Runtime recovery launch names another Node state directory"
        );
        super::vmm_runtime_paths::ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            state_directory,
            checkpoint,
        )?;
        socket_root.paths_from_checkpoint(checkpoint)?;
        let checkpoint_path = HostPath::new(
            runtime_checkpoint_path(
                &state_directory.path().join("checkpoints"),
                &checkpoint.cat_id,
            )
            .to_string_lossy()
            .into_owned(),
        )
        .context("recovery checkpoint path is not canonical")?;
        super::vmm_process::VmmProcessExpectation::from_checkpoint(checkpoint.clone())?
            .with_checkpoint_path(checkpoint_path)?;
        return Ok(());
    }
    match &checkpoint.step {
        ReconcileStep::PrepareDevice { .. } | ReconcileStep::PrepareNetwork { .. }
            if binding == DesiredCheckpointBinding::Current =>
        {
            Ok(())
        }
        ReconcileStep::CleanupRelease { cleanup }
            if binding == DesiredCheckpointBinding::Current =>
        {
            let [intent] = desired.volumes.as_slice() else {
                anyhow::bail!("current cleanup recovery requires one root intent")
            };
            let [observed] = checkpoint.volumes.as_slice() else {
                anyhow::bail!("current cleanup recovery requires one observed root")
            };
            let cats_api::runtime_reconciliation::CleanupTarget::Volume {
                volume_id,
                attachment_id,
                ..
            } = &cleanup.target
            else {
                anyhow::bail!("current cleanup recovery is not a Volume release")
            };
            anyhow::ensure!(
                cleanup.inventory_session.node_id == desired.placement.node_id
                    && cleanup.desired_read_position >= cleanup.inventory_read_position
                    && volume_id == &intent.volume_id
                    && attachment_id == &intent.attachment_id
                    && observed.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
                    && observed.disk_id.as_ref() == Some(&intent.disk_id)
                    && observed.volume_id == intent.volume_id
                    && observed.devices.is_empty(),
                "current cleanup recovery does not bind the exact Desired root"
            );
            Ok(())
        }
        ReconcileStep::Quarantined if binding == DesiredCheckpointBinding::Current => {
            anyhow::ensure!(
                checkpoint
                    .volumes
                    .iter()
                    .all(|volume| volume.devices.is_empty()),
                "quarantined recovery checkpoint contains a device"
            );
            Ok(())
        }
        _ => anyhow::bail!("recovery encountered an unsupported checkpoint phase"),
    }
}

pub(super) fn validate_scanned_checkpoint(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    binding: DesiredCheckpointBinding,
    blockds: Option<&BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    checkpoint_directory: &std::path::Path,
    blob: Option<&dyn BlobStore>,
    deadline: std::time::Instant,
) -> anyhow::Result<()> {
    let top_level_binding_is_valid = match binding {
        DesiredCheckpointBinding::Current => {
            checkpoint.placement_epoch == desired.placement.placement_epoch
                && checkpoint.desired_revision == desired.desired_revision
                && checkpoint.spec_digest == desired.spec_digest
        }
        DesiredCheckpointBinding::Superseded => {
            checkpoint.desired_revision < desired.desired_revision
                && checkpoint.placement_epoch <= desired.placement.placement_epoch
        }
    };
    let phase_envelope_is_valid = scanned_checkpoint_phase_envelope_is_valid(checkpoint);
    anyhow::ensure!(
        checkpoint.version == cats_api::runtime_reconciliation::ContractVersion::V1
            && checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && top_level_binding_is_valid
            && phase_envelope_is_valid
            && checkpoint_process_projections_match_retained_launch(checkpoint)
            && checkpoint.mounts.is_empty()
            && matches!(
                checkpoint.guest_transport,
                GuestTransportEvidence::Unavailable
            )
            && matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent),
        "Runtime checkpoint does not bind the current Desired phase envelope"
    );
    match &checkpoint.step {
        ReconcileStep::AcquireVolume { request } => match binding {
            DesiredCheckpointBinding::Current => {
                let state_directory = checkpoint_directory
                    .parent()
                    .context("checkpoint namespace lacks its state-directory parent")?;
                let target = desired
                    .volumes
                    .iter()
                    .find(|intent| request_matches_volume(request, desired, intent))
                    .context("Acquire checkpoint names no unique Desired target")?;
                let prepared: BTreeSet<&Id> = checkpoint
                    .volumes
                    .iter()
                    .filter(|volume| !volume.local_lineages.is_empty())
                    .map(|volume| &volume.volume_id)
                    .collect();
                let actual: BTreeSet<&Id> = blockds
                    .into_iter()
                    .flat_map(|blockds| blockds.keys())
                    .collect();
                let publication_window = !prepared.contains(&target.volume_id) && {
                    let mut expected = prepared.clone();
                    expected.insert(&target.volume_id);
                    actual == expected
                };
                anyhow::ensure!(
                    desired
                        .volumes
                        .iter()
                        .filter(|intent| request_matches_volume(request, desired, intent))
                        .count()
                        == 1
                        && multi_acquire_checkpoint_is_bound(
                            checkpoint,
                            desired,
                            state_directory,
                        )
                        && (actual == prepared || publication_window),
                    "Acquire checkpoint does not bind the complete Desired volume set"
                );
            }
            DesiredCheckpointBinding::Superseded => {
                validate_superseded_acquire_checkpoint(checkpoint, request)?;
            }
        },
        ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            data_directory,
            size_bytes,
            boot_image_digest,
            expected_blank_head,
            ..
        } => {
            let Some(blockd) = blockds.and_then(|blockds| blockds.get(volume_id)) else {
                anyhow::bail!("provision checkpoint lacks authorized blockd lineage")
            };
            let expected_blockds: BTreeSet<&Id> = checkpoint
                .volumes
                .iter()
                .filter(|volume| !volume.local_lineages.is_empty())
                .map(|volume| &volume.volume_id)
                .collect();
            let actual_blockds: BTreeSet<&Id> = blockds
                .into_iter()
                .flat_map(|blockds| blockds.keys())
                .collect();
            anyhow::ensure!(
                expected_blockds.len() == checkpoint.volumes.len()
                    && actual_blockds == expected_blockds,
                "provision checkpoint and AuthorizedBlockd set differ"
            );
            let attachment = &blockd.checkpoint.attachment;
            let checkpoint_volume = checkpoint
                .volumes
                .iter()
                .find(|volume| volume.volume_id == *volume_id)
                .context("provision checkpoint lacks its observed Volume")?;
            anyhow::ensure!(
                attachment_id == &attachment.identity.attachment_id
                    && *attachment_epoch == attachment.identity.attachment_epoch
                    && data_directory == &blockd.data_directory
                    && *size_bytes == attachment.size_bytes
                    && expected_blank_head == &attachment.head
                    && checkpoint_volume.size_bytes == Some(attachment.size_bytes)
                    && checkpoint_volume.durability == Some(attachment.durability),
                "provision checkpoint does not bind authorized blockd lineage"
            );
            if binding == DesiredCheckpointBinding::Current {
                let mut roots = desired
                    .volumes
                    .iter()
                    .filter(|intent| intent.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root);
                let intent = roots
                    .next()
                    .context("current provision checkpoint lacks its Root intent")?;
                anyhow::ensure!(
                    roots.next().is_none(),
                    "current provision checkpoint repeats the Root intent"
                );
                let blob = blob.context("provision checkpoint validation lacks image BlobStore")?;
                let ProvisionHeadRead::Ready { blank, target } =
                    expected_provision_heads(blob, desired, intent, deadline)
                else {
                    anyhow::bail!("provision checkpoint image manifest is unavailable or invalid")
                };
                let state_directory = checkpoint_directory
                    .parent()
                    .context("checkpoint namespace lacks its state-directory parent")?;
                anyhow::ensure!(
                    volume_id == &intent.volume_id
                        && boot_image_digest == &desired.runtime.boot_image_digest
                        && provision_checkpoint_is_bound(
                            checkpoint,
                            desired,
                            intent,
                            state_directory,
                            &blank,
                            &target,
                        ),
                    "current provision checkpoint does not bind the Desired image"
                );
            }
        }
        ReconcileStep::PrepareDevice { devices }
            if binding == DesiredCheckpointBinding::Current
                && devices.iter().any(|device| matches!(
                    device.serving_authority.as_ref(),
                    cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
                )) =>
        {
            validate_current_prepared_checkpoint(desired, checkpoint, blockds, true)?
        }
        ReconcileStep::PrepareNetwork { network, .. }
            if binding == DesiredCheckpointBinding::Current =>
        {
            anyhow::ensure!(
                network.network_config == desired.runtime.network_config,
                "PrepareNetwork checkpoint does not bind the exact Desired network"
            );
            crate::ch::validate_network_plan(&crate::ch::ChNetwork {
                tap: network.tap_name.as_str().to_owned(),
                ownership_token: network.ownership_token.clone(),
                config: network.network_config.clone(),
            })
            .context("validate checkpointed PrepareNetwork identity")?;
            validate_current_prepared_checkpoint(desired, checkpoint, blockds, false)?;
        }
        _ if checkpoint.runtime_launch.identity().is_some() => {
            if binding == DesiredCheckpointBinding::Current
                && desired.target == RuntimeTarget::Running
                && !matches!(checkpoint.step, ReconcileStep::CloseAdmission { .. })
            {
                validate_current_launched_checkpoint(desired, checkpoint, blockds)?;
            } else {
                let predecessor = super::sealed_running_predecessor(checkpoint, blockds)?;
                validate_current_launched_checkpoint(&predecessor, checkpoint, blockds)?;
            }
        }
        ReconcileStep::CleanupRelease { cleanup }
            if binding == DesiredCheckpointBinding::Current =>
        {
            validate_current_cleanup_checkpoint(desired, checkpoint, cleanup, blockds)?;
        }
        ReconcileStep::CleanupRelease { .. }
            if binding == DesiredCheckpointBinding::Superseded
                && cold_membership_detach_cleanup_checkpoint_is_supported(desired, checkpoint) =>
        {
            validate_cold_membership_detach_cleanup_checkpoint(checkpoint, blockds)?;
        }
        ReconcileStep::Quarantined if binding == DesiredCheckpointBinding::Current => {
            anyhow::ensure!(
                checkpoint
                    .volumes
                    .iter()
                    .all(|volume| volume.devices.is_empty()),
                "quarantined pre-launch checkpoint contains a device"
            );
        }
        ReconcileStep::Stable {
            state: StableState::Cold,
        } => validate_stable_cold_checkpoint(checkpoint, blockds)?,
        _ => anyhow::bail!("pre-launch scanner encountered an unsupported Runtime step"),
    }
    Ok(())
}

fn validate_cold_membership_detach_cleanup_checkpoint(
    checkpoint: &RuntimeCheckpoint,
    blockds: Option<&BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
) -> anyhow::Result<()> {
    let expected_blockds: BTreeSet<&Id> = checkpoint
        .volumes
        .iter()
        .filter(|volume| !volume.local_lineages.is_empty())
        .map(|volume| &volume.volume_id)
        .collect();
    let actual_blockds: BTreeSet<&Id> = blockds
        .into_iter()
        .flat_map(|by_volume| by_volume.keys())
        .collect();
    let target = super::lifecycle_steps::cold_membership_cleanup_target(checkpoint)
        .context("Cold detach cleanup checkpoint lacks target")?;
    let mut post_reclaim_blockds = expected_blockds.clone();
    post_reclaim_blockds.remove(target);
    anyhow::ensure!(
        expected_blockds == actual_blockds || post_reclaim_blockds == actual_blockds,
        "Cold detach cleanup checkpoint and retained cache set differ"
    );
    for volume in checkpoint
        .volumes
        .iter()
        .filter(|volume| !volume.local_lineages.is_empty())
    {
        let Some(blockd) = blockds.and_then(|by_volume| by_volume.get(&volume.volume_id)) else {
            anyhow::ensure!(
                &volume.volume_id == target,
                "Cold detach cleanup lost a non-target retained cache"
            );
            continue;
        };
        let VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        } = &volume.authority
        else {
            anyhow::bail!("Cold detach cleanup lineage is not Unowned")
        };
        anyhow::ensure!(
            cold_checkpoint_volume_matches_released_attachment(
                volume,
                &blockd.checkpoint.attachment,
                *attachment_epoch,
                head,
            ),
            "Cold detach cleanup retained cache identity is stale"
        );
    }
    Ok(())
}

fn scanned_checkpoint_phase_envelope_is_valid(checkpoint: &RuntimeCheckpoint) -> bool {
    match checkpoint.runtime_launch.identity() {
        Some(launch) => {
            checkpoint.runtime_incarnation.as_ref() == Some(&launch.runtime_incarnation)
        }
        None => {
            let stable_absent_is_valid = checkpoint.stable_state.is_none()
                || (checkpoint.stable_state == Some(StableState::Cold)
                    && matches!(
                        checkpoint.step,
                        ReconcileStep::Stable {
                            state: StableState::Cold
                        }
                    ));
            checkpoint.runtime_incarnation.is_none()
                && stable_absent_is_valid
                && checkpoint.networks.is_empty()
                && checkpoint.lifecycle_admission == LifecycleAdmission::Closed
                && checkpoint.route_gates.is_empty()
                && matches!(
                    checkpoint.require_idle,
                    RequireIdleCheckpoint::NotApplicable
                )
        }
    }
}

pub(super) fn checkpoint_process_projections_match_retained_launch(
    checkpoint: &RuntimeCheckpoint,
) -> bool {
    let Some(launch) = checkpoint.runtime_launch.identity() else {
        return checkpoint.processes.is_empty();
    };
    checkpoint.processes.iter().all(|process| {
        if checkpoint
            .processes
            .iter()
            .filter(|other| other.role == process.role)
            .count()
            != 1
        {
            return false;
        }
        match &process.role {
            ProcessRole::Vmm {
                runtime_incarnation,
            } => {
                let state_is_valid = match (&checkpoint.step, checkpoint.stable_state) {
                    (_, Some(StableState::Suspended))
                    | (ReconcileStep::SnapshotWarmRuntime { .. }, _) => {
                        process.state == ProcessState::Paused
                    }
                    (ReconcileStep::StopRuntime { .. }, _) => {
                        matches!(process.state, ProcessState::Running | ProcessState::Paused)
                    }
                    _ => process.state == ProcessState::Running,
                };
                let effect_identity_is_valid = match &checkpoint.step {
                    ReconcileStep::PauseRuntime {
                        runtime_incarnation: effect_incarnation,
                        process_start_time_ticks,
                    } => {
                        runtime_incarnation == effect_incarnation
                            && process.process_start_time_ticks == *process_start_time_ticks
                    }
                    ReconcileStep::StopRuntime {
                        runtime_incarnation: effect_incarnation,
                        process_start_time_ticks,
                        scope_id,
                    } => {
                        runtime_incarnation == effect_incarnation
                            && process.process_start_time_ticks == *process_start_time_ticks
                            && process.scope_id == *scope_id
                    }
                    _ => true,
                };
                runtime_incarnation == &launch.runtime_incarnation
                    && process.executable_path == launch.boot.vmm_executable.path
                    && process.scope_id == launch.scope_id
                    && process.control_socket_path == launch.api_socket_path
                    && state_is_valid
                    && effect_identity_is_valid
                    && process.ownership_token
                        == OwnershipTokenEvidence::Valid {
                            ownership_token: launch.process_identity_token.clone(),
                        }
                    && process.control_handshake == ControlHandshakeEvidence::Verified
                    && process.observed_vm_shape.as_ref().is_some_and(|shape| {
                        shape.vcpus == launch.vcpus
                            && shape.memory_bytes == launch.memory_bytes
                            && shape.boot_image_digest == launch.boot_image_digest
                            && shape.guest_config_digest == launch.guest_config_digest
                    })
            }
            ProcessRole::Blockd {
                volume_id,
                attachment_id,
                attachment_epoch,
            } => {
                let mut devices = launch.devices.iter().filter(|device| {
                    device.volume_id == *volume_id
                        && device.attachment_id == *attachment_id
                        && device.attachment_epoch == *attachment_epoch
                });
                let Some(device) = devices.next() else {
                    return false;
                };
                devices.next().is_none()
                    && process.executable_path == device.serving_process.executable_path
                    && process.scope_id == device.serving_process.scope_id
                    && process.control_socket_path == device.serving_process.control_socket_path
                    && process.state == ProcessState::Running
                    && process.ownership_token
                        == OwnershipTokenEvidence::Valid {
                            ownership_token: device.serving_process.process_identity_token.clone(),
                        }
                    && process.control_handshake == ControlHandshakeEvidence::Verified
                    && process.observed_vm_shape.is_none()
            }
        }
    })
}

fn validate_stable_cold_checkpoint(
    checkpoint: &RuntimeCheckpoint,
    blockds: Option<&BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        checkpoint.stable_state == Some(StableState::Cold)
            && checkpoint.runtime_incarnation.is_none()
            && checkpoint.runtime_launch.identity().is_none()
            && checkpoint.processes.is_empty()
            && !checkpoint.volumes.is_empty()
            && checkpoint.mounts.is_empty()
            && checkpoint.networks.is_empty()
            && matches!(
                checkpoint.guest_transport,
                GuestTransportEvidence::Unavailable
            )
            && matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent)
            && checkpoint.lifecycle_admission == LifecycleAdmission::Closed
            && checkpoint.route_gates.is_empty()
            && matches!(
                checkpoint.require_idle,
                RequireIdleCheckpoint::NotApplicable
            ),
        "Stable Cold checkpoint retains a live physical envelope"
    );
    let expected_blockds: BTreeSet<&Id> = checkpoint
        .volumes
        .iter()
        .filter(|volume| !volume.local_lineages.is_empty())
        .map(|volume| &volume.volume_id)
        .collect();
    let actual_blockds: BTreeSet<&Id> = blockds
        .into_iter()
        .flat_map(|by_volume| by_volume.keys())
        .collect();
    anyhow::ensure!(
        expected_blockds == actual_blockds,
        "Stable Cold checkpoint and retained cache lineage set differ"
    );
    for volume in &checkpoint.volumes {
        let VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        } = &volume.authority
        else {
            anyhow::bail!("Stable Cold checkpoint retains a non-Unowned Volume")
        };
        anyhow::ensure!(
            volume.devices.is_empty()
                && (volume.disk_kind != cats_api::runtime_reconciliation::ObservedDiskKind::Root
                    || head.generation.get() > 0),
            "Stable Cold checkpoint retains a device or blank Root"
        );
        match volume.local_lineages.as_slice() {
            [] => {}
            [lineage] => {
                let blockd = blockds
                    .and_then(|by_volume| by_volume.get(&volume.volume_id))
                    .context("Stable Cold released lineage lacks retained cache evidence")?;
                let attachment = &blockd.checkpoint.attachment;
                anyhow::ensure!(
                    lineage.data_directory == blockd.data_directory
                        && stable_cold_checkpoint_matches_released_attachment(
                            checkpoint,
                            attachment,
                            *attachment_epoch,
                            head,
                        ),
                    "Stable Cold retained cache lineage is stale or ambiguous"
                );
            }
            _ => anyhow::bail!("Stable Cold checkpoint has duplicate local lineages"),
        }
    }
    Ok(())
}

fn validate_current_prepared_checkpoint(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    blockds: Option<&BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    requires_retained_root_process: bool,
) -> anyhow::Result<()> {
    let Some(blockds) = blockds else {
        anyhow::bail!("prepared-device checkpoint lacks authorized blockd lineage")
    };
    anyhow::ensure!(
        blockds.len() == checkpoint.volumes.len(),
        "prepared-device checkpoint and authorized blockd inventory differ in exact size"
    );
    let devices = prepared_device_inputs(checkpoint)?;
    anyhow::ensure!(
        devices.len() == blockds.len(),
        "prepared-device checkpoint and authorized blockd inventory differ in exact size"
    );
    let refreshes_live_volume_projection = matches!(
        checkpoint.step,
        ReconcileStep::DrainPublish { .. }
            | ReconcileStep::PauseRuntime { .. }
            | ReconcileStep::SnapshotWarmRuntime { .. }
            | ReconcileStep::StopRuntime { .. }
            | ReconcileStep::CleanupRelease { .. }
    );
    for device in devices {
        let checkpoint_volume = checkpoint
            .volumes
            .iter()
            .find(|volume| volume.volume_id == device.volume_id)
            .context("prepared device lacks its observed Volume")?;
        let blockd = blockds
            .get(&device.volume_id)
            .context("prepared device lacks its authorized blockd lineage")?;
        let attachment = &blockd.checkpoint.attachment;
        let is_root_handoff = matches!(
            device.serving_authority.as_ref(),
            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
        );
        let checkpoint_volume_is_exact = if refreshes_live_volume_projection {
            prepared_device_input_matches_retained_lifecycle(&device, desired, checkpoint_volume)
        } else {
            prepared_device_input_is_exact(&device, desired, checkpoint_volume)
        };
        anyhow::ensure!(
            checkpoint_volume_is_exact
                && device.volume_id == attachment.identity.volume_id
                && device.attachment_id == attachment.identity.attachment_id
                && device.attachment_epoch == attachment.identity.attachment_epoch
                && device.acquire_origin == attachment.identity.acquire_origin
                && device.size_bytes == attachment.size_bytes
                && device.durability == attachment.durability
                && remote_head_is_same_or_later(&device.expected_head, &attachment.head)
                && device.serving_process.data_directory == blockd.data_directory
                && (!requires_retained_root_process
                    || !is_root_handoff
                    || blockd.retained_root_process.is_some()),
            "prepared-device checkpoint does not bind its authorized blockd lineage"
        );
    }
    Ok(())
}

fn validate_current_launched_checkpoint(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    blockds: Option<&BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
) -> anyhow::Result<()> {
    let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)
        .context("validate current retained VMM launch authority")?;
    let launch = authority.identity();
    anyhow::ensure!(
        desired.target == cats_api::runtime_reconciliation::RuntimeTarget::Running
            && launch.vcpus == desired.runtime.vcpus
            && launch.memory_bytes == desired.runtime.memory_bytes
            && launch.boot_image_digest == desired.runtime.boot_image_digest
            && launch.guest_config_digest == desired.runtime.guest_config_digest
            && launch.network.network_config == desired.runtime.network_config,
        "retained VMM launch does not bind the exact current Desired runtime"
    );
    validate_current_prepared_checkpoint(desired, checkpoint, blockds, false)
}

fn validate_current_cleanup_checkpoint(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    cleanup: &cats_api::runtime_reconciliation::CleanupRelease,
    blockds: Option<&BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
) -> anyhow::Result<()> {
    let [intent] = desired.volumes.as_slice() else {
        anyhow::bail!("current cleanup requires one root intent")
    };
    let [observed] = checkpoint.volumes.as_slice() else {
        anyhow::bail!("current cleanup requires one observed root")
    };
    let (
        cats_api::runtime_reconciliation::CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        anyhow::bail!("current cleanup is not an exact Volume release")
    };
    let lineage_bound = match blockds.and_then(|blockds| blockds.get(volume_id)) {
        Some(blockd) => {
            blockd.checkpoint.attachment.identity.attachment_id == *attachment_id
                && blockd.checkpoint.attachment.identity.attachment_epoch == *attachment_epoch
        }
        // A disposable-root release's authorized reclaim removes the entire
        // data tree while this same checkpoint is still current; complete
        // absence is that postcondition, not a binding failure. A partially
        // present tree never reaches this arm: the strict data-tree walkers
        // fail the scan on their own. Retaining dispositions keep requiring
        // their lineage.
        None => matches!(
            replay.disposition,
            cats_api::runtime_reconciliation::VolumeDisposition::DeleteDisposableRoot { .. }
        ),
    };
    anyhow::ensure!(
        cleanup.inventory_session.node_id == desired.placement.node_id
            && cleanup.desired_read_position >= cleanup.inventory_read_position
            && volume_id == &intent.volume_id
            && attachment_id == &intent.attachment_id
            && replay.disposition == intent.disposition
            && observed.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
            && observed.disk_id.as_ref() == Some(&intent.disk_id)
            && observed.volume_id == intent.volume_id
            && observed.size_bytes == Some(intent.size_bytes)
            && observed.durability == Some(intent.durability)
            && observed.devices.is_empty()
            && lineage_bound,
        "current cleanup checkpoint does not bind the exact stale lineage"
    );
    Ok(())
}

fn validate_superseded_acquire_checkpoint(
    checkpoint: &RuntimeCheckpoint,
    request: &cats_api::runtime_reconciliation::VolumeAcquireRequest,
) -> anyhow::Result<()> {
    let cats_api::runtime_reconciliation::VolumeAcquireRequest::Normal {
        volume_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
        ..
    } = request
    else {
        anyhow::bail!("superseded first-slice checkpoint is not a normal acquire")
    };
    let [volume] = checkpoint.volumes.as_slice() else {
        anyhow::bail!("superseded Acquire checkpoint does not contain one Volume")
    };
    anyhow::ensure!(
        volume.volume_id == *volume_id
            && volume.disk_kind == cats_api::runtime_reconciliation::ObservedDiskKind::Root
            && volume.size_bytes.is_some()
            && volume.durability.is_some()
            && volume.local_lineages.is_empty()
            && volume.devices.is_empty()
            && matches!(
                volume.authority,
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch,
                    ..
                } if attachment_epoch == *expected_unowned_epoch
            )
            && *desired_revision == checkpoint.desired_revision
            && *placement_epoch == checkpoint.placement_epoch
            && !attachment_id.as_str().is_empty()
            && *lease_duration_ms > 0,
        "superseded Acquire checkpoint is not a closed pre-effect journal"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use cats_api::route_grant_v2::decode_route_grant_v2_public_key_ring;
    #[cfg(target_os = "linux")]
    use cats_api::runtime_reconciliation::RuntimeLaunch;
    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, decode_desired_runtime_spec, decode_runtime_checkpoint,
        encode_node_observation, encode_runtime_checkpoint, inventory_digest, spec_digest,
        AssignedKind, AssignedPlacement, ContractVersion, DesiredRuntimeSpec, Epoch, Id,
        InventorySource, Ipv4Address, IsolatedIpv4Kind, KeyId, MacAddress, NetworkConfig,
        NodeObservation, OwnershipTokenEvidence, RandomId128, ReconcileStep, Revision,
        RuntimeConfig, RuntimeTarget, RuntimeTransition, SessionBinding, Sha256Digest, StableState,
    };

    use super::*;
    use crate::route_grant_v2::{RouteGrantV2KeyRing, RouteGrantV2Verifier};

    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;
    const ACTIVE_ROUTE_RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#;

    #[test]
    fn residue_aggregation_never_builds_item_4097_across_sources() {
        let residue = |index| NodeResidue::ControlSocket {
            socket_path: HostPath::new(format!("/tmp/residue-{index}")).unwrap(),
            role_hint: None,
            ownership_token: OwnershipTokenEvidence::Missing,
        };
        let mut aggregate = InventoryProbeAggregation::new();
        append_residue_or_mark_incomplete(
            &mut aggregate,
            InventorySource::Checkpoint,
            (0..NODE_OBSERVATION_MAX_RESIDUE_ITEMS - 1)
                .map(residue)
                .collect(),
        );
        append_residue_or_mark_incomplete(
            &mut aggregate,
            InventorySource::DataDirectory,
            vec![residue(NODE_OBSERVATION_MAX_RESIDUE_ITEMS - 1)],
        );
        assert_eq!(aggregate.residue.len(), NODE_OBSERVATION_MAX_RESIDUE_ITEMS);
        assert!(aggregate.unavailable_sources.is_empty());

        append_residue_or_mark_incomplete(
            &mut aggregate,
            InventorySource::Network,
            vec![residue(NODE_OBSERVATION_MAX_RESIDUE_ITEMS)],
        );
        assert_eq!(
            aggregate.residue.len(),
            NODE_OBSERVATION_MAX_RESIDUE_ITEMS,
            "item 4097 must not enter the wire projection"
        );
        assert_eq!(aggregate.unavailable_sources, [InventorySource::Network]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_structure_rejects_runtime_device_and_path_drift_but_allows_endpoint_supersession() {
        let desired = decode_desired_runtime_spec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-desired.json"
        )))
        .unwrap();
        let mut checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let state = crate::state_directory::StateDirectory::unanchored("/var/lib/cats".into());
        let socket_root = super::super::vmm_socket_namespace::ManagedVmmSocketRoot::installed();
        let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap().clone();
        let sockets = socket_root.paths_for(&incarnation).unwrap();
        let files = super::super::vmm_runtime_paths::ManagedVmmLaunchFilePaths::for_incarnation(
            &state,
            &incarnation,
        )
        .unwrap();
        let ReconcileStep::StartRuntime {
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *api_socket_path = sockets.api_socket_path().clone();
        *vsock_socket_path = sockets.vsock_socket_path().clone();
        *memory_file_path = files.memory_file_path().clone();
        *serial_log_path = files.serial_log_path().clone();
        *vmm_log_path = files.vmm_log_path().clone();
        checkpoint.runtime_launch = RuntimeLaunch::Present(Box::new(
            checkpoint.step.start_runtime_launch_identity().unwrap(),
        ));
        validate_checkpoint_recovery_structure(
            &desired,
            &checkpoint,
            DesiredCheckpointBinding::Current,
            &state,
            &socket_root,
        )
        .unwrap();

        let mut endpoint_only = desired.clone();
        endpoint_only.desired_revision = Revision::new(desired.desired_revision.get() + 1).unwrap();
        endpoint_only.spec_digest = spec_digest(&endpoint_only).unwrap();
        validate_checkpoint_recovery_structure(
            &endpoint_only,
            &checkpoint,
            DesiredCheckpointBinding::Superseded,
            &state,
            &socket_root,
        )
        .unwrap();

        let mut runtime_drift = checkpoint.clone();
        let ReconcileStep::StartRuntime { vcpus, .. } = &mut runtime_drift.step else {
            unreachable!()
        };
        *vcpus += 1;
        runtime_drift.runtime_launch = RuntimeLaunch::Present(Box::new(
            runtime_drift.step.start_runtime_launch_identity().unwrap(),
        ));
        assert!(validate_checkpoint_recovery_structure(
            &desired,
            &runtime_drift,
            DesiredCheckpointBinding::Current,
            &state,
            &socket_root,
        )
        .is_err());

        let mut device_drift = checkpoint.clone();
        let ReconcileStep::StartRuntime { devices, .. } = &mut device_drift.step else {
            unreachable!()
        };
        devices[0].volume_intent_id = Id::new("vint_foreign").unwrap();
        device_drift.volumes[0].volume_intent_id = Some(Id::new("vint_foreign").unwrap());
        device_drift.runtime_launch = RuntimeLaunch::Present(Box::new(
            device_drift.step.start_runtime_launch_identity().unwrap(),
        ));
        assert!(validate_checkpoint_recovery_structure(
            &desired,
            &device_drift,
            DesiredCheckpointBinding::Current,
            &state,
            &socket_root,
        )
        .is_err());

        let mut path_drift = checkpoint.clone();
        let ReconcileStep::StartRuntime {
            memory_file_path, ..
        } = &mut path_drift.step
        else {
            unreachable!()
        };
        *memory_file_path = HostPath::new("/var/lib/cats/foreign-memory".to_owned()).unwrap();
        path_drift.runtime_launch = RuntimeLaunch::Present(Box::new(
            path_drift.step.start_runtime_launch_identity().unwrap(),
        ));
        assert!(validate_checkpoint_recovery_structure(
            &desired,
            &path_drift,
            DesiredCheckpointBinding::Current,
            &state,
            &socket_root,
        )
        .is_err());

        let mut placement_drift = endpoint_only;
        placement_drift.placement.placement_epoch =
            Epoch::new(desired.placement.placement_epoch.get() + 1).unwrap();
        placement_drift.spec_digest = spec_digest(&placement_drift).unwrap();
        assert!(validate_checkpoint_recovery_structure(
            &placement_drift,
            &checkpoint,
            DesiredCheckpointBinding::Superseded,
            &state,
            &socket_root,
        )
        .is_err());
    }

    #[test]
    fn retained_launch_mints_vmm_expectations_through_running_tail_retirement() {
        let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        assert!(scanned_checkpoint_phase_envelope_is_valid(&checkpoint));
        let cat_id = checkpoint.cat_id.clone();
        let evidence = RuntimeCheckpointInventoryEvidence {
            checkpoint,
            binding: DesiredCheckpointBinding::Current,
            definite_release_rejected: false,
        };
        let expected = vmm_process_expectations(
            std::path::Path::new("/var/lib/cats/checkpoints"),
            &BTreeMap::from([(cat_id.clone(), evidence.clone())]),
        )
        .unwrap();
        let expectation = expected.get(&cat_id).unwrap();
        assert_eq!(expectation.cat_id(), &cat_id);
        assert_eq!(
            expectation.checkpoint_path().unwrap().as_str(),
            "/var/lib/cats/checkpoints/cat-cat_01.checkpoint.json"
        );

        let mut tail = evidence.clone();
        tail.checkpoint.step = ReconcileStep::Stable {
            state: StableState::Running,
        };
        tail.checkpoint.stable_state = Some(StableState::Running);
        encode_runtime_checkpoint(&tail.checkpoint).unwrap();
        assert!(scanned_checkpoint_phase_envelope_is_valid(&tail.checkpoint));
        let tail_expected = vmm_process_expectations(
            std::path::Path::new("/var/lib/cats/checkpoints"),
            &BTreeMap::from([(cat_id.clone(), tail.clone())]),
        )
        .unwrap();
        assert_eq!(
            tail_expected.get(&cat_id).unwrap().launch_identity(),
            expectation.launch_identity()
        );

        let mut mismatched_incarnation = tail.checkpoint.clone();
        mismatched_incarnation.runtime_incarnation = None;
        assert!(!scanned_checkpoint_phase_envelope_is_valid(
            &mismatched_incarnation
        ));

        let superseded = RuntimeCheckpointInventoryEvidence {
            binding: DesiredCheckpointBinding::Superseded,
            ..evidence
        };
        let superseded_expected = vmm_process_expectations(
            std::path::Path::new("/var/lib/cats/checkpoints"),
            &BTreeMap::from([(cat_id, superseded)]),
        )
        .unwrap();
        assert_eq!(
            superseded_expected
                .values()
                .next()
                .unwrap()
                .launch_identity(),
            expectation.launch_identity()
        );
    }

    #[test]
    fn persisted_lifecycle_processes_require_exact_launch_and_effect_identity() {
        let mut checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        assert!(checkpoint_process_projections_match_retained_launch(
            &checkpoint
        ));
        let launch = checkpoint.runtime_launch.identity().unwrap().clone();
        let process_start_time_ticks = WireU64::new(99).unwrap();
        checkpoint.step = ReconcileStep::StopRuntime {
            runtime_incarnation: launch.runtime_incarnation.clone(),
            process_start_time_ticks,
            scope_id: launch.scope_id.clone(),
        };
        checkpoint.processes = vec![
            ProcessEvidence {
                role: ProcessRole::Vmm {
                    runtime_incarnation: launch.runtime_incarnation.clone(),
                },
                process_id: 41,
                process_start_time_ticks,
                executable_path: launch.boot.vmm_executable.path.clone(),
                scope_id: launch.scope_id.clone(),
                control_socket_path: launch.api_socket_path.clone(),
                state: ProcessState::Running,
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: launch.process_identity_token.clone(),
                },
                control_handshake: ControlHandshakeEvidence::Verified,
                observed_vm_shape: Some(cats_api::runtime_reconciliation::ObservedVmShape {
                    vcpus: launch.vcpus,
                    memory_bytes: launch.memory_bytes,
                    boot_image_digest: launch.boot_image_digest.clone(),
                    guest_config_digest: launch.guest_config_digest.clone(),
                }),
            },
            ProcessEvidence {
                role: ProcessRole::Blockd {
                    volume_id: launch.devices[0].volume_id.clone(),
                    attachment_id: launch.devices[0].attachment_id.clone(),
                    attachment_epoch: launch.devices[0].attachment_epoch,
                },
                process_id: 42,
                process_start_time_ticks: WireU64::new(100).unwrap(),
                executable_path: launch.devices[0].serving_process.executable_path.clone(),
                scope_id: launch.devices[0].serving_process.scope_id.clone(),
                control_socket_path: launch.devices[0]
                    .serving_process
                    .control_socket_path
                    .clone(),
                state: ProcessState::Running,
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: launch.devices[0]
                        .serving_process
                        .process_identity_token
                        .clone(),
                },
                control_handshake: ControlHandshakeEvidence::Verified,
                observed_vm_shape: None,
            },
        ];
        encode_runtime_checkpoint(&checkpoint).unwrap();
        assert!(checkpoint_process_projections_match_retained_launch(
            &checkpoint
        ));

        let mut stale_effect_pid = checkpoint.clone();
        stale_effect_pid.processes[0].process_start_time_ticks = WireU64::new(101).unwrap();
        assert!(!checkpoint_process_projections_match_retained_launch(
            &stale_effect_pid
        ));

        let mut foreign_blockd = checkpoint.clone();
        let ProcessRole::Blockd { attachment_id, .. } = &mut foreign_blockd.processes[1].role
        else {
            unreachable!()
        };
        *attachment_id = Id::new("att_foreign").unwrap();
        assert!(!checkpoint_process_projections_match_retained_launch(
            &foreign_blockd
        ));

        let mut duplicate_vmm = checkpoint;
        duplicate_vmm
            .processes
            .push(duplicate_vmm.processes[0].clone());
        duplicate_vmm.processes[2].process_id = 43;
        assert!(!checkpoint_process_projections_match_retained_launch(
            &duplicate_vmm
        ));
    }

    #[test]
    fn retained_lifecycle_volume_accepts_only_monotonic_exact_lineage_evolution() {
        let desired = decode_desired_runtime_spec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-desired.json"
        )))
        .unwrap();
        let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let device = checkpoint.runtime_launch.identity().unwrap().devices[0].clone();
        let mut evolved = checkpoint.volumes[0].clone();
        let VolumeAuthorityEvidence::Owned { head, .. } = &mut evolved.authority else {
            unreachable!()
        };
        head.generation = cats_api::runtime_reconciliation::Generation::new(4).unwrap();
        let lineage = &mut evolved.local_lineages[0];
        lineage.local_durable_generation =
            cats_api::runtime_reconciliation::Generation::new(5).unwrap();
        lineage.remote_durable_generation = head.generation;
        lineage.pending_pack_count = WireU64::new(1).unwrap();
        assert!(!prepared_device_input_is_exact(&device, &desired, &evolved));
        assert!(prepared_device_input_matches_retained_lifecycle(
            &device, &desired, &evolved
        ));

        let mut same_generation_conflict = evolved.clone();
        let VolumeAuthorityEvidence::Owned { head, .. } = &mut same_generation_conflict.authority
        else {
            unreachable!()
        };
        head.generation = device.expected_head.generation;
        head.root_hash = Some(Sha256Digest::from_bytes([0x51; 32]));
        same_generation_conflict.local_lineages[0].remote_durable_generation = head.generation;
        same_generation_conflict.local_lineages[0].local_durable_generation = head.generation;
        assert!(!prepared_device_input_matches_retained_lifecycle(
            &device,
            &desired,
            &same_generation_conflict,
        ));

        let mut remote_drift = evolved;
        remote_drift.local_lineages[0].remote_durable_generation =
            cats_api::runtime_reconciliation::Generation::new(3).unwrap();
        assert!(!prepared_device_input_matches_retained_lifecycle(
            &device,
            &desired,
            &remote_drift,
        ));
    }

    #[test]
    fn launched_head_chain_rejects_rollback_and_same_generation_conflicts() {
        let head = |generation, byte| cats_api::runtime_reconciliation::RemoteHead {
            generation: cats_api::runtime_reconciliation::Generation::new(generation).unwrap(),
            root_hash: (generation > 0).then(|| Sha256Digest::from_bytes([byte; 32])),
            root_object_id: (generation > 0).then(|| {
                cats_api::runtime_reconciliation::AsciiText::new(format!(
                    "roots/{generation}-{byte}"
                ))
                .unwrap()
            }),
        };
        let blank = head(0, 0);
        let launch = head(1, 1);
        let current = head(2, 2);
        assert!(launched_head_chain_is_monotonic(&blank, &launch, &current));
        assert!(!launched_head_chain_is_monotonic(
            &current, &launch, &current
        ));
        assert!(!launched_head_chain_is_monotonic(&blank, &current, &launch));
        assert!(!launched_head_chain_is_monotonic(
            &blank,
            &launch,
            &head(1, 9),
        ));
    }

    struct Probe {
        source: InventorySource,
        result: InventoryAbsence,
        calls: Arc<AtomicUsize>,
    }

    struct KeyRingReader {
        calls: Arc<AtomicUsize>,
        value: RuntimeInventoryKeyRing,
        fail: bool,
        cancel_before_return: bool,
    }

    impl runtime_inventory_key_ring_reader_sealed::Sealed for KeyRingReader {}

    impl RuntimeInventoryKeyRingReader for KeyRingReader {
        fn read(
            &self,
            context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryKeyRing> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.cancel_before_return {
                context.cancel_for_test();
            }
            anyhow::ensure!(!self.fail, "injected installed ring read failure");
            Ok(self.value.clone())
        }
    }

    impl super::super::inventory_probe_sealed::Sealed for Probe {}

    impl InventoryAbsenceProbe for Probe {
        fn source(&self) -> InventorySource {
            self.source
        }

        fn prove_absent(
            &self,
            _context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<InventoryAbsence> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.result.clone())
        }
    }

    fn context() -> RuntimeInventoryScanContext {
        let desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        RuntimeInventoryScanContext::for_test(
            crate::runtime_spine::RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: desired.session.node_id.clone(),
                    node_boot_id: desired.session.node_boot_id.clone(),
                    agent_instance_id: desired.session.agent_instance_id.clone(),
                    agent_session_epoch: desired.session.agent_session_epoch,
                },
                heartbeat_sequence: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired,
            },
            Instant::now() + std::time::Duration::from_secs(5),
        )
    }

    fn assigned_context() -> RuntimeInventoryScanContext {
        let mut context = context();
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: Id::new("ws_01").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: Id::new("node_a").unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2_147_483_648,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: Id::new("net_01").unwrap(),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: Vec::new(),
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        context
            .coordinates_mut()
            .desired
            .desired_specs
            .push(desired);
        context
    }

    fn probes(
        unavailable: Option<InventorySource>,
        calls: &Arc<AtomicUsize>,
    ) -> Vec<Arc<dyn InventoryAbsenceProbe>> {
        REQUIRED_SOURCES
            .into_iter()
            .map(|source| {
                Arc::new(Probe {
                    source,
                    result: if unavailable == Some(source) {
                        InventoryAbsence::Unavailable
                    } else {
                        InventoryAbsence::Empty
                    },
                    calls: Arc::clone(calls),
                }) as Arc<dyn InventoryAbsenceProbe>
            })
            .collect()
    }

    #[test]
    fn every_closed_source_is_required_and_empty_scan_is_complete() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut missing = probes(None, &calls);
        missing.pop();
        assert_eq!(
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), missing).unwrap_err(),
            InventoryProbeSetError::Missing(InventorySource::GuestMount)
        );
        let mut duplicate = probes(None, &calls);
        duplicate.push(Arc::new(Probe {
            source: InventorySource::Checkpoint,
            result: InventoryAbsence::Empty,
            calls: Arc::clone(&calls),
        }));
        assert_eq!(
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), duplicate).unwrap_err(),
            InventoryProbeSetError::Duplicate(InventorySource::Checkpoint)
        );

        let scanner =
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), probes(None, &calls))
                .unwrap()
                .with_running_tail_transport_for_test(
                    AdmissionCellRegistry::new(PathBuf::from("/checkpoints")),
                    Arc::new(PlatformGuestReadyTransportPort),
                );
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(context()).unwrap()
        else {
            panic!("all empty sources must produce a complete scan")
        };
        assert!(inventory.runtimes().is_empty());
        assert!(inventory.residue().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), REQUIRED_SOURCES.len());
    }

    #[test]
    fn one_unavailable_source_never_becomes_empty_success() {
        let calls = Arc::new(AtomicUsize::new(0));
        let scanner = CleanSlateInventoryScanner::new(
            PathBuf::from("/checkpoints"),
            probes(Some(InventorySource::MetadataStore), &calls),
        )
        .unwrap();
        assert!(matches!(
            scanner.scan_complete(context()).unwrap(),
            RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources,
                ..
            }
                if unavailable_sources == [InventorySource::MetadataStore]
        ));
    }

    #[test]
    fn complete_residue_is_reported_canonically_without_becoming_absence() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut all = probes(None, &calls);
        let process = all
            .iter_mut()
            .find(|probe| probe.source() == InventorySource::ControlSocket)
            .unwrap();
        *process = Arc::new(Probe {
            source: InventorySource::ControlSocket,
            result: InventoryAbsence::Residue(vec![
                NodeResidue::ControlSocket {
                    socket_path: HostPath::new("/run/cats/z.sock").unwrap(),
                    role_hint: None,
                    ownership_token:
                        cats_api::runtime_reconciliation::OwnershipTokenEvidence::Missing,
                },
                NodeResidue::ControlSocket {
                    socket_path: HostPath::new("/run/cats/a.sock").unwrap(),
                    role_hint: None,
                    ownership_token:
                        cats_api::runtime_reconciliation::OwnershipTokenEvidence::Missing,
                },
            ]),
            calls: Arc::clone(&calls),
        });
        let scanner = CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), all).unwrap();
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(context()).unwrap()
        else {
            panic!("a completely enumerated residue source must remain a complete scan")
        };
        assert_eq!(inventory.residue().len(), 2);
        assert!(matches!(
            &inventory.residue()[0],
            NodeResidue::ControlSocket { socket_path, .. }
                if socket_path.as_str() == "/run/cats/a.sock"
        ));
    }

    #[test]
    fn installed_ring_is_read_once_and_projected_without_blocking_absence() {
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let kid = KeyId::new("a".repeat(64)).unwrap();
        let version = Epoch::new(7).unwrap();
        let digest =
            cats_api::runtime_reconciliation::key_ring_digest(version, std::slice::from_ref(&kid))
                .unwrap();
        let scanner = CleanSlateInventoryScanner::new(
            PathBuf::from("/checkpoints"),
            probes(None, &probe_calls),
        )
        .unwrap()
        .with_key_ring_reader(Arc::new(KeyRingReader {
            calls: Arc::clone(&reader_calls),
            value: RuntimeInventoryKeyRing::Loaded {
                version,
                digest: digest.clone(),
                kids: vec![kid.clone()],
            },
            fail: false,
            cancel_before_return: false,
        }));
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(context()).unwrap()
        else {
            panic!("valid installed ring must preserve the complete inventory")
        };
        assert_eq!(
            inventory.key_ring(),
            &RuntimeInventoryKeyRing::Loaded {
                version,
                digest,
                kids: vec![kid],
            }
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 1);

        let absent_calls = Arc::new(AtomicUsize::new(0));
        let absent = CleanSlateInventoryScanner::new(
            PathBuf::from("/checkpoints"),
            probes(None, &probe_calls),
        )
        .unwrap()
        .with_key_ring_reader(Arc::new(KeyRingReader {
            calls: Arc::clone(&absent_calls),
            value: RuntimeInventoryKeyRing::Unavailable,
            fail: false,
            cancel_before_return: false,
        }));
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            absent.scan_complete(context()).unwrap()
        else {
            panic!("an absent ring must not make a non-Route inventory incomplete")
        };
        assert_eq!(inventory.key_ring(), &RuntimeInventoryKeyRing::Unavailable);
        assert_eq!(absent_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn active_verifier_reader_tracks_the_exact_in_process_ring() {
        let artifact = decode_route_grant_v2_public_key_ring(ACTIVE_ROUTE_RING).unwrap();
        let public_keys = artifact.public_keys().unwrap();
        let initial = RouteGrantV2KeyRing::from_artifact(&artifact).unwrap();
        let verifier = Arc::new(RouteGrantV2Verifier::new(initial));
        let reader = ActiveRuntimeInventoryKeyRingReader::new(Arc::clone(&verifier));

        assert_eq!(
            reader.read(&context()).unwrap(),
            RuntimeInventoryKeyRing::Loaded {
                version: artifact.ring_version,
                digest: artifact.digest().unwrap(),
                kids: artifact
                    .keys
                    .iter()
                    .map(|entry| entry.kid.clone())
                    .collect(),
            }
        );

        let replacement = RouteGrantV2KeyRing::new(Epoch::new(2).unwrap(), public_keys).unwrap();
        let replacement_digest = replacement.digest().clone();
        let replacement_kids = replacement.loaded_kids().to_vec();
        verifier.replace_ring(replacement).unwrap();
        assert_eq!(
            reader.read(&context()).unwrap(),
            RuntimeInventoryKeyRing::Loaded {
                version: Epoch::new(2).unwrap(),
                digest: replacement_digest,
                kids: replacement_kids,
            }
        );
    }

    #[test]
    fn failed_or_cancelled_ring_read_never_returns_or_caches_a_complete_scan() {
        for (fail, cancel_before_return) in [(true, false), (false, true)] {
            let probe_calls = Arc::new(AtomicUsize::new(0));
            let reader_calls = Arc::new(AtomicUsize::new(0));
            let scanner = CleanSlateInventoryScanner::new(
                PathBuf::from("/checkpoints"),
                probes(None, &probe_calls),
            )
            .unwrap()
            .with_key_ring_reader(Arc::new(KeyRingReader {
                calls: Arc::clone(&reader_calls),
                value: RuntimeInventoryKeyRing::Unavailable,
                fail,
                cancel_before_return,
            }));
            assert!(scanner.scan_complete(context()).is_err());
            assert_eq!(reader_calls.load(Ordering::SeqCst), 1);
            assert!(scanner.scan_complete(context()).is_err());
            assert_eq!(reader_calls.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn assigned_but_physically_empty_cat_is_closed_and_progressing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let scanner =
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), probes(None, &calls))
                .unwrap();
        let context = assigned_context();
        let coordinates = context.coordinates().clone();
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(context).unwrap()
        else {
            panic!("all empty sources must produce a complete assigned scan")
        };
        assert_eq!(inventory.runtimes().len(), 1);
        let runtime = &inventory.runtimes()[0];
        assert_eq!(runtime.cat_id.as_str(), "cat_01");
        assert!(runtime.applied_desired.is_some());
        assert!(matches!(
            runtime.checkpoint,
            CheckpointEvidence::Missing { .. }
        ));
        assert_eq!(runtime.lifecycle_admission, LifecycleAdmission::Closed);
        assert!(matches!(
            runtime.conditions.as_slice(),
            [Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: ReconcileStep::InspectInventory { .. }
                }
            }]
        ));

        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            node_id: coordinates.session.node_id,
            node_boot_id: coordinates.session.node_boot_id,
            agent_instance_id: coordinates.session.agent_instance_id,
            agent_session_epoch: coordinates.session.agent_session_epoch,
            heartbeat_sequence: coordinates.heartbeat_sequence,
            observed_at_unix_ms: inventory.observed_at_unix_ms(),
            complete_inventory: true,
            inventory_epoch: coordinates.inventory_epoch,
            inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
            inventory_read_position: Some(coordinates.desired.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: inventory.runtimes().to_vec(),
            residue: inventory.residue().to_vec(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        encode_node_observation(&observation).unwrap();
    }
}

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
use cats_api::runtime_artifacts::{
    inspect_installed_route_grant_v2_public_key_ring, InstalledRouteGrantV2PublicKeyRingState,
};
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, AppliedDesiredEvidence, CheckpointEvidence, Condition,
    DesiredRuntimeSpec, GuestTransportEvidence, HostPath, Id, InventorySource, LifecycleAdmission,
    LocalLineageState, LocalVolumeLineage, ObservedDevice, ObservedRuntimeStatus, ObservedVolume,
    ProcessEvidence, ProgressingReason, ReconcileStep, RequireIdleCheckpoint, RuntimeCheckpoint,
    RuntimeTarget, UnixMillis, VolumeAuthorityEvidence, WarmSnapshotEvidence, WireU64,
};
use cats_storage::{
    authority::{
        remote_head_is_same_or_later, validate_authorized_serving_attachment,
        validate_volume_record, LastVolumeTransition, VolumeRecord,
    },
    BlobStore,
};
use thiserror::Error;

use crate::route_grant_v2::RouteGrantV2KeyRing;
use crate::runtime_spine::{
    CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeInventoryKeyRing,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
};

use super::{
    admission_registry::AdmissionCellRegistry,
    guest_ready::{GuestReadyTransportPort, PlatformGuestReadyTransportPort},
    kernel_nbd::{KernelNbdInventoryPort, KernelNbdPoolScanOutcome},
    network::{
        prepare_device_checkpoint_view, prepared_device_inputs, NodeGlobalNetworkScanAdmission,
    },
    prepare_device_retirement::prepared_device_input_is_exact,
    probe_exact_guest_ready,
    retained_runtime_launch::RetainedRuntimeLaunchAuthority,
    root_provision_process::{
        ManagedServingKey, NodeGlobalManagedProcessScanAdmission,
        RetainedRootProvisionProcessAttempt, RootProvisionAuthoritySnapshot,
        RootProvisionProcessExpectation, StopReceiptSocketAdmission,
        TargetControlProcessLaunchIdentity,
    },
    running_admission::RunningTailScanAdmission,
    running_launch_authority::validate_retained_running_scan_exact_set,
    runtime_checkpoint_path,
    signed_running::{
        expected_provision_heads, provision_checkpoint_is_bound, request_matches_volume,
        superseded_checkpoint_has_supported_replan, unowned_observed_volume, ProvisionHeadRead,
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
    RuntimeCheckpoints(BTreeMap<Id, RuntimeCheckpointInventoryEvidence>),
    AuthorizedBlockd(BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBlockdInventoryEvidence {
    pub data_directory: HostPath,
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
    Unavailable,
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
        desired: &DesiredRuntimeSpec,
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
}

pub(crate) mod network_inventory_bridge_sealed {
    pub(crate) trait Sealed {}
}

#[derive(Debug)]
pub(crate) enum NetworkInventoryBridgeOutcome {
    Complete(NodeGlobalNetworkScanAdmission),
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

/// One bounded read of the Node's installed Route v2 verifier ring. The
/// scanner calls this port at most once per full scan and never retains a
/// successful result for a later scan.
pub(crate) trait RuntimeInventoryKeyRingReader:
    runtime_inventory_key_ring_reader_sealed::Sealed + Send + Sync + 'static
{
    fn read(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryKeyRing>;
}

#[derive(Debug)]
pub(crate) struct InstalledRuntimeInventoryKeyRingReader;

impl runtime_inventory_key_ring_reader_sealed::Sealed for InstalledRuntimeInventoryKeyRingReader {}

impl RuntimeInventoryKeyRingReader for InstalledRuntimeInventoryKeyRingReader {
    fn read(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryKeyRing> {
        context.check_active()?;
        let installed = inspect_installed_route_grant_v2_public_key_ring()
            .context("inspect the fixed installed Route Grant v2 public-key ring")?;
        context.check_active()?;
        match installed {
            InstalledRouteGrantV2PublicKeyRingState::Unavailable => {
                Ok(RuntimeInventoryKeyRing::Unavailable)
            }
            InstalledRouteGrantV2PublicKeyRingState::Loaded(installed) => {
                let ring = RouteGrantV2KeyRing::from_artifact(installed.ring())
                    .context("construct the installed Route Grant v2 verifier ring")?;
                Ok(RuntimeInventoryKeyRing::Loaded {
                    version: ring.version(),
                    digest: ring.digest().clone(),
                    kids: ring.loaded_kids().to_vec(),
                })
            }
        }
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
    volumes_by_cat: BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
    checkpoints_by_cat: BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    coverage: InventoryCoverageAggregator,
}

impl InventoryProbeAggregation {
    fn new() -> Self {
        Self {
            unavailable_sources: Vec::new(),
            volumes_by_cat: BTreeMap::new(),
            checkpoints_by_cat: BTreeMap::new(),
            blockd_by_cat: BTreeMap::new(),
            coverage: InventoryCoverageAggregator::new(),
        }
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
                return Ok(RuntimeInventoryScanOutcome::Incomplete {
                    unavailable_sources: aggregate.unavailable_sources,
                });
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
            let serving_expected = serving_process_expectations(
                &context,
                bridge.as_ref(),
                &aggregate.checkpoints_by_cat,
                &aggregate.blockd_by_cat,
                &aggregate.volumes_by_cat,
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
            match bridge.inspect_all(
                root_expected,
                serving_expected,
                vmm_expected,
                stop_receipt_sockets,
                &context,
            )? {
                RootProcessInventoryBridgeOutcome::Complete(admission) => {
                    processes_by_cat = admission.process_projections();
                    serving_devices_by_cat = admission.vhost_device_projections();
                    serving_status_by_cat = admission.serving_status_projections();
                    node_global_process_admission = Some(admission);
                }
                RootProcessInventoryBridgeOutcome::Unavailable => {
                    aggregate.unavailable_sources.extend([
                        InventorySource::Systemd,
                        InventorySource::Process,
                        InventorySource::ControlSocket,
                    ]);
                }
            }
            context
                .remaining()
                .context("root-process inventory bridge deadline expired after inspection")?;
            if let Some(kernel_nbd) = &self.kernel_nbd_port {
                let managed_processes = node_global_process_admission.as_ref().context(
                    "kernel-NBD pool scan lacks its same-pass managed-process admission",
                )?;
                match kernel_nbd.scan_complete_pool(&context, managed_processes)? {
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
                    KernelNbdPoolScanOutcome::Unavailable => {
                        aggregate
                            .unavailable_sources
                            .push(InventorySource::BlockFrontend);
                    }
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
                return Ok(RuntimeInventoryScanOutcome::Incomplete {
                    unavailable_sources: vec![
                        InventorySource::Systemd,
                        InventorySource::Process,
                        InventorySource::ControlSocket,
                        InventorySource::DataDirectory,
                    ],
                });
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
                NetworkInventoryBridgeOutcome::Unavailable => {
                    aggregate.unavailable_sources.push(InventorySource::Network);
                }
            }
            context
                .remaining()
                .context("network inventory bridge deadline expired after inspection")?;
        }
        if !aggregate.unavailable_sources.is_empty() {
            return Ok(RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources: aggregate.unavailable_sources,
            });
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
                if desired.target != RuntimeTarget::Running {
                    continue;
                }
                let Some(checkpoint_evidence) = aggregate.checkpoints_by_cat.get(&desired.cat_id)
                else {
                    continue;
                };
                if checkpoint_evidence.binding != DesiredCheckpointBinding::Current
                    || checkpoint_evidence
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
                    continue;
                };
                let vmm = vmm.clone();
                let guest_ready = match probe_exact_guest_ready(
                    guest_ready.as_ref(),
                    &context,
                    desired,
                    checkpoint,
                    &vmm,
                ) {
                    Ok(evidence) => evidence,
                    Err(_) => {
                        // A booting Guest or an earlier Format/Mount phase is
                        // an exact closed observation, not a reason to starve
                        // the physical effect that will make it Ready. A
                        // cancelled/deadline-expired scan is still propagated.
                        context.check_active()?;
                        continue;
                    }
                };
                let observed_cell = registry
                    .existing_session(&desired.cat_id)
                    .context("observe the process-owned Running admission cell")?
                    .map(|session| session.cell().observe());
                tail.insert_exact(
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
        let mut runtimes = context
            .coordinates()
            .desired
            .desired_specs
            .iter()
            .map(|desired| {
                runtime_from_inventory(
                    desired,
                    inventory_epoch,
                    &projection,
                    aggregate
                        .volumes_by_cat
                        .remove(&desired.cat_id)
                        .unwrap_or_default(),
                    aggregate.checkpoints_by_cat.remove(&desired.cat_id),
                    aggregate
                        .blockd_by_cat
                        .remove(&desired.cat_id)
                        .unwrap_or_default(),
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
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(tail) = &running_tail_admission {
            for runtime in &mut runtimes {
                tail.project_runtime(runtime)?;
            }
        }
        anyhow::ensure!(
            aggregate.volumes_by_cat.is_empty()
                && aggregate.checkpoints_by_cat.is_empty()
                && aggregate.blockd_by_cat.is_empty()
                && processes_by_cat.is_empty()
                && serving_devices_by_cat.is_empty()
                && serving_status_by_cat.is_empty()
                && networks_by_cat.is_empty(),
            "inventory named a Cat outside Desired"
        );

        Ok(RuntimeInventoryScanOutcome::Complete(
            CompleteRuntimeInventory::from_validated_coverage(
                coverage,
                observed_at_unix_ms,
                key_ring,
                runtimes,
                Vec::new(),
            )
            .with_node_global_process_admission(node_global_process_admission)
            .with_node_global_network_admission(node_global_network_admission)
            .with_kernel_nbd_pool_admission(kernel_nbd_pool_admission)
            .with_running_tail_admission(running_tail_admission),
        ))
    }
}

fn vmm_process_expectations(
    checkpoint_directory: &std::path::Path,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
) -> anyhow::Result<BTreeMap<Id, super::vmm_process::VmmProcessExpectation>> {
    let mut expected = BTreeMap::new();
    for (cat_id, evidence) in checkpoints_by_cat {
        if evidence.binding != DesiredCheckpointBinding::Current
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

fn root_process_expectations(
    context: &RuntimeInventoryScanContext,
    checkpoint_directory: &std::path::Path,
    blob: Option<&dyn BlobStore>,
    executable_path: &HostPath,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
) -> anyhow::Result<BTreeMap<Id, RootProvisionProcessExpectation>> {
    let mut expected = BTreeMap::new();
    for desired in &context.coordinates().desired.desired_specs {
        let Some(checkpoint) = checkpoints_by_cat.get(&desired.cat_id) else {
            continue;
        };
        if checkpoint.binding != DesiredCheckpointBinding::Current {
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
            .context("current root-provision checkpoint lacks AuthorizedBlockd lineage")?;
        let mut roots = blockds.values().filter(|blockd| {
            blockd.checkpoint.volume.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root
        });
        let blockd = roots
            .next()
            .context("current root-provision checkpoint lacks Root AuthorizedBlockd lineage")?;
        anyhow::ensure!(
            roots.next().is_none(),
            "current root-provision checkpoint has duplicate Root AuthorizedBlockd lineage"
        );
        anyhow::ensure!(
            blockd.binding == DesiredCheckpointBinding::Current,
            "current root-provision checkpoint has superseded AuthorizedBlockd lineage"
        );
        validate_scanned_checkpoint(
            desired,
            &checkpoint.checkpoint,
            checkpoint.binding,
            Some(blockds),
            checkpoint_directory,
            blob,
            context.deadline(),
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
            let expectation = RootProvisionProcessExpectation::from_retained_prepare_device(
                &prepared_checkpoint,
                desired,
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

pub(super) fn serving_process_expectations(
    context: &RuntimeInventoryScanContext,
    bridge: &dyn RootProcessInventoryBridge,
    checkpoints_by_cat: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
    blockd_by_cat: &BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    volumes_by_cat: &BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>>,
) -> anyhow::Result<
    BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdExpectation>,
> {
    let mut expected = BTreeMap::new();
    for desired in &context.coordinates().desired.desired_specs {
        let Some(checkpoint) = checkpoints_by_cat.get(&desired.cat_id) else {
            continue;
        };
        if checkpoint.binding != DesiredCheckpointBinding::Current
            || !(matches!(
                checkpoint.checkpoint.step,
                ReconcileStep::PrepareDevice { .. } | ReconcileStep::PrepareNetwork { .. }
            ) || checkpoint.checkpoint.runtime_launch.identity().is_some())
        {
            continue;
        }
        let devices = prepared_device_inputs(&checkpoint.checkpoint)?;
        anyhow::ensure!(
            super::network::prepared_device_set_is_exact(desired, &devices),
            "prepared-device checkpoint does not cover the exact Desired Volume set"
        );
        let blockds = blockd_by_cat
            .get(&desired.cat_id)
            .context("prepared-device checkpoint lacks AuthorizedBlockd inventory")?;
        anyhow::ensure!(
            blockds.len() == devices.len(),
            "prepared-device checkpoint and AuthorizedBlockd inventory differ in exact size"
        );
        for prepared in devices {
            let blockd = blockds
                .get(&prepared.volume_id)
                .context("prepared device lacks its AuthorizedBlockd lineage")?;
            anyhow::ensure!(
                blockd.binding == DesiredCheckpointBinding::Current,
                "current prepared device has superseded AuthorizedBlockd lineage"
            );
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
                desired,
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

fn runtime_from_inventory(
    desired: &DesiredRuntimeSpec,
    inventory_epoch: cats_api::runtime_reconciliation::Epoch,
    projection: &InventoryProjectionContext<'_>,
    mut volume_evidence: Vec<AuthorityVolumeInventoryEvidence>,
    checkpoint: Option<RuntimeCheckpointInventoryEvidence>,
    blockds: BTreeMap<Id, AuthorizedBlockdInventoryEvidence>,
    mut managed: RuntimeManagedProjection,
) -> anyhow::Result<ObservedRuntimeStatus> {
    let checkpoint_path = runtime_checkpoint_path(projection.checkpoint_directory, &desired.cat_id);
    let checkpoint_path = HostPath::new(
        checkpoint_path
            .to_str()
            .context("checkpoint path is not UTF-8")?
            .to_owned(),
    )
    .ok_or_else(|| anyhow::anyhow!("checkpoint path is not a valid HostPath"))?;

    for blockd in blockds.values() {
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
        let authoritative_head_is_adoptable = match (&runtime_checkpoint.step, &volume.authority) {
            (
                ReconcileStep::ProvisionRootImage {
                    expected_blank_head,
                    expected_provisioned_head,
                    ..
                },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) => head == expected_blank_head || head == expected_provisioned_head,
            (
                ReconcileStep::CleanupRelease { cleanup },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) => cleanup
                .volume_release
                .as_ref()
                .is_some_and(|release| release.generation == head.generation),
            (
                ReconcileStep::PrepareDevice { devices },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) => devices
                .iter()
                .find(|device| device.volume_id == volume.volume_id)
                .is_some_and(|device| &device.expected_head == head),
            (
                ReconcileStep::PrepareNetwork { devices, .. },
                VolumeAuthorityEvidence::Owned { head, .. },
            ) => devices
                .iter()
                .find(|device| device.volume_id == volume.volume_id)
                .is_some_and(|device| &device.expected_head == head),
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
            (ReconcileStep::StartRuntime { .. }, VolumeAuthorityEvidence::Owned { head, .. }) => {
                head == &attachment.head
            }
            (_, VolumeAuthorityEvidence::Owned { head, .. })
                if runtime_checkpoint.runtime_launch.identity().is_some() =>
            {
                remote_head_is_same_or_later(head, &attachment.head)
            }
            (_, VolumeAuthorityEvidence::Owned { head, .. }) => head == &attachment.head,
            (
                ReconcileStep::CleanupRelease { cleanup },
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch,
                    head,
                },
            ) => cleanup_release_matches_released_authority(
                cleanup,
                attachment,
                *attachment_epoch,
                head,
            ),
            (ReconcileStep::Quarantined, VolumeAuthorityEvidence::Unowned { .. }) => true,
            _ => false,
        };
        let mixed_binding_is_closed = checkpoint_binding == DesiredCheckpointBinding::Current
            && blockd.binding == DesiredCheckpointBinding::Superseded
            && current_checkpoint_adopts_blockd(runtime_checkpoint, attachment);
        anyhow::ensure!(
            blockd.binding == checkpoint_binding || mixed_binding_is_closed,
            "Runtime and authorized blockd checkpoint bindings disagree"
        );
        anyhow::ensure!(
            volume.volume_id == attachment.identity.volume_id
                && authority_owner_or_exact_release_matches(
                    &volume.authority,
                    runtime_checkpoint,
                    attachment,
                )
                && authority_record_matches_local_attachment(
                    authority_record,
                    runtime_checkpoint,
                    attachment,
                )
                && authoritative_head_is_adoptable
                && volume.local_lineages.is_empty(),
            "authorized blockd lineage conflicts with Volume authority"
        );
        let released = matches!(volume.authority, VolumeAuthorityEvidence::Unowned { .. });
        let authority_generation = match &volume.authority {
            VolumeAuthorityEvidence::Owned { head, .. }
            | VolumeAuthorityEvidence::Unowned { head, .. } => head.generation,
            _ => unreachable!("owned or exact released authority was checked above"),
        };
        let status = managed
            .serving_status
            .remove(&attachment.identity.volume_id);
        anyhow::ensure!(
            !released || status.is_none(),
            "released authorized lineage still has an exact serving process"
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
                authority_generation,
                authority_generation,
                WireU64::new(0).expect("zero fits WireU64"),
                released,
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
            state: if released {
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
    });
    let definite_release_rejected = checkpoint
        .as_ref()
        .is_some_and(|evidence| evidence.definite_release_rejected);

    let (step, checkpoint_evidence, runtime_incarnation, stable_state, lifecycle_admission) =
        match checkpoint {
            Some(inventory_checkpoint) => {
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
                (
                    checkpoint.step,
                    evidence,
                    checkpoint.runtime_incarnation,
                    checkpoint.stable_state,
                    checkpoint.lifecycle_admission,
                )
            }
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
        || unsupported_superseded
        || definite_release_rejected
        || (matches!(&step, ReconcileStep::CleanupRelease { .. })
            && volumes.iter().any(|volume| {
                matches!(&volume.authority, VolumeAuthorityEvidence::Unowned { .. })
            }));
    let conditions = if frozen_contract_stop {
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
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
    if record.lease_owner.is_none() {
        // Released local bytes may remain only behind an exact cleanup or a
        // durable closed quarantine. The metadata probe validates the release
        // marker before constructing the former projection.
        return matches!(
            checkpoint.step,
            ReconcileStep::CleanupRelease { .. } | ReconcileStep::Quarantined
        );
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
        && record.last_transition
            == Some(LastVolumeTransition::NormalAcquire {
                request: attachment.acquire_request.clone(),
                result: attachment.acquire_result.clone(),
            })
}

fn current_checkpoint_adopts_blockd(
    checkpoint: &RuntimeCheckpoint,
    attachment: &cats_storage::authority::AuthorizedServingAttachment,
) -> bool {
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
        _ => false,
    }
}

fn authority_owner_or_exact_release_matches(
    authority: &VolumeAuthorityEvidence,
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

fn validate_scanned_checkpoint(
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
            && checkpoint.processes.is_empty()
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
                let [intent] = desired.volumes.as_slice() else {
                    anyhow::bail!("current Acquire checkpoint requires one root Volume")
                };
                anyhow::ensure!(
                    request_matches_volume(request, desired, intent)
                        && (checkpoint.volumes == [unowned_observed_volume(intent)]
                            || current_acquire_adoption_is_closed(
                                checkpoint,
                                intent,
                                blockds.and_then(|blockds| blockds.get(&intent.volume_id)),
                            )),
                    "Acquire checkpoint does not bind the exact Desired root"
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
                let [intent] = desired.volumes.as_slice() else {
                    anyhow::bail!("current provision checkpoint requires one root Volume")
                };
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
        _ if binding == DesiredCheckpointBinding::Current
            && checkpoint.runtime_launch.identity().is_some() =>
        {
            validate_current_launched_checkpoint(desired, checkpoint, blockds)?;
        }
        ReconcileStep::CleanupRelease { cleanup }
            if binding == DesiredCheckpointBinding::Current =>
        {
            validate_current_cleanup_checkpoint(desired, checkpoint, cleanup, blockds)?;
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
        _ => anyhow::bail!("pre-launch scanner encountered an unsupported Runtime step"),
    }
    Ok(())
}

fn scanned_checkpoint_phase_envelope_is_valid(checkpoint: &RuntimeCheckpoint) -> bool {
    match checkpoint.runtime_launch.identity() {
        Some(launch) => {
            checkpoint.runtime_incarnation.as_ref() == Some(&launch.runtime_incarnation)
        }
        None => {
            checkpoint.runtime_incarnation.is_none()
                && checkpoint.stable_state.is_none()
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
        anyhow::ensure!(
            prepared_device_input_is_exact(&device, desired, checkpoint_volume)
                && device.volume_id == attachment.identity.volume_id
                && device.attachment_id == attachment.identity.attachment_id
                && device.attachment_epoch == attachment.identity.attachment_epoch
                && device.acquire_origin == attachment.identity.acquire_origin
                && device.size_bytes == attachment.size_bytes
                && device.durability == attachment.durability
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

fn current_acquire_adoption_is_closed(
    checkpoint: &RuntimeCheckpoint,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    blockd: Option<&AuthorizedBlockdInventoryEvidence>,
) -> bool {
    let [observed] = checkpoint.volumes.as_slice() else {
        return false;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    let Some(expected_epoch) = (match &intent.acquire {
        cats_api::runtime_reconciliation::VolumeAcquire::Normal {
            expected_unowned_epoch,
            ..
        } => expected_unowned_epoch
            .get()
            .checked_add(1)
            .and_then(cats_api::runtime_reconciliation::FenceEpoch::new),
        cats_api::runtime_reconciliation::VolumeAcquire::Takeover { .. } => None,
    }) else {
        return false;
    };
    observed.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&intent.disk_id)
        && observed.volume_id == intent.volume_id
        && observed.size_bytes == Some(intent.size_bytes)
        && observed.durability == Some(intent.durability)
        && attachment_id == &intent.attachment_id
        && *attachment_epoch == expected_epoch
        && head.generation.get() == 0
        && observed.devices.is_empty()
        && (observed.local_lineages.is_empty()
            || blockd.is_some_and(|blockd| {
                blockd.checkpoint.attachment.identity.attachment_id == *attachment_id
                    && blockd.checkpoint.attachment.identity.attachment_epoch == *attachment_epoch
            }))
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
            && blockds
                .and_then(|blockds| blockds.get(volume_id))
                .is_some_and(|blockd| {
                    blockd.checkpoint.attachment.identity.attachment_id == *attachment_id
                        && blockd.checkpoint.attachment.identity.attachment_epoch
                            == *attachment_epoch
                }),
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

    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, decode_runtime_checkpoint, encode_node_observation,
        encode_runtime_checkpoint, inventory_digest, spec_digest, AssignedKind, AssignedPlacement,
        ContractVersion, DesiredRuntimeSpec, Epoch, Id, InventorySource, Ipv4Address,
        IsolatedIpv4Kind, KeyId, MacAddress, NetworkConfig, NodeObservation, RandomId128,
        ReconcileStep, Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, SessionBinding,
        Sha256Digest, StableState,
    };

    use super::*;

    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    #[test]
    fn current_retained_launch_mints_vmm_expectations_through_running_tail() {
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
        assert!(vmm_process_expectations(
            std::path::Path::new("/var/lib/cats/checkpoints"),
            &BTreeMap::from([(cat_id, superseded)]),
        )
        .unwrap()
        .is_empty());
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
            RuntimeInventoryScanOutcome::Incomplete { unavailable_sources }
                if unavailable_sources == [InventorySource::MetadataStore]
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

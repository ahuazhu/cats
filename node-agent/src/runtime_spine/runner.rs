//! One-step orchestration for the durable signed Node spine.

use std::collections::{BTreeSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cats_api::runtime_reconciliation::{
    inventory_digest, AdmissionInventoryAttestation, AgentSession, ContractError,
    ContractErrorDetail, ContractVersion, DesiredReadRequest, DesiredReadSnapshot,
    DesiredRuntimeSpec, Epoch, Id, InventorySource, KeyId, NodeObservation, NodeResidue,
    ObservationAcceptance, ObservationInventoryAcceptance, ObservedRuntimeStatus, RandomId128,
    RuntimeSpineError, RuntimeSpineErrorDetail, RuntimeVolumeAuthorityRejection, Sha256Digest,
    UnixMillis,
};
use thiserror::Error;

use crate::state_directory::StateDirectory;

use super::{
    DurableRuntimeSpineRequest, RuntimeSpineAttempt, RuntimeSpineDesiredWork, RuntimeSpineFullScan,
    RuntimeSpineHttpClient, RuntimeSpineJournal, RuntimeSpineJournalError, RuntimeSpineRetryReason,
};

const REQUIRED_INVENTORY_SOURCES: [InventorySource; 11] = [
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

/// Performs one bounded scan of every physical source required by Runtime §6.
///
/// This capability is sealed to the crate until a production composition root
/// can supply concrete, cooperatively cancellable probes. Implementations must
/// pass `context.deadline()` to every blocking I/O boundary and return promptly
/// after `context.check_active()` reports cancellation. The runner, not the
/// scanner, owns protocol identities and the inventory digest.
pub trait RuntimeInventoryScanner:
    super::inventory_scanner_sealed::Sealed + Send + Sync + 'static
{
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome>;
}

/// Performs at most one explicitly typed local publication repair before a
/// physical inventory scan. Unlike [`RuntimeInventoryScanner`], this port may
/// mutate only crash-recovery artifacts that are exactly bound to the current
/// durable Desired snapshot. Returning `Recovered` forces the runner to start
/// a new iteration; repaired state is never projected without a fresh scan.
pub(crate) trait RuntimePreScanRecovery: Send + Sync + 'static {
    fn recover_one(
        &self,
        context: RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimePreScanRecoveryOutcome {
    NoChange,
    Recovered { cat_id: Id },
}

/// Executes one bounded, typed reconciliation unit for an exact fresh Desired
/// spec after restart admission has been re-established.
///
/// The runner invokes this seam only after a physical full inventory produced
/// in the current process has been accepted by Control, then a newer Desired
/// snapshot has been read and durably stored. Implementations must re-read the
/// Cat checkpoint from `context.state_directory()` before planning an effect.
/// A Cloud Hypervisor network adapter must pass
/// `&desired.runtime.network_config` unchanged to its typed network/VMM
/// primitive; legacy NodeJob fields or Cat-ID-derived networking are not an
/// admissible substitute. An implementation may return `Applied` only when
/// the current accepted full inventory already proves this Desired item needs
/// no persistent or physical change. Any checkpoint write, authority
/// mutation, process/device/network action, or postcondition confirmation
/// returns `RefreshInventory` so a new full scan is the sole bridge onward.
pub trait RuntimeDesiredEffect: Send + Sync + 'static {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome>;
}

/// Closed control decision returned by a typed Desired effect. Only
/// `RetryExact` retains the same in-memory admission and exact Desired unit;
/// every other non-applied decision leaves that batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeDesiredEffectOutcome {
    /// The accepted full inventory already proved this item converged; this
    /// invocation performed no persistent or physical change.
    Applied,
    RetryExact,
    RefreshInventory,
    ReplanDesired,
    IdentityRepairRequired,
    SessionReplacementRequired,
    Stop(RuntimeDesiredEffectStopReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeDesiredEffectStopReason {
    LocalContract,
    DeploymentMismatch,
    AuthorityRejected(RuntimeVolumeAuthorityRejection),
}

/// Operator-selected budgets for one bounded inventory scan and one bounded
/// physical reconciler step. These are local execution limits, not protocol
/// SLAs; deriving both absolute deadlines from one `now` ensures queue time is
/// never refunded at a later blocking boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSpineDeadlinePolicy {
    scan_timeout: Duration,
    effect_step_timeout: Duration,
}

impl RuntimeSpineDeadlinePolicy {
    pub fn new(
        scan_timeout: Duration,
        effect_step_timeout: Duration,
    ) -> Result<Self, RuntimeSpineDeadlinePolicyError> {
        if scan_timeout.is_zero() {
            return Err(RuntimeSpineDeadlinePolicyError::ZeroScanTimeout);
        }
        if effect_step_timeout.is_zero() {
            return Err(RuntimeSpineDeadlinePolicyError::ZeroEffectStepTimeout);
        }
        Ok(Self {
            scan_timeout,
            effect_step_timeout,
        })
    }

    pub fn deadlines_from(
        self,
        now: Instant,
    ) -> Result<RuntimeSpineRunDeadlines, RuntimeSpineDeadlinePolicyError> {
        let scan = now
            .checked_add(self.scan_timeout)
            .ok_or(RuntimeSpineDeadlinePolicyError::ScanDeadlineOverflow)?;
        let effect_step = now
            .checked_add(self.effect_step_timeout)
            .ok_or(RuntimeSpineDeadlinePolicyError::EffectStepDeadlineOverflow)?;
        Ok(RuntimeSpineRunDeadlines { scan, effect_step })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSpineRunDeadlines {
    scan: Instant,
    effect_step: Instant,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSpineDeadlinePolicyError {
    #[error("runtime inventory scan timeout must be positive")]
    ZeroScanTimeout,
    #[error("runtime effect-step timeout must be positive")]
    ZeroEffectStepTimeout,
    #[error("runtime inventory scan deadline overflowed Instant")]
    ScanDeadlineOverflow,
    #[error("runtime effect-step deadline overflowed Instant")]
    EffectStepDeadlineOverflow,
}

#[derive(Debug, Clone)]
pub struct RuntimeDesiredEffectContext {
    state_directory: StateDirectory,
    deadline: Instant,
    cancellation: RuntimeInventoryScanCancellation,
    accepted_full: Option<RuntimeDesiredEffectAdmission>,
}

/// Shared read-only deadline/cancellation boundary for physical identity
/// inspection. Both a full inventory scan and a Desired effect may inspect
/// the same systemd/process/socket tuple; creation remains effect-only.
pub(crate) trait RuntimePhysicalReadContext {
    fn deadline(&self) -> Instant;
    fn check_active(&self) -> anyhow::Result<()>;
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimePreScanRecoveryContext {
    state_directory: StateDirectory,
    coordinates: RuntimeSpineFullScan,
    deadline: Instant,
    cancellation: RuntimeInventoryScanCancellation,
}

impl RuntimePreScanRecoveryContext {
    fn new(
        state_directory: StateDirectory,
        coordinates: RuntimeSpineFullScan,
        deadline: Instant,
        cancellation: RuntimeInventoryScanCancellation,
    ) -> Self {
        Self {
            state_directory,
            coordinates,
            deadline,
            cancellation,
        }
    }

    pub(crate) fn state_directory(&self) -> &StateDirectory {
        &self.state_directory
    }

    pub(crate) fn coordinates(&self) -> &RuntimeSpineFullScan {
        &self.coordinates
    }

    pub(crate) fn check_active(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.cancellation.is_cancelled(),
            "runtime pre-scan recovery was cancelled"
        );
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "runtime pre-scan recovery deadline expired"
        );
        Ok(())
    }

    pub(crate) fn inventory_context(&self) -> RuntimeInventoryScanContext {
        RuntimeInventoryScanContext::new(
            self.coordinates.clone(),
            self.deadline,
            self.cancellation.clone(),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        state_directory: StateDirectory,
        coordinates: RuntimeSpineFullScan,
        deadline: Instant,
    ) -> Self {
        Self::new(
            state_directory,
            coordinates,
            deadline,
            RuntimeInventoryScanCancellation::new(),
        )
    }
}

/// The exact current-process full inventory acceptance that opened the one
/// subsequent Desired effect batch. It is never reconstructed from an old
/// checkpoint or a previous process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDesiredEffectAdmission {
    session: AgentSession,
    observation: NodeObservation,
    attestation: AdmissionInventoryAttestation,
    // Bound only by the successful Desired read which opens the effect batch.
    // CleanupRelease must carry this exact accepted cursor; reconstructing it
    // from the inventory attestation would lose the case where Desired
    // advanced after the scan but still accepted the same physical evidence.
    desired_read_position: Option<cats_api::runtime_reconciliation::Sequence>,
}

impl RuntimeDesiredEffectAdmission {
    fn from_acceptance(
        mut session: AgentSession,
        observation: NodeObservation,
        acceptance: &ObservationAcceptance,
    ) -> Option<Self> {
        let ObservationInventoryAcceptance::Full { attestation } = &acceptance.inventory else {
            return None;
        };
        if !super::acceptance_matches_observation(acceptance, &observation)
            || session.node_id != observation.node_id
            || session.node_boot_id != observation.node_boot_id
            || session.agent_instance_id != observation.agent_instance_id
            || session.agent_session_epoch != observation.agent_session_epoch
            || acceptance.lease_deadline_unix_ms < session.lease_deadline_unix_ms
            || attestation.accepted_at_unix_ms != acceptance.accepted_at_unix_ms
        {
            return None;
        }
        session.lease_deadline_unix_ms = acceptance.lease_deadline_unix_ms;
        Some(Self {
            session,
            observation,
            attestation: attestation.clone(),
            desired_read_position: None,
        })
    }

    pub fn session(&self) -> &AgentSession {
        &self.session
    }

    pub fn observation(&self) -> &NodeObservation {
        &self.observation
    }

    pub fn attestation(&self) -> &AdmissionInventoryAttestation {
        &self.attestation
    }

    pub fn desired_read_position(&self) -> Option<cats_api::runtime_reconciliation::Sequence> {
        self.desired_read_position
    }

    fn bind_desired_read_position(&mut self, snapshot: &DesiredReadSnapshot) -> anyhow::Result<()> {
        anyhow::ensure!(
            snapshot.version == self.session.version
                && snapshot.session.node_id == self.session.node_id
                && snapshot.session.node_boot_id == self.session.node_boot_id
                && snapshot.session.agent_instance_id == self.session.agent_instance_id
                && snapshot.session.agent_session_epoch == self.session.agent_session_epoch
                && snapshot.read_position >= self.attestation.inventory_read_position,
            "accepted Desired snapshot does not bind the current full effect admission"
        );
        self.desired_read_position = Some(snapshot.read_position);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        session: AgentSession,
        observation: NodeObservation,
        attestation: AdmissionInventoryAttestation,
    ) -> Self {
        let desired_read_position = attestation.inventory_read_position;
        Self {
            session,
            observation,
            attestation,
            desired_read_position: Some(desired_read_position),
        }
    }
}

impl RuntimeDesiredEffectContext {
    fn new(
        state_directory: StateDirectory,
        deadline: Instant,
        cancellation: RuntimeInventoryScanCancellation,
        accepted_full: Option<RuntimeDesiredEffectAdmission>,
    ) -> Self {
        Self {
            state_directory,
            deadline,
            cancellation,
            accepted_full,
        }
    }

    pub fn state_directory(&self) -> &StateDirectory {
        &self.state_directory
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn check_active(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.cancellation.is_cancelled(),
            "runtime Desired effect was cancelled"
        );
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "runtime Desired effect deadline expired"
        );
        Ok(())
    }

    pub fn accepted_full(&self) -> anyhow::Result<&RuntimeDesiredEffectAdmission> {
        self.accepted_full.as_ref().ok_or_else(|| {
            anyhow::anyhow!("runtime Desired effect lacks current-process full admission")
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(state_directory: StateDirectory, deadline: Instant) -> Self {
        Self::new(
            state_directory,
            deadline,
            RuntimeInventoryScanCancellation::new(),
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_admission(
        state_directory: StateDirectory,
        deadline: Instant,
        admission: RuntimeDesiredEffectAdmission,
    ) -> Self {
        Self::new(
            state_directory,
            deadline,
            RuntimeInventoryScanCancellation::new(),
            Some(admission),
        )
    }

    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.cancellation.cancel();
    }
}

impl RuntimePhysicalReadContext for RuntimeDesiredEffectContext {
    fn deadline(&self) -> Instant {
        RuntimeDesiredEffectContext::deadline(self)
    }

    fn check_active(&self) -> anyhow::Result<()> {
        RuntimeDesiredEffectContext::check_active(self)
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeInventoryScanContext {
    coordinates: RuntimeSpineFullScan,
    deadline: Instant,
    cancellation: RuntimeInventoryScanCancellation,
}

impl RuntimeInventoryScanContext {
    fn new(
        coordinates: RuntimeSpineFullScan,
        deadline: Instant,
        cancellation: RuntimeInventoryScanCancellation,
    ) -> Self {
        Self {
            coordinates,
            deadline,
            cancellation,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(coordinates: RuntimeSpineFullScan, deadline: Instant) -> Self {
        Self::new(
            coordinates,
            deadline,
            RuntimeInventoryScanCancellation::new(),
        )
    }

    #[cfg(test)]
    pub(crate) fn coordinates_mut(&mut self) -> &mut RuntimeSpineFullScan {
        &mut self.coordinates
    }

    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.cancellation.cancel();
    }

    pub fn coordinates(&self) -> &RuntimeSpineFullScan {
        &self.coordinates
    }

    /// The one absolute deadline shared by the scan and every underlying I/O.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn remaining(&self) -> anyhow::Result<Duration> {
        self.check_active()?;
        self.deadline()
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow::anyhow!("runtime inventory scan deadline expired"))
    }

    pub fn check_active(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.cancellation.is_cancelled(),
            "runtime inventory scan was cancelled"
        );
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "runtime inventory scan deadline expired"
        );
        Ok(())
    }
}

impl RuntimePhysicalReadContext for RuntimeInventoryScanContext {
    fn deadline(&self) -> Instant {
        RuntimeInventoryScanContext::deadline(self)
    }

    fn check_active(&self) -> anyhow::Result<()> {
        RuntimeInventoryScanContext::check_active(self)
    }
}

#[derive(Debug, Clone)]
struct RuntimeInventoryScanCancellation {
    cancelled: Arc<AtomicBool>,
}

impl RuntimeInventoryScanCancellation {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeInventoryKeyRing {
    Unavailable,
    #[allow(dead_code)] // Reserved for the non-empty scanner; not forgeable outside this crate.
    Loaded {
        version: Epoch,
        digest: Sha256Digest,
        kids: Vec<KeyId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRuntimeInventory {
    observed_at_unix_ms: UnixMillis,
    key_ring: RuntimeInventoryKeyRing,
    runtimes: Vec<ObservedRuntimeStatus>,
    residue: Vec<NodeResidue>,
}

impl CompleteRuntimeInventory {
    pub(crate) fn from_validated_coverage(
        _coverage: CompleteInventoryCoverage,
        observed_at_unix_ms: UnixMillis,
        key_ring: RuntimeInventoryKeyRing,
        runtimes: Vec<ObservedRuntimeStatus>,
        residue: Vec<NodeResidue>,
    ) -> Self {
        Self {
            observed_at_unix_ms,
            key_ring,
            runtimes,
            residue,
        }
    }

    #[cfg(test)]
    fn for_test(
        observed_at_unix_ms: UnixMillis,
        key_ring: RuntimeInventoryKeyRing,
        runtimes: Vec<ObservedRuntimeStatus>,
        residue: Vec<NodeResidue>,
    ) -> Self {
        Self {
            observed_at_unix_ms,
            key_ring,
            runtimes,
            residue,
        }
    }

    #[cfg(test)]
    pub(crate) fn observed_at_unix_ms(&self) -> UnixMillis {
        self.observed_at_unix_ms
    }

    #[cfg(test)]
    pub(crate) fn runtimes(&self) -> &[ObservedRuntimeStatus] {
        &self.runtimes
    }

    #[cfg(test)]
    pub(crate) fn residue(&self) -> &[NodeResidue] {
        &self.residue
    }
}

/// Opaque proof that each member of Runtime's closed inventory-source set was
/// visited exactly once. Only the validated aggregator can create it.
pub(crate) struct CompleteInventoryCoverage {
    _private: (),
}

pub(crate) struct InventoryCoverageAggregator {
    covered: BTreeSet<InventorySource>,
}

impl InventoryCoverageAggregator {
    pub(crate) fn new() -> Self {
        Self {
            covered: BTreeSet::new(),
        }
    }

    pub(crate) fn record(&mut self, source: InventorySource) -> anyhow::Result<()> {
        anyhow::ensure!(
            REQUIRED_INVENTORY_SOURCES.contains(&source),
            "unknown runtime inventory source {source:?}"
        );
        anyhow::ensure!(
            self.covered.insert(source),
            "runtime inventory source {source:?} was scanned more than once"
        );
        Ok(())
    }

    pub(crate) fn finish(self) -> anyhow::Result<CompleteInventoryCoverage> {
        for source in REQUIRED_INVENTORY_SOURCES {
            anyhow::ensure!(
                self.covered.contains(&source),
                "runtime inventory source {source:?} was not scanned"
            );
        }
        anyhow::ensure!(
            self.covered.len() == REQUIRED_INVENTORY_SOURCES.len(),
            "runtime inventory coverage contains an unknown source"
        );
        Ok(CompleteInventoryCoverage { _private: () })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryScanOutcome {
    Complete(CompleteRuntimeInventory),
    Incomplete {
        unavailable_sources: Vec<InventorySource>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSpineRunRetry {
    Transport(RuntimeSpineRetryReason),
    DesiredReadInProgress,
}

/// Observable result of one bounded runner iteration.
#[derive(Debug)]
pub enum RuntimeSpineRunStep {
    DesiredAccepted,
    /// A full observation physically scanned by this runner was accepted.
    /// Local service readiness additionally requires a nonempty full inventory.
    /// Runtime convergence is deliberately not a readiness prerequisite: the
    /// accepted inventory may be the Missing/Inspect baseline that admits the
    /// first effect for a newly assigned Cat.
    ObservationAccepted {
        service_ready: bool,
    },
    /// A durable observation prepared by a predecessor process was resolved.
    /// It repairs an ambiguous result but cannot establish restart admission
    /// or local readiness without a new physical scan.
    ObservationReplayed,
    /// One exact local crash-publication artifact was repaired. The next
    /// iteration must perform recovery classification again before scanning.
    PreScanRecovered {
        cat_id: Id,
    },
    EffectApplied {
        cat_id: Id,
    },
    EffectsApplied,
    EffectRetryExact {
        cat_id: Id,
    },
    EffectRefreshInventory {
        cat_id: Id,
    },
    EffectReplanDesired {
        cat_id: Id,
    },
    EffectIdentityRepairRequired {
        cat_id: Id,
    },
    EffectSessionReplacementRequired {
        cat_id: Id,
    },
    EffectStopped {
        cat_id: Id,
        reason: RuntimeDesiredEffectStopReason,
    },
    RetryExact(RuntimeSpineRunRetry),
    /// A definite server result made the retained Desired cursor unusable.
    DesiredInvalidated {
        status: u16,
        error: RuntimeSpineError,
    },
    /// The current registration/session can no longer authorize new work.
    SessionInvalid {
        status: u16,
        error: RuntimeSpineError,
    },
    /// A definite rejection that cannot safely be repaired by guessing.
    Rejected {
        status: u16,
        error: RuntimeSpineError,
    },
    RouteUnavailable,
    ScanUnavailable(anyhow::Error),
    ScanIncomplete {
        unavailable_sources: Vec<InventorySource>,
    },
    ScanDeadlineExceeded,
    PreScanRecoveryUnavailable(anyhow::Error),
    PreScanRecoveryDeadlineExceeded,
    EffectUnavailable {
        cat_id: Id,
        error: anyhow::Error,
    },
    EffectDeadlineExceeded {
        cat_id: Id,
    },
}

#[derive(Debug, Error)]
pub enum RuntimeSpineRunError {
    #[error(transparent)]
    Journal(#[from] RuntimeSpineJournalError),
    #[error("runtime-spine canonical request is invalid: {0}")]
    Contract(#[from] ContractError),
    #[error("start runtime-spine {worker} worker: {source}")]
    WorkerStart {
        worker: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("runtime-spine blocking worker stopped: {0}")]
    WorkerStopped(String),
    #[error("runtime-spine inventory scan lane is poisoned after cancellation or timeout")]
    ScanLanePoisoned,
    #[error("runtime-spine inventory scan queue is full")]
    ScanQueueFull,
    #[error("runtime-spine Desired effect lane is poisoned after cancellation or timeout")]
    EffectLanePoisoned,
    #[error("runtime-spine Desired effect queue is full")]
    EffectQueueFull,
    #[error("runtime-spine journal queue is full")]
    JournalQueueFull,
    #[error("runtime-spine worker shutdown failed: {0}")]
    WorkerShutdown(String),
    #[error("runtime-spine scanner returned an invalid outcome: {0}")]
    InvalidScan(&'static str),
    #[error("runtime-spine worker composition is invalid: {0}")]
    InvalidComposition(&'static str),
}

enum PendingWork {
    Desired(DurableRuntimeSpineRequest<DesiredReadRequest>),
    Observation(DurableRuntimeSpineRequest<NodeObservation>),
    Scan(RuntimeSpineFullScan),
}

enum JournalCommand {
    Next(tokio::sync::oneshot::Sender<Result<PendingWork, RuntimeSpineJournalError>>),
    AcceptDesired {
        snapshot: DesiredReadSnapshot,
        bytes: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>,
    },
    PrepareObservation {
        candidate: NodeObservation,
        reply: tokio::sync::oneshot::Sender<
            Result<DurableRuntimeSpineRequest<NodeObservation>, RuntimeSpineJournalError>,
        >,
    },
    AcceptObservation {
        acceptance: ObservationAcceptance,
        bytes: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>,
    },
    InvalidateDesired(tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>),
    InvalidateDesiredAfterEffect(
        tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>,
    ),
}

struct JournalLane {
    sender: Option<mpsc::SyncSender<JournalCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl JournalLane {
    fn start(
        state_directory: StateDirectory,
        registered_session: AgentSession,
    ) -> Result<Self, RuntimeSpineRunError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let guard_state = state_directory.clone();
        let guard_session = registered_session.clone();
        let thread = std::thread::Builder::new()
            .name("cats-runtime-spine-journal".to_owned())
            .spawn(move || {
                let _lane_guard =
                    match RuntimeSpineJournal::open_exclusive(&guard_state, guard_session) {
                        Ok(guard) => {
                            let _ = ready_sender.send(Ok(()));
                            guard
                        }
                        Err(error) => {
                            let _ = ready_sender.send(Err(error));
                            return;
                        }
                    };
                while let Ok(command) = receiver.recv() {
                    match command {
                        JournalCommand::Next(reply) => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    if let Some(pending) = journal.pending_observation() {
                                        return Ok(PendingWork::Observation(pending));
                                    }
                                    match journal.desired_work()? {
                                        RuntimeSpineDesiredWork::Request(request) => {
                                            Ok(PendingWork::Desired(request))
                                        }
                                        RuntimeSpineDesiredWork::Scan(_) => {
                                            Ok(PendingWork::Scan(journal.full_scan()?))
                                        }
                                    }
                                });
                            let _ = reply.send(result);
                        }
                        JournalCommand::AcceptDesired {
                            snapshot,
                            bytes,
                            reply,
                        } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| journal.accept_desired(snapshot, &bytes));
                            let _ = reply.send(result);
                        }
                        JournalCommand::PrepareObservation { candidate, reply } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| journal.prepare_observation(candidate));
                            let _ = reply.send(result);
                        }
                        JournalCommand::AcceptObservation {
                            acceptance,
                            bytes,
                            reply,
                        } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    journal.accept_observation(acceptance, &bytes)
                                });
                            let _ = reply.send(result);
                        }
                        JournalCommand::InvalidateDesired(reply) => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    journal.invalidate_desired_after_observation_rejection()
                                });
                            let _ = reply.send(result);
                        }
                        JournalCommand::InvalidateDesiredAfterEffect(reply) => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    journal.invalidate_desired_after_effect_replan()
                                });
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|source| RuntimeSpineRunError::WorkerStart {
                worker: "journal",
                source,
            })?;
        let mut lane = Self {
            sender: Some(sender),
            thread: Some(thread),
        };
        let ready = ready_receiver
            .recv()
            .map_err(|_| RuntimeSpineRunError::WorkerStopped("journal startup".to_owned()))
            .and_then(|result| result.map_err(RuntimeSpineRunError::from));
        match ready {
            Ok(()) => Ok(lane),
            Err(primary) => {
                if let Err(cleanup) = lane.shutdown_blocking() {
                    return Err(RuntimeSpineRunError::WorkerShutdown(format!(
                        "journal startup failed ({primary}); cleanup also failed ({cleanup})"
                    )));
                }
                Err(primary)
            }
        }
    }

    async fn next(&self) -> Result<PendingWork, RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::Next(reply))?;
        receive("journal", received).await
    }

    async fn accept_desired(
        &self,
        snapshot: DesiredReadSnapshot,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::AcceptDesired {
            snapshot,
            bytes,
            reply,
        })?;
        receive("journal", received).await
    }

    async fn prepare_observation(
        &self,
        candidate: NodeObservation,
    ) -> Result<DurableRuntimeSpineRequest<NodeObservation>, RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::PrepareObservation { candidate, reply })?;
        receive("journal", received).await
    }

    async fn accept_observation(
        &self,
        acceptance: ObservationAcceptance,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::AcceptObservation {
            acceptance,
            bytes,
            reply,
        })?;
        receive("journal", received).await
    }

    async fn invalidate_desired(&self) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::InvalidateDesired(reply))?;
        receive("journal", received).await
    }

    async fn invalidate_desired_after_effect_replan(&self) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::InvalidateDesiredAfterEffect(reply))?;
        receive("journal", received).await
    }

    fn send(&self, command: JournalCommand) -> Result<(), RuntimeSpineRunError> {
        match self
            .sender
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("journal".to_owned()))?
            .try_send(command)
        {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => Err(RuntimeSpineRunError::JournalQueueFull),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                Err(RuntimeSpineRunError::WorkerStopped("journal".to_owned()))
            }
        }
    }

    fn shutdown_blocking(&mut self) -> Result<(), RuntimeSpineRunError> {
        self.sender.take();
        join_worker_blocking("journal", self.thread.take())
    }
}

impl Drop for JournalLane {
    fn drop(&mut self) {
        let _ = self.shutdown_blocking();
    }
}

fn open_journal(
    state_directory: &StateDirectory,
    registered_session: &AgentSession,
) -> Result<RuntimeSpineJournal, RuntimeSpineJournalError> {
    RuntimeSpineJournal::open_under_lane_lock(state_directory, registered_session.clone())
}

enum ScanCommand {
    Complete {
        context: RuntimeInventoryScanContext,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<RuntimeInventoryScanOutcome>>,
    },
}

#[derive(Default)]
struct ScanLaneState {
    poisoned: AtomicBool,
    active: Mutex<Option<RuntimeInventoryScanCancellation>>,
}

struct ScanLane {
    sender: Option<mpsc::SyncSender<ScanCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
    state: Arc<ScanLaneState>,
}

impl ScanLane {
    fn start(scanner: Arc<dyn RuntimeInventoryScanner>) -> Result<Self, RuntimeSpineRunError> {
        // One queued request is the complete non-authoritative buffer. A
        // cancelled in-flight request poisons the lane instead of permitting a
        // second scan to overlap it.
        let (sender, receiver) = mpsc::sync_channel(1);
        let state = Arc::new(ScanLaneState::default());
        let worker_state = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name("cats-runtime-spine-scan".to_owned())
            .spawn(move || {
                while let Ok(ScanCommand::Complete { context, reply }) = receiver.recv() {
                    let result = if context.check_active().is_ok() {
                        scanner.scan_complete(context)
                    } else {
                        Err(anyhow::anyhow!(
                            "runtime inventory scan was cancelled before execution"
                        ))
                    };
                    active_scan(&worker_state.active).take();
                    // If the async deadline or caller cancellation already
                    // won, the receiver is gone and the late result is
                    // deliberately discarded.
                    let _ = reply.send(result);
                }
            })
            .map_err(|source| RuntimeSpineRunError::WorkerStart {
                worker: "inventory scan",
                source,
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
            state,
        })
    }

    async fn scan_complete(
        &self,
        coordinates: RuntimeSpineFullScan,
        deadline: Instant,
    ) -> Result<ScanWait, RuntimeSpineRunError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            return Err(RuntimeSpineRunError::ScanLanePoisoned);
        }
        if Instant::now() >= deadline {
            return Ok(ScanWait::DeadlineExceeded);
        }
        let cancellation = RuntimeInventoryScanCancellation::new();
        let context = RuntimeInventoryScanContext::new(coordinates, deadline, cancellation.clone());
        {
            let mut active = active_scan(&self.state.active);
            if active.is_some() {
                return Err(RuntimeSpineRunError::ScanQueueFull);
            }
            *active = Some(cancellation.clone());
        }
        let (reply, received) = tokio::sync::oneshot::channel();
        let command = ScanCommand::Complete { context, reply };
        let send_result = self
            .sender
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("inventory scan".to_owned()))?
            .try_send(command);
        if let Err(error) = send_result {
            active_scan(&self.state.active).take();
            return match error {
                mpsc::TrySendError::Full(_) => Err(RuntimeSpineRunError::ScanQueueFull),
                mpsc::TrySendError::Disconnected(_) => Err(RuntimeSpineRunError::WorkerStopped(
                    "inventory scan".to_owned(),
                )),
            };
        }

        let mut guard = ActiveScanGuard {
            cancellation,
            state: Arc::clone(&self.state),
            armed: true,
        };
        let timed =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), received).await;
        match timed {
            Ok(Ok(result)) => {
                guard.disarm();
                if Instant::now() >= deadline {
                    Ok(ScanWait::DeadlineExceeded)
                } else {
                    Ok(ScanWait::Finished(result))
                }
            }
            Ok(Err(_)) => {
                guard.poison();
                Err(RuntimeSpineRunError::WorkerStopped(
                    "inventory scan".to_owned(),
                ))
            }
            Err(_) => {
                guard.poison();
                Ok(ScanWait::DeadlineExceeded)
            }
        }
    }

    fn cancel_and_poison(&self) {
        self.state.poisoned.store(true, Ordering::Release);
        if let Some(cancellation) = active_scan(&self.state.active).as_ref() {
            cancellation.cancel();
        }
    }

    fn shutdown_blocking(&mut self) -> Result<(), RuntimeSpineRunError> {
        self.cancel_and_poison();
        self.sender.take();
        join_worker_blocking("inventory scan", self.thread.take())
    }
}

impl Drop for ScanLane {
    fn drop(&mut self) {
        let _ = self.shutdown_blocking();
    }
}

enum EffectCommand {
    Apply {
        context: Box<RuntimeDesiredEffectContext>,
        desired: Box<DesiredRuntimeSpec>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<RuntimeDesiredEffectOutcome>>,
    },
    Recover {
        context: Box<RuntimePreScanRecoveryContext>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<RuntimePreScanRecoveryOutcome>>,
    },
}

#[derive(Default)]
struct EffectLaneState {
    poisoned: AtomicBool,
    active: Mutex<Option<RuntimeInventoryScanCancellation>>,
}

struct EffectLane {
    sender: Option<mpsc::SyncSender<EffectCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
    state: Arc<EffectLaneState>,
    has_recovery: bool,
}

impl EffectLane {
    fn start(
        effect: Arc<dyn RuntimeDesiredEffect>,
        recovery: Option<Arc<dyn RuntimePreScanRecovery>>,
    ) -> Result<Self, RuntimeSpineRunError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let state = Arc::new(EffectLaneState::default());
        let worker_state = Arc::clone(&state);
        let has_recovery = recovery.is_some();
        let thread = std::thread::Builder::new()
            .name("cats-runtime-spine-effect".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        EffectCommand::Apply {
                            context,
                            desired,
                            reply,
                        } => {
                            let result = if context.check_active().is_ok() {
                                effect.apply(*context, &desired)
                            } else {
                                Err(anyhow::anyhow!(
                                    "runtime Desired effect was cancelled before execution"
                                ))
                            };
                            active_effect(&worker_state.active).take();
                            let _ = reply.send(result);
                        }
                        EffectCommand::Recover { context, reply } => {
                            let result = if context.check_active().is_ok() {
                                recovery.as_ref().map_or_else(
                                    || Ok(RuntimePreScanRecoveryOutcome::NoChange),
                                    |recovery| recovery.recover_one(*context),
                                )
                            } else {
                                Err(anyhow::anyhow!(
                                    "runtime pre-scan recovery was cancelled before execution"
                                ))
                            };
                            active_effect(&worker_state.active).take();
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|source| RuntimeSpineRunError::WorkerStart {
                worker: "Desired effect",
                source,
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
            state,
            has_recovery,
        })
    }

    fn has_recovery(&self) -> bool {
        self.has_recovery
    }

    async fn recover(
        &self,
        state_directory: StateDirectory,
        coordinates: RuntimeSpineFullScan,
        deadline: Instant,
    ) -> Result<RecoveryWait, RuntimeSpineRunError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            return Err(RuntimeSpineRunError::EffectLanePoisoned);
        }
        if Instant::now() >= deadline {
            return Ok(RecoveryWait::DeadlineExceeded);
        }
        let cancellation = RuntimeInventoryScanCancellation::new();
        let context = RuntimePreScanRecoveryContext::new(
            state_directory,
            coordinates,
            deadline,
            cancellation.clone(),
        );
        {
            let mut active = active_effect(&self.state.active);
            if active.is_some() {
                return Err(RuntimeSpineRunError::EffectQueueFull);
            }
            *active = Some(cancellation.clone());
        }
        let (reply, received) = tokio::sync::oneshot::channel();
        let command = EffectCommand::Recover {
            context: Box::new(context),
            reply,
        };
        let send_result = self
            .sender
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("pre-scan recovery".to_owned()))?
            .try_send(command);
        if let Err(error) = send_result {
            active_effect(&self.state.active).take();
            return match error {
                mpsc::TrySendError::Full(_) => Err(RuntimeSpineRunError::EffectQueueFull),
                mpsc::TrySendError::Disconnected(_) => Err(RuntimeSpineRunError::WorkerStopped(
                    "pre-scan recovery".to_owned(),
                )),
            };
        }

        let mut guard = ActiveEffectGuard {
            cancellation,
            state: Arc::clone(&self.state),
            armed: true,
        };
        match receive_effect_result_until(received, deadline).await {
            EffectReceive::Delivered(result) => {
                guard.disarm();
                Ok(RecoveryWait::Finished(result))
            }
            EffectReceive::Closed => {
                guard.poison();
                Err(RuntimeSpineRunError::WorkerStopped(
                    "pre-scan recovery".to_owned(),
                ))
            }
            EffectReceive::DeadlineExceeded => {
                guard.poison();
                Ok(RecoveryWait::DeadlineExceeded)
            }
        }
    }

    async fn apply(
        &self,
        state_directory: StateDirectory,
        desired: DesiredRuntimeSpec,
        accepted_full: Option<RuntimeDesiredEffectAdmission>,
        deadline: Instant,
    ) -> Result<EffectWait, RuntimeSpineRunError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            return Err(RuntimeSpineRunError::EffectLanePoisoned);
        }
        if Instant::now() >= deadline {
            return Ok(EffectWait::DeadlineExceeded);
        }
        let cancellation = RuntimeInventoryScanCancellation::new();
        let context = RuntimeDesiredEffectContext::new(
            state_directory,
            deadline,
            cancellation.clone(),
            accepted_full,
        );
        {
            let mut active = active_effect(&self.state.active);
            if active.is_some() {
                return Err(RuntimeSpineRunError::EffectQueueFull);
            }
            *active = Some(cancellation.clone());
        }
        let (reply, received) = tokio::sync::oneshot::channel();
        let command = EffectCommand::Apply {
            context: Box::new(context),
            desired: Box::new(desired),
            reply,
        };
        let send_result = self
            .sender
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("Desired effect".to_owned()))?
            .try_send(command);
        if let Err(error) = send_result {
            active_effect(&self.state.active).take();
            return match error {
                mpsc::TrySendError::Full(_) => Err(RuntimeSpineRunError::EffectQueueFull),
                mpsc::TrySendError::Disconnected(_) => Err(RuntimeSpineRunError::WorkerStopped(
                    "Desired effect".to_owned(),
                )),
            };
        }

        let mut guard = ActiveEffectGuard {
            cancellation,
            state: Arc::clone(&self.state),
            armed: true,
        };
        match receive_effect_result_until(received, deadline).await {
            EffectReceive::Delivered(result) => {
                guard.disarm();
                // A completed typed outcome is the authoritative phase
                // boundary even when it became ready together with the outer
                // deadline. Discarding it could replay a physical step from
                // the old full-inventory admission.
                Ok(EffectWait::Finished(result))
            }
            EffectReceive::Closed => {
                guard.poison();
                Err(RuntimeSpineRunError::WorkerStopped(
                    "Desired effect".to_owned(),
                ))
            }
            EffectReceive::DeadlineExceeded => {
                guard.poison();
                Ok(EffectWait::DeadlineExceeded)
            }
        }
    }

    fn is_poisoned(&self) -> bool {
        self.state.poisoned.load(Ordering::Acquire)
    }

    fn cancel_and_poison(&self) {
        self.state.poisoned.store(true, Ordering::Release);
        if let Some(cancellation) = active_effect(&self.state.active).as_ref() {
            cancellation.cancel();
        }
    }

    fn shutdown_blocking(&mut self) -> Result<(), RuntimeSpineRunError> {
        self.cancel_and_poison();
        self.sender.take();
        join_worker_blocking("Desired effect", self.thread.take())
    }
}

impl Drop for EffectLane {
    fn drop(&mut self) {
        let _ = self.shutdown_blocking();
    }
}

fn active_effect(
    mutex: &Mutex<Option<RuntimeInventoryScanCancellation>>,
) -> MutexGuard<'_, Option<RuntimeInventoryScanCancellation>> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

enum EffectWait {
    Finished(anyhow::Result<RuntimeDesiredEffectOutcome>),
    DeadlineExceeded,
}

enum RecoveryWait {
    Finished(anyhow::Result<RuntimePreScanRecoveryOutcome>),
    DeadlineExceeded,
}

enum EffectReceive<T> {
    Delivered(anyhow::Result<T>),
    Closed,
    DeadlineExceeded,
}

/// Resolve the effect result/deadline race with the typed result as the
/// explicit winner when both are ready. The final `try_recv` closes the small
/// scheduler window between the deadline branch becoming ready and it being
/// selected; a result not yet delivered at that point remains unknown.
async fn receive_effect_result_until<T>(
    mut received: tokio::sync::oneshot::Receiver<anyhow::Result<T>>,
    deadline: Instant,
) -> EffectReceive<T> {
    let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timer);
    tokio::select! {
        biased;
        result = &mut received => match result {
            Ok(result) => EffectReceive::Delivered(result),
            Err(_) => EffectReceive::Closed,
        },
        () = &mut timer => match received.try_recv() {
            Ok(result) => EffectReceive::Delivered(result),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => EffectReceive::Closed,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                EffectReceive::DeadlineExceeded
            }
        },
    }
}

struct ActiveEffectGuard {
    cancellation: RuntimeInventoryScanCancellation,
    state: Arc<EffectLaneState>,
    armed: bool,
}

impl ActiveEffectGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn poison(&mut self) {
        if self.armed {
            self.cancellation.cancel();
            self.state.poisoned.store(true, Ordering::Release);
            self.armed = false;
        }
    }
}

impl Drop for ActiveEffectGuard {
    fn drop(&mut self) {
        self.poison();
    }
}

fn active_scan(
    mutex: &Mutex<Option<RuntimeInventoryScanCancellation>>,
) -> MutexGuard<'_, Option<RuntimeInventoryScanCancellation>> {
    match mutex.lock() {
        Ok(guard) => guard,
        // The token has no multi-field invariant. Recovering it lets shutdown
        // still cancel and join a scanner after a worker panic.
        Err(poisoned) => poisoned.into_inner(),
    }
}

enum ScanWait {
    Finished(anyhow::Result<RuntimeInventoryScanOutcome>),
    DeadlineExceeded,
}

struct ActiveScanGuard {
    cancellation: RuntimeInventoryScanCancellation,
    state: Arc<ScanLaneState>,
    armed: bool,
}

impl ActiveScanGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn poison(&mut self) {
        if self.armed {
            self.cancellation.cancel();
            self.state.poisoned.store(true, Ordering::Release);
            self.armed = false;
        }
    }
}

impl Drop for ActiveScanGuard {
    fn drop(&mut self) {
        self.poison();
    }
}

fn join_worker_blocking(
    worker: &'static str,
    thread: Option<std::thread::JoinHandle<()>>,
) -> Result<(), RuntimeSpineRunError> {
    let Some(thread) = thread else {
        return Ok(());
    };
    thread
        .join()
        .map_err(|_| RuntimeSpineRunError::WorkerStopped(format!("{worker} panicked")))
}

async fn receive<T>(
    worker: &'static str,
    received: tokio::sync::oneshot::Receiver<Result<T, RuntimeSpineJournalError>>,
) -> Result<T, RuntimeSpineRunError> {
    received
        .await
        .map_err(|_| RuntimeSpineRunError::WorkerStopped(worker.to_owned()))?
        .map_err(RuntimeSpineRunError::from)
}

/// Drives the signed spine without doing filesystem or inventory work on the
/// async executor. Calling `run_once_with_deadlines` concurrently is
/// intentionally prevented by its `&mut self` receiver.
pub struct RuntimeSpineRunner {
    state_directory: StateDirectory,
    registered_session: AgentSession,
    client: RuntimeSpineHttpClient,
    journal_lane: Option<JournalLane>,
    scan_lane: Option<ScanLane>,
    effect_lane: Option<EffectLane>,
    current_process_scan_observation_id: Option<RandomId128>,
    effect_admission_open: bool,
    effect_admission: Option<RuntimeDesiredEffectAdmission>,
    pending_effects: VecDeque<DesiredRuntimeSpec>,
}

impl std::fmt::Debug for RuntimeSpineRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeSpineRunner")
            .field("state_directory", &self.state_directory)
            .field("registered_session", &self.registered_session)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl RuntimeSpineRunner {
    pub fn new(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
    ) -> Result<Self, RuntimeSpineRunError> {
        Self::new_inner(
            state_directory,
            registered_session,
            client,
            scanner,
            None,
            None,
        )
    }

    /// Production composition with the only typed Desired-to-effect seam.
    /// The executor remains unreachable until a current-process full physical
    /// inventory has been accepted and a fresh Desired snapshot is persisted.
    pub fn new_with_desired_effects(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
        effect: Arc<dyn RuntimeDesiredEffect>,
    ) -> Result<Self, RuntimeSpineRunError> {
        Self::new_inner(
            state_directory,
            registered_session,
            client,
            scanner,
            Some(effect),
            None,
        )
    }

    /// Production composition with a serialized, typed local publication
    /// recovery step before each physical scan.
    pub(crate) fn new_with_recovery_and_desired_effects(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
        recovery: Arc<dyn RuntimePreScanRecovery>,
        effect: Arc<dyn RuntimeDesiredEffect>,
    ) -> Result<Self, RuntimeSpineRunError> {
        Self::new_inner(
            state_directory,
            registered_session,
            client,
            scanner,
            Some(effect),
            Some(recovery),
        )
    }

    fn new_inner(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
        effect: Option<Arc<dyn RuntimeDesiredEffect>>,
        recovery: Option<Arc<dyn RuntimePreScanRecovery>>,
    ) -> Result<Self, RuntimeSpineRunError> {
        // Start the non-authoritative scanner first. If acquiring the journal
        // flock then fails, the effect and ScanLane Drops join the already
        // started threads before this constructor returns.
        let scan_lane = ScanLane::start(scanner)?;
        if recovery.is_some() && effect.is_none() {
            return Err(RuntimeSpineRunError::InvalidComposition(
                "pre-scan recovery requires the serialized Desired mutation lane",
            ));
        }
        let effect_lane = effect
            .map(|effect| EffectLane::start(effect, recovery))
            .transpose()?;
        let journal_lane = JournalLane::start(state_directory.clone(), registered_session.clone())?;
        Ok(Self {
            state_directory,
            registered_session,
            client,
            journal_lane: Some(journal_lane),
            scan_lane: Some(scan_lane),
            effect_lane,
            current_process_scan_observation_id: None,
            effect_admission_open: false,
            effect_admission: None,
            pending_effects: VecDeque::new(),
        })
    }

    pub async fn run_once_with_deadlines(
        &mut self,
        deadlines: RuntimeSpineRunDeadlines,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        // A timed-out blocking effect may still be returning from its provider
        // call. Do not start a fresh scan beside that unknown physical phase;
        // shutdown joins it before a successor runner establishes new
        // full-inventory admission.
        if self
            .effect_lane
            .as_ref()
            .is_some_and(EffectLane::is_poisoned)
        {
            return Err(RuntimeSpineRunError::EffectLanePoisoned);
        }
        if !self.pending_effects.is_empty() {
            return self.run_next_effect(deadlines.effect_step).await;
        }
        let work = self.journal_lane()?.next().await?;

        match work {
            PendingWork::Desired(request) => self.send_desired(request).await,
            PendingWork::Observation(request) => self.send_observation(request).await,
            PendingWork::Scan(scan) => {
                if self
                    .effect_lane
                    .as_ref()
                    .is_some_and(EffectLane::has_recovery)
                {
                    match self
                        .effect_lane()?
                        .recover(
                            self.state_directory.clone(),
                            scan.clone(),
                            deadlines.effect_step,
                        )
                        .await?
                    {
                        RecoveryWait::Finished(Ok(RuntimePreScanRecoveryOutcome::Recovered {
                            cat_id,
                        })) => return Ok(RuntimeSpineRunStep::PreScanRecovered { cat_id }),
                        RecoveryWait::Finished(Ok(RuntimePreScanRecoveryOutcome::NoChange)) => {}
                        RecoveryWait::Finished(Err(error)) => {
                            return Ok(RuntimeSpineRunStep::PreScanRecoveryUnavailable(error));
                        }
                        RecoveryWait::DeadlineExceeded => {
                            return Ok(RuntimeSpineRunStep::PreScanRecoveryDeadlineExceeded);
                        }
                    }
                }
                let coordinates = scan.clone();
                let outcome = match self
                    .scan_lane()?
                    .scan_complete(scan, deadlines.scan)
                    .await?
                {
                    ScanWait::Finished(Ok(outcome)) => outcome,
                    ScanWait::Finished(Err(error)) => {
                        return Ok(RuntimeSpineRunStep::ScanUnavailable(error));
                    }
                    ScanWait::DeadlineExceeded => {
                        return Ok(RuntimeSpineRunStep::ScanDeadlineExceeded);
                    }
                };
                if Instant::now() >= deadlines.scan {
                    return Ok(RuntimeSpineRunStep::ScanDeadlineExceeded);
                }
                let inventory = match outcome {
                    RuntimeInventoryScanOutcome::Complete(inventory) => inventory,
                    RuntimeInventoryScanOutcome::Incomplete {
                        unavailable_sources,
                    } => {
                        if unavailable_sources.is_empty() {
                            return Err(RuntimeSpineRunError::InvalidScan(
                                "an incomplete scan has no unavailable source",
                            ));
                        }
                        return Ok(RuntimeSpineRunStep::ScanIncomplete {
                            unavailable_sources,
                        });
                    }
                };
                let candidate = build_full_observation(coordinates, inventory)?;
                let request = self.journal_lane()?.prepare_observation(candidate).await?;
                self.current_process_scan_observation_id =
                    Some(request.value().observation_id.clone());
                self.send_observation(request).await
            }
        }
    }

    #[cfg(test)]
    async fn run_once_until(
        &mut self,
        shared_deadline: Instant,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        self.run_once_with_deadlines(RuntimeSpineRunDeadlines {
            scan: shared_deadline,
            effect_step: shared_deadline,
        })
        .await
    }

    /// Stops the ordered effect, scan and journal workers and waits until no
    /// late filesystem or physical action can outlive this runner. Production
    /// session replacement and process shutdown must use this boundary before
    /// constructing a successor.
    pub async fn shutdown(mut self) -> Result<(), RuntimeSpineRunError> {
        let workers = self.take_workers();
        // `spawn_blocking` keeps running when this future is cancelled. It owns
        // all lanes, so cancellation cannot detach a Rust thread or drop the
        // journal flock before effects and the scanner have actually exited.
        tokio::task::spawn_blocking(move || workers.shutdown_blocking())
            .await
            .map_err(|error| {
                RuntimeSpineRunError::WorkerShutdown(format!("shutdown join task failed: {error}"))
            })?
    }

    fn journal_lane(&self) -> Result<&JournalLane, RuntimeSpineRunError> {
        self.journal_lane
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("journal".to_owned()))
    }

    fn scan_lane(&self) -> Result<&ScanLane, RuntimeSpineRunError> {
        self.scan_lane
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("inventory scan".to_owned()))
    }

    fn effect_lane(&self) -> Result<&EffectLane, RuntimeSpineRunError> {
        self.effect_lane
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("Desired effect".to_owned()))
    }

    fn take_workers(&mut self) -> RunnerWorkers {
        RunnerWorkers {
            effect_lane: self.effect_lane.take(),
            scan_lane: self.scan_lane.take(),
            journal_lane: self.journal_lane.take(),
        }
    }

    async fn run_next_effect(
        &mut self,
        deadline: Instant,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        let desired = self
            .pending_effects
            .front()
            .cloned()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("Desired effect".to_owned()))?;
        let cat_id = desired.cat_id.clone();
        let wait = match self
            .effect_lane()?
            .apply(
                self.state_directory.clone(),
                desired,
                self.effect_admission.clone(),
                deadline,
            )
            .await
        {
            Ok(wait) => wait,
            Err(error) => {
                // A closed or poisoned worker cannot prove whether the queued
                // effect linearized. Never preserve the old admission batch.
                self.clear_effect_batch();
                return Err(error);
            }
        };
        match wait {
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::Applied)) => {
                self.pending_effects.pop_front();
                if self.pending_effects.is_empty() {
                    self.effect_admission = None;
                    Ok(RuntimeSpineRunStep::EffectsApplied)
                } else {
                    Ok(RuntimeSpineRunStep::EffectApplied { cat_id })
                }
            }
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::RetryExact)) => {
                Ok(RuntimeSpineRunStep::EffectRetryExact { cat_id })
            }
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::RefreshInventory)) => {
                self.clear_effect_batch();
                Ok(RuntimeSpineRunStep::EffectRefreshInventory { cat_id })
            }
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::ReplanDesired)) => {
                // Clear the in-memory admission before the fallible durable
                // invalidation. If persistence itself fails, the runner stops
                // without making the old batch runnable again.
                self.clear_effect_batch();
                self.journal_lane()?
                    .invalidate_desired_after_effect_replan()
                    .await?;
                Ok(RuntimeSpineRunStep::EffectReplanDesired { cat_id })
            }
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired)) => {
                self.clear_effect_batch();
                Ok(RuntimeSpineRunStep::EffectIdentityRepairRequired { cat_id })
            }
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired)) => {
                self.clear_effect_batch();
                Ok(RuntimeSpineRunStep::EffectSessionReplacementRequired { cat_id })
            }
            EffectWait::Finished(Ok(RuntimeDesiredEffectOutcome::Stop(reason))) => {
                self.clear_effect_batch();
                Ok(RuntimeSpineRunStep::EffectStopped { cat_id, reason })
            }
            EffectWait::Finished(Err(error)) => {
                // `anyhow::Error` carries no proof that the effect remained
                // pre-linearization. Conservatively discard the entire old
                // admission batch; the durable Desired journal now leads the
                // next iteration through a fresh physical scan.
                self.clear_effect_batch();
                Ok(RuntimeSpineRunStep::EffectUnavailable { cat_id, error })
            }
            EffectWait::DeadlineExceeded => {
                // The worker is cancelled and poisoned because its phase is
                // unknown. Never replay this Cat or another Cat from the old
                // accepted inventory. Shutdown/restart joins the late worker;
                // the successor can establish a new full-scan admission.
                self.clear_effect_batch();
                Ok(RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id })
            }
        }
    }

    fn clear_effect_batch(&mut self) {
        self.pending_effects.clear();
        self.effect_admission = None;
        self.effect_admission_open = false;
    }

    async fn send_desired(
        &mut self,
        request: DurableRuntimeSpineRequest<DesiredReadRequest>,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        match self.client.desired_read(request.bytes()).await? {
            RuntimeSpineAttempt::Accepted(accepted) => {
                let desired_specs = accepted.value.desired_specs.clone();
                if self.effect_lane.is_some() && self.effect_admission_open {
                    self.effect_admission
                        .as_mut()
                        .ok_or(RuntimeSpineRunError::InvalidScan(
                            "effect admission opened without its accepted full inventory",
                        ))?
                        .bind_desired_read_position(&accepted.value)
                        .map_err(|_| {
                            RuntimeSpineRunError::InvalidScan(
                                "accepted Desired does not bind the effect admission",
                            )
                        })?;
                }
                self.journal_lane()?
                    .accept_desired(accepted.value, accepted.bytes)
                    .await?;
                if self.effect_lane.is_some() && self.effect_admission_open {
                    self.effect_admission_open = false;
                    self.pending_effects = desired_specs.into();
                    if self.pending_effects.is_empty() {
                        self.effect_admission = None;
                        Ok(RuntimeSpineRunStep::EffectsApplied)
                    } else {
                        Ok(RuntimeSpineRunStep::DesiredAccepted)
                    }
                } else {
                    Ok(RuntimeSpineRunStep::DesiredAccepted)
                }
            }
            RuntimeSpineAttempt::RetryExact(reason) => Ok(RuntimeSpineRunStep::RetryExact(
                RuntimeSpineRunRetry::Transport(reason),
            )),
            RuntimeSpineAttempt::RouteUnavailable => Ok(RuntimeSpineRunStep::RouteUnavailable),
            RuntimeSpineAttempt::Rejected { status, error } => {
                if desired_in_progress(&error) {
                    Ok(RuntimeSpineRunStep::RetryExact(
                        RuntimeSpineRunRetry::DesiredReadInProgress,
                    ))
                } else if invalid_session(&error) {
                    Ok(RuntimeSpineRunStep::SessionInvalid { status, error })
                } else {
                    Ok(RuntimeSpineRunStep::Rejected { status, error })
                }
            }
        }
    }

    async fn send_observation(
        &mut self,
        request: DurableRuntimeSpineRequest<NodeObservation>,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        match self.client.observation(request.bytes()).await? {
            RuntimeSpineAttempt::Accepted(accepted) => {
                let establishes_effect_admission = request.value().complete_inventory
                    && self.current_process_scan_observation_id.as_ref()
                        == Some(&request.value().observation_id);
                let service_ready = establishes_effect_admission
                    && observation_opens_service_readiness(request.value());
                let admission = if establishes_effect_admission {
                    Some(
                        RuntimeDesiredEffectAdmission::from_acceptance(
                            self.registered_session.clone(),
                            request.value().clone(),
                            &accepted.value,
                        )
                        .ok_or(RuntimeSpineRunError::InvalidScan(
                            "accepted full observation does not form one effect admission",
                        ))?,
                    )
                } else {
                    None
                };
                self.journal_lane()?
                    .accept_observation(accepted.value, accepted.bytes)
                    .await?;
                self.current_process_scan_observation_id = None;
                if establishes_effect_admission {
                    self.effect_admission = admission;
                    self.effect_admission_open = true;
                    Ok(RuntimeSpineRunStep::ObservationAccepted { service_ready })
                } else {
                    Ok(RuntimeSpineRunStep::ObservationReplayed)
                }
            }
            RuntimeSpineAttempt::RetryExact(reason) => Ok(RuntimeSpineRunStep::RetryExact(
                RuntimeSpineRunRetry::Transport(reason),
            )),
            RuntimeSpineAttempt::RouteUnavailable => Ok(RuntimeSpineRunStep::RouteUnavailable),
            RuntimeSpineAttempt::Rejected { status, error } => {
                match desired_invalidation_binding(&error, request.value()) {
                    DesiredInvalidationBinding::Exact => {
                        self.journal_lane()?.invalidate_desired().await?;
                        self.current_process_scan_observation_id = None;
                        Ok(RuntimeSpineRunStep::DesiredInvalidated { status, error })
                    }
                    DesiredInvalidationBinding::Mismatch => Ok(RuntimeSpineRunStep::RetryExact(
                        RuntimeSpineRunRetry::Transport(RuntimeSpineRetryReason::InvalidResponse),
                    )),
                    DesiredInvalidationBinding::NotApplicable if invalid_session(&error) => {
                        Ok(RuntimeSpineRunStep::SessionInvalid { status, error })
                    }
                    DesiredInvalidationBinding::NotApplicable => {
                        Ok(RuntimeSpineRunStep::Rejected { status, error })
                    }
                }
            }
        }
    }
}

fn observation_opens_service_readiness(observation: &NodeObservation) -> bool {
    observation.complete_inventory
        && observation.inventory_digest.is_some()
        && !observation.runtimes.is_empty()
}

impl Drop for RuntimeSpineRunner {
    fn drop(&mut self) {
        // This fallback is intentionally synchronous: dropping a runner may
        // not detach any owned thread. Production callers use `shutdown`,
        // which moves the same ordered join onto Tokio's blocking pool.
        let _ = self.take_workers().shutdown_blocking();
    }
}

struct RunnerWorkers {
    effect_lane: Option<EffectLane>,
    scan_lane: Option<ScanLane>,
    journal_lane: Option<JournalLane>,
}

impl RunnerWorkers {
    fn shutdown_blocking(mut self) -> Result<(), RuntimeSpineRunError> {
        if let Some(effect) = self.effect_lane.as_ref() {
            effect.cancel_and_poison();
        }
        if let Some(scan) = self.scan_lane.as_ref() {
            scan.cancel_and_poison();
        }
        let effect_result = self
            .effect_lane
            .as_mut()
            .map_or(Ok(()), EffectLane::shutdown_blocking);
        let scan_result = self
            .scan_lane
            .as_mut()
            .map_or(Ok(()), ScanLane::shutdown_blocking);
        // The journal lane, and therefore its flock, remains alive until the
        // effect and scan lanes have been cancelled and joined. Always attempt
        // every join even if an earlier worker panicked.
        let journal_result = self
            .journal_lane
            .as_mut()
            .map_or(Ok(()), JournalLane::shutdown_blocking);
        match (effect_result, scan_result, journal_result) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (effect, scan, journal) => {
                let mut failures = Vec::new();
                if let Err(error) = effect {
                    failures.push(format!("Desired effect: {error}"));
                }
                if let Err(error) = scan {
                    failures.push(format!("inventory scan: {error}"));
                }
                if let Err(error) = journal {
                    failures.push(format!("journal: {error}"));
                }
                Err(RuntimeSpineRunError::WorkerShutdown(failures.join("; ")))
            }
        }
    }
}

fn build_full_observation(
    scan: RuntimeSpineFullScan,
    inventory: CompleteRuntimeInventory,
) -> Result<NodeObservation, ContractError> {
    let (key_ring_version, key_ring_digest, loaded_kids) = match inventory.key_ring {
        RuntimeInventoryKeyRing::Unavailable => (None, None, Vec::new()),
        RuntimeInventoryKeyRing::Loaded {
            version,
            digest,
            kids,
        } => (Some(version), Some(digest), kids),
    };
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .expect("a simple UUID is a valid RandomId128"),
        node_id: scan.session.node_id,
        node_boot_id: scan.session.node_boot_id,
        agent_instance_id: scan.session.agent_instance_id,
        agent_session_epoch: scan.session.agent_session_epoch,
        heartbeat_sequence: scan.heartbeat_sequence,
        observed_at_unix_ms: inventory.observed_at_unix_ms,
        complete_inventory: true,
        inventory_epoch: scan.inventory_epoch,
        inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
        inventory_read_position: Some(scan.desired.read_position),
        key_ring_version,
        key_ring_digest,
        loaded_kids,
        runtimes: inventory.runtimes,
        residue: inventory.residue,
    };
    observation.inventory_digest = Some(inventory_digest(&observation)?);
    Ok(observation)
}

fn desired_in_progress(error: &RuntimeSpineError) -> bool {
    matches!(
        error.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(
                contract_error.error.as_ref(),
                ContractErrorDetail::DesiredReadInProgress { .. }
            )
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesiredInvalidationBinding {
    Exact,
    Mismatch,
    NotApplicable,
}

fn desired_invalidation_binding(
    error: &RuntimeSpineError,
    pending: &NodeObservation,
) -> DesiredInvalidationBinding {
    let RuntimeSpineErrorDetail::ContractError { contract_error } = error.error.as_ref() else {
        return DesiredInvalidationBinding::NotApplicable;
    };
    let (node_id, agent_session_epoch, read_position) = match contract_error.error.as_ref() {
        ContractErrorDetail::InventoryReadPositionExpired {
            node_id,
            agent_session_epoch,
            read_position,
            ..
        }
        | ContractErrorDetail::AssignedSetChanged {
            node_id,
            agent_session_epoch,
            read_position,
        } => (node_id, agent_session_epoch, read_position),
        _ => return DesiredInvalidationBinding::NotApplicable,
    };
    if node_id == &pending.node_id
        && agent_session_epoch == &pending.agent_session_epoch
        && Some(*read_position) == pending.inventory_read_position
    {
        DesiredInvalidationBinding::Exact
    } else {
        DesiredInvalidationBinding::Mismatch
    }
}

fn invalid_session(error: &RuntimeSpineError) -> bool {
    match error.error.as_ref() {
        RuntimeSpineErrorDetail::AuthenticationFailed
        | RuntimeSpineErrorDetail::IdentityNotEligible => true,
        RuntimeSpineErrorDetail::ContractError { contract_error } => matches!(
            contract_error.error.as_ref(),
            ContractErrorDetail::MissingAgentSession { .. }
                | ContractErrorDetail::StaleSession { .. }
                | ContractErrorDetail::WrongSession { .. }
                | ContractErrorDetail::SessionExpired { .. }
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::io::Read as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc as test_mpsc, Mutex};

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
    use cats_api::runtime_reconciliation::{
        decode_agent_session, decode_desired_read_request, decode_desired_read_snapshot,
        decode_node_observation, encode_desired_read_snapshot, encode_observation_acceptance,
        encode_runtime_spine_error, spec_digest, AdmissionInventoryAttestation,
        AppliedDesiredEvidence, AssignedKind, AssignedPlacement, CheckpointEvidence,
        ContractVersion, GuestTransportEvidence, HostPath, Id, Ipv4Address, IsolatedIpv4Kind,
        LifecycleAdmission, MacAddress, NetworkConfig, ObservationAcceptance,
        ObservationInventoryAcceptance, ReconcileStep, Revision, RuntimeConfig,
        RuntimeSpineErrorDetail, RuntimeTarget, RuntimeTransition, Sequence, SessionBinding,
        UnixMillis, WarmSnapshotEvidence, DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
        NODE_OBSERVATION_MAX_WIRE_BYTES,
    };
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use crate::ch::{BlockPath, ChConfig, ChNetwork};
    use crate::runtime_spine::{ProductionRuntimeDesiredEffect, RuntimeLaunchPort};

    use super::*;

    const SESSION: &[u8] = br#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","immutable_host_id":"host_a","lease_deadline_unix_ms":1720000060000,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","registration_attempt_id":"55555555555555555555555555555555","version":1}"#;
    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    struct EmptyScanner {
        calls: AtomicUsize,
    }

    struct CountingDelegatingScanner {
        calls: AtomicUsize,
        inner: Arc<dyn RuntimeInventoryScanner>,
    }

    struct IncompleteScanner;

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for IncompleteScanner {}

    impl RuntimeInventoryScanner for IncompleteScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            context.check_active()?;
            Ok(RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources: vec![InventorySource::Process],
            })
        }
    }

    struct AssignedScanner;

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for AssignedScanner {}

    impl RuntimeInventoryScanner for AssignedScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            context.check_active()?;
            let runtimes = context
                .coordinates()
                .desired
                .desired_specs
                .iter()
                .map(|desired| ObservedRuntimeStatus {
                    cat_id: desired.cat_id.clone(),
                    applied_desired: Some(AppliedDesiredEvidence {
                        desired_revision: desired.desired_revision,
                        spec_digest: desired.spec_digest.clone(),
                        placement: desired.placement.clone(),
                        target: desired.target,
                    }),
                    runtime_incarnation: None,
                    stable_state: None,
                    step: ReconcileStep::InspectInventory {
                        inventory_epoch: Epoch::new(1).unwrap(),
                    },
                    checkpoint: CheckpointEvidence::Missing {
                        checkpoint_path: HostPath::new(format!(
                            "/var/lib/cats/{}.json",
                            desired.cat_id.as_str()
                        ))
                        .unwrap(),
                    },
                    processes: Vec::new(),
                    volumes: Vec::new(),
                    mounts: Vec::new(),
                    networks: Vec::new(),
                    guest_transport: GuestTransportEvidence::Unavailable,
                    warm_snapshot: WarmSnapshotEvidence::Absent,
                    lifecycle_admission: LifecycleAdmission::Closed,
                    routes: Vec::new(),
                    platform_guards: 0,
                    conditions: Vec::new(),
                })
                .collect();
            Ok(RuntimeInventoryScanOutcome::Complete(
                CompleteRuntimeInventory::for_test(
                    UnixMillis::new(1_720_000_004_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    runtimes,
                    Vec::new(),
                ),
            ))
        }
    }

    struct CountingEffect {
        calls: AtomicUsize,
    }

    struct DecisionEffect {
        outcome: RuntimeDesiredEffectOutcome,
        calls: AtomicUsize,
    }

    struct FailingEffect {
        calls: AtomicUsize,
    }

    struct SequencedRecovery {
        calls: AtomicUsize,
    }

    impl RuntimePreScanRecovery for SequencedRecovery {
        fn recover_one(
            &self,
            context: RuntimePreScanRecoveryContext,
        ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
            context.check_active()?;
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Ok(RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: Id::new("cat_recovered").unwrap(),
                })
            } else {
                Ok(RuntimePreScanRecoveryOutcome::NoChange)
            }
        }
    }

    struct NonCooperativeEffect {
        calls: AtomicUsize,
        delay: Duration,
    }

    struct NeverLaunch {
        calls: AtomicUsize,
    }

    impl crate::runtime_spine::runtime_launch_port_sealed::Sealed for NeverLaunch {}

    impl RuntimeLaunchPort for NeverLaunch {
        fn launch(
            &self,
            _desired: &DesiredRuntimeSpec,
            _network: &ChNetwork,
        ) -> anyhow::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn production_network_config(ip_bin: std::path::PathBuf) -> ChConfig {
        ChConfig {
            block_direct: false,
            ch_bin: "unused-ch".into(),
            kernel: "unused-kernel".into(),
            initramfs: None,
            boot_contract: None,
            cmdline: String::new(),
            seed_image: None,
            block_path: BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin: "unused-nbd-client".into(),
            nbd_devices: 8,
            ip_bin,
        }
    }

    impl RuntimeDesiredEffect for CountingEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            let accepted = context.accepted_full()?;
            assert_eq!(accepted.session().node_id, desired.placement.node_id);
            assert!(accepted.observation().complete_inventory);
            assert_eq!(
                accepted.observation().inventory_digest.as_ref(),
                Some(&accepted.attestation().inventory_digest)
            );
            assert_eq!(
                desired.runtime.network_config,
                desired_with_network().runtime.network_config
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeDesiredEffectOutcome::Applied)
        }
    }

    #[tokio::test]
    async fn typed_pre_scan_recovery_is_serialized_on_the_mutation_lane() {
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let recovery = Arc::new(SequencedRecovery {
            calls: AtomicUsize::new(0),
        });
        let recovery_port: Arc<dyn RuntimePreScanRecovery> = recovery.clone();
        let mut lane = EffectLane::start(effect.clone(), Some(recovery_port)).unwrap();
        let snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        let coordinates = RuntimeSpineFullScan {
            session: snapshot.session.clone(),
            heartbeat_sequence: Sequence::new(1).unwrap(),
            inventory_epoch: Epoch::new(1).unwrap(),
            desired: snapshot,
        };
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            lane.recover(
                StateDirectory::unanchored(root.path().to_path_buf()),
                coordinates.clone(),
                Instant::now(),
            )
            .await
            .unwrap(),
            RecoveryWait::DeadlineExceeded
        ));
        assert_eq!(recovery.calls.load(Ordering::SeqCst), 0);
        let RecoveryWait::Finished(Ok(RuntimePreScanRecoveryOutcome::Recovered { cat_id })) = lane
            .recover(
                StateDirectory::unanchored(root.path().to_path_buf()),
                coordinates.clone(),
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap()
        else {
            panic!("first recovery command did not return its typed repair")
        };
        assert_eq!(cat_id, Id::new("cat_recovered").unwrap());
        assert!(matches!(
            lane.recover(
                StateDirectory::unanchored(root.path().to_path_buf()),
                coordinates,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap(),
            RecoveryWait::Finished(Ok(RuntimePreScanRecoveryOutcome::NoChange))
        ));
        assert_eq!(recovery.calls.load(Ordering::SeqCst), 2);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        lane.shutdown_blocking().unwrap();
    }

    impl RuntimeDesiredEffect for DecisionEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            _desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.outcome.clone())
        }
    }

    impl RuntimeDesiredEffect for FailingEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            _desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("effect outcome became unknown after its durable step")
        }
    }

    impl RuntimeDesiredEffect for NonCooperativeEffect {
        fn apply(
            &self,
            _context: RuntimeDesiredEffectContext,
            _desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Models a provider call that cannot observe cancellation until it
            // returns. The runner must not scan beside this late phase.
            std::thread::sleep(self.delay);
            Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
        }
    }

    fn desired_with_network() -> DesiredRuntimeSpec {
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
        desired
    }

    fn effect_admission_for(desired: &DesiredRuntimeSpec) -> RuntimeDesiredEffectAdmission {
        let session = decode_agent_session(SESSION).unwrap();
        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        snapshot.desired_specs = vec![desired.clone()];
        let runtime = ObservedRuntimeStatus {
            cat_id: desired.cat_id.clone(),
            applied_desired: Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            }),
            runtime_incarnation: None,
            stable_state: None,
            step: ReconcileStep::InspectInventory {
                inventory_epoch: Epoch::new(1).unwrap(),
            },
            checkpoint: CheckpointEvidence::Missing {
                checkpoint_path: HostPath::new("/var/lib/cats/cat_01.json").unwrap(),
            },
            processes: Vec::new(),
            volumes: Vec::new(),
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: Vec::new(),
        };
        let observation = build_full_observation(
            RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: session.node_id.clone(),
                    node_boot_id: session.node_boot_id.clone(),
                    agent_instance_id: session.agent_instance_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                },
                heartbeat_sequence: Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired: snapshot,
            },
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                vec![runtime],
                Vec::new(),
            ),
        )
        .unwrap();
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest: observation.inventory_digest.clone().unwrap(),
            inventory_read_position: observation.inventory_read_position.unwrap(),
            accepted_at_unix_ms: UnixMillis::new(1_720_000_005_000).unwrap(),
        };
        RuntimeDesiredEffectAdmission::for_test(session, observation, attestation)
    }

    fn snapshot_with_network() -> Vec<u8> {
        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        snapshot.desired_specs = vec![desired_with_network()];
        encode_desired_read_snapshot(&snapshot).unwrap()
    }

    fn prepare_unconsumed_effect_desired(
        state: &StateDirectory,
        registered: &AgentSession,
    ) -> DesiredRuntimeSpec {
        let mut journal = RuntimeSpineJournal::open_for_test(state, registered.clone()).unwrap();
        assert!(matches!(
            journal.desired_work().unwrap(),
            RuntimeSpineDesiredWork::Request(_)
        ));
        let first = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        journal.accept_desired(first.clone(), SNAPSHOT).unwrap();
        let observation = build_full_observation(
            journal.full_scan().unwrap(),
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                Vec::new(),
                Vec::new(),
            ),
        )
        .unwrap();
        journal.prepare_observation(observation.clone()).unwrap();
        let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
        let acceptance = ObservationAcceptance {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: observation.node_id.clone(),
                node_boot_id: observation.node_boot_id.clone(),
                agent_instance_id: observation.agent_instance_id.clone(),
                agent_session_epoch: observation.agent_session_epoch,
            },
            observation_id: observation.observation_id.clone(),
            heartbeat_sequence: observation.heartbeat_sequence,
            accepted_at_unix_ms: accepted_at,
            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
            inventory: ObservationInventoryAcceptance::Full {
                attestation: AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: observation.node_id,
                    agent_session_epoch: observation.agent_session_epoch,
                    inventory_epoch: observation.inventory_epoch,
                    inventory_digest: observation.inventory_digest.unwrap(),
                    inventory_read_position: observation.inventory_read_position.unwrap(),
                    accepted_at_unix_ms: accepted_at,
                },
            },
        };
        let acceptance_bytes = encode_observation_acceptance(&acceptance).unwrap();
        journal
            .accept_observation(acceptance, &acceptance_bytes)
            .unwrap();
        let RuntimeSpineDesiredWork::Request(request) = journal.desired_work().unwrap() else {
            panic!("accepted full inventory must advance the Desired request")
        };
        let desired = desired_with_network();
        let mut second = first;
        second.session = request.value().session.clone();
        second.request_sequence = request.value().request_sequence;
        second.read_position = cats_api::runtime_reconciliation::Sequence::new(13).unwrap();
        second.issued_at_unix_ms = UnixMillis::new(1_720_000_010_000).unwrap();
        second.expires_at_unix_ms = UnixMillis::new(1_720_000_040_000).unwrap();
        second.desired_specs = vec![desired.clone()];
        let bytes = encode_desired_read_snapshot(&second).unwrap();
        journal.accept_desired(second, &bytes).unwrap();
        desired
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for EmptyScanner {}

    impl RuntimeInventoryScanner for EmptyScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            context.check_active()?;
            Ok(RuntimeInventoryScanOutcome::Complete(
                CompleteRuntimeInventory::for_test(
                    UnixMillis::new(1_720_000_004_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    Vec::new(),
                    Vec::new(),
                ),
            ))
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for CountingDelegatingScanner {}

    impl RuntimeInventoryScanner for CountingDelegatingScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.scan_complete(context)
        }
    }

    struct ControlledScanner {
        calls: AtomicUsize,
        started: test_mpsc::SyncSender<()>,
        release: Mutex<test_mpsc::Receiver<()>>,
        exited: test_mpsc::SyncSender<()>,
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for ControlledScanner {}

    impl RuntimeInventoryScanner for ControlledScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            let result = context.check_active();
            self.exited.send(()).unwrap();
            result?;
            anyhow::bail!("controlled scanner was released before cancellation")
        }
    }

    struct DropWitnessScanner {
        dropped: test_mpsc::SyncSender<()>,
    }

    impl Drop for DropWitnessScanner {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for DropWitnessScanner {}

    impl RuntimeInventoryScanner for DropWitnessScanner {
        fn scan_complete(
            &self,
            _context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            unreachable!("construction-failure scanner must never receive work")
        }
    }

    struct PanicScanner;

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for PanicScanner {}

    impl RuntimeInventoryScanner for PanicScanner {
        fn scan_complete(
            &self,
            _context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            panic!("injected scanner panic")
        }
    }

    fn signer() -> Ed25519RequestSigner {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        Ed25519RequestSigner::from_pkcs8_der(Id::new("credential_a").unwrap(), &der).unwrap()
    }

    async fn spawn(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://{address}/"), task)
    }

    fn wire_response(status: StatusCode, body: Vec<u8>) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn expired_deadline_never_enqueues_or_calls_a_probe() {
        let app = Router::new().route(
            cats_api::runtime_reconciliation::DESIRED_READ_PATH,
            post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
        );
        let (origin, server) = spawn(app).await;
        let scanner = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            scanner.clone(),
        )
        .unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert!(matches!(
            runner.run_once_until(Instant::now()).await.unwrap(),
            RuntimeSpineRunStep::ScanDeadlineExceeded
        ));
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 0);

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[test]
    fn deadline_policy_rejects_zero_and_overflow() {
        assert_eq!(
            RuntimeSpineDeadlinePolicy::new(Duration::ZERO, Duration::from_secs(1)),
            Err(RuntimeSpineDeadlinePolicyError::ZeroScanTimeout)
        );
        assert_eq!(
            RuntimeSpineDeadlinePolicy::new(Duration::from_secs(1), Duration::ZERO),
            Err(RuntimeSpineDeadlinePolicyError::ZeroEffectStepTimeout)
        );

        let scan_overflow = RuntimeSpineDeadlinePolicy::new(Duration::MAX, Duration::from_secs(1))
            .unwrap()
            .deadlines_from(Instant::now());
        assert_eq!(
            scan_overflow,
            Err(RuntimeSpineDeadlinePolicyError::ScanDeadlineOverflow)
        );

        let effect_overflow =
            RuntimeSpineDeadlinePolicy::new(Duration::from_secs(1), Duration::MAX)
                .unwrap()
                .deadlines_from(Instant::now());
        assert_eq!(
            effect_overflow,
            Err(RuntimeSpineDeadlinePolicyError::EffectStepDeadlineOverflow)
        );
    }

    #[tokio::test]
    async fn delivered_typed_effect_result_wins_an_already_ready_deadline() {
        let (send, receive) = tokio::sync::oneshot::channel();
        send.send(Ok(RuntimeDesiredEffectOutcome::RefreshInventory))
            .unwrap();

        assert!(matches!(
            receive_effect_result_until(receive, Instant::now()).await,
            EffectReceive::Delivered(Ok(RuntimeDesiredEffectOutcome::RefreshInventory))
        ));
    }

    #[tokio::test]
    async fn pending_effect_uses_only_its_precomputed_absolute_deadline() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let effect = Arc::new(DecisionEffect {
            outcome: RuntimeDesiredEffectOutcome::Applied,
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state,
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired_with_network());

        assert!(matches!(
            runner
                .run_once_with_deadlines(RuntimeSpineRunDeadlines {
                    scan: Instant::now(),
                    effect_step: Instant::now() + Duration::from_secs(5),
                })
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectsApplied
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);

        runner.pending_effects.push_back(desired_with_network());
        assert!(matches!(
            runner
                .run_once_with_deadlines(RuntimeSpineRunDeadlines {
                    scan: Instant::now() + Duration::from_secs(5),
                    effect_step: Instant::now(),
                })
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectDeadlineExceeded { .. }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        assert!(runner.pending_effects.is_empty());

        runner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unknown_effect_error_discards_old_admission_and_returns_to_full_scan() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = prepare_unconsumed_effect_desired(&state, &registered);
        let effect = Arc::new(FailingEffect {
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state.clone(),
            registered.clone(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired.clone());
        runner.effect_admission_open = true;

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectUnavailable { .. }
        ));
        assert!(runner.pending_effects.is_empty());
        assert!(runner.effect_admission.is_none());
        assert!(!runner.effect_admission_open);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        runner.shutdown().await.unwrap();

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let RuntimeSpineDesiredWork::Scan(snapshot) = recovered.desired_work().unwrap() else {
            panic!("an unknown effect outcome must require a fresh full inventory")
        };
        assert_eq!(snapshot.desired_specs, vec![desired]);
    }

    #[tokio::test]
    async fn timed_out_noncooperative_effect_blocks_a_successor_scan_until_shutdown() {
        let root = tempfile::tempdir().unwrap();
        let scanner = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        let effect = Arc::new(NonCooperativeEffect {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(100),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            scanner.clone(),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired_with_network());

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_millis(20))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectDeadlineExceeded { .. }
        ));
        assert!(runner.pending_effects.is_empty());
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(1))
                .await,
            Err(RuntimeSpineRunError::EffectLanePoisoned)
        ));
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 0);

        tokio::time::timeout(Duration::from_secs(1), runner.shutdown())
            .await
            .expect("shutdown must join the late effect")
            .unwrap();
    }

    #[tokio::test]
    async fn only_explicit_retry_exact_retains_the_same_effect_unit() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired_with_network();
        let effect = Arc::new(DecisionEffect {
            outcome: RuntimeDesiredEffectOutcome::RetryExact,
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired.clone());

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectRetryExact { .. }
        ));
        assert_eq!(runner.pending_effects.front(), Some(&desired));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        runner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_full_inventory_never_reaches_the_typed_effect_seam() {
        let snapshot = snapshot_with_network();
        let app = Router::new().route(
            cats_api::runtime_reconciliation::DESIRED_READ_PATH,
            post(move || {
                let snapshot = snapshot.clone();
                async move { wire_response(StatusCode::OK, snapshot) }
            }),
        );
        let (origin, server) = spawn(app).await;
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(IncompleteScanner),
            effect.clone(),
        )
        .unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        for _ in 0..2 {
            assert!(matches!(
                runner
                    .run_once_until(Instant::now() + Duration::from_secs(5))
                    .await
                    .unwrap(),
                RuntimeSpineRunStep::ScanIncomplete { .. }
            ));
        }
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn effect_waits_for_current_process_full_acceptance_and_fresh_desired() {
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(|request: Request<Body>| async move {
                    let body = to_bytes(request.into_body(), DESIRED_READ_REQUEST_MAX_WIRE_BYTES)
                        .await
                        .unwrap();
                    let request = decode_desired_read_request(&body).unwrap();
                    let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
                    snapshot.session = request.session;
                    snapshot.request_sequence = request.request_sequence;
                    snapshot.read_position = request.request_sequence;
                    snapshot.desired_specs = vec![desired_with_network()];
                    wire_response(
                        StatusCode::OK,
                        encode_desired_read_snapshot(&snapshot).unwrap(),
                    )
                }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(|request: Request<Body>| async move {
                    let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                        .await
                        .unwrap();
                    let observation = decode_node_observation(&body).unwrap();
                    let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
                    let acceptance = ObservationAcceptance {
                        version: ContractVersion::V1,
                        session: SessionBinding {
                            node_id: observation.node_id.clone(),
                            node_boot_id: observation.node_boot_id.clone(),
                            agent_instance_id: observation.agent_instance_id.clone(),
                            agent_session_epoch: observation.agent_session_epoch,
                        },
                        observation_id: observation.observation_id.clone(),
                        heartbeat_sequence: observation.heartbeat_sequence,
                        accepted_at_unix_ms: accepted_at,
                        lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
                        inventory: ObservationInventoryAcceptance::Full {
                            attestation: AdmissionInventoryAttestation {
                                version: ContractVersion::V1,
                                node_id: observation.node_id.clone(),
                                agent_session_epoch: observation.agent_session_epoch,
                                inventory_epoch: observation.inventory_epoch,
                                inventory_digest: observation.inventory_digest.clone().unwrap(),
                                inventory_read_position: observation
                                    .inventory_read_position
                                    .unwrap(),
                                accepted_at_unix_ms: accepted_at,
                            },
                        },
                    };
                    wire_response(
                        StatusCode::OK,
                        encode_observation_acceptance(&acceptance).unwrap(),
                    )
                }),
            );
        let (origin, server) = spawn(app).await;
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(AssignedScanner),
            effect.clone(),
        )
        .unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ObservationAccepted {
                service_ready: true
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectsApplied
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn effect_replan_durably_supersedes_the_unconsumed_desired() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = prepare_unconsumed_effect_desired(&state, &registered);
        let effect = Arc::new(DecisionEffect {
            outcome: RuntimeDesiredEffectOutcome::ReplanDesired,
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state.clone(),
            registered.clone(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired);

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectReplanDesired { .. }
        ));
        assert!(runner.pending_effects.is_empty());
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        runner.shutdown().await.unwrap();

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let RuntimeSpineDesiredWork::Request(next) = recovered.desired_work().unwrap() else {
            panic!("replan must durably advance to a fresh Desired read")
        };
        assert_eq!(next.value().request_sequence.get(), 3);
    }

    #[tokio::test]
    async fn effect_inventory_refresh_drops_the_batch_and_returns_to_the_same_scan() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = prepare_unconsumed_effect_desired(&state, &registered);
        let effect = Arc::new(DecisionEffect {
            outcome: RuntimeDesiredEffectOutcome::RefreshInventory,
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state.clone(),
            registered.clone(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired.clone());

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectRefreshInventory { .. }
        ));
        assert!(runner.pending_effects.is_empty());
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        runner.shutdown().await.unwrap();

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let RuntimeSpineDesiredWork::Scan(snapshot) = recovered.desired_work().unwrap() else {
            panic!("inventory refresh must return to the same accepted Desired scan")
        };
        assert_eq!(snapshot.desired_specs, vec![desired]);
    }

    #[tokio::test]
    async fn effect_identity_repair_never_retries_or_replaces_the_session_locally() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = prepare_unconsumed_effect_desired(&state, &registered);
        let effect = Arc::new(DecisionEffect {
            outcome: RuntimeDesiredEffectOutcome::IdentityRepairRequired,
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state.clone(),
            registered.clone(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect.clone(),
        )
        .unwrap();
        runner.pending_effects.push_back(desired.clone());

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectIdentityRepairRequired { .. }
        ));
        assert!(runner.pending_effects.is_empty());
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        runner.shutdown().await.unwrap();

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let RuntimeSpineDesiredWork::Scan(snapshot) = recovered.desired_work().unwrap() else {
            panic!("identity repair must not invent a replacement session or Desired request")
        };
        assert_eq!(snapshot.desired_specs, vec![desired]);
    }

    #[tokio::test]
    async fn hanging_production_ip_is_reaped_before_shutdown_releases_the_journal_flock() {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("ip.pid");
        let started_fifo_path = root.path().join("ip.started");
        let started_fifo_c =
            CString::new(started_fifo_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is a live NUL-terminated string and mode contains
        // only permission bits. The test owns the previously absent path.
        assert_eq!(unsafe { libc::mkfifo(started_fifo_c.as_ptr(), 0o600) }, 0);
        // O_RDWR prevents either endpoint's open from becoming another timing
        // condition. The byte itself is the exact child-started barrier.
        let mut started_fifo = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&started_fifo_path)
            .unwrap();
        let fake_ip = root.path().join("ip");
        std::fs::write(
            &fake_ip,
            format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{pid}'\nprintf x > '{started}'\nexec /bin/sleep 60\n",
                pid = pid_file.display(),
                started = started_fifo_path.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();

        let launch = Arc::new(NeverLaunch {
            calls: AtomicUsize::new(0),
        });
        let effect = Arc::new(ProductionRuntimeDesiredEffect::new(
            production_network_config(fake_ip),
            launch.clone(),
        ));
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let client =
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap();
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state.clone(),
            registered.clone(),
            client.clone(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect,
        )
        .unwrap();
        let desired = desired_with_network();
        runner.effect_admission = Some(effect_admission_for(&desired));
        runner.pending_effects.push_back(desired);

        let child_started = async {
            let mut started = [0_u8; 1];
            loop {
                match started_fifo.read(&mut started) {
                    Ok(1) => return started,
                    Ok(0) => panic!("child-start FIFO closed before its barrier byte"),
                    Ok(_) => unreachable!("one-byte child-start buffer cannot read more"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("read child-start FIFO: {error}"),
                }
            }
        };
        tokio::pin!(child_started);
        let mut effect_step =
            Box::pin(runner.run_once_until(Instant::now() + Duration::from_secs(30)));
        let started = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                result = &mut effect_step => {
                    panic!("effect returned before the hanging ip child-start barrier: {result:?}")
                }
                started = &mut child_started => started,
            }
        })
        .await
        .expect("fake ip never entered its hanging command");
        assert_eq!(started, [b'x']);
        assert!(pid_file.exists());
        assert_eq!(launch.calls.load(Ordering::SeqCst), 0);

        let blocked_scanner: Arc<dyn RuntimeInventoryScanner> = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        assert!(matches!(
            RuntimeSpineRunner::new(
                state.clone(),
                registered.clone(),
                client.clone(),
                blocked_scanner,
            ),
            Err(RuntimeSpineRunError::Journal(
                RuntimeSpineJournalError::Io { .. }
            ))
        ));

        // Cancelling the in-flight wait must poison the lane and signal the
        // exact active effect. Shutdown is then the oracle that the worker
        // killed and reaped its child before releasing the journal flock.
        drop(effect_step);
        assert!(runner.effect_lane().unwrap().is_poisoned());
        tokio::time::timeout(Duration::from_secs(3), runner.shutdown())
            .await
            .expect("hanging ip prevented runner shutdown from joining")
            .unwrap();

        let pid: libc::pid_t = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let mut status = 0;
        // SAFETY: pid was written by the exact child spawned above and the
        // status pointer is valid for this nonblocking waitpid probe.
        let wait = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(wait, -1, "Host ip remained waitable after runner shutdown");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "Host ip was not reaped before the journal flock was released"
        );

        let successor = RuntimeSpineRunner::new(
            state,
            registered,
            client,
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
        )
        .expect("runner shutdown did not release the journal flock");
        successor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn predecessor_observation_replay_never_establishes_restart_admission() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let mut predecessor =
            RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        assert!(matches!(
            predecessor.desired_work().unwrap(),
            RuntimeSpineDesiredWork::Request(_)
        ));
        let snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        predecessor.accept_desired(snapshot, SNAPSHOT).unwrap();
        let candidate = build_full_observation(
            predecessor.full_scan().unwrap(),
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                Vec::new(),
                Vec::new(),
            ),
        )
        .unwrap();
        predecessor.prepare_observation(candidate).unwrap();
        drop(predecessor);

        let app = Router::new().route(
            cats_api::runtime_reconciliation::OBSERVATION_PATH,
            post(|request: Request<Body>| async move {
                let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                    .await
                    .unwrap();
                let observation = decode_node_observation(&body).unwrap();
                let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
                let acceptance = ObservationAcceptance {
                    version: ContractVersion::V1,
                    session: SessionBinding {
                        node_id: observation.node_id.clone(),
                        node_boot_id: observation.node_boot_id.clone(),
                        agent_instance_id: observation.agent_instance_id.clone(),
                        agent_session_epoch: observation.agent_session_epoch,
                    },
                    observation_id: observation.observation_id.clone(),
                    heartbeat_sequence: observation.heartbeat_sequence,
                    accepted_at_unix_ms: accepted_at,
                    lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
                    inventory: ObservationInventoryAcceptance::Full {
                        attestation: AdmissionInventoryAttestation {
                            version: ContractVersion::V1,
                            node_id: observation.node_id.clone(),
                            agent_session_epoch: observation.agent_session_epoch,
                            inventory_epoch: observation.inventory_epoch,
                            inventory_digest: observation.inventory_digest.clone().unwrap(),
                            inventory_read_position: observation.inventory_read_position.unwrap(),
                            accepted_at_unix_ms: accepted_at,
                        },
                    },
                };
                wire_response(
                    StatusCode::OK,
                    encode_observation_acceptance(&acceptance).unwrap(),
                )
            }),
        );
        let (origin, server) = spawn(app).await;
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            state,
            registered,
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(IncompleteScanner),
            effect.clone(),
        )
        .unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ObservationReplayed
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn timed_out_scan_poison_and_cancelled_shutdown_keep_the_flock_until_join() {
        let app = Router::new().route(
            cats_api::runtime_reconciliation::DESIRED_READ_PATH,
            post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
        );
        let (origin, server) = spawn(app).await;
        let (started_sender, started_receiver) = test_mpsc::sync_channel(1);
        let (release_sender, release_receiver) = test_mpsc::sync_channel(1);
        let (exited_sender, exited_receiver) = test_mpsc::sync_channel(1);
        let scanner = Arc::new(ControlledScanner {
            calls: AtomicUsize::new(0),
            started: started_sender,
            release: Mutex::new(release_receiver),
            exited: exited_sender,
        });
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();
        let mut runner = RuntimeSpineRunner::new(
            state.clone(),
            registered.clone(),
            client.clone(),
            scanner.clone(),
        )
        .unwrap();
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_millis(50))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ScanDeadlineExceeded
        ));
        started_receiver.try_recv().unwrap();
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await,
            Err(RuntimeSpineRunError::ScanLanePoisoned)
        ));

        let mut shutdown = Box::pin(runner.shutdown());
        assert!(matches!(
            futures_util::poll!(shutdown.as_mut()),
            std::task::Poll::Pending
        ));
        drop(shutdown);

        let blocked_scanner: Arc<dyn RuntimeInventoryScanner> = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        assert!(matches!(
            RuntimeSpineRunner::new(
                state.clone(),
                registered.clone(),
                client.clone(),
                blocked_scanner,
            ),
            Err(RuntimeSpineRunError::Journal(
                RuntimeSpineJournalError::Io { .. }
            ))
        ));

        release_sender.send(()).unwrap();
        tokio::task::spawn_blocking(move || {
            exited_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("cancelled scanner did not exit")
        })
        .await
        .unwrap();

        let successor = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let scanner: Arc<dyn RuntimeInventoryScanner> = Arc::new(EmptyScanner {
                    calls: AtomicUsize::new(0),
                });
                match RuntimeSpineRunner::new(
                    state.clone(),
                    registered.clone(),
                    client.clone(),
                    scanner,
                ) {
                    Ok(runner) => break runner,
                    Err(RuntimeSpineRunError::Journal(RuntimeSpineJournalError::Io { .. })) => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("unexpected successor error: {error}"),
                }
            }
        })
        .await
        .expect("shutdown cleanup did not release the journal flock");
        successor.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn constructor_joins_the_scan_lane_when_the_journal_flock_is_busy() {
        let app = Router::new().route(
            cats_api::runtime_reconciliation::DESIRED_READ_PATH,
            post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
        );
        let (origin, server) = spawn(app).await;
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();
        let owner = RuntimeSpineRunner::new(
            state.clone(),
            registered.clone(),
            client.clone(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
        )
        .unwrap();
        let (dropped_sender, dropped_receiver) = test_mpsc::sync_channel(1);
        let candidate: Arc<dyn RuntimeInventoryScanner> = Arc::new(DropWitnessScanner {
            dropped: dropped_sender,
        });
        assert!(RuntimeSpineRunner::new(state, registered, client, candidate).is_err());
        dropped_receiver
            .try_recv()
            .expect("constructor returned before joining the started scan lane");

        owner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn scan_join_failure_still_closes_and_joins_the_journal_lane() {
        let app = Router::new().route(
            cats_api::runtime_reconciliation::DESIRED_READ_PATH,
            post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
        );
        let (origin, server) = spawn(app).await;
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();
        let mut runner = RuntimeSpineRunner::new(
            state.clone(),
            registered.clone(),
            client.clone(),
            Arc::new(PanicScanner),
        )
        .unwrap();
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await,
            Err(RuntimeSpineRunError::WorkerStopped(_))
        ));
        assert!(matches!(
            runner.shutdown().await,
            Err(RuntimeSpineRunError::WorkerShutdown(ref message))
                if message.contains("inventory scan")
        ));

        let successor = RuntimeSpineRunner::new(
            state,
            registered,
            client,
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
        )
        .expect("journal flock was not released after the scanner join failed");
        successor.shutdown().await.unwrap();
        server.abort();
    }

    fn invalidation_error(
        expired: bool,
        node_id: Id,
        agent_session_epoch: Epoch,
        read_position: cats_api::runtime_reconciliation::Sequence,
    ) -> RuntimeSpineError {
        let detail = if expired {
            ContractErrorDetail::InventoryReadPositionExpired {
                node_id,
                agent_session_epoch,
                read_position,
                expires_at_unix_ms: UnixMillis::new(1_720_000_030_000).unwrap(),
                server_time_unix_ms: UnixMillis::new(1_720_000_030_000).unwrap(),
            }
        } else {
            ContractErrorDetail::AssignedSetChanged {
                node_id,
                agent_session_epoch,
                read_position,
            }
        };
        RuntimeSpineError {
            version: ContractVersion::V1,
            error: Box::new(RuntimeSpineErrorDetail::ContractError {
                contract_error: ContractError {
                    version: ContractVersion::V1,
                    error: Box::new(detail),
                    message: "cursor rejected".to_owned(),
                },
            }),
            message: "cursor rejected".to_owned(),
        }
    }

    fn pending_full_observation() -> NodeObservation {
        let registered = decode_agent_session(SESSION).unwrap();
        let desired =
            cats_api::runtime_reconciliation::decode_desired_read_snapshot(SNAPSHOT).unwrap();
        build_full_observation(
            RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: registered.node_id,
                    node_boot_id: registered.node_boot_id,
                    agent_instance_id: registered.agent_instance_id,
                    agent_session_epoch: registered.agent_session_epoch,
                },
                heartbeat_sequence: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired,
            },
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                Vec::new(),
                Vec::new(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn cursor_invalidation_errors_bind_every_pending_observation_coordinate() {
        let pending = pending_full_observation();
        let read_position = pending.inventory_read_position.unwrap();
        for expired in [true, false] {
            assert_eq!(
                desired_invalidation_binding(
                    &invalidation_error(
                        expired,
                        pending.node_id.clone(),
                        pending.agent_session_epoch,
                        read_position,
                    ),
                    &pending,
                ),
                DesiredInvalidationBinding::Exact
            );
            assert_eq!(
                desired_invalidation_binding(
                    &invalidation_error(
                        expired,
                        Id::new("node_b").unwrap(),
                        pending.agent_session_epoch,
                        read_position,
                    ),
                    &pending,
                ),
                DesiredInvalidationBinding::Mismatch
            );
            assert_eq!(
                desired_invalidation_binding(
                    &invalidation_error(
                        expired,
                        pending.node_id.clone(),
                        Epoch::new(pending.agent_session_epoch.get() + 1).unwrap(),
                        read_position,
                    ),
                    &pending,
                ),
                DesiredInvalidationBinding::Mismatch
            );
            assert_eq!(
                desired_invalidation_binding(
                    &invalidation_error(
                        expired,
                        pending.node_id.clone(),
                        pending.agent_session_epoch,
                        cats_api::runtime_reconciliation::Sequence::new(read_position.get() + 1)
                            .unwrap(),
                    ),
                    &pending,
                ),
                DesiredInvalidationBinding::Mismatch
            );
        }
    }

    #[tokio::test]
    async fn mismatched_cursor_rejection_replays_exact_bytes_until_a_bound_rejection_arrives() {
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let observed_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let serving_calls = Arc::clone(&observation_calls);
        let serving_bodies = Arc::clone(&observed_bodies);
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move |request: Request<Body>| {
                    let calls = Arc::clone(&serving_calls);
                    let bodies = Arc::clone(&serving_bodies);
                    async move {
                        let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                            .await
                            .unwrap()
                            .to_vec();
                        bodies.lock().unwrap().push(body.clone());
                        let observation = decode_node_observation(&body).unwrap();
                        let call = calls.fetch_add(1, Ordering::SeqCst);
                        let node_id = if call == 0 {
                            Id::new("node_b").unwrap()
                        } else {
                            observation.node_id.clone()
                        };
                        let error = invalidation_error(
                            false,
                            node_id,
                            observation.agent_session_epoch,
                            observation.inventory_read_position.unwrap(),
                        );
                        wire_response(
                            StatusCode::CONFLICT,
                            encode_runtime_spine_error(&error).unwrap(),
                        )
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let scanner = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            scanner.clone(),
        )
        .unwrap();
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::RetryExact(RuntimeSpineRunRetry::Transport(
                RuntimeSpineRetryReason::InvalidResponse
            ))
        ));
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredInvalidated { .. }
        ));
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 1);
        {
            let bodies = observed_bodies.lock().unwrap();
            assert_eq!(bodies.len(), 2);
            assert_eq!(bodies[0], bodies[1]);
        }

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn response_loss_replays_the_durable_observation_without_rescanning() {
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let observed_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let committed_acceptance = Arc::new(Mutex::new(None::<Vec<u8>>));
        let serving_calls = Arc::clone(&observation_calls);
        let serving_bodies = Arc::clone(&observed_bodies);
        let serving_acceptance = Arc::clone(&committed_acceptance);
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move |request: Request<Body>| {
                    let calls = Arc::clone(&serving_calls);
                    let bodies = Arc::clone(&serving_bodies);
                    let committed = Arc::clone(&serving_acceptance);
                    async move {
                        let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                            .await
                            .unwrap()
                            .to_vec();
                        bodies.lock().unwrap().push(body.clone());
                        let observation = decode_node_observation(&body).unwrap();
                        let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
                        let acceptance = ObservationAcceptance {
                            version: ContractVersion::V1,
                            session: SessionBinding {
                                node_id: observation.node_id.clone(),
                                node_boot_id: observation.node_boot_id.clone(),
                                agent_instance_id: observation.agent_instance_id.clone(),
                                agent_session_epoch: observation.agent_session_epoch,
                            },
                            observation_id: observation.observation_id.clone(),
                            heartbeat_sequence: observation.heartbeat_sequence,
                            accepted_at_unix_ms: accepted_at,
                            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
                            inventory: ObservationInventoryAcceptance::Full {
                                attestation: AdmissionInventoryAttestation {
                                    version: ContractVersion::V1,
                                    node_id: observation.node_id.clone(),
                                    agent_session_epoch: observation.agent_session_epoch,
                                    inventory_epoch: observation.inventory_epoch,
                                    inventory_digest: observation.inventory_digest.clone().unwrap(),
                                    inventory_read_position: observation
                                        .inventory_read_position
                                        .unwrap(),
                                    accepted_at_unix_ms: accepted_at,
                                },
                            },
                        };
                        let acceptance_bytes = encode_observation_acceptance(&acceptance).unwrap();
                        let committed_bytes = {
                            let mut stored = committed.lock().unwrap();
                            stored
                                .get_or_insert_with(|| acceptance_bytes.clone())
                                .clone()
                        };
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            // The server-side acceptance is already committed.
                            // Lose the response body afterwards so the client
                            // must replay the exact observation to discover it.
                            let failed = futures_util::stream::once(async {
                                Err::<String, std::io::Error>(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionReset,
                                    "injected response loss after acceptance commit",
                                ))
                            });
                            return Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                                .header(header::CACHE_CONTROL, "no-store")
                                .body(Body::from_stream(failed))
                                .unwrap();
                        }
                        assert_eq!(acceptance_bytes, committed_bytes);
                        wire_response(StatusCode::OK, committed_bytes)
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let proc_root = root.path().join("test-proc");
        let systemd_root = root.path().join("test-system.slice");
        let block_root = root.path().join("test-block");
        let network_root = root.path().join("test-net");
        let socket_root = root.path().join("test-sockets");
        for directory in [
            &proc_root,
            &systemd_root,
            &block_root,
            &network_root,
            &socket_root,
        ] {
            std::fs::create_dir(directory).unwrap();
        }
        let concrete = crate::runtime::reconciliation::clean_slate_scanner_for_test(
            crate::runtime::reconciliation::TestCleanSlateProbeConfig {
                state_directory: state.clone(),
                proc_root,
                systemd_cgroup_root: systemd_root,
                block_class_root: block_root,
                network_class_root: network_root,
                legacy_socket_root: socket_root,
                cloud_hypervisor_binary: root.path().join("bin/cloud-hypervisor"),
                blockd_binary: root.path().join("bin/cats-blockd"),
                guest_agent_binary: root.path().join("bin/cats-guest-agent"),
            },
        )
        .unwrap();
        let scanner = Arc::new(CountingDelegatingScanner {
            calls: AtomicUsize::new(0),
            inner: concrete,
        });
        let scanner_port: Arc<dyn RuntimeInventoryScanner> = scanner.clone();
        let registered = decode_agent_session(SESSION).unwrap();
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();
        let mut runner = RuntimeSpineRunner::new(
            state.clone(),
            registered.clone(),
            client.clone(),
            scanner_port,
        )
        .unwrap();
        let duplicate_scanner: Arc<dyn RuntimeInventoryScanner> = scanner.clone();
        assert!(matches!(
            RuntimeSpineRunner::new(
                state.clone(),
                registered.clone(),
                client.clone(),
                duplicate_scanner,
            ),
            Err(RuntimeSpineRunError::Journal(
                RuntimeSpineJournalError::Io { .. }
            ))
        ));

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + std::time::Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + std::time::Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::RetryExact(RuntimeSpineRunRetry::Transport(
                RuntimeSpineRetryReason::Transport
            ))
        ));
        let committed_acceptance = committed_acceptance.lock().unwrap().clone().unwrap();
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + std::time::Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ObservationAccepted {
                service_ready: false
            }
        ));

        assert_eq!(scanner.calls.load(Ordering::SeqCst), 1);
        {
            let bodies = observed_bodies.lock().unwrap();
            assert_eq!(bodies.len(), 2);
            assert_eq!(bodies[0], bodies[1]);
        }
        runner.shutdown().await.unwrap();
        let recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let (_, acceptance) = recovered.full_observation().unwrap();
        assert_eq!(
            encode_observation_acceptance(acceptance).unwrap(),
            committed_acceptance
        );
        assert_eq!(
            recovered.session().lease_deadline_unix_ms,
            acceptance.lease_deadline_unix_ms
        );
        drop(recovered);
        let successor_scanner: Arc<dyn RuntimeInventoryScanner> = scanner;
        let successor = RuntimeSpineRunner::new(
            state,
            decode_agent_session(SESSION).unwrap(),
            client,
            successor_scanner,
        )
        .unwrap();
        successor.shutdown().await.unwrap();
        server.abort();
    }
}

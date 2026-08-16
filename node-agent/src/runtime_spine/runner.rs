//! One-step orchestration for the durable signed Node spine.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    inventory_digest, node_observation_canonical_wire_size, AdmissionInventoryAttestation,
    AgentSession, AppliedDesiredEvidence, Condition, ContractError, ContractErrorDetail,
    ContractVersion, DegradedReason, DegradedSource, DesiredReadRequest, DesiredReadSnapshot,
    DesiredRuntimeSpec, Epoch, Id, InventorySource, KeyId, LifecycleAdmission, NodeObservation,
    NodeResidue, ObservationAcceptance, ObservationInventoryAcceptance, ObservedRuntimeStatus,
    ProcessRole, ProcessState, RandomId128, ReadyReason, ReconcileStep, RouteGateState,
    RuntimeSpineError, RuntimeSpineErrorDetail, RuntimeTarget, RuntimeVolumeAuthorityRejection,
    Sha256Digest, StableState, UnixMillis, NODE_OBSERVATION_MAX_WIRE_BYTES,
};
use thiserror::Error;

#[cfg(feature = "proposed-node-residue-reclamation")]
use crate::runtime::reconciliation::{
    DataDirectoryReclaimAdmission, DataDirectoryReclaimScanAdmission,
};
use crate::runtime::reconciliation::{
    KernelNbdPoolAdmission, KernelNbdPoolScanAdmission, NodeGlobalManagedProcessAdmission,
    NodeGlobalManagedProcessScanAdmission, NodeGlobalNetworkAdmission,
    NodeGlobalNetworkScanAdmission, RunningTailAdmission, RunningTailScanAdmission,
};
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
const EFFECT_RESOURCE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const EFFECT_RESOURCE_SHUTDOWN_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CONCURRENT_CAT_EFFECT_WORKERS: usize = 8;
const NODE_GLOBAL_EFFECT_WAIT_INTERVAL: Duration = Duration::from_millis(10);
static NEXT_RUNTIME_EFFECT_WORKER_ID: AtomicU64 = AtomicU64::new(1);

fn next_runtime_effect_worker_id() -> u64 {
    NEXT_RUNTIME_EFFECT_WORKER_ID.fetch_add(1, Ordering::Relaxed)
}

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

/// Mandatory admission reconciliation which runs on the serialized mutation
/// lane before every physical scan. It may only close process-local admission
/// (and durably settle the matching close edge); it cannot open a gate or
/// repair unrelated publication artifacts.
pub(crate) trait RuntimePreScanAdmission: Send + Sync + 'static {
    fn reconcile(
        &self,
        context: RuntimePreScanAdmissionContext,
    ) -> anyhow::Result<RuntimePreScanAdmissionOutcome>;
    fn fail_close_cats(&self, cat_ids: &BTreeSet<Id>);
    fn fail_close_all(&self);
}

/// Process-local Running gates which the mandatory pre-scan proved safe to
/// retain through a subsequently incomplete physical scan. An ordinary
/// successful return is not enough: an untrusted session may have been
/// deliberately fail-closed while reconciliation still completed normally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuntimePreScanAdmissionOutcome {
    retained_running_cats: BTreeSet<Id>,
    exact_physical_negative_cats: BTreeSet<Id>,
}

impl RuntimePreScanAdmissionOutcome {
    pub(crate) fn retained_running_cats(cat_ids: impl IntoIterator<Item = Id>) -> Self {
        Self {
            retained_running_cats: cat_ids.into_iter().collect(),
            exact_physical_negative_cats: BTreeSet::new(),
        }
    }

    fn retains(&self, cat_id: &Id) -> bool {
        self.retained_running_cats.contains(cat_id)
    }

    fn exclude(&mut self, cat_ids: &BTreeSet<Id>) {
        self.retained_running_cats
            .retain(|cat_id| !cat_ids.contains(cat_id));
        self.exact_physical_negative_cats
            .extend(cat_ids.iter().cloned());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DegradedObservationCause {
    SourceUnavailable(Vec<InventorySource>),
    WireBudgetExceeded(Vec<InventorySource>),
    AttestationRefreshFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimePreScanRecoveryOutcome {
    NoChange,
    Recovered {
        cat_id: Id,
    },
    /// Fresh signed authority evidence proved that the persisted one-shot
    /// intent has already been closed by a successor which cannot be encoded
    /// safely in the public inventory. No local writer was recovered; the
    /// retained Desired must be invalidated before any scan/effect retry.
    ReplanDesired {
        cat_id: Id,
    },
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

pub(crate) mod effect_resource_owner_sealed {
    pub(crate) trait Sealed {}
}

/// Process-local ownership for helper resources which may outlive one
/// cancelled/ambiguous physical effect. The effect worker is the only
/// producer. Shutdown therefore closes and joins that worker before invoking
/// `shutdown_until`, while readiness is forbidden whenever `has_pending`
/// reports an unresolved resource.
pub(crate) trait RuntimeEffectResourceOwner:
    effect_resource_owner_sealed::Sealed + Send + Sync + 'static
{
    /// Nonblocking maintenance. Implementations may reap completed resources
    /// but must not wait for a live child here.
    fn poll(&self) -> anyhow::Result<()>;

    fn has_pending(&self) -> bool;

    /// Bounded producer-closed shutdown. A deadline failure must retain the
    /// unresolved resources so the caller cannot claim a clean join.
    fn shutdown_until(&self, deadline: Instant) -> anyhow::Result<()>;
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
    node_global_process: Option<NodeGlobalManagedProcessAdmission>,
    node_global_network: Option<NodeGlobalNetworkAdmission>,
    kernel_nbd_pool: Option<KernelNbdPoolAdmission>,
    running_tail: Option<RunningTailAdmission>,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    data_directory_reclaim: Option<DataDirectoryReclaimAdmission>,
    node_global_effect_gate: Arc<NodeGlobalEffectGate>,
    node_global_effect_open: Arc<AtomicBool>,
    effect_worker_id: u64,
}

#[derive(Debug, Default)]
struct NodeGlobalEffectGate {
    owner: Mutex<Option<u64>>,
    changed: Condvar,
}

impl NodeGlobalEffectGate {
    fn acquire(
        &self,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RuntimeNodeGlobalEffectPermit> {
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| anyhow::anyhow!("Node-global Desired effect gate was poisoned"))?;
        loop {
            context.check_active()?;
            anyhow::ensure!(
                context.node_global_effect_open.load(Ordering::Acquire),
                "Node-global Desired effect admission was invalidated"
            );
            match *owner {
                None => {
                    *owner = Some(context.effect_worker_id);
                    return Ok(RuntimeNodeGlobalEffectPermit(()));
                }
                Some(worker_id) if worker_id == context.effect_worker_id => {
                    return Ok(RuntimeNodeGlobalEffectPermit(()));
                }
                Some(_) => {
                    let remaining = context.deadline.saturating_duration_since(Instant::now());
                    let wait = remaining.min(NODE_GLOBAL_EFFECT_WAIT_INTERVAL);
                    let (next, _) = self.changed.wait_timeout(owner, wait).map_err(|_| {
                        anyhow::anyhow!("Node-global Desired effect gate was poisoned")
                    })?;
                    owner = next;
                }
            }
        }
    }

    fn release_worker_and_close(&self, worker_id: u64, open: &AtomicBool) {
        let mut owner = match self.owner.lock() {
            Ok(owner) => owner,
            Err(poisoned) => poisoned.into_inner(),
        };
        if owner.as_ref() == Some(&worker_id) {
            // Close while ownership is retained so no sibling can acquire in
            // the interval before this exact worker releases the gate.
            open.store(false, Ordering::Release);
            *owner = None;
            self.changed.notify_all();
        }
    }
}

/// Proof that this exact Cat worker owns (or re-entered) the batch-global
/// effect authority. Dropping this marker does not release ownership: the
/// worker closes and releases it only after the entire effect call returns.
pub(crate) struct RuntimeNodeGlobalEffectPermit(());

/// Shared read-only deadline/cancellation boundary for physical identity
/// inspection. Both a full inventory scan and a Desired effect may inspect
/// the same systemd/process/socket tuple; creation remains effect-only.
pub(crate) trait RuntimePhysicalReadContext {
    fn deadline(&self) -> Instant;
    fn check_active(&self) -> anyhow::Result<()>;
}

/// The complete Cat-name set from one accepted Desired snapshot. The private
/// field prevents a provider adapter from constructing "all checkpoints" out
/// of a hand-picked subset; only the runner's accepted scan/effect contexts
/// can mint this proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeAssignedCatSet {
    cat_ids: BTreeSet<Id>,
}

impl RuntimeAssignedCatSet {
    fn from_snapshot(snapshot: &DesiredReadSnapshot) -> anyhow::Result<Self> {
        let cat_ids = snapshot
            .desired_specs
            .iter()
            .map(|desired| desired.cat_id.clone())
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            cat_ids.len() == snapshot.desired_specs.len(),
            "accepted Desired snapshot repeats a Cat identity"
        );
        Ok(Self { cat_ids })
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &Id> {
        self.cat_ids.iter()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimePreScanAdmissionContext {
    coordinates: RuntimeSpineFullScan,
    deadline: Instant,
    cancellation: RuntimeInventoryScanCancellation,
}

impl RuntimePreScanAdmissionContext {
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

    pub(crate) fn coordinates(&self) -> &RuntimeSpineFullScan {
        &self.coordinates
    }

    pub(crate) fn check_active(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.cancellation.is_cancelled(),
            "runtime pre-scan admission reconciliation was cancelled"
        );
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "runtime pre-scan admission reconciliation deadline expired"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(coordinates: RuntimeSpineFullScan, deadline: Instant) -> Self {
        Self::new(
            coordinates,
            deadline,
            RuntimeInventoryScanCancellation::new(),
        )
    }
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

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
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
    assigned_cats: Option<RuntimeAssignedCatSet>,
    node_global_process: Option<NodeGlobalManagedProcessAdmission>,
    node_global_network: Option<NodeGlobalNetworkAdmission>,
    kernel_nbd_pool: Option<KernelNbdPoolAdmission>,
    running_tail: Option<RunningTailAdmission>,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    data_directory_reclaim: Option<DataDirectoryReclaimAdmission>,
}

impl RuntimeDesiredEffectAdmission {
    #[expect(
        clippy::too_many_arguments,
        reason = "each provider-private scan proof stays an explicit member of one accepted full observation"
    )]
    fn from_acceptance(
        mut session: AgentSession,
        observation: NodeObservation,
        acceptance: &ObservationAcceptance,
        node_global_process: Option<NodeGlobalManagedProcessAdmission>,
        node_global_network: Option<NodeGlobalNetworkAdmission>,
        kernel_nbd_pool: Option<KernelNbdPoolAdmission>,
        running_tail: Option<RunningTailAdmission>,
        #[cfg(feature = "proposed-node-residue-reclamation")] data_directory_reclaim: Option<
            DataDirectoryReclaimAdmission,
        >,
    ) -> Option<Self> {
        let ObservationInventoryAcceptance::Full { attestation } = &acceptance.inventory else {
            return None;
        };
        #[cfg(feature = "proposed-node-residue-reclamation")]
        let data_directory_reclaim_matches = data_directory_reclaim
            .as_ref()
            .is_none_or(|admission| admission.matches_observation(&observation));
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        let data_directory_reclaim_matches = true;
        if !super::acceptance_matches_observation(acceptance, &observation)
            || session.node_id != observation.node_id
            || session.node_boot_id != observation.node_boot_id
            || session.agent_instance_id != observation.agent_instance_id
            || session.agent_session_epoch != observation.agent_session_epoch
            || acceptance.lease_deadline_unix_ms < session.lease_deadline_unix_ms
            || attestation.accepted_at_unix_ms != acceptance.accepted_at_unix_ms
            || node_global_process
                .as_ref()
                .is_some_and(|admission| !admission.matches_observation(&observation))
            || node_global_network
                .as_ref()
                .is_some_and(|admission| !admission.matches_observation(&observation))
            || kernel_nbd_pool
                .as_ref()
                .is_some_and(|admission| !admission.matches_observation(&observation))
            || running_tail
                .as_ref()
                .is_some_and(|admission| !admission.matches_observation(&observation))
            || !data_directory_reclaim_matches
        {
            return None;
        }
        session.lease_deadline_unix_ms = acceptance.lease_deadline_unix_ms;
        Some(Self {
            session,
            observation,
            attestation: attestation.clone(),
            desired_read_position: None,
            assigned_cats: None,
            node_global_process,
            node_global_network,
            kernel_nbd_pool,
            running_tail,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim,
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

    pub(crate) fn assigned_cats(&self) -> anyhow::Result<&RuntimeAssignedCatSet> {
        self.assigned_cats.as_ref().ok_or_else(|| {
            anyhow::anyhow!("runtime Desired effect lacks its accepted assigned-Cat set")
        })
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
        let assigned_cats = RuntimeAssignedCatSet::from_snapshot(snapshot)?;
        self.desired_read_position = Some(snapshot.read_position);
        self.assigned_cats = Some(assigned_cats);
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
            assigned_cats: None,
            node_global_process: None,
            node_global_network: None,
            kernel_nbd_pool: None,
            running_tail: None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn bind_assigned_cats_for_test(mut self, snapshot: &DesiredReadSnapshot) -> Self {
        self.assigned_cats = Some(
            RuntimeAssignedCatSet::from_snapshot(snapshot)
                .expect("test Desired snapshot has unique Cat identities"),
        );
        self
    }

    #[cfg(test)]
    pub(crate) fn with_observation_for_test(mut self, observation: NodeObservation) -> Self {
        self.observation = observation;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_running_tail_for_test(mut self, admission: RunningTailAdmission) -> Self {
        self.running_tail = Some(admission);
        self
    }

    #[cfg(all(test, feature = "proposed-node-residue-reclamation"))]
    pub(crate) fn with_data_directory_reclaim_for_test(
        mut self,
        admission: DataDirectoryReclaimAdmission,
    ) -> Self {
        self.data_directory_reclaim = Some(admission);
        self
    }
}

impl RuntimeDesiredEffectContext {
    fn new(
        state_directory: StateDirectory,
        deadline: Instant,
        cancellation: RuntimeInventoryScanCancellation,
        accepted_full: Option<RuntimeDesiredEffectAdmission>,
        node_global_effect_gate: Arc<NodeGlobalEffectGate>,
        node_global_effect_open: Arc<AtomicBool>,
        effect_worker_id: u64,
    ) -> Self {
        let node_global_process = accepted_full
            .as_ref()
            .and_then(|admission| admission.node_global_process.clone());
        let node_global_network = accepted_full
            .as_ref()
            .and_then(|admission| admission.node_global_network.clone());
        let kernel_nbd_pool = accepted_full
            .as_ref()
            .and_then(|admission| admission.kernel_nbd_pool.clone());
        let running_tail = accepted_full
            .as_ref()
            .and_then(|admission| admission.running_tail.clone());
        #[cfg(feature = "proposed-node-residue-reclamation")]
        let data_directory_reclaim = accepted_full
            .as_ref()
            .and_then(|admission| admission.data_directory_reclaim.clone());
        Self {
            state_directory,
            deadline,
            cancellation,
            accepted_full,
            node_global_process,
            node_global_network,
            kernel_nbd_pool,
            running_tail,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim,
            node_global_effect_gate,
            node_global_effect_open,
            effect_worker_id,
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

    pub(crate) fn linearization_permit(
        &self,
    ) -> anyhow::Result<RuntimeDesiredEffectLinearizationPermit<'_>> {
        let permit = self.cancellation.linearization_permit()?;
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "runtime Desired effect deadline expired"
        );
        Ok(permit)
    }

    pub fn accepted_full(&self) -> anyhow::Result<&RuntimeDesiredEffectAdmission> {
        self.accepted_full.as_ref().ok_or_else(|| {
            anyhow::anyhow!("runtime Desired effect lacks current-process full admission")
        })
    }

    pub(crate) fn node_global_process(&self) -> anyhow::Result<&NodeGlobalManagedProcessAdmission> {
        self.node_global_process.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime Desired effect lacks its scanner-sealed Node-global process admission"
            )
        })
    }

    pub(crate) fn node_global_network(&self) -> anyhow::Result<&NodeGlobalNetworkAdmission> {
        self.node_global_network.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime Desired effect lacks its scanner-sealed Node-global network admission"
            )
        })
    }

    pub(crate) fn kernel_nbd_pool(&self) -> anyhow::Result<&KernelNbdPoolAdmission> {
        self.kernel_nbd_pool.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime Desired effect lacks its scanner-sealed kernel-NBD pool admission"
            )
        })
    }

    pub(crate) fn optional_kernel_nbd_pool(&self) -> Option<&KernelNbdPoolAdmission> {
        self.kernel_nbd_pool.as_ref()
    }

    pub(crate) fn running_tail_admission(&self) -> Option<&RunningTailAdmission> {
        self.running_tail.as_ref()
    }

    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub(crate) fn optional_data_directory_reclaim(&self) -> Option<&DataDirectoryReclaimAdmission> {
        self.data_directory_reclaim.as_ref()
    }

    /// Serializes the use of one accepted full scan as Node-global mutation
    /// authority while leaving Cat-local reconciliation independent. The
    /// caller must acquire this only after it has classified its exact Cat
    /// step as one that will inspect or mutate a shared Host namespace. The
    /// logical ownership remains attached to this worker through the final
    /// provider postcondition even if the returned marker leaves scope.
    pub(crate) fn lock_node_global_effect(&self) -> anyhow::Result<RuntimeNodeGlobalEffectPermit> {
        self.node_global_effect_gate.acquire(self)
    }

    #[cfg(test)]
    pub(crate) fn for_test(state_directory: StateDirectory, deadline: Instant) -> Self {
        Self::new(
            state_directory,
            deadline,
            RuntimeInventoryScanCancellation::new(),
            None,
            Arc::new(NodeGlobalEffectGate::default()),
            Arc::new(AtomicBool::new(true)),
            next_runtime_effect_worker_id(),
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
            Arc::new(NodeGlobalEffectGate::default()),
            Arc::new(AtomicBool::new(true)),
            next_runtime_effect_worker_id(),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_node_global_process(
        state_directory: StateDirectory,
        deadline: Instant,
        admission: NodeGlobalManagedProcessAdmission,
    ) -> Self {
        Self {
            state_directory,
            deadline,
            cancellation: RuntimeInventoryScanCancellation::new(),
            accepted_full: None,
            node_global_process: Some(admission),
            node_global_network: None,
            kernel_nbd_pool: None,
            running_tail: None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: None,
            node_global_effect_gate: Arc::new(NodeGlobalEffectGate::default()),
            node_global_effect_open: Arc::new(AtomicBool::new(true)),
            effect_worker_id: next_runtime_effect_worker_id(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_node_global_process_for_test(
        mut self,
        admission: NodeGlobalManagedProcessAdmission,
    ) -> Self {
        self.node_global_process = Some(admission);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_node_global_network_for_test(
        mut self,
        admission: NodeGlobalNetworkAdmission,
    ) -> Self {
        self.node_global_network = Some(admission);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_kernel_nbd_pool_for_test(
        mut self,
        admission: KernelNbdPoolAdmission,
    ) -> Self {
        self.kernel_nbd_pool = Some(admission);
        self
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

    pub(crate) fn assigned_cats(&self) -> anyhow::Result<RuntimeAssignedCatSet> {
        RuntimeAssignedCatSet::from_snapshot(&self.coordinates.desired)
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
    state: Arc<RuntimeCancellationState>,
}

#[derive(Debug)]
struct RuntimeCancellationState {
    cancelled: AtomicBool,
    linearization: RwLock<()>,
}

/// Read-side permit which orders one final durable CAS against cancellation.
/// Cancellation takes the write side before publishing its state, so either
/// it wins and no checkpoint changes, or the already-admitted CAS completes
/// before cancellation becomes observable.
pub(crate) struct RuntimeDesiredEffectLinearizationPermit<'a> {
    _guard: RwLockReadGuard<'a, ()>,
}

impl RuntimeInventoryScanCancellation {
    fn new() -> Self {
        Self {
            state: Arc::new(RuntimeCancellationState {
                cancelled: AtomicBool::new(false),
                linearization: RwLock::new(()),
            }),
        }
    }

    fn cancel(&self) {
        let _linearization = self
            .state
            .linearization
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.state.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    fn linearization_permit(&self) -> anyhow::Result<RuntimeDesiredEffectLinearizationPermit<'_>> {
        let guard = self
            .state
            .linearization
            .read()
            .map_err(|_| anyhow::anyhow!("runtime cancellation linearization was poisoned"))?;
        anyhow::ensure!(
            !self.state.cancelled.load(Ordering::Acquire),
            "runtime Desired effect was cancelled"
        );
        Ok(RuntimeDesiredEffectLinearizationPermit { _guard: guard })
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
    residue_sources: BTreeSet<InventorySource>,
    node_global_process: Option<NodeGlobalManagedProcessScanAdmission>,
    node_global_network: Option<Box<NodeGlobalNetworkScanAdmission>>,
    kernel_nbd_pool: Option<Box<KernelNbdPoolScanAdmission>>,
    running_tail: Option<Box<RunningTailScanAdmission>>,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    data_directory_reclaim: Option<Box<DataDirectoryReclaimScanAdmission>>,
}

impl CompleteRuntimeInventory {
    pub(crate) fn from_validated_coverage(
        _coverage: CompleteInventoryCoverage,
        observed_at_unix_ms: UnixMillis,
        key_ring: RuntimeInventoryKeyRing,
        runtimes: Vec<ObservedRuntimeStatus>,
        residue: Vec<NodeResidue>,
        residue_sources: BTreeSet<InventorySource>,
    ) -> Self {
        Self {
            observed_at_unix_ms,
            key_ring,
            runtimes,
            residue,
            residue_sources,
            node_global_process: None,
            node_global_network: None,
            kernel_nbd_pool: None,
            running_tail: None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: None,
        }
    }

    pub(crate) fn with_node_global_process_admission(
        mut self,
        admission: Option<NodeGlobalManagedProcessScanAdmission>,
    ) -> Self {
        self.node_global_process = admission;
        self
    }

    pub(crate) fn take_node_global_process_admission(
        &mut self,
    ) -> Option<NodeGlobalManagedProcessScanAdmission> {
        self.node_global_process.take()
    }

    pub(crate) fn with_node_global_network_admission(
        mut self,
        admission: Option<NodeGlobalNetworkScanAdmission>,
    ) -> Self {
        self.node_global_network = admission.map(Box::new);
        self
    }

    pub(crate) fn take_node_global_network_admission(
        &mut self,
    ) -> Option<NodeGlobalNetworkScanAdmission> {
        self.node_global_network.take().map(|admission| *admission)
    }

    pub(crate) fn with_kernel_nbd_pool_admission(
        mut self,
        admission: Option<KernelNbdPoolScanAdmission>,
    ) -> Self {
        self.kernel_nbd_pool = admission.map(Box::new);
        self
    }

    pub(crate) fn take_kernel_nbd_pool_admission(&mut self) -> Option<KernelNbdPoolScanAdmission> {
        self.kernel_nbd_pool.take().map(|admission| *admission)
    }

    pub(crate) fn with_running_tail_admission(
        mut self,
        admission: Option<RunningTailScanAdmission>,
    ) -> Self {
        self.running_tail = admission.map(Box::new);
        self
    }

    pub(crate) fn take_running_tail_admission(&mut self) -> Option<RunningTailScanAdmission> {
        self.running_tail.take().map(|admission| *admission)
    }

    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub(crate) fn with_data_directory_reclaim_admission(
        mut self,
        admission: Option<DataDirectoryReclaimScanAdmission>,
    ) -> Self {
        self.data_directory_reclaim = admission.map(Box::new);
        self
    }

    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub(crate) fn take_data_directory_reclaim_admission(
        &mut self,
    ) -> Option<DataDirectoryReclaimScanAdmission> {
        self.data_directory_reclaim
            .take()
            .map(|admission| *admission)
    }

    fn residue_sources(&self) -> Vec<InventorySource> {
        self.residue_sources.iter().copied().collect()
    }

    /// Binds one scanner-produced Node-global process admission through the
    /// same full-observation builder used by the production runner. Linux
    /// acceptance teardown needs a fresh physical scan after the runner has
    /// joined; manufacturing fixed test coordinates here would sever the
    /// process proof from the real boot, session, digest and public process
    /// projection that authorized it.
    #[cfg(test)]
    pub(crate) fn bind_node_global_process_for_test(
        mut self,
        coordinates: RuntimeSpineFullScan,
    ) -> anyhow::Result<(NodeObservation, NodeGlobalManagedProcessAdmission)> {
        let private = self
            .take_node_global_process_admission()
            .context("complete inventory lacks its Node-global process admission")?;
        let observation = build_full_observation(coordinates, self)
            .context("build test full observation through the production projection")?;
        let admission = private
            .bind(&observation)
            .context("bind test Node-global process proof to the full observation")?;
        Ok((observation, admission))
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
            residue_sources: BTreeSet::new(),
            node_global_process: None,
            node_global_network: None,
            kernel_nbd_pool: None,
            running_tail: None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: None,
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

    /// Fault-injection seam for signed-cycle acceptance tests. The runner
    /// still owns observation coordinates and recomputes the inventory digest
    /// after this scanner output returns; provider-private admissions remain
    /// attached and independently constrain the subsequent production effect.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn runtimes_mut_for_test(&mut self) -> &mut [ObservedRuntimeStatus] {
        &mut self.runtimes
    }

    #[cfg(test)]
    pub(crate) fn residue(&self) -> &[NodeResidue] {
        &self.residue
    }

    #[cfg(test)]
    pub(crate) fn key_ring(&self) -> &RuntimeInventoryKeyRing {
        &self.key_ring
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
    Complete(Box<CompleteRuntimeInventory>),
    Incomplete {
        unavailable_sources: Vec<InventorySource>,
        /// Per-Cat physical negatives completed before a later source became
        /// unavailable. These facts may only close retained Running authority;
        /// they never manufacture a partial runtime projection themselves.
        exact_physical_negative_cats: BTreeSet<Id>,
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
        /// This Node may admit Route traffic: it attested a complete
        /// inventory, holds runtimes, and has no unsettled physical effect.
        service_ready: bool,
        /// This process established a session-bound complete-inventory
        /// admission attestation. True of a cordoned empty Node, which
        /// `service_ready` deliberately is not.
        inventory_attested: bool,
    },
    /// A durable observation prepared by a predecessor process was resolved.
    /// It repairs an ambiguous result but cannot establish restart admission
    /// or local readiness without a new physical scan.
    ObservationReplayed,
    /// A current-process incomplete scan refreshed only previously proven
    /// Running Cat rows against the retained full inventory epoch. It never
    /// opens Desired effect admission or replaces the full attestation.
    PartialObservationAccepted {
        degraded_runtimes: usize,
    },
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
    PreScanAdmissionUnavailable(anyhow::Error),
    PreScanAdmissionDeadlineExceeded,
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
    #[error("runtime-spine effect resource maintenance failed: {0}")]
    EffectResource(String),
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
    PrepareDegradedPartial {
        coordinates: RuntimeSpineFullScan,
        cause: DegradedObservationCause,
        retained_admission: RuntimePreScanAdmissionOutcome,
        observed_at_unix_ms: UnixMillis,
        reply: tokio::sync::oneshot::Sender<
            Result<Option<DurableRuntimeSpineRequest<NodeObservation>>, RuntimeSpineJournalError>,
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
                        JournalCommand::PrepareDegradedPartial {
                            coordinates,
                            cause,
                            retained_admission,
                            observed_at_unix_ms,
                            reply,
                        } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    let full = journal
                                        .full_observation()
                                        .map(|(observation, _)| observation.clone());
                                    let last = journal
                                        .last_observation()
                                        .map(|(observation, _)| observation.clone());
                                    let Some(candidate) = build_degraded_partial_observation(
                                        coordinates,
                                        full.as_ref(),
                                        last.as_ref(),
                                        cause,
                                        &retained_admission,
                                        observed_at_unix_ms,
                                    ) else {
                                        return Ok(None);
                                    };
                                    journal.prepare_observation(candidate).map(Some)
                                });
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

    async fn prepare_degraded_partial(
        &self,
        coordinates: RuntimeSpineFullScan,
        cause: DegradedObservationCause,
        retained_admission: RuntimePreScanAdmissionOutcome,
        observed_at_unix_ms: UnixMillis,
    ) -> Result<Option<DurableRuntimeSpineRequest<NodeObservation>>, RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::PrepareDegradedPartial {
            coordinates,
            cause,
            retained_admission,
            observed_at_unix_ms,
            reply,
        })?;
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
            if self
                .thread
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                return Err(RuntimeSpineRunError::WorkerStopped(
                    "inventory scan".to_owned(),
                ));
            }
            if active_scan(&self.state.active).is_some() {
                // The cancelled read-only scanner still owns the lane. Do
                // not overlap another physical scan; let the runner publish
                // another bounded partial Degraded heartbeat instead.
                return Ok(ScanWait::DeadlineExceeded);
            }
            // A cooperatively cancelled scanner returned after its caller's
            // deadline. Its late result was discarded, but the single lane
            // can now safely perform a fresh full scan.
            self.state.poisoned.store(false, Ordering::Release);
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
                    Ok(ScanWait::Finished(Box::new(result)))
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
    Recover {
        context: Box<RuntimePreScanRecoveryContext>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<RuntimePreScanRecoveryOutcome>>,
    },
    ReconcileAdmission {
        context: Box<RuntimePreScanAdmissionContext>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<RuntimePreScanAdmissionOutcome>>,
    },
}

#[derive(Default)]
struct CoordinatorLaneState {
    poisoned: AtomicBool,
    active: Mutex<Option<RuntimeInventoryScanCancellation>>,
}

struct CoordinatorLane {
    sender: Option<mpsc::SyncSender<EffectCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
    state: Arc<CoordinatorLaneState>,
    has_recovery: bool,
    has_pre_scan_admission: bool,
    pre_scan_admission: Option<Arc<dyn RuntimePreScanAdmission>>,
}

impl CoordinatorLane {
    fn start(
        pre_scan_admission: Option<Arc<dyn RuntimePreScanAdmission>>,
        recovery: Option<Arc<dyn RuntimePreScanRecovery>>,
        resource_owner: Option<Arc<dyn RuntimeEffectResourceOwner>>,
    ) -> Result<Self, RuntimeSpineRunError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let state = Arc::new(CoordinatorLaneState::default());
        let worker_state = Arc::clone(&state);
        let has_recovery = recovery.is_some();
        let has_pre_scan_admission = pre_scan_admission.is_some();
        let lane_pre_scan_admission = pre_scan_admission.clone();
        let thread = std::thread::Builder::new()
            .name("cats-runtime-spine-effect".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        EffectCommand::Recover { context, reply } => {
                            let resources_ready = resource_owner
                                .as_ref()
                                .map(|owner| {
                                    owner.poll()?;
                                    anyhow::ensure!(
                                        !owner.has_pending(),
                                        "runtime recovery resource owner retains pending work"
                                    );
                                    Ok(())
                                })
                                .unwrap_or(Ok(()));
                            let result =
                                if context.check_active().is_ok() && resources_ready.is_ok() {
                                    recovery.as_ref().map_or_else(
                                        || Ok(RuntimePreScanRecoveryOutcome::NoChange),
                                        |recovery| recovery.recover_one(*context),
                                    )
                                } else {
                                    resources_ready.and_then(|()| {
                                        Err(anyhow::anyhow!(
                                        "runtime pre-scan recovery was cancelled before execution"
                                    ))
                                    })
                                };
                            active_effect(&worker_state.active).take();
                            let _ = reply.send(result);
                        }
                        EffectCommand::ReconcileAdmission { context, reply } => {
                            let result = if context.check_active().is_ok() {
                                pre_scan_admission.as_ref().map_or(
                                    Ok(RuntimePreScanAdmissionOutcome::default()),
                                    |admission| admission.reconcile(*context),
                                )
                            } else {
                                if let Some(admission) = &pre_scan_admission {
                                    admission.fail_close_all();
                                }
                                Err(anyhow::anyhow!(
                                    "runtime pre-scan admission was cancelled before execution"
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
            has_pre_scan_admission,
            pre_scan_admission: lane_pre_scan_admission,
        })
    }

    fn has_recovery(&self) -> bool {
        self.has_recovery
    }

    fn has_pre_scan_admission(&self) -> bool {
        self.has_pre_scan_admission
    }

    fn fail_close_all_admission(&self) {
        if let Some(admission) = &self.pre_scan_admission {
            admission.fail_close_all();
        }
    }

    fn fail_close_admission_cats(&self, cat_ids: &BTreeSet<Id>) {
        if let Some(admission) = &self.pre_scan_admission {
            admission.fail_close_cats(cat_ids);
        }
    }

    async fn reconcile_pre_scan_admission(
        &self,
        coordinates: RuntimeSpineFullScan,
        deadline: Instant,
    ) -> Result<AdmissionWait, RuntimeSpineRunError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            self.fail_close_all_admission();
            return Err(RuntimeSpineRunError::EffectLanePoisoned);
        }
        if Instant::now() >= deadline {
            if let Some(admission) = &self.pre_scan_admission {
                admission.fail_close_all();
            }
            return Ok(AdmissionWait::DeadlineExceeded);
        }
        let cancellation = RuntimeInventoryScanCancellation::new();
        let context =
            RuntimePreScanAdmissionContext::new(coordinates, deadline, cancellation.clone());
        {
            let mut active = active_effect(&self.state.active);
            if active.is_some() {
                drop(active);
                self.fail_close_all_admission();
                return Err(RuntimeSpineRunError::EffectQueueFull);
            }
            *active = Some(cancellation.clone());
        }
        let (reply, received) = tokio::sync::oneshot::channel();
        let command = EffectCommand::ReconcileAdmission {
            context: Box::new(context),
            reply,
        };
        let Some(sender) = self.sender.as_ref() else {
            active_effect(&self.state.active).take();
            self.fail_close_all_admission();
            return Err(RuntimeSpineRunError::WorkerStopped(
                "pre-scan admission".to_owned(),
            ));
        };
        let send_result = sender.try_send(command);
        if let Err(error) = send_result {
            active_effect(&self.state.active).take();
            self.fail_close_all_admission();
            return match error {
                mpsc::TrySendError::Full(_) => Err(RuntimeSpineRunError::EffectQueueFull),
                mpsc::TrySendError::Disconnected(_) => Err(RuntimeSpineRunError::WorkerStopped(
                    "pre-scan admission".to_owned(),
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
                if result.is_err() {
                    self.fail_close_all_admission();
                }
                guard.disarm();
                Ok(AdmissionWait::Finished(result))
            }
            EffectReceive::Closed => {
                self.fail_close_all_admission();
                guard.poison();
                Err(RuntimeSpineRunError::WorkerStopped(
                    "pre-scan admission".to_owned(),
                ))
            }
            EffectReceive::DeadlineExceeded => {
                if let Some(admission) = &self.pre_scan_admission {
                    admission.fail_close_all();
                }
                guard.poison();
                Ok(AdmissionWait::DeadlineExceeded)
            }
        }
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

impl Drop for CoordinatorLane {
    fn drop(&mut self) {
        let _ = self.shutdown_blocking();
    }
}

struct CatEffectCommand {
    context: RuntimeDesiredEffectContext,
    desired: DesiredRuntimeSpec,
}

struct CatEffectCompletion {
    cat_id: Id,
    desired: DesiredRuntimeSpec,
    result: anyhow::Result<RuntimeDesiredEffectOutcome>,
}

struct CatEffectWorker {
    cancellation: RuntimeInventoryScanCancellation,
    deadline: Instant,
    timed_out: bool,
    discard_result: bool,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Bounded set of exact Cat-keyed, one-command worker mailboxes.
///
/// A worker is never reassigned to another Cat and no second command can be
/// admitted for the same key until its first thread has been joined. A timed
/// out provider call therefore consumes one bounded slot but cannot poison a
/// sibling Cat or detach from runner shutdown. The completion wake channel is
/// unbounded only at the transport type level: a worker sends exactly once and
/// remains in `active` until that message is drained, so at most `limit`
/// completions can be queued.
struct CatEffectWorkers {
    effect: Arc<dyn RuntimeDesiredEffect>,
    completion_sender: tokio::sync::mpsc::UnboundedSender<CatEffectCompletion>,
    completion_receiver: tokio::sync::mpsc::UnboundedReceiver<CatEffectCompletion>,
    active: BTreeMap<Id, CatEffectWorker>,
    limit: usize,
    #[cfg(test)]
    dispatch_count_for_test: Option<Arc<AtomicUsize>>,
}

impl CatEffectWorkers {
    fn new(
        effect: Arc<dyn RuntimeDesiredEffect>,
        limit: usize,
    ) -> Result<Self, RuntimeSpineRunError> {
        if limit == 0 {
            return Err(RuntimeSpineRunError::InvalidComposition(
                "per-Cat Desired effect worker limit must be positive",
            ));
        }
        let (completion_sender, completion_receiver) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            effect,
            completion_sender,
            completion_receiver,
            active: BTreeMap::new(),
            limit,
            #[cfg(test)]
            dispatch_count_for_test: None,
        })
    }

    #[cfg(test)]
    fn set_dispatch_count_for_test(&mut self, dispatch_count: Arc<AtomicUsize>) {
        self.dispatch_count_for_test = Some(dispatch_count);
    }

    fn has_active(&self) -> bool {
        !self.active.is_empty()
    }

    fn available_slots(&self) -> usize {
        self.limit.saturating_sub(self.active.len())
    }

    fn dispatch(
        &mut self,
        state_directory: StateDirectory,
        desired: DesiredRuntimeSpec,
        accepted_full: Option<RuntimeDesiredEffectAdmission>,
        node_global_effect_gate: Arc<NodeGlobalEffectGate>,
        node_global_effect_open: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<(), RuntimeSpineRunError> {
        if self.active.len() >= self.limit {
            return Err(RuntimeSpineRunError::EffectQueueFull);
        }
        let cat_id = desired.cat_id.clone();
        if self.active.contains_key(&cat_id) {
            return Err(RuntimeSpineRunError::InvalidComposition(
                "one Cat was dispatched while its reconciler was already in flight",
            ));
        }
        let cancellation = RuntimeInventoryScanCancellation::new();
        let effect_worker_id = next_runtime_effect_worker_id();
        let context = RuntimeDesiredEffectContext::new(
            state_directory,
            deadline,
            cancellation.clone(),
            accepted_full,
            node_global_effect_gate,
            node_global_effect_open,
            effect_worker_id,
        );
        let (command_sender, command_receiver) = mpsc::sync_channel::<CatEffectCommand>(1);
        let effect = Arc::clone(&self.effect);
        let completion = self.completion_sender.clone();
        let global_gate = Arc::clone(&context.node_global_effect_gate);
        let global_open = Arc::clone(&context.node_global_effect_open);
        let worker_cat_id = cat_id.clone();
        let thread = std::thread::Builder::new()
            .name("cats-runtime-cat-effect".to_owned())
            .spawn(move || {
                let Ok(command) = command_receiver.recv() else {
                    return;
                };
                let CatEffectCommand { context, desired } = command;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    if context.check_active().is_ok() {
                        effect.apply(context, &desired)
                    } else {
                        Err(anyhow::anyhow!(
                            "runtime Desired effect was cancelled before execution"
                        ))
                    }
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("per-Cat Desired effect worker panicked")));
                global_gate.release_worker_and_close(effect_worker_id, global_open.as_ref());
                // This send is the worker's final observable action. The
                // coordinator may therefore join synchronously after receipt
                // without waiting on provider or filesystem work.
                let _ = completion.send(CatEffectCompletion {
                    cat_id: worker_cat_id,
                    desired,
                    result,
                });
            })
            .map_err(|source| RuntimeSpineRunError::WorkerStart {
                worker: "per-Cat Desired effect",
                source,
            })?;
        self.active.insert(
            cat_id.clone(),
            CatEffectWorker {
                cancellation,
                deadline,
                timed_out: false,
                discard_result: false,
                thread: Some(thread),
            },
        );
        if command_sender
            .send(CatEffectCommand { context, desired })
            .is_err()
        {
            // The thread exited before accepting the only bounded command.
            // It cannot have called user code, but it must still be joined.
            let mut worker = self.active.remove(&cat_id).ok_or_else(|| {
                RuntimeSpineRunError::WorkerStopped("per-Cat Desired effect startup".to_owned())
            })?;
            let _ = join_worker_blocking("per-Cat Desired effect", worker.thread.take());
            return Err(RuntimeSpineRunError::WorkerStopped(
                "per-Cat Desired effect startup".to_owned(),
            ));
        }
        #[cfg(test)]
        if let Some(dispatch_count) = &self.dispatch_count_for_test {
            // This is the runner's exact successful mailbox-dispatch boundary:
            // the worker accepted the sole command and may now enter the
            // physical effect. Tests use it to prove that an earlier session
            // rejection did not merely happen to leave local state unchanged.
            dispatch_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn wait_next(
        &mut self,
        poll_deadline: Instant,
    ) -> Result<CatEffectWait, RuntimeSpineRunError> {
        loop {
            match self.completion_receiver.try_recv() {
                Ok(completion) => return self.finish_completion(completion),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    return Err(RuntimeSpineRunError::WorkerStopped(
                        "per-Cat Desired effect completion".to_owned(),
                    ));
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            }

            let task_deadline = self
                .active
                .values()
                .filter(|worker| !worker.timed_out && !worker.discard_result)
                .map(|worker| worker.deadline)
                .min();
            let wait_deadline =
                task_deadline.map_or(poll_deadline, |deadline| deadline.min(poll_deadline));
            if Instant::now() >= wait_deadline {
                if let Some(cat_id) = self.mark_expired() {
                    return Ok(CatEffectWait::DeadlineExceeded { cat_id });
                }
                let cat_id = self.active.keys().next().cloned().ok_or_else(|| {
                    RuntimeSpineRunError::WorkerStopped(
                        "per-Cat Desired effect wait without an active worker".to_owned(),
                    )
                })?;
                return Ok(CatEffectWait::AwaitingLateWorker { cat_id });
            }

            let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(wait_deadline));
            tokio::pin!(timer);
            tokio::select! {
                biased;
                completion = self.completion_receiver.recv() => {
                    let completion = completion.ok_or_else(|| RuntimeSpineRunError::WorkerStopped(
                        "per-Cat Desired effect completion".to_owned(),
                    ))?;
                    return self.finish_completion(completion);
                }
                () = &mut timer => {}
            }
        }
    }

    fn mark_expired(&mut self) -> Option<Id> {
        let now = Instant::now();
        let expired = self
            .active
            .iter()
            .filter(|(_, worker)| {
                !worker.timed_out && !worker.discard_result && now >= worker.deadline
            })
            .map(|(cat_id, _)| cat_id.clone())
            .collect::<Vec<_>>();
        for cat_id in &expired {
            if let Some(worker) = self.active.get_mut(cat_id) {
                worker.timed_out = true;
                worker.cancellation.cancel();
            }
        }
        expired.into_iter().next()
    }

    fn finish_completion(
        &mut self,
        completion: CatEffectCompletion,
    ) -> Result<CatEffectWait, RuntimeSpineRunError> {
        let Some(mut worker) = self.active.remove(&completion.cat_id) else {
            return Err(RuntimeSpineRunError::WorkerStopped(
                "stale or duplicate per-Cat Desired effect completion".to_owned(),
            ));
        };
        join_worker_blocking("per-Cat Desired effect", worker.thread.take())?;
        if worker.timed_out {
            Ok(CatEffectWait::LateWorkerJoined {
                cat_id: completion.cat_id,
            })
        } else if worker.discard_result {
            Ok(CatEffectWait::Discarded {
                cat_id: completion.cat_id,
            })
        } else {
            Ok(CatEffectWait::Finished {
                desired: Box::new(completion.desired),
                result: completion.result,
            })
        }
    }

    fn cancel_all(&self) {
        for worker in self.active.values() {
            worker.cancellation.cancel();
        }
    }

    fn cancel_all_and_discard(&mut self) {
        for worker in self.active.values_mut() {
            worker.discard_result = true;
            worker.cancellation.cancel();
        }
    }

    fn shutdown_blocking(&mut self) -> Result<(), RuntimeSpineRunError> {
        self.cancel_all();
        let mut failures = Vec::new();
        while let Some((cat_id, mut worker)) = self.active.pop_first() {
            if let Err(error) = join_worker_blocking("per-Cat Desired effect", worker.thread.take())
            {
                failures.push(format!("{cat_id}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RuntimeSpineRunError::WorkerShutdown(failures.join("; ")))
        }
    }
}

impl Drop for CatEffectWorkers {
    fn drop(&mut self) {
        let _ = self.shutdown_blocking();
    }
}

enum CatEffectWait {
    Finished {
        desired: Box<DesiredRuntimeSpec>,
        result: anyhow::Result<RuntimeDesiredEffectOutcome>,
    },
    DeadlineExceeded {
        cat_id: Id,
    },
    AwaitingLateWorker {
        cat_id: Id,
    },
    LateWorkerJoined {
        cat_id: Id,
    },
    Discarded {
        cat_id: Id,
    },
}

enum DeferredEffectDecision {
    IdentityRepairRequired { cat_id: Id },
}

impl DeferredEffectDecision {
    fn into_run_step(self) -> RuntimeSpineRunStep {
        match self {
            Self::IdentityRepairRequired { cat_id } => {
                RuntimeSpineRunStep::EffectIdentityRepairRequired { cat_id }
            }
        }
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

enum RecoveryWait {
    Finished(anyhow::Result<RuntimePreScanRecoveryOutcome>),
    DeadlineExceeded,
}

enum AdmissionWait {
    Finished(anyhow::Result<RuntimePreScanAdmissionOutcome>),
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
    state: Arc<CoordinatorLaneState>,
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
    Finished(Box<anyhow::Result<RuntimeInventoryScanOutcome>>),
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
    coordinator_lane: Option<CoordinatorLane>,
    cat_effect_workers: Option<CatEffectWorkers>,
    effect_resource_owner: Option<Arc<dyn RuntimeEffectResourceOwner>>,
    current_process_scan_observation_id: Option<RandomId128>,
    current_process_partial_observation_id: Option<RandomId128>,
    current_process_node_global_process: Option<NodeGlobalManagedProcessAdmission>,
    current_process_node_global_network: Option<NodeGlobalNetworkAdmission>,
    current_process_kernel_nbd_pool: Option<KernelNbdPoolAdmission>,
    current_process_running_tail: Option<RunningTailAdmission>,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    current_process_data_directory_reclaim: Option<DataDirectoryReclaimAdmission>,
    effect_admission_open: bool,
    effect_admission: Option<RuntimeDesiredEffectAdmission>,
    node_global_effect_gate: Option<Arc<NodeGlobalEffectGate>>,
    node_global_effect_open: Option<Arc<AtomicBool>>,
    effect_batch_closing: bool,
    deferred_effect_decision: Option<DeferredEffectDecision>,
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
            None,
            None,
        )
    }

    /// Production composition for an effect which may transfer a bounded
    /// helper resource into process-local cleanup ownership after an ambiguous
    /// provider call.
    #[allow(
        clippy::too_many_arguments,
        reason = "production composition keeps each independently owned runtime port explicit"
    )]
    pub(crate) fn new_with_recovery_desired_effects_and_resource_owner(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
        pre_scan_admission: Arc<dyn RuntimePreScanAdmission>,
        recovery: Arc<dyn RuntimePreScanRecovery>,
        effect: Arc<dyn RuntimeDesiredEffect>,
        resource_owner: Arc<dyn RuntimeEffectResourceOwner>,
    ) -> Result<Self, RuntimeSpineRunError> {
        Self::new_inner(
            state_directory,
            registered_session,
            client,
            scanner,
            Some(effect),
            Some(pre_scan_admission),
            Some(recovery),
            Some(resource_owner),
        )
    }

    #[cfg(test)]
    pub(crate) fn set_effect_dispatch_count_for_test(
        &mut self,
        dispatch_count: Arc<AtomicUsize>,
    ) -> Result<(), RuntimeSpineRunError> {
        self.cat_effect_workers
            .as_mut()
            .ok_or(RuntimeSpineRunError::InvalidComposition(
                "test dispatch observer requires the Desired effect lane",
            ))?
            .set_dispatch_count_for_test(dispatch_count);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the private constructor preserves explicit optional production ports"
    )]
    fn new_inner(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
        effect: Option<Arc<dyn RuntimeDesiredEffect>>,
        pre_scan_admission: Option<Arc<dyn RuntimePreScanAdmission>>,
        recovery: Option<Arc<dyn RuntimePreScanRecovery>>,
        resource_owner: Option<Arc<dyn RuntimeEffectResourceOwner>>,
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
        if pre_scan_admission.is_some() && effect.is_none() {
            return Err(RuntimeSpineRunError::InvalidComposition(
                "pre-scan admission requires the serialized Desired mutation lane",
            ));
        }
        if resource_owner.is_some() && effect.is_none() {
            return Err(RuntimeSpineRunError::InvalidComposition(
                "effect resource owner requires the serialized Desired mutation lane",
            ));
        }
        let coordinator_lane = if pre_scan_admission.is_some() || recovery.is_some() {
            Some(CoordinatorLane::start(
                pre_scan_admission,
                recovery,
                resource_owner.clone(),
            )?)
        } else {
            None
        };
        let cat_effect_workers = effect
            .map(|effect| CatEffectWorkers::new(effect, MAX_CONCURRENT_CAT_EFFECT_WORKERS))
            .transpose()?;
        let journal_lane = JournalLane::start(state_directory.clone(), registered_session.clone())?;
        Ok(Self {
            state_directory,
            registered_session,
            client,
            journal_lane: Some(journal_lane),
            scan_lane: Some(scan_lane),
            coordinator_lane,
            cat_effect_workers,
            effect_resource_owner: resource_owner,
            current_process_scan_observation_id: None,
            current_process_partial_observation_id: None,
            current_process_node_global_process: None,
            current_process_node_global_network: None,
            current_process_kernel_nbd_pool: None,
            current_process_running_tail: None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            current_process_data_directory_reclaim: None,
            effect_admission_open: false,
            effect_admission: None,
            node_global_effect_gate: None,
            node_global_effect_open: None,
            effect_batch_closing: false,
            deferred_effect_decision: None,
            pending_effects: VecDeque::new(),
        })
    }

    /// Returns only the current-process complete observation whose accepted
    /// attestation opened this effect admission. Usage sampling must never be
    /// reconstructed from a retained checkpoint or a partial heartbeat.
    pub(crate) fn accepted_full_observation(&self) -> Option<NodeObservation> {
        self.effect_admission
            .as_ref()
            .map(|admission| admission.observation().clone())
    }

    pub async fn run_once_with_deadlines(
        &mut self,
        deadlines: RuntimeSpineRunDeadlines,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        if let Some(owner) = &self.effect_resource_owner {
            owner
                .poll()
                .map_err(|error| RuntimeSpineRunError::EffectResource(format!("{error:#}")))?;
        }
        // A timed-out blocking effect may still be returning from its provider
        // call. Do not start a fresh scan beside that unknown physical phase;
        // shutdown joins it before a successor runner establishes new
        // full-inventory admission.
        if self
            .coordinator_lane
            .as_ref()
            .is_some_and(CoordinatorLane::is_poisoned)
        {
            return Err(RuntimeSpineRunError::EffectLanePoisoned);
        }
        if self.effect_batch_is_live() {
            if let Some(step) = self.run_next_effect(deadlines.effect_step).await? {
                return Ok(step);
            }
        }
        let work = self.journal_lane()?.next().await?;

        match work {
            PendingWork::Desired(request) => self.send_desired(request).await,
            PendingWork::Observation(request) => self.send_observation(request).await,
            PendingWork::Scan(scan) => {
                let mut retained_admission = RuntimePreScanAdmissionOutcome::default();
                self.current_process_node_global_process = None;
                self.current_process_node_global_network = None;
                self.current_process_kernel_nbd_pool = None;
                self.current_process_running_tail = None;
                #[cfg(feature = "proposed-node-residue-reclamation")]
                {
                    self.current_process_data_directory_reclaim = None;
                }
                if self
                    .coordinator_lane
                    .as_ref()
                    .is_some_and(CoordinatorLane::has_pre_scan_admission)
                {
                    match self
                        .coordinator_lane()?
                        .reconcile_pre_scan_admission(scan.clone(), deadlines.effect_step)
                        .await?
                    {
                        AdmissionWait::Finished(Ok(outcome)) => {
                            retained_admission = outcome;
                        }
                        AdmissionWait::Finished(Err(error)) => {
                            return Ok(RuntimeSpineRunStep::PreScanAdmissionUnavailable(error));
                        }
                        AdmissionWait::DeadlineExceeded => {
                            return Ok(RuntimeSpineRunStep::PreScanAdmissionDeadlineExceeded);
                        }
                    }
                }
                if self
                    .coordinator_lane
                    .as_ref()
                    .is_some_and(CoordinatorLane::has_recovery)
                {
                    match self
                        .coordinator_lane()?
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
                        RecoveryWait::Finished(Ok(
                            RuntimePreScanRecoveryOutcome::ReplanDesired { cat_id },
                        )) => {
                            self.clear_effect_batch();
                            self.journal_lane()?
                                .invalidate_desired_after_effect_replan()
                                .await?;
                            return Ok(RuntimeSpineRunStep::EffectReplanDesired { cat_id });
                        }
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
                    ScanWait::Finished(result) => match *result {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            // An explicit scanner error is stronger than an
                            // unavailable source: the complete-source
                            // contract is corrupt, conflicting or foreign.
                            // The earlier endpoint-only latch may therefore
                            // no longer preserve any old route safely.
                            if let Some(coordinator_lane) = &self.coordinator_lane {
                                coordinator_lane.fail_close_all_admission();
                            }
                            return Ok(RuntimeSpineRunStep::ScanUnavailable(error));
                        }
                    },
                    ScanWait::DeadlineExceeded => {
                        return self
                            .publish_degraded_partial(
                                coordinates,
                                DegradedObservationCause::AttestationRefreshFailed,
                                retained_admission,
                                RuntimeSpineRunStep::ScanDeadlineExceeded,
                            )
                            .await;
                    }
                };
                if Instant::now() >= deadlines.scan {
                    return self
                        .publish_degraded_partial(
                            coordinates,
                            DegradedObservationCause::AttestationRefreshFailed,
                            retained_admission,
                            RuntimeSpineRunStep::ScanDeadlineExceeded,
                        )
                        .await;
                }
                let mut inventory = match outcome {
                    RuntimeInventoryScanOutcome::Complete(inventory) => *inventory,
                    RuntimeInventoryScanOutcome::Incomplete {
                        unavailable_sources,
                        exact_physical_negative_cats,
                    } => {
                        if unavailable_sources.is_empty() {
                            if let Some(coordinator_lane) = &self.coordinator_lane {
                                coordinator_lane.fail_close_all_admission();
                            }
                            return Err(RuntimeSpineRunError::InvalidScan(
                                "an incomplete scan has no unavailable source",
                            ));
                        }
                        apply_incomplete_physical_negatives(
                            &coordinates,
                            self.coordinator_lane.as_ref(),
                            &mut retained_admission,
                            &exact_physical_negative_cats,
                        )?;
                        return self
                            .publish_degraded_partial(
                                coordinates,
                                DegradedObservationCause::SourceUnavailable(
                                    unavailable_sources.clone(),
                                ),
                                retained_admission,
                                RuntimeSpineRunStep::ScanIncomplete {
                                    unavailable_sources,
                                },
                            )
                            .await;
                    }
                };
                let mut wire_budget_sources = inventory.residue_sources();
                let node_global_process = inventory.take_node_global_process_admission();
                let exact_running_negative_cats = node_global_process
                    .as_ref()
                    .map(NodeGlobalManagedProcessScanAdmission::exact_running_negative_cats)
                    .unwrap_or_default();
                let node_global_network = inventory.take_node_global_network_admission();
                let kernel_nbd_pool = inventory.take_kernel_nbd_pool_admission();
                let running_tail = inventory.take_running_tail_admission();
                #[cfg(feature = "proposed-node-residue-reclamation")]
                let data_directory_reclaim = inventory.take_data_directory_reclaim_admission();
                let mut candidate =
                    build_full_observation_candidate(coordinates.clone(), inventory);
                if node_observation_exceeds_wire_budget(&candidate)? {
                    apply_incomplete_physical_negatives(
                        &coordinates,
                        self.coordinator_lane.as_ref(),
                        &mut retained_admission,
                        &exact_running_negative_cats,
                    )?;
                    if wire_budget_sources.is_empty() {
                        wire_budget_sources.extend(REQUIRED_INVENTORY_SOURCES);
                    }
                    return self
                        .publish_degraded_partial(
                            coordinates,
                            DegradedObservationCause::WireBudgetExceeded(
                                wire_budget_sources.clone(),
                            ),
                            retained_admission,
                            RuntimeSpineRunStep::ScanIncomplete {
                                unavailable_sources: wire_budget_sources,
                            },
                        )
                        .await;
                }
                candidate.inventory_digest = Some(inventory_digest(&candidate)?);
                let node_global_process = node_global_process
                    .map(|admission| admission.bind(&candidate))
                    .transpose()
                    .map_err(|_| {
                        RuntimeSpineRunError::InvalidScan(
                            "provider-private process admission conflicts with full observation",
                        )
                    })?;
                let node_global_network = node_global_network
                    .map(|admission| admission.bind(&candidate))
                    .transpose()
                    .map_err(|_| {
                        RuntimeSpineRunError::InvalidScan(
                            "provider-private network admission conflicts with full observation",
                        )
                    })?;
                let kernel_nbd_pool = kernel_nbd_pool
                    .map(|admission| admission.bind(&candidate))
                    .transpose()
                    .map_err(|_| {
                        RuntimeSpineRunError::InvalidScan(
                            "provider-private kernel-NBD admission conflicts with full observation",
                        )
                    })?;
                let running_tail = running_tail
                    .map(|admission| admission.bind(&candidate))
                    .transpose()
                    .map_err(|_| {
                        RuntimeSpineRunError::InvalidScan(
                            "provider-private Running-tail admission conflicts with full observation",
                        )
                    })?;
                #[cfg(feature = "proposed-node-residue-reclamation")]
                let data_directory_reclaim = data_directory_reclaim
                    .map(|admission| admission.bind(&candidate))
                    .transpose()
                    .map_err(|_| {
                        RuntimeSpineRunError::InvalidScan(
                            "provider-private DataDirectory admission conflicts with full observation",
                        )
                    })?;
                self.current_process_node_global_process = node_global_process;
                self.current_process_node_global_network = node_global_network;
                self.current_process_kernel_nbd_pool = kernel_nbd_pool;
                self.current_process_running_tail = running_tail;
                #[cfg(feature = "proposed-node-residue-reclamation")]
                {
                    self.current_process_data_directory_reclaim = data_directory_reclaim;
                }
                let request = self.journal_lane()?.prepare_observation(candidate).await?;
                self.current_process_scan_observation_id =
                    Some(request.value().observation_id.clone());
                self.send_observation(request).await
            }
        }
    }

    async fn publish_degraded_partial(
        &mut self,
        coordinates: RuntimeSpineFullScan,
        cause: DegradedObservationCause,
        retained_admission: RuntimePreScanAdmissionOutcome,
        fallback: RuntimeSpineRunStep,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        let observed_at_unix_ms = current_unix_millis()?;
        let request = self
            .journal_lane()?
            .prepare_degraded_partial(coordinates, cause, retained_admission, observed_at_unix_ms)
            .await?;
        let Some(request) = request else {
            return Ok(fallback);
        };
        self.current_process_partial_observation_id = Some(request.value().observation_id.clone());
        self.send_observation(request).await
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

    fn coordinator_lane(&self) -> Result<&CoordinatorLane, RuntimeSpineRunError> {
        self.coordinator_lane
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("Desired effect".to_owned()))
    }

    fn take_workers(&mut self) -> RunnerWorkers {
        if let Some(open) = &self.node_global_effect_open {
            open.store(false, Ordering::Release);
        }
        RunnerWorkers {
            coordinator_lane: self.coordinator_lane.take(),
            cat_effect_workers: self.cat_effect_workers.take(),
            scan_lane: self.scan_lane.take(),
            journal_lane: self.journal_lane.take(),
            effect_resource_owner: self.effect_resource_owner.take(),
        }
    }

    fn effect_batch_is_live(&self) -> bool {
        !self.pending_effects.is_empty()
            || self.effect_batch_closing
            || self
                .cat_effect_workers
                .as_ref()
                .is_some_and(CatEffectWorkers::has_active)
    }

    async fn run_next_effect(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<RuntimeSpineRunStep>, RuntimeSpineRunError> {
        loop {
            if self.pending_effects.is_empty()
                && !self
                    .cat_effect_workers
                    .as_ref()
                    .is_some_and(CatEffectWorkers::has_active)
            {
                if let Some(decision) = self.deferred_effect_decision.take() {
                    self.finish_effect_batch();
                    return Ok(Some(decision.into_run_step()));
                }
                let closed = self.effect_batch_closing;
                self.finish_effect_batch();
                return if closed {
                    Ok(None)
                } else {
                    Ok(Some(RuntimeSpineRunStep::EffectsApplied))
                };
            }

            if !self.pending_effects.is_empty()
                && self
                    .effect_resource_owner
                    .as_ref()
                    .is_some_and(|owner| owner.has_pending())
            {
                let cat_id = self
                    .pending_effects
                    .front()
                    .expect("nonempty Desired effect queue has a front")
                    .cat_id
                    .clone();
                self.hard_close_effect_batch();
                return Ok(Some(RuntimeSpineRunStep::EffectUnavailable {
                    cat_id,
                    error: anyhow::anyhow!("runtime effect resource owner retains pending work"),
                }));
            }

            if !self.pending_effects.is_empty() && Instant::now() >= deadline {
                let desired = self
                    .pending_effects
                    .pop_front()
                    .expect("nonempty Desired effect queue has a front");
                let cat_id = desired.cat_id;
                self.require_refresh_after_cat_failure();
                return Ok(Some(RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id }));
            }

            let available_slots = self
                .cat_effect_workers
                .as_ref()
                .ok_or_else(|| {
                    RuntimeSpineRunError::WorkerStopped("per-Cat Desired effect".to_owned())
                })?
                .available_slots();
            if available_slots > 0 && !self.pending_effects.is_empty() {
                let gate = self
                    .node_global_effect_gate
                    .get_or_insert_with(|| Arc::new(NodeGlobalEffectGate::default()))
                    .clone();
                let open = self
                    .node_global_effect_open
                    .get_or_insert_with(|| Arc::new(AtomicBool::new(!self.effect_batch_closing)))
                    .clone();
                let state_directory = self.state_directory.clone();
                let admission = self.effect_admission.clone();
                for _ in 0..available_slots {
                    let Some(desired) = self.pending_effects.pop_front() else {
                        break;
                    };
                    self.cat_effect_workers
                        .as_mut()
                        .ok_or_else(|| {
                            RuntimeSpineRunError::WorkerStopped("per-Cat Desired effect".to_owned())
                        })?
                        .dispatch(
                            state_directory.clone(),
                            desired,
                            admission.clone(),
                            Arc::clone(&gate),
                            Arc::clone(&open),
                            deadline,
                        )?;
                }
            }

            let wait = self
                .cat_effect_workers
                .as_mut()
                .ok_or_else(|| {
                    RuntimeSpineRunError::WorkerStopped("per-Cat Desired effect".to_owned())
                })?
                .wait_next(deadline)
                .await?;
            match wait {
                CatEffectWait::Finished { desired, result } => {
                    if self
                        .node_global_effect_open
                        .as_ref()
                        .is_some_and(|open| !open.load(Ordering::Acquire))
                    {
                        // A worker consumed the one-shot Node-global part of
                        // this accepted full admission. Cat-local siblings
                        // may finish, but the next coordinator phase is a
                        // fresh full scan.
                        self.effect_batch_closing = true;
                    }
                    let cat_id = desired.cat_id.clone();
                    match result {
                        Ok(RuntimeDesiredEffectOutcome::Applied) => {
                            let drained = self.pending_effects.is_empty()
                                && !self
                                    .cat_effect_workers
                                    .as_ref()
                                    .is_some_and(CatEffectWorkers::has_active);
                            if drained && !self.effect_batch_closing {
                                self.finish_effect_batch();
                                return Ok(Some(RuntimeSpineRunStep::EffectsApplied));
                            }
                            if drained {
                                self.finish_effect_batch();
                            }
                            return Ok(Some(RuntimeSpineRunStep::EffectApplied { cat_id }));
                        }
                        Ok(RuntimeDesiredEffectOutcome::RetryExact) => {
                            self.pending_effects.push_back(*desired);
                            return Ok(Some(RuntimeSpineRunStep::EffectRetryExact { cat_id }));
                        }
                        Ok(RuntimeDesiredEffectOutcome::RefreshInventory) => {
                            self.hard_close_effect_batch();
                            return Ok(Some(RuntimeSpineRunStep::EffectRefreshInventory {
                                cat_id,
                            }));
                        }
                        Ok(RuntimeDesiredEffectOutcome::ReplanDesired) => {
                            // Close the accepted batch before the fallible
                            // durable invalidation. Sibling completions are
                            // drained but can no longer publish an outcome.
                            self.hard_close_effect_batch();
                            self.journal_lane()?
                                .invalidate_desired_after_effect_replan()
                                .await?;
                            return Ok(Some(RuntimeSpineRunStep::EffectReplanDesired { cat_id }));
                        }
                        Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired) => {
                            self.hard_close_effect_batch();
                            // Identity repair parks the production Node loop.
                            // Defer that terminal action until every cancelled
                            // sibling is joined so no late provider thread can
                            // live forever beside the parked task.
                            self.deferred_effect_decision =
                                Some(DeferredEffectDecision::IdentityRepairRequired { cat_id });
                        }
                        Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired) => {
                            self.hard_close_effect_batch();
                            return Ok(Some(
                                RuntimeSpineRunStep::EffectSessionReplacementRequired { cat_id },
                            ));
                        }
                        Ok(RuntimeDesiredEffectOutcome::Stop(reason)) => {
                            // Stop is scoped to this exact Cat. It must not
                            // terminate or cancel independent Cat workers,
                            // but the batch was not wholly Applied and must
                            // return through a fresh accepted full scan.
                            self.require_refresh_after_cat_failure();
                            let drained = self.pending_effects.is_empty()
                                && !self
                                    .cat_effect_workers
                                    .as_ref()
                                    .is_some_and(CatEffectWorkers::has_active);
                            if drained {
                                self.finish_effect_batch();
                            }
                            return Ok(Some(RuntimeSpineRunStep::EffectStopped { cat_id, reason }));
                        }
                        Err(error) => {
                            // The unknown phase withdraws only this Cat's
                            // unit. Close Node-global use of the shared full
                            // admission, while already admitted Cat-local
                            // siblings retain their independent workers.
                            self.require_refresh_after_cat_failure();
                            return Ok(Some(RuntimeSpineRunStep::EffectUnavailable {
                                cat_id,
                                error,
                            }));
                        }
                    }
                }
                CatEffectWait::DeadlineExceeded { cat_id } => {
                    self.require_refresh_after_cat_failure();
                    return Ok(Some(RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id }));
                }
                CatEffectWait::AwaitingLateWorker { cat_id } => {
                    return Ok(Some(RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id }));
                }
                CatEffectWait::LateWorkerJoined { cat_id }
                | CatEffectWait::Discarded { cat_id } => {
                    let _ = cat_id;
                    // A late or invalidated result carries no reusable phase
                    // claim. Drain it, then either wait for siblings or let
                    // the durable journal start the mandatory fresh scan.
                }
            }
        }
    }

    fn clear_effect_batch(&mut self) {
        self.hard_close_effect_batch();
    }

    fn require_refresh_after_cat_failure(&mut self) {
        self.effect_admission_open = false;
        self.effect_batch_closing = true;
        if let Some(open) = &self.node_global_effect_open {
            open.store(false, Ordering::Release);
        }
    }

    fn hard_close_effect_batch(&mut self) {
        self.pending_effects.clear();
        self.effect_admission = None;
        self.effect_admission_open = false;
        self.effect_batch_closing = true;
        if let Some(open) = &self.node_global_effect_open {
            open.store(false, Ordering::Release);
        }
        if let Some(workers) = &mut self.cat_effect_workers {
            workers.cancel_all_and_discard();
        }
    }

    fn finish_effect_batch(&mut self) {
        self.pending_effects.clear();
        self.effect_admission = None;
        self.effect_admission_open = false;
        if let Some(open) = &self.node_global_effect_open {
            open.store(false, Ordering::Release);
        }
        self.node_global_effect_gate = None;
        self.node_global_effect_open = None;
        self.effect_batch_closing = false;
    }

    async fn send_desired(
        &mut self,
        request: DurableRuntimeSpineRequest<DesiredReadRequest>,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        match self.client.desired_read(request.bytes()).await? {
            RuntimeSpineAttempt::Accepted(accepted) => {
                let desired_specs = accepted.value.desired_specs.clone();
                if self.cat_effect_workers.is_some() && self.effect_admission_open {
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
                if self.cat_effect_workers.is_some() && self.effect_admission_open {
                    self.effect_admission_open = false;
                    self.pending_effects = desired_specs.into();
                    if self.pending_effects.is_empty() {
                        self.finish_effect_batch();
                        Ok(RuntimeSpineRunStep::EffectsApplied)
                    } else {
                        self.node_global_effect_gate =
                            Some(Arc::new(NodeGlobalEffectGate::default()));
                        self.node_global_effect_open = Some(Arc::new(AtomicBool::new(true)));
                        self.effect_batch_closing = false;
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
                let establishes_partial_heartbeat = !request.value().complete_inventory
                    && self.current_process_partial_observation_id.as_ref()
                        == Some(&request.value().observation_id);
                let degraded_runtimes = request.value().runtimes.len();
                let settled = self
                    .effect_resource_owner
                    .as_ref()
                    .is_none_or(|owner| !owner.has_pending());
                let inventory_attested = establishes_effect_admission && settled;
                let service_ready =
                    inventory_attested && observation_opens_service_readiness(request.value());
                let admission = if establishes_effect_admission {
                    let node_global_process = self.current_process_node_global_process.take();
                    let node_global_network = self.current_process_node_global_network.take();
                    let kernel_nbd_pool = self.current_process_kernel_nbd_pool.take();
                    let running_tail = self.current_process_running_tail.take();
                    #[cfg(feature = "proposed-node-residue-reclamation")]
                    let data_directory_reclaim = self.current_process_data_directory_reclaim.take();
                    Some(
                        RuntimeDesiredEffectAdmission::from_acceptance(
                            self.registered_session.clone(),
                            request.value().clone(),
                            &accepted.value,
                            node_global_process,
                            node_global_network,
                            kernel_nbd_pool,
                            running_tail,
                            #[cfg(feature = "proposed-node-residue-reclamation")]
                            data_directory_reclaim,
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
                self.current_process_partial_observation_id = None;
                self.current_process_node_global_process = None;
                self.current_process_node_global_network = None;
                self.current_process_kernel_nbd_pool = None;
                self.current_process_running_tail = None;
                #[cfg(feature = "proposed-node-residue-reclamation")]
                {
                    self.current_process_data_directory_reclaim = None;
                }
                if establishes_effect_admission {
                    self.effect_admission = admission;
                    self.effect_admission_open = true;
                    self.node_global_effect_gate = None;
                    self.node_global_effect_open = None;
                    self.effect_batch_closing = false;
                    self.deferred_effect_decision = None;
                    Ok(RuntimeSpineRunStep::ObservationAccepted {
                        service_ready,
                        inventory_attested,
                    })
                } else if establishes_partial_heartbeat {
                    Ok(RuntimeSpineRunStep::PartialObservationAccepted { degraded_runtimes })
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
                        self.current_process_partial_observation_id = None;
                        self.current_process_node_global_process = None;
                        self.current_process_node_global_network = None;
                        self.current_process_kernel_nbd_pool = None;
                        self.current_process_running_tail = None;
                        #[cfg(feature = "proposed-node-residue-reclamation")]
                        {
                            self.current_process_data_directory_reclaim = None;
                        }
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
    coordinator_lane: Option<CoordinatorLane>,
    cat_effect_workers: Option<CatEffectWorkers>,
    scan_lane: Option<ScanLane>,
    journal_lane: Option<JournalLane>,
    effect_resource_owner: Option<Arc<dyn RuntimeEffectResourceOwner>>,
}

impl RunnerWorkers {
    fn shutdown_blocking(mut self) -> Result<(), RuntimeSpineRunError> {
        if let Some(workers) = self.cat_effect_workers.as_ref() {
            workers.cancel_all();
        }
        if let Some(coordinator) = self.coordinator_lane.as_ref() {
            coordinator.cancel_and_poison();
        }
        if let Some(scan) = self.scan_lane.as_ref() {
            scan.cancel_and_poison();
        }
        let cat_effect_result = self
            .cat_effect_workers
            .as_mut()
            .map_or(Ok(()), CatEffectWorkers::shutdown_blocking);
        // Drop the producer implementation before asking its resource owner
        // to prove that every late helper has been reaped.
        self.cat_effect_workers.take();
        let coordinator_result = self
            .coordinator_lane
            .as_mut()
            .map_or(Ok(()), CoordinatorLane::shutdown_blocking);
        // All Cat producers and the Node coordinator have now closed. Attempt
        // bounded cleanup before scanner/journal teardown can be reported as
        // a clean runner shutdown.
        let effect_resource_result = self.effect_resource_owner.as_ref().map_or(Ok(()), |owner| {
            let shutdown_once = || {
                let deadline = Instant::now()
                    .checked_add(EFFECT_RESOURCE_SHUTDOWN_TIMEOUT)
                    .unwrap_or_else(Instant::now);
                owner.shutdown_until(deadline)
            };
            match shutdown_once() {
                Ok(()) => Ok(()),
                Err(first_error) => {
                    // The Host registration lease lives outside this runner
                    // task and is released only after shutdown returns. Never
                    // turn a bounded timeout into a leaked owner followed by
                    // lease release: retain and retry until every late helper
                    // is reaped. A permanently uncooperative helper therefore
                    // quarantines this task without reopening Host authority.
                    loop {
                        std::thread::sleep(EFFECT_RESOURCE_SHUTDOWN_RETRY_INTERVAL);
                        if shutdown_once().is_ok() {
                            break Err(RuntimeSpineRunError::WorkerShutdown(format!(
                                "effect resource owner: {first_error:#}"
                            )));
                        }
                    }
                }
            }
        });
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
        match (
            cat_effect_result,
            coordinator_result,
            effect_resource_result,
            scan_result,
            journal_result,
        ) {
            (Ok(()), Ok(()), Ok(()), Ok(()), Ok(())) => Ok(()),
            (cat_effect, coordinator, effect_resource, scan, journal) => {
                let mut failures = Vec::new();
                if let Err(error) = cat_effect {
                    failures.push(format!("per-Cat Desired effect: {error}"));
                }
                if let Err(error) = coordinator {
                    failures.push(format!("effect coordinator: {error}"));
                }
                if let Err(error) = effect_resource {
                    failures.push(format!("effect resource owner: {error}"));
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

fn current_unix_millis() -> Result<UnixMillis, RuntimeSpineRunError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeSpineRunError::InvalidScan("system clock is before the Unix epoch"))?;
    let millis = u64::try_from(elapsed.as_millis())
        .map_err(|_| RuntimeSpineRunError::InvalidScan("system clock exceeds UnixMillis"))?;
    UnixMillis::new(millis).ok_or(RuntimeSpineRunError::InvalidScan(
        "system clock is not a valid UnixMillis",
    ))
}

fn apply_incomplete_physical_negatives(
    coordinates: &RuntimeSpineFullScan,
    coordinator_lane: Option<&CoordinatorLane>,
    retained_admission: &mut RuntimePreScanAdmissionOutcome,
    exact_physical_negative_cats: &BTreeSet<Id>,
) -> Result<(), RuntimeSpineRunError> {
    let assigned = coordinates
        .desired
        .desired_specs
        .iter()
        .map(|desired| &desired.cat_id)
        .collect::<BTreeSet<_>>();
    if exact_physical_negative_cats
        .iter()
        .any(|cat_id| !assigned.contains(cat_id))
    {
        if let Some(coordinator_lane) = coordinator_lane {
            coordinator_lane.fail_close_all_admission();
        }
        return Err(RuntimeSpineRunError::InvalidScan(
            "an incomplete scan named a physical-negative Cat outside Desired",
        ));
    }
    if !exact_physical_negative_cats.is_empty() {
        // Close the live cell before allowing the journal lane to clone any
        // old full Runtime into a partial heartbeat.
        if let Some(coordinator_lane) = coordinator_lane {
            coordinator_lane.fail_close_admission_cats(exact_physical_negative_cats);
        }
        retained_admission.exclude(exact_physical_negative_cats);
    }
    Ok(())
}

fn build_degraded_partial_observation(
    scan: RuntimeSpineFullScan,
    full: Option<&NodeObservation>,
    last: Option<&NodeObservation>,
    cause: DegradedObservationCause,
    retained_admission: &RuntimePreScanAdmissionOutcome,
    observed_at_unix_ms: UnixMillis,
) -> Option<NodeObservation> {
    let full = full.filter(|observation| {
        observation.complete_inventory
            && observation.node_id == scan.session.node_id
            && observation.node_boot_id == scan.session.node_boot_id
            && observation.agent_instance_id == scan.session.agent_instance_id
            && observation.agent_session_epoch == scan.session.agent_session_epoch
    });
    let wire_budget_exceeded = matches!(&cause, DegradedObservationCause::WireBudgetExceeded(_));
    let reason = match cause {
        DegradedObservationCause::SourceUnavailable(unavailable_sources)
        | DegradedObservationCause::WireBudgetExceeded(unavailable_sources) => {
            let sources = unavailable_sources
                .into_iter()
                .map(degraded_source)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if sources.is_empty() {
                return None;
            }
            DegradedReasonTemplate::SourceUnavailable(sources)
        }
        DegradedObservationCause::AttestationRefreshFailed => {
            DegradedReasonTemplate::AttestationRefreshFailed
        }
    };
    // Accepted Runtime Inventory §5 permits a partial only after Control has
    // accepted a full attestation for this session.  In particular, a first
    // scan which exceeds the wire budget must remain a local Incomplete result;
    // inventing an unanchored empty partial here would create a protocol that
    // both the durable journal and Control correctly reject.
    let full = full?;

    let desired_by_cat = scan
        .desired
        .desired_specs
        .iter()
        .map(|desired| (&desired.cat_id, desired))
        .collect::<BTreeMap<_, _>>();
    let mut runtimes = Vec::new();
    for runtime in &full.runtimes {
        let Some(desired) = desired_by_cat.get(&runtime.cat_id) else {
            continue;
        };
        let exact_physical_negative = retained_admission
            .exact_physical_negative_cats
            .contains(&runtime.cat_id);
        if !is_proven_current_running(runtime, desired)
            || (!exact_physical_negative && !retained_admission.retains(&runtime.cat_id))
        {
            continue;
        }
        let previous_reason = last
            .filter(|observation| observation.inventory_epoch == full.inventory_epoch)
            .and_then(|observation| {
                observation
                    .runtimes
                    .iter()
                    .find(|candidate| candidate.cat_id == runtime.cat_id)
            })
            .and_then(|runtime| runtime.conditions.iter().find_map(degraded_reason));
        let since_unix_ms = match (&reason, previous_reason) {
            (
                DegradedReasonTemplate::SourceUnavailable(_),
                Some(DegradedReason::SourceUnavailable { since_unix_ms, .. }),
            )
            | (
                DegradedReasonTemplate::AttestationRefreshFailed,
                Some(DegradedReason::AttestationRefreshFailed { since_unix_ms, .. }),
            ) => since_unix_ms,
            _ => observed_at_unix_ms,
        };
        let mut degraded = runtime.clone();
        if exact_physical_negative {
            // The private Node-global process sweep proved that the exact VMM
            // which made this old Running/Open status route-ready is absent
            // (or no longer Running). Publish that Cat explicitly: omission
            // from a partial deliberately leaves Control's prior Cat row
            // unchanged. The process-local cell was closed before this
            // projection was handed to the journal lane.
            degraded.lifecycle_admission = LifecycleAdmission::Closed;
            for route in &mut degraded.routes {
                route.gate = RouteGateState::Closed;
                route.cancellation_pending = true;
            }
            let expected_incarnation = degraded.runtime_incarnation.clone();
            degraded.processes.retain(|process| {
                !matches!(
                    &process.role,
                    ProcessRole::Vmm {
                        runtime_incarnation
                    } if Some(runtime_incarnation) == expected_incarnation.as_ref()
                )
            });
            degraded
                .conditions
                .retain(|condition| !matches!(condition, Condition::Ready { .. }));
        }
        degraded
            .conditions
            .retain(|condition| !matches!(condition, Condition::Degraded { .. }));
        degraded.conditions.push(Condition::Degraded {
            reason: match &reason {
                DegradedReasonTemplate::SourceUnavailable(sources) => {
                    DegradedReason::SourceUnavailable {
                        sources: sources.clone(),
                        since_unix_ms,
                    }
                }
                DegradedReasonTemplate::AttestationRefreshFailed => {
                    DegradedReason::AttestationRefreshFailed {
                        inventory_epoch: full.inventory_epoch,
                        since_unix_ms,
                    }
                }
            },
        });
        runtimes.push(degraded);
    }
    if runtimes.is_empty() && !wire_budget_exceeded {
        return None;
    }

    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .expect("a simple UUID is a valid RandomId128"),
        node_id: scan.session.node_id,
        node_boot_id: scan.session.node_boot_id,
        agent_instance_id: scan.session.agent_instance_id,
        agent_session_epoch: scan.session.agent_session_epoch,
        heartbeat_sequence: scan.heartbeat_sequence,
        observed_at_unix_ms,
        complete_inventory: false,
        inventory_epoch: full.inventory_epoch,
        inventory_digest: None,
        inventory_read_position: None,
        key_ring_version: full.key_ring_version,
        key_ring_digest: full.key_ring_digest.clone(),
        loaded_kids: full.loaded_kids.clone(),
        runtimes,
        residue: Vec::new(),
    };
    if !fit_partial_observation_to_wire_budget(
        &mut observation,
        &retained_admission.exact_physical_negative_cats,
    ) {
        return None;
    }
    if observation.runtimes.is_empty() && !wire_budget_exceeded {
        return None;
    }
    Some(observation)
}

fn fit_partial_observation_to_wire_budget(
    observation: &mut NodeObservation,
    protected_cats: &BTreeSet<Id>,
) -> bool {
    let Ok(mut wire_size) = node_observation_canonical_wire_size(observation) else {
        return false;
    };
    while wire_size > NODE_OBSERVATION_MAX_WIRE_BYTES {
        let Some(remove_index) = observation
            .runtimes
            .iter()
            .rposition(|runtime| !protected_cats.contains(&runtime.cat_id))
        else {
            return false;
        };
        let removed = observation.runtimes.remove(remove_index);
        let Ok(encoded) = serde_json::to_vec(&removed) else {
            return false;
        };
        // Removing a final array member removes its exact JSON bytes and, when
        // another member remains, the separating comma. Object-key order does
        // not change encoded length, so this stays exact without repeatedly
        // serializing an up-to-8-MiB observation.
        let separator = usize::from(!observation.runtimes.is_empty());
        let Some(smaller) = wire_size.checked_sub(encoded.len() + separator) else {
            return false;
        };
        wire_size = smaller;
    }
    debug_assert_eq!(
        node_observation_canonical_wire_size(observation).ok(),
        Some(wire_size)
    );
    true
}

enum DegradedReasonTemplate {
    SourceUnavailable(Vec<DegradedSource>),
    AttestationRefreshFailed,
}

fn degraded_reason(condition: &Condition) -> Option<DegradedReason> {
    match condition {
        Condition::Degraded { reason } => Some(reason.clone()),
        _ => None,
    }
}

fn is_proven_current_running(
    runtime: &ObservedRuntimeStatus,
    desired: &DesiredRuntimeSpec,
) -> bool {
    let expected = AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    };
    let Some(incarnation) = runtime.runtime_incarnation.as_ref() else {
        return false;
    };
    desired.target == RuntimeTarget::Running
        && runtime.applied_desired.as_ref() == Some(&expected)
        && runtime.stable_state == Some(StableState::Running)
        && matches!(
            runtime.step,
            ReconcileStep::Stable {
                state: StableState::Running
            }
        )
        && runtime.lifecycle_admission == LifecycleAdmission::Open
        && runtime.conditions.iter().any(|condition| {
            matches!(
                condition,
                Condition::Ready {
                    reason: ReadyReason::PostconditionSatisfied {
                        target: RuntimeTarget::Running
                    }
                }
            )
        })
        && runtime.conditions.iter().all(|condition| {
            matches!(
                condition,
                Condition::Ready { .. } | Condition::Degraded { .. }
            )
        })
        && runtime
            .processes
            .iter()
            .filter(|process| {
                matches!(
                    &process.role,
                    ProcessRole::Vmm {
                        runtime_incarnation
                    } if runtime_incarnation == incarnation
                ) && process.state == ProcessState::Running
            })
            .count()
            == 1
}

fn degraded_source(source: InventorySource) -> DegradedSource {
    match source {
        InventorySource::Checkpoint => DegradedSource::Checkpoint,
        InventorySource::Systemd => DegradedSource::Systemd,
        InventorySource::Process => DegradedSource::Process,
        InventorySource::ControlSocket => DegradedSource::ControlSocket,
        InventorySource::BlockFrontend => DegradedSource::BlockFrontend,
        InventorySource::Network => DegradedSource::Network,
        InventorySource::DataDirectory => DegradedSource::DataDirectory,
        InventorySource::PendingPack => DegradedSource::PendingPack,
        InventorySource::WarmSnapshot => DegradedSource::WarmSnapshot,
        InventorySource::MetadataStore => DegradedSource::MetadataStore,
        InventorySource::GuestMount => DegradedSource::GuestMount,
    }
}

#[cfg(test)]
fn build_full_observation(
    scan: RuntimeSpineFullScan,
    inventory: CompleteRuntimeInventory,
) -> Result<NodeObservation, ContractError> {
    let mut observation = build_full_observation_candidate(scan, inventory);
    observation.inventory_digest = Some(inventory_digest(&observation)?);
    Ok(observation)
}

fn build_full_observation_candidate(
    scan: RuntimeSpineFullScan,
    inventory: CompleteRuntimeInventory,
) -> NodeObservation {
    let (key_ring_version, key_ring_digest, loaded_kids) = match inventory.key_ring {
        RuntimeInventoryKeyRing::Unavailable => (None, None, Vec::new()),
        RuntimeInventoryKeyRing::Loaded {
            version,
            digest,
            kids,
        } => (Some(version), Some(digest), kids),
    };
    NodeObservation {
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
    }
}

fn node_observation_exceeds_wire_budget(
    observation: &NodeObservation,
) -> Result<bool, ContractError> {
    Ok(node_observation_canonical_wire_size(observation)? > NODE_OBSERVATION_MAX_WIRE_BYTES)
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc as test_mpsc, Mutex};

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
    use cats_api::route_grant_v2::{
        RouteAdmissionV2Reason, RouteGrantV2Claims, RouteGrantV2TimeVerdict,
        ROUTE_GRANT_V2_AUDIENCE, ROUTE_GRANT_V2_ISSUER, ROUTE_GRANT_V2_VERSION,
    };
    use cats_api::runtime_reconciliation::{
        decode_agent_session, decode_desired_read_request, decode_desired_read_snapshot,
        decode_node_observation, decode_runtime_checkpoint, encode_desired_read_snapshot,
        encode_node_observation, encode_observation_acceptance, encode_runtime_spine_error,
        spec_digest, AdmissionInventoryAttestation, AppliedDesiredEvidence, AssignedKind,
        AssignedPlacement, CheckpointEvidence, CheckpointRouteGate, Condition, ContractVersion,
        ControlHandshakeEvidence, EndpointIntent, FenceEpoch, GuestBootId, GuestTransportEvidence,
        HostPath, Hostname, HttpProtocol, Id, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission,
        MacAddress, NetworkConfig, ObservationAcceptance, ObservationInventoryAcceptance,
        ObservedRouteGate, ObservedVmShape, OwnershipTokenEvidence, ProcessEvidence, ProcessRole,
        ProcessState, ReadyReason, ReconcileStep, Revision, RouteGateBinding, RouteGateState,
        RuntimeConfig, RuntimeLaunch, RuntimeSpineErrorDetail, RuntimeTarget, RuntimeTransition,
        Sequence, SessionBinding, StableState, UnixMillis, WarmSnapshotEvidence, WireU64,
        DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
    };
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use crate::ch::{BlockPath, ChConfig, ChNetwork};
    use crate::runtime::reconciliation::{AdmissionCell, AdmissionSnapshot, VmmProcessExpectation};
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

    struct WireOverflowScanner {
        calls: AtomicUsize,
    }

    struct ExactRunningNegativeWireOverflowScanner;

    struct TransientRunningProbeScanner {
        calls: AtomicUsize,
    }

    struct DelayedTransientRunningProbeScanner {
        calls: AtomicUsize,
        delay: Duration,
    }

    struct InvalidIncompleteScanner;

    struct ErrorScanner;

    fn wire_overflow_residue() -> Vec<NodeResidue> {
        (0..cats_api::runtime_reconciliation::NODE_OBSERVATION_MAX_RESIDUE_ITEMS)
            .map(|index| NodeResidue::ControlSocket {
                // 4,096 stable items can exceed the wire budget even though
                // the independent item-count budget is satisfied.
                socket_path: HostPath::new(format!("/{}-{index:04}", "x".repeat(2_194))).unwrap(),
                role_hint: None,
                ownership_token: OwnershipTokenEvidence::Missing,
            })
            .collect()
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for IncompleteScanner {}

    impl RuntimeInventoryScanner for IncompleteScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            context.check_active()?;
            Ok(RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources: vec![InventorySource::Process],
                exact_physical_negative_cats: BTreeSet::new(),
            })
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for WireOverflowScanner {}

    impl RuntimeInventoryScanner for WireOverflowScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            context.check_active()?;
            let mut inventory = CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                Vec::new(),
                wire_overflow_residue(),
            );
            inventory
                .residue_sources
                .insert(InventorySource::ControlSocket);
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(inventory)))
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed
        for ExactRunningNegativeWireOverflowScanner
    {
    }

    impl RuntimeInventoryScanner for ExactRunningNegativeWireOverflowScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            context.check_active()?;
            let desired = context
                .coordinates()
                .desired
                .desired_specs
                .first()
                .context("test Desired lacks its Running Cat")?;
            let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
            )))?;
            anyhow::ensure!(
                checkpoint.cat_id == desired.cat_id,
                "test absent-VMM expectation names another Cat"
            );
            let vmm = VmmProcessExpectation::from_checkpoint(checkpoint)?.with_checkpoint_path(
                HostPath::new("/var/lib/cats/checkpoints/cat_01.json")
                    .context("test checkpoint path is canonical")?,
            )?;
            let process_admission = NodeGlobalManagedProcessScanAdmission::from_root_controls(
                BTreeMap::new(),
                BTreeMap::new(),
            )?
            .with_vmms(
                BTreeMap::from([(desired.cat_id.clone(), vmm)]),
                BTreeMap::new(),
            )?;
            let mut inventory = CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_020_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                Vec::new(),
                wire_overflow_residue(),
            )
            .with_node_global_process_admission(Some(process_admission));
            inventory
                .residue_sources
                .insert(InventorySource::ControlSocket);
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(inventory)))
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for TransientRunningProbeScanner {}

    impl RuntimeInventoryScanner for TransientRunningProbeScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            context.check_active()?;
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call < 2 {
                return Ok(RuntimeInventoryScanOutcome::Incomplete {
                    unavailable_sources: vec![InventorySource::Process],
                    exact_physical_negative_cats: BTreeSet::new(),
                });
            }
            let desired = context
                .coordinates()
                .desired
                .desired_specs
                .first()
                .expect("test Desired contains the Running Cat");
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(
                CompleteRuntimeInventory::for_test(
                    UnixMillis::new(1_720_000_020_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    vec![ready_running_runtime(desired)],
                    Vec::new(),
                ),
            )))
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed
        for DelayedTransientRunningProbeScanner
    {
    }

    impl RuntimeInventoryScanner for DelayedTransientRunningProbeScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                std::thread::sleep(self.delay);
                context.check_active()?;
                unreachable!("test scanner's first call must be cancelled by its deadline")
            }
            context.check_active()?;
            let desired = context
                .coordinates()
                .desired
                .desired_specs
                .first()
                .expect("test Desired contains the Running Cat");
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(
                CompleteRuntimeInventory::for_test(
                    UnixMillis::new(1_720_000_020_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    vec![ready_running_runtime(desired)],
                    Vec::new(),
                ),
            )))
        }
    }

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for ErrorScanner {}

    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for InvalidIncompleteScanner {}

    impl RuntimeInventoryScanner for InvalidIncompleteScanner {
        fn scan_complete(
            &self,
            _context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            Ok(RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources: Vec::new(),
                exact_physical_negative_cats: BTreeSet::new(),
            })
        }
    }

    impl RuntimeInventoryScanner for ErrorScanner {
        fn scan_complete(
            &self,
            _context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            anyhow::bail!("injected complete-source conflict")
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
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(
                CompleteRuntimeInventory::for_test(
                    UnixMillis::new(1_720_000_004_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    runtimes,
                    Vec::new(),
                ),
            )))
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

    struct TestPreScanAdmission {
        calls: AtomicUsize,
        fail_closes: AtomicUsize,
        fail: AtomicBool,
    }

    struct CellBackedPreScanAdmission {
        cat_id: Id,
        cell: Arc<AdmissionCell>,
        fail_closes: AtomicUsize,
    }

    struct OrderedPreScanAdmission {
        calls: AtomicUsize,
        cell_open: Arc<AtomicBool>,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    struct OrderedReplanRecovery {
        calls: AtomicUsize,
        cat_id: Id,
        cell_open: Arc<AtomicBool>,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    struct TestEffectResourceOwner {
        pending: AtomicBool,
        polls: AtomicUsize,
        shutdowns: AtomicUsize,
        shutdown_failures: AtomicUsize,
        effect_dropped: Option<Arc<AtomicBool>>,
    }

    impl TestEffectResourceOwner {
        fn new(pending: bool) -> Self {
            Self {
                pending: AtomicBool::new(pending),
                polls: AtomicUsize::new(0),
                shutdowns: AtomicUsize::new(0),
                shutdown_failures: AtomicUsize::new(0),
                effect_dropped: None,
            }
        }
    }

    impl effect_resource_owner_sealed::Sealed for TestEffectResourceOwner {}

    impl RuntimeEffectResourceOwner for TestEffectResourceOwner {
        fn poll(&self) -> anyhow::Result<()> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn has_pending(&self) -> bool {
            self.pending.load(Ordering::SeqCst)
        }

        fn shutdown_until(&self, _deadline: Instant) -> anyhow::Result<()> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            if let Some(effect_dropped) = &self.effect_dropped {
                anyhow::ensure!(
                    effect_dropped.load(Ordering::SeqCst),
                    "resource shutdown ran before the effect producer joined"
                );
            }
            if self
                .shutdown_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                anyhow::bail!("injected resource shutdown timeout");
            }
            self.pending.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    struct DropWitnessEffect {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropWitnessEffect {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl RuntimeDesiredEffect for DropWitnessEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            _desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            Ok(RuntimeDesiredEffectOutcome::Applied)
        }
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

    impl RuntimePreScanAdmission for TestPreScanAdmission {
        fn reconcile(
            &self,
            context: RuntimePreScanAdmissionContext,
        ) -> anyhow::Result<RuntimePreScanAdmissionOutcome> {
            context.check_active()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(
                !self.fail.load(Ordering::SeqCst),
                "injected admission failure"
            );
            Ok(RuntimePreScanAdmissionOutcome::retained_running_cats(
                context
                    .coordinates()
                    .desired
                    .desired_specs
                    .iter()
                    .map(|desired| desired.cat_id.clone()),
            ))
        }

        fn fail_close_all(&self) {
            self.fail_closes.fetch_add(1, Ordering::SeqCst);
        }

        fn fail_close_cats(&self, _cat_ids: &BTreeSet<Id>) {
            self.fail_closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RuntimePreScanAdmission for CellBackedPreScanAdmission {
        fn reconcile(
            &self,
            context: RuntimePreScanAdmissionContext,
        ) -> anyhow::Result<RuntimePreScanAdmissionOutcome> {
            context.check_active()?;
            anyhow::ensure!(
                context
                    .coordinates()
                    .desired
                    .desired_specs
                    .iter()
                    .any(|desired| desired.cat_id == self.cat_id),
                "test admission Cat is outside Desired"
            );
            Ok(RuntimePreScanAdmissionOutcome::retained_running_cats([
                self.cat_id.clone(),
            ]))
        }

        fn fail_close_all(&self) {
            self.fail_closes.fetch_add(1, Ordering::SeqCst);
            self.cell.force_close();
        }

        fn fail_close_cats(&self, cat_ids: &BTreeSet<Id>) {
            if cat_ids.contains(&self.cat_id) {
                self.fail_closes.fetch_add(1, Ordering::SeqCst);
                self.cell.force_close();
            }
        }
    }

    impl RuntimePreScanAdmission for OrderedPreScanAdmission {
        fn reconcile(
            &self,
            context: RuntimePreScanAdmissionContext,
        ) -> anyhow::Result<RuntimePreScanAdmissionOutcome> {
            context.check_active()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.cell_open.store(false, Ordering::SeqCst);
            self.order.lock().unwrap().push("admission");
            Ok(RuntimePreScanAdmissionOutcome::default())
        }

        fn fail_close_all(&self) {
            self.cell_open.store(false, Ordering::SeqCst);
        }

        fn fail_close_cats(&self, _cat_ids: &BTreeSet<Id>) {
            self.cell_open.store(false, Ordering::SeqCst);
        }
    }

    impl RuntimePreScanRecovery for OrderedReplanRecovery {
        fn recover_one(
            &self,
            context: RuntimePreScanRecoveryContext,
        ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
            context.check_active()?;
            anyhow::ensure!(
                !self.cell_open.load(Ordering::SeqCst),
                "publication recovery ran before mandatory admission closed the cell"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.order.lock().unwrap().push("recovery");
            Ok(RuntimePreScanRecoveryOutcome::ReplanDesired {
                cat_id: self.cat_id.clone(),
            })
        }
    }

    struct NonCooperativeEffect {
        calls: AtomicUsize,
        delay: Duration,
    }

    struct BlockingRetryEffect {
        slow_cat: Id,
        slow_started: test_mpsc::SyncSender<()>,
        slow_release: Mutex<test_mpsc::Receiver<()>>,
        ready_cat: Id,
        ready_started: test_mpsc::SyncSender<()>,
    }

    struct BlockingAppliedEffect {
        slow_cat: Id,
        slow_started: test_mpsc::SyncSender<()>,
        slow_release: Mutex<test_mpsc::Receiver<()>>,
        ready_cat: Id,
        ready_started: test_mpsc::SyncSender<()>,
    }

    struct StopOneCatEffect {
        stopped_cat: Id,
    }

    struct BoundedBlockingEffect {
        started: test_mpsc::SyncSender<Id>,
        release: Mutex<test_mpsc::Receiver<()>>,
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    struct GlobalGateEffect {
        first_cat: Id,
        first_entered: test_mpsc::SyncSender<()>,
        first_release: Mutex<test_mpsc::Receiver<()>>,
        second_allowed: Mutex<test_mpsc::Receiver<()>>,
        first_reentries: AtomicUsize,
        second_mutations: AtomicUsize,
    }

    struct IdentityAndBlockingSiblingEffect {
        identity_cat: Id,
        sibling_started: test_mpsc::SyncSender<()>,
        identity_unblock: test_mpsc::SyncSender<()>,
        identity_waits_for_sibling: Mutex<test_mpsc::Receiver<()>>,
        sibling_release: Mutex<test_mpsc::Receiver<()>>,
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
            vmm_launcher_bin: "unused-vmm-launcher".into(),
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
        let recovery = Arc::new(SequencedRecovery {
            calls: AtomicUsize::new(0),
        });
        let recovery_port: Arc<dyn RuntimePreScanRecovery> = recovery.clone();
        let mut lane = CoordinatorLane::start(None, Some(recovery_port), None).unwrap();
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
        lane.shutdown_blocking().unwrap();
    }

    #[tokio::test]
    async fn mandatory_pre_scan_admission_ignores_pending_resources_and_every_error_fails_closed() {
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let owner = Arc::new(TestEffectResourceOwner::new(true));
        let admission_port: Arc<dyn RuntimePreScanAdmission> = admission.clone();
        let owner_port: Arc<dyn RuntimeEffectResourceOwner> = owner.clone();
        let mut lane =
            CoordinatorLane::start(Some(admission_port), None, Some(owner_port)).unwrap();
        let snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        let coordinates = RuntimeSpineFullScan {
            session: snapshot.session.clone(),
            heartbeat_sequence: Sequence::new(1).unwrap(),
            inventory_epoch: Epoch::new(1).unwrap(),
            desired: snapshot,
        };

        assert!(matches!(
            lane.reconcile_pre_scan_admission(coordinates.clone(), Instant::now())
                .await
                .unwrap(),
            AdmissionWait::DeadlineExceeded
        ));
        assert_eq!(admission.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 1);

        assert!(matches!(
            lane.reconcile_pre_scan_admission(
                coordinates.clone(),
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap(),
            AdmissionWait::Finished(Ok(_))
        ));
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.polls.load(Ordering::SeqCst), 0);

        admission.fail.store(true, Ordering::SeqCst);
        let AdmissionWait::Finished(Err(error)) = lane
            .reconcile_pre_scan_admission(coordinates, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap()
        else {
            panic!("injected admission error was not returned")
        };
        assert!(error.to_string().contains("injected admission failure"));
        assert_eq!(admission.calls.load(Ordering::SeqCst), 2);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 2);
        owner.pending.store(false, Ordering::SeqCst);
        lane.shutdown_blocking().unwrap();
    }

    #[tokio::test]
    async fn pending_effect_resource_blocks_recovery_before_user_code() {
        let recovery = Arc::new(SequencedRecovery {
            calls: AtomicUsize::new(0),
        });
        let owner = Arc::new(TestEffectResourceOwner::new(true));
        let recovery_port: Arc<dyn RuntimePreScanRecovery> = recovery.clone();
        let owner_port: Arc<dyn RuntimeEffectResourceOwner> = owner.clone();
        let mut lane = CoordinatorLane::start(None, Some(recovery_port), Some(owner_port)).unwrap();
        let root = tempfile::tempdir().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        let coordinates = RuntimeSpineFullScan {
            session: snapshot.session.clone(),
            heartbeat_sequence: Sequence::new(1).unwrap(),
            inventory_epoch: Epoch::new(1).unwrap(),
            desired: snapshot,
        };
        let RecoveryWait::Finished(Err(error)) = lane
            .recover(
                StateDirectory::unanchored(root.path().to_path_buf()),
                coordinates,
                deadline,
            )
            .await
            .unwrap()
        else {
            panic!("pending owner did not close pre-scan recovery")
        };
        assert!(
            error.to_string().contains("retains pending work"),
            "{error:#}"
        );
        assert_eq!(recovery.calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.polls.load(Ordering::SeqCst), 1);
        owner.pending.store(false, Ordering::SeqCst);
        lane.shutdown_blocking().unwrap();
    }

    #[test]
    fn resource_shutdown_follows_effect_join_and_failure_retains_the_owner() {
        let effect_dropped = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(TestEffectResourceOwner {
            pending: AtomicBool::new(false),
            polls: AtomicUsize::new(0),
            shutdowns: AtomicUsize::new(0),
            shutdown_failures: AtomicUsize::new(0),
            effect_dropped: Some(Arc::clone(&effect_dropped)),
        });
        let owner_port: Arc<dyn RuntimeEffectResourceOwner> = owner.clone();
        let lane = CoordinatorLane::start(None, None, Some(owner_port.clone())).unwrap();
        let workers = CatEffectWorkers::new(
            Arc::new(DropWitnessEffect {
                dropped: Arc::clone(&effect_dropped),
            }),
            1,
        )
        .unwrap();
        RunnerWorkers {
            coordinator_lane: Some(lane),
            cat_effect_workers: Some(workers),
            scan_lane: None,
            journal_lane: None,
            effect_resource_owner: Some(owner_port),
        }
        .shutdown_blocking()
        .unwrap();
        assert!(effect_dropped.load(Ordering::SeqCst));
        assert_eq!(owner.shutdowns.load(Ordering::SeqCst), 1);

        let failing_owner = Arc::new(TestEffectResourceOwner {
            pending: AtomicBool::new(true),
            polls: AtomicUsize::new(0),
            shutdowns: AtomicUsize::new(0),
            shutdown_failures: AtomicUsize::new(1),
            effect_dropped: None,
        });
        let failing_owner_port: Arc<dyn RuntimeEffectResourceOwner> = failing_owner.clone();
        let error = RunnerWorkers {
            coordinator_lane: None,
            cat_effect_workers: None,
            scan_lane: None,
            journal_lane: None,
            effect_resource_owner: Some(failing_owner_port),
        }
        .shutdown_blocking()
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected resource shutdown timeout"),
            "{error}"
        );
        assert_eq!(failing_owner.shutdowns.load(Ordering::SeqCst), 2);
        assert!(!failing_owner.pending.load(Ordering::SeqCst));
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

    impl RuntimeDesiredEffect for BlockingRetryEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            if desired.cat_id == self.slow_cat {
                self.slow_started.send(()).unwrap();
                self.slow_release.lock().unwrap().recv().unwrap();
                return Ok(RuntimeDesiredEffectOutcome::RetryExact);
            }
            anyhow::ensure!(desired.cat_id == self.ready_cat, "unexpected test Cat");
            self.ready_started.send(()).unwrap();
            Ok(RuntimeDesiredEffectOutcome::Applied)
        }
    }

    impl RuntimeDesiredEffect for BlockingAppliedEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            if desired.cat_id == self.slow_cat {
                self.slow_started.send(()).unwrap();
                self.slow_release.lock().unwrap().recv().unwrap();
                return Ok(RuntimeDesiredEffectOutcome::Applied);
            }
            anyhow::ensure!(desired.cat_id == self.ready_cat, "unexpected test Cat");
            self.ready_started.send(()).unwrap();
            Ok(RuntimeDesiredEffectOutcome::Applied)
        }
    }

    impl RuntimeDesiredEffect for StopOneCatEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            if desired.cat_id == self.stopped_cat {
                Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                ))
            } else {
                Ok(RuntimeDesiredEffectOutcome::Applied)
            }
        }
    }

    impl RuntimeDesiredEffect for BoundedBlockingEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            self.started.send(desired.cat_id.clone()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(RuntimeDesiredEffectOutcome::Applied)
        }
    }

    impl RuntimeDesiredEffect for GlobalGateEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            if desired.cat_id != self.first_cat {
                self.second_allowed.lock().unwrap().recv().unwrap();
            }
            let _global = context.lock_node_global_effect()?;
            if desired.cat_id == self.first_cat {
                self.first_entered.send(()).unwrap();
                self.first_release.lock().unwrap().recv().unwrap();
                // A composite effect may pass through several independently
                // typed Node-global adapters. Re-entry belongs to this same
                // worker until the entire apply call returns.
                let _reentered = context.lock_node_global_effect()?;
                self.first_reentries.fetch_add(1, Ordering::SeqCst);
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            } else {
                self.second_mutations.fetch_add(1, Ordering::SeqCst);
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
        }
    }

    impl RuntimeDesiredEffect for IdentityAndBlockingSiblingEffect {
        fn apply(
            &self,
            context: RuntimeDesiredEffectContext,
            desired: &DesiredRuntimeSpec,
        ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
            context.check_active()?;
            if desired.cat_id == self.identity_cat {
                self.identity_waits_for_sibling
                    .lock()
                    .unwrap()
                    .recv()
                    .unwrap();
                return Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired);
            }
            self.sibling_started.send(()).unwrap();
            self.identity_unblock.send(()).unwrap();
            self.sibling_release.lock().unwrap().recv().unwrap();
            Ok(RuntimeDesiredEffectOutcome::Applied)
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

    fn desired_with_network_for_cat(cat_id: &str) -> DesiredRuntimeSpec {
        let mut desired = desired_with_network();
        desired.cat_id = Id::new(cat_id).unwrap();
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    fn running_route_fixture() -> (
        DesiredRuntimeSpec,
        ObservedRuntimeStatus,
        Arc<AdmissionCell>,
        RouteGrantV2Claims,
    ) {
        let mut desired = desired_with_network();
        let endpoint = EndpointIntent {
            endpoint_id: Id::new("endpoint_01").unwrap(),
            hostname: Hostname::new("app.cats.run").unwrap(),
            route_epoch: Epoch::new(1).unwrap(),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        };
        desired.endpoints = vec![endpoint.clone()];
        desired.spec_digest = spec_digest(&desired).unwrap();

        let mut runtime = ready_running_runtime(&desired);
        let runtime_incarnation = runtime.runtime_incarnation.clone().unwrap();
        let binding = RouteGateBinding {
            workspace_id: desired.workspace_id.clone(),
            endpoint_id: endpoint.endpoint_id.clone(),
            hostname: endpoint.hostname.clone(),
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            runtime_incarnation: runtime_incarnation.clone(),
            route_epoch: endpoint.route_epoch,
            protocol: endpoint.protocol,
            target_port: endpoint.target_port,
        };
        runtime.routes = vec![ObservedRouteGate {
            binding: binding.clone(),
            gate: RouteGateState::Active,
            active_guards: 0,
            cancellation_pending: false,
            instance_count: 1,
        }];
        let cell = AdmissionCell::new(
            AdmissionSnapshot::new(
                desired.desired_revision,
                desired.spec_digest.clone(),
                desired.placement.clone(),
                Some(runtime_incarnation.clone()),
                LifecycleAdmission::Open,
                vec![CheckpointRouteGate {
                    binding: binding.clone(),
                    gate: RouteGateState::Active,
                }],
            )
            .with_guest_ipv4(desired.runtime.network_config.guest_ipv4.clone()),
        )
        .unwrap();
        let claims = RouteGrantV2Claims {
            version: ROUTE_GRANT_V2_VERSION,
            iss: ROUTE_GRANT_V2_ISSUER.to_owned(),
            aud: ROUTE_GRANT_V2_AUDIENCE.to_owned(),
            workspace_id: binding.workspace_id,
            endpoint_id: binding.endpoint_id,
            hostname: binding.hostname,
            cat_id: binding.cat_id,
            node_id: binding.node_id,
            runtime_incarnation,
            route_epoch: binding.route_epoch,
            protocol: binding.protocol,
            target_port: binding.target_port,
            gateway_public_key_spki_sha256: Sha256Digest::from_bytes([0; 32]),
            iat: 1_786_156_800,
            nbf: 1_786_156_800,
            exp: 1_786_156_920,
        };
        (desired, runtime, cell, claims)
    }

    fn ready_running_runtime(desired: &DesiredRuntimeSpec) -> ObservedRuntimeStatus {
        let incarnation = RandomId128::new("51515151515151515151515151515151").unwrap();
        let step = ReconcileStep::Stable {
            state: StableState::Running,
        };
        let mut runtime_launch = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
        .runtime_launch;
        let RuntimeLaunch::Present(identity) = &mut runtime_launch else {
            panic!("fixed StartRuntime checkpoint retains launch identity")
        };
        identity.runtime_incarnation = incarnation.clone();
        identity.scope_id = Id::new(format!("cats-vmm-{}.service", incarnation.as_str())).unwrap();
        ObservedRuntimeStatus {
            cat_id: desired.cat_id.clone(),
            applied_desired: Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: RuntimeTarget::Running,
            }),
            runtime_incarnation: Some(incarnation.clone()),
            stable_state: Some(StableState::Running),
            step: step.clone(),
            checkpoint: CheckpointEvidence::Valid {
                checkpoint_path: HostPath::new("/var/lib/cats/checkpoints/cat_01.json").unwrap(),
                content_digest: Sha256Digest::from_bytes([0x51; 32]),
                version: ContractVersion::V1,
                cat_id: desired.cat_id.clone(),
                node_id: desired.placement.node_id.clone(),
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement_epoch: desired.placement.placement_epoch,
                runtime_incarnation: Some(incarnation.clone()),
                runtime_launch: Box::new(runtime_launch),
                stable_state: Some(StableState::Running),
                step: Box::new(step),
                require_idle: Box::new(
                    cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
                ),
                updated_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
            },
            processes: vec![ProcessEvidence {
                role: ProcessRole::Vmm {
                    runtime_incarnation: incarnation.clone(),
                },
                process_id: 101,
                process_start_time_ticks: WireU64::new(1).unwrap(),
                executable_path: HostPath::new("/usr/bin/cloud-hypervisor").unwrap(),
                scope_id: Id::new(format!("cats-vmm-{}.service", incarnation.as_str())).unwrap(),
                control_socket_path: HostPath::new("/run/cats/cat_01/vmm.sock").unwrap(),
                state: ProcessState::Running,
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: RandomId128::new("52525252525252525252525252525252").unwrap(),
                },
                control_handshake: ControlHandshakeEvidence::Verified,
                observed_vm_shape: Some(ObservedVmShape {
                    vcpus: desired.runtime.vcpus,
                    memory_bytes: desired.runtime.memory_bytes,
                    boot_image_digest: desired.runtime.boot_image_digest.clone(),
                    guest_config_digest: desired.runtime.guest_config_digest.clone(),
                }),
            }],
            volumes: Vec::new(),
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::VsockReady {
                runtime_incarnation: incarnation,
                guest_cid: 3,
                guest_port: 5000,
                guest_agent_protocol_version: ContractVersion::V1,
                guest_boot_id: GuestBootId::new("53535353535353535353535353535353").unwrap(),
            },
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Open,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: vec![Condition::Ready {
                reason: ReadyReason::PostconditionSatisfied {
                    target: RuntimeTarget::Running,
                },
            }],
        }
    }

    fn effect_admission_for(desired: &DesiredRuntimeSpec) -> RuntimeDesiredEffectAdmission {
        let session = decode_agent_session(SESSION).unwrap();
        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        snapshot.desired_specs = vec![desired.clone()];
        let accepted_desired = snapshot.clone();
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
            .bind_assigned_cats_for_test(&accepted_desired)
    }

    #[test]
    fn effect_admission_retains_the_complete_unique_desired_cat_set() {
        let desired = desired_with_network();
        let mut admission = effect_admission_for(&desired);
        assert_eq!(
            admission
                .assigned_cats()
                .unwrap()
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec![desired.cat_id.clone()]
        );

        let mut duplicate = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        duplicate.desired_specs = vec![desired.clone(), desired];
        let previous_read_position = admission.desired_read_position();
        duplicate.read_position = Sequence::new(previous_read_position.unwrap().get() + 1).unwrap();
        assert!(admission.bind_desired_read_position(&duplicate).is_err());
        assert_eq!(admission.desired_read_position(), previous_read_position);
        assert_eq!(
            admission
                .assigned_cats()
                .unwrap()
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec![Id::new("cat_01").unwrap()]
        );
    }

    #[test]
    fn accepted_effect_admission_keeps_only_the_exact_scanner_private_process_binding() {
        let desired = desired_with_network();
        let base = effect_admission_for(&desired);
        let session = base.session().clone();
        let observation = base.observation().clone();
        let attestation = base.attestation().clone();
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
            accepted_at_unix_ms: attestation.accepted_at_unix_ms,
            lease_deadline_unix_ms: session.lease_deadline_unix_ms,
            inventory: ObservationInventoryAcceptance::Full {
                attestation: attestation.clone(),
            },
        };
        let private = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
        )
        .unwrap()
        .bind(&observation)
        .unwrap();
        let admitted = RuntimeDesiredEffectAdmission::from_acceptance(
            session.clone(),
            observation.clone(),
            &acceptance,
            Some(private),
            None,
            None,
            None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            None,
        )
        .expect("exact private scan binding must enter the effect context");
        assert!(admitted.node_global_process.is_some());

        let mut another_observation = observation.clone();
        another_observation.observation_id =
            RandomId128::new("99999999999999999999999999999999").unwrap();
        let foreign_private = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
        )
        .unwrap()
        .bind(&another_observation)
        .unwrap();
        assert!(RuntimeDesiredEffectAdmission::from_acceptance(
            session,
            observation,
            &acceptance,
            Some(foreign_private),
            None,
            None,
            None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            None,
        )
        .is_none());
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
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(
                CompleteRuntimeInventory::for_test(
                    UnixMillis::new(1_720_000_004_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    Vec::new(),
                    Vec::new(),
                ),
            )))
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
    async fn timed_out_noncooperative_effect_blocks_a_successor_scan_without_node_poison() {
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

        assert!(runner
            .run_once_until(Instant::now() + Duration::from_millis(20))
            .await
            .is_ok());
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_exact_slow_cat_does_not_block_a_ready_sibling_cat() {
        let root = tempfile::tempdir().unwrap();
        let slow = desired_with_network_for_cat("cat_slow");
        let ready = desired_with_network_for_cat("cat_ready");
        let (slow_started_tx, slow_started_rx) = test_mpsc::sync_channel(1);
        let (slow_release_tx, slow_release_rx) = test_mpsc::sync_channel(1);
        let (ready_started_tx, ready_started_rx) = test_mpsc::sync_channel(1);
        let effect = Arc::new(BlockingRetryEffect {
            slow_cat: slow.cat_id.clone(),
            slow_started: slow_started_tx,
            slow_release: Mutex::new(slow_release_rx),
            ready_cat: ready.cat_id.clone(),
            ready_started: ready_started_tx,
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect,
        )
        .unwrap();
        runner.pending_effects.extend([slow, ready]);

        let running = tokio::spawn(async move {
            let step = runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap();
            (runner, step)
        });
        tokio::task::spawn_blocking(move || {
            slow_started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("slow Cat never entered its worker")
        })
        .await
        .unwrap();
        let ready_started_before_release = tokio::task::spawn_blocking(move || {
            ready_started_rx
                .recv_timeout(Duration::from_millis(100))
                .is_ok()
        })
        .await
        .unwrap();
        slow_release_tx.send(()).unwrap();
        let (runner, _step) = running.await.unwrap();

        assert!(
            ready_started_before_release,
            "a slow RetryExact Cat serialized the independent ready Cat"
        );
        runner.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_cat_timeout_does_not_poison_the_node_or_cancel_a_ready_sibling() {
        let root = tempfile::tempdir().unwrap();
        let slow = desired_with_network_for_cat("cat_timeout");
        let ready = desired_with_network_for_cat("cat_ready_after_timeout");
        let (slow_started_tx, slow_started_rx) = test_mpsc::sync_channel(1);
        let (slow_release_tx, slow_release_rx) = test_mpsc::sync_channel(1);
        let (ready_started_tx, ready_started_rx) = test_mpsc::sync_channel(1);
        let effect = Arc::new(BlockingAppliedEffect {
            slow_cat: slow.cat_id.clone(),
            slow_started: slow_started_tx,
            slow_release: Mutex::new(slow_release_rx),
            ready_cat: ready.cat_id.clone(),
            ready_started: ready_started_tx,
        });
        let scanner = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            scanner.clone(),
            effect,
        )
        .unwrap();
        runner.pending_effects.extend([slow.clone(), ready.clone()]);

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(1))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectApplied { cat_id } if cat_id == ready.cat_id
        ));
        slow_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("slow Cat never entered its worker");
        ready_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("ready sibling never ran independently");

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_millis(20))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id } if cat_id == slow.cat_id
        ));
        // The late physical phase still blocks a fresh Node-global scan, but
        // the runner remains live instead of poisoning the whole effect lane.
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_millis(20))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id } if cat_id == slow.cat_id
        ));
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 0);

        slow_release_tx.send(()).unwrap();
        runner.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_stopped_cat_does_not_cancel_an_applied_sibling() {
        let root = tempfile::tempdir().unwrap();
        let stopped = desired_with_network_for_cat("cat_stopped");
        let ready = desired_with_network_for_cat("cat_ready_beside_stop");
        let effect = Arc::new(StopOneCatEffect {
            stopped_cat: stopped.cat_id.clone(),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect,
        )
        .unwrap();
        runner
            .pending_effects
            .extend([stopped.clone(), ready.clone()]);

        let first = runner
            .run_once_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let second = runner
            .run_once_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(
            matches!(
                (&first, &second),
            (
                RuntimeSpineRunStep::EffectStopped { cat_id, .. },
                RuntimeSpineRunStep::EffectApplied { cat_id: ready_id }
            ) if cat_id == &stopped.cat_id && ready_id == &ready.cat_id
            ) || matches!(
                (&first, &second),
                (
                    RuntimeSpineRunStep::EffectApplied { cat_id },
                    RuntimeSpineRunStep::EffectStopped { cat_id: stopped_id, .. }
                ) if cat_id == &ready.cat_id && stopped_id == &stopped.cat_id
            )
        );
        runner.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn per_cat_workers_are_single_flight_and_globally_bounded() {
        let root = tempfile::tempdir().unwrap();
        let (started_tx, started_rx) = test_mpsc::sync_channel(16);
        let (release_tx, release_rx) = test_mpsc::sync_channel(16);
        let effect = Arc::new(BoundedBlockingEffect {
            started: started_tx,
            release: Mutex::new(release_rx),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut workers = CatEffectWorkers::new(effect.clone(), 2).unwrap();
        let dispatch_count = Arc::new(AtomicUsize::new(0));
        workers.set_dispatch_count_for_test(Arc::clone(&dispatch_count));
        let gate = Arc::new(NodeGlobalEffectGate::default());
        let open = Arc::new(AtomicBool::new(true));
        let first = desired_with_network_for_cat("cat_one");
        let second = desired_with_network_for_cat("cat_two");
        let overflow = desired_with_network_for_cat("cat_three");
        let deadline = Instant::now() + Duration::from_secs(2);
        workers
            .dispatch(
                StateDirectory::unanchored(root.path().to_path_buf()),
                first.clone(),
                None,
                Arc::clone(&gate),
                Arc::clone(&open),
                deadline,
            )
            .unwrap();
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            workers.dispatch(
                StateDirectory::unanchored(root.path().to_path_buf()),
                first,
                None,
                Arc::clone(&gate),
                Arc::clone(&open),
                deadline,
            ),
            Err(RuntimeSpineRunError::InvalidComposition(_))
        ));
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        workers
            .dispatch(
                StateDirectory::unanchored(root.path().to_path_buf()),
                second,
                None,
                Arc::clone(&gate),
                Arc::clone(&open),
                deadline,
            )
            .unwrap();
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 2);
        assert!(matches!(
            workers.dispatch(
                StateDirectory::unanchored(root.path().to_path_buf()),
                overflow,
                None,
                gate,
                open,
                deadline,
            ),
            Err(RuntimeSpineRunError::EffectQueueFull)
        ));
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 2);
        for _ in 0..2 {
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("bounded worker never started");
        }
        assert_eq!(effect.max_active.load(Ordering::SeqCst), 2);
        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                workers
                    .wait_next(Instant::now() + Duration::from_secs(1))
                    .await
                    .unwrap(),
                CatEffectWait::Finished { .. }
            ));
        }
        workers.shutdown_blocking().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_worker_limit_backpressures_the_ninth_cat() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let (started_tx, started_rx) =
            test_mpsc::sync_channel(MAX_CONCURRENT_CAT_EFFECT_WORKERS + 1);
        let (release_tx, release_rx) =
            test_mpsc::sync_channel(MAX_CONCURRENT_CAT_EFFECT_WORKERS + 1);
        let effect = Arc::new(BoundedBlockingEffect {
            started: started_tx,
            release: Mutex::new(release_rx),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut workers =
            CatEffectWorkers::new(effect.clone(), MAX_CONCURRENT_CAT_EFFECT_WORKERS).unwrap();
        let gate = Arc::new(NodeGlobalEffectGate::default());
        let open = Arc::new(AtomicBool::new(true));
        let deadline = Instant::now() + Duration::from_secs(2);
        for index in 0..MAX_CONCURRENT_CAT_EFFECT_WORKERS {
            workers
                .dispatch(
                    state.clone(),
                    desired_with_network_for_cat(&format!("cat_bounded_{index}")),
                    None,
                    Arc::clone(&gate),
                    Arc::clone(&open),
                    deadline,
                )
                .unwrap();
        }
        assert!(matches!(
            workers.dispatch(
                state,
                desired_with_network_for_cat("cat_bounded_overflow"),
                None,
                gate,
                open,
                deadline,
            ),
            Err(RuntimeSpineRunError::EffectQueueFull)
        ));
        for _ in 0..MAX_CONCURRENT_CAT_EFFECT_WORKERS {
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("production-bounded worker never started");
        }
        assert_eq!(
            effect.max_active.load(Ordering::SeqCst),
            MAX_CONCURRENT_CAT_EFFECT_WORKERS
        );
        for _ in 0..MAX_CONCURRENT_CAT_EFFECT_WORKERS {
            release_tx.send(()).unwrap();
        }
        for _ in 0..MAX_CONCURRENT_CAT_EFFECT_WORKERS {
            assert!(matches!(
                workers
                    .wait_next(Instant::now() + Duration::from_secs(1))
                    .await
                    .unwrap(),
                CatEffectWait::Finished { .. }
            ));
        }
        workers.shutdown_blocking().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepted_full_node_global_authority_is_one_shot_across_cats() {
        let root = tempfile::tempdir().unwrap();
        let first = desired_with_network_for_cat("cat_global_first");
        let second = desired_with_network_for_cat("cat_global_second");
        let (first_entered_tx, first_entered_rx) = test_mpsc::sync_channel(1);
        let (first_release_tx, first_release_rx) = test_mpsc::sync_channel(1);
        let (second_allowed_tx, second_allowed_rx) = test_mpsc::sync_channel(1);
        let effect = Arc::new(GlobalGateEffect {
            first_cat: first.cat_id.clone(),
            first_entered: first_entered_tx,
            first_release: Mutex::new(first_release_rx),
            second_allowed: Mutex::new(second_allowed_rx),
            first_reentries: AtomicUsize::new(0),
            second_mutations: AtomicUsize::new(0),
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
        runner.pending_effects.extend([first.clone(), second]);

        let running = tokio::spawn(async move {
            let step = runner
                .run_once_until(Instant::now() + Duration::from_secs(2))
                .await
                .unwrap();
            (runner, step)
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first global effect never acquired the gate");
        second_allowed_tx.send(()).unwrap();
        first_release_tx.send(()).unwrap();
        let (runner, step) = running.await.unwrap();
        assert!(matches!(
            step,
            RuntimeSpineRunStep::EffectRefreshInventory { cat_id } if cat_id == first.cat_id
        ));
        assert_eq!(effect.first_reentries.load(Ordering::SeqCst), 1);
        assert_eq!(effect.second_mutations.load(Ordering::SeqCst), 0);
        runner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn first_scan_wire_overflow_stays_local_without_transport_or_pending_journal() {
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let serving_observation_calls = Arc::clone(&observation_calls);
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move || {
                    let observation_calls = Arc::clone(&serving_observation_calls);
                    async move {
                        observation_calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let scanner = Arc::new(WireOverflowScanner {
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new(
            state.clone(),
            registered.clone(),
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
        for _ in 0..2 {
            let RuntimeSpineRunStep::ScanIncomplete {
                unavailable_sources,
            } = runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap()
            else {
                panic!("wire overflow must remain a typed local Incomplete result")
            };
            assert_eq!(unavailable_sources, vec![InventorySource::ControlSocket]);
        }
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 2);
        assert_eq!(observation_calls.load(Ordering::SeqCst), 0);

        runner.shutdown().await.unwrap();
        let journal = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        assert!(journal.pending_observation().is_none());
        assert!(journal.full_observation().is_none());
        assert!(journal.last_observation().is_none());
        assert!(journal.full_scan().is_ok(), "overflow must not block retry");
        server.abort();
    }

    #[tokio::test]
    async fn anchored_wire_overflow_fail_closes_exact_absent_vmm_before_partial_publication() {
        let (desired, running, cell, claims) = running_route_fixture();
        drop(
            cell.acquire_verified_route(&claims, RouteGrantV2TimeVerdict::Valid)
                .expect("known-positive local route must admit before the negative scan")
                .0,
        );

        let registered = decode_agent_session(SESSION).unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let mut predecessor =
            RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        assert!(matches!(
            predecessor.desired_work().unwrap(),
            RuntimeSpineDesiredWork::Request(_)
        ));
        let mut initial_snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        initial_snapshot.desired_specs = vec![desired.clone()];
        let initial_snapshot_bytes = encode_desired_read_snapshot(&initial_snapshot).unwrap();
        predecessor
            .accept_desired(initial_snapshot.clone(), &initial_snapshot_bytes)
            .unwrap();
        let initial_full = build_full_observation(
            predecessor.full_scan().unwrap(),
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                vec![running],
                Vec::new(),
            ),
        )
        .unwrap();
        predecessor
            .prepare_observation(initial_full.clone())
            .unwrap();
        let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
        let initial_acceptance = ObservationAcceptance {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: initial_full.node_id.clone(),
                node_boot_id: initial_full.node_boot_id.clone(),
                agent_instance_id: initial_full.agent_instance_id.clone(),
                agent_session_epoch: initial_full.agent_session_epoch,
            },
            observation_id: initial_full.observation_id.clone(),
            heartbeat_sequence: initial_full.heartbeat_sequence,
            accepted_at_unix_ms: accepted_at,
            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
            inventory: ObservationInventoryAcceptance::Full {
                attestation: AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: initial_full.node_id.clone(),
                    agent_session_epoch: initial_full.agent_session_epoch,
                    inventory_epoch: initial_full.inventory_epoch,
                    inventory_digest: initial_full.inventory_digest.clone().unwrap(),
                    inventory_read_position: initial_full.inventory_read_position.unwrap(),
                    accepted_at_unix_ms: accepted_at,
                },
            },
        };
        predecessor
            .accept_observation(
                initial_acceptance.clone(),
                &encode_observation_acceptance(&initial_acceptance).unwrap(),
            )
            .unwrap();
        drop(predecessor);

        let observed = Arc::new(Mutex::new(Vec::<NodeObservation>::new()));
        let serving_observed = Arc::clone(&observed);
        let serving_desired = desired.clone();
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(move |request: Request<Body>| {
                    let desired = serving_desired.clone();
                    async move {
                        let body =
                            to_bytes(request.into_body(), DESIRED_READ_REQUEST_MAX_WIRE_BYTES)
                                .await
                                .unwrap();
                        let request = decode_desired_read_request(&body).unwrap();
                        let sequence = request.request_sequence.get();
                        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
                        snapshot.session = request.session;
                        snapshot.request_sequence = request.request_sequence;
                        snapshot.read_position = Sequence::new(12 + sequence).unwrap();
                        snapshot.issued_at_unix_ms =
                            UnixMillis::new(1_720_000_010_000 + sequence).unwrap();
                        snapshot.expires_at_unix_ms =
                            UnixMillis::new(1_720_000_040_000 + sequence).unwrap();
                        snapshot.desired_specs = vec![desired];
                        wire_response(
                            StatusCode::OK,
                            encode_desired_read_snapshot(&snapshot).unwrap(),
                        )
                    }
                }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move |request: Request<Body>| {
                    let observed = Arc::clone(&serving_observed);
                    async move {
                        let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                            .await
                            .unwrap();
                        let observation = decode_node_observation(&body).unwrap();
                        assert!(!observation.complete_inventory);
                        observed.lock().unwrap().push(observation.clone());
                        let accepted_at = UnixMillis::new(1_720_000_100_000).unwrap();
                        wire_response(
                            StatusCode::OK,
                            encode_observation_acceptance(&ObservationAcceptance {
                                version: ContractVersion::V1,
                                session: SessionBinding {
                                    node_id: observation.node_id.clone(),
                                    node_boot_id: observation.node_boot_id.clone(),
                                    agent_instance_id: observation.agent_instance_id.clone(),
                                    agent_session_epoch: observation.agent_session_epoch,
                                },
                                observation_id: observation.observation_id,
                                heartbeat_sequence: observation.heartbeat_sequence,
                                accepted_at_unix_ms: accepted_at,
                                lease_deadline_unix_ms: UnixMillis::new(1_720_000_160_000).unwrap(),
                                inventory: ObservationInventoryAcceptance::Partial {
                                    inventory_epoch: observation.inventory_epoch,
                                },
                            })
                            .unwrap(),
                        )
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let admission = Arc::new(CellBackedPreScanAdmission {
            cat_id: desired.cat_id.clone(),
            cell: Arc::clone(&cell),
            fail_closes: AtomicUsize::new(0),
        });
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_inner(
            state,
            registered,
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(ExactRunningNegativeWireOverflowScanner),
            Some(effect.clone()),
            Some(admission.clone()),
            None,
            None,
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
            RuntimeSpineRunStep::PartialObservationAccepted {
                degraded_runtimes: 1
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 1);
        {
            let observations = observed.lock().unwrap();
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].runtimes.len(), 1);
            let negative = &observations[0].runtimes[0];
            assert_eq!(negative.cat_id, desired.cat_id);
            assert_eq!(negative.lifecycle_admission, LifecycleAdmission::Closed);
            assert!(negative.routes.iter().all(|route| {
                route.gate == RouteGateState::Closed && route.cancellation_pending
            }));
            assert!(!negative
                .processes
                .iter()
                .any(|process| matches!(process.role, ProcessRole::Vmm { .. })));
            assert!(!negative
                .conditions
                .iter()
                .any(|condition| matches!(condition, Condition::Ready { .. })));
        }
        assert_eq!(
            cell.acquire_verified_route(&claims, RouteGrantV2TimeVerdict::Valid)
                .unwrap_err(),
            RouteAdmissionV2Reason::GateClosed
        );

        runner.shutdown().await.unwrap();
        server.abort();
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
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new_inner(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(IncompleteScanner),
            Some(effect.clone()),
            Some(admission.clone()),
            None,
            None,
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
        assert_eq!(admission.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            admission.fail_closes.load(Ordering::SeqCst),
            0,
            "a successful typed pre-scan survives transient Incomplete inventory"
        );

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[test]
    fn hybrid_incomplete_closes_exact_negative_before_partial_projection() {
        let desired = desired_with_network();
        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        snapshot.desired_specs = vec![desired.clone()];
        let coordinates = RuntimeSpineFullScan {
            session: snapshot.session.clone(),
            heartbeat_sequence: Sequence::new(2).unwrap(),
            inventory_epoch: Epoch::new(1).unwrap(),
            desired: snapshot,
        };
        let full = build_full_observation(
            coordinates.clone(),
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                vec![ready_running_runtime(&desired)],
                Vec::new(),
            ),
        )
        .unwrap();
        assert_eq!(
            full.runtimes[0].lifecycle_admission,
            LifecycleAdmission::Open
        );
        assert!(full.runtimes[0]
            .conditions
            .iter()
            .any(|condition| matches!(condition, Condition::Ready { .. })));

        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let admission_port: Arc<dyn RuntimePreScanAdmission> = admission.clone();
        let mut lane = CoordinatorLane::start(Some(admission_port), None, None).unwrap();
        let negatives = BTreeSet::from([desired.cat_id.clone()]);
        let mut retained =
            RuntimePreScanAdmissionOutcome::retained_running_cats([desired.cat_id.clone()]);
        apply_incomplete_physical_negatives(&coordinates, Some(&lane), &mut retained, &negatives)
            .unwrap();
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 1);
        assert!(!retained.retains(&desired.cat_id));
        let partial = build_degraded_partial_observation(
            coordinates,
            Some(&full),
            Some(&full),
            DegradedObservationCause::SourceUnavailable(vec![InventorySource::Network]),
            &retained,
            UnixMillis::new(1_720_000_005_000).unwrap(),
        )
        .expect("the exact negative Cat must be projected rather than omitted");
        assert_eq!(partial.runtimes.len(), 1);
        let runtime = &partial.runtimes[0];
        assert_eq!(runtime.cat_id, desired.cat_id);
        assert_eq!(runtime.lifecycle_admission, LifecycleAdmission::Closed);
        assert!(runtime
            .routes
            .iter()
            .all(|route| { route.gate == RouteGateState::Closed && route.cancellation_pending }));
        assert!(!runtime
            .processes
            .iter()
            .any(|process| matches!(process.role, ProcessRole::Vmm { .. })));
        assert!(!runtime
            .conditions
            .iter()
            .any(|condition| matches!(condition, Condition::Ready { .. })));
        lane.shutdown_blocking().unwrap();
    }

    #[tokio::test]
    async fn transient_running_probe_failure_reports_partial_degraded_without_teardown() {
        let desired = desired_with_network();
        let registered = decode_agent_session(SESSION).unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let mut predecessor =
            RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        assert!(matches!(
            predecessor.desired_work().unwrap(),
            RuntimeSpineDesiredWork::Request(_)
        ));
        let mut initial_snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        initial_snapshot.desired_specs = vec![desired.clone()];
        let initial_snapshot_bytes = encode_desired_read_snapshot(&initial_snapshot).unwrap();
        predecessor
            .accept_desired(initial_snapshot.clone(), &initial_snapshot_bytes)
            .unwrap();
        let initial_full = build_full_observation(
            predecessor.full_scan().unwrap(),
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                vec![ready_running_runtime(&desired)],
                Vec::new(),
            ),
        )
        .unwrap();
        predecessor
            .prepare_observation(initial_full.clone())
            .unwrap();
        let initial_accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
        let initial_attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: initial_full.node_id.clone(),
            agent_session_epoch: initial_full.agent_session_epoch,
            inventory_epoch: initial_full.inventory_epoch,
            inventory_digest: initial_full.inventory_digest.clone().unwrap(),
            inventory_read_position: initial_full.inventory_read_position.unwrap(),
            accepted_at_unix_ms: initial_accepted_at,
        };
        let initial_acceptance = ObservationAcceptance {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: initial_full.node_id.clone(),
                node_boot_id: initial_full.node_boot_id.clone(),
                agent_instance_id: initial_full.agent_instance_id.clone(),
                agent_session_epoch: initial_full.agent_session_epoch,
            },
            observation_id: initial_full.observation_id.clone(),
            heartbeat_sequence: initial_full.heartbeat_sequence,
            accepted_at_unix_ms: initial_accepted_at,
            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
            inventory: ObservationInventoryAcceptance::Full {
                attestation: initial_attestation.clone(),
            },
        };
        predecessor
            .accept_observation(
                initial_acceptance.clone(),
                &encode_observation_acceptance(&initial_acceptance).unwrap(),
            )
            .unwrap();
        drop(predecessor);

        let observed = Arc::new(Mutex::new(Vec::<NodeObservation>::new()));
        let serving_observed = Arc::clone(&observed);
        let serving_desired = desired.clone();
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(move |request: Request<Body>| {
                    let desired = serving_desired.clone();
                    async move {
                        let body =
                            to_bytes(request.into_body(), DESIRED_READ_REQUEST_MAX_WIRE_BYTES)
                                .await
                                .unwrap();
                        let request = decode_desired_read_request(&body).unwrap();
                        let sequence = request.request_sequence.get();
                        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
                        snapshot.session = request.session;
                        snapshot.request_sequence = request.request_sequence;
                        snapshot.read_position = Sequence::new(11 + sequence).unwrap();
                        snapshot.issued_at_unix_ms =
                            UnixMillis::new(1_720_000_010_000 + sequence).unwrap();
                        snapshot.expires_at_unix_ms =
                            UnixMillis::new(1_720_000_040_000 + sequence).unwrap();
                        snapshot.desired_specs = vec![desired];
                        wire_response(
                            StatusCode::OK,
                            encode_desired_read_snapshot(&snapshot).unwrap(),
                        )
                    }
                }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move |request: Request<Body>| {
                    let observed = Arc::clone(&serving_observed);
                    async move {
                        let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                            .await
                            .unwrap();
                        let observation = decode_node_observation(&body).unwrap();
                        observed.lock().unwrap().push(observation.clone());
                        let accepted_at = UnixMillis::new(
                            1_720_000_100_000 + observation.heartbeat_sequence.get(),
                        )
                        .unwrap();
                        let inventory = if observation.complete_inventory {
                            ObservationInventoryAcceptance::Full {
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
                            }
                        } else {
                            ObservationInventoryAcceptance::Partial {
                                inventory_epoch: observation.inventory_epoch,
                            }
                        };
                        let acceptance = ObservationAcceptance {
                            version: ContractVersion::V1,
                            session: SessionBinding {
                                node_id: observation.node_id.clone(),
                                node_boot_id: observation.node_boot_id.clone(),
                                agent_instance_id: observation.agent_instance_id.clone(),
                                agent_session_epoch: observation.agent_session_epoch,
                            },
                            observation_id: observation.observation_id,
                            heartbeat_sequence: observation.heartbeat_sequence,
                            accepted_at_unix_ms: accepted_at,
                            lease_deadline_unix_ms: UnixMillis::new(1_720_000_200_000).unwrap(),
                            inventory,
                        };
                        wire_response(
                            StatusCode::OK,
                            encode_observation_acceptance(&acceptance).unwrap(),
                        )
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let scanner = Arc::new(TransientRunningProbeScanner {
            calls: AtomicUsize::new(0),
        });
        let mut runner = RuntimeSpineRunner::new_inner(
            state,
            registered,
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            scanner.clone(),
            Some(effect.clone()),
            Some(admission.clone()),
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        let degraded = runner
            .run_once_until(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(matches!(
            degraded,
            RuntimeSpineRunStep::PartialObservationAccepted {
                degraded_runtimes: 1
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 0);

        let observations = observed.lock().unwrap().clone();
        assert_eq!(observations.len(), 1);
        let partial = &observations[0];
        assert!(!partial.complete_inventory);
        assert_eq!(partial.inventory_epoch, initial_attestation.inventory_epoch);
        assert_eq!(partial.inventory_digest, None);
        assert_eq!(partial.inventory_read_position, None);
        let runtime = partial
            .runtimes
            .first()
            .expect("Running Cat partial status");
        assert_eq!(runtime.processes, initial_full.runtimes[0].processes);
        assert_eq!(runtime.lifecycle_admission, LifecycleAdmission::Open);
        let [Condition::Ready {
            reason:
                ReadyReason::PostconditionSatisfied {
                    target: RuntimeTarget::Running,
                },
        }, Condition::Degraded {
            reason:
                DegradedReason::SourceUnavailable {
                    sources,
                    since_unix_ms,
                },
        }] = runtime.conditions.as_slice()
        else {
            panic!("Running Cat did not retain Ready alongside source-specific Degraded")
        };
        assert_eq!(sources, &[DegradedSource::Process]);
        let first_degraded_since = *since_unix_ms;
        drop(observations);

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::PartialObservationAccepted {
                degraded_runtimes: 1
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 0);
        {
            let observations = observed.lock().unwrap();
            assert_eq!(observations.len(), 2);
            assert!(!observations[1].complete_inventory);
            assert_eq!(
                observations[1].inventory_epoch,
                initial_attestation.inventory_epoch
            );
            assert!(matches!(
                observations[1].runtimes[0].conditions.as_slice(),
                [
                    Condition::Ready { .. },
                    Condition::Degraded {
                        reason: DegradedReason::SourceUnavailable { since_unix_ms, .. }
                    }
                ] if *since_unix_ms == first_degraded_since
            ));
        }

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ObservationAccepted {
                service_ready: true,
                inventory_attested: true
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 0);
        {
            let observations = observed.lock().unwrap();
            assert_eq!(observations.len(), 3);
            assert!(observations[2].complete_inventory);
            assert_eq!(observations[2].inventory_epoch.get(), 2);
            assert!(observations[2].runtimes[0]
                .conditions
                .iter()
                .all(|condition| !matches!(condition, Condition::Degraded { .. })));
        }

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn transient_running_scan_deadline_reports_attestation_degraded_then_recovers() {
        let desired = desired_with_network();
        let registered = decode_agent_session(SESSION).unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let mut predecessor =
            RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        predecessor.desired_work().unwrap();
        let mut initial_snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        initial_snapshot.desired_specs = vec![desired.clone()];
        let snapshot_bytes = encode_desired_read_snapshot(&initial_snapshot).unwrap();
        predecessor
            .accept_desired(initial_snapshot.clone(), &snapshot_bytes)
            .unwrap();
        let initial_full = build_full_observation(
            predecessor.full_scan().unwrap(),
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                vec![ready_running_runtime(&desired)],
                Vec::new(),
            ),
        )
        .unwrap();
        predecessor
            .prepare_observation(initial_full.clone())
            .unwrap();
        let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
        let full_acceptance = ObservationAcceptance {
            version: ContractVersion::V1,
            session: initial_snapshot.session.clone(),
            observation_id: initial_full.observation_id.clone(),
            heartbeat_sequence: initial_full.heartbeat_sequence,
            accepted_at_unix_ms: accepted_at,
            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
            inventory: ObservationInventoryAcceptance::Full {
                attestation: AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: initial_full.node_id.clone(),
                    agent_session_epoch: initial_full.agent_session_epoch,
                    inventory_epoch: initial_full.inventory_epoch,
                    inventory_digest: initial_full.inventory_digest.clone().unwrap(),
                    inventory_read_position: initial_full.inventory_read_position.unwrap(),
                    accepted_at_unix_ms: accepted_at,
                },
            },
        };
        predecessor
            .accept_observation(
                full_acceptance.clone(),
                &encode_observation_acceptance(&full_acceptance).unwrap(),
            )
            .unwrap();
        drop(predecessor);

        let observed = Arc::new(Mutex::new(Vec::<NodeObservation>::new()));
        let serving_observed = Arc::clone(&observed);
        let serving_desired = desired.clone();
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(move |request: Request<Body>| {
                    let desired = serving_desired.clone();
                    async move {
                        let body =
                            to_bytes(request.into_body(), DESIRED_READ_REQUEST_MAX_WIRE_BYTES)
                                .await
                                .unwrap();
                        let request = decode_desired_read_request(&body).unwrap();
                        let sequence = request.request_sequence.get();
                        let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
                        snapshot.session = request.session;
                        snapshot.request_sequence = request.request_sequence;
                        snapshot.read_position = Sequence::new(11 + sequence).unwrap();
                        snapshot.issued_at_unix_ms =
                            UnixMillis::new(1_720_000_010_000 + sequence).unwrap();
                        snapshot.expires_at_unix_ms =
                            UnixMillis::new(1_720_000_040_000 + sequence).unwrap();
                        snapshot.desired_specs = vec![desired];
                        wire_response(
                            StatusCode::OK,
                            encode_desired_read_snapshot(&snapshot).unwrap(),
                        )
                    }
                }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move |request: Request<Body>| {
                    let observed = Arc::clone(&serving_observed);
                    async move {
                        let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                            .await
                            .unwrap();
                        let observation = decode_node_observation(&body).unwrap();
                        observed.lock().unwrap().push(observation.clone());
                        let accepted_at = UnixMillis::new(
                            1_720_000_100_000 + observation.heartbeat_sequence.get(),
                        )
                        .unwrap();
                        let inventory = if observation.complete_inventory {
                            ObservationInventoryAcceptance::Full {
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
                            }
                        } else {
                            ObservationInventoryAcceptance::Partial {
                                inventory_epoch: observation.inventory_epoch,
                            }
                        };
                        let acceptance = ObservationAcceptance {
                            version: ContractVersion::V1,
                            session: SessionBinding {
                                node_id: observation.node_id.clone(),
                                node_boot_id: observation.node_boot_id.clone(),
                                agent_instance_id: observation.agent_instance_id.clone(),
                                agent_session_epoch: observation.agent_session_epoch,
                            },
                            observation_id: observation.observation_id,
                            heartbeat_sequence: observation.heartbeat_sequence,
                            accepted_at_unix_ms: accepted_at,
                            lease_deadline_unix_ms: UnixMillis::new(1_720_000_200_000).unwrap(),
                            inventory,
                        };
                        wire_response(
                            StatusCode::OK,
                            encode_observation_acceptance(&acceptance).unwrap(),
                        )
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let scanner = Arc::new(DelayedTransientRunningProbeScanner {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(100),
        });
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let mut runner = RuntimeSpineRunner::new_inner(
            state,
            registered,
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            scanner.clone(),
            Some(effect.clone()),
            Some(admission.clone()),
            None,
            None,
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
                .run_once_until(Instant::now() + Duration::from_millis(20))
                .await
                .unwrap(),
            RuntimeSpineRunStep::PartialObservationAccepted {
                degraded_runtimes: 1
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 0);
        {
            let observations = observed.lock().unwrap();
            assert!(matches!(
                observations[0].runtimes[0].conditions.as_slice(),
                [
                    Condition::Ready { .. },
                    Condition::Degraded {
                        reason: DegradedReason::AttestationRefreshFailed {
                            inventory_epoch,
                            ..
                        }
                    }
                ] if *inventory_epoch == initial_full.inventory_epoch
            ));
        }

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ObservationAccepted {
                service_ready: true,
                inventory_attested: true
            }
        ));
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 2);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 0);
        {
            let observations = observed.lock().unwrap();
            assert_eq!(observations.len(), 2);
            assert!(observations[1].complete_inventory);
            assert!(observations[1].runtimes[0]
                .conditions
                .iter()
                .all(|condition| !matches!(condition, Condition::Degraded { .. })));
        }

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn explicit_scanner_error_fail_closes_successful_pre_scan_admission() {
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
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new_inner(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(ErrorScanner),
            Some(effect.clone()),
            Some(admission.clone()),
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        let RuntimeSpineRunStep::ScanUnavailable(error) = runner
            .run_once_until(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
        else {
            panic!("explicit scanner error did not remain typed")
        };
        assert!(error.to_string().contains("complete-source conflict"));
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 1);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);

        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn invalid_empty_incomplete_scan_fail_closes_pre_scan_admission() {
        let snapshot = snapshot_with_network();
        let app = Router::new().route(
            cats_api::runtime_reconciliation::DESIRED_READ_PATH,
            post(move || {
                let snapshot = snapshot.clone();
                async move { wire_response(StatusCode::OK, snapshot) }
            }),
        );
        let (origin, server) = spawn(app).await;
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new_inner(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(InvalidIncompleteScanner),
            Some(Arc::new(CountingEffect {
                calls: AtomicUsize::new(0),
            })),
            Some(admission.clone()),
            None,
            None,
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
            Err(RuntimeSpineRunError::InvalidScan(_))
        ));
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.fail_closes.load(Ordering::SeqCst), 1);
        runner.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn pending_resource_blocks_readiness_until_a_fresh_desired_effect_batch() {
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
        let resource_owner = Arc::new(TestEffectResourceOwner::new(true));
        let resource_owner_port: Arc<dyn RuntimeEffectResourceOwner> = resource_owner.clone();
        let root = tempfile::tempdir().unwrap();
        let mut runner = RuntimeSpineRunner::new_inner(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap(),
            Arc::new(AssignedScanner),
            Some(effect.clone()),
            None,
            None,
            Some(resource_owner_port),
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
                service_ready: false,
                inventory_attested: false
            }
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        resource_owner.pending.store(false, Ordering::SeqCst);
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
    async fn pre_scan_replan_invalidates_desired_before_scanner_or_effect() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        {
            let mut journal =
                RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
            assert!(matches!(
                journal.desired_work().unwrap(),
                RuntimeSpineDesiredWork::Request(_)
            ));
            let mut snapshot = decode_desired_read_snapshot(SNAPSHOT).unwrap();
            snapshot.desired_specs = vec![desired_with_network()];
            let bytes = encode_desired_read_snapshot(&snapshot).unwrap();
            journal.accept_desired(snapshot, &bytes).unwrap();
        }

        let scanner = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        let effect = Arc::new(CountingEffect {
            calls: AtomicUsize::new(0),
        });
        let cell_open = Arc::new(AtomicBool::new(true));
        let order = Arc::new(Mutex::new(Vec::new()));
        let admission = Arc::new(OrderedPreScanAdmission {
            calls: AtomicUsize::new(0),
            cell_open: Arc::clone(&cell_open),
            order: Arc::clone(&order),
        });
        let admission_port: Arc<dyn RuntimePreScanAdmission> = admission.clone();
        let recovery = Arc::new(OrderedReplanRecovery {
            calls: AtomicUsize::new(0),
            cat_id: Id::new("cat_closed_takeover").unwrap(),
            cell_open: Arc::clone(&cell_open),
            order: Arc::clone(&order),
        });
        let recovery_port: Arc<dyn RuntimePreScanRecovery> = recovery.clone();
        let mut runner = RuntimeSpineRunner::new_inner(
            state.clone(),
            registered.clone(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            scanner.clone(),
            Some(effect.clone()),
            Some(admission_port),
            Some(recovery_port),
            None,
        )
        .unwrap();
        // Model stale process-local admission left by the preceding loop. The
        // pre-scan proof must discard it before invalidating the old Desired.
        runner.effect_admission_open = true;

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectReplanDesired { cat_id }
                if cat_id == Id::new("cat_closed_takeover").unwrap()
        ));
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
        assert_eq!(recovery.calls.load(Ordering::SeqCst), 1);
        assert!(!cell_open.load(Ordering::SeqCst));
        assert_eq!(*order.lock().unwrap(), ["admission", "recovery"]);
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 0);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert!(runner.pending_effects.is_empty());
        assert!(runner.effect_admission.is_none());
        assert!(!runner.effect_admission_open);
        runner.shutdown().await.unwrap();

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let RuntimeSpineDesiredWork::Request(next) = recovered.desired_work().unwrap() else {
            panic!("pre-scan replan must durably advance to a fresh Desired read")
        };
        assert_eq!(next.value().request_sequence.get(), 2);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_repair_waits_until_every_cancelled_sibling_is_joined() {
        let root = tempfile::tempdir().unwrap();
        let identity = desired_with_network_for_cat("cat_identity_repair");
        let sibling = desired_with_network_for_cat("cat_late_sibling");
        let (sibling_started_tx, sibling_started_rx) = test_mpsc::sync_channel(1);
        let (identity_unblock_tx, identity_wait_rx) = test_mpsc::sync_channel(1);
        let (sibling_release_tx, sibling_release_rx) = test_mpsc::sync_channel(1);
        let effect = Arc::new(IdentityAndBlockingSiblingEffect {
            identity_cat: identity.cat_id.clone(),
            sibling_started: sibling_started_tx,
            identity_unblock: identity_unblock_tx,
            identity_waits_for_sibling: Mutex::new(identity_wait_rx),
            sibling_release: Mutex::new(sibling_release_rx),
        });
        let mut runner = RuntimeSpineRunner::new_with_desired_effects(
            StateDirectory::unanchored(root.path().to_path_buf()),
            decode_agent_session(SESSION).unwrap(),
            RuntimeSpineHttpClient::for_loopback_test("http://127.0.0.1:1/", signer()).unwrap(),
            Arc::new(EmptyScanner {
                calls: AtomicUsize::new(0),
            }),
            effect,
        )
        .unwrap();
        runner
            .pending_effects
            .extend([identity.clone(), sibling.clone()]);

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_millis(30))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectDeadlineExceeded { cat_id } if cat_id == sibling.cat_id
        ));
        sibling_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("identity-repair sibling never entered its worker");
        sibling_release_tx.send(()).unwrap();

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_secs(1))
                .await
                .unwrap(),
            RuntimeSpineRunStep::EffectIdentityRepairRequired { cat_id }
                if cat_id == identity.cat_id
        ));
        runner.shutdown().await.unwrap();
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

        // Cancelling the in-flight wait leaves only this exact Cat worker
        // active. Shutdown is the oracle that it is cancelled and joined
        // before the journal flock can be released.
        drop(effect_step);
        assert!(runner
            .cat_effect_workers
            .as_ref()
            .is_some_and(CatEffectWorkers::has_active));
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
        let admission = Arc::new(TestPreScanAdmission {
            calls: AtomicUsize::new(0),
            fail_closes: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let mut runner = RuntimeSpineRunner::new_inner(
            state.clone(),
            registered.clone(),
            client.clone(),
            scanner.clone(),
            Some(Arc::new(CountingEffect {
                calls: AtomicUsize::new(0),
            })),
            Some(admission.clone()),
            None,
            None,
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
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            admission.fail_closes.load(Ordering::SeqCst),
            0,
            "a successful typed pre-scan survives scanner timeout"
        );
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + Duration::from_millis(50))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ScanDeadlineExceeded
        ));
        assert_eq!(
            scanner.calls.load(Ordering::SeqCst),
            1,
            "a timed-out scanner must not overlap a second physical scan"
        );

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
    fn full_observation_projects_the_exact_loaded_route_key_ring() {
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        let version = Epoch::new(7).unwrap();
        let kids = vec![
            KeyId::new("a".repeat(64)).unwrap(),
            KeyId::new("b".repeat(64)).unwrap(),
        ];
        let digest = cats_api::runtime_reconciliation::key_ring_digest(version, &kids).unwrap();
        let observation = build_full_observation(
            RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: registered.node_id,
                    node_boot_id: registered.node_boot_id,
                    agent_instance_id: registered.agent_instance_id,
                    agent_session_epoch: registered.agent_session_epoch,
                },
                heartbeat_sequence: Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired,
            },
            CompleteRuntimeInventory::for_test(
                UnixMillis::new(1_720_000_004_000).unwrap(),
                RuntimeInventoryKeyRing::Loaded {
                    version,
                    digest: digest.clone(),
                    kids: kids.clone(),
                },
                Vec::new(),
                Vec::new(),
            ),
        )
        .unwrap();

        assert_eq!(observation.key_ring_version, Some(version));
        assert_eq!(observation.key_ring_digest, Some(digest));
        assert_eq!(observation.loaded_kids, kids);
        assert_eq!(
            observation.inventory_digest,
            Some(inventory_digest(&observation).unwrap())
        );
    }

    #[test]
    fn complete_observation_wire_budget_accepts_exact_8_mib_and_closes_plus_one() {
        fn path_with_len(length: usize, index: usize) -> HostPath {
            let suffix = format!("{index:04}");
            HostPath::new(format!("/{}{}", "x".repeat(length - 5), suffix)).unwrap()
        }

        let target = NODE_OBSERVATION_MAX_WIRE_BYTES;
        let mut empty = pending_full_observation();
        empty.residue.clear();
        empty.inventory_digest = Some(inventory_digest(&empty).unwrap());
        let empty_len = serde_json::to_vec(&empty).unwrap().len();
        let mut shape = None;
        for path_len in 1_500..4_096 {
            let item = NodeResidue::ControlSocket {
                socket_path: path_with_len(path_len, 0),
                role_hint: None,
                ownership_token: OwnershipTokenEvidence::Missing,
            };
            let item_len = serde_json::to_vec(&item).unwrap().len();
            let count = (target - empty_len + 1) / (item_len + 1);
            if count == 0
                || count > cats_api::runtime_reconciliation::NODE_OBSERVATION_MAX_RESIDUE_ITEMS
            {
                continue;
            }
            let current = empty_len + count * item_len + count - 1;
            let gap = target - current;
            if path_len + gap < 4_096 {
                shape = Some((path_len, count, gap));
                break;
            }
        }
        let (path_len, count, gap) = shape.expect("one valid 8 MiB residue packing exists");
        let mut exact = empty;
        exact.residue = (0..count)
            .map(|index| NodeResidue::ControlSocket {
                socket_path: path_with_len(
                    path_len + if index + 1 == count { gap } else { 0 },
                    index,
                ),
                role_hint: None,
                ownership_token: OwnershipTokenEvidence::Missing,
            })
            .collect();
        exact.inventory_digest = Some(inventory_digest(&exact).unwrap());
        assert_eq!(serde_json::to_vec(&exact).unwrap().len(), target);
        assert_eq!(encode_node_observation(&exact).unwrap().len(), target);
        assert!(!node_observation_exceeds_wire_budget(&exact).unwrap());

        let NodeResidue::ControlSocket { socket_path, .. } = exact.residue.last_mut().unwrap()
        else {
            unreachable!()
        };
        *socket_path = HostPath::new(format!("{}x", socket_path.as_str())).unwrap();
        assert_eq!(serde_json::to_vec(&exact).unwrap().len(), target + 1);
        assert!(node_observation_exceeds_wire_budget(&exact).unwrap());
    }

    #[test]
    fn first_scan_wire_overflow_cannot_manufacture_an_unanchored_partial() {
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        assert!(build_degraded_partial_observation(
            RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: registered.node_id,
                    node_boot_id: registered.node_boot_id,
                    agent_instance_id: registered.agent_instance_id,
                    agent_session_epoch: registered.agent_session_epoch,
                },
                heartbeat_sequence: Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired,
            },
            None,
            None,
            DegradedObservationCause::WireBudgetExceeded(vec![InventorySource::ControlSocket]),
            &RuntimePreScanAdmissionOutcome::retained_running_cats([]),
            UnixMillis::new(1_720_000_004_000).unwrap(),
        )
        .is_none());
    }

    #[test]
    fn wire_overflow_after_an_accepted_full_has_a_bounded_anchored_partial() {
        let full = pending_full_observation();
        let registered = decode_agent_session(SESSION).unwrap();
        let desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        let partial = build_degraded_partial_observation(
            RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: registered.node_id,
                    node_boot_id: registered.node_boot_id,
                    agent_instance_id: registered.agent_instance_id,
                    agent_session_epoch: registered.agent_session_epoch,
                },
                heartbeat_sequence: Sequence::new(2).unwrap(),
                inventory_epoch: Epoch::new(2).unwrap(),
                desired,
            },
            Some(&full),
            Some(&full),
            DegradedObservationCause::WireBudgetExceeded(vec![InventorySource::ControlSocket]),
            &RuntimePreScanAdmissionOutcome::retained_running_cats([]),
            UnixMillis::new(1_720_000_004_000).unwrap(),
        )
        .expect("an accepted full attestation may anchor an empty bounded partial");
        assert!(!partial.complete_inventory);
        assert_eq!(partial.inventory_epoch, full.inventory_epoch);
        assert_eq!(partial.inventory_digest, None);
        assert_eq!(partial.inventory_read_position, None);
        assert!(partial.runtimes.is_empty() && partial.residue.is_empty());
        assert!(
            encode_node_observation(&partial).unwrap().len() <= NODE_OBSERVATION_MAX_WIRE_BYTES
        );
    }

    #[test]
    fn test_process_admission_binding_uses_real_full_coordinates_and_projection() {
        let registered = decode_agent_session(SESSION).unwrap();
        let mut desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        desired.desired_specs = vec![desired_with_network()];
        let coordinates = RuntimeSpineFullScan {
            session: SessionBinding {
                node_id: registered.node_id.clone(),
                node_boot_id: registered.node_boot_id.clone(),
                agent_instance_id: registered.agent_instance_id.clone(),
                agent_session_epoch: registered.agent_session_epoch,
            },
            heartbeat_sequence: Sequence::new(7).unwrap(),
            inventory_epoch: Epoch::new(9).unwrap(),
            desired,
        };
        let private = || {
            NodeGlobalManagedProcessScanAdmission::from_root_controls(
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            )
            .unwrap()
        };

        let inventory = CompleteRuntimeInventory::for_test(
            UnixMillis::new(1_720_000_004_000).unwrap(),
            RuntimeInventoryKeyRing::Unavailable,
            Vec::new(),
            Vec::new(),
        )
        .with_node_global_process_admission(Some(private()));
        let (observation, admission) = inventory
            .bind_node_global_process_for_test(coordinates.clone())
            .unwrap();
        assert_eq!(observation.node_boot_id, registered.node_boot_id);
        assert_eq!(observation.heartbeat_sequence, Sequence::new(7).unwrap());
        assert_eq!(observation.inventory_epoch, Epoch::new(9).unwrap());
        assert!(admission.matches_observation(&observation));

        let mut foreign_boot = observation.clone();
        foreign_boot.node_boot_id =
            cats_api::runtime_reconciliation::NodeBootId::new("ffffffffffffffffffffffffffffffff")
                .unwrap();
        assert!(!admission.matches_observation(&foreign_boot));

        let mut foreign_runtime = ObservedRuntimeStatus {
            cat_id: Id::new("cat_foreign").unwrap(),
            applied_desired: None,
            runtime_incarnation: None,
            stable_state: None,
            step: ReconcileStep::InspectInventory {
                inventory_epoch: Epoch::new(9).unwrap(),
            },
            checkpoint: CheckpointEvidence::Missing {
                checkpoint_path: HostPath::new("/var/lib/cats/cat_foreign.json").unwrap(),
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
        foreign_runtime.processes.push(ProcessEvidence {
            role: ProcessRole::Blockd {
                volume_id: Id::new("volume_foreign").unwrap(),
                attachment_id: Id::new("attachment_foreign").unwrap(),
                attachment_epoch: FenceEpoch::new(1).unwrap(),
            },
            process_id: 41,
            process_start_time_ticks: WireU64::new(42).unwrap(),
            executable_path: HostPath::new("/opt/cats/bin/cats-blockd").unwrap(),
            scope_id: Id::new("scope_foreign").unwrap(),
            control_socket_path: HostPath::new("/run/cats/blockd-v1/foreign.sock").unwrap(),
            state: ProcessState::Running,
            ownership_token: OwnershipTokenEvidence::Missing,
            control_handshake: ControlHandshakeEvidence::Unavailable,
            observed_vm_shape: None,
        });
        let foreign = CompleteRuntimeInventory::for_test(
            UnixMillis::new(1_720_000_004_000).unwrap(),
            RuntimeInventoryKeyRing::Unavailable,
            vec![foreign_runtime],
            Vec::new(),
        )
        .with_node_global_process_admission(Some(private()));
        let error = foreign
            .bind_node_global_process_for_test(coordinates)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("public process projection"),
            "{error:#}"
        );
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
                service_ready: false,
                ..
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

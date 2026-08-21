//! Concurrent-wake admission control (ADR-0002 §8 and its open item
//! "Warm/Suspended wake storm 的准入与限流").
//!
//! # Why bytes and not a plain count
//!
//! The 2026-07-21 concurrency experiment measured ten simultaneous 512 MiB
//! Warm restores and found the first-health P50 collapsing from 0.53 s on
//! local NVMe to 19.05 s on EBS, while the Cloud Hypervisor `vm.restore` API
//! call itself stayed at 25–26 ms in both runs. The bottleneck is therefore
//! **Guest memory page read-back**, not the VMM. Admission is consequently
//! accounted in *resume commitment bytes* — the memory a wake must fault back
//! in — with a wake count ceiling only as defence in depth so that many tiny
//! Cats cannot bypass the byte budget.
//!
//! # Why it queues instead of rejecting
//!
//! A node-side rejection is not usable here: the control plane converges any
//! failed resume/restore to a clean Cold fallback (ADR-0002 §7). Rejecting a
//! wake merely because the node is momentarily saturated would destroy the
//! local Suspended memory backing or Warm snapshot and turn every rejected
//! wake into a full Cold boot — making a wake storm strictly worse. Rejection
//! also cannot make page read-back faster.
//!
//! So a wake **waits** for budget up to a deadline. Bounded concurrency makes
//! total wake time degrade linearly (two batches of ten ≈ 2× one batch)
//! instead of collapsing (10× concurrency on EBS cost 36× the latency).
//! Only two conditions are genuine failures, and both are unsatisfiable by
//! waiting:
//!
//! - the commitment of a single Cat exceeds the whole node budget, and
//! - the deadline elapses.
//!
//! # Defaults
//!
//! Defaults are pinned to the *validated* operating point — ten concurrent
//! wakes and 5 GiB of concurrent commitment (10 × 512 MiB) — not to a proven
//! optimum. Beyond that point there is no measurement, and per ADRs a
//! prototype measurement must never become a production SLA. Operators on
//! faster or slower storage should re-measure before raising these.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cats_api::runtime_reconciliation::{
    Epoch, Id, Ipv4Address, RandomId128, RouteGateBinding, SessionBinding,
};
use thiserror::Error;
use tokio::sync::watch;

/// Concurrent wake footprint validated by the 2026-07-21 experiment:
/// ten simultaneous 512 MiB restores.
pub const DEFAULT_WAKE_COMMITMENT_BUDGET_BYTES: u64 = 10 * 512 * 1024 * 1024;
/// Concurrency validated by the same run.
pub const DEFAULT_MAX_CONCURRENT_WAKES: usize = 10;
/// How long a wake may wait for budget before the node admits it cannot
/// serve the wake. Chosen above the slowest measured concurrent restore
/// (EBS first-health P50 19.05 s) so that a legitimately slow medium queues
/// rather than falls back to Cold.
pub const DEFAULT_WAKE_QUEUE_TIMEOUT: Duration = Duration::from_secs(60);

/// Node-level ceiling on concurrent wakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeBudget {
    /// Total resume-commitment bytes admitted at once.
    pub commitment_bytes: u64,
    /// Hard ceiling on concurrently admitted wakes.
    pub max_wakes: usize,
    /// Bounded wait before a wake is treated as unservable.
    pub queue_timeout: Duration,
}

impl Default for WakeBudget {
    fn default() -> Self {
        Self {
            commitment_bytes: DEFAULT_WAKE_COMMITMENT_BUDGET_BYTES,
            max_wakes: DEFAULT_MAX_CONCURRENT_WAKES,
            queue_timeout: DEFAULT_WAKE_QUEUE_TIMEOUT,
        }
    }
}

/// Why a wake could not be admitted. Both variants are unsatisfiable by
/// waiting, so both are genuine failures that converge to Cold (ADR-0002 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// One Cat needs more than the entire node budget. Waiting can never
    /// help, so this must not be reported as a transient condition.
    ExceedsNodeBudget { requested: u64, budget: u64 },
    /// The bounded wait elapsed while other wakes held the budget.
    QueueTimeout { requested: u64, waited: Duration },
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsNodeBudget { requested, budget } => write!(
                f,
                "resume commitment {requested} B exceeds the node wake budget {budget} B; \
                 this Cat can never be woken on this node"
            ),
            Self::QueueTimeout { requested, waited } => write!(
                f,
                "waited {:.1}s for {requested} B of wake budget",
                waited.as_secs_f64()
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    commitment_bytes: u64,
    wakes: usize,
}

/// Snapshot of current saturation, for telemetry and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WakeLoad {
    pub wakes: usize,
    pub commitment_bytes: u64,
    pub peak_wakes: usize,
    pub peak_commitment_bytes: u64,
}

#[derive(Debug, Default)]
struct State {
    in_flight: InFlight,
    peak: InFlight,
}

/// Admits concurrent wakes against a node budget.
#[derive(Debug)]
pub struct WakeAdmission {
    budget: WakeBudget,
    state: Mutex<State>,
    released: Condvar,
}

impl WakeAdmission {
    pub fn new(budget: WakeBudget) -> Self {
        Self {
            budget,
            state: Mutex::new(State::default()),
            released: Condvar::new(),
        }
    }

    pub fn budget(&self) -> WakeBudget {
        self.budget
    }

    pub fn load(&self) -> WakeLoad {
        let state = self.state.lock().expect("wake admission mutex");
        WakeLoad {
            wakes: state.in_flight.wakes,
            commitment_bytes: state.in_flight.commitment_bytes,
            peak_wakes: state.peak.wakes,
            peak_commitment_bytes: state.peak.commitment_bytes,
        }
    }

    /// Reserve budget for one wake, waiting up to the configured timeout.
    ///
    /// The returned permit releases the reservation on drop, so a wake that
    /// fails or panics never leaks commitment and wedges the node.
    pub fn acquire(&self, commitment_bytes: u64) -> Result<WakePermit<'_>, AdmissionError> {
        self.acquire_until(commitment_bytes, self.budget.queue_timeout)
    }

    /// `acquire` with an explicit bound, so tests need not wait a minute.
    pub fn acquire_until(
        &self,
        commitment_bytes: u64,
        timeout: Duration,
    ) -> Result<WakePermit<'_>, AdmissionError> {
        // Unsatisfiable by waiting: fail before joining the queue. A zero
        // budget would otherwise stall every wake until the deadline.
        if commitment_bytes > self.budget.commitment_bytes || self.budget.max_wakes == 0 {
            return Err(AdmissionError::ExceedsNodeBudget {
                requested: commitment_bytes,
                budget: self.budget.commitment_bytes,
            });
        }

        let started = Instant::now();
        let mut state = self.state.lock().expect("wake admission mutex");
        loop {
            if self.fits(&state.in_flight, commitment_bytes) {
                state.in_flight.wakes += 1;
                // Checked at the call boundary above, so this cannot overflow.
                state.in_flight.commitment_bytes += commitment_bytes;
                state.peak.wakes = state.peak.wakes.max(state.in_flight.wakes);
                state.peak.commitment_bytes = state
                    .peak
                    .commitment_bytes
                    .max(state.in_flight.commitment_bytes);
                return Ok(WakePermit {
                    admission: self,
                    commitment_bytes,
                });
            }
            let elapsed = started.elapsed();
            let Some(remaining) = timeout.checked_sub(elapsed) else {
                return Err(AdmissionError::QueueTimeout {
                    requested: commitment_bytes,
                    waited: elapsed,
                });
            };
            // Condvar waits may wake spuriously; the loop re-checks the fit.
            let (next, _) = self
                .released
                .wait_timeout(state, remaining)
                .expect("wake admission mutex");
            state = next;
        }
    }

    fn fits(&self, in_flight: &InFlight, commitment_bytes: u64) -> bool {
        if in_flight.wakes >= self.budget.max_wakes {
            return false;
        }
        // A zero-commitment wake still consumes a slot, checked above, so an
        // accounting bug cannot admit an unbounded number of them.
        in_flight
            .commitment_bytes
            .checked_add(commitment_bytes)
            .is_some_and(|total| total <= self.budget.commitment_bytes)
    }

    fn release(&self, commitment_bytes: u64) {
        let mut state = self.state.lock().expect("wake admission mutex");
        state.in_flight.wakes = state.in_flight.wakes.saturating_sub(1);
        state.in_flight.commitment_bytes = state
            .in_flight
            .commitment_bytes
            .saturating_sub(commitment_bytes);
        drop(state);
        // Several waiters may now fit: a small wake can proceed where a large
        // one still cannot, so wake all of them and let each re-check.
        self.released.notify_all();
    }
}

/// Holds one wake's reservation. Releasing is unconditional on drop.
#[derive(Debug)]
pub struct WakePermit<'a> {
    admission: &'a WakeAdmission,
    commitment_bytes: u64,
}

impl WakePermit<'_> {
    pub fn commitment_bytes(&self) -> u64 {
        self.commitment_bytes
    }
}

impl Drop for WakePermit<'_> {
    fn drop(&mut self) {
        self.admission.release(self.commitment_bytes);
    }
}

/// Resume commitment for a Cat with `memory_mib` of Guest RAM.
///
/// Both wake paths are charged the Guest RAM size: Suspended must refault it
/// from the file-backed memory zone and Warm must read it back out of the
/// snapshot. ADR-0002 §8 names this the "resume commitment" for both states.
pub fn resume_commitment_bytes(memory_mib: u64) -> u64 {
    memory_mib.saturating_mul(1024 * 1024)
}

/// The exact Running result that may admit platform work and per-Endpoint
/// Route operations.
///
/// This identity is deliberately independent from the lifecycle CAS-chain
/// head. A declined RequireIdle Suspend becomes the new terminal chain head,
/// but retains this predecessor identity when its AdmissionCell never closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRuntimeReady {
    source_lifecycle_operation_id: Id,
    runtime_incarnation: RandomId128,
    guest_ipv4: Ipv4Address,
}

impl EffectiveRuntimeReady {
    pub fn new(
        source_lifecycle_operation_id: Id,
        runtime_incarnation: RandomId128,
        guest_ipv4: Ipv4Address,
    ) -> Self {
        Self {
            source_lifecycle_operation_id,
            runtime_incarnation,
            guest_ipv4,
        }
    }

    pub fn source_lifecycle_operation_id(&self) -> &Id {
        &self.source_lifecycle_operation_id
    }

    pub fn runtime_incarnation(&self) -> &RandomId128 {
        &self.runtime_incarnation
    }

    pub fn guest_ipv4(&self) -> &Ipv4Address {
        &self.guest_ipv4
    }
}

/// The lifecycle half of the shared per-Cat admission linearization point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleRouteAdmission {
    Closed { closing_operation_id: Id },
    RuntimeReady(EffectiveRuntimeReady),
}

/// One exact Control-derived EnableRoute command.
///
/// Route epoch is part of `binding`; keeping the complete binding in this
/// value makes replay compare the hostname/protocol/port as well as the
/// Endpoint, runtime and epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableRoute {
    route_operation_id: Id,
    source_lifecycle_operation_id: Id,
    agent_session: SessionBinding,
    binding: RouteGateBinding,
}

impl EnableRoute {
    pub fn new(
        route_operation_id: Id,
        source_lifecycle_operation_id: Id,
        agent_session: SessionBinding,
        binding: RouteGateBinding,
    ) -> Self {
        Self {
            route_operation_id,
            source_lifecycle_operation_id,
            agent_session,
            binding,
        }
    }

    pub fn route_operation_id(&self) -> &Id {
        &self.route_operation_id
    }

    pub fn binding(&self) -> &RouteGateBinding {
        &self.binding
    }
}

/// Exact terminal receipt for an EnableRoute that linearized before any
/// competing lifecycle close.
///
/// Control must close this receipt against the current AgentSession and the
/// Cat's effective RuntimeReady identity before it may sign a Route Grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingRoute {
    route_operation_id: Id,
    source_lifecycle_operation_id: Id,
    runtime_incarnation: RandomId128,
    route_epoch: Epoch,
    endpoint_id: Id,
    agent_session: SessionBinding,
    binding: RouteGateBinding,
}

impl ServingRoute {
    pub fn route_operation_id(&self) -> &Id {
        &self.route_operation_id
    }

    pub fn source_lifecycle_operation_id(&self) -> &Id {
        &self.source_lifecycle_operation_id
    }

    pub fn runtime_incarnation(&self) -> &RandomId128 {
        &self.runtime_incarnation
    }

    pub fn route_epoch(&self) -> Epoch {
        self.route_epoch
    }

    pub fn endpoint_id(&self) -> &Id {
        &self.endpoint_id
    }

    pub fn agent_session(&self) -> &SessionBinding {
        &self.agent_session
    }

    pub fn binding(&self) -> &RouteGateBinding {
        &self.binding
    }

    /// Pure receipt-side half of Route signing admission. A Control-side
    /// projection can apply the same exact comparison without consulting a
    /// Ready or Route Observation.
    pub fn matches_authority(
        &self,
        effective_runtime_ready: &EffectiveRuntimeReady,
        current_agent_session: &SessionBinding,
    ) -> bool {
        self.source_lifecycle_operation_id == effective_runtime_ready.source_lifecycle_operation_id
            && self.runtime_incarnation == effective_runtime_ready.runtime_incarnation
            && &self.agent_session == current_agent_session
            && self.binding.runtime_incarnation == effective_runtime_ready.runtime_incarnation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnableRouteOutcome {
    Serving(ServingRoute),
    Replay(ServingRoute),
}

/// Exact endpoint-local close command. It cannot close a replacement gate:
/// the expected Serving operation and complete binding must still be current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisableRoute {
    route_operation_id: Id,
    source_lifecycle_operation_id: Id,
    agent_session: SessionBinding,
    expected_serving_operation_id: Id,
    binding: RouteGateBinding,
}

impl DisableRoute {
    pub fn new(
        route_operation_id: Id,
        source_lifecycle_operation_id: Id,
        agent_session: SessionBinding,
        expected_serving_operation_id: Id,
        binding: RouteGateBinding,
    ) -> Self {
        Self {
            route_operation_id,
            source_lifecycle_operation_id,
            agent_session,
            expected_serving_operation_id,
            binding,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRoute {
    route_operation_id: Id,
    endpoint_id: Id,
    route_epoch: Epoch,
    agent_session: SessionBinding,
}

impl ClosedRoute {
    pub fn route_operation_id(&self) -> &Id {
        &self.route_operation_id
    }

    pub fn endpoint_id(&self) -> &Id {
        &self.endpoint_id
    }

    pub fn route_epoch(&self) -> Epoch {
        self.route_epoch
    }

    pub fn agent_session(&self) -> &SessionBinding {
        &self.agent_session
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableRouteOutcome {
    Closed(ClosedRoute),
    Replay(ClosedRoute),
}

/// Exact lifecycle command edge that closes admission before touching the
/// Guest, VMM or storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseLifecycleAdmission {
    closing_operation_id: Id,
    expected_runtime_ready: EffectiveRuntimeReady,
}

impl CloseLifecycleAdmission {
    pub fn new(closing_operation_id: Id, expected_runtime_ready: EffectiveRuntimeReady) -> Self {
        Self {
            closing_operation_id,
            expected_runtime_ready,
        }
    }

    pub fn closing_operation_id(&self) -> &Id {
        &self.closing_operation_id
    }

    pub fn expected_runtime_ready(&self) -> &EffectiveRuntimeReady {
        &self.expected_runtime_ready
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRouteEpoch {
    pub endpoint_id: Id,
    pub route_epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleCloseOutcome {
    Closed {
        closed_route_epochs: Vec<ClosedRouteEpoch>,
    },
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClosedLifecycleSuccessor {
    current_operation_id: Id,
    expected_previous_closing_operation_id: Id,
}

/// RequireIdle's Busy result is an exact non-mutation proof from the same
/// mutex that would otherwise close lifecycle admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdleLifecycleCloseOutcome {
    Busy {
        effective_runtime_ready: EffectiveRuntimeReady,
        platform_guards: u32,
        endpoint_guards: Vec<(Id, u32)>,
    },
    Closed {
        closed_route_epochs: Vec<ClosedRouteEpoch>,
    },
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSessionReplacementOutcome {
    Replaced {
        closed_route_epochs: Vec<ClosedRouteEpoch>,
    },
    Replay,
}

/// Exact process-local work that must drain after lifecycle admission closes
/// and before a Suspend, Warm, Cold, Stop or Delete effect touches the VMM or
/// its storage. Endpoint entries are emitted in stable Endpoint-ID order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleGuardCounts {
    pub platform_guards: u32,
    pub endpoint_guards: Vec<(Id, u32)>,
}

impl LifecycleGuardCounts {
    pub fn is_drained(&self) -> bool {
        self.platform_guards == 0 && self.endpoint_guards.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteInterlockError {
    #[error("the admission cell is unavailable")]
    Unavailable,
    #[error("the command is bound to a stale AgentSession")]
    StaleAgentSession,
    #[error("the replacement AgentSession is not a strict successor on the same Node")]
    InvalidAgentSessionSuccessor,
    #[error("the lifecycle source is no longer RuntimeReady")]
    StaleLifecycleSource,
    #[error("the route belongs to another Cat")]
    WrongCat,
    #[error("the route belongs to another Node")]
    WrongNode,
    #[error("the route names another runtime incarnation")]
    WrongRuntimeIncarnation,
    #[error("the Route operation ID was reused with another command")]
    RouteOperationConflict,
    #[error("the Endpoint Route lane moved past this command")]
    StaleRouteOperation,
    #[error("a closed or ambiguously closed Endpoint requires a higher route epoch")]
    RouteEpochNotAdvanced,
    #[error("the Endpoint is already serving another Route operation")]
    EndpointAlreadyServing,
    #[error("the previous Route generation still owns guards")]
    ActiveRouteGuards,
    #[error("the route is not currently serving")]
    RouteNotServing,
    #[error("the admission guard counter is exhausted")]
    CounterExhausted,
    #[error("the requested lifecycle close is stale")]
    StaleLifecycleClose,
    #[error("the requested RuntimeReady successor does not follow the exact close")]
    StaleRuntimeReadySuccessor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointGateState {
    Serving,
    Closed,
}

#[derive(Debug)]
struct EndpointRouteState {
    enable: EnableRoute,
    receipt: ServingRoute,
    gate: EndpointGateState,
    last_disable: Option<(DisableRoute, ClosedRoute)>,
    active_guards: u32,
    cancellation: watch::Sender<bool>,
}

#[derive(Debug)]
struct LifecycleRouteAdmissionState {
    agent_session: SessionBinding,
    lifecycle: LifecycleRouteAdmission,
    /// Exact most-recent Closed -> Closed lane edge. Keeping the predecessor
    /// prevents an operation ID replay with different ancestry from being
    /// mistaken for the accepted successor.
    closed_successor: Option<ClosedLifecycleSuccessor>,
    routes: BTreeMap<Id, EndpointRouteState>,
    platform_guards: u32,
}

/// Shared Node-local linearization point for the lifecycle lane, independent
/// per-Endpoint Route lanes and data-plane guard acquisition.
///
/// The mutex contains no filesystem or network work. A lifecycle command and
/// an EnableRoute therefore have only two possible orders: Enable installs
/// first and is then closed, or close wins and the late Enable has zero
/// effects. AgentSession replacement closes every process-local gate and
/// retains each epoch as a reopen floor.
#[derive(Debug)]
pub struct LifecycleRouteAdmissionCell {
    cat_id: Id,
    state: Mutex<LifecycleRouteAdmissionState>,
}

impl LifecycleRouteAdmissionCell {
    pub fn new(
        cat_id: Id,
        agent_session: SessionBinding,
        lifecycle: LifecycleRouteAdmission,
    ) -> Arc<Self> {
        Arc::new(Self {
            cat_id,
            state: Mutex::new(LifecycleRouteAdmissionState {
                agent_session,
                lifecycle,
                closed_successor: None,
                routes: BTreeMap::new(),
                platform_guards: 0,
            }),
        })
    }

    /// Construct a Cat admission cell from its explicit genesis/Start anchor.
    /// Startup and Cat creation use this constructor so a missing RuntimeReady
    /// can never default the process-local gates open.
    pub fn new_fail_closed(
        cat_id: Id,
        agent_session: SessionBinding,
        closed_anchor_operation_id: Id,
    ) -> Arc<Self> {
        Self::new(
            cat_id,
            agent_session,
            LifecycleRouteAdmission::Closed {
                closing_operation_id: closed_anchor_operation_id,
            },
        )
    }

    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn effective_runtime_ready(
        &self,
    ) -> Result<Option<EffectiveRuntimeReady>, RouteInterlockError> {
        let state = self.lock()?;
        Ok(match &state.lifecycle {
            LifecycleRouteAdmission::Closed { .. } => None,
            LifecycleRouteAdmission::RuntimeReady(ready) => Some(ready.clone()),
        })
    }

    pub fn publish_runtime_ready(
        &self,
        expected_closing_operation_id: &Id,
        ready: EffectiveRuntimeReady,
    ) -> Result<bool, RouteInterlockError> {
        let mut state = self.lock()?;
        if state.lifecycle == LifecycleRouteAdmission::RuntimeReady(ready.clone()) {
            return Ok(false);
        }
        match &state.lifecycle {
            LifecycleRouteAdmission::Closed {
                closing_operation_id,
            } if closing_operation_id == expected_closing_operation_id => {
                state.lifecycle = LifecycleRouteAdmission::RuntimeReady(ready);
                state.closed_successor = None;
                Ok(true)
            }
            LifecycleRouteAdmission::Closed { .. } | LifecycleRouteAdmission::RuntimeReady(_) => {
                Err(RouteInterlockError::StaleRuntimeReadySuccessor)
            }
        }
    }

    pub fn enable_route(
        &self,
        command: &EnableRoute,
    ) -> Result<EnableRouteOutcome, RouteInterlockError> {
        let mut state = self.lock()?;
        validate_enable_prefix(&self.cat_id, &state, command)?;

        if let Some(current) = state.routes.get(&command.binding.endpoint_id) {
            if current.enable.route_operation_id == command.route_operation_id {
                return if current.enable == *command && current.gate == EndpointGateState::Serving {
                    Ok(EnableRouteOutcome::Replay(current.receipt.clone()))
                } else {
                    Err(RouteInterlockError::RouteOperationConflict)
                };
            }
            if current.receipt.route_epoch >= command.binding.route_epoch {
                return Err(RouteInterlockError::RouteEpochNotAdvanced);
            }
            if current.gate == EndpointGateState::Serving {
                return Err(RouteInterlockError::EndpointAlreadyServing);
            }
            if current.active_guards != 0 {
                return Err(RouteInterlockError::ActiveRouteGuards);
            }
        }

        let receipt = ServingRoute {
            route_operation_id: command.route_operation_id.clone(),
            source_lifecycle_operation_id: command.source_lifecycle_operation_id.clone(),
            runtime_incarnation: command.binding.runtime_incarnation.clone(),
            route_epoch: command.binding.route_epoch,
            endpoint_id: command.binding.endpoint_id.clone(),
            agent_session: command.agent_session.clone(),
            binding: command.binding.clone(),
        };
        let (cancellation, _) = watch::channel(false);
        state.routes.insert(
            command.binding.endpoint_id.clone(),
            EndpointRouteState {
                enable: command.clone(),
                receipt: receipt.clone(),
                gate: EndpointGateState::Serving,
                last_disable: None,
                active_guards: 0,
                cancellation,
            },
        );
        Ok(EnableRouteOutcome::Serving(receipt))
    }

    pub fn disable_route(
        &self,
        command: &DisableRoute,
    ) -> Result<DisableRouteOutcome, RouteInterlockError> {
        let mut state = self.lock()?;
        validate_route_command_prefix(
            &self.cat_id,
            &state,
            &command.agent_session,
            &command.source_lifecycle_operation_id,
            &command.binding,
        )?;
        let route = state
            .routes
            .get_mut(&command.binding.endpoint_id)
            .ok_or(RouteInterlockError::RouteNotServing)?;
        if let Some((previous, receipt)) = &route.last_disable {
            if previous.route_operation_id == command.route_operation_id {
                return if previous == command {
                    Ok(DisableRouteOutcome::Replay(receipt.clone()))
                } else {
                    Err(RouteInterlockError::RouteOperationConflict)
                };
            }
        }
        if route.enable.route_operation_id != command.expected_serving_operation_id
            || route.enable.binding != command.binding
            || route.gate != EndpointGateState::Serving
        {
            return Err(RouteInterlockError::StaleRouteOperation);
        }
        route.gate = EndpointGateState::Closed;
        let _ = route.cancellation.send(true);
        let receipt = ClosedRoute {
            route_operation_id: command.route_operation_id.clone(),
            endpoint_id: command.binding.endpoint_id.clone(),
            route_epoch: command.binding.route_epoch,
            agent_session: command.agent_session.clone(),
        };
        route.last_disable = Some((command.clone(), receipt.clone()));
        Ok(DisableRouteOutcome::Closed(receipt))
    }

    pub fn close_lifecycle(
        &self,
        command: &CloseLifecycleAdmission,
    ) -> Result<LifecycleCloseOutcome, RouteInterlockError> {
        let mut state = self.lock()?;
        if matches!(
            &state.lifecycle,
            LifecycleRouteAdmission::Closed {
                closing_operation_id
            } if closing_operation_id == &command.closing_operation_id
        ) {
            return Ok(LifecycleCloseOutcome::Replay);
        }
        validate_lifecycle_close(&state, command)?;
        let closed_route_epochs = close_all_routes(&mut state);
        state.lifecycle = LifecycleRouteAdmission::Closed {
            closing_operation_id: command.closing_operation_id.clone(),
        };
        state.closed_successor = None;
        Ok(LifecycleCloseOutcome::Closed {
            closed_route_epochs,
        })
    }

    pub fn try_close_lifecycle_if_idle(
        &self,
        command: &CloseLifecycleAdmission,
    ) -> Result<IdleLifecycleCloseOutcome, RouteInterlockError> {
        let mut state = self.lock()?;
        if matches!(
            &state.lifecycle,
            LifecycleRouteAdmission::Closed {
                closing_operation_id
            } if closing_operation_id == &command.closing_operation_id
        ) {
            return Ok(IdleLifecycleCloseOutcome::Replay);
        }
        validate_lifecycle_close(&state, command)?;
        let endpoint_guards = state
            .routes
            .iter()
            .filter(|(_, route)| route.active_guards != 0)
            .map(|(endpoint_id, route)| (endpoint_id.clone(), route.active_guards))
            .collect::<Vec<_>>();
        if state.platform_guards != 0 || !endpoint_guards.is_empty() {
            return Ok(IdleLifecycleCloseOutcome::Busy {
                effective_runtime_ready: command.expected_runtime_ready.clone(),
                platform_guards: state.platform_guards,
                endpoint_guards,
            });
        }
        let closed_route_epochs = close_all_routes(&mut state);
        state.lifecycle = LifecycleRouteAdmission::Closed {
            closing_operation_id: command.closing_operation_id.clone(),
        };
        state.closed_successor = None;
        Ok(IdleLifecycleCloseOutcome::Closed {
            closed_route_epochs,
        })
    }

    /// Advance the lifecycle lane across an exact Closed predecessor without
    /// reopening any gate. This is the first linearization point for legal
    /// successors such as Killed -> Cold/Delete and Suspended/Warm ->
    /// Cold/Stop. Epoch floors, cancellations and guard counters are retained.
    ///
    /// A wrong predecessor and a reused current operation ID have zero effect.
    pub fn adopt_closed_lifecycle_successor(
        &self,
        current_operation_id: &Id,
        expected_previous_closing_operation_id: &Id,
    ) -> Result<LifecycleCloseOutcome, RouteInterlockError> {
        let mut state = self.lock()?;
        if let LifecycleRouteAdmission::Closed {
            closing_operation_id,
        } = &state.lifecycle
        {
            if closing_operation_id == current_operation_id {
                return if state.closed_successor.as_ref()
                    == Some(&ClosedLifecycleSuccessor {
                        current_operation_id: current_operation_id.clone(),
                        expected_previous_closing_operation_id:
                            expected_previous_closing_operation_id.clone(),
                    }) {
                    Ok(LifecycleCloseOutcome::Replay)
                } else {
                    Err(RouteInterlockError::StaleLifecycleClose)
                };
            }
            if closing_operation_id != expected_previous_closing_operation_id {
                return Err(RouteInterlockError::StaleLifecycleClose);
            }
        } else {
            return Err(RouteInterlockError::StaleLifecycleClose);
        }

        state.lifecycle = LifecycleRouteAdmission::Closed {
            closing_operation_id: current_operation_id.clone(),
        };
        state.closed_successor = Some(ClosedLifecycleSuccessor {
            current_operation_id: current_operation_id.clone(),
            expected_previous_closing_operation_id: expected_previous_closing_operation_id.clone(),
        });
        Ok(LifecycleCloseOutcome::Closed {
            closed_route_epochs: Vec::new(),
        })
    }

    pub fn replace_agent_session(
        &self,
        expected: &SessionBinding,
        replacement: &SessionBinding,
    ) -> Result<AgentSessionReplacementOutcome, RouteInterlockError> {
        let mut state = self.lock()?;
        if &state.agent_session == replacement {
            return Ok(AgentSessionReplacementOutcome::Replay);
        }
        if &state.agent_session != expected {
            return Err(RouteInterlockError::StaleAgentSession);
        }
        if replacement.node_id != expected.node_id
            || replacement.agent_session_epoch <= expected.agent_session_epoch
        {
            return Err(RouteInterlockError::InvalidAgentSessionSuccessor);
        }
        let closed_route_epochs = close_all_routes(&mut state);
        state.agent_session = replacement.clone();
        Ok(AgentSessionReplacementOutcome::Replaced {
            closed_route_epochs,
        })
    }

    /// Fail closed every Endpoint lane without changing lifecycle authority.
    /// Used when the installed Route verification ring becomes unavailable or
    /// its delivery worker fails. A concurrent guard acquisition is ordered by
    /// this cell mutex: it either fails, or is acquired first and cancelled.
    pub fn emergency_close_routes(&self) -> Result<Vec<ClosedRouteEpoch>, RouteInterlockError> {
        let mut state = self.lock()?;
        Ok(close_all_routes(&mut state))
    }

    /// Fail closed one exact locally installed Enable after Control proves
    /// that its durable Endpoint lane superseded or invalidated that result.
    /// A later Enable for the same Endpoint is left untouched; the stale
    /// response cannot close a successor operation by endpoint ID alone.
    pub fn emergency_close_route(
        &self,
        endpoint_id: &Id,
        expected_serving_operation_id: &Id,
    ) -> Result<Option<ClosedRouteEpoch>, RouteInterlockError> {
        let mut state = self.lock()?;
        let Some(route) = state.routes.get_mut(endpoint_id) else {
            return Ok(None);
        };
        if &route.enable.route_operation_id != expected_serving_operation_id {
            return Ok(None);
        }
        route.gate = EndpointGateState::Closed;
        let _ = route.cancellation.send(true);
        Ok(Some(ClosedRouteEpoch {
            endpoint_id: endpoint_id.clone(),
            route_epoch: route.receipt.route_epoch,
        }))
    }

    /// Returns a Serving receipt only when all three authorities intersect:
    /// the current RuntimeReady source, the current AgentSession and the live
    /// per-Endpoint gate. Observation is deliberately absent.
    pub fn current_serving_route(
        &self,
        endpoint_id: &Id,
    ) -> Result<Option<ServingRoute>, RouteInterlockError> {
        let state = self.lock()?;
        Ok(state
            .routes
            .get(endpoint_id)
            .filter(|route| route_is_current(&state, route))
            .map(|route| route.receipt.clone()))
    }

    pub fn acquire_route(
        self: &Arc<Self>,
        binding: &RouteGateBinding,
    ) -> Result<(RouteUseGuard, Ipv4Address), RouteInterlockError> {
        if binding.cat_id != self.cat_id {
            return Err(RouteInterlockError::WrongCat);
        }
        let mut state = self.lock()?;
        let ready = match &state.lifecycle {
            LifecycleRouteAdmission::RuntimeReady(ready) => ready.clone(),
            LifecycleRouteAdmission::Closed { .. } => {
                return Err(RouteInterlockError::StaleLifecycleSource)
            }
        };
        let agent_session = state.agent_session.clone();
        let route = state
            .routes
            .get_mut(&binding.endpoint_id)
            .ok_or(RouteInterlockError::RouteNotServing)?;
        if route.gate != EndpointGateState::Serving
            || route.enable.binding != *binding
            || route.enable.source_lifecycle_operation_id != ready.source_lifecycle_operation_id
            || route.enable.binding.runtime_incarnation != ready.runtime_incarnation
            || route.enable.agent_session != agent_session
        {
            return Err(RouteInterlockError::RouteNotServing);
        }
        route.active_guards = route
            .active_guards
            .checked_add(1)
            .ok_or(RouteInterlockError::CounterExhausted)?;
        Ok((
            RouteUseGuard {
                cell: Arc::clone(self),
                endpoint_id: binding.endpoint_id.clone(),
                serving_operation_id: route.enable.route_operation_id.clone(),
                cancellation: route.cancellation.subscribe(),
            },
            ready.guest_ipv4,
        ))
    }

    pub fn acquire_platform(self: &Arc<Self>) -> Result<PlatformUseGuard, RouteInterlockError> {
        let mut state = self.lock()?;
        if !matches!(state.lifecycle, LifecycleRouteAdmission::RuntimeReady(_)) {
            return Err(RouteInterlockError::StaleLifecycleSource);
        }
        state.platform_guards = state
            .platform_guards
            .checked_add(1)
            .ok_or(RouteInterlockError::CounterExhausted)?;
        Ok(PlatformUseGuard {
            cell: Arc::clone(self),
        })
    }

    /// Observe guard drain from the same mutex that admits and releases
    /// guards. This is deliberately a synchronous snapshot: lifecycle effects
    /// apply their own bounded command deadline and never infer drain from
    /// Route telemetry.
    pub fn active_guard_counts(&self) -> Result<LifecycleGuardCounts, RouteInterlockError> {
        let state = self.lock()?;
        Ok(LifecycleGuardCounts {
            platform_guards: state.platform_guards,
            endpoint_guards: state
                .routes
                .iter()
                .filter(|(_, route)| route.active_guards != 0)
                .map(|(endpoint_id, route)| (endpoint_id.clone(), route.active_guards))
                .collect(),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, LifecycleRouteAdmissionState>, RouteInterlockError> {
        self.state
            .lock()
            .map_err(|_| RouteInterlockError::Unavailable)
    }

    fn release_route(&self, endpoint_id: &Id, serving_operation_id: &Id) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(route) = state.routes.get_mut(endpoint_id) else {
            close_all_routes(&mut state);
            return;
        };
        if &route.enable.route_operation_id != serving_operation_id || route.active_guards == 0 {
            close_all_routes(&mut state);
            return;
        }
        route.active_guards -= 1;
    }

    fn release_platform(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.platform_guards == 0 {
            close_all_routes(&mut state);
        } else {
            state.platform_guards -= 1;
        }
    }

    #[cfg(test)]
    fn snapshot(&self) -> RouteInterlockSnapshot {
        let state = self.state.lock().expect("route interlock test mutex");
        RouteInterlockSnapshot {
            agent_session: state.agent_session.clone(),
            lifecycle: state.lifecycle.clone(),
            routes: state
                .routes
                .iter()
                .map(|(endpoint_id, route)| RouteInterlockEndpointSnapshot {
                    endpoint_id: endpoint_id.clone(),
                    route_epoch: route.receipt.route_epoch,
                    gate: route.gate,
                    active_guards: route.active_guards,
                })
                .collect(),
            platform_guards: state.platform_guards,
        }
    }
}

#[derive(Debug)]
pub struct RouteUseGuard {
    cell: Arc<LifecycleRouteAdmissionCell>,
    endpoint_id: Id,
    serving_operation_id: Id,
    cancellation: watch::Receiver<bool>,
}

impl RouteUseGuard {
    pub async fn cancelled(&mut self) {
        if *self.cancellation.borrow() {
            return;
        }
        let _ = self.cancellation.changed().await;
    }
}

impl Drop for RouteUseGuard {
    fn drop(&mut self) {
        self.cell
            .release_route(&self.endpoint_id, &self.serving_operation_id);
    }
}

#[derive(Debug)]
pub struct PlatformUseGuard {
    cell: Arc<LifecycleRouteAdmissionCell>,
}

impl Drop for PlatformUseGuard {
    fn drop(&mut self) {
        self.cell.release_platform();
    }
}

fn validate_enable_prefix(
    cat_id: &Id,
    state: &LifecycleRouteAdmissionState,
    command: &EnableRoute,
) -> Result<(), RouteInterlockError> {
    validate_route_command_prefix(
        cat_id,
        state,
        &command.agent_session,
        &command.source_lifecycle_operation_id,
        &command.binding,
    )
}

fn validate_route_command_prefix(
    cat_id: &Id,
    state: &LifecycleRouteAdmissionState,
    agent_session: &SessionBinding,
    source_lifecycle_operation_id: &Id,
    binding: &RouteGateBinding,
) -> Result<(), RouteInterlockError> {
    if agent_session != &state.agent_session {
        return Err(RouteInterlockError::StaleAgentSession);
    }
    if &binding.cat_id != cat_id {
        return Err(RouteInterlockError::WrongCat);
    }
    if binding.node_id != agent_session.node_id {
        return Err(RouteInterlockError::WrongNode);
    }
    let LifecycleRouteAdmission::RuntimeReady(ready) = &state.lifecycle else {
        return Err(RouteInterlockError::StaleLifecycleSource);
    };
    if source_lifecycle_operation_id != &ready.source_lifecycle_operation_id {
        return Err(RouteInterlockError::StaleLifecycleSource);
    }
    if binding.runtime_incarnation != ready.runtime_incarnation {
        return Err(RouteInterlockError::WrongRuntimeIncarnation);
    }
    Ok(())
}

fn validate_lifecycle_close(
    state: &LifecycleRouteAdmissionState,
    command: &CloseLifecycleAdmission,
) -> Result<(), RouteInterlockError> {
    match &state.lifecycle {
        LifecycleRouteAdmission::RuntimeReady(ready)
            if ready == &command.expected_runtime_ready =>
        {
            Ok(())
        }
        LifecycleRouteAdmission::Closed { .. } | LifecycleRouteAdmission::RuntimeReady(_) => {
            Err(RouteInterlockError::StaleLifecycleClose)
        }
    }
}

fn close_all_routes(state: &mut LifecycleRouteAdmissionState) -> Vec<ClosedRouteEpoch> {
    state
        .routes
        .iter_mut()
        .map(|(endpoint_id, route)| {
            route.gate = EndpointGateState::Closed;
            let _ = route.cancellation.send(true);
            ClosedRouteEpoch {
                endpoint_id: endpoint_id.clone(),
                route_epoch: route.receipt.route_epoch,
            }
        })
        .collect()
}

fn route_is_current(state: &LifecycleRouteAdmissionState, route: &EndpointRouteState) -> bool {
    let LifecycleRouteAdmission::RuntimeReady(ready) = &state.lifecycle else {
        return false;
    };
    route.gate == EndpointGateState::Serving
        && route.enable.agent_session == state.agent_session
        && route.receipt.matches_authority(ready, &state.agent_session)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteInterlockSnapshot {
    agent_session: SessionBinding,
    lifecycle: LifecycleRouteAdmission,
    routes: Vec<RouteInterlockEndpointSnapshot>,
    platform_guards: u32,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteInterlockEndpointSnapshot {
    endpoint_id: Id,
    route_epoch: Epoch,
    gate: EndpointGateState,
    active_guards: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::{Hostname, HttpProtocol, NodeBootId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    const MIB: u64 = 1024 * 1024;

    fn budget(commitment_bytes: u64, max_wakes: usize) -> WakeBudget {
        WakeBudget {
            commitment_bytes,
            max_wakes,
            queue_timeout: Duration::from_millis(50),
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: &str) -> RandomId128 {
        RandomId128::new(value).unwrap()
    }

    fn session(epoch: u64) -> SessionBinding {
        let agent_instance_id = match epoch {
            1 => "11111111111111111111111111111111",
            2 => "22222222222222222222222222222222",
            _ => "33333333333333333333333333333333",
        };
        SessionBinding {
            node_id: id("node_01"),
            node_boot_id: NodeBootId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            agent_instance_id: random(agent_instance_id),
            agent_session_epoch: Epoch::new(epoch).unwrap(),
        }
    }

    fn ready(source: &str, incarnation: &str) -> EffectiveRuntimeReady {
        EffectiveRuntimeReady::new(
            id(source),
            random(incarnation),
            Ipv4Address::new("10.0.0.2").unwrap(),
        )
    }

    fn binding(
        endpoint_id: &str,
        hostname: &str,
        incarnation: &str,
        route_epoch: u64,
    ) -> RouteGateBinding {
        RouteGateBinding {
            workspace_id: id("ws_01"),
            endpoint_id: id(endpoint_id),
            hostname: Hostname::new(hostname).unwrap(),
            cat_id: id("cat_01"),
            node_id: id("node_01"),
            runtime_incarnation: random(incarnation),
            route_epoch: Epoch::new(route_epoch).unwrap(),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        }
    }

    fn enable(
        operation_id: &str,
        source: &str,
        agent_session: &SessionBinding,
        binding: RouteGateBinding,
    ) -> EnableRoute {
        EnableRoute::new(id(operation_id), id(source), agent_session.clone(), binding)
    }

    fn route_cell(
        agent_session: &SessionBinding,
        ready: &EffectiveRuntimeReady,
    ) -> Arc<LifecycleRouteAdmissionCell> {
        LifecycleRouteAdmissionCell::new(
            id("cat_01"),
            agent_session.clone(),
            LifecycleRouteAdmission::RuntimeReady(ready.clone()),
        )
    }

    #[test]
    fn defaults_match_the_validated_operating_point() {
        let budget = WakeBudget::default();
        // Ten simultaneous 512 MiB restores (2026-07-21 concurrency run).
        assert_eq!(budget.max_wakes, 10);
        assert_eq!(budget.commitment_bytes, 10 * 512 * MIB);
    }

    #[test]
    fn commitment_is_guest_ram_and_cannot_overflow() {
        assert_eq!(resume_commitment_bytes(512), 512 * MIB);
        assert_eq!(resume_commitment_bytes(0), 0);
        assert_eq!(resume_commitment_bytes(u64::MAX), u64::MAX);
    }

    #[test]
    fn admits_up_to_the_byte_budget_then_queues() {
        let admission = WakeAdmission::new(budget(1024 * MIB, 100));
        let first = admission.acquire(512 * MIB).expect("first fits");
        let _second = admission.acquire(512 * MIB).expect("second fits");
        assert_eq!(admission.load().commitment_bytes, 1024 * MIB);

        let error = admission
            .acquire_until(512 * MIB, Duration::from_millis(20))
            .expect_err("budget is exhausted");
        assert!(matches!(error, AdmissionError::QueueTimeout { .. }));

        drop(first);
        admission
            .acquire_until(512 * MIB, Duration::from_millis(20))
            .expect("released budget is reusable");
    }

    #[test]
    fn wake_count_ceiling_bounds_many_tiny_cats() {
        // Byte budget alone would admit thousands of 1 MiB Cats.
        let admission = WakeAdmission::new(budget(1024 * MIB, 2));
        let _a = admission.acquire(MIB).expect("first");
        let _b = admission.acquire(MIB).expect("second");
        let error = admission
            .acquire_until(MIB, Duration::from_millis(20))
            .expect_err("count ceiling holds");
        assert!(matches!(error, AdmissionError::QueueTimeout { .. }));
        assert_eq!(admission.load().wakes, 2);
    }

    #[test]
    fn zero_commitment_still_consumes_a_slot() {
        let admission = WakeAdmission::new(budget(1024 * MIB, 1));
        let _only = admission.acquire(0).expect("zero-byte wake is admitted");
        let error = admission
            .acquire_until(0, Duration::from_millis(20))
            .expect_err("a zero-byte wake must not be unbounded");
        assert!(matches!(error, AdmissionError::QueueTimeout { .. }));
    }

    #[test]
    fn oversized_cat_fails_immediately_rather_than_waiting() {
        let admission = WakeAdmission::new(budget(256 * MIB, 10));
        let started = Instant::now();
        let error = admission
            .acquire_until(512 * MIB, Duration::from_secs(30))
            .expect_err("cannot ever fit");
        // Waiting can never satisfy it, so it must not burn the deadline.
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            error,
            AdmissionError::ExceedsNodeBudget {
                requested,
                budget: 268_435_456,
            } if requested == 512 * MIB
        ));
    }

    #[test]
    fn zero_max_wakes_is_reported_as_unsatisfiable_not_a_timeout() {
        let admission = WakeAdmission::new(budget(1024 * MIB, 0));
        let error = admission
            .acquire_until(MIB, Duration::from_secs(30))
            .expect_err("a disabled node admits nothing");
        assert!(matches!(error, AdmissionError::ExceedsNodeBudget { .. }));
    }

    /// Stands in for a wake that is admitted and then fails mid-flight.
    fn failing_wake(admission: &WakeAdmission) -> Result<(), &'static str> {
        let _permit = admission.acquire(512 * MIB).expect("admitted");
        Err("resume lost the boot id")
    }

    #[test]
    fn permit_release_is_unconditional_on_drop() {
        let admission = WakeAdmission::new(budget(512 * MIB, 1));
        // A wake that fails mid-flight must not leak its commitment.
        assert!(failing_wake(&admission).is_err());
        assert_eq!(admission.load().commitment_bytes, 0);
        assert_eq!(admission.load().wakes, 0);
        admission.acquire(512 * MIB).expect("budget was returned");
    }

    #[test]
    fn permit_release_survives_a_panicking_wake() {
        let admission = Arc::new(WakeAdmission::new(budget(512 * MIB, 1)));
        let panicked = {
            let admission = Arc::clone(&admission);
            std::thread::spawn(move || {
                let _permit = admission.acquire(512 * MIB).expect("admitted");
                panic!("wake blew up");
            })
            .join()
        };
        assert!(panicked.is_err());
        // Drop still ran during unwind, so the node is not wedged.
        assert_eq!(admission.load().wakes, 0);
        admission.acquire(512 * MIB).expect("budget was returned");
    }

    #[test]
    fn a_wake_storm_is_serialized_and_never_exceeds_the_ceiling() {
        // 24 wakes of 512 MiB against the validated 10 × 512 MiB budget.
        let admission = Arc::new(WakeAdmission::new(WakeBudget {
            commitment_bytes: 10 * 512 * MIB,
            max_wakes: 10,
            queue_timeout: Duration::from_secs(30),
        }));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..24 {
            let admission = Arc::clone(&admission);
            let completed = Arc::clone(&completed);
            handles.push(std::thread::spawn(move || {
                let permit = admission.acquire(512 * MIB).expect("eventually admitted");
                // Observe the ceiling from inside the critical section.
                let load = admission.load();
                assert!(load.wakes <= 10, "admitted {} wakes", load.wakes);
                assert!(load.commitment_bytes <= 10 * 512 * MIB);
                std::thread::sleep(Duration::from_millis(5));
                drop(permit);
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for handle in handles {
            handle.join().expect("wake thread");
        }
        // Every wake is served; the storm is spread, not dropped.
        assert_eq!(completed.load(Ordering::SeqCst), 24);
        let load = admission.load();
        assert_eq!(load.wakes, 0);
        assert_eq!(load.commitment_bytes, 0);
        assert!(load.peak_wakes <= 10, "peak {} wakes", load.peak_wakes);
        assert!(load.peak_commitment_bytes <= 10 * 512 * MIB);
    }

    #[test]
    fn a_large_wake_is_not_starved_by_a_stream_of_small_ones() {
        // notify_all + re-check means the big waiter competes on each release
        // instead of being permanently skipped.
        let admission = Arc::new(WakeAdmission::new(WakeBudget {
            commitment_bytes: 512 * MIB,
            max_wakes: 8,
            queue_timeout: Duration::from_secs(30),
        }));
        let hold = admission.acquire(512 * MIB).expect("fill the budget");
        let big = {
            let admission = Arc::clone(&admission);
            std::thread::spawn(move || {
                admission
                    .acquire_until(512 * MIB, Duration::from_secs(10))
                    .map(|permit| permit.commitment_bytes())
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        drop(hold);
        assert_eq!(big.join().expect("big wake thread"), Ok(512 * MIB));
    }

    #[test]
    fn lifecycle_close_and_enable_share_one_linearization_point() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        for sequence in 0..64 {
            let agent_session = session(1);
            let runtime_ready = ready("op_start_01", INCARNATION);
            let cell = route_cell(&agent_session, &runtime_ready);
            let command = enable(
                &format!("rop_enable_{sequence}"),
                "op_start_01",
                &agent_session,
                binding("ep_01", "web.example.test", INCARNATION, 1),
            );
            let close = CloseLifecycleAdmission::new(id("op_stop_01"), runtime_ready);
            let barrier = Arc::new(Barrier::new(3));

            let enable_result = {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cell.enable_route(&command)
                })
            };
            let close_result = {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cell.close_lifecycle(&close)
                })
            };
            barrier.wait();

            let enable_result = enable_result.join().expect("Enable thread");
            let close_result = close_result
                .join()
                .expect("lifecycle close thread")
                .expect("lifecycle close");
            match enable_result {
                Ok(EnableRouteOutcome::Serving(_)) => assert!(matches!(
                    close_result,
                    LifecycleCloseOutcome::Closed {
                        ref closed_route_epochs
                    } if closed_route_epochs.len() == 1
                )),
                Err(RouteInterlockError::StaleLifecycleSource) => assert!(matches!(
                    close_result,
                    LifecycleCloseOutcome::Closed {
                        ref closed_route_epochs
                    } if closed_route_epochs.is_empty()
                )),
                unexpected => panic!("invalid interlock outcome: {unexpected:?}"),
            }
            assert_eq!(cell.current_serving_route(&id("ep_01")).unwrap(), None);
            assert!(matches!(
                cell.snapshot().lifecycle,
                LifecycleRouteAdmission::Closed { .. }
            ));
        }
    }

    #[test]
    fn late_enable_after_lifecycle_close_has_zero_effect() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let agent_session = session(1);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&agent_session, &runtime_ready);
        let command = enable(
            "rop_enable_01",
            "op_start_01",
            &agent_session,
            binding("ep_01", "web.example.test", INCARNATION, 1),
        );
        cell.close_lifecycle(&CloseLifecycleAdmission::new(
            id("op_stop_01"),
            runtime_ready,
        ))
        .unwrap();
        let closed = cell.snapshot();

        assert_eq!(
            cell.enable_route(&command),
            Err(RouteInterlockError::StaleLifecycleSource)
        );
        assert_eq!(cell.snapshot(), closed);
    }

    #[test]
    fn genesis_anchor_is_fail_closed_until_exact_start_publishes_ready() {
        let agent_session = session(1);
        let creation_id = id("cat_creation_01");
        let runtime_ready = ready("op_start_01", "10101010101010101010101010101010");
        let cell = LifecycleRouteAdmissionCell::new_fail_closed(
            id("cat_01"),
            agent_session,
            creation_id.clone(),
        );

        assert_eq!(cell.effective_runtime_ready().unwrap(), None);
        assert_eq!(
            cell.publish_runtime_ready(&id("wrong_creation"), runtime_ready.clone()),
            Err(RouteInterlockError::StaleRuntimeReadySuccessor)
        );
        assert!(cell
            .publish_runtime_ready(&creation_id, runtime_ready.clone())
            .unwrap());
        assert_eq!(cell.effective_runtime_ready().unwrap(), Some(runtime_ready));
    }

    #[test]
    fn killed_closed_lane_adopts_cold_then_delete_without_reopening_routes() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let agent_session = session(1);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&agent_session, &runtime_ready);
        cell.enable_route(&enable(
            "rop_enable_01",
            "op_start_01",
            &agent_session,
            binding("ep_01", "web.example.test", INCARNATION, 7),
        ))
        .unwrap();
        cell.close_lifecycle(&CloseLifecycleAdmission::new(
            id("op_killed_01"),
            runtime_ready,
        ))
        .unwrap();
        let closed = cell.snapshot();

        assert_eq!(
            cell.adopt_closed_lifecycle_successor(&id("op_cold_01"), &id("op_killed_01")),
            Ok(LifecycleCloseOutcome::Closed {
                closed_route_epochs: Vec::new(),
            })
        );
        assert_eq!(cell.current_serving_route(&id("ep_01")).unwrap(), None);
        assert_eq!(cell.snapshot().routes, closed.routes);
        assert_eq!(
            cell.adopt_closed_lifecycle_successor(&id("op_delete_01"), &id("op_cold_01")),
            Ok(LifecycleCloseOutcome::Closed {
                closed_route_epochs: Vec::new(),
            })
        );
        assert!(matches!(
            cell.snapshot().lifecycle,
            LifecycleRouteAdmission::Closed {
                closing_operation_id
            } if closing_operation_id == id("op_delete_01")
        ));
    }

    #[test]
    fn suspended_and_warm_closed_anchors_adopt_legal_successors() {
        let agent_session = session(1);
        let suspended = LifecycleRouteAdmissionCell::new_fail_closed(
            id("cat_01"),
            agent_session.clone(),
            id("op_suspended_01"),
        );
        assert!(matches!(
            suspended
                .adopt_closed_lifecycle_successor(&id("op_cold_01"), &id("op_suspended_01"))
                .unwrap(),
            LifecycleCloseOutcome::Closed { .. }
        ));

        let warm = LifecycleRouteAdmissionCell::new_fail_closed(
            id("cat_01"),
            agent_session,
            id("op_warm_01"),
        );
        assert!(matches!(
            warm.adopt_closed_lifecycle_successor(&id("op_stop_01"), &id("op_warm_01"))
                .unwrap(),
            LifecycleCloseOutcome::Closed { .. }
        ));
    }

    #[test]
    fn wrong_closed_predecessor_racing_exact_successor_has_zero_effect() {
        for sequence in 0..64 {
            let cell = LifecycleRouteAdmissionCell::new_fail_closed(
                id("cat_01"),
                session(1),
                id("op_killed_01"),
            );
            let barrier = Arc::new(Barrier::new(3));
            let exact = {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cell.adopt_closed_lifecycle_successor(
                        &id(&format!("op_cold_{sequence}")),
                        &id("op_killed_01"),
                    )
                })
            };
            let wrong = {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cell.adopt_closed_lifecycle_successor(
                        &id(&format!("op_delete_{sequence}")),
                        &id("foreign_predecessor"),
                    )
                })
            };
            barrier.wait();

            assert!(matches!(
                exact.join().expect("exact successor thread"),
                Ok(LifecycleCloseOutcome::Closed { .. })
            ));
            assert_eq!(
                wrong.join().expect("wrong predecessor thread"),
                Err(RouteInterlockError::StaleLifecycleClose)
            );
            let current = id(&format!("op_cold_{sequence}"));
            assert!(matches!(
                cell.snapshot().lifecycle,
                LifecycleRouteAdmission::Closed {
                    closing_operation_id
                } if closing_operation_id == current
            ));
            assert_eq!(
                cell.adopt_closed_lifecycle_successor(&current, &id("foreign_predecessor")),
                Err(RouteInterlockError::StaleLifecycleClose)
            );
            assert_eq!(
                cell.adopt_closed_lifecycle_successor(&current, &id("op_killed_01")),
                Ok(LifecycleCloseOutcome::Replay)
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_close_cancels_a_guard_that_linearized_first() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let agent_session = session(1);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&agent_session, &runtime_ready);
        let route_binding = binding("ep_01", "web.example.test", INCARNATION, 1);
        cell.enable_route(&enable(
            "rop_enable_01",
            "op_start_01",
            &agent_session,
            route_binding.clone(),
        ))
        .unwrap();
        let (mut guard, _) = cell.acquire_route(&route_binding).unwrap();

        cell.close_lifecycle(&CloseLifecycleAdmission::new(
            id("op_stop_01"),
            runtime_ready,
        ))
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), guard.cancelled())
            .await
            .expect("lifecycle close must cancel the admitted route guard");
    }

    #[test]
    fn session_replacement_invalidates_serving_and_burns_the_epoch() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let old_session = session(1);
        let new_session = session(2);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&old_session, &runtime_ready);
        let old_enable = enable(
            "rop_enable_01",
            "op_start_01",
            &old_session,
            binding("ep_01", "web.example.test", INCARNATION, 7),
        );
        let old_receipt = match cell.enable_route(&old_enable).unwrap() {
            EnableRouteOutcome::Serving(receipt) => receipt,
            EnableRouteOutcome::Replay(_) => panic!("first Enable cannot replay"),
        };
        assert_eq!(old_receipt.agent_session(), &old_session);
        assert!(old_receipt.matches_authority(&runtime_ready, &old_session));

        assert!(matches!(
            cell.replace_agent_session(&old_session, &new_session)
                .unwrap(),
            AgentSessionReplacementOutcome::Replaced {
                ref closed_route_epochs
            } if closed_route_epochs == &vec![ClosedRouteEpoch {
                endpoint_id: id("ep_01"),
                route_epoch: Epoch::new(7).unwrap(),
            }]
        ));
        assert_eq!(cell.current_serving_route(&id("ep_01")).unwrap(), None);
        assert!(!old_receipt.matches_authority(&runtime_ready, &new_session));

        let same_epoch = enable(
            "rop_enable_02",
            "op_start_01",
            &new_session,
            binding("ep_01", "web.example.test", INCARNATION, 7),
        );
        assert_eq!(
            cell.enable_route(&same_epoch),
            Err(RouteInterlockError::RouteEpochNotAdvanced)
        );
        let next_epoch = enable(
            "rop_enable_03",
            "op_start_01",
            &new_session,
            binding("ep_01", "web.example.test", INCARNATION, 8),
        );
        let new_receipt = match cell.enable_route(&next_epoch).unwrap() {
            EnableRouteOutcome::Serving(receipt) => receipt,
            EnableRouteOutcome::Replay(_) => panic!("new epoch cannot replay"),
        };
        assert_eq!(new_receipt.agent_session(), &new_session);

        let before_stale = cell.snapshot();
        let stale_session = enable(
            "rop_enable_04",
            "op_start_01",
            &old_session,
            binding("ep_01", "web.example.test", INCARNATION, 9),
        );
        assert_eq!(
            cell.enable_route(&stale_session),
            Err(RouteInterlockError::StaleAgentSession)
        );
        assert_eq!(cell.snapshot(), before_stale);
    }

    #[test]
    fn superseded_result_closes_only_its_exact_local_serving_operation() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let agent_session = session(1);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&agent_session, &runtime_ready);
        cell.enable_route(&enable(
            "rop_enable_01",
            "op_start_01",
            &agent_session,
            binding("ep_01", "web.example.test", INCARNATION, 7),
        ))
        .unwrap();

        assert_eq!(
            cell.emergency_close_route(&id("ep_01"), &id("rop_enable_01")),
            Ok(Some(ClosedRouteEpoch {
                endpoint_id: id("ep_01"),
                route_epoch: Epoch::new(7).unwrap(),
            }))
        );
        assert_eq!(cell.current_serving_route(&id("ep_01")).unwrap(), None);

        cell.enable_route(&enable(
            "rop_enable_02",
            "op_start_01",
            &agent_session,
            binding("ep_01", "web.example.test", INCARNATION, 8),
        ))
        .unwrap();
        let successor = cell
            .current_serving_route(&id("ep_01"))
            .unwrap()
            .expect("burned epoch successor is Serving");

        assert_eq!(
            cell.emergency_close_route(&id("ep_01"), &id("rop_enable_01")),
            Ok(None)
        );
        assert_eq!(
            cell.current_serving_route(&id("ep_01")).unwrap(),
            Some(successor)
        );
    }

    #[test]
    fn require_idle_busy_retains_effective_runtime_ready_without_closing() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let agent_session = session(1);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&agent_session, &runtime_ready);
        let route_binding = binding("ep_01", "web.example.test", INCARNATION, 3);
        cell.enable_route(&enable(
            "rop_enable_01",
            "op_start_01",
            &agent_session,
            route_binding.clone(),
        ))
        .unwrap();
        let (route_guard, _) = cell.acquire_route(&route_binding).unwrap();
        let platform_guard = cell.acquire_platform().unwrap();
        let before = cell.snapshot();
        let suspend = CloseLifecycleAdmission::new(id("op_suspend_01"), runtime_ready.clone());

        assert_eq!(
            cell.active_guard_counts().unwrap(),
            LifecycleGuardCounts {
                platform_guards: 1,
                endpoint_guards: vec![(id("ep_01"), 1)],
            }
        );

        assert_eq!(
            cell.try_close_lifecycle_if_idle(&suspend).unwrap(),
            IdleLifecycleCloseOutcome::Busy {
                effective_runtime_ready: runtime_ready.clone(),
                platform_guards: 1,
                endpoint_guards: vec![(id("ep_01"), 1)],
            }
        );
        assert_eq!(cell.snapshot(), before);
        assert_eq!(
            cell.current_serving_route(&id("ep_01"))
                .unwrap()
                .unwrap()
                .source_lifecycle_operation_id(),
            runtime_ready.source_lifecycle_operation_id()
        );

        drop(route_guard);
        drop(platform_guard);
        assert!(cell.active_guard_counts().unwrap().is_drained());
        assert!(matches!(
            cell.try_close_lifecycle_if_idle(&suspend).unwrap(),
            IdleLifecycleCloseOutcome::Closed { .. }
        ));
        assert_eq!(cell.current_serving_route(&id("ep_01")).unwrap(), None);
    }

    #[test]
    fn endpoint_disable_does_not_change_an_unrelated_route_lane() {
        const INCARNATION: &str = "10101010101010101010101010101010";
        let agent_session = session(1);
        let runtime_ready = ready("op_start_01", INCARNATION);
        let cell = route_cell(&agent_session, &runtime_ready);
        let binding_a = binding("ep_a", "a.example.test", INCARNATION, 1);
        let binding_b = binding("ep_b", "b.example.test", INCARNATION, 1);
        let enable_a = enable(
            "rop_enable_a",
            "op_start_01",
            &agent_session,
            binding_a.clone(),
        );
        let enable_b = enable("rop_enable_b", "op_start_01", &agent_session, binding_b);
        cell.enable_route(&enable_a).unwrap();
        cell.enable_route(&enable_b).unwrap();
        let serving_b = cell.current_serving_route(&id("ep_b")).unwrap();
        let disable_a = DisableRoute::new(
            id("rop_disable_a"),
            id("op_start_01"),
            agent_session,
            id("rop_enable_a"),
            binding_a,
        );

        assert!(matches!(
            cell.disable_route(&disable_a).unwrap(),
            DisableRouteOutcome::Closed(_)
        ));
        assert_eq!(cell.current_serving_route(&id("ep_a")).unwrap(), None);
        assert_eq!(cell.current_serving_route(&id("ep_b")).unwrap(), serving_b);
        assert!(matches!(
            cell.disable_route(&disable_a).unwrap(),
            DisableRouteOutcome::Replay(_)
        ));
    }

    #[test]
    fn old_enable_cannot_reopen_a_successor_runtime() {
        const OLD_INCARNATION: &str = "10101010101010101010101010101010";
        const NEW_INCARNATION: &str = "20202020202020202020202020202020";
        let agent_session = session(1);
        let old_ready = ready("op_start_01", OLD_INCARNATION);
        let cell = route_cell(&agent_session, &old_ready);
        let old_enable = enable(
            "rop_enable_01",
            "op_start_01",
            &agent_session,
            binding("ep_01", "web.example.test", OLD_INCARNATION, 1),
        );
        cell.enable_route(&old_enable).unwrap();
        cell.close_lifecycle(&CloseLifecycleAdmission::new(id("op_stop_01"), old_ready))
            .unwrap();
        let new_ready = ready("op_start_02", NEW_INCARNATION);
        assert!(cell
            .publish_runtime_ready(&id("op_stop_01"), new_ready)
            .unwrap());
        let successor = enable(
            "rop_enable_02",
            "op_start_02",
            &agent_session,
            binding("ep_01", "web.example.test", NEW_INCARNATION, 2),
        );
        cell.enable_route(&successor).unwrap();
        let before_late = cell.snapshot();

        assert_eq!(
            cell.enable_route(&old_enable),
            Err(RouteInterlockError::StaleLifecycleSource)
        );
        assert_eq!(cell.snapshot(), before_late);
        assert_eq!(
            cell.current_serving_route(&id("ep_01"))
                .unwrap()
                .unwrap()
                .source_lifecycle_operation_id(),
            &id("op_start_02")
        );
    }
}

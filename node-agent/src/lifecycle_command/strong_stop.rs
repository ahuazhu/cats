//! Production-neutral strong-Stop orchestration.
//!
//! The journal is the source of Stop authority.  This module never creates a
//! fence token: an owned blocking worker retains the exact token returned by
//! [`FileLifecycleCommandJournal::record_stop_fence`], closes lifecycle
//! admission as its first physical linearization point, and then performs only
//! bounded synchronous platform effects while the fence guard is current.
//!
//! Waiting for the returned handle is deliberately cancellation-safe.  The
//! caller waits for an independently owned worker; dropping one waiter cannot
//! cancel an already accepted Stop or release its durable fence.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use cats_api::runtime_reconciliation::{Id, Sha256Digest};
use thiserror::Error;

use crate::admission::{
    CloseLifecycleAdmission, LifecycleCloseOutcome, LifecycleRouteAdmissionCell,
};

use super::journal::{
    CurrentStopFenceGuard, DurableStopFence, ExactCommandResult, FileLifecycleCommandJournal,
    LifecycleJournalError, StoredLifecycleJournal,
};

/// The exact system-manager execution boundary dedicated to one Cat.
///
/// A scope implementation must never interpret this as a prefix or parent
/// slice.  Strong Stop may kill this exact scope only; a scope owned by a
/// sibling Cat is a hard failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedicatedCatExecutionScope {
    cat_id: Id,
    scope_id: Id,
}

impl DedicatedCatExecutionScope {
    pub fn new(cat_id: Id, scope_id: Id) -> Self {
        Self { cat_id, scope_id }
    }

    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn scope_id(&self) -> &Id {
        &self.scope_id
    }
}

/// One scope identity returned by complete platform inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedExecutionScope {
    cat_id: Id,
    scope_id: Id,
}

impl ObservedExecutionScope {
    pub fn new(cat_id: Id, scope_id: Id) -> Self {
        Self { cat_id, scope_id }
    }

    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn scope_id(&self) -> &Id {
        &self.scope_id
    }
}

/// Provider-neutral proof that the exact dedicated scope is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionScopeAbsenceReceipt {
    cat_id: Id,
    scope_id: Id,
    proof_digest: Sha256Digest,
}

impl ExecutionScopeAbsenceReceipt {
    pub fn new(cat_id: Id, scope_id: Id, proof_digest: Sha256Digest) -> Self {
        Self {
            cat_id,
            scope_id,
            proof_digest,
        }
    }

    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn scope_id(&self) -> &Id {
        &self.scope_id
    }

    pub fn proof_digest(&self) -> &Sha256Digest {
        &self.proof_digest
    }
}

/// Complete inspection of the one expected execution-scope name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionScopeInventory {
    Absent(ExecutionScopeAbsenceReceipt),
    Present(ObservedExecutionScope),
}

/// Provider-neutral proof that no Guest-facing block frontend for the Cat is
/// live.  Non-serving publishers are outside this proof and may continue L->R
/// convergence under the Stop fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendAbsenceReceipt {
    cat_id: Id,
    proof_digest: Sha256Digest,
}

impl FrontendAbsenceReceipt {
    pub fn new(cat_id: Id, proof_digest: Sha256Digest) -> Self {
        Self {
            cat_id,
            proof_digest,
        }
    }

    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn proof_digest(&self) -> &Sha256Digest {
        &self.proof_digest
    }
}

/// Complete Guest-facing frontend inspection for one Cat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontendInventory {
    Absent(FrontendAbsenceReceipt),
    Present { frontend_ids: Vec<Id> },
}

/// A bounded platform-port failure.  Ambiguous graceful, force-kill and
/// frontend-close responses do not themselves fail Strong Stop: the final
/// absence inspections decide the postcondition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{operation}: {detail}")]
pub struct StrongStopPortError {
    operation: &'static str,
    detail: String,
}

impl StrongStopPortError {
    pub fn new(operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            operation,
            detail: detail.into(),
        }
    }
}

/// Initiates Guest/VMM graceful shutdown for one exact dedicated scope.
///
/// The method must return no later than the supplied absolute deadline.
/// Waiting for scope exit belongs to
/// [`DedicatedExecutionScopePort::wait_for_absence_until`].
pub trait GracefulShutdownPort: Send + Sync + 'static {
    fn request_graceful_shutdown(
        &self,
        scope: &DedicatedCatExecutionScope,
        deadline: Instant,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<(), StrongStopPortError>;
}

/// Owns complete discovery and exact force-kill of the dedicated Cat scope.
pub trait DedicatedExecutionScopePort: Send + Sync + 'static {
    /// Inspect the exact expected scope name.  Returning a different owner or
    /// scope identity is treated as foreign evidence, never as a kill target.
    fn inspect_scope(
        &self,
        expected: &DedicatedCatExecutionScope,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<ExecutionScopeInventory, StrongStopPortError>;

    /// Wait no later than `deadline` for graceful exit and return a fresh
    /// complete inspection.  Implementations must be bounded by the supplied
    /// deadline; the orchestrator independently prevents force-kill before it.
    fn wait_for_absence_until(
        &self,
        expected: &DedicatedCatExecutionScope,
        deadline: Instant,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<ExecutionScopeInventory, StrongStopPortError>;

    /// Force-kill only the exact dedicated scope.  The response may be
    /// ambiguous; final complete inspection is the success oracle.
    fn force_kill_scope(
        &self,
        expected: &DedicatedCatExecutionScope,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<(), StrongStopPortError>;
}

/// Closes and then proves absence of all Guest-facing block frontends.
pub trait GuestFrontendPort: Send + Sync + 'static {
    /// Close only frontends bound to the exact Cat/fence.  The response may be
    /// ambiguous; `inspect_frontends` remains the postcondition oracle.
    fn close_frontends(
        &self,
        cat_id: &Id,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<(), StrongStopPortError>;

    fn inspect_frontends(
        &self,
        cat_id: &Id,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<FrontendInventory, StrongStopPortError>;
}

/// Encodes the command-specific canonical `Killed` terminal result.
///
/// The Strong Stop core deliberately does not depend on the lifecycle wire.
/// A production command worker captures its exact accepted command in this
/// port. AgentSession authenticates the later transport commit only and is not
/// part of durable result identity. The guard lets the encoder derive fence
/// evidence without accepting caller-created fence bytes.
pub trait KilledResultEncoder: Send + Sync + 'static {
    fn encode_killed_result(
        &self,
        receipt: &StrongStopReceipt,
        fence: &CurrentStopFenceGuard<'_>,
    ) -> Result<ExactCommandResult, StrongStopPortError>;
}

/// Object-safe production ports captured by the owned Strong Stop worker.
#[derive(Clone)]
pub struct StrongStopPorts {
    graceful: Arc<dyn GracefulShutdownPort>,
    execution_scope: Arc<dyn DedicatedExecutionScopePort>,
    frontends: Arc<dyn GuestFrontendPort>,
}

impl StrongStopPorts {
    pub fn new(
        graceful: Arc<dyn GracefulShutdownPort>,
        execution_scope: Arc<dyn DedicatedExecutionScopePort>,
        frontends: Arc<dyn GuestFrontendPort>,
    ) -> Self {
        Self {
            graceful,
            execution_scope,
            frontends,
        }
    }
}

/// Exact local inputs for one already accepted, durably fenced Strong Stop.
#[derive(Debug, Clone)]
pub enum StrongStopAdmissionEdge {
    RuntimeReady(CloseLifecycleAdmission),
    ClosedSuccessor {
        current_operation_id: Id,
        expected_previous_closing_operation_id: Id,
    },
}

impl StrongStopAdmissionEdge {
    pub fn current_operation_id(&self) -> &Id {
        match self {
            Self::RuntimeReady(close) => close.closing_operation_id(),
            Self::ClosedSuccessor {
                current_operation_id,
                ..
            } => current_operation_id,
        }
    }
}

/// Exact local inputs for one already accepted, durably fenced Strong Stop.
#[derive(Debug, Clone)]
pub struct StrongStopRequest {
    admission_edge: StrongStopAdmissionEdge,
    execution_scope: DedicatedCatExecutionScope,
    grace_deadline: Instant,
}

impl StrongStopRequest {
    pub fn new(
        lifecycle_close: CloseLifecycleAdmission,
        execution_scope: DedicatedCatExecutionScope,
        grace_deadline: Instant,
    ) -> Self {
        Self {
            admission_edge: StrongStopAdmissionEdge::RuntimeReady(lifecycle_close),
            execution_scope,
            grace_deadline,
        }
    }

    /// Build a Strong Stop whose predecessor already left the admission cell
    /// Closed. Cold/Delete and cleanup successors use this edge instead of
    /// inventing a RuntimeReady value merely to pass the close API.
    pub fn new_closed_successor(
        current_operation_id: Id,
        expected_previous_closing_operation_id: Id,
        execution_scope: DedicatedCatExecutionScope,
        grace_deadline: Instant,
    ) -> Self {
        Self {
            admission_edge: StrongStopAdmissionEdge::ClosedSuccessor {
                current_operation_id,
                expected_previous_closing_operation_id,
            },
            execution_scope,
            grace_deadline,
        }
    }

    pub fn admission_edge(&self) -> &StrongStopAdmissionEdge {
        &self.admission_edge
    }

    pub fn operation_id(&self) -> &Id {
        self.admission_edge.current_operation_id()
    }

    pub fn execution_scope(&self) -> &DedicatedCatExecutionScope {
        &self.execution_scope
    }

    pub fn grace_deadline(&self) -> Instant {
        self.grace_deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStopDisposition {
    AlreadyAbsent,
    ExitedDuringGrace,
    ForcedAfterDeadline,
}

/// Killed-condition evidence.  Construction is private: this value exists
/// only after both final absence probes and the final fence assertion pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrongStopReceipt {
    operation_id: Id,
    lifecycle_close: LifecycleCloseOutcome,
    disposition: ExecutionStopDisposition,
    execution_scope_absence: ExecutionScopeAbsenceReceipt,
    frontend_absence: FrontendAbsenceReceipt,
}

impl StrongStopReceipt {
    pub fn operation_id(&self) -> &Id {
        &self.operation_id
    }

    pub fn lifecycle_close(&self) -> &LifecycleCloseOutcome {
        &self.lifecycle_close
    }

    pub fn disposition(&self) -> ExecutionStopDisposition {
        self.disposition
    }

    pub fn execution_scope_absence(&self) -> &ExecutionScopeAbsenceReceipt {
        &self.execution_scope_absence
    }

    pub fn frontend_absence(&self) -> &FrontendAbsenceReceipt {
        &self.frontend_absence
    }
}

/// Successful Strong Stop whose canonical `Killed` result is already durable
/// in the returned exact terminal journal record.
#[derive(Debug, Clone)]
pub struct StrongStopCompletion {
    receipt: StrongStopReceipt,
    terminal_record: StoredLifecycleJournal,
}

impl StrongStopCompletion {
    pub fn receipt(&self) -> &StrongStopReceipt {
        &self.receipt
    }

    pub fn terminal_record(&self) -> &StoredLifecycleJournal {
        &self.terminal_record
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StrongStopError {
    #[error(
        "strong Stop Cat binding mismatch: fence={fence_cat_id}, cell={cell_cat_id}, scope={scope_cat_id}"
    )]
    CatBindingMismatch {
        fence_cat_id: Id,
        cell_cat_id: Id,
        scope_cat_id: Id,
    },
    #[error(
        "strong Stop operation mismatch: fence={fence_operation_id}, close={close_operation_id}"
    )]
    OperationBindingMismatch {
        fence_operation_id: Id,
        close_operation_id: Id,
    },
    #[error("durable Stop fence authority failed: {detail}")]
    FenceAuthority { detail: String },
    #[error("durable Killed result settlement failed: {detail}")]
    TerminalSettlement { detail: String },
    #[error("lifecycle admission close failed: {detail}")]
    AdmissionClose { detail: String },
    #[error("{operation} failed: {detail}")]
    Port {
        operation: &'static str,
        detail: String,
    },
    #[error(
        "expected dedicated scope {expected_scope_id} for Cat {expected_cat_id}, observed foreign scope {observed_scope_id} for Cat {observed_cat_id}"
    )]
    ForeignExecutionScope {
        expected_cat_id: Id,
        expected_scope_id: Id,
        observed_cat_id: Id,
        observed_scope_id: Id,
    },
    #[error("execution-scope absence receipt does not bind the exact dedicated Cat scope")]
    InvalidExecutionScopeAbsenceReceipt,
    #[error(
        "frontend absence receipt belongs to Cat {observed_cat_id}, expected {expected_cat_id}"
    )]
    InvalidFrontendAbsenceReceipt {
        expected_cat_id: Id,
        observed_cat_id: Id,
    },
    #[error("dedicated execution scope {scope_id} for Cat {cat_id} remains present")]
    ExecutionScopeStillPresent { cat_id: Id, scope_id: Id },
    #[error("Guest-facing frontends remain present: {frontend_ids:?}")]
    FrontendsStillPresent { frontend_ids: Vec<Id> },
    #[error("frontend inventory reported Present with an empty identity set")]
    InvalidFrontendInventory,
    #[error("failed to spawn owned strong Stop worker: {detail}")]
    WorkerSpawn { detail: String },
    #[error("owned strong Stop worker panicked")]
    WorkerPanicked,
    #[error("owned strong Stop waiter failed: {detail}")]
    WorkerWait { detail: String },
}

/// Cloneable observation handle for the independently owned Stop worker.
/// Multiple callers may wait; none owns cancellation of the worker.
#[derive(Clone)]
pub struct StrongStopHandle {
    completion: Arc<WorkerCompletion>,
}

impl StrongStopHandle {
    pub fn wait_blocking(&self) -> Result<StrongStopCompletion, StrongStopError> {
        self.completion.wait()
    }

    /// Async convenience around the blocking completion condition.  Tokio
    /// cannot cancel a running `spawn_blocking` closure, and the actual Stop is
    /// owned by a separate OS thread in any case.
    pub async fn wait(&self) -> Result<StrongStopCompletion, StrongStopError> {
        let completion = Arc::clone(&self.completion);
        tokio::task::spawn_blocking(move || completion.wait())
            .await
            .map_err(|error| StrongStopError::WorkerWait {
                detail: error.to_string(),
            })?
    }

    pub fn is_finished(&self) -> bool {
        self.completion.is_finished()
    }
}

/// Start one independently owned Strong Stop worker.
///
/// `fenced_record` and `durable_stop_fence` must be the pair returned by one
/// successful `record_stop_fence` call.  The worker revalidates that pair
/// before lifecycle close and immediately before returning Killed evidence.
pub fn spawn_strong_stop(
    journal: Arc<FileLifecycleCommandJournal>,
    fenced_record: StoredLifecycleJournal,
    durable_stop_fence: DurableStopFence,
    admission: Arc<LifecycleRouteAdmissionCell>,
    request: StrongStopRequest,
    ports: StrongStopPorts,
    killed_result_encoder: Arc<dyn KilledResultEncoder>,
) -> Result<StrongStopHandle, StrongStopError> {
    validate_bindings(&durable_stop_fence, &admission, &request)?;

    let completion = Arc::new(WorkerCompletion::default());
    let worker_completion = Arc::clone(&completion);
    let _worker = std::thread::Builder::new()
        .name("cats-strong-stop".into())
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                execute_strong_stop(
                    &journal,
                    fenced_record,
                    durable_stop_fence,
                    &admission,
                    &request,
                    &ports,
                    killed_result_encoder.as_ref(),
                )
            }))
            .unwrap_or(Err(StrongStopError::WorkerPanicked));
            worker_completion.finish(outcome);
        })
        .map_err(|error| StrongStopError::WorkerSpawn {
            detail: error.to_string(),
        })?;

    Ok(StrongStopHandle { completion })
}

fn validate_bindings(
    fence: &DurableStopFence,
    admission: &LifecycleRouteAdmissionCell,
    request: &StrongStopRequest,
) -> Result<(), StrongStopError> {
    if fence.cat_id() != admission.cat_id() || fence.cat_id() != request.execution_scope.cat_id() {
        return Err(StrongStopError::CatBindingMismatch {
            fence_cat_id: fence.cat_id().clone(),
            cell_cat_id: admission.cat_id().clone(),
            scope_cat_id: request.execution_scope.cat_id().clone(),
        });
    }
    if fence.operation_id() != request.operation_id() {
        return Err(StrongStopError::OperationBindingMismatch {
            fence_operation_id: fence.operation_id().clone(),
            close_operation_id: request.operation_id().clone(),
        });
    }
    Ok(())
}

fn execute_strong_stop(
    journal: &FileLifecycleCommandJournal,
    fenced_record: StoredLifecycleJournal,
    durable_stop_fence: DurableStopFence,
    admission: &LifecycleRouteAdmissionCell,
    request: &StrongStopRequest,
    ports: &StrongStopPorts,
    killed_result_encoder: &dyn KilledResultEncoder,
) -> Result<StrongStopCompletion, StrongStopError> {
    let fence = journal
        .retain_current_stop_fence(&fenced_record, &durable_stop_fence)
        .map_err(fence_error)?;

    let receipt = execute_strong_stop_barrier(&fence, admission, request, ports)?;
    let terminal_result = killed_result_encoder
        .encode_killed_result(&receipt, &fence)
        .map_err(|error| port_error("encode canonical Killed result", error))?;
    fence.assert_current().map_err(fence_error)?;
    drop(fence);

    // This fresh CAS/token validation closes the small window after releasing
    // the physical-effect guard. The owned worker does not become complete
    // until the exact Killed result is durable, so caller cancellation cannot
    // strand an accepted Stop in Executing after physical success.
    let terminal_record = journal
        .complete_after_stop(&fenced_record, &durable_stop_fence, terminal_result)
        .map_err(|error| StrongStopError::TerminalSettlement {
            detail: error.to_string(),
        })?;

    Ok(StrongStopCompletion {
        receipt,
        terminal_record,
    })
}

/// Execute only the physical Strong Stop barrier under a retained journal
/// guard. Warm/Cold/Delete and failure handlers may use this core, then encode
/// their own typed result and call the appropriate journal terminal CAS.
/// A standalone Stop owner uses [`spawn_strong_stop`]. The atomic lifecycle
/// executor already runs each Cat on its own owned blocking worker and must
/// call this barrier directly so its outer state machine performs the sole
/// terminal CAS; nesting `spawn_strong_stop` there would double-settle one
/// journal generation.
pub fn execute_strong_stop_barrier(
    fence: &CurrentStopFenceGuard<'_>,
    admission: &LifecycleRouteAdmissionCell,
    request: &StrongStopRequest,
    ports: &StrongStopPorts,
) -> Result<StrongStopReceipt, StrongStopError> {
    if fence.cat_id() != admission.cat_id() || fence.cat_id() != request.execution_scope.cat_id() {
        return Err(StrongStopError::CatBindingMismatch {
            fence_cat_id: fence.cat_id().clone(),
            cell_cat_id: admission.cat_id().clone(),
            scope_cat_id: request.execution_scope.cat_id().clone(),
        });
    }
    if fence.operation_id() != request.operation_id() {
        return Err(StrongStopError::OperationBindingMismatch {
            fence_operation_id: fence.operation_id().clone(),
            close_operation_id: request.operation_id().clone(),
        });
    }
    fence.assert_current().map_err(fence_error)?;

    // The retained journal guard above is read/authority work.  This is the
    // first physical linearization point: after it wins, no late EnableRoute
    // can install and all already installed gates are closed/cancelled.
    let lifecycle_close = match &request.admission_edge {
        StrongStopAdmissionEdge::RuntimeReady(close) => admission.close_lifecycle(close),
        StrongStopAdmissionEdge::ClosedSuccessor {
            current_operation_id,
            expected_previous_closing_operation_id,
        } => admission.adopt_closed_lifecycle_successor(
            current_operation_id,
            expected_previous_closing_operation_id,
        ),
    }
    .map_err(|error| StrongStopError::AdmissionClose {
        detail: error.to_string(),
    })?;

    let initial_scope = ports
        .execution_scope
        .inspect_scope(&request.execution_scope, fence)
        .map_err(|error| port_error("inspect dedicated execution scope", error))?;
    let disposition = match classify_scope(initial_scope, &request.execution_scope)? {
        ClassifiedScope::Absent(_) => ExecutionStopDisposition::AlreadyAbsent,
        ClassifiedScope::ExactPresent => stop_present_scope(request, ports, fence)?,
    };

    // Close response ambiguity is resolved by the final complete inventory.
    let _ = ports
        .frontends
        .close_frontends(request.execution_scope.cat_id(), fence);

    let final_scope = ports
        .execution_scope
        .inspect_scope(&request.execution_scope, fence)
        .map_err(|error| port_error("verify final execution-scope absence", error))?;
    let execution_scope_absence = match classify_scope(final_scope, &request.execution_scope)? {
        ClassifiedScope::Absent(receipt) => receipt,
        ClassifiedScope::ExactPresent => {
            return Err(StrongStopError::ExecutionScopeStillPresent {
                cat_id: request.execution_scope.cat_id().clone(),
                scope_id: request.execution_scope.scope_id().clone(),
            })
        }
    };

    let frontend_absence = match ports
        .frontends
        .inspect_frontends(request.execution_scope.cat_id(), fence)
        .map_err(|error| port_error("verify final frontend absence", error))?
    {
        FrontendInventory::Absent(receipt) => {
            if receipt.cat_id() != request.execution_scope.cat_id() {
                return Err(StrongStopError::InvalidFrontendAbsenceReceipt {
                    expected_cat_id: request.execution_scope.cat_id().clone(),
                    observed_cat_id: receipt.cat_id().clone(),
                });
            }
            receipt
        }
        FrontendInventory::Present { frontend_ids } if frontend_ids.is_empty() => {
            return Err(StrongStopError::InvalidFrontendInventory)
        }
        FrontendInventory::Present { frontend_ids } => {
            return Err(StrongStopError::FrontendsStillPresent { frontend_ids })
        }
    };

    // This assertion is intentionally immediately before construction of the
    // Killed-condition receipt. Direct Stop asserts once more after encoding;
    // other command workers must likewise retain this guard through their
    // command-specific result construction.
    fence.assert_current().map_err(fence_error)?;
    Ok(StrongStopReceipt {
        operation_id: fence.operation_id().clone(),
        lifecycle_close,
        disposition,
        execution_scope_absence,
        frontend_absence,
    })
}

fn stop_present_scope(
    request: &StrongStopRequest,
    ports: &StrongStopPorts,
    fence: &CurrentStopFenceGuard<'_>,
) -> Result<ExecutionStopDisposition, StrongStopError> {
    // A graceful request failure is not a proof that the request had no
    // effect.  Continue to deadline and discover the scope postcondition.
    let _ = ports.graceful.request_graceful_shutdown(
        &request.execution_scope,
        request.grace_deadline,
        fence,
    );
    let after_grace = ports.execution_scope.wait_for_absence_until(
        &request.execution_scope,
        request.grace_deadline,
        fence,
    );
    if let Ok(inventory) = after_grace {
        match classify_scope(inventory, &request.execution_scope)? {
            ClassifiedScope::Absent(_) => return Ok(ExecutionStopDisposition::ExitedDuringGrace),
            ClassifiedScope::ExactPresent => {}
        }
    }

    sleep_until(request.grace_deadline);
    let at_deadline = ports
        .execution_scope
        .inspect_scope(&request.execution_scope, fence)
        .map_err(|error| port_error("reinspect execution scope at grace deadline", error))?;
    match classify_scope(at_deadline, &request.execution_scope)? {
        ClassifiedScope::Absent(_) => Ok(ExecutionStopDisposition::ExitedDuringGrace),
        ClassifiedScope::ExactPresent => {
            debug_assert!(Instant::now() >= request.grace_deadline);
            // Force response ambiguity is settled by the final inspection in
            // `execute_strong_stop`; do not blindly retry here.
            let _ = ports
                .execution_scope
                .force_kill_scope(&request.execution_scope, fence);
            Ok(ExecutionStopDisposition::ForcedAfterDeadline)
        }
    }
}

fn sleep_until(deadline: Instant) {
    if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        std::thread::sleep(remaining);
    }
}

enum ClassifiedScope {
    Absent(ExecutionScopeAbsenceReceipt),
    ExactPresent,
}

fn classify_scope(
    inventory: ExecutionScopeInventory,
    expected: &DedicatedCatExecutionScope,
) -> Result<ClassifiedScope, StrongStopError> {
    match inventory {
        ExecutionScopeInventory::Absent(receipt) => {
            if receipt.cat_id() != expected.cat_id() || receipt.scope_id() != expected.scope_id() {
                return Err(StrongStopError::InvalidExecutionScopeAbsenceReceipt);
            }
            Ok(ClassifiedScope::Absent(receipt))
        }
        ExecutionScopeInventory::Present(observed)
            if observed.cat_id() == expected.cat_id()
                && observed.scope_id() == expected.scope_id() =>
        {
            Ok(ClassifiedScope::ExactPresent)
        }
        ExecutionScopeInventory::Present(observed) => Err(StrongStopError::ForeignExecutionScope {
            expected_cat_id: expected.cat_id().clone(),
            expected_scope_id: expected.scope_id().clone(),
            observed_cat_id: observed.cat_id().clone(),
            observed_scope_id: observed.scope_id().clone(),
        }),
    }
}

fn fence_error(error: LifecycleJournalError) -> StrongStopError {
    StrongStopError::FenceAuthority {
        detail: error.to_string(),
    }
}

fn port_error(operation: &'static str, error: StrongStopPortError) -> StrongStopError {
    StrongStopError::Port {
        operation,
        detail: error.to_string(),
    }
}

type WorkerResult = Result<StrongStopCompletion, StrongStopError>;

#[derive(Default)]
struct WorkerCompletion {
    result: Mutex<Option<WorkerResult>>,
    ready: Condvar,
}

impl WorkerCompletion {
    fn finish(&self, outcome: WorkerResult) {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *result = Some(outcome);
        self.ready.notify_all();
    }

    fn wait(&self) -> WorkerResult {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(outcome) = result.as_ref() {
                return outcome.clone();
            }
            result = self
                .ready
                .wait(result)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn is_finished(&self) -> bool {
        self.result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    use cats_api::runtime_lifecycle::{
        CommandFailedResult, CommandFailureReason, DiskRole, ExecutionAbsenceProof,
        ImmutableRuntimeConfig, KilledResult, LifecycleCommand, LifecycleCommandEnvelope,
        LifecycleCommandResponse, LifecyclePredecessor, NodeResult, PlacementIdentity,
        RetainedEvidence, RuntimeNetworkConfig, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig,
        RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority, StopSpec,
        TerminalResultKind, VolumeTerminalReceipt,
    };
    use cats_api::runtime_reconciliation::{
        Durability, Epoch, FenceEpoch, Generation, Ipv4Address, MacAddress, NodeBootId,
        RandomId128, SessionBinding, UnixMillis,
    };
    use tempfile::TempDir;

    use crate::admission::{EffectiveRuntimeReady, LifecycleRouteAdmission};

    use super::*;
    use crate::lifecycle_command::journal::{
        AdmitCommandOutcome, CommandJournalState, ExactBytes, ExecutionStep, GenesisLocalInventory,
        LifecycleJournalRecord,
    };

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn random(value: &str) -> RandomId128 {
        RandomId128::new(value).expect("valid test random ID")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn session() -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .expect("valid boot ID"),
            agent_instance_id: random("11111111111111111111111111111111"),
            agent_session_epoch: Epoch::new(1).expect("positive session epoch"),
        }
    }

    fn ready() -> EffectiveRuntimeReady {
        EffectiveRuntimeReady::new(
            id("start_op"),
            random("22222222222222222222222222222222"),
            Ipv4Address::new("10.0.0.2").expect("valid test IP"),
        )
    }

    struct JournalFixture {
        _directory: TempDir,
        journal: Arc<FileLifecycleCommandJournal>,
        fenced_record: StoredLifecycleJournal,
        fence: DurableStopFence,
        request: LifecycleCommandEnvelope,
    }

    fn placement() -> PlacementIdentity {
        PlacementIdentity {
            node_id: id("node_a"),
            placement_epoch: Epoch::new(1).expect("positive placement epoch"),
        }
    }

    fn runtime_config() -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id("config_strong_stop"),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_a"),
                guest_mac: MacAddress::new("02:00:00:00:00:01").expect("valid MAC"),
                guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid gateway IP"),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_root"),
                disk_id: id("disk_root"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("root_serial"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .expect("valid immutable config")
    }

    fn genesis_request() -> LifecycleCommandEnvelope {
        let placement = placement();
        LifecycleCommandEnvelope::new(
            id("genesis_start"),
            id("workspace_a"),
            id("cat_01"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config(),
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation_strong_stop"),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_root"),
                    disk_id: id("disk_root"),
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).expect("zero unowned epoch"),
                        transition_id: random("33333333333333333333333333333333"),
                    },
                }],
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000)
                    .expect("positive wire deadline"),
            })),
        )
        .expect("canonical Genesis Start")
    }

    fn absence_proof() -> ExecutionAbsenceProof {
        ExecutionAbsenceProof {
            stop_fence_receipt_digest: digest(9),
            admission_closed_receipt_digest: digest(10),
            dedicated_scope_absence_receipt_digest: digest(11),
            frontend_absence_receipt_digest: digest(12),
            restart_source_absence_receipt_digest: digest(13),
        }
    }

    fn start_failed_response(request: &LifecycleCommandEnvelope) -> LifecycleCommandResponse {
        LifecycleCommandResponse::new(
            request,
            NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::VmmFailed,
                not_running: absence_proof(),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(14),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 0,
                    quarantined_count: 0,
                },
                retained_volume_receipts: Vec::new(),
            })),
        )
        .expect("canonical StartFailed response")
    }

    fn stop_request(
        operation_id: Id,
        previous: &LifecycleCommandResponse,
        previous_digest: Sha256Digest,
    ) -> LifecycleCommandEnvelope {
        LifecycleCommandEnvelope::new(
            operation_id,
            previous.workspace_id.clone(),
            previous.cat_id.clone(),
            previous.node_id.clone(),
            previous.placement_identity.clone(),
            runtime_config(),
            Some(previous.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: previous.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::StartFailed,
                terminal_result_digest: previous_digest,
                node_id: previous.node_id.clone(),
                placement_identity: previous.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(9_000_000).expect("positive wire deadline"),
            }),
        )
        .expect("canonical Stop successor")
    }

    fn journal_fixture(operation_id: Id) -> JournalFixture {
        let genesis = genesis_request();
        let cat_id = genesis.cat_id.clone();
        let directory = tempfile::tempdir().expect("temporary journal directory");
        let journal = Arc::new(
            FileLifecycleCommandJournal::open(directory.path(), &cat_id)
                .expect("open lifecycle journal"),
        );
        let genesis_accepted = match journal
            .admit_api(&genesis, GenesisLocalInventory::ConfirmedEmpty)
            .expect("admit Genesis Start")
        {
            AdmitCommandOutcome::Accepted(stored) => stored,
            _ => panic!("first exact Genesis Start must be accepted"),
        };
        let (genesis_fenced, genesis_fence) = journal
            .record_stop_fence(
                &genesis_accepted,
                ExecutionStep {
                    name: id("failed_start_cleanup"),
                    recovery_payload: ExactBytes::new(b"start-cleanup-step".to_vec()),
                },
                ExactBytes::new(b"durable-fence-payload".to_vec()),
            )
            .expect("durably record failed-Start fence");
        let start_failed = start_failed_response(&genesis);
        let exact_start_failed = ExactCommandResult::from_api(&start_failed)
            .expect("retain canonical StartFailed response");
        let start_failed_digest = exact_start_failed.result_digest().clone();
        journal
            .complete_after_stop(&genesis_fenced, &genesis_fence, exact_start_failed)
            .expect("durably complete StartFailed predecessor");
        let request = stop_request(operation_id, &start_failed, start_failed_digest);
        let stop_accepted = match journal
            .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
            .expect("admit exact Stop successor")
        {
            AdmitCommandOutcome::Accepted(stored) => stored,
            _ => panic!("first exact Stop successor must be accepted"),
        };
        let (fenced_record, fence) = journal
            .record_stop_fence(
                &stop_accepted,
                ExecutionStep {
                    name: id("strong_stop"),
                    recovery_payload: ExactBytes::new(b"strong-stop-step".to_vec()),
                },
                ExactBytes::new(b"durable-fence-payload".to_vec()),
            )
            .expect("retain durable Stop fence on Stop successor");
        JournalFixture {
            _directory: directory,
            journal,
            fenced_record,
            fence,
            request,
        }
    }

    fn scope(cat_id: &Id) -> DedicatedCatExecutionScope {
        DedicatedCatExecutionScope::new(cat_id.clone(), id("cat_scope"))
    }

    fn observed(scope: &DedicatedCatExecutionScope) -> ExecutionScopeInventory {
        ExecutionScopeInventory::Present(ObservedExecutionScope::new(
            scope.cat_id().clone(),
            scope.scope_id().clone(),
        ))
    }

    fn scope_absent(scope: &DedicatedCatExecutionScope, proof: u8) -> ExecutionScopeInventory {
        ExecutionScopeInventory::Absent(ExecutionScopeAbsenceReceipt::new(
            scope.cat_id().clone(),
            scope.scope_id().clone(),
            digest(proof),
        ))
    }

    fn frontend_absent(cat_id: &Id, proof: u8) -> FrontendInventory {
        FrontendInventory::Absent(FrontendAbsenceReceipt::new(cat_id.clone(), digest(proof)))
    }

    #[derive(Default)]
    struct BlockingGate {
        open: Mutex<bool>,
        changed: Condvar,
    }

    impl BlockingGate {
        fn wait(&self) {
            let mut open = self.open.lock().expect("blocking gate mutex");
            while !*open {
                open = self.changed.wait(open).expect("blocking gate mutex");
            }
        }

        fn open(&self) {
            *self.open.lock().expect("blocking gate mutex") = true;
            self.changed.notify_all();
        }
    }

    struct FakeState {
        events: Vec<&'static str>,
        all_effects_saw_closed_admission: bool,
        scope_inspections: VecDeque<Result<ExecutionScopeInventory, StrongStopPortError>>,
        graceful_wait: Option<Result<ExecutionScopeInventory, StrongStopPortError>>,
        frontend_inventory: Option<Result<FrontendInventory, StrongStopPortError>>,
        force_called_at: Option<Instant>,
    }

    struct FakePorts {
        admission: Arc<LifecycleRouteAdmissionCell>,
        state: Mutex<FakeState>,
        graceful_started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        graceful_gate: Option<Arc<BlockingGate>>,
    }

    impl FakePorts {
        fn new(
            admission: Arc<LifecycleRouteAdmissionCell>,
            scope_inspections: Vec<ExecutionScopeInventory>,
            graceful_wait: ExecutionScopeInventory,
            frontend_inventory: FrontendInventory,
        ) -> Arc<Self> {
            Arc::new(Self {
                admission,
                state: Mutex::new(FakeState {
                    events: Vec::new(),
                    all_effects_saw_closed_admission: true,
                    scope_inspections: scope_inspections.into_iter().map(Ok).collect(),
                    graceful_wait: Some(Ok(graceful_wait)),
                    frontend_inventory: Some(Ok(frontend_inventory)),
                    force_called_at: None,
                }),
                graceful_started: Mutex::new(None),
                graceful_gate: None,
            })
        }

        fn with_graceful_gate(
            mut self: Arc<Self>,
            started: tokio::sync::oneshot::Sender<()>,
            gate: Arc<BlockingGate>,
        ) -> Arc<Self> {
            Arc::get_mut(&mut self)
                .expect("fixture has one owner")
                .graceful_gate = Some(gate);
            *self.graceful_started.lock().expect("started sender mutex") = Some(started);
            self
        }

        fn observe_effect(&self, event: &'static str) {
            let admission_closed = self
                .admission
                .effective_runtime_ready()
                .expect("admission cell available")
                .is_none();
            let mut state = self.state.lock().expect("fake ports mutex");
            state.events.push(event);
            state.all_effects_saw_closed_admission &= admission_closed;
        }

        fn events(&self) -> Vec<&'static str> {
            self.state.lock().expect("fake ports mutex").events.clone()
        }

        fn force_called_at(&self) -> Option<Instant> {
            self.state.lock().expect("fake ports mutex").force_called_at
        }
    }

    impl GracefulShutdownPort for FakePorts {
        fn request_graceful_shutdown(
            &self,
            _scope: &DedicatedCatExecutionScope,
            _deadline: Instant,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<(), StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            self.observe_effect("graceful.request");
            if let Some(started) = self
                .graceful_started
                .lock()
                .expect("started sender mutex")
                .take()
            {
                let _ = started.send(());
            }
            if let Some(gate) = &self.graceful_gate {
                gate.wait();
            }
            Ok(())
        }
    }

    impl DedicatedExecutionScopePort for FakePorts {
        fn inspect_scope(
            &self,
            _expected: &DedicatedCatExecutionScope,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<ExecutionScopeInventory, StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            self.observe_effect("scope.inspect");
            self.state
                .lock()
                .expect("fake ports mutex")
                .scope_inspections
                .pop_front()
                .expect("configured scope inspection")
        }

        fn wait_for_absence_until(
            &self,
            _expected: &DedicatedCatExecutionScope,
            _deadline: Instant,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<ExecutionScopeInventory, StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            self.observe_effect("scope.wait");
            self.state
                .lock()
                .expect("fake ports mutex")
                .graceful_wait
                .take()
                .expect("configured graceful wait")
        }

        fn force_kill_scope(
            &self,
            _expected: &DedicatedCatExecutionScope,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<(), StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            self.observe_effect("scope.force_kill");
            self.state.lock().expect("fake ports mutex").force_called_at = Some(Instant::now());
            Ok(())
        }
    }

    impl GuestFrontendPort for FakePorts {
        fn close_frontends(
            &self,
            _cat_id: &Id,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<(), StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            self.observe_effect("frontend.close");
            Ok(())
        }

        fn inspect_frontends(
            &self,
            _cat_id: &Id,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<FrontendInventory, StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            self.observe_effect("frontend.inspect");
            self.state
                .lock()
                .expect("fake ports mutex")
                .frontend_inventory
                .take()
                .expect("configured frontend inventory")
        }
    }

    struct FakeKilledResultEncoder {
        request: LifecycleCommandEnvelope,
    }

    impl KilledResultEncoder for FakeKilledResultEncoder {
        fn encode_killed_result(
            &self,
            receipt: &StrongStopReceipt,
            fence: &CurrentStopFenceGuard<'_>,
        ) -> Result<ExactCommandResult, StrongStopPortError> {
            assert_eq!(fence.fence_payload(), b"durable-fence-payload");
            let response = LifecycleCommandResponse::new(
                &self.request,
                NodeResult::Killed(Box::new(KilledResult {
                    stopped_runtime_incarnation: Some(random("66666666666666666666666666666666")),
                    execution_absence: ExecutionAbsenceProof {
                        stop_fence_receipt_digest: digest(21),
                        admission_closed_receipt_digest: digest(22),
                        dedicated_scope_absence_receipt_digest: receipt
                            .execution_scope_absence()
                            .proof_digest()
                            .clone(),
                        frontend_absence_receipt_digest: receipt
                            .frontend_absence()
                            .proof_digest()
                            .clone(),
                        restart_source_absence_receipt_digest: digest(23),
                    },
                    stop_fence_receipt_digest: digest(21),
                    retained_volume_receipts: vec![VolumeTerminalReceipt {
                        volume_id: id("volume_root"),
                        disk_id: id("disk_root"),
                        disk_role: DiskRole::Root,
                        attachment_id: id("attachment_root"),
                        attachment_epoch: FenceEpoch::new(1).expect("positive attachment epoch"),
                        local_durable_generation: Generation::new(2).expect("local generation"),
                        remote_durable_generation: Generation::new(1).expect("remote generation"),
                        authority_receipt_digest: Some(digest(25)),
                    }],
                    retained_evidence: RetainedEvidence {
                        artifact_manifest_digest: digest(24),
                        adoptable_count: 0,
                        gc_candidate_count: 0,
                        retained_authority_or_data_count: 1,
                        quarantined_count: 0,
                    },
                })),
            )
            .map_err(|error| {
                StrongStopPortError::new("encode Killed response", error.to_string())
            })?;
            ExactCommandResult::from_api(&response).map_err(|error| {
                StrongStopPortError::new("retain Killed response", error.to_string())
            })
        }
    }

    struct StopFixture {
        _journal_directory: TempDir,
        journal: Arc<FileLifecycleCommandJournal>,
        fenced_record: StoredLifecycleJournal,
        fence: DurableStopFence,
        admission: Arc<LifecycleRouteAdmissionCell>,
        request: StrongStopRequest,
        killed_result_encoder: Arc<dyn KilledResultEncoder>,
        cat_id: Id,
        scope: DedicatedCatExecutionScope,
    }

    fn stop_fixture(deadline: Instant) -> StopFixture {
        let cat_id = id("cat_01");
        let operation_id = id("stop_op");
        let journal = journal_fixture(operation_id.clone());
        assert_eq!(journal.request.cat_id, cat_id);
        let runtime_ready = ready();
        let admission = LifecycleRouteAdmissionCell::new(
            cat_id.clone(),
            session(),
            LifecycleRouteAdmission::RuntimeReady(runtime_ready.clone()),
        );
        let scope = scope(&cat_id);
        let request = StrongStopRequest::new(
            CloseLifecycleAdmission::new(operation_id, runtime_ready),
            scope.clone(),
            deadline,
        );
        StopFixture {
            _journal_directory: journal._directory,
            journal: journal.journal,
            fenced_record: journal.fenced_record,
            fence: journal.fence,
            admission,
            request,
            killed_result_encoder: Arc::new(FakeKilledResultEncoder {
                request: journal.request,
            }),
            cat_id,
            scope,
        }
    }

    fn spawn_with_fake(fixture: &StopFixture, fake: Arc<FakePorts>) -> StrongStopHandle {
        let graceful: Arc<dyn GracefulShutdownPort> = fake.clone();
        let execution_scope: Arc<dyn DedicatedExecutionScopePort> = fake.clone();
        let frontends: Arc<dyn GuestFrontendPort> = fake;
        spawn_strong_stop(
            Arc::clone(&fixture.journal),
            fixture.fenced_record.clone(),
            fixture.fence.clone(),
            Arc::clone(&fixture.admission),
            fixture.request.clone(),
            StrongStopPorts::new(graceful, execution_scope, frontends),
            Arc::clone(&fixture.killed_result_encoder),
        )
        .expect("spawn Strong Stop")
    }

    fn journal_is_terminal(journal: &FileLifecycleCommandJournal) -> bool {
        matches!(
            journal
                .load()
                .expect("load lifecycle journal")
                .as_ref()
                .map(StoredLifecycleJournal::record),
            Some(LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal { .. },
                ..
            })
        )
    }

    fn journal_is_executing(journal: &FileLifecycleCommandJournal) -> bool {
        matches!(
            journal
                .load()
                .expect("load lifecycle journal")
                .as_ref()
                .map(StoredLifecycleJournal::record),
            Some(LifecycleJournalRecord::Command {
                state: CommandJournalState::Executing { .. },
                ..
            })
        )
    }

    #[test]
    fn admission_close_precedes_every_platform_effect_and_graceful_exit_settles() {
        let fixture = stop_fixture(Instant::now() + Duration::from_secs(1));
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![observed(&fixture.scope), scope_absent(&fixture.scope, 3)],
            scope_absent(&fixture.scope, 2),
            frontend_absent(&fixture.cat_id, 4),
        );
        let completion = spawn_with_fake(&fixture, Arc::clone(&fake))
            .wait_blocking()
            .expect("Strong Stop succeeds");

        assert_eq!(
            completion.receipt().disposition(),
            ExecutionStopDisposition::ExitedDuringGrace
        );
        assert!(
            fake.state
                .lock()
                .expect("fake ports mutex")
                .all_effects_saw_closed_admission,
            "no physical port may run before lifecycle admission closes"
        );
        assert_eq!(
            fake.events(),
            vec![
                "scope.inspect",
                "graceful.request",
                "scope.wait",
                "frontend.close",
                "scope.inspect",
                "frontend.inspect",
            ]
        );
        assert_eq!(
            fixture
                .admission
                .effective_runtime_ready()
                .expect("admission cell available"),
            None
        );

        assert!(matches!(
            completion.terminal_record().record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal { .. },
                ..
            }
        ));
    }

    #[test]
    fn already_closed_predecessor_is_adopted_before_strong_stop_effects() {
        let mut fixture = stop_fixture(Instant::now() + Duration::from_secs(1));
        let predecessor = id("killed_op");
        fixture.admission = LifecycleRouteAdmissionCell::new_fail_closed(
            fixture.cat_id.clone(),
            session(),
            predecessor.clone(),
        );
        fixture.request = StrongStopRequest::new_closed_successor(
            id("stop_op"),
            predecessor,
            fixture.scope.clone(),
            Instant::now() + Duration::from_secs(1),
        );
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![
                scope_absent(&fixture.scope, 2),
                scope_absent(&fixture.scope, 3),
            ],
            scope_absent(&fixture.scope, 4),
            frontend_absent(&fixture.cat_id, 5),
        );

        let completion = spawn_with_fake(&fixture, Arc::clone(&fake))
            .wait_blocking()
            .expect("Closed successor Strong Stop succeeds");

        assert_eq!(
            completion.receipt().disposition(),
            ExecutionStopDisposition::AlreadyAbsent
        );
        assert!(matches!(
            completion.receipt().lifecycle_close(),
            LifecycleCloseOutcome::Closed {
                closed_route_epochs
            } if closed_route_epochs.is_empty()
        ));
        assert!(
            fake.state
                .lock()
                .expect("fake ports mutex")
                .all_effects_saw_closed_admission
        );
        assert_eq!(
            fake.events(),
            vec![
                "scope.inspect",
                "frontend.close",
                "scope.inspect",
                "frontend.inspect",
            ]
        );
        assert!(journal_is_terminal(&fixture.journal));
    }

    #[test]
    fn grace_timeout_force_kills_only_after_deadline() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let fixture = stop_fixture(deadline);
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![
                observed(&fixture.scope),
                observed(&fixture.scope),
                scope_absent(&fixture.scope, 4),
            ],
            observed(&fixture.scope),
            frontend_absent(&fixture.cat_id, 5),
        );
        let completion = spawn_with_fake(&fixture, Arc::clone(&fake))
            .wait_blocking()
            .expect("forced Strong Stop succeeds after absence proof");

        assert_eq!(
            completion.receipt().disposition(),
            ExecutionStopDisposition::ForcedAfterDeadline
        );
        assert!(
            fake.force_called_at().expect("force-kill called") >= deadline,
            "force-kill must never run before the exact grace deadline"
        );
        assert_eq!(
            fake.events(),
            vec![
                "scope.inspect",
                "graceful.request",
                "scope.wait",
                "scope.inspect",
                "scope.force_kill",
                "frontend.close",
                "scope.inspect",
                "frontend.inspect",
            ]
        );
    }

    #[test]
    fn foreign_sibling_scope_is_rejected_without_grace_or_kill() {
        let fixture = stop_fixture(Instant::now());
        let foreign = ExecutionScopeInventory::Present(ObservedExecutionScope::new(
            id("cat_sibling"),
            id("sibling_scope"),
        ));
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![foreign],
            scope_absent(&fixture.scope, 2),
            frontend_absent(&fixture.cat_id, 3),
        );
        let error = spawn_with_fake(&fixture, Arc::clone(&fake))
            .wait_blocking()
            .expect_err("foreign scope must fail closed");

        assert!(matches!(
            error,
            StrongStopError::ForeignExecutionScope { .. }
        ));
        assert_eq!(fake.events(), vec!["scope.inspect"]);
        assert!(
            fake.state
                .lock()
                .expect("fake ports mutex")
                .all_effects_saw_closed_admission
        );
    }

    #[test]
    fn final_execution_scope_presence_cannot_return_killed() {
        let fixture = stop_fixture(Instant::now());
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![
                observed(&fixture.scope),
                observed(&fixture.scope),
                observed(&fixture.scope),
            ],
            observed(&fixture.scope),
            frontend_absent(&fixture.cat_id, 3),
        );
        let error = spawn_with_fake(&fixture, fake)
            .wait_blocking()
            .expect_err("live scope cannot produce Killed");

        assert_eq!(
            error,
            StrongStopError::ExecutionScopeStillPresent {
                cat_id: fixture.cat_id.clone(),
                scope_id: fixture.scope.scope_id().clone(),
            }
        );
        assert!(journal_is_executing(&fixture.journal));
    }

    #[test]
    fn final_frontend_presence_cannot_return_killed() {
        let fixture = stop_fixture(Instant::now() + Duration::from_secs(1));
        let frontend_ids = vec![id("root_frontend")];
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![observed(&fixture.scope), scope_absent(&fixture.scope, 3)],
            scope_absent(&fixture.scope, 2),
            FrontendInventory::Present {
                frontend_ids: frontend_ids.clone(),
            },
        );
        let error = spawn_with_fake(&fixture, fake)
            .wait_blocking()
            .expect_err("live frontend cannot produce Killed");

        assert_eq!(
            error,
            StrongStopError::FrontendsStillPresent { frontend_ids }
        );
        assert!(journal_is_executing(&fixture.journal));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_one_waiter_does_not_cancel_the_accepted_stop() {
        let fixture = stop_fixture(Instant::now() + Duration::from_secs(1));
        let gate = Arc::new(BlockingGate::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let fake = FakePorts::new(
            Arc::clone(&fixture.admission),
            vec![observed(&fixture.scope), scope_absent(&fixture.scope, 3)],
            scope_absent(&fixture.scope, 2),
            frontend_absent(&fixture.cat_id, 4),
        )
        .with_graceful_gate(started_tx, Arc::clone(&gate));
        let handle = spawn_with_fake(&fixture, fake);

        let cancelled_waiter_handle = handle.clone();
        let cancelled_waiter = tokio::spawn(async move { cancelled_waiter_handle.wait().await });
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("Strong Stop reached graceful port")
            .expect("Strong Stop worker did not drop notification");
        cancelled_waiter.abort();
        assert!(cancelled_waiter
            .await
            .expect_err("waiter was aborted")
            .is_cancelled());

        // No response waiter or handle remains. The independently owned
        // command worker must still durably settle the exact Killed result.
        drop(handle);
        gate.open();
        let journal = Arc::clone(&fixture.journal);
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                let journal = Arc::clone(&journal);
                let terminal = tokio::task::spawn_blocking(move || journal_is_terminal(&journal))
                    .await
                    .expect("journal poll worker");
                if terminal {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("owned worker outlives every cancelled/dropped waiter");
    }
}

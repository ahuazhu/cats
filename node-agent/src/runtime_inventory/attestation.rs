//! Synchronous lifecycle-to-inventory handoff for post-Stop authority.
//!
//! The lifecycle executor never owns a telemetry transport. It submits one
//! bounded request to the process's sole inventory runner and blocks its
//! already-dedicated worker until a newly collected Full report is durably
//! accepted by Control. A readiness snapshot or periodic Full can never
//! satisfy this edge because the request is associated with a report whose
//! physical scan starts only after the runner dequeues it.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cats_api::runtime_inventory::{
    full_inventory_digest, ObservedCommandJournal, ObservedRuntimePhysicalState,
    RuntimeInventoryAttestation, RuntimeInventoryBody, RuntimeInventoryReport,
    RUNTIME_INVENTORY_MAX_CATS,
};
use cats_api::runtime_lifecycle::{
    validate_lifecycle_command_envelope, LifecycleCommand, LifecycleCommandEnvelope,
};
use cats_api::runtime_reconciliation::{SessionBinding, UnixMillis};
use thiserror::Error;

/// Object-safe boundary consumed by the synchronous Cold/Delete handler.
/// Implementations must return only a newly accepted current-session Full;
/// cached readiness and independently posted telemetry are not authority.
pub trait RuntimeInventoryAttestationPort: Send + Sync + 'static {
    fn force_full_and_wait(
        &self,
        command: &LifecycleCommandEnvelope,
        deadline_unix_ms: UnixMillis,
    ) -> anyhow::Result<RuntimeInventoryAttestation>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RuntimeInventoryForceFullError {
    #[error("runtime inventory force-Full coordinator is not bound to an AgentSession")]
    NotBound,
    #[error("runtime inventory force-Full coordinator already has an active runner")]
    AlreadyBound,
    #[error("runtime inventory force-Full coordinator is closed")]
    Closed,
    #[error("runtime inventory force-Full request deadline expired")]
    DeadlineExpired,
    #[error("runtime inventory force-Full command is not a canonical Cold/Delete command")]
    InvalidCommand,
    #[error("runtime inventory force-Full deadline exceeds the command convergence deadline")]
    DeadlineExceedsCommand,
    #[error("runtime inventory force-Full request capacity is exhausted")]
    CapacityExceeded,
    #[error("runtime inventory force-Full request belongs to another Node session")]
    WrongSession,
    #[error("post-Stop Full inventory did not prove the requested command: {reason}")]
    PostStopEvidenceMismatch { reason: &'static str },
    #[error("runtime inventory force-Full coordinator state is unavailable")]
    StateUnavailable,
}

enum CoordinatorBinding {
    Unbound,
    Bound(SessionBinding),
    Closed,
}

struct CoordinatorState {
    binding: CoordinatorBinding,
    queued: VecDeque<Arc<ForceFullRequest>>,
}

/// Caller-created shared handle. Composition passes the same `Arc` to the
/// installed lifecycle executor and to `RuntimeInventoryRunner::open`.
pub struct RuntimeInventoryForceFullCoordinator {
    state: Mutex<CoordinatorState>,
    wake_runner: tokio::sync::Notify,
}

impl std::fmt::Debug for RuntimeInventoryForceFullCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInventoryForceFullCoordinator")
            .finish_non_exhaustive()
    }
}

impl RuntimeInventoryForceFullCoordinator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CoordinatorState {
                binding: CoordinatorBinding::Unbound,
                queued: VecDeque::new(),
            }),
            wake_runner: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn bind_once(
        &self,
        session: &SessionBinding,
    ) -> Result<(), RuntimeInventoryForceFullError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeInventoryForceFullError::StateUnavailable)?;
        match &state.binding {
            CoordinatorBinding::Unbound => {
                state.binding = CoordinatorBinding::Bound(session.clone());
                Ok(())
            }
            CoordinatorBinding::Bound(_) | CoordinatorBinding::Closed => {
                Err(RuntimeInventoryForceFullError::AlreadyBound)
            }
        }
    }

    pub(super) fn take_pending(
        &self,
        session: &SessionBinding,
    ) -> Result<Vec<Arc<ForceFullRequest>>, RuntimeInventoryForceFullError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeInventoryForceFullError::StateUnavailable)?;
        match &state.binding {
            CoordinatorBinding::Bound(bound) if bound == session => {
                Ok(state.queued.drain(..).collect())
            }
            CoordinatorBinding::Bound(_) => Err(RuntimeInventoryForceFullError::WrongSession),
            CoordinatorBinding::Unbound => Err(RuntimeInventoryForceFullError::NotBound),
            CoordinatorBinding::Closed => Err(RuntimeInventoryForceFullError::Closed),
        }
    }

    pub(super) async fn notified(&self) {
        self.wake_runner.notified().await;
    }

    pub(super) fn close(&self) {
        let queued = match self.state.lock() {
            Ok(mut state) => {
                state.binding = CoordinatorBinding::Closed;
                state.queued.drain(..).collect::<Vec<_>>()
            }
            Err(_) => return,
        };
        for request in queued {
            request.complete(Err(RuntimeInventoryForceFullError::Closed));
        }
        self.wake_runner.notify_waiters();
    }
}

impl RuntimeInventoryAttestationPort for RuntimeInventoryForceFullCoordinator {
    fn force_full_and_wait(
        &self,
        command: &LifecycleCommandEnvelope,
        deadline_unix_ms: UnixMillis,
    ) -> anyhow::Result<RuntimeInventoryAttestation> {
        if validate_lifecycle_command_envelope(command).is_err() {
            return Err(RuntimeInventoryForceFullError::InvalidCommand.into());
        }
        let command_deadline = match &command.command {
            LifecycleCommand::Cold(spec) => spec.convergence_deadline_unix_ms,
            LifecycleCommand::Delete(spec) => spec.convergence_deadline_unix_ms,
            _ => return Err(RuntimeInventoryForceFullError::InvalidCommand.into()),
        };
        if deadline_unix_ms > command_deadline {
            return Err(RuntimeInventoryForceFullError::DeadlineExceedsCommand.into());
        }
        let deadline = monotonic_deadline(deadline_unix_ms)?;
        let request = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RuntimeInventoryForceFullError::StateUnavailable)?;
            let session = match &state.binding {
                CoordinatorBinding::Bound(session) if session.node_id == command.node_id => {
                    session.clone()
                }
                CoordinatorBinding::Bound(_) => {
                    return Err(RuntimeInventoryForceFullError::WrongSession.into())
                }
                CoordinatorBinding::Unbound => {
                    return Err(RuntimeInventoryForceFullError::NotBound.into())
                }
                CoordinatorBinding::Closed => {
                    return Err(RuntimeInventoryForceFullError::Closed.into())
                }
            };
            if state.queued.len() >= RUNTIME_INVENTORY_MAX_CATS {
                return Err(RuntimeInventoryForceFullError::CapacityExceeded.into());
            }
            let request = Arc::new(ForceFullRequest::new(command.clone(), session, deadline));
            state.queued.push_back(Arc::clone(&request));
            request
        };
        self.wake_runner.notify_one();
        request.wait().map_err(anyhow::Error::new)
    }
}

pub(super) struct ForceFullRequest {
    command: LifecycleCommandEnvelope,
    session: SessionBinding,
    deadline: Instant,
    result: Mutex<Option<Result<RuntimeInventoryAttestation, RuntimeInventoryForceFullError>>>,
    completed: Condvar,
}

impl ForceFullRequest {
    fn new(command: LifecycleCommandEnvelope, session: SessionBinding, deadline: Instant) -> Self {
        Self {
            command,
            session,
            deadline,
            result: Mutex::new(None),
            completed: Condvar::new(),
        }
    }

    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) fn complete(
        &self,
        result: Result<RuntimeInventoryAttestation, RuntimeInventoryForceFullError>,
    ) {
        let Ok(mut slot) = self.result.lock() else {
            return;
        };
        if slot.is_none() {
            *slot = Some(result);
            self.completed.notify_all();
        }
    }

    fn wait(&self) -> Result<RuntimeInventoryAttestation, RuntimeInventoryForceFullError> {
        let mut slot = self
            .result
            .lock()
            .map_err(|_| RuntimeInventoryForceFullError::StateUnavailable)?;
        loop {
            if let Some(result) = slot.take() {
                return result;
            }
            let now = Instant::now();
            if now >= self.deadline {
                return Err(RuntimeInventoryForceFullError::DeadlineExpired);
            }
            let (next, wait) = self
                .completed
                .wait_timeout(slot, self.deadline.saturating_duration_since(now))
                .map_err(|_| RuntimeInventoryForceFullError::StateUnavailable)?;
            slot = next;
            if wait.timed_out() && slot.is_none() {
                return Err(RuntimeInventoryForceFullError::DeadlineExpired);
            }
        }
    }
}

pub(super) fn complete_post_stop_request(
    request: &ForceFullRequest,
    report: &RuntimeInventoryReport,
    attestation: &RuntimeInventoryAttestation,
) {
    request.complete(
        validate_post_stop_full(request, report, attestation).map(|()| attestation.clone()),
    );
}

fn validate_post_stop_full(
    request: &ForceFullRequest,
    report: &RuntimeInventoryReport,
    attestation: &RuntimeInventoryAttestation,
) -> Result<(), RuntimeInventoryForceFullError> {
    if report.session != request.session || attestation.session != request.session {
        return Err(RuntimeInventoryForceFullError::WrongSession);
    }
    let RuntimeInventoryBody::Full {
        inventory_epoch,
        scan_id,
        inventory_digest,
        cats,
        unattributed_artifacts,
    } = &report.inventory
    else {
        return Err(mismatch("accepted report is not Full"));
    };
    if attestation.inventory_epoch != *inventory_epoch
        || attestation.scan_id != *scan_id
        || attestation.inventory_digest != *inventory_digest
        || attestation.source_report_id != report.report_id
        || attestation.source_sequence != report.sequence
        || full_inventory_digest(report).ok().as_ref() != Some(inventory_digest)
    {
        return Err(mismatch("Full attestation does not bind the exact report"));
    }
    if !unattributed_artifacts.is_empty() {
        return Err(mismatch(
            "Full inventory contains unattributed physical artifacts",
        ));
    }
    let cat = cats
        .binary_search_by(|cat| cat.cat_id.as_str().cmp(request.command.cat_id.as_str()))
        .ok()
        .and_then(|index| cats.get(index))
        .ok_or_else(|| mismatch("Full inventory omitted the command Cat"))?;
    if cat.observed_placement != request.command.placement_identity {
        return Err(mismatch(
            "Full inventory placement differs from the command",
        ));
    }
    if cat.observed_physical_state != ObservedRuntimePhysicalState::Absent
        || cat.observed_runtime_incarnation.is_some()
    {
        return Err(mismatch("Full inventory does not prove runtime absence"));
    }
    match &cat.observed_command_journal {
        Some(ObservedCommandJournal::Executing {
            operation_id,
            command_kind,
            request_fingerprint,
            ..
        }) if operation_id == &request.command.operation_id
            && *command_kind == request.command.command_kind()
            && request_fingerprint == &request.command.request_fingerprint => {}
        _ => {
            return Err(mismatch(
                "Full inventory does not contain the exact executing command journal",
            ))
        }
    }
    Ok(())
}

fn mismatch(reason: &'static str) -> RuntimeInventoryForceFullError {
    RuntimeInventoryForceFullError::PostStopEvidenceMismatch { reason }
}

fn monotonic_deadline(
    deadline_unix_ms: UnixMillis,
) -> Result<Instant, RuntimeInventoryForceFullError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeInventoryForceFullError::DeadlineExpired)?;
    let now_ms = u64::try_from(elapsed.as_millis())
        .map_err(|_| RuntimeInventoryForceFullError::DeadlineExpired)?;
    let remaining_ms = deadline_unix_ms
        .get()
        .checked_sub(now_ms)
        .ok_or(RuntimeInventoryForceFullError::DeadlineExpired)?;
    if remaining_ms == 0 {
        return Err(RuntimeInventoryForceFullError::DeadlineExpired);
    }
    Instant::now()
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or(RuntimeInventoryForceFullError::DeadlineExpired)
}

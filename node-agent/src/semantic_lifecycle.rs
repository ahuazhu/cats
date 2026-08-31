//! Simple synchronous Control -> Node Cat lifecycle protocol.
//!
//! Idempotency is derived from the Cat identity, immutable create
//! configuration and requested target state. There is deliberately no
//! request ID, Operation projection, command poll or result-post lane here.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cats_api::runtime_reconciliation::Id;
use cats_api::runtime_reconciliation::RandomId128;
use cats_api::semantic_control::{
    noded_cat_path, NodedCatActionRequest, NodedCatConfig, NodedCatListResponse, NodedCatResponse,
    NodedCatView, NodedCreateCatRequest, NodedResultStatus, NodedServiceToken,
    SemanticErrorBody as WireErrorBody, SemanticErrorCode,
};
use cats_api::sessions::{
    ExecRequest, ExecResponse, ShellClientControl, ShellServerControl, MAX_EXEC_JSON_BODY_BYTES,
    MAX_SHELL_MESSAGE_BYTES,
};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};

use crate::guest_client::{GuestClient, GuestExecError, GuestShell, GuestShellStartError};
use crate::semantic_node_client::{NodeClientFuture, NodePlacementGate, NodeResetExecutor};
use cats_api::guest::GuestShellFrame;

pub use cats_api::semantic_control::{
    CatAction as SemanticCatAction, CatState as SemanticCatState,
    NodedCatConfig as SemanticCatConfig, NodedDiskMount as SemanticMount,
};

fn canonicalize_config(config: &mut SemanticCatConfig) {
    config.mounts.sort_by(|left, right| {
        (left.disk_id.as_str(), left.mount_path.as_str())
            .cmp(&(right.disk_id.as_str(), right.mount_path.as_str()))
    });
}

/// Cooperative cancellation installed before destroy waits for an old action.
#[derive(Debug, Clone)]
pub struct SemanticActionCancellation {
    signal: Arc<watch::Sender<bool>>,
}

impl SemanticActionCancellation {
    pub(crate) fn new() -> Self {
        let (signal, _) = watch::channel(false);
        Self {
            signal: Arc::new(signal),
        }
    }

    fn cancel(&self) {
        self.signal.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.signal.borrow()
    }

    pub async fn cancelled(&self) {
        let mut signal = self.signal.subscribe();
        if *signal.borrow_and_update() {
            return;
        }
        let _ = signal.wait_for(|cancelled| *cancelled).await;
    }
}

/// One physical effect invocation. `config` is always the full Cat config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEffectRequest {
    pub cat_id: String,
    pub action: SemanticCatAction,
    pub config: SemanticCatConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEffectError {
    pub code: SemanticErrorCode,
    pub message: String,
}

impl SemanticEffectError {
    pub fn new(code: SemanticErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub type SemanticEffectFuture =
    Pin<Box<dyn Future<Output = Result<(), SemanticEffectError>> + Send + 'static>>;

/// Exact Node-local endpoint for a Running physical Cat.
///
/// This is deliberately not a lifecycle projection. It is sampled only after
/// a successful Running effect (or while discovering the postcondition of a
/// failed leaving-Running effect), and every admitted access session retains
/// this exact incarnation and VMM peer identity for its complete lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAccessTarget {
    pub(crate) runtime_incarnation: RandomId128,
    pub(crate) vsock_socket: PathBuf,
    pub(crate) guest_port: u32,
    pub(crate) vmm_pid: u32,
}

/// Boundary implemented by FakeVmm tests and by the installed Node effects.
///
/// Effects must observe `cancellation` at bounded interruption points. A
/// destroy request does not start cleanup until the cancelled future returns.
pub trait SemanticCatEffects: Send + Sync + 'static {
    fn execute(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> SemanticEffectFuture;

    /// Stop every Node-local physical effect and remove only local artifacts.
    /// This is registration reset, not the product `destroy` action: it must
    /// never delete a RootDisk or PersistentDisk.
    fn reset_all(&self) -> SemanticEffectFuture {
        Box::pin(async { Ok(()) })
    }

    /// Return the exact physical endpoint only while this Cat is Running.
    /// Fake effects that do not expose a Guest transport may keep the default.
    fn running_access_target(
        &self,
        _cat_id: &str,
    ) -> Result<Option<RuntimeAccessTarget>, SemanticEffectError> {
        Ok(None)
    }
}

const MAX_RUNTIME_ACCESS_SESSIONS_PER_CAT: usize = 8;
const MAX_RUNTIME_ACCESS_SESSIONS_PER_NODE: usize = 256;
const PRODUCTION_RUNTIME_ACCESS_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const RUNTIME_ACCESS_DRAIN_TIMEOUT: Duration = PRODUCTION_RUNTIME_ACCESS_DRAIN_TIMEOUT;
#[cfg(test)]
const RUNTIME_ACCESS_DRAIN_TIMEOUT: Duration = Duration::from_millis(200);
const PRODUCTION_GUEST_ACCESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const GUEST_ACCESS_CONNECT_TIMEOUT: Duration = PRODUCTION_GUEST_ACCESS_CONNECT_TIMEOUT;
#[cfg(test)]
const GUEST_ACCESS_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const SHELL_CHANNEL_CAPACITY: usize = 16;
#[cfg(not(test))]
const SHELL_IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const SHELL_IO_TIMEOUT: Duration = Duration::from_millis(100);
const SHELL_CLOSE_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(250);
const PRODUCTION_SESSION_FORCE_CLOSE_GRACE: Duration = Duration::from_secs(1);
#[cfg(not(test))]
const SESSION_FORCE_CLOSE_GRACE: Duration = PRODUCTION_SESSION_FORCE_CLOSE_GRACE;
#[cfg(test)]
const SESSION_FORCE_CLOSE_GRACE: Duration = Duration::from_millis(50);
/// Guest timeout cleanup can join two one-second I/O workers. Leave a full
/// three seconds after its requested wall deadline for kill/reap and the
/// terminal response before declaring the result ambiguous.
const PRODUCTION_EXEC_GUEST_TERMINAL_MARGIN: Duration = Duration::from_secs(3);
#[cfg(not(test))]
const EXEC_GUEST_TERMINAL_MARGIN: Duration = PRODUCTION_EXEC_GUEST_TERMINAL_MARGIN;
#[cfg(test)]
const EXEC_GUEST_TERMINAL_MARGIN: Duration = Duration::from_millis(100);
const PRODUCTION_EXEC_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(not(test))]
const EXEC_WORKER_JOIN_TIMEOUT: Duration = PRODUCTION_EXEC_WORKER_JOIN_TIMEOUT;
#[cfg(test)]
const EXEC_WORKER_JOIN_TIMEOUT: Duration = Duration::from_millis(200);
/// Production's 10 s access drain plus 1 s forced-close grace. Kept explicit
/// so Control can place its T+30 s transport timeout outside Node's T+21 s
/// worst-case HTTP envelope even though unit tests shorten the live drain.
const EXEC_UNKNOWN_RETENTION_ENVELOPE: Duration = Duration::from_secs(
    PRODUCTION_RUNTIME_ACCESS_DRAIN_TIMEOUT.as_secs()
        + PRODUCTION_SESSION_FORCE_CLOSE_GRACE.as_secs(),
);

fn exec_dispatch_timeout(effective_timeout_ms: u64) -> Duration {
    GUEST_ACCESS_CONNECT_TIMEOUT
        .checked_add(Duration::from_millis(effective_timeout_ms))
        .and_then(|timeout| timeout.checked_add(EXEC_GUEST_TERMINAL_MARGIN))
        .unwrap_or(Duration::MAX)
}

fn exec_max_response_timeout(effective_timeout_ms: u64) -> Duration {
    PRODUCTION_GUEST_ACCESS_CONNECT_TIMEOUT
        .checked_add(Duration::from_millis(effective_timeout_ms))
        .and_then(|timeout| timeout.checked_add(PRODUCTION_EXEC_GUEST_TERMINAL_MARGIN))
        .and_then(|timeout| timeout.checked_add(PRODUCTION_EXEC_WORKER_JOIN_TIMEOUT))
        .and_then(|timeout| timeout.checked_add(EXEC_UNKNOWN_RETENTION_ENVELOPE))
        .unwrap_or(Duration::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RuntimeAccessCloseMode {
    Graceful,
    Force,
}

#[derive(Debug, Clone)]
struct RuntimeAccessCancellation {
    signal: Arc<watch::Sender<Option<RuntimeAccessCloseMode>>>,
}

impl RuntimeAccessCancellation {
    fn new() -> Self {
        let (signal, _) = watch::channel(None);
        Self {
            signal: Arc::new(signal),
        }
    }

    fn cancel(&self, mode: RuntimeAccessCloseMode) {
        self.signal.send_if_modified(|current| {
            if current.is_none_or(|current| current < mode) {
                *current = Some(mode);
                true
            } else {
                false
            }
        });
    }

    fn mode(&self) -> Option<RuntimeAccessCloseMode> {
        *self.signal.borrow()
    }

    fn is_cancelled(&self) -> bool {
        self.mode().is_some()
    }

    async fn cancelled(&self) -> RuntimeAccessCloseMode {
        let mut signal = self.signal.subscribe();
        if let Some(mode) = *signal.borrow_and_update() {
            return mode;
        }
        loop {
            if signal.changed().await.is_err() {
                return RuntimeAccessCloseMode::Force;
            }
            if let Some(mode) = *signal.borrow_and_update() {
                return mode;
            }
        }
    }

    async fn forced(&self) {
        let mut signal = self.signal.subscribe();
        loop {
            if *signal.borrow_and_update() == Some(RuntimeAccessCloseMode::Force) {
                return;
            }
            if signal.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Debug, Default)]
struct RuntimeAccessGateState {
    target: Option<RuntimeAccessTarget>,
    accepting: bool,
    reopen_when_drained: bool,
    /// A dispatched Guest session ended without a terminal Guest result. The
    /// physical Cat may still contain a live process, so only a strong
    /// Destroy/reset may clear this fail-closed latch.
    cleanup_unproven: bool,
    next_session: u64,
    sessions: BTreeMap<u64, RuntimeAccessCancellation>,
}

#[derive(Debug)]
struct RuntimeAccessGate {
    state: Mutex<RuntimeAccessGateState>,
    changed: watch::Sender<u64>,
}

impl RuntimeAccessGate {
    fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            state: Mutex::new(RuntimeAccessGateState::default()),
            changed,
        }
    }

    fn state(&self) -> MutexGuard<'_, RuntimeAccessGateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn open(&self, target: RuntimeAccessTarget) {
        let mut state = self.state();
        // An incarnation is never replaced underneath retained sessions. A
        // successful Run opens only after the previous lane was fully drained.
        state.target = Some(target);
        if state.sessions.is_empty() && !state.cleanup_unproven {
            state.accepting = true;
            state.reopen_when_drained = false;
        } else {
            state.reopen_when_drained = true;
        }
    }

    fn close_and_cancel(&self, mode: RuntimeAccessCloseMode) -> watch::Receiver<u64> {
        let mut state = self.state();
        state.accepting = false;
        state.reopen_when_drained = false;
        for cancellation in state.sessions.values() {
            cancellation.cancel(mode);
        }
        self.changed.subscribe()
    }

    fn acquire(
        self: &Arc<Self>,
        node_permit: OwnedSemaphorePermit,
    ) -> Result<RuntimeAccessSession, RuntimeAccessError> {
        let mut state = self.state();
        if !state.accepting {
            return Err(RuntimeAccessError::Closing);
        }
        if state.sessions.len() >= MAX_RUNTIME_ACCESS_SESSIONS_PER_CAT {
            return Err(RuntimeAccessError::LimitReached);
        }
        let target = state.target.clone().ok_or(RuntimeAccessError::Closing)?;
        state.next_session = state.next_session.wrapping_add(1);
        let session_id = state.next_session;
        let cancellation = RuntimeAccessCancellation::new();
        state.sessions.insert(session_id, cancellation.clone());
        Ok(RuntimeAccessSession {
            gate: Arc::downgrade(self),
            session_id,
            target,
            cancellation,
            cleanup_proof_required: AtomicBool::new(false),
            cleanup_proven: AtomicBool::new(false),
            _node_permit: node_permit,
        })
    }

    fn remove(&self, session_id: u64, cleanup_unproven: bool) {
        let mut state = self.state();
        state.cleanup_unproven |= cleanup_unproven;
        let removed = state.sessions.remove(&session_id).is_some();
        if removed
            && state.sessions.is_empty()
            && state.reopen_when_drained
            && !state.cleanup_unproven
        {
            // A failed leaving-Running effect may discover that the exact
            // physical runtime remains Running while its last graceful session
            // is still proving remote cleanup. Reopen only after that proof.
            state.accepting = true;
            state.reopen_when_drained = false;
        }
        drop(state);
        if removed {
            self.changed
                .send_modify(|version| *version = version.wrapping_add(1));
        }
    }

    fn mark_cleanup_unproven(&self) {
        let mut state = self.state();
        state.cleanup_unproven = true;
        state.accepting = false;
        state.reopen_when_drained = false;
    }

    fn cleanup_unproven(&self) -> bool {
        self.state().cleanup_unproven
    }

    fn clear_cleanup_unproven_after_strong_stop(&self) {
        let mut state = self.state();
        state.cleanup_unproven = false;
        state.reopen_when_drained = false;
    }

    fn active_count(&self) -> usize {
        self.state().sessions.len()
    }

    fn drain_snapshot(&self) -> (bool, bool) {
        let state = self.state();
        (state.sessions.is_empty(), state.cleanup_unproven)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeAccessError {
    NotFound,
    NotRunning,
    Closing,
    ResetRequired,
    LimitReached,
}

#[derive(Debug)]
struct RuntimeAccessSession {
    gate: Weak<RuntimeAccessGate>,
    session_id: u64,
    target: RuntimeAccessTarget,
    cancellation: RuntimeAccessCancellation,
    cleanup_proof_required: AtomicBool,
    cleanup_proven: AtomicBool,
    _node_permit: OwnedSemaphorePermit,
}

impl RuntimeAccessSession {
    fn target(&self) -> &RuntimeAccessTarget {
        &self.target
    }

    fn cancellation(&self) -> RuntimeAccessCancellation {
        self.cancellation.clone()
    }

    fn require_cleanup_proof(&self) {
        self.cleanup_proof_required.store(true, Ordering::Release);
    }

    fn prove_cleanup(&self) {
        self.cleanup_proven.store(true, Ordering::Release);
    }

    fn mark_cleanup_unproven(&self) {
        if let Some(gate) = self.gate.upgrade() {
            gate.mark_cleanup_unproven();
        }
    }
}

impl Drop for RuntimeAccessSession {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.upgrade() {
            let cleanup_unproven = self.cleanup_proof_required.load(Ordering::Acquire)
                && !self.cleanup_proven.load(Ordering::Acquire);
            gate.remove(self.session_id, cleanup_unproven);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticResponseStatus {
    Ok,
    AlreadyDone,
    Busy,
    Conflict,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCatResponse {
    pub status: SemanticResponseStatus,
    pub code: String,
    pub cat_id: String,
    pub state: Option<SemanticCatState>,
    pub active_action: Option<SemanticCatAction>,
    pub error: Option<WireErrorBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCatView {
    pub cat_id: String,
    pub workspace_id: Id,
    pub state: Option<SemanticCatState>,
    pub active_action: Option<SemanticCatAction>,
    pub cpu: u32,
    pub memory_bytes: u64,
    pub boot_image: String,
    pub mounts: Vec<SemanticMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCatList {
    pub cats: Vec<SemanticCatView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticHealth {
    pub status: &'static str,
}

#[derive(Debug, Clone)]
struct CatRecord {
    config: SemanticCatConfig,
    state: Option<SemanticCatState>,
}

#[derive(Debug, Clone)]
struct ActiveAction {
    sequence: u64,
    action: SemanticCatAction,
    cancellation: SemanticActionCancellation,
    completion: watch::Sender<Option<SemanticCatResponse>>,
}

enum EffectDecision {
    Start(u64),
    Join(watch::Receiver<Option<SemanticCatResponse>>),
    WaitForChange,
}

#[derive(Debug, Default)]
struct CatLaneState {
    record: Option<CatRecord>,
    active: Option<ActiveAction>,
    destroy_pending: bool,
    next_sequence: u64,
}

#[derive(Debug)]
struct CatLane {
    state: Mutex<CatLaneState>,
    changed: watch::Sender<u64>,
    access: Arc<RuntimeAccessGate>,
}

impl CatLane {
    fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            state: Mutex::new(CatLaneState::default()),
            changed,
            access: Arc::new(RuntimeAccessGate::new()),
        }
    }

    fn state(&self) -> MutexGuard<'_, CatLaneState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish_change(&self) {
        self.changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }
}

/// In-memory registration-period authority for synchronous Cat actions.
#[derive(Clone)]
pub struct SemanticNodeService {
    effects: Arc<dyn SemanticCatEffects>,
    cats: Arc<Mutex<BTreeMap<String, Arc<CatLane>>>>,
    placement_gate: Arc<NodePlacementGate>,
    access_limit: Arc<Semaphore>,
}

impl SemanticNodeService {
    /// Standalone-ready composition for FakeVmm and focused tests.
    /// Production composition uses [`Self::with_placement_gate`] so the
    /// registration supervisor owns the initial Closed -> Open transition.
    pub fn new(effects: Arc<dyn SemanticCatEffects>) -> Self {
        let placement_gate = Arc::new(NodePlacementGate::default());
        placement_gate.open();
        Self::with_placement_gate(effects, placement_gate)
    }

    pub fn with_placement_gate(
        effects: Arc<dyn SemanticCatEffects>,
        placement_gate: Arc<NodePlacementGate>,
    ) -> Self {
        Self {
            effects,
            cats: Arc::new(Mutex::new(BTreeMap::new())),
            placement_gate,
            access_limit: Arc::new(Semaphore::new(MAX_RUNTIME_ACCESS_SESSIONS_PER_NODE)),
        }
    }

    pub fn placement_gate(&self) -> Arc<NodePlacementGate> {
        Arc::clone(&self.placement_gate)
    }

    fn acquire_runtime_access(
        &self,
        cat_id: &str,
    ) -> Result<RuntimeAccessSession, RuntimeAccessError> {
        if !self.placement_gate.is_open() {
            return Err(RuntimeAccessError::ResetRequired);
        }
        let lane = self
            .existing_lane(cat_id)
            .ok_or(RuntimeAccessError::NotFound)?;
        // The lifecycle state lock and the access gate lock are always taken
        // in this order. Beginning a lifecycle action therefore excludes a new
        // access acquisition before the action closes and drains the gate.
        let state = lane.state();
        let running = state
            .record
            .as_ref()
            .is_some_and(|record| record.state == Some(SemanticCatState::Running));
        if !running {
            return Err(RuntimeAccessError::NotRunning);
        }
        if state.active.is_some() || state.destroy_pending {
            return Err(RuntimeAccessError::Closing);
        }
        let permit = Arc::clone(&self.access_limit)
            .try_acquire_owned()
            .map_err(|_| RuntimeAccessError::LimitReached)?;
        lane.access.acquire(permit)
    }

    fn cats(&self) -> MutexGuard<'_, BTreeMap<String, Arc<CatLane>>> {
        self.cats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn existing_lane(&self, cat_id: &str) -> Option<Arc<CatLane>> {
        self.cats().get(cat_id).cloned()
    }

    fn lane_if_open(&self, cat_id: &str) -> Result<Arc<CatLane>, SemanticCatResponse> {
        let mut cats = self.cats();
        if !self.placement_gate.is_open() {
            return Err(reset_required_response(cat_id.to_owned()));
        }
        Ok(cats
            .entry(cat_id.to_owned())
            .or_insert_with(|| Arc::new(CatLane::new()))
            .clone())
    }

    fn existing_lane_if_open(
        &self,
        cat_id: &str,
    ) -> Result<Option<Arc<CatLane>>, SemanticCatResponse> {
        let cats = self.cats();
        if !self.placement_gate.is_open() {
            return Err(reset_required_response(cat_id.to_owned()));
        }
        Ok(cats.get(cat_id).cloned())
    }

    pub async fn create(
        &self,
        cat_id: String,
        mut config: SemanticCatConfig,
    ) -> SemanticCatResponse {
        if parse_cat_id(&cat_id).is_none() {
            return response_error(
                cat_id,
                SemanticResponseStatus::Conflict,
                "invalid_request",
                "cat_id must be a valid cat_ resource ID",
                None,
                None,
            );
        }
        if let Err(message) = config.validate() {
            return response_error(
                cat_id,
                SemanticResponseStatus::Conflict,
                "invalid_request",
                message.to_string(),
                None,
                None,
            );
        }
        canonicalize_config(&mut config);
        let lane = match self.lane_if_open(&cat_id) {
            Ok(lane) => lane,
            Err(response) => return response,
        };
        loop {
            let decision = {
                let mut state = lane.state();
                if let Some(record) = &state.record {
                    if record.state == Some(SemanticCatState::Destroyed) {
                        return response_error(
                            cat_id,
                            SemanticResponseStatus::Conflict,
                            "cat_destroyed",
                            "the cat_id was destroyed during this registration period",
                            record.state,
                            state.active.as_ref().map(|active| active.action),
                        );
                    }
                    if record.config != config {
                        return response_error(
                            cat_id,
                            SemanticResponseStatus::Conflict,
                            "cat_configuration_conflict",
                            "cat_id already exists with a different configuration",
                            record.state,
                            state.active.as_ref().map(|active| active.action),
                        );
                    }
                }
                if state.destroy_pending {
                    return busy_response(&cat_id, &state, "destroy is pending");
                }
                if let Some(active) = &state.active {
                    if active.action == SemanticCatAction::Create {
                        EffectDecision::Join(active.completion.subscribe())
                    } else {
                        return busy_response(&cat_id, &state, "another action is active");
                    }
                } else if let Some(record) = &state.record {
                    if record.state == Some(SemanticCatState::Running) {
                        return already_response(cat_id, "already_running", record.state, None);
                    }
                    return response_error(
                        cat_id,
                        SemanticResponseStatus::Conflict,
                        "invalid_state",
                        "create cannot replay after the Cat left its created Running state",
                        record.state,
                        None,
                    );
                } else {
                    let sequence = begin_action(&mut state, SemanticCatAction::Create);
                    state.record = Some(CatRecord {
                        config: config.clone(),
                        state: None,
                    });
                    EffectDecision::Start(sequence)
                }
            };
            match decision {
                EffectDecision::Start(sequence) => {
                    return self
                        .run_effect(&cat_id, lane, sequence, SemanticCatAction::Create)
                        .await;
                }
                EffectDecision::Join(completion) => {
                    let response = wait_for_effect_completion(&cat_id, &lane, completion).await;
                    if response.status == SemanticResponseStatus::Failed {
                        return response;
                    }
                }
                EffectDecision::WaitForChange => {
                    unreachable!("create never cancels another action")
                }
            }
        }
    }

    pub async fn action(
        &self,
        cat_id: String,
        action: SemanticCatAction,
        mut requested_config: Option<SemanticCatConfig>,
    ) -> SemanticCatResponse {
        if parse_cat_id(&cat_id).is_none() {
            return response_error(
                cat_id,
                SemanticResponseStatus::Conflict,
                "invalid_request",
                "cat_id must be a valid cat_ resource ID",
                None,
                None,
            );
        }
        if matches!(
            action,
            SemanticCatAction::Create | SemanticCatAction::Destroy
        ) {
            return response_error(
                cat_id,
                SemanticResponseStatus::Conflict,
                "invalid_action",
                "use the create or destroy endpoint for this action",
                None,
                None,
            );
        }
        match (action, &mut requested_config) {
            (SemanticCatAction::Run, Some(config)) => {
                if let Err(message) = config.validate() {
                    return response_error(
                        cat_id,
                        SemanticResponseStatus::Conflict,
                        "invalid_request",
                        message.to_string(),
                        None,
                        None,
                    );
                }
                canonicalize_config(config);
            }
            (SemanticCatAction::Run, None) => {
                return response_error(
                    cat_id,
                    SemanticResponseStatus::Conflict,
                    "invalid_request",
                    "run requires the complete current Cat config",
                    None,
                    None,
                );
            }
            (_, Some(_)) => {
                return response_error(
                    cat_id,
                    SemanticResponseStatus::Conflict,
                    "invalid_request",
                    "only run accepts a Cat config",
                    None,
                    None,
                );
            }
            (_, None) => {}
        }
        let lane = if action == SemanticCatAction::Run {
            match self.lane_if_open(&cat_id) {
                Ok(lane) => lane,
                Err(response) => return response,
            }
        } else {
            let Some(lane) = (match self.existing_lane_if_open(&cat_id) {
                Ok(lane) => lane,
                Err(response) => return response,
            }) else {
                return not_found_response(cat_id);
            };
            lane
        };
        if action == SemanticCatAction::Run {
            let mut state = lane.state();
            if state.record.is_none() {
                state.record = Some(CatRecord {
                    config: requested_config
                        .clone()
                        .expect("Run configuration was validated above"),
                    // A recovery target has no Host-local instance. Treat it
                    // as physically Cold so the ordinary Run transition can
                    // create the first VMM on this Node.
                    state: Some(SemanticCatState::Cold),
                });
            }
        }
        loop {
            let sequence = {
                let mut state = lane.state();
                let Some(record) = &state.record else {
                    return not_found_response(cat_id);
                };
                if record.state == Some(SemanticCatState::Destroyed) {
                    return response_error(
                        cat_id,
                        SemanticResponseStatus::Conflict,
                        "cat_destroyed",
                        "the cat_id was destroyed during this registration period",
                        record.state,
                        state.active.as_ref().map(|active| active.action),
                    );
                }
                if state.destroy_pending {
                    return busy_response(&cat_id, &state, "destroy is pending");
                }
                if let Some(active) = &state.active {
                    if active.action == action {
                        if requested_config
                            .as_ref()
                            .is_some_and(|config| config != &record.config)
                        {
                            return response_error(
                                cat_id,
                                SemanticResponseStatus::Conflict,
                                "cat_configuration_conflict",
                                "the active run uses a different configuration",
                                record.state,
                                Some(active.action),
                            );
                        }
                        EffectDecision::Join(active.completion.subscribe())
                    } else {
                        return busy_response(&cat_id, &state, "another action is active");
                    }
                } else if Some(action.target_state()) == record.state {
                    if requested_config
                        .as_ref()
                        .is_some_and(|config| config != &record.config)
                    {
                        return response_error(
                            cat_id,
                            SemanticResponseStatus::Conflict,
                            "cat_configuration_conflict",
                            "a Running Cat cannot be replayed with a different configuration",
                            record.state,
                            None,
                        );
                    }
                    return already_response(cat_id, already_code(action), record.state, None);
                } else if !legal_transition(record.state, action) {
                    return response_error(
                        cat_id,
                        SemanticResponseStatus::Conflict,
                        "invalid_state",
                        "action is not valid from the current state",
                        record.state,
                        None,
                    );
                } else {
                    if let Some(config) = &requested_config {
                        state
                            .record
                            .as_mut()
                            .expect("the transition was validated against this Cat record")
                            .config = config.clone();
                    }
                    EffectDecision::Start(begin_action(&mut state, action))
                }
            };
            match sequence {
                EffectDecision::Start(sequence) => {
                    return self.run_effect(&cat_id, lane, sequence, action).await;
                }
                EffectDecision::Join(completion) => {
                    let response = wait_for_effect_completion(&cat_id, &lane, completion).await;
                    if response.status == SemanticResponseStatus::Failed {
                        return response;
                    }
                }
                EffectDecision::WaitForChange => {
                    unreachable!("action never cancels another action")
                }
            }
        }
    }

    pub async fn destroy(&self, cat_id: String) -> SemanticCatResponse {
        if !self.placement_gate.is_open() {
            return reset_required_response(cat_id);
        }
        self.destroy_for_reset(cat_id).await
    }

    async fn destroy_for_reset(&self, cat_id: String) -> SemanticCatResponse {
        if parse_cat_id(&cat_id).is_none() {
            return response_error(
                cat_id,
                SemanticResponseStatus::Conflict,
                "invalid_request",
                "cat_id must be a valid cat_ resource ID",
                None,
                None,
            );
        }
        let Some(lane) = self.existing_lane(&cat_id) else {
            return not_found_response(cat_id);
        };
        loop {
            let mut changed = lane.changed.subscribe();
            let sequence = {
                let mut state = lane.state();
                let Some(record) = &state.record else {
                    return not_found_response(cat_id);
                };
                if record.state == Some(SemanticCatState::Destroyed) {
                    return already_response(cat_id, "already_destroyed", record.state, None);
                }
                state.destroy_pending = true;
                if let Some(active) = &state.active {
                    if active.action == SemanticCatAction::Destroy {
                        EffectDecision::Join(active.completion.subscribe())
                    } else {
                        lane.access.close_and_cancel(RuntimeAccessCloseMode::Force);
                        active.cancellation.cancel();
                        EffectDecision::WaitForChange
                    }
                } else {
                    EffectDecision::Start(begin_action(&mut state, SemanticCatAction::Destroy))
                }
            };
            match sequence {
                EffectDecision::Start(sequence) => {
                    return self
                        .run_effect(&cat_id, lane, sequence, SemanticCatAction::Destroy)
                        .await;
                }
                EffectDecision::Join(completion) => {
                    let response = wait_for_effect_completion(&cat_id, &lane, completion).await;
                    if response.status == SemanticResponseStatus::Failed {
                        return response;
                    }
                }
                EffectDecision::WaitForChange => {
                    let _ = changed.changed().await;
                }
            }
        }
    }

    /// Close admission, cancel and join every active Cat action, then ask the
    /// installed effects owner to stop all local processes and artifacts.
    /// Product disks are never deleted by this reset.
    pub async fn reset_all(&self) -> anyhow::Result<()> {
        self.placement_gate.close();
        let lanes = self.cats().values().cloned().collect::<Vec<_>>();
        for lane in &lanes {
            lane.access.close_and_cancel(RuntimeAccessCloseMode::Force);
        }
        let drain_deadline = Instant::now() + RUNTIME_ACCESS_DRAIN_TIMEOUT;
        loop {
            if lanes.iter().all(|lane| lane.access.active_count() == 0) {
                break;
            }
            if Instant::now() >= drain_deadline {
                // Physical reset below closes the exact VMM sockets as a final
                // backstop. Do not leave a registration reset wedged forever
                // behind an uncooperative client bridge.
                tracing::warn!(
                    active_sessions = lanes
                        .iter()
                        .map(|lane| lane.access.active_count())
                        .sum::<usize>(),
                    "runtime access sessions did not drain before Node reset"
                );
                break;
            }
            tokio::task::yield_now().await;
        }
        loop {
            let mut active = false;
            for lane in &lanes {
                let state = lane.state();
                if let Some(action) = &state.active {
                    action.cancellation.cancel();
                    active = true;
                }
            }
            if !active {
                break;
            }
            tokio::task::yield_now().await;
        }
        self.effects
            .reset_all()
            .await
            .map_err(|error| anyhow::anyhow!(error.message))?;
        self.cats().clear();
        Ok(())
    }

    async fn run_effect(
        &self,
        cat_id: &str,
        lane: Arc<CatLane>,
        sequence: u64,
        action: SemanticCatAction,
    ) -> SemanticCatResponse {
        let (config, cancellation, completion_sender, completion) = {
            let state = lane.state();
            let record = state
                .record
                .as_ref()
                .expect("action always has a Cat record");
            let active = state
                .active
                .as_ref()
                .expect("started action remains active");
            (
                record.config.clone(),
                active.cancellation.clone(),
                active.completion.clone(),
                active.completion.subscribe(),
            )
        };
        let effects = Arc::clone(&self.effects);
        let effect_cat_id = cat_id.to_owned();
        let effect_lane = Arc::clone(&lane);
        tokio::spawn(async move {
            let result = if matches!(
                action,
                SemanticCatAction::Suspend
                    | SemanticCatAction::Warm
                    | SemanticCatAction::Cold
                    | SemanticCatAction::Destroy
            ) {
                let close_mode = if action == SemanticCatAction::Destroy {
                    RuntimeAccessCloseMode::Force
                } else {
                    RuntimeAccessCloseMode::Graceful
                };
                match close_and_drain_runtime_access(&effect_lane, close_mode, &cancellation).await
                {
                    Ok(()) => {
                        run_physical_effect(
                            Arc::clone(&effects),
                            effect_cat_id.clone(),
                            action,
                            config,
                            cancellation,
                        )
                        .await
                    }
                    Err(error) if action == SemanticCatAction::Destroy => {
                        tracing::warn!(
                            cat_id = effect_cat_id,
                            error = %error.message,
                            "runtime access did not drain before strong Destroy; continuing with physical teardown"
                        );
                        run_physical_effect(
                            Arc::clone(&effects),
                            effect_cat_id.clone(),
                            action,
                            config,
                            cancellation,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            } else {
                run_physical_effect(
                    Arc::clone(&effects),
                    effect_cat_id.clone(),
                    action,
                    config,
                    cancellation,
                )
                .await
            };

            let mut running_target = None;
            let result = if result.is_ok()
                && matches!(action, SemanticCatAction::Create | SemanticCatAction::Run)
            {
                match effects.running_access_target(&effect_cat_id) {
                    Ok(target) => {
                        running_target = target;
                        result
                    }
                    Err(error) => Err(error),
                }
            } else {
                if result.is_err() {
                    // Postcondition discovery permits a safely drained access
                    // lane to retain its exact Running target after a failed
                    // leaving-Running effect. The semantic failure state still
                    // prevents new public acquisition until Control resolves it.
                    running_target = effects.running_access_target(&effect_cat_id).ok().flatten();
                }
                result
            };
            let response = complete_effect(
                &effect_cat_id,
                &effect_lane,
                sequence,
                action,
                result,
                running_target,
            );
            completion_sender.send_replace(Some(response));
            effect_lane.publish_change();
        });

        wait_for_effect_completion(cat_id, &lane, completion).await
    }

    pub fn get(&self, cat_id: &str) -> Option<SemanticCatView> {
        let lane = self.existing_lane(cat_id)?;
        let result = view(cat_id, &lane.state());
        result
    }

    pub fn list(&self) -> SemanticCatList {
        let lanes = self
            .cats()
            .iter()
            .map(|(cat_id, lane)| (cat_id.clone(), Arc::clone(lane)))
            .collect::<Vec<_>>();
        SemanticCatList {
            cats: lanes
                .into_iter()
                .filter_map(|(cat_id, lane)| view(&cat_id, &lane.state()))
                .collect(),
        }
    }
}

async fn run_physical_effect(
    effects: Arc<dyn SemanticCatEffects>,
    cat_id: String,
    action: SemanticCatAction,
    config: SemanticCatConfig,
    cancellation: SemanticActionCancellation,
) -> Result<(), SemanticEffectError> {
    let effect = effects.execute(
        SemanticEffectRequest {
            cat_id,
            action,
            config,
        },
        cancellation,
    );
    tokio::spawn(effect).await.unwrap_or_else(|error| {
        Err(SemanticEffectError::new(
            SemanticErrorCode::InternalError,
            format!("physical effect task failed: {error}"),
        ))
    })
}

async fn close_and_drain_runtime_access(
    lane: &CatLane,
    mode: RuntimeAccessCloseMode,
    action_cancellation: &SemanticActionCancellation,
) -> Result<(), SemanticEffectError> {
    let mut changed = lane.access.close_and_cancel(mode);
    if mode == RuntimeAccessCloseMode::Graceful && lane.access.cleanup_unproven() {
        return Err(SemanticEffectError::new(
            SemanticErrorCode::NodeUnavailable,
            "a prior runtime session ended without Guest cleanup proof; strong Destroy or Node reset is required",
        ));
    }
    let deadline = Instant::now() + RUNTIME_ACCESS_DRAIN_TIMEOUT;
    loop {
        if action_cancellation.is_cancelled() {
            return Err(SemanticEffectError::new(
                SemanticErrorCode::ActionCancelled,
                "lifecycle action was preempted while draining runtime access",
            ));
        }
        // The last session records an unproven cleanup and removes itself
        // under this same gate mutex. An ordinary drain may therefore never
        // observe "empty" separately from the fail-closed latch.
        let (sessions_empty, cleanup_unproven) = lane.access.drain_snapshot();
        if mode == RuntimeAccessCloseMode::Graceful && cleanup_unproven {
            return Err(SemanticEffectError::new(
                SemanticErrorCode::NodeUnavailable,
                "a runtime session ended without Guest cleanup proof; strong Destroy or Node reset is required",
            ));
        }
        if sessions_empty {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::select! {
            _ = action_cancellation.cancelled() => {
                return Err(SemanticEffectError::new(
                    SemanticErrorCode::ActionCancelled,
                    "lifecycle action was preempted while draining runtime access",
                ));
            }
            changed_result = tokio::time::timeout(remaining, changed.changed()) => {
                if changed_result.is_err() {
                    break;
                }
            }
        }
    }
    Err(SemanticEffectError::new(
        SemanticErrorCode::Timeout,
        "runtime access sessions did not drain before the lifecycle deadline",
    ))
}

async fn wait_for_effect_completion(
    cat_id: &str,
    lane: &CatLane,
    mut completion: watch::Receiver<Option<SemanticCatResponse>>,
) -> SemanticCatResponse {
    loop {
        if let Some(response) = completion.borrow_and_update().clone() {
            return response;
        }
        if completion.changed().await.is_err() {
            let (state, active_action) = {
                let state = lane.state();
                (
                    state.record.as_ref().and_then(|record| record.state),
                    state.active.as_ref().map(|active| active.action),
                )
            };
            return response_error(
                cat_id.to_owned(),
                SemanticResponseStatus::Failed,
                "internal_error",
                "physical effect completion channel closed",
                state,
                active_action,
            );
        }
    }
}

impl NodeResetExecutor for SemanticNodeService {
    fn reset_all_cats(&self) -> NodeClientFuture<()> {
        let service = self.clone();
        Box::pin(async move { service.reset_all().await })
    }
}

fn begin_action(state: &mut CatLaneState, action: SemanticCatAction) -> u64 {
    state.next_sequence = state.next_sequence.wrapping_add(1);
    let sequence = state.next_sequence;
    let (completion, _) = watch::channel(None);
    state.active = Some(ActiveAction {
        sequence,
        action,
        cancellation: SemanticActionCancellation::new(),
        completion,
    });
    sequence
}

fn complete_effect(
    cat_id: &str,
    lane: &CatLane,
    sequence: u64,
    action: SemanticCatAction,
    result: Result<(), SemanticEffectError>,
    running_target: Option<RuntimeAccessTarget>,
) -> SemanticCatResponse {
    let mut state = lane.state();
    let is_current = state
        .active
        .as_ref()
        .is_some_and(|active| active.sequence == sequence && active.action == action);
    if !is_current {
        return response_error(
            cat_id.to_owned(),
            SemanticResponseStatus::Failed,
            "internal_error",
            "action completion did not match the active Cat action",
            state.record.as_ref().and_then(|record| record.state),
            state.active.as_ref().map(|active| active.action),
        );
    }

    if action == SemanticCatAction::Destroy && result.is_ok() {
        // A successful strong Destroy is the only per-Cat operation that can
        // discharge an earlier ambiguous session cleanup. Reset removes the
        // complete registration-period gate after its own strong stop.
        lane.access.clear_cleanup_unproven_after_strong_stop();
    }
    if let Some(target) = running_target {
        lane.access.open(target);
    } else {
        lane.access.close_and_cancel(RuntimeAccessCloseMode::Force);
    }
    state.active = None;
    let cancelled_for_destroy = state.destroy_pending && action != SemanticCatAction::Destroy;
    let response = match result {
        Ok(()) if cancelled_for_destroy => response_error(
            cat_id.to_owned(),
            SemanticResponseStatus::Failed,
            "action_cancelled",
            "action was cancelled by destroy",
            state.record.as_ref().and_then(|record| record.state),
            None,
        ),
        Ok(()) => {
            let target = action.target_state();
            if let Some(record) = &mut state.record {
                record.state = Some(target);
            }
            if action == SemanticCatAction::Destroy {
                state.destroy_pending = false;
            }
            SemanticCatResponse {
                status: SemanticResponseStatus::Ok,
                code: success_code(action).to_owned(),
                cat_id: cat_id.to_owned(),
                state: Some(target),
                active_action: None,
                error: None,
            }
        }
        Err(_error) if cancelled_for_destroy => response_error(
            cat_id.to_owned(),
            SemanticResponseStatus::Failed,
            "action_cancelled",
            "action was cancelled by destroy",
            state.record.as_ref().and_then(|record| record.state),
            None,
        ),
        Err(error) => {
            if let Some(record) = &mut state.record {
                record.state = Some(SemanticCatState::Failure);
            }
            if action == SemanticCatAction::Destroy {
                state.destroy_pending = false;
            }
            SemanticCatResponse {
                status: SemanticResponseStatus::Failed,
                code: error_code_name(error.code).to_owned(),
                cat_id: cat_id.to_owned(),
                state: Some(SemanticCatState::Failure),
                active_action: None,
                error: Some(WireErrorBody {
                    code: error.code,
                    message: error.message,
                }),
            }
        }
    };
    response
}

fn parse_cat_id(value: &str) -> Option<Id> {
    let id = Id::new(value.to_owned())?;
    noded_cat_path(&id).ok()?;
    Some(id)
}

fn legal_transition(from: Option<SemanticCatState>, action: SemanticCatAction) -> bool {
    action.allowed_from(from)
}

fn view(cat_id: &str, state: &CatLaneState) -> Option<SemanticCatView> {
    let record = state.record.as_ref()?;
    Some(SemanticCatView {
        cat_id: cat_id.to_owned(),
        workspace_id: record.config.workspace_id.clone(),
        state: record.state,
        active_action: state.active.as_ref().map(|active| active.action),
        cpu: record.config.cpu,
        memory_bytes: record.config.memory_bytes,
        boot_image: record.config.boot_image.clone(),
        mounts: record.config.mounts.clone(),
    })
}

fn busy_response(cat_id: &str, state: &CatLaneState, message: &str) -> SemanticCatResponse {
    response_error(
        cat_id.to_owned(),
        SemanticResponseStatus::Busy,
        "busy",
        message,
        state.record.as_ref().and_then(|record| record.state),
        state.active.as_ref().map(|active| active.action),
    )
}

fn not_found_response(cat_id: String) -> SemanticCatResponse {
    response_error(
        cat_id,
        SemanticResponseStatus::Failed,
        "cat_not_found",
        "cat_id does not exist on this Node",
        None,
        None,
    )
}

fn reset_required_response(cat_id: String) -> SemanticCatResponse {
    response_error(
        cat_id,
        SemanticResponseStatus::Conflict,
        "node_reset_required",
        "Node registration is not ready for Cat actions",
        None,
        None,
    )
}

fn response_error(
    cat_id: String,
    status: SemanticResponseStatus,
    code: impl Into<String>,
    message: impl Into<String>,
    state: Option<SemanticCatState>,
    active_action: Option<SemanticCatAction>,
) -> SemanticCatResponse {
    let code = code.into();
    let wire_code = error_code_from_name(&code);
    SemanticCatResponse {
        status,
        code: code.clone(),
        cat_id,
        state,
        active_action,
        error: Some(WireErrorBody {
            code: wire_code,
            message: message.into(),
        }),
    }
}

fn error_code_from_name(code: &str) -> SemanticErrorCode {
    match code {
        "unauthorized" => SemanticErrorCode::Unauthorized,
        "invalid_request" | "invalid_action" => SemanticErrorCode::InvalidRequest,
        "cat_not_found" => SemanticErrorCode::CatNotFound,
        "cat_configuration_conflict" => SemanticErrorCode::CatConfigurationConflict,
        "cat_destroyed" => SemanticErrorCode::CatDestroyed,
        "invalid_state" => SemanticErrorCode::InvalidState,
        "busy" => SemanticErrorCode::Busy,
        "node_reset_required" => SemanticErrorCode::NodeResetRequired,
        "action_cancelled" => SemanticErrorCode::ActionCancelled,
        _ => SemanticErrorCode::InternalError,
    }
}

fn error_code_name(code: SemanticErrorCode) -> &'static str {
    match code {
        SemanticErrorCode::Unauthorized => "unauthorized",
        SemanticErrorCode::InvalidRequest => "invalid_request",
        SemanticErrorCode::CatNotFound => "cat_not_found",
        SemanticErrorCode::CatConfigurationConflict => "cat_configuration_conflict",
        SemanticErrorCode::CatDestroyed => "cat_destroyed",
        SemanticErrorCode::InvalidState => "invalid_state",
        SemanticErrorCode::Busy => "busy",
        SemanticErrorCode::NodeUnavailable => "node_unavailable",
        SemanticErrorCode::NodeResetRequired => "node_reset_required",
        SemanticErrorCode::NodeIdentityConflict => "node_identity_conflict",
        SemanticErrorCode::DiskNotFound => "disk_not_found",
        SemanticErrorCode::SnapshotNotFound => "snapshot_not_found",
        SemanticErrorCode::DiskSizeConflict => "disk_size_conflict",
        SemanticErrorCode::DiskDeleted => "disk_deleted",
        SemanticErrorCode::DiskInUse => "disk_in_use",
        SemanticErrorCode::DiskAlreadyAttached => "disk_already_attached",
        SemanticErrorCode::DiskBindingConflict => "disk_binding_conflict",
        SemanticErrorCode::SnapshotConfigurationConflict => "snapshot_configuration_conflict",
        SemanticErrorCode::SnapshotInUse => "snapshot_in_use",
        SemanticErrorCode::DiskOwned => "disk_owned",
        SemanticErrorCode::HeadConflict => "head_conflict",
        SemanticErrorCode::DiskNotInitialized => "disk_not_initialized",
        SemanticErrorCode::GenerationExhausted => "generation_exhausted",
        SemanticErrorCode::SnapshotCorrupt => "snapshot_corrupt",
        SemanticErrorCode::StorageUnavailable => "storage_unavailable",
        SemanticErrorCode::MountPathConflict => "mount_path_conflict",
        SemanticErrorCode::CatMustBeCold => "cat_must_be_cold",
        SemanticErrorCode::GuestStartFailed => "guest_start_failed",
        SemanticErrorCode::GuestSuspendFailed => "guest_suspend_failed",
        SemanticErrorCode::GuestWarmFailed => "guest_warm_failed",
        SemanticErrorCode::GuestColdFailed => "guest_cold_failed",
        SemanticErrorCode::DestroyFailed => "destroy_failed",
        SemanticErrorCode::ActionCancelled => "action_cancelled",
        SemanticErrorCode::Timeout => "timeout",
        SemanticErrorCode::InternalError => "internal_error",
    }
}

fn already_response(
    cat_id: String,
    code: &'static str,
    state: Option<SemanticCatState>,
    active_action: Option<SemanticCatAction>,
) -> SemanticCatResponse {
    SemanticCatResponse {
        status: SemanticResponseStatus::AlreadyDone,
        code: code.to_owned(),
        cat_id,
        state,
        active_action,
        error: None,
    }
}

fn success_code(action: SemanticCatAction) -> &'static str {
    match action {
        SemanticCatAction::Create | SemanticCatAction::Run => "cat_running",
        SemanticCatAction::Suspend => "cat_suspended",
        SemanticCatAction::Warm => "cat_warm",
        SemanticCatAction::Cold => "cat_cold",
        SemanticCatAction::Destroy => "cat_destroyed",
    }
}

fn already_code(action: SemanticCatAction) -> &'static str {
    match action {
        SemanticCatAction::Create | SemanticCatAction::Run => "already_running",
        SemanticCatAction::Suspend => "already_suspended",
        SemanticCatAction::Warm => "already_warm",
        SemanticCatAction::Cold => "already_cold",
        SemanticCatAction::Destroy => "already_destroyed",
    }
}

#[derive(Clone)]
struct SemanticHttpState {
    service: SemanticNodeService,
    bearer_token: NodedServiceToken,
}

/// Build the authenticated synchronous Node API router.
pub fn semantic_node_router(
    service: SemanticNodeService,
    bearer_token: NodedServiceToken,
) -> Router {
    let state = SemanticHttpState {
        service,
        bearer_token,
    };
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/cats", get(list_cats))
        .route(
            "/v1/cats/{cat_id}",
            get(get_cat).put(create_cat).delete(destroy_cat),
        )
        .route("/v1/cats/{cat_id}/actions/run", post(run_cat))
        .route("/v1/cats/{cat_id}/actions/suspend", post(suspend_cat))
        .route("/v1/cats/{cat_id}/actions/warm", post(warm_cat))
        .route("/v1/cats/{cat_id}/actions/cold", post(cold_cat))
        .route(
            "/v1/cats/{cat_id}/exec",
            post(exec_cat).layer(DefaultBodyLimit::max(MAX_EXEC_JSON_BODY_BYTES)),
        )
        .route("/v1/cats/{cat_id}/shell", get(shell_cat))
        .with_state(state)
}

fn authorized(headers: &HeaderMap, expected: &NodedServiceToken) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    value
        .to_str()
        .ok()
        .and_then(NodedServiceToken::parse_authorization)
        .is_some_and(|token| &token == expected)
}

fn unauthorized() -> impl IntoResponse {
    wire_error_response(
        SemanticErrorCode::Unauthorized,
        "missing or invalid noded service token",
    )
}

async fn health(State(state): State<SemanticHttpState>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    if !state.service.placement_gate().is_open() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not_ready" })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

async fn list_cats(
    State(state): State<SemanticHttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    let cats = state
        .service
        .list()
        .cats
        .into_iter()
        .map(wire_view)
        .collect::<Result<Vec<_>, _>>();
    match cats {
        Ok(cats) => (StatusCode::OK, Json(NodedCatListResponse { cats })).into_response(),
        Err(error) => wire_error_response(
            SemanticErrorCode::InternalError,
            format!("invalid Node Cat inventory: {error}"),
        ),
    }
}

async fn get_cat(
    State(state): State<SemanticHttpState>,
    headers: HeaderMap,
    Path(cat_id): Path<String>,
) -> impl IntoResponse {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    match state.service.get(&cat_id) {
        Some(cat) => match wire_view(cat) {
            Ok(cat) => (StatusCode::OK, Json(cat)).into_response(),
            Err(error) => wire_error_response(
                SemanticErrorCode::InternalError,
                format!("invalid Node Cat state: {error}"),
            ),
        },
        None => protocol_response(not_found_response(cat_id)),
    }
}

async fn create_cat(
    State(state): State<SemanticHttpState>,
    headers: HeaderMap,
    Path(cat_id): Path<String>,
    request: Result<Json<NodedCreateCatRequest>, JsonRejection>,
) -> impl IntoResponse {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    let Json(config) = match request {
        Ok(request) => request,
        Err(error) => {
            return wire_error_response(SemanticErrorCode::InvalidRequest, error.to_string())
        }
    };
    protocol_response(state.service.create(cat_id, config).await)
}

async fn destroy_cat(
    State(state): State<SemanticHttpState>,
    headers: HeaderMap,
    Path(cat_id): Path<String>,
) -> impl IntoResponse {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    protocol_response(state.service.destroy(cat_id).await)
}

macro_rules! action_handler {
    ($name:ident, $action:expr) => {
        async fn $name(
            State(state): State<SemanticHttpState>,
            headers: HeaderMap,
            Path(cat_id): Path<String>,
            request: Result<Json<NodedCatActionRequest>, JsonRejection>,
        ) -> impl IntoResponse {
            if !authorized(&headers, &state.bearer_token) {
                return unauthorized().into_response();
            }
            let Json(request) = match request {
                Ok(request) => request,
                Err(error) => {
                    return wire_error_response(SemanticErrorCode::InvalidRequest, error.to_string())
                }
            };
            if let Err(error) = request.validate_for($action) {
                return wire_error_response(SemanticErrorCode::InvalidRequest, error.to_string());
            }
            protocol_response(state.service.action(cat_id, $action, request.config).await)
        }
    };
}

action_handler!(run_cat, SemanticCatAction::Run);
action_handler!(suspend_cat, SemanticCatAction::Suspend);
action_handler!(warm_cat, SemanticCatAction::Warm);
action_handler!(cold_cat, SemanticCatAction::Cold);

async fn exec_cat(
    State(state): State<SemanticHttpState>,
    headers: HeaderMap,
    Path(cat_id): Path<String>,
    request: Result<Json<ExecRequest>, JsonRejection>,
) -> axum::response::Response {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return wire_error_response(SemanticErrorCode::InvalidRequest, error.to_string())
        }
    };
    if let Err(error) = request.validate() {
        return wire_error_response(SemanticErrorCode::InvalidRequest, error.to_string());
    }
    // Reserve the complete exact-peer connect/mux budget before the Guest's
    // requested execution window. Once this dispatch deadline fires, the
    // bounded worker join below consumes the final response-cleanup budget.
    let host_deadline = exec_dispatch_timeout(request.effective_timeout_ms());
    debug_assert!(
        host_deadline <= exec_max_response_timeout(request.effective_timeout_ms()),
        "Exec dispatch deadline must fit the published Node response envelope"
    );
    let session = match state.service.acquire_runtime_access(&cat_id) {
        Ok(session) => session,
        Err(error) => return runtime_access_error_response(error),
    };
    let target = session.target().clone();
    let cancellation = session.cancellation();
    let session = Arc::new(session);
    let worker_session = Arc::clone(&session);
    let (handle_sender, mut handle_receiver) = oneshot::channel();
    let mut worker =
        tokio::task::spawn_blocking(move || -> Result<ExecResponse, GuestExecError> {
            // Keep admission until the exact Guest connection and its command have
            // both terminated, even if the HTTP request future is dropped.
            let _session = Arc::clone(&worker_session);
            let mut guest = GuestClient::connect_hybrid_vsock_long_running_exact_peer(
                &target.vsock_socket,
                target.guest_port,
                GUEST_ACCESS_CONNECT_TIMEOUT,
                target.vmm_pid,
            )
            .map_err(GuestExecError::Other)?;
            let cancellation_handle = guest.cancellation_handle().map_err(GuestExecError::Other)?;
            handle_sender.send(cancellation_handle).map_err(|_| {
                GuestExecError::Other(anyhow::anyhow!(
                    "exec caller disconnected during Guest connect"
                ))
            })?;
            worker_session.require_cleanup_proof();
            let result = guest.exec_with_options_classified(
                request.command,
                request.timeout_ms,
                request.env,
                request.stdin,
            );
            if match &result {
                Ok(_) => true,
                Err(error) => guest_exec_error_proves_remote_cleanup(error),
            } {
                worker_session.prove_cleanup();
            }
            result.map(|(exit_code, stdout, stderr)| ExecResponse {
                exit_code,
                stdout,
                stderr,
            })
        });

    let deadline = tokio::time::sleep(host_deadline);
    tokio::pin!(deadline);

    let cancellation_handle = tokio::select! {
        handle = &mut handle_receiver => match handle {
            Ok(handle) => handle,
            Err(_) => return exec_worker_response(worker.await),
        },
        mode = cancellation.cancelled() => {
            let handle = await_late_exec_handle(&mut handle_receiver).await;
            close_exec_worker(handle.as_ref(), &cancellation, mode, &mut worker).await;
            return wire_error_response(
                SemanticErrorCode::Busy,
                "exec stopped because Cat runtime access is closing",
            );
        }
        () = &mut deadline => {
            let handle = await_late_exec_handle(&mut handle_receiver).await;
            if let Some(handle) = &handle {
                handle.cancel();
            }
            let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut worker).await;
            return exec_result_unknown_response("exec exceeded the Node response deadline");
        }
    };

    tokio::select! {
        result = &mut worker => {
            if !exec_worker_proves_remote_cleanup(&result) {
                retain_guard_after_unknown_exec_result(&session, &cancellation).await;
            }
            exec_worker_response(result)
        },
        mode = cancellation.cancelled() => {
            close_exec_worker(
                Some(&cancellation_handle),
                &cancellation,
                mode,
                &mut worker,
            ).await;
            wire_error_response(
                SemanticErrorCode::Busy,
                "exec stopped because Cat runtime access is closing",
            )
        }
        () = &mut deadline => {
            cancellation_handle.cancel();
            let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut worker).await;
            exec_result_unknown_response("exec exceeded the Node response deadline")
        }
    }
}

async fn await_late_exec_handle(
    receiver: &mut oneshot::Receiver<crate::guest_client::GuestConnectionCancellation>,
) -> Option<crate::guest_client::GuestConnectionCancellation> {
    tokio::time::timeout(
        GUEST_ACCESS_CONNECT_TIMEOUT + SESSION_FORCE_CLOSE_GRACE,
        receiver,
    )
    .await
    .ok()
    .and_then(Result::ok)
}

async fn close_exec_worker(
    handle: Option<&crate::guest_client::GuestConnectionCancellation>,
    cancellation: &RuntimeAccessCancellation,
    mode: RuntimeAccessCloseMode,
    worker: &mut tokio::task::JoinHandle<Result<ExecResponse, GuestExecError>>,
) {
    let Some(handle) = handle else {
        let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, worker).await;
        return;
    };
    if mode == RuntimeAccessCloseMode::Force {
        handle.cancel();
        let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, worker).await;
        return;
    }

    handle.request_remote_close();
    let graceful_deadline = tokio::time::sleep(
        RUNTIME_ACCESS_DRAIN_TIMEOUT
            .checked_add(SESSION_FORCE_CLOSE_GRACE)
            .unwrap_or(Duration::MAX),
    );
    tokio::pin!(graceful_deadline);
    let mut worker_finished = false;
    let mut remote_cleanup_proven = false;
    tokio::select! {
        result = &mut *worker => {
            worker_finished = true;
            remote_cleanup_proven = exec_worker_proves_remote_cleanup(&result);
        },
        () = cancellation.forced() => {},
        () = &mut graceful_deadline => {},
    }
    if remote_cleanup_proven {
        return;
    }
    if worker_finished {
        // EOF or a local bridge failure is not proof that Guest finished
        // kill/reap. Retain the outer guard until the ordinary lifecycle drain
        // has failed, unless Destroy upgrades this session to Force first.
        tokio::select! {
            () = cancellation.forced() => {},
            () = &mut graceful_deadline => {},
        }
    }
    // The ordinary lifecycle drain has already failed before this backstop.
    // A later Destroy may also upgrade the signal to Force immediately.
    handle.cancel();
    if !worker_finished {
        let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut *worker).await;
    }
}

fn exec_worker_proves_remote_cleanup(
    result: &Result<Result<ExecResponse, GuestExecError>, tokio::task::JoinError>,
) -> bool {
    matches!(
        result,
        Ok(Ok(_))
            | Ok(Err(GuestExecError::Timeout { .. }))
            | Ok(Err(GuestExecError::Cancelled { .. }))
            | Ok(Err(GuestExecError::RemoteError { .. }))
    )
}

fn guest_exec_error_proves_remote_cleanup(error: &GuestExecError) -> bool {
    matches!(
        error,
        GuestExecError::Timeout { .. }
            | GuestExecError::Cancelled { .. }
            | GuestExecError::RemoteError { .. }
    )
}

async fn retain_guard_after_unknown_exec_result(
    session: &RuntimeAccessSession,
    cancellation: &RuntimeAccessCancellation,
) {
    session.mark_cleanup_unproven();
    tokio::select! {
        () = cancellation.forced() => {},
        () = tokio::time::sleep(
            RUNTIME_ACCESS_DRAIN_TIMEOUT
                .checked_add(SESSION_FORCE_CLOSE_GRACE)
                .unwrap_or(Duration::MAX),
        ) => {},
    }
}

fn exec_result_unknown_response(message: impl Into<String>) -> axum::response::Response {
    wire_error_response(
        SemanticErrorCode::NodeUnavailable,
        format!(
            "{}; command result is unknown and must not be retried automatically",
            message.into()
        ),
    )
}

fn exec_worker_response(
    result: Result<Result<ExecResponse, GuestExecError>, tokio::task::JoinError>,
) -> axum::response::Response {
    match result {
        Ok(Ok(response)) => match response.validate() {
            Ok(()) => (StatusCode::OK, Json(response)).into_response(),
            Err(error) => guest_access_error_response(format!(
                "Guest exec response violated the public bound: {error}"
            )),
        },
        Ok(Err(GuestExecError::Timeout { message })) => {
            wire_error_response(SemanticErrorCode::Timeout, message)
        }
        Ok(Err(GuestExecError::Cancelled { message })) => exec_result_unknown_response(message),
        Ok(Err(GuestExecError::RemoteError { message })) => guest_access_error_response(message),
        Ok(Err(GuestExecError::Other(error))) => {
            guest_access_error_response(format!("Guest exec failed: {error:#}"))
        }
        Err(error) => guest_access_error_response(format!("Guest exec task failed: {error}")),
    }
}

#[derive(Debug, Deserialize)]
struct ShellQuery {
    #[serde(default = "default_shell_rows")]
    rows: u16,
    #[serde(default = "default_shell_cols")]
    cols: u16,
}

const fn default_shell_rows() -> u16 {
    24
}

const fn default_shell_cols() -> u16 {
    80
}

async fn shell_cat(
    State(state): State<SemanticHttpState>,
    headers: HeaderMap,
    Path(cat_id): Path<String>,
    Query(query): Query<ShellQuery>,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    if !authorized(&headers, &state.bearer_token) {
        return unauthorized().into_response();
    }
    let dimensions = ShellClientControl::Resize {
        rows: query.rows,
        cols: query.cols,
    };
    if let Err(error) = dimensions.validate() {
        return wire_error_response(SemanticErrorCode::InvalidRequest, error.to_string());
    }
    let session = match state.service.acquire_runtime_access(&cat_id) {
        Ok(session) => session,
        Err(error) => return runtime_access_error_response(error),
    };
    let target = session.target().clone();
    let cancellation = session.cancellation();
    let connected = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        // Retain admission while preparing. noded does not return HTTP 101
        // until both the exact VMM handshake and Guest ShellReady succeed.
        let guest = GuestClient::connect_hybrid_vsock_shell_exact_peer(
            &target.vsock_socket,
            target.guest_port,
            GUEST_ACCESS_CONNECT_TIMEOUT,
            target.vmm_pid,
        )?;
        // From the first Shell request onward, only Guest Exit proves that the
        // PTY process group was killed/reaped. Handler loss and transport EOF
        // must leave the per-Cat fail-closed latch set.
        session.require_cleanup_proof();
        let shell = match guest.start_shell(query.rows, query.cols) {
            Ok(shell) => shell,
            Err(GuestShellStartError::RemoteTerminal { message }) => {
                session.prove_cleanup();
                return Err(anyhow::anyhow!("guest error: {message}"));
            }
            Err(GuestShellStartError::Ambiguous(error)) => return Err(error),
        };
        let cancellation_handle = shell.cancellation_handle()?;
        Ok((session, shell, cancellation_handle))
    })
    .await;
    let (session, shell, cancellation_handle) = match connected {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => {
            return guest_access_error_response(format!("Guest shell failed: {error:#}"))
        }
        Err(error) => {
            return guest_access_error_response(format!("Guest shell task failed: {error}"))
        }
    };
    if let Some(mode) = cancellation.mode() {
        close_prepared_shell(
            session,
            shell,
            cancellation_handle,
            cancellation.clone(),
            mode,
        )
        .await;
        return wire_error_response(
            SemanticErrorCode::Busy,
            "shell stopped because Cat runtime access is closing",
        );
    }
    upgrade
        .max_frame_size(MAX_SHELL_MESSAGE_BYTES)
        .max_message_size(MAX_SHELL_MESSAGE_BYTES)
        .on_upgrade(move |socket| serve_shell(socket, session, shell, cancellation_handle))
}

async fn close_prepared_shell(
    session: RuntimeAccessSession,
    shell: GuestShell,
    cancellation_handle: crate::guest_client::GuestConnectionCancellation,
    cancellation: RuntimeAccessCancellation,
    mode: RuntimeAccessCloseMode,
) {
    let session = Arc::new(session);
    let reader = match shell.try_clone() {
        Ok(reader) => reader,
        Err(_) => {
            if mode == RuntimeAccessCloseMode::Graceful {
                tokio::select! {
                    () = cancellation.forced() => {},
                    () = tokio::time::sleep(
                        RUNTIME_ACCESS_DRAIN_TIMEOUT + SESSION_FORCE_CLOSE_GRACE,
                    ) => {},
                }
            }
            cancellation_handle.cancel();
            drop(session);
            return;
        }
    };
    let (guest_sender, _guest_receiver) = mpsc::channel(SHELL_CHANNEL_CAPACITY);
    let (remote_terminal, mut remote_terminal_receiver) = watch::channel(false);
    let reader_guard = Arc::clone(&session);
    let mut reader_worker = tokio::task::spawn_blocking(move || {
        read_guest_shell(reader, guest_sender, reader_guard, remote_terminal)
    });
    let writer_guard = Arc::clone(&session);
    let mut writer_worker = tokio::task::spawn_blocking(move || {
        let _guard = writer_guard;
        let mut shell = shell;
        let _ = shell.send(&GuestShellFrame::Close);
    });
    wait_for_remote_shell_cleanup(&cancellation, mode, &mut remote_terminal_receiver).await;
    cancellation_handle.cancel();
    let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut reader_worker).await;
    let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut writer_worker).await;
    drop(session);
}

async fn serve_shell(
    mut socket: WebSocket,
    session: RuntimeAccessSession,
    shell: GuestShell,
    cancellation_handle: crate::guest_client::GuestConnectionCancellation,
) {
    let cancellation = session.cancellation();
    let session = Arc::new(session);
    let reader = match shell.try_clone() {
        Ok(reader) => reader,
        Err(error) => {
            send_shell_control(
                &mut socket,
                &cancellation,
                ShellServerControl::Error {
                    message: format!("clone Guest shell reader: {error:#}"),
                },
            )
            .await;
            cancellation_handle.cancel();
            drop(session);
            let _ = tokio::time::timeout(
                SHELL_CLOSE_ENQUEUE_TIMEOUT,
                socket.send(Message::Close(None)),
            )
            .await;
            return;
        }
    };
    let (guest_sender, mut guest_receiver) = mpsc::channel(SHELL_CHANNEL_CAPACITY);
    let (remote_terminal, mut remote_terminal_receiver) = watch::channel(false);
    let reader_guard = Arc::clone(&session);
    let mut reader_worker = tokio::task::spawn_blocking(move || {
        read_guest_shell(reader, guest_sender, reader_guard, remote_terminal)
    });
    let (writer_sender, writer_receiver) = mpsc::channel(SHELL_CHANNEL_CAPACITY);
    let writer_guard = Arc::clone(&session);
    let mut writer_worker = tokio::task::spawn_blocking(move || {
        let _guard = writer_guard;
        write_guest_shell(shell, writer_receiver)
    });

    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    if !send_guest_shell_frame(
                        &writer_sender,
                        &cancellation,
                        GuestShellFrame::Input { data: data.to_vec() },
                    ).await {
                        break;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    let control = serde_json::from_str::<ShellClientControl>(text.as_str());
                    match control {
                        Ok(control) if control.validate().is_ok() => {
                            let frame = match control {
                                ShellClientControl::Resize { rows, cols } => {
                                    GuestShellFrame::Resize { rows, cols }
                                }
                                ShellClientControl::Close => break,
                            };
                            if !send_guest_shell_frame(&writer_sender, &cancellation, frame).await {
                                break;
                            }
                        }
                        Ok(_) | Err(_) => {
                            send_shell_control(
                                &mut socket,
                                &cancellation,
                                ShellServerControl::Error {
                                    message: "invalid shell control frame".to_owned(),
                                },
                            ).await;
                            break;
                        }
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    if !send_shell_message(&mut socket, &cancellation, Message::Pong(data)).await {
                        break;
                    }
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            },
            outgoing = guest_receiver.recv() => match outgoing {
                Some(Ok(GuestShellFrame::Output { data })) => {
                    if !send_shell_message(
                        &mut socket,
                        &cancellation,
                        Message::Binary(data.into()),
                    ).await {
                        break;
                    }
                }
                Some(Ok(GuestShellFrame::Exit { exit_code })) => {
                    send_shell_control(
                        &mut socket,
                        &cancellation,
                        ShellServerControl::Exit { exit_code },
                    ).await;
                    break;
                }
                Some(Ok(_)) => {
                    send_shell_control(
                        &mut socket,
                        &cancellation,
                        ShellServerControl::Error {
                            message: "Guest sent an invalid shell frame".to_owned(),
                        },
                    ).await;
                    break;
                }
                Some(Err(message)) => {
                    send_shell_control(
                        &mut socket,
                        &cancellation,
                        ShellServerControl::Error { message },
                    ).await;
                    break;
                }
                None => break,
            },
            _mode = cancellation.cancelled() => break,
        }
    }

    if cancellation.mode().is_none() {
        let _ = send_shell_message(&mut socket, &cancellation, Message::Close(None)).await;
        cancellation.cancel(RuntimeAccessCloseMode::Graceful);
    }
    // Close enqueue cannot itself be held forever by a full bounded channel.
    let _ = tokio::time::timeout(
        SHELL_CLOSE_ENQUEUE_TIMEOUT,
        writer_sender.send(GuestShellFrame::Close),
    )
    .await;
    let mode = cancellation
        .mode()
        .unwrap_or(RuntimeAccessCloseMode::Graceful);
    wait_for_remote_shell_cleanup(&cancellation, mode, &mut remote_terminal_receiver).await;
    cancellation_handle.cancel();
    drop(writer_sender);
    let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut reader_worker).await;
    let _ = tokio::time::timeout(EXEC_WORKER_JOIN_TIMEOUT, &mut writer_worker).await;
    // The outer guard is intentionally last: reader, writer and coordinator
    // jointly retain admission until every worker has reached terminal exit.
    drop(session);
}

fn read_guest_shell(
    mut shell: GuestShell,
    sender: mpsc::Sender<Result<GuestShellFrame, String>>,
    session: Arc<RuntimeAccessSession>,
    remote_terminal: watch::Sender<bool>,
) {
    let cancellation = session.cancellation();
    let mut forwarding = true;
    loop {
        match shell.recv() {
            Ok(frame) => {
                let terminal = matches!(frame, GuestShellFrame::Exit { .. });
                if terminal {
                    session.prove_cleanup();
                    remote_terminal.send_replace(true);
                }
                if forwarding && !send_guest_shell_event(&sender, &cancellation, Ok(frame)) {
                    // A full channel, oversized downstream message or slow WS
                    // sink closes forwarding, not the proof reader. Ask the
                    // coordinator to send Guest Close, discard further Output,
                    // and keep reading until exact Exit or transport EOF.
                    cancellation.cancel(RuntimeAccessCloseMode::Graceful);
                    forwarding = false;
                }
                if terminal {
                    return;
                }
                if cancellation.is_cancelled() {
                    forwarding = false;
                }
            }
            Err(error) => {
                let _ = send_guest_shell_event(
                    &sender,
                    &cancellation,
                    Err(format!(
                        "node unavailable: Guest shell bridge closed: {error:#}"
                    )),
                );
                session.mark_cleanup_unproven();
                return;
            }
        }
    }
}

fn write_guest_shell(mut shell: GuestShell, mut receiver: mpsc::Receiver<GuestShellFrame>) {
    while let Some(frame) = receiver.blocking_recv() {
        let terminal = matches!(frame, GuestShellFrame::Close);
        if shell.send(&frame).is_err() || terminal {
            return;
        }
    }
}

fn send_guest_shell_event(
    sender: &mpsc::Sender<Result<GuestShellFrame, String>>,
    cancellation: &RuntimeAccessCancellation,
    mut event: Result<GuestShellFrame, String>,
) -> bool {
    let deadline = Instant::now() + SHELL_IO_TIMEOUT;
    loop {
        match sender.try_send(event) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
            Err(mpsc::error::TrySendError::Full(returned)) => {
                event = returned;
                if cancellation.is_cancelled() || Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

async fn bounded_shell_io<F, T>(cancellation: &RuntimeAccessCancellation, future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _mode = cancellation.cancelled() => None,
        result = tokio::time::timeout(SHELL_IO_TIMEOUT, future) => result.ok(),
    }
}

async fn send_shell_message(
    socket: &mut WebSocket,
    cancellation: &RuntimeAccessCancellation,
    message: Message,
) -> bool {
    if !shell_websocket_message_is_bounded(cancellation, &message) {
        // The Guest protocol has a larger JSON-frame cap than the session
        // WebSocket contract. A buggy or version-skewed Guest must not make
        // noded emit an oversized internal frame. Graceful cancellation asks
        // the Guest to close/reap; absent Exit, the session drop latches the
        // Cat cleanup as unproven.
        cancellation.cancel(RuntimeAccessCloseMode::Graceful);
        return false;
    }
    matches!(
        bounded_shell_io(cancellation, socket.send(message)).await,
        Some(Ok(()))
    )
}

fn shell_websocket_message_is_bounded(
    cancellation: &RuntimeAccessCancellation,
    message: &Message,
) -> bool {
    if shell_websocket_payload_len(message) <= MAX_SHELL_MESSAGE_BYTES {
        return true;
    }
    cancellation.cancel(RuntimeAccessCloseMode::Graceful);
    false
}

fn shell_websocket_payload_len(message: &Message) -> usize {
    match message {
        Message::Text(text) => text.len(),
        Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
        Message::Close(Some(frame)) => 2usize.saturating_add(frame.reason.len()),
        Message::Close(None) => 0,
    }
}

async fn send_guest_shell_frame(
    sender: &mpsc::Sender<GuestShellFrame>,
    cancellation: &RuntimeAccessCancellation,
    frame: GuestShellFrame,
) -> bool {
    matches!(
        bounded_shell_io(cancellation, sender.send(frame)).await,
        Some(Ok(()))
    )
}

async fn send_shell_control(
    socket: &mut WebSocket,
    cancellation: &RuntimeAccessCancellation,
    control: ShellServerControl,
) -> bool {
    if let Ok(json) = serde_json::to_string(&control) {
        return send_shell_message(socket, cancellation, Message::Text(json.into())).await;
    }
    false
}

async fn wait_for_remote_shell_cleanup(
    cancellation: &RuntimeAccessCancellation,
    mode: RuntimeAccessCloseMode,
    remote_terminal: &mut watch::Receiver<bool>,
) {
    if *remote_terminal.borrow_and_update() {
        return;
    }
    let wait = async {
        while remote_terminal.changed().await.is_ok() {
            if *remote_terminal.borrow_and_update() {
                return;
            }
        }
    };
    let deadline = if mode == RuntimeAccessCloseMode::Force {
        SHELL_CLOSE_ENQUEUE_TIMEOUT
    } else {
        RUNTIME_ACCESS_DRAIN_TIMEOUT
            .checked_add(SESSION_FORCE_CLOSE_GRACE)
            .unwrap_or(Duration::MAX)
    };
    if mode == RuntimeAccessCloseMode::Force {
        let _ = tokio::time::timeout(deadline, wait).await;
    } else {
        tokio::select! {
            () = wait => {},
            () = cancellation.forced() => {},
            () = tokio::time::sleep(deadline) => {},
        }
    }
}

fn runtime_access_error_response(error: RuntimeAccessError) -> axum::response::Response {
    match error {
        RuntimeAccessError::NotFound => wire_error_response(
            SemanticErrorCode::CatNotFound,
            "cat_id does not exist on this Node",
        ),
        RuntimeAccessError::NotRunning => wire_error_response(
            SemanticErrorCode::InvalidState,
            "Cat must be Running for exec or shell",
        ),
        RuntimeAccessError::Closing => wire_error_response(
            SemanticErrorCode::Busy,
            "Cat runtime access is closing for a lifecycle action",
        ),
        RuntimeAccessError::ResetRequired => wire_error_response(
            SemanticErrorCode::NodeResetRequired,
            "Node registration is not ready for runtime access",
        ),
        RuntimeAccessError::LimitReached => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(WireErrorBody {
                code: SemanticErrorCode::Busy,
                message: "runtime access session limit reached".to_owned(),
            }),
        )
            .into_response(),
    }
}

fn guest_access_error_response(message: impl Into<String>) -> axum::response::Response {
    wire_error_response(SemanticErrorCode::NodeUnavailable, message)
}

fn protocol_response(response: SemanticCatResponse) -> axum::response::Response {
    let SemanticCatResponse {
        status,
        cat_id,
        state,
        error,
        ..
    } = response;
    match status {
        SemanticResponseStatus::Ok | SemanticResponseStatus::AlreadyDone => terminal_wire_response(
            cat_id,
            state,
            if status == SemanticResponseStatus::Ok {
                NodedResultStatus::Ok
            } else {
                NodedResultStatus::AlreadyDone
            },
            None,
        ),
        SemanticResponseStatus::Failed if state == Some(SemanticCatState::Failure) => {
            terminal_wire_response(cat_id, state, NodedResultStatus::Failed, error)
        }
        SemanticResponseStatus::Busy
        | SemanticResponseStatus::Conflict
        | SemanticResponseStatus::Failed => {
            let error = error.unwrap_or(WireErrorBody {
                code: SemanticErrorCode::InternalError,
                message: "semantic Node action failed without an error".to_owned(),
            });
            wire_error_response(error.code, error.message)
        }
    }
}

fn terminal_wire_response(
    cat_id: String,
    state: Option<SemanticCatState>,
    status: NodedResultStatus,
    error: Option<WireErrorBody>,
) -> axum::response::Response {
    let Some(cat_id) = parse_cat_id(&cat_id) else {
        return wire_error_response(
            SemanticErrorCode::InternalError,
            "Node produced an invalid cat_id",
        );
    };
    let Some(state) = state else {
        return wire_error_response(
            SemanticErrorCode::InternalError,
            "Node action returned without a terminal Cat state",
        );
    };
    let response = NodedCatResponse {
        status,
        cat_id,
        state,
        error,
    };
    debug_assert!(response.validate().is_ok());
    (StatusCode::OK, Json(response)).into_response()
}

fn wire_view(view: SemanticCatView) -> Result<NodedCatView, &'static str> {
    let cat_id = parse_cat_id(&view.cat_id).ok_or("invalid cat_id")?;
    let result = NodedCatView {
        cat_id,
        state: view.state,
        active_action: view.active_action,
        config: NodedCatConfig {
            workspace_id: view.workspace_id,
            cpu: view.cpu,
            memory_bytes: view.memory_bytes,
            boot_image: view.boot_image,
            mounts: view.mounts,
        },
    };
    result.validate().map_err(|_| "invalid Cat view")?;
    Ok(result)
}

fn wire_error_response(
    code: SemanticErrorCode,
    message: impl Into<String>,
) -> axum::response::Response {
    let status =
        StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(WireErrorBody {
            code,
            message: message.into(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    #[derive(Default)]
    struct RecordingEffects {
        calls: Mutex<Vec<SemanticCatAction>>,
        creates: AtomicUsize,
        block_create: AtomicBool,
        fail_create: AtomicBool,
        create_delay_ms: AtomicUsize,
        create_started: Notify,
    }

    impl RecordingEffects {
        fn actions(&self) -> Vec<SemanticCatAction> {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl SemanticCatEffects for RecordingEffects {
        fn execute(
            &self,
            request: SemanticEffectRequest,
            cancellation: SemanticActionCancellation,
        ) -> SemanticEffectFuture {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.action);
            if request.action == SemanticCatAction::Create {
                self.creates.fetch_add(1, Ordering::SeqCst);
                self.create_started.notify_one();
            }
            let blocked = self.block_create.load(Ordering::SeqCst)
                && request.action == SemanticCatAction::Create;
            let fail_create = self.fail_create.load(Ordering::SeqCst)
                && request.action == SemanticCatAction::Create;
            let delay_ms = self.create_delay_ms.load(Ordering::SeqCst);
            Box::pin(async move {
                if blocked {
                    cancellation.cancelled().await;
                    return Err(SemanticEffectError::new(
                        SemanticErrorCode::ActionCancelled,
                        "cancelled by destroy",
                    ));
                }
                if delay_ms > 0 && request.action == SemanticCatAction::Create {
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(delay_ms as u64)) => {}
                        () = cancellation.cancelled() => {
                            return Err(SemanticEffectError::new(
                                SemanticErrorCode::ActionCancelled,
                                "cancelled by destroy",
                            ));
                        }
                    }
                }
                if fail_create {
                    return Err(SemanticEffectError::new(
                        SemanticErrorCode::InternalError,
                        "original physical failure",
                    ));
                }
                Ok(())
            })
        }

        fn running_access_target(
            &self,
            _cat_id: &str,
        ) -> Result<Option<RuntimeAccessTarget>, SemanticEffectError> {
            Ok(Some(RuntimeAccessTarget {
                runtime_incarnation: RandomId128::new("a".repeat(32))
                    .expect("valid runtime incarnation"),
                vsock_socket: PathBuf::from("/test/fake-vsock.sock"),
                guest_port: 5_000,
                vmm_pid: 42,
            }))
        }
    }

    fn config() -> SemanticCatConfig {
        SemanticCatConfig {
            workspace_id: Id::new("ws_01").expect("valid workspace ID"),
            cpu: 2,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            boot_image: "ubuntu-24.04".to_owned(),
            mounts: vec![SemanticMount {
                disk_id: Id::new("disk_01").expect("valid disk ID"),
                volume_id: Id::new("vol_01").expect("valid volume ID"),
                filesystem_uuid: cats_api::runtime_reconciliation::RandomId128::new("1".repeat(32))
                    .expect("valid filesystem UUID"),
                format: cats_api::semantic_control::PersistentDiskFormat::Ext4,
                mount_path: cats_api::semantic_control::PersistentMountPath::new("/data")
                    .expect("valid mount path"),
            }],
        }
    }

    #[tokio::test]
    async fn create_and_target_state_replays_do_not_repeat_effects() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());

        let created = service.create("cat_01".to_owned(), config()).await;
        assert_eq!(created.status, SemanticResponseStatus::Ok);
        let replay = service.create("cat_01".to_owned(), config()).await;
        assert_eq!(replay.status, SemanticResponseStatus::AlreadyDone);

        let already_running = service
            .action("cat_01".to_owned(), SemanticCatAction::Run, Some(config()))
            .await;
        assert_eq!(already_running.status, SemanticResponseStatus::AlreadyDone);
        assert_eq!(effects.actions(), vec![SemanticCatAction::Create]);
    }

    #[tokio::test]
    async fn concurrent_same_create_waits_and_replays_one_effect() {
        let effects = Arc::new(RecordingEffects::default());
        effects.create_delay_ms.store(30, Ordering::SeqCst);
        let service = SemanticNodeService::new(effects.clone());
        let first_service = service.clone();
        let first =
            tokio::spawn(async move { first_service.create("cat_01".to_owned(), config()).await });
        tokio::time::timeout(Duration::from_secs(1), effects.create_started.notified())
            .await
            .expect("first create starts");
        let second = service.create("cat_01".to_owned(), config()).await;
        let first = first.await.expect("first create joins");

        assert_eq!(first.status, SemanticResponseStatus::Ok);
        assert_eq!(second.status, SemanticResponseStatus::AlreadyDone);
        assert_eq!(effects.creates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_same_create_returns_the_original_failure_to_every_waiter() {
        let effects = Arc::new(RecordingEffects::default());
        effects.create_delay_ms.store(30, Ordering::SeqCst);
        effects.fail_create.store(true, Ordering::SeqCst);
        let service = SemanticNodeService::new(effects.clone());
        let first_service = service.clone();
        let first =
            tokio::spawn(async move { first_service.create("cat_01".to_owned(), config()).await });
        tokio::time::timeout(Duration::from_secs(1), effects.create_started.notified())
            .await
            .expect("first create starts");

        let second = service.create("cat_01".to_owned(), config()).await;
        let first = first.await.expect("first create joins");

        for response in [first, second] {
            assert_eq!(response.status, SemanticResponseStatus::Failed);
            let error = response.error.expect("failure includes an error");
            assert_eq!(error.code, SemanticErrorCode::InternalError);
            assert_eq!(error.message, "original physical failure");
        }
        assert_eq!(effects.creates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropped_create_waiter_does_not_abandon_the_node_owned_effect() {
        let effects = Arc::new(RecordingEffects::default());
        effects.create_delay_ms.store(30, Ordering::SeqCst);
        let service = SemanticNodeService::new(effects.clone());
        let first_service = service.clone();
        let first =
            tokio::spawn(async move { first_service.create("cat_01".to_owned(), config()).await });
        tokio::time::timeout(Duration::from_secs(1), effects.create_started.notified())
            .await
            .expect("create effect starts");

        first.abort();
        let _ = first.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let cat = service.get("cat_01").expect("Cat marker remains");
                if cat.state == Some(SemanticCatState::Running) && cat.active_action.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Node-owned effect reaches its terminal state");

        let replay = service.create("cat_01".to_owned(), config()).await;
        assert_eq!(replay.status, SemanticResponseStatus::AlreadyDone);
        assert_eq!(effects.creates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_cats_execute_in_parallel() {
        let effects = Arc::new(RecordingEffects::default());
        effects.block_create.store(true, Ordering::SeqCst);
        let service = SemanticNodeService::new(effects.clone());
        let first_service = service.clone();
        let second_service = service.clone();
        let first =
            tokio::spawn(async move { first_service.create("cat_01".to_owned(), config()).await });
        let second =
            tokio::spawn(async move { second_service.create("cat_02".to_owned(), config()).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            while effects.creates.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both Cat effects start without waiting for one another");

        service
            .reset_all()
            .await
            .expect("reset releases both creates");
        assert_eq!(first.await.expect("first joins").code, "action_cancelled");
        assert_eq!(second.await.expect("second joins").code, "action_cancelled");
    }

    #[tokio::test]
    async fn different_action_is_busy_while_create_is_running() {
        let effects = Arc::new(RecordingEffects::default());
        effects.block_create.store(true, Ordering::SeqCst);
        let service = SemanticNodeService::new(effects.clone());
        let create_service = service.clone();
        let create =
            tokio::spawn(async move { create_service.create("cat_01".to_owned(), config()).await });
        tokio::time::timeout(Duration::from_secs(1), effects.create_started.notified())
            .await
            .expect("create effect starts");

        let busy = service
            .action("cat_01".to_owned(), SemanticCatAction::Cold, None)
            .await;
        assert_eq!(busy.status, SemanticResponseStatus::Busy);

        let destroyed = service.destroy("cat_01".to_owned()).await;
        assert_eq!(destroyed.status, SemanticResponseStatus::Ok);
        let cancelled = create.await.expect("create task joins");
        assert_eq!(cancelled.code, "action_cancelled");
        assert_eq!(
            effects.actions(),
            vec![SemanticCatAction::Create, SemanticCatAction::Destroy]
        );
    }

    #[tokio::test]
    async fn destroyed_marker_rejects_old_cat_id_create() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;
        service.destroy("cat_01".to_owned()).await;

        let replay = service.create("cat_01".to_owned(), config()).await;
        assert_eq!(replay.code, "cat_destroyed");
        assert_eq!(replay.status, SemanticResponseStatus::Conflict);
        assert_eq!(
            service.get("cat_01").expect("destroyed marker").state,
            Some(SemanticCatState::Destroyed)
        );
    }

    #[tokio::test]
    async fn closed_registration_gate_prevents_physical_effects() {
        let effects = Arc::new(RecordingEffects::default());
        let gate = Arc::new(NodePlacementGate::default());
        let service = SemanticNodeService::with_placement_gate(effects.clone(), gate);

        let response = service.create("cat_01".to_owned(), config()).await;
        assert_eq!(response.code, "node_reset_required");
        assert!(effects.actions().is_empty());
    }

    #[tokio::test]
    async fn reset_cancels_active_cats_and_starts_a_new_marker_period() {
        let effects = Arc::new(RecordingEffects::default());
        effects.block_create.store(true, Ordering::SeqCst);
        let service = SemanticNodeService::new(effects.clone());
        let create_service = service.clone();
        let create =
            tokio::spawn(async move { create_service.create("cat_01".to_owned(), config()).await });
        tokio::time::timeout(Duration::from_secs(1), effects.create_started.notified())
            .await
            .expect("create starts");

        service.reset_all().await.expect("reset completes");
        assert_eq!(create.await.expect("create joins").code, "action_cancelled");
        assert!(service.list().cats.is_empty());
        assert!(!service.placement_gate().is_open());

        service.placement_gate().open();
        effects.block_create.store(false, Ordering::SeqCst);
        let recreated = service.create("cat_01".to_owned(), config()).await;
        assert_eq!(recreated.status, SemanticResponseStatus::Ok);
    }

    #[tokio::test]
    async fn run_installs_the_complete_latest_cold_config() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;
        service
            .action("cat_01".to_owned(), SemanticCatAction::Cold, None)
            .await;

        let mut latest = config();
        latest.mounts.push(SemanticMount {
            disk_id: Id::new("disk_02").expect("valid disk ID"),
            volume_id: Id::new("vol_02").expect("valid volume ID"),
            filesystem_uuid: cats_api::runtime_reconciliation::RandomId128::new("2".repeat(32))
                .expect("valid filesystem UUID"),
            format: cats_api::semantic_control::PersistentDiskFormat::Ext4,
            mount_path: cats_api::semantic_control::PersistentMountPath::new("/cache")
                .expect("valid mount path"),
        });
        let running = service
            .action(
                "cat_01".to_owned(),
                SemanticCatAction::Run,
                Some(latest.clone()),
            )
            .await;
        assert_eq!(running.status, SemanticResponseStatus::Ok);
        assert_eq!(
            service.get("cat_01").expect("running Cat").mounts,
            latest.mounts
        );
    }

    #[tokio::test]
    async fn leaving_running_closes_cancels_and_drains_runtime_access() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        assert_eq!(
            service.create("cat_01".to_owned(), config()).await.status,
            SemanticResponseStatus::Ok
        );
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        assert_eq!(
            session.target().runtime_incarnation,
            RandomId128::new("a".repeat(32)).expect("valid runtime incarnation")
        );
        let cancelled = session.cancellation();

        let suspend_service = service.clone();
        let suspend = tokio::spawn(async move {
            suspend_service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), cancelled.cancelled())
            .await
            .expect("active runtime access is cancelled");
        assert_eq!(
            service.acquire_runtime_access("cat_01").unwrap_err(),
            RuntimeAccessError::Closing
        );
        assert!(
            !suspend.is_finished(),
            "lifecycle waits for the access guard"
        );
        drop(session);

        let response = tokio::time::timeout(Duration::from_secs(1), suspend)
            .await
            .expect("suspend drains")
            .expect("suspend task joins");
        assert_eq!(response.status, SemanticResponseStatus::Ok);
        assert_eq!(
            service.acquire_runtime_access("cat_01").unwrap_err(),
            RuntimeAccessError::NotRunning
        );
        assert_eq!(
            effects.actions(),
            vec![SemanticCatAction::Create, SemanticCatAction::Suspend]
        );
    }

    #[tokio::test]
    async fn non_destructive_lifecycle_never_runs_before_stubborn_session_proof() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        let cancellation = session.cancellation();
        let suspend_service = service.clone();
        let suspend = tokio::spawn(async move {
            suspend_service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
                .await
                .expect("session is asked to close"),
            RuntimeAccessCloseMode::Graceful
        );
        let response = tokio::time::timeout(Duration::from_secs(1), suspend)
            .await
            .expect("stubborn session reaches drain deadline")
            .expect("suspend task joins");
        assert_eq!(response.status, SemanticResponseStatus::Failed);
        assert_eq!(
            effects.actions(),
            vec![SemanticCatAction::Create],
            "physical Suspend must not run without remote cleanup proof"
        );
        drop(session);
    }

    #[tokio::test]
    async fn strong_destroy_continues_after_stubborn_session_drain_timeout() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        let cancellation = session.cancellation();
        let destroy_service = service.clone();
        let destroy =
            tokio::spawn(async move { destroy_service.destroy("cat_01".to_owned()).await });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
                .await
                .expect("session is force closed"),
            RuntimeAccessCloseMode::Force
        );
        let response = tokio::time::timeout(Duration::from_secs(1), destroy)
            .await
            .expect("strong Destroy does not remain blocked")
            .expect("destroy task joins");
        assert_eq!(response.status, SemanticResponseStatus::Ok);
        assert_eq!(
            effects.actions(),
            vec![SemanticCatAction::Create, SemanticCatAction::Destroy]
        );
        drop(session);
    }

    #[tokio::test]
    async fn destroy_upgrades_an_in_progress_graceful_drain_to_force() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        let cancellation = session.cancellation();
        let suspend_service = service.clone();
        let suspend = tokio::spawn(async move {
            suspend_service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
                .await
                .expect("Suspend starts graceful drain"),
            RuntimeAccessCloseMode::Graceful
        );
        let destroy_service = service.clone();
        let destroy =
            tokio::spawn(async move { destroy_service.destroy("cat_01".to_owned()).await });
        tokio::time::timeout(Duration::from_secs(1), cancellation.forced())
            .await
            .expect("Destroy upgrades access cancellation to Force");
        let suspend_response = tokio::time::timeout(Duration::from_secs(1), suspend)
            .await
            .expect("preempted Suspend returns")
            .expect("Suspend task joins");
        assert_eq!(suspend_response.code, "action_cancelled");
        let destroy_response = tokio::time::timeout(Duration::from_secs(1), destroy)
            .await
            .expect("strong Destroy continues")
            .expect("Destroy task joins");
        assert_eq!(destroy_response.status, SemanticResponseStatus::Ok);
        assert_eq!(
            effects.actions(),
            vec![SemanticCatAction::Create, SemanticCatAction::Destroy]
        );
        drop(session);
    }

    #[tokio::test]
    async fn shell_style_guard_is_retained_by_outer_reader_and_writer() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;
        let outer = Arc::new(
            service
                .acquire_runtime_access("cat_01")
                .expect("Running access is open"),
        );
        let reader = Arc::clone(&outer);
        let writer = Arc::clone(&outer);
        let cancellation = outer.cancellation();
        let suspend_service = service.clone();
        let suspend = tokio::spawn(async move {
            suspend_service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
            .await
            .expect("session is cancelled");
        drop(reader);
        drop(outer);
        assert!(
            !suspend.is_finished(),
            "writer guard still retains admission"
        );
        drop(writer);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), suspend)
                .await
                .expect("all guards drain")
                .expect("suspend task joins")
                .status,
            SemanticResponseStatus::Ok
        );
    }

    #[tokio::test]
    async fn blocked_shell_sink_is_interrupted_by_cancellation() {
        let cancellation = RuntimeAccessCancellation::new();
        let task_cancellation = cancellation.clone();
        let blocked = tokio::spawn(async move {
            bounded_shell_io(&task_cancellation, std::future::pending::<()>()).await
        });
        tokio::task::yield_now().await;
        cancellation.cancel(RuntimeAccessCloseMode::Graceful);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), blocked)
                .await
                .expect("blocked sink observes cancellation")
                .expect("sink task joins"),
            None
        );
    }

    #[tokio::test]
    async fn multiframe_slow_consumer_keeps_proof_reader_until_guest_exit() {
        use std::os::unix::net::UnixStream;

        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;
        let session = Arc::new(
            service
                .acquire_runtime_access("cat_01")
                .expect("Running access is open"),
        );
        session.require_cleanup_proof();
        let cancellation = session.cancellation();
        let (node_stream, mut fake_guest) = UnixStream::pair().expect("fake Guest shell pair");
        let shell = GuestShell::from_test_stream(node_stream);
        let (sender, _slow_consumer) = mpsc::channel(1);
        let (remote_terminal, mut remote_terminal_receiver) = watch::channel(false);
        let reader_session = Arc::clone(&session);
        let reader = tokio::task::spawn_blocking(move || {
            read_guest_shell(shell, sender, reader_session, remote_terminal)
        });

        cats_api::guest::write_frame(&mut fake_guest, &GuestShellFrame::Output { data: vec![1] })
            .expect("write first Output that fills guest_sender");
        cats_api::guest::write_frame(&mut fake_guest, &GuestShellFrame::Output { data: vec![2] })
            .expect("write second Output for blocked forwarding");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
                .await
                .expect("full guest_sender cancels forwarding"),
            RuntimeAccessCloseMode::Graceful
        );
        cats_api::guest::write_frame(&mut fake_guest, &GuestShellFrame::Exit { exit_code: 0 })
            .expect("write cleanup proof after forwarding stopped");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !*remote_terminal_receiver.borrow_and_update() {
                remote_terminal_receiver
                    .changed()
                    .await
                    .expect("proof reader remains live");
            }
        })
        .await
        .expect("exact Guest Exit is observed");
        reader.await.expect("proof reader joins");
        drop(session);
        drop(
            service
                .acquire_runtime_access("cat_01")
                .expect("proved cleanup leaves access available"),
        );
        assert_eq!(
            service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
                .status,
            SemanticResponseStatus::Ok
        );
    }

    #[test]
    fn fake_guest_output_enforces_the_exact_websocket_payload_boundary() {
        let cancellation = RuntimeAccessCancellation::new();
        let maximum = Message::Binary(vec![0x5a; MAX_SHELL_MESSAGE_BYTES].into());
        assert_eq!(shell_websocket_payload_len(&maximum), 65_536);
        assert!(shell_websocket_message_is_bounded(&cancellation, &maximum));
        assert!(!cancellation.is_cancelled());

        let oversized = Message::Binary(vec![0x5a; MAX_SHELL_MESSAGE_BYTES + 1].into());
        assert_eq!(shell_websocket_payload_len(&oversized), 65_537);
        assert!(!shell_websocket_message_is_bounded(
            &cancellation,
            &oversized
        ));
        assert_eq!(cancellation.mode(), Some(RuntimeAccessCloseMode::Graceful));
    }

    #[tokio::test]
    async fn cleanup_latch_wins_the_last_guard_drain_race() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        session.require_cleanup_proof();
        let cancellation = session.cancellation();
        let suspend_service = service.clone();
        let suspend = tokio::spawn(async move {
            suspend_service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
            .await
            .expect("ordinary drain begins");

        // Model EOF/handler abort completing after drain has already sampled
        // an active guard. Drop records the latch and removal atomically.
        session.mark_cleanup_unproven();
        drop(session);
        let response = tokio::time::timeout(Duration::from_secs(1), suspend)
            .await
            .expect("latched drain returns")
            .expect("Suspend task joins");
        assert_eq!(response.status, SemanticResponseStatus::Failed);
        assert_eq!(
            response.error.expect("typed failure").code,
            SemanticErrorCode::NodeUnavailable
        );
        assert_eq!(effects.actions(), vec![SemanticCatAction::Create]);
        let lane = service.existing_lane("cat_01").expect("Cat lane remains");
        assert!(lane.access.cleanup_unproven());
        assert_eq!(lane.access.active_count(), 0, "last guard was released");
    }

    #[tokio::test]
    async fn unproven_handler_cleanup_remains_latched_after_the_grace_period() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        session.require_cleanup_proof();
        tokio::time::sleep(
            RUNTIME_ACCESS_DRAIN_TIMEOUT
                .checked_add(SESSION_FORCE_CLOSE_GRACE)
                .unwrap_or(Duration::MAX),
        )
        .await;
        drop(session);

        let response = service
            .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
            .await;
        assert_eq!(response.status, SemanticResponseStatus::Failed);
        assert_eq!(
            response.error.expect("typed failure").code,
            SemanticErrorCode::NodeUnavailable
        );
        assert_eq!(effects.actions(), vec![SemanticCatAction::Create]);
    }

    #[test]
    fn exec_response_budget_orders_connect_guest_cleanup_and_node_join() {
        let guest_timeout_ms = 120_000;
        assert_eq!(
            exec_dispatch_timeout(guest_timeout_ms),
            Duration::from_secs(120) + GUEST_ACCESS_CONNECT_TIMEOUT + EXEC_GUEST_TERMINAL_MARGIN
        );
        assert_eq!(
            exec_max_response_timeout(guest_timeout_ms),
            Duration::from_secs(120 + 21)
        );
    }

    #[tokio::test]
    async fn runtime_access_limits_are_independent_of_lifecycle_actions() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;

        let sessions = (0..MAX_RUNTIME_ACCESS_SESSIONS_PER_CAT)
            .map(|_| {
                service
                    .acquire_runtime_access("cat_01")
                    .expect("session below per-Cat limit")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            service.acquire_runtime_access("cat_01").unwrap_err(),
            RuntimeAccessError::LimitReached
        );
        assert_eq!(
            service
                .get("cat_01")
                .expect("Cat remains registered")
                .active_action,
            None
        );
        drop(sessions);
        service
            .acquire_runtime_access("cat_01")
            .expect("dropping guards releases the access limit");
    }

    #[test]
    fn canonical_guest_exec_timeout_maps_to_gateway_timeout() {
        let response = exec_worker_response(Ok(Err(GuestExecError::Timeout {
            message: "guest error: exec timed out after 120000 ms".to_owned(),
        })));
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn exact_guest_exec_error_proves_cleanup_and_leaves_access_available() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        session.require_cleanup_proof();
        let error = GuestExecError::RemoteError {
            message: "guest error: Permission denied".to_owned(),
        };
        assert!(guest_exec_error_proves_remote_cleanup(&error));
        session.prove_cleanup();
        drop(session);
        drop(
            service
                .acquire_runtime_access("cat_01")
                .expect("exact Guest Error did not latch the access gate"),
        );
        assert_eq!(
            service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
                .status,
            SemanticResponseStatus::Ok
        );
    }

    #[tokio::test]
    async fn reset_closes_and_drains_runtime_access_before_clearing_markers() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        service.create("cat_01".to_owned(), config()).await;
        let session = service
            .acquire_runtime_access("cat_01")
            .expect("Running access is open");
        let cancelled = session.cancellation();
        let reset_service = service.clone();
        let reset = tokio::spawn(async move { reset_service.reset_all().await });
        tokio::time::timeout(Duration::from_secs(1), cancelled.cancelled())
            .await
            .expect("reset cancels the runtime session");
        assert!(!reset.is_finished(), "reset waits for the retained guard");
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), reset)
            .await
            .expect("reset drains")
            .expect("reset task joins")
            .expect("reset succeeds");
        assert!(service.list().cats.is_empty());
        assert!(!service.placement_gate().is_open());
    }

    async fn spawn_http(service: SemanticNodeService) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server address");
        let router = semantic_node_router(
            service,
            NodedServiceToken::new("test-secret-that-is-at-least-32-bytes")
                .expect("valid service token"),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve test API");
        });
        (format!("http://{addr}"), task)
    }

    #[tokio::test]
    async fn exec_http_body_limit_accepts_exact_cap_and_rejects_cap_plus_one() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects.clone());
        let (origin, server) = spawn_http(service).await;
        let client = reqwest::Client::new();

        let exact = client
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .header(header::CONTENT_TYPE, "application/json")
            .body(vec![b' '; MAX_EXEC_JSON_BODY_BYTES])
            .send()
            .await
            .expect("exact-cap malformed request");
        assert_eq!(exact.status(), StatusCode::BAD_REQUEST);
        let exact: WireErrorBody = exact.json().await.expect("exact-cap error body");
        assert_eq!(exact.code, SemanticErrorCode::InvalidRequest);
        assert!(
            !exact.message.contains("length limit"),
            "the exact cap reaches JSON parsing rather than the body limiter"
        );

        let oversized = client
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .header(header::CONTENT_TYPE, "application/json")
            .body(vec![b' '; MAX_EXEC_JSON_BODY_BYTES + 1])
            .send()
            .await
            .expect("oversized malformed request");
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
        let oversized: WireErrorBody = oversized.json().await.expect("oversized error body");
        assert_eq!(oversized.code, SemanticErrorCode::InvalidRequest);
        assert!(oversized.message.contains("length limit"));
        assert!(
            effects.actions().is_empty(),
            "body rejection must precede Guest/effect dispatch"
        );
        server.abort();
    }

    #[cfg(target_os = "linux")]
    struct GuestTargetEffects(RuntimeAccessTarget);

    #[cfg(target_os = "linux")]
    impl SemanticCatEffects for GuestTargetEffects {
        fn execute(
            &self,
            _request: SemanticEffectRequest,
            _cancellation: SemanticActionCancellation,
        ) -> SemanticEffectFuture {
            Box::pin(async { Ok(()) })
        }

        fn running_access_target(
            &self,
            _cat_id: &str,
        ) -> Result<Option<RuntimeAccessTarget>, SemanticEffectError> {
            Ok(Some(self.0.clone()))
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exec_host_deadline_closes_a_guest_that_hangs_after_dispatch() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::os::unix::net::UnixListener;

        let directory = tempfile::tempdir().expect("temporary vsock directory");
        let path = directory.path().join("hung-exec-vsock.sock");
        let listener = UnixListener::bind(&path).expect("bind fake hybrid vsock");
        let peer = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().expect("accept noded exec");
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("bound fake peer read");
            let mut connect = String::new();
            BufReader::new(server.try_clone().expect("clone fake peer"))
                .read_line(&mut connect)
                .expect("read hybrid connect");
            assert_eq!(connect, "CONNECT 5000\n");
            server
                .write_all(b"OK 1073741824\n")
                .expect("write hybrid ACK");
            let request: cats_api::guest::GuestRequest =
                cats_api::guest::read_frame(&mut server).expect("read dispatched Exec");
            assert!(matches!(
                request.body,
                cats_api::guest::GuestRequestBody::Exec { .. }
            ));
            let mut byte = [0_u8; 1];
            assert_eq!(
                server.read(&mut byte).unwrap_or(0),
                0,
                "Host deadline must close the hung Guest connection"
            );
        });
        let effects = Arc::new(GuestTargetEffects(RuntimeAccessTarget {
            runtime_incarnation: RandomId128::new("b".repeat(32))
                .expect("valid runtime incarnation"),
            vsock_socket: path,
            guest_port: 5_000,
            vmm_pid: std::process::id(),
        }));
        let service = SemanticNodeService::new(effects);
        assert_eq!(
            service.create("cat_01".to_owned(), config()).await.status,
            SemanticResponseStatus::Ok
        );
        let (origin, server) = spawn_http(service).await;
        let response = reqwest::Client::new()
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&ExecRequest {
                command: vec!["sleep".to_owned(), "forever".to_owned()],
                timeout_ms: Some(20),
                env: BTreeMap::new(),
                stdin: Vec::new(),
            })
            .send()
            .await
            .expect("hung exec response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error: WireErrorBody = response.json().await.expect("semantic error body");
        assert_eq!(error.code, SemanticErrorCode::NodeUnavailable);
        assert!(error.message.contains("result is unknown"));
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(move || peer.join()),
        )
        .await
        .expect("fake Guest cleanup is bounded")
        .expect("fake Guest join task succeeds")
        .expect("fake Guest peer joins");
        server.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn slow_exact_connect_still_allows_guest_timeout_cleanup_to_finish() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let directory = tempfile::tempdir().expect("temporary vsock directory");
        let path = directory.path().join("slow-exec-vsock.sock");
        let listener = UnixListener::bind(&path).expect("bind fake hybrid vsock");
        let peer = std::thread::spawn(move || {
            let (mut guest, _) = listener.accept().expect("accept noded exec");
            let mut connect = String::new();
            BufReader::new(guest.try_clone().expect("clone fake peer"))
                .read_line(&mut connect)
                .expect("read hybrid connect");
            // Consume almost the full exact-connect budget. The Guest must
            // still receive its complete T plus terminal cleanup margin.
            std::thread::sleep(GUEST_ACCESS_CONNECT_TIMEOUT - Duration::from_millis(50));
            guest
                .write_all(b"OK 1073741824\n")
                .expect("write delayed hybrid ACK");
            let request: cats_api::guest::GuestRequest =
                cats_api::guest::read_frame(&mut guest).expect("read dispatched Exec");
            std::thread::sleep(Duration::from_millis(120));
            cats_api::guest::write_frame(
                &mut guest,
                &cats_api::guest::GuestResponse {
                    id: request.id,
                    body: cats_api::guest::GuestResponseBody::Error {
                        message: "exec timed out after 20 ms".to_owned(),
                    },
                },
            )
            .expect("write known Guest timeout after cleanup");
        });
        let service = SemanticNodeService::new(Arc::new(GuestTargetEffects(RuntimeAccessTarget {
            runtime_incarnation: RandomId128::new("e".repeat(32))
                .expect("valid runtime incarnation"),
            vsock_socket: path,
            guest_port: 5_000,
            vmm_pid: std::process::id(),
        })));
        service.create("cat_01".to_owned(), config()).await;
        let (origin, server) = spawn_http(service).await;
        let response = reqwest::Client::new()
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&ExecRequest {
                command: vec!["sleep".to_owned(), "forever".to_owned()],
                timeout_ms: Some(20),
                env: BTreeMap::new(),
                stdin: Vec::new(),
            })
            .send()
            .await
            .expect("known Guest timeout response");
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let error: WireErrorBody = response.json().await.expect("semantic error body");
        assert_eq!(error.code, SemanticErrorCode::Timeout);
        peer.join().expect("fake Guest peer joins");
        server.abort();
    }

    #[cfg(target_os = "linux")]
    async fn exercise_fake_guest_shell_output(output_len: usize, expect_forwarded: bool) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        let directory = tempfile::tempdir().expect("temporary vsock directory");
        let path = directory
            .path()
            .join(format!("shell-output-{output_len}.sock"));
        let listener = UnixListener::bind(&path).expect("bind fake hybrid vsock");
        let peer = std::thread::spawn(move || {
            let (mut guest, _) = listener.accept().expect("accept noded shell");
            guest
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("bound fake Guest reads");
            let mut connect = String::new();
            BufReader::new(guest.try_clone().expect("clone fake peer"))
                .read_line(&mut connect)
                .expect("read hybrid connect");
            assert_eq!(connect, "CONNECT 5000\n");
            guest
                .write_all(b"OK 1073741824\n")
                .expect("write hybrid ACK");
            let request: cats_api::guest::GuestRequest =
                cats_api::guest::read_frame(&mut guest).expect("read Shell request");
            assert!(matches!(
                request.body,
                cats_api::guest::GuestRequestBody::Shell { .. }
            ));
            cats_api::guest::write_frame(
                &mut guest,
                &cats_api::guest::GuestResponse {
                    id: request.id,
                    body: cats_api::guest::GuestResponseBody::ShellReady,
                },
            )
            .expect("write ShellReady");
            cats_api::guest::write_frame(
                &mut guest,
                &GuestShellFrame::Output {
                    data: vec![0x5a; output_len],
                },
            )
            .expect("write fake Guest output");
            let close: GuestShellFrame =
                cats_api::guest::read_frame(&mut guest).expect("read Node Close");
            assert_eq!(close, GuestShellFrame::Close);
            cats_api::guest::write_frame(&mut guest, &GuestShellFrame::Exit { exit_code: 0 })
                .expect("write terminal Guest Exit");
        });
        let effects = Arc::new(GuestTargetEffects(RuntimeAccessTarget {
            runtime_incarnation: RandomId128::new("c".repeat(32))
                .expect("valid runtime incarnation"),
            vsock_socket: path,
            guest_port: 5_000,
            vmm_pid: std::process::id(),
        }));
        let service = SemanticNodeService::new(effects);
        assert_eq!(
            service.create("cat_01".to_owned(), config()).await.status,
            SemanticResponseStatus::Ok
        );
        let (origin, server) = spawn_http(service.clone()).await;
        let mut request = format!(
            "{}/v1/cats/cat_01/shell?rows=24&cols=80",
            origin.replacen("http://", "ws://", 1)
        )
        .into_client_request()
        .expect("build noded WebSocket request");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-secret-that-is-at-least-32-bytes"),
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(request)
            .await
            .expect("connect noded shell");
        let received = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("bounded WebSocket receive");
        if expect_forwarded {
            assert!(matches!(
                received,
                Some(Ok(ClientMessage::Binary(data))) if data.len() == MAX_SHELL_MESSAGE_BYTES
            ));
            socket
                .send(ClientMessage::Text(r#"{"type":"close"}"#.into()))
                .await
                .expect("send accepted shell control Close");
        } else {
            assert!(
                !matches!(received, Some(Ok(ClientMessage::Binary(_)))),
                "oversized Guest output must never reach the internal WebSocket"
            );
        }
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(move || peer.join()),
        )
        .await
        .expect("fake Guest cleanup is bounded")
        .expect("fake Guest join task succeeds")
        .expect("fake Guest peer joins");
        drop(socket);
        let lane = service.existing_lane("cat_01").expect("Cat lane remains");
        tokio::time::timeout(Duration::from_secs(2), async {
            while lane.access.active_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shell guard is released");
        assert!(
            !lane.access.cleanup_unproven(),
            "terminal Guest Exit proves oversized-session cleanup"
        );
        assert_eq!(
            service
                .action("cat_01".to_owned(), SemanticCatAction::Suspend, None)
                .await
                .status,
            SemanticResponseStatus::Ok,
            "Close followed by exact Guest Exit permits ordinary lifecycle"
        );
        server.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fake_guest_shell_output_accepts_65536_and_rejects_65537() {
        exercise_fake_guest_shell_output(MAX_SHELL_MESSAGE_BYTES, true).await;
        exercise_fake_guest_shell_output(MAX_SHELL_MESSAGE_BYTES + 1, false).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exact_guest_shell_error_does_not_latch_runtime_cleanup() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        use tokio_tungstenite::tungstenite::http::HeaderValue;

        let directory = tempfile::tempdir().expect("temporary vsock directory");
        let path = directory.path().join("shell-terminal-error.sock");
        let listener = UnixListener::bind(&path).expect("bind fake hybrid vsock");
        let peer = std::thread::spawn(move || {
            let (mut guest, _) = listener.accept().expect("accept noded shell");
            let mut connect = String::new();
            BufReader::new(guest.try_clone().expect("clone fake peer"))
                .read_line(&mut connect)
                .expect("read hybrid connect");
            guest
                .write_all(b"OK 1073741824\n")
                .expect("write hybrid ACK");
            let request: cats_api::guest::GuestRequest =
                cats_api::guest::read_frame(&mut guest).expect("read Shell request");
            cats_api::guest::write_frame(
                &mut guest,
                &cats_api::guest::GuestResponse {
                    id: request.id,
                    body: cats_api::guest::GuestResponseBody::Error {
                        message: "shell unavailable".to_owned(),
                    },
                },
            )
            .expect("write terminal Guest Error");
        });
        let service = SemanticNodeService::new(Arc::new(GuestTargetEffects(RuntimeAccessTarget {
            runtime_incarnation: RandomId128::new("d".repeat(32))
                .expect("valid runtime incarnation"),
            vsock_socket: path,
            guest_port: 5_000,
            vmm_pid: std::process::id(),
        })));
        service.create("cat_01".to_owned(), config()).await;
        let (origin, server) = spawn_http(service.clone()).await;
        let mut request = format!(
            "{}/v1/cats/cat_01/shell?rows=24&cols=80",
            origin.replacen("http://", "ws://", 1)
        )
        .into_client_request()
        .expect("build noded WebSocket request");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-secret-that-is-at-least-32-bytes"),
        );
        let error = tokio_tungstenite::connect_async(request)
            .await
            .expect_err("Guest Error rejects before WebSocket 101");
        assert!(matches!(
            error,
            tokio_tungstenite::tungstenite::Error::Http(ref response)
                if response.status() == StatusCode::SERVICE_UNAVAILABLE
        ));
        peer.join().expect("fake Guest peer joins");
        let lane = service.existing_lane("cat_01").expect("Cat lane remains");
        assert_eq!(lane.access.active_count(), 0);
        assert!(!lane.access.cleanup_unproven());
        drop(
            service
                .acquire_runtime_access("cat_01")
                .expect("terminal Guest Error leaves access usable"),
        );
        server.abort();
    }

    #[tokio::test]
    async fn http_requires_exact_bearer_token_and_wires_queries() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        let (origin, server) = spawn_http(service.clone()).await;
        let client = reqwest::Client::new();

        for authorization in [None, Some("Bearer wrong")] {
            let mut request = client.get(format!("{origin}/v1/health"));
            if let Some(value) = authorization {
                request = request.header(header::AUTHORIZATION, value);
            }
            assert_eq!(
                request.send().await.expect("health response").status(),
                StatusCode::UNAUTHORIZED
            );
        }

        let health = client
            .get(format!("{origin}/v1/health"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .send()
            .await
            .expect("authorized health");
        assert_eq!(health.status(), StatusCode::OK);

        service.placement_gate().close();
        let not_ready = client
            .get(format!("{origin}/v1/health"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .send()
            .await
            .expect("closed-gate health");
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        service.placement_gate().open();

        let created = client
            .put(format!("{origin}/v1/cats/cat_01"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&config())
            .send()
            .await
            .expect("create response");
        assert_eq!(created.status(), StatusCode::OK);

        let missing_run_config = client
            .post(format!("{origin}/v1/cats/cat_01/actions/run"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("invalid run response");
        assert_eq!(missing_run_config.status(), StatusCode::BAD_REQUEST);

        let unexpected_cold_config = client
            .post(format!("{origin}/v1/cats/cat_01/actions/cold"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&NodedCatActionRequest {
                config: Some(config()),
            })
            .send()
            .await
            .expect("invalid cold response");
        assert_eq!(unexpected_cold_config.status(), StatusCode::BAD_REQUEST);

        let cat: serde_json::Value = client
            .get(format!("{origin}/v1/cats/cat_01"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .send()
            .await
            .expect("get response")
            .json()
            .await
            .expect("cat JSON");
        assert_eq!(cat["state"], "running");

        let list: serde_json::Value = client
            .get(format!("{origin}/v1/cats"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .send()
            .await
            .expect("list response")
            .json()
            .await
            .expect("list JSON");
        assert_eq!(list["cats"].as_array().expect("cats array").len(), 1);

        let unauthorized_exec = client
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .json(&ExecRequest {
                command: vec!["true".to_owned()],
                timeout_ms: None,
                env: BTreeMap::new(),
                stdin: Vec::new(),
            })
            .send()
            .await
            .expect("unauthorized exec response");
        assert_eq!(unauthorized_exec.status(), StatusCode::UNAUTHORIZED);

        let invalid_exec = client
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&ExecRequest {
                command: Vec::new(),
                timeout_ms: None,
                env: BTreeMap::new(),
                stdin: Vec::new(),
            })
            .send()
            .await
            .expect("invalid exec response");
        assert_eq!(invalid_exec.status(), StatusCode::BAD_REQUEST);

        let unauthorized_shell = client
            .get(format!("{origin}/v1/cats/cat_01/shell?rows=24&cols=80"))
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .expect("unauthorized shell response");
        assert_eq!(unauthorized_shell.status(), StatusCode::UNAUTHORIZED);

        let invalid_shell = client
            .get(format!("{origin}/v1/cats/cat_01/shell?rows=0&cols=80"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .expect("invalid shell response");
        assert_eq!(invalid_shell.status(), StatusCode::BAD_REQUEST);

        let unavailable_shell = client
            .get(format!("{origin}/v1/cats/cat_01/shell?rows=24&cols=80"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .expect("unavailable Guest shell response");
        assert_eq!(
            unavailable_shell.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "noded must reject before returning WebSocket 101 when Guest ShellReady fails"
        );

        let cold = client
            .post(format!("{origin}/v1/cats/cat_01/actions/cold"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&NodedCatActionRequest { config: None })
            .send()
            .await
            .expect("cold response");
        assert_eq!(cold.status(), StatusCode::OK);
        let cold_exec = client
            .post(format!("{origin}/v1/cats/cat_01/exec"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&ExecRequest {
                command: vec!["true".to_owned()],
                timeout_ms: None,
                env: BTreeMap::new(),
                stdin: Vec::new(),
            })
            .send()
            .await
            .expect("Cold exec response");
        assert_eq!(cold_exec.status(), StatusCode::UNPROCESSABLE_ENTITY);

        server.abort();
    }
}

//! Simple synchronous Control -> Node Cat lifecycle protocol.
//!
//! Idempotency is derived from the Cat identity, immutable create
//! configuration and requested target state. There is deliberately no
//! request ID, Operation projection, command poll or result-post lane here.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    noded_cat_path, NodedCatActionRequest, NodedCatConfig, NodedCatListResponse, NodedCatResponse,
    NodedCatView, NodedCreateCatRequest, NodedResultStatus, NodedServiceToken,
    SemanticErrorBody as WireErrorBody, SemanticErrorCode,
};
use tokio::sync::watch;

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
    fn new() -> Self {
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
}

impl CatLane {
    fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            state: Mutex::new(CatLaneState::default()),
            changed,
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
}

impl SemanticNodeService {
    pub fn new(effects: Arc<dyn SemanticCatEffects>) -> Self {
        Self {
            effects,
            cats: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn cats(&self) -> MutexGuard<'_, BTreeMap<String, Arc<CatLane>>> {
        self.cats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn existing_lane(&self, cat_id: &str) -> Option<Arc<CatLane>> {
        self.cats().get(cat_id).cloned()
    }

    fn lane(&self, cat_id: &str) -> Arc<CatLane> {
        self.cats()
            .entry(cat_id.to_owned())
            .or_insert_with(|| Arc::new(CatLane::new()))
            .clone()
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
        let lane = self.lane(&cat_id);
        loop {
            let mut changed = lane.changed.subscribe();
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
                        None
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
                    Some(sequence)
                }
            };
            match decision {
                Some(sequence) => {
                    return self
                        .run_effect(&cat_id, lane, sequence, SemanticCatAction::Create)
                        .await;
                }
                None => {
                    let _ = changed.changed().await;
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
                        None
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
                    Some(begin_action(&mut state, action))
                }
            };
            match sequence {
                Some(sequence) => {
                    return self.run_effect(&cat_id, lane, sequence, action).await;
                }
                None => {
                    let _ = changed.changed().await;
                }
            }
        }
    }

    pub async fn destroy(&self, cat_id: String) -> SemanticCatResponse {
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
                    if active.action != SemanticCatAction::Destroy {
                        active.cancellation.cancel();
                    }
                    None
                } else {
                    Some(begin_action(&mut state, SemanticCatAction::Destroy))
                }
            };
            match sequence {
                Some(sequence) => {
                    return self
                        .run_effect(&cat_id, lane, sequence, SemanticCatAction::Destroy)
                        .await;
                }
                None => {
                    let _ = changed.changed().await;
                }
            }
        }
    }

    async fn run_effect(
        &self,
        cat_id: &str,
        lane: Arc<CatLane>,
        sequence: u64,
        action: SemanticCatAction,
    ) -> SemanticCatResponse {
        let (config, cancellation) = {
            let state = lane.state();
            let record = state
                .record
                .as_ref()
                .expect("action always has a Cat record");
            let active = state
                .active
                .as_ref()
                .expect("started action remains active");
            (record.config.clone(), active.cancellation.clone())
        };
        let effect = self.effects.execute(
            SemanticEffectRequest {
                cat_id: cat_id.to_owned(),
                action,
                config,
            },
            cancellation,
        );
        let result = tokio::spawn(effect).await.unwrap_or_else(|error| {
            Err(SemanticEffectError::new(
                SemanticErrorCode::InternalError,
                format!("physical effect task failed: {error}"),
            ))
        });

        let response = {
            let mut state = lane.state();
            let is_current = state
                .active
                .as_ref()
                .is_some_and(|active| active.sequence == sequence && active.action == action);
            if !is_current {
                response_error(
                    cat_id.to_owned(),
                    SemanticResponseStatus::Failed,
                    "internal_error",
                    "action completion did not match the active Cat action",
                    state.record.as_ref().and_then(|record| record.state),
                    state.active.as_ref().map(|active| active.action),
                )
            } else {
                state.active = None;
                let cancelled_for_destroy =
                    state.destroy_pending && action != SemanticCatAction::Destroy;
                match result {
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
                }
            }
        };
        lane.publish_change();
        response
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

fn begin_action(state: &mut CatLaneState, action: SemanticCatAction) -> u64 {
    state.next_sequence = state.next_sequence.wrapping_add(1);
    let sequence = state.next_sequence;
    state.active = Some(ActiveAction {
        sequence,
        action,
        cancellation: SemanticActionCancellation::new(),
    });
    sequence
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
        SemanticErrorCode::DiskSizeConflict => "disk_size_conflict",
        SemanticErrorCode::DiskDeleted => "disk_deleted",
        SemanticErrorCode::DiskInUse => "disk_in_use",
        SemanticErrorCode::DiskAlreadyAttached => "disk_already_attached",
        SemanticErrorCode::DiskBindingConflict => "disk_binding_conflict",
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
                Ok(())
            })
        }
    }

    fn config() -> SemanticCatConfig {
        SemanticCatConfig {
            cpu: 2,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            boot_image: "ubuntu-24.04".to_owned(),
            mounts: vec![SemanticMount {
                disk_id: Id::new("disk_01").expect("valid disk ID"),
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
    async fn http_requires_exact_bearer_token_and_wires_queries() {
        let effects = Arc::new(RecordingEffects::default());
        let service = SemanticNodeService::new(effects);
        let (origin, server) = spawn_http(service).await;
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

        let created = client
            .put(format!("{origin}/v1/cats/cat_01"))
            .bearer_auth("test-secret-that-is-at-least-32-bytes")
            .json(&config())
            .send()
            .await
            .expect("create response");
        assert_eq!(created.status(), StatusCode::OK);

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

        server.abort();
    }
}

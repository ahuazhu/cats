use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    CatAction as NodeAction, CatState as NodeState, NodedCatConfig, NodedControlEndpoint,
    NodedDiskMount, NodedServiceToken, PersistentDiskFormat, PersistentMountPath,
    SemanticErrorCode,
};
use cats_control_plane::semantic_adapters::SemanticNodedLifecycleAdapter;
use cats_control_plane::semantic_lifecycle::{
    classify_action, classify_create, ActionClaim, ActionDecision, Admission,
    CatAction as ControlAction, CatCreateConfig, CatMount, CatRecord, CatSelector,
    CatState as ControlState, CreateCatRequest, CreateDecision, IngressError, IngressPort,
    LifecycleOutcome, LifecycleTimeouts, NodeControlEndpoint, OutcomeStatus, SemanticFuture,
    SemanticLifecycleService, SemanticLifecycleStore, StoreError,
};
use cats_control_plane::semantic_node_recovery::{
    CatRecoveryStatus, RecoveryAdmission, RecoveryCandidate, RecoveryClaim, RecoveryFinish,
    RecoveryFuture, RecoveryTimeouts, SemanticNodeRecoveryService, SemanticNodeRecoveryStore,
};
use cats_control_plane::semantic_noded_client::{SemanticNodedClient, SemanticNodedClientConfig};
use cats_node_agent::semantic_lifecycle::{
    semantic_node_router, SemanticActionCancellation, SemanticCatEffects, SemanticEffectError,
    SemanticEffectFuture, SemanticEffectRequest, SemanticNodeService,
};
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;

const CAT_ID: &str = "cat_01";
const NODE_ID: &str = "node_01";
const WORKSPACE_ID: &str = "ws_01";

#[derive(Clone)]
struct MemoryLifecycleStore {
    inner: Arc<Mutex<MemoryStoreState>>,
}

struct MemoryStoreState {
    cat: Option<CatRecord>,
    endpoint: String,
}

impl MemoryLifecycleStore {
    fn new(endpoint: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryStoreState {
                cat: None,
                endpoint,
            })),
        }
    }

    fn state(&self) -> MutexGuard<'_, MemoryStoreState> {
        self.inner.lock().expect("memory lifecycle store")
    }

    fn cat(&self) -> CatRecord {
        self.state().cat.clone().expect("Cat exists")
    }
}

impl SemanticLifecycleStore for MemoryLifecycleStore {
    fn admit_create<'a>(
        &'a self,
        request: &'a CreateCatRequest,
    ) -> SemanticFuture<'a, Result<Admission, StoreError>> {
        Box::pin(async move {
            let mut state = self.state();
            match classify_create(state.cat.as_ref(), request) {
                CreateDecision::Insert => {
                    let cat = CatRecord {
                        cat_id: CAT_ID.to_owned(),
                        workspace_id: request.workspace_id.clone(),
                        cat_slug: request.cat_slug.clone(),
                        state: None,
                        current_action: Some(ControlAction::Create),
                        current_action_node_id: Some(NODE_ID.to_owned()),
                        node_id: None,
                        config: request.config.clone(),
                    };
                    state.cat = Some(cat.clone());
                    Ok(Admission::Claimed(ActionClaim {
                        cat,
                        action: ControlAction::Create,
                        started_at_unix_ms: 1,
                        recovery_started_at_unix_ms: None,
                        node_id: Some(NODE_ID.to_owned()),
                    }))
                }
                CreateDecision::AlreadyExists => Ok(Admission::Already {
                    cat: state.cat.clone().expect("classified existing Cat"),
                    code: ControlAction::Create.already_code(),
                }),
                CreateDecision::SameAction => {
                    let cat = state.cat.clone().expect("classified existing Cat");
                    Ok(Admission::SameAction(ActionClaim {
                        node_id: cat.current_action_node_id.clone(),
                        cat,
                        action: ControlAction::Create,
                        started_at_unix_ms: 1,
                        recovery_started_at_unix_ms: None,
                    }))
                }
                CreateDecision::Busy => Ok(Admission::Busy(
                    state.cat.clone().expect("classified existing Cat"),
                )),
                CreateDecision::ConfigurationConflict => Ok(Admission::Conflict {
                    cat: state.cat.clone().expect("classified existing Cat"),
                    code: "cat_configuration_conflict",
                }),
            }
        })
    }

    fn admit_action<'a>(
        &'a self,
        selector: &'a CatSelector,
        action: ControlAction,
    ) -> SemanticFuture<'a, Result<Admission, StoreError>> {
        Box::pin(async move {
            let mut state = self.state();
            let Some(existing) = state.cat.clone() else {
                return Ok(Admission::NotFound);
            };
            if !selector_matches(selector, &existing) {
                return Ok(Admission::NotFound);
            }
            match classify_action(&existing, action) {
                ActionDecision::Claim => {
                    let selected_node = if action == ControlAction::Destroy {
                        existing
                            .current_action_node_id
                            .clone()
                            .or_else(|| existing.node_id.clone())
                    } else {
                        existing
                            .node_id
                            .clone()
                            .or_else(|| Some(NODE_ID.to_owned()))
                    };
                    let cat = state.cat.as_mut().expect("existing Cat");
                    if action == ControlAction::Destroy && cat.state.is_none() {
                        cat.state = Some(ControlState::Failure);
                    }
                    cat.current_action = Some(action);
                    cat.current_action_node_id = selected_node.clone();
                    let cat = cat.clone();
                    Ok(Admission::Claimed(ActionClaim {
                        cat,
                        action,
                        started_at_unix_ms: 1,
                        recovery_started_at_unix_ms: None,
                        node_id: selected_node,
                    }))
                }
                ActionDecision::AlreadyDone => Ok(Admission::Already {
                    cat: existing,
                    code: action.already_code(),
                }),
                ActionDecision::SameAction => Ok(Admission::SameAction(ActionClaim {
                    node_id: existing.current_action_node_id.clone(),
                    cat: existing,
                    action,
                    started_at_unix_ms: 1,
                    recovery_started_at_unix_ms: None,
                })),
                ActionDecision::Busy => Ok(Admission::Busy(existing)),
                ActionDecision::InvalidState => Ok(Admission::InvalidState(existing)),
            }
        })
    }

    fn pending_destroy_claims<'a>(
        &'a self,
        _minimum_age: Duration,
        _limit: usize,
    ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn rotate_pending_destroy<'a>(
        &'a self,
        _claim: &'a ActionClaim,
    ) -> SemanticFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> SemanticFuture<'a, Result<NodeControlEndpoint, StoreError>> {
        Box::pin(async move {
            if node_id != NODE_ID {
                return Err(StoreError::new("unexpected Node selection"));
            }
            NodeControlEndpoint::new(self.state().endpoint.clone())
        })
    }

    fn complete_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
        resulting_state: ControlState,
    ) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
        Box::pin(async move {
            let mut state = self.state();
            let cat = exact_claimed_cat(&mut state, claim)?;
            cat.state = Some(resulting_state);
            cat.current_action = None;
            cat.current_action_node_id = None;
            cat.node_id = match resulting_state {
                ControlState::Cold | ControlState::Destroyed => None,
                _ => claim.node_id.clone(),
            };
            Ok(cat.clone())
        })
    }

    fn fail_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
        _code: &'a str,
        _message: &'a str,
    ) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
        Box::pin(async move {
            let mut state = self.state();
            let cat = exact_claimed_cat(&mut state, claim)?;
            cat.state = Some(ControlState::Failure);
            cat.current_action = None;
            cat.current_action_node_id = None;
            Ok(cat.clone())
        })
    }
}

fn selector_matches(selector: &CatSelector, cat: &CatRecord) -> bool {
    match selector {
        CatSelector::Id(cat_id) => cat_id == &cat.cat_id,
        CatSelector::Slug {
            workspace_id,
            cat_slug,
        } => workspace_id == &cat.workspace_id && cat_slug == &cat.cat_slug,
    }
}

fn exact_claimed_cat<'a>(
    state: &'a mut MemoryStoreState,
    claim: &ActionClaim,
) -> Result<&'a mut CatRecord, StoreError> {
    let cat = state
        .cat
        .as_mut()
        .ok_or_else(|| StoreError::new("claimed Cat disappeared"))?;
    if cat.cat_id != claim.cat.cat_id
        || cat.current_action != Some(claim.action)
        || cat.current_action_node_id != claim.node_id
    {
        return Err(StoreError::new("action completion lost its exact claim"));
    }
    Ok(cat)
}

#[derive(Default)]
struct FakeEffectState {
    states: BTreeMap<String, NodeState>,
    requests: Vec<SemanticEffectRequest>,
}

#[derive(Clone)]
struct ControlledFakeEffects {
    inner: Arc<Mutex<FakeEffectState>>,
    trace: Arc<Mutex<Vec<String>>>,
}

impl ControlledFakeEffects {
    fn new(trace: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeEffectState::default())),
            trace,
        }
    }

    fn physical_state(&self, cat_id: &str) -> Option<NodeState> {
        self.inner
            .lock()
            .expect("fake effects")
            .states
            .get(cat_id)
            .copied()
    }

    fn requests(&self) -> Vec<SemanticEffectRequest> {
        self.inner.lock().expect("fake effects").requests.clone()
    }
}

impl SemanticCatEffects for ControlledFakeEffects {
    fn execute(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> SemanticEffectFuture {
        let effects = self.clone();
        Box::pin(async move {
            if cancellation.is_cancelled() && request.action != NodeAction::Destroy {
                return Err(SemanticEffectError::new(
                    SemanticErrorCode::ActionCancelled,
                    "cancelled controlled effect",
                ));
            }
            let mut state = effects.inner.lock().expect("fake effects");
            let current = state.states.get(&request.cat_id).copied();
            let legal = match request.action {
                NodeAction::Create => current.is_none(),
                NodeAction::Run => matches!(
                    current,
                    None | Some(NodeState::Suspended | NodeState::Warm | NodeState::Cold)
                ),
                NodeAction::Suspend => current == Some(NodeState::Running),
                NodeAction::Warm => {
                    matches!(current, Some(NodeState::Running | NodeState::Suspended))
                }
                NodeAction::Cold => matches!(
                    current,
                    Some(NodeState::Running | NodeState::Suspended | NodeState::Warm)
                ),
                NodeAction::Destroy => current.is_some(),
            };
            if !legal {
                return Err(SemanticEffectError::new(
                    SemanticErrorCode::InvalidState,
                    "controlled effect received an invalid physical transition",
                ));
            }
            state.requests.push(request.clone());
            if request.action == NodeAction::Destroy {
                state.states.remove(&request.cat_id);
            } else {
                state
                    .states
                    .insert(request.cat_id.clone(), request.action.target_state());
            }
            drop(state);
            effects
                .trace
                .lock()
                .expect("vertical trace")
                .push(format!("effect:{}", action_name(request.action)));
            Ok(())
        })
    }

    fn reset_all(&self) -> SemanticEffectFuture {
        let effects = self.clone();
        Box::pin(async move {
            effects.inner.lock().expect("fake effects").states.clear();
            effects
                .trace
                .lock()
                .expect("vertical trace")
                .push("effect:reset".to_owned());
            Ok(())
        })
    }
}

#[derive(Clone, Default)]
struct BlockingCreateEffects {
    create_started: Arc<Notify>,
    actions: Arc<Mutex<Vec<NodeAction>>>,
}

impl BlockingCreateEffects {
    async fn wait_for_create(&self) {
        self.create_started.notified().await;
    }

    fn actions(&self) -> Vec<NodeAction> {
        self.actions.lock().expect("blocking effects").clone()
    }
}

impl SemanticCatEffects for BlockingCreateEffects {
    fn execute(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> SemanticEffectFuture {
        let effects = self.clone();
        Box::pin(async move {
            effects
                .actions
                .lock()
                .expect("blocking effects")
                .push(request.action);
            if request.action == NodeAction::Create {
                effects.create_started.notify_one();
                while !cancellation.is_cancelled() {
                    tokio::task::yield_now().await;
                }
                return Err(SemanticEffectError::new(
                    SemanticErrorCode::ActionCancelled,
                    "create cancelled by destroy",
                ));
            }
            if request.action == NodeAction::Destroy {
                return Ok(());
            }
            Err(SemanticEffectError::new(
                SemanticErrorCode::InvalidState,
                "blocking effects only support create and destroy",
            ))
        })
    }
}

fn action_name(action: NodeAction) -> &'static str {
    match action {
        NodeAction::Create => "create",
        NodeAction::Run => "run",
        NodeAction::Suspend => "suspend",
        NodeAction::Warm => "warm",
        NodeAction::Cold => "cold",
        NodeAction::Destroy => "destroy",
    }
}

#[derive(Clone)]
struct MemoryIngress {
    inner: Arc<Mutex<Option<(String, String)>>>,
    effects: ControlledFakeEffects,
    trace: Arc<Mutex<Vec<String>>>,
}

impl MemoryIngress {
    fn new(effects: ControlledFakeEffects, trace: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            effects,
            trace,
        }
    }

    fn target(&self) -> Option<(String, String)> {
        self.inner.lock().expect("memory ingress").clone()
    }

    fn set_target(&self, cat_id: &str, node_id: &str) {
        *self.inner.lock().expect("memory ingress") = Some((cat_id.to_owned(), node_id.to_owned()));
    }
}

impl IngressPort for MemoryIngress {
    fn withdraw<'a>(
        &'a self,
        cat_id: &'a str,
        old_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>> {
        Box::pin(async move {
            let mut target = self.inner.lock().expect("memory ingress");
            if target
                .as_ref()
                .is_some_and(|current| current != &(cat_id.to_owned(), old_node_id.to_owned()))
            {
                return Err(IngressError::new("withdrew a different ingress target"));
            }
            *target = None;
            self.trace
                .lock()
                .expect("vertical trace")
                .push(format!("withdraw:{cat_id}@{old_node_id}"));
            Ok(())
        })
    }

    fn publish<'a>(
        &'a self,
        cat_id: &'a str,
        new_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>> {
        Box::pin(async move {
            if self.effects.physical_state(cat_id) != Some(NodeState::Running) {
                return Err(IngressError::new(
                    "ingress publish happened before the Node was Running",
                ));
            }
            *self.inner.lock().expect("memory ingress") =
                Some((cat_id.to_owned(), new_node_id.to_owned()));
            self.trace
                .lock()
                .expect("vertical trace")
                .push(format!("publish:{cat_id}@{new_node_id}"));
            Ok(())
        })
    }
}

struct RunningNode {
    endpoint: NodedControlEndpoint,
    service: SemanticNodeService,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl RunningNode {
    async fn start(effects: impl SemanticCatEffects, token: NodedServiceToken) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind semantic Node test listener");
        let address = listener.local_addr().expect("semantic Node address");
        let endpoint =
            NodedControlEndpoint::new(format!("http://{address}")).expect("semantic Node endpoint");
        let service = SemanticNodeService::new(Arc::new(effects));
        let router = semantic_node_router(service.clone(), token);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Self {
            endpoint,
            service,
            shutdown,
            task,
        }
    }

    async fn stop(self) {
        self.shutdown.send(()).expect("stop semantic Node server");
        self.task
            .await
            .expect("join semantic Node server")
            .expect("semantic Node server result");
    }
}

#[derive(Clone)]
struct MemoryRecoveryStore {
    inner: Arc<Mutex<MemoryRecoveryState>>,
}

struct MemoryRecoveryState {
    cat: CatRecord,
    source_node_id: String,
    target_node_id: String,
    target_endpoint: String,
}

impl MemoryRecoveryStore {
    fn new(target_endpoint: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryRecoveryState {
                cat: CatRecord {
                    cat_id: CAT_ID.to_owned(),
                    workspace_id: WORKSPACE_ID.to_owned(),
                    cat_slug: "web".to_owned(),
                    state: Some(ControlState::Running),
                    current_action: None,
                    current_action_node_id: None,
                    node_id: Some("node_source".to_owned()),
                    config: create_request().config,
                },
                source_node_id: "node_source".to_owned(),
                target_node_id: "node_target".to_owned(),
                target_endpoint,
            })),
        }
    }

    fn cat(&self) -> CatRecord {
        self.inner.lock().expect("recovery store").cat.clone()
    }
}

impl SemanticNodeRecoveryStore for MemoryRecoveryStore {
    fn list_source_cats<'a>(
        &'a self,
        source_node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>> {
        Box::pin(async move {
            let state = self.inner.lock().expect("recovery store");
            Ok((source_node_id == state.source_node_id
                && state.cat.node_id.as_deref() == Some(source_node_id))
            .then(|| RecoveryCandidate {
                cat_id: state.cat.cat_id.clone(),
            })
            .into_iter()
            .collect())
        })
    }

    fn claim<'a>(
        &'a self,
        source_node_id: &'a str,
        cat_id: &'a str,
    ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>> {
        Box::pin(async move {
            let mut state = self.inner.lock().expect("recovery store");
            if source_node_id != state.source_node_id
                || cat_id != state.cat.cat_id
                || state.cat.node_id.as_deref() != Some(source_node_id)
            {
                return Ok(RecoveryAdmission::Stale);
            }
            let already = state.cat.current_action == Some(ControlAction::Run)
                && state.cat.current_action_node_id.as_deref() == Some(&state.target_node_id);
            if !already {
                state.cat.current_action = Some(ControlAction::Run);
                state.cat.current_action_node_id = Some(state.target_node_id.clone());
            }
            let claim = RecoveryClaim {
                cat: state.cat.clone(),
                source_node_id: state.source_node_id.clone(),
                target_node_id: state.target_node_id.clone(),
                target_state: ControlState::Running,
                started_at_unix_ms: 1,
            };
            Ok(if already {
                RecoveryAdmission::AlreadyClaimed(claim)
            } else {
                RecoveryAdmission::Claimed(claim)
            })
        })
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>> {
        Box::pin(async move {
            let state = self.inner.lock().expect("recovery store");
            if node_id != state.target_node_id {
                return Err(StoreError::new("recovery selected an unexpected Node"));
            }
            NodeControlEndpoint::new(state.target_endpoint.clone())
        })
    }

    fn finish<'a>(
        &'a self,
        claim: &'a RecoveryClaim,
        result: RecoveryFinish<'a>,
    ) -> RecoveryFuture<'a, Result<Option<CatRecord>, StoreError>> {
        Box::pin(async move {
            let mut state = self.inner.lock().expect("recovery store");
            if state.cat.cat_id != claim.cat.cat_id
                || state.cat.current_action != Some(ControlAction::Run)
                || state.cat.current_action_node_id.as_deref() != Some(&claim.target_node_id)
            {
                return Ok(None);
            }
            state.cat.current_action = None;
            state.cat.current_action_node_id = None;
            match result {
                RecoveryFinish::Recovered => {
                    state.cat.state = Some(claim.target_state);
                    state.cat.node_id = Some(claim.target_node_id.clone());
                }
                RecoveryFinish::RetrySource { .. } => {
                    state.cat.state = Some(claim.target_state);
                    state.cat.node_id = Some(claim.source_node_id.clone());
                }
                RecoveryFinish::Failed { .. } => {
                    state.cat.state = Some(ControlState::Failure);
                    state.cat.node_id = None;
                }
            }
            Ok(Some(state.cat.clone()))
        })
    }
}

fn create_request() -> CreateCatRequest {
    CreateCatRequest {
        workspace_id: WORKSPACE_ID.to_owned(),
        cat_slug: "web".to_owned(),
        config: CatCreateConfig {
            cpu_count: 2,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            boot_image: "ubuntu-24.04".to_owned(),
            mounts: vec![CatMount {
                disk_id: "disk_01".to_owned(),
                volume_id: "vol_01".to_owned(),
                filesystem_uuid: "11111111111111111111111111111111".to_owned(),
                disk_format: "ext4".to_owned(),
                mount_path: "/data".to_owned(),
            }],
        },
    }
}

fn noded_config() -> NodedCatConfig {
    NodedCatConfig {
        workspace_id: Id::new(WORKSPACE_ID).expect("Workspace ID"),
        cpu: 2,
        memory_bytes: 4 * 1024 * 1024 * 1024,
        boot_image: "ubuntu-24.04".to_owned(),
        mounts: vec![NodedDiskMount {
            disk_id: Id::new("disk_01").expect("Disk ID"),
            volume_id: Id::new("vol_01").expect("Volume ID"),
            filesystem_uuid: cats_api::runtime_reconciliation::RandomId128::new("1".repeat(32))
                .expect("filesystem UUID"),
            format: PersistentDiskFormat::Ext4,
            mount_path: PersistentMountPath::new("/data").expect("mount path"),
        }],
    }
}

fn test_timeouts() -> LifecycleTimeouts {
    LifecycleTimeouts {
        total: Duration::from_secs(2),
        node_request: Duration::from_secs(1),
        retry_count: 0,
        retry_interval: Duration::ZERO,
        recovery_poll_interval: Duration::from_millis(1),
        create_cleanup: Duration::from_secs(1),
    }
}

fn assert_outcome(
    outcome: &LifecycleOutcome,
    expected_status: OutcomeStatus,
    expected_state: ControlState,
) {
    assert_eq!(outcome.status, expected_status);
    assert_eq!(outcome.cat.state, Some(expected_state));
}

fn assert_ingress(ingress: &MemoryIngress, running: bool) {
    let expected = running.then(|| (CAT_ID.to_owned(), NODE_ID.to_owned()));
    assert_eq!(ingress.target(), expected);
}

#[tokio::test]
async fn semantic_control_to_node_http_lifecycle_is_scenario_idempotent() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let effects = ControlledFakeEffects::new(Arc::clone(&trace));
    let token = NodedServiceToken::new("vertical-test-service-token-00000001")
        .expect("valid service token");
    let node = RunningNode::start(effects.clone(), token.clone()).await;

    let store = MemoryLifecycleStore::new(node.endpoint.as_str().to_owned());
    let ingress = MemoryIngress::new(effects.clone(), Arc::clone(&trace));
    let wire_client = SemanticNodedClient::new(token, SemanticNodedClientConfig::default())
        .expect("semantic noded client");
    let adapter = SemanticNodedLifecycleAdapter::with_call_deadline(
        wire_client.clone(),
        Duration::from_secs(1),
    )
    .expect("semantic lifecycle adapter");
    let service =
        SemanticLifecycleService::new(store.clone(), adapter, ingress.clone(), test_timeouts());
    let selector = CatSelector::Id(CAT_ID.to_owned());

    let created = service
        .create(create_request())
        .await
        .expect("create through real HTTP");
    assert_outcome(&created, OutcomeStatus::Ok, ControlState::Running);
    assert_ingress(&ingress, true);
    let repeated = service
        .create(create_request())
        .await
        .expect("repeat create");
    assert_outcome(
        &repeated,
        OutcomeStatus::AlreadyExists,
        ControlState::Running,
    );
    assert_ingress(&ingress, true);

    let suspended = service
        .suspend(selector.clone())
        .await
        .expect("suspend through real HTTP");
    assert_outcome(&suspended, OutcomeStatus::Ok, ControlState::Suspended);
    assert_ingress(&ingress, false);
    let repeated = service
        .suspend(selector.clone())
        .await
        .expect("repeat suspend");
    assert_outcome(
        &repeated,
        OutcomeStatus::AlreadyDone,
        ControlState::Suspended,
    );
    assert_ingress(&ingress, false);

    let running = service
        .run(selector.clone())
        .await
        .expect("run suspended Cat through real HTTP");
    assert_outcome(&running, OutcomeStatus::Ok, ControlState::Running);
    assert_ingress(&ingress, true);
    let repeated = service.run(selector.clone()).await.expect("repeat run");
    assert_outcome(&repeated, OutcomeStatus::AlreadyDone, ControlState::Running);
    assert_ingress(&ingress, true);

    let warm = service
        .warm(selector.clone())
        .await
        .expect("warm through real HTTP");
    assert_outcome(&warm, OutcomeStatus::Ok, ControlState::Warm);
    assert_ingress(&ingress, false);
    let repeated = service.warm(selector.clone()).await.expect("repeat warm");
    assert_outcome(&repeated, OutcomeStatus::AlreadyDone, ControlState::Warm);
    assert_ingress(&ingress, false);

    let cold = service
        .cold(selector.clone())
        .await
        .expect("cold through real HTTP");
    assert_outcome(&cold, OutcomeStatus::Ok, ControlState::Cold);
    assert_ingress(&ingress, false);
    let repeated = service.cold(selector.clone()).await.expect("repeat cold");
    assert_outcome(&repeated, OutcomeStatus::AlreadyDone, ControlState::Cold);
    assert_ingress(&ingress, false);

    let running = service
        .run(selector.clone())
        .await
        .expect("run cold Cat through real HTTP");
    assert_outcome(&running, OutcomeStatus::Ok, ControlState::Running);
    assert_ingress(&ingress, true);
    let repeated = service
        .run(selector.clone())
        .await
        .expect("repeat second run");
    assert_outcome(&repeated, OutcomeStatus::AlreadyDone, ControlState::Running);
    assert_ingress(&ingress, true);

    let destroyed = service
        .destroy(selector.clone())
        .await
        .expect("destroy through real HTTP");
    assert_outcome(&destroyed, OutcomeStatus::Ok, ControlState::Destroyed);
    assert_ingress(&ingress, false);
    let repeated = service.destroy(selector).await.expect("repeat destroy");
    assert_outcome(
        &repeated,
        OutcomeStatus::AlreadyDone,
        ControlState::Destroyed,
    );
    assert_ingress(&ingress, false);

    assert_eq!(store.cat().state, Some(ControlState::Destroyed));
    let node_view = wire_client
        .get_cat(
            &node.endpoint,
            &Id::new(CAT_ID).expect("Cat ID"),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("read destroyed marker over HTTP");
    assert_eq!(node_view.state, Some(NodeState::Destroyed));

    let requests = effects.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.action)
            .collect::<Vec<_>>(),
        [
            NodeAction::Create,
            NodeAction::Suspend,
            NodeAction::Run,
            NodeAction::Warm,
            NodeAction::Cold,
            NodeAction::Run,
            NodeAction::Destroy,
        ]
    );
    assert!(requests
        .windows(2)
        .all(|pair| pair[0].config == pair[1].config));
    assert_eq!(
        *trace.lock().expect("vertical trace"),
        [
            "effect:create",
            "publish:cat_01@node_01",
            "withdraw:cat_01@node_01",
            "effect:suspend",
            "effect:run",
            "publish:cat_01@node_01",
            "withdraw:cat_01@node_01",
            "effect:warm",
            "effect:cold",
            "effect:run",
            "publish:cat_01@node_01",
            "withdraw:cat_01@node_01",
            "effect:destroy",
        ]
    );

    node.stop().await;
}

#[tokio::test]
async fn semantic_destroy_preempts_an_in_progress_create_over_http() {
    let effects = BlockingCreateEffects::default();
    let token =
        NodedServiceToken::new("destroy-preemption-token-00000001").expect("valid service token");
    let node = RunningNode::start(effects.clone(), token.clone()).await;
    let store = MemoryLifecycleStore::new(node.endpoint.as_str().to_owned());
    let ingress_effects = ControlledFakeEffects::new(Arc::new(Mutex::new(Vec::new())));
    let ingress = MemoryIngress::new(ingress_effects, Arc::new(Mutex::new(Vec::new())));
    let wire_client = SemanticNodedClient::new(token, SemanticNodedClientConfig::default())
        .expect("semantic noded client");
    let adapter =
        SemanticNodedLifecycleAdapter::with_call_deadline(wire_client, Duration::from_secs(1))
            .expect("semantic lifecycle adapter");
    let service = Arc::new(SemanticLifecycleService::new(
        store.clone(),
        adapter,
        ingress,
        test_timeouts(),
    ));

    let create_service = Arc::clone(&service);
    let create = tokio::spawn(async move { create_service.create(create_request()).await });
    tokio::time::timeout(Duration::from_secs(1), effects.wait_for_create())
        .await
        .expect("create reaches the blocking physical effect");

    let destroyed = service
        .destroy(CatSelector::Id(CAT_ID.to_owned()))
        .await
        .expect("destroy preempts create");
    assert_outcome(&destroyed, OutcomeStatus::Ok, ControlState::Destroyed);
    assert!(matches!(
        create.await.expect("create task joins"),
        Err(cats_control_plane::semantic_lifecycle::LifecycleError::Store(_))
    ));
    assert_eq!(effects.actions(), [NodeAction::Create, NodeAction::Destroy]);
    assert_eq!(store.cat().state, Some(ControlState::Destroyed));

    node.stop().await;
}

#[tokio::test]
async fn offline_recovery_allows_a_bounded_double_run_then_source_reset_converges() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let source_effects = ControlledFakeEffects::new(Arc::clone(&trace));
    let target_effects = ControlledFakeEffects::new(Arc::clone(&trace));
    let token =
        NodedServiceToken::new("dual-node-test-service-token-000001").expect("valid service token");
    let source = RunningNode::start(source_effects.clone(), token.clone()).await;
    let target = RunningNode::start(target_effects.clone(), token.clone()).await;
    let wire_client = SemanticNodedClient::new(token, SemanticNodedClientConfig::default())
        .expect("semantic noded client");

    wire_client
        .create_cat(
            &source.endpoint,
            &Id::new(CAT_ID).expect("Cat ID"),
            &noded_config(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("source Cat starts");
    assert_eq!(
        source_effects.physical_state(CAT_ID),
        Some(NodeState::Running)
    );

    let store = MemoryRecoveryStore::new(target.endpoint.as_str().to_owned());
    let ingress = MemoryIngress::new(target_effects.clone(), Arc::clone(&trace));
    ingress.set_target(CAT_ID, "node_source");
    let adapter = SemanticNodedLifecycleAdapter::with_call_deadline(
        wire_client.clone(),
        Duration::from_secs(1),
    )
    .expect("semantic recovery adapter");
    let recovery = SemanticNodeRecoveryService::new(
        store.clone(),
        adapter,
        ingress.clone(),
        RecoveryTimeouts {
            node_request: Duration::from_secs(1),
            retry_count: 0,
            retry_interval: Duration::ZERO,
        },
    );
    let report = recovery
        .recover_offline_node("node_source")
        .await
        .expect("recover offline source");
    assert_eq!(
        report.cats[0].status,
        CatRecoveryStatus::Recovered {
            target_node_id: "node_target".to_owned(),
            state: ControlState::Running,
        }
    );
    assert_eq!(
        ingress.target(),
        Some((CAT_ID.to_owned(), "node_target".to_owned()))
    );
    assert_eq!(store.cat().node_id.as_deref(), Some("node_target"));

    // The accepted heartbeat design permits this short interval. New ingress
    // already points only to the target, but both physical copies can exist
    // until the returned source is commanded through registration reset.
    assert_eq!(
        source_effects.physical_state(CAT_ID),
        Some(NodeState::Running)
    );
    assert_eq!(
        target_effects.physical_state(CAT_ID),
        Some(NodeState::Running)
    );
    source
        .service
        .reset_all()
        .await
        .expect("returning source reset");
    assert_eq!(source_effects.physical_state(CAT_ID), None);
    assert_eq!(
        target_effects.physical_state(CAT_ID),
        Some(NodeState::Running)
    );
    let source_list = wire_client
        .list_cats(&source.endpoint, Instant::now() + Duration::from_secs(1))
        .await
        .expect("source list after reset");
    assert!(source_list.cats.is_empty());

    {
        let events = trace.lock().expect("vertical trace");
        let withdraw = events
            .iter()
            .position(|event| event == "withdraw:cat_01@node_source")
            .expect("ingress withdraw");
        let target_run = events
            .iter()
            .rposition(|event| event == "effect:run")
            .expect("target run");
        let publish = events
            .iter()
            .position(|event| event == "publish:cat_01@node_target")
            .expect("target publish");
        let reset = events
            .iter()
            .position(|event| event == "effect:reset")
            .expect("source reset");
        assert!(withdraw < target_run && target_run < publish && publish < reset);
    }

    source.stop().await;
    target.stop().await;
}

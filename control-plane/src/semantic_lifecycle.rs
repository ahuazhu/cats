//! Synchronous, scenario-idempotent Cat lifecycle coordination.
//!
//! This module is deliberately independent from the former durable command
//! model.  A store implementation atomically claims `current_action`, returns
//! from its transaction, and only then does this service contact `noded`.
//! Repeated calls are classified from the current Cat and requested target;
//! there is no caller request ID or separate operation resource.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};

/// Boxed future used by the persistence and noded integration ports.
pub type SemanticFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Stable Cat states exposed by the synchronous protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatState {
    Running,
    Suspended,
    Warm,
    Cold,
    Failure,
    Destroyed,
}

/// Product lifecycle actions. Each action has one semantic target state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatAction {
    Create,
    Run,
    Suspend,
    Warm,
    Cold,
    Destroy,
}

impl CatAction {
    /// Stable target of this action.
    pub const fn target(self) -> CatState {
        match self {
            Self::Create | Self::Run => CatState::Running,
            Self::Suspend => CatState::Suspended,
            Self::Warm => CatState::Warm,
            Self::Cold => CatState::Cold,
            Self::Destroy => CatState::Destroyed,
        }
    }

    pub const fn already_code(self) -> &'static str {
        match self {
            Self::Create => "already_exists",
            Self::Run => "already_running",
            Self::Suspend => "already_suspended",
            Self::Warm => "already_warm",
            Self::Cold => "already_cold",
            Self::Destroy => "already_destroyed",
        }
    }

    fn success_code(self) -> &'static str {
        match self {
            Self::Create => "cat_created",
            Self::Run => "cat_running",
            Self::Suspend => "cat_suspended",
            Self::Warm => "cat_warm",
            Self::Cold => "cat_cold",
            Self::Destroy => "cat_destroyed",
        }
    }
}

/// One persistent-disk mount in the immutable Cat create configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CatMount {
    pub disk_id: String,
    pub volume_id: String,
    pub filesystem_uuid: String,
    pub disk_format: String,
    pub mount_path: String,
}

/// Configuration whose equality defines a repeated Cat create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatCreateConfig {
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub boot_image: String,
    pub mounts: Vec<CatMount>,
}

impl CatCreateConfig {
    /// Compares create configuration without treating mount order as meaning.
    pub fn semantically_matches(&self, other: &Self) -> bool {
        self.cpu_count == other.cpu_count
            && self.memory_bytes == other.memory_bytes
            && self.boot_image == other.boot_image
            && sorted_mounts(&self.mounts) == sorted_mounts(&other.mounts)
    }
}

fn sorted_mounts(mounts: &[CatMount]) -> Vec<&CatMount> {
    let mut mounts = mounts.iter().collect::<Vec<_>>();
    mounts.sort_unstable();
    mounts
}

/// Workspace-scoped Cat create request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCatRequest {
    pub workspace_id: String,
    pub cat_slug: String,
    pub config: CatCreateConfig,
}

/// A current Cat row as seen by the semantic lifecycle service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatRecord {
    pub cat_id: String,
    pub workspace_id: String,
    pub cat_slug: String,
    /// `None` is permitted only while the first create is unresolved.
    pub state: Option<CatState>,
    pub current_action: Option<CatAction>,
    pub current_action_node_id: Option<String>,
    pub node_id: Option<String>,
    pub config: CatCreateConfig,
}

/// Cat identity accepted by lifecycle actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatSelector {
    Id(String),
    Slug {
        workspace_id: String,
        cat_slug: String,
    },
}

/// Pure create classification shared by Store implementations and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateDecision {
    Insert,
    AlreadyExists,
    SameAction,
    Busy,
    ConfigurationConflict,
}

/// Classifies a create from current product state. The Store must repeat this
/// decision while holding the slug uniqueness/row lock before inserting or
/// claiming anything.
pub fn classify_create(existing: Option<&CatRecord>, request: &CreateCatRequest) -> CreateDecision {
    let Some(cat) = existing else {
        return CreateDecision::Insert;
    };
    if !cat.config.semantically_matches(&request.config) {
        return CreateDecision::ConfigurationConflict;
    }
    match cat.current_action {
        Some(CatAction::Create) => CreateDecision::SameAction,
        Some(_) => CreateDecision::Busy,
        None => CreateDecision::AlreadyExists,
    }
}

/// Pure state-action classification shared by Store implementations and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDecision {
    Claim,
    AlreadyDone,
    SameAction,
    Busy,
    InvalidState,
}

/// Classifies an action from a locked Cat row.
pub fn classify_action(cat: &CatRecord, action: CatAction) -> ActionDecision {
    if cat.state == Some(action.target()) {
        return ActionDecision::AlreadyDone;
    }
    match cat.current_action {
        Some(current) if current == action => return ActionDecision::SameAction,
        Some(_) if action != CatAction::Destroy => return ActionDecision::Busy,
        // Destroy is the one product action allowed to replace an unresolved
        // action. The Store must preserve that action's selected Node so noded
        // can cancel it and clean the same physical execution lane.
        Some(_) => {}
        None => {}
    }
    let allowed = match action {
        CatAction::Create => false,
        CatAction::Run => matches!(
            cat.state,
            Some(CatState::Suspended | CatState::Warm | CatState::Cold)
        ),
        CatAction::Suspend => cat.state == Some(CatState::Running),
        CatAction::Warm => matches!(cat.state, Some(CatState::Running | CatState::Suspended)),
        CatAction::Cold => matches!(
            cat.state,
            Some(CatState::Running | CatState::Suspended | CatState::Warm)
        ),
        CatAction::Destroy => cat.state != Some(CatState::Destroyed),
    };
    if allowed {
        ActionDecision::Claim
    } else {
        ActionDecision::InvalidState
    }
}

/// A transactionally claimed action. The database-assigned start time is part
/// of the identity so a late recovery cannot settle a later occurrence of the
/// same Cat/action/Node tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionClaim {
    pub cat: CatRecord,
    pub action: CatAction,
    pub started_at_unix_ms: i64,
    pub node_id: Option<String>,
}

/// Atomic admission result returned after the Store transaction has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Claimed(ActionClaim),
    SameAction(ActionClaim),
    Already { cat: CatRecord, code: &'static str },
    Busy(CatRecord),
    Conflict { cat: CatRecord, code: &'static str },
    InvalidState(CatRecord),
    NotFound,
    Rejected { code: String, message: String },
}

/// Store integration failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub message: String,
}

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// A validated noded control address loaded from `nodes.control_endpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeControlEndpoint(String);

impl NodeControlEndpoint {
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty() {
            return Err(StoreError::new("Node control endpoint is empty"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Persistence boundary for the synchronous protocol.
///
/// `admit_create` and `admit_action` must decide and claim atomically. They
/// must not return `Claimed` until `current_action` and
/// `current_action_node_id` have committed. Conversely, none of these methods
/// may perform an noded network request. `complete_action` and `fail_action`
/// update only when the row still has the exact claimed action and Node.
pub trait SemanticLifecycleStore: Send + Sync {
    fn admit_create<'a>(
        &'a self,
        request: &'a CreateCatRequest,
    ) -> SemanticFuture<'a, Result<Admission, StoreError>>;

    fn admit_action<'a>(
        &'a self,
        selector: &'a CatSelector,
        action: CatAction,
    ) -> SemanticFuture<'a, Result<Admission, StoreError>>;

    /// Returns a bounded snapshot of committed Destroy claims old enough not
    /// to belong exclusively to a still-running admission request. The rows
    /// remain authoritative only while their exact action and Node still
    /// match during settlement.
    fn pending_destroy_claims<'a>(
        &'a self,
        minimum_age: Duration,
        limit: usize,
    ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>>;

    /// Moves a failed recovery attempt behind older untried Destroy claims.
    /// The update must match the exact current Destroy occurrence and Node; a
    /// stale recovery attempt is a successful no-op.
    fn rotate_pending_destroy<'a>(
        &'a self,
        claim: &'a ActionClaim,
    ) -> SemanticFuture<'a, Result<bool, StoreError>>;

    /// Resolves `nodes.control_endpoint` after admission has committed.
    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> SemanticFuture<'a, Result<NodeControlEndpoint, StoreError>>;

    fn complete_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
        resulting_state: CatState,
    ) -> SemanticFuture<'a, Result<CatRecord, StoreError>>;

    fn fail_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
        code: &'a str,
        message: &'a str,
    ) -> SemanticFuture<'a, Result<CatRecord, StoreError>>;
}

/// Persistence discovery used only by the level-triggered stale-action
/// recovery worker. Implementations must use database time for the age test.
pub trait SemanticActionRecoveryStore: SemanticLifecycleStore {
    fn stale_actions<'a>(
        &'a self,
        stale_after: Duration,
        limit: usize,
    ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>>;

    /// Moves an unresolved ordinary action behind older untried claims. The
    /// update must match the exact action occurrence and selected Node; a
    /// stale recovery attempt is a successful no-op.
    fn rotate_stale_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
    ) -> SemanticFuture<'a, Result<bool, StoreError>>;
}

/// Exact command sent synchronously to noded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCommand {
    pub cat_id: String,
    pub workspace_id: String,
    pub action: CatAction,
    /// Create and run carry the complete desired Cat configuration. Other
    /// actions operate on the already-known local Cat.
    pub config: Option<CatCreateConfig>,
}

impl NodeCommand {
    fn from_claim(claim: &ActionClaim) -> Self {
        Self {
            cat_id: claim.cat.cat_id.clone(),
            workspace_id: claim.cat.workspace_id.clone(),
            action: claim.action,
            config: matches!(claim.action, CatAction::Create | CatAction::Run)
                .then(|| claim.cat.config.clone()),
        }
    }
}

/// Successful or definite terminal noded response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCommandResult {
    Succeeded(CatState),
    AlreadyDone(CatState),
    Failed { code: String, message: String },
    Busy,
    Conflict { code: String, message: String },
}

/// Current noded knowledge used after an ambiguous call or Control restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCatStatus {
    Absent,
    Present {
        /// `None` is valid while the first Create effect is still in
        /// progress. It is not a terminal state and cannot satisfy recovery.
        state: Option<CatState>,
        active_action: Option<CatAction>,
    },
    Failed {
        code: String,
        message: String,
    },
}

/// Transport error. A timeout remains ambiguous and is always followed by
/// noded state discovery before Control writes a terminal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeClientError {
    Timeout,
    Unavailable(String),
    Protocol(String),
}

/// HTTP integration boundary. The implementation owns shared Bearer service
/// authentication and maps the supplied endpoint onto the noded routes.
pub trait NodedClient: Send + Sync {
    fn execute<'a>(
        &'a self,
        endpoint: &'a NodeControlEndpoint,
        command: &'a NodeCommand,
    ) -> SemanticFuture<'a, Result<NodeCommandResult, NodeClientError>>;

    fn inspect<'a>(
        &'a self,
        endpoint: &'a NodeControlEndpoint,
        cat_id: &'a str,
    ) -> SemanticFuture<'a, Result<NodeCatStatus, NodeClientError>>;
}

/// Unique-ingress update failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressError {
    pub message: String,
}

impl IngressError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Traffic-entry boundary shared by ordinary lifecycle and cross-Node
/// recovery. Both methods must be scenario-idempotent.
///
/// Leaving Running (including moving a still-running Cat to another Node)
/// withdraws the old target before any physical Node action. Create/run only
/// publish after noded has reported the new instance Running.
pub trait IngressPort: Send + Sync {
    fn withdraw<'a>(
        &'a self,
        cat_id: &'a str,
        old_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>>;

    fn publish<'a>(
        &'a self,
        cat_id: &'a str,
        new_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>>;
}

/// Bounded retry and recovery policy for one synchronous API request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleTimeouts {
    pub total: Duration,
    pub node_request: Duration,
    /// Additional attempts after the first call.
    pub retry_count: usize,
    pub retry_interval: Duration,
    pub recovery_poll_interval: Duration,
    pub create_cleanup: Duration,
}

impl Default for LifecycleTimeouts {
    fn default() -> Self {
        Self {
            total: Duration::from_secs(120),
            node_request: Duration::from_secs(30),
            retry_count: 2,
            retry_interval: Duration::from_millis(250),
            recovery_poll_interval: Duration::from_millis(250),
            create_cleanup: Duration::from_secs(10),
        }
    }
}

/// Whether this request performed work or found its semantic target satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeStatus {
    Ok,
    AlreadyDone,
    AlreadyExists,
}

/// Successful product response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleOutcome {
    pub status: OutcomeStatus,
    pub code: &'static str,
    pub cat: CatRecord,
}

/// Product-semantic or infrastructure failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    Store(StoreError),
    NotFound,
    Busy(CatRecord),
    Conflict {
        cat: CatRecord,
        code: &'static str,
    },
    InvalidState(CatRecord),
    Failed {
        cat: CatRecord,
        code: String,
        message: String,
    },
    Timeout {
        cat: CatRecord,
    },
    Rejected {
        code: String,
        message: String,
    },
}

impl From<StoreError> for LifecycleError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// Orchestrates one synchronous Control-to-noded lifecycle action.
#[derive(Clone)]
pub struct SemanticLifecycleService<S, N, I> {
    store: S,
    noded: N,
    ingress: I,
    timeouts: LifecycleTimeouts,
}

/// A lifecycle action becomes eligible for recovery after the foreground
/// request's 120-second deadline plus a five-second scheduling margin. This
/// is deliberately independent from heartbeat age: the scanner confirms the
/// exact Cat state with noded before settlement.
pub const DEFAULT_STALE_ACTION_AGE: Duration = Duration::from_secs(125);
pub const DEFAULT_ACTION_RECOVERY_SCAN_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_ACTION_RECOVERY_BATCH_SIZE: usize = 64;
pub const DEFAULT_ACTION_RECOVERY_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRecoveryPolicy {
    pub stale_after: Duration,
    pub scan_interval: Duration,
    pub batch_size: usize,
    pub concurrency: usize,
}

impl Default for ActionRecoveryPolicy {
    fn default() -> Self {
        Self {
            stale_after: DEFAULT_STALE_ACTION_AGE,
            scan_interval: DEFAULT_ACTION_RECOVERY_SCAN_INTERVAL,
            batch_size: DEFAULT_ACTION_RECOVERY_BATCH_SIZE,
            concurrency: DEFAULT_ACTION_RECOVERY_CONCURRENCY,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActionRecoveryReport {
    pub discovered: usize,
    pub settled: usize,
    pub unresolved: usize,
}

impl<S, N, I> SemanticLifecycleService<S, N, I>
where
    S: SemanticLifecycleStore,
    N: NodedClient,
    I: IngressPort,
{
    pub fn new(store: S, noded: N, ingress: I, timeouts: LifecycleTimeouts) -> Self {
        Self {
            store,
            noded,
            ingress,
            timeouts,
        }
    }

    pub async fn create(
        &self,
        request: CreateCatRequest,
    ) -> Result<LifecycleOutcome, LifecycleError> {
        let admission = self.store.admit_create(&request).await?;
        self.handle_admission(admission).await
    }

    pub async fn run(&self, selector: CatSelector) -> Result<LifecycleOutcome, LifecycleError> {
        self.action(selector, CatAction::Run).await
    }

    pub async fn suspend(&self, selector: CatSelector) -> Result<LifecycleOutcome, LifecycleError> {
        self.action(selector, CatAction::Suspend).await
    }

    pub async fn warm(&self, selector: CatSelector) -> Result<LifecycleOutcome, LifecycleError> {
        self.action(selector, CatAction::Warm).await
    }

    pub async fn cold(&self, selector: CatSelector) -> Result<LifecycleOutcome, LifecycleError> {
        self.action(selector, CatAction::Cold).await
    }

    pub async fn destroy(&self, selector: CatSelector) -> Result<LifecycleOutcome, LifecycleError> {
        self.action(selector, CatAction::Destroy).await
    }

    /// Resumes a committed `current_action` found by a recovery scanner.
    /// The service discovers noded state before deciding whether the exact
    /// semantic command still needs to be sent.
    pub async fn resume(&self, claim: ActionClaim) -> Result<LifecycleOutcome, LifecycleError> {
        self.drive_claim(claim, true).await
    }

    /// Recovers a bounded batch of Destroy claims that survived their
    /// admitting Control request. Multiple claims are driven concurrently,
    /// but each retains the normal discovery-first and exact-settlement
    /// semantics.
    pub async fn recover_pending_destroys(
        &self,
        minimum_age: Duration,
        limit: usize,
        max_in_flight: usize,
    ) -> Result<PendingDestroyRecoveryReport, StoreError> {
        if limit == 0 {
            return Ok(PendingDestroyRecoveryReport::default());
        }
        let claims = self
            .store
            .pending_destroy_claims(minimum_age, limit)
            .await?;
        let discovered = claims.len();
        let results = stream::iter(claims)
            .map(|claim| async move {
                let cat_id = claim.cat.cat_id.clone();
                let recovery_claim = claim.clone();
                let result = self.resume(claim).await;
                let rotation = if result.is_err() {
                    Some(self.store.rotate_pending_destroy(&recovery_claim).await)
                } else {
                    None
                };
                (cat_id, result, rotation)
            })
            .buffer_unordered(max_in_flight.max(1))
            .collect::<Vec<_>>()
            .await;

        let mut report = PendingDestroyRecoveryReport {
            discovered,
            ..PendingDestroyRecoveryReport::default()
        };
        for (cat_id, result, rotation) in results {
            match result {
                Ok(_) => report.completed += 1,
                Err(error) => {
                    report.failed += 1;
                    tracing::warn!(%cat_id, ?error, "pending Destroy recovery failed");
                    if let Some(Err(rotation_error)) = rotation {
                        tracing::warn!(
                            %cat_id,
                            ?rotation_error,
                            "failed Destroy recovery could not be rotated"
                        );
                    }
                }
            }
        }
        Ok(report)
    }

    async fn action(
        &self,
        selector: CatSelector,
        action: CatAction,
    ) -> Result<LifecycleOutcome, LifecycleError> {
        let admission = self.store.admit_action(&selector, action).await?;
        self.handle_admission(admission).await
    }

    async fn handle_admission(
        &self,
        admission: Admission,
    ) -> Result<LifecycleOutcome, LifecycleError> {
        match admission {
            Admission::Claimed(claim) => self.drive_claim(claim, false).await,
            Admission::SameAction(claim) => self.drive_claim(claim, true).await,
            Admission::Already { cat, code } => Ok(LifecycleOutcome {
                status: if code == "already_exists" {
                    OutcomeStatus::AlreadyExists
                } else {
                    OutcomeStatus::AlreadyDone
                },
                code,
                cat,
            }),
            Admission::Busy(cat) => Err(LifecycleError::Busy(cat)),
            Admission::Conflict { cat, code } => Err(LifecycleError::Conflict { cat, code }),
            Admission::InvalidState(cat) => Err(LifecycleError::InvalidState(cat)),
            Admission::NotFound => Err(LifecycleError::NotFound),
            Admission::Rejected { code, message } => {
                Err(LifecycleError::Rejected { code, message })
            }
        }
    }

    async fn drive_claim(
        &self,
        claim: ActionClaim,
        recover_first: bool,
    ) -> Result<LifecycleOutcome, LifecycleError> {
        if claim.action.target() != CatState::Destroyed && claim.node_id.is_none() {
            return self
                .fail(
                    &claim,
                    "node_unavailable",
                    "claimed action has no selected Node",
                )
                .await;
        }
        if claim.action == CatAction::Destroy && claim.node_id.is_none() {
            return self.complete(&claim, CatState::Destroyed).await;
        }

        if let Some(old_node_id) = self.withdraw_target(&claim) {
            if let Err(error) = self.ingress.withdraw(&claim.cat.cat_id, old_node_id).await {
                return self
                    .fail(&claim, "ingress_withdraw_failed", &error.message)
                    .await;
            }
        }

        let deadline = Instant::now() + self.timeouts.total;
        let node_id = claim.node_id.as_deref().expect("Node checked above");

        if recover_first {
            match self.discover(&claim, node_id, deadline).await? {
                Discovery::Complete(state) => return self.complete(&claim, state).await,
                Discovery::Failed { code, message } => {
                    return self.fail(&claim, &code, &message).await;
                }
                Discovery::Execute => {}
                Discovery::TimedOut => return self.timeout(&claim).await,
            }
        }

        let command = NodeCommand::from_claim(&claim);
        let mut last_transport = NodeClientError::Timeout;
        for attempt in 0..=self.timeouts.retry_count {
            if Instant::now() >= deadline {
                break;
            }
            // A Node may explicitly re-register a changed control endpoint.
            // Resolve immediately before every network call; never retain the
            // endpoint as part of the Node's immutable identity.
            let endpoint = self.store.node_control_endpoint(node_id).await?;
            match self.execute_once(&endpoint, &command, deadline).await {
                Ok(NodeCommandResult::Succeeded(state) | NodeCommandResult::AlreadyDone(state)) => {
                    if state != claim.action.target() {
                        return self
                            .fail(
                                &claim,
                                "node_protocol_error",
                                "noded returned success without the requested target state",
                            )
                            .await;
                    }
                    return self.complete(&claim, state).await;
                }
                Ok(
                    NodeCommandResult::Failed { code, message }
                    | NodeCommandResult::Conflict { code, message },
                ) => {
                    return self.fail(&claim, &code, &message).await;
                }
                Ok(NodeCommandResult::Busy) => {
                    match self.discover(&claim, node_id, deadline).await? {
                        Discovery::Complete(state) => return self.complete(&claim, state).await,
                        Discovery::Failed { code, message } => {
                            return self.fail(&claim, &code, &message).await;
                        }
                        Discovery::Execute => {}
                        Discovery::TimedOut => return self.timeout(&claim).await,
                    }
                }
                Err(error) => last_transport = error,
            }
            if attempt < self.timeouts.retry_count
                && !sleep_until(self.timeouts.retry_interval, deadline).await
            {
                break;
            }
        }

        match self.discover(&claim, node_id, deadline).await? {
            Discovery::Complete(state) => self.complete(&claim, state).await,
            Discovery::Failed { code, message } => self.fail(&claim, &code, &message).await,
            Discovery::Execute | Discovery::TimedOut => {
                if claim.action == CatAction::Create {
                    self.cleanup_failed_create(&claim, node_id).await;
                }
                match last_transport {
                    NodeClientError::Protocol(message) => {
                        self.fail(&claim, "node_protocol_error", &message).await
                    }
                    NodeClientError::Unavailable(message) => {
                        self.fail(&claim, "node_unavailable", &message).await
                    }
                    NodeClientError::Timeout => self.timeout(&claim).await,
                }
            }
        }
    }

    async fn execute_once(
        &self,
        endpoint: &NodeControlEndpoint,
        command: &NodeCommand,
        deadline: Instant,
    ) -> Result<NodeCommandResult, NodeClientError> {
        let Some(timeout) = bounded_timeout(self.timeouts.node_request, deadline) else {
            return Err(NodeClientError::Timeout);
        };
        match tokio::time::timeout(timeout, self.noded.execute(endpoint, command)).await {
            Ok(result) => result,
            Err(_) => Err(NodeClientError::Timeout),
        }
    }

    async fn inspect_once(
        &self,
        endpoint: &NodeControlEndpoint,
        cat_id: &str,
        deadline: Instant,
    ) -> Result<NodeCatStatus, NodeClientError> {
        let Some(timeout) = bounded_timeout(self.timeouts.node_request, deadline) else {
            return Err(NodeClientError::Timeout);
        };
        match tokio::time::timeout(timeout, self.noded.inspect(endpoint, cat_id)).await {
            Ok(result) => result,
            Err(_) => Err(NodeClientError::Timeout),
        }
    }

    async fn discover(
        &self,
        claim: &ActionClaim,
        node_id: &str,
        deadline: Instant,
    ) -> Result<Discovery, LifecycleError> {
        loop {
            if Instant::now() >= deadline {
                return Ok(Discovery::TimedOut);
            }
            let endpoint = self.store.node_control_endpoint(node_id).await?;
            match self
                .inspect_once(&endpoint, &claim.cat.cat_id, deadline)
                .await
            {
                Ok(NodeCatStatus::Absent) if claim.action == CatAction::Destroy => {
                    return Ok(Discovery::Complete(CatState::Destroyed));
                }
                Ok(NodeCatStatus::Absent) => return Ok(Discovery::Execute),
                Ok(NodeCatStatus::Present { state, .. })
                    if state == Some(claim.action.target()) =>
                {
                    return Ok(Discovery::Complete(claim.action.target()));
                }
                Ok(NodeCatStatus::Present {
                    active_action: Some(action),
                    ..
                }) if action == claim.action => {
                    if !sleep_until(self.timeouts.recovery_poll_interval, deadline).await {
                        return Ok(Discovery::TimedOut);
                    }
                }
                Ok(NodeCatStatus::Present {
                    active_action: Some(_),
                    ..
                }) if claim.action == CatAction::Destroy => return Ok(Discovery::Execute),
                Ok(NodeCatStatus::Present {
                    active_action: Some(_),
                    ..
                }) => {
                    return Ok(Discovery::Failed {
                        code: "node_busy".to_owned(),
                        message: "noded is executing a different action for this Cat".to_owned(),
                    });
                }
                Ok(NodeCatStatus::Present {
                    active_action: None,
                    ..
                }) => return Ok(Discovery::Execute),
                Ok(NodeCatStatus::Failed { code, message }) => {
                    return Ok(Discovery::Failed { code, message });
                }
                Err(NodeClientError::Protocol(message)) => {
                    return Ok(Discovery::Failed {
                        code: "node_protocol_error".to_owned(),
                        message,
                    });
                }
                Err(NodeClientError::Timeout | NodeClientError::Unavailable(_)) => {
                    if !sleep_until(self.timeouts.recovery_poll_interval, deadline).await {
                        return Ok(Discovery::TimedOut);
                    }
                }
            }
        }
    }

    async fn cleanup_failed_create(&self, claim: &ActionClaim, node_id: &str) {
        let Ok(endpoint) = self.store.node_control_endpoint(node_id).await else {
            return;
        };
        let cleanup = NodeCommand {
            cat_id: claim.cat.cat_id.clone(),
            workspace_id: claim.cat.workspace_id.clone(),
            action: CatAction::Destroy,
            config: None,
        };
        let _ = tokio::time::timeout(
            self.timeouts.create_cleanup,
            self.noded.execute(&endpoint, &cleanup),
        )
        .await;
    }

    async fn complete(
        &self,
        claim: &ActionClaim,
        state: CatState,
    ) -> Result<LifecycleOutcome, LifecycleError> {
        if state == CatState::Running {
            let Some(node_id) = claim.node_id.as_deref() else {
                return self
                    .fail(
                        claim,
                        "node_unavailable",
                        "Running result has no selected Node",
                    )
                    .await;
            };
            if let Err(error) = self.ingress.publish(&claim.cat.cat_id, node_id).await {
                return self
                    .fail(claim, "ingress_publish_failed", &error.message)
                    .await;
            }
        }
        let cat = self.store.complete_action(claim, state).await?;
        Ok(LifecycleOutcome {
            status: OutcomeStatus::Ok,
            code: claim.action.success_code(),
            cat,
        })
    }

    async fn fail(
        &self,
        claim: &ActionClaim,
        code: &str,
        message: &str,
    ) -> Result<LifecycleOutcome, LifecycleError> {
        let cat = self.store.fail_action(claim, code, message).await?;
        Err(LifecycleError::Failed {
            cat,
            code: code.to_owned(),
            message: message.to_owned(),
        })
    }

    async fn timeout(&self, claim: &ActionClaim) -> Result<LifecycleOutcome, LifecycleError> {
        let cat = self
            .store
            .fail_action(claim, "timeout", "noded action timed out")
            .await?;
        Err(LifecycleError::Timeout { cat })
    }

    fn withdraw_target<'a>(&self, claim: &'a ActionClaim) -> Option<&'a str> {
        let old_node_id = claim.cat.node_id.as_deref()?;
        let leaves_running = claim.cat.state == Some(CatState::Running)
            && claim.action != CatAction::Create
            && !(claim.action == CatAction::Run && claim.node_id.as_deref() == Some(old_node_id));
        let changes_node = claim.node_id.as_deref().is_some_and(|new_node_id| {
            new_node_id != old_node_id && claim.action == CatAction::Run
        });
        (leaves_running || changes_node).then_some(old_node_id)
    }
}

impl<S, N, I> SemanticLifecycleService<S, N, I>
where
    S: SemanticActionRecoveryStore,
    N: NodedClient,
    I: IngressPort,
{
    /// Runs one bounded, concurrent recovery pass. Every claim is discovered
    /// from the current PostgreSQL row and then follows the same `resume`
    /// state machine as a repeated user request.
    pub async fn recover_stale_actions_once(
        &self,
        policy: ActionRecoveryPolicy,
    ) -> Result<ActionRecoveryReport, StoreError> {
        if policy.stale_after.is_zero() || policy.batch_size == 0 || policy.concurrency == 0 {
            return Err(StoreError::new("invalid semantic action recovery policy"));
        }
        let claims = self
            .store
            .stale_actions(policy.stale_after, policy.batch_size)
            .await?;
        let discovered = claims.len();
        let outcomes = stream::iter(claims)
            .map(|claim| async move {
                let cat_id = claim.cat.cat_id.clone();
                let action = claim.action;
                let started_at_unix_ms = claim.started_at_unix_ms;
                let recovery_claim = claim.clone();
                let result = self.resume(claim).await;
                let needs_rotation = !matches!(
                    &result,
                    Ok(_) | Err(LifecycleError::Failed { .. } | LifecycleError::Timeout { .. })
                );
                let rotation = if needs_rotation {
                    Some(self.store.rotate_stale_action(&recovery_claim).await)
                } else {
                    None
                };
                (cat_id, action, started_at_unix_ms, result, rotation)
            })
            .buffer_unordered(policy.concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut report = ActionRecoveryReport {
            discovered,
            ..ActionRecoveryReport::default()
        };
        for (cat_id, action, started_at_unix_ms, result, rotation) in outcomes {
            match result {
                Ok(outcome) => {
                    report.settled += 1;
                    tracing::info!(
                        %cat_id,
                        ?action,
                        started_at_unix_ms,
                        state = ?outcome.cat.state,
                        "stale semantic Cat action recovered"
                    );
                }
                Err(error @ (LifecycleError::Failed { .. } | LifecycleError::Timeout { .. })) => {
                    report.settled += 1;
                    tracing::warn!(
                        %cat_id,
                        ?action,
                        started_at_unix_ms,
                        ?error,
                        "stale semantic Cat action recovered to terminal failure"
                    );
                }
                Err(error) => {
                    report.unresolved += 1;
                    tracing::warn!(
                        %cat_id,
                        ?action,
                        started_at_unix_ms,
                        ?error,
                        "stale semantic Cat action recovery did not settle"
                    );
                    if let Some(Err(rotation_error)) = rotation {
                        tracing::warn!(
                            %cat_id,
                            ?action,
                            started_at_unix_ms,
                            ?rotation_error,
                            "unresolved semantic Cat action could not be rotated"
                        );
                    }
                }
            }
        }
        Ok(report)
    }

    /// Level-triggered recovery loop. Multi-replica exclusion is supplied by
    /// the PostgreSQL singleton wrapper in the composition root.
    pub async fn run_stale_action_recovery(&self, policy: ActionRecoveryPolicy) {
        loop {
            if let Err(error) = self.recover_stale_actions_once(policy).await {
                tracing::warn!(message = %error.message, "stale semantic Cat action scan failed");
            }
            tokio::time::sleep(policy.scan_interval).await;
        }
    }
}

/// Summary of one bounded pending-Destroy recovery pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingDestroyRecoveryReport {
    pub discovered: usize,
    pub completed: usize,
    pub failed: usize,
}

enum Discovery {
    Complete(CatState),
    Failed { code: String, message: String },
    Execute,
    TimedOut,
}

fn bounded_timeout(configured: Duration, deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .map(|remaining| configured.min(remaining))
        .filter(|duration| !duration.is_zero())
}

async fn sleep_until(duration: Duration, deadline: Instant) -> bool {
    if duration.is_zero() {
        tokio::task::yield_now().await;
        return Instant::now() < deadline;
    }
    let Some(duration) = bounded_timeout(duration, deadline) else {
        return false;
    };
    tokio::time::sleep(duration).await;
    Instant::now() < deadline
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct MockStore {
        state: Arc<Mutex<MockStoreState>>,
    }

    struct MockStoreState {
        admissions: VecDeque<Admission>,
        stale_actions: VecDeque<Vec<ActionClaim>>,
        pending_destroy_claims: VecDeque<Vec<ActionClaim>>,
        endpoint_errors: VecDeque<StoreError>,
        cat: CatRecord,
        in_transaction: bool,
        endpoint_reads: usize,
        completions: usize,
        failures: usize,
        rotations: usize,
    }

    impl MockStore {
        fn new(cat: CatRecord, admission: Admission) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockStoreState {
                    admissions: VecDeque::from([admission]),
                    stale_actions: VecDeque::new(),
                    pending_destroy_claims: VecDeque::new(),
                    endpoint_errors: VecDeque::new(),
                    cat,
                    in_transaction: false,
                    endpoint_reads: 0,
                    completions: 0,
                    failures: 0,
                    rotations: 0,
                })),
            }
        }

        fn with_stale_actions(self, claims: Vec<ActionClaim>) -> Self {
            self.state
                .lock()
                .expect("mock store")
                .stale_actions
                .push_back(claims);
            self
        }

        fn queue_pending_destroy(&self, claim: ActionClaim) {
            self.state
                .lock()
                .expect("mock store")
                .pending_destroy_claims
                .push_back(vec![claim]);
        }

        fn queue_endpoint_error(&self, error: StoreError) {
            self.state
                .lock()
                .expect("mock store")
                .endpoint_errors
                .push_back(error);
        }
    }

    impl SemanticLifecycleStore for MockStore {
        fn admit_create<'a>(
            &'a self,
            _request: &'a CreateCatRequest,
        ) -> SemanticFuture<'a, Result<Admission, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                state.in_transaction = true;
                let admission = state.admissions.pop_front().expect("admission");
                state.in_transaction = false;
                Ok(admission)
            })
        }

        fn admit_action<'a>(
            &'a self,
            _selector: &'a CatSelector,
            _action: CatAction,
        ) -> SemanticFuture<'a, Result<Admission, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                state.in_transaction = true;
                let admission = state.admissions.pop_front().expect("admission");
                state.in_transaction = false;
                Ok(admission)
            })
        }

        fn pending_destroy_claims<'a>(
            &'a self,
            _minimum_age: Duration,
            _limit: usize,
        ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("mock store")
                    .pending_destroy_claims
                    .pop_front()
                    .unwrap_or_default())
            })
        }

        fn rotate_pending_destroy<'a>(
            &'a self,
            claim: &'a ActionClaim,
        ) -> SemanticFuture<'a, Result<bool, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                let current = state.cat.current_action == Some(CatAction::Destroy)
                    && state.cat.current_action_node_id == claim.node_id;
                if current {
                    state.rotations += 1;
                }
                Ok(current)
            })
        }

        fn node_control_endpoint<'a>(
            &'a self,
            _node_id: &'a str,
        ) -> SemanticFuture<'a, Result<NodeControlEndpoint, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                assert!(!state.in_transaction, "endpoint read crossed admission tx");
                state.endpoint_reads += 1;
                if let Some(error) = state.endpoint_errors.pop_front() {
                    return Err(error);
                }
                NodeControlEndpoint::new("http://node.test")
            })
        }

        fn complete_action<'a>(
            &'a self,
            claim: &'a ActionClaim,
            resulting_state: CatState,
        ) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                state.completions += 1;
                state.cat.state = Some(resulting_state);
                state.cat.current_action = None;
                state.cat.current_action_node_id = None;
                state.cat.node_id = match resulting_state {
                    CatState::Cold | CatState::Destroyed => None,
                    _ => claim.node_id.clone(),
                };
                Ok(state.cat.clone())
            })
        }

        fn fail_action<'a>(
            &'a self,
            _claim: &'a ActionClaim,
            _code: &'a str,
            _message: &'a str,
        ) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                state.failures += 1;
                state.cat.state = Some(CatState::Failure);
                state.cat.current_action = None;
                state.cat.current_action_node_id = None;
                Ok(state.cat.clone())
            })
        }
    }

    impl SemanticActionRecoveryStore for MockStore {
        fn stale_actions<'a>(
            &'a self,
            _stale_after: Duration,
            _limit: usize,
        ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("mock store")
                    .stale_actions
                    .pop_front()
                    .unwrap_or_default())
            })
        }

        fn rotate_stale_action<'a>(
            &'a self,
            claim: &'a ActionClaim,
        ) -> SemanticFuture<'a, Result<bool, StoreError>> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("mock store");
                let current = state.cat.current_action == Some(claim.action)
                    && state.cat.current_action_node_id == claim.node_id;
                if current {
                    state.rotations += 1;
                }
                Ok(current)
            })
        }
    }

    #[derive(Clone)]
    struct MockNoded {
        store: MockStore,
        state: Arc<Mutex<MockNodedState>>,
    }

    struct MockNodedState {
        execute: VecDeque<Result<NodeCommandResult, NodeClientError>>,
        inspect: VecDeque<Result<NodeCatStatus, NodeClientError>>,
        commands: Vec<NodeCommand>,
        events: Vec<String>,
    }

    impl MockNoded {
        fn new(
            store: MockStore,
            execute: impl IntoIterator<Item = Result<NodeCommandResult, NodeClientError>>,
            inspect: impl IntoIterator<Item = Result<NodeCatStatus, NodeClientError>>,
        ) -> Self {
            Self {
                store,
                state: Arc::new(Mutex::new(MockNodedState {
                    execute: execute.into_iter().collect(),
                    inspect: inspect.into_iter().collect(),
                    commands: Vec::new(),
                    events: Vec::new(),
                })),
            }
        }
    }

    impl NodedClient for MockNoded {
        fn execute<'a>(
            &'a self,
            _endpoint: &'a NodeControlEndpoint,
            command: &'a NodeCommand,
        ) -> SemanticFuture<'a, Result<NodeCommandResult, NodeClientError>> {
            Box::pin(async move {
                assert!(
                    !self.store.state.lock().expect("mock store").in_transaction,
                    "network call crossed admission tx"
                );
                let mut state = self.state.lock().expect("mock noded");
                state.events.push(format!("node:{:?}", command.action));
                state.commands.push(command.clone());
                state
                    .execute
                    .pop_front()
                    .unwrap_or(Err(NodeClientError::Timeout))
            })
        }

        fn inspect<'a>(
            &'a self,
            _endpoint: &'a NodeControlEndpoint,
            _cat_id: &'a str,
        ) -> SemanticFuture<'a, Result<NodeCatStatus, NodeClientError>> {
            Box::pin(async move {
                assert!(
                    !self.store.state.lock().expect("mock store").in_transaction,
                    "query crossed admission tx"
                );
                self.state
                    .lock()
                    .expect("mock noded")
                    .inspect
                    .pop_front()
                    .unwrap_or(Err(NodeClientError::Timeout))
            })
        }
    }

    #[derive(Clone)]
    struct MockIngress {
        noded_state: Arc<Mutex<MockNodedState>>,
    }

    impl MockIngress {
        fn new(noded: &MockNoded) -> Self {
            Self {
                noded_state: noded.state.clone(),
            }
        }
    }

    impl IngressPort for MockIngress {
        fn withdraw<'a>(
            &'a self,
            _cat_id: &'a str,
            old_node_id: &'a str,
        ) -> SemanticFuture<'a, Result<(), IngressError>> {
            Box::pin(async move {
                self.noded_state
                    .lock()
                    .expect("mock noded")
                    .events
                    .push(format!("withdraw:{old_node_id}"));
                Ok(())
            })
        }

        fn publish<'a>(
            &'a self,
            _cat_id: &'a str,
            new_node_id: &'a str,
        ) -> SemanticFuture<'a, Result<(), IngressError>> {
            Box::pin(async move {
                self.noded_state
                    .lock()
                    .expect("mock noded")
                    .events
                    .push(format!("publish:{new_node_id}"));
                Ok(())
            })
        }
    }

    fn config() -> CatCreateConfig {
        CatCreateConfig {
            cpu_count: 2,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            boot_image: "ubuntu-24.04".to_owned(),
            mounts: vec![CatMount {
                disk_id: "disk-1".to_owned(),
                volume_id: "vol-1".to_owned(),
                filesystem_uuid: "11111111111111111111111111111111".to_owned(),
                disk_format: "ext4".to_owned(),
                mount_path: "/data".to_owned(),
            }],
        }
    }

    fn cat(state: Option<CatState>, action: Option<CatAction>) -> CatRecord {
        CatRecord {
            cat_id: "cat-1".to_owned(),
            workspace_id: "workspace-1".to_owned(),
            cat_slug: "web".to_owned(),
            state,
            current_action: action,
            current_action_node_id: action.map(|_| "node-1".to_owned()),
            node_id: Some("node-1".to_owned()),
            config: config(),
        }
    }

    fn claim(cat: CatRecord, action: CatAction) -> ActionClaim {
        ActionClaim {
            cat,
            action,
            started_at_unix_ms: 1,
            node_id: Some("node-1".to_owned()),
        }
    }

    fn fast_timeouts() -> LifecycleTimeouts {
        LifecycleTimeouts {
            total: Duration::from_millis(100),
            node_request: Duration::from_millis(20),
            retry_count: 1,
            retry_interval: Duration::ZERO,
            recovery_poll_interval: Duration::ZERO,
            create_cleanup: Duration::from_millis(20),
        }
    }

    #[test]
    fn create_config_ignores_mount_order_but_not_values() {
        let request = CreateCatRequest {
            workspace_id: "workspace-1".to_owned(),
            cat_slug: "web".to_owned(),
            config: CatCreateConfig {
                mounts: vec![
                    CatMount {
                        disk_id: "disk-2".to_owned(),
                        volume_id: "vol-2".to_owned(),
                        filesystem_uuid: "22222222222222222222222222222222".to_owned(),
                        disk_format: "ext4".to_owned(),
                        mount_path: "/cache".to_owned(),
                    },
                    CatMount {
                        disk_id: "disk-1".to_owned(),
                        volume_id: "vol-1".to_owned(),
                        filesystem_uuid: "11111111111111111111111111111111".to_owned(),
                        disk_format: "ext4".to_owned(),
                        mount_path: "/data".to_owned(),
                    },
                ],
                ..config()
            },
        };
        let mut existing = cat(Some(CatState::Running), None);
        existing.config.mounts = request.config.mounts.iter().rev().cloned().collect();
        assert_eq!(
            classify_create(Some(&existing), &request),
            CreateDecision::AlreadyExists
        );
        existing.config.memory_bytes += 1;
        assert_eq!(
            classify_create(Some(&existing), &request),
            CreateDecision::ConfigurationConflict
        );
    }

    #[test]
    fn action_classification_checks_target_and_current_action() {
        assert_eq!(
            classify_action(&cat(Some(CatState::Running), None), CatAction::Run),
            ActionDecision::AlreadyDone
        );
        assert_eq!(
            classify_action(
                &cat(Some(CatState::Cold), Some(CatAction::Run)),
                CatAction::Run
            ),
            ActionDecision::SameAction
        );
        assert_eq!(
            classify_action(
                &cat(Some(CatState::Running), Some(CatAction::Warm)),
                CatAction::Cold
            ),
            ActionDecision::Busy
        );
        assert_eq!(
            classify_action(
                &cat(Some(CatState::Running), Some(CatAction::Warm)),
                CatAction::Destroy
            ),
            ActionDecision::Claim
        );
        assert_eq!(
            classify_action(&cat(None, Some(CatAction::Create)), CatAction::Destroy),
            ActionDecision::Claim
        );
        assert_eq!(
            classify_action(&cat(Some(CatState::Failure), None), CatAction::Run),
            ActionDecision::InvalidState
        );
        assert_eq!(
            classify_action(&cat(Some(CatState::Failure), None), CatAction::Destroy),
            ActionDecision::Claim
        );
    }

    #[tokio::test]
    async fn claimed_action_calls_noded_after_admission_and_commits_target() {
        let original = cat(Some(CatState::Cold), Some(CatAction::Run));
        let action_claim = claim(original.clone(), CatAction::Run);
        let store = MockStore::new(original, Admission::Claimed(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [Ok(NodeCommandResult::Succeeded(CatState::Running))],
            [],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let outcome = service
            .run(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("run");

        assert_eq!(outcome.status, OutcomeStatus::Ok);
        assert_eq!(outcome.cat.state, Some(CatState::Running));
        assert_eq!(store.state.lock().expect("store").completions, 1);
        let commands = noded.state.lock().expect("noded").commands.clone();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].action, CatAction::Run);
        assert_eq!(commands[0].config, Some(config()));
        assert_eq!(
            noded.state.lock().expect("noded").events,
            ["node:Run", "publish:node-1"]
        );
    }

    #[tokio::test]
    async fn same_action_recovers_completed_noded_effect_without_reexecuting() {
        let original = cat(Some(CatState::Cold), Some(CatAction::Run));
        let action_claim = claim(original.clone(), CatAction::Run);
        let store = MockStore::new(original, Admission::SameAction(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [],
            [Ok(NodeCatStatus::Present {
                state: Some(CatState::Running),
                active_action: None,
            })],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let outcome = service
            .run(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("recovered run");

        assert_eq!(outcome.cat.state, Some(CatState::Running));
        assert!(noded.state.lock().expect("noded").commands.is_empty());
        assert_eq!(store.state.lock().expect("store").completions, 1);
    }

    #[tokio::test]
    async fn timeout_retries_same_command_then_recovers_by_query() {
        let original = cat(None, Some(CatAction::Create));
        let action_claim = claim(original.clone(), CatAction::Create);
        let store = MockStore::new(original, Admission::Claimed(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [Err(NodeClientError::Timeout), Err(NodeClientError::Timeout)],
            [Ok(NodeCatStatus::Present {
                state: Some(CatState::Running),
                active_action: None,
            })],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let outcome = service
            .create(CreateCatRequest {
                workspace_id: "workspace-1".to_owned(),
                cat_slug: "web".to_owned(),
                config: config(),
            })
            .await
            .expect("query recovered create");

        assert_eq!(outcome.cat.state, Some(CatState::Running));
        let commands = noded.state.lock().expect("noded").commands.clone();
        assert_eq!(commands.len(), 2);
        assert!(commands
            .iter()
            .all(|command| command.action == CatAction::Create));
        assert_eq!(commands[0], commands[1]);
        assert_eq!(store.state.lock().expect("store").endpoint_reads, 3);
    }

    #[tokio::test]
    async fn failed_create_timeout_sends_one_destroy_and_marks_failure() {
        let original = cat(None, Some(CatAction::Create));
        let action_claim = claim(original.clone(), CatAction::Create);
        let store = MockStore::new(original, Admission::Claimed(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [
                Err(NodeClientError::Timeout),
                Err(NodeClientError::Timeout),
                Ok(NodeCommandResult::AlreadyDone(CatState::Destroyed)),
            ],
            [Err(NodeClientError::Timeout)],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let error = service
            .create(CreateCatRequest {
                workspace_id: "workspace-1".to_owned(),
                cat_slug: "web".to_owned(),
                config: config(),
            })
            .await
            .expect_err("create must time out");

        assert!(matches!(error, LifecycleError::Timeout { .. }));
        let commands = noded.state.lock().expect("noded").commands.clone();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[2].action, CatAction::Destroy);
        assert_eq!(store.state.lock().expect("store").failures, 1);
    }

    #[tokio::test]
    async fn already_target_never_resolves_node_or_calls_noded() {
        let original = cat(Some(CatState::Running), None);
        let store = MockStore::new(
            original.clone(),
            Admission::Already {
                cat: original,
                code: CatAction::Run.already_code(),
            },
        );
        let noded = MockNoded::new(store.clone(), [], []);
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let outcome = service
            .run(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("already running");

        assert_eq!(outcome.status, OutcomeStatus::AlreadyDone);
        assert_eq!(outcome.code, "already_running");
        assert_eq!(store.state.lock().expect("store").endpoint_reads, 0);
        assert!(noded.state.lock().expect("noded").commands.is_empty());
    }

    #[tokio::test]
    async fn destroy_without_placement_completes_without_noded() {
        let mut original = cat(Some(CatState::Cold), Some(CatAction::Destroy));
        original.node_id = None;
        original.current_action_node_id = None;
        let action_claim = ActionClaim {
            cat: original.clone(),
            action: CatAction::Destroy,
            started_at_unix_ms: 1,
            node_id: None,
        };
        let store = MockStore::new(original, Admission::Claimed(action_claim));
        let noded = MockNoded::new(store.clone(), [], []);
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let outcome = service
            .destroy(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("destroy cold Cat");

        assert_eq!(outcome.cat.state, Some(CatState::Destroyed));
        assert_eq!(store.state.lock().expect("store").endpoint_reads, 0);
        assert!(noded.state.lock().expect("noded").commands.is_empty());
    }

    #[tokio::test]
    async fn repeated_destroy_preempts_the_node_action_seen_during_recovery() {
        let original = cat(Some(CatState::Running), Some(CatAction::Destroy));
        let action_claim = claim(original.clone(), CatAction::Destroy);
        let store = MockStore::new(original, Admission::SameAction(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [Ok(NodeCommandResult::Succeeded(CatState::Destroyed))],
            [Ok(NodeCatStatus::Present {
                state: Some(CatState::Running),
                active_action: Some(CatAction::Warm),
            })],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let outcome = service
            .destroy(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("destroy must preempt the stale Node action");

        assert_eq!(outcome.cat.state, Some(CatState::Destroyed));
        assert_eq!(
            noded
                .state
                .lock()
                .expect("noded")
                .commands
                .iter()
                .map(|command| command.action)
                .collect::<Vec<_>>(),
            [CatAction::Destroy]
        );
        assert_eq!(store.state.lock().expect("store").failures, 0);
    }

    #[tokio::test]
    async fn recovery_scan_redispatches_destroy_committed_before_control_crash() {
        let original = cat(Some(CatState::Failure), Some(CatAction::Destroy));
        let action_claim = claim(original.clone(), CatAction::Destroy);
        let store = MockStore::new(original, Admission::SameAction(action_claim.clone()));
        store.queue_pending_destroy(action_claim);
        let noded = MockNoded::new(
            store.clone(),
            [Ok(NodeCommandResult::Succeeded(CatState::Destroyed))],
            [Ok(NodeCatStatus::Present {
                state: None,
                active_action: Some(CatAction::Create),
            })],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let report = service
            .recover_pending_destroys(Duration::ZERO, 32, 4)
            .await
            .expect("scan committed Destroy");

        assert_eq!(
            report,
            PendingDestroyRecoveryReport {
                discovered: 1,
                completed: 1,
                failed: 0,
            }
        );
        assert_eq!(store.state.lock().expect("store").completions, 1);
        assert_eq!(
            noded
                .state
                .lock()
                .expect("noded")
                .commands
                .iter()
                .map(|command| command.action)
                .collect::<Vec<_>>(),
            [CatAction::Destroy]
        );
    }

    #[tokio::test]
    async fn failed_pending_destroy_is_rotated_behind_untried_claims() {
        let original = cat(Some(CatState::Failure), Some(CatAction::Destroy));
        let action_claim = claim(original.clone(), CatAction::Destroy);
        let store = MockStore::new(original, Admission::SameAction(action_claim.clone()));
        store.queue_pending_destroy(action_claim);
        store.queue_endpoint_error(StoreError::new("Node endpoint unavailable"));
        let noded = MockNoded::new(store.clone(), [], []);
        let ingress = MockIngress::new(&noded);
        let service = SemanticLifecycleService::new(store.clone(), noded, ingress, fast_timeouts());

        let report = service
            .recover_pending_destroys(Duration::ZERO, 32, 4)
            .await
            .expect("scan remains available after one claim fails");

        assert_eq!(report.discovered, 1);
        assert_eq!(report.completed, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(store.state.lock().expect("store").rotations, 1);
    }

    #[tokio::test]
    async fn cross_node_run_withdraws_old_then_starts_then_publishes_new() {
        let original = cat(Some(CatState::Running), Some(CatAction::Run));
        let action_claim = ActionClaim {
            cat: original.clone(),
            action: CatAction::Run,
            started_at_unix_ms: 1,
            node_id: Some("node-2".to_owned()),
        };
        let store = MockStore::new(original, Admission::Claimed(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [Ok(NodeCommandResult::Succeeded(CatState::Running))],
            [],
        );
        let ingress = MockIngress::new(&noded);
        let service = SemanticLifecycleService::new(store, noded.clone(), ingress, fast_timeouts());

        service
            .run(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("cross-Node run");

        assert_eq!(
            noded.state.lock().expect("noded").events,
            ["withdraw:node-1", "node:Run", "publish:node-2"]
        );
    }

    #[tokio::test]
    async fn leaving_running_withdraws_before_node_action_and_does_not_publish() {
        let original = cat(Some(CatState::Running), Some(CatAction::Cold));
        let action_claim = claim(original.clone(), CatAction::Cold);
        let store = MockStore::new(original, Admission::Claimed(action_claim));
        let noded = MockNoded::new(
            store.clone(),
            [Ok(NodeCommandResult::Succeeded(CatState::Cold))],
            [],
        );
        let ingress = MockIngress::new(&noded);
        let service = SemanticLifecycleService::new(store, noded.clone(), ingress, fast_timeouts());

        service
            .cold(CatSelector::Id("cat-1".to_owned()))
            .await
            .expect("cold");

        assert_eq!(
            noded.state.lock().expect("noded").events,
            ["withdraw:node-1", "node:Cold"]
        );
    }

    #[tokio::test]
    async fn stale_action_scan_discovers_noded_terminal_state_without_reexecution() {
        let original = cat(None, Some(CatAction::Create));
        let action_claim = claim(original.clone(), CatAction::Create);
        let store = MockStore::new(original, Admission::SameAction(action_claim.clone()))
            .with_stale_actions(vec![action_claim]);
        let noded = MockNoded::new(
            store.clone(),
            [],
            [Ok(NodeCatStatus::Present {
                state: Some(CatState::Running),
                active_action: None,
            })],
        );
        let ingress = MockIngress::new(&noded);
        let service =
            SemanticLifecycleService::new(store.clone(), noded.clone(), ingress, fast_timeouts());

        let report = service
            .recover_stale_actions_once(ActionRecoveryPolicy {
                stale_after: Duration::from_secs(125),
                scan_interval: Duration::from_secs(5),
                batch_size: 64,
                concurrency: 8,
            })
            .await
            .expect("stale action scan");

        assert_eq!(
            report,
            ActionRecoveryReport {
                discovered: 1,
                settled: 1,
                unresolved: 0,
            }
        );
        assert!(noded.state.lock().expect("noded").commands.is_empty());
        assert_eq!(store.state.lock().expect("store").completions, 1);
        assert_eq!(
            noded.state.lock().expect("noded").events,
            ["publish:node-1"]
        );
    }

    #[tokio::test]
    async fn unresolved_stale_action_is_rotated_behind_untried_claims() {
        let original = cat(None, Some(CatAction::Create));
        let action_claim = claim(original.clone(), CatAction::Create);
        let store = MockStore::new(original, Admission::SameAction(action_claim.clone()))
            .with_stale_actions(vec![action_claim]);
        store.queue_endpoint_error(StoreError::new("Node endpoint unavailable"));
        let noded = MockNoded::new(store.clone(), [], []);
        let ingress = MockIngress::new(&noded);
        let service = SemanticLifecycleService::new(store.clone(), noded, ingress, fast_timeouts());

        let report = service
            .recover_stale_actions_once(ActionRecoveryPolicy::default())
            .await
            .expect("scan remains available after one claim fails");

        assert_eq!(report.discovered, 1);
        assert_eq!(report.settled, 0);
        assert_eq!(report.unresolved, 1);
        assert_eq!(store.state.lock().expect("store").rotations, 1);
    }

    #[test]
    fn stale_action_recovery_starts_after_foreground_deadline() {
        let stale_after = ActionRecoveryPolicy::default().stale_after;
        assert_eq!(stale_after, Duration::from_secs(125));
        assert!(stale_after > LifecycleTimeouts::default().total);
    }
}

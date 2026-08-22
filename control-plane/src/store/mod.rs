//! Control-plane persistence (PostgreSQL implementation of the §17.3 tables).
//!
//! Every user-facing invariant that must hold under concurrency is enforced
//! here with constraints, not in handler code: unique names per workspace,
//! one mount binding per disk (RWO), at most one live attachment per disk,
//! monotonic generations.
//!
//! The store shares one database with the storage MetadataStore (its tables
//! are prefixed `cats_storage_`); ownership of the control tables stays here.
//! Tests isolate through a per-test schema selected via the DSN's
//! `options=-csearch_path=...` parameter.

mod accounts;
mod executor;
mod leadership;
mod metrics;
mod node_identities;
mod object_write_gateway_client;
mod rows;
pub(crate) mod runtime_authority;
mod schema;
pub mod semantic;
mod transaction;

pub(crate) use transaction::AuthorityRequestContext;

pub use leadership::SingletonRole;
pub(crate) use leadership::SingletonSession;
pub use object_write_gateway_client::{
    ObjectWriteGatewayClient, OBJECT_WRITE_GATEWAY_POSTGRES_ROLE,
    OBJECT_WRITE_GATEWAY_PROTOCOL_VERSION_V1,
};
use rows::{row_to_account, row_to_workspace};
pub use runtime_authority::host_fence_provider_queue::{
    HostFenceProviderClaimV1, HostFenceProviderObjectCutoffV1, HostFenceProviderQueueClient,
    HostFenceProviderQueueRecordV1, HostFenceProviderQueueStateV1, PgObjectWriteCutoffPort,
    HOST_FENCE_PROVIDER_EVIDENCE_MAX_BYTES, HOST_FENCE_PROVIDER_LEASE_MAX_MS,
    HOST_FENCE_PROVIDER_POSTGRES_ROLE, HOST_FENCE_PROVIDER_QUEUE_VERSION_V1,
    HOST_FENCE_PROVIDER_REQUEST_MAX_BYTES,
};

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::Client;
use uuid::Uuid;

use cats_api::auth::{Account, AccountInvitation, AccountKind, Workspace, WorkspaceToken};
use cats_api::error::{ApiError, ErrorCode};
use cats_api::ids;

pub type Result<T> = std::result::Result<T, ApiError>;

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

pub fn new_id(prefix: &str) -> String {
    ids::make_id(prefix, &Uuid::new_v4().simple().to_string()[..12])
}

fn dns_slug(value: &str, max_len: usize) -> String {
    let mut slug = String::with_capacity(value.len().min(max_len));
    for ch in value.chars() {
        if slug.len() == max_len {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if ch == '-' && !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "cat".to_string()
    } else {
        slug
    }
}

pub struct Store {
    /// One serialized connection, the same concurrency shape the SQLite
    /// implementation had. `with` reconnects lazily after the server drops
    /// it. Option lets reconnect retire a dead FD before dialing and lets
    /// `Drop` move the live client onto a non-runtime thread.
    pub(super) client: Mutex<Option<Client>>,
    dsn: DsnSource,
    ca_file: Option<String>,
    #[cfg(test)]
    commit_response_loss_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    request_commit_response_loss_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    commit_response_loss_delay_ms: std::sync::atomic::AtomicU64,
}

/// Each Store retains the V1 single-connection ordering. Four fixed workers
/// let independent Store instances (notably replicas exercised in one test
/// process) progress without creating a thread per operation.
pub const CONTROL_STORE_BLOCKING_WORKERS: usize = 4;
pub const CONTROL_STORE_CONNECTIONS: usize = 1;
pub const CONTROL_STORE_QUEUE_CAPACITY: usize = 64;
pub const CONTROL_STORE_CLEANUP_QUEUE_CAPACITY: usize = 64;
pub const CONTROL_STORE_LEADERSHIP_WORKERS: usize = 3;
pub const CONTROL_STORE_LEADERSHIP_QUEUE_CAPACITY: usize = 8;
// A production process starts at most one session for each role. The larger
// hard ceiling also supports several in-process replicas in contract tests
// without making the persistent session count unbounded.
pub const CONTROL_STORE_SINGLETON_CONNECTIONS: usize = 16;
pub const CONTROL_STORE_LEADERSHIP_CLEANUP_QUEUE_CAPACITY: usize =
    CONTROL_STORE_SINGLETON_CONNECTIONS;

/// Client-side connection deadlines complement PostgreSQL's server-side
/// statement and lock timeouts. `TCP_USER_TIMEOUT` bounds unacknowledged data;
/// keepalive probes bound an otherwise silent half-open established socket.
pub const CONTROL_STORE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONTROL_STORE_TCP_USER_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONTROL_STORE_KEEPALIVE_IDLE: Duration = Duration::from_secs(2);
pub const CONTROL_STORE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);
pub const CONTROL_STORE_KEEPALIVE_RETRIES: u32 = 3;
/// Conservative Linux bound from the last acknowledged packet: wait for the
/// first keepalive probe, then allow at most `TCP_USER_TIMEOUT` without an ACK.
pub const CONTROL_STORE_ESTABLISHED_IO_FAILURE_BOUND: Duration = Duration::from_secs(7);
pub const CONTROL_STORE_LANE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

static CONTROL_STORE_SINGLETON_CONNECTIONS_IN_USE: AtomicUsize = AtomicUsize::new(0);

/// Permit for a PostgreSQL session that intentionally outlives one executor
/// job. Ordinary Store work has one connection; singleton advisory locks have
/// a separate process-wide budget so persistent sessions remain bounded.
pub(super) struct ConnectionBudgetPermit {
    in_use: &'static AtomicUsize,
}

impl Drop for ConnectionBudgetPermit {
    fn drop(&mut self) {
        self.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_connection_budget(
    in_use: &'static AtomicUsize,
    limit: usize,
    kind: &str,
    rejection: metrics::RejectionKind,
) -> Result<ConnectionBudgetPermit> {
    in_use
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < limit).then_some(current + 1)
        })
        .map(|_| ConnectionBudgetPermit { in_use })
        .map_err(|current| {
            metrics::record_rejection(rejection);
            ApiError::unavailable(format!(
                "control-store {kind} connection limit reached ({current}/{limit})"
            ))
        })
}

pub(super) fn acquire_singleton_connection_budget() -> Result<ConnectionBudgetPermit> {
    acquire_connection_budget(
        &CONTROL_STORE_SINGLETON_CONNECTIONS_IN_USE,
        CONTROL_STORE_SINGLETON_CONNECTIONS,
        "singleton",
        metrics::RejectionKind::SingletonConnection,
    )
}

const CONTROL_STORE_EXECUTOR_LIMITS: executor::Limits = executor::Limits {
    workers: CONTROL_STORE_BLOCKING_WORKERS,
    queue_capacity: CONTROL_STORE_QUEUE_CAPACITY,
    cleanup_capacity: CONTROL_STORE_CLEANUP_QUEUE_CAPACITY,
};
const CONTROL_STORE_LEADERSHIP_EXECUTOR_LIMITS: executor::Limits = executor::Limits {
    workers: CONTROL_STORE_LEADERSHIP_WORKERS,
    queue_capacity: CONTROL_STORE_LEADERSHIP_QUEUE_CAPACITY,
    cleanup_capacity: CONTROL_STORE_LEADERSHIP_CLEANUP_QUEUE_CAPACITY,
};

static CONTROL_STORE_EXECUTOR: OnceLock<std::result::Result<executor::BlockingExecutor, String>> =
    OnceLock::new();
static CONTROL_STORE_LEADERSHIP_EXECUTOR: OnceLock<
    std::result::Result<executor::BlockingExecutor, String>,
> = OnceLock::new();
static CONTROL_STORE_ADMISSION: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
static CONTROL_STORE_LANES: OnceLock<Mutex<HashMap<usize, Weak<tokio::sync::Semaphore>>>> =
    OnceLock::new();

fn control_store_admission() -> Arc<tokio::sync::Semaphore> {
    Arc::clone(CONTROL_STORE_ADMISSION.get_or_init(|| {
        Arc::new(tokio::sync::Semaphore::new(
            CONTROL_STORE_BLOCKING_WORKERS + CONTROL_STORE_QUEUE_CAPACITY,
        ))
    }))
}

fn try_admit_control_store_work() -> Result<tokio::sync::OwnedSemaphorePermit> {
    control_store_admission().try_acquire_owned().map_err(|_| {
        metrics::record_rejection(metrics::RejectionKind::Admission);
        ApiError::unavailable(format!(
            "control-store queue is full (capacity {CONTROL_STORE_QUEUE_CAPACITY})"
        ))
    })
}

fn control_store_lane(store: &Arc<Store>) -> Arc<tokio::sync::Semaphore> {
    let key = Arc::as_ptr(store) as usize;
    let lanes = CONTROL_STORE_LANES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut lanes = match lanes.lock() {
        Ok(lanes) => lanes,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(lane) = lanes.get(&key).and_then(Weak::upgrade) {
        return lane;
    }
    let lane = Arc::new(tokio::sync::Semaphore::new(CONTROL_STORE_CONNECTIONS));
    lanes.insert(key, Arc::downgrade(&lane));
    lane
}

fn control_store_executor() -> Result<&'static executor::BlockingExecutor> {
    match CONTROL_STORE_EXECUTOR.get_or_init(|| {
        executor::BlockingExecutor::new("cats-control-pg", CONTROL_STORE_EXECUTOR_LIMITS)
            .map_err(|error| format!("start control-store blocking executor: {error}"))
    }) {
        Ok(executor) => Ok(executor),
        Err(error) => Err(ApiError::unavailable(error.clone())),
    }
}

fn control_store_leadership_executor() -> Result<&'static executor::BlockingExecutor> {
    match CONTROL_STORE_LEADERSHIP_EXECUTOR.get_or_init(|| {
        executor::BlockingExecutor::new(
            "cats-control-pg-leader",
            CONTROL_STORE_LEADERSHIP_EXECUTOR_LIMITS,
        )
        .map_err(|error| format!("start control-store leadership executor: {error}"))
    }) {
        Ok(executor) => Ok(executor),
        Err(error) => Err(ApiError::unavailable(error.clone())),
    }
}

fn drop_on_executor<T: Send + 'static>(
    value: T,
    executor_provider: fn() -> Result<&'static executor::BlockingExecutor>,
    kind: metrics::ExecutorKind,
) {
    if tokio::runtime::Handle::try_current().is_err() {
        // Calls already running on a Cats blocking worker have no Tokio
        // context and may destroy the synchronous client directly.
        drop(value);
        return;
    }

    // DsnSource::resolve initializes both static executors before any Client
    // can be created. Static OnceLock values are never shut down, so every
    // live Client has a permanently available cleanup destination.
    let executor = executor_provider()
        .expect("a live control-store Client has an initialized blocking executor");
    type DropJob = Box<dyn FnOnce() + Send + 'static>;
    let operation: DropJob = Box::new(move || drop(value));
    let operation = match executor.try_execute_cleanup(operation) {
        Ok(()) => return,
        Err(executor::CleanupSubmitError::Full(operation)) => {
            metrics::record_rejection(match kind {
                metrics::ExecutorKind::Normal => metrics::RejectionKind::NormalCleanup,
                metrics::ExecutorKind::Leadership => metrics::RejectionKind::LeadershipCleanup,
            });
            operation
        }
        Err(executor::CleanupSubmitError::Shutdown(_)) => {
            unreachable!("static control-store executor cannot shut down")
        }
    };
    match executor.execute_cleanup(operation) {
        Ok(()) => {}
        Err(executor::CleanupSubmitError::Full(_)) => {
            unreachable!("blocking cleanup admission does not reject a full queue")
        }
        Err(executor::CleanupSubmitError::Shutdown(_)) => {
            unreachable!("static control-store executor cannot shut down")
        }
    }
}

fn drop_on_normal_executor<T: Send + 'static>(value: T) {
    drop_on_executor(value, control_store_executor, metrics::ExecutorKind::Normal);
}

pub(super) fn drop_on_leadership_executor<T: Send + 'static>(value: T) {
    drop_on_executor(
        value,
        control_store_leadership_executor,
        metrics::ExecutorKind::Leadership,
    );
}

/// Where the control store obtains its PostgreSQL DSN on each connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DsnSource {
    /// A fixed development credential.
    Literal(String),
    /// A file kept current by the platform and re-read after a disconnect.
    File(PathBuf),
}

impl DsnSource {
    /// Resolve without ever including the credential-bearing contents in an
    /// error message.
    fn resolve(&self) -> Result<String> {
        // A live synchronous Client must always have a bounded place to run
        // and to be destroyed. Initializing both fixed executors before any
        // dial makes a permanently cached executor startup failure fail the
        // connect itself instead of stranding an advisory-lock owner later.
        control_store_executor()?;
        control_store_leadership_executor()?;
        let url = match self {
            Self::Literal(url) => Ok(url.clone()),
            Self::File(path) => {
                let contents = fs::read_to_string(path).map_err(|error| {
                    internal(format!(
                        "read control-store PostgreSQL DSN from {}: {error}",
                        path.display()
                    ))
                })?;
                let url = contents.trim();
                if url.is_empty() {
                    return Err(internal(format!(
                        "control-store PostgreSQL DSN file {} is empty",
                        path.display()
                    )));
                }
                Ok(url.to_string())
            }
        }?;
        Ok(dsn_with_client_failure_bounds(&url))
    }
}

fn dsn_with_client_failure_bounds(dsn: &str) -> String {
    let settings = format!(
        "connect_timeout={}\
         &tcp_user_timeout={}\
         &keepalives=1\
         &keepalives_idle={}\
         &keepalives_interval={}\
         &keepalives_retries={}",
        CONTROL_STORE_CONNECT_TIMEOUT.as_secs(),
        CONTROL_STORE_TCP_USER_TIMEOUT.as_secs(),
        CONTROL_STORE_KEEPALIVE_IDLE.as_secs(),
        CONTROL_STORE_KEEPALIVE_INTERVAL.as_secs(),
        CONTROL_STORE_KEEPALIVE_RETRIES,
    );
    if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        let separator = if dsn.contains('?') { '&' } else { '?' };
        format!("{dsn}{separator}{settings}")
    } else {
        format!(
            "{dsn} connect_timeout={} tcp_user_timeout={} keepalives=1 \
             keepalives_idle={} keepalives_interval={} keepalives_retries={}",
            CONTROL_STORE_CONNECT_TIMEOUT.as_secs(),
            CONTROL_STORE_TCP_USER_TIMEOUT.as_secs(),
            CONTROL_STORE_KEEPALIVE_IDLE.as_secs(),
            CONTROL_STORE_KEEPALIVE_INTERVAL.as_secs(),
            CONTROL_STORE_KEEPALIVE_RETRIES,
        )
    }
}

/// Client destruction uses the same bounded worker set as queries. This Drop
/// only schedules that work when it runs on Tokio; it never joins a new OS
/// thread or blocks a runtime worker on the synchronous driver's runtime.
impl Drop for Store {
    fn drop(&mut self) {
        if let Some(lanes) = CONTROL_STORE_LANES.get() {
            let key = self as *const Store as usize;
            match lanes.lock() {
                Ok(mut lanes) => {
                    lanes.remove(&key);
                }
                Err(poisoned) => {
                    poisoned.into_inner().remove(&key);
                }
            }
        }
        let guard = match self.client.get_mut() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(client) = guard.take() {
            drop_on_normal_executor(client);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub kind: AccountKind,
    pub workos_organization_id: String,
    pub billing_account_id: String,
    pub personal_owner_user_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRecord {
    pub id: String,
    pub account_id: String,
    pub slug: String,
    pub display_name: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceScope {
    pub account: AccountRecord,
    pub workspace: WorkspaceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingLedgerRecord {
    pub billing_account_id: String,
    /// Account that owns this Billing Account. Named for what it holds: the
    /// funds side keys on Accounts, never on Workspaces.
    pub account_id: String,
    pub signup_credit_nanos: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupGrantState {
    Pending,
    Applied,
}

pub(super) fn internal(error: impl std::fmt::Display + 'static) -> ApiError {
    if let Some(postgres) = (&error as &dyn Any).downcast_ref::<postgres::Error>() {
        metrics::record_postgres_error(postgres);
    }
    ApiError::internal(error.to_string())
}

/// Constraint violations (SQLSTATE class 23) and the store's own immutability
/// triggers (raised as P0001) both surface as conflicts, mirroring what the
/// SQLite implementation reported for its CHECK/UNIQUE/trigger aborts.
pub(super) fn is_constraint(e: &postgres::Error) -> bool {
    e.code().is_some_and(|state| {
        state.code().starts_with("23") || state == &postgres::error::SqlState::RAISE_EXCEPTION
    })
}

/// Run `f` on a thread that is allowed to block.
///
/// The sync `postgres` client owns an internal runtime and panics when used
/// directly on a Tokio worker thread. Production async callers use
/// `Store::execute`, below, and only await its result. This compatibility seam
/// remains for startup and synchronous tests: a multi-thread runtime marks the
/// call as blocking so another Tokio worker can take its place; a current-thread
/// test has no worker to preserve and uses a scoped helper.
pub(crate) fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        Ok(_) => std::thread::scope(|scope| {
            scope
                .spawn(f)
                .join()
                .expect("control-store operation panicked")
        }),
        Err(_) => f(),
    }
}

impl Store {
    /// Open and migrate the initial connection without occupying a Tokio
    /// worker. Startup awaits the same bounded executor used by requests.
    pub async fn connect_from_async(dsn: DsnSource, ca_file: Option<String>) -> Result<Self> {
        let _latency = metrics::RequestTimer::new(metrics::ExecutorKind::Normal);
        execute_on(
            control_store_executor()?,
            CONTROL_STORE_QUEUE_CAPACITY,
            metrics::ExecutorKind::Normal,
            move || Store::connect_from(&dsn, ca_file.as_deref()),
        )
        .await
    }

    /// Execute one complete synchronous Store operation on the fixed worker.
    ///
    /// The closure must own its request inputs because it may wait in the
    /// bounded queue after its caller yields. Dropping this future while it is
    /// queued removes the closure, so an abandoned mutation cannot run later.
    pub async fn execute<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Arc<Store>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let _latency = metrics::RequestTimer::new(metrics::ExecutorKind::Normal);
        // Admission precedes the async lane wait, so the executor queue plus
        // all per-connection waiters has one process-wide hard bound.
        let admission = try_admit_control_store_work()?;
        let lane = control_store_lane(self);
        let lane_permit =
            match tokio::time::timeout(CONTROL_STORE_LANE_ACQUIRE_TIMEOUT, lane.acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => {
                    return Err(ApiError::unavailable(
                        "control-store connection lane is shutting down",
                    ));
                }
                Err(_) => {
                    metrics::record_lane_acquire_timeout();
                    return Err(ApiError::unavailable(format!(
                        "control-store connection lane was unavailable for {} seconds",
                        CONTROL_STORE_LANE_ACQUIRE_TIMEOUT.as_secs()
                    )));
                }
            };
        let store = Arc::clone(self);
        execute_on(
            control_store_executor()?,
            CONTROL_STORE_QUEUE_CAPACITY,
            metrics::ExecutorKind::Normal,
            move || {
                let _admission = admission;
                let _lane = lane_permit;
                operation(&store)
            },
        )
        .await
    }

    /// Lock the connection and run `f` off-runtime. The server closing the
    /// connection (restart, failover, idle timeout) must cost one reconnect,
    /// not a wedged store, so `f` receives the reconnect outcome instead of a
    /// guaranteed client.
    fn enter<T: Send>(
        &self,
        f: impl FnOnce(std::result::Result<&mut Client, ApiError>) -> T + Send,
    ) -> T {
        self.enter_with_retirement(|client| (f(client), false))
    }

    /// Variant of [`Self::enter`] for operations that may leave session-level
    /// PostgreSQL state behind when their cleanup result is uncertain. A true
    /// retirement flag closes that connection before another caller can use
    /// it. Panics also retire the session, which makes session advisory locks
    /// fail-safe without attempting PostgreSQL work while unwinding.
    fn enter_with_retirement<T: Send>(
        &self,
        f: impl FnOnce(std::result::Result<&mut Client, ApiError>) -> (T, bool) + Send,
    ) -> T {
        let mut guard = self.client.lock().unwrap();
        let client: &mut Option<Client> = &mut guard;
        off_runtime(move || {
            if client.as_ref().is_none_or(|client| client.is_closed()) {
                // Retire the dead socket before opening its replacement so
                // the one-connection lane never transiently owns two FDs.
                drop(client.take());
                match schema::connect_client(&self.dsn, self.ca_file.as_deref()) {
                    Ok(mut fresh) => {
                        if let Err(error) = configure_session(&mut fresh) {
                            return f(Err(error)).0;
                        }
                        *client = Some(fresh);
                    }
                    Err(error) => return f(Err(error)).0,
                }
            }
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f(Ok(client.as_mut().expect("client was just ensured")))
            }));
            match outcome {
                Ok((value, retire)) => {
                    if retire {
                        drop(client.take());
                    }
                    value
                }
                Err(payload) => {
                    // Closing the session is the only panic-safe proof that a
                    // session advisory lock cannot survive this operation.
                    drop(client.take());
                    std::panic::resume_unwind(payload)
                }
            }
        })
    }

    pub(crate) fn with<T: Send>(
        &self,
        f: impl FnOnce(&mut Client) -> std::result::Result<T, postgres::Error> + Send,
    ) -> Result<T> {
        self.enter(|client| {
            let client = client?;
            f(client).map_err(|error| {
                if is_constraint(&error) {
                    ApiError::conflict(format!("constraint violation: {error}"))
                } else if client.is_closed()
                    || matches!(
                        error.code(),
                        Some(&postgres::error::SqlState::QUERY_CANCELED)
                            | Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE)
                    )
                {
                    metrics::record_postgres_error(&error);
                    ApiError::unavailable(format!(
                        "control-store PostgreSQL operation was unavailable: {error}"
                    ))
                } else {
                    internal(error)
                }
            })
        })
    }
}

pub(crate) fn metrics_snapshot(store: &Store) -> metrics::StoreMetricsSnapshot {
    metrics::snapshot(store)
}

pub(crate) async fn execute_leadership<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let _latency = metrics::RequestTimer::new(metrics::ExecutorKind::Leadership);
    execute_on(
        control_store_leadership_executor()?,
        CONTROL_STORE_LEADERSHIP_QUEUE_CAPACITY,
        metrics::ExecutorKind::Leadership,
        operation,
    )
    .await
}

/// Run connection/session destruction on the leadership executor and do not
/// return until it has physically completed. Cleanup admission is reserved
/// from ordinary leadership work; temporary saturation waits instead of
/// dropping an advisory-lock owner into an unjoinable fallback.
pub(crate) async fn execute_leadership_cleanup(
    operation: impl FnOnce() + Send + 'static,
) -> Result<()> {
    execute_leadership_cleanup_on(control_store_leadership_executor()?, operation).await
}

async fn execute_leadership_cleanup_on(
    executor: &executor::BlockingExecutor,
    operation: impl FnOnce() + Send + 'static,
) -> Result<()> {
    type CleanupJob = Box<dyn FnOnce() + Send + 'static>;

    let (completed, completion) = tokio::sync::oneshot::channel();
    let mut cleanup: CleanupJob = Box::new(move || {
        operation();
        let _ = completed.send(());
    });
    let mut recorded_saturation = false;
    loop {
        match executor.try_execute_cleanup(cleanup) {
            Ok(()) => break,
            Err(executor::CleanupSubmitError::Full(returned)) => {
                cleanup = returned;
                if !recorded_saturation {
                    metrics::record_rejection(metrics::RejectionKind::LeadershipCleanup);
                    recorded_saturation = true;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(executor::CleanupSubmitError::Shutdown(_)) => {
                return Err(ApiError::unavailable(
                    "control-store leadership cleanup executor is shutting down",
                ));
            }
        }
    }
    completion.await.map_err(|_| {
        ApiError::internal("control-store leadership cleanup failed before completion")
    })
}

async fn execute_on<T: Send + 'static>(
    executor: &'static executor::BlockingExecutor,
    queue_capacity: usize,
    kind: metrics::ExecutorKind,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let execution = match executor.try_execute(operation) {
        Ok(execution) => execution,
        Err(executor::SubmitError::Full) => {
            metrics::record_rejection(match kind {
                metrics::ExecutorKind::Normal => metrics::RejectionKind::NormalQueue,
                metrics::ExecutorKind::Leadership => metrics::RejectionKind::LeadershipQueue,
            });
            let snapshot = executor.snapshot();
            tracing::warn!(
                active = snapshot.active,
                queued = snapshot.queued,
                workers = snapshot.limits.workers,
                queue_capacity = snapshot.limits.queue_capacity,
                peak_active = snapshot.peak_active,
                "control-store blocking queue rejected work"
            );
            return Err(ApiError::unavailable(format!(
                "control-store queue is full (capacity {queue_capacity})"
            )));
        }
        Err(executor::SubmitError::Shutdown) => {
            return Err(ApiError::unavailable(
                "control-store executor is shutting down",
            ));
        }
    };
    execution.await.map_err(|error| match error {
        executor::ExecutionError::Panicked => internal("control-store executor job panicked"),
        executor::ExecutionError::Shutdown => {
            ApiError::unavailable("control-store executor stopped before completing work")
        }
    })?
}

/// Every ordinary connection, including a lazy reconnect, gets the same
/// bounded SQL settings. `connect_timeout` is applied while opening the socket
/// in `schema::connect_client`; these server-side settings cover statements
/// and lock waits after authentication succeeds.
fn configure_session(client: &mut Client) -> Result<()> {
    client
        .batch_execute(
            "SET statement_timeout = '5s'; \
             SET lock_timeout = '2s'",
        )
        .map_err(|error| {
            ApiError::unavailable(format!(
                "configure control-store PostgreSQL session: {error}"
            ))
        })
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}

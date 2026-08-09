//! Control-plane assembly: config, shared state, reconciler task and HTTP
//! server. `spawn` is used by the binary and by every integration/E2E test.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::Context;
use cats_api::runtime_reconciliation::{GuestRuntimeProfileReceipt, RuntimeProvisionerTrustBundle};
use cats_metering::{CreditStore, UsageStore};
use cats_storage::{BlobStore, MetadataStore};

use crate::controller::{AutoTierPolicy, Controller, NodeLivenessAuthority};
use crate::store::{
    AuthorityRequestContext, DsnSource, ObservationStoreLane, SingletonRole, Store,
};

const SINGLETON_ELECTION_RETRY: Duration = Duration::from_millis(500);
const SINGLETON_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const RUNTIME_SPINE_GLOBAL_IN_FLIGHT: usize = 64;
const RUNTIME_VOLUME_TRANSITION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Non-authoritative, per-replica admission for signed A19/A20 Node ingress.
/// PostgreSQL remains the concurrency authority; these permits only bound
/// memory and handler work before a request reaches it. Registration uses the
/// global lane; the two session-bound A20 routes also take a per-Node permit.
pub(crate) struct RuntimeSpineAdmission {
    global: Arc<tokio::sync::Semaphore>,
    per_node: Mutex<BTreeMap<String, Weak<tokio::sync::Semaphore>>>,
}

impl RuntimeSpineAdmission {
    fn new() -> Self {
        Self {
            global: Arc::new(tokio::sync::Semaphore::new(RUNTIME_SPINE_GLOBAL_IN_FLIGHT)),
            per_node: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn try_global(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.global.clone().try_acquire_owned()
    }

    pub(crate) fn try_node(
        &self,
        node_id: &cats_api::runtime_reconciliation::Id,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        let semaphore = {
            let mut nodes = self
                .per_node
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            nodes.retain(|_, weak| weak.strong_count() != 0);
            match nodes.get(node_id.as_str()).and_then(Weak::upgrade) {
                Some(semaphore) => semaphore,
                None => {
                    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
                    nodes.insert(node_id.as_str().to_owned(), Arc::downgrade(&semaphore));
                    semaphore
                }
            }
        };
        semaphore.try_acquire_owned()
    }

    #[cfg(test)]
    pub(crate) fn available_global_permits_for_test(&self) -> usize {
        self.global.available_permits()
    }
}

/// Owns every A22 Store closure independently of the client connection. A
/// dropped handler cancels its request context, while this registry keeps the
/// closure joined and lets graceful shutdown prove that no late mutation or
/// read is still running.
pub(crate) struct RuntimeVolumeTransitionService {
    accepting: AtomicBool,
    active: AtomicUsize,
    next_request_id: AtomicU64,
    active_requests: Mutex<BTreeMap<u64, AuthorityRequestContext>>,
    changed: tokio::sync::Notify,
    #[cfg(test)]
    pause_after_admission: AtomicBool,
    #[cfg(test)]
    pause_entered: AtomicBool,
    #[cfg(test)]
    pause_changed: tokio::sync::Notify,
    #[cfg(test)]
    pause_before_node_resolution: AtomicBool,
    #[cfg(test)]
    node_resolution_entered: AtomicBool,
    #[cfg(test)]
    node_resolution_changed: tokio::sync::Notify,
    #[cfg(test)]
    pause_response_encoding: AtomicBool,
    #[cfg(test)]
    response_encoding_entered: AtomicBool,
    #[cfg(test)]
    response_encoding_changed: tokio::sync::Notify,
    #[cfg(test)]
    deadline_override_ms: AtomicU64,
}

impl RuntimeVolumeTransitionService {
    fn new() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            active: AtomicUsize::new(0),
            next_request_id: AtomicU64::new(1),
            active_requests: Mutex::new(BTreeMap::new()),
            changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            pause_after_admission: AtomicBool::new(false),
            #[cfg(test)]
            pause_entered: AtomicBool::new(false),
            #[cfg(test)]
            pause_changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            pause_before_node_resolution: AtomicBool::new(false),
            #[cfg(test)]
            node_resolution_entered: AtomicBool::new(false),
            #[cfg(test)]
            node_resolution_changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            pause_response_encoding: AtomicBool::new(false),
            #[cfg(test)]
            response_encoding_entered: AtomicBool::new(false),
            #[cfg(test)]
            response_encoding_changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            deadline_override_ms: AtomicU64::new(0),
        }
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        request_context: AuthorityRequestContext,
    ) -> Option<RuntimeVolumeTransitionRequestGuard> {
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        let request_id = self
            .next_request_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()?;
        self.active.fetch_add(1, Ordering::AcqRel);
        self.active_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id, request_context.clone());
        if !self.accepting.load(Ordering::Acquire) {
            request_context.cancel();
            self.finish(request_id);
            return None;
        }
        Some(RuntimeVolumeTransitionRequestGuard {
            service: self.clone(),
            request_id,
        })
    }

    fn finish(&self, request_id: u64) {
        self.active_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id);
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.changed.notify_waiters();
        }
    }

    fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        for context in self
            .active_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
        {
            context.cancel();
        }
        self.changed.notify_waiters();
    }

    async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let joined = tokio::time::timeout(RUNTIME_VOLUME_TRANSITION_SHUTDOWN_TIMEOUT, async {
            loop {
                let changed = self.changed.notified();
                if self.active.load(Ordering::Acquire) == 0 {
                    break;
                }
                changed.await;
            }
        })
        .await;
        anyhow::ensure!(
            joined.is_ok(),
            "runtime volume-transition requests exceeded the shutdown deadline"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn arm_pause_after_admission_for_test(&self) {
        self.pause_entered.store(false, Ordering::Release);
        self.pause_after_admission.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn pause_after_admission_for_test(&self) {
        if !self.pause_after_admission.load(Ordering::Acquire) {
            return;
        }
        self.pause_entered.store(true, Ordering::Release);
        self.pause_changed.notify_waiters();
        loop {
            let changed = self.pause_changed.notified();
            if !self.pause_after_admission.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_paused_admission_for_test(&self) {
        loop {
            let changed = self.pause_changed.notified();
            if self.pause_entered.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn release_paused_admission_for_test(&self) {
        self.pause_after_admission.store(false, Ordering::Release);
        self.pause_changed.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn arm_pause_before_node_resolution_for_test(&self) {
        self.node_resolution_entered.store(false, Ordering::Release);
        self.pause_before_node_resolution
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn pause_before_node_resolution_for_test(&self) {
        if !self.pause_before_node_resolution.load(Ordering::Acquire) {
            return;
        }
        self.node_resolution_entered.store(true, Ordering::Release);
        self.node_resolution_changed.notify_waiters();
        loop {
            let changed = self.node_resolution_changed.notified();
            if !self.pause_before_node_resolution.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_paused_node_resolution_for_test(&self) {
        loop {
            let changed = self.node_resolution_changed.notified();
            if self.node_resolution_entered.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn release_paused_node_resolution_for_test(&self) {
        self.pause_before_node_resolution
            .store(false, Ordering::Release);
        self.node_resolution_changed.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn arm_pause_response_encoding_for_test(&self) {
        self.response_encoding_entered
            .store(false, Ordering::Release);
        self.pause_response_encoding.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn pause_response_encoding_for_test(&self) {
        if !self.pause_response_encoding.load(Ordering::Acquire) {
            return;
        }
        self.response_encoding_entered
            .store(true, Ordering::Release);
        self.response_encoding_changed.notify_waiters();
        loop {
            let changed = self.response_encoding_changed.notified();
            if !self.pause_response_encoding.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_paused_response_encoding_for_test(&self) {
        loop {
            let changed = self.response_encoding_changed.notified();
            if self.response_encoding_entered.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn release_paused_response_encoding_for_test(&self) {
        self.pause_response_encoding.store(false, Ordering::Release);
        self.response_encoding_changed.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn set_deadline_override_for_test(&self, deadline: Duration) {
        let millis = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
        assert!(millis > 0, "the A22 test deadline must be non-zero");
        self.deadline_override_ms.store(millis, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn clear_deadline_override_for_test(&self) {
        self.deadline_override_ms.store(0, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn deadline_for_test(&self, production: Duration) -> Duration {
        match self.deadline_override_ms.load(Ordering::Acquire) {
            0 => production,
            millis => Duration::from_millis(millis),
        }
    }

    #[cfg(test)]
    pub(crate) fn active_for_test(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

pub(crate) struct RuntimeVolumeTransitionRequestGuard {
    service: Arc<RuntimeVolumeTransitionService>,
    request_id: u64,
}

impl Drop for RuntimeVolumeTransitionRequestGuard {
    fn drop(&mut self) {
        self.service.finish(self.request_id);
    }
}

/// Ask an elected-role supervisor to stop if its election task is cancelled.
/// The supervisor owns the PostgreSQL session, so dropping this guard cannot
/// release leadership ahead of the role it is fencing.
struct CancelSingletonOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for CancelSingletonOnDrop {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            let _ = cancel.send(());
        }
    }
}

#[derive(Clone)]
pub struct Config {
    /// `host:port`; use port 0 to pick a free port (tests).
    pub listen: String,
    /// Control-plane resource database. Production uses a mounted Secret file
    /// so a reconnect observes rotated credentials; tests use a literal URL
    /// with `options=-csearch_path%3D<schema>`.
    pub control_store_dsn: DsnSource,
    /// CA bundle for verifying the control database's TLS certificate (RDS).
    pub control_store_ca_file: Option<PathBuf>,
    /// Usage ledger is injected independently from control-plane metadata.
    /// Local development may point a SQLite adapter at a local file;
    /// production uses the PostgreSQL usage adapter.
    pub usage_store: Arc<dyn UsageStore>,
    /// Append-only prepaid credit ledger. It may share the same physical
    /// database as the usage projection while remaining a separate port.
    pub credit_store: Arc<dyn CreditStore>,
    /// Open authoritative volume-root/lease port, shared with blockd.
    pub storage_meta: Arc<dyn MetadataStore>,
    /// Read-only access to the immutable golden-image namespace. The A21
    /// resolver applies its own exact key, byte cap and concurrency boundary.
    pub image_blob: Arc<dyn BlobStore>,
    /// Service credential used by node agents, gateways and controller jobs.
    pub auth_token: String,
    /// Exact, startup-validated release receipt from the active qualified
    /// Guest runtime. It binds both new Agent sessions and Cat placement.
    /// Production loads it from the one canonical installed path.
    pub guest_runtime_profile_receipt: GuestRuntimeProfileReceipt,
    /// Exact deployment-provisioner trust bundle loaded from the one A23
    /// installed path. Startup persists/exact-replays its monotonic lineage
    /// before opening the administrator listener.
    pub runtime_provisioner_trust_bundle: RuntimeProvisionerTrustBundle,
    /// Private-key authority for short-lived V1 Endpoint Route Grants. It is
    /// intentionally absent from Gateway and Node configuration.
    pub route_grant_signer: Arc<crate::route_grant::RouteGrantSigner>,
    /// Administrator credential for fleet management and monitoring APIs.
    pub admin_token: String,
    /// Optional AuthKit configuration for browser sessions and user CLI
    /// access tokens. Service/admin machine credentials remain separate.
    pub workos: Option<Arc<crate::auth::WorkOsConfig>>,
    /// Optional Stripe-hosted top-up integration. Balance and signup credit
    /// remain available when Stripe is not configured.
    pub stripe: Option<Arc<crate::billing::StripeClient>>,
    /// Rollout kill switch for 402 admission and automatic Cold convergence.
    /// Production enables this only with a working top-up path.
    pub billing_enforcement_enabled: bool,
    pub node_lease_timeout_ms: i64,
    pub reconcile_interval_ms: u64,
    pub auto_tier_policy: AutoTierPolicy,
    /// How long `POST .../oci-deployments` may hold a request open before it
    /// answers `202` with an operation to poll.
    ///
    /// This is a transition affordance, not a correctness boundary: the deploy
    /// is durable and pollable either way. It exists so a caller written
    /// against the older synchronous response keeps receiving `200`, and it
    /// must stay comfortably below the idle timeout of whatever proxy fronts
    /// Cats -- otherwise that proxy answers 504 first and the caller learns
    /// nothing. Lower it as callers adopt polling.
    pub oci_deploy_sync_wait_ms: u64,
}

/// Default synchronous wait for an OCI deploy.
///
/// Covers a first-pull deploy of a multi-hundred-megabyte image, which is the
/// case that was timing out. The edge in front of Cats must allow more than
/// this; `deploy/aws/terraform/modules/cats-kubernetes` sets the ALB's idle
/// timeout accordingly.
pub const DEFAULT_OCI_DEPLOY_SYNC_WAIT_MS: u64 = 240_000;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub(crate) observation_store: Arc<ObservationStoreLane>,
    pub usage: Arc<dyn UsageStore>,
    pub credits: Arc<dyn CreditStore>,
    pub storage_meta: Arc<dyn MetadataStore>,
    pub(crate) cat_create:
        Arc<crate::store::runtime_authority::cat_create_service::CatCreateService>,
    pub(crate) readiness: Arc<ReadinessLatch>,
    pub notify: Arc<tokio::sync::Notify>,
    pub controller: Arc<Controller>,
    pub cfg: Arc<Config>,
    pub(crate) agent_session_registration_policy: Arc<crate::store::AgentSessionRegistrationPolicy>,
    pub(crate) runtime_spine_admission: Arc<RuntimeSpineAdmission>,
    pub(crate) runtime_volume_transition_admission: Arc<RuntimeSpineAdmission>,
    pub(crate) runtime_volume_transition_service: Arc<RuntimeVolumeTransitionService>,
    pub(crate) runtime_node_authority:
        Arc<crate::api::runtime_node_authority::RuntimeNodeAuthorityService>,
    /// The old Controller/NodeJob runtime exists only to keep the explicit
    /// pre-cutover integration harness exercising its historical contract.
    /// Production handlers consult this before touching any legacy work row
    /// or Node HTTP surface.
    pub(crate) legacy_node_runtime_for_tests: bool,
}

pub struct Handle {
    /// Bound address, e.g. `127.0.0.1:53412`.
    pub addr: std::net::SocketAddr,
    pub state: AppState,
    server_task: tokio::task::JoinHandle<()>,
    reconciler_task: Option<tokio::task::JoinHandle<()>>,
    billing_enforcer_task: Option<tokio::task::JoinHandle<()>>,
    image_manifest_resolver: Arc<
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver,
    >,
    server_shutdown: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

pub(crate) struct ReadinessLatch(std::sync::atomic::AtomicBool);

impl ReadinessLatch {
    fn new() -> Self {
        Self(std::sync::atomic::AtomicBool::new(true))
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn poison(&self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn begin_shutdown(&self) {
        self.state.cat_create.begin_shutdown();
        self.state
            .runtime_volume_transition_service
            .begin_shutdown();
        self.state.runtime_node_authority.begin_shutdown();
        self.image_manifest_resolver.begin_shutdown();
        self.state.observation_store.begin_shutdown();
        if let Some(shutdown) = self
            .server_shutdown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = shutdown.send(());
        }
        if let Some(task) = &self.reconciler_task {
            task.abort();
        }
        if let Some(task) = &self.billing_enforcer_task {
            task.abort();
        }
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        // Stop accepting product work before waiting for the dedicated
        // blocking manifest lane. The resolver itself closes its queue and
        // bounds this wait by the provider transport deadline.
        self.begin_shutdown();
        let observation_store = self.state.observation_store.shutdown();
        let volume_transitions = self.state.runtime_volume_transition_service.shutdown();
        let commit_resolutions = self.state.cat_create.shutdown_commit_resolutions();
        let node_authority_resolutions = self
            .state
            .runtime_node_authority
            .shutdown_commit_resolutions();
        let manifest_reads = self.image_manifest_resolver.shutdown();
        let (_, transition_result, commit_result, node_authority_result, manifest_result) = tokio::join!(
            observation_store,
            volume_transitions,
            commit_resolutions,
            node_authority_resolutions,
            manifest_reads
        );
        if !manifest_result {
            tracing::warn!("image manifest reads exceeded the shutdown deadline");
        }
        // Graceful shutdown has already stopped admission. Abort any unrelated
        // long-lived HTTP connection after Cat commit ownership is resolved.
        self.server_task.abort();
        transition_result?;
        commit_result.map_err(anyhow::Error::from)?;
        node_authority_result.map_err(anyhow::Error::from)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Drop cannot await. It still prevents new work and cancels async
        // roles; production's signal path calls the async shutdown above.
        self.begin_shutdown();
        self.server_task.abort();
    }
}

/// Run one background role only while this process owns its PostgreSQL
/// advisory lock. The lock connection is separate from the API Store
/// connection: a slow handler cannot delay lease health, and losing the
/// database session aborts the role before another replica takes it over.
pub fn spawn_singleton_task<F, Fut>(
    store: Arc<Store>,
    role: SingletonRole,
    make_task: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        'election: loop {
            let session_store = store.clone();
            let mut session = match crate::store::execute_leadership(move || {
                session_store.singleton_session(role)
            })
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(
                        role = role.name(),
                        error = %error,
                        "opening singleton election session failed"
                    );
                    tokio::time::sleep(SINGLETON_ELECTION_RETRY).await;
                    continue;
                }
            };

            loop {
                match singleton_try_acquire(session).await {
                    Ok((returned, true)) => {
                        session = returned;
                        break;
                    }
                    Ok((returned, false)) => {
                        session = returned;
                        tokio::time::sleep(SINGLETON_ELECTION_RETRY).await;
                    }
                    Err(error) => {
                        tracing::warn!(
                            role = role.name(),
                            error = %error,
                            "singleton election session failed"
                        );
                        tokio::time::sleep(SINGLETON_ELECTION_RETRY).await;
                        continue 'election;
                    }
                }
            }

            tracing::info!(role = role.name(), "acquired singleton leadership");
            let (cancel, cancelled) = tokio::sync::oneshot::channel();
            let supervisor =
                tokio::spawn(run_elected_singleton(session, role, make_task(), cancelled));
            // Declared after the JoinHandle so task cancellation sends the
            // signal before detaching the supervisor. The supervisor retains
            // the advisory lock until its role has actually stopped.
            let cancel_on_drop = CancelSingletonOnDrop(Some(cancel));
            if let Err(error) = supervisor.await {
                tracing::error!(
                    role = role.name(),
                    %error,
                    "singleton supervisor failed; relinquishing leadership"
                );
            }
            drop(cancel_on_drop);
            tokio::time::sleep(SINGLETON_ELECTION_RETRY).await;
        }
    })
}

async fn run_elected_singleton<Fut>(
    session: crate::store::SingletonSession,
    role: SingletonRole,
    task: Fut,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
) where
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut session = Some(session);
    let mut task = tokio::spawn(task);
    loop {
        tokio::select! {
            result = &mut task => {
                match result {
                    Ok(()) => tracing::warn!(
                        role = role.name(),
                        "singleton task exited; relinquishing leadership"
                    ),
                    Err(error) => tracing::error!(
                        role = role.name(),
                        %error,
                        "singleton task failed; relinquishing leadership"
                    ),
                }
                break;
            }
            _ = &mut cancelled => {
                task.abort();
                let _ = (&mut task).await;
                break;
            }
            _ = tokio::time::sleep(SINGLETON_HEALTH_INTERVAL) => {
                let current = session.take().expect("singleton session is present between checks");
                match singleton_check(current).await {
                    Ok(returned) => session = Some(returned),
                    Err(error) => {
                        tracing::warn!(
                            role = role.name(),
                            %error,
                            "singleton leadership connection was lost"
                        );
                        task.abort();
                        let _ = (&mut task).await;
                        break;
                    }
                }
            }
        }
    }
    // `task.await` above proves its future has been dropped before this owner
    // releases the PostgreSQL session and makes leadership acquirable again.
    if let Some(session) = session {
        let _ = crate::store::execute_leadership(move || {
            drop(session);
            Ok(())
        })
        .await;
    }
}

async fn singleton_try_acquire(
    mut session: crate::store::SingletonSession,
) -> crate::store::Result<(crate::store::SingletonSession, bool)> {
    crate::store::execute_leadership(move || {
        let acquired = session.try_acquire()?;
        Ok((session, acquired))
    })
    .await
}

async fn singleton_check(
    mut session: crate::store::SingletonSession,
) -> crate::store::Result<crate::store::SingletonSession> {
    crate::store::execute_leadership(move || {
        session.check()?;
        Ok(session)
    })
    .await
}

async fn run_reconciler_role(controller: Arc<Controller>, store: Arc<Store>, interval: Duration) {
    let reap_interrupted_deploys = async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match store
                .execute(|store| store.fail_interrupted_oci_deployments())
                .await
            {
                Ok(0) => {}
                Ok(count) => tracing::warn!(
                    count,
                    "failed OCI deployments whose owner sessions disappeared"
                ),
                Err(error) => tracing::error!(
                    %error,
                    "checking interrupted OCI deployments failed"
                ),
            }
        }
    };
    tokio::join!(controller.run(interval), reap_interrupted_deploys);
}

/// Start the control plane inside the current tokio runtime.
pub async fn spawn(cfg: Config) -> anyhow::Result<Handle> {
    spawn_inner(cfg, false).await
}

/// Pre-cutover integration harness. The shipped daemon calls [`spawn`], whose
/// production route map has no legacy heartbeat or Node work mutation routes.
#[doc(hidden)]
pub async fn spawn_with_legacy_node_runtime_for_tests(cfg: Config) -> anyhow::Result<Handle> {
    spawn_inner(cfg, true).await
}

async fn spawn_inner(cfg: Config, legacy_node_runtime_for_tests: bool) -> anyhow::Result<Handle> {
    anyhow::ensure!(
        !cfg.auth_token.is_empty(),
        "service token must not be empty"
    );
    anyhow::ensure!(!cfg.admin_token.is_empty(), "admin token must not be empty");
    anyhow::ensure!(
        cfg.auth_token != cfg.admin_token,
        "service and admin tokens must be different"
    );
    anyhow::ensure!(
        legacy_node_runtime_for_tests || !cfg.billing_enforcement_enabled,
        "legacy Cat billing enforcement is unavailable during the signed runtime cutover"
    );
    anyhow::ensure!(
        cfg.auto_tier_policy
            .warm_after_ms
            .is_none_or(|value| value > 0),
        "automatic Warm threshold must be positive"
    );
    anyhow::ensure!(
        cfg.auto_tier_policy
            .cold_after_ms
            .is_none_or(|value| value > 0),
        "automatic Cold threshold must be positive"
    );
    let cfg = Arc::new(cfg);
    let agent_session_registration_policy = Arc::new(
        crate::store::AgentSessionRegistrationPolicy::from_release_receipt(
            &cfg.guest_runtime_profile_receipt,
        )?,
    );
    let ca_file = cfg
        .control_store_ca_file
        .as_deref()
        .and_then(|path| path.to_str())
        .map(str::to_string);
    let store = Arc::new(Store::connect_from_async(cfg.control_store_dsn.clone(), ca_file).await?);
    let trust_bundle = cfg.runtime_provisioner_trust_bundle.clone();
    store
        .execute(move |store| store.install_runtime_provisioner_trust_bundle(&trust_bundle))
        .await
        .context("install runtime provisioner trust bundle")?;
    let observation_store = ObservationStoreLane::connect_from_async(
        cfg.control_store_dsn.clone(),
        cfg.control_store_ca_file
            .as_deref()
            .and_then(|path| path.to_str())
            .map(str::to_string),
    )
    .await?;
    if let Some(workos) = &cfg.workos {
        let organizations = workos.account_organizations().clone();
        store
            .execute(move |store| store.ensure_configured_accounts(&organizations))
            .await?;
    } else {
        // The credential-free development shape has one explicit bootstrap
        // account. Production WorkOS deployments provision Accounts through
        // AuthKit onboarding or the configured mapping instead.
        store
            .execute(|store| {
                store.ensure_configured_accounts(&std::collections::BTreeMap::from([(
                    "default".to_string(),
                    "local-development".to_string(),
                )]))
            })
            .await?;
    }
    if legacy_node_runtime_for_tests {
        // Legacy OCI deploys are driven by an in-memory Node HTTP task. Only
        // the explicit legacy harness is allowed to converge those rows; the
        // signed production process must not claim ownership of that runtime.
        match store
            .execute(|store| store.fail_interrupted_oci_deployments())
            .await
        {
            Ok(0) => {}
            Ok(count) => {
                tracing::warn!("failed {count} OCI deployment(s) interrupted by a restart")
            }
            Err(error) => {
                tracing::error!("converging interrupted OCI deployments failed: {error}")
            }
        }
    }
    let usage = cfg.usage_store.clone();
    let credits = cfg.credit_store.clone();
    let storage_meta = cfg.storage_meta.clone();
    let image_manifests = Arc::new(
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver::new(
            cfg.image_blob.clone(),
        ),
    );
    let cat_create = Arc::new(
        crate::store::runtime_authority::cat_create_service::CatCreateService::new(
            store.clone(),
            image_manifests.clone(),
            Arc::new(
                crate::store::runtime_authority::placement_planner::PostgresCatCreatePlacementPlanner::new(
                    store.clone(),
                ),
            ),
            Arc::new(
                crate::store::runtime_authority::cat_create_service::UuidCatCreateIdentitySource,
            ),
            &cfg.guest_runtime_profile_receipt,
        )?,
    );
    let readiness = Arc::new(ReadinessLatch::new());
    let notify = Arc::new(tokio::sync::Notify::new());
    let controller = Controller::new_with_liveness_authority(
        store.clone(),
        storage_meta.clone(),
        notify.clone(),
        cfg.node_lease_timeout_ms,
        cfg.auth_token.clone(),
        cfg.auto_tier_policy,
        if legacy_node_runtime_for_tests {
            NodeLivenessAuthority::LegacyHeartbeatForTests
        } else {
            NodeLivenessAuthority::SignedSession
        },
    );
    let state = AppState {
        runtime_node_authority: Arc::new(
            crate::api::runtime_node_authority::RuntimeNodeAuthorityService::new(
                store.clone(),
                cfg.runtime_provisioner_trust_bundle.clone(),
                Arc::clone(&readiness),
            ),
        ),
        store,
        observation_store,
        usage,
        credits,
        storage_meta,
        cat_create,
        readiness,
        notify,
        controller: controller.clone(),
        cfg: cfg.clone(),
        agent_session_registration_policy,
        runtime_spine_admission: Arc::new(RuntimeSpineAdmission::new()),
        runtime_volume_transition_admission: Arc::new(RuntimeSpineAdmission::new()),
        runtime_volume_transition_service: Arc::new(RuntimeVolumeTransitionService::new()),
        legacy_node_runtime_for_tests,
    };

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = if legacy_node_runtime_for_tests {
        crate::api::router_with_legacy_node_runtime_for_tests(state.clone())
    } else {
        crate::api::router(state.clone())
    };
    let (server_shutdown, server_shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = server_shutdown_rx.await;
            })
            .await
        {
            tracing::error!("control plane server exited: {e}");
        }
    });
    let interval = Duration::from_millis(cfg.reconcile_interval_ms);
    let reconciler_task = legacy_node_runtime_for_tests.then(|| {
        let reconciler = controller.clone();
        let reconciler_store = state.store.clone();
        spawn_singleton_task(state.store.clone(), SingletonRole::Reconciler, move || {
            run_reconciler_role(reconciler.clone(), reconciler_store.clone(), interval)
        })
    });
    let billing_enforcer_task =
        (legacy_node_runtime_for_tests && cfg.billing_enforcement_enabled).then(|| {
        let enforcement_state = state.clone();
        spawn_singleton_task(
            state.store.clone(),
            SingletonRole::BillingEnforcer,
            move || {
                let enforcement_state = enforcement_state.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        interval.tick().await;
                        if let Err(error) =
                            crate::api::enforce_exhausted_billing_accounts(&enforcement_state).await
                        {
                            tracing::error!(error = %error.0, "billing credit enforcement failed");
                        }
                    }
                }
            },
        )
    });

    tracing::info!(%addr, "control plane ready");
    Ok(Handle {
        addr,
        state,
        server_task,
        reconciler_task,
        billing_enforcer_task,
        image_manifest_resolver: image_manifests,
        server_shutdown: std::sync::Mutex::new(Some(server_shutdown)),
    })
}

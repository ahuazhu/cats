//! Control-plane assembly: config, shared state, singleton tasks and HTTP
//! servers. Every process composes the independent Route v2 machine authority.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::Context;
use cats_api::gateway_workload_identity::GatewayWorkloadIdentityAuthority;
use cats_api::runtime_artifacts::{
    InstalledGatewayMachineArtifacts, InstalledRouteGrantV2Signer,
    InstalledRouteV2RotationOperatorTrust,
};
use cats_api::runtime_reconciliation::{GuestRuntimeProfileReceipt, RuntimeProvisionerTrustBundle};
use cats_metering::{CreditStore, UsageStore};
use cats_storage::BlobStore;

use crate::store::{
    DsnSource, LifecycleStoreLane, ObservationStoreLane, RouteStoreLane, SingletonRole, Store,
};

const SINGLETON_ELECTION_RETRY: Duration = Duration::from_millis(500);
const SINGLETON_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const RUNTIME_SPINE_GLOBAL_IN_FLIGHT: usize = 64;
const ROUTE_RESOLVE_V2_GLOBAL_IN_FLIGHT: usize = 32;
const GATEWAY_AUTHENTICATION_GLOBAL_IN_FLIGHT: usize = 32;

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
}

/// Ask an elected-role supervisor to stop if its election task is cancelled.
/// The supervisor owns the PostgreSQL session, so dropping this guard cannot
/// release leadership ahead of the role it is fencing.
struct CancelSingletonOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

impl CancelSingletonOnDrop {
    fn cancel(&mut self) {
        if let Some(cancel) = self.0.take() {
            let _ = cancel.send(());
        }
    }
}

impl Drop for CancelSingletonOnDrop {
    fn drop(&mut self) {
        self.cancel();
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
    /// Control-owned object-store boundary. A21 reads exact immutable
    /// golden-image keys; the delete sweeper removes only an authority-proved
    /// exact `volumes/<volume_id>/` prefix.
    pub image_blob: Arc<dyn BlobStore>,
    /// Service credential used by node agents, gateways and controller jobs.
    pub auth_token: String,
    /// Shared Bearer credential for semantic Node registration, heartbeat and
    /// synchronous Control -> noded calls.
    pub noded_service_token: String,
    /// Exact, startup-validated release receipt from the active qualified
    /// Guest runtime. It binds both new Agent sessions and Cat placement.
    /// Production loads it from the one canonical installed path.
    pub guest_runtime_profile_receipt: GuestRuntimeProfileReceipt,
    /// Exact deployment-provisioner trust bundle loaded from the one A23
    /// installed path. Startup persists/exact-replays its monotonic lineage
    /// before opening the administrator listener.
    pub runtime_provisioner_trust_bundle: RuntimeProvisionerTrustBundle,
    /// Independent release-bound public trust for the offline E13 cutover
    /// operator key. It is loaded only from its canonical installed path.
    pub production_cutover_operator_trust_bundle:
        cats_api::production_mutation_admission::ProductionCutoverOperatorTrustBundle,
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

/// Fully validated composition for the independent Gateway machine listener.
/// Fixed PEM/private bytes are parsed and dropped by `new`; this value retains
/// only the TLS provider objects, canonical Gateway install candidate and
/// validated Route v2 signer/binding.
pub struct GatewayMachineConfig {
    listen: String,
    rotation_listen: Option<String>,
    gateway_authority: GatewayWorkloadIdentityAuthority,
    tls_config: crate::gateway_machine::GatewayMachineTlsConfig,
    rotation_tls_config: Option<crate::route_rotation_machine::RouteRotationMachineTlsConfig>,
    signing_authority: Arc<crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority>,
    rotation_operator_trust: Option<InstalledRouteV2RotationOperatorTrust>,
    rotation_release_commit_sha: Option<String>,
}

impl GatewayMachineConfig {
    pub fn new(
        listen: impl Into<String>,
        rotation_listen: impl Into<String>,
        gateway_artifacts: InstalledGatewayMachineArtifacts,
        signer_artifacts: InstalledRouteGrantV2Signer,
        rotation_operator_trust: InstalledRouteV2RotationOperatorTrust,
        route_grant_v2_ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        let listen = listen.into();
        let rotation_listen = rotation_listen.into();
        anyhow::ensure!(
            !listen.is_empty(),
            "Gateway machine listen address is empty"
        );
        anyhow::ensure!(
            !rotation_listen.is_empty() && rotation_listen != listen,
            "Route rotation machine listen must be nonempty and independent"
        );
        // Complete TLS/key-pair validation before PostgreSQL installation or
        // either network bind. Raw fixed private bytes drop on return.
        let tls_config = crate::gateway_machine::GatewayMachineTlsConfig::from_installed_artifacts(
            &gateway_artifacts,
        )?;
        let rotation_tls_config =
            crate::route_rotation_machine::RouteRotationMachineTlsConfig::from_installed_artifacts(
                &gateway_artifacts,
            )?;
        let signing_authority = Arc::new(
            crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority::from_installed_artifacts(
                &signer_artifacts,
                route_grant_v2_ttl_seconds,
            )?,
        );
        let rotation_release_commit_sha = embedded_route_v2_rotation_release_commit_sha(
            rotation_operator_trust.trust().release_commit_sha.as_str(),
        )?;
        Ok(Self {
            listen,
            rotation_listen: Some(rotation_listen),
            gateway_authority: gateway_artifacts.authority().clone(),
            tls_config,
            rotation_tls_config: Some(rotation_tls_config),
            signing_authority,
            rotation_operator_trust: Some(rotation_operator_trust),
            rotation_release_commit_sha: Some(rotation_release_commit_sha),
        })
    }

    #[cfg(any(debug_assertions, feature = "test-support"))]
    pub(crate) fn from_test_composition(
        listen: impl Into<String>,
        gateway_authority: GatewayWorkloadIdentityAuthority,
        tls_config: crate::gateway_machine::GatewayMachineTlsConfig,
        signing_authority: Arc<crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority>,
    ) -> anyhow::Result<Self> {
        let listen = listen.into();
        anyhow::ensure!(
            !listen.is_empty(),
            "Gateway machine test listen address is empty"
        );
        Ok(Self {
            listen,
            rotation_listen: None,
            gateway_authority,
            tls_config,
            rotation_tls_config: None,
            signing_authority,
            rotation_operator_trust: None,
            rotation_release_commit_sha: None,
        })
    }
}

fn embedded_route_v2_rotation_release_commit_sha(trust_release: &str) -> anyhow::Result<String> {
    let embedded = option_env!("CATS_RELEASE_COMMIT_SHA");
    #[cfg(debug_assertions)]
    let embedded = embedded.unwrap_or(trust_release);
    #[cfg(not(debug_assertions))]
    let embedded = embedded
        .context("release build omitted CATS_RELEASE_COMMIT_SHA for Route v2 rotation authority")?;
    // Name both sides: a mismatch here stops startup, and without the values
    // an operator cannot tell a stale trust bundle from a build that embedded
    // the wrong commit.
    anyhow::ensure!(
        embedded == trust_release,
        "Route v2 rotation operator trust does not bind this exact release: \
         binary embeds {embedded:?}, trust bundle binds {trust_release:?}"
    );
    Ok(embedded.to_owned())
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
    pub(crate) semantic_resources: Arc<dyn crate::api::semantic_resources::SemanticResourceApi>,
    pub(crate) semantic_node_http: crate::api::semantic_nodes::SemanticNodeHttpState,
    pub(crate) observation_store: Arc<ObservationStoreLane>,
    pub(crate) lifecycle_store: Arc<LifecycleStoreLane>,
    pub(crate) route_store: Arc<RouteStoreLane>,
    pub usage: Arc<dyn UsageStore>,
    pub credits: Arc<dyn CreditStore>,
    pub(crate) cat_create:
        Arc<crate::store::runtime_authority::cat_create_service::CatCreateService>,
    pub(crate) persistent_disk_create: Arc<
        crate::store::runtime_authority::persistent_disk_create_service::PersistentDiskCreateService,
    >,
    pub(crate) product_mutations:
        Arc<crate::store::runtime_authority::product_mutation_service::ProductMutationService>,
    pub(crate) readiness: Arc<ReadinessLatch>,
    pub cfg: Arc<Config>,
    pub(crate) agent_session_registration_policy: Arc<crate::store::AgentSessionRegistrationPolicy>,
    pub(crate) runtime_spine_admission: Arc<RuntimeSpineAdmission>,
    /// Per-replica work bound for the machine-authenticated Route Grant v2
    /// resolve lane. Authentication is checked before a permit is acquired.
    pub(crate) route_resolve_admission: Arc<crate::api::route_resolve_v2::RouteResolveV2Admission>,
    /// Independent work bound for the Node's read of its own object-write
    /// writer authority. It is deliberately separate from the Desired-read and
    /// volume-transition lanes so one authority read per Agent session can
    /// never contend with, or be starved by, the reconcile loop.
    pub(crate) object_write_authority_read_admission: Arc<RuntimeSpineAdmission>,
    pub(crate) runtime_node_authority:
        Arc<crate::api::runtime_node_authority::RuntimeNodeAuthorityService>,
    pub(crate) route_v2_signing_operator:
        Option<Arc<crate::api::route_signing_operator::RouteV2SigningOperatorService>>,
}

pub struct Handle {
    /// Bound address, e.g. `127.0.0.1:53412`.
    pub addr: std::net::SocketAddr,
    /// Bound when the installed signer is active. A disabled signer keeps this
    /// absent and poisons readiness while the rotation listener remains live.
    pub gateway_machine_addr: Option<std::net::SocketAddr>,
    /// Bound whenever the production Route rotation authority is installed,
    /// including while the loaded signer is disabled and readiness is closed.
    pub route_rotation_machine_addr: Option<std::net::SocketAddr>,
    pub state: AppState,
    server_task: tokio::task::JoinHandle<()>,
    semantic_node_liveness_shutdown: tokio::sync::watch::Sender<bool>,
    semantic_node_liveness_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    volume_delete_sweeper_task: Option<ManagedSingletonTask>,
    route_controller_task: ManagedSingletonTask,
    image_manifest_resolver: Arc<
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver,
    >,
    server_shutdown: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    gateway_machine_listener: Option<crate::gateway_machine::GatewayMachineListener>,
    route_rotation_machine_listener:
        Option<crate::route_rotation_machine::RouteRotationMachineListener>,
}

/// Joinable ownership of one elected background role.
pub struct ManagedSingletonTask {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ManagedSingletonTask {
    /// Stop election retries and signal an active role to relinquish leadership.
    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Signal shutdown and wait for the role, retained resolutions and
    /// PostgreSQL advisory-lock release to complete.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let mut task = self.task.lock().await;
        let result = match task.as_mut() {
            Some(task) => task.await.context("singleton election task failed"),
            None => Ok(()),
        };
        // Keep the handle in the slot while awaiting it. If this shutdown
        // future is cancelled, a later call can resume the same join instead
        // of mistaking a detached cleanup for a completed one.
        task.take();
        result
    }
}

pub(crate) struct ReadinessLatch(std::sync::atomic::AtomicBool);

impl ReadinessLatch {
    pub(crate) fn new() -> Self {
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
        if let Some(listener) = &self.route_rotation_machine_listener {
            listener.begin_shutdown();
        }
        if let Some(listener) = &self.gateway_machine_listener {
            listener.begin_shutdown();
        }
        self.state.cat_create.begin_shutdown();
        self.state.persistent_disk_create.begin_shutdown();
        self.state.product_mutations.begin_shutdown();
        self.state.route_resolve_admission.begin_shutdown();
        self.state.runtime_node_authority.begin_shutdown();
        if let Some(service) = &self.state.route_v2_signing_operator {
            service.begin_shutdown();
        }
        self.image_manifest_resolver.begin_shutdown();
        self.state.observation_store.begin_shutdown();
        self.state.lifecycle_store.begin_shutdown();
        self.state.route_store.begin_shutdown();
        if let Some(shutdown) = self
            .server_shutdown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = shutdown.send(());
        }
        self.semantic_node_liveness_shutdown.send_replace(true);
        if let Some(task) = &self.volume_delete_sweeper_task {
            task.begin_shutdown();
        }
        self.route_controller_task.begin_shutdown();
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        // Stop accepting product work before waiting for the dedicated
        // blocking manifest lane. The resolver itself closes its queue and
        // bounds this wait by the provider transport deadline.
        self.begin_shutdown();
        let observation_store = self.state.observation_store.shutdown();
        let lifecycle_store = self.state.lifecycle_store.shutdown();
        let route_store = self.state.route_store.shutdown();
        let route_resolutions = self.state.route_resolve_admission.shutdown();
        let commit_resolutions = self.state.cat_create.shutdown_commit_resolutions();
        let persistent_disk_commit_resolutions = self
            .state
            .persistent_disk_create
            .shutdown_commit_resolutions();
        let product_mutation_commit_resolutions =
            self.state.product_mutations.shutdown_commit_resolutions();
        let node_authority_resolutions = self
            .state
            .runtime_node_authority
            .shutdown_commit_resolutions();
        let route_rotation_resolutions = async {
            if let Some(service) = &self.state.route_v2_signing_operator {
                service.shutdown_commit_resolutions().await
            } else {
                Ok(())
            }
        };
        let manifest_reads = self.image_manifest_resolver.shutdown();
        let volume_delete_sweeper = async {
            if let Some(task) = &self.volume_delete_sweeper_task {
                task.shutdown().await
            } else {
                Ok(())
            }
        };
        let route_controller = self.route_controller_task.shutdown();
        let semantic_node_liveness = async {
            let mut task = self.semantic_node_liveness_task.lock().await;
            match task.take() {
                Some(task) => task.await.context("semantic Node liveness task failed"),
                None => Ok(()),
            }
        };
        let gateway_machine = async {
            if let Some(listener) = &self.gateway_machine_listener {
                listener.shutdown().await
            } else {
                Ok(())
            }
        };
        let route_rotation_machine = async {
            if let Some(listener) = &self.route_rotation_machine_listener {
                listener.shutdown().await
            } else {
                Ok(())
            }
        };
        let (
            _,
            _,
            _,
            route_result,
            commit_result,
            persistent_disk_commit_result,
            product_mutation_commit_result,
            node_authority_result,
            route_rotation_result,
            manifest_result,
            gateway_machine_result,
            route_rotation_machine_result,
            volume_delete_sweeper_result,
            route_controller_result,
            semantic_node_liveness_result,
        ) = tokio::join!(
            observation_store,
            lifecycle_store,
            route_store,
            route_resolutions,
            commit_resolutions,
            persistent_disk_commit_resolutions,
            product_mutation_commit_resolutions,
            node_authority_resolutions,
            route_rotation_resolutions,
            manifest_reads,
            gateway_machine,
            route_rotation_machine,
            volume_delete_sweeper,
            route_controller,
            semantic_node_liveness
        );
        if !manifest_result {
            tracing::warn!("image manifest reads exceeded the shutdown deadline");
        }
        // Graceful shutdown has already stopped admission. Abort any unrelated
        // long-lived HTTP connection after Cat commit ownership is resolved.
        self.server_task.abort();
        route_result?;
        gateway_machine_result?;
        route_rotation_machine_result?;
        volume_delete_sweeper_result?;
        route_controller_result?;
        semantic_node_liveness_result?;
        commit_result.map_err(anyhow::Error::from)?;
        persistent_disk_commit_result.map_err(anyhow::Error::from)?;
        product_mutation_commit_result.map_err(anyhow::Error::from)?;
        node_authority_result.map_err(anyhow::Error::from)?;
        route_rotation_result
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
    tokio::spawn(run_singleton_election(store, role, make_task, None))
}

/// Run one background role under a joinable PostgreSQL singleton election.
pub fn spawn_managed_singleton_task<F, Fut>(
    store: Arc<Store>,
    role: SingletonRole,
    make_task: F,
) -> ManagedSingletonTask
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(run_singleton_election(
        store,
        role,
        make_task,
        Some(shutdown_rx),
    ));
    ManagedSingletonTask {
        shutdown,
        task: tokio::sync::Mutex::new(Some(task)),
    }
}

async fn run_singleton_election<F, Fut>(
    store: Arc<Store>,
    role: SingletonRole,
    make_task: F,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    'election: loop {
        if singleton_shutdown_requested(&shutdown) {
            return;
        }
        let session_store = store.clone();
        let mut session =
            match crate::store::execute_leadership(move || session_store.singleton_session(role))
                .await
            {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(
                        role = role.name(),
                        error = %error,
                        "opening singleton election session failed"
                    );
                    if singleton_retry_or_shutdown(&mut shutdown).await {
                        return;
                    }
                    continue;
                }
            };

        loop {
            if singleton_shutdown_requested(&shutdown) {
                return;
            }
            match singleton_try_acquire(session).await {
                Ok((returned, true)) => {
                    session = returned;
                    break;
                }
                Ok((returned, false)) => {
                    session = returned;
                    if singleton_retry_or_shutdown(&mut shutdown).await {
                        return;
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        role = role.name(),
                        error = %error,
                        "singleton election session failed"
                    );
                    if singleton_retry_or_shutdown(&mut shutdown).await {
                        return;
                    }
                    continue 'election;
                }
            }
        }

        tracing::info!(role = role.name(), "acquired singleton leadership");
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let task = make_task();
        let mut supervisor = tokio::spawn(run_elected_singleton(session, role, task, cancelled));
        // Declared after the JoinHandle so task cancellation sends the signal
        // before detaching the supervisor. The supervisor retains the advisory
        // lock until its role has actually stopped.
        let mut cancel_on_drop = CancelSingletonOnDrop(Some(cancel));
        let (supervisor_result, stopping) = match shutdown.as_mut() {
            Some(shutdown) => tokio::select! {
                result = &mut supervisor => (result, false),
                () = wait_for_singleton_shutdown(shutdown) => {
                    cancel_on_drop.cancel();
                    (supervisor.await, true)
                }
            },
            None => (supervisor.await, false),
        };
        if let Err(error) = supervisor_result {
            tracing::error!(
                role = role.name(),
                %error,
                "singleton supervisor failed; relinquishing leadership"
            );
        }
        drop(cancel_on_drop);
        if stopping || singleton_shutdown_requested(&shutdown) {
            return;
        }
        if singleton_retry_or_shutdown(&mut shutdown).await {
            return;
        }
    }
}

fn singleton_shutdown_requested(shutdown: &Option<tokio::sync::watch::Receiver<bool>>) -> bool {
    shutdown
        .as_ref()
        .is_some_and(|shutdown| *shutdown.borrow() || shutdown.has_changed().is_err())
}

async fn singleton_retry_or_shutdown(
    shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>,
) -> bool {
    match shutdown.as_mut() {
        Some(shutdown) => tokio::select! {
            () = tokio::time::sleep(SINGLETON_ELECTION_RETRY) => false,
            () = wait_for_singleton_shutdown(shutdown) => true,
        },
        None => {
            tokio::time::sleep(SINGLETON_ELECTION_RETRY).await;
            false
        }
    }
}

async fn wait_for_singleton_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
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
    if let Some(session) = session {
        if let Err(error) = crate::store::execute_leadership_cleanup(move || {
            session.close_now();
        })
        .await
        {
            tracing::error!(
                role = role.name(),
                %error,
                "singleton advisory session cleanup failed"
            );
        }
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

/// Start the public control plane plus the isolated mTLS Gateway machine
/// listener. The machine authority is installed/exact-replayed before either
/// listener binds; failure has no bearer/plain/public-router fallback.
pub async fn spawn_with_gateway_machine(
    cfg: Config,
    gateway_machine: GatewayMachineConfig,
) -> anyhow::Result<Handle> {
    anyhow::ensure!(
        !cfg.auth_token.is_empty(),
        "service token must not be empty"
    );
    anyhow::ensure!(!cfg.admin_token.is_empty(), "admin token must not be empty");
    anyhow::ensure!(
        cfg.auth_token != cfg.admin_token,
        "service and admin tokens must be different"
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
    anyhow::ensure!(
        cfg.production_cutover_operator_trust_bundle.deployment_id
            == cfg.runtime_provisioner_trust_bundle.deployment_id,
        "production cutover operator trust deployment does not match Control deployment"
    );
    match option_env!("CATS_RELEASE_COMMIT_SHA") {
        Some(release_commit) => anyhow::ensure!(
            release_commit
                == cfg
                    .production_cutover_operator_trust_bundle
                    .source_commit_sha,
            "production cutover operator trust is not bound to this qualified Control release"
        ),
        None => anyhow::ensure!(
            cfg!(any(debug_assertions, feature = "test-support")),
            "production Control build has no qualified release commit"
        ),
    }
    if let Some(installed) = &gateway_machine.rotation_operator_trust {
        let trust = installed.trust().clone();
        let exact_bytes = installed.exact_bytes().to_vec();
        store
            .execute(move |store| {
                store.install_route_v2_rotation_operator_trust(&trust, &exact_bytes)
            })
            .await
            .context("install Route v2 rotation operator trust")?;
    }
    let signing_authority = Arc::clone(&gateway_machine.signing_authority);
    store
        .execute(move |store| store.install_route_grant_v2_signer_authority(&signing_authority))
        .await
        .context("install Route Grant v2 signing authority")?;
    let gateway_authority = gateway_machine.gateway_authority.clone();
    store
        .execute(move |store| store.install_gateway_workload_identity_authority(&gateway_authority))
        .await
        .context("install Gateway workload identity authority")?;
    let observation_store = ObservationStoreLane::connect_from_async(
        cfg.control_store_dsn.clone(),
        cfg.control_store_ca_file
            .as_deref()
            .and_then(|path| path.to_str())
            .map(str::to_string),
    )
    .await?;
    let lifecycle_store = LifecycleStoreLane::connect_from_async(
        cfg.control_store_dsn.clone(),
        cfg.control_store_ca_file
            .as_deref()
            .and_then(|path| path.to_str())
            .map(str::to_string),
    )
    .await?;
    let route_store = RouteStoreLane::connect_from_async(
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
    let usage = cfg.usage_store.clone();
    let credits = cfg.credit_store.clone();
    let image_manifests = Arc::new(
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver::new(
            cfg.image_blob.clone(),
        ),
    );
    let product_identities: Arc<
        dyn crate::store::runtime_authority::product_identity::ProductIdentitySource,
    > = Arc::new(crate::store::runtime_authority::product_identity::UuidProductIdentitySource);
    let cat_create = Arc::new(
        crate::store::runtime_authority::cat_create_service::CatCreateService::new(
            store.clone(),
            image_manifests.clone(),
            Arc::new(
                crate::store::runtime_authority::placement_planner::PostgresCatCreatePlacementPlanner::new(
                    store.clone(),
                ),
            ),
            Arc::clone(&product_identities),
            &cfg.guest_runtime_profile_receipt,
        )?,
    );
    let persistent_disk_create = Arc::new(
        crate::store::runtime_authority::persistent_disk_create_service::PersistentDiskCreateService::new(
            store.clone(),
            Arc::clone(&product_identities),
        ),
    );
    let product_mutations = Arc::new(
        crate::store::runtime_authority::product_mutation_service::ProductMutationService::new(
            store.clone(),
            product_identities,
            agent_session_registration_policy
                .approved_guest_config_digest()
                .clone(),
        ),
    );
    let readiness = Arc::new(ReadinessLatch::new());
    let gateway_machine_control = Arc::new(
        crate::api::route_resolve_v2::RouteResolveV2MachineControl::new(Arc::clone(&readiness)),
    );
    let route_v2_signing_operator = match (
        gateway_machine.rotation_operator_trust.as_ref(),
        gateway_machine.rotation_release_commit_sha.as_ref(),
    ) {
        (Some(installed), Some(release)) => Some(Arc::new(
            crate::api::route_signing_operator::RouteV2SigningOperatorService::new(
                Arc::clone(&store),
                installed.trust().clone(),
                release.clone(),
                Arc::clone(&readiness),
                Arc::new(gateway_machine.signing_authority.binding().clone()),
                Some(Arc::clone(&gateway_machine_control)),
            )?,
        )),
        (None, None) => None,
        _ => anyhow::bail!("incomplete Route v2 rotation operator composition"),
    };
    let noded_service_token =
        cats_api::semantic_control::NodedServiceToken::new(cfg.noded_service_token.clone())
            .context("CATS_NODED_SERVICE_TOKEN must satisfy the semantic noded token contract")?;
    let semantic_node_repository: Arc<dyn crate::semantic_node::NodeRepository> =
        Arc::new(crate::semantic_adapters::SemanticNodeRepositoryAdapter::new(Arc::clone(&store)));
    let semantic_node_probe: Arc<dyn crate::semantic_node::NodeHealthProbe> = Arc::new(
        crate::semantic_node::HttpNodeHealthProbe::new(noded_service_token.clone())?,
    );
    let semantic_node_service = Arc::new(
        crate::semantic_node::NodeManagementService::with_default_heartbeat_policy(
            semantic_node_repository,
            semantic_node_probe,
        ),
    );
    let semantic_node_http = crate::api::semantic_nodes::SemanticNodeHttpState::new(
        Arc::clone(&semantic_node_service),
        noded_service_token.clone(),
    );
    let semantic_noded_client = crate::semantic_noded_client::SemanticNodedClient::new(
        noded_service_token,
        crate::semantic_noded_client::SemanticNodedClientConfig::default(),
    )?;
    let semantic_lifecycle = crate::semantic_lifecycle::SemanticLifecycleService::new(
        crate::semantic_adapters::SemanticStoreAdapter::new(Arc::clone(&store)),
        crate::semantic_adapters::SemanticNodedLifecycleAdapter::new(semantic_noded_client),
        crate::semantic_adapters::SemanticIngressAdapter::new(Arc::clone(&store)),
        crate::semantic_lifecycle::LifecycleTimeouts::default(),
    );
    let semantic_resources: Arc<dyn crate::api::semantic_resources::SemanticResourceApi> = Arc::new(
        crate::semantic_resource_service::ProductionSemanticResourceApi::new(
            semantic_lifecycle,
            crate::semantic_resource_service::PostgresSemanticResourceStore::new(Arc::clone(
                &store,
            )),
        ),
    );
    let (semantic_node_liveness_shutdown, semantic_node_liveness_rx) =
        tokio::sync::watch::channel(false);
    let semantic_node_liveness_task = tokio::spawn(async move {
        semantic_node_service
            .run_liveness_monitor(semantic_node_liveness_rx)
            .await;
    });
    let state = AppState {
        runtime_node_authority: Arc::new(
            crate::api::runtime_node_authority::RuntimeNodeAuthorityService::new(
                store.clone(),
                cfg.runtime_provisioner_trust_bundle.clone(),
                cfg.production_cutover_operator_trust_bundle.clone(),
                Arc::clone(&readiness),
            ),
        ),
        route_v2_signing_operator,
        semantic_resources,
        semantic_node_http,
        store,
        observation_store,
        lifecycle_store,
        route_store,
        usage,
        credits,
        cat_create,
        persistent_disk_create,
        product_mutations,
        readiness,
        cfg: cfg.clone(),
        agent_session_registration_policy,
        runtime_spine_admission: Arc::new(RuntimeSpineAdmission::new()),
        route_resolve_admission: Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Admission::new(
                ROUTE_RESOLVE_V2_GLOBAL_IN_FLIGHT,
            ),
        ),
        object_write_authority_read_admission: Arc::new(RuntimeSpineAdmission::new()),
    };

    let (gateway_machine_listener, route_rotation_machine_listener) = {
        let mut machine = gateway_machine;
        let route_rotation_machine_listener = match (
            machine.rotation_listen.take(),
            machine.rotation_tls_config.take(),
        ) {
            (Some(listen), Some(tls)) => Some(
                crate::route_rotation_machine::RouteRotationMachineListener::spawn(
                    &listen,
                    tls,
                    state.clone(),
                )
                .await?,
            ),
            (None, None) if machine.rotation_operator_trust.is_none() => None,
            _ => anyhow::bail!("incomplete Route rotation machine-listener composition"),
        };
        let signer = machine.signing_authority.signer().cloned().map(Arc::new);
        let binding = Arc::new(machine.signing_authority.binding().clone());
        let gateway_machine_listener = if gateway_machine_signer_may_serve_at_startup(
            &state.readiness,
            signer.is_some(),
        ) {
            let control = Arc::clone(&gateway_machine_control);
            let service = Arc::new(
                crate::api::route_resolve_v2::RouteResolveV2Service::for_gateway_machine(
                    Arc::clone(&state.store),
                    signer,
                    binding,
                    state
                        .agent_session_registration_policy
                        .approved_guest_config_digest()
                        .clone(),
                    GATEWAY_AUTHENTICATION_GLOBAL_IN_FLIGHT,
                    ROUTE_RESOLVE_V2_GLOBAL_IN_FLIGHT,
                    Arc::clone(&control),
                ),
            );
            Some(
                crate::gateway_machine::GatewayMachineListener::spawn(
                    &machine.listen,
                    machine.tls_config,
                    service,
                    control,
                )
                .await?,
            )
        } else {
            tracing::error!(
                "Route Grant v2 signer is disabled; Gateway machine serving and readiness remain closed until process restart after installing an active authority"
            );
            None
        };
        (gateway_machine_listener, route_rotation_machine_listener)
    };

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = crate::api::router(state.clone());
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
    // Billing enforcement previously published Desired mutations.  The
    // clean-slate atomic lifecycle release has no such side channel; billing
    // remains queryable, and enforcement must later admit an exact lifecycle
    // command through the same one-unresolved-per-Cat lane.
    let delete_sweeper = Arc::new(
        crate::store::runtime_authority::delete_sweeper::DeleteSweeper::new(
            state.store.clone(),
            cfg.image_blob.clone(),
        ),
    );
    let volume_delete_sweeper_task = Some(spawn_managed_singleton_task(
        state.store.clone(),
        SingletonRole::VolumeDeleteSweeper,
        move || {
            let delete_sweeper = Arc::clone(&delete_sweeper);
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let deadline = std::time::Instant::now() + Duration::from_secs(30);
                    let budget =
                        crate::store::runtime_authority::delete_sweeper::DeleteSweepBudget::new(
                            32,
                            cats_storage::BLOB_LIST_PAGE_MAX_KEYS,
                        )
                        .expect("fixed production delete sweep budget is valid");
                    match delete_sweeper.run_once(budget, deadline).await {
                        Ok(pass) => {
                            if pass.candidates_examined > 0 {
                                tracing::info!(
                                    candidates = pass.candidates_examined,
                                    objects_deleted = pass.objects_deleted,
                                    completions = pass.completions_committed,
                                    blocked_missing_provider_evidence =
                                        pass.blocked_missing_provider_evidence,
                                    more_work = pass.more_work,
                                    "volume delete sweep pass completed"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "volume delete sweep pass failed");
                        }
                    }
                }
            }
        },
    ));
    let route_controller_store = Arc::clone(&state.store);
    let route_controller_task = spawn_managed_singleton_task(
        Arc::clone(&state.store),
        SingletonRole::RouteController,
        move || {
            let route_controller_store = Arc::clone(&route_controller_store);
            async move {
                // The elected supervisor owns cancellation. Constructing a
                // fresh lightweight runner for each leadership tenure keeps
                // scan cursor state local to that tenure while PostgreSQL
                // remains the exact per-Endpoint authority.
                crate::store::runtime_authority::route_controller::RouteController::new(
                    route_controller_store,
                )
                .run()
                .await;
            }
        },
    );

    let gateway_machine_addr = gateway_machine_listener
        .as_ref()
        .map(crate::gateway_machine::GatewayMachineListener::addr);
    let route_rotation_machine_addr = route_rotation_machine_listener
        .as_ref()
        .map(crate::route_rotation_machine::RouteRotationMachineListener::addr);
    tracing::info!(%addr, ?gateway_machine_addr, ?route_rotation_machine_addr, "control plane ready");
    Ok(Handle {
        addr,
        gateway_machine_addr,
        route_rotation_machine_addr,
        state,
        server_task,
        semantic_node_liveness_shutdown,
        semantic_node_liveness_task: tokio::sync::Mutex::new(Some(semantic_node_liveness_task)),
        volume_delete_sweeper_task,
        route_controller_task,
        image_manifest_resolver: image_manifests,
        server_shutdown: std::sync::Mutex::new(Some(server_shutdown)),
        gateway_machine_listener,
        route_rotation_machine_listener,
    })
}

fn gateway_machine_signer_may_serve_at_startup(
    readiness: &ReadinessLatch,
    signer_present: bool,
) -> bool {
    if !signer_present {
        readiness.poison();
        return false;
    }
    readiness.is_ready()
}

#[cfg(test)]
mod gateway_machine_startup_tests {
    use super::{gateway_machine_signer_may_serve_at_startup, ReadinessLatch};

    #[test]
    fn disabled_v2_signer_closes_startup_readiness_and_machine_bind() {
        let readiness = ReadinessLatch::new();
        assert!(!gateway_machine_signer_may_serve_at_startup(
            &readiness, false
        ));
        assert_eq!(
            crate::api::readiness_status(&readiness),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );

        // The latch and composition decision are intentionally one-way. A
        // corrected artifact/PG current is recovered by restart; runtime reload
        // remains future work.
        assert!(!gateway_machine_signer_may_serve_at_startup(
            &readiness, true
        ));
        assert!(!readiness.is_ready());
    }
}

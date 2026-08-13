//! Control-plane assembly: config, shared state, reconciler task and HTTP
//! server. `spawn` is used by the binary and by every integration/E2E test.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::Context;
use cats_api::gateway_workload_identity::GatewayWorkloadIdentityAuthority;
use cats_api::runtime_artifacts::{InstalledGatewayMachineArtifacts, InstalledRouteGrantV2Signer};
use cats_api::runtime_reconciliation::{GuestRuntimeProfileReceipt, RuntimeProvisionerTrustBundle};
use cats_metering::{CreditStore, UsageStore};
use cats_storage::BlobStore;
#[cfg(debug_assertions)]
use cats_storage::MetadataStore;

use crate::controller::{AutoTierPolicy, Controller, NodeLivenessAuthority};
use crate::store::{
    AuthorityRequestContext, DsnSource, ObservationStoreLane, SingletonRole, Store,
};

const SINGLETON_ELECTION_RETRY: Duration = Duration::from_millis(500);
const SINGLETON_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const RUNTIME_SPINE_GLOBAL_IN_FLIGHT: usize = 64;
const ROUTE_RESOLVE_V2_GLOBAL_IN_FLIGHT: usize = 32;
const GATEWAY_AUTHENTICATION_GLOBAL_IN_FLIGHT: usize = 32;
const RUNTIME_VOLUME_TRANSITION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const FLEET_VERIFICATION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Owns each fleet-verification Store execution independently of its HTTP
/// connection. A dropped response cancels the request context, while this
/// registry keeps graceful shutdown from abandoning the claimed connection
/// lane or PostgreSQL transaction before physical settlement.
pub(crate) struct FleetVerificationService {
    accepting: AtomicBool,
    active: AtomicUsize,
    next_request_id: AtomicU64,
    active_requests: Mutex<BTreeMap<u64, AuthorityRequestContext>>,
    changed: tokio::sync::Notify,
}

impl FleetVerificationService {
    pub(crate) fn new() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            active: AtomicUsize::new(0),
            next_request_id: AtomicU64::new(1),
            active_requests: Mutex::new(BTreeMap::new()),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        request_context: AuthorityRequestContext,
    ) -> Option<FleetVerificationRequestGuard> {
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
        Some(FleetVerificationRequestGuard {
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
        let joined = tokio::time::timeout(FLEET_VERIFICATION_SHUTDOWN_TIMEOUT, async {
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
            "fleet-verification requests exceeded the shutdown deadline"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn active_for_test(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

pub(crate) struct FleetVerificationRequestGuard {
    service: Arc<FleetVerificationService>,
    request_id: u64,
}

impl Drop for FleetVerificationRequestGuard {
    fn drop(&mut self) {
        self.service.finish(self.request_id);
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
    /// Legacy storage fixture for the debug-only retired-product test
    /// composition. This field does not exist in release builds.
    #[cfg(debug_assertions)]
    pub retired_storage_meta_for_tests: Option<Arc<dyn MetadataStore>>,
    /// Control-owned object-store boundary. A21 reads exact immutable
    /// golden-image keys; the delete sweeper removes only an authority-proved
    /// exact `volumes/<volume_id>/` prefix.
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

/// Fully validated composition for the independent Gateway machine listener.
/// Fixed PEM/private bytes are parsed and dropped by `new`; this value retains
/// only the TLS provider objects, canonical Gateway install candidate and
/// validated Route v2 signer/binding.
pub struct GatewayMachineConfig {
    listen: String,
    gateway_authority: GatewayWorkloadIdentityAuthority,
    tls_config: crate::gateway_machine::GatewayMachineTlsConfig,
    signing_authority: Arc<crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority>,
}

impl GatewayMachineConfig {
    pub fn new(
        listen: impl Into<String>,
        gateway_artifacts: InstalledGatewayMachineArtifacts,
        signer_artifacts: InstalledRouteGrantV2Signer,
        route_grant_ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        let listen = listen.into();
        anyhow::ensure!(
            !listen.is_empty(),
            "Gateway machine listen address is empty"
        );
        // Complete TLS/key-pair validation before PostgreSQL installation or
        // either network bind. Raw fixed private bytes drop on return.
        let tls_config = crate::gateway_machine::GatewayMachineTlsConfig::from_installed_artifacts(
            &gateway_artifacts,
        )?;
        let signing_authority = Arc::new(
            crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority::from_installed_artifacts(
                &signer_artifacts,
                route_grant_ttl_seconds,
            )?,
        );
        Ok(Self {
            listen,
            gateway_authority: gateway_artifacts.authority().clone(),
            tls_config,
            signing_authority,
        })
    }

    #[cfg(feature = "test-support")]
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
            gateway_authority,
            tls_config,
            signing_authority,
        })
    }
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
    #[cfg(debug_assertions)]
    pub retired_storage_meta_for_tests: Option<Arc<dyn MetadataStore>>,
    pub(crate) cat_create:
        Arc<crate::store::runtime_authority::cat_create_service::CatCreateService>,
    pub(crate) persistent_disk_create: Arc<
        crate::store::runtime_authority::persistent_disk_create_service::PersistentDiskCreateService,
    >,
    pub(crate) product_mutations:
        Arc<crate::store::runtime_authority::product_mutation_service::ProductMutationService>,
    pub(crate) readiness: Arc<ReadinessLatch>,
    pub notify: Arc<tokio::sync::Notify>,
    pub controller: Arc<Controller>,
    pub cfg: Arc<Config>,
    pub(crate) agent_session_registration_policy: Arc<crate::store::AgentSessionRegistrationPolicy>,
    pub(crate) runtime_spine_admission: Arc<RuntimeSpineAdmission>,
    /// Per-replica work bound for the machine-authenticated Route Grant v2
    /// resolve lane. Authentication is checked before a permit is acquired.
    pub(crate) route_resolve_admission: Arc<crate::api::route_resolve_v2::RouteResolveV2Admission>,
    pub(crate) runtime_volume_transition_admission: Arc<RuntimeSpineAdmission>,
    pub(crate) runtime_volume_transition_service: Arc<RuntimeVolumeTransitionService>,
    pub(crate) fleet_verification_service: Arc<FleetVerificationService>,
    pub(crate) runtime_node_authority:
        Arc<crate::api::runtime_node_authority::RuntimeNodeAuthorityService>,
    /// The retired product authority exists only in debug test compositions.
    #[cfg(debug_assertions)]
    pub(crate) retired_product_authority_for_tests: bool,
}

impl AppState {
    pub(crate) const fn retired_product_authority_for_tests(&self) -> bool {
        #[cfg(debug_assertions)]
        {
            self.retired_product_authority_for_tests
        }
        #[cfg(not(debug_assertions))]
        {
            false
        }
    }
}

pub struct Handle {
    /// Bound address, e.g. `127.0.0.1:53412`.
    pub addr: std::net::SocketAddr,
    /// Bound only when `spawn_with_gateway_machine` receives a complete fixed
    /// machine composition.
    pub gateway_machine_addr: Option<std::net::SocketAddr>,
    pub state: AppState,
    server_task: tokio::task::JoinHandle<()>,
    reconciler_task: Option<tokio::task::JoinHandle<()>>,
    billing_enforcer_task: Option<tokio::task::JoinHandle<()>>,
    volume_delete_sweeper_task: Option<tokio::task::JoinHandle<()>>,
    image_manifest_resolver: Arc<
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver,
    >,
    server_shutdown: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    gateway_machine_listener: Option<crate::gateway_machine::GatewayMachineListener>,
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
        if let Some(listener) = &self.gateway_machine_listener {
            listener.begin_shutdown();
        }
        self.state.cat_create.begin_shutdown();
        self.state.persistent_disk_create.begin_shutdown();
        self.state.product_mutations.begin_shutdown();
        self.state
            .runtime_volume_transition_service
            .begin_shutdown();
        self.state.fleet_verification_service.begin_shutdown();
        self.state.route_resolve_admission.begin_shutdown();
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
        if let Some(task) = &self.volume_delete_sweeper_task {
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
        let fleet_verifications = self.state.fleet_verification_service.shutdown();
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
        let manifest_reads = self.image_manifest_resolver.shutdown();
        let gateway_machine = async {
            if let Some(listener) = &self.gateway_machine_listener {
                listener.shutdown().await
            } else {
                Ok(())
            }
        };
        let (
            _,
            transition_result,
            fleet_verification_result,
            route_result,
            commit_result,
            persistent_disk_commit_result,
            product_mutation_commit_result,
            node_authority_result,
            manifest_result,
            gateway_machine_result,
        ) = tokio::join!(
            observation_store,
            volume_transitions,
            fleet_verifications,
            route_resolutions,
            commit_resolutions,
            persistent_disk_commit_resolutions,
            product_mutation_commit_resolutions,
            node_authority_resolutions,
            manifest_reads,
            gateway_machine
        );
        if !manifest_result {
            tracing::warn!("image manifest reads exceeded the shutdown deadline");
        }
        // Graceful shutdown has already stopped admission. Abort any unrelated
        // long-lived HTTP connection after Cat commit ownership is resolved.
        self.server_task.abort();
        transition_result?;
        fleet_verification_result?;
        route_result?;
        gateway_machine_result?;
        commit_result.map_err(anyhow::Error::from)?;
        persistent_disk_commit_result.map_err(anyhow::Error::from)?;
        product_mutation_commit_result.map_err(anyhow::Error::from)?;
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
    spawn_singleton_task_with_system_resolutions(store, role, move |_| make_task())
}

pub(crate) fn spawn_singleton_task_with_system_resolutions<F, Fut>(
    store: Arc<Store>,
    role: SingletonRole,
    make_task: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(crate::store::runtime_authority::SystemDesiredMutationResolutionOwner) -> Fut
        + Send
        + Sync
        + 'static,
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
            let resolutions =
                crate::store::runtime_authority::SystemDesiredMutationResolutionOwner::default();
            let task = make_task(resolutions.clone());
            let supervisor = tokio::spawn(run_elected_singleton(
                session,
                role,
                task,
                cancelled,
                resolutions,
            ));
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
    resolutions: crate::store::runtime_authority::SystemDesiredMutationResolutionOwner,
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
    // Dropping the role cancels PRE_COMMIT work. A Store closure may already
    // have been claimed by its blocking executor, or COMMIT may have been sent
    // with an ambiguous response, so retain leadership through its physical
    // rollback/commit and exact Operation resolution.
    resolutions.close();
    resolutions.wait_empty().await;
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

async fn run_runtime_maintenance_role(store: Arc<Store>, period: Duration) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match store
            .execute(|store| store.runtime_maintenance_scan())
            .await
        {
            Ok(report) => tracing::debug!(
                sampled_pending_operations = report.sampled_pending_operations,
                sampled_pending_on_fenced_node = report.sampled_pending_on_fenced_node,
                sampled_deleted_tombstones = report.sampled_deleted_tombstones,
                sampled_retained_api_results = report.sampled_retained_api_results,
                "completed production runtime maintenance scan"
            ),
            Err(error) => tracing::error!(%error, "production runtime maintenance scan failed"),
        }
    }
}

/// Start the control plane inside the current tokio runtime.
pub async fn spawn(cfg: Config) -> anyhow::Result<Handle> {
    spawn_inner(cfg, false, None).await
}

/// Start the public control plane plus the isolated mTLS Gateway machine
/// listener. The machine authority is installed/exact-replayed before either
/// listener binds; failure has no bearer/plain/public-router fallback.
pub async fn spawn_with_gateway_machine(
    cfg: Config,
    gateway_machine: GatewayMachineConfig,
) -> anyhow::Result<Handle> {
    spawn_inner(cfg, false, Some(gateway_machine)).await
}

/// Retired product/controller harness. It uses the exact production Node
/// ingress map; in particular it cannot install heartbeat, inventory,
/// registration, or work-status compatibility routes.
#[cfg(debug_assertions)]
pub async fn spawn_for_retired_product_tests(cfg: Config) -> anyhow::Result<Handle> {
    spawn_inner(cfg, true, None).await
}

async fn spawn_inner(
    cfg: Config,
    retired_product_authority_for_tests: bool,
    gateway_machine: Option<GatewayMachineConfig>,
) -> anyhow::Result<Handle> {
    #[cfg(not(debug_assertions))]
    anyhow::ensure!(
        !retired_product_authority_for_tests,
        "retired product authority is absent from release builds"
    );
    anyhow::ensure!(
        !cfg.auth_token.is_empty(),
        "service token must not be empty"
    );
    anyhow::ensure!(!cfg.admin_token.is_empty(), "admin token must not be empty");
    anyhow::ensure!(
        cfg.auth_token != cfg.admin_token,
        "service and admin tokens must be different"
    );
    ensure_route_signing_keys_are_separate(
        cfg.route_grant_signer.public_key_sha256(),
        gateway_machine
            .as_ref()
            .and_then(|machine| machine.signing_authority.binding().active_kid()),
    )?;
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
    if let Some(machine) = &gateway_machine {
        let signing_authority = Arc::clone(&machine.signing_authority);
        store
            .execute(move |store| store.install_route_grant_v2_signer_authority(&signing_authority))
            .await
            .context("install Route Grant v2 signing authority")?;
        let gateway_authority = machine.gateway_authority.clone();
        store
            .execute(move |store| {
                store.install_gateway_workload_identity_authority(&gateway_authority)
            })
            .await
            .context("install Gateway workload identity authority")?;
    }
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
    if retired_product_authority_for_tests {
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
    #[cfg(debug_assertions)]
    anyhow::ensure!(
        retired_product_authority_for_tests || cfg.retired_storage_meta_for_tests.is_none(),
        "legacy storage metadata is only valid in the retired product test composition"
    );
    #[cfg(debug_assertions)]
    let retired_storage_meta = cfg.retired_storage_meta_for_tests.clone();
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
    let notify = Arc::new(tokio::sync::Notify::new());
    let controller = Controller::new_with_liveness_authority(
        store.clone(),
        #[cfg(debug_assertions)]
        retired_storage_meta.clone(),
        notify.clone(),
        cfg.node_lease_timeout_ms,
        cfg.auth_token.clone(),
        cfg.auto_tier_policy,
        if retired_product_authority_for_tests {
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
        #[cfg(debug_assertions)]
        retired_storage_meta_for_tests: retired_storage_meta,
        cat_create,
        persistent_disk_create,
        product_mutations,
        readiness,
        notify,
        controller: controller.clone(),
        cfg: cfg.clone(),
        agent_session_registration_policy,
        runtime_spine_admission: Arc::new(RuntimeSpineAdmission::new()),
        route_resolve_admission: Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Admission::new(
                ROUTE_RESOLVE_V2_GLOBAL_IN_FLIGHT,
            ),
        ),
        runtime_volume_transition_admission: Arc::new(RuntimeSpineAdmission::new()),
        runtime_volume_transition_service: Arc::new(RuntimeVolumeTransitionService::new()),
        fleet_verification_service: Arc::new(FleetVerificationService::new()),
        #[cfg(debug_assertions)]
        retired_product_authority_for_tests,
    };

    let gateway_machine_listener = if let Some(machine) = gateway_machine {
        let signer = machine.signing_authority.signer().cloned().map(Arc::new);
        let binding = Arc::new(machine.signing_authority.binding().clone());
        if gateway_machine_signer_may_serve_at_startup(&state.readiness, signer.is_some()) {
            let control = Arc::new(
                crate::api::route_resolve_v2::RouteResolveV2MachineControl::new(Arc::clone(
                    &state.readiness,
                )),
            );
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
        }
    } else {
        None
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
    let interval = Duration::from_millis(cfg.reconcile_interval_ms);
    let reconciler_task = Some(if retired_product_authority_for_tests {
        let reconciler = controller.clone();
        let reconciler_store = state.store.clone();
        spawn_singleton_task(state.store.clone(), SingletonRole::Reconciler, move || {
            run_reconciler_role(reconciler.clone(), reconciler_store.clone(), interval)
        })
    } else {
        let maintenance_store = state.store.clone();
        let maintenance_interval = interval.max(Duration::from_secs(5));
        spawn_singleton_task(
            state.store.clone(),
            SingletonRole::RuntimeSweeper,
            move || run_runtime_maintenance_role(maintenance_store.clone(), maintenance_interval),
        )
    });
    let billing_enforcer_task = cfg.billing_enforcement_enabled.then(|| {
        let enforcement_state = state.clone();
        spawn_singleton_task_with_system_resolutions(
            state.store.clone(),
            SingletonRole::BillingEnforcer,
            move |resolution_owner| {
                let enforcement_state = enforcement_state.clone();
                async move {
                    let mut cursor = None;
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        interval.tick().await;
                        if let Err(error) = crate::api::enforce_exhausted_billing_accounts(
                            &enforcement_state,
                            &mut cursor,
                            &resolution_owner,
                        )
                        .await
                        {
                            tracing::error!(error = %error.0, "billing credit enforcement failed");
                        }
                    }
                }
            },
        )
    });
    let delete_sweeper = Arc::new(
        crate::store::runtime_authority::delete_sweeper::DeleteSweeper::new(
            state.store.clone(),
            cfg.image_blob.clone(),
        ),
    );
    let volume_delete_sweeper_task = Some(spawn_singleton_task(
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

    let gateway_machine_addr = gateway_machine_listener
        .as_ref()
        .map(crate::gateway_machine::GatewayMachineListener::addr);
    tracing::info!(%addr, ?gateway_machine_addr, "control plane ready");
    Ok(Handle {
        addr,
        gateway_machine_addr,
        state,
        server_task,
        reconciler_task,
        billing_enforcer_task,
        volume_delete_sweeper_task,
        image_manifest_resolver: image_manifests,
        server_shutdown: std::sync::Mutex::new(Some(server_shutdown)),
        gateway_machine_listener,
    })
}

/// Route Grant v1 remains live during the v2 cutover, but its signing key must
/// never be repurposed as the independent Gateway-to-Node capability key. This
/// check deliberately runs before any PostgreSQL connection or listener bind.
fn ensure_route_signing_keys_are_separate(
    legacy_v1_spki_sha256: &str,
    route_v2_active_kid: Option<&cats_api::runtime_reconciliation::KeyId>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        route_v2_active_kid.is_none_or(|kid| kid.as_str() != legacy_v1_spki_sha256),
        "Route Grant v1 and v2 must use different Ed25519 signing keys"
    );
    Ok(())
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
mod route_signing_key_separation_tests {
    use super::{
        ensure_route_signing_keys_are_separate, gateway_machine_signer_may_serve_at_startup,
        ReadinessLatch,
    };
    use cats_api::runtime_reconciliation::KeyId;

    #[test]
    fn startup_rejects_reusing_the_legacy_v1_spki_as_the_v2_active_kid() {
        let legacy = "fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb";
        let reused = KeyId::new(legacy).unwrap();
        assert!(ensure_route_signing_keys_are_separate(legacy, Some(&reused)).is_err());

        let independent =
            KeyId::new("2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99").unwrap();
        ensure_route_signing_keys_are_separate(legacy, Some(&independent)).unwrap();
        ensure_route_signing_keys_are_separate(legacy, None).unwrap();
    }

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

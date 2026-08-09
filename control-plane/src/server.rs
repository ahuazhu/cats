//! Control-plane assembly: config, shared state, reconciler task and HTTP
//! server. `spawn` is used by the binary and by every integration/E2E test.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cats_metering::{CreditStore, UsageStore};
use cats_storage::{BlobStore, MetadataStore};

use crate::controller::{AutoTierPolicy, Controller};
use crate::store::{DsnSource, SingletonRole, Store};

const SINGLETON_ELECTION_RETRY: Duration = Duration::from_millis(500);
const SINGLETON_HEALTH_INTERVAL: Duration = Duration::from_secs(1);

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
    pub usage: Arc<dyn UsageStore>,
    pub credits: Arc<dyn CreditStore>,
    pub storage_meta: Arc<dyn MetadataStore>,
    #[allow(
        dead_code,
        reason = "F2d consumes the staged A21 resolver when the Cat-create route switches"
    )]
    pub(crate) image_manifests:
        Arc<dyn crate::store::runtime_authority::cat_create_service::CatCreateManifestResolver>,
    pub notify: Arc<tokio::sync::Notify>,
    pub controller: Arc<Controller>,
    pub cfg: Arc<Config>,
}

pub struct Handle {
    /// Bound address, e.g. `127.0.0.1:53412`.
    pub addr: std::net::SocketAddr,
    pub state: AppState,
    server_task: tokio::task::JoinHandle<()>,
    reconciler_task: tokio::task::JoinHandle<()>,
    billing_enforcer_task: Option<tokio::task::JoinHandle<()>>,
    image_manifest_resolver: Arc<
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver,
    >,
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn begin_shutdown(&self) {
        self.server_task.abort();
        self.reconciler_task.abort();
        if let Some(task) = &self.billing_enforcer_task {
            task.abort();
        }
    }

    pub async fn shutdown(&self) {
        // Stop accepting product work before waiting for the dedicated
        // blocking manifest lane. The resolver itself closes its queue and
        // bounds this wait by the provider transport deadline.
        self.begin_shutdown();
        if !self.image_manifest_resolver.shutdown().await {
            tracing::warn!("image manifest reads exceeded the shutdown deadline");
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Drop cannot await. It still prevents new work and cancels async
        // roles; production's signal path calls the async shutdown above.
        self.image_manifest_resolver.begin_shutdown();
        self.begin_shutdown();
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
    let ca_file = cfg
        .control_store_ca_file
        .as_deref()
        .and_then(|path| path.to_str())
        .map(str::to_string);
    let store = Arc::new(Store::connect_from_async(cfg.control_store_dsn.clone(), ca_file).await?);
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
    // An OCI deploy is driven by an in-memory task holding one-pull registry
    // credentials that are never persisted, so a deploy in flight when this
    // process died cannot be resumed. Report it as failed instead of leaving
    // its operation unresolved and its (cat, app, digest) identity blocked --
    // a caller polling that operation would otherwise wait forever.
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
    let usage = cfg.usage_store.clone();
    let credits = cfg.credit_store.clone();
    let storage_meta = cfg.storage_meta.clone();
    let image_manifests = Arc::new(
        crate::store::runtime_authority::image_manifest_resolver::ImmutableImageManifestResolver::new(
            cfg.image_blob.clone(),
        ),
    );
    let notify = Arc::new(tokio::sync::Notify::new());
    let controller = Controller::new(
        store.clone(),
        storage_meta.clone(),
        notify.clone(),
        cfg.node_lease_timeout_ms,
        cfg.auth_token.clone(),
        cfg.auto_tier_policy,
    );
    let state = AppState {
        store,
        usage,
        credits,
        storage_meta,
        image_manifests: image_manifests.clone(),
        notify,
        controller: controller.clone(),
        cfg: cfg.clone(),
    };

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = crate::api::router(state.clone());
    let server_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("control plane server exited: {e}");
        }
    });
    let interval = Duration::from_millis(cfg.reconcile_interval_ms);
    let reconciler = controller.clone();
    let reconciler_store = state.store.clone();
    let reconciler_task =
        spawn_singleton_task(state.store.clone(), SingletonRole::Reconciler, move || {
            run_reconciler_role(reconciler.clone(), reconciler_store.clone(), interval)
        });
    let billing_enforcer_task = cfg.billing_enforcement_enabled.then(|| {
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
    })
}

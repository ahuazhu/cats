//! Clean-slate semantic Control assembly.
//!
//! The public HTTP server owns only workspace/auth/billing, semantic resource
//! operations, committed-Destroy recovery and semantic Node
//! registration/liveness. Retired lifecycle, inventory, AgentSession and
//! Route Operation workers are not composed.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cats_api::runtime_reconciliation::{GuestRuntimeProfileReceipt, RuntimeProvisionerTrustBundle};
use cats_metering::{CreditStore, UsageStore};
use cats_storage::BlobStore;

use crate::store::{DsnSource, SingletonRole, Store};

const SINGLETON_ELECTION_RETRY: Duration = Duration::from_millis(500);
const SINGLETON_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const DESTROY_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
// A live request owns its claim for at most the default 120-second lifecycle
// deadline. Waiting beyond it prevents the recovery task from racing the
// ordinary response path while still bounding crash recovery.
const DESTROY_RECOVERY_MINIMUM_AGE: Duration = Duration::from_secs(125);
const DESTROY_RECOVERY_BATCH_SIZE: usize = 32;
const DESTROY_RECOVERY_MAX_IN_FLIGHT: usize = 4;

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub control_store_dsn: DsnSource,
    pub control_store_ca_file: Option<PathBuf>,
    pub usage_store: Arc<dyn UsageStore>,
    pub credit_store: Arc<dyn CreditStore>,
    /// Retained as a storage-provider boundary for independently composed
    /// volume/object-write workers. Semantic lifecycle does not read it.
    pub image_blob: Arc<dyn BlobStore>,
    pub auth_token: String,
    pub noded_service_token: String,
    /// Retained in configuration until Node effect composition consumes the
    /// same qualified runtime receipt directly.
    pub guest_runtime_profile_receipt: GuestRuntimeProfileReceipt,
    pub runtime_provisioner_trust_bundle: RuntimeProvisionerTrustBundle,
    pub production_cutover_operator_trust_bundle:
        cats_api::production_mutation_admission::ProductionCutoverOperatorTrustBundle,
    pub admin_token: String,
    pub workos: Option<Arc<crate::auth::WorkOsConfig>>,
    pub stripe: Option<Arc<crate::billing::StripeClient>>,
    pub billing_enforcement_enabled: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub(crate) semantic_resources: Arc<dyn crate::api::semantic_resources::SemanticResourceApi>,
    pub(crate) semantic_node_http: crate::api::semantic_nodes::SemanticNodeHttpState,
    pub usage: Arc<dyn UsageStore>,
    pub credits: Arc<dyn CreditStore>,
    pub(crate) readiness: Arc<ReadinessLatch>,
    pub(crate) runtime_node_authority:
        Arc<crate::api::runtime_node_authority::RuntimeNodeAuthorityService>,
    pub cfg: Arc<Config>,
}

pub struct Handle {
    pub addr: std::net::SocketAddr,
    pub state: AppState,
    server_task: tokio::task::JoinHandle<()>,
    semantic_destroy_recovery_task: ManagedSingletonTask,
    semantic_node_liveness_shutdown: tokio::sync::watch::Sender<bool>,
    semantic_node_liveness_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    server_shutdown: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
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
        if let Some(shutdown) = self
            .server_shutdown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = shutdown.send(());
        }
        self.semantic_destroy_recovery_task.begin_shutdown();
        self.semantic_node_liveness_shutdown.send_replace(true);
        self.state.runtime_node_authority.begin_shutdown();
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        self.semantic_destroy_recovery_task
            .shutdown()
            .await
            .context("semantic Destroy recovery task failed")?;
        let mut task = self.semantic_node_liveness_task.lock().await;
        if let Some(task) = task.take() {
            task.await.context("semantic Node liveness task failed")?;
        }
        self.state
            .runtime_node_authority
            .shutdown_commit_resolutions()
            .await
            .map_err(anyhow::Error::from)?;
        self.server_task.abort();
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.begin_shutdown();
        self.server_task.abort();
    }
}

/// Start the one semantic Control listener.
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
    let cfg = Arc::new(cfg);
    let ca_file = cfg
        .control_store_ca_file
        .as_deref()
        .and_then(|path| path.to_str())
        .map(str::to_owned);
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
    if let Some(workos) = &cfg.workos {
        let organizations = workos.account_organizations().clone();
        store
            .execute(move |store| store.ensure_configured_accounts(&organizations))
            .await?;
    } else {
        store
            .execute(|store| {
                store.ensure_configured_accounts(&std::collections::BTreeMap::from([(
                    "default".to_owned(),
                    "local-development".to_owned(),
                )]))
            })
            .await?;
    }

    let noded_service_token =
        cats_api::semantic_control::NodedServiceToken::new(cfg.noded_service_token.clone())
            .context("CATS_NODED_SERVICE_TOKEN must satisfy the semantic noded token contract")?;
    let semantic_noded_client = crate::semantic_noded_client::SemanticNodedClient::new(
        noded_service_token.clone(),
        crate::semantic_noded_client::SemanticNodedClientConfig::default(),
    )?;
    let semantic_noded =
        crate::semantic_adapters::SemanticNodedLifecycleAdapter::new(semantic_noded_client);
    let semantic_ingress =
        crate::semantic_adapters::SemanticIngressAdapter::new(Arc::clone(&store));
    let recovery = Arc::new(
        crate::semantic_node_recovery::SemanticNodeRecoveryService::new(
            crate::semantic_node_recovery::PostgresSemanticNodeRecoveryStore::new(Arc::clone(
                &store,
            )),
            semantic_noded.clone(),
            semantic_ingress.clone(),
            crate::semantic_node_recovery::RecoveryTimeouts::default(),
        ),
    );
    let planned_drain_recovery = Arc::clone(&recovery);
    let offline_recovery: crate::semantic_node::OfflineNodeRecovery = Arc::new(move |node_id| {
        let recovery = Arc::clone(&recovery);
        Box::pin(async move {
            let report = recovery
                .recover_offline_node(&node_id)
                .await
                .map_err(|error| cats_api::error::ApiError::internal(error.message))?;
            for cat in report.cats {
                tracing::info!(
                    source_node_id = %report.source_node_id,
                    cat_id = %cat.cat_id,
                    status = ?cat.status,
                    "offline Node Cat recovery settled"
                );
            }
            Ok(())
        })
    });
    let planned_drain: crate::semantic_node::PlannedNodeDrain = Arc::new(move |node_id| {
        let recovery = Arc::clone(&planned_drain_recovery);
        Box::pin(async move {
            recovery
                .drain_node(&node_id)
                .await
                .map_err(|error| cats_api::error::ApiError::internal(error.message))
        })
    });
    let semantic_node_repository: Arc<dyn crate::semantic_node::NodeRepository> =
        Arc::new(crate::semantic_adapters::SemanticNodeRepositoryAdapter::new(Arc::clone(&store)));
    let semantic_node_probe: Arc<dyn crate::semantic_node::NodeHealthProbe> = Arc::new(
        crate::semantic_node::HttpNodeHealthProbe::new(noded_service_token.clone())?,
    );
    let semantic_node_service = Arc::new(
        crate::semantic_node::NodeManagementService::with_default_heartbeat_policy(
            semantic_node_repository,
            semantic_node_probe,
        )
        .with_offline_recovery(offline_recovery)
        .with_planned_drain(planned_drain),
    );
    let semantic_node_http = crate::api::semantic_nodes::SemanticNodeHttpState::new(
        Arc::clone(&semantic_node_service),
        noded_service_token.clone(),
    );
    let semantic_lifecycle = crate::semantic_lifecycle::SemanticLifecycleService::new(
        crate::semantic_adapters::SemanticStoreAdapter::new(Arc::clone(&store)),
        semantic_noded,
        semantic_ingress,
        crate::semantic_lifecycle::LifecycleTimeouts::default(),
    );
    let destroy_recovery_lifecycle = semantic_lifecycle.clone();
    let semantic_destroy_recovery_task = spawn_managed_singleton_task(
        Arc::clone(&store),
        SingletonRole::SemanticDestroyRecovery,
        move || {
            let lifecycle = destroy_recovery_lifecycle.clone();
            async move {
                let mut interval = tokio::time::interval(DESTROY_RECOVERY_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    match lifecycle
                        .recover_pending_destroys(
                            DESTROY_RECOVERY_MINIMUM_AGE,
                            DESTROY_RECOVERY_BATCH_SIZE,
                            DESTROY_RECOVERY_MAX_IN_FLIGHT,
                        )
                        .await
                    {
                        Ok(report) if report.discovered > 0 => tracing::info!(
                            discovered = report.discovered,
                            completed = report.completed,
                            failed = report.failed,
                            "pending Destroy recovery pass completed"
                        ),
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(?error, "pending Destroy discovery failed");
                        }
                    }
                }
            }
        },
    );
    let semantic_resources: Arc<dyn crate::api::semantic_resources::SemanticResourceApi> = Arc::new(
        crate::semantic_resource_service::ProductionSemanticResourceApi::with_disk_backend(
            semantic_lifecycle,
            crate::semantic_resource_service::PostgresSemanticResourceStore::new(Arc::clone(
                &store,
            )),
            crate::semantic_strict_disk_backend::AuthorityPersistentDiskBackend::new(
                Arc::clone(&store),
                Arc::clone(&cfg.image_blob),
            ),
        ),
    );
    let (semantic_node_liveness_shutdown, semantic_node_liveness_rx) =
        tokio::sync::watch::channel(false);
    let semantic_node_liveness_task = tokio::spawn(async move {
        semantic_node_service
            .run_liveness_monitor(semantic_node_liveness_rx)
            .await;
    });
    let readiness = Arc::new(ReadinessLatch::new());
    let runtime_node_authority = Arc::new(
        crate::api::runtime_node_authority::RuntimeNodeAuthorityService::new(
            Arc::clone(&store),
            cfg.runtime_provisioner_trust_bundle.clone(),
            cfg.production_cutover_operator_trust_bundle.clone(),
            Arc::clone(&readiness),
        ),
    );
    let state = AppState {
        store,
        semantic_resources,
        semantic_node_http,
        usage: Arc::clone(&cfg.usage_store),
        credits: Arc::clone(&cfg.credit_store),
        readiness,
        runtime_node_authority,
        cfg,
    };
    let listener = tokio::net::TcpListener::bind(&state.cfg.listen)
        .await
        .with_context(|| format!("bind {}", state.cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = crate::api::router(state.clone());
    let (server_shutdown, server_shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = server_shutdown_rx.await;
            })
            .await
        {
            tracing::error!(%error, "control plane server exited");
        }
    });
    tracing::info!(%addr, "semantic control plane ready");
    Ok(Handle {
        addr,
        state,
        server_task,
        semantic_destroy_recovery_task,
        semantic_node_liveness_shutdown,
        semantic_node_liveness_task: tokio::sync::Mutex::new(Some(semantic_node_liveness_task)),
        server_shutdown: std::sync::Mutex::new(Some(server_shutdown)),
    })
}

/// Joinable ownership of one elected storage/background role.
pub struct ManagedSingletonTask {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ManagedSingletonTask {
    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let mut task = self.task.lock().await;
        let result = match task.as_mut() {
            Some(task) => task.await.context("singleton election task failed"),
            None => Ok(()),
        };
        task.take();
        result
    }
}

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
        if shutdown_requested(&shutdown) {
            return;
        }
        let session_store = Arc::clone(&store);
        let mut session =
            match crate::store::execute_leadership(move || session_store.singleton_session(role))
                .await
            {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(role = role.name(), %error, "opening singleton session failed");
                    if retry_or_shutdown(&mut shutdown).await {
                        return;
                    }
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
                    if retry_or_shutdown(&mut shutdown).await {
                        return;
                    }
                }
                Err(error) => {
                    tracing::warn!(role = role.name(), %error, "singleton election failed");
                    if retry_or_shutdown(&mut shutdown).await {
                        return;
                    }
                    continue 'election;
                }
            }
        }
        let mut task = tokio::spawn(make_task());
        loop {
            tokio::select! {
                _ = &mut task => break,
                () = wait_for_shutdown_optional(&mut shutdown) => {
                    task.abort();
                    let _ = task.await;
                    close_singleton(session).await;
                    return;
                }
                _ = tokio::time::sleep(SINGLETON_HEALTH_INTERVAL) => {
                    match singleton_check(session).await {
                        Ok(returned) => session = returned,
                        Err(error) => {
                            tracing::warn!(role = role.name(), %error, "singleton session lost");
                            task.abort();
                            let _ = task.await;
                            if retry_or_shutdown(&mut shutdown).await {
                                return;
                            }
                            continue 'election;
                        }
                    }
                }
            }
        }
        close_singleton(session).await;
        if retry_or_shutdown(&mut shutdown).await {
            return;
        }
    }
}

fn shutdown_requested(shutdown: &Option<tokio::sync::watch::Receiver<bool>>) -> bool {
    shutdown
        .as_ref()
        .is_some_and(|shutdown| *shutdown.borrow() || shutdown.has_changed().is_err())
}

async fn retry_or_shutdown(shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>) -> bool {
    match shutdown.as_mut() {
        Some(shutdown) => tokio::select! {
            _ = tokio::time::sleep(SINGLETON_ELECTION_RETRY) => false,
            _ = wait_for_shutdown(shutdown) => true,
        },
        None => {
            tokio::time::sleep(SINGLETON_ELECTION_RETRY).await;
            false
        }
    }
}

async fn wait_for_shutdown_optional(shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match shutdown.as_mut() {
        Some(shutdown) => wait_for_shutdown(shutdown).await,
        None => std::future::pending().await,
    }
}

async fn wait_for_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() || shutdown.changed().await.is_err() {
            return;
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

async fn close_singleton(session: crate::store::SingletonSession) {
    if let Err(error) = crate::store::execute_leadership_cleanup(move || session.close_now()).await
    {
        tracing::error!(%error, "singleton session cleanup failed");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn singleton_reenters_election_after_its_postgres_session_is_lost() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None)
                .expect("test Store"),
        );
        let starts = Arc::new(AtomicUsize::new(0));
        let task_starts = Arc::clone(&starts);
        let role = SingletonRole::SemanticDestroyRecovery;
        let task = spawn_managed_singleton_task(Arc::clone(&store), role, move || {
            let task_starts = Arc::clone(&task_starts);
            async move {
                task_starts.fetch_add(1, Ordering::AcqRel);
                std::future::pending::<()>().await;
            }
        });

        cats_test_support::wait_until_async("first singleton leadership", || async {
            starts.load(Ordering::Acquire) == 1
        })
        .await;

        let role_key = role.lock_key();
        let terminated: bool = store
            .execute(move |store| {
                store.with(|client| {
                    let rows = client.query(
                        "SELECT pid FROM pg_catalog.pg_locks
                          WHERE locktype='advisory'
                            AND classid=hashtext(current_schema())::oid
                            AND objid=$1::int4::oid
                            AND objsubid=2
                            AND granted
                            AND pid<>pg_backend_pid()",
                        &[&role_key],
                    )?;
                    assert_eq!(rows.len(), 1, "calibrate exact singleton lock lookup");
                    let pid: i32 = rows[0].get(0);
                    client
                        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
                        .map(|row| row.get(0))
                })
            })
            .await
            .expect("terminate elected singleton session");
        assert!(terminated);

        cats_test_support::wait_until_async("singleton leadership after session loss", || async {
            starts.load(Ordering::Acquire) >= 2
        })
        .await;
        task.shutdown().await.expect("singleton shutdown");
    }
}

//! Control-plane assembly: config, shared state, reconciler task and HTTP
//! server. `spawn` is used by the binary and by every integration/E2E test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cats_storage::MetadataStore;

use crate::controller::Controller;
use crate::store::Store;

#[derive(Clone)]
pub struct Config {
    /// `host:port`; use port 0 to pick a free port (tests).
    pub listen: String,
    /// Control-plane resource database.
    pub db_path: PathBuf,
    /// Open authoritative volume-root/lease port, shared with blockd.
    pub storage_meta: Arc<dyn MetadataStore>,
    /// Service credential used by node agents, gateways and controller jobs.
    pub auth_token: String,
    /// Administrator credential for fleet management and monitoring APIs.
    pub admin_token: String,
    /// User credentials keyed by the one project each credential may access.
    /// A `*` entry is reserved for the in-process development/test config.
    pub project_tokens: BTreeMap<String, String>,
    /// Optional AuthKit configuration for browser sessions. Bearer-token
    /// authentication remains available for CLI and service callers.
    pub workos: Option<Arc<crate::auth::WorkOsConfig>>,
    pub node_lease_timeout_ms: i64,
    pub reconcile_interval_ms: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub storage_meta: Arc<dyn MetadataStore>,
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
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn shutdown(&self) {
        self.server_task.abort();
        self.reconciler_task.abort();
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown();
    }
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
        !cfg.project_tokens.is_empty(),
        "at least one project token is required"
    );
    let mut unique_project_tokens = BTreeSet::new();
    for (project, token) in &cfg.project_tokens {
        anyhow::ensure!(!project.is_empty(), "project name must not be empty");
        anyhow::ensure!(!token.is_empty(), "project token must not be empty");
        anyhow::ensure!(
            token != &cfg.auth_token && token != &cfg.admin_token,
            "service, admin and project tokens must be different"
        );
        anyhow::ensure!(
            unique_project_tokens.insert(token.clone()),
            "a project token may be bound to only one project"
        );
    }
    let cfg = Arc::new(cfg);
    let store = Arc::new(Store::open(&cfg.db_path)?);
    let storage_meta = cfg.storage_meta.clone();
    let notify = Arc::new(tokio::sync::Notify::new());
    let controller = Controller::new(
        store.clone(),
        storage_meta.clone(),
        notify.clone(),
        cfg.node_lease_timeout_ms,
        cfg.auth_token.clone(),
    );
    let state = AppState {
        store,
        storage_meta,
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
    let reconciler_task = tokio::spawn(controller.run(interval));

    tracing::info!(%addr, "control plane ready");
    Ok(Handle {
        addr,
        state,
        server_task,
        reconciler_task,
    })
}

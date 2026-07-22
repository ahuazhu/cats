//! Control-plane assembly: config, shared state, reconciler task and HTTP
//! server. `spawn` is used by the binary and by every integration/E2E test.

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
    pub auth_token: String,
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

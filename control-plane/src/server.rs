//! Control-plane assembly: config, shared state, reconciler task and HTTP
//! server. `spawn` is used by the binary and by every integration/E2E test.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cats_metering::{CreditStore, UsageStore};
use cats_storage::MetadataStore;

use crate::controller::{AutoTierPolicy, Controller};
use crate::store::{DsnSource, Store};

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
    /// Service credential used by node agents, gateways and controller jobs.
    pub auth_token: String,
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
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn shutdown(&self) {
        self.server_task.abort();
        self.reconciler_task.abort();
        if let Some(task) = &self.billing_enforcer_task {
            task.abort();
        }
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
    let store = Arc::new(Store::connect_from(
        &cfg.control_store_dsn,
        cfg.control_store_ca_file
            .as_deref()
            .and_then(|p| p.to_str()),
    )?);
    if let Some(workos) = &cfg.workos {
        store.ensure_configured_accounts(workos.account_organizations())?;
    } else {
        // The credential-free development shape has one explicit bootstrap
        // account. Production WorkOS deployments provision Accounts through
        // AuthKit onboarding or the configured mapping instead.
        store.ensure_configured_accounts(&std::collections::BTreeMap::from([(
            "default".to_string(),
            "local-development".to_string(),
        )]))?;
    }
    // An OCI deploy is driven by an in-memory task holding one-pull registry
    // credentials that are never persisted, so a deploy in flight when this
    // process died cannot be resumed. Report it as failed instead of leaving
    // its operation unresolved and its (cat, app, digest) identity blocked --
    // a caller polling that operation would otherwise wait forever.
    match store.fail_interrupted_oci_deployments() {
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
    let billing_enforcer_task = cfg.billing_enforcement_enabled.then(|| {
        let enforcement_state = state.clone();
        tokio::spawn(async move {
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
        })
    });

    tracing::info!(%addr, "control plane ready");
    Ok(Handle {
        addr,
        state,
        server_task,
        reconciler_task,
        billing_enforcer_task,
    })
}

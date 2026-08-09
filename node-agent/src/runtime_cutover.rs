//! Production entry point for the signed Runtime spine cutover.
//!
//! The legacy [`crate::server`] remains available to the pre-cutover test
//! suite, but the shipped Node binary starts here. The first production
//! scanner can attest only a physically empty Host; any non-empty fact remains
//! fail-closed for the later identity-aware scanner. This path does not
//! construct `NodeRuntime`, adopt a legacy ledger, or run a destructive
//! residue/device sweep.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::agent_registration::AgentRegistrationConfig;
use crate::runtime::reconciliation::{
    installed_clean_slate_scanner, InstalledCleanSlateProbeConfig,
};
use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeSpineHttpClient, RuntimeSpineRunStep,
    RuntimeSpineRunner,
};

const SCAN_DEADLINE: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Fail-closed placeholder until the typed Runtime §7 planner/effect adapter
/// is composed. The clean-slate scanner can attest physical absence, but it
/// cannot authorize a later assigned-spec mutation; retaining this error keeps
/// that post-attestation seam non-mutating.
struct UnavailableDesiredEffect;

impl RuntimeDesiredEffect for UnavailableDesiredEffect {
    fn apply(
        &self,
        _context: RuntimeDesiredEffectContext,
        _desired: &cats_api::runtime_reconciliation::DesiredRuntimeSpec,
    ) -> anyhow::Result<()> {
        anyhow::bail!("typed Runtime Desired effect adapter is not composed")
    }
}

pub struct SignedRuntimeCutoverConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub agent_registration: AgentRegistrationConfig,
    pub cloud_hypervisor_binary: std::path::PathBuf,
    pub blockd_binary: std::path::PathBuf,
    pub guest_agent_binary: std::path::PathBuf,
    pub metering_cgroup_root: Option<std::path::PathBuf>,
}

pub struct SignedRuntimeCutoverHandle {
    pub addr: std::net::SocketAddr,
    shutdown_runner: Option<tokio::sync::oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    runner_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl SignedRuntimeCutoverHandle {
    /// Runs until process shutdown or a component failure. Shutdown first
    /// cancels and joins the effect and scanner workers, then joins the journal
    /// worker and drops its flock inside `RuntimeSpineRunner::shutdown`; only
    /// then is the local health listener stopped and the process allowed to
    /// return.
    pub async fn run_until_signal(mut self) -> anyhow::Result<()> {
        enum Stop {
            Signal(anyhow::Result<()>),
            Server(Result<anyhow::Result<()>, tokio::task::JoinError>),
            Runner(Result<anyhow::Result<()>, tokio::task::JoinError>),
        }

        let stop = tokio::select! {
            signal = shutdown_signal() => Stop::Signal(signal),
            result = &mut self.server_task => Stop::Server(result),
            result = &mut self.runner_task => Stop::Runner(result),
        };
        let (outcome, stop_server) = match stop {
            Stop::Signal(signal) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine during shutdown",
                );
                (signal.and(runner), true)
            }
            Stop::Server(server) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine after listener exit",
                );
                (
                    join_result(server, "signed Runtime health listener task stopped").and(runner),
                    false,
                )
            }
            Stop::Runner(runner) => {
                self.shutdown_runner.take();
                (
                    join_result(runner, "signed Runtime spine task stopped"),
                    true,
                )
            }
        };
        if stop_server {
            self.server_task.abort();
            let _ = (&mut self.server_task).await;
        }
        outcome
    }

    fn request_runner_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown_runner.take() {
            let _ = shutdown.send(());
        }
    }
}

fn join_result(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    context: &'static str,
) -> anyhow::Result<()> {
    result.context(context)?
}

impl Drop for SignedRuntimeCutoverHandle {
    fn drop(&mut self) {
        self.request_runner_shutdown();
        self.server_task.abort();
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = terminate.recv() => {}
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[derive(Clone)]
struct Readiness(Arc<AtomicBool>);

impl Readiness {
    fn closed() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

async fn health(State(readiness): State<Readiness>) -> (StatusCode, &'static str) {
    if readiness.is_ready() {
        (StatusCode::OK, "signed Runtime inventory attested")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "signed Runtime inventory is not attested",
        )
    }
}

fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .with_state(readiness)
}

pub async fn spawn_signed_runtime_cutover(
    config: SignedRuntimeCutoverConfig,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    let session = config
        .agent_registration
        .register_until_session(&config.control_plane_url)
        .await
        .context("establish durable Agent session")?;
    let client = RuntimeSpineHttpClient::for_production(
        &config.control_plane_url,
        &config.agent_registration,
    )?;
    let scanner = installed_clean_slate_scanner(InstalledCleanSlateProbeConfig {
        state_directory: config.agent_registration.runtime_state_directory(),
        cloud_hypervisor_binary: config.cloud_hypervisor_binary,
        blockd_binary: config.blockd_binary,
        guest_agent_binary: config.guest_agent_binary,
        metering_cgroup_root: config.metering_cgroup_root,
    })
    .context("compose installed clean-slate inventory probes")?;
    let runner = RuntimeSpineRunner::new_with_desired_effects(
        config.agent_registration.runtime_state_directory(),
        session,
        client,
        scanner,
        Arc::new(UnavailableDesiredEffect),
    )?;
    // Bind before spawning either owned task. If binding fails, `runner` drops
    // synchronously and no detached worker can outlive this failed startup.
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind signed Runtime health listener {}", config.listen))?;
    let addr = listener.local_addr()?;

    let readiness = Readiness::closed();
    let runner_readiness = readiness.clone();
    let (shutdown_runner, mut runner_shutdown) = tokio::sync::oneshot::channel();
    let runner_task = tokio::spawn(async move {
        let mut runner = runner;
        let run_result = tokio::select! {
            result = run_signed_spine(&mut runner, &runner_readiness) => result,
            _ = &mut runner_shutdown => Ok(()),
        };
        runner_readiness.set(false);
        let shutdown_result = runner.shutdown().await;
        match (run_result, shutdown_result) {
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
            (Err(error), Err(shutdown)) => {
                Err(error.context(format!("signed Runtime worker shutdown failed: {shutdown}")))
            }
            (Ok(()), Ok(())) => Ok(()),
        }
    });

    let server_task = tokio::spawn(async move {
        axum::serve(listener, health_router(readiness))
            .await
            .context("serve signed Runtime health listener")
    });

    Ok(SignedRuntimeCutoverHandle {
        addr,
        shutdown_runner: Some(shutdown_runner),
        server_task,
        runner_task,
    })
}

async fn run_signed_spine(
    runner: &mut RuntimeSpineRunner,
    readiness: &Readiness,
) -> anyhow::Result<()> {
    loop {
        let step = runner
            .run_once_until(Instant::now() + SCAN_DEADLINE)
            .await?;
        if apply_readiness_policy(step, readiness)? {
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
}

/// Returns true when the caller should apply the bounded retry delay.
fn apply_readiness_policy(
    step: RuntimeSpineRunStep,
    readiness: &Readiness,
) -> anyhow::Result<bool> {
    match step {
        RuntimeSpineRunStep::DesiredAccepted => {
            // A fresh Desired must be reconciled and attested before the
            // process can advertise local readiness again.
            readiness.set(false);
            Ok(false)
        }
        RuntimeSpineRunStep::ObservationAccepted => {
            readiness.set(true);
            Ok(false)
        }
        RuntimeSpineRunStep::ObservationReplayed
        | RuntimeSpineRunStep::EffectApplied { .. }
        | RuntimeSpineRunStep::EffectsApplied
        | RuntimeSpineRunStep::DesiredInvalidated { .. } => {
            readiness.set(false);
            Ok(false)
        }
        RuntimeSpineRunStep::RetryExact(_)
        | RuntimeSpineRunStep::ScanUnavailable(_)
        | RuntimeSpineRunStep::ScanIncomplete { .. }
        | RuntimeSpineRunStep::ScanDeadlineExceeded
        | RuntimeSpineRunStep::EffectUnavailable { .. }
        | RuntimeSpineRunStep::EffectDeadlineExceeded { .. } => {
            readiness.set(false);
            Ok(true)
        }
        RuntimeSpineRunStep::SessionInvalid { status, error } => {
            readiness.set(false);
            anyhow::bail!("signed Runtime session was rejected with {status}: {error:?}");
        }
        RuntimeSpineRunStep::Rejected { status, error } => {
            readiness.set(false);
            anyhow::bail!("signed Runtime request was rejected with {status}: {error:?}");
        }
        RuntimeSpineRunStep::RouteUnavailable => {
            readiness.set(false);
            anyhow::bail!("signed Runtime routes are not deployed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_stays_closed_without_an_accepted_full_observation() {
        let readiness = Readiness::closed();
        let response = health(State(readiness.clone())).await;
        assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.1, "signed Runtime inventory is not attested");

        readiness.set(true);
        assert_eq!(health(State(readiness)).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn cutover_listener_exposes_no_legacy_mutation_surface() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, health_router(Readiness::closed()))
                .await
                .unwrap();
        });
        for path in [
            "/v1/jobs",
            "/v1/nodes/heartbeat",
            "/v1/nodes/register",
            "/v1/nodes/work-status",
            "/v1/internal/work/acquire",
            "/v1/internal/work/release",
        ] {
            let response = reqwest::get(format!("http://{address}{path}"))
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        }
        server.abort();
    }

    #[test]
    fn unavailable_or_residue_scan_can_never_open_readiness() {
        let readiness = Readiness::closed();
        assert!(apply_readiness_policy(
            RuntimeSpineRunStep::ScanIncomplete {
                unavailable_sources: vec![
                    cats_api::runtime_reconciliation::InventorySource::MetadataStore,
                ],
            },
            &readiness,
        )
        .unwrap());
        assert!(!readiness.is_ready());

        readiness.set(true);
        assert!(apply_readiness_policy(
            RuntimeSpineRunStep::ScanUnavailable(anyhow::anyhow!("physical residue")),
            &readiness,
        )
        .unwrap());
        assert!(!readiness.is_ready());
    }
}

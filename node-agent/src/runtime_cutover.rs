//! Production composition for the atomic lifecycle cutover.
//!
//! The process has exactly three independent Node-to-Control lanes: the
//! per-Cat atomic lifecycle command runner owns physical effects and exact
//! Operation settlement, the Route command runner owns Endpoint gate
//! transitions, and the runtime inventory runner is observation-only. There
//! is no Desired/NodeObservation compatibility runner and no second local
//! lifecycle ledger in this composition.

use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::admission_registry::LifecycleAdmissionRegistry;
use crate::agent_registration::AgentRegistrationConfig;
use crate::lifecycle_command::runner::{
    LifecycleCommandExecutor, LifecycleCommandHttpClient, LifecycleCommandRunner,
    LifecycleCommandTransport,
};
use crate::route_command::{RouteCommandHttpClient, RouteCommandRunner, RouteCommandTransport};
use crate::route_v2_machine::{RouteV2MachineConfig, RouteV2MachineListener};
use crate::runtime_inventory::{
    RuntimeInventoryForceFullCoordinator, RuntimeInventoryHttpClient, RuntimeInventoryReadiness,
    RuntimeInventoryRunner, RuntimeInventorySource, RuntimeInventoryTransport,
    StartupInventoryCache,
};

/// Required clean-slate production composition.
///
/// Every authority-bearing dependency is injected explicitly. In particular,
/// there is no unavailable/no-op lifecycle executor, empty inventory source,
/// or legacy Desired fallback.
pub struct SignedRuntimeCutoverConfig {
    pub listen: String,
    pub route_v2_machine: RouteV2MachineConfig,
    pub control_plane_url: String,
    pub agent_registration: AgentRegistrationConfig,
    pub lifecycle_executor: Arc<dyn LifecycleCommandExecutor>,
    pub lifecycle_admission_registry: Arc<LifecycleAdmissionRegistry>,
    pub startup_inventory_cache: Arc<StartupInventoryCache>,
    pub runtime_inventory_source: Arc<dyn RuntimeInventorySource>,
    pub runtime_inventory_force_full: Arc<RuntimeInventoryForceFullCoordinator>,
    #[cfg(test)]
    pub(crate) lifecycle_transport_for_test: Option<Arc<dyn LifecycleCommandTransport>>,
    #[cfg(test)]
    pub(crate) runtime_inventory_transport_for_test: Option<Arc<dyn RuntimeInventoryTransport>>,
    #[cfg(test)]
    pub(crate) route_command_transport_for_test: Option<Arc<dyn RouteCommandTransport>>,
}

/// Owned process composition. Dropping the handle requests conservative
/// shutdown; `run_until_signal` additionally joins Route tunnels and all
/// durable runners before releasing the retained Agent registration/Host
/// lock.
pub struct SignedRuntimeCutoverHandle {
    pub addr: std::net::SocketAddr,
    pub route_v2_addr: std::net::SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    runners_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    route_v2_machine: RouteV2MachineListener,
}

impl SignedRuntimeCutoverHandle {
    /// Wait for process shutdown or the first component failure. Route ingress
    /// is closed and drained before lifecycle workers are asked to stop, so no
    /// admitted tunnel can outlive its runtime guard.
    pub async fn run_until_signal(mut self) -> anyhow::Result<()> {
        enum Stop {
            Signal(anyhow::Result<()>),
            Server(Result<anyhow::Result<()>, tokio::task::JoinError>),
            Runners(Result<anyhow::Result<()>, tokio::task::JoinError>),
            RunnerShutdown(Result<(), tokio::sync::watch::error::RecvError>),
            Route(anyhow::Result<()>),
        }

        // The runner owner flips this same channel immediately after the
        // first lifecycle/inventory/Route-command task exits, before waiting
        // for the remaining tasks to join. Observe that edge here so Route
        // ingress closes promptly instead of remaining open behind a bounded
        // network retry in another runner.
        let mut runner_shutdown = self.shutdown.subscribe();
        let stop = tokio::select! {
            signal = shutdown_signal() => Stop::Signal(signal),
            result = &mut self.server_task => Stop::Server(result),
            result = &mut self.runners_task => Stop::Runners(result),
            changed = runner_shutdown.changed() => Stop::RunnerShutdown(changed),
            result = self.route_v2_machine.wait() => Stop::Route(result),
        };

        self.route_v2_machine.begin_shutdown();
        let route_shutdown = self.shutdown_route_v2_machine().await;
        self.shutdown.send_replace(true);

        match stop {
            Stop::Signal(signal) => {
                let runners = join_component(
                    (&mut self.runners_task).await,
                    "join atomic lifecycle and runtime inventory runners",
                );
                self.server_task.abort();
                let _ = (&mut self.server_task).await;
                signal.and(route_shutdown).and(runners)
            }
            Stop::Server(server) => {
                let runners = join_component(
                    (&mut self.runners_task).await,
                    "join runners after health listener exit",
                );
                join_component(server, "runtime health listener stopped")
                    .and(route_shutdown)
                    .and(runners)
            }
            Stop::Runners(runners) => {
                self.server_task.abort();
                let _ = (&mut self.server_task).await;
                join_component(
                    runners,
                    "atomic lifecycle/runtime inventory runners stopped",
                )
                .and(route_shutdown)
            }
            Stop::RunnerShutdown(changed) => {
                let runners = join_component(
                    (&mut self.runners_task).await,
                    "join runners after component shutdown request",
                );
                self.server_task.abort();
                let _ = (&mut self.server_task).await;
                changed
                    .context("atomic lifecycle runner shutdown signal closed")
                    .and(route_shutdown)
                    .and(runners)
            }
            Stop::Route(route) => {
                let runners = join_component(
                    (&mut self.runners_task).await,
                    "join runners after Route v2 listener exit",
                );
                self.server_task.abort();
                let _ = (&mut self.server_task).await;
                route.and(route_shutdown).and(runners)
            }
        }
    }

    async fn shutdown_route_v2_machine(&mut self) -> anyhow::Result<()> {
        self.route_v2_machine.shutdown().await
    }
}

impl Drop for SignedRuntimeCutoverHandle {
    fn drop(&mut self) {
        self.route_v2_machine.begin_shutdown();
        self.shutdown.send_replace(true);
        self.server_task.abort();
    }
}

fn join_component(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    context: &'static str,
) -> anyhow::Result<()> {
    result.context(context)?
}

async fn supervise_runtime_runners(
    mut lifecycle_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    mut inventory_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    mut route_command_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    worker_shutdown: tokio::sync::watch::Sender<bool>,
) -> anyhow::Result<()> {
    enum First {
        Shutdown,
        Lifecycle(Result<anyhow::Result<()>, tokio::task::JoinError>),
        Inventory(Result<anyhow::Result<()>, tokio::task::JoinError>),
        RouteCommand(Result<anyhow::Result<()>, tokio::task::JoinError>),
    }

    let first = tokio::select! {
        changed = shutdown_rx.changed() => {
            let _ = changed;
            First::Shutdown
        }
        result = &mut lifecycle_task => First::Lifecycle(result),
        result = &mut inventory_task => First::Inventory(result),
        result = &mut route_command_task => First::RouteCommand(result),
    };
    // A component exit is process-wide. Publish shutdown before joining any
    // sibling so a bounded retry/collection loop can converge and release its
    // resources instead of leaving the Host-global registration lease held.
    worker_shutdown.send_replace(true);

    match first {
        First::Shutdown => {
            let lifecycle = join_component(
                lifecycle_task.await,
                "join atomic lifecycle runner during shutdown",
            );
            let inventory = join_component(
                inventory_task.await,
                "join runtime inventory runner during shutdown",
            );
            let route_command = join_component(
                route_command_task.await,
                "join Route command runner during shutdown",
            );
            lifecycle.and(inventory).and(route_command)
        }
        First::Lifecycle(lifecycle) => {
            let inventory = join_component(
                inventory_task.await,
                "join runtime inventory after lifecycle runner stopped",
            );
            let route_command = join_component(
                route_command_task.await,
                "join Route command after lifecycle runner stopped",
            );
            join_component(lifecycle, "atomic lifecycle runner stopped")
                .and(inventory)
                .and(route_command)
        }
        First::Inventory(inventory) => {
            let lifecycle = join_component(
                lifecycle_task.await,
                "join lifecycle runner after runtime inventory stopped",
            );
            let route_command = join_component(
                route_command_task.await,
                "join Route command after runtime inventory stopped",
            );
            join_component(inventory, "runtime inventory runner stopped")
                .and(lifecycle)
                .and(route_command)
        }
        First::RouteCommand(route_command) => {
            let lifecycle = join_component(
                lifecycle_task.await,
                "join lifecycle runner after Route command stopped",
            );
            let inventory = join_component(
                inventory_task.await,
                "join runtime inventory after Route command stopped",
            );
            join_component(route_command, "Route command runner stopped")
                .and(lifecycle)
                .and(inventory)
        }
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
struct Readiness {
    inventory: tokio::sync::watch::Receiver<RuntimeInventoryReadiness>,
}

impl Readiness {
    fn is_attested(&self) -> bool {
        matches!(
            &*self.inventory.borrow(),
            RuntimeInventoryReadiness::Attested { .. }
        )
    }
}

async fn health(State(readiness): State<Readiness>) -> (StatusCode, &'static str) {
    readiness_response(&readiness)
}

async fn attested(State(readiness): State<Readiness>) -> (StatusCode, &'static str) {
    readiness_response(&readiness)
}

fn readiness_response(readiness: &Readiness) -> (StatusCode, &'static str) {
    if readiness.is_attested() {
        (StatusCode::OK, "runtime inventory attested")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime inventory is awaiting a session Full attestation",
        )
    }
}

fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/attestedz", get(attested))
        .with_state(readiness)
}

/// Register one AgentSession, perform the lifecycle lane's sole complete
/// physical scan and journal enumeration, then start lifecycle, inventory and
/// Route as independently owned tasks.
pub async fn spawn_signed_runtime_cutover(
    config: SignedRuntimeCutoverConfig,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    let session = config
        .agent_registration
        .register_until_session(&config.control_plane_url)
        .await
        .context("establish durable Agent session")?;

    let lifecycle_transport = lifecycle_transport(&config)?;
    let runtime_inventory_transport = runtime_inventory_transport(&config)?;
    let state_directory = config.agent_registration.runtime_state_directory();
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);

    // This is the unique startup scan and descriptor-safe journal
    // enumeration. It initializes the shared registry and publishes the
    // Joined telemetry seed before any command worker or Route listener is
    // started.
    let lifecycle_runner = LifecycleCommandRunner::open(
        state_directory.clone(),
        session.clone(),
        lifecycle_transport,
        Arc::clone(&config.lifecycle_executor),
        Arc::clone(&config.lifecycle_admission_registry),
        Arc::clone(&config.startup_inventory_cache),
        shutdown_rx.clone(),
    )
    .await
    .context("open atomic lifecycle runner")?;

    let (runtime_inventory_runner, inventory_readiness) = RuntimeInventoryRunner::open(
        state_directory,
        session.clone(),
        runtime_inventory_transport,
        Arc::clone(&config.runtime_inventory_source),
        Arc::clone(&config.runtime_inventory_force_full),
        shutdown_rx.clone(),
    )
    .await
    .context("open runtime inventory runner")?;

    // Route command execution uses the exact verifier owned by the listener
    // configuration. Construct it only after lifecycle startup initialized
    // the shared registry, and before moving that configuration into the
    // listener.
    let route_command_runner = RouteCommandRunner::new(
        session,
        route_command_transport(&config)?,
        Arc::clone(&config.lifecycle_admission_registry),
        config.route_v2_machine.verifier(),
        shutdown_rx.clone(),
    )
    .context("open signed Route command runner")?;

    // Bind health before spawning background work. A bind failure therefore
    // cannot detach a runner or release the Host lock at an ambiguous point.
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind runtime health listener {}", config.listen))?;
    let addr = listener.local_addr()?;

    // Registry initialization above is the required Route startup barrier.
    let route_v2_machine = RouteV2MachineListener::spawn(
        config.route_v2_machine,
        Arc::clone(&config.lifecycle_admission_registry),
    )
    .await
    .context("start authenticated Node Route v2 listener")?;
    let route_v2_addr = route_v2_machine.addr();

    let readiness = Readiness {
        inventory: inventory_readiness,
    };
    let server_task = tokio::spawn(async move {
        axum::serve(listener, health_router(readiness))
            .await
            .context("serve runtime health listener")
    });

    let worker_shutdown = shutdown.clone();
    // Retain the Host-global lock through every runner join. The handle only
    // owns a shutdown request; dropping it cannot release the lock while an
    // accepted command worker is still finishing a bounded physical effect.
    let registration_lease = config.agent_registration;
    let runners_task = tokio::spawn(async move {
        let lifecycle_task =
            tokio::spawn(async move { lifecycle_runner.run().await.map_err(anyhow::Error::new) });
        let inventory_task = tokio::spawn(async move {
            runtime_inventory_runner
                .run()
                .await
                .map_err(anyhow::Error::new)
        });
        let route_command_task =
            tokio::spawn(
                async move { route_command_runner.run().await.map_err(anyhow::Error::new) },
            );
        let outcome = supervise_runtime_runners(
            lifecycle_task,
            inventory_task,
            route_command_task,
            shutdown_rx,
            worker_shutdown,
        )
        .await;
        drop(registration_lease);
        outcome
    });

    Ok(SignedRuntimeCutoverHandle {
        addr,
        route_v2_addr,
        shutdown,
        server_task,
        runners_task,
        route_v2_machine,
    })
}

fn lifecycle_transport(
    config: &SignedRuntimeCutoverConfig,
) -> anyhow::Result<Arc<dyn LifecycleCommandTransport>> {
    #[cfg(test)]
    if let Some(transport) = config.lifecycle_transport_for_test.as_ref() {
        return Ok(Arc::clone(transport));
    }
    #[cfg(test)]
    if config.agent_registration.uses_loopback_transport_for_test() {
        return Ok(Arc::new(LifecycleCommandHttpClient::for_loopback_test(
            &config.control_plane_url,
            config.agent_registration.runtime_request_signer(),
        )?));
    }
    Ok(Arc::new(LifecycleCommandHttpClient::for_production(
        &config.control_plane_url,
        &config.agent_registration,
    )?))
}

fn runtime_inventory_transport(
    config: &SignedRuntimeCutoverConfig,
) -> anyhow::Result<Arc<dyn RuntimeInventoryTransport>> {
    #[cfg(test)]
    if let Some(transport) = config.runtime_inventory_transport_for_test.as_ref() {
        return Ok(Arc::clone(transport));
    }
    #[cfg(test)]
    if config.agent_registration.uses_loopback_transport_for_test() {
        return Ok(Arc::new(RuntimeInventoryHttpClient::for_loopback_test(
            &config.control_plane_url,
            config.agent_registration.runtime_request_signer(),
        )?));
    }
    Ok(Arc::new(RuntimeInventoryHttpClient::for_production(
        &config.control_plane_url,
        &config.agent_registration,
    )?))
}

fn route_command_transport(
    config: &SignedRuntimeCutoverConfig,
) -> anyhow::Result<Arc<dyn RouteCommandTransport>> {
    #[cfg(test)]
    if let Some(transport) = config.route_command_transport_for_test.as_ref() {
        return Ok(Arc::clone(transport));
    }
    Ok(Arc::new(RouteCommandHttpClient::for_production(
        &config.control_plane_url,
        &config.agent_registration,
    )?))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn health_stays_closed_before_full_inventory_attestation() {
        let (_sender, inventory) =
            tokio::sync::watch::channel(RuntimeInventoryReadiness::AwaitingFull);
        assert_eq!(
            health(State(Readiness { inventory })).await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime inventory is awaiting a session Full attestation"
            )
        );
    }

    #[tokio::test]
    async fn component_failure_requests_shutdown_and_joins_healthy_siblings() {
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut sibling_shutdown = shutdown.subscribe();
        let mut route_shutdown = shutdown.subscribe();
        let sibling_observed_shutdown = Arc::new(AtomicBool::new(false));
        let route_observed_shutdown = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&sibling_observed_shutdown);
        let route_observed = Arc::clone(&route_observed_shutdown);
        let lifecycle_task =
            tokio::spawn(async { anyhow::bail!("injected lifecycle component failure") });
        let inventory_task = tokio::spawn(async move {
            while !*sibling_shutdown.borrow() {
                sibling_shutdown
                    .changed()
                    .await
                    .context("wait for component shutdown")?;
            }
            observed.store(true, Ordering::SeqCst);
            Ok(())
        });
        let route_command_task = tokio::spawn(async move {
            while !*route_shutdown.borrow() {
                route_shutdown
                    .changed()
                    .await
                    .context("wait for Route component shutdown")?;
            }
            route_observed.store(true, Ordering::SeqCst);
            Ok(())
        });

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            supervise_runtime_runners(
                lifecycle_task,
                inventory_task,
                route_command_task,
                shutdown_rx,
                shutdown,
            ),
        )
        .await
        .expect("component supervisor did not wedge")
        .expect_err("injected component failure must fail the process");

        assert!(error
            .to_string()
            .contains("injected lifecycle component failure"));
        assert!(sibling_observed_shutdown.load(Ordering::SeqCst));
        assert!(route_observed_shutdown.load(Ordering::SeqCst));
    }

    #[test]
    fn production_composition_has_no_legacy_desired_or_usage_runner() {
        let source = include_str!("runtime_cutover.rs");
        assert!(source.contains("RouteCommandRunner::new"));
        let route_listener = source
            .find("let route_v2_machine = RouteV2MachineListener::spawn")
            .expect("mandatory Route v2 listener is composed");
        let lifecycle_inventory_tasks = source
            .find("let runners_task = tokio::spawn")
            .expect("lifecycle/inventory task owner is composed");
        assert!(
            route_listener < lifecycle_inventory_tasks,
            "Route v2 listener must bind before lifecycle/inventory tasks can start"
        );
        for forbidden_optional_route in [
            ["route_v2_machine: ", "Option"].concat(),
            ["route_v2_addr: ", "Option"].concat(),
            ["route_command_runner", ".map"].concat(),
            ["wait_optional", "_runner"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden_optional_route),
                "Route v2 composition must not retain optional fallback {forbidden_optional_route:?}"
            );
        }
        for forbidden in [
            ["Runtime", "Spine", "Runner"].concat(),
            ["Runtime", "Desired", "Effect"].concat(),
            ["Signed", "Usage", "Pipeline"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }
}

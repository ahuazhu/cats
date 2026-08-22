use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    CatAction, CatState, NodeHeartbeatRequest, NodeName, NodeRegistrationRequest, NodeStatus,
    NodedControlEndpoint, NodedServiceToken,
};
use cats_node_agent::semantic_lifecycle::{
    semantic_node_router, SemanticActionCancellation, SemanticCatEffects, SemanticEffectError,
    SemanticEffectFuture, SemanticEffectRequest, SemanticNodeService,
};
use cats_node_agent::semantic_node_client::{
    HttpSemanticNodeTransport, NodeClientFuture, NodeHeartbeatSource, NodePlacementGate,
    SemanticNodeSupervisor,
};
use clap::Parser;

#[derive(Parser)]
#[command(name = "cats-noded", about = "Cats semantic Node agent")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7001")]
    listen: String,
    #[arg(long)]
    control_plane_url: String,
    /// Externally reachable absolute origin reported during registration.
    #[arg(long)]
    control_endpoint: String,
    #[arg(long, env = "CATS_NODED_SERVICE_TOKEN", hide_env_values = true)]
    service_token: String,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    node_name: String,
    #[arg(long)]
    vendor: String,
    #[arg(long)]
    region: String,
    #[arg(long)]
    zone: String,
    #[arg(long)]
    instance_id: String,
    #[arg(long)]
    machine_type: String,
    #[arg(long, env = "CATS_NODE_VERSION")]
    node_version: String,
    #[arg(long, default_value_t = 1)]
    total_cpu: u32,
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024_u64)]
    total_memory: u64,
    /// VMM effects adapter. The clean-slate integration cut currently exposes
    /// only `fake`; `ch` fails startup until the installed effect adapter is
    /// connected to the semantic action trait.
    #[arg(long, default_value = "fake")]
    vmm: String,
}

#[derive(Default)]
struct FakeSemanticEffects {
    states: Arc<Mutex<BTreeMap<String, CatState>>>,
}

impl SemanticCatEffects for FakeSemanticEffects {
    fn execute(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> SemanticEffectFuture {
        let states = Arc::clone(&self.states);
        Box::pin(async move {
            if cancellation.is_cancelled() && request.action != CatAction::Destroy {
                return Err(SemanticEffectError::new(
                    cats_api::semantic_control::SemanticErrorCode::ActionCancelled,
                    "action was cancelled by destroy",
                ));
            }
            let mut states = states
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match request.action {
                CatAction::Create | CatAction::Run => {
                    states.insert(request.cat_id, CatState::Running);
                }
                CatAction::Suspend => {
                    states.insert(request.cat_id, CatState::Suspended);
                }
                CatAction::Warm => {
                    states.insert(request.cat_id, CatState::Warm);
                }
                CatAction::Cold => {
                    states.insert(request.cat_id, CatState::Cold);
                }
                CatAction::Destroy => {
                    states.remove(&request.cat_id);
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct ServiceHeartbeatSource {
    service: SemanticNodeService,
    node_id: Id,
    total_cpu: u32,
    total_memory: u64,
}

impl NodeHeartbeatSource for ServiceHeartbeatSource {
    fn snapshot(&self) -> NodeClientFuture<NodeHeartbeatRequest> {
        let service = self.service.clone();
        let node_id = self.node_id.clone();
        let total_cpu = self.total_cpu;
        let total_memory = self.total_memory;
        Box::pin(async move {
            let reported_status = if service.placement_gate().is_open() {
                NodeStatus::Running
            } else {
                NodeStatus::ResetRequired
            };
            let cats = service.list();
            let mut running_cat_count = 0_u32;
            let mut suspended_cat_count = 0_u32;
            let mut warm_cat_count = 0_u32;
            for cat in cats.cats {
                match cat.state {
                    Some(CatState::Running) => {
                        running_cat_count = running_cat_count.saturating_add(1);
                    }
                    Some(CatState::Suspended) => {
                        suspended_cat_count = suspended_cat_count.saturating_add(1);
                    }
                    Some(CatState::Warm) => {
                        warm_cat_count = warm_cat_count.saturating_add(1);
                    }
                    _ => {}
                }
            }
            let node_reported_at_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before the Unix epoch")?
                .as_millis()
                .try_into()
                .context("Node timestamp does not fit u64")?;
            Ok(NodeHeartbeatRequest {
                node_id,
                node_reported_at_unix_ms,
                reported_status,
                total_cpu,
                cpu_utilized: 0.0,
                total_memory,
                memory_utilized: 0,
                running_cat_count,
                suspended_cat_count,
                warm_cat_count,
            })
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    anyhow::ensure!(
        args.vmm == "fake",
        "--vmm {} is not connected to the semantic lifecycle yet; use --vmm fake",
        args.vmm
    );
    anyhow::ensure!(
        args.total_cpu > 0 && args.total_memory > 0,
        "Node heartbeat capacity must be positive"
    );

    let token = NodedServiceToken::new(args.service_token)
        .context("service token must satisfy the shared noded token contract")?;
    let node_id = Id::new(args.node_id).context("invalid node_id")?;
    let registration = NodeRegistrationRequest {
        node_id: node_id.clone(),
        node_name: NodeName::new(args.node_name).context("invalid node_name")?,
        control_endpoint: NodedControlEndpoint::new(args.control_endpoint)
            .context("invalid control_endpoint")?,
        vendor: args.vendor,
        region: args.region,
        zone: args.zone,
        instance_id: args.instance_id,
        machine_type: args.machine_type,
        node_version: args.node_version,
        reset_completed: false,
    };
    registration
        .validate()
        .context("validate Node registration")?;

    let placement_gate = Arc::new(NodePlacementGate::default());
    let effects: Arc<dyn SemanticCatEffects> = Arc::new(FakeSemanticEffects::default());
    let service = SemanticNodeService::with_placement_gate(effects, Arc::clone(&placement_gate));
    let reset: Arc<dyn cats_node_agent::semantic_node_client::NodeResetExecutor> =
        Arc::new(service.clone());
    let transport = Arc::new(HttpSemanticNodeTransport::new(
        args.control_plane_url,
        token.clone(),
    )?);
    let supervisor =
        SemanticNodeSupervisor::new(transport, reset, Arc::clone(&placement_gate), registration)?;
    let heartbeat_source: Arc<dyn NodeHeartbeatSource> = Arc::new(ServiceHeartbeatSource {
        service: service.clone(),
        node_id,
        total_cpu: args.total_cpu,
        total_memory: args.total_memory,
    });

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("bind semantic noded listener {}", args.listen))?;
    let addr = listener.local_addr()?;
    let router = semantic_node_router(service, token);
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server_shutdown = shutdown_rx.clone();
    let mut server_task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                if !*server_shutdown.borrow() {
                    let _ = server_shutdown.changed().await;
                }
            })
            .await
            .context("serve semantic noded API")
    });
    let mut supervisor_task =
        tokio::spawn(async move { supervisor.run(heartbeat_source, shutdown_rx).await });
    tracing::info!(%addr, "semantic noded fake listener is ready; placement opens after registration");

    enum Stop {
        Signal(anyhow::Result<()>),
        Server(Result<anyhow::Result<()>, tokio::task::JoinError>),
        Supervisor(Result<anyhow::Result<()>, tokio::task::JoinError>),
    }
    let stop = tokio::select! {
        signal = shutdown_signal() => Stop::Signal(signal),
        result = &mut server_task => Stop::Server(result),
        result = &mut supervisor_task => Stop::Supervisor(result),
    };
    shutdown.send_replace(true);
    match stop {
        Stop::Signal(signal) => signal
            .and(join_task(server_task.await, "semantic noded server"))
            .and(join_task(supervisor_task.await, "semantic Node supervisor")),
        Stop::Server(server) => join_task(server, "semantic noded server").and(join_task(
            supervisor_task.await,
            "semantic Node supervisor after server exit",
        )),
        Stop::Supervisor(supervisor) => {
            join_task(supervisor, "semantic Node supervisor").and(join_task(
                server_task.await,
                "semantic noded server after supervisor exit",
            ))
        }
    }
}

fn join_task(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    component: &'static str,
) -> anyhow::Result<()> {
    result.with_context(|| format!("join {component}"))?
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(anyhow::Error::from),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await.map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    #[test]
    fn semantic_entrypoint_has_no_old_poll_or_operation_runtime() {
        let source = include_str!("main.rs");
        assert!(source.contains("semantic_node_router"));
        assert!(source.contains("SemanticNodeSupervisor"));
        let old_spawn = ["spawn_signed_runtime_", "cutover"].concat();
        let old_runner = ["LifecycleCommand", "Runner"].concat();
        let old_authority = ["Lifecycle", "Operation"].concat();
        assert!(!source.contains(&old_spawn));
        assert!(!source.contains(&old_runner));
        assert!(!source.contains(&old_authority));
    }

    #[test]
    fn semantic_cli_requires_registration_identity_and_service_token() {
        let command = super::Args::command();
        for required in [
            "control_plane_url",
            "control_endpoint",
            "service_token",
            "node_id",
            "node_name",
            "instance_id",
        ] {
            let argument = command
                .get_arguments()
                .find(|argument| argument.get_id().as_str() == required)
                .expect("semantic argument exists");
            assert!(argument.is_required_set(), "{required} must be required");
        }
    }
}

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    CatAction, CatState, NodeHeartbeatRequest, NodeName, NodeRegistrationRequest, NodeStatus,
    NodedControlEndpoint, NodedServiceToken,
};
use cats_metadata_store_postgres::PostgresVolumeDataAuthority;
use cats_node_agent::ch::{BlockPath, ChConfig};
use cats_node_agent::semantic_installed::{InstalledCatConfig, InstalledSemanticCatEffects};
use cats_node_agent::semantic_lifecycle::{
    semantic_node_router, SemanticActionCancellation, SemanticCatEffects, SemanticEffectError,
    SemanticEffectFuture, SemanticEffectRequest, SemanticNodeService,
};
use cats_node_agent::semantic_node_client::{
    HttpSemanticNodeTransport, NodeClientFuture, NodeHeartbeatSource, NodePlacementGate,
    SemanticNodeSupervisor, SemanticNodeTransport,
};
use cats_node_agent::semantic_usage::{
    detect_delegated_cgroup, run_usage_delivery, run_usage_sampler, CatUsageMeters,
    MeteringCgroupRoot,
};
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStoreFactory;
use cats_storage::authority::{CatVolumeStore, VolumeDataAuthority};
use cats_storage::{open_blob_store, AdapterConfig, AdapterSelection, BlobStoreFactory};
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
    #[arg(long, env = "CATS_AUTH_TOKEN", hide_env_values = true)]
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
    #[arg(
        long,
        env = "CATS_NODE_VERSION",
        default_value = env!("CARGO_PKG_VERSION")
    )]
    node_version: String,
    #[arg(long, default_value_t = 1)]
    total_cpu: u32,
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024_u64)]
    total_memory: u64,
    /// VMM effects adapter. `fake` is for process tests; `ch` owns the real
    /// blockd, Cloud Hypervisor and Guest effects.
    #[arg(long, default_value = "fake")]
    vmm: String,
    #[arg(long, default_value = "/var/lib/cats/semantic-node")]
    state_directory: PathBuf,
    #[arg(long, default_value = "/run/cats/semantic-node")]
    runtime_directory: PathBuf,
    #[arg(long, default_value = "/var/lib/cats/node/host.lock")]
    host_lock: PathBuf,
    #[arg(long, default_value = "/run/cats/blockd-v1")]
    blockd_socket_root: PathBuf,
    #[arg(long, default_value = "/var/lib/cats/golden-root-cache/rootfs.ext4")]
    golden_root_cache_image: PathBuf,
    #[arg(long, default_value = "/opt/cats/bin/cats-blockd")]
    blockd_bin: PathBuf,
    #[arg(long)]
    metadata_store_adapter: Option<String>,
    #[arg(long = "metadata-store-option", value_name = "KEY=VALUE")]
    metadata_store_options: Vec<String>,
    #[arg(long)]
    object_store_adapter: Option<String>,
    #[arg(long = "object-store-option", value_name = "KEY=VALUE")]
    object_store_options: Vec<String>,
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024_u64)]
    root_size_bytes: u64,
    #[arg(long, default_value_t = 60_000)]
    volume_lease_duration_ms: u64,
    #[arg(long, default_value_t = 120_000)]
    effect_timeout_ms: u64,
    #[arg(long, default_value_t = 60_000)]
    guest_ready_timeout_ms: u64,
    #[arg(
        long,
        env = "CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE",
        value_name = "PATH"
    )]
    guest_runtime_profile_receipt_file: Option<PathBuf>,
    #[arg(long, default_value = "/usr/local/bin/cloud-hypervisor")]
    ch_bin: PathBuf,
    #[arg(long)]
    ch_seed_image: Option<PathBuf>,
    #[arg(long, default_value = "kernel-nbd")]
    ch_block_path: String,
    #[arg(long, default_value_t = false)]
    ch_block_direct: bool,
    #[arg(long, default_value_t = 1)]
    ch_vhost_user_queues: usize,
    #[arg(long, default_value_t = 256)]
    ch_vhost_user_queue_size: u16,
    #[arg(long, default_value = "/usr/sbin/nbd-client")]
    ch_nbd_client: PathBuf,
    #[arg(long, default_value_t = 64)]
    ch_nbd_devices: u32,
    #[arg(long, default_value = "/usr/sbin/ip")]
    ch_ip_bin: PathBuf,
    /// Delegated cgroup v2 subtree the Node meters Cats in. Defaults to the
    /// subtree systemd delegated to this unit. `off` disables billing
    /// observation; the runtime is unaffected either way.
    #[arg(long, env = "CATS_METERING_CGROUP_ROOT", default_value = "auto")]
    metering_cgroup_root: String,
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

/// Prepare the Host's billing meter root.
///
/// Metering is observation, not authority. An explicitly configured root that
/// cannot be prepared is an operator error and fails startup; auto-detection
/// that cannot be satisfied leaves the Node serving with metering off and says
/// so loudly, because refusing to run would be the larger outage.
fn metering_cgroup_root(setting: &str) -> anyhow::Result<Option<MeteringCgroupRoot>> {
    match setting {
        "off" => {
            tracing::warn!("Cat usage metering is disabled by configuration");
            Ok(None)
        }
        "auto" => {
            let prepared = detect_delegated_cgroup()
                .and_then(|delegated| MeteringCgroupRoot::initialize(&delegated));
            match prepared {
                Ok(root) => Ok(Some(root)),
                Err(error) => {
                    tracing::error!(
                        error = %format!("{error:#}"),
                        "could not prepare the delegated metering cgroup; compute usage on this \
                         Node will not be billed"
                    );
                    Ok(None)
                }
            }
        }
        explicit => MeteringCgroupRoot::initialize(std::path::Path::new(explicit))
            .with_context(|| format!("prepare the configured metering cgroup root {explicit}"))
            .map(Some),
    }
}

fn semantic_effects(
    args: &Args,
    node_id: &Id,
    meters: Arc<CatUsageMeters>,
) -> anyhow::Result<Arc<dyn SemanticCatEffects>> {
    match args.vmm.as_str() {
        "fake" => Ok(Arc::new(FakeSemanticEffects::default())),
        "ch" => {
            let receipt_path = args
                .guest_runtime_profile_receipt_file
                .as_deref()
                .context("--guest-runtime-profile-receipt-file is required for --vmm ch")?;
            let installed =
                cats_api::runtime_artifacts::load_installed_guest_runtime_profile_receipt(
                    receipt_path,
                )
                .context("load installed Guest runtime profile")?;
            cats_api::runtime_artifacts::validate_installed_node_guest_runtime(&installed)
                .context("validate installed Guest runtime")?;
            let metadata_name = args
                .metadata_store_adapter
                .clone()
                .context("--metadata-store-adapter is required for --vmm ch")?;
            anyhow::ensure!(
                metadata_name == cats_metadata_store_postgres::ADAPTER_NAME,
                "installed mode supports only the postgres metadata adapter"
            );
            let object_name = args
                .object_store_adapter
                .clone()
                .context("--object-store-adapter is required for --vmm ch")?;
            let metadata_config = AdapterConfig::from_cli(args.metadata_store_options.clone())
                .context("metadata adapter options")?;
            let object_config = AdapterConfig::from_cli(args.object_store_options.clone())
                .context("object adapter options")?;
            let authority = PostgresVolumeDataAuthority::open_runtime(&metadata_config)
                .context("open PostgreSQL Cat volume authority")?;
            let volume_store: Arc<dyn CatVolumeStore> = authority.clone();
            let volume_data: Arc<dyn VolumeDataAuthority> = authority;
            let object_factories: [&dyn BlobStoreFactory; 2] =
                [&FileBlobStoreFactory, &AwsS3BlobStoreFactory];
            let blob = open_blob_store(&object_name, &object_config, &object_factories)
                .context("open installed object store")?;
            let socket_root = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::from_canonical_path(
                cats_api::runtime_reconciliation::HostPath::new(
                    args.blockd_socket_root.to_string_lossy().into_owned(),
                )
                .context("blockd socket root is not canonical")?,
            )
            .context("blockd socket root is invalid")?;
            let boot_contract = installed.boot_contract();
            let ch = ChConfig {
                block_direct: args.ch_block_direct,
                ch_bin: args.ch_bin.clone(),
                kernel: cats_api::runtime_artifacts::GUEST_KERNEL_PATH.into(),
                initramfs: boot_contract
                    .initramfs()
                    .map(|_| cats_api::runtime_artifacts::GUEST_INITRAMFS_PATH.into()),
                boot_contract: Some(boot_contract),
                cmdline: installed.receipt().kernel_cmdline.as_str().to_owned(),
                seed_image: args.ch_seed_image.clone(),
                block_path: BlockPath::parse(&args.ch_block_path)?,
                vhost_user_queues: args.ch_vhost_user_queues,
                vhost_user_queue_size: args.ch_vhost_user_queue_size,
                nbd_client_bin: args.ch_nbd_client.clone(),
                nbd_devices: args.ch_nbd_devices,
                ip_bin: args.ch_ip_bin.clone(),
            };
            Ok(Arc::new(InstalledSemanticCatEffects::new(
                InstalledCatConfig {
                    node_id: node_id.clone(),
                    state_directory: args.state_directory.clone(),
                    runtime_directory: args.runtime_directory.clone(),
                    host_lock: args.host_lock.clone(),
                    blockd_binary: args.blockd_bin.clone(),
                    blockd_socket_root: socket_root,
                    golden_root_cache_image: args.golden_root_cache_image.clone(),
                    metadata_store: AdapterSelection::new(metadata_name, metadata_config),
                    object_store: AdapterSelection::new(object_name, object_config),
                    ch,
                    root_size_bytes: args.root_size_bytes,
                    lease_duration_ms: args.volume_lease_duration_ms,
                    effect_timeout: Duration::from_millis(args.effect_timeout_ms),
                    guest_ready_timeout: Duration::from_millis(args.guest_ready_timeout_ms),
                },
                volume_store,
                volume_data,
                blob,
                meters,
            )?))
        }
        unsupported => anyhow::bail!("unsupported --vmm {unsupported}; expected fake or ch"),
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
        args.total_cpu > 0 && args.total_memory > 0,
        "Node heartbeat capacity must be positive"
    );
    let node_id = Id::new(args.node_id.clone()).context("invalid node_id")?;
    let vmm_mode = args.vmm.clone();
    let meters = Arc::new(CatUsageMeters::new(
        node_id.clone(),
        if args.vmm == "ch" {
            metering_cgroup_root(&args.metering_cgroup_root)?
        } else {
            None
        },
    )?);
    let effects = semantic_effects(&args, &node_id, Arc::clone(&meters))?;

    let token = NodedServiceToken::new(args.service_token)
        .context("service token must satisfy the shared noded token contract")?;
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
    let service = SemanticNodeService::with_placement_gate(effects, Arc::clone(&placement_gate));
    let reset: Arc<dyn cats_node_agent::semantic_node_client::NodeResetExecutor> =
        Arc::new(service.clone());
    let transport = Arc::new(HttpSemanticNodeTransport::new(
        args.control_plane_url,
        token.clone(),
    )?);
    let usage_transport: Arc<dyn SemanticNodeTransport> = Arc::clone(&transport) as Arc<_>;
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
    let usage_shutdown_rx = shutdown_rx.clone();
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
    // Billing observation runs beside the runtime, never inside it: neither
    // task can fail an effect, and neither failure stops the Node.
    let sampler_task = tokio::spawn(run_usage_sampler(
        Arc::clone(&meters),
        usage_shutdown_rx.clone(),
    ));
    let delivery_task = tokio::spawn(run_usage_delivery(
        meters,
        usage_transport,
        usage_shutdown_rx,
    ));
    tracing::info!(%addr, vmm = %vmm_mode, "semantic noded listener is ready; placement opens after registration");

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
    if let Err(error) = join_task(sampler_task.await, "Cat usage sampler") {
        tracing::warn!(error = %format!("{error:#}"), "Cat usage sampler stopped early");
    }
    if let Err(error) = join_task(delivery_task.await, "Cat usage delivery") {
        tracing::warn!(error = %format!("{error:#}"), "Cat usage delivery stopped early");
    }
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
    use cats_api::runtime_reconciliation::Id;
    use clap::{CommandFactory as _, Parser as _};

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

    #[test]
    fn semantic_effect_selection_is_explicit() {
        let mut args = super::Args::try_parse_from([
            "cats-noded",
            "--control-plane-url",
            "http://127.0.0.1:7300",
            "--control-endpoint",
            "http://127.0.0.1:7001",
            "--service-token",
            "test-service-token",
            "--node-id",
            "node_01",
            "--node-name",
            "worker-01",
            "--vendor",
            "test",
            "--region",
            "test-1",
            "--zone",
            "test-1a",
            "--instance-id",
            "instance-01",
            "--machine-type",
            "test.large",
            "--node-version",
            "test",
            "--vmm",
            "fake",
        ])
        .expect("parse fake noded arguments");
        let node_id = Id::new("node_01").unwrap();
        let meters = std::sync::Arc::new(
            cats_node_agent::semantic_usage::CatUsageMeters::new(node_id.clone(), None)
                .expect("meters"),
        );
        assert!(super::semantic_effects(&args, &node_id, meters.clone()).is_ok());
        args.vmm = "other".to_owned();
        let error = match super::semantic_effects(&args, &node_id, meters) {
            Ok(_) => panic!("unknown VMM must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("expected fake or ch"));
    }
}

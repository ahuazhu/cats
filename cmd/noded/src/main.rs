use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cats_node_agent::ch::{BlockPath, ChConfig};
use cats_node_agent::lifecycle_command::installed::{
    installed_atomic_lifecycle_executor, installed_atomic_start_runtime_port,
    InstalledAtomicColdDeletePort, InstalledAtomicLifecycleConfig,
    InstalledAtomicStartBlockdConfig, InstalledAtomicStartObjectWriteMode,
    InstalledAtomicStartRuntimeConfig, InstalledAtomicStartVolumePort,
    InstalledColdDeleteLocalPort, InstalledLifecycleKernelNbdConfig,
    InstalledPhysicalInspectionConfig, InstalledSuspendWarmPlatform,
};
use cats_node_agent::lifecycle_volume_client::LifecycleVolumeHttpClient;
use cats_node_agent::route_v2_machine::RouteV2MachineConfig;
use cats_node_agent::runtime_cutover::{spawn_signed_runtime_cutover, SignedRuntimeCutoverConfig};
use cats_node_agent::runtime_inventory::{
    ProductionRuntimeInventorySource, RuntimeInventoryForceFullCoordinator, StartupInventoryCache,
};
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStoreFactory;
use cats_storage::{open_blob_store, AdapterConfig, AdapterSelection, BlobStoreFactory};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-noded", about = "Cats node agent")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    #[arg(long)]
    control_plane_url: String,
    #[arg(
        long,
        env = "CATS_ROUTE_V2_PUBLIC_KEY_RING_FILE",
        default_value = cats_api::route_grant_v2::ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH
    )]
    route_v2_public_key_ring_file: PathBuf,
    /// Mandatory TLS listener for authenticated Gateway Route v2 tunnels.
    #[arg(long, env = "CATS_ROUTE_V2_MACHINE_LISTEN")]
    route_v2_machine_listen: String,
    /// Server-authenticated HTTPS origin for adjacent Route v2 ring delivery.
    /// It is independent from the public management Control origin.
    #[arg(long, env = "CATS_ROUTE_V2_ROTATION_ORIGIN")]
    route_v2_rotation_origin: String,
    /// Bare HTTPS origin of the ObjectWrite Gateway. A production worker is
    /// denied direct object-store writes by IAM, so this is the only path by
    /// which a serving process can publish; it is independent from the public
    /// management Control origin.
    #[arg(long, env = "CATS_OBJECT_WRITE_GATEWAY_URL")]
    object_write_gateway_url: Option<String>,
    /// PEM roots that issue this deployment's ObjectWrite Gateway server
    /// certificate. The artifact is installed with the Route v2 revision.
    #[arg(
        long,
        env = "CATS_OBJECT_WRITE_GATEWAY_CA_FILE",
        default_value = cats_api::route_grant_v2::NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH
    )]
    object_write_gateway_ca_file: PathBuf,
    #[arg(
        long,
        env = "CATS_GATEWAY_CLIENT_CA_BUNDLE_FILE",
        default_value = cats_api::gateway_workload_identity::GATEWAY_CLIENT_CA_BUNDLE_PATH
    )]
    gateway_client_ca_bundle_file: PathBuf,
    #[arg(
        long,
        env = "CATS_NODE_ROUTE_V2_SERVER_CERTIFICATE_FILE",
        default_value = cats_api::route_grant_v2::NODE_ROUTE_V2_SERVER_CERTIFICATE_PATH
    )]
    node_route_v2_server_certificate_file: PathBuf,
    #[arg(
        long,
        env = "CATS_NODE_ROUTE_V2_SERVER_PRIVATE_KEY_FILE",
        default_value = cats_api::route_grant_v2::NODE_ROUTE_V2_SERVER_PRIVATE_KEY_PATH
    )]
    node_route_v2_server_private_key_file: PathBuf,
    #[arg(
        long,
        env = "CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE",
        value_name = "PATH"
    )]
    guest_runtime_profile_receipt_file: Option<PathBuf>,
    #[arg(long)]
    blockd_bin: PathBuf,
    /// Installed `systemctl` used for exact Cat-slice discovery and Stop.
    #[arg(
        long,
        env = "CATS_RUNTIME_SYSTEMCTL_BIN",
        default_value = "/usr/bin/systemctl"
    )]
    runtime_systemctl_bin: PathBuf,
    /// Installed `systemd-run` used to create command-scoped child services.
    #[arg(
        long,
        env = "CATS_RUNTIME_SYSTEMD_RUN_BIN",
        default_value = "/usr/bin/systemd-run"
    )]
    runtime_systemd_run_bin: PathBuf,
    /// Root of the unified cgroup-v2 namespace inspected by the lifecycle
    /// runner. Test deployments may provide an isolated fixture root.
    #[arg(long, env = "CATS_CGROUP_ROOT", default_value = "/sys/fs/cgroup")]
    runtime_cgroup_root: PathBuf,
    #[arg(long, env = "CATS_RUNTIME_PROC_ROOT", default_value = "/proc")]
    runtime_proc_root: PathBuf,
    #[arg(
        long,
        env = "CATS_RUNTIME_NETWORK_CLASS_ROOT",
        default_value = "/sys/class/net"
    )]
    runtime_network_class_root: PathBuf,
    #[arg(
        long,
        env = "CATS_RUNTIME_SYS_BLOCK_ROOT",
        default_value = "/sys/block"
    )]
    runtime_sys_block_root: PathBuf,
    #[arg(long, env = "CATS_RUNTIME_DEVICE_ROOT", default_value = "/dev")]
    runtime_device_root: PathBuf,
    #[arg(
        long,
        env = "CATS_RUNTIME_BLOCKD_SOCKET_ROOT",
        default_value = "/run/cats/blockd-v1"
    )]
    runtime_blockd_socket_root: PathBuf,
    #[arg(
        long,
        env = "CATS_RUNTIME_VMM_SOCKET_ROOT",
        default_value = "/run/cats/vmm-v1"
    )]
    runtime_vmm_socket_root: PathBuf,
    #[arg(long)]
    metadata_store_adapter: String,
    #[arg(long = "metadata-store-option", value_name = "KEY=VALUE")]
    metadata_store_options: Vec<String>,
    #[arg(long)]
    object_store_adapter: String,
    #[arg(long = "object-store-option", value_name = "KEY=VALUE")]
    object_store_options: Vec<String>,
    /// Initial A22 NormalAcquire lease. This must cover the checkpoint and
    /// fresh-scan bridge to the root-provision process; serving blockd renews
    /// the exact epoch independently afterwards.
    #[arg(
        long,
        env = "CATS_RUNTIME_VOLUME_LEASE_DURATION_MS",
        default_value_t = 60_000
    )]
    runtime_volume_lease_duration_ms: u64,
    #[arg(long, default_value_t = 1500)]
    blockd_lease_ttl_ms: i64,
    /// Per-volume remotely unpublished local journal limit.
    #[arg(long, env = "CATS_BLOCKD_MAX_STAGED_BYTES",
          default_value_t = cats_api::blockd::DEFAULT_MAX_STAGED_BYTES)]
    blockd_max_staged_bytes: u64,
    /// Per-volume tiny-generation count limit.
    #[arg(long, env = "CATS_BLOCKD_MAX_STAGED_PACKS",
          default_value_t = cats_api::blockd::DEFAULT_MAX_STAGED_PACKS)]
    blockd_max_staged_packs: usize,
    /// Per-volume physical cache + journal footprint limit.
    #[arg(long, env = "CATS_BLOCKD_MAX_LOCAL_BYTES",
          default_value_t = cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES)]
    blockd_max_local_bytes: u64,
    /// Local budget for one complete signed Runtime inventory scan. This is an
    /// operator safety limit, not a protocol or product latency SLA.
    #[arg(
        long,
        env = "CATS_RUNTIME_INVENTORY_SCAN_TIMEOUT_MS",
        default_value_t = 5_000
    )]
    runtime_inventory_scan_timeout_ms: u64,
    /// Local budget for one durable signed Runtime physical step. It is
    /// intentionally independent from the inventory scan budget.
    #[arg(
        long,
        env = "CATS_RUNTIME_EFFECT_STEP_TIMEOUT_MS",
        default_value_t = 30_000
    )]
    runtime_effect_step_timeout_ms: u64,

    /// VMM mode: fake (host processes) or ch (Cloud Hypervisor, Linux+KVM).
    #[arg(long, default_value = "ch")]
    vmm: String,
    #[arg(long, default_value = "/opt/cats/bin/cats-vmm-launcher")]
    vmm_launcher_bin: PathBuf,
    #[arg(long, default_value = "/usr/local/bin/cloud-hypervisor")]
    ch_bin: PathBuf,
    /// Raw golden-root image written into fresh root volumes.
    #[arg(long)]
    ch_seed_image: Option<PathBuf>,
    /// Guest block data path: `kernel-nbd` (Phase A) or `vhost-user` (native
    /// virtio-blk straight into cats-blockd).
    #[arg(long, default_value = "kernel-nbd")]
    ch_block_path: String,
    /// Open the kernel-NBD device with O_DIRECT, so the host page cache stops
    /// acking Guest writes the engine has not seen yet. Off matches Cloud
    /// Hypervisor's default and is what the fleet runs today; on is what a
    /// like-for-like comparison against vhost-user requires (ADR-0015).
    #[arg(long, default_value_t = false)]
    ch_block_direct: bool,
    /// virtio-blk queues per disk on the vhost-user path.
    #[arg(long, default_value_t = 1)]
    ch_vhost_user_queues: usize,
    /// Depth of each virtio-blk queue on the vhost-user path.
    #[arg(long, default_value_t = 256)]
    ch_vhost_user_queue_size: u16,
    #[arg(long, default_value = "/usr/sbin/nbd-client")]
    ch_nbd_client: PathBuf,
    #[arg(long, default_value_t = 64)]
    ch_nbd_devices: u32,
    #[arg(long, default_value = "/usr/sbin/ip")]
    ch_ip_bin: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let receipt_path = args
        .guest_runtime_profile_receipt_file
        .as_deref()
        .context("--guest-runtime-profile-receipt-file or CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE is required")?;
    let installed_receipt =
        cats_api::runtime_artifacts::load_installed_guest_runtime_profile_receipt(receipt_path)?;
    cats_api::runtime_artifacts::validate_installed_node_guest_runtime(&installed_receipt)?;
    let ch_config = installed_ch_config(&args, &installed_receipt)?;
    anyhow::ensure!(
        args.metadata_store_adapter == cats_metadata_store_postgres::ADAPTER_NAME,
        "the signed production Runtime supports only --metadata-store-adapter {}",
        cats_metadata_store_postgres::ADAPTER_NAME,
    );
    let metadata_config =
        AdapterConfig::from_cli(args.metadata_store_options).context("metadata adapter options")?;
    let object_config =
        AdapterConfig::from_cli(args.object_store_options).context("object adapter options")?;
    let metadata_store =
        AdapterSelection::new(args.metadata_store_adapter.clone(), metadata_config.clone());
    let object_store =
        AdapterSelection::new(args.object_store_adapter.clone(), object_config.clone());
    let object_factories: [&dyn BlobStoreFactory; 2] =
        [&FileBlobStoreFactory, &AwsS3BlobStoreFactory];
    let root_image_store = open_blob_store(
        &args.object_store_adapter,
        &object_config,
        &object_factories,
    )
    .context("open signed Runtime object store")?;
    let volume_authority =
        cats_metadata_store_postgres::PostgresVolumeDataAuthority::open_runtime(&metadata_config)
            .context("open PostgreSQL Runtime Volume authorities")?;
    let volume_inventory_authority: Arc<
        dyn cats_storage::authority::RuntimeVolumeInventoryAuthority,
    > = volume_authority;
    let agent_registration =
        cats_node_agent::agent_registration::AgentRegistrationConfig::load_installed(
            installed_receipt.receipt(),
        )?;
    let route_v2_artifacts =
        cats_api::runtime_artifacts::load_installed_node_route_v2_machine_artifacts(
            &args.route_v2_public_key_ring_file,
            &args.gateway_client_ca_bundle_file,
            &args.node_route_v2_server_certificate_file,
            &args.node_route_v2_server_private_key_file,
        )
        .context("load mandatory installed Route v2 machine artifacts")?;
    let route_v2_machine = RouteV2MachineConfig::from_installed_artifacts(
        args.route_v2_machine_listen,
        agent_registration.identity().node_id.clone(),
        &route_v2_artifacts,
        &args.route_v2_rotation_origin,
    )
    .context("compose mandatory Route v2 listener and ring delivery")?;
    let inventory_timeout = Duration::from_millis(args.runtime_inventory_scan_timeout_ms);
    let effect_timeout = Duration::from_millis(args.runtime_effect_step_timeout_ms);
    anyhow::ensure!(
        !inventory_timeout.is_zero() && !effect_timeout.is_zero(),
        "Runtime inventory/effect timeouts must be positive"
    );

    // These three values are created once and shared by lifecycle startup,
    // installed effects, Route, and the observation-only inventory lane. A
    // second scanner, registry, or force-Full sender would create a competing
    // view of the same Cat.
    let lifecycle_admission_registry =
        cats_node_agent::admission_registry::LifecycleAdmissionRegistry::new_uninitialized();
    let startup_inventory_cache = StartupInventoryCache::new();
    let runtime_inventory_force_full = RuntimeInventoryForceFullCoordinator::new();
    let state_directory = agent_registration.runtime_state_directory();

    let kernel_nbd = match ch_config.block_path {
        BlockPath::KernelNbd => Some(InstalledLifecycleKernelNbdConfig {
            sys_block_root: args.runtime_sys_block_root,
            device_root: args.runtime_device_root,
            nbd_client_binary: ch_config.nbd_client_bin.clone(),
            device_count: ch_config.nbd_devices,
        }),
        BlockPath::VhostUser => None,
    };
    let managed_process_binaries = BTreeSet::from([
        args.blockd_bin.clone(),
        ch_config.vmm_launcher_bin.clone(),
        ch_config.ch_bin.clone(),
    ]);
    let physical = InstalledPhysicalInspectionConfig {
        state_directory: state_directory.clone(),
        node_id: agent_registration.identity().node_id.clone(),
        volume_inventory_authority: Arc::clone(&volume_inventory_authority),
        systemctl_binary: args.runtime_systemctl_bin,
        cgroup_root: args.runtime_cgroup_root,
        proc_root: args.runtime_proc_root,
        ip_binary: ch_config.ip_bin.clone(),
        network_class_root: args.runtime_network_class_root,
        managed_socket_roots: vec![
            args.runtime_blockd_socket_root,
            args.runtime_vmm_socket_root,
        ],
        managed_process_binaries,
        kernel_nbd,
        inventory_timeout,
        physical_probe_timeout: effect_timeout,
    };
    let lifecycle_volume_control = Arc::new(
        LifecycleVolumeHttpClient::for_production(&args.control_plane_url, &agent_registration)
            .context("open signed lifecycle Volume client")?,
    );
    let start_volume_port = InstalledAtomicStartVolumePort::new(
        state_directory.clone(),
        Arc::clone(&volume_inventory_authority),
        Arc::clone(&lifecycle_volume_control),
        Arc::clone(&lifecycle_admission_registry),
        Duration::from_millis(args.runtime_volume_lease_duration_ms),
        effect_timeout,
    )
    .context("compose installed atomic Start Volume port")?;

    // Gateway mode derives the current writer-authority ID and credential key
    // from this exact retained Agent registration. Direct-provider mode is
    // accepted only when the installed Start adapter validates that the
    // configured backend needs no Gateway credential.
    let object_write_mode = match args.object_write_gateway_url {
        Some(gateway_origin) => InstalledAtomicStartObjectWriteMode::Gateway {
            gateway_origin,
            server_ca_bundle_file: args.object_write_gateway_ca_file.clone(),
            control_plane_origin: args.control_plane_url.clone(),
            registration: Arc::new(agent_registration.clone()),
        },
        None => InstalledAtomicStartObjectWriteMode::DirectProvider,
    };
    let suspend_warm_platform = InstalledSuspendWarmPlatform::for_production(physical.clone())
        .context("compose installed Suspend/Warm platform")?;
    let start_runtime_port =
        installed_atomic_start_runtime_port(InstalledAtomicStartRuntimeConfig {
            physical: physical.clone(),
            admission_registry: Arc::clone(&lifecycle_admission_registry),
            suspend_warm_platform: suspend_warm_platform.clone(),
            ch: ch_config,
            systemd_run_binary: args.runtime_systemd_run_bin,
            blockd: InstalledAtomicStartBlockdConfig {
                blockd_binary: args.blockd_bin,
                metadata_store,
                object_store,
                lease_ttl_ms: args.blockd_lease_ttl_ms,
                max_staged_bytes: args.blockd_max_staged_bytes,
                max_staged_packs: args.blockd_max_staged_packs,
                max_local_bytes: args.blockd_max_local_bytes,
            },
            root_image_store,
            object_write_mode,
            persistent_initialization_control: Arc::clone(&lifecycle_volume_control),
            effect_timeout,
            guest_ready_timeout: effect_timeout,
        })
        .context("compose installed atomic Start runtime port")?;
    let cold_delete_local =
        InstalledColdDeleteLocalPort::new(state_directory, Arc::clone(&volume_inventory_authority));
    let cold_delete_port = InstalledAtomicColdDeletePort::new(
        cold_delete_local,
        Arc::clone(&lifecycle_volume_control),
        Arc::clone(&lifecycle_admission_registry),
        effect_timeout,
    )
    .context("compose installed Cold/Delete port")?;
    let installed = installed_atomic_lifecycle_executor(InstalledAtomicLifecycleConfig {
        physical,
        admission_registry: Arc::clone(&lifecycle_admission_registry),
        startup_inventory_cache: Arc::clone(&startup_inventory_cache),
        start_volume_port,
        start_runtime_port,
        suspend_warm_platform,
        cold_delete_port,
        runtime_inventory_force_full: Arc::clone(&runtime_inventory_force_full),
    })
    .context("compose installed atomic lifecycle executor")?;
    let runtime_inventory_source = ProductionRuntimeInventorySource::new(
        Arc::clone(&installed.startup_inventory_cache),
        Arc::clone(&installed.inventory_collection),
    );
    let handle = spawn_signed_runtime_cutover(SignedRuntimeCutoverConfig {
        listen: args.listen,
        route_v2_machine,
        control_plane_url: args.control_plane_url,
        agent_registration,
        lifecycle_executor: installed.executor,
        lifecycle_admission_registry: installed.admission_registry,
        startup_inventory_cache: installed.startup_inventory_cache,
        runtime_inventory_source,
        runtime_inventory_force_full: installed.runtime_inventory_force_full,
    })
    .await?;
    eprintln!(
        "signed Runtime listener {} and authenticated Route v2 listener {} are bound; readiness stays closed until complete inventory is attested",
        handle.addr, handle.route_v2_addr
    );
    handle.run_until_signal().await
}

fn installed_ch_config(
    args: &Args,
    installed: &cats_api::runtime_artifacts::InstalledGuestRuntimeProfileReceipt,
) -> anyhow::Result<ChConfig> {
    anyhow::ensure!(
        args.vmm == "ch",
        "the signed production Runtime supports only --vmm ch"
    );
    anyhow::ensure!(
        args.vmm_launcher_bin.is_absolute(),
        "--vmm-launcher-bin must be an absolute installed path"
    );
    let boot_contract = installed.boot_contract();
    let initramfs = boot_contract
        .initramfs()
        .map(|_| cats_api::runtime_artifacts::GUEST_INITRAMFS_PATH.into());
    Ok(ChConfig {
        block_direct: args.ch_block_direct,
        vmm_launcher_bin: args.vmm_launcher_bin.clone(),
        ch_bin: args.ch_bin.clone(),
        kernel: cats_api::runtime_artifacts::GUEST_KERNEL_PATH.into(),
        initramfs,
        boot_contract: Some(boot_contract),
        cmdline: installed.receipt().kernel_cmdline.as_str().to_owned(),
        seed_image: args.ch_seed_image.clone(),
        block_path: BlockPath::parse(&args.ch_block_path)?,
        vhost_user_queues: args.ch_vhost_user_queues,
        vhost_user_queue_size: args.ch_vhost_user_queue_size,
        nbd_client_bin: args.ch_nbd_client.clone(),
        nbd_devices: args.ch_nbd_devices,
        ip_bin: args.ch_ip_bin.clone(),
    })
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn production_cli_has_no_identity_or_guest_byte_overrides() {
        let command = super::Args::command();
        let ids = command
            .get_arguments()
            .map(|argument| argument.get_id().as_str())
            .collect::<Vec<_>>();
        for forbidden in [
            "node_id",
            "state_dir",
            "ch_kernel",
            "ch_initramfs",
            "ch_cmdline",
            "ch_network_cidr",
            "route_grant_public_key_file",
            "guest_agent_bin",
            "metering_cgroup_root",
            "wake_commitment_budget_bytes",
            "max_concurrent_wakes",
            "wake_queue_timeout_secs",
        ] {
            assert!(
                !ids.contains(&forbidden),
                "forbidden production override {forbidden}"
            );
        }
        assert!(ids.contains(&"guest_runtime_profile_receipt_file"));
        assert!(ids.contains(&"runtime_volume_lease_duration_ms"));
        assert!(!ids.contains(&"auth_token"));
        for required in ["route_v2_machine_listen", "route_v2_rotation_origin"] {
            let argument = command
                .get_arguments()
                .find(|argument| argument.get_id().as_str() == required)
                .expect("mandatory Route v2 argument exists");
            assert!(
                argument.is_required_set(),
                "production Route v2 argument {required} must be mandatory"
            );
        }
    }

    #[test]
    fn production_entrypoint_cannot_start_the_legacy_node_runtime() {
        let source = include_str!("main.rs");
        assert!(source.contains("spawn_signed_runtime_cutover"));
        assert!(source.contains("PostgresVolumeDataAuthority::open_runtime"));
        assert!(source.contains("open_blob_store"));
        assert!(source.contains("installed_atomic_lifecycle_executor"));
        assert!(source.contains("installed_atomic_start_runtime_port"));
        assert!(source.contains("ProductionRuntimeInventorySource::new"));
        assert!(source.contains("load mandatory installed Route v2 machine artifacts"));
        assert!(source.contains("compose mandatory Route v2 listener and ring delivery"));
        let route_artifacts = source
            .find("load_installed_node_route_v2_machine_artifacts")
            .expect("mandatory Route v2 artifacts are loaded");
        let daemon_spawn = source
            .find("spawn_signed_runtime_cutover(SignedRuntimeCutoverConfig")
            .expect("atomic daemon is spawned");
        assert!(
            route_artifacts < daemon_spawn,
            "Route v2 artifacts must fail closed before lifecycle/inventory startup"
        );
        let optional_route_fallback = ["(None, ", "None) => None"].concat();
        assert!(!source.contains(&optional_route_fallback));
        let legacy_spawn = ["server", "::{", "spawn"].concat();
        let legacy_runtime = ["Node", "Runtime", "::", "new"].concat();
        let legacy_spine = ["Runtime", "Spine", "Deadline", "Policy"].concat();
        let legacy_blockd = ["Authorized", "Blockd", "Launch", "Config"].concat();
        assert!(!source.contains(&legacy_spawn));
        assert!(!source.contains(&legacy_runtime));
        assert!(!source.contains(&legacy_spine));
        assert!(!source.contains(&legacy_blockd));
    }
}

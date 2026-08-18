use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cats_node_agent::ch::{BlockPath, ChConfig};
use cats_node_agent::route_v2_machine::RouteV2MachineConfig;
use cats_node_agent::runtime::reconciliation::AuthorizedBlockdLaunchConfig;
use cats_node_agent::runtime_cutover::{spawn_signed_runtime_cutover, SignedRuntimeCutoverConfig};
use cats_node_agent::runtime_spine::RuntimeSpineDeadlinePolicy;
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
    /// Independent TLS listener for authenticated Gateway Route v2 tunnels.
    /// Absence keeps this ingress closed and does not read its fixed artifacts.
    #[arg(long, env = "CATS_ROUTE_V2_MACHINE_LISTEN")]
    route_v2_machine_listen: Option<String>,
    /// Server-authenticated HTTPS origin for adjacent Route v2 ring delivery.
    /// It is mandatory with the machine listener and is independent from the
    /// public management Control origin.
    #[arg(long, env = "CATS_ROUTE_V2_ROTATION_ORIGIN")]
    route_v2_rotation_origin: Option<String>,
    /// Bare HTTPS origin of the ObjectWrite Gateway. A production worker is
    /// denied direct object-store writes by IAM, so this is the only path by
    /// which a serving process can publish; it is independent from the public
    /// management Control origin.
    #[arg(long, env = "CATS_OBJECT_WRITE_GATEWAY_URL")]
    object_write_gateway_url: Option<String>,
    /// The Control-side ObjectWriteAuthority this Host's attachment credentials
    /// are registered under. Control refuses a registration naming any other
    /// authority and the Node cannot derive it, so it is configured with the
    /// gateway origin and the two are required together.
    #[arg(long, env = "CATS_OBJECT_WRITE_WRITER_AUTHORITY_ID")]
    object_write_writer_authority_id: Option<String>,
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
    #[arg(long)]
    guest_agent_bin: PathBuf,
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
    /// Delegated cgroup v2 subtree for authoritative billing counters.
    #[arg(long, env = "CATS_METERING_CGROUP_ROOT")]
    metering_cgroup_root: Option<PathBuf>,

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

    /// Concurrent-wake commitment budget in bytes (ADR-0002 §8). Accounted in
    /// bytes because the 2026-07-21 run showed Guest memory page read-back is
    /// the limit, not the VMM. Default is the validated operating point
    /// (10 x 512 MiB), not a proven optimum: re-measure before raising it.
    #[arg(long, env = "CATS_WAKE_COMMITMENT_BUDGET_BYTES",
          default_value_t = cats_node_agent::admission::DEFAULT_WAKE_COMMITMENT_BUDGET_BYTES)]
    wake_commitment_budget_bytes: u64,
    /// Ceiling on concurrently admitted wakes, so many tiny Cats cannot
    /// bypass the byte budget. Default is the validated concurrency.
    #[arg(long, env = "CATS_MAX_CONCURRENT_WAKES",
          default_value_t = cats_node_agent::admission::DEFAULT_MAX_CONCURRENT_WAKES)]
    max_concurrent_wakes: usize,
    /// How long a wake may queue for budget before the node reports it cannot
    /// serve the wake. Above the slowest measured concurrent restore (EBS
    /// first-health P50 19.05 s) so a slow medium queues instead of falling
    /// back to Cold.
    #[arg(long, env = "CATS_WAKE_QUEUE_TIMEOUT_SECS", default_value_t = 60)]
    wake_queue_timeout_secs: u64,

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
    let authorized_blockd_launch = AuthorizedBlockdLaunchConfig {
        blockd_binary: args.blockd_bin.clone(),
        metadata_store: AdapterSelection::new(
            args.metadata_store_adapter.clone(),
            metadata_config.clone(),
        ),
        object_store: AdapterSelection::new(
            args.object_store_adapter.clone(),
            object_config.clone(),
        ),
        max_staged_bytes: args.blockd_max_staged_bytes,
        max_staged_packs: args.blockd_max_staged_packs,
        max_local_bytes: args.blockd_max_local_bytes,
        // Filled in by the cutover composition, which owns the credential
        // namespace path and the validated gateway origin.
        object_write_gateway: None,
    };
    let object_factories: [&dyn BlobStoreFactory; 2] =
        [&FileBlobStoreFactory, &AwsS3BlobStoreFactory];
    let blob_store = open_blob_store(
        &args.object_store_adapter,
        &object_config,
        &object_factories,
    )
    .context("open signed Runtime object store")?;
    let volume_authority =
        cats_metadata_store_postgres::PostgresVolumeDataAuthority::open_runtime(&metadata_config)
            .context("open PostgreSQL Runtime Volume authorities")?;
    let volume_data_authority: Arc<dyn cats_storage::authority::VolumeDataAuthority> =
        volume_authority.clone();
    let volume_inventory_authority: Arc<
        dyn cats_storage::authority::RuntimeVolumeInventoryAuthority,
    > = volume_authority;
    let agent_registration =
        cats_node_agent::agent_registration::AgentRegistrationConfig::load_installed(
            installed_receipt.receipt(),
        )?;
    let route_v2_machine = match (
        args.route_v2_machine_listen,
        args.route_v2_rotation_origin.as_deref(),
    ) {
        (Some(listen), Some(rotation_origin)) => {
            let artifacts =
                cats_api::runtime_artifacts::load_installed_node_route_v2_machine_artifacts(
                    &args.route_v2_public_key_ring_file,
                    &args.gateway_client_ca_bundle_file,
                    &args.node_route_v2_server_certificate_file,
                    &args.node_route_v2_server_private_key_file,
                )?;
            Some(RouteV2MachineConfig::from_installed_artifacts(
                listen,
                agent_registration.identity().node_id.clone(),
                &artifacts,
                rotation_origin,
            )?)
        }
        (None, None) => None,
        _ => anyhow::bail!(
            "--route-v2-machine-listen and --route-v2-rotation-origin must be configured together"
        ),
    };
    let object_write_gateway = match (
        args.object_write_gateway_url,
        args.object_write_writer_authority_id,
    ) {
        (Some(gateway_url), Some(writer_authority_id)) => {
            Some(cats_node_agent::runtime_cutover::ObjectWriteGatewayComposition {
                gateway_url,
                writer_authority_id: cats_api::runtime_reconciliation::Id::new(
                    &writer_authority_id,
                )
                .context("--object-write-writer-authority-id is not a canonical Id")?,
            })
        }
        (None, None) => None,
        _ => anyhow::bail!(
            "--object-write-gateway-url and --object-write-writer-authority-id must be configured together"
        ),
    };
    let deadline_policy = RuntimeSpineDeadlinePolicy::new(
        Duration::from_millis(args.runtime_inventory_scan_timeout_ms),
        Duration::from_millis(args.runtime_effect_step_timeout_ms),
    )
    .context("validate signed Runtime scan/effect deadline policy")?;
    let metering_cgroup_root = args
        .metering_cgroup_root
        .context("--metering-cgroup-root or CATS_METERING_CGROUP_ROOT is required")?;
    let handle = spawn_signed_runtime_cutover(SignedRuntimeCutoverConfig {
        listen: args.listen,
        route_v2_machine,
        control_plane_url: args.control_plane_url,
        agent_registration,
        ch_config,
        authorized_blockd_launch,
        guest_agent_binary: args.guest_agent_bin,
        metering_cgroup_root: Some(metering_cgroup_root),
        volume_data_authority,
        volume_inventory_authority,
        blob_store,
        volume_lease_duration_ms: args.runtime_volume_lease_duration_ms,
        deadline_policy,
        object_write_gateway,
    })
    .await?;
    match handle.route_v2_addr {
        Some(route_v2_addr) => eprintln!(
            "signed Runtime listener {} and authenticated Route v2 listener {} are bound; readiness stays closed until complete inventory is attested",
            handle.addr, route_v2_addr
        ),
        None => eprintln!(
            "signed Runtime listener {} is bound; Route v2 machine ingress is closed; readiness stays closed until complete inventory is attested",
            handle.addr
        ),
    }
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
        ] {
            assert!(
                !ids.contains(&forbidden),
                "forbidden production override {forbidden}"
            );
        }
        assert!(ids.contains(&"guest_runtime_profile_receipt_file"));
        assert!(ids.contains(&"runtime_volume_lease_duration_ms"));
        assert!(!ids.contains(&"auth_token"));
    }

    #[test]
    fn production_entrypoint_cannot_start_the_legacy_node_runtime() {
        let source = include_str!("main.rs");
        assert!(source.contains("spawn_signed_runtime_cutover"));
        assert!(source.contains("PostgresVolumeDataAuthority::open_runtime"));
        assert!(source.contains("open_blob_store"));
        let legacy_spawn = ["server", "::{", "spawn"].concat();
        let legacy_runtime = ["Node", "Runtime", "::", "new"].concat();
        assert!(!source.contains(&legacy_spawn));
        assert!(!source.contains(&legacy_runtime));
    }
}

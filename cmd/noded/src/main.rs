use std::path::PathBuf;

use anyhow::Context;
use cats_node_agent::runtime_cutover::{spawn_signed_runtime_cutover, SignedRuntimeCutoverConfig};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-noded", about = "Cats node agent")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    #[arg(long)]
    control_plane_url: String,
    /// Ed25519 public key used to verify control-plane signed Route Grants.
    #[arg(long, env = "CATS_ROUTE_GRANT_PUBLIC_KEY_FILE")]
    route_grant_public_key_file: PathBuf,
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
    #[arg(long, default_value = "fake")]
    vmm: String,
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
    let agent_registration =
        cats_node_agent::agent_registration::AgentRegistrationConfig::load_installed(
            installed_receipt.receipt(),
        )?;
    let handle = spawn_signed_runtime_cutover(SignedRuntimeCutoverConfig {
        listen: args.listen,
        control_plane_url: args.control_plane_url,
        agent_registration,
        cloud_hypervisor_binary: args.ch_bin,
        blockd_binary: args.blockd_bin,
        guest_agent_binary: args.guest_agent_bin,
        metering_cgroup_root: args.metering_cgroup_root,
    })
    .await?;
    eprintln!(
        "signed Runtime listener {} is bound; readiness stays closed until complete inventory is attested",
        handle.addr
    );
    handle.run_until_signal().await
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
        ] {
            assert!(
                !ids.contains(&forbidden),
                "forbidden production override {forbidden}"
            );
        }
        assert!(ids.contains(&"guest_runtime_profile_receipt_file"));
        assert!(!ids.contains(&"auth_token"));
    }

    #[test]
    fn production_entrypoint_cannot_start_the_legacy_node_runtime() {
        let source = include_str!("main.rs");
        assert!(source.contains("spawn_signed_runtime_cutover"));
        let legacy_spawn = ["server", "::{", "spawn"].concat();
        let legacy_runtime = ["Node", "Runtime", "::", "new"].concat();
        assert!(!source.contains(&legacy_spawn));
        assert!(!source.contains(&legacy_runtime));
    }
}

use std::path::PathBuf;

use clap::Parser;

use cats_node_agent::runtime::NodeConfig;
use cats_node_agent::server::{spawn, ServerConfig};

#[derive(Parser, Debug)]
#[command(name = "cats-noded", about = "Cats node agent")]
struct Args {
    #[arg(long)]
    node_id: String,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    #[arg(long)]
    control_plane_url: String,
    #[arg(long, env = "CATS_AUTH_TOKEN", default_value = "dev-token")]
    auth_token: String,
    #[arg(long, default_value = "")]
    gateway_url: String,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    blockd_bin: PathBuf,
    #[arg(long)]
    guest_agent_bin: PathBuf,
    #[arg(long)]
    meta_sqlite: PathBuf,
    /// File blobstore root. Exactly one of --blob-file-root / --blob-s3-* .
    #[arg(long)]
    blob_file_root: Option<PathBuf>,
    #[arg(long)]
    blob_s3_endpoint: Option<String>,
    #[arg(long)]
    blob_s3_bucket: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    blob_s3_region: String,
    #[arg(long, default_value = "")]
    blob_s3_prefix: String,
    #[arg(long, default_value_t = 16)]
    cpus: u32,
    #[arg(long, default_value_t = 32768)]
    memory_mib: u64,
    #[arg(long, default_value_t = 1000)]
    heartbeat_ms: u64,
    #[arg(long, default_value_t = 1500)]
    blockd_lease_ttl_ms: i64,

    /// VMM mode: fake (host processes) or ch (Cloud Hypervisor, Linux+KVM).
    #[arg(long, default_value = "fake")]
    vmm: String,
    #[arg(long, default_value = "/usr/local/bin/cloud-hypervisor")]
    ch_bin: PathBuf,
    #[arg(long, default_value = "/opt/cats/guest/vmlinux")]
    ch_kernel: PathBuf,
    #[arg(long)]
    ch_initramfs: Option<PathBuf>,
    #[arg(long, default_value = "console=ttyS0 root=/dev/vda rw quiet")]
    ch_cmdline: String,
    /// Raw golden-root image written into fresh root volumes.
    #[arg(long)]
    ch_seed_image: Option<PathBuf>,
    #[arg(long, default_value = "/usr/sbin/nbd-client")]
    ch_nbd_client: PathBuf,
    #[arg(long, default_value_t = 64)]
    ch_nbd_devices: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let blob = match (&args.blob_file_root, &args.blob_s3_endpoint) {
        (Some(root), None) => cats_node_agent::runtime::BlobBackend::File { root: root.clone() },
        (None, Some(endpoint)) => cats_node_agent::runtime::BlobBackend::S3 {
            endpoint: endpoint.clone(),
            bucket: args.blob_s3_bucket.clone().ok_or_else(|| {
                anyhow::anyhow!("--blob-s3-bucket is required with --blob-s3-endpoint")
            })?,
            region: args.blob_s3_region.clone(),
            prefix: args.blob_s3_prefix.clone(),
        },
        _ => anyhow::bail!("exactly one of --blob-file-root or --blob-s3-endpoint must be given"),
    };
    let vmm = match args.vmm.as_str() {
        "fake" => cats_node_agent::runtime::VmmMode::Fake,
        "ch" => cats_node_agent::runtime::VmmMode::CloudHypervisor(cats_node_agent::ch::ChConfig {
            ch_bin: args.ch_bin.clone(),
            kernel: args.ch_kernel.clone(),
            initramfs: args.ch_initramfs.clone(),
            cmdline: args.ch_cmdline.clone(),
            seed_image: args.ch_seed_image.clone(),
            nbd_client_bin: args.ch_nbd_client.clone(),
            nbd_devices: args.ch_nbd_devices,
        }),
        other => anyhow::bail!("unknown --vmm {other} (expected fake|ch)"),
    };
    let handle = spawn(ServerConfig {
        listen: args.listen,
        control_plane_url: args.control_plane_url,
        auth_token: args.auth_token,
        gateway_url: args.gateway_url,
        cpus: args.cpus,
        memory_mib: args.memory_mib,
        heartbeat_ms: args.heartbeat_ms,
        node: NodeConfig {
            node_id: args.node_id,
            state_dir: args.state_dir,
            blockd_bin: args.blockd_bin,
            guest_agent_bin: args.guest_agent_bin,
            meta_sqlite: args.meta_sqlite,
            blob,
            blockd_lease_ttl_ms: args.blockd_lease_ttl_ms,
            vmm,
        },
    })
    .await?;
    println!("READY {}", handle.addr);
    std::future::pending::<()>().await;
    Ok(())
}

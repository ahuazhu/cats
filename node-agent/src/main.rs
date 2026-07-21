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
    #[arg(long)]
    blob_file_root: PathBuf,
    #[arg(long, default_value_t = 16)]
    cpus: u32,
    #[arg(long, default_value_t = 32768)]
    memory_mib: u64,
    #[arg(long, default_value_t = 1000)]
    heartbeat_ms: u64,
    #[arg(long, default_value_t = 1500)]
    blockd_lease_ttl_ms: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
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
            blob_file_root: args.blob_file_root,
            blockd_lease_ttl_ms: args.blockd_lease_ttl_ms,
        },
    })
    .await?;
    println!("READY {}", handle.addr);
    std::future::pending::<()>().await;
    Ok(())
}

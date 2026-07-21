use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-controld", about = "Cats control plane")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7300")]
    listen: String,
    #[arg(long, default_value = "cats-control.db")]
    db_path: PathBuf,
    #[arg(long, default_value = "cats-storage-meta.db")]
    storage_meta_path: PathBuf,
    #[arg(long, env = "CATS_AUTH_TOKEN", default_value = "dev-token")]
    auth_token: String,
    #[arg(long, default_value_t = 10_000)]
    node_lease_timeout_ms: i64,
    #[arg(long, default_value_t = 500)]
    reconcile_interval_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let handle = cats_control_plane::server::spawn(cats_control_plane::server::Config {
        listen: args.listen,
        db_path: args.db_path,
        storage_meta_path: args.storage_meta_path,
        auth_token: args.auth_token,
        node_lease_timeout_ms: args.node_lease_timeout_ms,
        reconcile_interval_ms: args.reconcile_interval_ms,
    })
    .await?;
    println!("READY {}", handle.addr);
    // Run until killed.
    std::future::pending::<()>().await;
    Ok(())
}

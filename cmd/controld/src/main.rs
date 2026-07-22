use cats_metadata_store_sqlite::SqliteMetadataStoreFactory;
use cats_storage::{open_metadata_store, AdapterConfig, MetadataStoreFactory};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-controld", about = "Cats control plane")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7300")]
    listen: String,
    #[arg(long, default_value = "cats-control.db")]
    db_path: std::path::PathBuf,
    #[arg(long, default_value = "sqlite")]
    metadata_store_adapter: String,
    #[arg(
        long = "metadata-store-option",
        value_name = "KEY=VALUE",
        default_value = "path=cats-storage-meta.db"
    )]
    metadata_store_options: Vec<String>,
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let metadata_config = AdapterConfig::from_cli(args.metadata_store_options)?;
    let metadata_factories: [&dyn MetadataStoreFactory; 1] = [&SqliteMetadataStoreFactory];
    let storage_meta = open_metadata_store(
        &args.metadata_store_adapter,
        &metadata_config,
        &metadata_factories,
    )?;
    let handle = cats_control_plane::server::spawn(cats_control_plane::server::Config {
        listen: args.listen,
        db_path: args.db_path,
        storage_meta,
        auth_token: args.auth_token,
        node_lease_timeout_ms: args.node_lease_timeout_ms,
        reconcile_interval_ms: args.reconcile_interval_ms,
    })
    .await?;
    println!("READY {}", handle.addr);
    std::future::pending::<()>().await;
    Ok(())
}

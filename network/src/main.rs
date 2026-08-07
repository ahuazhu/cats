use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-gatewayd", about = "Cats endpoint gateway")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7400")]
    listen: String,
    #[arg(long, default_value = "http://127.0.0.1:7300")]
    control_plane_url: String,
    #[arg(long, env = "CATS_AUTH_TOKEN", default_value = "dev-service-token")]
    auth_token: String,
    #[arg(long, default_value_t = 1000)]
    cache_ttl_ms: u64,
    #[arg(long, env = "CATS_SHARED_ROUTE_CACHE_TABLE")]
    shared_route_cache_table: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let handle = cats_network::spawn(cats_network::GatewayConfig {
        listen: args.listen,
        control_plane_url: args.control_plane_url,
        auth_token: args.auth_token,
        cache_ttl_ms: args.cache_ttl_ms,
        shared_route_cache_table: args.shared_route_cache_table,
    })
    .await?;
    println!("READY {}", handle.addr);
    std::future::pending::<()>().await;
    Ok(())
}

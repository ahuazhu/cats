use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use cats_api::route_grant_v2::{
    GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH, GATEWAY_ROUTE_V2_CLIENT_PRIVATE_KEY_PATH,
    NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH,
};
use cats_api::runtime_artifacts::load_installed_gateway_node_route_v2_machine_artifacts;
use cats_network::route_v2::{
    BoxedGatewayTunnel, ControlMachineTarget, ControlRouteResolver, GatewayIngress,
    GatewayIngressConfig, GatewayNodeRouteV2Client, RouteCache, RouteCacheConfig, TunnelConnector,
    TunnelFuture,
};
use clap::Parser;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(name = "cats-gatewayd", about = "Cats Route Grant v2 public Gateway")]
struct Args {
    #[arg(long, env = "CATS_GATEWAY_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// Strict HTTPS authority of the independent Control machine listener.
    #[arg(long, env = "CATS_ROUTE_V2_CONTROL_MACHINE_URL")]
    control_plane_url: String,
    #[arg(long, env = "CATS_GATEWAY_MAX_CONNECTIONS", default_value_t = 4_096)]
    max_connections: usize,
    #[arg(
        long,
        env = "CATS_GATEWAY_MAX_REQUEST_HEAD_BYTES",
        default_value_t = 32 * 1024
    )]
    max_request_head_bytes: usize,
    #[arg(
        long,
        env = "CATS_GATEWAY_REQUEST_HEAD_DEADLINE_MS",
        default_value_t = 5_000
    )]
    request_head_deadline_ms: u64,
    #[arg(
        long,
        env = "CATS_GATEWAY_PUBLIC_EGRESS_DEADLINE_MS",
        default_value_t = 5_000
    )]
    public_egress_deadline_ms: u64,
    #[arg(
        long,
        env = "CATS_GATEWAY_SHUTDOWN_DRAIN_DEADLINE_MS",
        default_value_t = 10_000
    )]
    shutdown_drain_deadline_ms: u64,
    #[arg(
        long,
        env = "CATS_GATEWAY_ROUTE_CACHE_MAX_ENTRIES",
        default_value_t = 1_024
    )]
    route_cache_max_entries: usize,
    #[arg(
        long,
        env = "CATS_GATEWAY_ROUTE_CACHE_MAX_BYTES",
        default_value_t = 8 * 1024 * 1024
    )]
    route_cache_max_bytes: usize,
    #[arg(
        long,
        env = "CATS_GATEWAY_ROUTE_RESOLVE_CONCURRENCY",
        default_value_t = 32
    )]
    route_resolve_concurrency: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize Gateway logging: {error}"))?;
    let args = Args::parse();
    let control_target = ControlMachineTarget::new(args.control_plane_url)
        .context("Control Route v2 machine URL must be a canonical HTTPS authority")?;

    // One pinned read supplies the exact same Gateway leaf/private key to the
    // Control and Node hops, closing the Grant's SPKI proof-of-possession
    // binding. The frozen set has only one machine-server CA bundle, so G2
    // must install a bundle that validates both Control and Node server chains.
    let artifacts = load_installed_gateway_node_route_v2_machine_artifacts(
        Path::new(NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH),
        Path::new(GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH),
        Path::new(GATEWAY_ROUTE_V2_CLIENT_PRIVATE_KEY_PATH),
    )
    .context("load fixed Gateway Route v2 machine artifacts")?;
    let resolver = ControlRouteResolver::from_installed_artifacts(control_target, &artifacts)
        .context("compose authenticated Control Route resolver")?
        .into_route_resolver();
    let node_client = GatewayNodeRouteV2Client::from_installed_artifacts(&artifacts)
        .context("compose authenticated Node Route tunnel client")?;
    let connector: TunnelConnector = Arc::new(move |route| {
        let client = node_client.clone();
        Box::pin(async move {
            client
                .open_tunnel(&route)
                .await
                .map(|tunnel| Box::new(tunnel) as BoxedGatewayTunnel)
        }) as TunnelFuture
    });

    let cache = RouteCache::new(
        RouteCacheConfig {
            max_entries: args.route_cache_max_entries,
            max_bytes: args.route_cache_max_bytes,
            max_concurrent_resolves: args.route_resolve_concurrency,
            ..RouteCacheConfig::default()
        },
        resolver,
    )
    .context("validate bounded Route cache")?;
    let ingress = GatewayIngress::new(
        GatewayIngressConfig {
            max_public_connections: args.max_connections,
            max_public_request_head_bytes: args.max_request_head_bytes,
            public_request_head_deadline: Duration::from_millis(args.request_head_deadline_ms),
            public_egress_deadline: Duration::from_millis(args.public_egress_deadline_ms),
            shutdown_drain_deadline: Duration::from_millis(args.shutdown_drain_deadline_ms),
        },
        cache,
        connector,
    )
    .context("validate public Gateway bounds")?;
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind public Gateway listener {}", args.listen))?;
    tracing::info!(listen = %args.listen, "cats-gatewayd ready");
    ingress
        .serve(listener, shutdown_signal())
        .await
        .context("serve public Gateway")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

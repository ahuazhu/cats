use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{AsciiText, Id, ProviderScope};
use cats_control_plane::object_write_gateway::{
    run_object_write_gateway, ObjectWriteGatewayConfig,
};
use cats_control_plane::store::{DsnSource, ObjectWriteGatewayClient};
use cats_host_fence_aws::{
    AwsObjectWriteConfig, AwsObjectWriteGatewayDownstream, VerifiedAwsProviderBinding,
};
use clap::Parser;

const AWS_BINDING_DEADLINE: Duration = Duration::from_secs(30);
const DEFAULT_CERTIFICATE_FILE: &str =
    "/run/cats/object-write-gateway/tls/object-write-server-certificate.pem";
const DEFAULT_PRIVATE_KEY_FILE: &str =
    "/run/cats/object-write-gateway/tls/object-write-server-private-key.pem";
const DEFAULT_SPOOL_ROOT: &str = "/var/lib/cats/object-write-spool";

#[derive(Debug, Parser)]
#[command(
    name = "cats-object-write-gatewayd",
    about = "Cats attachment-authenticated immutable object-write gateway"
)]
struct Args {
    #[arg(
        long,
        env = "CATS_OBJECT_WRITE_GATEWAY_LISTEN",
        default_value = "0.0.0.0:7443"
    )]
    listen: String,
    #[arg(long, env = "CATS_CONTROL_POSTGRES_URL_FILE")]
    control_store_url_file: PathBuf,
    #[arg(long, env = "CATS_CONTROL_POSTGRES_CA_FILE")]
    control_store_ca_file: PathBuf,
    #[arg(long, env = "CATS_CONTROL_POSTGRES_SCHEMA")]
    control_store_schema: String,
    #[arg(
        long,
        env = "CATS_OBJECT_WRITE_GATEWAY_SERVER_CERTIFICATE_FILE",
        default_value = DEFAULT_CERTIFICATE_FILE
    )]
    server_certificate_file: PathBuf,
    #[arg(
        long,
        env = "CATS_OBJECT_WRITE_GATEWAY_SERVER_PRIVATE_KEY_FILE",
        default_value = DEFAULT_PRIVATE_KEY_FILE
    )]
    server_private_key_file: PathBuf,
    #[arg(
        long,
        env = "CATS_OBJECT_WRITE_DURABLE_SPOOL_ROOT",
        default_value = DEFAULT_SPOOL_ROOT
    )]
    durable_spool_root: PathBuf,
    #[arg(long, env = "CATS_OBJECT_WRITE_PROVIDER")]
    provider: String,
    #[arg(long, env = "CATS_OBJECT_WRITE_PARTITION")]
    partition: String,
    #[arg(long, env = "CATS_OBJECT_WRITE_ACCOUNT_ID")]
    account_id: String,
    #[arg(long, env = "CATS_OBJECT_WRITE_REGION")]
    region: String,
    #[arg(long, env = "CATS_OBJECT_WRITE_BUCKET")]
    bucket: String,
    #[arg(long, env = "CATS_OBJECT_WRITE_PREFIX")]
    prefix: String,
    #[arg(long, env = "CATS_OBJECT_WRITE_OBJECT_STORE_SCOPE_ID")]
    object_store_scope_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let provider_scope = ProviderScope {
        provider: parse_id("provider", args.provider)?,
        partition: parse_id("partition", args.partition)?,
        account_id: parse_id("account ID", args.account_id)?,
        region: parse_id("region", args.region.clone())?,
    };
    anyhow::ensure!(
        provider_scope.provider.as_str() == "aws",
        "object-write production adapter requires provider=aws"
    );

    let ca_file = args
        .control_store_ca_file
        .to_str()
        .context("control-store CA path is not UTF-8")?
        .to_owned();
    let authority = ObjectWriteGatewayClient::connect_from_async(
        DsnSource::File(args.control_store_url_file),
        Some(ca_file),
        args.control_store_schema,
    )
    .await
    .context("connect dedicated object-write gateway PostgreSQL lane")?;
    let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(args.region))
        .load()
        .await;
    let binding = VerifiedAwsProviderBinding::establish(
        &sdk,
        &provider_scope,
        Instant::now() + AWS_BINDING_DEADLINE,
    )
    .await
    .map_err(|error| anyhow::anyhow!("verify AWS provider binding: {error:?}"))?;
    let object_store_scope_id =
        AsciiText::new(args.object_store_scope_id).context("object-store scope ID is invalid")?;
    let adapter_config = AwsObjectWriteConfig::new(
        provider_scope,
        args.bucket,
        args.prefix,
        object_store_scope_id,
        args.durable_spool_root.clone(),
    )
    .map_err(|error| anyhow::anyhow!("validate AWS object-write target: {error}"))?;
    let downstream = Arc::new(
        AwsObjectWriteGatewayDownstream::from_verified_binding(adapter_config, &binding)
            .map_err(|error| anyhow::anyhow!("construct AWS object-write adapter: {error}"))?,
    );
    let config = ObjectWriteGatewayConfig {
        listen: args.listen,
        server_certificate_file: args.server_certificate_file,
        server_private_key_file: args.server_private_key_file,
        durable_spool_root: args.durable_spool_root,
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
    Box::pin(run_object_write_gateway(
        config,
        authority,
        downstream,
        shutdown_rx,
    ))
    .await
}

fn parse_id(label: &str, value: String) -> anyhow::Result<Id> {
    Id::new(value).with_context(|| format!("object-write {label} is invalid"))
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use cats_metadata_store_postgres::PostgresMetadataStoreFactory;
use cats_metadata_store_sqlite::SqliteMetadataStoreFactory;
use cats_metering::{CreditStore, SqliteUsageStore, UsageStore};
use cats_storage::{open_metadata_store, AdapterConfig, MetadataStoreFactory};
use cats_usage_store_aws_stream::{AwsUsageStreamConfig, AwsUsageStreamStore};
use cats_usage_store_postgres::{DsnSource, PostgresUsageStore, DEFAULT_SCHEMA, DEFAULT_WORKERS};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-controld", about = "Cats control plane")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7300")]
    listen: String,
    /// Local SQLite file for the development-shape usage/credit ledger. The
    /// control resource store itself is PostgreSQL (`--control-store-url`).
    #[arg(long, default_value = "cats-control.db")]
    db_path: std::path::PathBuf,
    /// Control resource database. Falls back to CATS_POSTGRES_URL, the same
    /// DSN the storage metadata adapter uses: one database, disjoint tables.
    #[arg(long, env = "CATS_CONTROL_POSTGRES_URL")]
    control_store_url: Option<String>,
    /// CA bundle for the control database's TLS certificate (RDS).
    #[arg(long, env = "CATS_CONTROL_POSTGRES_CA_FILE")]
    control_store_ca_file: Option<std::path::PathBuf>,
    /// Usage ledger adapter. SQLite is for local development; production
    /// should use the independent PostgreSQL usage database/schema.
    #[arg(
        long,
        env = "CATS_USAGE_STORE_ADAPTER",
        default_value = "sqlite",
        value_parser = ["sqlite", "postgres"]
    )]
    usage_store_adapter: String,
    /// Durable delivery in front of the query projection. Production uses
    /// Kinesis; direct mode is retained for local development.
    #[arg(
        long,
        env = "CATS_USAGE_DELIVERY_ADAPTER",
        default_value = "direct",
        value_parser = ["direct", "aws-kinesis"]
    )]
    usage_delivery_adapter: String,
    #[arg(long, env = "CATS_USAGE_AWS_REGION", default_value = "us-east-1")]
    usage_aws_region: String,
    #[arg(long, env = "CATS_USAGE_KINESIS_STREAM")]
    usage_kinesis_stream: Option<String>,
    #[arg(long, env = "CATS_USAGE_ARCHIVE_BUCKET")]
    usage_archive_bucket: Option<String>,
    #[arg(long, env = "CATS_USAGE_CHECKPOINT_TABLE")]
    usage_checkpoint_table: Option<String>,
    /// SQLite usage path. Defaults to --db-path so the local dev shape stays
    /// single-file without coupling production usage storage to metadata.
    #[arg(long, env = "CATS_USAGE_SQLITE_PATH")]
    usage_sqlite_path: Option<std::path::PathBuf>,
    /// Environment variable containing the production usage PostgreSQL URL.
    #[arg(
        long,
        env = "CATS_USAGE_POSTGRES_URL_ENV",
        default_value = "CATS_USAGE_POSTGRES_URL"
    )]
    usage_postgres_url_env: String,
    /// File holding the usage PostgreSQL URL, re-read on every connect.
    ///
    /// Prefer this over `--usage-postgres-url-env` wherever the password is
    /// rotated: an environment variable is fixed for the life of the process,
    /// so a reconnect after a rotation presents a credential the server has
    /// already stopped accepting. Takes precedence when both are given.
    #[arg(long, env = "CATS_USAGE_POSTGRES_URL_FILE")]
    usage_postgres_url_file: Option<std::path::PathBuf>,
    #[arg(long, env = "CATS_USAGE_POSTGRES_CA_FILE")]
    usage_postgres_ca_file: Option<String>,
    #[arg(
        long,
        env = "CATS_USAGE_POSTGRES_SCHEMA",
        default_value = DEFAULT_SCHEMA
    )]
    usage_postgres_schema: String,
    #[arg(
        long,
        env = "CATS_USAGE_POSTGRES_WORKERS",
        default_value_t = DEFAULT_WORKERS
    )]
    usage_postgres_workers: usize,
    #[arg(long, default_value = "sqlite")]
    metadata_store_adapter: String,
    #[arg(
        long = "metadata-store-option",
        value_name = "KEY=VALUE",
        default_value = "path=cats-storage-meta.db"
    )]
    metadata_store_options: Vec<String>,
    #[arg(long, env = "CATS_AUTH_TOKEN", default_value = "dev-service-token")]
    auth_token: String,
    #[arg(long, env = "CATS_ADMIN_TOKEN", default_value = "dev-admin-token")]
    admin_token: String,
    /// WorkOS AuthKit application client ID. Setting any WorkOS option
    /// enables AuthKit and requires the complete configuration.
    #[arg(long, env = "WORKOS_CLIENT_ID")]
    workos_client_id: Option<String>,
    #[arg(long, env = "WORKOS_API_KEY")]
    workos_api_key: Option<String>,
    /// 64 hexadecimal characters (generate with `openssl rand -hex 32`).
    #[arg(long, env = "WORKOS_COOKIE_PASSWORD")]
    workos_cookie_password: Option<String>,
    #[arg(long, env = "WORKOS_REDIRECT_URI")]
    workos_redirect_uri: Option<String>,
    /// Exact `iss` claim published in this WorkOS application's access tokens.
    #[arg(long, env = "WORKOS_ISSUER")]
    workos_issuer: Option<String>,
    /// Bind a Cats Account to exactly one WorkOS Organization.
    #[arg(
        long = "workos-account-organization",
        env = "CATS_WORKOS_ACCOUNT_ORGANIZATIONS",
        value_delimiter = ',',
        value_name = "ACCOUNT=ORG_ID"
    )]
    workos_account_organizations: Vec<String>,
    #[arg(long, env = "CATS_WORKOS_ADMIN_ORGANIZATION_ID")]
    workos_admin_organization_id: Option<String>,
    #[arg(
        long,
        env = "CATS_WORKOS_ADMIN_PERMISSION",
        default_value = "cats:fleet:admin"
    )]
    workos_admin_permission: String,
    /// Override Secure on AuthKit cookies. Defaults to true for HTTPS redirects.
    #[arg(long, env = "CATS_WORKOS_COOKIE_SECURE")]
    workos_cookie_secure: Option<bool>,
    /// Parent domain for AuthKit cookies when consoles use subdomains.
    #[arg(long, env = "CATS_WORKOS_COOKIE_DOMAIN")]
    workos_cookie_domain: Option<String>,
    #[arg(long, env = "CATS_USER_SITE_URL")]
    user_site_url: Option<String>,
    #[arg(long, env = "CATS_ADMIN_SITE_URL")]
    admin_site_url: Option<String>,
    /// Stripe secret key. Setting any Stripe option enables hosted prepaid
    /// top-ups and requires a webhook secret plus at least one fixed Price.
    #[arg(long, env = "STRIPE_SECRET_KEY")]
    stripe_secret_key: Option<String>,
    #[arg(long, env = "STRIPE_WEBHOOK_SECRET")]
    stripe_webhook_secret: Option<String>,
    #[arg(
        long = "stripe-topup-price",
        env = "CATS_STRIPE_TOPUP_PRICES",
        value_delimiter = ',',
        value_name = "CENTS=PRICE_ID"
    )]
    stripe_topup_prices: Vec<String>,
    #[arg(long, env = "CATS_STRIPE_CHECKOUT_SUCCESS_URL")]
    stripe_checkout_success_url: Option<String>,
    #[arg(long, env = "CATS_STRIPE_CHECKOUT_CANCEL_URL")]
    stripe_checkout_cancel_url: Option<String>,
    #[arg(long, env = "CATS_STRIPE_LIVEMODE", default_value_t = true)]
    stripe_livemode: bool,
    #[arg(
        long,
        env = "CATS_BILLING_ENFORCEMENT_ENABLED",
        default_value_t = false
    )]
    billing_enforcement_enabled: bool,
    /// Override only for integration tests or an explicit Stripe proxy.
    #[arg(
        long,
        env = "CATS_STRIPE_API_BASE_URL",
        default_value = "https://api.stripe.com",
        hide = true
    )]
    stripe_api_base_url: String,
    /// Override only for integration tests or an explicit WorkOS proxy.
    #[arg(
        long,
        env = "WORKOS_API_BASE_URL",
        default_value = "https://api.workos.com",
        hide = true
    )]
    workos_api_base_url: String,
    #[arg(long, default_value_t = 10_000)]
    node_lease_timeout_ms: i64,
    #[arg(long, default_value_t = 500)]
    reconcile_interval_ms: u64,
    /// Seconds a stable Suspended Cat remains before automatic Warm.
    /// Zero disables this automatic boundary.
    #[arg(long, env = "CATS_AUTO_WARM_AFTER_SECONDS", default_value_t = 600)]
    auto_warm_after_seconds: u64,
    /// Seconds a stable Warm Cat remains before automatic Cold.
    /// Zero disables this automatic boundary.
    #[arg(long, env = "CATS_AUTO_COLD_AFTER_SECONDS", default_value_t = 86_400)]
    auto_cold_after_seconds: u64,
    /// Milliseconds an OCI deploy may hold its request open before answering
    /// `202` with an operation to poll. Must stay below the idle timeout of the
    /// proxy in front of Cats, or that proxy answers 504 first.
    #[arg(
        long,
        env = "CATS_OCI_DEPLOY_SYNC_WAIT_MS",
        default_value_t = cats_control_plane::server::DEFAULT_OCI_DEPLOY_SYNC_WAIT_MS
    )]
    oci_deploy_sync_wait_ms: u64,
}

fn threshold_ms(seconds: u64, name: &str) -> anyhow::Result<Option<i64>> {
    if seconds == 0 {
        return Ok(None);
    }
    let millis = seconds
        .checked_mul(1_000)
        .ok_or_else(|| anyhow::anyhow!("{name} threshold is too large"))?;
    Ok(Some(i64::try_from(millis).map_err(|_| {
        anyhow::anyhow!("{name} threshold is too large")
    })?))
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = terminate.recv() => {}
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
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
    let metadata_factories: [&dyn MetadataStoreFactory; 2] =
        [&SqliteMetadataStoreFactory, &PostgresMetadataStoreFactory];
    let storage_meta = open_metadata_store(
        &args.metadata_store_adapter,
        &metadata_config,
        &metadata_factories,
    )?;
    let (usage_projection, credit_store): (Arc<dyn UsageStore>, Arc<dyn CreditStore>) =
        match args.usage_store_adapter.as_str() {
            "sqlite" => {
                let store = Arc::new(SqliteUsageStore::open(
                    args.usage_sqlite_path
                        .as_deref()
                        .unwrap_or(args.db_path.as_path()),
                )?);
                (store.clone(), store)
            }
            "postgres" => {
                let dsn = match args.usage_postgres_url_file.as_deref() {
                    Some(path) => {
                        // The metadata adapter refuses this ambiguity outright.
                        // Here it cannot: --usage-postgres-url-env carries a
                        // clap default, so it is always "set". Say plainly
                        // which source won instead of ranking them in silence
                        // -- an operator mid-cutover has both in place, and
                        // which one holds the current password is the exact
                        // question that cost an outage.
                        if std::env::var_os(&args.usage_postgres_url_env).is_some() {
                            tracing::warn!(
                                file = %path.display(),
                                ignored_environment_variable = %args.usage_postgres_url_env,
                                "usage PostgreSQL DSN comes from the file; the environment \
                                 variable is set but not read"
                            );
                        }
                        DsnSource::File(path.to_path_buf())
                    }
                    None => DsnSource::Literal(
                        std::env::var(&args.usage_postgres_url_env).map_err(|_| {
                            anyhow::anyhow!(
                                "usage PostgreSQL URL environment variable {} is not set",
                                args.usage_postgres_url_env
                            )
                        })?,
                    ),
                };
                let store = Arc::new(PostgresUsageStore::connect_from(
                    &dsn,
                    args.usage_postgres_ca_file.as_deref(),
                    &args.usage_postgres_schema,
                    args.usage_postgres_workers,
                )?);
                (store.clone(), store)
            }
            _ => unreachable!("clap validates usage_store_adapter"),
        };
    let usage_store: Arc<dyn UsageStore> = match args.usage_delivery_adapter.as_str() {
        "direct" => usage_projection.clone(),
        "aws-kinesis" => {
            let required = |value: Option<String>, name: &str| {
                value.ok_or_else(|| anyhow::anyhow!("{name} is required for aws-kinesis delivery"))
            };
            let stream = AwsUsageStreamStore::load(
                usage_projection,
                AwsUsageStreamConfig {
                    region: args.usage_aws_region,
                    stream_name: required(args.usage_kinesis_stream, "CATS_USAGE_KINESIS_STREAM")?,
                    archive_bucket: required(
                        args.usage_archive_bucket,
                        "CATS_USAGE_ARCHIVE_BUCKET",
                    )?,
                    checkpoint_table: required(
                        args.usage_checkpoint_table,
                        "CATS_USAGE_CHECKPOINT_TABLE",
                    )?,
                },
            )
            .await?;
            stream.spawn_projector();
            stream
        }
        _ => unreachable!("clap validates usage_delivery_adapter"),
    };
    let any_workos_option = args.workos_client_id.is_some()
        || args.workos_api_key.is_some()
        || args.workos_cookie_password.is_some()
        || args.workos_redirect_uri.is_some()
        || args.workos_issuer.is_some()
        || !args.workos_account_organizations.is_empty()
        || args.workos_admin_organization_id.is_some()
        || args.workos_cookie_domain.is_some()
        || args.user_site_url.is_some()
        || args.admin_site_url.is_some();
    let workos = if any_workos_option {
        let client_id = args
            .workos_client_id
            .ok_or_else(|| anyhow::anyhow!("WORKOS_CLIENT_ID is required"))?;
        let api_key = args
            .workos_api_key
            .ok_or_else(|| anyhow::anyhow!("WORKOS_API_KEY is required"))?;
        let cookie_password = args
            .workos_cookie_password
            .ok_or_else(|| anyhow::anyhow!("WORKOS_COOKIE_PASSWORD is required"))?;
        let redirect_uri = args
            .workos_redirect_uri
            .ok_or_else(|| anyhow::anyhow!("WORKOS_REDIRECT_URI is required"))?;
        let issuer_url = args
            .workos_issuer
            .ok_or_else(|| anyhow::anyhow!("WORKOS_ISSUER is required"))?;
        let admin_organization_id = args
            .workos_admin_organization_id
            .ok_or_else(|| anyhow::anyhow!("CATS_WORKOS_ADMIN_ORGANIZATION_ID is required"))?;
        let mut mappings = BTreeMap::new();
        for value in &args.workos_account_organizations {
            let (account, organization_id) = value.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("--workos-account-organization must be ACCOUNT=ORG_ID")
            })?;
            anyhow::ensure!(
                !account.is_empty() && !organization_id.is_empty(),
                "--workos-account-organization must be ACCOUNT=ORG_ID"
            );
            anyhow::ensure!(
                mappings
                    .insert(account.to_string(), organization_id.to_string())
                    .is_none(),
                "duplicate WorkOS mapping for account {account}"
            );
        }
        let cookie_secure = args
            .workos_cookie_secure
            .unwrap_or_else(|| redirect_uri.starts_with("https://"));
        Some(Arc::new(cats_control_plane::auth::WorkOsConfig::new(
            cats_control_plane::auth::WorkOsConfigParams {
                client_id,
                api_key,
                api_base_url: args.workos_api_base_url,
                issuer_url,
                redirect_uri,
                cookie_password,
                account_organizations: mappings,
                admin_organization_id,
                admin_permission: args.workos_admin_permission,
                cookie_secure,
                cookie_domain: args.workos_cookie_domain,
                user_site_url: args.user_site_url,
                admin_site_url: args.admin_site_url,
            },
        )?))
    } else {
        None
    };
    let any_stripe_option = args.stripe_secret_key.is_some()
        || args.stripe_webhook_secret.is_some()
        || !args.stripe_topup_prices.is_empty()
        || args.stripe_checkout_success_url.is_some()
        || args.stripe_checkout_cancel_url.is_some();
    let stripe = if any_stripe_option {
        let secret_key = args
            .stripe_secret_key
            .ok_or_else(|| anyhow::anyhow!("STRIPE_SECRET_KEY is required"))?;
        let webhook_secret = args
            .stripe_webhook_secret
            .ok_or_else(|| anyhow::anyhow!("STRIPE_WEBHOOK_SECRET is required"))?;
        let mut prices = BTreeMap::new();
        for value in &args.stripe_topup_prices {
            let (amount, price_id) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--stripe-topup-price must be CENTS=PRICE_ID"))?;
            let amount = amount.parse::<i64>().map_err(|_| {
                anyhow::anyhow!("Stripe top-up amount {amount:?} is not integer cents")
            })?;
            anyhow::ensure!(
                prices.insert(amount, price_id.to_string()).is_none(),
                "duplicate Stripe top-up amount {amount}"
            );
        }
        Some(Arc::new(cats_control_plane::billing::StripeClient::new(
            cats_control_plane::billing::StripeConfig {
                secret_key,
                webhook_secret,
                topup_prices: prices,
                checkout_success_url: args
                    .stripe_checkout_success_url
                    .unwrap_or_else(|| "https://cats.run/user/?topup=success".to_string()),
                checkout_cancel_url: args
                    .stripe_checkout_cancel_url
                    .unwrap_or_else(|| "https://cats.run/user/?topup=cancelled".to_string()),
                livemode: args.stripe_livemode,
                api_base_url: args.stripe_api_base_url,
            },
        )?))
    } else {
        None
    };
    anyhow::ensure!(
        !args.billing_enforcement_enabled || stripe.is_some(),
        "CATS_BILLING_ENFORCEMENT_ENABLED requires a complete Stripe top-up configuration"
    );
    let control_store_url = args
        .control_store_url
        .or_else(|| std::env::var("CATS_POSTGRES_URL").ok())
        .context("the control store needs a PostgreSQL URL: --control-store-url, CATS_CONTROL_POSTGRES_URL or CATS_POSTGRES_URL")?;
    let handle = cats_control_plane::server::spawn(cats_control_plane::server::Config {
        listen: args.listen,
        control_store_url,
        control_store_ca_file: args.control_store_ca_file,
        usage_store,
        credit_store,
        storage_meta,
        auth_token: args.auth_token,
        admin_token: args.admin_token,
        workos,
        stripe,
        billing_enforcement_enabled: args.billing_enforcement_enabled,
        node_lease_timeout_ms: args.node_lease_timeout_ms,
        reconcile_interval_ms: args.reconcile_interval_ms,
        auto_tier_policy: cats_control_plane::controller::AutoTierPolicy {
            warm_after_ms: threshold_ms(args.auto_warm_after_seconds, "automatic Warm")?,
            cold_after_ms: threshold_ms(args.auto_cold_after_seconds, "automatic Cold")?,
        },
        oci_deploy_sync_wait_ms: args.oci_deploy_sync_wait_ms,
    })
    .await?;
    println!("READY {}", handle.addr);
    shutdown_signal().await?;
    // cats-controld is PID 1 in the production image. Explicitly handling
    // SIGTERM stops the reconciler as soon as Kubernetes removes the Pod from
    // Service endpoints, so the deployment gap cannot look like Node loss.
    handle.shutdown();
    println!("SHUTDOWN");
    Ok(())
}

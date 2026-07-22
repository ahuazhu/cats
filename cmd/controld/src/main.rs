use std::collections::BTreeMap;
use std::sync::Arc;

use cats_metadata_store_postgres::PostgresMetadataStoreFactory;
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
    #[arg(long, env = "CATS_AUTH_TOKEN", default_value = "dev-service-token")]
    auth_token: String,
    #[arg(long, env = "CATS_ADMIN_TOKEN", default_value = "dev-admin-token")]
    admin_token: String,
    /// Bind a user token to exactly one project (repeatable: PROJECT=TOKEN).
    #[arg(
        long = "project-token",
        env = "CATS_PROJECT_TOKENS",
        value_delimiter = ',',
        value_name = "PROJECT=TOKEN"
    )]
    project_tokens: Vec<String>,
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
    /// Bind a Cats project to exactly one WorkOS Organization.
    #[arg(
        long = "workos-project-organization",
        env = "CATS_WORKOS_PROJECT_ORGANIZATIONS",
        value_delimiter = ',',
        value_name = "PROJECT=ORG_ID"
    )]
    workos_project_organizations: Vec<String>,
    #[arg(long, env = "CATS_WORKOS_ADMIN_ORGANIZATION_ID")]
    workos_admin_organization_id: Option<String>,
    #[arg(
        long,
        env = "CATS_WORKOS_ADMIN_PERMISSION",
        default_value = "cats:fleet:admin"
    )]
    workos_admin_permission: String,
    /// Show static-token forms in addition to WorkOS login.
    #[arg(long, env = "CATS_WORKOS_ALLOW_TOKEN_LOGIN", default_value_t = false)]
    workos_allow_token_login: bool,
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
    let mut project_tokens = BTreeMap::new();
    if args.project_tokens.is_empty() {
        project_tokens.insert("default".to_string(), "dev-token".to_string());
    } else {
        for value in &args.project_tokens {
            let (project, token) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--project-token must be PROJECT=TOKEN"))?;
            anyhow::ensure!(
                !project.is_empty() && project != "*" && !token.is_empty(),
                "--project-token must be PROJECT=TOKEN"
            );
            anyhow::ensure!(
                !project_tokens.values().any(|existing| existing == token),
                "a project token may be bound to only one project"
            );
            anyhow::ensure!(
                project_tokens
                    .insert(project.to_string(), token.to_string())
                    .is_none(),
                "duplicate --project-token for project {project}"
            );
        }
    }
    let any_workos_option = args.workos_client_id.is_some()
        || args.workos_api_key.is_some()
        || args.workos_cookie_password.is_some()
        || args.workos_redirect_uri.is_some()
        || !args.workos_project_organizations.is_empty()
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
        let admin_organization_id = args
            .workos_admin_organization_id
            .ok_or_else(|| anyhow::anyhow!("CATS_WORKOS_ADMIN_ORGANIZATION_ID is required"))?;
        let mut mappings = BTreeMap::new();
        for value in &args.workos_project_organizations {
            let (project, organization_id) = value.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("--workos-project-organization must be PROJECT=ORG_ID")
            })?;
            anyhow::ensure!(
                !project.is_empty() && !organization_id.is_empty(),
                "--workos-project-organization must be PROJECT=ORG_ID"
            );
            anyhow::ensure!(
                mappings
                    .insert(project.to_string(), organization_id.to_string())
                    .is_none(),
                "duplicate WorkOS mapping for project {project}"
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
                redirect_uri,
                cookie_password,
                project_organizations: mappings,
                admin_organization_id,
                admin_permission: args.workos_admin_permission,
                cookie_secure,
                cookie_domain: args.workos_cookie_domain,
                user_site_url: args.user_site_url,
                admin_site_url: args.admin_site_url,
                allow_token_login: args.workos_allow_token_login,
            },
        )?))
    } else {
        None
    };
    let handle = cats_control_plane::server::spawn(cats_control_plane::server::Config {
        listen: args.listen,
        db_path: args.db_path,
        storage_meta,
        auth_token: args.auth_token,
        admin_token: args.admin_token,
        project_tokens,
        workos,
        node_lease_timeout_ms: args.node_lease_timeout_ms,
        reconcile_interval_ms: args.reconcile_interval_ms,
    })
    .await?;
    println!("READY {}", handle.addr);
    std::future::pending::<()>().await;
    Ok(())
}

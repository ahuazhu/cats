use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cats_api::auth::{CliAuthConfigResponse, MeResponse, Workspace};
use cats_api::requests::ListResponse;
use reqwest::blocking::Client as HttpClient;
use workos::resources::user_management::AuthenticateWithRefreshTokenParams;

use crate::config::{Credentials, StoredConfig, DEFAULT_API_URL};

pub struct UserSession {
    pub api_url: String,
    pub access_token: String,
    pub workspace: String,
    pub config: StoredConfig,
}

pub fn configured_api_url(provided: Option<&str>) -> Result<String> {
    if let Some(value) = provided {
        return Ok(normalize_api_url(value));
    }
    Ok(StoredConfig::load()?
        .map(|config| config.api_url)
        .unwrap_or_else(|| DEFAULT_API_URL.to_string()))
}

pub fn login(provided_api_url: Option<&str>) -> Result<StoredConfig> {
    let api_url = configured_api_url(provided_api_url)?;
    let http = http_client()?;
    let public: CliAuthConfigResponse = get_json(&http, &format!("{api_url}/auth/config"), None)?;
    anyhow::ensure!(
        public.workos_enabled,
        "WorkOS login is not configured at {api_url}"
    );
    let client_id = public
        .workos_client_id
        .context("control plane did not publish its WorkOS client ID")?;
    let workos_api_base_url = public
        .workos_api_base_url
        .context("control plane did not publish its WorkOS API base URL")?;
    let workos = workos::Client::builder()
        .client_id(&client_id)
        .base_url(&workos_api_base_url)
        .try_build()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let runtime = tokio::runtime::Runtime::new()?;
    let device = runtime
        .block_on(workos.authkit().start_device_authorization())
        .map_err(|error| anyhow::anyhow!("start WorkOS device login: {error}"))?;
    let verification_url = device
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device.verification_uri);
    println!("Open this URL to sign in:\n  {verification_url}");
    println!("Verification code: {}", device.user_code);
    if let Err(error) = open::that_detached(verification_url) {
        eprintln!("Could not open a browser automatically: {error}");
    }
    println!("Waiting for authentication…");
    let interval = Duration::from_secs_f64(device.interval.unwrap_or(5.0).max(1.0));
    let authenticated = runtime
        .block_on(
            workos
                .authkit()
                .poll_device_code(&device.device_code, interval),
        )
        .map_err(|error| anyhow::anyhow!("WorkOS login failed: {error}"))?;
    let mut credentials = Credentials {
        access_token: authenticated.access_token.into_inner(),
        refresh_token: authenticated.refresh_token.into_inner(),
        active_organization_id: authenticated.organization_id,
    };
    let me: MeResponse = get_json(
        &http,
        &format!("{api_url}/v1/me"),
        Some(&credentials.access_token),
    )?;
    anyhow::ensure!(
        !me.workspaces.is_empty(),
        "your WorkOS account does not belong to a Cats workspace"
    );
    let selected = me
        .workspaces
        .iter()
        .find(|workspace| {
            workspace.organization_id.as_deref() == credentials.active_organization_id.as_deref()
        })
        .cloned()
        .unwrap_or_else(|| me.workspaces[0].clone());
    if selected.organization_id != credentials.active_organization_id {
        credentials = refresh_for_workspace(&runtime, &workos, &credentials, &selected)?;
    }
    credentials.save(&api_url)?;
    let mut config = StoredConfig::new(api_url, client_id, workos_api_base_url);
    config.user = Some(me.user);
    config.current_workspace = Some(selected.slug);
    config.workspaces = me.workspaces;
    config.save()?;
    Ok(config)
}

pub fn user_session(
    provided_api_url: Option<&str>,
    workspace_override: Option<&str>,
) -> Result<UserSession> {
    let mut config = StoredConfig::load()?.context("not logged in; run `cats login`")?;
    let api_url = configured_api_url(provided_api_url)?;
    anyhow::ensure!(
        api_url == config.api_url,
        "not logged in to {api_url}; run `cats login --api-url {api_url}`"
    );
    let workspace_slug = workspace_override
        .map(str::to_string)
        .or_else(|| config.current_workspace.clone())
        .context("no workspace selected; run `cats workspace use <name>`")?;
    let workspace = config
        .workspaces
        .iter()
        .find(|candidate| candidate.slug == workspace_slug)
        .cloned()
        .with_context(|| {
            format!("unknown workspace {workspace_slug}; run `cats workspace list` to refresh")
        })?;
    let mut credentials =
        Credentials::load(&api_url)?.context("login credentials are missing; run `cats login`")?;
    if credentials.active_organization_id != workspace.organization_id
        || token_expires_soon(&credentials.access_token)
    {
        let workos = public_client(&config)?;
        let runtime = tokio::runtime::Runtime::new()?;
        credentials = refresh_for_workspace(&runtime, &workos, &credentials, &workspace)?;
        credentials.save(&api_url)?;
    }
    config.current_workspace = Some(workspace_slug.clone());
    config.save()?;
    Ok(UserSession {
        api_url,
        access_token: credentials.access_token,
        workspace: workspace_slug,
        config,
    })
}

pub fn sync_workspaces(session: &mut UserSession) -> Result<Vec<Workspace>> {
    let http = http_client()?;
    let response: ListResponse<Workspace> = get_json(
        &http,
        &format!("{}/v1/workspaces", session.api_url),
        Some(&session.access_token),
    )?;
    session.config.workspaces = response.items.clone();
    if !session
        .config
        .workspaces
        .iter()
        .any(|workspace| Some(&workspace.slug) == session.config.current_workspace.as_ref())
    {
        session.config.current_workspace = session
            .config
            .workspaces
            .first()
            .map(|workspace| workspace.slug.clone());
    }
    session.config.save()?;
    Ok(response.items)
}

pub fn switch_workspace(provided_api_url: Option<&str>, slug: &str) -> Result<Workspace> {
    let mut session = user_session(provided_api_url, None)?;
    let workspaces = sync_workspaces(&mut session)?;
    let workspace = workspaces
        .into_iter()
        .find(|workspace| workspace.slug == slug)
        .with_context(|| format!("workspace {slug} is not available to this user"))?;
    let current_credentials = Credentials::load(&session.api_url)?
        .context("login credentials are missing; run `cats login`")?;
    let runtime = tokio::runtime::Runtime::new()?;
    let workos = public_client(&session.config)?;
    let credentials = refresh_for_workspace(&runtime, &workos, &current_credentials, &workspace)?;
    credentials.save(&session.api_url)?;
    session.config.current_workspace = Some(workspace.slug.clone());
    session.config.save()?;
    Ok(workspace)
}

pub fn logout(provided_api_url: Option<&str>) -> Result<()> {
    let Some(mut config) = StoredConfig::load()? else {
        return Ok(());
    };
    let api_url = configured_api_url(provided_api_url)?;
    if api_url == config.api_url {
        if let Some(mut credentials) = Credentials::load(&api_url)? {
            if token_expires_soon(&credentials.access_token) {
                if let (Ok(runtime), Ok(workos)) =
                    (tokio::runtime::Runtime::new(), public_client(&config))
                {
                    if let Some(workspace) = config
                        .current_workspace
                        .as_deref()
                        .and_then(|slug| config.workspaces.iter().find(|item| item.slug == slug))
                    {
                        if let Ok(refreshed) =
                            refresh_for_workspace(&runtime, &workos, &credentials, workspace)
                        {
                            credentials = refreshed;
                        }
                    }
                }
            }
            let http = http_client()?;
            if let Err(error) = post_empty(
                &http,
                &format!("{api_url}/v1/auth/logout"),
                &credentials.access_token,
            ) {
                eprintln!("Warning: remote session revocation failed: {error}");
            }
        }
        Credentials::delete(&api_url)?;
        config.clear_identity();
        config.save()?;
    }
    Ok(())
}

fn public_client(config: &StoredConfig) -> Result<workos::Client> {
    workos::Client::builder()
        .client_id(&config.workos_client_id)
        .base_url(&config.workos_api_base_url)
        .try_build()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn refresh_for_workspace(
    runtime: &tokio::runtime::Runtime,
    workos: &workos::Client,
    credentials: &Credentials,
    workspace: &Workspace,
) -> Result<Credentials> {
    let mut params = AuthenticateWithRefreshTokenParams::new(credentials.refresh_token.clone());
    params.organization_id = workspace.organization_id.clone();
    let refreshed = runtime
        .block_on(
            workos
                .user_management()
                .authenticate_with_refresh_token(params),
        )
        .map_err(|error| anyhow::anyhow!("refresh WorkOS session: {error}"))?;
    if refreshed.organization_id != workspace.organization_id {
        bail!("WorkOS did not authorize workspace {}", workspace.slug);
    }
    Ok(Credentials {
        access_token: refreshed.access_token.into_inner(),
        refresh_token: refreshed.refresh_token.into_inner(),
        active_organization_id: refreshed.organization_id,
    })
}

fn token_expires_soon(token: &str) -> bool {
    let expires_at = token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|payload| serde_json::from_slice::<serde_json::Value>(&payload).ok())
        .and_then(|claims| claims.get("exp").and_then(serde_json::Value::as_u64));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX);
    expires_at.is_none_or(|expires_at| expires_at <= now.saturating_add(60))
}

fn http_client() -> Result<HttpClient> {
    Ok(HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .build()?)
}

fn get_json<T: serde::de::DeserializeOwned>(
    http: &HttpClient,
    url: &str,
    token: Option<&str>,
) -> Result<T> {
    let mut request = http.get(url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().context("control plane unreachable")?;
    parse_json_response(response)
}

fn post_empty(http: &HttpClient, url: &str, token: &str) -> Result<()> {
    let response = http
        .post(url)
        .bearer_auth(token)
        .header("content-length", "0")
        .send()
        .context("control plane unreachable")?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let text = response.text().unwrap_or_default();
    response_error(status, &text)
}

fn parse_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::blocking::Response,
) -> Result<T> {
    let status = response.status();
    let text = response.text().unwrap_or_default();
    if !status.is_success() {
        return response_error(status, &text);
    }
    serde_json::from_str(&text).context("malformed control-plane response")
}

fn response_error<T>(status: reqwest::StatusCode, text: &str) -> Result<T> {
    if let Ok(error) = serde_json::from_str::<cats_api::error::ErrorBody>(text) {
        bail!("{} ({:?})", error.message, error.code);
    }
    bail!("HTTP {status}: {text}")
}

fn normalize_api_url(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_expiration_is_read_without_treating_it_as_verified_identity() {
        let future = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({ "exp": u64::MAX - 1 })).unwrap());
        assert!(!token_expires_soon(&format!("header.{future}.signature")));
        assert!(token_expires_soon("not-a-jwt"));
    }
}

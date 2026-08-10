use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cats_api::auth::{CliAuthConfigResponse, MeResponse, Workspace};
use cats_api::requests::ListResponse;
use reqwest::blocking::Client as HttpClient;
use workos::resources::user_management::AuthenticateWithRefreshTokenParams;

use crate::config::{
    canonical_https_origin, CliStateLock, Credentials, FleetAdminCredentials, FleetAdminStateLock,
    StoredConfig, DEFAULT_API_URL,
};

pub(crate) struct UserSession {
    pub api_url: String,
    pub access_token: String,
    pub workspace: String,
    pub config: StoredConfig,
}

pub(crate) struct FleetAdminSession {
    pub api_url: String,
    pub access_token: String,
    state_lock: FleetAdminStateLock,
}

impl FleetAdminSession {
    pub(crate) fn assert_current(&self) -> Result<()> {
        self.state_lock.assert_current()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        api_url: String,
        access_token: String,
        state_lock: FleetAdminStateLock,
    ) -> Self {
        Self {
            api_url,
            access_token,
            state_lock,
        }
    }
}

pub(crate) struct FleetAdminIdentity {
    pub email: String,
}

struct FleetAdminPublicConfig {
    client_id: String,
    api_base_url: String,
    organization_id: String,
}

pub(crate) fn configured_api_url(provided: Option<&str>) -> Result<String> {
    if let Some(value) = provided {
        return Ok(normalize_api_url(value));
    }
    Ok(StoredConfig::load()?
        .map(|config| config.api_url)
        .unwrap_or_else(|| DEFAULT_API_URL.to_string()))
}

pub(crate) fn login(provided_api_url: Option<&str>) -> Result<StoredConfig> {
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
            Some(workspace.organization_id.as_str())
                == credentials.active_organization_id.as_deref()
        })
        .cloned()
        .unwrap_or_else(|| me.workspaces[0].clone());
    if Some(selected.organization_id.as_str()) != credentials.active_organization_id.as_deref() {
        credentials = refresh_for_workspace(
            &runtime,
            &workos,
            &credentials,
            &selected,
            Some(&me.user.id),
        )?;
    }
    let _state_lock = CliStateLock::acquire()?;
    credentials.save(&api_url)?;
    let mut config = StoredConfig::new(api_url, client_id, workos_api_base_url);
    config.user = Some(me.user);
    config.current_workspace = Some(selected.selector().to_string());
    config.workspaces = me.workspaces;
    config.save()?;
    Ok(config)
}

/// Acquire a WorkOS device session independently of all Cats Workspace state,
/// then scope the rotating refresh token to the configured admin Organization.
pub(crate) fn fleet_admin_login(provided_api_url: Option<&str>) -> Result<FleetAdminIdentity> {
    let (raw_api_url, canonical_origin) = fleet_admin_origins(provided_api_url)?;
    let public = fleet_admin_public_config(&canonical_origin)?;
    let workos = public_workos_client(&public.client_id, &public.api_base_url)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let device = runtime
        .block_on(workos.authkit().start_device_authorization())
        .map_err(|error| anyhow::anyhow!("start WorkOS fleet-administrator login: {error}"))?;
    let verification_url = device
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device.verification_uri);
    println!("Open this URL to sign in as a fleet administrator:\n  {verification_url}");
    println!("Verification code: {}", device.user_code);
    if let Err(error) = open::that_detached(verification_url) {
        eprintln!("Could not open a browser automatically: {error}");
    }
    println!("Waiting for fleet-administrator authentication…");
    let interval = Duration::from_secs_f64(device.interval.unwrap_or(5.0).max(1.0));
    let authenticated = runtime
        .block_on(
            workos
                .authkit()
                .poll_device_code(&device.device_code, interval),
        )
        .map_err(|error| anyhow::anyhow!("WorkOS fleet-administrator login failed: {error}"))?;
    let subject = authenticated.user.id.clone();
    let email = authenticated.user.email.clone();
    let initial = FleetAdminCredentials {
        access_token: authenticated.access_token.into_inner(),
        refresh_token: authenticated.refresh_token.into_inner(),
        organization_id: authenticated.organization_id.unwrap_or_default(),
        subject,
        email,
    };
    let credentials =
        scope_fleet_admin_credentials(&runtime, &workos, initial, &public.organization_id)?;
    let lock = FleetAdminStateLock::acquire(&canonical_origin)?;
    // Login intentionally replaces any prior administrator identity, but it
    // still rereads the globally shared credential while holding the same
    // origin lock as refresh/logout. This detects corrupt current state and
    // prevents a concurrent rotating refresh from being silently overwritten.
    let _previous = lock.load_credentials(&raw_api_url)?;
    lock.save_credentials(&credentials)?;
    Ok(FleetAdminIdentity {
        email: credentials.email,
    })
}

pub(crate) fn fleet_admin_session(provided_api_url: Option<&str>) -> Result<FleetAdminSession> {
    let (raw_api_url, canonical_origin) = fleet_admin_origins(provided_api_url)?;
    let lock = FleetAdminStateLock::acquire(&canonical_origin)?;
    let mut credentials = lock
        .load_credentials(&raw_api_url)?
        .context("not signed in as a fleet administrator; run `cats admin login`")?;
    let public = fleet_admin_public_config_locked(&lock, &canonical_origin)?;
    if credentials.organization_id != public.organization_id
        || token_expires_soon(&credentials.access_token)
    {
        let workos = public_workos_client(&public.client_id, &public.api_base_url)?;
        let runtime = tokio::runtime::Runtime::new()?;
        lock.assert_current()?;
        let refreshed = refresh_for_fleet_admin(
            &runtime,
            &workos,
            &credentials,
            &public.organization_id,
            Some(&credentials.subject),
        );
        lock.assert_current()?;
        credentials = refreshed?;
        lock.save_credentials(&credentials)?;
    }
    Ok(FleetAdminSession {
        api_url: canonical_origin,
        access_token: credentials.access_token,
        state_lock: lock,
    })
}

pub(crate) fn fleet_admin_logout(provided_api_url: Option<&str>) -> Result<()> {
    let (raw_api_url, canonical_origin) = fleet_admin_origins(provided_api_url)?;
    let lock = FleetAdminStateLock::acquire(&canonical_origin)?;
    if let Some(credentials) = lock.load_credentials(&raw_api_url)? {
        let http = http_client()?;
        lock.assert_current()?;
        let result = post_empty(
            &http,
            &fleet_admin_request_url(&canonical_origin, "/v1/auth/logout")?,
            &credentials.access_token,
        );
        lock.assert_current()?;
        if let Err(error) = result {
            eprintln!("Warning: fleet-administrator session revocation failed: {error}");
        }
    }
    lock.delete_credentials()
}

fn fleet_admin_origins(provided_api_url: Option<&str>) -> Result<(String, String)> {
    let raw_api_url = configured_api_url(provided_api_url)?;
    let canonical_origin = canonical_https_origin(&raw_api_url)?;
    Ok((raw_api_url, canonical_origin))
}

fn fleet_admin_public_config_locked(
    lock: &FleetAdminStateLock,
    canonical_origin: &str,
) -> Result<FleetAdminPublicConfig> {
    lock.assert_current()?;
    let result = fleet_admin_public_config(canonical_origin);
    lock.assert_current()?;
    result
}

fn fleet_admin_public_config(canonical_origin: &str) -> Result<FleetAdminPublicConfig> {
    anyhow::ensure!(
        canonical_https_origin(canonical_origin)? == canonical_origin,
        "fleet-administrator network authority is not canonical"
    );
    let http = http_client()?;
    let public: CliAuthConfigResponse = get_json(
        &http,
        &fleet_admin_request_url(canonical_origin, "/auth/config")?,
        None,
    )?;
    anyhow::ensure!(
        public.workos_enabled,
        "WorkOS fleet-administrator login is not configured at {canonical_origin}"
    );
    Ok(FleetAdminPublicConfig {
        client_id: public
            .workos_client_id
            .context("control plane did not publish its WorkOS client ID")?,
        api_base_url: public
            .workos_api_base_url
            .context("control plane did not publish its WorkOS API base URL")?,
        organization_id: public
            .workos_admin_organization_id
            .context("control plane did not publish its fleet-administrator Organization")?,
    })
}

fn fleet_admin_request_url(canonical_origin: &str, path: &str) -> Result<String> {
    anyhow::ensure!(
        canonical_https_origin(canonical_origin)? == canonical_origin,
        "fleet-administrator request origin is not canonical"
    );
    anyhow::ensure!(
        path.starts_with('/') && !path.starts_with("//"),
        "invalid request path"
    );
    #[cfg(test)]
    if let Some(base) = std::env::var_os("CATS_TEST_FLEET_ADMIN_HTTP_BASE_URL") {
        let base = base
            .to_str()
            .context("test fleet-administrator HTTP base URL is not UTF-8")?;
        let parsed =
            reqwest::Url::parse(base).context("invalid test fleet-administrator HTTP base URL")?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.host_str().is_some_and(|host| {
                    host.eq_ignore_ascii_case("localhost")
                        || host.parse::<std::net::IpAddr>().is_ok()
                })
                && parsed.path() == "/"
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "test fleet-administrator HTTP base URL must be an exact loopback origin"
        );
        return Ok(format!("{}{}", base.trim_end_matches('/'), path));
    }
    Ok(format!("{canonical_origin}{path}"))
}

fn public_workos_client(client_id: &str, api_base_url: &str) -> Result<workos::Client> {
    workos::Client::builder()
        .client_id(client_id)
        .base_url(api_base_url)
        .try_build()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn refresh_for_fleet_admin(
    runtime: &tokio::runtime::Runtime,
    workos: &workos::Client,
    credentials: &FleetAdminCredentials,
    organization_id: &str,
    expected_subject: Option<&str>,
) -> Result<FleetAdminCredentials> {
    let mut params = AuthenticateWithRefreshTokenParams::new(credentials.refresh_token.clone());
    params.organization_id = Some(organization_id.to_owned());
    let refreshed = runtime
        .block_on(
            workos
                .user_management()
                .authenticate_with_refresh_token(params),
        )
        .map_err(|error| anyhow::anyhow!("refresh WorkOS fleet-administrator session: {error}"))?;
    anyhow::ensure!(
        refreshed.organization_id.as_deref() == Some(organization_id),
        "WorkOS did not authorize the deployment's fleet-administrator Organization"
    );
    if expected_subject.is_some_and(|expected| refreshed.user.id != expected) {
        bail!("WorkOS refreshed a different fleet-administrator identity");
    }
    Ok(FleetAdminCredentials {
        access_token: refreshed.access_token.into_inner(),
        refresh_token: refreshed.refresh_token.into_inner(),
        organization_id: organization_id.to_owned(),
        subject: refreshed.user.id,
        email: refreshed.user.email,
    })
}

fn scope_fleet_admin_credentials(
    runtime: &tokio::runtime::Runtime,
    workos: &workos::Client,
    credentials: FleetAdminCredentials,
    organization_id: &str,
) -> Result<FleetAdminCredentials> {
    if credentials.organization_id == organization_id {
        return Ok(credentials);
    }
    let subject = credentials.subject.clone();
    refresh_for_fleet_admin(
        runtime,
        workos,
        &credentials,
        organization_id,
        Some(&subject),
    )
}

pub(crate) fn user_session(
    provided_api_url: Option<&str>,
    workspace_override: Option<&str>,
) -> Result<UserSession> {
    let _state_lock = CliStateLock::acquire()?;
    let config = StoredConfig::load()?.context("not logged in; run `cats login`")?;
    let api_url = configured_api_url(provided_api_url)?;
    anyhow::ensure!(
        api_url == config.api_url,
        "not logged in to {api_url}; run `cats login --api-url {api_url}`"
    );
    let workspace_selector = workspace_override
        .map(str::to_string)
        .or_else(|| config.current_workspace.clone())
        .context("no workspace selected; run `cats workspace use <name>`")?;
    let workspace =
        resolve_workspace(&config.workspaces, &workspace_selector).with_context(|| {
            format!("unknown workspace {workspace_selector}; run `cats workspace list` to refresh")
        })?;
    let mut credentials =
        Credentials::load(&api_url)?.context("login credentials are missing; run `cats login`")?;
    if credentials.active_organization_id.as_deref() != Some(workspace.organization_id.as_str())
        || token_expires_soon(&credentials.access_token)
    {
        let workos = public_client(&config)?;
        let runtime = tokio::runtime::Runtime::new()?;
        credentials = refresh_for_workspace(
            &runtime,
            &workos,
            &credentials,
            &workspace,
            config.user.as_ref().map(|user| user.id.as_str()),
        )?;
        credentials.save(&api_url)?;
    }
    Ok(UserSession {
        api_url,
        access_token: credentials.access_token,
        workspace: workspace.id.clone(),
        config,
    })
}

pub(crate) fn sync_workspaces(session: &mut UserSession) -> Result<Vec<Workspace>> {
    let http = http_client()?;
    let response: ListResponse<Workspace> = get_json(
        &http,
        &format!("{}/v1/workspaces", session.api_url),
        Some(&session.access_token),
    )?;
    let _state_lock = CliStateLock::acquire()?;
    let mut config =
        StoredConfig::load()?.context("login configuration disappeared; run `cats login`")?;
    anyhow::ensure!(
        config.api_url == session.api_url,
        "login configuration changed while workspaces were refreshing"
    );
    config.workspaces = response.items.clone();
    let current_is_available = config
        .current_workspace
        .as_deref()
        .and_then(|selector| resolve_workspace(&config.workspaces, selector))
        .is_some();
    if !current_is_available {
        config.current_workspace = config
            .workspaces
            .first()
            .map(|workspace| workspace.selector().to_string());
    }
    config.save()?;
    session.config = config;
    Ok(response.items)
}

pub(crate) fn switch_workspace(
    provided_api_url: Option<&str>,
    selector: &str,
) -> Result<Workspace> {
    let mut session = user_session(provided_api_url, None)?;
    sync_workspaces(&mut session)?;
    let _state_lock = CliStateLock::acquire()?;
    let mut config =
        StoredConfig::load()?.context("login configuration disappeared; run `cats login`")?;
    anyhow::ensure!(
        config.api_url == session.api_url,
        "login configuration changed while selecting a workspace"
    );
    let workspace = resolve_workspace(&config.workspaces, selector)
        .with_context(|| format!("workspace {selector} is not available to this user"))?;
    let current_credentials = Credentials::load(&session.api_url)?
        .context("login credentials are missing; run `cats login`")?;
    if current_credentials.active_organization_id.as_deref()
        != Some(workspace.organization_id.as_str())
        || token_expires_soon(&current_credentials.access_token)
    {
        let runtime = tokio::runtime::Runtime::new()?;
        let workos = public_client(&config)?;
        let credentials = refresh_for_workspace(
            &runtime,
            &workos,
            &current_credentials,
            &workspace,
            config.user.as_ref().map(|user| user.id.as_str()),
        )?;
        credentials.save(&session.api_url)?;
    }
    config.current_workspace = Some(workspace.selector().to_string());
    config.save()?;
    Ok(workspace)
}

fn resolve_workspace(workspaces: &[Workspace], selector: &str) -> Option<Workspace> {
    if let Some(workspace) = workspaces
        .iter()
        .find(|workspace| workspace.selector() == selector)
    {
        return Some(workspace.clone());
    }
    if let Some(workspace) = workspaces.iter().find(|workspace| workspace.id == selector) {
        return Some(workspace.clone());
    }
    let mut matches = workspaces
        .iter()
        .filter(|workspace| workspace.slug == selector);
    let workspace = matches.next()?.clone();
    matches.next().is_none().then_some(workspace)
}

pub(crate) fn logout(provided_api_url: Option<&str>) -> Result<()> {
    let Some(config) = StoredConfig::load()? else {
        return Ok(());
    };
    let api_url = configured_api_url(provided_api_url)?;
    if api_url == config.api_url {
        let _state_lock = CliStateLock::acquire()?;
        let Some(mut config) = StoredConfig::load()? else {
            return Ok(());
        };
        anyhow::ensure!(
            config.api_url == api_url,
            "login configuration changed while logout was starting"
        );
        if let Some(mut credentials) = Credentials::load(&api_url)? {
            if token_expires_soon(&credentials.access_token) {
                if let (Ok(runtime), Ok(workos)) =
                    (tokio::runtime::Runtime::new(), public_client(&config))
                {
                    if let Some(workspace) = config
                        .current_workspace
                        .as_deref()
                        .and_then(|selector| resolve_workspace(&config.workspaces, selector))
                    {
                        if let Ok(refreshed) = refresh_for_workspace(
                            &runtime,
                            &workos,
                            &credentials,
                            &workspace,
                            config.user.as_ref().map(|user| user.id.as_str()),
                        ) {
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
    expected_user_id: Option<&str>,
) -> Result<Credentials> {
    let mut params = AuthenticateWithRefreshTokenParams::new(credentials.refresh_token.clone());
    params.organization_id = Some(workspace.organization_id.clone());
    let refreshed = runtime
        .block_on(
            workos
                .user_management()
                .authenticate_with_refresh_token(params),
        )
        .map_err(|error| anyhow::anyhow!("refresh WorkOS session: {error}"))?;
    if refreshed.organization_id.as_deref() != Some(workspace.organization_id.as_str()) {
        bail!("WorkOS did not authorize workspace {}", workspace.slug);
    }
    if expected_user_id.is_some_and(|expected| refreshed.user.id != expected) {
        bail!("WorkOS refreshed a different user identity");
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
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus};
    use std::thread;
    use std::time::Instant;

    use super::*;

    const ADMIN_REFRESH_CHILD_ROLE: &str = "CATS_TEST_ADMIN_REFRESH_CHILD_ROLE";
    const ADMIN_REFRESH_ROOT: &str = "CATS_TEST_ADMIN_REFRESH_ROOT";
    const ADMIN_REFRESH_API_URL: &str = "CATS_TEST_ADMIN_REFRESH_API_URL";
    const ADMIN_LOCK_ABA_CHILD_ROLE: &str = "CATS_TEST_ADMIN_LOCK_ABA_CHILD_ROLE";
    const ADMIN_LOCK_ABA_API_URL: &str = "CATS_TEST_ADMIN_LOCK_ABA_API_URL";
    const ADMIN_LOCK_ABA_BACKUP: &str = "CATS_TEST_ADMIN_LOCK_ABA_BACKUP";
    const ADMIN_LOCK_ABA_EXPECTED_ERROR: &str = "CATS_TEST_ADMIN_LOCK_ABA_EXPECTED_ERROR";
    const ADMIN_MIGRATION_CHILD_MODE: &str = "CATS_TEST_ADMIN_MIGRATION_CHILD_MODE";
    const ADMIN_MIGRATION_API_URL: &str = "CATS_TEST_ADMIN_MIGRATION_API_URL";

    fn admin_credentials(organization_id: &str) -> FleetAdminCredentials {
        FleetAdminCredentials {
            access_token: "access-before".to_owned(),
            refresh_token: "refresh-before".to_owned(),
            organization_id: organization_id.to_owned(),
            subject: "user_admin".to_owned(),
            email: "admin@example.com".to_owned(),
        }
    }

    fn read_http_request(mut stream: &std::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "HTTP request ended before its body");
            request.extend_from_slice(&buffer[..count]);
            let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                return request;
            }
        }
    }

    fn write_json_response(mut stream: &std::net::TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    }

    fn marker(root: &Path, name: &str) -> PathBuf {
        root.join(name)
    }

    fn wait_for_child_marker(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for child marker {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_marker(path: &Path, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if path.exists() {
                return;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "admin-refresh child exited before publishing {}: {status}",
                    path.display()
                );
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for admin-refresh marker {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn unexpired_access_token() -> String {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({ "exp": u64::MAX - 1 })).unwrap());
        format!("header.{payload}.signature")
    }

    fn spawn_admin_refresh_child(
        root: &Path,
        credential_root: &Path,
        config_dir: &Path,
        environment_root: &Path,
        api_url: &str,
        http_base_url: &str,
        role: &str,
    ) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth::tests::fleet_admin_refresh_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env(ADMIN_REFRESH_CHILD_ROLE, role)
            .env(ADMIN_REFRESH_ROOT, root)
            .env(ADMIN_REFRESH_API_URL, api_url)
            .env_remove("CATS_TEST_FLEET_ADMIN_LOCK_ROOT")
            .env("CATS_TEST_CREDENTIAL_STORE_DIR", credential_root)
            .env("CATS_TEST_FLEET_ADMIN_HTTP_BASE_URL", http_base_url)
            .env("CATS_CONFIG_DIR", config_dir)
            .env("HOME", environment_root)
            .env("XDG_DATA_HOME", environment_root)
            .spawn()
            .unwrap()
    }

    fn spawn_admin_lock_aba_holder(
        root: &Path,
        lock_root: &Path,
        credential_root: &Path,
        config_dir: &Path,
        api_url: &str,
        http_base_url: &str,
        expected_error: &str,
    ) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth::tests::fleet_admin_lock_aba_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env(ADMIN_LOCK_ABA_CHILD_ROLE, "holder")
            .env(ADMIN_LOCK_ABA_API_URL, api_url)
            .env(ADMIN_LOCK_ABA_EXPECTED_ERROR, expected_error)
            .env("CATS_TEST_FLEET_ADMIN_LOCK_ROOT", lock_root)
            .env("CATS_TEST_CREDENTIAL_STORE_DIR", credential_root)
            .env(
                "CATS_TEST_CREDENTIAL_STORE_AUDIT_FILE",
                marker(root, "credential-audit"),
            )
            .env("CATS_TEST_FLEET_ADMIN_HTTP_BASE_URL", http_base_url)
            .env(
                "CATS_TEST_FLEET_ADMIN_AFTER_LOCK_MARKER",
                marker(root, "locked"),
            )
            .env(
                "CATS_TEST_FLEET_ADMIN_AFTER_LOCK_RELEASE",
                marker(root, "release"),
            )
            .env("CATS_CONFIG_DIR", config_dir)
            .spawn()
            .unwrap()
    }

    fn spawn_admin_lock_aba_mutator(
        lock_root: &Path,
        backup: &Path,
        api_url: &str,
        role: &str,
    ) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth::tests::fleet_admin_lock_aba_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env(ADMIN_LOCK_ABA_CHILD_ROLE, role)
            .env(ADMIN_LOCK_ABA_API_URL, api_url)
            .env(ADMIN_LOCK_ABA_BACKUP, backup)
            .env("CATS_TEST_FLEET_ADMIN_LOCK_ROOT", lock_root)
            .spawn()
            .unwrap()
    }

    fn spawn_admin_migration_child(
        lock_root: &Path,
        credential_root: &Path,
        api_url: &str,
        mode: &str,
    ) -> ExitStatus {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth::tests::fleet_admin_credential_migration_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env(ADMIN_MIGRATION_CHILD_MODE, mode)
            .env(ADMIN_MIGRATION_API_URL, api_url)
            .env("CATS_TEST_FLEET_ADMIN_LOCK_ROOT", lock_root)
            .env("CATS_TEST_CREDENTIAL_STORE_DIR", credential_root)
            .status()
            .unwrap()
    }

    fn wait_for_child_without_network(child: &mut Child, listener: &TcpListener) -> ExitStatus {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match listener.accept() {
                Ok((_stream, _)) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("stale fleet-administrator lock holder performed network I/O");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("inspect test control listener: {error}"),
            }
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fleet-administrator lock holder did not exit after identity changed");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn jwt_expiration_is_read_without_treating_it_as_verified_identity() {
        let future = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({ "exp": u64::MAX - 1 })).unwrap());
        assert!(!token_expires_soon(&format!("header.{future}.signature")));
        assert!(token_expires_soon("not-a-jwt"));
    }

    #[test]
    fn workspace_resolution_prefers_account_qualified_selectors() {
        let workspaces = vec![
            serde_json::from_value::<Workspace>(serde_json::json!({
                "id": "ws_acme_default",
                "account_id": "acct_acme",
                "account_slug": "acme",
                "account_display_name": "Acme",
                "slug": "default",
                "locator": "acme",
                "display_name": "Default",
                "kind": "organization",
                "organization_id": "org_acme",
                "is_default": true
            }))
            .unwrap(),
            serde_json::from_value::<Workspace>(serde_json::json!({
                "id": "ws_acme_dev",
                "account_id": "acct_acme",
                "account_slug": "acme",
                "account_display_name": "Acme",
                "slug": "dev",
                "locator": "acme/dev",
                "display_name": "Development",
                "kind": "organization",
                "organization_id": "org_acme",
                "is_default": false
            }))
            .unwrap(),
            serde_json::from_value::<Workspace>(serde_json::json!({
                "id": "ws_other_dev",
                "account_id": "acct_other",
                "account_slug": "other",
                "account_display_name": "Other",
                "slug": "dev",
                "locator": "other/dev",
                "display_name": "Development",
                "kind": "organization",
                "organization_id": "org_other",
                "is_default": false
            }))
            .unwrap(),
        ];
        assert_eq!(
            resolve_workspace(&workspaces, "acme/dev").unwrap().id,
            "ws_acme_dev"
        );
        assert_eq!(
            resolve_workspace(&workspaces, "ws_acme_dev").unwrap().id,
            "ws_acme_dev",
            "an immutable workspace ID must resolve to itself"
        );
        assert!(
            resolve_workspace(&workspaces, "dev").is_none(),
            "a bare slug shared by two accounts is ambiguous"
        );
        assert_eq!(
            resolve_workspace(&workspaces, "default").unwrap().id,
            "ws_acme_default",
            "a bare slug unique across accounts still resolves"
        );
    }

    #[test]
    fn admin_only_identity_needs_no_workspace_or_scope_refresh() {
        let workos = public_workos_client("client_test", "http://127.0.0.1:1").unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let credentials = admin_credentials("org_admin");
        let scoped =
            scope_fleet_admin_credentials(&runtime, &workos, credentials, "org_admin").unwrap();
        assert_eq!(scoped.organization_id, "org_admin");
        assert_eq!(scoped.subject, "user_admin");
    }

    #[test]
    fn ordinary_workspace_scope_refreshes_independently_to_admin_org() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&stream);
            let request = String::from_utf8(request).unwrap();
            assert!(request.contains(r#""refresh_token":"refresh-before""#));
            assert!(request.contains(r#""organization_id":"org_admin""#));
            assert!(!request.contains("workspace"));
            let body = serde_json::json!({
                "user": {
                    "object": "user",
                    "id": "user_admin",
                    "email": "admin@example.com",
                    "email_verified": true,
                    "created_at": "2026-08-10T00:00:00.000Z",
                    "updated_at": "2026-08-10T00:00:00.000Z"
                },
                "organization_id": "org_admin",
                "access_token": "access-admin",
                "refresh_token": "refresh-admin"
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let workos = public_workos_client("client_test", &format!("http://{address}")).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let scoped = scope_fleet_admin_credentials(
            &runtime,
            &workos,
            admin_credentials("org_ordinary_workspace"),
            "org_admin",
        )
        .unwrap();
        assert_eq!(scoped.organization_id, "org_admin");
        assert_eq!(scoped.access_token, "access-admin");
        server.join().unwrap();
    }

    #[test]
    fn fleet_admin_refresh_is_serial_across_process_environment_splits() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let credential_root = root.join("credential-store");
        let config_a = root.join("config-a");
        let config_b = root.join("config-b");
        let home_a = root.join("home-a");
        let home_b = root.join("home-b");
        for path in [&config_a, &config_b, &home_a, &home_b, &credential_root] {
            std::fs::create_dir(path).unwrap();
        }
        let nonce = root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>();
        let first_api_url = format!("https://LOCK-{nonce}.example");
        let second_api_url = format!("https://lock-{nonce}.example:443/");
        let canonical_origin = canonical_https_origin(&first_api_url).unwrap();
        assert_eq!(
            canonical_origin,
            canonical_https_origin(&second_api_url).unwrap()
        );
        let legacy_credential =
            FleetAdminCredentials::test_store_path(&credential_root, &first_api_url);
        let encoded = serde_json::to_string(&admin_credentials("org_admin")).unwrap();
        std::fs::write(&legacy_credential, &encoded).unwrap();

        let control_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let control_address = control_listener.local_addr().unwrap();
        let workos_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let workos_address = workos_listener.local_addr().unwrap();
        let http_base_url = format!("http://{control_address}");
        let workos_url = format!("http://{workos_address}");

        let control_server = thread::spawn(move || {
            let response = serde_json::json!({
                "workos_enabled": true,
                "workos_client_id": "client_test",
                "workos_api_base_url": workos_url,
                "workos_admin_organization_id": "org_admin"
            })
            .to_string();
            for _ in 0..2 {
                let (stream, _) = control_listener.accept().unwrap();
                let request = String::from_utf8(read_http_request(&stream)).unwrap();
                assert!(request.starts_with("GET /auth/config HTTP/1.1\r\n"));
                write_json_response(&stream, &response);
            }
        });

        let refresh_seen = marker(&root, "refresh-seen");
        let release_refresh = marker(&root, "release-refresh");
        let refresh_seen_for_server = refresh_seen.clone();
        let release_for_server = release_refresh.clone();
        let refreshed_access_token = unexpired_access_token();
        let access_for_server = refreshed_access_token.clone();
        let workos_server = thread::spawn(move || {
            let (stream, _) = workos_listener.accept().unwrap();
            let request = String::from_utf8(read_http_request(&stream)).unwrap();
            assert!(request.contains(r#""refresh_token":"refresh-before""#));
            assert!(request.contains(r#""organization_id":"org_admin""#));
            std::fs::write(refresh_seen_for_server, b"seen").unwrap();
            wait_for_child_marker(&release_for_server);
            let response = serde_json::json!({
                "user": {
                    "object": "user",
                    "id": "user_admin",
                    "email": "admin@example.com",
                    "email_verified": true,
                    "created_at": "2026-08-10T00:00:00.000Z",
                    "updated_at": "2026-08-10T00:00:00.000Z"
                },
                "organization_id": "org_admin",
                "access_token": access_for_server,
                "refresh_token": "refresh-after"
            })
            .to_string();
            write_json_response(&stream, &response);
        });

        let mut first = spawn_admin_refresh_child(
            &root,
            &credential_root,
            &config_a,
            &home_a,
            &first_api_url,
            &http_base_url,
            "first",
        );
        wait_for_marker(&refresh_seen, &mut first);
        let mut second = spawn_admin_refresh_child(
            &root,
            &credential_root,
            &config_b,
            &home_b,
            &second_api_url,
            &http_base_url,
            "second",
        );
        wait_for_marker(&marker(&root, "second-saw-contention"), &mut second);

        std::fs::write(release_refresh, b"release").unwrap();
        let first_status = first.wait().unwrap();
        let second_status = second.wait().unwrap();
        assert!(first_status.success(), "first child failed: {first_status}");
        assert!(
            second_status.success(),
            "second child failed: {second_status}"
        );
        control_server.join().unwrap();
        workos_server.join().unwrap();

        assert_eq!(
            std::fs::read_to_string(marker(&root, "first-observed-access")).unwrap(),
            refreshed_access_token
        );
        assert_eq!(
            std::fs::read_to_string(marker(&root, "second-observed-access")).unwrap(),
            refreshed_access_token
        );
        let canonical_credential =
            FleetAdminCredentials::test_store_path(&credential_root, &canonical_origin);
        let persisted: FleetAdminCredentials =
            serde_json::from_slice(&std::fs::read(&canonical_credential).unwrap()).unwrap();
        assert_eq!(persisted.refresh_token, "refresh-after");
        assert_eq!(persisted.access_token, refreshed_access_token);
        assert!(
            !legacy_credential.exists(),
            "legacy raw-origin account must be removed only after exact canonical persistence"
        );
    }

    #[test]
    fn fleet_admin_legacy_credential_migration_is_exact_reentrant_and_conflict_closed() {
        let raw_api_url = "https://CONTROL.example";
        let canonical_origin = canonical_https_origin(raw_api_url).unwrap();
        let original = serde_json::to_string(&admin_credentials("org_admin")).unwrap();

        for mode in ["raw-only", "already-copied", "conflict"] {
            let directory = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(directory.path()).unwrap();
            let lock_root = root.join("global-lock-root");
            let credential_root = root.join("credential-store");
            std::fs::create_dir(&credential_root).unwrap();
            let raw_path = FleetAdminCredentials::test_store_path(&credential_root, raw_api_url);
            let canonical_path =
                FleetAdminCredentials::test_store_path(&credential_root, &canonical_origin);
            std::fs::write(&raw_path, &original).unwrap();
            let mut conflicting_encoded = None;
            if mode == "already-copied" {
                std::fs::write(&canonical_path, &original).unwrap();
            } else if mode == "conflict" {
                let mut conflicting = admin_credentials("org_admin");
                conflicting.refresh_token = "different-rotating-token".to_owned();
                let encoded = serde_json::to_string(&conflicting).unwrap();
                std::fs::write(&canonical_path, &encoded).unwrap();
                conflicting_encoded = Some(encoded);
            }

            let status =
                spawn_admin_migration_child(&lock_root, &credential_root, raw_api_url, mode);
            assert!(status.success(), "migration child {mode} failed: {status}");
            if mode == "conflict" {
                assert_eq!(std::fs::read_to_string(&raw_path).unwrap(), original);
                assert_eq!(
                    std::fs::read_to_string(&canonical_path).unwrap(),
                    conflicting_encoded.unwrap(),
                    "conflicting accounts must remain byte-exact and untouched"
                );
            } else {
                assert!(!raw_path.exists(), "legacy account remained after {mode}");
                assert_eq!(
                    std::fs::read_to_string(&canonical_path).unwrap(),
                    original,
                    "migration must preserve exact credential bytes for {mode}"
                );
            }
        }
    }

    #[test]
    #[ignore = "spawned by fleet_admin_legacy_credential_migration_is_exact_reentrant_and_conflict_closed"]
    fn fleet_admin_credential_migration_process_child() {
        let Some(mode) = std::env::var_os(ADMIN_MIGRATION_CHILD_MODE) else {
            return;
        };
        let mode = mode.to_str().unwrap();
        let api_url = std::env::var(ADMIN_MIGRATION_API_URL).unwrap();
        let lock = FleetAdminStateLock::acquire(&api_url).unwrap();
        let result = lock.load_credentials(&api_url);
        if mode == "conflict" {
            let error = format!("{:#}", result.unwrap_err());
            assert!(
                error.contains("canonical and legacy fleet-administrator credentials disagree"),
                "{error}"
            );
        } else {
            assert_eq!(result.unwrap(), Some(admin_credentials("org_admin")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn fleet_admin_lock_identity_changes_fail_before_credentials_or_network() {
        for (mutation, expected_error) in [
            (
                "rename-root",
                "fleet-administrator lock ancestor identity changed",
            ),
            (
                "replace-lock",
                "fleet-administrator lock path was unlinked or replaced",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(directory.path()).unwrap();
            let lock_root = root.join("global-lock-root");
            let credential_root = root.join("credential-store");
            let config_dir = root.join("config");
            let backup = root.join("old-lock-root");
            let api_url = "https://control.example";
            std::fs::create_dir(&credential_root).unwrap();
            std::fs::create_dir(&config_dir).unwrap();
            let credential_path = FleetAdminCredentials::test_store_path(&credential_root, api_url);
            std::fs::write(
                credential_path,
                serde_json::to_string(&admin_credentials("org_admin")).unwrap(),
            )
            .unwrap();

            let control_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let http_base_url = format!("http://{}", control_listener.local_addr().unwrap());
            let mut holder = spawn_admin_lock_aba_holder(
                &root,
                &lock_root,
                &credential_root,
                &config_dir,
                api_url,
                &http_base_url,
                expected_error,
            );
            wait_for_marker(&marker(&root, "locked"), &mut holder);

            let mut mutator = spawn_admin_lock_aba_mutator(&lock_root, &backup, api_url, mutation);
            let mutator_status = mutator.wait().unwrap();
            assert!(
                mutator_status.success(),
                "{mutation} child failed: {mutator_status}"
            );

            std::fs::write(marker(&root, "release"), b"release").unwrap();
            let holder_status = wait_for_child_without_network(&mut holder, &control_listener);
            assert!(
                holder_status.success(),
                "holder after {mutation} failed its regression oracle: {holder_status}"
            );
            assert!(
                !marker(&root, "credential-audit").exists(),
                "stale holder touched credentials after {mutation}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "spawned by fleet_admin_lock_identity_changes_fail_before_credentials_or_network"]
    fn fleet_admin_lock_aba_process_child() {
        let Some(role) = std::env::var_os(ADMIN_LOCK_ABA_CHILD_ROLE) else {
            return;
        };
        let role = role.to_str().unwrap();
        let api_url = std::env::var(ADMIN_LOCK_ABA_API_URL).unwrap();
        let lock_root = PathBuf::from(std::env::var_os("CATS_TEST_FLEET_ADMIN_LOCK_ROOT").unwrap());
        match role {
            "holder" => {
                let expected = std::env::var(ADMIN_LOCK_ABA_EXPECTED_ERROR).unwrap();
                let error = fleet_admin_session(Some(&api_url))
                    .err()
                    .expect("stale lock holder must fail closed");
                let error = format!("{error:#}");
                assert!(error.contains(&expected), "{error}");
            }
            "rename-root" => {
                let backup = PathBuf::from(std::env::var_os(ADMIN_LOCK_ABA_BACKUP).unwrap());
                std::fs::rename(&lock_root, backup).unwrap();
                let replacement = FleetAdminStateLock::try_acquire(&api_url).unwrap();
                assert!(
                    replacement.is_some(),
                    "replacement root must create an independently lockable inode"
                );
            }
            "replace-lock" => {
                let lock_path =
                    lock_root.join(crate::config::fleet_admin_lock_filename(&api_url).unwrap());
                std::fs::remove_file(lock_path).unwrap();
                let replacement = FleetAdminStateLock::try_acquire(&api_url).unwrap();
                assert!(
                    replacement.is_some(),
                    "replacement path must create an independently lockable inode"
                );
            }
            other => panic!("unknown fleet-administrator ABA child role {other}"),
        }
    }

    #[test]
    #[ignore = "spawned by fleet_admin_refresh_is_serial_across_process_environment_splits"]
    fn fleet_admin_refresh_process_child() {
        let Some(role) = std::env::var_os(ADMIN_REFRESH_CHILD_ROLE) else {
            return;
        };
        let role = role.to_str().unwrap();
        let root = PathBuf::from(std::env::var_os(ADMIN_REFRESH_ROOT).unwrap());
        let api_url = std::env::var(ADMIN_REFRESH_API_URL).unwrap();
        let configured_directory = PathBuf::from(std::env::var_os("CATS_CONFIG_DIR").unwrap());
        assert_eq!(
            crate::config::config_path(),
            configured_directory.join("config.json")
        );

        if role == "second" {
            assert!(
                FleetAdminStateLock::try_acquire(&api_url)
                    .unwrap()
                    .is_none(),
                "HOME/XDG_DATA_HOME/CATS_CONFIG_DIR splits must contend on one API credential"
            );
            std::fs::write(marker(&root, "second-saw-contention"), b"contended").unwrap();
        }
        let session = fleet_admin_session(Some(&api_url)).unwrap();
        assert_eq!(session.api_url, canonical_https_origin(&api_url).unwrap());
        std::fs::write(
            marker(&root, &format!("{role}-observed-access")),
            session.access_token,
        )
        .unwrap();
    }
}

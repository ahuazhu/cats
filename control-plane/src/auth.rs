//! WorkOS AuthKit integration for browser sessions and CLI device login.
//!
//! Browser sessions use separate encrypted, HttpOnly cookies for the user and
//! administrator sites. The CLI sends short-lived WorkOS access JWTs, which
//! are verified against WorkOS JWKS on every API request. A WorkOS
//! Organization is mapped explicitly to one Cats workspace/project; an
//! organization-less AuthKit user receives an isolated personal workspace.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use workos::enums::UserOrganizationMembershipStatus;
use workos::helpers::{
    seal, seal_session, unseal, AuthKitAuthorizationUrlParams, AuthKitPkceCodeExchangeParams,
    SessionData, SessionManager, SessionRefreshOptions, SessionState,
};
use workos::models::RevokeSession;
use workos::resources::organization_membership::ListOrganizationMembershipsParams;
use workos::resources::user_management::RevokeSessionParams;

use cats_api::auth::{CliAuthConfigResponse, MeResponse, UserProfile, Workspace, WorkspaceKind};
use cats_api::error::ApiError;

use crate::api::Failure;
use crate::server::AppState;

const USER_SESSION_COOKIE: &str = "cats_user_session";
const ADMIN_SESSION_COOKIE: &str = "cats_admin_session";
const USER_FLOW_COOKIE: &str = "cats_user_auth_flow";
const ADMIN_FLOW_COOKIE: &str = "cats_admin_auth_flow";
const SESSION_MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
const FLOW_MAX_AGE_SECONDS: u64 = 10 * 60;
const FLOW_MAX_AGE_UNIX_SECONDS: i64 = 10 * 60;

#[derive(Clone)]
pub struct WorkOsConfig {
    client: workos::Client,
    client_id: String,
    api_base_url: String,
    issuer_url: String,
    jwks: Arc<workos::helpers::JwksHelper>,
    redirect_uri: String,
    cookie_password: String,
    project_organizations: BTreeMap<String, String>,
    admin_organization_id: String,
    admin_permission: String,
    cookie_secure: bool,
    cookie_domain: Option<String>,
    user_site_url: String,
    admin_site_url: String,
}

pub struct WorkOsConfigParams {
    pub client_id: String,
    pub api_key: String,
    pub api_base_url: String,
    /// Exact `iss` claim published in this WorkOS application's access tokens.
    pub issuer_url: String,
    pub redirect_uri: String,
    pub cookie_password: String,
    /// Cats project -> WorkOS Organization ID.
    pub project_organizations: BTreeMap<String, String>,
    pub admin_organization_id: String,
    pub admin_permission: String,
    pub cookie_secure: bool,
    /// Optional parent domain used when user/admin sites are on subdomains.
    pub cookie_domain: Option<String>,
    /// Login completion destinations. Relative paths preserve local-dev behavior.
    pub user_site_url: Option<String>,
    pub admin_site_url: Option<String>,
}

impl WorkOsConfig {
    pub fn new(params: WorkOsConfigParams) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !params.client_id.is_empty(),
            "WorkOS client ID must not be empty"
        );
        anyhow::ensure!(
            !params.api_key.is_empty(),
            "WorkOS API key must not be empty"
        );
        anyhow::ensure!(
            !params.project_organizations.is_empty(),
            "at least one WorkOS project/organization mapping is required"
        );
        anyhow::ensure!(
            !params.admin_organization_id.is_empty(),
            "WorkOS admin organization ID must not be empty"
        );
        anyhow::ensure!(
            !params.admin_permission.is_empty(),
            "WorkOS admin permission must not be empty"
        );
        let mut organization_ids = BTreeSet::new();
        for (project, organization_id) in &params.project_organizations {
            anyhow::ensure!(!project.is_empty(), "Cats project name must not be empty");
            anyhow::ensure!(
                !organization_id.is_empty(),
                "WorkOS organization ID must not be empty"
            );
            anyhow::ensure!(
                organization_ids.insert(organization_id),
                "a WorkOS organization may map to only one Cats project"
            );
        }
        // Exercise the SDK's password validation at startup rather than on
        // the first user login. The sealed value is immediately discarded.
        seal(&"cats-cookie-password-check", &params.cookie_password)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        let redirect = reqwest::Url::parse(&params.redirect_uri)
            .map_err(|error| anyhow::anyhow!("invalid WorkOS redirect URI: {error}"))?;
        anyhow::ensure!(
            matches!(redirect.scheme(), "http" | "https"),
            "WorkOS redirect URI must use http or https"
        );
        let issuer = reqwest::Url::parse(&params.issuer_url)
            .map_err(|error| anyhow::anyhow!("invalid WorkOS issuer URL: {error}"))?;
        anyhow::ensure!(
            matches!(issuer.scheme(), "http" | "https")
                && issuer.host_str().is_some()
                && issuer.query().is_none()
                && issuer.fragment().is_none(),
            "WorkOS issuer must be an absolute http(s) URL without a query or fragment"
        );
        if let Some(domain) = &params.cookie_domain {
            anyhow::ensure!(
                !domain.is_empty()
                    && !domain.starts_with('.')
                    && !domain
                        .chars()
                        .any(|ch| ch.is_whitespace() || ch == ';' || ch == '/'),
                "WorkOS cookie domain must be a bare DNS name"
            );
        }
        let user_site_url = params.user_site_url.unwrap_or_else(|| "/user/".into());
        let admin_site_url = params.admin_site_url.unwrap_or_else(|| "/admin/".into());
        validate_site_url(&user_site_url, "user")?;
        validate_site_url(&admin_site_url, "admin")?;

        let client_id = params.client_id.clone();
        let api_base_url = params.api_base_url.trim_end_matches('/').to_string();
        let issuer_url = params.issuer_url;
        let client = workos::Client::builder()
            .client_id(&client_id)
            .api_key(params.api_key)
            .base_url(&api_base_url)
            .try_build()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let jwks = Arc::new(client.jwks());
        Ok(Self {
            client,
            client_id,
            api_base_url,
            issuer_url,
            jwks,
            redirect_uri: params.redirect_uri,
            cookie_password: params.cookie_password,
            project_organizations: params.project_organizations,
            admin_organization_id: params.admin_organization_id,
            admin_permission: params.admin_permission,
            cookie_secure: params.cookie_secure,
            cookie_domain: params.cookie_domain,
            user_site_url,
            admin_site_url,
        })
    }

    fn project_for_organization(&self, organization_id: &str) -> Option<&str> {
        self.project_organizations
            .iter()
            .find_map(|(project, candidate)| {
                (candidate == organization_id).then_some(project.as_str())
            })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    /// Verify a CLI bearer token cryptographically and turn its organization
    /// scope into the existing Cats project namespace. A valid token for an
    /// unmapped organization remains authenticated but has no project access.
    pub async fn verify_access_token(&self, token: &str) -> Result<AccessIdentity, ApiError> {
        let header = decode_header(token)
            .map_err(|_| ApiError::unauthenticated("invalid WorkOS access token"))?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::unauthenticated(
                "unsupported WorkOS access token algorithm",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| ApiError::unauthenticated("WorkOS access token has no key ID"))?;
        let keys = self.jwks.fetch().await.map_err(|error| {
            tracing::warn!(error = %error, "WorkOS JWKS fetch failed");
            ApiError::unavailable("WorkOS signing keys are temporarily unavailable")
        })?;
        let jwk = keys
            .keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .ok_or_else(|| ApiError::unauthenticated("unknown WorkOS signing key"))?;
        if jwk.kty.as_deref() != Some("RSA") || jwk.alg.as_deref() != Some("RS256") {
            return Err(ApiError::unauthenticated("invalid WorkOS signing key"));
        }
        let modulus = jwk
            .other
            .get("n")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let exponent = jwk
            .other
            .get("e")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let key = DecodingKey::from_rsa_components(modulus, exponent)
            .map_err(|_| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.set_issuer(&[self.issuer_url.as_str()]);
        let claims = decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    kid,
                    "WorkOS access token validation failed"
                );
                ApiError::unauthenticated("invalid or expired WorkOS access token")
            })?
            .claims;
        if claims.client_id != self.client_id || claims.sub.is_empty() || claims.sid.is_empty() {
            return Err(ApiError::unauthenticated(
                "WorkOS access token belongs to another application",
            ));
        }
        let organization_id = claims.org_id.filter(|value| !value.is_empty());
        let project = organization_id
            .as_deref()
            .and_then(|org| self.project_for_organization(org).map(str::to_string))
            .or_else(|| {
                organization_id
                    .is_none()
                    .then(|| format!("personal-{}", claims.sub))
            });
        Ok(AccessIdentity {
            user_id: claims.sub,
            session_id: claims.sid,
            organization_id,
            project,
            role: claims.role,
            permissions: claims.permissions,
        })
    }

    pub async fn me(&self, identity: &AccessIdentity) -> Result<MeResponse, ApiError> {
        let user = self
            .client
            .user_management()
            .get_user(&identity.user_id)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "WorkOS user lookup failed");
                ApiError::unavailable("WorkOS user profile is temporarily unavailable")
            })?;
        Ok(MeResponse {
            user: UserProfile {
                id: user.id,
                email: user.email,
                name: user.name.or_else(|| {
                    let joined = [user.first_name, user.last_name]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" ");
                    (!joined.is_empty()).then_some(joined)
                }),
            },
            workspaces: self.workspaces_for(identity).await?,
        })
    }

    pub async fn workspaces_for(
        &self,
        identity: &AccessIdentity,
    ) -> Result<Vec<Workspace>, ApiError> {
        let mut result = Vec::new();
        if identity.organization_id.is_none() {
            let slug = format!("personal-{}", identity.user_id);
            result.push(Workspace {
                display_name: "Personal".to_string(),
                slug,
                kind: WorkspaceKind::Personal,
                organization_id: None,
                role: Some("owner".to_string()),
            });
        }
        let mut after = None;
        loop {
            let page = self
                .client
                .organization_membership()
                .list_organization_memberships(ListOrganizationMembershipsParams {
                    after: after.clone(),
                    limit: Some(100),
                    user_id: Some(identity.user_id.clone()),
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    tracing::warn!(error = %error, "WorkOS organization membership lookup failed");
                    ApiError::unavailable(
                        "WorkOS workspace memberships are temporarily unavailable",
                    )
                })?;
            for membership in page.data {
                if membership.status != UserOrganizationMembershipStatus::Active {
                    continue;
                }
                let Some(slug) = self
                    .project_for_organization(&membership.organization_id)
                    .map(str::to_string)
                else {
                    continue;
                };
                result.push(Workspace {
                    display_name: membership.organization_name.unwrap_or_else(|| slug.clone()),
                    slug,
                    kind: WorkspaceKind::Organization,
                    organization_id: Some(membership.organization_id),
                    role: Some(membership.role.slug),
                });
            }
            after = page.list_metadata.after;
            if after.is_none() {
                break;
            }
        }
        result.sort_by(|left, right| left.slug.cmp(&right.slug));
        result.dedup_by(|left, right| left.slug == right.slug);
        Ok(result)
    }

    pub async fn revoke_cli_session(&self, identity: &AccessIdentity) -> Result<(), ApiError> {
        let params = RevokeSessionParams::new(RevokeSession {
            session_id: identity.session_id.clone(),
        });
        self.client
            .user_management()
            .revoke_session(params)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "WorkOS CLI session revocation failed");
                ApiError::unavailable("WorkOS session could not be revoked")
            })?;
        Ok(())
    }

    pub fn is_fleet_administrator(&self, identity: &AccessIdentity) -> bool {
        identity.organization_id.as_deref() == Some(self.admin_organization_id.as_str())
            && identity
                .permissions
                .iter()
                .any(|permission| permission == &self.admin_permission)
    }

    fn site_url(&self, site: Site) -> &str {
        match site {
            Site::User => &self.user_site_url,
            Site::Admin => &self.admin_site_url,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessIdentity {
    pub user_id: String,
    pub session_id: String,
    pub organization_id: Option<String>,
    pub project: Option<String>,
    pub role: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    sub: String,
    sid: String,
    client_id: String,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[allow(dead_code)]
    exp: u64,
    #[allow(dead_code)]
    iss: String,
}

fn validate_site_url(value: &str, site: &str) -> anyhow::Result<()> {
    if value.starts_with('/') && !value.starts_with("//") {
        return Ok(());
    }
    let url = reqwest::Url::parse(value)
        .map_err(|error| anyhow::anyhow!("invalid {site} site URL: {error}"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{site} site URL must be an absolute HTTP(S) URL without query or fragment"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Site {
    User,
    Admin,
}

impl Site {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::User => "/user/",
            Self::Admin => "/admin/",
        }
    }

    fn session_cookie(self) -> &'static str {
        match self {
            Self::User => USER_SESSION_COOKIE,
            Self::Admin => ADMIN_SESSION_COOKIE,
        }
    }

    fn flow_cookie(self) -> &'static str {
        match self {
            Self::User => USER_FLOW_COOKIE,
            Self::Admin => ADMIN_FLOW_COOKIE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebIdentity {
    pub project: Option<String>,
    pub administrator: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginFlow {
    state: String,
    code_verifier: String,
    site: Site,
    organization_id: Option<String>,
    project: Option<String>,
    return_to: String,
    created_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    site: String,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SiteQuery {
    site: String,
}

#[derive(Debug, Serialize)]
struct SessionUser {
    id: String,
    email: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    authenticated: bool,
    site: Site,
    project: Option<String>,
    role: String,
    permissions: Vec<String>,
    user: Option<SessionUser>,
}

pub async fn config(State(state): State<AppState>) -> Response {
    let mut response = Json(CliAuthConfigResponse {
        workos_enabled: state.cfg.workos.is_some(),
        workos_client_id: state
            .cfg
            .workos
            .as_ref()
            .map(|config| config.client_id().to_string()),
        workos_api_base_url: state
            .cfg
            .workos
            .as_ref()
            .map(|config| config.api_base_url().to_string()),
    })
    .into_response();
    set_no_store(&mut response);
    response
}

pub async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let site = Site::parse(&query.site).ok_or_else(|| ApiError::invalid("unknown auth site"))?;
    let (organization_id, project) = match site {
        Site::User => {
            if let Some(project) = query.project.as_deref() {
                if project.starts_with("personal-user_") {
                    (None, Some(project.to_string()))
                } else {
                    let organization_id =
                        config.project_organizations.get(project).ok_or_else(|| {
                            ApiError::new(cats_api::error::ErrorCode::NotFound, "unknown project")
                        })?;
                    (Some(organization_id.clone()), Some(project.to_string()))
                }
            } else {
                // The public user site does not know a user's project before
                // authentication. Resolve it from the returned WorkOS identity.
                (None, None)
            }
        }
        Site::Admin => (Some(config.admin_organization_id.clone()), None),
    };
    let return_to = query
        .return_to
        .as_deref()
        .filter(|value| *value == site.root() || *value == config.site_url(site))
        .map(str::to_string)
        .unwrap_or_else(|| config.site_url(site).to_string());
    let authorization = config
        .client
        .authkit()
        .pkce_authorization_url(AuthKitAuthorizationUrlParams {
            redirect_uri: config.redirect_uri.clone(),
            provider: Some("authkit".to_string()),
            organization_id: organization_id.clone(),
            ..Default::default()
        })
        .map_err(|error| ApiError::internal(format!("build WorkOS authorization URL: {error}")))?;
    let flow = LoginFlow {
        state: authorization.state,
        code_verifier: authorization.code_verifier,
        site,
        organization_id,
        project,
        return_to,
        created_at_unix: crate::store::now_unix(),
    };
    let sealed = seal(&flow, &config.cookie_password)
        .map_err(|error| ApiError::internal(format!("seal WorkOS login state: {error}")))?;
    let mut response = Redirect::to(&authorization.url).into_response();
    append_set_cookie(
        &mut response,
        site.flow_cookie(),
        &sealed,
        FLOW_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    if let Some(error) = query.error {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::Unauthenticated,
            format!("WorkOS authentication was not completed: {error}"),
        )
        .into());
    }
    let code = query
        .code
        .ok_or_else(|| ApiError::invalid("missing WorkOS authorization code"))?;
    let returned_state = query
        .state
        .ok_or_else(|| ApiError::invalid("missing WorkOS state"))?;
    let flow = [Site::User, Site::Admin]
        .into_iter()
        .filter_map(|site| {
            cookie_value(&headers, site.flow_cookie()).and_then(|sealed| {
                unseal::<LoginFlow>(&sealed, &config.cookie_password)
                    .ok()
                    .filter(|flow| flow.site == site && flow.state == returned_state)
            })
        })
        .next()
        .ok_or_else(|| {
            ApiError::new(
                cats_api::error::ErrorCode::Unauthenticated,
                "invalid or expired WorkOS login state",
            )
        })?;
    if crate::store::now_unix() - flow.created_at_unix > FLOW_MAX_AGE_UNIX_SECONDS {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::Unauthenticated,
            "WorkOS login state expired",
        )
        .into());
    }

    let auth = config
        .client
        .authkit()
        .pkce_code_exchange(AuthKitPkceCodeExchangeParams {
            code,
            code_verifier: flow.code_verifier.clone(),
        })
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "WorkOS authorization-code exchange failed");
            ApiError::new(
                cats_api::error::ErrorCode::Unauthenticated,
                "WorkOS authentication failed",
            )
        })?;
    if flow
        .organization_id
        .as_deref()
        .is_some_and(|expected| auth.organization_id.as_deref() != Some(expected))
    {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::PermissionDenied,
            "WorkOS session organization does not match the requested workspace",
        )
        .into());
    }
    let sealed_session = seal_session(
        &SessionData {
            access_token: auth.access_token,
            refresh_token: auth.refresh_token,
            user: Some(auth.user),
            impersonator: auth.impersonator,
        },
        &config.cookie_password,
    )
    .map_err(|error| ApiError::internal(format!("seal WorkOS session: {error}")))?;
    let session =
        SessionManager::new(None, &sealed_session, &config.cookie_password).authenticate();
    validate_flow_identity(config, &flow, &session)?;

    let mut response = Redirect::to(&flow.return_to).into_response();
    append_set_cookie(
        &mut response,
        flow.site.session_cookie(),
        &sealed_session,
        SESSION_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    append_delete_cookie(
        &mut response,
        flow.site.flow_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SiteQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let site = Site::parse(&query.site).ok_or_else(|| ApiError::invalid("unknown auth site"))?;
    let sealed = cookie_value(&headers, site.session_cookie()).unwrap_or_default();
    let manager = SessionManager::new(Some(&config.client), &sealed, &config.cookie_password);
    let mut session = manager.authenticate();
    let mut replacement_cookie = None;
    if session.needs_refresh {
        let refreshed = manager
            .refresh(SessionRefreshOptions::default())
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "WorkOS session refresh failed");
                ApiError::new(
                    cats_api::error::ErrorCode::Unauthenticated,
                    "WorkOS session expired",
                )
            })?;
        if refreshed.authenticated {
            replacement_cookie = Some(refreshed.sealed_session);
            session = SessionManager::new(
                None,
                replacement_cookie.as_deref().unwrap_or_default(),
                &config.cookie_password,
            )
            .authenticate();
        }
    }
    let identity = validate_session_identity(config, site, &session)?;
    let user = session.user.map(|user| SessionUser {
        id: user.id,
        email: user.email,
        name: user.name.or_else(|| {
            let joined = [user.first_name, user.last_name]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            (!joined.is_empty()).then_some(joined)
        }),
    });
    let mut response = Json(SessionResponse {
        authenticated: true,
        site,
        project: identity.project,
        role: session.role,
        permissions: session.permissions,
        user,
    })
    .into_response();
    if let Some(sealed) = replacement_cookie {
        append_set_cookie(
            &mut response,
            site.session_cookie(),
            &sealed,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    set_no_store(&mut response);
    Ok(response)
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SiteQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let site = Site::parse(&query.site).ok_or_else(|| ApiError::invalid("unknown auth site"))?;
    let sealed = cookie_value(&headers, site.session_cookie()).unwrap_or_default();
    let manager = SessionManager::new(Some(&config.client), sealed, &config.cookie_password);
    let session = manager.authenticate();
    if !session.session_id.is_empty() {
        let params = RevokeSessionParams::new(RevokeSession {
            session_id: session.session_id,
        });
        if let Err(error) = config.client.user_management().revoke_session(params).await {
            tracing::warn!(error = %error, "WorkOS session revocation failed");
        }
    }
    let mut response = Redirect::to(config.site_url(site)).into_response();
    append_delete_cookie(
        &mut response,
        site.session_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

fn validate_flow_identity(
    config: &WorkOsConfig,
    flow: &LoginFlow,
    session: &SessionState,
) -> Result<WebIdentity, Failure> {
    let identity = validate_session_identity(config, flow.site, session)?;
    if flow.site == Site::User && flow.organization_id.is_none() && flow.project.is_none() {
        return Ok(identity);
    }
    if flow.site == Site::User && session.organization_id.is_empty() {
        if flow.organization_id.is_none() && flow.project.as_deref() != identity.project.as_deref()
        {
            return Err(ApiError::new(
                cats_api::error::ErrorCode::PermissionDenied,
                "WorkOS session does not match the requested personal workspace",
            )
            .into());
        }
        return Ok(identity);
    }
    if Some(session.organization_id.as_str()) != flow.organization_id.as_deref()
        || identity.project != flow.project
    {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::PermissionDenied,
            "WorkOS session does not match the requested workspace",
        )
        .into());
    }
    Ok(identity)
}

fn validate_session_identity(
    config: &WorkOsConfig,
    site: Site,
    session: &SessionState,
) -> Result<WebIdentity, Failure> {
    if !session.authenticated {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::Unauthenticated,
            "missing, invalid, or expired WorkOS session",
        )
        .into());
    }
    match site {
        Site::User => {
            if session.organization_id.is_empty() {
                let user_id = session
                    .user
                    .as_ref()
                    .map(|user| user.id.as_str())
                    .filter(|user_id| !user_id.is_empty())
                    .ok_or_else(|| {
                        ApiError::new(
                            cats_api::error::ErrorCode::Unauthenticated,
                            "WorkOS personal session has no user identity",
                        )
                    })?;
                return Ok(WebIdentity {
                    project: Some(format!("personal-{user_id}")),
                    administrator: false,
                });
            }
            let project = config
                .project_for_organization(&session.organization_id)
                .ok_or_else(|| {
                    ApiError::new(
                        cats_api::error::ErrorCode::PermissionDenied,
                        "WorkOS organization is not mapped to a Cats project",
                    )
                })?;
            Ok(WebIdentity {
                project: Some(project.to_string()),
                administrator: false,
            })
        }
        Site::Admin => {
            if session.organization_id != config.admin_organization_id
                || !session
                    .permissions
                    .iter()
                    .any(|permission| permission == &config.admin_permission)
            {
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "WorkOS session lacks fleet administrator permission",
                )
                .into());
            }
            Ok(WebIdentity {
                project: None,
                administrator: true,
            })
        }
    }
}

fn identity_from_cookie(state: &AppState, headers: &HeaderMap, site: Site) -> Option<WebIdentity> {
    let config = state.cfg.workos.as_ref()?;
    let sealed = cookie_value(headers, site.session_cookie())?;
    let session = SessionManager::new(None, sealed, &config.cookie_password).authenticate();
    validate_session_identity(config, site, &session).ok()
}

pub fn web_session_allows_project(state: &AppState, headers: &HeaderMap, project: &str) -> bool {
    identity_from_cookie(state, headers, Site::Admin).is_some_and(|identity| identity.administrator)
        || identity_from_cookie(state, headers, Site::User)
            .and_then(|identity| identity.project)
            .is_some_and(|allowed| allowed == project)
}

pub fn web_session_is_admin(state: &AppState, headers: &HeaderMap) -> bool {
    identity_from_cookie(state, headers, Site::Admin).is_some_and(|identity| identity.administrator)
}

pub fn has_any_web_session(state: &AppState, headers: &HeaderMap) -> bool {
    identity_from_cookie(state, headers, Site::User).is_some()
        || identity_from_cookie(state, headers, Site::Admin).is_some()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(candidate, value)| (candidate == name).then(|| value.to_string()))
}

fn append_set_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age_seconds: u64,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    let secure_attribute = if secure { "; Secure" } else { "" };
    let domain_attribute = domain
        .map(|value| format!("; Domain={value}"))
        .unwrap_or_default();
    let cookie = format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure_attribute}{domain_attribute}"
    );
    let value = HeaderValue::from_str(&cookie)
        .map_err(|_| ApiError::internal("failed to encode session cookie"))?;
    response.headers_mut().append(header::SET_COOKIE, value);
    Ok(())
}

fn append_delete_cookie(
    response: &mut Response,
    name: &str,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    append_set_cookie(response, name, "", 0, secure, domain)
}

fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

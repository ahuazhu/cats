use super::session::{validate_flow_identity, UserContext};
use super::*;

pub(super) fn validate_site_url(value: &str, site: &str) -> anyhow::Result<()> {
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
pub(super) enum Site {
    User,
    Admin,
}

impl Site {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    pub(super) fn root(self) -> &'static str {
        match self {
            Self::User => "/user/",
            Self::Admin => "/admin/",
        }
    }

    pub(super) fn session_cookie(self) -> &'static str {
        match self {
            Self::User => USER_SESSION_COOKIE,
            Self::Admin => ADMIN_SESSION_COOKIE,
        }
    }

    pub(super) fn flow_cookie(self) -> &'static str {
        match self {
            Self::User => USER_FLOW_COOKIE,
            Self::Admin => ADMIN_FLOW_COOKIE,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct LoginFlow {
    pub(super) state: String,
    pub(super) code_verifier: String,
    pub(super) site: Site,
    pub(super) organization_id: Option<String>,
    pub(super) workspace_id: Option<String>,
    pub(super) return_to: String,
    pub(super) created_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    site: String,
    #[serde(default)]
    workspace: Option<String>,
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
        workos_admin_organization_id: state
            .cfg
            .workos
            .as_ref()
            .map(|config| config.admin_organization_id.clone()),
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
    let (organization_id, workspace_id) = match site {
        Site::User => {
            if let Some(workspace_id) = query.workspace.as_deref() {
                let workspace_id = workspace_id.to_string();
                let lookup_workspace_id = workspace_id.clone();
                let scope = state
                    .store
                    .execute(move |store| store.workspace_scope(&lookup_workspace_id))
                    .await?;
                (
                    Some(scope.account.workos_organization_id),
                    Some(workspace_id.to_string()),
                )
            } else {
                // The public user site does not know which workspace a user
                // owns before authentication. Resolve it from the returned
                // WorkOS identity.
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
        workspace_id,
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
    let returned_state = query
        .state
        .ok_or_else(|| ApiError::invalid("missing WorkOS state"))?;
    let flow = [Site::User, Site::Admin]
        .into_iter()
        .find_map(|site| {
            cookie_values(&headers, site.flow_cookie())
                .into_iter()
                .rev()
                .find_map(|sealed| {
                    unseal::<LoginFlow>(&sealed, &config.cookie_password)
                        .ok()
                        .filter(|flow| flow.site == site && flow.state == returned_state)
                })
        })
        .ok_or_else(|| {
            ApiError::new(
                cats_protocol::error::ErrorCode::Unauthenticated,
                "invalid or expired WorkOS login state",
            )
        })?;
    if crate::store::now_unix() - flow.created_at_unix > FLOW_MAX_AGE_UNIX_SECONDS {
        return Err(ApiError::new(
            cats_protocol::error::ErrorCode::Unauthenticated,
            "WorkOS login state expired",
        )
        .into());
    }
    if let Some(error) = query.error {
        tracing::warn!(site = ?flow.site, error, "WorkOS authentication was not completed");
        return auth_error_redirect(config, &flow, "authentication_failed");
    }
    let code = query
        .code
        .ok_or_else(|| ApiError::invalid("missing WorkOS authorization code"))?;

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
                cats_protocol::error::ErrorCode::Unauthenticated,
                "WorkOS authentication failed",
            )
        })?;
    if flow
        .organization_id
        .as_deref()
        .is_some_and(|expected| auth.organization_id.as_deref() != Some(expected))
    {
        tracing::warn!(
            site = ?flow.site,
            "WorkOS session organization does not match the requested scope"
        );
        return auth_error_redirect(config, &flow, identity_error_code(flow.site));
    }
    let personal_scope = if flow.site == Site::User && auth.organization_id.is_none() {
        let display_name = auth
            .user
            .name
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&auth.user.email);
        Some(
            provision_personal_account(&state, &auth.user.id, display_name)
                .await?
                .workos_organization_id,
        )
    } else {
        None
    };
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
    let (sealed_session, session) = if let Some(organization_id) = personal_scope {
        scope_session_to_organization(
            config,
            sealed_session,
            session,
            &organization_id,
            "personal account",
        )
        .await?
    } else {
        scope_unmapped_user_session(config, &state.store, &flow, sealed_session, session).await
    };
    let validation_config = state
        .cfg
        .workos
        .clone()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let validation_flow = flow.clone();
    let validation_session = session.clone();
    let identity = match state
        .store
        .execute(move |store| {
            validate_flow_identity(
                &validation_config,
                store,
                &validation_flow,
                &validation_session,
            )
            .map_err(|failure| failure.0)
        })
        .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                site = ?flow.site,
                error = %error,
                "WorkOS session is not authorized for the requested site"
            );
            return auth_error_redirect(config, &flow, identity_error_code(flow.site));
        }
    };

    let mut response = Redirect::to(&flow.return_to).into_response();
    append_set_cookie(
        &mut response,
        flow.site.session_cookie(),
        &sealed_session,
        SESSION_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    if flow.site == Site::User {
        let workspace_id = if let Some(workspace_id) = flow.workspace_id.as_deref() {
            workspace_id.to_string()
        } else {
            identity
                .default_workspace_id
                .clone()
                .ok_or_else(|| ApiError::internal("user login selected no workspace"))?
        };
        let workspace = state
            .store
            .execute(move |store| store.workspace_by_id(&workspace_id))
            .await?;
        let user_id = identity
            .user_id
            .as_deref()
            .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
        let context = seal(
            &UserContext {
                user_id: user_id.to_string(),
                account_id: workspace.account_id,
                workspace_id: workspace.id,
            },
            &config.cookie_password,
        )
        .map_err(|error| ApiError::internal(format!("seal workspace context: {error}")))?;
        append_set_cookie(
            &mut response,
            USER_CONTEXT_COOKIE,
            &context,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    if !session.session_id.is_empty() {
        config
            .browser_session_heads
            .lock()
            .await
            .insert(session.session_id.clone(), sealed_session);
    }
    append_delete_cookie(
        &mut response,
        flow.site.flow_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

pub(super) async fn scope_session_to_organization(
    config: &WorkOsConfig,
    sealed_session: String,
    session: SessionState,
    organization_id: &str,
    label: &str,
) -> Result<(String, SessionState), Failure> {
    let user_id = session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
    let manager = SessionManager::new(
        Some(&config.client),
        &sealed_session,
        &config.cookie_password,
    );
    let refreshed = manager
        .refresh(SessionRefreshOptions {
            organization_id: Some(organization_id.to_string()),
        })
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, organization_id, label, "WorkOS organization switch failed");
            ApiError::unavailable("WorkOS organization switch is temporarily unavailable")
        })?;
    if !refreshed.authenticated {
        return Err(ApiError::new(
            cats_protocol::error::ErrorCode::PermissionDenied,
            format!("WorkOS did not authorize {label}"),
        )
        .into());
    }
    let candidate = SessionManager::new(None, &refreshed.sealed_session, &config.cookie_password)
        .authenticate();
    if !candidate.authenticated
        || candidate.organization_id != organization_id
        || candidate.user.as_ref().map(|user| user.id.as_str()) != Some(user_id.as_str())
    {
        return Err(ApiError::new(
            cats_protocol::error::ErrorCode::PermissionDenied,
            format!("WorkOS returned an invalid {label} session"),
        )
        .into());
    }
    Ok((refreshed.sealed_session, candidate))
}

async fn scope_unmapped_user_session(
    config: &WorkOsConfig,
    store: &std::sync::Arc<crate::store::Store>,
    flow: &LoginFlow,
    sealed_session: String,
    session: SessionState,
) -> (String, SessionState) {
    let organization_id = session.organization_id.clone();
    let account_is_unmapped = store
        .execute(move |store| Ok(store.account_for_organization(&organization_id)?.is_none()))
        .await
        .unwrap_or(false);
    let should_rescope = flow.site == Site::User
        && flow.organization_id.is_none()
        && flow.workspace_id.is_none()
        && session.authenticated
        && !session.organization_id.is_empty()
        && account_is_unmapped;
    if !should_rescope {
        return (sealed_session, session);
    }
    let Some(user_id) = session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|user_id| !user_id.is_empty())
    else {
        return (sealed_session, session);
    };
    let target = match config
        .single_mapped_workspace_for_user(store, &user_id)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => return (sealed_session, session),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "WorkOS user workspace resolution failed"
            );
            return (sealed_session, session);
        }
    };
    let (workspace_id, organization_id) = target;
    let manager = SessionManager::new(
        Some(&config.client),
        &sealed_session,
        &config.cookie_password,
    );
    let refreshed = match manager
        .refresh(SessionRefreshOptions {
            organization_id: Some(organization_id.clone()),
        })
        .await
    {
        Ok(refreshed) if refreshed.authenticated => refreshed,
        Ok(refreshed) => {
            tracing::warn!(
                reason = refreshed.reason,
                workspace_id,
                "WorkOS session could not switch to the user's Cats workspace"
            );
            return (sealed_session, session);
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                workspace_id,
                "WorkOS workspace session refresh failed"
            );
            return (sealed_session, session);
        }
    };
    let candidate = SessionManager::new(None, &refreshed.sealed_session, &config.cookie_password)
        .authenticate();
    let same_user = candidate.user.as_ref().map(|user| user.id.as_str()) == Some(user_id.as_str());
    if !candidate.authenticated
        || candidate.organization_id != organization_id
        || !same_user
        || !store
            .execute({
                let workspace_id = workspace_id.clone();
                let organization_id = candidate.organization_id.clone();
                move |store| {
                    let workspace = store.workspace_by_id(&workspace_id)?;
                    let account = store.account_by_id(&workspace.account_id)?;
                    Ok(account.workos_organization_id == organization_id)
                }
            })
            .await
            .unwrap_or(false)
    {
        tracing::warn!(
            workspace_id,
            "WorkOS returned an invalid workspace-scoped session"
        );
        return (sealed_session, session);
    }
    (refreshed.sealed_session, candidate)
}

fn identity_error_code(site: Site) -> &'static str {
    match site {
        Site::User => "workspace_access_required",
        Site::Admin => "admin_access_required",
    }
}

fn auth_error_redirect(
    config: &WorkOsConfig,
    flow: &LoginFlow,
    error_code: &str,
) -> Result<Response, Failure> {
    let separator = if flow.return_to.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!("{}{separator}auth_error={error_code}", flow.return_to);
    let mut response = Redirect::to(&location).into_response();
    append_delete_cookie(
        &mut response,
        flow.site.flow_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

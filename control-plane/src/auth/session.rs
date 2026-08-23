use super::web_flow::{scope_session_to_organization, LoginFlow, Site};
use super::workos_client::workos_user_profile;
use super::*;

#[derive(Debug, Clone)]
pub struct WebIdentity {
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub account_id: Option<String>,
    pub default_workspace_id: Option<String>,
    pub administrator: bool,
    pub permissions: Vec<String>,
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
    active_account_id: Option<String>,
    active_workspace_id: Option<String>,
    accounts: Vec<Account>,
    workspaces: Vec<Workspace>,
    role: String,
    permissions: Vec<String>,
    user: Option<SessionUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct UserContext {
    pub(super) user_id: String,
    pub(super) account_id: String,
    pub(super) workspace_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SwitchWorkspaceRequest {
    workspace_id: String,
}

fn best_session_cookie(
    config: &WorkOsConfig,
    headers: &HeaderMap,
    cookie_name: &str,
) -> Option<(String, SessionState)> {
    let mut refreshable = None;
    for sealed in cookie_values(headers, cookie_name).into_iter().rev() {
        let session =
            SessionManager::new(None, sealed.clone(), &config.cookie_password).authenticate();
        if session.authenticated {
            return Some((sealed, session));
        }
        if session.needs_refresh && refreshable.is_none() {
            refreshable = Some((sealed, session));
        }
    }
    refreshable
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
    let (sealed, mut session) = best_session_cookie(config, &headers, site.session_cookie())
        .unwrap_or_else(|| {
            let sealed = String::new();
            let session =
                SessionManager::new(None, &sealed, &config.cookie_password).authenticate();
            (sealed, session)
        });
    let manager = SessionManager::new(Some(&config.client), &sealed, &config.cookie_password);
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
    let (body, replacement_context) =
        session_response(&state, config, site, &session, &headers).await?;
    let mut response = Json(body).into_response();
    if let Some(sealed) = replacement_cookie {
        if !session.session_id.is_empty() {
            config
                .browser_session_heads
                .lock()
                .await
                .insert(session.session_id.clone(), sealed.clone());
        }
        append_set_cookie(
            &mut response,
            site.session_cookie(),
            &sealed,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    if let Some(context) = replacement_context {
        append_set_cookie(
            &mut response,
            USER_CONTEXT_COOKIE,
            &context,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    set_no_store(&mut response);
    Ok(response)
}

pub async fn switch_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SwitchWorkspaceRequest>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let (requested_sealed, requested_session) =
        best_session_cookie(config, &headers, USER_SESSION_COOKIE)
            .ok_or_else(|| ApiError::unauthenticated("missing WorkOS user session"))?;
    if !requested_session.authenticated || requested_session.session_id.is_empty() {
        return Err(ApiError::unauthenticated("invalid WorkOS user session").into());
    }
    let requested_user_id = requested_session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
    let workspace_id = request.workspace_id;
    let (workspace, account) = state
        .store
        .execute(move |store| {
            let workspace = store.workspace_by_id(&workspace_id)?;
            let account = store.account_by_id(&workspace.account_id)?;
            Ok((workspace, account))
        })
        .await?;
    if account.status != "active"
        || !config
            .user_has_active_membership(&requested_user_id, &account.workos_organization_id)
            .await?
    {
        return Err(ApiError::new(
            ErrorCode::PermissionDenied,
            "workspace is not available to this user",
        )
        .into());
    }

    // WorkOS refresh tokens rotate. Serialize scope changes and always start
    // from the latest sealed head for this WorkOS session, not the possibly
    // stale cookie carried by a concurrently submitted browser tab.
    let mut heads = config.browser_session_heads.lock().await;
    let current_sealed = heads
        .get(&requested_session.session_id)
        .cloned()
        .unwrap_or(requested_sealed);
    let current_session =
        SessionManager::new(None, &current_sealed, &config.cookie_password).authenticate();
    if !current_session.authenticated
        || current_session.session_id != requested_session.session_id
        || current_session.user.as_ref().map(|user| user.id.as_str())
            != Some(requested_user_id.as_str())
    {
        return Err(ApiError::unauthenticated("WorkOS user session expired").into());
    }
    let (active_sealed, active_session, switched_account) =
        if current_session.organization_id == account.workos_organization_id {
            (current_sealed, current_session, false)
        } else {
            let (sealed, session) = scope_session_to_organization(
                config,
                current_sealed,
                current_session,
                &account.workos_organization_id,
                "account",
            )
            .await?;
            (sealed, session, true)
        };
    heads.insert(active_session.session_id.clone(), active_sealed.clone());
    drop(heads);

    let context = seal(
        &UserContext {
            user_id: requested_user_id,
            account_id: account.id,
            workspace_id: workspace.id,
        },
        &config.cookie_password,
    )
    .map_err(|error| ApiError::internal(format!("seal workspace context: {error}")))?;
    let mut context_headers = HeaderMap::new();
    context_headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{USER_CONTEXT_COOKIE}={context}"))
            .map_err(|_| ApiError::internal("workspace context cookie is invalid"))?,
    );
    let (body, _) = session_response(
        &state,
        config,
        Site::User,
        &active_session,
        &context_headers,
    )
    .await?;
    let mut response = Json(body).into_response();
    if switched_account {
        append_set_cookie(
            &mut response,
            USER_SESSION_COOKIE,
            &active_sealed,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    append_set_cookie(
        &mut response,
        USER_CONTEXT_COOKIE,
        &context,
        SESSION_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

async fn session_response(
    state: &AppState,
    config: &WorkOsConfig,
    site: Site,
    session: &SessionState,
    headers: &HeaderMap,
) -> Result<(SessionResponse, Option<String>), Failure> {
    let session = session.clone();
    let validation_session = session.clone();
    let validation_config = config.clone();
    let identity = state
        .store
        .execute(move |store| {
            validate_session_identity(&validation_config, store, site, &validation_session)
                .map_err(|failure| failure.0)
        })
        .await?;
    let user = session
        .user
        .clone()
        .map(workos_user_profile)
        .map(|user| SessionUser {
            id: user.id,
            email: user.email,
            name: user.name,
        });
    if site == Site::Admin {
        return Ok((
            SessionResponse {
                authenticated: true,
                site,
                active_account_id: None,
                active_workspace_id: None,
                accounts: Vec::new(),
                workspaces: Vec::new(),
                role: session.role.clone(),
                permissions: session.permissions.clone(),
                user,
            },
            None,
        ));
    }
    let user_id = identity
        .user_id
        .as_deref()
        .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
    let organization_id = identity.organization_id.as_deref().ok_or_else(|| {
        ApiError::new(ErrorCode::PermissionDenied, "session has no account scope")
    })?;
    if !config
        .user_has_active_membership(user_id, organization_id)
        .await?
    {
        return Err(ApiError::new(
            ErrorCode::PermissionDenied,
            "WorkOS account membership is not active",
        )
        .into());
    }
    let access = AccessIdentity {
        user_id: user_id.to_string(),
        session_id: session.session_id.clone(),
        organization_id: Some(organization_id.to_string()),
        role: Some(session.role.clone()),
        permissions: session.permissions.clone(),
    };
    let (accounts, workspaces) = config
        .accounts_and_workspaces_for(&state.store, &access)
        .await?;
    let current_account_id = identity
        .account_id
        .as_deref()
        .ok_or_else(|| ApiError::internal("session account resolution failed"))?;
    let sealed_context = cookie_value(headers, USER_CONTEXT_COOKIE);
    let context = sealed_context
        .as_deref()
        .and_then(|sealed| unseal::<UserContext>(sealed, &config.cookie_password).ok())
        .filter(|context| {
            context.user_id == user_id
                && context.account_id == current_account_id
                && workspaces.iter().any(|workspace| {
                    workspace.id == context.workspace_id
                        && workspace.account_id == context.account_id
                })
        });
    let (selected, replacement_context) = if let Some(context) = context {
        let selected = workspaces
            .iter()
            .find(|workspace| workspace.id == context.workspace_id)
            .cloned()
            .ok_or_else(|| ApiError::internal("workspace context validation drifted"))?;
        (selected, None)
    } else {
        let selected = workspaces
            .iter()
            .find(|workspace| workspace.account_id == current_account_id && workspace.is_default)
            .cloned()
            .ok_or_else(|| ApiError::internal("account has no default workspace"))?;
        let sealed = seal(
            &UserContext {
                user_id: user_id.to_string(),
                account_id: selected.account_id.clone(),
                workspace_id: selected.id.clone(),
            },
            &config.cookie_password,
        )
        .map_err(|error| ApiError::internal(format!("seal workspace context: {error}")))?;
        (selected, Some(sealed))
    };
    Ok((
        SessionResponse {
            authenticated: true,
            site,
            active_account_id: Some(selected.account_id.clone()),
            active_workspace_id: Some(selected.id.clone()),
            accounts,
            workspaces,
            role: session.role.clone(),
            permissions: session.permissions.clone(),
            user,
        },
        replacement_context,
    ))
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
    let session = best_session_cookie(config, &headers, site.session_cookie())
        .map(|(_, session)| session)
        .unwrap_or_else(|| SessionManager::new(None, "", &config.cookie_password).authenticate());
    if !session.session_id.is_empty() {
        let params = RevokeSessionParams::new(RevokeSession {
            session_id: session.session_id.clone(),
        });
        if let Err(error) = config.client.user_management().revoke_session(params).await {
            tracing::warn!(error = %error, "WorkOS session revocation failed");
        }
        config
            .browser_session_heads
            .lock()
            .await
            .remove(&session.session_id);
    }
    let mut response = Redirect::to(config.site_url(site)).into_response();
    append_delete_cookie(
        &mut response,
        site.session_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    if site == Site::User {
        append_delete_cookie(
            &mut response,
            USER_CONTEXT_COOKIE,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    set_no_store(&mut response);
    Ok(response)
}

pub(super) fn validate_flow_identity(
    config: &WorkOsConfig,
    store: &crate::store::Store,
    flow: &LoginFlow,
    session: &SessionState,
) -> Result<WebIdentity, Failure> {
    let identity = validate_session_identity(config, store, flow.site, session)?;
    if flow.site == Site::User && flow.organization_id.is_none() && flow.workspace_id.is_none() {
        return Ok(identity);
    }
    let workspace_matches = match flow.workspace_id.as_deref() {
        Some(workspace_id) => {
            store.workspace_belongs_to_organization(workspace_id, &session.organization_id)?
        }
        None => true,
    };
    if Some(session.organization_id.as_str()) != flow.organization_id.as_deref()
        || !workspace_matches
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
    store: &crate::store::Store,
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
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "WorkOS user session is not scoped to an account",
                )
                .into());
            }
            let account = store
                .account_for_organization(&session.organization_id)?
                .ok_or_else(|| {
                    ApiError::new(
                        cats_api::error::ErrorCode::PermissionDenied,
                        "WorkOS organization is not mapped to a Cats account",
                    )
                })?;
            if account.status != "active" {
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "Cats account is not active",
                )
                .into());
            }
            let default_workspace_id = store
                .workspaces_for_account(&account.id)?
                .into_iter()
                .find(|workspace| workspace.is_default)
                .map(|workspace| workspace.id)
                .ok_or_else(|| ApiError::internal("Cats account has no default workspace"))?;
            Ok(WebIdentity {
                user_id: session.user.as_ref().map(|user| user.id.clone()),
                organization_id: Some(session.organization_id.clone()),
                account_id: Some(account.id),
                default_workspace_id: Some(default_workspace_id),
                administrator: false,
                permissions: session.permissions.clone(),
            })
        }
        Site::Admin => {
            if !session_is_admin(config, session) {
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "WorkOS session lacks fleet administrator permission",
                )
                .into());
            }
            Ok(WebIdentity {
                user_id: session.user.as_ref().map(|user| user.id.clone()),
                organization_id: Some(session.organization_id.clone()),
                account_id: None,
                default_workspace_id: None,
                administrator: true,
                permissions: session.permissions.clone(),
            })
        }
    }
}

fn session_is_admin(config: &WorkOsConfig, session: &SessionState) -> bool {
    session.authenticated
        && session.organization_id == config.admin_organization_id
        && session
            .permissions
            .iter()
            .any(|permission| permission == &config.admin_permission)
}

/// Cryptographically validate the dedicated sealed admin cookie and expose
/// only its identity candidate. Stale permission claims are deliberately not
/// consulted; A23 performs an online current-membership/role verification on
/// every apply and replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FleetAdministratorIdentityCandidate {
    pub(crate) subject: String,
    pub(crate) organization_id: String,
}

pub(crate) fn sealed_admin_session_candidate(
    config: &WorkOsConfig,
    sealed: &str,
) -> Result<FleetAdministratorIdentityCandidate, ApiError> {
    let session =
        SessionManager::new(None, sealed.to_owned(), &config.cookie_password).authenticate();
    if !session.authenticated {
        return Err(ApiError::unauthenticated(
            "invalid or expired WorkOS administrator session",
        ));
    }
    let subject = session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthenticated("WorkOS administrator session has no subject"))?;
    if session.organization_id.is_empty() {
        return Err(ApiError::unauthenticated(
            "WorkOS administrator session has no organization scope",
        ));
    }
    Ok(FleetAdministratorIdentityCandidate {
        subject,
        organization_id: session.organization_id,
    })
}

/// Validate the sealed administrator cookie without entering the control
/// store. The normal admin identity path has the same predicate; its Store
/// closure is only needed to share machinery with workspace-scoped sessions.
pub fn web_session_is_admin_without_store(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(config) = state.cfg.workos.as_ref() else {
        return false;
    };
    let Some((_, session)) = best_session_cookie(config, headers, Site::Admin.session_cookie())
    else {
        return false;
    };
    session_is_admin(config, &session)
}

async fn identity_from_cookie(
    state: &AppState,
    headers: &HeaderMap,
    site: Site,
) -> Option<WebIdentity> {
    let config = state.cfg.workos.clone()?;
    let (_, session) = best_session_cookie(&config, headers, site.session_cookie())?;
    state
        .store
        .execute(move |store| {
            validate_session_identity(&config, store, site, &session).map_err(|failure| failure.0)
        })
        .await
        .ok()
}

pub async fn web_user_identity(state: &AppState, headers: &HeaderMap) -> Option<WebIdentity> {
    identity_from_cookie(state, headers, Site::User).await
}

pub async fn web_session_allows_workspace(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
) -> Result<bool, ApiError> {
    if identity_from_cookie(state, headers, Site::Admin)
        .await
        .is_some_and(|identity| identity.administrator)
    {
        return Ok(true);
    }
    let Some(identity) = identity_from_cookie(state, headers, Site::User).await else {
        return Ok(false);
    };
    let (Some(user_id), Some(organization_id)) = (
        identity.user_id.as_deref(),
        identity.organization_id.as_deref(),
    ) else {
        return Ok(false);
    };
    let workspace_id = workspace_id.to_string();
    let organization_id_for_store = organization_id.to_string();
    if !state
        .store
        .execute(move |store| {
            store.workspace_belongs_to_organization(&workspace_id, &organization_id_for_store)
        })
        .await?
    {
        return Ok(false);
    }
    let Some(workos) = state.cfg.workos.as_ref() else {
        return Ok(false);
    };
    workos
        .user_has_active_membership(user_id, organization_id)
        .await
}

pub async fn web_session_is_admin(state: &AppState, headers: &HeaderMap) -> bool {
    identity_from_cookie(state, headers, Site::Admin)
        .await
        .is_some_and(|identity| identity.administrator)
}

pub async fn has_any_web_session(state: &AppState, headers: &HeaderMap) -> bool {
    identity_from_cookie(state, headers, Site::User)
        .await
        .is_some()
        || identity_from_cookie(state, headers, Site::Admin)
            .await
            .is_some()
}

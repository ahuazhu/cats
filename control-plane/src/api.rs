//! Versioned HTTP API (arch doc §17). Mutations return `202 + Operation`;
//! `Idempotency-Key` retries replay the original operation; actions live
//! under `/actions/<verb>` (path-safe rendering of the `:verb` convention).

use std::collections::BTreeMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use cats_api::auth::{
    AccountInvitation, AccountMember, CreateInvitationRequest, CreateWorkspaceRequest,
    UpdateAccountMemberRequest, UpdateWorkspaceRequest, Workspace,
};
use cats_api::billing::{BillingBalance, CreateCheckoutRequest, CreateCheckoutResponse};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::metering::{
    CatUsageSummary, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse,
    UsageDetailLine, UsageMetric, UsageReport, UsageSummaryLine, UsageTimeBucket,
};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_metering::{
    AttributedCheckpoint, CheckoutIntent, CheckoutPayment, CheckoutRefund,
    CreditApplyOutcome, IngestOutcome, RateCard, UsageAttribution, UsageInterval,
    UsageQuery as MeterUsageQuery, UsageView,
};

use crate::server::AppState;

pub struct Failure(pub ApiError);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ErrorBody {
            code: self.0.code,
            message: self.0.message,
            request_id: None,
        };
        let mut response = (status, Json(body)).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        Failure(e)
    }
}

type ApiResult<T> = std::result::Result<T, Failure>;

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

#[derive(Debug, Clone)]
enum Principal {
    Service,
    Administrator,
    User(crate::auth::AccessIdentity),
}

async fn bearer_principal(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<Principal>> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    if token == state.cfg.auth_token {
        return Ok(Some(Principal::Service));
    }
    if token == state.cfg.admin_token {
        return Ok(Some(Principal::Administrator));
    }
    let workos =
        state.cfg.workos.as_ref().ok_or_else(|| {
            ApiError::unauthenticated("missing or invalid authentication credential")
        })?;
    Ok(Some(Principal::User(
        workos.verify_access_token(token).await?,
    )))
}

fn auth_failure(authenticated: bool) -> Failure {
    if authenticated {
        ApiError::new(
            ErrorCode::PermissionDenied,
            "authentication credential is not allowed for this resource",
        )
        .into()
    } else {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "missing or invalid authentication credential",
        )
        .into()
    }
}

async fn check_authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if bearer_principal(state, headers).await?.is_some()
        || crate::auth::has_any_web_session(state, headers)
    {
        return Ok(());
    }
    Err(auth_failure(false))
}

async fn check_workspace_auth(
    state: &AppState,
    headers: &HeaderMap,
    workspace: &str,
) -> ApiResult<crate::store::WorkspaceScope> {
    let principal = bearer_principal(state, headers).await?;
    let mut resolved_scope = None;
    let bearer_allowed = match &principal {
        Some(Principal::Administrator) => true,
        Some(Principal::User(identity)) => {
            let Some(organization_id) = identity.organization_id.as_deref() else {
                return Err(auth_failure(true));
            };
            let scope = state.store.workspace_scope(workspace)?;
            let allowed = scope.account.status == "active"
                && scope.account.workos_organization_id == organization_id
                && state
                    .cfg
                    .workos
                    .as_ref()
                    .expect("a WorkOS user principal requires WorkOS configuration")
                    .user_has_active_membership(&identity.user_id, organization_id)
                    .await?;
            resolved_scope = Some(scope);
            allowed
        }
        Some(Principal::Service) | None => false,
    };
    if bearer_allowed || crate::auth::web_session_allows_workspace(state, headers, workspace).await? {
        return resolved_scope
            .map(Ok)
            .unwrap_or_else(|| state.store.workspace_scope(workspace))
            .map_err(Into::into);
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers),
    ))
}

async fn check_admin_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let principal = bearer_principal(state, headers).await?;
    let bearer_allowed = match &principal {
        Some(Principal::Administrator) => true,
        Some(Principal::User(identity)) => state
            .cfg
            .workos
            .as_ref()
            .is_some_and(|workos| workos.is_fleet_administrator(identity)),
        Some(Principal::Service) | None => false,
    };
    if bearer_allowed || crate::auth::web_session_is_admin(state, headers) {
        return Ok(());
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers),
    ))
}

async fn check_service_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let principal = bearer_principal(state, headers).await?;
    if matches!(
        principal,
        Some(Principal::Service | Principal::Administrator)
    ) {
        return Ok(());
    }
    Err(auth_failure(principal.is_some()))
}

async fn require_cli_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<crate::auth::AccessIdentity> {
    match bearer_principal(state, headers).await? {
        Some(Principal::User(identity)) => Ok(identity),
        Some(_) => Err(auth_failure(true)),
        None => Err(auth_failure(false)),
    }
}

const MEMBERS_MANAGE_PERMISSION: &str = "cats:members:manage";

async fn require_account_manager(
    state: &AppState,
    headers: &HeaderMap,
    account_id: &str,
) -> ApiResult<(crate::store::AccountRecord, String)> {
    let principal = bearer_principal(state, headers).await?;
    let bearer_identity = match principal {
        Some(Principal::User(identity)) => Some(identity),
        Some(_) => return Err(auth_failure(true)),
        None => None,
    };
    let (user_id, organization_id, permissions) = if let Some(identity) = bearer_identity {
        (
            identity.user_id,
            identity.organization_id,
            identity.permissions,
        )
    } else if let Some(identity) = crate::auth::web_user_identity(state, headers) {
        let user_id = identity.user_id.ok_or_else(|| auth_failure(true))?;
        (user_id, identity.organization_id, identity.permissions)
    } else {
        return Err(auth_failure(false));
    };
    let account = state.store.account_by_id(account_id)?;
    if user_id.is_empty()
        || organization_id.as_deref() != Some(account.workos_organization_id.as_str())
        || !permissions
            .iter()
            .any(|permission| permission == MEMBERS_MANAGE_PERMISSION)
    {
        return Err(auth_failure(true));
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    if !workos
        .user_has_active_membership(&user_id, &account.workos_organization_id)
        .await?
    {
        return Err(auth_failure(true));
    }
    Ok((account, user_id))
}

fn cordon_registered_node(state: &AppState, id: &str) -> ApiResult<()> {
    let node = state.store.get_node(id)?;
    if node.state == NodeState::Draining && !state.store.cats_on_node(id)?.is_empty() {
        return Err(ApiError::failed_precondition(
            "node drain is still in progress; use uncordon to cancel it",
        )
        .into());
    }
    state.store.set_node_state(id, NodeState::Cordoned)?;
    Ok(())
}

fn idem_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn if_match(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"'))
        .and_then(|s| s.parse().ok())
}

fn billing_account_id_for_workspace(state: &AppState, workspace: &str) -> Result<String, ApiError> {
    state.store.billing_account_id_for_workspace(workspace)
}

fn metering_failure(error: cats_metering::MeteringError) -> Failure {
    match error {
        cats_metering::MeteringError::Invalid(message) => ApiError::invalid(message).into(),
        cats_metering::MeteringError::Conflict(message) => ApiError::conflict(message).into(),
        other => ApiError::internal(other.to_string()).into(),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(crate::ui::portal))
        .route("/zh-CN", get(crate::ui::zh_home_redirect))
        .route("/zh-CN/", get(crate::ui::zh_home))
        .route("/docs", get(crate::ui::docs_redirect))
        .route("/docs/", get(crate::ui::docs_index))
        .route("/docs/{slug}", get(crate::ui::docs_detail_redirect))
        .route("/docs/{slug}/", get(crate::ui::docs_detail))
        .route("/zh-CN/docs", get(crate::ui::zh_docs_redirect))
        .route("/zh-CN/docs/", get(crate::ui::zh_docs_index))
        .route(
            "/zh-CN/docs/{slug}",
            get(crate::ui::zh_docs_detail_redirect),
        )
        .route("/zh-CN/docs/{slug}/", get(crate::ui::zh_docs_detail))
        .route("/robots.txt", get(crate::ui::robots))
        .route("/sitemap.xml", get(crate::ui::sitemap))
        .route("/site.webmanifest", get(crate::ui::web_manifest))
        .route("/assets/public.css", get(crate::ui::public_styles))
        .route("/assets/cats-mark.svg", get(crate::ui::cats_mark))
        .route("/assets/cats-logo.svg", get(crate::ui::cats_logo))
        .route("/assets/cats-og.svg", get(crate::ui::cats_og))
        .route("/assets/cats-og.png", get(crate::ui::cats_og_png))
        .route("/user", get(crate::ui::user_console))
        .route("/user/", get(crate::ui::user_console))
        .route("/user/{account}/{workspace}", get(crate::ui::user_console))
        .route("/user/{account}/{workspace}/", get(crate::ui::user_console))
        .route("/admin", get(crate::ui::admin_console))
        .route("/admin/", get(crate::ui::admin_console))
        .route("/ui/styles.css", get(crate::ui::styles))
        .route("/ui/i18n.js", get(crate::ui::i18n_script))
        .route("/ui/common.js", get(crate::ui::common_script))
        .route("/ui/user.js", get(crate::ui::user_script))
        .route("/ui/admin.js", get(crate::ui::admin_script))
        .route("/auth/config", get(crate::auth::config))
        .route("/auth/login", get(crate::auth::login))
        .route("/auth/callback", get(crate::auth::callback))
        .route("/auth/session", get(crate::auth::session))
        .route("/auth/workspace", post(crate::auth::switch_workspace))
        .route("/auth/logout", get(crate::auth::logout))
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/me", get(cli_me))
        .route("/v1/workspaces", get(list_workspaces))
        .route(
            "/v1/accounts/{account}/workspaces",
            post(create_account_workspace),
        )
        .route(
            "/v1/workspaces/{workspace}",
            axum::routing::patch(update_workspace),
        )
        .route("/v1/auth/logout", post(cli_logout))
        .route(
            "/v1/accounts/{account}/invitations",
            post(create_account_invitation).get(list_account_invitations),
        )
        .route(
            "/v1/accounts/{account}/invitations/{invitation}/actions/revoke",
            post(revoke_account_invitation),
        )
        .route("/v1/accounts/{account}/members", get(list_account_members))
        .route(
            "/v1/accounts/{account}/members/{membership}",
            axum::routing::patch(update_account_member).delete(deactivate_account_member),
        )
        .route(
            "/v1/workspaces/{workspace}/cats",
            post(create_cat).get(list_cats),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}",
            get(get_cat).delete(delete_cat),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/actions/{verb}",
            post(cat_action),
        )
        .route("/v1/workspaces/{workspace}/cats/{cat}/exec", post(exec_cat))
        .route("/v1/workspaces/{workspace}/cats/{cat}/shell", get(shell_cat))
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/auto-suspend",
            get(get_auto_suspend).put(update_auto_suspend),
        )
        .route("/v1/workspaces/{workspace}/cats/{cat}/work", get(get_cat_work))
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/endpoints",
            post(create_endpoint).get(list_endpoints),
        )
        .route(
            "/v1/workspaces/{workspace}/disks",
            post(create_disk).get(list_disks),
        )
        .route(
            "/v1/workspaces/{workspace}/disks/{disk}",
            get(get_disk).delete(delete_disk),
        )
        .route(
            "/v1/workspaces/{workspace}/disks/{disk}/actions/{verb}",
            post(disk_action),
        )
        .route(
            "/v1/workspaces/{workspace}/disks/{disk}/snapshots",
            post(create_snapshot).get(list_snapshots),
        )
        .route("/v1/operations/{id}", get(get_operation))
        .route("/v1/workspaces/{workspace}/operations", get(list_operations))
        .route("/v1/nodes/register", post(register_node))
        .route("/v1/nodes/heartbeat", post(heartbeat))
        .route("/v1/nodes/work-status", post(node_work_status))
        .route("/v1/internal/work/acquire", post(acquire_work))
        .route("/v1/internal/work/release", post(release_work))
        .route(
            "/v1/internal/usage/checkpoints",
            post(ingest_usage_checkpoints),
        )
        .route("/v1/workspaces/{workspace}/billing/usage", get(workspace_usage))
        .route(
            "/v1/workspaces/{workspace}/billing/balance",
            get(workspace_billing_balance),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/checkout",
            post(create_billing_checkout),
        )
        .route("/v1/billing/stripe/webhook", post(stripe_webhook))
        .route("/v1/nodes/{id}/actions/cordon", post(cordon_node))
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/admin/nodes", get(admin_list_nodes))
        .route("/v1/admin/workspaces", get(admin_list_workspaces))
        .route(
            "/v1/admin/nodes/{id}",
            get(admin_get_node).delete(admin_delete_node),
        )
        .route("/v1/admin/nodes/{id}/cats", get(admin_node_cats))
        .route(
            "/v1/admin/nodes/{id}/actions/{verb}",
            post(admin_node_action),
        )
        .route("/v1/admin/monitoring", get(admin_monitoring))
        .route("/metrics", get(prometheus_metrics))
        .route("/v1/routes/resolve", get(resolve_route))
        .route("/v1/routes/wake", post(wake_route_handler))
        .fallback(crate::ui::not_found)
        .with_state(state)
}

async fn cli_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<cats_api::auth::MeResponse>> {
    let identity = require_cli_identity(&state, &headers).await?;
    if identity.organization_id.is_none() {
        crate::auth::provision_personal_account(&state, &identity.user_id, &identity.user_id)
            .await?;
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    Ok(Json(workos.me(&state.store, &identity).await?))
}

async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    let identity = require_cli_identity(&state, &headers).await?;
    if identity.organization_id.is_none() {
        crate::auth::provision_personal_account(&state, &identity.user_id, &identity.user_id)
            .await?;
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    Ok(Json(ListResponse {
        items: workos.workspaces_for(&state.store, &identity).await?,
    }))
}

async fn cli_logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let identity = require_cli_identity(&state, &headers).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    workos.revoke_cli_session(&identity).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn workspace_response(
    state: &AppState,
    account: &crate::store::AccountRecord,
    workspace_id: &str,
) -> ApiResult<Workspace> {
    let (_, workspaces) = state
        .store
        .account_and_workspace_views(&account.workos_organization_id, None, &[])?
        .ok_or_else(|| ApiError::failed_precondition("account is not active"))?;
    workspaces
        .into_iter()
        .find(|workspace| workspace.id == workspace_id)
        .ok_or_else(|| ApiError::internal("workspace was not visible after mutation").into())
}

async fn create_account_workspace(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateWorkspaceRequest>,
) -> ApiResult<Response> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workspace =
        state
            .store
            .create_workspace(&account.id, &request.slug, &request.display_name)?;
    Ok((
        StatusCode::CREATED,
        Json(workspace_response(&state, &account, &workspace.id)?),
    )
        .into_response())
}

async fn update_workspace(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> ApiResult<Json<Workspace>> {
    let existing = state.store.workspace_by_id(&workspace_id)?;
    let (account, _) = require_account_manager(&state, &headers, &existing.account_id).await?;
    let workspace = state.store.update_workspace(
        &workspace_id,
        request.slug.as_deref(),
        request.display_name.as_deref(),
    )?;
    Ok(Json(workspace_response(&state, &account, &workspace.id)?))
}

async fn create_account_invitation(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateInvitationRequest>,
) -> ApiResult<Response> {
    let (account, inviter_user_id) = require_account_manager(&state, &headers, &account_id).await?;
    if account.kind == cats_api::auth::AccountKind::Personal {
        return Err(ApiError::failed_precondition(
            "personal accounts do not accept member invitations",
        )
        .into());
    }
    let email = request.email.trim().to_ascii_lowercase();
    if email.len() > 320
        || !email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
    {
        return Err(ApiError::invalid("invitation email is invalid").into());
    }
    if !matches!(request.role_slug.as_str(), "member" | "admin") {
        return Err(ApiError::invalid("role_slug must be member or admin").into());
    }
    let idempotency_key = idem_key(&headers)
        .filter(|key| !key.is_empty() && key.len() <= 255)
        .ok_or_else(|| {
            ApiError::invalid("a non-empty Idempotency-Key of at most 255 bytes is required")
        })?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let invitation = workos
        .send_account_invitation(
            &account,
            &inviter_user_id,
            &email,
            &request.role_slug,
            &idempotency_key,
        )
        .await?;
    state
        .store
        .record_invitation(&invitation, &account.workos_organization_id)?;
    Ok((StatusCode::CREATED, Json(invitation)).into_response())
}

async fn list_account_invitations(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<AccountInvitation>>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let items = workos.list_account_invitations(&account).await?;
    for invitation in &items {
        state
            .store
            .record_invitation(invitation, &account.workos_organization_id)?;
    }
    Ok(Json(ListResponse { items }))
}

async fn revoke_account_invitation(
    State(state): State<AppState>,
    Path((account_id, invitation_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AccountInvitation>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let invitation = workos
        .revoke_account_invitation(&account, &invitation_id)
        .await?;
    state
        .store
        .record_invitation(&invitation, &account.workos_organization_id)?;
    Ok(Json(invitation))
}

async fn list_account_members(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<AccountMember>>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let items = workos.list_account_members(&account).await?;
    for member in &items {
        state.store.upsert_membership_shadow(
            &member.membership_id,
            &account.id,
            &member.user.id,
            &member.role_slug,
            &member.status,
        )?;
    }
    Ok(Json(ListResponse { items }))
}

async fn update_account_member(
    State(state): State<AppState>,
    Path((account_id, membership_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateAccountMemberRequest>,
) -> ApiResult<Json<AccountMember>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    if !matches!(request.role_slug.as_str(), "member" | "admin") {
        return Err(ApiError::invalid("role_slug must be member or admin").into());
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let members = workos.list_account_members(&account).await?;
    let target = members
        .iter()
        .find(|member| member.membership_id == membership_id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "membership not found"))?;
    let active_admins = members
        .iter()
        .filter(|member| member.status == "active" && member.role_slug == "admin")
        .count();
    if target.status == "active"
        && target.role_slug == "admin"
        && request.role_slug != "admin"
        && active_admins <= 1
    {
        return Err(ApiError::failed_precondition(
            "an organization account must retain an active administrator",
        )
        .into());
    }
    let member = workos
        .update_account_member(&account, &membership_id, &request.role_slug)
        .await?;
    state.store.upsert_membership_shadow(
        &member.membership_id,
        &account.id,
        &member.user.id,
        &member.role_slug,
        &member.status,
    )?;
    Ok(Json(member))
}

async fn deactivate_account_member(
    State(state): State<AppState>,
    Path((account_id, membership_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let (account, actor_user_id) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let members = workos.list_account_members(&account).await?;
    let target = members
        .iter()
        .find(|member| member.membership_id == membership_id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "membership not found"))?;
    if target.user.id == actor_user_id {
        return Err(ApiError::failed_precondition(
            "use another account administrator to deactivate your own membership",
        )
        .into());
    }
    let active_admins = members
        .iter()
        .filter(|member| member.status == "active" && member.role_slug == "admin")
        .count();
    if target.role_slug == "admin" && active_admins <= 1 {
        return Err(ApiError::failed_precondition(
            "an organization account must retain an active administrator",
        )
        .into());
    }
    workos
        .deactivate_account_member(&account, &membership_id)
        .await?;
    state.store.upsert_membership_shadow(
        &target.membership_id,
        &account.id,
        &target.user.id,
        &target.role_slug,
        "inactive",
    )?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Cats
// ---------------------------------------------------------------------------

async fn create_cat(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateCatRequest>,
) -> ApiResult<Response> {
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    require_funded(&state, &workspace).await?;
    if req.name.is_empty()
        || !req
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::invalid("cat name must be non-empty [a-z0-9-]").into());
    }
    let route = format!("POST /cats {workspace}/{}", req.name);
    if let Some(key) = idem_key(&headers) {
        if let Some(op_id) = state.store.idempotency_lookup(&key, &route)? {
            let op = state.store.get_operation(&op_id)?;
            let cat = state.store.must_get_cat_by_id(&op.resource_id)?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(CatOperationResponse { operation: op, cat }),
            )
                .into_response());
        }
    }
    let extra = req
        .disk
        .as_ref()
        .map(|d| (d.name.as_str(), d.size_bytes, d.mount_at.as_str()));
    let (cat, _disks, op) = state.store.create_cat(
        &scope.workspace,
        &req.name,
        &req.image,
        req.cpus,
        req.memory_mib,
        req.root_size_bytes,
        req.auto_suspend,
        extra,
    )?;
    if let Some(key) = idem_key(&headers) {
        state.store.idempotency_store(&key, &route, &op.id)?;
    }
    state.notify.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse { operation: op, cat }),
    )
        .into_response())
}

async fn list_cats(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Cat>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(ListResponse {
        items: state.store.list_cats(&workspace)?,
    }))
}

async fn get_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Cat>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(state.store.get_cat(&workspace, &cat)?))
}

async fn cat_action(
    State(state): State<AppState>,
    Path((workspace, cat, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let desired = match verb.as_str() {
        "start" | "resume" => DesiredState::Running,
        "suspend" => DesiredState::Suspended,
        "warm" => DesiredState::Warm,
        "stop" => DesiredState::Cold,
        _ => return Err(ApiError::invalid(format!("unknown action {verb}")).into()),
    };
    if desired == DesiredState::Running {
        require_funded(&state, &workspace).await?;
    }
    let route = format!("POST /cats/{}/actions/{verb}", cat.id);
    if let Some(key) = idem_key(&headers) {
        if let Some(op_id) = state.store.idempotency_lookup(&key, &route)? {
            let op = state.store.get_operation(&op_id)?;
            let cat = state.store.must_get_cat_by_id(&cat.id)?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(CatOperationResponse { operation: op, cat }),
            )
                .into_response());
        }
    }
    let op =
        state
            .store
            .set_desired(&cat.id, desired, if_match(&headers), &format!("cat.{verb}"))?;
    if let Some(key) = idem_key(&headers) {
        state.store.idempotency_store(&key, &route, &op.id)?;
    }
    state.notify.notify_one();
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse { operation: op, cat }),
    )
        .into_response())
}

async fn delete_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let op = state.store.set_desired(
        &cat.id,
        DesiredState::Deleted,
        if_match(&headers),
        "cat.delete",
    )?;
    state.notify.notify_one();
    let cat_snapshot = state.store.must_get_cat_by_id(&cat.id)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse {
            operation: op,
            cat: cat_snapshot,
        }),
    )
        .into_response())
}

async fn exec_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<ExecResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    if req.command.is_empty() {
        return Err(ApiError::invalid("command must be a non-empty argv array").into());
    }
    let owner = format!("exec_{}", uuid::Uuid::new_v4().simple());
    let cat_id = cat.id.clone();
    // Bounds both the work lease and the transport timeout below, so a caller
    // asking for a long-running command gets one instead of a 60 s transport
    // failure. Note the Guest agent does not enforce it: a runaway command keeps
    // running there until the Cat is stopped.
    let ttl_ms = req.timeout_ms.unwrap_or(120_000).clamp(1_000, 3_600_000);
    let lease = state
        .store
        .acquire_work(&cat.id, WorkKind::Exec, &owner, "exec", ttl_ms)?;
    let result: ApiResult<ExecResponse> = async {
        let mut cat = cat;
        let mut retried_suspend_conflict = false;
        loop {
            // Shell/exec always wakes (arch doc §8.2). An exec that reaches
            // the node while its suspend gate is closing gets a transient
            // 409 and cancels that suspend. Wait for the control plane to
            // observe Running again, then retry the exec once.
            cat = ensure_running(&state, cat).await?;
            let node = state
                .store
                .list_nodes()?
                .into_iter()
                .find(|n| Some(&n.id) == cat.node_id.as_ref())
                .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
            let url = format!(
                "{}/v1/cats/{}/exec",
                node.agent_url.trim_end_matches('/'),
                cat.id
            );
            let resp = state
                .controller
                .http
                .post(url)
                // The shared client carries a 60 s timeout meant for node job
                // dispatch, which is shorter than the exec timeout this handler
                // already accepted (`timeout_ms`, 120 s by default). Without this
                // override a command that runs longer than 60 s fails in transport
                // while its work lease is still valid -- measured: fio write
                // workloads returned nothing at all, and `sleep 70` failed.
                .timeout(Duration::from_millis(ttl_ms) + Duration::from_secs(15))
                .bearer_auth(&state.cfg.auth_token)
                .json(&req)
                .send()
                .await
                .map_err(|e| ApiError::unavailable(format!("node agent unreachable: {e}")))?;
            let status = resp.status();
            if status.is_success() {
                break resp
                    .json::<ExecResponse>()
                    .await
                    .map_err(|e| ApiError::internal(format!("bad exec response: {e}")).into());
            }
            if status == StatusCode::CONFLICT && !retried_suspend_conflict {
                retried_suspend_conflict = true;
                continue;
            }
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            let message = if detail.is_empty() {
                format!("exec failed: {status}")
            } else {
                format!("exec failed: {detail}")
            };
            break Err(ApiError::unavailable(message).into());
        }
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result.map(Json)
}

#[derive(Debug, Deserialize)]
struct ShellQuery {
    #[serde(default = "default_terminal_rows")]
    rows: u16,
    #[serde(default = "default_terminal_cols")]
    cols: u16,
}

fn default_terminal_rows() -> u16 {
    24
}

fn default_terminal_cols() -> u16 {
    80
}

async fn shell_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    Query(query): Query<ShellQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if !(1..=1_000).contains(&query.rows) || !(1..=1_000).contains(&query.cols) {
        return Err(ApiError::invalid("terminal dimensions must be in 1..=1000").into());
    }
    let cat = state.store.get_cat(&workspace, &cat)?;
    let owner = format!("shell_{}", uuid::Uuid::new_v4().simple());
    let lease = state
        .store
        .acquire_work(&cat.id, WorkKind::Exec, &owner, "shell", 120_000)?;
    state.notify.notify_one();
    let cat_id = cat.id.clone();

    let prepared = prepare_node_shell(&state, cat, query.rows, query.cols).await;
    let node_socket = match prepared {
        Ok(socket) => socket,
        Err(error) => {
            let _ = state.store.release_work(&lease.id);
            let _ = state.controller.maybe_auto_suspend(&cat_id);
            return Err(error);
        }
    };
    let cleanup_state = state.clone();
    Ok(ws
        .max_message_size(MAX_SHELL_MESSAGE_BYTES)
        .max_frame_size(MAX_SHELL_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            proxy_shell(
                socket,
                node_socket,
                cleanup_state.clone(),
                cat_id.clone(),
                owner,
            )
            .await;
            let _ = cleanup_state.store.release_work(&lease.id);
            let _ = cleanup_state.controller.maybe_auto_suspend(&cat_id);
        }))
}

async fn prepare_node_shell(
    state: &AppState,
    mut cat: Cat,
    rows: u16,
    cols: u16,
) -> ApiResult<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut retried_suspend_conflict = false;
    loop {
        cat = ensure_running(state, cat).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|node| Some(&node.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
        let mut url = reqwest::Url::parse(node.agent_url.trim_end_matches('/'))
            .map_err(|error| ApiError::internal(format!("invalid node agent URL: {error}")))?;
        url.set_scheme(match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => return Err(ApiError::internal("node agent URL must use http or https").into()),
        })
        .map_err(|_| ApiError::internal("invalid node WebSocket URL"))?;
        url.set_path(&format!("/v1/cats/{}/shell", cat.id));
        url.set_query(Some(&format!("rows={rows}&cols={cols}")));
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|error| ApiError::internal(format!("build node shell request: {error}")))?;
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", state.cfg.auth_token))
                .map_err(|_| ApiError::internal("invalid service authorization header"))?,
        );
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => return Ok(socket),
            Err(tokio_tungstenite::tungstenite::Error::Http(response))
                if response.status() == StatusCode::CONFLICT && !retried_suspend_conflict =>
            {
                retried_suspend_conflict = true;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // The node explains itself in the response body -- which Cat, which
            // state, which node. Tungstenite's Display prints only the status
            // line, so pass the body through or the caller sees one opaque 503
            // wrapped in another.
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                let status = response.status();
                let body = response
                    .into_body()
                    .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
                    .unwrap_or_default();
                let detail = if body.is_empty() {
                    format!("node shell connection failed: HTTP {status}")
                } else {
                    format!("node shell connection failed: HTTP {status}: {body}")
                };
                return Err(ApiError::unavailable(detail).into());
            }
            Err(error) => {
                return Err(
                    ApiError::unavailable(format!("node shell connection failed: {error}")).into(),
                )
            }
        }
    }
}

async fn proxy_shell(
    client: WebSocket,
    node: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    state: AppState,
    cat_id: String,
    owner: String,
) {
    let (mut client_sender, mut client_receiver) = client.split();
    let (mut node_sender, mut node_receiver) = node.split();
    let mut renewal = tokio::time::interval(Duration::from_secs(30));
    renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renewal.tick().await;

    loop {
        tokio::select! {
            incoming = client_receiver.next() => {
                let Some(Ok(message)) = incoming else { break };
                let message = match message {
                    Message::Text(text) => {
                        tokio_tungstenite::tungstenite::Message::Text(text.to_string().into())
                    }
                    Message::Binary(data) => tokio_tungstenite::tungstenite::Message::Binary(data),
                    Message::Ping(data) => tokio_tungstenite::tungstenite::Message::Ping(data),
                    Message::Pong(data) => tokio_tungstenite::tungstenite::Message::Pong(data),
                    Message::Close(_) => tokio_tungstenite::tungstenite::Message::Close(None),
                };
                if node_sender.send(message).await.is_err() {
                    break;
                }
            }
            outgoing = node_receiver.next() => {
                let Some(Ok(message)) = outgoing else { break };
                let message = match message {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        Message::Text(text.to_string().into())
                    }
                    tokio_tungstenite::tungstenite::Message::Binary(data) => Message::Binary(data),
                    tokio_tungstenite::tungstenite::Message::Ping(data) => Message::Ping(data),
                    tokio_tungstenite::tungstenite::Message::Pong(data) => Message::Pong(data),
                    tokio_tungstenite::tungstenite::Message::Close(_) => Message::Close(None),
                    tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
                };
                if client_sender.send(message).await.is_err() {
                    break;
                }
            }
            _ = renewal.tick() => {
                if let Err(error) = state.store.acquire_work(
                    &cat_id,
                    WorkKind::Exec,
                    &owner,
                    "shell",
                    120_000,
                ) {
                    tracing::warn!(cat_id, error = %error, "shell work lease renewal failed");
                    break;
                }
            }
        }
    }
    let _ = node_sender
        .send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await;
}

async fn get_auto_suspend(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AutoSuspendResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let work = state
        .store
        .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?;
    Ok(Json(AutoSuspendResponse { cat, work }))
}

async fn update_auto_suspend(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateAutoSuspendRequest>,
) -> ApiResult<Json<AutoSuspendResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let cat = state.store.set_auto_suspend(&cat.id, request.enabled)?;
    if request.enabled {
        state.controller.maybe_auto_suspend(&cat.id)?;
    }
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    let work = state
        .store
        .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?;
    Ok(Json(AutoSuspendResponse { cat, work }))
}

async fn get_cat_work(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<CatWorkStatus>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    Ok(Json(
        state
            .store
            .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?,
    ))
}

/// Wake a cat for exec/gateway traffic and wait until it reports Running.
pub async fn ensure_running(state: &AppState, cat: Cat) -> ApiResult<Cat> {
    let wake_started = std::time::Instant::now();
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    require_funded(state, &cat.workspace_id).await?;
    if cat.desired_state == DesiredState::Running && cat.observed_state == ObservedState::Running {
        return Ok(cat);
    }
    state.store.ensure_desired_running(&cat.id)?;
    let desired_update_us = wake_started.elapsed().as_micros();
    state.notify.notify_one();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let current = state.store.must_get_cat_by_id(&cat.id)?;
        match current.observed_state {
            ObservedState::Running => {
                tracing::info!(
                    cat = %cat.id,
                    total_us = wake_started.elapsed().as_micros(),
                    desired_update_us,
                    "wake wait timings"
                );
                return Ok(current);
            }
            ObservedState::Failed => {
                return Err(ApiError::unavailable("cat failed to start").into())
            }
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            return Err(ApiError::new(ErrorCode::DeadlineExceeded, "wake timed out").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Disks
// ---------------------------------------------------------------------------

async fn create_disk(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateDiskRequest>,
) -> ApiResult<Json<Disk>> {
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    if req.size_bytes == 0 || req.size_bytes > cats_api::chunk::MAX_VOLUME_BYTES {
        return Err(ApiError::invalid("disk size out of range").into());
    }
    let disk = state
        .store
        .create_disk(&scope.workspace, &req.name, req.size_bytes)?;
    // Create the storage volume eagerly so snapshots/resize work pre-attach.
    let size = cats_api::chunk::round_up_to_chunk(req.size_bytes);
    match state.storage_meta.create_volume(&disk.volume_id, size) {
        Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    Ok(Json(disk))
}

async fn list_disks(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Disk>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(ListResponse {
        items: state.store.list_disks(&workspace)?,
    }))
}

async fn get_disk(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Disk>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(state.store.get_disk(&workspace, &disk)?))
}

async fn delete_disk(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    if disk.kind == DiskKind::Root {
        return Err(ApiError::failed_precondition("root disks are deleted with their cat").into());
    }
    if disk.bound_cat_id.is_some() {
        return Err(ApiError::failed_precondition("disk must be Available (unmount first)").into());
    }
    match state.storage_meta.delete_volume(&disk.volume_id) {
        Ok(()) | Err(cats_storage::MetaError::NotFound(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    state.store.delete_disk_row(&disk.id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct DiskActionBody {
    #[serde(default)]
    cat_id: Option<String>,
    #[serde(default)]
    mount_at: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

async fn disk_action(
    State(state): State<AppState>,
    Path((workspace, disk, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<DiskActionBody>,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    match verb.as_str() {
        "mount" => {
            let cat_ref = body
                .cat_id
                .ok_or_else(|| ApiError::invalid("cat_id required"))?;
            let mount_at = body
                .mount_at
                .ok_or_else(|| ApiError::invalid("mount_at required"))?;
            let cat = state.store.get_cat(&workspace, &cat_ref)?;
            if disk.kind == DiskKind::Root {
                return Err(ApiError::failed_precondition("cannot mount a root disk").into());
            }
            let binding = state.store.bind_disk(&disk.id, &cat.id, &mount_at)?;
            // Hot attach when running; cold cats pick the disk up at start.
            if cat.observed_state == ObservedState::Running {
                if let Err(e) = hot_attach(&state, &cat, &disk, &binding.mount_path).await {
                    state.store.unbind_disk(&disk.id)?;
                    return Err(e);
                }
            }
            Ok(Json(binding).into_response())
        }
        "unmount" => {
            let Some(bound_cat) = disk.bound_cat_id.clone() else {
                return Err(ApiError::failed_precondition("disk is not mounted").into());
            };
            let cat = state.store.must_get_cat_by_id(&bound_cat)?;
            if cat.observed_state == ObservedState::Running {
                hot_detach(&state, &cat, &disk).await?;
            }
            match state.storage_meta.revoke_lease(&disk.volume_id) {
                Ok(()) | Err(cats_storage::MetaError::NotFound(_)) => {}
                Err(e) => return Err(ApiError::internal(e.to_string()).into()),
            }
            state.store.unbind_disk(&disk.id)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        "resize" => {
            let new_size = body
                .size_bytes
                .ok_or_else(|| ApiError::invalid("size_bytes required"))?;
            if disk.bound_cat_id.is_some() {
                return Err(ApiError::failed_precondition(
                    "v1 resize requires the disk to be Available",
                )
                .into());
            }
            if new_size < disk.size_bytes {
                return Err(ApiError::invalid("shrink is not supported").into());
            }
            let rounded = cats_api::chunk::round_up_to_chunk(new_size);
            state
                .storage_meta
                .resize_volume(&disk.volume_id, rounded)
                .map_err(|e| ApiError::failed_precondition(e.to_string()))?;
            state.store.set_disk_size(&disk.id, new_size)?;
            Ok(Json(state.store.get_disk(&workspace, &disk.id)?).into_response())
        }
        _ => Err(ApiError::invalid(format!("unknown disk action {verb}")).into()),
    }
}

async fn hot_attach(state: &AppState, cat: &Cat, disk: &Disk, mount_path: &str) -> ApiResult<()> {
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "disk_attach", 120_000)?;
    let cat_id = cat.id.clone();
    let result = async {
        let cat = ensure_running(state, cat.clone()).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
        match state.storage_meta.create_volume(&disk.volume_id, size) {
            Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
            Err(e) => return Err(ApiError::internal(e.to_string()).into()),
        }
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("attach_{}", disk.id),
            ),
            cat_generation: cat.generation,
            action: cats_api::nodejob::NodeJobAction::AttachDisk {
                cat_id: cat.id.clone(),
                volume: cats_api::nodejob::VolumeGrant {
                    disk_id: disk.id.clone(),
                    volume_id: disk.volume_id.clone(),
                    attachment_id: format!("att_{}_{}_{}", cat.id, disk.id, cat.generation),
                    epoch: 0,
                    size_bytes: size,
                    mount_path: mount_path.to_string(),
                },
            },
        };
        dispatch_or_unavailable(state, &node.agent_url, &job).await
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result
}

async fn hot_detach(state: &AppState, cat: &Cat, disk: &Disk) -> ApiResult<()> {
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "disk_detach", 120_000)?;
    let cat_id = cat.id.clone();
    let result = async {
        let cat = ensure_running(state, cat.clone()).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("detach_{}", disk.id),
            ),
            cat_generation: cat.generation,
            action: cats_api::nodejob::NodeJobAction::DetachDisk {
                cat_id: cat.id.clone(),
                disk_id: disk.id.clone(),
            },
        };
        dispatch_or_unavailable(state, &node.agent_url, &job).await
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result
}

async fn dispatch_or_unavailable(
    state: &AppState,
    agent_url: &str,
    job: &cats_api::nodejob::NodeJob,
) -> ApiResult<()> {
    let resp = state
        .controller
        .http
        .post(format!("{}/v1/jobs", agent_url.trim_end_matches('/')))
        .bearer_auth(&state.cfg.auth_token)
        .json(job)
        .send()
        .await
        .map_err(|e| ApiError::unavailable(format!("node agent unreachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::unavailable(format!("node agent returned {}", resp.status())).into());
    }
    let result: cats_api::nodejob::NodeJobResult = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if result.phase != cats_api::nodejob::JobPhase::Succeeded {
        return Err(
            ApiError::unavailable(result.error.unwrap_or_else(|| "job failed".into())).into(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

async fn create_snapshot(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Snapshot>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    let snap_id = crate::store::new_id(cats_api::ids::SNAPSHOT_PREFIX);
    let row = state
        .storage_meta
        .create_snapshot(&snap_id, &disk.volume_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(Snapshot {
        id: row.snapshot_id,
        disk_id: disk.id,
        generation: row.generation,
        root_hash_hex: row.root_hash.map(hex_lower).unwrap_or_default(),
        created_at_unix: crate::store::now_unix(),
    }))
}

fn hex_lower(h: [u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

async fn list_snapshots(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Snapshot>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    let rows = state
        .storage_meta
        .list_snapshots(&disk.volume_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(ListResponse {
        items: rows
            .into_iter()
            .map(|r| Snapshot {
                id: r.snapshot_id,
                disk_id: disk.id.clone(),
                generation: r.generation,
                root_hash_hex: r.root_hash.map(hex_lower).unwrap_or_default(),
                created_at_unix: 0,
            })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Endpoints / routes
// ---------------------------------------------------------------------------

async fn create_endpoint(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<CreateEndpointRequest>,
) -> ApiResult<Json<EndpointResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if req.name.is_empty()
        || req.name.len() > 24
        || !req
            .name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        || req.name.starts_with('-')
        || req.name.ends_with('-')
    {
        return Err(
            ApiError::invalid("endpoint name must be 1-24 lowercase [a-z0-9-] characters").into(),
        );
    }
    if req.target_port == 0 {
        return Err(ApiError::invalid("endpoint target_port must be non-zero").into());
    }
    if req.protocol != "http" {
        return Err(ApiError::invalid("only http endpoints are currently supported").into());
    }
    let cat = state.store.get_cat(&workspace, &cat)?;
    let ep = state.store.create_endpoint(
        &cat,
        &req.name,
        req.target_port,
        &req.protocol,
        req.wake_policy,
    )?;
    // If the cat is already running, bind the route immediately.
    if let (ObservedState::Running, Some(node_id)) = (cat.observed_state, &cat.node_id) {
        if let Some(node) = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| &n.id == node_id)
        {
            state
                .store
                .publish_routes(&cat.id, &node.id, &node.gateway_url)?;
        }
    }
    Ok(Json(EndpointResponse { endpoint: ep }))
}

async fn list_endpoints(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Endpoint>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    Ok(Json(ListResponse {
        items: state.store.endpoints_for_cat(&cat.id)?,
    }))
}

#[derive(serde::Deserialize)]
pub(crate) struct ResolveQuery {
    hostname: String,
}

#[derive(serde::Serialize)]
struct ResolveResponse {
    binding: RouteBinding,
    state: String,
    observed_state: ObservedState,
    node_agent_url: String,
}

async fn resolve_route(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<ResolveResponse>> {
    check_service_auth(&state, &headers).await?;
    let (binding, route_state) = state.store.resolve_route(&q.hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    let node_agent_url = state
        .store
        .list_nodes()?
        .into_iter()
        .find(|n| n.id == binding.node_id)
        .map(|n| n.agent_url)
        .unwrap_or_default();
    Ok(Json(ResolveResponse {
        binding,
        state: route_state,
        observed_state: cat.observed_state,
        node_agent_url,
    }))
}

/// Gateway wake entry: waits until the cat backing `hostname` is running.
async fn wake_route(state: &AppState, hostname: &str) -> ApiResult<()> {
    let (binding, _) = state.store.resolve_route(hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    if binding.wake_policy == WakePolicy::NoWake && cat.observed_state != ObservedState::Running {
        return Err(ApiError::unavailable("endpoint does not wake on request").into());
    }
    ensure_running(state, cat).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterNodeRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    state.store.register_node(
        &req.node_id,
        &req.agent_url,
        &req.gateway_url,
        req.cpus,
        req.memory_mib,
    )?;
    state.notify.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    state
        .store
        .heartbeat_node(&req.node_id, req.telemetry.as_ref())?;
    // Drift detection: trust node reports for steady states at the same
    // generation; the reconciler drives any resulting divergence.
    for hb in &req.cats {
        if let Ok(cat) = state.store.must_get_cat_by_id(&hb.cat_id) {
            if cat.generation == hb.generation
                && cat.node_id.as_deref() == Some(req.node_id.as_str())
                && cat.observed_state != hb.state
                && matches!(
                    cat.observed_state,
                    ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
                )
            {
                state.store.set_observed(&cat.id, hb.state)?;
                state.notify.notify_one();
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn ingest_usage_checkpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IngestUsageCheckpointsRequest>,
) -> ApiResult<Json<IngestUsageCheckpointsResponse>> {
    check_service_auth(&state, &headers).await?;
    if req.checkpoints.len() > 10_000 {
        return Err(ApiError::invalid("at most 10000 checkpoints per request").into());
    }
    // A missing/lost node cannot invent a producer identity. Registration is
    // also what lets operations fence a replaced node before accepting data.
    state.store.get_node(&req.node_id)?;

    let mut accepted = 0_u64;
    let mut duplicates = 0_u64;
    for checkpoint in req.checkpoints {
        let expected_source = format!("node/{}/cat/{}", req.node_id, checkpoint.cat_id);
        if checkpoint.source_id != expected_source {
            return Err(ApiError::invalid(format!(
                "checkpoint source_id must be {expected_source}"
            ))
            .into());
        }
        let frozen_attribution = state
            .usage
            .source_epoch_attribution(&checkpoint.source_id, &checkpoint.source_epoch)
            .await
            .map_err(metering_failure)?;
        let attribution = match state.store.must_get_cat_by_id(&checkpoint.cat_id) {
            Ok(cat) => {
                if cat.node_id.as_deref() != Some(req.node_id.as_str()) {
                    return Err(ApiError::conflict(format!(
                        "node {} does not own Cat {}",
                        req.node_id, checkpoint.cat_id
                    ))
                    .into());
                }
                // A lifecycle job finalizes the runtime epoch that existed
                // before the desired-state mutation bumped the control-plane
                // generation. Accept an older acknowledged generation while
                // this node still owns the Cat; never accept a future one.
                if checkpoint.cat_generation > cat.generation {
                    return Err(ApiError::conflict(format!(
                        "Cat {} checkpoint generation {} is newer than current {}",
                        checkpoint.cat_id, checkpoint.cat_generation, cat.generation
                    ))
                    .into());
                }
                if let Some(attribution) = frozen_attribution {
                    validate_cat_attribution(&attribution, &cat)?;
                    attribution
                } else {
                    UsageAttribution {
                        billing_account_id: billing_account_id_for_workspace(&state, &cat.workspace_id)?,
                        workspace_id: cat.workspace_id,
                        resource_type: "cat".to_string(),
                        resource_id: checkpoint.cat_id.clone(),
                        attributed_cat_id: Some(checkpoint.cat_id.clone()),
                    }
                }
            }
            Err(error) if error.code == ErrorCode::NotFound => {
                // Durable outboxes can replay after resource deletion. Reuse
                // attribution already frozen in this exact source epoch; the
                // node never supplies or changes billing ownership.
                let attribution = frozen_attribution.ok_or_else(|| {
                    ApiError::conflict(format!(
                        "no frozen attribution exists for deleted Cat {} source epoch",
                        checkpoint.cat_id
                    ))
                })?;
                if !cat_attribution_matches(&attribution, &checkpoint.cat_id, None) {
                    return Err(ApiError::conflict(
                        "stored source-epoch attribution does not match checkpoint Cat",
                    )
                    .into());
                }
                attribution
            }
            Err(error) => return Err(error.into()),
        };
        let value = AttributedCheckpoint {
            attribution,
            checkpoint,
        };
        match state.usage.ingest(&value).await.map_err(metering_failure)? {
            IngestOutcome::Accepted => accepted += 1,
            IngestOutcome::Duplicate => duplicates += 1,
        }
    }
    Ok(Json(IngestUsageCheckpointsResponse {
        accepted,
        duplicates,
    }))
}

fn cat_attribution_matches(
    attribution: &UsageAttribution,
    cat_id: &str,
    workspace: Option<&str>,
) -> bool {
    attribution.resource_type == "cat"
        && attribution.resource_id == cat_id
        && attribution.attributed_cat_id.as_deref() == Some(cat_id)
        && workspace.is_none_or(|workspace| attribution.workspace_id == workspace)
}

fn validate_cat_attribution(attribution: &UsageAttribution, cat: &Cat) -> Result<(), Failure> {
    if cat_attribution_matches(attribution, &cat.id, Some(&cat.workspace_id)) {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "stored source-epoch attribution does not match current Cat ownership",
        )
        .into())
    }
}

struct BillingProjection {
    signup_credit_nanos: i128,
    credit_nanos: i128,
    usage_nanos: u128,
    available_nanos: i128,
    latest_interval_end_unix_ms: Option<i64>,
    stripe_customer_id: Option<String>,
}

fn unix_millis() -> Result<i64, Failure> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system time is before Unix epoch"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| ApiError::internal("system time is out of range").into())
}

async fn billing_projection(state: &AppState, workspace: &str) -> ApiResult<BillingProjection> {
    let now_ms = unix_millis()?;
    let ledger = state.store.billing_ledger_for_workspace(workspace)?;
    let rate_card = RateCard::sprites_compute_v1();
    let credit = state
        .credits
        .ensure_account(
            &ledger.billing_account_id,
            &ledger.account_id,
            "USD",
            ledger.signup_credit_nanos,
            now_ms,
        )
        .await
        .map_err(metering_failure)?;
    // Every Workspace in an Account bills to that Account, so the balance is
    // read per Billing Account and never filtered by Workspace here.
    let usage = state
        .usage
        .query(&MeterUsageQuery {
            billing_account_id: ledger.billing_account_id,
            workspace_id: None,
            attributed_cat_id: None,
            interval_start_unix_ms: 0,
            interval_end_unix_ms: now_ms.max(1),
        })
        .await
        .map_err(metering_failure)?;
    let mut usage_nanos = 0_u128;
    for aggregate in usage.totals {
        if let Some(amount) = rate_card
            .rate_quantity(aggregate.metric, aggregate.quantity)
            .map_err(metering_failure)?
        {
            usage_nanos = usage_nanos
                .checked_add(amount)
                .ok_or_else(|| ApiError::internal("rated balance overflow"))?;
        }
    }
    let usage_signed = i128::try_from(usage_nanos)
        .map_err(|_| ApiError::internal("rated balance exceeds signed money range"))?;
    let available_nanos = credit
        .credit_nanos
        .checked_sub(usage_signed)
        .ok_or_else(|| ApiError::internal("available balance overflow"))?;
    Ok(BillingProjection {
        signup_credit_nanos: ledger.signup_credit_nanos,
        credit_nanos: credit.credit_nanos,
        usage_nanos,
        available_nanos,
        latest_interval_end_unix_ms: usage.latest_interval_end_unix_ms,
        stripe_customer_id: credit.stripe_customer_id,
    })
}

async fn require_funded(state: &AppState, workspace: &str) -> ApiResult<()> {
    if !state.cfg.billing_enforcement_enabled {
        return Ok(());
    }
    let projection = billing_projection(state, workspace).await?;
    if projection.available_nanos <= 0 {
        return Err(ApiError::payment_required(
            "prepaid balance is exhausted; add funds in Billing before starting paid work",
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn enforce_exhausted_billing_accounts(state: &AppState) -> ApiResult<()> {
    let active_cats = state
        .store
        .list_all_cats()?
        .into_iter()
        .filter(|cat| cat.desired_state == DesiredState::Running)
        .map(|cat| {
            let account_id = state.store.workspace_by_id(&cat.workspace_id)?.account_id;
            Ok((cat, account_id))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let accounts = active_cats
        .iter()
        .map(|(cat, account_id)| (account_id.clone(), cat.workspace_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut changed = false;
    for (account_id, workspace) in accounts {
        let projection = billing_projection(state, &workspace).await?;
        if projection.available_nanos > 0 {
            continue;
        }
        for (cat, _) in active_cats
            .iter()
            .filter(|(_, cat_account_id)| cat_account_id == &account_id)
        {
            match state
                .store
                .set_desired(&cat.id, DesiredState::Cold, None, "cat.credit_exhausted")
            {
                Ok(_) => {
                    changed = true;
                    tracing::warn!(
                        billing_account = %billing_account_id_for_workspace(state, &workspace)?,
                        cat_id = %cat.id,
                        "prepaid balance exhausted; converging Cat to Cold"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        cat_id = %cat.id,
                        error = %error,
                        "could not apply exhausted-credit Cold state"
                    );
                }
            }
        }
    }
    if changed {
        state.notify.notify_one();
    }
    Ok(())
}

async fn workspace_billing_balance(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let projection = billing_projection(&state, &workspace).await?;
    let stripe_enabled = state.cfg.stripe.is_some();
    let topup_options_cents = state
        .cfg
        .stripe
        .as_ref()
        .map(|stripe| stripe.topup_options_cents())
        .unwrap_or_default();
    let balance = BillingBalance {
        billing_account_id: billing_account_id_for_workspace(&state, &workspace)?,
        workspace_id: workspace.clone(),
        currency: "USD".to_string(),
        status: if projection.available_nanos > 0 {
            "active"
        } else {
            "payment_required"
        }
        .to_string(),
        credit_nanos: projection.credit_nanos.to_string(),
        provisional_usage_nanos: projection.usage_nanos.to_string(),
        available_credit_nanos: projection.available_nanos.to_string(),
        signup_credit_nanos: projection.signup_credit_nanos.to_string(),
        stripe_enabled,
        topup_options_cents,
        usage_visible_through_unix_ms: projection.latest_interval_end_unix_ms,
    };
    let mut response = Json(balance).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn create_billing_checkout(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateCheckoutRequest>,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let stripe = state
        .cfg
        .stripe
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("Stripe top-ups are not configured"))?;
    if !stripe.topup_options_cents().contains(&request.amount_cents) {
        return Err(ApiError::invalid("unsupported top-up amount").into());
    }
    let idempotency_key = idem_key(&headers)
        .filter(|value| !value.trim().is_empty() && value.len() <= 200)
        .ok_or_else(|| ApiError::invalid("Idempotency-Key is required for Checkout"))?;
    let scope = state.store.workspace_scope(&workspace)?;
    let billing_account_id = scope.account.billing_account_id.clone();
    let projection = billing_projection(&state, &workspace).await?;
    let mut hasher = Sha256::new();
    for value in [&billing_account_id, &idempotency_key] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let intent_id = format!("checkout_{}", hex::encode(hasher.finalize()));
    let intent = state
        .credits
        .create_checkout_intent(&CheckoutIntent {
            intent_id,
            billing_account_id,
            account_id: scope.account.id,
            amount_cents: request.amount_cents,
            currency: "USD".to_string(),
            created_at_unix_ms: unix_millis()?,
            stripe_session_id: None,
            checkout_url: None,
        })
        .await
        .map_err(metering_failure)?;
    let intent = if intent.stripe_session_id.is_some() && intent.checkout_url.is_some() {
        intent
    } else {
        let session = stripe
            .create_checkout_session(&intent, projection.stripe_customer_id.as_deref())
            .await?;
        state
            .credits
            .attach_checkout_session(&intent.intent_id, &session.id, &session.url)
            .await
            .map_err(metering_failure)?
    };
    let response = CreateCheckoutResponse {
        checkout_intent_id: intent.intent_id,
        stripe_session_id: intent
            .stripe_session_id
            .ok_or_else(|| ApiError::internal("checkout session was not persisted"))?,
        url: intent
            .checkout_url
            .ok_or_else(|| ApiError::internal("checkout URL was not persisted"))?,
    };
    let mut response = Json(response).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StripeObjectId {
    Id(String),
    Object { id: String },
}

impl StripeObjectId {
    fn into_id(self) -> String {
        match self {
            Self::Id(id) | Self::Object { id } => id,
        }
    }
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSessionEvent {
    id: String,
    amount_total: Option<i64>,
    currency: Option<String>,
    payment_status: String,
    payment_intent: Option<StripeObjectId>,
    customer: Option<StripeObjectId>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct StripeRefundEvent {
    id: String,
    amount: i64,
    currency: String,
    status: Option<String>,
    payment_intent: Option<StripeObjectId>,
}

async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let stripe = state
        .cfg
        .stripe
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("Stripe top-ups are not configured"))?;
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::invalid("Stripe-Signature header is required"))?;
    let verified = stripe.verify_webhook(signature, &body)?;
    if matches!(
        verified.event.event_type.as_str(),
        "refund.created" | "refund.updated"
    ) {
        let refund: StripeRefundEvent = serde_json::from_value(verified.event.data.object)
            .map_err(|error| ApiError::invalid(format!("invalid refund event: {error}")))?;
        if refund.status.as_deref() != Some("succeeded") {
            return Ok(StatusCode::NO_CONTENT);
        }
        let payment_intent_id = refund
            .payment_intent
            .map(StripeObjectId::into_id)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiError::invalid("refund payment_intent is missing"))?;
        let outcome = state
            .credits
            .apply_checkout_refund(&CheckoutRefund {
                event_id: verified.event.id,
                payload_sha256: verified.payload_sha256,
                stripe_refund_id: refund.id,
                stripe_payment_intent_id: payment_intent_id,
                amount_cents: refund.amount,
                currency: refund.currency.to_ascii_uppercase(),
                livemode: stripe.livemode(),
                processed_at_unix_ms: unix_millis()?,
            })
            .await
            .map_err(metering_failure)?;
        return match outcome {
            CreditApplyOutcome::Accepted | CreditApplyOutcome::Duplicate => {
                Ok(StatusCode::NO_CONTENT)
            }
        };
    }
    if !matches!(
        verified.event.event_type.as_str(),
        "checkout.session.completed" | "checkout.session.async_payment_succeeded"
    ) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let session: StripeCheckoutSessionEvent = serde_json::from_value(verified.event.data.object)
        .map_err(|error| ApiError::invalid(format!("invalid Checkout session event: {error}")))?;
    // A completed session can still be awaiting an asynchronous payment.
    // Only the paid state is allowed to mint credit.
    if session.payment_status != "paid" {
        return Ok(StatusCode::NO_CONTENT);
    }
    let intent_id = session
        .metadata
        .get("checkout_intent_id")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ApiError::invalid("Checkout metadata is missing checkout_intent_id"))?;
    let billing_account_id = session
        .metadata
        .get("billing_account_id")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ApiError::invalid("Checkout metadata is missing billing_account_id"))?;
    let amount_cents = session
        .amount_total
        .filter(|amount| *amount > 0)
        .ok_or_else(|| ApiError::invalid("Checkout amount_total must be positive"))?;
    let currency = session
        .currency
        .map(|value| value.to_ascii_uppercase())
        .ok_or_else(|| ApiError::invalid("Checkout currency is missing"))?;
    let payment_intent_id = session
        .payment_intent
        .map(StripeObjectId::into_id)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::invalid("Checkout payment_intent is missing"))?;
    let outcome = state
        .credits
        .apply_checkout_payment(&CheckoutPayment {
            event_id: verified.event.id,
            payload_sha256: verified.payload_sha256,
            intent_id,
            billing_account_id,
            stripe_session_id: session.id,
            stripe_payment_intent_id: payment_intent_id,
            stripe_customer_id: session.customer.map(StripeObjectId::into_id),
            amount_cents,
            currency,
            livemode: stripe.livemode(),
            processed_at_unix_ms: unix_millis()?,
        })
        .await
        .map_err(metering_failure)?;
    match outcome {
        CreditApplyOutcome::Accepted | CreditApplyOutcome::Duplicate => Ok(StatusCode::NO_CONTENT),
    }
}

#[derive(Debug, Deserialize)]
struct ProjectUsageQuery {
    from_ms: i64,
    to_ms: i64,
    #[serde(default)]
    cat: Option<String>,
    /// Immutable Cat resource ID for historical queries after deletion.
    #[serde(default)]
    cat_id: Option<String>,
    #[serde(default)]
    detail: bool,
    /// Optional bounded projection for charts and period-level detail tables.
    #[serde(default)]
    bucket_ms: Option<i64>,
}

const MIN_USAGE_BUCKET_MS: i64 = 60_000;
const MAX_USAGE_BUCKETS: i64 = 512;

fn validate_usage_bucket(
    from_ms: i64,
    to_ms: i64,
    bucket_ms: Option<i64>,
) -> Result<Option<i64>, Failure> {
    let Some(bucket_ms) = bucket_ms else {
        return Ok(None);
    };
    if bucket_ms < MIN_USAGE_BUCKET_MS {
        return Err(
            ApiError::invalid(format!("bucket_ms must be at least {MIN_USAGE_BUCKET_MS}")).into(),
        );
    }
    let duration = to_ms
        .checked_sub(from_ms)
        .ok_or_else(|| ApiError::invalid("usage query interval overflow"))?;
    if duration <= 0 {
        return Err(ApiError::invalid("usage query interval must be non-empty").into());
    }
    let bucket_count = duration
        .checked_add(bucket_ms - 1)
        .ok_or_else(|| ApiError::invalid("usage bucket count overflow"))?
        / bucket_ms;
    if bucket_count > MAX_USAGE_BUCKETS {
        return Err(ApiError::invalid(format!(
            "bucket_ms produces more than {MAX_USAGE_BUCKETS} buckets"
        ))
        .into());
    }
    Ok(Some(bucket_ms))
}

fn usage_time_buckets(
    intervals: &[UsageInterval],
    from_ms: i64,
    to_ms: i64,
    bucket_ms: i64,
    rate_card: &RateCard,
) -> cats_metering::Result<Vec<UsageTimeBucket>> {
    if to_ms <= from_ms {
        return Ok(Vec::new());
    }
    let duration = to_ms
        .checked_sub(from_ms)
        .ok_or(cats_metering::MeteringError::Overflow)?;
    let bucket_count = usize::try_from(
        duration
            .checked_add(bucket_ms - 1)
            .ok_or(cats_metering::MeteringError::Overflow)?
            / bucket_ms,
    )
    .map_err(|_| cats_metering::MeteringError::Overflow)?;
    let mut quantities = vec![BTreeMap::<&'static str, (UsageMetric, u128)>::new(); bucket_count];

    for interval in intervals {
        let interval_start = interval.interval_start_unix_ms.max(from_ms);
        let interval_end = interval.interval_end_unix_ms.min(to_ms);
        if interval_end <= interval_start || interval.quantity == 0 {
            continue;
        }
        let duration = u128::try_from(interval_end - interval_start)
            .map_err(|_| cats_metering::MeteringError::Overflow)?;
        let mut cursor = interval_start;
        while cursor < interval_end {
            let index = usize::try_from((cursor - from_ms) / bucket_ms)
                .map_err(|_| cats_metering::MeteringError::Overflow)?;
            let boundary = from_ms
                .checked_add(
                    i64::try_from(index + 1)
                        .map_err(|_| cats_metering::MeteringError::Overflow)?
                        .checked_mul(bucket_ms)
                        .ok_or(cats_metering::MeteringError::Overflow)?,
                )
                .ok_or(cats_metering::MeteringError::Overflow)?;
            let part_end = interval_end.min(boundary);
            let start_offset = u128::try_from(cursor - interval_start)
                .map_err(|_| cats_metering::MeteringError::Overflow)?;
            let end_offset = u128::try_from(part_end - interval_start)
                .map_err(|_| cats_metering::MeteringError::Overflow)?;
            let quantity_at_start = interval
                .quantity
                .checked_mul(start_offset)
                .ok_or(cats_metering::MeteringError::Overflow)?
                / duration;
            let quantity_at_end = interval
                .quantity
                .checked_mul(end_offset)
                .ok_or(cats_metering::MeteringError::Overflow)?
                / duration;
            let part_quantity = quantity_at_end
                .checked_sub(quantity_at_start)
                .ok_or(cats_metering::MeteringError::Overflow)?;
            let entry = quantities[index]
                .entry(interval.metric.slug())
                .or_insert((interval.metric, 0));
            entry.1 = entry
                .1
                .checked_add(part_quantity)
                .ok_or(cats_metering::MeteringError::Overflow)?;
            cursor = part_end;
        }
    }

    quantities
        .into_iter()
        .enumerate()
        .map(|(index, values)| {
            let interval_start_unix_ms = from_ms
                .checked_add(
                    i64::try_from(index)
                        .map_err(|_| cats_metering::MeteringError::Overflow)?
                        .checked_mul(bucket_ms)
                        .ok_or(cats_metering::MeteringError::Overflow)?,
                )
                .ok_or(cats_metering::MeteringError::Overflow)?;
            let interval_end_unix_ms = interval_start_unix_ms
                .checked_add(bucket_ms)
                .ok_or(cats_metering::MeteringError::Overflow)?
                .min(to_ms);
            let mut amount_nanos = 0_u128;
            let mut items = Vec::with_capacity(values.len());
            for (_, (metric, quantity)) in values {
                let amount = rate_card.rate_quantity(metric, quantity)?;
                if let Some(amount) = amount {
                    amount_nanos = amount_nanos
                        .checked_add(amount)
                        .ok_or(cats_metering::MeteringError::Overflow)?;
                }
                items.push(UsageSummaryLine {
                    metric,
                    quantity: quantity.to_string(),
                    unit: metric.canonical_unit().to_string(),
                    amount_nanos: amount.map(|value| value.to_string()),
                });
            }
            Ok(UsageTimeBucket {
                interval_start_unix_ms,
                interval_end_unix_ms,
                items,
                amount_nanos: amount_nanos.to_string(),
            })
        })
        .collect()
}

async fn workspace_usage_view(
    state: &AppState,
    workspace: &str,
    attributed_cat_id: Option<String>,
    interval_start_unix_ms: i64,
    interval_end_unix_ms: i64,
) -> ApiResult<(String, UsageView)> {
    let ledger = state.store.billing_ledger_for_workspace(workspace)?;
    let view = state
        .usage
        .query(&MeterUsageQuery {
            billing_account_id: ledger.billing_account_id.clone(),
            workspace_id: Some(workspace.to_string()),
            attributed_cat_id,
            interval_start_unix_ms,
            interval_end_unix_ms,
        })
        .await
        .map_err(metering_failure)?;
    let latest_interval_end_unix_ms = view.latest_interval_end_unix_ms;
    let mut totals = view.totals;
    let mut cats = view.cats;
    let mut details = view.details;
    totals.sort_by_key(|aggregate| aggregate.metric.slug());
    for cat in &mut cats {
        cat.items.sort_by_key(|aggregate| aggregate.metric.slug());
    }
    cats.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    details.sort_by(|left, right| {
        (
            left.interval_start_unix_ms,
            left.interval_end_unix_ms,
            left.source_id.as_str(),
            left.end_sequence,
        )
            .cmp(&(
                right.interval_start_unix_ms,
                right.interval_end_unix_ms,
                right.source_id.as_str(),
                right.end_sequence,
            ))
    });
    Ok((
        ledger.billing_account_id,
        UsageView {
            totals,
            cats,
            details,
            latest_interval_end_unix_ms,
        },
    ))
}

async fn workspace_usage(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    Query(query): Query<ProjectUsageQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if query.cat.is_some() && query.cat_id.is_some() {
        return Err(ApiError::invalid("cat and cat_id are mutually exclusive").into());
    }
    let bucket_ms = validate_usage_bucket(query.from_ms, query.to_ms, query.bucket_ms)?;
    let cat_id = if let Some(cat_id) = query.cat_id {
        if cat_id.trim().is_empty() {
            return Err(ApiError::invalid("cat_id must not be empty").into());
        }
        Some(cat_id)
    } else {
        query
            .cat
            .as_deref()
            .map(|cat| state.store.get_cat(&workspace, cat).map(|cat| cat.id))
            .transpose()?
    };
    let (billing_account_id, view) =
        workspace_usage_view(&state, &workspace, cat_id, query.from_ms, query.to_ms).await?;
    let rate_card = RateCard::sprites_compute_v1();

    let mut amount_nanos = 0_u128;
    let mut items = Vec::with_capacity(view.totals.len());
    for aggregate in &view.totals {
        let amount = rate_card
            .rate_quantity(aggregate.metric, aggregate.quantity)
            .map_err(metering_failure)?;
        if let Some(amount) = amount {
            amount_nanos = amount_nanos
                .checked_add(amount)
                .ok_or_else(|| ApiError::internal("rated amount overflow"))?;
        }
        items.push(UsageSummaryLine {
            metric: aggregate.metric,
            quantity: aggregate.quantity.to_string(),
            unit: aggregate.metric.canonical_unit().to_string(),
            amount_nanos: amount.map(|value| value.to_string()),
        });
    }

    let mut cats = Vec::with_capacity(view.cats.len());
    for cat in &view.cats {
        let mut cat_amount = 0_u128;
        let mut cat_items = Vec::with_capacity(cat.items.len());
        for aggregate in &cat.items {
            let amount = rate_card
                .rate_quantity(aggregate.metric, aggregate.quantity)
                .map_err(metering_failure)?;
            if let Some(amount) = amount {
                cat_amount = cat_amount
                    .checked_add(amount)
                    .ok_or_else(|| ApiError::internal("rated Cat amount overflow"))?;
            }
            cat_items.push(UsageSummaryLine {
                metric: aggregate.metric,
                quantity: aggregate.quantity.to_string(),
                unit: aggregate.metric.canonical_unit().to_string(),
                amount_nanos: amount.map(|value| value.to_string()),
            });
        }
        cats.push(CatUsageSummary {
            cat_id: cat.cat_id.clone(),
            items: cat_items,
            amount_nanos: cat_amount.to_string(),
        });
    }

    let time_buckets = if let (Some(bucket_ms), Some(latest_interval_end_unix_ms)) =
        (bucket_ms, view.latest_interval_end_unix_ms)
    {
        usage_time_buckets(
            &view.details,
            query.from_ms,
            query.to_ms.min(latest_interval_end_unix_ms),
            bucket_ms,
            &rate_card,
        )
        .map_err(metering_failure)?
    } else {
        Vec::new()
    };
    let details = if query.detail {
        view.details
            .iter()
            .map(|interval| UsageDetailLine {
                interval_start_unix_ms: interval.interval_start_unix_ms,
                interval_end_unix_ms: interval.interval_end_unix_ms,
                resource_type: interval.attribution.resource_type.clone(),
                resource_id: interval.attribution.resource_id.clone(),
                attributed_cat_id: interval.attribution.attributed_cat_id.clone(),
                metric: interval.metric,
                quantity: interval.quantity.to_string(),
                unit: interval.metric.canonical_unit().to_string(),
                source_id: interval.source_id.clone(),
                source_epoch: interval.source_epoch.clone(),
                end_sequence: interval.end_sequence,
            })
            .collect()
    } else {
        Vec::new()
    };
    let report = UsageReport {
        billing_account_id,
        workspace_id: workspace,
        interval_start_unix_ms: query.from_ms,
        interval_end_unix_ms: query.to_ms,
        status: "provisional".to_string(),
        currency: rate_card.currency,
        rate_card_id: rate_card.id,
        latest_interval_end_unix_ms: view.latest_interval_end_unix_ms,
        items,
        cats,
        time_buckets,
        details,
        amount_nanos: amount_nanos.to_string(),
    };
    let mut response = Json(report).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn node_work_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NodeWorkStatusRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    let should_wake = state.store.ingest_guest_work(&request)?;
    if should_wake {
        state.notify.notify_one();
    } else {
        state.controller.maybe_auto_suspend(&request.cat_id)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn acquire_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AcquireWorkRequest>,
) -> ApiResult<Json<AcquireWorkResponse>> {
    check_service_auth(&state, &headers).await?;
    if request.kind == WorkKind::Guest {
        return Err(ApiError::invalid("guest work must come through the owning node").into());
    }
    let lease = state.store.acquire_work(
        &request.cat_id,
        request.kind,
        &request.owner_id,
        &request.label,
        request.ttl_ms,
    )?;
    Ok(Json(AcquireWorkResponse { lease }))
}

async fn release_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReleaseWorkRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    if let Some(cat_id) = state.store.release_work(&request.lease_id)? {
        state.controller.maybe_auto_suspend(&cat_id)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn cordon_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    cordon_registered_node(&state, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Node>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_nodes()?,
    }))
}

async fn admin_list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeSummary>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_node_summaries()?,
    }))
}

/// Resource routes key on the immutable workspace ID, so a machine token — which
/// has no WorkOS identity to enumerate its own workspaces from — needs a way to
/// turn an `account/workspace` locator into that ID.
async fn admin_list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_all_workspace_views()?,
    }))
}

async fn admin_get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<NodeSummary>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(state.store.node_summary(&id)?))
}

async fn admin_node_cats(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeCatSummary>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.node_cat_summaries(&id)?,
    }))
}

async fn admin_node_action(
    State(state): State<AppState>,
    Path((id, verb)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let node = state.store.get_node(&id)?;
    let status = match verb.as_str() {
        "cordon" => {
            cordon_registered_node(&state, &id)?;
            StatusCode::OK
        }
        "uncordon" => {
            if node.state == NodeState::Lost {
                return Err(ApiError::failed_precondition(
                    "lost node must heartbeat or register before uncordon",
                )
                .into());
            }
            state.store.set_node_state(&id, NodeState::Ready)?;
            state.notify.notify_one();
            StatusCode::OK
        }
        "drain" => {
            if node.state == NodeState::Lost {
                return Err(ApiError::failed_precondition(
                    "lost nodes are fenced automatically and cannot be drained",
                )
                .into());
            }
            state.store.set_node_state(&id, NodeState::Draining)?;
            state.notify.notify_one();
            StatusCode::ACCEPTED
        }
        _ => return Err(ApiError::invalid(format!("unknown node action {verb}")).into()),
    };
    Ok((status, Json(state.store.node_summary(&id)?)).into_response())
}

async fn admin_delete_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    state.store.delete_node(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

fn monitoring_snapshot(state: &AppState) -> crate::store::Result<MonitoringOverview> {
    let mut cat_counts = CatStateCounts::default();
    for cat in state.store.list_all_cats()? {
        cat_counts.total += 1;
        match cat.observed_state {
            ObservedState::Running => cat_counts.running += 1,
            ObservedState::Suspended => cat_counts.suspended += 1,
            ObservedState::Warm => cat_counts.warm += 1,
            ObservedState::Cold => cat_counts.cold += 1,
            ObservedState::Failed | ObservedState::Unknown => cat_counts.failed_or_unknown += 1,
            _ => cat_counts.transitional += 1,
        }
    }

    let summaries = state.store.list_node_summaries()?;
    let mut node_counts = NodeStateCounts::default();
    let mut capacity = FleetCapacity::default();
    let mut usage = FleetUsage::default();
    let mut cpu_weighted_sum = 0.0;
    let mut cpu_weight = 0_u64;
    let mut logical_cpus = 0_u64;
    let mut memory_total = 0_u64;
    let mut memory_available = 0_u64;
    let mut memory_samples = 0_u64;
    let mut disk_total = 0_u64;
    let mut disk_available = 0_u64;
    let mut disk_samples = 0_u64;
    for summary in &summaries {
        node_counts.total += 1;
        match summary.node.state {
            NodeState::Ready => node_counts.ready += 1,
            NodeState::Cordoned => node_counts.cordoned += 1,
            NodeState::Draining => node_counts.draining += 1,
            NodeState::Lost => node_counts.lost += 1,
        }
        capacity.total_cpus += u64::from(summary.node.capacity.cpus);
        capacity.total_memory_mib += summary.node.capacity.memory_mib;
        capacity.assigned_cpus += u64::from(summary.assigned_cpus);
        capacity.assigned_memory_mib += summary.assigned_memory_mib;

        if summary.node.state == NodeState::Lost {
            continue;
        }
        let Some(telemetry) = &summary.node.telemetry else {
            continue;
        };
        if let Some(count) = telemetry.host_logical_cpus {
            logical_cpus += u64::from(count);
        }
        if let Some(percent) = telemetry.host_cpu_usage_percent {
            let weight = u64::from(
                telemetry
                    .host_logical_cpus
                    .unwrap_or(summary.node.capacity.cpus),
            );
            if weight > 0 {
                cpu_weighted_sum += percent.clamp(0.0, 100.0) * weight as f64;
                cpu_weight += weight;
            }
        }
        if let (Some(total), Some(available)) = (
            telemetry.host_memory_total_mib,
            telemetry.host_memory_available_mib,
        ) {
            memory_total = memory_total.saturating_add(total);
            memory_available = memory_available.saturating_add(available.min(total));
            memory_samples += 1;
        }
        if let (Some(total), Some(available)) = (
            telemetry.host_disk_total_bytes,
            telemetry.host_disk_available_bytes,
        ) {
            disk_total = disk_total.saturating_add(total);
            disk_available = disk_available.saturating_add(available.min(total));
            disk_samples += 1;
        }
    }
    if cpu_weight > 0 {
        usage.cpu_usage_percent = Some(cpu_weighted_sum / cpu_weight as f64);
    }
    if logical_cpus > 0 {
        usage.logical_cpus = Some(logical_cpus);
    }
    if memory_samples > 0 {
        usage.memory_total_mib = Some(memory_total);
        usage.memory_used_mib = Some(memory_total.saturating_sub(memory_available));
    }
    if disk_samples > 0 {
        usage.disk_total_bytes = Some(disk_total);
        usage.disk_used_bytes = Some(disk_total.saturating_sub(disk_available));
    }

    Ok(MonitoringOverview {
        generated_at_unix: crate::store::now_unix(),
        cats: cat_counts,
        nodes: node_counts,
        operations: state.store.operation_counts()?,
        capacity,
        usage,
    })
}

async fn admin_monitoring(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MonitoringOverview>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(monitoring_snapshot(&state)?))
}

async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let overview = monitoring_snapshot(&state)?;
    let mut body = String::new();
    macro_rules! metric {
        ($name:expr, $value:expr) => {
            body.push_str(&format!("{} {}\n", $name, $value));
        };
    }
    metric!("cats_control_plane_cats_total", overview.cats.total);
    metric!("cats_control_plane_cats_running", overview.cats.running);
    metric!("cats_control_plane_cats_suspended", overview.cats.suspended);
    metric!("cats_control_plane_cats_warm", overview.cats.warm);
    metric!("cats_control_plane_cats_cold", overview.cats.cold);
    metric!(
        "cats_control_plane_cats_transitional",
        overview.cats.transitional
    );
    metric!(
        "cats_control_plane_cats_failed_or_unknown",
        overview.cats.failed_or_unknown
    );
    metric!("cats_control_plane_nodes_ready", overview.nodes.ready);
    metric!("cats_control_plane_nodes_cordoned", overview.nodes.cordoned);
    metric!("cats_control_plane_nodes_draining", overview.nodes.draining);
    metric!("cats_control_plane_nodes_lost", overview.nodes.lost);
    metric!(
        "cats_control_plane_operations_pending",
        overview.operations.pending
    );
    metric!(
        "cats_control_plane_operations_running",
        overview.operations.running
    );
    metric!(
        "cats_control_plane_operations_succeeded",
        overview.operations.succeeded
    );
    metric!(
        "cats_control_plane_operations_failed",
        overview.operations.failed
    );
    metric!(
        "cats_control_plane_capacity_cpus",
        overview.capacity.total_cpus
    );
    metric!(
        "cats_control_plane_capacity_assigned_cpus",
        overview.capacity.assigned_cpus
    );
    metric!(
        "cats_control_plane_capacity_memory_mib",
        overview.capacity.total_memory_mib
    );
    metric!(
        "cats_control_plane_capacity_assigned_memory_mib",
        overview.capacity.assigned_memory_mib
    );
    if let Some(percent) = overview.usage.cpu_usage_percent {
        metric!("cats_control_plane_host_cpu_usage_percent", percent);
    }
    if let Some(logical_cpus) = overview.usage.logical_cpus {
        metric!("cats_control_plane_host_logical_cpus", logical_cpus);
    }
    if let Some(total) = overview.usage.memory_total_mib {
        metric!("cats_control_plane_host_memory_total_mib", total);
    }
    if let Some(used) = overview.usage.memory_used_mib {
        metric!("cats_control_plane_host_memory_used_mib", used);
    }
    if let Some(total) = overview.usage.disk_total_bytes {
        metric!("cats_control_plane_host_disk_total_bytes", total);
    }
    if let Some(used) = overview.usage.disk_used_bytes {
        metric!("cats_control_plane_host_disk_used_bytes", used);
    }
    for summary in state.store.list_node_summaries()? {
        let node_id = summary
            .node
            .id
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('"', "\\\"");
        metric!(
            format!("cats_node_heartbeat_age_seconds{{node_id=\"{node_id}\"}}"),
            summary.heartbeat_age_seconds
        );
        if let Some(telemetry) = summary.node.telemetry {
            metric!(
                format!("cats_node_observed_cats{{node_id=\"{node_id}\"}}"),
                telemetry.observed_cats
            );
            metric!(
                format!("cats_node_allocated_cpus{{node_id=\"{node_id}\"}}"),
                telemetry.allocated_cpus
            );
            metric!(
                format!("cats_node_allocated_memory_mib{{node_id=\"{node_id}\"}}"),
                telemetry.allocated_memory_mib
            );
            // Concurrent-wake gate saturation (ADR-0002 §8). Exported
            // unconditionally so a node sitting at its budget is visible as a
            // gauge rather than only as wake latency.
            metric!(
                format!("cats_node_wake_in_flight{{node_id=\"{node_id}\"}}"),
                telemetry.wake_in_flight
            );
            metric!(
                format!("cats_node_wake_commitment_bytes{{node_id=\"{node_id}\"}}"),
                telemetry.wake_commitment_bytes
            );
            metric!(
                format!("cats_node_wake_peak_in_flight{{node_id=\"{node_id}\"}}"),
                telemetry.wake_peak_in_flight
            );
            metric!(
                format!("cats_node_wake_commitment_budget_bytes{{node_id=\"{node_id}\"}}"),
                telemetry.wake_commitment_budget_bytes
            );
            if let Some(logical_cpus) = telemetry.host_logical_cpus {
                metric!(
                    format!("cats_node_logical_cpus{{node_id=\"{node_id}\"}}"),
                    logical_cpus
                );
            }
            if let Some(percent) = telemetry.host_cpu_usage_percent {
                metric!(
                    format!("cats_node_cpu_usage_percent{{node_id=\"{node_id}\"}}"),
                    percent
                );
            }
            if let Some(load) = telemetry.load_average_1m {
                metric!(
                    format!("cats_node_load_average_1m{{node_id=\"{node_id}\"}}"),
                    load
                );
            }
            if let Some(available) = telemetry.host_memory_available_mib {
                metric!(
                    format!("cats_node_memory_available_mib{{node_id=\"{node_id}\"}}"),
                    available
                );
            }
            if let Some(total) = telemetry.host_memory_total_mib {
                metric!(
                    format!("cats_node_memory_total_mib{{node_id=\"{node_id}\"}}"),
                    total
                );
                if let Some(available) = telemetry.host_memory_available_mib {
                    metric!(
                        format!("cats_node_memory_used_mib{{node_id=\"{node_id}\"}}"),
                        total.saturating_sub(available.min(total))
                    );
                }
            }
            if let Some(available) = telemetry.host_disk_available_bytes {
                metric!(
                    format!("cats_node_disk_available_bytes{{node_id=\"{node_id}\"}}"),
                    available
                );
            }
            if let Some(total) = telemetry.host_disk_total_bytes {
                metric!(
                    format!("cats_node_disk_total_bytes{{node_id=\"{node_id}\"}}"),
                    total
                );
                if let Some(available) = telemetry.host_disk_available_bytes {
                    metric!(
                        format!("cats_node_disk_used_bytes{{node_id=\"{node_id}\"}}"),
                        total.saturating_sub(available.min(total))
                    );
                }
            }
            for cat in telemetry.cat_resources {
                let cat_id = cat
                    .cat_id
                    .replace('\\', "\\\\")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('"', "\\\"");
                let labels = format!("node_id=\"{node_id}\",cat_id=\"{cat_id}\"");
                if let Some(cores) = cat.cpu_usage_cores {
                    metric!(format!("cats_cat_cpu_usage_cores{{{labels}}}"), cores);
                }
                if let Some(bytes) = cat.memory_rss_bytes {
                    metric!(format!("cats_cat_memory_rss_bytes{{{labels}}}"), bytes);
                }
                if let Some(bytes) = cat.host_disk_used_bytes {
                    metric!(format!("cats_cat_host_disk_used_bytes{{{labels}}}"), bytes);
                }
            }
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

/// Wake handler used by the gateway (`POST /v1/routes/wake?hostname=`).
async fn wake_route_handler(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    wake_route(&state, &q.hostname).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_operation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Operation>> {
    // Authenticate before looking up an opaque ID so unauthenticated callers
    // cannot use status differences to enumerate operations.
    check_authenticated(&state, &headers).await?;
    let operation = state.store.get_operation(&id)?;
    let scope = check_workspace_auth(&state, &headers, &operation.workspace_id).await?;
    if scope.workspace.id != operation.workspace_id {
        return Err(ApiError::internal("operation workspace ownership is inconsistent").into());
    }
    Ok(Json(operation))
}

async fn list_operations(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Operation>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(ListResponse {
        items: state.store.list_operations(&workspace)?,
    }))
}

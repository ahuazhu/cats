//! Versioned HTTP API. Cat and PersistentDisk lifecycle mutations use the
//! synchronous semantic protocol; their identity comes from current resource
//! state and target state, not a caller request token or a separate result
//! resource.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use cats_api::auth::{
    AccountInvitation, AccountMember, CreateInvitationRequest, CreateWorkspaceRequest,
    CreateWorkspaceTokenRequest, CreatedWorkspaceToken, UpdateAccountMemberRequest,
    UpdateWorkspaceRequest, Workspace, WorkspaceToken,
};
use cats_api::billing::{BillingBalance, CreateCheckoutRequest, CreateCheckoutResponse};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::list::ListResponse;
use cats_api::metering::{
    CatUsageSummary, UsageDetailLine, UsageMetric, UsageReport, UsageSummaryLine, UsageTimeBucket,
};
use cats_metering::{
    CheckoutIntent, CheckoutPayment, CheckoutRefund, CreditApplyOutcome, RateCard,
    UsageQuery as MeterUsageQuery,
};
use cats_metering::{UsageInterval, UsageView};

use crate::server::AppState;

mod accounts;
mod billing;
mod nodes;
pub(crate) mod runtime_node_authority;
mod runtime_usage;
pub mod semantic_nodes;
pub mod semantic_resources;
mod usage;

use accounts::*;
use billing::*;
use nodes::*;
use usage::*;

#[derive(Debug)]
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

async fn readiness(State(state): State<AppState>) -> Response {
    if readiness_status(&state.readiness) == StatusCode::OK {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unready").into_response()
    }
}

pub(crate) fn readiness_status(readiness: &crate::server::ReadinessLatch) -> StatusCode {
    if readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

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
    WorkspaceAutomation { workspace_id: String },
    User(crate::auth::AccessIdentity),
}

fn workspace_token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
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
    let token_hash = workspace_token_hash(token);
    if let Some(workspace_id) = state
        .store
        .execute(move |store| store.active_workspace_for_token_hash(&token_hash))
        .await?
    {
        return Ok(Some(Principal::WorkspaceAutomation { workspace_id }));
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
            let workspace_id = workspace.to_string();
            let scope = state
                .store
                .execute(move |store| store.workspace_scope(&workspace_id))
                .await?;
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
        Some(Principal::WorkspaceAutomation { workspace_id }) => workspace_id == workspace,
        Some(Principal::Service) | None => false,
    };
    if bearer_allowed
        || crate::auth::web_session_allows_workspace(state, headers, workspace).await?
    {
        if let Some(scope) = resolved_scope {
            return Ok(scope);
        }
        let workspace = workspace.to_string();
        return state
            .store
            .execute(move |store| store.workspace_scope(&workspace))
            .await
            .map_err(Into::into);
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers).await,
    ))
}

async fn check_workspace_token_admin(
    state: &AppState,
    headers: &HeaderMap,
    workspace: &str,
) -> ApiResult<crate::store::WorkspaceScope> {
    match bearer_principal(state, headers).await? {
        Some(Principal::WorkspaceAutomation { .. }) | Some(Principal::Service) => {
            Err(auth_failure(true))
        }
        _ => check_workspace_auth(state, headers, workspace).await,
    }
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
        Some(Principal::Service | Principal::WorkspaceAutomation { .. }) | None => false,
    };
    if bearer_allowed || crate::auth::web_session_is_admin(state, headers).await {
        return Ok(());
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers).await,
    ))
}

/// Authenticate the observability endpoint without consulting PostgreSQL.
/// Static scrape credentials, WorkOS administrator JWTs, and the sealed admin
/// browser session preserve the existing administrator surface while a stuck
/// control-store lane remains diagnosable.
async fn check_metrics_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if let Some(token) = bearer_token(headers) {
        if token == state.cfg.admin_token {
            return Ok(());
        }
        if token == state.cfg.auth_token {
            return Err(auth_failure(true));
        }
        let Some(workos) = state.cfg.workos.as_ref() else {
            return Err(auth_failure(false));
        };
        let identity = workos.verify_access_token(token).await?;
        if workos.is_fleet_administrator(&identity) {
            return Ok(());
        }
        return Err(auth_failure(true));
    }
    if crate::auth::web_session_is_admin_without_store(state, headers) {
        return Ok(());
    }
    Err(auth_failure(false))
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
    } else if let Some(identity) = crate::auth::web_user_identity(state, headers).await {
        let user_id = identity.user_id.ok_or_else(|| auth_failure(true))?;
        (user_id, identity.organization_id, identity.permissions)
    } else {
        return Err(auth_failure(false));
    };
    let account_id = account_id.to_string();
    let account = state
        .store
        .execute(move |store| store.account_by_id(&account_id))
        .await?;
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

fn idem_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

async fn billing_account_id_for_workspace(
    state: &AppState,
    workspace: &str,
) -> Result<String, ApiError> {
    let workspace = workspace.to_string();
    state
        .store
        .execute(move |store| store.billing_account_id_for_workspace(&workspace))
        .await
}

fn metering_failure(error: cats_metering::MeteringError) -> Failure {
    match error {
        cats_metering::MeteringError::Invalid(message) => ApiError::invalid(message).into(),
        cats_metering::MeteringError::Conflict(message) => ApiError::conflict(message).into(),
        other => ApiError::internal(other.to_string()).into(),
    }
}

pub fn router(state: AppState) -> Router {
    let semantic_resources = semantic_resources::routes(Arc::clone(&state.semantic_resources));
    let semantic_nodes = semantic_nodes::routes(state.semantic_node_http.clone());
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
        .merge(crate::ui::console_asset_routes())
        .route("/auth/config", get(crate::auth::config))
        .route("/auth/login", get(crate::auth::login))
        .route("/auth/callback", get(crate::auth::callback))
        .route("/auth/session", get(crate::auth::session))
        .route("/auth/workspace", post(crate::auth::switch_workspace))
        .route("/auth/logout", get(crate::auth::logout))
        .route("/healthz", get(readiness))
        .route("/metrics", get(prometheus_metrics))
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
            "/v1/workspaces/{workspace}/tokens",
            post(create_workspace_token).get(list_workspace_tokens),
        )
        .route(
            "/v1/workspaces/{workspace}/tokens/{token}",
            axum::routing::delete(revoke_workspace_token),
        )
        .route(
            "/v1/admin/usage/source-terminal/discover",
            post(runtime_usage::discover_source_terminal),
        )
        .route(
            "/v1/admin/usage/target-terminal/begin",
            post(runtime_usage::begin_target_terminal),
        )
        .route(
            "/v1/admin/usage/target-terminal/complete",
            post(runtime_usage::complete_target_terminal),
        )
        .route(
            "/v1/admin/runtime/node-authority-applies",
            post(runtime_node_authority::apply_runtime_node_authority)
                .fallback(runtime_node_authority::apply_runtime_node_authority),
        )
        .route(
            "/v1/admin/production/mutation-admission-commands",
            post(runtime_node_authority::apply_production_mutation_admission)
                .fallback(runtime_node_authority::apply_production_mutation_admission),
        )
        .route(
            "/v1/admin/production/mutation-admission-command-discoveries",
            post(runtime_node_authority::discover_production_mutation_admission_command),
        )
        .route(
            "/v1/admin/production/mutation-admission-state-discoveries",
            post(runtime_node_authority::get_production_mutation_admission_state),
        )
        .route(
            "/v1/admin/production/qualification-product-inventory-discoveries",
            post(runtime_node_authority::discover_production_qualification_product_inventory),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/balance",
            get(workspace_billing_balance),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/checkout",
            post(create_billing_checkout),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/usage",
            get(workspace_usage),
        )
        .route("/v1/billing/stripe/webhook", post(stripe_webhook))
        .route("/v1/admin/workspaces", get(admin_list_workspaces))
        .merge(semantic_resources)
        .merge(semantic_nodes)
        .fallback(crate::ui::not_found)
        .with_state(state)
}

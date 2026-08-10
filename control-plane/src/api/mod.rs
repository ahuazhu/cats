//! Versioned HTTP API (arch doc §17). Mutations return `202 + Operation`;
//! `Idempotency-Key` retries replay the original operation; actions live
//! under `/actions/<verb>` (path-safe rendering of the `:verb` convention).

use std::collections::BTreeMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
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
    RejectedCheckpoint, UsageDetailLine, UsageMetric, UsageReport, UsageSummaryLine,
    UsageTimeBucket, MAX_USAGE_INGEST_BODY_BYTES,
};
use cats_api::oci::{DeployOciRequest, OciDeployment};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_metering::{
    AttributedCheckpoint, CheckoutIntent, CheckoutPayment, CheckoutRefund, CreditApplyOutcome,
    IngestOutcome, RateCard, UsageAttribution, UsageInterval, UsageQuery as MeterUsageQuery,
    UsageView,
};

use crate::server::AppState;
use crate::store::OciDeploymentClaim;

mod accounts;
mod agent_registration;
mod billing;
mod cat_create_v2;
mod cats;
mod disks;
mod endpoints;
mod nodes;
mod operations;
mod routes;
pub(crate) mod runtime_node_authority;
mod runtime_spine;
mod runtime_volume_transitions;
mod sessions;
mod usage;

use accounts::*;
use billing::*;
use cat_create_v2::*;
use cats::*;
use disks::*;
use endpoints::*;
use nodes::*;
use operations::*;
use routes::*;
use sessions::*;
use usage::*;

pub(crate) use billing::enforce_exhausted_billing_accounts;
pub use cats::ensure_running;

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

/// Reject an entry point whose implementation still owns legacy work leases
/// or calls the retired Node HTTP runtime. This check must be the first handler
/// action so production cannot authenticate, write an idempotency/work row, or
/// emit an outbound call before failing closed.
fn require_legacy_node_runtime_for_tests(state: &AppState) -> ApiResult<()> {
    if state.legacy_node_runtime_for_tests {
        Ok(())
    } else {
        Err(
            ApiError::unavailable("operation is unavailable during the signed runtime cutover")
                .into(),
        )
    }
}

async fn readiness(State(state): State<AppState>) -> Response {
    if state.readiness.is_ready() {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unready").into_response()
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

async fn check_authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if bearer_principal(state, headers).await?.is_some()
        || crate::auth::has_any_web_session(state, headers).await
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

async fn cordon_registered_node(state: &AppState, id: &str) -> ApiResult<()> {
    let id = id.to_string();
    state
        .store
        .execute(move |store| {
            let node = store.get_node(&id)?;
            if node.state == NodeState::Draining && !store.cats_on_node(&id)?.is_empty() {
                return Err(ApiError::failed_precondition(
                    "node drain is still in progress; use uncordon to cancel it",
                ));
            }
            store.set_node_state(&id, NodeState::Cordoned)
        })
        .await?;
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

async fn reject_legacy_authority(
    _request: axum::extract::Request,
    _next: axum::middleware::Next,
) -> Response {
    Failure(ApiError::unavailable(
        "legacy product authority is unavailable during the signed runtime cutover",
    ))
    .into_response()
}

pub fn router(state: AppState) -> Router {
    let cat_create_route = if state.legacy_node_runtime_for_tests {
        post(create_cat_legacy_for_tests)
    } else {
        post(create_cat_v2)
    };
    // These handlers read or mutate the retired Cat/Operation/Node authority.
    // Keep them reachable only from the explicit pre-cutover test composition.
    // The production middleware runs before authentication, body extraction,
    // PostgreSQL access, idempotency writes, and outbound Node calls.
    let legacy_authority = Router::new()
        .route("/v1/workspaces/{workspace}/cats", get(list_cats))
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}",
            get(get_cat).delete(delete_cat),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/actions/{verb}",
            post(cat_action),
        )
        .route("/v1/workspaces/{workspace}/cats/{cat}/exec", post(exec_cat))
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/oci-deployments",
            post(deploy_oci).get(list_oci_deployments),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/shell",
            get(shell_cat),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/auto-suspend",
            get(get_auto_suspend).put(update_auto_suspend),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/expiry",
            get(get_expiry).put(update_expiry),
        )
        .route(
            "/v1/workspaces/{workspace}/cats/{cat}/work",
            get(get_cat_work),
        )
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
        .route(
            "/v1/workspaces/{workspace}/operations",
            get(list_operations),
        )
        .route(
            "/v1/internal/usage/checkpoints",
            post(ingest_usage_checkpoints)
                .layer(DefaultBodyLimit::max(MAX_USAGE_INGEST_BODY_BYTES)),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/usage",
            get(workspace_usage),
        )
        .route("/v1/nodes/{id}/actions/cordon", post(cordon_node))
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/admin/nodes", get(admin_list_nodes))
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
        .route("/v1/routes/resolve", get(resolve_route))
        .route("/v1/routes/wake", post(wake_route_handler));
    let legacy_authority = if state.legacy_node_runtime_for_tests {
        legacy_authority
    } else {
        legacy_authority.route_layer(axum::middleware::from_fn(reject_legacy_authority))
    };
    let runtime_volume_authority = if state.legacy_node_runtime_for_tests {
        Router::new()
    } else {
        Router::new()
            .route(
                "/v1/internal/runtime/volume-transitions",
                post(runtime_volume_transitions::mutation)
                    .fallback(runtime_volume_transitions::mutation),
            )
            .route(
                "/v1/internal/runtime/volume-transition-evidence",
                post(runtime_volume_transitions::evidence)
                    .fallback(runtime_volume_transitions::evidence),
            )
    };

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
        .route(
            "/ui/cat-create-v2.mjs",
            get(crate::ui::cat_create_v2_script),
        )
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
        .route("/v1/workspaces/{workspace}/cats", cat_create_route)
        .route(
            "/v1/workspaces/{workspace}/tokens",
            post(create_workspace_token).get(list_workspace_tokens),
        )
        .route(
            "/v1/workspaces/{workspace}/tokens/{token}",
            axum::routing::delete(revoke_workspace_token),
        )
        .route(
            "/v1/internal/runtime/agent-sessions",
            post(agent_registration::register_agent_session)
                .fallback(agent_registration::register_agent_session),
        )
        .route(
            "/v1/internal/runtime/desired-reads",
            post(runtime_spine::desired_read).fallback(runtime_spine::desired_read),
        )
        .route(
            "/v1/internal/runtime/observations",
            post(runtime_spine::observation).fallback(runtime_spine::observation),
        )
        .route(
            "/v1/admin/runtime/node-authority-applies",
            post(runtime_node_authority::apply_runtime_node_authority)
                .fallback(runtime_node_authority::apply_runtime_node_authority),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/balance",
            get(workspace_billing_balance),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/checkout",
            post(create_billing_checkout),
        )
        .route("/v1/billing/stripe/webhook", post(stripe_webhook))
        .route("/v1/admin/workspaces", get(admin_list_workspaces))
        .merge(runtime_volume_authority)
        .merge(legacy_authority)
        .fallback(crate::ui::not_found)
        .with_state(state)
}

/// Adds the retired shared-bearer Node heartbeat/work mutation surface only
/// for pre-cutover integration suites. No production composition root calls
/// this function.
#[doc(hidden)]
pub fn router_with_legacy_node_runtime_for_tests(state: AppState) -> Router {
    router(state.clone()).merge(
        Router::new()
            .route(
                "/v1/nodes/heartbeat",
                post(nodes::legacy_heartbeat_for_tests),
            )
            .route("/v1/nodes/work-status", post(node_work_status))
            .route("/v1/internal/work/acquire", post(acquire_work))
            .route("/v1/internal/work/release", post(release_work))
            .with_state(state),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn route_method_set_matches_snapshot() {
        let source = include_str!("mod.rs");
        let router = source
            .split_once("pub fn router")
            .expect("router declaration")
            .1
            .split_once(".fallback(crate::ui::not_found)")
            .expect("router fallback")
            .0;
        let mut routes = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = router[cursor..].find(".route(") {
            let start = cursor + offset + ".route(".len();
            let mut depth = 1;
            let mut in_string = false;
            let mut escaped = false;
            let mut end = start;
            for (offset, byte) in router.as_bytes()[start..].iter().enumerate() {
                end = start + offset + 1;
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if *byte == b'\\' {
                        escaped = true;
                    } else if *byte == b'"' {
                        in_string = false;
                    }
                    continue;
                }
                match *byte {
                    b'"' => in_string = true,
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let call = &router[start..end - 1];
            let path_start = call.find('"').expect("route path") + 1;
            let path_end = path_start + call[path_start..].find('"').expect("route path end");
            let path = &call[path_start..path_end];
            let methods = &call[path_end + 1..];
            for (name, method) in [
                ("get", "GET"),
                ("post", "POST"),
                ("put", "PUT"),
                ("patch", "PATCH"),
                ("delete", "DELETE"),
            ] {
                let needle = format!("{name}(");
                for (index, _) in methods.match_indices(&needle) {
                    let is_method = index == 0
                        || !methods.as_bytes()[index - 1].is_ascii_alphanumeric()
                            && methods.as_bytes()[index - 1] != b'_';
                    if is_method {
                        routes.push(format!("{method} {path}"));
                    }
                }
            }
            cursor = end;
        }
        assert!(
            router.contains(".route(\"/v1/workspaces/{workspace}/cats\", cat_create_route)"),
            "conditional Cat-create route is missing",
        );
        routes.push("POST /v1/workspaces/{workspace}/cats".to_string());
        routes.sort();

        let expected = r#"DELETE /v1/accounts/{account}/members/{membership}
DELETE /v1/admin/nodes/{id}
DELETE /v1/workspaces/{workspace}/cats/{cat}
DELETE /v1/workspaces/{workspace}/disks/{disk}
DELETE /v1/workspaces/{workspace}/tokens/{token}
GET /
GET /admin
GET /admin/
GET /assets/cats-logo.svg
GET /assets/cats-mark.svg
GET /assets/cats-og.png
GET /assets/cats-og.svg
GET /assets/public.css
GET /auth/callback
GET /auth/config
GET /auth/login
GET /auth/logout
GET /auth/session
GET /docs
GET /docs/
GET /docs/{slug}
GET /docs/{slug}/
GET /healthz
GET /metrics
GET /robots.txt
GET /site.webmanifest
GET /sitemap.xml
GET /ui/admin.js
GET /ui/cat-create-v2.mjs
GET /ui/common.js
GET /ui/i18n.js
GET /ui/styles.css
GET /ui/user.js
GET /user
GET /user/
GET /user/{account}/{workspace}
GET /user/{account}/{workspace}/
GET /v1/accounts/{account}/invitations
GET /v1/accounts/{account}/members
GET /v1/admin/monitoring
GET /v1/admin/nodes
GET /v1/admin/nodes/{id}
GET /v1/admin/nodes/{id}/cats
GET /v1/admin/workspaces
GET /v1/me
GET /v1/nodes
GET /v1/operations/{id}
GET /v1/routes/resolve
GET /v1/workspaces
GET /v1/workspaces/{workspace}/billing/balance
GET /v1/workspaces/{workspace}/billing/usage
GET /v1/workspaces/{workspace}/cats
GET /v1/workspaces/{workspace}/cats/{cat}
GET /v1/workspaces/{workspace}/cats/{cat}/auto-suspend
GET /v1/workspaces/{workspace}/cats/{cat}/endpoints
GET /v1/workspaces/{workspace}/cats/{cat}/expiry
GET /v1/workspaces/{workspace}/cats/{cat}/oci-deployments
GET /v1/workspaces/{workspace}/cats/{cat}/shell
GET /v1/workspaces/{workspace}/cats/{cat}/work
GET /v1/workspaces/{workspace}/disks
GET /v1/workspaces/{workspace}/disks/{disk}
GET /v1/workspaces/{workspace}/disks/{disk}/snapshots
GET /v1/workspaces/{workspace}/operations
GET /v1/workspaces/{workspace}/tokens
GET /zh-CN
GET /zh-CN/
GET /zh-CN/docs
GET /zh-CN/docs/
GET /zh-CN/docs/{slug}
GET /zh-CN/docs/{slug}/
PATCH /v1/accounts/{account}/members/{membership}
PATCH /v1/workspaces/{workspace}
POST /auth/workspace
POST /v1/accounts/{account}/invitations
POST /v1/accounts/{account}/invitations/{invitation}/actions/revoke
POST /v1/accounts/{account}/workspaces
POST /v1/admin/nodes/{id}/actions/{verb}
POST /v1/admin/runtime/node-authority-applies
POST /v1/auth/logout
POST /v1/billing/stripe/webhook
POST /v1/internal/runtime/agent-sessions
POST /v1/internal/runtime/desired-reads
POST /v1/internal/runtime/observations
POST /v1/internal/runtime/volume-transition-evidence
POST /v1/internal/runtime/volume-transitions
POST /v1/internal/usage/checkpoints
POST /v1/nodes/{id}/actions/cordon
POST /v1/routes/wake
POST /v1/workspaces/{workspace}/billing/checkout
POST /v1/workspaces/{workspace}/cats
POST /v1/workspaces/{workspace}/cats/{cat}/actions/{verb}
POST /v1/workspaces/{workspace}/cats/{cat}/endpoints
POST /v1/workspaces/{workspace}/cats/{cat}/exec
POST /v1/workspaces/{workspace}/cats/{cat}/oci-deployments
POST /v1/workspaces/{workspace}/disks
POST /v1/workspaces/{workspace}/disks/{disk}/actions/{verb}
POST /v1/workspaces/{workspace}/disks/{disk}/snapshots
POST /v1/workspaces/{workspace}/tokens
PUT /v1/workspaces/{workspace}/cats/{cat}/auto-suspend
PUT /v1/workspaces/{workspace}/cats/{cat}/expiry"#;
        assert_eq!(routes, expected.lines().collect::<Vec<_>>());
    }
}

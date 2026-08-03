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
    UsageDetailLine, UsageMetric, UsageReport, UsageSummaryLine, UsageTimeBucket,
    MAX_USAGE_INGEST_BODY_BYTES,
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
mod billing;
mod cats;
mod disks;
mod endpoints;
mod nodes;
mod operations;
mod routes;
mod sessions;
mod usage;

use accounts::*;
use billing::*;
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
    if let Some(workspace_id) = state
        .store
        .active_workspace_for_token_hash(&workspace_token_hash(token))?
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
        Some(Principal::WorkspaceAutomation { workspace_id }) => workspace_id == workspace,
        Some(Principal::Service) | None => false,
    };
    if bearer_allowed
        || crate::auth::web_session_allows_workspace(state, headers, workspace).await?
    {
        return resolved_scope
            .map(Ok)
            .unwrap_or_else(|| state.store.workspace_scope(workspace))
            .map_err(Into::into);
    }
    Err(auth_failure(
        principal.is_some() || crate::auth::has_any_web_session(state, headers),
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
            "/v1/workspaces/{workspace}/tokens",
            post(create_workspace_token).get(list_workspace_tokens),
        )
        .route(
            "/v1/workspaces/{workspace}/tokens/{token}",
            axum::routing::delete(revoke_workspace_token),
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
        .route("/v1/nodes/register", post(register_node))
        .route("/v1/nodes/heartbeat", post(heartbeat))
        .route("/v1/nodes/work-status", post(node_work_status))
        .route("/v1/internal/work/acquire", post(acquire_work))
        .route("/v1/internal/work/release", post(release_work))
        .route(
            "/v1/internal/usage/checkpoints",
            post(ingest_usage_checkpoints)
                .layer(DefaultBodyLimit::max(MAX_USAGE_INGEST_BODY_BYTES)),
        )
        .route(
            "/v1/workspaces/{workspace}/billing/usage",
            get(workspace_usage),
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

#[cfg(test)]
mod tests {
    #[test]
    fn route_method_set_matches_snapshot() {
        let source = include_str!("mod.rs");
        let router = source
            .split_once("pub fn router")
            .expect("router declaration")
            .1
            .split_once(".fallback")
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
POST /v1/auth/logout
POST /v1/billing/stripe/webhook
POST /v1/internal/usage/checkpoints
POST /v1/internal/work/acquire
POST /v1/internal/work/release
POST /v1/nodes/heartbeat
POST /v1/nodes/register
POST /v1/nodes/work-status
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

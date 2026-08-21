//! OCI application deployment on an already-Running atomic Cat.
//!
//! This feature has its own attempt identity and PostgreSQL session fence. It
//! does not create or settle Cat lifecycle Operations, acquire legacy Work
//! leases, wake a Cat, or dispatch lifecycle work.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cats_api::error::{ApiError, ErrorBody};
use cats_api::list::ListResponse;
use cats_api::oci::{
    DeployOciRequest, OciDeployment, OciDeploymentAttempt, OciDeploymentAttemptState,
};
use cats_api::runtime_reconciliation::Id;
use serde::Deserialize;

use super::{check_workspace_auth, ApiResult};
use crate::server::AppState;
use crate::store::runtime_authority::product_reads::ProductRead;
use crate::store::{OciDeploymentClaim, OciDeploymentLease, OciRuntimeTarget};

const OCI_DEPLOY_POLL_INTERVAL: Duration = Duration::from_millis(200);
const OCI_DEPLOY_EXECUTION_TIMEOUT: Duration = Duration::from_secs(3_615);

pub(super) async fn list_oci_deployments(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<OciDeployment>>> {
    let (_, cat_id) = resolve_current_cat_id(&state, &workspace, &cat, &headers).await?;
    let items = state
        .store
        .execute(move |store| store.list_oci_deployments(&cat_id))
        .await?;
    Ok(Json(ListResponse { items }))
}

#[derive(Debug, Deserialize)]
pub(super) struct DeployOciQuery {
    wait_ms: Option<u64>,
}

pub(super) async fn deploy_oci(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    Query(query): Query<DeployOciQuery>,
    headers: HeaderMap,
    Json(request): Json<DeployOciRequest>,
) -> ApiResult<Response> {
    let workspace_scope = check_workspace_auth(&state, &headers, &workspace).await?;
    let workspace_id = Id::new(workspace_scope.workspace.id)
        .ok_or_else(|| ApiError::internal("stored workspace ID is invalid"))?;
    let name_or_id =
        Id::new(cat).ok_or_else(|| ApiError::invalid("cat must be a valid Cat name or ID"))?;
    let image_digest = cats_api::oci::pinned_digest(&request.image)
        .ok_or_else(|| {
            ApiError::invalid(
                "image must be pinned by digest, as <reference>@sha256:<64 hex lowercase>",
            )
        })?
        .to_owned();
    let app = Id::new(request.app.clone())
        .ok_or_else(|| ApiError::invalid("app must be a valid identifier"))?;
    let target_workspace = workspace_id.clone();
    let target = state
        .store
        .execute(move |store| store.resolve_oci_runtime_target(&target_workspace, &name_or_id))
        .await?;
    let cat_id = target.cat_id.clone();
    let claim_cat_id = cat_id.clone();
    let claim_app = app.as_str().to_owned();
    let claim = state
        .store
        .execute(move |store| store.claim_oci_deployment(&claim_cat_id, &claim_app, &image_digest))
        .await?;
    let attempt_id = match claim {
        OciDeploymentClaim::Replay { deployment } => {
            return Ok((StatusCode::OK, Json(deployment)).into_response())
        }
        OciDeploymentClaim::AlreadyRunning {
            record_id,
            attempt_id,
        } => {
            tracing::info!(%record_id, %attempt_id, %cat_id, app = %app, "joining OCI attempt");
            attempt_id
        }
        OciDeploymentClaim::Claimed {
            record_id,
            attempt_id,
            lease,
        } => {
            spawn_oci_deploy(
                &state,
                target,
                request,
                record_id,
                attempt_id.clone(),
                lease,
            );
            attempt_id
        }
    };
    let max_wait_ms = state.cfg.oci_deploy_sync_wait_ms;
    let wait = Duration::from_millis(query.wait_ms.unwrap_or(max_wait_ms).min(max_wait_ms));
    await_oci_deployment(&state, workspace_id, cat_id, attempt_id, wait).await
}

pub(super) async fn get_oci_deployment_attempt(
    State(state): State<AppState>,
    Path((workspace, cat, attempt)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<OciDeploymentAttempt>> {
    let (workspace_id, cat_id) = resolve_current_cat_id(&state, &workspace, &cat, &headers).await?;
    let attempt_id = Id::new(attempt)
        .filter(|id| id.as_str().starts_with("oci_attempt_"))
        .ok_or_else(|| ApiError::not_found("OCI deployment attempt"))?;
    let attempt = state
        .store
        .execute(move |store| store.oci_deployment_attempt(&workspace_id, &cat_id, &attempt_id))
        .await?;
    Ok(Json(attempt))
}

fn spawn_oci_deploy(
    state: &AppState,
    target: OciRuntimeTarget,
    request: DeployOciRequest,
    record_id: Id,
    attempt_id: Id,
    owner_fence: Box<OciDeploymentLease>,
) {
    let state = state.clone();
    tokio::spawn(async move {
        let _owner_fence = owner_fence;
        let app = request.app.clone();
        let outcome = drive_oci_deploy(&state, &target, &request).await;
        let recorded = match &outcome {
            Ok(deployment) => {
                let deployment = deployment.clone();
                let record_id = record_id.clone();
                let attempt_id = attempt_id.clone();
                state
                    .store
                    .execute(move |store| {
                        store.succeed_oci_deployment(&record_id, &attempt_id, &deployment)
                    })
                    .await
            }
            Err(error) => {
                let error = ErrorBody::new(error.code, &error.message);
                let record_id = record_id.clone();
                let attempt_id = attempt_id.clone();
                state
                    .store
                    .execute(move |store| {
                        store.fail_oci_deployment(&record_id, &attempt_id, &error)
                    })
                    .await
            }
        };
        match (outcome, recorded) {
            (Ok(_), Ok(true)) => {
                tracing::info!(cat = %target.cat_id, %app, %attempt_id, "OCI deployment succeeded")
            }
            (Err(error), Ok(true)) => {
                tracing::warn!(cat = %target.cat_id, %app, %attempt_id, %error, "OCI deployment failed")
            }
            (_, Ok(false)) => {
                tracing::warn!(cat = %target.cat_id, %app, %attempt_id, "discarded stale OCI result")
            }
            (_, Err(error)) => {
                tracing::error!(cat = %target.cat_id, %app, %attempt_id, %error, "recording OCI result failed")
            }
        }
    });
}

async fn drive_oci_deploy(
    state: &AppState,
    target: &OciRuntimeTarget,
    request: &DeployOciRequest,
) -> Result<OciDeployment, ApiError> {
    let url = format!(
        "{}/v1/cats/{}/oci-deployments",
        target.node_transport_target.as_str().trim_end_matches('/'),
        target.cat_id
    );
    let response = reqwest::Client::new()
        .post(url)
        .timeout(OCI_DEPLOY_EXECUTION_TIMEOUT)
        .bearer_auth(&state.cfg.auth_token)
        .json(request)
        .send()
        .await
        .map_err(|error| {
            ApiError::unavailable(format!("Node OCI endpoint unreachable: {error}"))
        })?;
    let status = response.status();
    if status.is_success() {
        return response
            .json::<OciDeployment>()
            .await
            .map_err(|error| ApiError::internal(format!("bad OCI deployment response: {error}")));
    }
    let detail = response.text().await.unwrap_or_default();
    let message = if detail.trim().is_empty() {
        format!("OCI deployment failed: {status}")
    } else {
        format!("OCI deployment failed: {}", detail.trim())
    };
    Err(ApiError::unavailable(message))
}

async fn await_oci_deployment(
    state: &AppState,
    workspace_id: Id,
    cat_id: Id,
    attempt_id: Id,
    wait: Duration,
) -> ApiResult<Response> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let query_workspace = workspace_id.clone();
        let query_cat = cat_id.clone();
        let query_attempt = attempt_id.clone();
        let attempt = state
            .store
            .execute(move |store| {
                store.oci_deployment_attempt(&query_workspace, &query_cat, &query_attempt)
            })
            .await?;
        match attempt.state {
            OciDeploymentAttemptState::Succeeded => {
                let deployment = attempt
                    .deployment
                    .ok_or_else(|| ApiError::internal("succeeded OCI attempt has no deployment"))?;
                return Ok((StatusCode::OK, Json(deployment)).into_response());
            }
            OciDeploymentAttemptState::Failed => {
                let error = attempt.error.unwrap_or_else(|| {
                    ErrorBody::new(
                        cats_api::error::ErrorCode::Unavailable,
                        "OCI deployment failed",
                    )
                });
                return Err(ApiError::new(error.code, error.message).into());
            }
            OciDeploymentAttemptState::Running => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok((StatusCode::ACCEPTED, Json(attempt)).into_response());
        }
        tokio::time::sleep(OCI_DEPLOY_POLL_INTERVAL).await;
    }
}

async fn resolve_current_cat_id(
    state: &AppState,
    workspace: &str,
    cat: &str,
    headers: &HeaderMap,
) -> ApiResult<(Id, Id)> {
    let scope = check_workspace_auth(state, headers, workspace).await?;
    let workspace_id = Id::new(scope.workspace.id)
        .ok_or_else(|| ApiError::internal("stored workspace ID is invalid"))?;
    let name_or_id = Id::new(cat.to_owned())
        .ok_or_else(|| ApiError::invalid("cat must be a valid Cat name or ID"))?;
    let readiness = state.readiness.clone();
    let query_workspace = workspace_id.clone();
    let read = state
        .store
        .execute(move |store| {
            let read = store.resolve_runtime_cat_id(&query_workspace, &name_or_id);
            if matches!(read, Ok(ProductRead::Corrupt)) {
                readiness.poison();
            }
            read
        })
        .await?;
    match read {
        ProductRead::Found(cat_id) => Ok((workspace_id, *cat_id)),
        ProductRead::NotFound => Err(ApiError::not_found("cat").into()),
        ProductRead::Corrupt => Err(ApiError::internal("Cat product state is corrupt").into()),
    }
}

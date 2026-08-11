//! Workspace-qualified read access to canonical runtime Operations.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{encode_operation, Id};

use super::{check_workspace_auth, ApiResult};
use crate::server::AppState;
use crate::store::runtime_authority::RuntimeOperationRead;

pub(super) async fn get_runtime_operation(
    State(state): State<AppState>,
    Path((workspace, operation)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Authorization deliberately precedes both opaque-ID parsing and the
    // runtime_operations lookup.
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    let workspace_id = Id::new(scope.workspace.id)
        .ok_or_else(|| ApiError::internal("stored workspace ID is invalid"))?;
    let Some(operation_id) = Id::new(operation) else {
        return Err(ApiError::not_found("operation").into());
    };
    let lookup_operation_id = operation_id.clone();
    let read = state
        .store
        .execute(move |store| store.get_runtime_operation(&workspace_id, &lookup_operation_id))
        .await?;
    let operation = match read {
        RuntimeOperationRead::Found(operation) => operation,
        RuntimeOperationRead::NotFound => return Err(ApiError::not_found("operation").into()),
        RuntimeOperationRead::Corrupt => {
            tracing::error!(
                workspace_id = %workspace,
                operation_id = %operation_id,
                "runtime Operation query found stored projection corruption"
            );
            state.readiness.poison();
            return Err(ApiError::internal("stored runtime Operation is corrupt").into());
        }
    };
    let body = match encode_operation(&operation) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "stored runtime Operation could not be re-encoded");
            state.readiness.poison();
            return Err(ApiError::internal("stored runtime Operation is corrupt").into());
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(|_| ApiError::internal("could not construct Operation response").into())
}

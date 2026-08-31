//! Independent UsageStore terminal-authority administration.
//!
//! Runtime checkpoint ingestion is intentionally absent from this cutover.
//! Its retired wire bound attribution to a legacy Desired revision; a future
//! producer must bind one exact lifecycle Operation and runtime incarnation.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cats_metering::{
    target_terminal_request_sha256, UsageTargetTerminalReceipt, UsageTargetTerminalRequest,
    UsageTerminalPrepareOutcome,
};
use cats_protocol::error::{ApiError, ErrorBody, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::server::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiscoverSourceTerminalRequest {
    source_id: String,
    source_epoch: String,
}

#[derive(Debug, Serialize)]
struct BeginTargetTerminalResponse {
    state: &'static str,
    request_sha256: String,
}

#[derive(Debug, Serialize)]
struct CompleteTargetTerminalResponse {
    state: &'static str,
    request_sha256: String,
    receipt: Option<UsageTargetTerminalReceipt>,
}

pub(super) async fn discover_source_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DiscoverSourceTerminalRequest>,
) -> Response {
    if let Err(error) = super::check_admin_auth(&state, &headers).await {
        return error.into_response();
    }
    if request.source_id.is_empty() || request.source_epoch.is_empty() {
        return invalid("source_id and source_epoch are required");
    }
    match state
        .usage
        .source_terminal_receipt(&request.source_id, &request.source_epoch)
        .await
    {
        Ok(Some(receipt)) => Json(receipt).into_response(),
        Ok(None) => api_error(ApiError::not_found("usage source terminal receipt")),
        Err(error) => metering_error(error),
    }
}

pub(super) async fn begin_target_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UsageTargetTerminalRequest>,
) -> Response {
    if let Err(error) = super::check_admin_auth(&state, &headers).await {
        return error.into_response();
    }
    let request_sha256 = match target_terminal_request_sha256(&request) {
        Ok(digest) => digest,
        Err(error) => return metering_error(error),
    };
    match state.usage.begin_target_terminal(&request).await {
        Ok(outcome) => Json(BeginTargetTerminalResponse {
            state: match outcome {
                UsageTerminalPrepareOutcome::Prepared => "prepared",
                UsageTerminalPrepareOutcome::ExactReplay => "exact_replay",
            },
            request_sha256,
        })
        .into_response(),
        Err(error) => metering_error(error),
    }
}

pub(super) async fn complete_target_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UsageTargetTerminalRequest>,
) -> Response {
    if let Err(error) = super::check_admin_auth(&state, &headers).await {
        return error.into_response();
    }
    let request_sha256 = match target_terminal_request_sha256(&request) {
        Ok(digest) => digest,
        Err(error) => return metering_error(error),
    };
    match state.usage.complete_target_terminal(&request).await {
        Ok(receipt) => {
            let status = if receipt.is_some() {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (
                status,
                Json(CompleteTargetTerminalResponse {
                    state: if receipt.is_some() {
                        "terminal"
                    } else {
                        "pending"
                    },
                    request_sha256,
                    receipt,
                }),
            )
                .into_response()
        }
        Err(error) => metering_error(error),
    }
}

fn invalid(message: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidArgument, message)
}

fn api_error(error: ApiError) -> Response {
    let status =
        StatusCode::from_u16(error.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    error_response(status, error.code, error.message)
}

fn metering_error(error: cats_metering::MeteringError) -> Response {
    match error {
        cats_metering::MeteringError::Invalid(message) => invalid(message),
        cats_metering::MeteringError::Conflict(message) => {
            error_response(StatusCode::CONFLICT, ErrorCode::Conflict, message)
        }
        other => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            other.to_string(),
        ),
    }
}

fn error_response(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Response {
    let mut response = (status, Json(ErrorBody::new(code, message))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

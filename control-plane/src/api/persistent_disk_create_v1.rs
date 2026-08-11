//! Strict public PersistentDisk-create HTTP adapter.

use std::time::Instant;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::Response;

use cats_api::error::ApiError;

use super::{check_workspace_auth, require_funded, ApiResult, Failure};
use crate::server::AppState;
use crate::store::runtime_authority::persistent_disk_create_service::{
    parse_authorized_persistent_disk_create, persistent_disk_create_absolute_deadline,
    AuthorizedPersistentDiskCreateIngress, PersistentDiskCreateHttpFields,
    PersistentDiskCreateHttpResult, PersistentDiskCreateServiceError,
    PERSISTENT_DISK_CREATE_MAX_BODY_BYTES,
};

const BODY_READ_LIMIT: usize = PERSISTENT_DISK_CREATE_MAX_BODY_BYTES + 1;
const TEMPORARILY_UNAVAILABLE_BODY: &[u8] = br#"{"code":"temporarily_unavailable","message":"PersistentDisk authority is temporarily unavailable"}"#;
const INTERNAL_BODY: &[u8] = br#"{"code":"internal","message":"internal server error"}"#;

pub(crate) async fn create_persistent_disk_v1(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> ApiResult<Response> {
    let headers_received_at = Instant::now();
    let absolute_deadline = persistent_disk_create_absolute_deadline(headers_received_at)?;
    let ingress = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(absolute_deadline),
        authorized_ingress(&state, &workspace, headers_received_at, request),
    )
    .await
    {
        Ok(ingress) => ingress?,
        Err(_) => {
            return Ok(closed_response(
                StatusCode::SERVICE_UNAVAILABLE,
                TEMPORARILY_UNAVAILABLE_BODY,
                true,
            ));
        }
    };
    match state.persistent_disk_create.replay(&ingress).await {
        Ok(Some(result)) => return http_response(result),
        Ok(None) => {}
        Err(error) => return service_error_response(&state, error),
    }
    match tokio::time::timeout_at(
        tokio::time::Instant::from_std(ingress.absolute_deadline()),
        require_funded(&state, ingress.authenticated_workspace_id().as_str()),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Ok(closed_response(
                StatusCode::SERVICE_UNAVAILABLE,
                TEMPORARILY_UNAVAILABLE_BODY,
                true,
            ));
        }
    }
    match state.persistent_disk_create.create(ingress).await {
        Ok(result) => http_response(result),
        Err(error) => service_error_response(&state, error),
    }
}

fn service_error_response(
    state: &AppState,
    error: PersistentDiskCreateServiceError,
) -> ApiResult<Response> {
    match error {
        PersistentDiskCreateServiceError::Request(error) => Err(Failure(error)),
        PersistentDiskCreateServiceError::TemporarilyUnavailable => Ok(closed_response(
            StatusCode::SERVICE_UNAVAILABLE,
            TEMPORARILY_UNAVAILABLE_BODY,
            true,
        )),
        PersistentDiskCreateServiceError::Fatal(error) => {
            tracing::error!(error = %error, "PersistentDisk create encountered fatal stored authority corruption");
            state.readiness.poison();
            Ok(closed_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_BODY,
                false,
            ))
        }
    }
}

async fn authorized_ingress(
    state: &AppState,
    workspace: &str,
    headers_received_at: Instant,
    request: Request<Body>,
) -> ApiResult<AuthorizedPersistentDiskCreateIngress> {
    let scope = check_workspace_auth(state, request.headers(), workspace).await?;

    let authenticated_workspace_id =
        cats_api::runtime_reconciliation::Id::new(scope.workspace.id.clone())
            .ok_or_else(|| ApiError::internal("authenticated Workspace ID is invalid"))?;
    let raw_path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| request.uri().path().as_bytes().to_vec());
    let fields = http_fields(request.headers());
    let raw_body = read_body(request.into_body()).await?;
    parse_authorized_persistent_disk_create(
        &authenticated_workspace_id,
        headers_received_at,
        &raw_path_and_query,
        &fields,
        &raw_body,
    )
    .map_err(Into::into)
}

async fn read_body(body: Body) -> ApiResult<Bytes> {
    let bytes = to_bytes(body, BODY_READ_LIMIT)
        .await
        .map_err(|_| ApiError::invalid("PersistentDisk create body exceeds 4096 bytes"))?;
    if bytes.len() > PERSISTENT_DISK_CREATE_MAX_BODY_BYTES {
        return Err(ApiError::invalid("PersistentDisk create body exceeds 4096 bytes").into());
    }
    Ok(bytes)
}

fn http_fields(headers: &HeaderMap) -> PersistentDiskCreateHttpFields {
    PersistentDiskCreateHttpFields {
        content_type: header_occurrences(headers, header::CONTENT_TYPE),
        content_encoding: header_occurrences(headers, header::CONTENT_ENCODING),
        if_match: header_occurrences(headers, header::IF_MATCH),
        idempotency_key: header_occurrences(
            headers,
            axum::http::HeaderName::from_static("idempotency-key"),
        ),
    }
}

fn header_occurrences(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
) -> Vec<Vec<u8>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

fn http_response(result: PersistentDiskCreateHttpResult) -> ApiResult<Response> {
    let status = StatusCode::from_u16(result.http_status)
        .map_err(|_| ApiError::internal("stored PersistentDisk create HTTP status is invalid"))?;
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(content_type) = result.content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response
        .body(Body::from(result.response_body))
        .map_err(|_| {
            ApiError::internal("could not construct PersistentDisk create response").into()
        })
}

fn closed_response(status: StatusCode, body: &'static [u8], retry_after: bool) -> Response {
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    if retry_after {
        response = response.header(header::RETRY_AFTER, "1");
    }
    response
        .body(Body::from(body))
        .expect("fixed PersistentDisk-create response headers are valid")
}

//! Strict production adapters for covered lifecycle, Endpoint and Disk mutations.

use std::time::Instant;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::Response;
use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::Id;

use super::{check_workspace_auth, require_funded, ApiResult, Failure};
use crate::server::AppState;
use crate::store::runtime_authority::product_mutation_service::{
    parse_authorized_endpoint_bind, parse_authorized_product_mutation,
    product_mutation_absolute_deadline, AuthorizedProductMutationIngress, CatLifecycleAction,
    ProductMutation, ProductMutationHttpFields, ProductMutationHttpResult,
    ProductMutationServiceError, PRODUCT_MUTATION_MAX_BODY_BYTES,
};

const BODY_READ_LIMIT: usize = PRODUCT_MUTATION_MAX_BODY_BYTES + 1;
pub(crate) async fn cat_lifecycle_v2(
    State(state): State<AppState>,
    Path((workspace, cat, verb)): Path<(String, String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    let received_at = Instant::now();
    let deadline = product_mutation_absolute_deadline(received_at)?;
    let scope = timeout_at(
        deadline,
        check_workspace_auth(&state, request.headers(), &workspace),
    )
    .await??;
    let workspace_id = authenticated_workspace_id(&scope.workspace.id)?;
    let action =
        CatLifecycleAction::parse(&verb).ok_or_else(|| ApiError::not_found("lifecycle action"))?;
    let ingress = authorized_after_auth(
        &workspace_id,
        Some(&cat),
        received_at,
        deadline,
        request,
        ProductMutation::Lifecycle(action),
    )
    .await?;
    if let Some(result) = state
        .product_mutations
        .replay(&ingress)
        .await
        .map_err(|error| map_service_error(&state, error))?
    {
        return http_response(result);
    }
    if action.requires_funding() {
        timeout_at(
            ingress.absolute_deadline(),
            require_funded(&state, ingress.authenticated_workspace_id().as_str()),
        )
        .await??;
    }
    execute(&state, ingress).await
}

pub(crate) async fn delete_cat_v2(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    let ingress = authorized_ingress(
        &state,
        &workspace,
        Some(&cat),
        request,
        ProductMutation::DeleteCat,
    )
    .await?;
    execute(&state, ingress).await
}

pub(crate) async fn bind_endpoint_v2(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    let received_at = Instant::now();
    let deadline = product_mutation_absolute_deadline(received_at)?;
    let scope = timeout_at(
        deadline,
        check_workspace_auth(&state, request.headers(), &workspace),
    )
    .await??;
    let workspace_id = authenticated_workspace_id(&scope.workspace.id)?;
    let raw_path = raw_path_and_query(request.uri());
    let fields = http_fields(request.headers());
    let body = timeout_at(deadline, read_body(request.into_body())).await??;
    let ingress = parse_authorized_endpoint_bind(
        &workspace_id,
        &cat,
        received_at,
        &raw_path,
        &fields,
        &body,
    )?;
    execute(&state, ingress).await
}

pub(crate) async fn unbind_endpoint_v2(
    State(state): State<AppState>,
    Path((workspace, cat, endpoint)): Path<(String, String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    let received_at = Instant::now();
    let deadline = product_mutation_absolute_deadline(received_at)?;
    let scope = timeout_at(
        deadline,
        check_workspace_auth(&state, request.headers(), &workspace),
    )
    .await??;
    let workspace_id = authenticated_workspace_id(&scope.workspace.id)?;
    let endpoint_id = Id::new(endpoint)
        .ok_or_else(|| ApiError::invalid("Endpoint ID is not a canonical runtime ID"))?;
    let ingress = authorized_after_auth(
        &workspace_id,
        Some(&cat),
        received_at,
        deadline,
        request,
        ProductMutation::UnbindEndpoint { endpoint_id },
    )
    .await?;
    execute(&state, ingress).await
}

pub(crate) async fn delete_disk_v2(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    let received_at = Instant::now();
    let deadline = product_mutation_absolute_deadline(received_at)?;
    let scope = timeout_at(
        deadline,
        check_workspace_auth(&state, request.headers(), &workspace),
    )
    .await??;
    let workspace_id = authenticated_workspace_id(&scope.workspace.id)?;
    let disk_id =
        Id::new(disk).ok_or_else(|| ApiError::invalid("Disk ID is not a canonical runtime ID"))?;
    let ingress = authorized_after_auth(
        &workspace_id,
        None,
        received_at,
        deadline,
        request,
        ProductMutation::DeleteDisk { disk_id },
    )
    .await?;
    execute(&state, ingress).await
}

async fn authorized_after_auth(
    workspace_id: &Id,
    cat: Option<&str>,
    received_at: Instant,
    deadline: Instant,
    request: Request<Body>,
    mutation: ProductMutation,
) -> ApiResult<AuthorizedProductMutationIngress> {
    let raw_path = raw_path_and_query(request.uri());
    let fields = http_fields(request.headers());
    let body = timeout_at(deadline, read_body(request.into_body())).await??;
    parse_authorized_product_mutation(
        workspace_id,
        cat,
        received_at,
        &raw_path,
        &fields,
        &body,
        mutation,
    )
    .map_err(Into::into)
}

async fn authorized_ingress(
    state: &AppState,
    workspace: &str,
    cat: Option<&str>,
    request: Request<Body>,
    mutation: ProductMutation,
) -> ApiResult<AuthorizedProductMutationIngress> {
    let received_at = Instant::now();
    let deadline = product_mutation_absolute_deadline(received_at)?;
    let scope = timeout_at(
        deadline,
        check_workspace_auth(state, request.headers(), workspace),
    )
    .await??;
    let workspace_id = authenticated_workspace_id(&scope.workspace.id)?;
    let raw_path = raw_path_and_query(request.uri());
    let fields = http_fields(request.headers());
    let body = timeout_at(deadline, read_body(request.into_body())).await??;
    parse_authorized_product_mutation(
        &workspace_id,
        cat,
        received_at,
        &raw_path,
        &fields,
        &body,
        mutation,
    )
    .map_err(Into::into)
}

async fn execute(
    state: &AppState,
    ingress: AuthorizedProductMutationIngress,
) -> ApiResult<Response> {
    match state.product_mutations.mutate(ingress).await {
        Ok(result) => http_response(result),
        Err(error) => Err(map_service_error(state, error)),
    }
}

fn map_service_error(state: &AppState, error: ProductMutationServiceError) -> Failure {
    match error {
        ProductMutationServiceError::Request(error) => Failure(error),
        ProductMutationServiceError::TemporarilyUnavailable => Failure(ApiError::unavailable(
            "product authority is temporarily unavailable",
        )),
        ProductMutationServiceError::Fatal(error) => {
            tracing::error!(error = %error, "product mutation encountered fatal authority corruption");
            state.readiness.poison();
            Failure(ApiError::internal("internal server error"))
        }
    }
}

fn authenticated_workspace_id(value: &str) -> ApiResult<Id> {
    Id::new(value.to_owned())
        .ok_or_else(|| ApiError::internal("authenticated Workspace ID is invalid").into())
}

fn raw_path_and_query(uri: &axum::http::Uri) -> Vec<u8> {
    uri.path_and_query()
        .map(|value| value.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| uri.path().as_bytes().to_vec())
}

async fn read_body(body: Body) -> ApiResult<Bytes> {
    let bytes = to_bytes(body, BODY_READ_LIMIT)
        .await
        .map_err(|_| ApiError::invalid("product mutation body exceeds 4096 bytes"))?;
    if bytes.len() > PRODUCT_MUTATION_MAX_BODY_BYTES {
        return Err(ApiError::invalid("product mutation body exceeds 4096 bytes").into());
    }
    Ok(bytes)
}

fn http_fields(headers: &HeaderMap) -> ProductMutationHttpFields {
    ProductMutationHttpFields {
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

fn http_response(result: ProductMutationHttpResult) -> ApiResult<Response> {
    let status = StatusCode::from_u16(result.http_status)
        .map_err(|_| ApiError::internal("stored product mutation status is invalid"))?;
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(content_type) = result.content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response
        .body(Body::from(result.response_body))
        .map_err(|_| ApiError::internal("could not construct product mutation response").into())
}

async fn timeout_at<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = T>,
) -> ApiResult<T> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| ApiError::unavailable("product mutation deadline elapsed").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn body_reader_stops_at_the_fixed_boundary() {
        assert_eq!(
            read_body(Body::from(vec![b'x'; PRODUCT_MUTATION_MAX_BODY_BYTES]))
                .await
                .unwrap()
                .len(),
            PRODUCT_MUTATION_MAX_BODY_BYTES
        );
        assert!(
            read_body(Body::from(vec![b'x'; PRODUCT_MUTATION_MAX_BODY_BYTES + 1]))
                .await
                .is_err()
        );
    }
}

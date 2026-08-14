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
    parse_authorized_endpoint_bind, parse_authorized_persistent_disk_binding,
    parse_authorized_product_mutation, product_mutation_absolute_deadline,
    AuthorizedProductMutationIngress, CatLifecycleAction, PersistentDiskBindingAction,
    ProductMutation, ProductMutationHttpFields, ProductMutationHttpResult,
    ProductMutationServiceError, PRODUCT_MUTATION_MAX_BODY_BYTES,
};

const BODY_READ_LIMIT: usize = PRODUCT_MUTATION_MAX_BODY_BYTES + 1;
pub(crate) async fn stop_cat_v2(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    cat_lifecycle_v2(state, workspace, cat, request, CatLifecycleAction::Stop).await
}

pub(crate) async fn suspend_cat_v2(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    cat_lifecycle_v2(state, workspace, cat, request, CatLifecycleAction::Suspend).await
}

pub(crate) async fn warm_cat_v2(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    cat_lifecycle_v2(state, workspace, cat, request, CatLifecycleAction::Warm).await
}

pub(crate) async fn resume_cat_v2(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    cat_lifecycle_v2(state, workspace, cat, request, CatLifecycleAction::Resume).await
}

async fn cat_lifecycle_v2(
    state: AppState,
    workspace: String,
    cat: String,
    request: Request<Body>,
    action: CatLifecycleAction,
) -> ApiResult<Response> {
    let received_at = Instant::now();
    let deadline = product_mutation_absolute_deadline(received_at)?;
    let scope = timeout_at(
        deadline,
        check_workspace_auth(&state, request.headers(), &workspace),
    )
    .await??;
    if action == CatLifecycleAction::Warm {
        return Err(ApiError::failed_precondition("Warm is unavailable in this release").into());
    }
    let workspace_id = authenticated_workspace_id(&scope.workspace.id)?;
    if matches!(
        action,
        CatLifecycleAction::Suspend | CatLifecycleAction::Resume
    ) {
        return Err(ApiError::failed_precondition(
            "Suspend and Resume are unavailable in this release",
        )
        .into());
    }
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

pub(crate) async fn attach_disk_v2(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    persistent_disk_binding_v2(
        state,
        workspace,
        disk,
        request,
        PersistentDiskBindingAction::Attach,
    )
    .await
}

pub(crate) async fn detach_disk_v2(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    request: Request<Body>,
) -> ApiResult<Response> {
    persistent_disk_binding_v2(
        state,
        workspace,
        disk,
        request,
        PersistentDiskBindingAction::Detach,
    )
    .await
}

async fn persistent_disk_binding_v2(
    state: AppState,
    workspace: String,
    disk: String,
    request: Request<Body>,
    action: PersistentDiskBindingAction,
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
    let ingress = parse_authorized_persistent_disk_binding(
        &workspace_id,
        &disk,
        received_at,
        &raw_path,
        &fields,
        &body,
        action,
    )?;
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
    use std::sync::Arc;

    use super::*;
    use cats_api::runtime_reconciliation::Id;
    use cats_metering::SqliteUsageStore;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_lifecycle_route_enforces_auth_envelope_and_exact_replay() {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let handle = crate::server::spawn(crate::server::Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: crate::store::DsnSource::Literal(
                crate::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            retired_storage_meta_for_tests: None,
            image_blob: crate::testsupport::unavailable_image_blob(),
            guest_runtime_profile_receipt: crate::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                crate::testsupport::test_runtime_provisioner_trust_bundle(),
            auth_token: "service-token".into(),
            route_grant_signer: crate::testsupport::route_grant_signer(),
            admin_token: "admin-token".into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 30_000,
            reconcile_interval_ms: 60_000,
            auto_tier_policy: Default::default(),
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        let workspace = tokio::task::block_in_place(|| {
            Id::new(
                handle
                    .state
                    .store
                    .list_all_workspace_views()
                    .unwrap()
                    .into_iter()
                    .find(|workspace| workspace.is_default)
                    .unwrap()
                    .id,
            )
            .unwrap()
        });
        let cat_id = tokio::task::block_in_place(|| {
            crate::store::runtime_authority::product_tests::seed_a2_http_cat(
                handle.state.store.as_ref(),
                &workspace,
            )
        });
        let url = format!(
            "{}/v1/workspaces/{workspace}/cats/{cat_id}/actions/stop",
            handle.base_url()
        );
        let client = reqwest::Client::new();

        let warm_url = format!(
            "{}/v1/workspaces/{workspace}/cats/{cat_id}/actions/warm",
            handle.base_url()
        );
        assert_eq!(
            client.post(&warm_url).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let warm = client
            .post(&warm_url)
            .bearer_auth("admin-token")
            .header("Idempotency-Key", "warm-disabled-r1")
            .send()
            .await
            .unwrap();
        assert_eq!(warm.status(), StatusCode::PRECONDITION_FAILED);
        let warm_body: cats_api::error::ErrorBody = warm.json().await.unwrap();
        assert_eq!(
            warm_body.code,
            cats_api::error::ErrorCode::FailedPrecondition
        );
        assert!(warm_body.message.contains("Warm"));

        // Authentication precedes body/envelope parsing on the legal V2
        // route, including for a deliberately malformed non-empty body.
        let unauthenticated = client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let wrong_principal = client
            .post(&url)
            .bearer_auth("service-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_principal.status(), StatusCode::FORBIDDEN);

        let malformed_envelope = client
            .post(&url)
            .bearer_auth("admin-token")
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "a2-http-malformed")
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_eq!(malformed_envelope.status(), StatusCode::BAD_REQUEST);

        let send = || {
            client
                .post(&url)
                .bearer_auth("admin-token")
                .header("Idempotency-Key", "a2-http-exact-replay")
                .send()
        };
        let first = send().await.unwrap();
        let first_status = first.status();
        assert_eq!(first.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
        let first_body = first.bytes().await.unwrap();
        assert_eq!(
            first_status,
            StatusCode::ACCEPTED,
            "unexpected lifecycle response: {}",
            String::from_utf8_lossy(&first_body)
        );
        let replay = send().await.unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(replay.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(replay.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(replay.bytes().await.unwrap(), first_body);

        let malformed_rows: i64 = tokio::task::block_in_place(|| {
            handle
                .state
                .store
                .with(|client| {
                    client
                        .query_one(
                            "SELECT count(*) FROM api_idempotency_results
                              WHERE authenticated_workspace_id=$1
                                AND idempotency_key='a2-http-malformed'",
                            &[&workspace.as_str()],
                        )
                        .map(|row| row.get(0))
                })
                .unwrap()
        });
        assert_eq!(malformed_rows, 0);
        let warm_rows: i64 = tokio::task::block_in_place(|| {
            handle
                .state
                .store
                .with(|client| {
                    client
                        .query_one(
                            "SELECT count(*) FROM api_idempotency_results
                              WHERE authenticated_workspace_id=$1
                                AND idempotency_key='warm-disabled-r1'",
                            &[&workspace.as_str()],
                        )
                        .map(|row| row.get(0))
                })
                .unwrap()
        });
        assert_eq!(warm_rows, 0);
        handle.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn disabled_suspend_and_resume_authenticate_without_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let handle = crate::server::spawn(crate::server::Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: crate::store::DsnSource::Literal(
                crate::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            retired_storage_meta_for_tests: None,
            image_blob: crate::testsupport::unavailable_image_blob(),
            guest_runtime_profile_receipt: crate::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                crate::testsupport::test_runtime_provisioner_trust_bundle(),
            auth_token: "service-token".into(),
            route_grant_signer: crate::testsupport::route_grant_signer(),
            admin_token: "admin-token".into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 30_000,
            reconcile_interval_ms: 60_000,
            auto_tier_policy: Default::default(),
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        let workspace = tokio::task::block_in_place(|| {
            Id::new(
                handle
                    .state
                    .store
                    .list_all_workspace_views()
                    .unwrap()
                    .into_iter()
                    .find(|workspace| workspace.is_default)
                    .unwrap()
                    .id,
            )
            .unwrap()
        });
        let cat_id = tokio::task::block_in_place(|| {
            crate::store::runtime_authority::product_tests::seed_a2_http_cat(
                handle.state.store.as_ref(),
                &workspace,
            )
        });
        let client = reqwest::Client::new();
        let suspend_url = format!(
            "{}/v1/workspaces/{workspace}/cats/{cat_id}/actions/suspend",
            handle.base_url()
        );
        assert_eq!(
            client.post(&suspend_url).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        for (action, key) in [
            ("suspend", "suspend-disabled-r1"),
            ("resume", "resume-disabled-r1"),
        ] {
            let url = format!(
                "{}/v1/workspaces/{workspace}/cats/{cat_id}/actions/{action}",
                handle.base_url()
            );
            let response = client
                .post(url)
                .bearer_auth("admin-token")
                .header("Idempotency-Key", key)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
            let body: cats_api::error::ErrorBody = response.json().await.unwrap();
            assert_eq!(body.code, cats_api::error::ErrorCode::FailedPrecondition);
        }

        let persisted_rows: i64 = tokio::task::block_in_place(|| {
            handle
                .state
                .store
                .with(|client| {
                    client
                        .query_one(
                            "SELECT count(*) FROM api_idempotency_results
                              WHERE authenticated_workspace_id=$1
                                AND idempotency_key IN (
                                    'suspend-disabled-r1', 'resume-disabled-r1')",
                            &[&workspace.as_str()],
                        )
                        .map(|row| row.get(0))
                })
                .unwrap()
        });
        assert_eq!(persisted_rows, 0);
        handle.shutdown().await.unwrap();
    }
}

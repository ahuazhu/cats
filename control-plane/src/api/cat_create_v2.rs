//! Strict public Cat-create HTTP adapter.

use std::time::Instant;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::Response;

use cats_api::error::ApiError;

use super::{check_workspace_auth, require_funded, ApiResult, Failure};
use crate::server::AppState;
use crate::store::runtime_authority::cat_create_service::{
    cat_create_absolute_deadline, parse_authorized_cat_create, AuthorizedCatCreateIngress,
    CatCreateHttpFields, CatCreateHttpResult, CatCreateServiceError, CAT_CREATE_MAX_BODY_BYTES,
};

const CAT_CREATE_BODY_READ_LIMIT: usize = CAT_CREATE_MAX_BODY_BYTES + 1;
const PLACEMENT_UNAVAILABLE_BODY: &[u8] =
    br#"{"code":"placement_unavailable","message":"no runtime node can currently accept this cat"}"#;
const TEMPORARILY_UNAVAILABLE_BODY: &[u8] =
    br#"{"code":"temporarily_unavailable","message":"runtime node authority is temporarily unavailable"}"#;
const INTERNAL_BODY: &[u8] = br#"{"code":"internal","message":"internal server error"}"#;

pub(crate) async fn create_cat_v2(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    request: Request<Body>,
) -> ApiResult<Response> {
    // The total public deadline starts when Axum hands the parsed headers to
    // the handler, before authentication or any external read.
    let headers_received_at = Instant::now();
    create_cat_v2_from_headers_at(state, workspace, request, headers_received_at).await
}

async fn create_cat_v2_from_headers_at(
    state: AppState,
    workspace: String,
    request: Request<Body>,
    headers_received_at: Instant,
) -> ApiResult<Response> {
    let absolute_deadline = cat_create_absolute_deadline(headers_received_at)?;
    let ingress = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(absolute_deadline),
        authorized_cat_create_ingress(&state, &workspace, headers_received_at, request),
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
    // CatCreateService owns the same absolute deadline. Do not wrap this call
    // in a handler timeout: before COMMIT_SENT it cancels safely, while after
    // COMMIT_SENT its registered non-cancellable owner must resolve the exact
    // durable result even if the deadline or client connection is gone.
    match state.cat_create.replay(&ingress).await {
        Ok(Some(result)) => return cat_create_http_response(result),
        Ok(None) => {}
        Err(error) => return cat_create_service_error_response(&state, error),
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
    match state.cat_create.create(ingress).await {
        Ok(result) => cat_create_http_response(result),
        Err(error) => cat_create_service_error_response(&state, error),
    }
}

fn cat_create_service_error_response(
    state: &AppState,
    error: CatCreateServiceError,
) -> ApiResult<Response> {
    match error {
        CatCreateServiceError::Request(error) => Err(Failure(error)),
        CatCreateServiceError::PlacementUnavailable => Ok(closed_response(
            StatusCode::SERVICE_UNAVAILABLE,
            PLACEMENT_UNAVAILABLE_BODY,
            true,
        )),
        CatCreateServiceError::TemporarilyUnavailable => Ok(closed_response(
            StatusCode::SERVICE_UNAVAILABLE,
            TEMPORARILY_UNAVAILABLE_BODY,
            true,
        )),
        CatCreateServiceError::Fatal(error) => {
            tracing::error!(error = %error, "Cat create encountered fatal stored/runtime corruption");
            state.readiness.poison();
            Ok(closed_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_BODY,
                false,
            ))
        }
    }
}

/// Authenticate the public request before parsing any byte of its Cat-create
/// payload, while retaining every byte the A17 fingerprint binds.
async fn authorized_cat_create_ingress(
    state: &AppState,
    workspace: &str,
    headers_received_at: Instant,
    request: Request<Body>,
) -> ApiResult<AuthorizedCatCreateIngress> {
    let scope = check_workspace_auth(state, request.headers(), workspace).await?;

    let authenticated_workspace_id =
        cats_api::runtime_reconciliation::Id::new(scope.workspace.id.clone())
            .ok_or_else(|| ApiError::internal("authenticated Workspace ID is invalid"))?;
    let raw_path_and_query = raw_path_and_query(request.uri());
    let fields = cat_create_http_fields(request.headers());
    let raw_body = read_cat_create_body(request.into_body()).await?;

    parse_authorized_cat_create(
        &authenticated_workspace_id,
        headers_received_at,
        &raw_path_and_query,
        &fields,
        &raw_body,
    )
    .map_err(Into::into)
}

fn raw_path_and_query(uri: &axum::http::Uri) -> Vec<u8> {
    uri.path_and_query()
        .map(|value| value.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| uri.path().as_bytes().to_vec())
}

async fn read_cat_create_body(body: Body) -> ApiResult<Bytes> {
    let bytes = to_bytes(body, CAT_CREATE_BODY_READ_LIMIT)
        .await
        .map_err(|_| ApiError::invalid("Cat create body exceeds 4096 bytes"))?;
    if bytes.len() > CAT_CREATE_MAX_BODY_BYTES {
        return Err(ApiError::invalid("Cat create body exceeds 4096 bytes").into());
    }
    Ok(bytes)
}

fn cat_create_http_fields(headers: &HeaderMap) -> CatCreateHttpFields {
    CatCreateHttpFields {
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

fn cat_create_http_response(result: CatCreateHttpResult) -> ApiResult<Response> {
    let status = StatusCode::from_u16(result.http_status)
        .map_err(|_| ApiError::internal("stored Cat create HTTP status is invalid"))?;
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(content_type) = result.content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response
        .body(Body::from(result.response_body))
        .map_err(|_| ApiError::internal("could not construct Cat create response").into())
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
        .expect("fixed Cat-create response headers are valid")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::HeaderValue;
    use cats_api::error::ErrorCode;
    use cats_metering::SqliteUsageStore;
    use cats_storage::{BlobError, BlobStore};
    use futures_util::StreamExt;

    use crate::store::runtime_authority::cat_create_service::CAT_CREATE_TOTAL_DEADLINE;

    use super::*;

    #[test]
    fn adapter_preserves_header_occurrences_and_exact_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.append(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        headers.append(header::IF_MATCH, HeaderValue::from_static("anything"));
        headers.append("idempotency-key", HeaderValue::from_static("  exact-key\t"));
        headers.append("idempotency-key", HeaderValue::from_static("second-key"));

        let fields = cat_create_http_fields(&headers);
        assert_eq!(
            fields.content_type,
            vec![b"application/json".to_vec(), b"text/plain".to_vec()]
        );
        assert_eq!(fields.content_encoding, vec![b"identity".to_vec()]);
        assert_eq!(fields.if_match, vec![b"anything".to_vec()]);
        assert_eq!(
            fields.idempotency_key,
            vec![b"  exact-key\t".to_vec(), b"second-key".to_vec()]
        );
    }

    #[test]
    fn adapter_preserves_encoded_path_and_query_spelling() {
        let encoded = "/v1/workspaces/%77s_01/cats?b=2&a=1"
            .parse::<axum::http::Uri>()
            .expect("encoded URI");
        assert_eq!(
            raw_path_and_query(&encoded),
            b"/v1/workspaces/%77s_01/cats?b=2&a=1"
        );
        let bare_query = "/v1/workspaces/ws_01/cats?"
            .parse::<axum::http::Uri>()
            .expect("bare query URI");
        assert_eq!(
            raw_path_and_query(&bare_query),
            b"/v1/workspaces/ws_01/cats?"
        );
    }

    #[tokio::test]
    async fn adapter_stops_after_the_4097th_body_byte() {
        assert_eq!(
            read_cat_create_body(Body::from(vec![b'x'; CAT_CREATE_MAX_BODY_BYTES]))
                .await
                .unwrap()
                .len(),
            CAT_CREATE_MAX_BODY_BYTES
        );
        let error = read_cat_create_body(Body::from(vec![b'x'; CAT_CREATE_MAX_BODY_BYTES + 1]))
            .await
            .unwrap_err();
        assert_eq!(error.0.code, ErrorCode::InvalidArgument);
        assert_eq!(error.0.message, "Cat create body exceeds 4096 bytes");
    }

    #[tokio::test]
    async fn fixed_outcomes_have_exact_status_headers_and_bytes() {
        for (response, expected_status, expected_body, retry_after) in [
            (
                closed_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    PLACEMENT_UNAVAILABLE_BODY,
                    true,
                ),
                StatusCode::SERVICE_UNAVAILABLE,
                PLACEMENT_UNAVAILABLE_BODY,
                true,
            ),
            (
                closed_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    TEMPORARILY_UNAVAILABLE_BODY,
                    true,
                ),
                StatusCode::SERVICE_UNAVAILABLE,
                TEMPORARILY_UNAVAILABLE_BODY,
                true,
            ),
            (
                closed_response(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_BODY, false),
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_BODY,
                false,
            ),
        ] {
            assert_eq!(response.status(), expected_status);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers().get(header::RETRY_AFTER).is_some(),
                retry_after
            );
            let emitted = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(emitted.as_ref(), expected_body);
        }
    }

    #[tokio::test]
    async fn adapter_emits_exact_stored_response_bytes() {
        let body = br#"{"cat_id":"cat_01","operation_id":"op_01"}"#.to_vec();
        let response = cat_create_http_response(CatCreateHttpResult {
            http_status: 202,
            content_type: Some("application/json"),
            response_body: body.clone(),
        })
        .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let emitted = to_bytes(response.into_body(), CAT_CREATE_MAX_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(emitted.as_ref(), body);
    }

    struct FixedImageBlob {
        reads: AtomicUsize,
    }

    impl BlobStore for FixedImageBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn get(&self, _key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            unreachable!()
        }

        fn get_bounded_until(
            &self,
            _key: &str,
            _maximum: usize,
            _deadline: Instant,
        ) -> cats_storage::blob::Result<Vec<u8>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(b"{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}".to_vec())
        }

        fn exists(&self, _key: &str) -> cats_storage::blob::Result<bool> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            Err(BlobError::Backend {
                key: "unused".into(),
                message: "unused".into(),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_route_uses_real_a21_a23_replays_and_poisons_readiness_on_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(
            SqliteUsageStore::open(&dir.path().join("usage.db")).expect("open usage store"),
        );
        let image_blob = Arc::new(FixedImageBlob {
            reads: AtomicUsize::new(0),
        });
        let release = crate::testsupport::test_guest_runtime_profile_receipt();
        let handle = crate::server::spawn(crate::server::Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: crate::store::DsnSource::Literal(
                crate::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            #[cfg(debug_assertions)]
            retired_storage_meta_for_tests: None,
            image_blob: image_blob.clone(),
            guest_runtime_profile_receipt: release.clone(),
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
        let workspace_id = tokio::task::block_in_place(|| {
            handle
                .state
                .store
                .list_all_workspace_views()
                .unwrap()
                .into_iter()
                .find(|workspace| workspace.is_default)
                .unwrap()
                .id
        });
        let body = br#"{"boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","durability":"strict","memory_bytes":2147483648,"name":"app","root_size_bytes":4194304,"vcpus":2}"#;
        let url = format!("{}/v1/workspaces/{workspace_id}/cats", handle.base_url());
        let client = reqwest::Client::new();
        let send = || {
            client
                .post(&url)
                .bearer_auth("admin-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header("Idempotency-Key", "exact-replay")
                .body(body.to_vec())
                .send()
        };

        let body_reads = Arc::new(AtomicUsize::new(0));
        let first_body_byte = [body[0]];
        let first_chunk = futures_util::stream::once({
            let body_reads = Arc::clone(&body_reads);
            async move {
                body_reads.fetch_add(1, Ordering::SeqCst);
                Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&first_body_byte))
            }
        });
        let trickle =
            first_chunk.chain(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let trickle_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/workspaces/{workspace_id}/cats"))
            .header(header::AUTHORIZATION, "Bearer admin-token")
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "trickle-timeout")
            .body(Body::from_stream(trickle))
            .unwrap();
        let headers_received_at = Instant::now()
            .checked_sub(CAT_CREATE_TOTAL_DEADLINE - Duration::from_secs(2))
            .unwrap();
        let started = Instant::now();
        let timeout = create_cat_v2_from_headers_at(
            handle.state.clone(),
            workspace_id.clone(),
            trickle_request,
            headers_received_at,
        )
        .await
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(timeout.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(timeout.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(timeout.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(timeout.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            to_bytes(timeout.into_body(), 4096).await.unwrap().as_ref(),
            TEMPORARILY_UNAVAILABLE_BODY
        );
        assert_eq!(body_reads.load(Ordering::SeqCst), 1);
        assert_eq!(image_blob.reads.load(Ordering::SeqCst), 0);
        assert_eq!(handle.state.cat_create.planner_calls_for_test(), 0);
        assert_eq!(handle.state.cat_create.active_commit_resolutions(), 0);
        let (store_rows, result_rows) = tokio::task::block_in_place(|| {
            handle.state.cat_create.durable_create_row_counts_for_test()
        })
        .unwrap();
        assert_eq!(store_rows, 0, "trickled ingress reached the Cat Store");
        assert_eq!(result_rows, 0, "trickled ingress stored an API result");

        let unavailable = send().await.unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            unavailable.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert_eq!(unavailable.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(unavailable.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            unavailable.bytes().await.unwrap().as_ref(),
            PLACEMENT_UNAVAILABLE_BODY
        );
        assert_eq!(image_blob.reads.load(Ordering::SeqCst), 1);

        // Placement unavailability stores no result. The exact same key must
        // therefore plan a fresh whole candidate batch after admission exists.
        let admission = tokio::task::block_in_place(|| {
            crate::store::runtime_authority::runtime_spine_tests::establish_empty_admission(
                handle.state.store.as_ref(),
                &release,
            )
        });
        tokio::task::block_in_place(|| {
            crate::store::runtime_authority::placement_policy::insert_policy_on_store_for_test(
                handle.state.store.as_ref(),
                &crate::store::runtime_authority::cat_create_service_tests::placement_policy(
                    &admission,
                ),
            )
            .unwrap();
        });
        let first = send().await.unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let first_body = first.bytes().await.unwrap();
        let replay = send().await.unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(replay.bytes().await.unwrap(), first_body);
        assert_eq!(image_blob.reads.load(Ordering::SeqCst), 2);

        tokio::task::block_in_place(|| {
            crate::store::runtime_authority::placement_policy::corrupt_policy_on_store_for_test(
                handle.state.store.as_ref(),
            )
            .unwrap();
        });
        let fatal = client
            .post(&url)
            .bearer_auth("admin-token")
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "fatal-corruption")
            .body(
                String::from_utf8(body.to_vec())
                    .unwrap()
                    .replace("\"app\"", "\"other\""),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(fatal.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(fatal.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(fatal.headers()[header::CACHE_CONTROL], "no-store");
        assert!(fatal.headers().get(header::RETRY_AFTER).is_none());
        assert_eq!(fatal.bytes().await.unwrap().as_ref(), INTERNAL_BODY);
        assert_eq!(
            client
                .get(format!("{}/healthz", handle.base_url()))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        handle.state.cat_create.begin_shutdown();
        let temporary = client
            .post(&url)
            .bearer_auth("admin-token")
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "after-shutdown")
            .body(
                String::from_utf8(body.to_vec())
                    .unwrap()
                    .replace("\"app\"", "\"shutdown\""),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(temporary.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            temporary.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert_eq!(temporary.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(temporary.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            temporary.bytes().await.unwrap().as_ref(),
            TEMPORARILY_UNAVAILABLE_BODY
        );
        assert_eq!(image_blob.reads.load(Ordering::SeqCst), 3);
        handle.shutdown().await.unwrap();
    }
}

//! Workspace-qualified read access to canonical runtime Operations.

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::Response;
use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{encode_operation, Id};

use super::{check_workspace_auth, ApiResult};
use crate::server::AppState;
use crate::store::runtime_authority::RuntimeOperationRead;

pub(super) async fn get_runtime_operation(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Read only the raw workspace slot needed for authorization. In
    // particular, do not ask Axum to percent-decode the Operation capture
    // before the caller's workspace authority has been established.
    let workspace = raw_workspace_segment(&uri).to_owned();
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    let workspace_id = Id::new(scope.workspace.id)
        .ok_or_else(|| ApiError::internal("stored workspace ID is invalid"))?;
    let Some(operation) = exact_operation_segment(&uri, &workspace_id) else {
        return Err(ApiError::not_found("operation").into());
    };
    let Some(operation_id) = Id::new(operation.to_owned()) else {
        return Err(ApiError::not_found("operation").into());
    };
    let readiness = state.readiness.clone();
    let poison_workspace_id = workspace_id.clone();
    let lookup_operation_id = operation_id.clone();
    let read = state
        .store
        .execute(move |store| {
            let read = store.get_runtime_operation(&workspace_id, &lookup_operation_id);
            if matches!(read, Ok(RuntimeOperationRead::Corrupt)) {
                tracing::error!(
                    workspace_id = %poison_workspace_id,
                    operation_id = %lookup_operation_id,
                    "runtime Operation query found stored projection corruption"
                );
                // A claimed Store closure outlives cancellation of the HTTP
                // future. Poison synchronously here so dropping a response
                // cannot leave this replica ready after deterministic stored
                // corruption was observed.
                readiness.poison();
            }
            read
        })
        .await?;
    let operation = match read {
        RuntimeOperationRead::Found(operation) => operation,
        RuntimeOperationRead::NotFound => return Err(ApiError::not_found("operation").into()),
        RuntimeOperationRead::Corrupt => {
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

fn raw_workspace_segment(uri: &Uri) -> &str {
    uri.path().split('/').nth(3).unwrap_or("")
}

fn exact_operation_segment<'a>(uri: &'a Uri, workspace_id: &Id) -> Option<&'a str> {
    let mut segments = uri.path().split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (
            Some(""),
            Some("v1"),
            Some("workspaces"),
            Some(workspace),
            Some("operations"),
            Some(operation),
            None,
        ) if workspace == workspace_id.as_str() && !operation.is_empty() => Some(operation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::{header, HeaderValue};
    use cats_metering::SqliteUsageStore;

    use super::*;
    use crate::controller::AutoTierPolicy;
    use crate::server::{Config, Handle};
    use crate::store::DsnSource;

    async fn server_with_corrupt_operation() -> (tempfile::TempDir, Handle, String, Id, Id) {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(
            SqliteUsageStore::open(&dir.path().join("usage.db")).expect("open usage store"),
        );
        let dsn = crate::testsupport::isolated_control_store_url();
        let handle = crate::server::spawn(Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(dsn.clone()),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            #[cfg(debug_assertions)]
            retired_storage_meta_for_tests: None,
            image_blob: crate::testsupport::unavailable_image_blob(),
            guest_runtime_profile_receipt: crate::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                crate::testsupport::test_runtime_provisioner_trust_bundle(),
            production_cutover_operator_trust_bundle:
                crate::testsupport::test_production_cutover_operator_trust_bundle(),
            auth_token: "service-token".into(),
            route_grant_signer: crate::testsupport::route_grant_signer(),
            admin_token: "admin-token".into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 30_000,
            reconcile_interval_ms: 60_000,
            auto_tier_policy: AutoTierPolicy::default(),
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        let workspace_id = tokio::task::block_in_place(|| {
            let workspace = handle
                .state
                .store
                .list_all_workspace_views()
                .unwrap()
                .into_iter()
                .find(|workspace| workspace.is_default)
                .unwrap()
                .id;
            Id::new(workspace).unwrap()
        });
        let operation_id = tokio::task::block_in_place(|| {
            crate::testsupport::begin_production_qualification_for_product_test(
                handle.state.store.as_ref(),
                &workspace_id,
            );
            crate::store::runtime_authority::product_tests::create_runtime_operation_for_api_test(
                handle.state.store.as_ref(),
                &workspace_id,
            )
        });
        let corrupt_operation_id = operation_id.clone();
        handle
            .state
            .store
            .execute(move |store| {
                store.with(|client| {
                    client.execute(
                        "UPDATE runtime_operations SET updated_at=updated_at+1
                          WHERE operation_id=$1",
                        &[&corrupt_operation_id.as_str()],
                    )?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        (dir, handle, dsn, workspace_id, operation_id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn claimed_corrupt_store_read_poisons_readiness_after_handler_cancellation() {
        let (_dir, handle, dsn, workspace_id, operation_id) = server_with_corrupt_operation().await;
        let mut table_lock =
            crate::testsupport::RuntimeOperationsTableLockForTest::acquire(&dsn).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer admin-token"),
        );
        let uri = format!("/v1/workspaces/{workspace_id}/operations/{operation_id}")
            .parse()
            .unwrap();
        let handler = tokio::spawn(get_runtime_operation(
            State(handle.state.clone()),
            OriginalUri(uri),
            headers,
        ));
        table_lock.wait_until_query_blocked().await;
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        table_lock.release();

        tokio::time::timeout(Duration::from_secs(2), async {
            while handle.state.readiness.is_ready() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("claimed corrupt Store closure did not poison readiness");
        handle.shutdown().await.unwrap();
    }
}

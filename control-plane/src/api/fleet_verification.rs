//! A19 administrator-only, observation-only cutover fleet snapshot.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use cats_api::error::ApiError;
use cats_api::fleet_verification::encode_fleet_verification_snapshot;

use super::{check_fleet_verification_admin_auth, ApiResult};
use crate::server::AppState;
use crate::store::AuthorityRequestContext;

const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

struct OwnedStoreRequest<T: Send + 'static> {
    request: AuthorityRequestContext,
    task: Option<tokio::task::JoinHandle<crate::store::Result<T>>>,
}

impl<T: Send + 'static> OwnedStoreRequest<T> {
    fn new(
        request: AuthorityRequestContext,
        task: tokio::task::JoinHandle<crate::store::Result<T>>,
    ) -> Self {
        Self {
            request,
            task: Some(task),
        }
    }

    async fn join_until(mut self, deadline: Instant) -> crate::store::Result<T> {
        let completed = {
            let task = self.task.as_mut().expect("owned Store task exists");
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => None,
                result = task => Some(result),
            }
        };
        if let Some(result) = completed {
            self.task = None;
            return result.map_err(|error| {
                ApiError::internal(format!("fleet verification Store owner failed: {error}"))
            })?;
        }
        self.request.cancel();
        // A deadline response owns the already-claimed blocking operation to
        // settlement. This releases its lane and PostgreSQL connection before
        // the 503 is returned and discards any value produced after timeout.
        let settled = self
            .task
            .as_mut()
            .expect("timed-out Store task remains owned")
            .await;
        self.task = None;
        if let Err(error) = settled {
            tracing::warn!(%error, "join timed-out fleet verification Store task");
        }
        Err(ApiError::unavailable(
            "fleet verification snapshot deadline expired",
        ))
    }
}

impl<T: Send + 'static> Drop for OwnedStoreRequest<T> {
    fn drop(&mut self) {
        self.request.cancel();
        let Some(task) = self.task.take() else {
            return;
        };
        // A dropped HTTP response cannot await, so transfer the claimed Store
        // task to an explicit joiner. The Store task itself is never detached:
        // it keeps owning the blocking execution, lane and connection until
        // cancellation reaches a transaction checkpoint and the job settles.
        let _joiner = tokio::spawn(async move {
            if let Err(error) = task.await {
                tracing::warn!(%error, "join dropped fleet verification Store task");
            }
        });
    }
}

pub(super) async fn fleet_verification(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let request_context = AuthorityRequestContext::new(deadline);
    if uri.path() != cats_api::fleet_verification::FLEET_VERIFICATION_PATH || uri.query().is_some()
    {
        return Err(ApiError::invalid("fleet verification request target is invalid").into());
    }
    check_fleet_verification_admin_auth(&state, &headers).await?;
    let request_guard = state
        .fleet_verification_service
        .begin(request_context.clone())
        .ok_or_else(|| ApiError::unavailable("fleet verification service is shutting down"))?;

    let approved_guest_config_digest = state
        .agent_session_registration_policy
        .approved_guest_config_digest()
        .clone();
    let worker_request = request_context.clone();
    let store = state.store.clone();
    let task = tokio::spawn(async move {
        let _request_guard = request_guard;
        let lane_request = worker_request.clone();
        store
            .execute_authority_request_owned(&lane_request, move |store| {
                store.fleet_verification_snapshot(&worker_request, &approved_guest_config_digest)
            })
            .await
    });
    let snapshot = OwnedStoreRequest::new(request_context, task)
        .join_until(deadline)
        .await?;
    let body = encode_fleet_verification_snapshot(&snapshot)
        .map_err(|_| ApiError::internal("could not encode fleet verification snapshot"))?;
    if Instant::now() >= deadline {
        return Err(ApiError::unavailable("fleet verification response deadline expired").into());
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .body(Body::from(body))
        .map_err(|_| ApiError::internal("could not build fleet verification response").into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn deadline_cancels_then_joins_owned_store_work_before_returning() {
        let request = AuthorityRequestContext::new(Instant::now() + Duration::from_millis(20));
        let worker_request = request.clone();
        let lane = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = lane.clone().acquire_owned().await.unwrap();
        let settled = Arc::new(AtomicBool::new(false));
        let worker_settled = Arc::clone(&settled);
        let task = tokio::spawn(async move {
            while !worker_request.is_cancelled_or_expired() {
                tokio::task::yield_now().await;
            }
            drop(permit);
            worker_settled.store(true, Ordering::Release);
            Ok(7_u8)
        });

        let error = OwnedStoreRequest::new(request, task)
            .join_until(Instant::now() + Duration::from_millis(5))
            .await
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert!(settled.load(Ordering::Acquire));
        assert!(lane.try_acquire().is_ok(), "Store lane was not reusable");
    }

    #[tokio::test]
    async fn dropping_http_owner_cancels_but_keeps_a_joiner_for_claimed_work() {
        let request = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(1));
        let worker_request = request.clone();
        let service = Arc::new(crate::server::FleetVerificationService::new());
        let request_guard = service.begin(request.clone()).unwrap();
        let lane = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = lane.clone().acquire_owned().await.unwrap();
        let (settled_tx, settled_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            while !worker_request.is_cancelled_or_expired() {
                tokio::task::yield_now().await;
            }
            drop(permit);
            drop(request_guard);
            let _ = settled_tx.send(());
            Ok(())
        });
        let owner = OwnedStoreRequest::new(request, task);

        drop(owner);
        tokio::time::timeout(Duration::from_millis(100), settled_rx)
            .await
            .expect("claimed Store owner did not settle after HTTP drop")
            .unwrap();
        assert_eq!(service.active_for_test(), 0);
        assert!(lane.try_acquire().is_ok(), "Store lane was not reusable");
    }
}

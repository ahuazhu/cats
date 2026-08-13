//! A19 administrator-only, observation-only cutover fleet snapshot.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use cats_api::error::ApiError;
use cats_api::fleet_verification::encode_fleet_verification_snapshot;

use super::{check_admin_auth, ApiResult};
use crate::server::AppState;
use crate::store::AuthorityRequestContext;

const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn fleet_verification(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());
    if uri.path() != cats_api::fleet_verification::FLEET_VERIFICATION_PATH || uri.query().is_some()
    {
        return Err(ApiError::invalid("fleet verification request target is invalid").into());
    }
    check_admin_auth(&state, &headers).await?;

    let approved_guest_config_digest = state
        .agent_session_registration_policy
        .approved_guest_config_digest()
        .clone();
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| ApiError::unavailable("fleet verification request deadline expired"))?;
    let worker_request = request_context.clone();
    let snapshot = tokio::time::timeout(
        remaining,
        state.store.execute(move |store| {
            store.fleet_verification_snapshot(&worker_request, &approved_guest_config_digest)
        }),
    )
    .await
    .map_err(|_| ApiError::unavailable("fleet verification snapshot deadline expired"))??;
    let body = encode_fleet_verification_snapshot(&snapshot)
        .map_err(|_| ApiError::internal("could not encode fleet verification snapshot"))?;

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

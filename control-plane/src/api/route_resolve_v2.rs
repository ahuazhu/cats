//! Strict Route Grant v2 resolve handler.
//!
//! The HTTP frame and authenticated-envelope work are production code. The
//! accepted architecture does not yet define a Gateway credential artifact,
//! current-credential Store, trust rotation, or TLS principal mapping. For
//! that reason the production router installs no value of
//! [`AuthenticatedGatewayPrincipal`], and every request fails before its body
//! is read or PostgreSQL is touched. Test support can insert the unforgeable
//! in-process proof to exercise the remainder of this route over loopback.

use std::error::Error as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use cats_api::error::ErrorCode;
use cats_api::route_grant_v2::{
    decode_route_resolve_v2_request, encode_route_resolve_v2_rejection,
    encode_route_resolve_v2_success, RouteResolveV2Rejection, RouteResolveV2RejectionCode,
    RouteResolveV2Success, RouteV2EnvelopeError, ROUTE_RESOLVE_V2_DEADLINE_MILLIS,
    ROUTE_RESOLVE_V2_METHOD, ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES, ROUTE_V2_JSON_CONTENT_TYPE,
};

use crate::server::AppState;
use crate::store::runtime_authority::route_signer::{
    RouteGrantV2AuthorityLoad, RouteGrantV2AuthorityRejection,
};
use crate::store::Store;

const ROUTE_RESOLVE_V2_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

/// Proof constructed only by a trusted in-process machine transport adapter.
///
/// There is intentionally no public constructor. An HTTP header cannot create
/// this value, so the current public/shared-bearer router cannot accidentally
/// authorize a Gateway while the credential authority remains undefined.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedGatewayPrincipal {
    _private: (),
}

impl AuthenticatedGatewayPrincipal {
    /// This constructor is an in-process trust boundary, not an authentication
    /// mechanism. It exists only in crate unit tests until a machine transport
    /// validates the future Gateway credential authority.
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Post-transport dependencies for one resolve lane. Keeping these separate
/// from [`AppState`] lets the future machine-authenticated listener compose
/// exactly this route without inheriting the public API's bearer/session
/// middleware.
pub(crate) struct RouteResolveV2Service {
    store: Arc<Store>,
    route_grant_signer: Option<Arc<crate::route_grant_v2::RouteGrantV2Signer>>,
    active_guest_digest: cats_api::runtime_reconciliation::Sha256Digest,
    admission: Arc<RouteResolveV2Admission>,
    #[cfg(test)]
    store_pause: Mutex<Option<RouteResolveV2StorePause>>,
}

/// Owns admitted Route v2 reads until both the handler and any Store closure
/// it started have settled. This is deliberately separate from the public API
/// admission lanes: a future machine listener must be able to stop and join
/// exactly its own work during shutdown.
pub(crate) struct RouteResolveV2Admission {
    permits: Arc<tokio::sync::Semaphore>,
    state: Mutex<RouteResolveV2AdmissionState>,
    changed: tokio::sync::Notify,
}

struct RouteResolveV2AdmissionState {
    accepting: bool,
    active: usize,
}

impl RouteResolveV2Admission {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(limit)),
            state: Mutex::new(RouteResolveV2AdmissionState {
                accepting: true,
                active: 0,
            }),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn try_begin(self: &Arc<Self>) -> Option<Arc<RouteResolveV2Lease>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting {
            return None;
        }
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
        state.active += 1;
        Some(Arc::new(RouteResolveV2Lease {
            admission: Arc::clone(self),
            _permit: permit,
        }))
    }

    pub(crate) fn begin_shutdown(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.accepting = false;
        self.permits.close();
        self.changed.notify_waiters();
    }

    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let joined = tokio::time::timeout(ROUTE_RESOLVE_V2_SHUTDOWN_DEADLINE, async {
            loop {
                let changed = self.changed.notified();
                if self.active_count() == 0 {
                    break;
                }
                changed.await;
            }
        })
        .await;
        anyhow::ensure!(
            joined.is_ok(),
            "Route v2 Store reads exceeded the shutdown deadline"
        );
        Ok(())
    }

    fn active_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    #[cfg(test)]
    fn exhaust_for_test(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.permits)
            .try_acquire_many_owned(self.permits.available_permits() as u32)
            .expect("test admission permits are available")
    }
}

struct RouteResolveV2Lease {
    admission: Arc<RouteResolveV2Admission>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for RouteResolveV2Lease {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.active > 0, "only an active Route v2 owner can finish");
        state.active -= 1;
        if state.active == 0 {
            self.admission.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct RouteResolveV2StorePause {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

impl RouteResolveV2Service {
    pub(crate) fn from_app_state(state: &AppState) -> Self {
        Self {
            store: Arc::clone(&state.store),
            // Route v2 must never borrow the legacy V1 key/config. A future
            // accepted secret-reference composition supplies this separately.
            route_grant_signer: None,
            active_guest_digest: state
                .agent_session_registration_policy
                .approved_guest_config_digest()
                .clone(),
            admission: Arc::clone(&state.route_resolve_admission),
            #[cfg(test)]
            store_pause: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        store: Arc<Store>,
        route_grant_signer: Arc<crate::route_grant_v2::RouteGrantV2Signer>,
        active_guest_digest: cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Self {
        Self {
            store,
            route_grant_signer: Some(route_grant_signer),
            active_guest_digest,
            admission: Arc::new(RouteResolveV2Admission::new(32)),
            store_pause: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn without_signer_for_test(
        store: Arc<Store>,
        active_guest_digest: cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Self {
        Self {
            store,
            route_grant_signer: None,
            active_guest_digest,
            admission: Arc::new(RouteResolveV2Admission::new(32)),
            store_pause: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn exhaust_admission_for_test(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.admission.exhaust_for_test()
    }

    #[cfg(test)]
    pub(crate) fn active_requests_for_test(&self) -> usize {
        self.admission.active_count()
    }

    #[cfg(test)]
    pub(crate) fn pause_store_after_start_for_test(
        &self,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        *self
            .store_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(RouteResolveV2StorePause { entered, release });
    }

    #[cfg(test)]
    pub(crate) async fn shutdown_for_test(&self) -> anyhow::Result<()> {
        self.admission.shutdown().await
    }
}

pub(crate) async fn resolve(
    Extension(service): Extension<Arc<RouteResolveV2Service>>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + Duration::from_millis(ROUTE_RESOLVE_V2_DEADLINE_MILLIS);
    if request.method().as_str() != ROUTE_RESOLVE_V2_METHOD {
        return rejection_response(
            StatusCode::METHOD_NOT_ALLOWED,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[(
                header::ALLOW,
                HeaderValue::from_static(ROUTE_RESOLVE_V2_METHOD),
            )],
        );
    }
    if request.uri().query().is_some() {
        return rejection_response(
            StatusCode::BAD_REQUEST,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[],
        );
    }

    // Authentication precedes body read/decode, admission and Store access.
    // The proof can only come from the future machine transport middleware.
    if request
        .extensions()
        .get::<AuthenticatedGatewayPrincipal>()
        .is_none()
    {
        return rejection_response(
            StatusCode::UNAUTHORIZED,
            RouteResolveV2RejectionCode::AuthenticationFailed,
            &[],
        );
    }
    let Some(route_grant_signer) = service.route_grant_signer.as_ref().cloned() else {
        // A machine principal must not accidentally activate this route before
        // the independent v2 signing-key composition exists.
        return unavailable_response();
    };

    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(ROUTE_V2_JSON_CONTENT_TYPE)
    }) {
        return rejection_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[],
        );
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return rejection_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[],
        );
    }
    if !headers.keys().all(route_resolve_v2_header_allowed) {
        return rejection_response(
            StatusCode::BAD_REQUEST,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[],
        );
    }
    if headers.contains_key(header::ACCEPT)
        && single_header_text(&headers, header::ACCEPT.as_str()).is_none_or(|value| {
            !value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(ROUTE_V2_JSON_CONTENT_TYPE)
        })
    {
        return rejection_response(
            StatusCode::NOT_ACCEPTABLE,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[],
        );
    }
    if declared_body_exceeds_limit(&headers) {
        return rejection_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            RouteResolveV2RejectionCode::InvalidRequest,
            &[],
        );
    }

    let request_lease = match service.admission.try_begin() {
        Some(lease) => lease,
        None => return unavailable_response(),
    };
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(request.into_body(), ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return rejection_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                RouteResolveV2RejectionCode::InvalidRequest,
                &[],
            );
        }
        Ok(Err(_)) => return internal_response(),
        Err(_) => return unavailable_response(),
    };
    let request = match decode_route_resolve_v2_request(&body) {
        Ok(request) => request,
        Err(RouteV2EnvelopeError::WireTooLarge) => {
            return rejection_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                RouteResolveV2RejectionCode::InvalidRequest,
                &[],
            );
        }
        Err(_) => {
            return rejection_response(
                StatusCode::BAD_REQUEST,
                RouteResolveV2RejectionCode::InvalidRequest,
                &[],
            );
        }
    };

    let signer_kid = route_grant_signer.kid().clone();
    let active_guest_digest = service.active_guest_digest.clone();
    let hostname = request.hostname;
    let store = service.store.clone();
    let store_lease = Arc::clone(&request_lease);
    #[cfg(test)]
    let store_pause = service
        .store_pause
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let loaded = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        store.execute(move |store| {
            let _store_lease = store_lease;
            #[cfg(test)]
            if let Some(pause) = store_pause {
                pause.entered.wait();
                pause.release.wait();
            }
            store.load_route_grant_v2_authority(&hostname, &signer_kid, &active_guest_digest)
        }),
    )
    .await;
    let snapshot = match loaded {
        Ok(Ok(RouteGrantV2AuthorityLoad::Ready(snapshot))) => snapshot,
        Ok(Ok(RouteGrantV2AuthorityLoad::Rejected(rejection))) => {
            return authority_rejection_response(rejection);
        }
        Ok(Err(error))
            if matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            return unavailable_response();
        }
        Ok(Err(_)) => return internal_response(),
        Err(_) => return unavailable_response(),
    };
    let issued = match route_grant_signer.issue(&snapshot) {
        Ok(issued) => issued,
        Err(_) => return unavailable_response(),
    };
    let response = match RouteResolveV2Success::new(
        snapshot.endpoint_id.clone(),
        snapshot.node_transport_target.clone(),
        issued.expires_at_unix_seconds,
        issued.token,
    )
    .and_then(|response| encode_route_resolve_v2_success(&response))
    {
        Ok(response) => response,
        Err(_) => return internal_response(),
    };
    if Instant::now() >= deadline {
        return unavailable_response();
    }
    success_response(response)
}

fn route_resolve_v2_header_allowed(name: &header::HeaderName) -> bool {
    name == header::HOST
        || name == header::CONTENT_TYPE
        || name == header::CONTENT_LENGTH
        || name == header::ACCEPT
        || name == header::TRANSFER_ENCODING
}

fn single_header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn declared_body_exceeds_limit(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_none_or(|length| length > ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES as u64)
}

fn authority_rejection_response(rejection: RouteGrantV2AuthorityRejection) -> Response {
    match rejection {
        RouteGrantV2AuthorityRejection::NotFound => rejection_response(
            StatusCode::NOT_FOUND,
            RouteResolveV2RejectionCode::NotFound,
            &[],
        ),
        RouteGrantV2AuthorityRejection::Gone => {
            rejection_response(StatusCode::GONE, RouteResolveV2RejectionCode::Gone, &[])
        }
        RouteGrantV2AuthorityRejection::WakeRequired => rejection_response(
            StatusCode::CONFLICT,
            RouteResolveV2RejectionCode::WakeRequired,
            &[],
        ),
        RouteGrantV2AuthorityRejection::Pending => rejection_response(
            StatusCode::CONFLICT,
            RouteResolveV2RejectionCode::Pending,
            &[],
        ),
        RouteGrantV2AuthorityRejection::Unavailable => unavailable_response(),
    }
}

fn unavailable_response() -> Response {
    rejection_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RouteResolveV2RejectionCode::Unavailable,
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn internal_response() -> Response {
    rejection_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        RouteResolveV2RejectionCode::Internal,
        &[],
    )
}

fn rejection_response(
    status: StatusCode,
    code: RouteResolveV2RejectionCode,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let body = encode_route_resolve_v2_rejection(&RouteResolveV2Rejection::new(code))
        .expect("fixed Route resolve rejection satisfies its wire contract");
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ROUTE_V2_JSON_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in extra_headers {
        headers.insert(name, value.clone());
    }
    response
}

fn success_response(body: Vec<u8>) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ROUTE_V2_JSON_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

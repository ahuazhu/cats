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
use std::sync::Arc;
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
    admission: Arc<tokio::sync::Semaphore>,
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
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
        }
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
    if headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::COOKIE)
        || [
            "idempotency-key",
            header::IF_MATCH.as_str(),
            header::IF_NONE_MATCH.as_str(),
            "x-http-method-override",
        ]
        .iter()
        .any(|name| headers.contains_key(*name))
    {
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

    let _permit = match service.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return unavailable_response(),
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
    let loaded = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        store.execute(move |store| {
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

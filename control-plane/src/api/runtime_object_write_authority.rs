//! Strict read-only ingress for one Node's own object-write writer authority.
//!
//! The Node cannot derive `owa1_<64hex>` — Control assigns it — and the fleet
//! writes one shared worker environment, so the authority ID cannot be Node
//! configuration either. This route closes that gap: the server answers, and
//! the caller asserts nothing.
//!
//! Framework admission, the bounded body and the shared per-Node A19 proof end
//! here, exactly as they do for the Desired-read and volume-transition routes.
//! Store code receives only an authenticated credential plus one closed
//! contract value, and the exact-current-`AgentSession` check that makes the
//! answer session-bound lives in the store transaction.
//!
//! The refusal envelope is the same `ErrorBody` the sibling object-write
//! credential registration route returns: the Node classifies this call by
//! status, never by a decoded error body.

use std::error::Error as _;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use cats_api::agent_registration::{
    verify_request_proof, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::object_write_gateway::{
    decode_object_write_writer_authority_read, encode_object_write_writer_authority_view,
    ObjectWriteWriterAuthorityView, OBJECT_WRITE_GATEWAY_METHOD,
    OBJECT_WRITE_WRITER_AUTHORITY_READ_MAX_WIRE_BYTES, OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH,
};
use cats_api::runtime_reconciliation::ContractVersion;

use crate::server::AppState;
use crate::store::AuthorityRequestContext;

/// The router registers this path as a literal so the route snapshot test can
/// see it. A contract change must break the build here rather than silently
/// leave the old route serving.
const _: () = assert!(matches!(
    OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH.as_bytes(),
    b"/v1/internal/runtime/object-write-authority-reads"
));
const _: () = assert!(matches!(OBJECT_WRITE_GATEWAY_METHOD.as_bytes(), b"POST"));

const HANDLER_DEADLINE: Duration = Duration::from_secs(5);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn writer_authority_read(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + HANDLER_DEADLINE;
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());

    if request.method().as_str() != OBJECT_WRITE_GATEWAY_METHOD {
        let mut response = error_response(ApiError::invalid(
            "object-write writer authority read requires POST",
        ));
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static(OBJECT_WRITE_GATEWAY_METHOD),
        );
        return response;
    }
    if request.uri().query().is_some() {
        return error_response(ApiError::invalid(
            "object-write writer authority read does not accept a query",
        ));
    }

    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) {
        let mut response = error_response(ApiError::invalid(
            "object-write writer authority read requires application/json",
        ));
        *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
        return response;
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        let mut response = error_response(ApiError::invalid(
            "object-write writer authority read does not accept Content-Encoding",
        ));
        *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
        return response;
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return error_response(ApiError::invalid(
            "object-write writer authority read does not accept Authorization",
        ));
    }
    if headers.contains_key(header::ACCEPT)
        && single_header_text(&headers, header::ACCEPT.as_str()).is_none_or(|value| {
            !value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
        })
    {
        let mut response = error_response(ApiError::invalid(
            "object-write writer authority read accepts only application/json",
        ));
        *response.status_mut() = StatusCode::NOT_ACCEPTABLE;
        return response;
    }
    if [
        "idempotency-key",
        header::IF_MATCH.as_str(),
        header::IF_NONE_MATCH.as_str(),
        header::COOKIE.as_str(),
        "x-http-method-override",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
    {
        return error_response(ApiError::invalid(
            "object-write writer authority read carried a forbidden semantic header",
        ));
    }

    let _global_permit = match state.object_write_authority_read_admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };

    if declared_body_exceeds_limit(&headers, OBJECT_WRITE_WRITER_AUTHORITY_READ_MAX_WIRE_BYTES) {
        return payload_too_large();
    }
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(
            request.into_body(),
            OBJECT_WRITE_WRITER_AUTHORITY_READ_MAX_WIRE_BYTES,
        ),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return payload_too_large();
        }
        Ok(Err(_)) => return internal_response(),
        Err(_) => return temporarily_unavailable(),
    };

    let authenticated = match (
        single_header_text(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header_text(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header_text(&headers, NODE_SIGNATURE_HEADER),
    ) {
        (Some(credential_id), Some(public_key_spki), Some(signature)) => verify_request_proof(
            OBJECT_WRITE_GATEWAY_METHOD,
            OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH,
            &body,
            credential_id,
            public_key_spki,
            signature,
        ),
        _ => Err(cats_api::agent_registration::RequestProofError),
    };
    let Ok(authenticated) = authenticated else {
        return authentication_failed();
    };
    let Ok(read) = decode_object_write_writer_authority_read(&body) else {
        return error_response(ApiError::invalid(
            "object-write writer authority read is malformed or noncanonical",
        ));
    };

    // The per-Node permit is taken after the credential resolves, so an
    // unauthenticated caller can neither select nor allocate one.
    let lookup_credential = authenticated.clone();
    let lookup_context = request_context.clone();
    let store = state.store.clone();
    let resolved = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        store.execute(move |store| {
            store.resolve_runtime_node_for_request(&lookup_credential, &lookup_context)
        }),
    )
    .await
    {
        Ok(Ok(Some(node_id))) => node_id,
        Ok(Ok(None)) => return identity_not_eligible(),
        Ok(Err(error)) if transient(&error) => return temporarily_unavailable(),
        Ok(Err(_)) => return internal_response(),
        Err(_) => return temporarily_unavailable(),
    };
    let _node_permit = match state
        .object_write_authority_read_admission
        .try_node(&resolved)
    {
        Ok(permit) => permit,
        Err(_) => return node_request_in_flight(),
    };

    let session = read.session.clone();
    let operation_context = request_context.clone();
    let store = state.store.clone();
    let read_authority = async move {
        store
            .execute(move |store| {
                store.object_write_writer_authority_for_node(
                    &authenticated,
                    &read,
                    &operation_context,
                )
            })
            .await
    };
    let authority =
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), read_authority)
            .await
        {
            Ok(Ok(Some(authority))) => authority,
            Ok(Ok(None)) => return identity_not_eligible(),
            Ok(Err(error)) if transient(&error) => return temporarily_unavailable(),
            Ok(Err(_)) => return internal_response(),
            Err(_) => return temporarily_unavailable(),
        };
    let view = ObjectWriteWriterAuthorityView {
        version: ContractVersion::V1,
        session,
        authority,
    };
    match encode_object_write_writer_authority_view(&view) {
        Ok(body) => success_response(body),
        Err(_) => internal_response(),
    }
}

fn transient(error: &ApiError) -> bool {
    matches!(
        error.code,
        ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
    )
}

fn single_header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn declared_body_exceeds_limit(headers: &HeaderMap, maximum: usize) -> bool {
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
        .is_none_or(|length| length > maximum as u64)
}

fn success_response(body: Vec<u8>) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn authentication_failed() -> Response {
    let mut response = error_response(ApiError::unauthenticated(
        "object-write writer authority read authentication failed",
    ));
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
    );
    response
}

fn identity_not_eligible() -> Response {
    error_response(ApiError::new(
        ErrorCode::PermissionDenied,
        "object-write writer authority read identity or session is not eligible",
    ))
}

fn node_request_in_flight() -> Response {
    let mut response = error_response(ApiError::unavailable(
        "another object-write writer authority read is in flight for this Node",
    ));
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn temporarily_unavailable() -> Response {
    let mut response = error_response(ApiError::unavailable(
        "object-write writer authority read is temporarily unavailable",
    ));
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn payload_too_large() -> Response {
    let mut response = error_response(ApiError::invalid(
        "object-write writer authority read exceeds its wire bound",
    ));
    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
    response
}

fn internal_response() -> Response {
    error_response(ApiError::internal(
        "object-write writer authority read failed internally",
    ))
}

fn error_response(error: ApiError) -> Response {
    let status =
        StatusCode::from_u16(error.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(ErrorBody::new(error.code, error.message))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

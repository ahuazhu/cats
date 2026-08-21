//! Strict session-bound runtime inventory ingress.
//!
//! The sole production route in this module accepts the clean
//! `RuntimeInventoryReport` contract. There is no Desired-read handler and no
//! legacy `NodeObservation` decoder. Store acceptance only updates telemetry,
//! the current full-inventory attestation, and a successful session renewal;
//! it cannot settle lifecycle Operations.

use std::error::Error as _;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use cats_api::agent_registration::{
    verify_request_proof, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::error::ErrorCode;
use cats_api::runtime_inventory::{
    decode_runtime_inventory_report, encode_runtime_inventory_acceptance,
    encode_runtime_inventory_error, RuntimeInventoryContractError, RuntimeInventoryError,
    RuntimeInventoryErrorDetail, RuntimeInventoryHttpProblem, RUNTIME_INVENTORY_METHOD,
    RUNTIME_INVENTORY_PATH, RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{AsciiText, ContractVersion};

use crate::server::AppState;
use crate::store::runtime_authority::runtime_spine::RuntimeInventoryOutcome;
use crate::store::AuthorityRequestContext;

const HANDLER_DEADLINE: Duration = Duration::from_secs(10);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn inventory(State(state): State<AppState>, request: Request<Body>) -> Response {
    let deadline = Instant::now() + HANDLER_DEADLINE;
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());

    if request.method().as_str() != RUNTIME_INVENTORY_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            RuntimeInventoryErrorDetail::HttpRequestRejected {
                problem: RuntimeInventoryHttpProblem::MethodNotAllowed,
            },
            "runtime inventory requires POST",
            &[(
                header::ALLOW,
                HeaderValue::from_static(RUNTIME_INVENTORY_METHOD),
            )],
        );
    }
    if request.uri().query().is_some() {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeInventoryHttpProblem::QueryNotAllowed,
            "runtime inventory does not accept a query",
        );
    }

    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) {
        return http_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RuntimeInventoryHttpProblem::ContentTypeNotAllowed,
            "runtime inventory requires application/json",
        );
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return http_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RuntimeInventoryHttpProblem::ContentEncodingNotAllowed,
            "runtime inventory does not accept Content-Encoding",
        );
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeInventoryHttpProblem::AuthorizationNotAllowed,
            "runtime inventory does not accept Authorization",
        );
    }
    if headers.contains_key(header::ACCEPT)
        && single_header_text(&headers, header::ACCEPT.as_str()).is_none_or(|value| {
            !value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
        })
    {
        return http_rejection(
            StatusCode::NOT_ACCEPTABLE,
            RuntimeInventoryHttpProblem::AcceptNotAllowed,
            "runtime inventory accepts only application/json",
        );
    }
    if [
        "idempotency-key",
        header::IF_MATCH.as_str(),
        header::IF_NONE_MATCH.as_str(),
        "x-http-method-override",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
    {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeInventoryHttpProblem::SemanticHeaderNotAllowed,
            "runtime inventory carried a forbidden semantic header",
        );
    }

    let _global_permit = match state.runtime_spine_admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    if declared_body_exceeds_limit(&headers, RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES) {
        return contract_rejection(RuntimeInventoryContractError::WireTooLarge);
    }
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(request.into_body(), RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return contract_rejection(RuntimeInventoryContractError::WireTooLarge);
        }
        Ok(Err(_)) => return internal_response(),
        Err(_) => return temporarily_unavailable(),
    };

    let proof = (
        single_header_text(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header_text(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header_text(&headers, NODE_SIGNATURE_HEADER),
    );
    let authenticated = match proof {
        (Some(credential_id), Some(public_key_spki), Some(signature)) => verify_request_proof(
            RUNTIME_INVENTORY_METHOD,
            RUNTIME_INVENTORY_PATH,
            &body,
            credential_id,
            public_key_spki,
            signature,
        ),
        _ => Err(cats_api::agent_registration::RequestProofError),
    };
    let authenticated = match authenticated {
        Ok(authenticated) => authenticated,
        Err(_) => return authentication_failed(),
    };
    let report = match decode_runtime_inventory_report(&body) {
        Ok(report) => report,
        Err(error) => return contract_rejection(error),
    };

    let lookup_credential = authenticated.clone();
    let lookup_store = state.observation_store.clone();
    let lookup = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        lookup_store.execute(move |store| store.resolve_runtime_node(&lookup_credential)),
    )
    .await;
    let node_id = match lookup {
        Ok(Ok(Some(node_id))) => node_id,
        Ok(Ok(None)) => return identity_not_eligible(),
        Ok(Err(error)) if transient(&error) => return temporarily_unavailable(),
        Ok(Err(_)) => return internal_response(),
        Err(_) => return temporarily_unavailable(),
    };
    let _node_permit = match state.runtime_spine_admission.try_node(&node_id) {
        Ok(permit) => permit,
        Err(_) => return node_request_in_flight(),
    };

    let store = state.observation_store.clone();
    let operation_context = request_context.clone();
    let response_context = request_context.clone();
    let operation = store.execute(move |store| {
        store.runtime_accept_inventory_for_request(&authenticated, &report, &operation_context)
    });
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation).await {
        Ok(Ok(RuntimeInventoryOutcome::Accepted(acceptance))) => {
            match encode_runtime_inventory_acceptance(&acceptance) {
                Ok(body) => success_response(body),
                Err(_) => internal_response(),
            }
        }
        Ok(Ok(RuntimeInventoryOutcome::Rejected(error))) => rejection_response(error),
        Ok(Err(_error)) if response_context.commit_was_attempted() => ambiguous_commit_response(),
        Ok(Err(error)) if transient(&error) => temporarily_unavailable(),
        Ok(Err(_)) => internal_response(),
        Err(_) if response_context.commit_was_attempted() => ambiguous_commit_response(),
        Err(_) => temporarily_unavailable(),
    }
}

fn transient(error: &cats_api::error::ApiError) -> bool {
    matches!(
        error.code,
        ErrorCode::Unavailable | ErrorCode::Conflict | ErrorCode::DeadlineExceeded
    )
}

fn rejection_response(error: RuntimeInventoryErrorDetail) -> Response {
    let status = match error {
        RuntimeInventoryErrorDetail::IdentityNotEligible => StatusCode::FORBIDDEN,
        RuntimeInventoryErrorDetail::MissingAgentSession { .. }
        | RuntimeInventoryErrorDetail::StaleSession { .. }
        | RuntimeInventoryErrorDetail::WrongSession { .. }
        | RuntimeInventoryErrorDetail::SessionExpired { .. }
        | RuntimeInventoryErrorDetail::StaleReportSequence { .. }
        | RuntimeInventoryErrorDetail::ReportSequenceConflict { .. }
        | RuntimeInventoryErrorDetail::MissingFullInventory { .. }
        | RuntimeInventoryErrorDetail::StaleInventoryEpoch { .. }
        | RuntimeInventoryErrorDetail::WrongInventoryEpoch { .. }
        | RuntimeInventoryErrorDetail::PartialCatNotInFullInventory { .. } => StatusCode::CONFLICT,
        RuntimeInventoryErrorDetail::MalformedPayload
        | RuntimeInventoryErrorDetail::UnsupportedVersion { .. }
        | RuntimeInventoryErrorDetail::LimitExceeded { .. } => StatusCode::BAD_REQUEST,
        RuntimeInventoryErrorDetail::AuthenticationFailed => StatusCode::UNAUTHORIZED,
        RuntimeInventoryErrorDetail::HttpRequestRejected { .. } => StatusCode::BAD_REQUEST,
        RuntimeInventoryErrorDetail::NodeRequestInFlight => StatusCode::CONFLICT,
        RuntimeInventoryErrorDetail::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        RuntimeInventoryErrorDetail::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, error, "runtime inventory was rejected", &[])
}

fn single_header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

fn declared_body_exceeds_limit(headers: &HeaderMap, maximum: usize) -> bool {
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(first) = lengths.next() else {
        return false;
    };
    if lengths.next().is_some() {
        return true;
    }
    first
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|length| length > maximum)
}

fn contract_rejection(error: RuntimeInventoryContractError) -> Response {
    let (status, detail, message) = match error {
        RuntimeInventoryContractError::WireTooLarge
        | RuntimeInventoryContractError::LimitExceeded => (
            StatusCode::PAYLOAD_TOO_LARGE,
            RuntimeInventoryErrorDetail::LimitExceeded {
                field: AsciiText::new("report").expect("static error field is valid"),
                maximum: cats_api::runtime_reconciliation::WireU64::new(
                    RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES as u64,
                )
                .expect("fixed report limit is valid"),
            },
            "runtime inventory exceeds its closed bound",
        ),
        RuntimeInventoryContractError::UnsupportedVersion => (
            StatusCode::CONFLICT,
            RuntimeInventoryErrorDetail::UnsupportedVersion {
                supported_version: ContractVersion::V1,
            },
            "runtime inventory version is unsupported",
        ),
        RuntimeInventoryContractError::Malformed
        | RuntimeInventoryContractError::InvalidContract
        | RuntimeInventoryContractError::DigestMismatch
        | RuntimeInventoryContractError::NotFullInventory => (
            StatusCode::BAD_REQUEST,
            RuntimeInventoryErrorDetail::MalformedPayload,
            "runtime inventory payload is malformed",
        ),
    };
    error_response(status, detail, message, &[])
}

fn authentication_failed() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        RuntimeInventoryErrorDetail::AuthenticationFailed,
        "runtime inventory authentication failed",
        &[(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
        )],
    )
}

fn identity_not_eligible() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        RuntimeInventoryErrorDetail::IdentityNotEligible,
        "runtime inventory identity is not eligible",
        &[],
    )
}

fn http_rejection(
    status: StatusCode,
    problem: RuntimeInventoryHttpProblem,
    message: &'static str,
) -> Response {
    error_response(
        status,
        RuntimeInventoryErrorDetail::HttpRequestRejected { problem },
        message,
        &[],
    )
}

fn node_request_in_flight() -> Response {
    error_response(
        StatusCode::CONFLICT,
        RuntimeInventoryErrorDetail::NodeRequestInFlight,
        "another runtime inventory request is in flight for this Node",
        &[],
    )
}

fn temporarily_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RuntimeInventoryErrorDetail::TemporarilyUnavailable,
        "runtime inventory is temporarily unavailable",
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn internal_response() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        RuntimeInventoryErrorDetail::Internal,
        "runtime inventory failed internally",
        &[],
    )
}

fn ambiguous_commit_response() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RuntimeInventoryErrorDetail::TemporarilyUnavailable,
        "runtime inventory commit outcome is unknown; retry the exact report",
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn error_response(
    status: StatusCode,
    detail: RuntimeInventoryErrorDetail,
    message: &'static str,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let envelope = RuntimeInventoryError {
        version: ContractVersion::V1,
        error: Box::new(detail),
        message: AsciiText::new(message).expect("static inventory error message is valid"),
    };
    let body = match encode_runtime_inventory_error(&envelope) {
        Ok(body) => body,
        Err(_) => {
            br#"{"code":"internal","message":"runtime inventory failed internally"}"#.to_vec()
        }
    };
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow, noarchive"),
    );
    for (name, value) in extra_headers {
        headers.insert(name.clone(), value.clone());
    }
    response
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_or_invalid_content_length_is_rejected_before_body_read() {
        let mut headers = HeaderMap::new();
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("2"));
        assert!(declared_body_exceeds_limit(&headers, 8));

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
        assert!(declared_body_exceeds_limit(&headers, 8));
    }

    #[test]
    fn contract_failure_mapping_never_claims_acceptance() {
        assert_eq!(
            contract_rejection(RuntimeInventoryContractError::DigestMismatch).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            contract_rejection(RuntimeInventoryContractError::WireTooLarge).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            contract_rejection(RuntimeInventoryContractError::UnsupportedVersion).status(),
            StatusCode::CONFLICT
        );
    }
}

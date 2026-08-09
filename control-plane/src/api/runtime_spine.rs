//! Strict A20 Desired-read and observation HTTP ingress.
//!
//! Framework admission, bounded raw bytes and the shared per-Node proof end
//! here. Store code receives only an authenticated credential plus one closed
//! runtime contract value.

use std::error::Error as _;
use std::io;
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
use cats_api::runtime_reconciliation::{
    decode_desired_read_request, decode_node_observation, encode_desired_read_snapshot,
    encode_observation_acceptance, encode_runtime_spine_error, ContractError, ContractErrorDetail,
    ContractName, ContractVersion, DesiredReadRequest, JsonPointer, LimitKind, NodeObservation,
    RuntimeSpineError, RuntimeSpineErrorDetail, RuntimeSpineHttpProblem, WireU64,
    DESIRED_READ_PATH, DESIRED_READ_REQUEST_MAX_WIRE_BYTES, NODE_OBSERVATION_MAX_WIRE_BYTES,
    OBSERVATION_PATH, RUNTIME_SPINE_METHOD,
};

use crate::server::AppState;
use crate::store::runtime_authority::runtime_spine::{RuntimeSpineOutcome, RuntimeSpineRejection};
use crate::store::AuthorityRequestContext;

const HANDLER_DEADLINE: Duration = Duration::from_secs(10);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

#[derive(Clone, Copy)]
enum Route {
    DesiredRead,
    Observation,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Self::DesiredRead => DESIRED_READ_PATH,
            Self::Observation => OBSERVATION_PATH,
        }
    }

    fn body_limit(self) -> usize {
        match self {
            Self::DesiredRead => DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
            Self::Observation => NODE_OBSERVATION_MAX_WIRE_BYTES,
        }
    }

    fn contract(self) -> ContractName {
        match self {
            Self::DesiredRead => ContractName::DesiredReadRequest,
            Self::Observation => ContractName::NodeObservation,
        }
    }
}

enum DecodedRequest {
    DesiredRead(DesiredReadRequest),
    Observation(Box<NodeObservation>),
}

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn desired_read(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    handle(state, request, Route::DesiredRead).await
}

pub(super) async fn observation(State(state): State<AppState>, request: Request<Body>) -> Response {
    handle(state, request, Route::Observation).await
}

async fn handle(state: AppState, request: Request<Body>, route: Route) -> Response {
    let deadline = Instant::now() + HANDLER_DEADLINE;
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());

    if request.method().as_str() != RUNTIME_SPINE_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            RuntimeSpineErrorDetail::HttpRequestRejected {
                problem: RuntimeSpineHttpProblem::MethodNotAllowed,
            },
            "runtime request requires POST",
            &[(
                header::ALLOW,
                HeaderValue::from_static(RUNTIME_SPINE_METHOD),
            )],
        );
    }
    if request.uri().query().is_some() {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeSpineHttpProblem::QueryNotAllowed,
            "runtime request does not accept a query",
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
            RuntimeSpineHttpProblem::ContentTypeNotAllowed,
            "runtime request requires application/json",
        );
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return http_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RuntimeSpineHttpProblem::ContentEncodingNotAllowed,
            "runtime request does not accept Content-Encoding",
        );
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeSpineHttpProblem::AuthorizationNotAllowed,
            "runtime request does not accept Authorization",
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
            RuntimeSpineHttpProblem::AcceptNotAllowed,
            "runtime request accepts only application/json",
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
            RuntimeSpineHttpProblem::SemanticHeaderNotAllowed,
            "runtime request carried a forbidden semantic header",
        );
    }

    let _global_permit = match state.runtime_spine_admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };

    if declared_body_exceeds_limit(&headers, route.body_limit()) {
        return contract_error_response(StatusCode::PAYLOAD_TOO_LARGE, body_limit_error(route));
    }
    let body = match to_bytes(request.into_body(), route.body_limit()).await {
        Ok(body) => body,
        Err(error)
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return contract_error_response(StatusCode::PAYLOAD_TOO_LARGE, body_limit_error(route));
        }
        Err(_) => return internal_response(),
    };

    let proof = (
        single_header_text(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header_text(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header_text(&headers, NODE_SIGNATURE_HEADER),
    );
    let authenticated = match proof {
        (Some(credential_id), Some(public_key_spki), Some(signature)) => verify_request_proof(
            RUNTIME_SPINE_METHOD,
            route.path(),
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

    let decoded = match route {
        Route::DesiredRead => match decode_desired_read_request(&body) {
            Ok(request) => DecodedRequest::DesiredRead(request),
            Err(error) => return contract_error_response(decode_status(&error), error),
        },
        Route::Observation => match decode_node_observation(&body) {
            Ok(observation) => DecodedRequest::Observation(Box::new(observation)),
            Err(error) => return contract_error_response(decode_status(&error), error),
        },
    };

    let lookup_credential = authenticated.clone();
    let lookup = match route {
        Route::DesiredRead => {
            let store = state.store.clone();
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                store.execute(move |store| store.resolve_runtime_node(&lookup_credential)),
            )
            .await
        }
        Route::Observation => {
            let store = state.observation_store.clone();
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                store.execute(move |store| store.resolve_runtime_node(&lookup_credential)),
            )
            .await
        }
    };
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

    let store = state.store.clone();
    let operation_context = request_context.clone();
    let response_context = request_context.clone();
    let operation = async move {
        match decoded {
            DecodedRequest::DesiredRead(request) => store
                .execute(move |store| {
                    store.runtime_desired_read_for_request(
                        &authenticated,
                        &request,
                        &operation_context,
                    )
                })
                .await
                .map(|outcome| match outcome {
                    RuntimeSpineOutcome::Accepted(response) => {
                        encode_desired_read_snapshot(&response)
                            .map(EncodedOutcome::Accepted)
                            .map_err(|_| ())
                    }
                    RuntimeSpineOutcome::Rejected(rejection) => {
                        Ok(EncodedOutcome::Rejected(rejection))
                    }
                }),
            DecodedRequest::Observation(observation) => state
                .observation_store
                .execute(move |store| {
                    store.runtime_accept_observation_for_request(
                        &authenticated,
                        observation.as_ref(),
                        &operation_context,
                    )
                })
                .await
                .map(|outcome| match outcome {
                    RuntimeSpineOutcome::Accepted(response) => {
                        encode_observation_acceptance(&response)
                            .map(EncodedOutcome::Accepted)
                            .map_err(|_| ())
                    }
                    RuntimeSpineOutcome::Rejected(rejection) => {
                        Ok(EncodedOutcome::Rejected(rejection))
                    }
                }),
        }
    };

    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation).await {
        Ok(Ok(Ok(EncodedOutcome::Accepted(body)))) => success_response(body),
        Ok(_) if response_context.commit_was_attempted() => ambiguous_commit_response(),
        Ok(Ok(Ok(EncodedOutcome::Rejected(rejection)))) => rejection_response(rejection),
        Ok(Ok(Err(()))) => internal_response(),
        Ok(Err(error)) if transient(&error) => temporarily_unavailable(),
        Ok(Err(_)) => internal_response(),
        Err(_) if response_context.commit_was_attempted() => ambiguous_commit_response(),
        Err(_) => temporarily_unavailable(),
    }
}

enum EncodedOutcome {
    Accepted(Vec<u8>),
    Rejected(RuntimeSpineRejection),
}

fn transient(error: &cats_api::error::ApiError) -> bool {
    matches!(
        error.code,
        ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
    )
}

fn rejection_response(rejection: RuntimeSpineRejection) -> Response {
    match rejection {
        RuntimeSpineRejection::IdentityNotEligible => identity_not_eligible(),
        RuntimeSpineRejection::Contract(error) => {
            contract_error_response(StatusCode::CONFLICT, error)
        }
    }
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

fn body_limit_error(route: Route) -> ContractError {
    let maximum = route.body_limit() as u64;
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::LimitExceeded {
            contract: route.contract(),
            json_pointer: JsonPointer::new(String::new()).expect("empty JSON pointer is valid"),
            limit: LimitKind::WireBytes,
            maximum: WireU64::new(maximum).expect("runtime route limit fits U64"),
            observed_at_least: WireU64::new(maximum + 1)
                .expect("runtime route limit plus one fits U64"),
        }),
        message: "runtime reconciliation contract limit exceeded".to_owned(),
    }
}

fn decode_status(error: &ContractError) -> StatusCode {
    match error.error.as_ref() {
        ContractErrorDetail::LimitExceeded { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        ContractErrorDetail::MalformedPayload { .. }
        | ContractErrorDetail::UnsupportedVersion { .. } => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn authentication_failed() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        RuntimeSpineErrorDetail::AuthenticationFailed,
        "runtime request authentication failed",
        &[(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
        )],
    )
}

fn identity_not_eligible() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        RuntimeSpineErrorDetail::IdentityNotEligible,
        "runtime request identity is not eligible",
        &[],
    )
}

fn http_rejection(
    status: StatusCode,
    problem: RuntimeSpineHttpProblem,
    message: &'static str,
) -> Response {
    error_response(
        status,
        RuntimeSpineErrorDetail::HttpRequestRejected { problem },
        message,
        &[],
    )
}

fn contract_error_response(status: StatusCode, error: ContractError) -> Response {
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        return internal_response();
    }
    error_response(
        status,
        RuntimeSpineErrorDetail::ContractError {
            contract_error: error,
        },
        "runtime contract was rejected",
        &[],
    )
}

fn node_request_in_flight() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        RuntimeSpineErrorDetail::NodeRequestInFlight,
        "another runtime request for this Node is in flight",
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn temporarily_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RuntimeSpineErrorDetail::TemporarilyUnavailable,
        "runtime service is temporarily unavailable",
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn internal_response() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        RuntimeSpineErrorDetail::Internal,
        "runtime service failed internally",
        &[],
    )
}

/// Deliberately produces an incomplete HTTP response. Once COMMIT may have
/// reached PostgreSQL, no status/envelope can truthfully assert success or
/// failure; the Node must retry the exact durable domain request.
fn ambiguous_commit_response() -> Response {
    let stream = futures_util::stream::once(async {
        Err::<&'static [u8], io::Error>(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "runtime authority commit outcome is unknown",
        ))
    });
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from_stream(stream))
        .expect("fixed ambiguous response is valid")
}

fn error_response(
    status: StatusCode,
    detail: RuntimeSpineErrorDetail,
    message: &'static str,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let envelope = RuntimeSpineError {
        version: ContractVersion::V1,
        error: Box::new(detail),
        message: message.to_owned(),
    };
    let body = encode_runtime_spine_error(&envelope)
        .expect("fixed runtime spine errors satisfy their closed wire contract");
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
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
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ambiguous_commit_response_cannot_be_mistaken_for_an_http_error_envelope() {
        let response = ambiguous_commit_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert!(to_bytes(response.into_body(), 1).await.is_err());
    }
}

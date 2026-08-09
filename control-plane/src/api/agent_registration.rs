//! Exact Agent registration HTTP ingress.
//!
//! HTTP/framework admission ends here. The Store receives only the shared
//! [`AuthenticatedNodeCredential`] and decoded runtime contract value.

use std::error::Error as _;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use cats_api::agent_registration::{
    encode_agent_registration_error, verify_request_proof, AgentRegistrationError,
    AgentRegistrationErrorDetail, HttpRequestRejection, JSON_CONTENT_TYPE,
    NODE_AUTHENTICATE_CHALLENGE, NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER,
    NODE_SIGNATURE_HEADER, REGISTRATION_METHOD, REGISTRATION_PATH,
    REGISTRATION_REQUEST_MAX_WIRE_BYTES, REGISTRATION_SUCCESS_MAX_WIRE_BYTES,
};
use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, encode_agent_session, ContractError, ContractErrorDetail,
    ContractName, ContractVersion, JsonPointer, LimitKind, WireU64,
};

use crate::server::AppState;
use crate::store::{AgentRegistrationOutcome, AgentRegistrationRejection};

pub(super) async fn register_agent_session(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    if request.method().as_str() != REGISTRATION_METHOD {
        return registration_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            AgentRegistrationErrorDetail::HttpRequestRejected {
                problem: HttpRequestRejection::MethodNotAllowed,
            },
            "Agent registration requires POST",
            &[(header::ALLOW, HeaderValue::from_static(REGISTRATION_METHOD))],
        );
    }
    if request.uri().query().is_some() {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            HttpRequestRejection::QueryNotAllowed,
            "Agent registration does not accept a query",
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
            HttpRequestRejection::ContentTypeNotAllowed,
            "Agent registration requires application/json",
        );
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return http_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            HttpRequestRejection::ContentEncodingNotAllowed,
            "Agent registration does not accept Content-Encoding",
        );
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            HttpRequestRejection::AuthorizationNotAllowed,
            "Agent registration does not accept Authorization",
        );
    }

    if declared_body_exceeds_limit(&headers) {
        return contract_error_response(StatusCode::PAYLOAD_TOO_LARGE, body_limit_error());
    }
    let body = match to_bytes(request.into_body(), REGISTRATION_REQUEST_MAX_WIRE_BYTES).await {
        Ok(body) => body,
        Err(error)
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return contract_error_response(StatusCode::PAYLOAD_TOO_LARGE, body_limit_error());
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
            REGISTRATION_METHOD,
            REGISTRATION_PATH,
            &body,
            credential_id,
            public_key_spki,
            signature,
        ),
        _ => Err(cats_api::agent_registration::RequestProofError),
    };
    let authenticated = match authenticated {
        Ok(authenticated) => authenticated,
        Err(_) => {
            return registration_error_response(
                StatusCode::UNAUTHORIZED,
                AgentRegistrationErrorDetail::AuthenticationFailed,
                "Agent registration authentication failed",
                &[(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
                )],
            );
        }
    };

    let attempt = match decode_agent_registration_attempt(&body) {
        Ok(attempt) => attempt,
        Err(error) => return contract_error_response(contract_decode_status(&error), error),
    };
    let policy = state.agent_session_registration_policy.clone();
    let outcome = state
        .store
        .execute(move |store| store.register_agent_session(&authenticated, &attempt, &policy))
        .await;
    match outcome {
        Ok(AgentRegistrationOutcome::Registered(session)) => match encode_agent_session(&session) {
            Ok(body) if body.len() <= REGISTRATION_SUCCESS_MAX_WIRE_BYTES => success_response(body),
            _ => internal_response(),
        },
        Ok(AgentRegistrationOutcome::Rejected(rejection)) => rejection_response(rejection),
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            registration_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                AgentRegistrationErrorDetail::TemporarilyUnavailable,
                "Agent registration is temporarily unavailable",
                &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
            )
        }
        Err(_) => internal_response(),
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
        .is_none_or(|length| length > REGISTRATION_REQUEST_MAX_WIRE_BYTES as u64)
}

fn body_limit_error() -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::LimitExceeded {
            contract: ContractName::AgentRegistrationAttempt,
            json_pointer: JsonPointer::new(String::new()).expect("empty JSON pointer is valid"),
            limit: LimitKind::WireBytes,
            maximum: WireU64::new(REGISTRATION_REQUEST_MAX_WIRE_BYTES as u64)
                .expect("registration body limit fits U64"),
            observed_at_least: WireU64::new(REGISTRATION_REQUEST_MAX_WIRE_BYTES as u64 + 1)
                .expect("registration body limit plus one fits U64"),
        }),
        message: "runtime reconciliation contract limit exceeded".to_owned(),
    }
}

fn contract_decode_status(error: &ContractError) -> StatusCode {
    match error.error.as_ref() {
        ContractErrorDetail::LimitExceeded { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        ContractErrorDetail::MalformedPayload { .. }
        | ContractErrorDetail::UnsupportedVersion { .. } => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn rejection_response(rejection: AgentRegistrationRejection) -> Response {
    match rejection {
        AgentRegistrationRejection::IdentityNotEligible => registration_error_response(
            StatusCode::FORBIDDEN,
            AgentRegistrationErrorDetail::IdentityNotEligible,
            "Agent registration identity is not eligible",
            &[],
        ),
        AgentRegistrationRejection::SessionEpochMismatch {
            current_agent_session_epoch,
            presented_expected_agent_session_epoch,
        } => registration_error_response(
            StatusCode::CONFLICT,
            AgentRegistrationErrorDetail::SessionEpochMismatch {
                current_agent_session_epoch,
                presented_expected_agent_session_epoch,
            },
            "Agent registration expected session epoch does not match current",
            &[],
        ),
        AgentRegistrationRejection::Contract(error) => match error.error.as_ref() {
            ContractErrorDetail::RegistrationAttemptConflict { .. } => {
                contract_error_response(StatusCode::CONFLICT, error)
            }
            ContractErrorDetail::GuestConfigMismatch { .. } => {
                contract_error_response(StatusCode::PRECONDITION_FAILED, error)
            }
            _ => internal_response(),
        },
    }
}

fn http_rejection(
    status: StatusCode,
    problem: HttpRequestRejection,
    message: &'static str,
) -> Response {
    registration_error_response(
        status,
        AgentRegistrationErrorDetail::HttpRequestRejected { problem },
        message,
        &[],
    )
}

fn contract_error_response(status: StatusCode, contract_error: ContractError) -> Response {
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        return internal_response();
    }
    registration_error_response(
        status,
        AgentRegistrationErrorDetail::ContractError { contract_error },
        "Agent registration contract was rejected",
        &[],
    )
}

fn internal_response() -> Response {
    registration_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        AgentRegistrationErrorDetail::Internal,
        "Agent registration failed internally",
        &[],
    )
}

fn registration_error_response(
    status: StatusCode,
    detail: AgentRegistrationErrorDetail,
    message: &'static str,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let envelope = AgentRegistrationError {
        version: ContractVersion::V1,
        error: detail,
        message: message.to_owned(),
    };
    let body = encode_agent_registration_error(&envelope)
        .expect("fixed Agent registration errors satisfy their closed wire contract");
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

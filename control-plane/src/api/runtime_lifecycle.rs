//! Strict Node-to-Control transport for atomic per-Cat lifecycle commands.
//!
//! This adapter owns only HTTP admission, bounded canonical wire decoding and
//! the shared per-Node request proof. PostgreSQL remains the authority for the
//! current credential lineage, AgentSession, command delivery and exact
//! terminal-result settlement.

use std::error::Error as _;
use std::io;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use cats_api::agent_registration::{
    verify_request_proof, AuthenticatedNodeCredential, JSON_CONTENT_TYPE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_lifecycle::{
    decode_lifecycle_command_poll_request, decode_lifecycle_result_commit_request,
    encode_atomic_lifecycle_error, encode_lifecycle_command_batch,
    encode_lifecycle_result_stored_ack, AtomicLifecycleError, LifecycleCommandPollRequest,
    LifecycleResultCommitRequest, RuntimeLifecycleContractError,
    LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES, LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES,
    LIFECYCLE_COMMAND_POLL_PATH, LIFECYCLE_INTERNAL_METHOD, LIFECYCLE_RESULT_COMMIT_MAX_WIRE_BYTES,
    LIFECYCLE_RESULT_COMMIT_PATH,
};
use cats_api::runtime_lifecycle_volume::{
    decode_lifecycle_volume_transition_request, encode_lifecycle_volume_transition_response,
    LifecycleVolumeTransitionRequest, RuntimeLifecycleVolumeContractError,
    LIFECYCLE_VOLUME_TRANSITION_PATH, LIFECYCLE_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{AsciiText, WireU64};

use crate::server::AppState;
use crate::store::runtime_authority::lifecycle_commands::{
    LifecycleCommandPollOutcome, LifecyclePollRejection, LifecycleResultCommitOutcome,
    LifecycleResultCommitRejection, LifecycleSessionRejection,
};

const HANDLER_DEADLINE: Duration = Duration::from_secs(10);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    CommandPoll,
    ResultCommit,
    VolumeTransition,
}

impl Route {
    const fn path(self) -> &'static str {
        match self {
            Self::CommandPoll => LIFECYCLE_COMMAND_POLL_PATH,
            Self::ResultCommit => LIFECYCLE_RESULT_COMMIT_PATH,
            Self::VolumeTransition => LIFECYCLE_VOLUME_TRANSITION_PATH,
        }
    }

    const fn request_body_limit(self) -> usize {
        match self {
            Self::CommandPoll => LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES,
            Self::ResultCommit => LIFECYCLE_RESULT_COMMIT_MAX_WIRE_BYTES,
            Self::VolumeTransition => LIFECYCLE_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
        }
    }
}

#[derive(Debug)]
enum DecodedRequest {
    CommandPoll(LifecycleCommandPollRequest),
    ResultCommit(Box<LifecycleResultCommitRequest>),
    VolumeTransition(Box<LifecycleVolumeTransitionRequest>),
}

#[derive(Debug)]
struct PreparedRequest {
    authenticated: AuthenticatedNodeCredential,
    decoded: DecodedRequest,
}

pub(super) async fn command_poll(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    handle(state, request, Route::CommandPoll).await
}

pub(super) async fn result_commit(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    handle(state, request, Route::ResultCommit).await
}

pub(super) async fn volume_transition(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    handle(state, request, Route::VolumeTransition).await
}

async fn handle(state: AppState, request: Request<Body>, route: Route) -> Response {
    let deadline = Instant::now() + HANDLER_DEADLINE;
    let prepared = match prepare_request(request, route, deadline).await {
        Ok(prepared) => prepared,
        Err(response) => return response,
    };

    match prepared.decoded {
        DecodedRequest::CommandPoll(poll) => {
            let outcome = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                execute_command_poll(&state, prepared.authenticated, poll),
            )
            .await;
            match outcome {
                Ok(Ok(LifecycleCommandPollOutcome::Batch(batch))) => {
                    match encode_lifecycle_command_batch(&batch) {
                        Ok(body) if body.len() <= LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES => {
                            success_response(body)
                        }
                        _ => opaque_response(StatusCode::INTERNAL_SERVER_ERROR, &[]),
                    }
                }
                Ok(Ok(LifecycleCommandPollOutcome::Rejected(rejection))) => {
                    poll_rejection_response(rejection)
                }
                Ok(Err(error)) if transient(&error) => temporarily_unavailable(),
                Ok(Err(_)) => opaque_response(StatusCode::INTERNAL_SERVER_ERROR, &[]),
                Err(_) => temporarily_unavailable(),
            }
        }
        DecodedRequest::ResultCommit(commit) => {
            let outcome = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                execute_result_commit(&state, prepared.authenticated, *commit),
            )
            .await;
            match outcome {
                Ok(Ok(LifecycleResultCommitOutcome::Stored {
                    acknowledgement, ..
                }))
                | Ok(Ok(LifecycleResultCommitOutcome::ExactReplay {
                    acknowledgement, ..
                })) => match encode_lifecycle_result_stored_ack(&acknowledgement) {
                    Ok(body) => success_response(body),
                    // PostgreSQL may already contain the exact result. Never
                    // turn a response-encoding failure into a definite error.
                    Err(_) => ambiguous_commit_response(),
                },
                Ok(Ok(LifecycleResultCommitOutcome::Rejected(rejection))) => {
                    result_rejection_response(rejection)
                }
                // Once the settlement closure starts, a timeout or Store
                // error cannot prove whether COMMIT became durable. Force the
                // Node to repost its exact journaled result.
                Ok(Err(_)) | Err(_) => ambiguous_commit_response(),
            }
        }
        DecodedRequest::VolumeTransition(request) => {
            let outcome = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                execute_volume_transition(&state, prepared.authenticated, *request),
            )
            .await;
            match outcome {
                Ok(Ok(response)) => match encode_lifecycle_volume_transition_response(&response) {
                    Ok(body) => success_response(body),
                    Err(_) => ambiguous_commit_response(),
                },
                // A Store error/timeout cannot prove whether the Volume
                // mutation and immutable receipt ledger committed. The Node
                // must replay this exact signed, journaled request.
                Ok(Err(_)) | Err(_) => ambiguous_commit_response(),
            }
        }
    }
}

/// Keep all synchronous PostgreSQL integration behind the independent
/// lifecycle lane so telemetry and ordinary product work cannot starve
/// command delivery or result settlement.
async fn execute_command_poll(
    state: &AppState,
    authenticated: AuthenticatedNodeCredential,
    poll: LifecycleCommandPollRequest,
) -> crate::store::Result<LifecycleCommandPollOutcome> {
    let store = state.lifecycle_store.clone();
    store
        .execute(move |store| store.poll_lifecycle_commands(&authenticated, &poll))
        .await
}

async fn execute_result_commit(
    state: &AppState,
    authenticated: AuthenticatedNodeCredential,
    commit: LifecycleResultCommitRequest,
) -> crate::store::Result<LifecycleResultCommitOutcome> {
    let store = state.lifecycle_store.clone();
    store
        .execute(move |store| store.commit_lifecycle_result(&authenticated, &commit))
        .await
}

async fn execute_volume_transition(
    state: &AppState,
    authenticated: AuthenticatedNodeCredential,
    request: LifecycleVolumeTransitionRequest,
) -> crate::store::Result<cats_api::runtime_lifecycle_volume::LifecycleVolumeTransitionResponse> {
    let store = state.lifecycle_store.clone();
    store
        .execute(move |store| {
            store.apply_lifecycle_volume_transition_wire(&authenticated, &request)
        })
        .await
}

async fn prepare_request(
    request: Request<Body>,
    route: Route,
    deadline: Instant,
) -> Result<PreparedRequest, Response> {
    if request.method().as_str() != LIFECYCLE_INTERNAL_METHOD {
        return Err(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            malformed_error("request method is not allowed"),
            &[(
                header::ALLOW,
                HeaderValue::from_static(LIFECYCLE_INTERNAL_METHOD),
            )],
        ));
    }
    if request.uri().query().is_some() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("request target is invalid"),
            &[],
        ));
    }

    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            malformed_error("request media type is not allowed"),
            &[],
        ));
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            malformed_error("request content encoding is not allowed"),
            &[],
        ));
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("request authorization header is not allowed"),
            &[],
        ));
    }
    if headers.contains_key(header::ACCEPT)
        && single_header_text(&headers, header::ACCEPT.as_str()).is_none_or(|value| {
            !value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
        })
    {
        return Err(error_response(
            StatusCode::NOT_ACCEPTABLE,
            malformed_error("response media type is not allowed"),
            &[],
        ));
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
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("request semantic header is not allowed"),
            &[],
        ));
    }

    if declared_body_exceeds_limit(&headers, route.request_body_limit()) {
        return Err(body_limit_response(route));
    }
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(request.into_body(), route.request_body_limit()),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return Err(body_limit_response(route));
        }
        Ok(Err(_)) => {
            return Err(opaque_response(StatusCode::INTERNAL_SERVER_ERROR, &[]));
        }
        Err(_) => return Err(temporarily_unavailable()),
    };

    let proof = (
        single_header_text(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header_text(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header_text(&headers, NODE_SIGNATURE_HEADER),
    );
    let authenticated = match proof {
        (Some(credential_id), Some(public_key_spki), Some(signature)) => verify_request_proof(
            LIFECYCLE_INTERNAL_METHOD,
            route.path(),
            &body,
            credential_id,
            public_key_spki,
            signature,
        ),
        _ => Err(cats_api::agent_registration::RequestProofError),
    };
    let authenticated = authenticated.map_err(|_| authentication_failed())?;

    let decoded = match route {
        Route::CommandPoll => decode_lifecycle_command_poll_request(&body)
            .map(DecodedRequest::CommandPoll)
            .map_err(|error| contract_error_response(error, route))?,
        Route::ResultCommit => decode_lifecycle_result_commit_request(&body)
            .map(Box::new)
            .map(DecodedRequest::ResultCommit)
            .map_err(|error| contract_error_response(error, route))?,
        Route::VolumeTransition => decode_lifecycle_volume_transition_request(&body)
            .map(Box::new)
            .map(DecodedRequest::VolumeTransition)
            .map_err(volume_contract_error_response)?,
    };
    Ok(PreparedRequest {
        authenticated,
        decoded,
    })
}

fn volume_contract_error_response(error: RuntimeLifecycleVolumeContractError) -> Response {
    match error {
        RuntimeLifecycleVolumeContractError::WireTooLarge => {
            body_limit_response(Route::VolumeTransition)
        }
        RuntimeLifecycleVolumeContractError::UnsupportedVersion
        | RuntimeLifecycleVolumeContractError::Malformed
        | RuntimeLifecycleVolumeContractError::InvalidContract => error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("lifecycle Volume transition body is invalid"),
            &[],
        ),
    }
}

fn poll_rejection_response(rejection: LifecyclePollRejection) -> Response {
    match rejection {
        LifecyclePollRejection::InvalidContract => error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("lifecycle poll is invalid"),
            &[],
        ),
        LifecyclePollRejection::Session(rejection) => session_rejection_response(rejection),
    }
}

fn result_rejection_response(rejection: LifecycleResultCommitRejection) -> Response {
    match rejection {
        LifecycleResultCommitRejection::InvalidContract => error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("lifecycle result is invalid"),
            &[],
        ),
        LifecycleResultCommitRejection::Session(rejection) => session_rejection_response(rejection),
        LifecycleResultCommitRejection::OperationNotFound => error_response(
            StatusCode::CONFLICT,
            AtomicLifecycleError::StaleOperation {
                current_operation_id: None,
            },
            &[],
        ),
        LifecycleResultCommitRejection::OperationNotCurrent {
            current_operation_id: Some(current_operation_id),
        } => error_response(
            StatusCode::CONFLICT,
            AtomicLifecycleError::SupersededOperation {
                current_operation_id,
            },
            &[],
        ),
        LifecycleResultCommitRejection::OperationNotCurrent {
            current_operation_id: None,
        } => error_response(
            StatusCode::CONFLICT,
            AtomicLifecycleError::StaleOperation {
                current_operation_id: None,
            },
            &[],
        ),
        LifecycleResultCommitRejection::ConflictingTerminalResult { operation_id } => {
            error_response(
                StatusCode::CONFLICT,
                AtomicLifecycleError::ConflictingTerminalResult { operation_id },
                &[],
            )
        }
    }
}

fn session_rejection_response(rejection: LifecycleSessionRejection) -> Response {
    match rejection {
        LifecycleSessionRejection::WrongSession {
            expected,
            presented,
        } if expected.node_id != presented.node_id => error_response(
            StatusCode::FORBIDDEN,
            AtomicLifecycleError::WrongNode {
                expected_node_id: expected.node_id,
            },
            &[],
        ),
        LifecycleSessionRejection::IdentityNotEligible
        | LifecycleSessionRejection::MissingAgentSession { .. }
        | LifecycleSessionRejection::StaleSession { .. }
        | LifecycleSessionRejection::WrongSession { .. }
        | LifecycleSessionRejection::SessionExpired { .. } => authentication_failed(),
    }
}

fn contract_error_response(error: RuntimeLifecycleContractError, route: Route) -> Response {
    match error {
        RuntimeLifecycleContractError::WireTooLarge => body_limit_response(route),
        RuntimeLifecycleContractError::Malformed
        | RuntimeLifecycleContractError::InvalidContract => error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("request body is invalid"),
            &[],
        ),
        RuntimeLifecycleContractError::NonCanonical => error_response(
            StatusCode::BAD_REQUEST,
            malformed_error("request body must be canonical JSON"),
            &[],
        ),
    }
}

fn body_limit_response(route: Route) -> Response {
    let maximum = u64::try_from(route.request_body_limit()).expect("wire limit fits u64");
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        AtomicLifecycleError::LimitExceeded {
            limit: fixed_ascii("wire_bytes"),
            maximum: WireU64::new(maximum).expect("positive wire limit fits WireU64"),
        },
        &[],
    )
}

fn malformed_error(message: &'static str) -> AtomicLifecycleError {
    AtomicLifecycleError::MalformedPayload {
        json_pointer: fixed_ascii("$"),
        message: fixed_ascii(message),
    }
}

fn fixed_ascii(value: &'static str) -> AsciiText {
    AsciiText::new(value).expect("fixed lifecycle HTTP text satisfies AsciiText")
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

fn transient(error: &cats_api::error::ApiError) -> bool {
    matches!(
        error.code,
        cats_api::error::ErrorCode::Unavailable | cats_api::error::ErrorCode::DeadlineExceeded
    )
}

fn authentication_failed() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        AtomicLifecycleError::AuthenticationFailed,
        &[(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
        )],
    )
}

fn temporarily_unavailable() -> Response {
    opaque_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn error_response(
    status: StatusCode,
    error: AtomicLifecycleError,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let body = encode_atomic_lifecycle_error(&error)
        .expect("fixed lifecycle HTTP error satisfies the closed error contract");
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

fn opaque_response(
    status: StatusCode,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let mut response = (status, Body::empty()).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in extra_headers {
        response.headers_mut().insert(name, value.clone());
    }
    response
}

/// Deliberately produces an incomplete response. A client can only recover by
/// reposting the exact durable terminal result from its local journal.
fn ambiguous_commit_response() -> Response {
    let stream = futures_util::stream::once(async {
        Err::<&'static [u8], io::Error>(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "lifecycle result commit outcome is unknown",
        ))
    });
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .expect("fixed ambiguous lifecycle response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    use cats_api::agent_registration::Ed25519RequestSigner;
    use cats_api::runtime_lifecycle::{
        decode_atomic_lifecycle_error, encode_lifecycle_command_poll_request,
        LifecycleCommandPollRequest,
    };
    use cats_api::runtime_reconciliation::{
        ContractVersion, Epoch, Id, NodeBootId, RandomId128, Sequence, SessionBinding,
    };

    fn signer() -> Ed25519RequestSigner {
        Ed25519RequestSigner::from_pkcs8_pem(
            Id::new("credential_lifecycle_http").unwrap(),
            include_bytes!("../../../tests/fixtures/test_request_private_ed25519.pem"),
        )
        .unwrap()
    }

    fn session(node_id: &str, session_epoch: u64) -> SessionBinding {
        SessionBinding {
            node_id: Id::new(node_id).unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: Epoch::new(session_epoch).unwrap(),
        }
    }

    fn poll_body(node_id: &str, session_epoch: u64) -> Vec<u8> {
        encode_lifecycle_command_poll_request(&LifecycleCommandPollRequest {
            version: ContractVersion::V1,
            session: session(node_id, session_epoch),
            request_sequence: Sequence::new(1).unwrap(),
        })
        .unwrap()
    }

    fn signed_request(route: Route, body: Vec<u8>) -> Request<Body> {
        let proof = signer().sign(LIFECYCLE_INTERNAL_METHOD, route.path(), &body);
        Request::builder()
            .method(LIFECYCLE_INTERNAL_METHOD)
            .uri(route.path())
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(Body::from(body))
            .unwrap()
    }

    async fn decoded_error(response: Response) -> AtomicLifecycleError {
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            JSON_CONTENT_TYPE
        );
        let body = to_bytes(response.into_body(), 16_384).await.unwrap();
        decode_atomic_lifecycle_error(&body).unwrap()
    }

    #[tokio::test]
    async fn exact_signed_canonical_poll_passes_http_and_proof_admission() {
        let prepared = prepare_request(
            signed_request(Route::CommandPoll, poll_body("node_http", 1)),
            Route::CommandPoll,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        match prepared.decoded {
            DecodedRequest::CommandPoll(poll) => {
                assert_eq!(poll.session.node_id.as_str(), "node_http");
                assert_eq!(poll.session.agent_session_epoch.get(), 1);
            }
            DecodedRequest::ResultCommit(_) => panic!("poll decoded as result commit"),
            DecodedRequest::VolumeTransition(_) => panic!("poll decoded as Volume transition"),
        }
    }

    #[tokio::test]
    async fn http_metadata_is_rejected_before_body_authentication() {
        let mut wrong_method = signed_request(Route::CommandPoll, poll_body("node_http", 1));
        *wrong_method.method_mut() = axum::http::Method::GET;
        let response = prepare_request(
            wrong_method,
            Route::CommandPoll,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers().get(header::ALLOW).unwrap(), "POST");

        for (name, value, status) in [
            (
                header::CONTENT_TYPE,
                "application/json; charset=utf-8",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                header::CONTENT_ENCODING,
                "identity",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                header::AUTHORIZATION,
                "Bearer secret",
                StatusCode::BAD_REQUEST,
            ),
            (header::ACCEPT, "*/*", StatusCode::NOT_ACCEPTABLE),
        ] {
            let mut request = signed_request(Route::CommandPoll, poll_body("node_http", 1));
            request
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
            let response = prepare_request(
                request,
                Route::CommandPoll,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap_err();
            assert_eq!(response.status(), status);
            assert!(matches!(
                decoded_error(response).await,
                AtomicLifecycleError::MalformedPayload { .. }
            ));
        }
    }

    #[tokio::test]
    async fn missing_duplicate_or_transplanted_proof_is_one_authentication_failure() {
        let mut requests = Vec::new();

        let mut missing = signed_request(Route::CommandPoll, poll_body("node_http", 1));
        missing.headers_mut().remove(NODE_SIGNATURE_HEADER);
        requests.push(missing);

        let mut duplicate = signed_request(Route::CommandPoll, poll_body("node_http", 1));
        duplicate.headers_mut().append(
            NODE_SIGNATURE_HEADER,
            HeaderValue::from_static("not-a-signature"),
        );
        requests.push(duplicate);

        let transplanted = signed_request(Route::CommandPoll, poll_body("node_http", 1));
        requests.push(
            Request::builder()
                .method(LIFECYCLE_INTERNAL_METHOD)
                .uri(LIFECYCLE_RESULT_COMMIT_PATH)
                .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(
                    NODE_CREDENTIAL_ID_HEADER,
                    transplanted.headers()[NODE_CREDENTIAL_ID_HEADER].clone(),
                )
                .header(
                    NODE_PUBLIC_KEY_SPKI_HEADER,
                    transplanted.headers()[NODE_PUBLIC_KEY_SPKI_HEADER].clone(),
                )
                .header(
                    NODE_SIGNATURE_HEADER,
                    transplanted.headers()[NODE_SIGNATURE_HEADER].clone(),
                )
                .body(Body::from(poll_body("node_http", 1)))
                .unwrap(),
        );

        for (index, request) in requests.into_iter().enumerate() {
            let route = if index == 2 {
                Route::ResultCommit
            } else {
                Route::CommandPoll
            };
            let response = prepare_request(request, route, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                NODE_AUTHENTICATE_CHALLENGE
            );
            assert_eq!(
                decoded_error(response).await,
                AtomicLifecycleError::AuthenticationFailed
            );
        }
    }

    #[tokio::test]
    async fn declared_and_actual_oversize_are_rejected_before_proof_or_decode() {
        let mut declared = Request::builder()
            .method(LIFECYCLE_INTERNAL_METHOD)
            .uri(LIFECYCLE_COMMAND_POLL_PATH)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(
                header::CONTENT_LENGTH,
                (LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES + 1).to_string(),
            )
            .body(Body::from("not signed"))
            .unwrap();
        declared.headers_mut().remove(NODE_SIGNATURE_HEADER);
        let response = prepare_request(
            declared,
            Route::CommandPoll,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(matches!(
            decoded_error(response).await,
            AtomicLifecycleError::LimitExceeded { .. }
        ));

        let actual = Request::builder()
            .method(LIFECYCLE_INTERNAL_METHOD)
            .uri(LIFECYCLE_COMMAND_POLL_PATH)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .body(Body::from(vec![
                b'x';
                LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES + 1
            ]))
            .unwrap();
        let response = prepare_request(
            actual,
            Route::CommandPoll,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn signed_malformed_and_noncanonical_bodies_fail_after_authentication() {
        let malformed = signed_request(Route::CommandPoll, b"{".to_vec());
        let response = prepare_request(
            malformed,
            Route::CommandPoll,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(matches!(
            decoded_error(response).await,
            AtomicLifecycleError::MalformedPayload { .. }
        ));

        let mut noncanonical_body = poll_body("node_http", 1);
        noncanonical_body.push(b'\n');
        let noncanonical = signed_request(Route::CommandPoll, noncanonical_body);
        let response = prepare_request(
            noncanonical,
            Route::CommandPoll,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let AtomicLifecycleError::MalformedPayload { message, .. } = decoded_error(response).await
        else {
            panic!("noncanonical body did not return malformed_payload");
        };
        assert_eq!(message.as_str(), "request body must be canonical JSON");
    }

    #[tokio::test]
    async fn stale_session_and_wrong_node_errors_reveal_no_session_details() {
        let stale = session_rejection_response(LifecycleSessionRejection::StaleSession {
            node_id: Id::new("node_http").unwrap(),
            presented_agent_session_epoch: Epoch::new(1).unwrap(),
            current_agent_session_epoch: Epoch::new(2).unwrap(),
        });
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            decoded_error(stale).await,
            AtomicLifecycleError::AuthenticationFailed
        );

        let wrong = session_rejection_response(LifecycleSessionRejection::WrongSession {
            expected: session("node_expected", 2),
            presented: session("node_other", 2),
        });
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            decoded_error(wrong).await,
            AtomicLifecycleError::WrongNode {
                expected_node_id: Id::new("node_expected").unwrap()
            }
        );
    }

    #[tokio::test]
    async fn ambiguous_commit_response_is_not_a_definite_error_envelope() {
        let response = ambiguous_commit_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert!(to_bytes(response.into_body(), 1).await.is_err());
    }
}

//! Strict signed Node transport for independent per-Endpoint Route commands.

use std::error::Error as _;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use cats_api::agent_registration::{
    verify_request_proof, AuthenticatedNodeCredential, JSON_CONTENT_TYPE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{AsciiText, WireU64};
use cats_api::runtime_route::{
    decode_route_command_poll_request, decode_route_result_commit_request,
    encode_route_command_batch, encode_route_result_stored_ack, encode_runtime_route_error,
    RouteCommandPollRequest, RouteResultCommitRequest, RuntimeRouteContractError,
    RuntimeRouteError, ROUTE_COMMAND_BATCH_MAX_WIRE_BYTES, ROUTE_COMMAND_POLL_MAX_WIRE_BYTES,
    ROUTE_COMMAND_POLL_PATH, ROUTE_INTERNAL_METHOD, ROUTE_RESULT_COMMIT_MAX_WIRE_BYTES,
    ROUTE_RESULT_COMMIT_PATH,
};

use crate::server::AppState;
use crate::store::runtime_authority::lifecycle_commands::LifecycleSessionRejection;
use crate::store::runtime_authority::route_operations::{
    RouteCommandPollOutcome, RouteCommandPollRejection, RouteResultCommitOutcome,
    RouteResultCommitRejection,
};

const HANDLER_DEADLINE: Duration = Duration::from_secs(10);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

#[derive(Debug, Clone, Copy)]
enum Route {
    CommandPoll,
    ResultCommit,
}

impl Route {
    const fn path(self) -> &'static str {
        match self {
            Self::CommandPoll => ROUTE_COMMAND_POLL_PATH,
            Self::ResultCommit => ROUTE_RESULT_COMMIT_PATH,
        }
    }

    const fn body_limit(self) -> usize {
        match self {
            Self::CommandPoll => ROUTE_COMMAND_POLL_MAX_WIRE_BYTES,
            Self::ResultCommit => ROUTE_RESULT_COMMIT_MAX_WIRE_BYTES,
        }
    }
}

enum DecodedRequest {
    CommandPoll(Box<RouteCommandPollRequest>),
    ResultCommit(Box<RouteResultCommitRequest>),
}

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

async fn handle(state: AppState, request: Request<Body>, route: Route) -> Response {
    let deadline = Instant::now() + HANDLER_DEADLINE;
    let prepared = match prepare_request(request, route, deadline).await {
        Ok(prepared) => prepared,
        Err(response) => return response,
    };
    match prepared.decoded {
        DecodedRequest::CommandPoll(poll) => {
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                execute_poll(&state, prepared.authenticated, *poll),
            )
            .await;
            match result {
                Ok(Ok(RouteCommandPollOutcome::Batch(batch))) => {
                    match encode_route_command_batch(&batch) {
                        Ok(body) if body.len() <= ROUTE_COMMAND_BATCH_MAX_WIRE_BYTES => {
                            success_response(body)
                        }
                        _ => internal_response(),
                    }
                }
                Ok(Ok(RouteCommandPollOutcome::Rejected(rejection))) => {
                    poll_rejection_response(rejection)
                }
                Ok(Err(error)) if transient(&error) => temporarily_unavailable(),
                Ok(Err(_)) => internal_response(),
                Err(_) => temporarily_unavailable(),
            }
        }
        DecodedRequest::ResultCommit(commit) => {
            let endpoint_id = commit.response.endpoint_id.clone();
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                execute_commit(&state, prepared.authenticated, *commit),
            )
            .await;
            match result {
                Ok(Ok(RouteResultCommitOutcome::Stored {
                    acknowledgement, ..
                }))
                | Ok(Ok(RouteResultCommitOutcome::ExactReplay {
                    acknowledgement, ..
                })) => match encode_route_result_stored_ack(&acknowledgement) {
                    Ok(body) => success_response(body),
                    Err(_) => ambiguous_commit_response(),
                },
                Ok(Ok(RouteResultCommitOutcome::Superseded { operation })) => error_response(
                    StatusCode::CONFLICT,
                    RuntimeRouteError::SupersededOperation {
                        endpoint_id: operation.endpoint_id,
                        current_operation_id: None,
                    },
                    &[],
                ),
                Ok(Ok(RouteResultCommitOutcome::Rejected(rejection))) => {
                    commit_rejection_response(rejection, endpoint_id)
                }
                // Once the settlement closure starts, neither timeout nor a
                // Store error proves whether COMMIT became durable.
                Ok(Err(_)) | Err(_) => ambiguous_commit_response(),
            }
        }
    }
}

async fn execute_poll(
    state: &AppState,
    authenticated: AuthenticatedNodeCredential,
    poll: RouteCommandPollRequest,
) -> crate::store::Result<RouteCommandPollOutcome> {
    let lane = Arc::clone(&state.route_store);
    lane.execute(move |store| store.poll_route_commands(&authenticated, &poll))
        .await
}

async fn execute_commit(
    state: &AppState,
    authenticated: AuthenticatedNodeCredential,
    commit: RouteResultCommitRequest,
) -> crate::store::Result<RouteResultCommitOutcome> {
    let lane = Arc::clone(&state.route_store);
    lane.execute(move |store| store.commit_route_result(&authenticated, &commit))
        .await
}

async fn prepare_request(
    request: Request<Body>,
    route: Route,
    deadline: Instant,
) -> Result<PreparedRequest, Response> {
    if request.method().as_str() != ROUTE_INTERNAL_METHOD {
        return Err(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            malformed("request method is not allowed"),
            &[(
                header::ALLOW,
                HeaderValue::from_static(ROUTE_INTERNAL_METHOD),
            )],
        ));
    }
    if request.uri().query().is_some() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            malformed("request target is invalid"),
            &[],
        ));
    }
    let headers = request.headers().clone();
    if single_header(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            malformed("request media type is not allowed"),
            &[],
        ));
    }
    if headers.contains_key(header::CONTENT_ENCODING)
        || headers.contains_key(header::AUTHORIZATION)
        || [
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
            malformed("request semantic headers are not allowed"),
            &[],
        ));
    }
    if headers.contains_key(header::ACCEPT)
        && single_header(&headers, header::ACCEPT.as_str()).is_none_or(|value| {
            !value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
        })
    {
        return Err(error_response(
            StatusCode::NOT_ACCEPTABLE,
            malformed("response media type is not allowed"),
            &[],
        ));
    }
    if declared_too_large(&headers, route.body_limit()) {
        return Err(limit_response(route.body_limit()));
    }
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(request.into_body(), route.body_limit()),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return Err(limit_response(route.body_limit()));
        }
        Ok(Err(_)) => return Err(internal_response()),
        Err(_) => return Err(temporarily_unavailable()),
    };
    let authenticated = match (
        single_header(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header(&headers, NODE_SIGNATURE_HEADER),
    ) {
        (Some(credential), Some(spki), Some(signature)) => verify_request_proof(
            ROUTE_INTERNAL_METHOD,
            route.path(),
            &body,
            credential,
            spki,
            signature,
        ),
        _ => Err(cats_api::agent_registration::RequestProofError),
    }
    .map_err(|_| authentication_failed())?;
    let decoded = match route {
        Route::CommandPoll => decode_route_command_poll_request(&body)
            .map(Box::new)
            .map(DecodedRequest::CommandPoll)
            .map_err(|error| contract_error_response(error, route))?,
        Route::ResultCommit => decode_route_result_commit_request(&body)
            .map(Box::new)
            .map(DecodedRequest::ResultCommit)
            .map_err(|error| contract_error_response(error, route))?,
    };
    Ok(PreparedRequest {
        authenticated,
        decoded,
    })
}

fn poll_rejection_response(rejection: RouteCommandPollRejection) -> Response {
    match rejection {
        RouteCommandPollRejection::InvalidContract => error_response(
            StatusCode::BAD_REQUEST,
            malformed("Route poll is invalid"),
            &[],
        ),
        RouteCommandPollRejection::Session(rejection) => session_rejection(rejection),
        RouteCommandPollRejection::RingAcknowledgementConflict => temporarily_unavailable(),
    }
}

fn commit_rejection_response(
    rejection: RouteResultCommitRejection,
    endpoint_id: cats_api::runtime_reconciliation::Id,
) -> Response {
    match rejection {
        RouteResultCommitRejection::InvalidContract => error_response(
            StatusCode::BAD_REQUEST,
            malformed("Route result is invalid"),
            &[],
        ),
        RouteResultCommitRejection::Session(rejection) => session_rejection(rejection),
        RouteResultCommitRejection::OperationNotFound => error_response(
            StatusCode::CONFLICT,
            RuntimeRouteError::StaleOperation {
                endpoint_id,
                current_operation_id: None,
            },
            &[],
        ),
        RouteResultCommitRejection::OperationNotCurrent {
            current_operation_id,
        } => error_response(
            StatusCode::CONFLICT,
            RuntimeRouteError::SupersededOperation {
                endpoint_id,
                current_operation_id,
            },
            &[],
        ),
        RouteResultCommitRejection::ConflictingTerminalResult { operation_id } => error_response(
            StatusCode::CONFLICT,
            RuntimeRouteError::ConflictingTerminalResult { operation_id },
            &[],
        ),
    }
}

fn session_rejection(rejection: LifecycleSessionRejection) -> Response {
    match rejection {
        LifecycleSessionRejection::WrongSession {
            expected,
            presented,
        } if expected.node_id != presented.node_id => error_response(
            StatusCode::FORBIDDEN,
            RuntimeRouteError::WrongNode {
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

fn contract_error_response(error: RuntimeRouteContractError, route: Route) -> Response {
    match error {
        RuntimeRouteContractError::WireTooLarge => limit_response(route.body_limit()),
        RuntimeRouteContractError::Malformed
        | RuntimeRouteContractError::InvalidContract
        | RuntimeRouteContractError::NonCanonical => error_response(
            StatusCode::BAD_REQUEST,
            malformed("request body is invalid or non-canonical"),
            &[],
        ),
    }
}

fn malformed(message: &'static str) -> RuntimeRouteError {
    RuntimeRouteError::MalformedPayload {
        json_pointer: AsciiText::new("$").expect("fixed JSON pointer is ASCII"),
        message: AsciiText::new(message).expect("fixed Route error is ASCII"),
    }
}

fn limit_response(maximum: usize) -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        RuntimeRouteError::LimitExceeded {
            limit: AsciiText::new("wire_bytes").expect("fixed limit name is ASCII"),
            maximum: WireU64::new(u64::try_from(maximum).expect("wire limit fits u64"))
                .expect("wire limit is positive"),
        },
        &[],
    )
}

fn authentication_failed() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        RuntimeRouteError::AuthenticationFailed,
        &[(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
        )],
    )
}

fn temporarily_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RuntimeRouteError::TemporarilyUnavailable,
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn internal_response() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        RuntimeRouteError::Internal,
        &[],
    )
}

fn error_response(
    status: StatusCode,
    error: RuntimeRouteError,
    extra: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let body = encode_runtime_route_error(&error)
        .expect("fixed Route HTTP error satisfies the closed contract");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in extra {
        response.headers_mut().insert(name, value.clone());
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

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    (values.next().is_none())
        .then(|| value.to_str().ok())
        .flatten()
}

fn declared_too_large(headers: &HeaderMap, maximum: usize) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_some()
        || value
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

fn ambiguous_commit_response() -> Response {
    let stream = futures_util::stream::once(async {
        Err::<&'static [u8], io::Error>(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Route result commit outcome is unknown",
        ))
    });
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .expect("fixed ambiguous Route response is valid")
}

//! Strict production-only A22 signed volume transition ingress.

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
#[cfg(feature = "proposed-node-residue-reclamation")]
use cats_api::runtime_reconciliation::{
    decode_runtime_residue_authority_request, encode_runtime_residue_authority_success,
    RuntimeResidueAuthorityRequest, RuntimeResidueAuthoritySuccess, RUNTIME_RESIDUE_AUTHORITY_PATH,
    RUNTIME_RESIDUE_AUTHORITY_REQUEST_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_volume_transition_evidence_request, decode_runtime_volume_transition_request,
    encode_runtime_volume_transition_error, encode_runtime_volume_transition_evidence_success,
    encode_runtime_volume_transition_success, ContractError, ContractErrorDetail, ContractName,
    ContractVersion, JsonPointer, LimitKind, RuntimeVolumeTransitionError,
    RuntimeVolumeTransitionErrorDetail, RuntimeVolumeTransitionEvidenceRequest,
    RuntimeVolumeTransitionHttpProblem, RuntimeVolumeTransitionRequest, WireU64,
    RUNTIME_SPINE_METHOD, RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES,
    RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
    RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_MAX_WIRE_BYTES, RUNTIME_VOLUME_TRANSITION_PATH,
    RUNTIME_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
};

use crate::server::AppState;
use crate::store::runtime_authority::volume_transition_auth::{
    VolumeTransitionStoreOutcome, VolumeTransitionStoreRejection,
};
use crate::store::runtime_authority::volume_transition_evidence::{
    authorization_evidence_unavailable, VolumeTransitionEvidenceLoad,
};
use crate::store::AuthorityRequestContext;

const MUTATION_DEADLINE: Duration = Duration::from_secs(10);
const EVIDENCE_DEADLINE: Duration = Duration::from_secs(5);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

#[derive(Clone, Copy)]
enum Route {
    Mutation,
    Evidence,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    ResidueAuthority,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Self::Mutation => RUNTIME_VOLUME_TRANSITION_PATH,
            Self::Evidence => RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            Self::ResidueAuthority => RUNTIME_RESIDUE_AUTHORITY_PATH,
        }
    }

    fn body_limit(self) -> usize {
        match self {
            Self::Mutation => RUNTIME_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
            Self::Evidence => RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_MAX_WIRE_BYTES,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            Self::ResidueAuthority => RUNTIME_RESIDUE_AUTHORITY_REQUEST_MAX_WIRE_BYTES,
        }
    }

    fn contract(self) -> ContractName {
        match self {
            Self::Mutation => ContractName::RuntimeVolumeTransitionRequest,
            Self::Evidence => ContractName::RuntimeVolumeTransitionEvidenceRequest,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            Self::ResidueAuthority => ContractName::RuntimeResidueAuthorityRequest,
        }
    }

    fn deadline(self) -> Duration {
        match self {
            Self::Mutation => MUTATION_DEADLINE,
            Self::Evidence => EVIDENCE_DEADLINE,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            Self::ResidueAuthority => EVIDENCE_DEADLINE,
        }
    }
}

enum DecodedRequest {
    Mutation(Box<RuntimeVolumeTransitionRequest>),
    Evidence(RuntimeVolumeTransitionEvidenceRequest),
    #[cfg(feature = "proposed-node-residue-reclamation")]
    ResidueAuthority(Box<RuntimeResidueAuthorityRequest>),
}

enum ExecutionOutcome {
    Mutation(
        Box<
            VolumeTransitionStoreOutcome<
                cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess,
            >,
        >,
    ),
    Evidence(VolumeTransitionStoreOutcome<VolumeTransitionEvidenceLoad>),
    #[cfg(feature = "proposed-node-residue-reclamation")]
    ResidueAuthority(VolumeTransitionStoreOutcome<Box<RuntimeResidueAuthoritySuccess>>),
}

enum OwnedExecutionResult {
    Executed(std::result::Result<ExecutionOutcome, cats_api::error::ApiError>),
    IdentityNotEligible,
    NodeRequestInFlight,
    TemporarilyUnavailable,
    Internal,
}

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn mutation(State(state): State<AppState>, request: Request<Body>) -> Response {
    handle(state, request, Route::Mutation).await
}

pub(super) async fn evidence(State(state): State<AppState>, request: Request<Body>) -> Response {
    handle(state, request, Route::Evidence).await
}

#[cfg(feature = "proposed-node-residue-reclamation")]
pub(super) async fn residue_authority(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    handle(state, request, Route::ResidueAuthority).await
}

async fn handle(state: AppState, request: Request<Body>, route: Route) -> Response {
    let route_deadline = route.deadline();
    #[cfg(test)]
    let route_deadline = state
        .runtime_volume_transition_service
        .deadline_for_test(route_deadline);
    let deadline = Instant::now() + route_deadline;
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());

    if request.method().as_str() != RUNTIME_SPINE_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            RuntimeVolumeTransitionErrorDetail::HttpRequestRejected {
                problem: RuntimeVolumeTransitionHttpProblem::MethodNotAllowed,
            },
            "runtime volume transition requires POST",
            &[(
                header::ALLOW,
                HeaderValue::from_static(RUNTIME_SPINE_METHOD),
            )],
        );
    }
    if request.uri().query().is_some() {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeVolumeTransitionHttpProblem::QueryNotAllowed,
            "runtime volume transition does not accept a query",
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
            RuntimeVolumeTransitionHttpProblem::ContentTypeNotAllowed,
            "runtime volume transition requires application/json",
        );
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return http_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RuntimeVolumeTransitionHttpProblem::ContentEncodingNotAllowed,
            "runtime volume transition does not accept Content-Encoding",
        );
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeVolumeTransitionHttpProblem::AuthorizationNotAllowed,
            "runtime volume transition does not accept Authorization",
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
            RuntimeVolumeTransitionHttpProblem::AcceptNotAllowed,
            "runtime volume transition accepts only application/json",
        );
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
        return http_rejection(
            StatusCode::BAD_REQUEST,
            RuntimeVolumeTransitionHttpProblem::SemanticHeaderNotAllowed,
            "runtime volume transition carried a forbidden semantic header",
        );
    }

    let global_permit = match state.runtime_volume_transition_admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    let Some(request_guard) = state
        .runtime_volume_transition_service
        .begin(request_context.clone())
    else {
        return temporarily_unavailable();
    };
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
            return contract_error_response(StatusCode::PAYLOAD_TOO_LARGE, body_limit_error(route));
        }
        Ok(Err(_)) => return internal_response(),
        Err(_) => return closed_response(),
    };

    let authenticated = match (
        single_header_text(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header_text(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header_text(&headers, NODE_SIGNATURE_HEADER),
    ) {
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
        Route::Mutation => match decode_runtime_volume_transition_request(&body) {
            Ok(request) => DecodedRequest::Mutation(Box::new(request)),
            Err(error) => return contract_error_response(decode_status(&error), error),
        },
        Route::Evidence => match decode_runtime_volume_transition_evidence_request(&body) {
            Ok(request) => DecodedRequest::Evidence(request),
            Err(error) => return contract_error_response(decode_status(&error), error),
        },
        #[cfg(feature = "proposed-node-residue-reclamation")]
        Route::ResidueAuthority => match decode_runtime_residue_authority_request(&body) {
            Ok(request) => DecodedRequest::ResidueAuthority(Box::new(request)),
            Err(error) => return contract_error_response(decode_status(&error), error),
        },
    };

    let operation_context = request_context.clone();
    let response_context = request_context.clone();
    let active_guest_digest = state
        .agent_session_registration_policy
        .approved_guest_config_digest()
        .clone();
    let store = state.store.clone();
    let admission = state.runtime_volume_transition_admission.clone();
    #[cfg(test)]
    let test_service = state.runtime_volume_transition_service.clone();
    let (send, mut receive) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _request_guard = request_guard;
        let _global_permit = global_permit;
        let mut node_permit = None;
        #[cfg(test)]
        test_service.pause_before_node_resolution_for_test().await;
        let lookup_credential = authenticated.clone();
        let lookup_context = operation_context.clone();
        let resolved = store
            .execute(move |store| {
                store.resolve_runtime_node_for_request(&lookup_credential, &lookup_context)
            })
            .await;
        let result = match resolved {
            Ok(Some(node_id)) => match admission.try_node(&node_id) {
                Ok(permit) => {
                    node_permit = Some(permit);
                    #[cfg(test)]
                    test_service.pause_after_admission_for_test().await;
                    let store_context = operation_context.clone();
                    OwnedExecutionResult::Executed(
                        store
                            .execute(move |store| match decoded {
                                DecodedRequest::Mutation(request) => store
                                    .runtime_volume_transition(
                                        &authenticated,
                                        &request,
                                        &active_guest_digest,
                                        &store_context,
                                    )
                                    .map(|outcome| ExecutionOutcome::Mutation(Box::new(outcome))),
                                DecodedRequest::Evidence(request) => store
                                    .runtime_volume_transition_evidence_with_context(
                                        &authenticated,
                                        &request,
                                        &active_guest_digest,
                                        &store_context,
                                    )
                                    .map(ExecutionOutcome::Evidence),
                                #[cfg(feature = "proposed-node-residue-reclamation")]
                                DecodedRequest::ResidueAuthority(request) => store
                                    .runtime_residue_authority_with_context(
                                        &authenticated,
                                        &request,
                                        &active_guest_digest,
                                        &store_context,
                                    )
                                    .map(ExecutionOutcome::ResidueAuthority),
                            })
                            .await,
                    )
                }
                Err(_) => OwnedExecutionResult::NodeRequestInFlight,
            },
            Ok(None) => OwnedExecutionResult::IdentityNotEligible,
            Err(error) if transient(&error) => OwnedExecutionResult::TemporarilyUnavailable,
            Err(_) => OwnedExecutionResult::Internal,
        };

        let response = if response_context.is_cancelled_or_expired() {
            closed_response()
        } else {
            #[cfg(test)]
            test_service.pause_response_encoding_for_test().await;
            if response_context.is_cancelled_or_expired() {
                closed_response()
            } else {
                let response = owned_execution_response(result, &response_context);
                if response_context.is_cancelled_or_expired() {
                    closed_response()
                } else {
                    response
                }
            }
        };
        let _node_permit = node_permit;
        let _ = send.send(response);
    });

    let response =
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut receive).await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return closed_response(),
            Err(_) => {
                request_context.cancel();
                let _ = receive.await;
                return closed_response();
            }
        };
    if request_context.is_cancelled_or_expired() {
        closed_response()
    } else {
        response
    }
}

fn owned_execution_response(
    result: OwnedExecutionResult,
    response_context: &AuthorityRequestContext,
) -> Response {
    match result {
        OwnedExecutionResult::Executed(Ok(ExecutionOutcome::Mutation(outcome))) => match *outcome {
            VolumeTransitionStoreOutcome::Accepted(success) => {
                match encode_runtime_volume_transition_success(&success) {
                    Ok(body) => success_response(body),
                    Err(_) => internal_response(),
                }
            }
            VolumeTransitionStoreOutcome::Rejected(rejection) => rejection_response(rejection),
        },
        OwnedExecutionResult::Executed(Ok(ExecutionOutcome::Evidence(
            VolumeTransitionStoreOutcome::Accepted(VolumeTransitionEvidenceLoad::Available(
                success,
            )),
        ))) => match encode_runtime_volume_transition_evidence_success(&success) {
            Ok(body) => success_response(body),
            Err(_) => internal_response(),
        },
        OwnedExecutionResult::Executed(Ok(ExecutionOutcome::Evidence(
            VolumeTransitionStoreOutcome::Accepted(VolumeTransitionEvidenceLoad::Unavailable {
                authorization_id,
            }),
        ))) => encoded_error_response(
            StatusCode::NOT_FOUND,
            authorization_evidence_unavailable(authorization_id),
            &[],
        ),
        OwnedExecutionResult::Executed(Ok(ExecutionOutcome::Evidence(
            VolumeTransitionStoreOutcome::Rejected(rejection),
        ))) => rejection_response(rejection),
        #[cfg(feature = "proposed-node-residue-reclamation")]
        OwnedExecutionResult::Executed(Ok(ExecutionOutcome::ResidueAuthority(
            VolumeTransitionStoreOutcome::Accepted(success),
        ))) => match encode_runtime_residue_authority_success(&success) {
            Ok(body) => success_response(body),
            Err(_) => internal_response(),
        },
        #[cfg(feature = "proposed-node-residue-reclamation")]
        OwnedExecutionResult::Executed(Ok(ExecutionOutcome::ResidueAuthority(
            VolumeTransitionStoreOutcome::Rejected(rejection),
        ))) => rejection_response(rejection),
        OwnedExecutionResult::Executed(Err(_)) if response_context.commit_was_attempted() => {
            closed_response()
        }
        OwnedExecutionResult::Executed(Err(error)) if transient(&error) => {
            temporarily_unavailable()
        }
        OwnedExecutionResult::Executed(Err(_)) | OwnedExecutionResult::Internal => {
            internal_response()
        }
        OwnedExecutionResult::IdentityNotEligible => identity_not_eligible(),
        OwnedExecutionResult::NodeRequestInFlight => node_request_in_flight(),
        OwnedExecutionResult::TemporarilyUnavailable => temporarily_unavailable(),
    }
}

fn rejection_response(rejection: VolumeTransitionStoreRejection) -> Response {
    match rejection {
        VolumeTransitionStoreRejection::IdentityNotEligible => identity_not_eligible(),
        VolumeTransitionStoreRejection::Contract(error) => {
            contract_error_response(StatusCode::CONFLICT, error)
        }
        VolumeTransitionStoreRejection::TransitionPreconditionFailed { cat_id, problem } => {
            error_response(
                StatusCode::CONFLICT,
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id,
                    problem,
                },
                match problem {
                    cats_api::runtime_reconciliation::RuntimeVolumeTransitionPreconditionProblem::InventorySessionReplaced => "complete inventory belongs to a replaced session",
                    cats_api::runtime_reconciliation::RuntimeVolumeTransitionPreconditionProblem::InventoryStale => "complete inventory is stale",
                    cats_api::runtime_reconciliation::RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch => "volume intent does not match current Desired",
                    cats_api::runtime_reconciliation::RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch => "cleanup evidence does not match current physical state",
                    cats_api::runtime_reconciliation::RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict => "another volume authorization branch has committed",
                },
                &[],
            )
        }
        VolumeTransitionStoreRejection::VolumeAuthorityRejected { volume_id, reason } => {
            error_response(
                StatusCode::CONFLICT,
                RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected { volume_id, reason },
                "volume authority rejected the transition",
                &[],
            )
        }
        VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
            authorization_id,
            reason,
        } => error_response(
            StatusCode::CONFLICT,
            RuntimeVolumeTransitionErrorDetail::VolumeAuthorizationRejected {
                authorization_id,
                reason,
            },
            "volume authorization rejected the transition",
            &[],
        ),
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

fn body_limit_error(route: Route) -> ContractError {
    let maximum = route.body_limit() as u64;
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::LimitExceeded {
            contract: route.contract(),
            json_pointer: JsonPointer::new(String::new()).expect("empty JSON pointer is valid"),
            limit: LimitKind::WireBytes,
            maximum: WireU64::new(maximum).expect("A22 body limit fits U64"),
            observed_at_least: WireU64::new(maximum + 1).expect("A22 limit plus one fits U64"),
        }),
        message: "runtime volume transition contract limit exceeded".to_owned(),
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

fn transient(error: &cats_api::error::ApiError) -> bool {
    matches!(
        error.code,
        ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
    )
}

fn authentication_failed() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        RuntimeVolumeTransitionErrorDetail::AuthenticationFailed,
        "runtime volume transition authentication failed",
        &[(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
        )],
    )
}

fn identity_not_eligible() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        RuntimeVolumeTransitionErrorDetail::IdentityNotEligible,
        "runtime volume transition identity is not eligible",
        &[],
    )
}

fn http_rejection(
    status: StatusCode,
    problem: RuntimeVolumeTransitionHttpProblem,
    message: &'static str,
) -> Response {
    error_response(
        status,
        RuntimeVolumeTransitionErrorDetail::HttpRequestRejected { problem },
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
        RuntimeVolumeTransitionErrorDetail::ContractError {
            contract_error: error,
        },
        "runtime volume transition contract was rejected",
        &[],
    )
}

fn node_request_in_flight() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight,
        "another volume transition request for this Node is in flight",
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn temporarily_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable,
        "runtime volume transition service is temporarily unavailable",
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn internal_response() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        RuntimeVolumeTransitionErrorDetail::Internal,
        "runtime volume transition service failed internally",
        &[],
    )
}

fn closed_response() -> Response {
    let stream = futures_util::stream::once(async {
        Err::<&'static [u8], io::Error>(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "runtime volume transition response is intentionally closed",
        ))
    });
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from_stream(stream))
        .expect("fixed ambiguous response is valid")
}

fn encoded_error_response(
    status: StatusCode,
    envelope: RuntimeVolumeTransitionError,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let body = encode_runtime_volume_transition_error(&envelope)
        .expect("A22 typed error satisfies its closed wire contract");
    debug_assert!(body.len() <= RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES);
    json_response(status, body, extra_headers)
}

fn error_response(
    status: StatusCode,
    detail: RuntimeVolumeTransitionErrorDetail,
    message: &'static str,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    encoded_error_response(
        status,
        RuntimeVolumeTransitionError {
            version: ContractVersion::V1,
            error: Box::new(detail),
            message: message.to_owned(),
        },
        extra_headers,
    )
}

fn success_response(body: Vec<u8>) -> Response {
    json_response(StatusCode::OK, body, &[])
}

fn json_response(
    status: StatusCode,
    body: Vec<u8>,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cats_api::agent_registration::{Ed25519RequestSigner, REGISTRATION_PATH};
    use cats_api::runtime_reconciliation::{
        decode_agent_session, decode_runtime_volume_transition_error,
        decode_runtime_volume_transition_evidence_success,
        decode_runtime_volume_transition_success, encode_agent_registration_attempt,
        encode_runtime_volume_transition_evidence_request,
        encode_runtime_volume_transition_request, guest_config_digest, AgentRegistrationAttempt,
        ContractVersion, CredentialBinding, Id, NodeBootId, NodeIdentity, NodeIdentityState,
        RandomId128, RuntimeVolumeTransition, RuntimeVolumeTransitionErrorDetail,
        RuntimeVolumeTransitionEvidenceRequest, SessionBinding, VolumeAcquireRequest,
    };
    use cats_metadata_store_sqlite::SqliteMetadataStore;
    use cats_metering::SqliteUsageStore;
    use cats_storage::MetadataStore;

    use super::*;
    use crate::controller::AutoTierPolicy;
    use crate::server::{spawn, spawn_for_retired_product_tests, Config, Handle};
    use crate::store::DsnSource;

    const SERVICE_TOKEN: &str = "a22-http-service-token";
    const ADMIN_TOKEN: &str = "a22-http-admin-token";

    struct TestNode {
        signer: Ed25519RequestSigner,
        session: cats_api::runtime_reconciliation::AgentSession,
    }

    impl TestNode {
        fn binding(&self) -> SessionBinding {
            SessionBinding {
                node_id: self.session.node_id.clone(),
                node_boot_id: self.session.node_boot_id.clone(),
                agent_instance_id: self.session.agent_instance_id.clone(),
                agent_session_epoch: self.session.agent_session_epoch,
            }
        }

        fn authenticated(&self) -> cats_api::agent_registration::AuthenticatedNodeCredential {
            cats_api::agent_registration::AuthenticatedNodeCredential::new(
                self.signer.credential_id().clone(),
                CredentialBinding::PublicKey {
                    public_key_spki_sha256: self.signer.public_key_spki_sha256(),
                },
            )
        }
    }

    struct Context {
        _dir: tempfile::TempDir,
        server: Handle,
        client: reqwest::Client,
        active_guest_config_digest: cats_api::runtime_reconciliation::Sha256Digest,
    }

    impl Context {
        async fn new() -> Self {
            Self::new_with_retired_product_authority(false).await
        }

        async fn new_with_retired_product_authority(retired: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
            let storage_meta: Arc<dyn MetadataStore> =
                Arc::new(SqliteMetadataStore::open(&dir.path().join("storage.db")).unwrap());
            let receipt = crate::testsupport::test_guest_runtime_profile_receipt();
            let config = Config {
                listen: "127.0.0.1:0".into(),
                control_store_dsn: DsnSource::Literal(
                    crate::testsupport::isolated_control_store_url(),
                ),
                control_store_ca_file: None,
                usage_store: usage.clone(),
                credit_store: usage,
                retired_storage_meta_for_tests: retired.then_some(storage_meta),
                image_blob: crate::testsupport::unavailable_image_blob(),
                auth_token: SERVICE_TOKEN.into(),
                guest_runtime_profile_receipt: receipt.clone(),
                runtime_provisioner_trust_bundle:
                    crate::testsupport::test_runtime_provisioner_trust_bundle(),
                route_grant_signer: crate::testsupport::route_grant_signer(),
                admin_token: ADMIN_TOKEN.into(),
                workos: None,
                stripe: None,
                billing_enforcement_enabled: false,
                node_lease_timeout_ms: 30_000,
                reconcile_interval_ms: 60_000,
                auto_tier_policy: AutoTierPolicy::default(),
                oci_deploy_sync_wait_ms: 5_000,
            };
            let server = if retired {
                spawn_for_retired_product_tests(config).await.unwrap()
            } else {
                spawn(config).await.unwrap()
            };
            Self {
                _dir: dir,
                server,
                client: reqwest::Client::new(),
                active_guest_config_digest: guest_config_digest(&receipt).unwrap(),
            }
        }

        async fn register(&self, suffix: &str, digit: char) -> TestNode {
            let mut private_key = vec![
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ];
            private_key.extend(std::iter::repeat_n(digit as u8, 32));
            let signer = Ed25519RequestSigner::from_pkcs8_der(
                Id::new(format!("credential-a22-{suffix}")).unwrap(),
                &private_key,
            )
            .unwrap();
            let identity = NodeIdentity {
                version: ContractVersion::V1,
                node_id: Id::new(format!("node-a22-{suffix}")).unwrap(),
                immutable_host_id: Id::new(format!("host-a22-{suffix}")).unwrap(),
                credential_id: signer.credential_id().clone(),
                credential_binding: CredentialBinding::PublicKey {
                    public_key_spki_sha256: signer.public_key_spki_sha256(),
                },
                state_path_id: Id::new(format!("state-a22-{suffix}")).unwrap(),
                state: NodeIdentityState::Provisioned,
            };
            crate::testsupport::provision_node_identity(&self.server.state.store, identity.clone())
                .await;
            let value = digit.to_string().repeat(32);
            let attempt = AgentRegistrationAttempt {
                version: ContractVersion::V1,
                node_id: identity.node_id,
                immutable_host_id: identity.immutable_host_id,
                node_boot_id: NodeBootId::new(value.clone()).unwrap(),
                agent_instance_id: RandomId128::new(value.clone()).unwrap(),
                registration_attempt_id: RandomId128::new(value).unwrap(),
                guest_config_digest: self.active_guest_config_digest.clone(),
                expected_agent_session_epoch: None,
            };
            let body = encode_agent_registration_attempt(&attempt).unwrap();
            let response = self
                .signed_with(&signer, REGISTRATION_PATH, body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            TestNode {
                signer,
                session: decode_agent_session(&response.bytes().await.unwrap()).unwrap(),
            }
        }

        fn signed_with(
            &self,
            signer: &Ed25519RequestSigner,
            path: &str,
            body: Vec<u8>,
        ) -> reqwest::RequestBuilder {
            self.signed_with_client(&self.client, signer, path, body)
        }

        fn signed_with_client(
            &self,
            client: &reqwest::Client,
            signer: &Ed25519RequestSigner,
            path: &str,
            body: Vec<u8>,
        ) -> reqwest::RequestBuilder {
            let proof = signer.sign(RUNTIME_SPINE_METHOD, path, &body);
            client
                .post(format!("{}{path}", self.server.base_url()))
                .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
                .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
                .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
                .header(NODE_SIGNATURE_HEADER, proof.signature)
                .body(body)
        }

        fn signed(&self, node: &TestNode, path: &str, body: Vec<u8>) -> reqwest::RequestBuilder {
            self.signed_with(&node.signer, path, body)
        }
    }

    fn evidence_body(node: &TestNode) -> Vec<u8> {
        encode_runtime_volume_transition_evidence_request(&RuntimeVolumeTransitionEvidenceRequest {
            version: ContractVersion::V1,
            session: node.binding(),
            authorization_id: Id::new("missing-a22-authorization").unwrap(),
        })
        .unwrap()
    }

    async fn assert_connection_closed(result: reqwest::Result<reqwest::Response>) {
        if let Ok(response) = result {
            assert!(
                response.bytes().await.is_err(),
                "a closed A22 response unexpectedly carried a typed body"
            );
        }
    }

    async fn wait_for_no_active_requests(service: &crate::server::RuntimeVolumeTransitionService) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while service.active_for_test() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("A22 service retained a completed request");
    }

    #[tokio::test]
    async fn node_resolution_deadline_closes_and_joins_the_owned_request() {
        let context = Context::new().await;
        let node = context.register("resolve-deadline", '4').await;
        let service = context
            .server
            .state
            .runtime_volume_transition_service
            .clone();
        service.set_deadline_override_for_test(Duration::from_millis(150));
        service.arm_pause_before_node_resolution_for_test();
        let request = tokio::spawn(
            context
                .signed(
                    &node,
                    RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
                    evidence_body(&node),
                )
                .send(),
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            service.wait_for_paused_node_resolution_for_test(),
        )
        .await
        .expect("A22 resolver did not enter its owned pause");
        assert_eq!(service.active_for_test(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;
        service.release_paused_node_resolution_for_test();
        assert_connection_closed(
            tokio::time::timeout(Duration::from_secs(3), request)
                .await
                .expect("deadline-bound A22 resolver did not join")
                .unwrap(),
        )
        .await;
        service.clear_deadline_override_for_test();
        wait_for_no_active_requests(&service).await;
    }

    #[tokio::test]
    async fn client_drop_and_shutdown_cancel_and_join_paused_node_resolution() {
        let context = Context::new().await;
        let node = context.register("resolve-shutdown", '5').await;
        let service = context
            .server
            .state
            .runtime_volume_transition_service
            .clone();
        service.arm_pause_before_node_resolution_for_test();
        let request = tokio::spawn(
            context
                .signed(
                    &node,
                    RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
                    evidence_body(&node),
                )
                .send(),
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            service.wait_for_paused_node_resolution_for_test(),
        )
        .await
        .expect("A22 resolver did not enter its owned pause");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(service.active_for_test(), 1);

        let shutdown = context.server.shutdown();
        tokio::pin!(shutdown);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned before the owned resolver joined"
        );
        service.release_paused_node_resolution_for_test();
        tokio::time::timeout(Duration::from_secs(5), &mut shutdown)
            .await
            .expect("shutdown did not join the released A22 resolver")
            .unwrap();
        assert_eq!(service.active_for_test(), 0);
    }

    #[tokio::test]
    async fn response_encoding_holds_service_and_permits_and_never_answers_after_deadline() {
        let context = Context::new().await;
        let node = context.register("encode-deadline", '6').await;
        let authenticated = node.authenticated();
        let session = node.binding();
        let digest = context.active_guest_config_digest.clone();
        let transition = context
            .server
            .state
            .store
            .execute(move |store| {
                Ok(
                    crate::store::runtime_authority::tests::prepare_a22_http_normal_fixture(
                        store,
                        authenticated,
                        session,
                        digest,
                    ),
                )
            })
            .await
            .unwrap();
        let body = encode_runtime_volume_transition_request(&transition).unwrap();
        let service = context
            .server
            .state
            .runtime_volume_transition_service
            .clone();
        let admission = context
            .server
            .state
            .runtime_volume_transition_admission
            .clone();
        let global_before = admission.available_global_permits_for_test();
        service.set_deadline_override_for_test(Duration::from_secs(1));
        service.arm_pause_response_encoding_for_test();
        let request = tokio::spawn(
            context
                .signed(&node, RUNTIME_VOLUME_TRANSITION_PATH, body.clone())
                .send(),
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            service.wait_for_paused_response_encoding_for_test(),
        )
        .await
        .expect("A22 response encoder did not enter its owned pause");
        assert_eq!(service.active_for_test(), 1);
        assert_eq!(
            admission.available_global_permits_for_test(),
            global_before - 1
        );
        assert!(
            admission.try_node(&node.session.node_id).is_err(),
            "per-Node admission was released before response encoding"
        );

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        service.release_paused_response_encoding_for_test();
        assert_connection_closed(
            tokio::time::timeout(Duration::from_secs(3), request)
                .await
                .expect("deadline-bound A22 encoder did not join")
                .unwrap(),
        )
        .await;
        service.clear_deadline_override_for_test();
        wait_for_no_active_requests(&service).await;
        assert_eq!(admission.available_global_permits_for_test(), global_before);

        let replay = context
            .signed(&node, RUNTIME_VOLUME_TRANSITION_PATH, body)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        decode_runtime_volume_transition_success(&replay.bytes().await.unwrap()).unwrap();
    }

    #[tokio::test]
    async fn committed_response_loss_holds_per_node_admission_and_exact_http_retry_recovers() {
        let context = Context::new().await;
        let node = context.register("normal", '1').await;
        let authenticated = node.authenticated();
        let session = node.binding();
        let digest = context.active_guest_config_digest.clone();
        let request = context
            .server
            .state
            .store
            .execute(move |store| {
                Ok(
                    crate::store::runtime_authority::tests::prepare_a22_http_normal_fixture(
                        store,
                        authenticated,
                        session,
                        digest,
                    ),
                )
            })
            .await
            .unwrap();
        let RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Normal { volume_id, .. },
        } = &request.transition
        else {
            panic!("A22 HTTP fixture must be one normal acquire")
        };
        let volume_id = volume_id.clone();
        let body = encode_runtime_volume_transition_request(&request).unwrap();
        context
            .server
            .state
            .runtime_volume_transition_service
            .arm_pause_after_admission_for_test();
        let first = tokio::spawn(
            context
                .signed(&node, RUNTIME_VOLUME_TRANSITION_PATH, body.clone())
                .send(),
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            context
                .server
                .state
                .runtime_volume_transition_service
                .wait_for_paused_admission_for_test(),
        )
        .await
        .expect("the first request did not acquire its per-Node permit");

        let concurrent_client = reqwest::Client::new();
        let concurrent = context
            .signed_with_client(
                &concurrent_client,
                &node.signer,
                RUNTIME_VOLUME_TRANSITION_PATH,
                body.clone(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(concurrent.status(), StatusCode::TOO_MANY_REQUESTS);
        let concurrent =
            decode_runtime_volume_transition_error(&concurrent.bytes().await.unwrap()).unwrap();
        assert!(matches!(
            concurrent.error.as_ref(),
            RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight
        ));

        context
            .server
            .state
            .store
            .inject_request_committed_response_loss_once_after(Duration::ZERO);
        context
            .server
            .state
            .runtime_volume_transition_service
            .release_paused_admission_for_test();
        let incomplete = first.await.unwrap();
        assert!(
            incomplete.is_err(),
            "an ambiguous commit must not become a typed HTTP response"
        );
        let committed_volume_id = volume_id.clone();
        let committed = context
            .server
            .state
            .store
            .execute(move |store| {
                Ok(
                    crate::store::runtime_authority::tests::stored_volume_for_a22_http_test(
                        store,
                        &committed_volume_id,
                    ),
                )
            })
            .await
            .unwrap();
        assert_eq!(committed.lease_epoch.get(), 8);
        assert!(committed.last_transition.is_some());
        let replay = context
            .signed(&node, RUNTIME_VOLUME_TRANSITION_PATH, body)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let success =
            decode_runtime_volume_transition_success(&replay.bytes().await.unwrap()).unwrap();
        assert_eq!(success.session, request.session);
        assert_eq!(success.cat_id, request.cat_id);
        let replay_volume = context
            .server
            .state
            .store
            .execute(move |store| {
                Ok(
                    crate::store::runtime_authority::tests::stored_volume_for_a22_http_test(
                        store, &volume_id,
                    ),
                )
            })
            .await
            .unwrap();
        assert_eq!(replay_volume, committed);
    }

    #[tokio::test]
    async fn evidence_http_hides_an_existing_authorization_from_the_wrong_node() {
        let context = Context::new().await;
        let authorized = context.register("authorized", '2').await;
        let authenticated = authorized.authenticated();
        let session = authorized.binding();
        let digest = context.active_guest_config_digest.clone();
        context
            .server
            .state
            .store
            .execute(move |store| {
                Ok(
                    crate::store::runtime_authority::tests::prepare_a22_http_takeover_fixture(
                        store,
                        authenticated,
                        session,
                        digest,
                    ),
                )
            })
            .await
            .unwrap();

        let authorized_request = RuntimeVolumeTransitionEvidenceRequest {
            version: ContractVersion::V1,
            session: authorized.binding(),
            authorization_id: Id::new("takeover-auth-1").unwrap(),
        };
        let response = context
            .signed(
                &authorized,
                RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
                encode_runtime_volume_transition_evidence_request(&authorized_request).unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let success =
            decode_runtime_volume_transition_evidence_success(&response.bytes().await.unwrap())
                .unwrap();
        assert_eq!(
            success.authorization_id,
            authorized_request.authorization_id
        );

        let wrong = context.register("wrong", '3').await;
        let wrong_request = RuntimeVolumeTransitionEvidenceRequest {
            version: ContractVersion::V1,
            session: wrong.binding(),
            authorization_id: Id::new("takeover-auth-1").unwrap(),
        };
        let response = context
            .signed(
                &wrong,
                RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
                encode_runtime_volume_transition_evidence_request(&wrong_request).unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let error =
            decode_runtime_volume_transition_error(&response.bytes().await.unwrap()).unwrap();
        assert!(matches!(
            error.error.as_ref(),
            RuntimeVolumeTransitionErrorDetail::AuthorizationEvidenceUnavailable {
                authorization_id
            } if authorization_id == &wrong_request.authorization_id
        ));
    }

    #[tokio::test]
    async fn production_router_installs_the_residue_authority_route_by_default() {
        let context = Context::new().await;
        let node = context.register("residue", '7').await;
        let response = context
            .signed(
                &node,
                "/v1/internal/runtime/residue-authority",
                b"{}".to_vec(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error =
            decode_runtime_volume_transition_error(&response.bytes().await.unwrap()).unwrap();
        assert!(matches!(
            error.error.as_ref(),
            RuntimeVolumeTransitionErrorDetail::ContractError { .. }
        ));
    }

    #[tokio::test]
    async fn retired_product_test_composition_does_not_register_a22_routes() {
        let context = Context::new_with_retired_product_authority(true).await;
        let response = context
            .client
            .post(format!(
                "{}{}",
                context.server.base_url(),
                RUNTIME_VOLUME_TRANSITION_PATH
            ))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(decode_runtime_volume_transition_error(&response.bytes().await.unwrap()).is_err());
    }
}

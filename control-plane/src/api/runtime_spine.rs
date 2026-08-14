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
        Err(_) => return temporarily_unavailable(),
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
        Ok(Ok(Ok(EncodedOutcome::Rejected(rejection)))) => rejection_response(rejection),
        Ok(_) if response_context.commit_was_attempted() => ambiguous_commit_response(),
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
    use std::sync::Arc;

    use cats_api::agent_registration::{Ed25519RequestSigner, REGISTRATION_PATH};
    use cats_api::runtime_reconciliation::{
        decode_agent_session, decode_desired_read_snapshot, decode_runtime_spine_error,
        encode_agent_registration_attempt, encode_desired_read_request, encode_node_observation,
        guest_config_digest, inventory_digest, AgentRegistrationAttempt, ContractErrorDetail,
        ContractVersion, CredentialBinding, DesiredReadRequest, Epoch, Id, NodeBootId,
        NodeIdentity, NodeIdentityState, NodeObservation, RandomId128, Sequence, SessionBinding,
        UnixMillis,
    };
    use cats_metering::SqliteUsageStore;

    use super::*;
    use crate::controller::AutoTierPolicy;
    use crate::server::{spawn, Config, Handle};
    use crate::store::DsnSource;

    const SERVICE_TOKEN: &str = "runtime-spine-phase-service-token";
    const ADMIN_TOKEN: &str = "runtime-spine-phase-admin-token";

    struct Context {
        _dir: tempfile::TempDir,
        server: Handle,
        client: reqwest::Client,
        signer: Ed25519RequestSigner,
        session: cats_api::runtime_reconciliation::AgentSession,
    }

    impl Context {
        async fn new(suffix: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
            let receipt = crate::testsupport::test_guest_runtime_profile_receipt();
            let server = spawn(Config {
                listen: "127.0.0.1:0".into(),
                control_store_dsn: DsnSource::Literal(
                    crate::testsupport::isolated_control_store_url(),
                ),
                control_store_ca_file: None,
                usage_store: usage.clone(),
                credit_store: usage,
                #[cfg(debug_assertions)]
                retired_storage_meta_for_tests: None,
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
            })
            .await
            .unwrap();
            let signer = Ed25519RequestSigner::from_pkcs8_pem(
                Id::new(format!("credential_phase_{suffix}")).unwrap(),
                include_bytes!("../../../tests/fixtures/route_grant_private_ed25519.pem"),
            )
            .unwrap();
            let identity = NodeIdentity {
                version: ContractVersion::V1,
                node_id: Id::new(format!("node_phase_{suffix}")).unwrap(),
                provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                    provider: Id::new("test_provider").unwrap(),
                    partition: Id::new("test_partition").unwrap(),
                    account_id: Id::new("test_account").unwrap(),
                    region: Id::new("test_region").unwrap(),
                },
                immutable_host_id: Id::new(format!("host_phase_{suffix}")).unwrap(),
                credential_id: signer.credential_id().clone(),
                credential_binding: CredentialBinding::PublicKey {
                    public_key_spki_sha256: signer.public_key_spki_sha256(),
                },
                state_path_id: Id::new(format!("state_phase_{suffix}")).unwrap(),
                state: NodeIdentityState::Provisioned,
            };
            crate::testsupport::provision_node_identity(&server.state.store, identity.clone())
                .await;
            let attempt = AgentRegistrationAttempt {
                version: ContractVersion::V1,
                node_id: identity.node_id,
                immutable_host_id: identity.immutable_host_id,
                node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
                agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
                registration_attempt_id: RandomId128::new("33333333333333333333333333333333")
                    .unwrap(),
                guest_config_digest: guest_config_digest(&receipt).unwrap(),
                expected_agent_session_epoch: None,
            };
            let body = encode_agent_registration_attempt(&attempt).unwrap();
            let response = Self::signed_with(
                &reqwest::Client::new(),
                &signer,
                &server,
                REGISTRATION_PATH,
                body,
            )
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let session = decode_agent_session(&response.bytes().await.unwrap()).unwrap();
            Self {
                _dir: dir,
                server,
                client: reqwest::Client::new(),
                signer,
                session,
            }
        }

        fn signed_with(
            client: &reqwest::Client,
            signer: &Ed25519RequestSigner,
            server: &Handle,
            path: &str,
            body: Vec<u8>,
        ) -> reqwest::RequestBuilder {
            let proof = signer.sign("POST", path, &body);
            client
                .post(format!("{}{path}", server.base_url()))
                .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
                .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
                .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
                .header(NODE_SIGNATURE_HEADER, proof.signature)
                .body(body)
        }

        fn signed(&self, path: &str, body: Vec<u8>) -> reqwest::RequestBuilder {
            Self::signed_with(&self.client, &self.signer, &self.server, path, body)
        }

        fn binding(&self) -> SessionBinding {
            SessionBinding {
                node_id: self.session.node_id.clone(),
                node_boot_id: self.session.node_boot_id.clone(),
                agent_instance_id: self.session.agent_instance_id.clone(),
                agent_session_epoch: self.session.agent_session_epoch,
            }
        }

        fn full_observation(&self, read_position: Sequence) -> NodeObservation {
            let mut observation = NodeObservation {
                version: ContractVersion::V1,
                observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
                node_id: self.session.node_id.clone(),
                node_boot_id: self.session.node_boot_id.clone(),
                agent_instance_id: self.session.agent_instance_id.clone(),
                agent_session_epoch: self.session.agent_session_epoch,
                heartbeat_sequence: Sequence::new(1).unwrap(),
                observed_at_unix_ms: UnixMillis::new(1).unwrap(),
                complete_inventory: true,
                inventory_epoch: Epoch::new(1).unwrap(),
                inventory_digest: None,
                inventory_read_position: Some(read_position),
                key_ring_version: None,
                key_ring_digest: None,
                loaded_kids: Vec::new(),
                runtimes: Vec::new(),
                residue: Vec::new(),
            };
            observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
            observation
        }

        async fn fingerprint(&self) -> String {
            crate::testsupport::runtime_spine_state_fingerprint(
                &self.server.state.store,
                self.session.node_id.clone(),
            )
            .await
        }

        fn arm_commit_response_loss_after(&self, delay: Duration) {
            self.server
                .state
                .store
                .inject_request_committed_response_loss_once_after(delay);
        }

        fn arm_delayed_commit_response_loss(&self) {
            self.arm_commit_response_loss_after(Duration::from_secs(11));
        }

        fn assert_commit_response_loss_remains_armed(&self) {
            assert!(
                self.server
                    .state
                    .store
                    .request_committed_response_loss_is_armed(),
                "a definite rejection must not enter COMMIT or consume response-loss injection"
            );
        }
    }

    async fn promptly(request: reqwest::RequestBuilder) -> reqwest::Response {
        tokio::time::timeout(Duration::from_secs(2), request.send())
            .await
            .expect("a definite rejection entered the commit/deadline path")
            .unwrap()
    }

    async fn decoded_error(response: reqwest::Response) -> RuntimeSpineError {
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            JSON_CONTENT_TYPE
        );
        decode_runtime_spine_error(&response.bytes().await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn ambiguous_commit_response_cannot_be_mistaken_for_an_http_error_envelope() {
        let response = ambiguous_commit_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert!(to_bytes(response.into_body(), 1).await.is_err());
    }

    #[tokio::test]
    async fn definite_runtime_rejections_rollback_before_commit_and_keep_exact_http_errors() {
        let wrong = Context::new("wrong").await;
        let mut wrong_binding = wrong.binding();
        wrong_binding.agent_instance_id =
            RandomId128::new("99999999999999999999999999999999").unwrap();
        let request = DesiredReadRequest {
            version: ContractVersion::V1,
            session: wrong_binding,
            request_sequence: Sequence::new(1).unwrap(),
        };
        let before = wrong.fingerprint().await;
        wrong.arm_delayed_commit_response_loss();
        let response = promptly(wrong.signed(
            DESIRED_READ_PATH,
            encode_desired_read_request(&request).unwrap(),
        ))
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(matches!(
            decoded_error(response).await.error.as_ref(),
            RuntimeSpineErrorDetail::ContractError { contract_error }
                if matches!(contract_error.error.as_ref(), ContractErrorDetail::WrongSession { .. })
        ));
        assert_eq!(wrong.fingerprint().await, before);
        wrong.assert_commit_response_loss_remains_armed();

        let expired = Context::new("expired").await;
        crate::testsupport::expire_agent_session_for_test(
            &expired.server.state.store,
            expired.session.node_id.clone(),
        )
        .await;
        let request = DesiredReadRequest {
            version: ContractVersion::V1,
            session: expired.binding(),
            request_sequence: Sequence::new(1).unwrap(),
        };
        let before = expired.fingerprint().await;
        expired.arm_delayed_commit_response_loss();
        let response = promptly(expired.signed(
            DESIRED_READ_PATH,
            encode_desired_read_request(&request).unwrap(),
        ))
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(matches!(
            decoded_error(response).await.error.as_ref(),
            RuntimeSpineErrorDetail::ContractError { contract_error }
                if matches!(contract_error.error.as_ref(), ContractErrorDetail::SessionExpired { .. })
        ));
        assert_eq!(expired.fingerprint().await, before);
        expired.assert_commit_response_loss_remains_armed();

        let changed = Context::new("changed").await;
        let desired = DesiredReadRequest {
            version: ContractVersion::V1,
            session: changed.binding(),
            request_sequence: Sequence::new(1).unwrap(),
        };
        let response = changed
            .signed(
                DESIRED_READ_PATH,
                encode_desired_read_request(&desired).unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let snapshot = decode_desired_read_snapshot(&response.bytes().await.unwrap()).unwrap();
        crate::testsupport::insert_assigned_desired_after_cursor_for_test(
            &changed.server.state.store,
            changed.session.node_id.clone(),
        )
        .await;
        let observation = changed.full_observation(snapshot.read_position);
        let before = changed.fingerprint().await;
        changed.arm_delayed_commit_response_loss();
        let response = promptly(changed.signed(
            OBSERVATION_PATH,
            encode_node_observation(&observation).unwrap(),
        ))
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(matches!(
            decoded_error(response).await.error.as_ref(),
            RuntimeSpineErrorDetail::ContractError { contract_error }
                if matches!(contract_error.error.as_ref(), ContractErrorDetail::AssignedSetChanged { .. })
        ));
        assert_eq!(changed.fingerprint().await, before);
        changed.assert_commit_response_loss_remains_armed();

        let ineligible = Context::new("ineligible").await;
        let request = DesiredReadRequest {
            version: ContractVersion::V1,
            session: ineligible.binding(),
            request_sequence: Sequence::new(1).unwrap(),
        };
        let body = encode_desired_read_request(&request).unwrap();
        let unprovisioned_signer = Ed25519RequestSigner::from_pkcs8_pem(
            Id::new("credential_phase_unprovisioned").unwrap(),
            include_bytes!("../../../tests/fixtures/route_grant_private_ed25519.pem"),
        )
        .unwrap();
        let before = ineligible.fingerprint().await;
        ineligible.arm_delayed_commit_response_loss();
        let response = promptly(Context::signed_with(
            &ineligible.client,
            &unprovisioned_signer,
            &ineligible.server,
            DESIRED_READ_PATH,
            body,
        ))
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(matches!(
            decoded_error(response).await.error.as_ref(),
            RuntimeSpineErrorDetail::IdentityNotEligible
        ));
        assert_eq!(ineligible.fingerprint().await, before);
        ineligible.assert_commit_response_loss_remains_armed();
    }

    #[tokio::test]
    async fn committed_runtime_mutation_closes_response_and_exact_retry_recovers() {
        let context = Context::new("committed_loss").await;
        let request = DesiredReadRequest {
            version: ContractVersion::V1,
            session: context.binding(),
            request_sequence: Sequence::new(1).unwrap(),
        };
        let body = encode_desired_read_request(&request).unwrap();
        let before = context.fingerprint().await;
        context.arm_commit_response_loss_after(Duration::ZERO);

        let incomplete = context
            .signed(DESIRED_READ_PATH, body.clone())
            .send()
            .await
            .expect_err("an ambiguous commit must close without an HTTP error envelope");
        assert!(incomplete.status().is_none());
        assert!(!context
            .server
            .state
            .store
            .request_committed_response_loss_is_armed());
        let committed = context.fingerprint().await;
        assert_ne!(
            committed, before,
            "the accepted mutation must have committed"
        );

        let replay = context
            .signed(DESIRED_READ_PATH, body)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let snapshot = decode_desired_read_snapshot(&replay.bytes().await.unwrap()).unwrap();
        assert_eq!(snapshot.request_sequence, request.request_sequence);
        assert_eq!(context.fingerprint().await, committed);
    }
}

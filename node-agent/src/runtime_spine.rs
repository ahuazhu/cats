//! Signed A20 Desired-read and observation transport for the Node.
//!
//! Callers pass the exact durable request bytes into this adapter. Transport,
//! framing, a malformed response, or a retryable server response all return
//! [`RuntimeSpineAttempt::RetryExact`]; the adapter never manufactures a new
//! domain sequence after an ambiguous outcome.

#[cfg(test)]
mod desired_effect;
mod runner;
mod state;

pub(crate) mod inventory_scanner_sealed {
    pub trait Sealed {}
}

#[cfg(test)]
pub(crate) mod runtime_launch_port_sealed {
    pub(crate) trait Sealed {}
}

#[cfg(test)]
pub(crate) use desired_effect::{ProductionRuntimeDesiredEffect, RuntimeLaunchPort};

pub(crate) use runner::{
    effect_resource_owner_sealed, InventoryCoverageAggregator, RuntimeAssignedCatSet,
    RuntimeEffectResourceOwner, RuntimeEffectSection, RuntimeInventoryKeyRing,
    RuntimeNodeGlobalEffectPermit, RuntimePhysicalReadContext,
};
pub use runner::{
    CompleteRuntimeInventory, RuntimeDesiredEffect, RuntimeDesiredEffectAdmission,
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
    RuntimeSpineDeadlinePolicy, RuntimeSpineDeadlinePolicyError, RuntimeSpineRunDeadlines,
    RuntimeSpineRunError, RuntimeSpineRunRetry, RuntimeSpineRunStep, RuntimeSpineRunner,
};
pub(crate) use runner::{
    RuntimePreScanAdmission, RuntimePreScanAdmissionContext, RuntimePreScanAdmissionOutcome,
    RuntimePreScanRecovery, RuntimePreScanRecoveryContext, RuntimePreScanRecoveryOutcome,
};
pub(crate) use state::RuntimeSpineJournal;
pub use state::{
    DurableRuntimeSpineRequest, RuntimeSpineDesiredWork, RuntimeSpineFullScan,
    RuntimeSpineJournalError,
};

use std::time::Duration;

use anyhow::Context as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{
    decode_desired_read_request, decode_desired_read_snapshot, decode_node_observation,
    decode_observation_acceptance, decode_runtime_spine_error, ContractError, ContractErrorDetail,
    DesiredReadSnapshot, NodeObservation, ObservationAcceptance, ObservationInventoryAcceptance,
    RuntimeSpineError, RuntimeSpineErrorDetail, RuntimeSpineHttpProblem, SessionBinding,
    DESIRED_READ_PATH, DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES, OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES,
    OBSERVATION_PATH, RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES, RUNTIME_SPINE_METHOD,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Exact response bytes retained alongside a successfully decoded A20 value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRuntimeSpineResponse<T> {
    pub value: T,
    pub bytes: Vec<u8>,
}

/// One attempt to resolve an already-durable A20 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSpineAttempt<T> {
    Accepted(AcceptedRuntimeSpineResponse<T>),
    /// The server definitely rejected the request before a domain success.
    Rejected {
        status: u16,
        error: RuntimeSpineError,
    },
    /// The commit/result is unknown or the server asked for backpressure.
    RetryExact(RuntimeSpineRetryReason),
    /// The exact A20 route is not deployed. Retrying cannot repair rollout.
    RouteUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSpineRetryReason {
    Transport,
    InvalidResponse,
    Backpressure,
    ServerFailure,
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

/// A no-redirect client bound to one exact Control Plane origin and Node key.
#[derive(Clone)]
pub struct RuntimeSpineHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::Client,
}

impl std::fmt::Debug for RuntimeSpineHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeSpineHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl RuntimeSpineHttpClient {
    pub fn for_production(
        control_plane_origin: &str,
        registration: &crate::agent_registration::AgentRegistrationConfig,
    ) -> anyhow::Result<Self> {
        Self::new(
            control_plane_origin,
            registration.runtime_request_signer(),
            TransportMode::ProductionHttps,
        )
    }

    #[doc(hidden)]
    pub fn for_loopback_test(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
    ) -> anyhow::Result<Self> {
        Self::new(control_plane_origin, signer, TransportMode::LoopbackTest)
    }

    fn new(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
        mode: TransportMode,
    ) -> anyhow::Result<Self> {
        let origin = validate_origin(control_plane_origin, mode)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(RESPONSE_TIMEOUT)
            .build()
            .context("build runtime-spine HTTP client")?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }

    /// Sends one exact canonical `DesiredReadRequest` body.
    pub async fn desired_read(
        &self,
        durable_body: &[u8],
    ) -> Result<RuntimeSpineAttempt<DesiredReadSnapshot>, ContractError> {
        let request = decode_desired_read_request(durable_body)?;
        Ok(
            match self
                .post(
                    DESIRED_READ_PATH,
                    durable_body,
                    DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES,
                    decode_desired_read_snapshot,
                )
                .await
            {
                RuntimeSpineAttempt::Accepted(accepted)
                    if accepted.value.version == request.version
                        && accepted.value.session == request.session
                        && accepted.value.request_sequence == request.request_sequence =>
                {
                    RuntimeSpineAttempt::Accepted(accepted)
                }
                RuntimeSpineAttempt::Accepted(_) => {
                    RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse)
                }
                other => other,
            },
        )
    }

    /// Sends one exact canonical `NodeObservation` body.
    pub async fn observation(
        &self,
        durable_body: &[u8],
    ) -> Result<RuntimeSpineAttempt<ObservationAcceptance>, ContractError> {
        let request = decode_node_observation(durable_body)?;
        Ok(
            match self
                .post(
                    OBSERVATION_PATH,
                    durable_body,
                    OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES,
                    decode_observation_acceptance,
                )
                .await
            {
                RuntimeSpineAttempt::Accepted(accepted)
                    if acceptance_matches_observation(&accepted.value, &request) =>
                {
                    RuntimeSpineAttempt::Accepted(accepted)
                }
                RuntimeSpineAttempt::Accepted(_) => {
                    RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse)
                }
                other => other,
            },
        )
    }

    async fn post<T>(
        &self,
        path: &'static str,
        durable_body: &[u8],
        success_cap: usize,
        decode_success: fn(&[u8]) -> Result<T, cats_api::runtime_reconciliation::ContractError>,
    ) -> RuntimeSpineAttempt<T> {
        let proof = self.signer.sign(RUNTIME_SPINE_METHOD, path, durable_body);
        let url = self
            .origin
            .join(path)
            .expect("validated origin accepts an absolute fixed path");
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(durable_body.to_vec())
            .send()
            .await;
        classify_response(response, success_cap, decode_success).await
    }
}

fn acceptance_matches_observation(
    acceptance: &ObservationAcceptance,
    observation: &NodeObservation,
) -> bool {
    acceptance.version == observation.version
        && acceptance.session
            == (SessionBinding {
                node_id: observation.node_id.clone(),
                node_boot_id: observation.node_boot_id.clone(),
                agent_instance_id: observation.agent_instance_id.clone(),
                agent_session_epoch: observation.agent_session_epoch,
            })
        && acceptance.observation_id == observation.observation_id
        && acceptance.heartbeat_sequence == observation.heartbeat_sequence
        && match (&acceptance.inventory, observation.complete_inventory) {
            (ObservationInventoryAcceptance::Full { attestation }, true) => {
                attestation.version == observation.version
                    && attestation.node_id == observation.node_id
                    && attestation.agent_session_epoch == observation.agent_session_epoch
                    && attestation.inventory_epoch == observation.inventory_epoch
                    && Some(&attestation.inventory_digest) == observation.inventory_digest.as_ref()
                    && Some(attestation.inventory_read_position)
                        == observation.inventory_read_position
            }
            (ObservationInventoryAcceptance::Partial { inventory_epoch }, false) => {
                *inventory_epoch == observation.inventory_epoch
            }
            _ => false,
        }
}

async fn classify_response<T>(
    response: Result<reqwest::Response, reqwest::Error>,
    success_cap: usize,
    decode_success: fn(&[u8]) -> Result<T, cats_api::runtime_reconciliation::ContractError>,
) -> RuntimeSpineAttempt<T> {
    let mut response = match response {
        Ok(response) => response,
        Err(_) => return RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::Transport),
    };
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return RuntimeSpineAttempt::RouteUnavailable;
    }
    let cap = if status == reqwest::StatusCode::OK {
        success_cap
    } else {
        RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES
    };
    if !valid_common_headers(response.headers())
        || declared_response_exceeds(response.headers(), cap)
    {
        return RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse);
    }
    let body = match read_bounded_body(&mut response, cap).await {
        Some(body) => body,
        None => return RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse),
    };

    if status == reqwest::StatusCode::OK {
        return match decode_success(&body) {
            Ok(value) => {
                RuntimeSpineAttempt::Accepted(AcceptedRuntimeSpineResponse { value, bytes: body })
            }
            Err(_) => RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse),
        };
    }

    let error = match decode_runtime_spine_error(&body) {
        Ok(error) => error,
        Err(_) => return RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse),
    };
    if !status_matches_error(status, response.headers(), &error) {
        return RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse);
    }
    match error.error.as_ref() {
        RuntimeSpineErrorDetail::NodeRequestInFlight
        | RuntimeSpineErrorDetail::TemporarilyUnavailable => {
            RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::Backpressure)
        }
        RuntimeSpineErrorDetail::Internal => {
            RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::ServerFailure)
        }
        _ => RuntimeSpineAttempt::Rejected {
            status: status.as_u16(),
            error,
        },
    }
}

fn valid_common_headers(headers: &reqwest::header::HeaderMap) -> bool {
    !headers.contains_key(reqwest::header::CONTENT_ENCODING)
        && has_one_header_ows_case_insensitive(
            headers,
            reqwest::header::CONTENT_TYPE,
            JSON_CONTENT_TYPE,
        )
        && has_one_exact_header(headers, reqwest::header::CACHE_CONTROL, "no-store")
}

fn status_matches_error(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    error: &RuntimeSpineError,
) -> bool {
    match error.error.as_ref() {
        RuntimeSpineErrorDetail::AuthenticationFailed => {
            status == reqwest::StatusCode::UNAUTHORIZED
                && has_one_exact_header(
                    headers,
                    reqwest::header::WWW_AUTHENTICATE,
                    NODE_AUTHENTICATE_CHALLENGE,
                )
        }
        RuntimeSpineErrorDetail::IdentityNotEligible => status == reqwest::StatusCode::FORBIDDEN,
        RuntimeSpineErrorDetail::HttpRequestRejected { problem } => match problem {
            RuntimeSpineHttpProblem::MethodNotAllowed => {
                status == reqwest::StatusCode::METHOD_NOT_ALLOWED
                    && has_one_exact_header(headers, reqwest::header::ALLOW, RUNTIME_SPINE_METHOD)
            }
            RuntimeSpineHttpProblem::QueryNotAllowed
            | RuntimeSpineHttpProblem::AuthorizationNotAllowed
            | RuntimeSpineHttpProblem::SemanticHeaderNotAllowed => {
                status == reqwest::StatusCode::BAD_REQUEST
            }
            RuntimeSpineHttpProblem::ContentTypeNotAllowed
            | RuntimeSpineHttpProblem::ContentEncodingNotAllowed => {
                status == reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
            }
            RuntimeSpineHttpProblem::AcceptNotAllowed => {
                status == reqwest::StatusCode::NOT_ACCEPTABLE
            }
        },
        RuntimeSpineErrorDetail::ContractError { contract_error } => {
            match contract_error.error.as_ref() {
                ContractErrorDetail::MalformedPayload { .. }
                | ContractErrorDetail::UnsupportedVersion { .. } => {
                    status == reqwest::StatusCode::BAD_REQUEST
                }
                ContractErrorDetail::LimitExceeded { .. } => {
                    status == reqwest::StatusCode::PAYLOAD_TOO_LARGE
                }
                _ => status == reqwest::StatusCode::CONFLICT,
            }
        }
        RuntimeSpineErrorDetail::NodeRequestInFlight => {
            status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && has_one_exact_header(headers, reqwest::header::RETRY_AFTER, "1")
        }
        RuntimeSpineErrorDetail::TemporarilyUnavailable => {
            status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && has_one_exact_header(headers, reqwest::header::RETRY_AFTER, "1")
        }
        RuntimeSpineErrorDetail::Internal => status == reqwest::StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn read_bounded_body(response: &mut reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= cap => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) => return Some(body),
        }
    }
}

fn declared_response_exceeds(headers: &reqwest::header::HeaderMap, cap: usize) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_some()
        || value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_none_or(|length| length > cap as u64)
}

fn has_one_exact_header(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn has_one_header_ows_case_insensitive(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(expected)
        })
        && values.next().is_none()
}

fn validate_origin(input: &str, mode: TransportMode) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(input).context("parse Control Plane origin")?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Control Plane origin has userinfo"
    );
    anyhow::ensure!(url.query().is_none(), "Control Plane origin has a query");
    anyhow::ensure!(
        url.fragment().is_none(),
        "Control Plane origin has a fragment"
    );
    anyhow::ensure!(url.path() == "/", "Control Plane origin has a path");
    match mode {
        TransportMode::ProductionHttps => {
            anyhow::ensure!(
                url.scheme() == "https",
                "production Control Plane origin must use HTTPS"
            );
        }
        TransportMode::LoopbackTest => {
            anyhow::ensure!(
                url.scheme() == "http"
                    && url
                        .host_str()
                        .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")),
                "test Control Plane origin must be loopback HTTP"
            );
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use cats_api::agent_registration::{verify_request_proof, NODE_SIGNATURE_HEADER};
    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, encode_desired_read_snapshot, encode_runtime_spine_error,
        ContractVersion, Id, RuntimeSpineError, RuntimeSpineErrorDetail, Sequence,
    };

    use super::*;

    const REQUEST: &[u8] = br#"{"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;
    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    fn signer() -> Ed25519RequestSigner {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        Ed25519RequestSigner::from_pkcs8_der(Id::new("credential_a").unwrap(), &der).unwrap()
    }

    async fn spawn(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://{address}/"), task)
    }

    fn wire_response(status: StatusCode, body: Vec<u8>) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn accepted_desired_response_requires_the_signed_exact_body() {
        let app = Router::new().route(
            DESIRED_READ_PATH,
            post(|request: Request<Body>| async move {
                assert!(request.headers().contains_key(NODE_SIGNATURE_HEADER));
                let headers = request.headers().clone();
                let body = to_bytes(request.into_body(), REQUEST.len()).await.unwrap();
                assert_eq!(body.as_ref(), REQUEST);
                let authenticated = verify_request_proof(
                    RUNTIME_SPINE_METHOD,
                    DESIRED_READ_PATH,
                    &body,
                    headers
                        .get(NODE_CREDENTIAL_ID_HEADER)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    headers
                        .get(NODE_PUBLIC_KEY_SPKI_HEADER)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    headers
                        .get(NODE_SIGNATURE_HEADER)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(authenticated.credential_id().as_str(), "credential_a");
                wire_response(StatusCode::OK, SNAPSHOT.to_vec())
            }),
        );
        let (origin, task) = spawn(app).await;
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();

        let RuntimeSpineAttempt::Accepted(accepted) = client.desired_read(REQUEST).await.unwrap()
        else {
            panic!("expected an accepted canonical snapshot")
        };
        assert_eq!(accepted.bytes, SNAPSHOT);
        assert_eq!(accepted.value.request_sequence.get(), 1);
        assert_eq!(accepted.value.read_position.get(), 12);
        task.abort();
    }

    #[tokio::test]
    async fn typed_backpressure_retries_but_definite_identity_rejection_does_not() {
        let calls = Arc::new(AtomicUsize::new(0));
        let serving_calls = calls.clone();
        let app = Router::new().route(
            DESIRED_READ_PATH,
            post(move || {
                let calls = serving_calls.clone();
                async move {
                    let (status, detail) = if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            RuntimeSpineErrorDetail::TemporarilyUnavailable,
                        )
                    } else {
                        (
                            StatusCode::FORBIDDEN,
                            RuntimeSpineErrorDetail::IdentityNotEligible,
                        )
                    };
                    let error = RuntimeSpineError {
                        version: ContractVersion::V1,
                        error: Box::new(detail),
                        message: "test".to_owned(),
                    };
                    let mut response =
                        wire_response(status, encode_runtime_spine_error(&error).unwrap());
                    if status == StatusCode::SERVICE_UNAVAILABLE {
                        response
                            .headers_mut()
                            .insert(header::RETRY_AFTER, "1".parse().unwrap());
                    }
                    response
                }
            }),
        );
        let (origin, task) = spawn(app).await;
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();

        assert!(matches!(
            client.desired_read(REQUEST).await.unwrap(),
            RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::Backpressure)
        ));
        assert!(matches!(
            client.desired_read(REQUEST).await.unwrap(),
            RuntimeSpineAttempt::Rejected {
                status: 403,
                error: RuntimeSpineError {
                    error,
                    ..
                }
            } if matches!(*error, RuntimeSpineErrorDetail::IdentityNotEligible)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn malformed_success_headers_and_redirects_never_become_success() {
        let redirected = Arc::new(AtomicUsize::new(0));
        let redirect_target = redirected.clone();
        let app = Router::new()
            .route(
                DESIRED_READ_PATH,
                post(|| async {
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(header::LOCATION, "/redirect-target")
                        .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(Body::empty())
                        .unwrap()
                }),
            )
            .route(
                "/redirect-target",
                post(move || {
                    let target = redirect_target.clone();
                    async move {
                        target.fetch_add(1, Ordering::SeqCst);
                        wire_response(StatusCode::OK, SNAPSHOT.to_vec())
                    }
                }),
            );
        let (origin, task) = spawn(app).await;
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();

        assert!(matches!(
            client.desired_read(REQUEST).await.unwrap(),
            RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse)
        ));
        assert_eq!(redirected.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn canonical_success_for_another_sequence_is_never_adopted() {
        let mut mismatched = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        mismatched.request_sequence = Sequence::new(2).unwrap();
        let body = encode_desired_read_snapshot(&mismatched).unwrap();
        let app = Router::new().route(
            DESIRED_READ_PATH,
            post(move || {
                let body = body.clone();
                async move { wire_response(StatusCode::OK, body) }
            }),
        );
        let (origin, task) = spawn(app).await;
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();

        assert!(matches!(
            client.desired_read(REQUEST).await.unwrap(),
            RuntimeSpineAttempt::RetryExact(RuntimeSpineRetryReason::InvalidResponse)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn a_noncanonical_local_request_is_not_signed_or_sent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let serving_calls = calls.clone();
        let app = Router::new().route(
            DESIRED_READ_PATH,
            post(move || {
                let calls = serving_calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    wire_response(StatusCode::OK, SNAPSHOT.to_vec())
                }
            }),
        );
        let (origin, task) = spawn(app).await;
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();

        assert!(client.desired_read(b"{}").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[test]
    fn production_origin_is_https_only_and_has_no_path_or_userinfo() {
        assert!(RuntimeSpineHttpClient::new(
            "http://cats.test/",
            signer(),
            TransportMode::ProductionHttps
        )
        .is_err());
        assert!(RuntimeSpineHttpClient::new(
            "https://cats.test/path",
            signer(),
            TransportMode::ProductionHttps
        )
        .is_err());
        assert!(RuntimeSpineHttpClient::new(
            "https://user@cats.test/",
            signer(),
            TransportMode::ProductionHttps
        )
        .is_err());
        RuntimeSpineHttpClient::new(
            "https://cats.test/",
            signer(),
            TransportMode::ProductionHttps,
        )
        .unwrap();
    }
}

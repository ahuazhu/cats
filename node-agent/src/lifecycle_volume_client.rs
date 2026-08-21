//! Production signed client for command-scoped lifecycle Volume transitions.
//!
//! The client submits one already-journaled exact request and never retries a
//! mutation internally. Timeout, transport loss, a non-success HTTP response,
//! or malformed response is ambiguous; the installed command state machine
//! keeps the same step executable and reposts the same canonical body.

use std::io::Read as _;
use std::time::Instant;

use anyhow::Context as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_lifecycle_volume::{
    decode_lifecycle_volume_transition_response, encode_lifecycle_volume_transition_request,
    LifecyclePersistentInitializationCommitRequest,
    LifecyclePersistentInitializationInspectRequest, LifecyclePersistentInitializationInspection,
    LifecycleStoredPersistentInitializationCommit, LifecycleVolumeTransitionApplied,
    LifecycleVolumeTransitionRejection, LifecycleVolumeTransitionRequest,
    LifecycleVolumeTransitionRequestKind, LifecycleVolumeTransitionResponse,
    LifecycleVolumeTransitionResult, LIFECYCLE_VOLUME_TRANSITION_METHOD,
    LIFECYCLE_VOLUME_TRANSITION_PATH, LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    ContractVersion, RandomId128, SessionBinding, Sha256Digest,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

#[derive(Clone)]
pub struct LifecycleVolumeHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for LifecycleVolumeHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LifecycleVolumeHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl LifecycleVolumeHttpClient {
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
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .context("build lifecycle Volume HTTP client")?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }

    /// Submit exactly one signed request. This function never performs a
    /// hidden retry; every error after submission is intentionally ambiguous.
    pub fn transition(
        &self,
        request: &LifecycleVolumeTransitionRequest,
        deadline: Instant,
    ) -> Result<LifecycleVolumeTransitionResponse, LifecycleVolumeClientError> {
        let body = encode_lifecycle_volume_transition_request(request)
            .map_err(|_| LifecycleVolumeClientError::InvalidRequest)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(LifecycleVolumeClientError::AmbiguousTimeout)?;
        let proof = self.signer.sign(
            LIFECYCLE_VOLUME_TRANSITION_METHOD,
            LIFECYCLE_VOLUME_TRANSITION_PATH,
            &body,
        );
        let url = self
            .origin
            .join(LIFECYCLE_VOLUME_TRANSITION_PATH)
            .expect("validated origin accepts the fixed lifecycle Volume path");
        let response = self
            .client
            .post(url)
            .timeout(remaining)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    LifecycleVolumeClientError::AmbiguousTimeout
                } else {
                    LifecycleVolumeClientError::AmbiguousTransport
                }
            })?;
        decode_response(request, response)
    }

    /// Execute one signed, authority-only initialization inspect. The method
    /// never retries; an ambiguous transport result remains owned by the
    /// durable Start phase which supplied the exact request.
    pub fn inspect_persistent_initialization(
        &self,
        session: SessionBinding,
        inspect: LifecyclePersistentInitializationInspectRequest,
        deadline: Instant,
    ) -> Result<LifecyclePersistentInitializationInspection, LifecycleVolumeClientError> {
        let expected_binding = inspect.binding.clone();
        let request = LifecycleVolumeTransitionRequest {
            version: ContractVersion::V1,
            session,
            transition: LifecycleVolumeTransitionRequestKind::InspectPersistentInitialization {
                inspect: Box::new(inspect),
            },
        };
        let response = self.transition(&request, deadline)?;
        match response.result {
            LifecycleVolumeTransitionResult::Applied {
                applied:
                    LifecycleVolumeTransitionApplied::PersistentInitializationInspected { inspection },
            } if inspection.binding == expected_binding => Ok(*inspection),
            LifecycleVolumeTransitionResult::Rejected { reason } => {
                Err(LifecycleVolumeClientError::Rejected(reason))
            }
            LifecycleVolumeTransitionResult::Applied { .. } => {
                Err(LifecycleVolumeClientError::AmbiguousInvalidResponse)
            }
        }
    }

    /// Execute one signed initialization commit or exact response-loss replay.
    /// AgentSession is outer transport identity only; the commit identity is
    /// the embedded Start/config/grant/evidence tuple.
    pub fn commit_persistent_initialization(
        &self,
        session: SessionBinding,
        expected_runtime_incarnation: &RandomId128,
        expected_format_plan_digest: &Sha256Digest,
        commit: LifecyclePersistentInitializationCommitRequest,
        deadline: Instant,
    ) -> Result<LifecycleStoredPersistentInitializationCommit, LifecycleVolumeClientError> {
        if &commit.guest_probe.runtime_incarnation != expected_runtime_incarnation
            || &commit.format_plan_digest != expected_format_plan_digest
        {
            return Err(LifecycleVolumeClientError::InvalidRequest);
        }
        let expected_commit = commit.clone();
        let request = LifecycleVolumeTransitionRequest {
            version: ContractVersion::V1,
            session,
            transition: LifecycleVolumeTransitionRequestKind::CommitPersistentInitialization {
                commit: Box::new(commit),
            },
        };
        let response = self.transition(&request, deadline)?;
        match response.result {
            LifecycleVolumeTransitionResult::Applied {
                applied:
                    LifecycleVolumeTransitionApplied::PersistentInitializationCommitted { committed },
            } if committed.receipt.request.as_ref() == &expected_commit => Ok(*committed),
            LifecycleVolumeTransitionResult::Rejected { reason } => {
                Err(LifecycleVolumeClientError::Rejected(reason))
            }
            LifecycleVolumeTransitionResult::Applied { .. } => {
                Err(LifecycleVolumeClientError::AmbiguousInvalidResponse)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LifecycleVolumeClientError {
    #[error("lifecycle Volume request is not a valid canonical contract")]
    InvalidRequest,
    #[error("lifecycle Volume request timed out with unknown commit status")]
    AmbiguousTimeout,
    #[error("lifecycle Volume transport failed with unknown commit status")]
    AmbiguousTransport,
    #[error("lifecycle Volume HTTP response has unknown commit status")]
    AmbiguousHttp,
    #[error("lifecycle Volume response is malformed or bound to another request")]
    AmbiguousInvalidResponse,
    #[error("lifecycle Volume authority rejected the exact request: {0:?}")]
    Rejected(LifecycleVolumeTransitionRejection),
}

fn decode_response(
    request: &LifecycleVolumeTransitionRequest,
    response: reqwest::blocking::Response,
) -> Result<LifecycleVolumeTransitionResponse, LifecycleVolumeClientError> {
    if response.status() != reqwest::StatusCode::OK
        || response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
        || !has_one_exact_header(
            response.headers(),
            reqwest::header::CONTENT_TYPE,
            JSON_CONTENT_TYPE,
        )
        || !has_one_exact_header(
            response.headers(),
            reqwest::header::CACHE_CONTROL,
            "no-store",
        )
        || declared_response_exceeds(
            response.headers(),
            LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES,
        )
    {
        return Err(LifecycleVolumeClientError::AmbiguousHttp);
    }
    let limit = u64::try_from(LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES)
        .expect("fixed response cap fits u64")
        + 1;
    let mut body = Vec::new();
    response
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|_| LifecycleVolumeClientError::AmbiguousTransport)?;
    if body.len() > LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES {
        return Err(LifecycleVolumeClientError::AmbiguousInvalidResponse);
    }
    let decoded = decode_lifecycle_volume_transition_response(&body)
        .map_err(|_| LifecycleVolumeClientError::AmbiguousInvalidResponse)?;
    let scope = request.transition.scope();
    if decoded.version != request.version
        || decoded.session != request.session
        || decoded.operation_id != scope.operation_id
        || decoded.request_fingerprint != scope.request_fingerprint
    {
        return Err(LifecycleVolumeClientError::AmbiguousInvalidResponse);
    }
    Ok(decoded)
}

fn has_one_exact_header(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.as_bytes() == expected.as_bytes()
}

fn declared_response_exceeds(headers: &reqwest::header::HeaderMap, maximum: usize) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
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

fn validate_origin(input: &str, mode: TransportMode) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(input).context("parse Control Plane origin")?;
    let scheme_ok = match mode {
        TransportMode::ProductionHttps => url.scheme() == "https",
        TransportMode::LoopbackTest => {
            url.scheme() == "http" && url.host_str().is_some_and(is_loopback_host)
        }
    };
    anyhow::ensure!(scheme_ok, "invalid lifecycle Volume Control origin scheme");
    anyhow::ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "lifecycle Volume Control origin must not contain credentials, path, query, or fragment"
    );
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_origin_is_https_and_loopback_relaxation_is_narrow() {
        assert!(
            validate_origin("https://control.example/", TransportMode::ProductionHttps).is_ok()
        );
        assert!(
            validate_origin("http://control.example/", TransportMode::ProductionHttps).is_err()
        );
        assert!(validate_origin("http://127.0.0.1:8080/", TransportMode::LoopbackTest).is_ok());
        assert!(validate_origin("http://control.example/", TransportMode::LoopbackTest).is_err());
        assert!(validate_origin(
            "https://control.example/path",
            TransportMode::ProductionHttps
        )
        .is_err());
    }
}

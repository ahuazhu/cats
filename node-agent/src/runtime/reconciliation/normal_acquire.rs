//! Exact A19-signed A22 normal-acquire client.
//!
//! The client accepts only a complete, already-checkpointed mutation request.
//! It validates every success field back to that request and the exact root
//! VolumeIntent, then returns the closed grant shape consumed by blockd. It
//! never opens a metadata adapter, calls a pure Control helper, generates a
//! transition ID, or falls back to a legacy ownership route.

use std::io::Read as _;
use std::time::{Duration, Instant};

use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_volume_transition_error, decode_runtime_volume_transition_success,
    encode_runtime_volume_transition_request, AcquireOrigin, ContractErrorDetail, ContractName,
    DiskKind, NormalAcquireRequest, NormalAcquireResult, RuntimeSpineHttpProblem,
    RuntimeVolumeAuthorityRejection, RuntimeVolumeTransition, RuntimeVolumeTransitionError,
    RuntimeVolumeTransitionErrorDetail, RuntimeVolumeTransitionOutcome,
    RuntimeVolumeTransitionRequest, VolumeAccess, VolumeAcquire, VolumeAcquireRequest,
    VolumeAdminState, VolumeDisposition, VolumeIntent, VolumeRecord, RUNTIME_SPINE_METHOD,
    RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES, RUNTIME_VOLUME_TRANSITION_PATH,
    RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_authorized_serving_record,
    validate_volume_record, AttachmentLineageIdentity, AuthorizedServingAttachment,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Strict HTTP result after A19 proof, response-header and bound-read checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedVolumeTransitionResponse {
    Success(Vec<u8>),
    ClosedError { status: u16, body: Vec<u8> },
    PlainRouteNotFound,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeTransitionTransportFailure {
    Cancelled,
    Timeout,
    Eof,
    Connection,
}

/// Narrow transport seam for the one fixed A22 mutation route.
pub trait A19SignedVolumeTransitionTransport: Send + Sync {
    fn post_a19_signed_json(
        &self,
        exact_path: &'static str,
        canonical_body: &[u8],
        success_wire_cap: usize,
        deadline: Instant,
    ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalAcquireAttempt {
    Granted(Box<AuthorizedServingAttachment>),
    RetryExact,
    RefreshInventory,
    SessionReplacementRequired,
    AuthorityRejected(RuntimeVolumeAuthorityRejection),
    StopForLocalContract,
    StopForDeploymentMismatch,
    Ambiguous,
}

/// Direct strict-authority resolution after an ambiguous normal acquire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalAcquireAuthorityRecovery {
    Granted(Box<AuthorizedServingAttachment>),
    RetryExact,
    Blocked,
}

#[derive(Debug, thiserror::Error)]
pub enum NormalAcquireClientError {
    #[error("invalid local A22 mutation request: {0:?}")]
    InvalidRequest(cats_api::runtime_reconciliation::ContractError),
    #[error("normal-acquire request is not exactly bound to the supplied root VolumeIntent")]
    InvalidVolumeBinding,
}

#[derive(Debug, Clone)]
pub struct ControlSignedNormalAcquireClient<T> {
    transport: T,
}

impl<T> ControlSignedNormalAcquireClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> ControlSignedNormalAcquireClient<T>
where
    T: A19SignedVolumeTransitionTransport,
{
    pub fn acquire(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        deadline: Instant,
    ) -> Result<NormalAcquireAttempt, NormalAcquireClientError> {
        let body = encode_runtime_volume_transition_request(request)
            .map_err(NormalAcquireClientError::InvalidRequest)?;
        let normal = validate_local_normal_request(request, volume)?;
        let response = match self.transport.post_a19_signed_json(
            RUNTIME_VOLUME_TRANSITION_PATH,
            &body,
            RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            deadline,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(NormalAcquireAttempt::Ambiguous),
        };
        match response {
            SignedVolumeTransitionResponse::Success(body) => {
                let Ok(success) = decode_runtime_volume_transition_success(&body) else {
                    return Ok(NormalAcquireAttempt::Ambiguous);
                };
                let Some(attachment) = exact_success_attachment(request, volume, normal, success)
                else {
                    return Ok(NormalAcquireAttempt::Ambiguous);
                };
                Ok(NormalAcquireAttempt::Granted(Box::new(attachment)))
            }
            SignedVolumeTransitionResponse::ClosedError { status, body } => {
                let Ok(error) = decode_runtime_volume_transition_error(&body) else {
                    return Ok(NormalAcquireAttempt::Ambiguous);
                };
                Ok(map_closed_error(status, &error, request, volume))
            }
            SignedVolumeTransitionResponse::PlainRouteNotFound => {
                Ok(NormalAcquireAttempt::StopForDeploymentMismatch)
            }
            SignedVolumeTransitionResponse::Ambiguous => Ok(NormalAcquireAttempt::Ambiguous),
        }
    }
}

/// Resolve an unknown HTTP outcome through the exact point-read authority
/// record allowed by A22 §3. This never reads transition history or SQL. The
/// exact current predecessor permits replay; only a complete matching current
/// owner and immutable NormalAcquire marker is adopted as success.
pub fn recover_normal_acquire_from_authority(
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    record: &VolumeRecord,
) -> Result<NormalAcquireAuthorityRecovery, NormalAcquireClientError> {
    let acquire = validate_local_normal_request(request, volume)?;
    if validate_volume_record(record).is_err()
        || record.volume_id != volume.volume_id
        || record.size_bytes != volume.size_bytes
        || record.durability != volume.durability
        || !matches!(record.admin_state, VolumeAdminState::Active)
    {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    }
    let VolumeAcquireRequest::Normal {
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
        ..
    } = acquire
    else {
        unreachable!("local validation accepted only Normal")
    };
    if record.lease_owner.is_none()
        && record.lease_epoch == *expected_unowned_epoch
        && record.lease_expires_at.is_none()
    {
        return Ok(NormalAcquireAuthorityRecovery::RetryExact);
    }
    let Some(cats_api::runtime_reconciliation::LastVolumeTransition::NormalAcquire {
        request: stored_request,
        result: stored_result,
    }) = &record.last_transition
    else {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    };
    let exact_request = NormalAcquireRequest {
        volume_id: volume.volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_unowned_epoch: *expected_unowned_epoch,
        desired_revision: *desired_revision,
        placement_epoch: *placement_epoch,
        lease_duration_ms: *lease_duration_ms,
    };
    if stored_request != &exact_request
        || stored_result.volume_id != volume.volume_id
        || stored_result.transition_id != *transition_id
        || stored_result.attachment_id != *attachment_id
        || record.lease_owner.as_ref() != Some(attachment_id)
        || record.lease_epoch != stored_result.resulting_epoch
        || record.lease_expires_at.is_none()
    {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    }
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: volume.volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: stored_result.resulting_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            },
            node_id: request.placement.node_id.clone(),
            placement_epoch: request.placement.placement_epoch,
        },
        size_bytes: record.size_bytes,
        durability: record.durability,
        head: record.head.clone(),
        // Preserve the first grant. A later successful renew may advance the
        // current expiry but cannot rewrite the acquire receipt.
        lease_expires_at: stored_result.lease_expires_at,
        acquire_request: stored_request.clone(),
        acquire_result: stored_result.clone(),
    };
    if validate_authorized_serving_record(record, &attachment, None).is_err() {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    }
    Ok(NormalAcquireAuthorityRecovery::Granted(Box::new(
        attachment,
    )))
}

fn validate_local_normal_request<'a>(
    request: &'a RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
) -> Result<&'a VolumeAcquireRequest, NormalAcquireClientError> {
    let RuntimeVolumeTransition::Acquire { request: acquire } = &request.transition else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    let VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = acquire
    else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    let VolumeAcquire::Normal {
        transition_id: intended_transition,
        expected_unowned_epoch: intended_epoch,
    } = &volume.acquire
    else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    if volume_id != &volume.volume_id
        || transition_id != intended_transition
        || attachment_id != &volume.attachment_id
        || expected_unowned_epoch != intended_epoch
        || desired_revision != &request.desired_revision
        || placement_epoch != &request.placement.placement_epoch
        || request.placement.node_id != request.session.node_id
        || *lease_duration_ms == 0
        || volume.size_bytes == 0
        || volume.disk_kind != DiskKind::Root
        || volume.access != VolumeAccess::ReadWriteOnce
        || volume.mount.is_some()
        || !matches!(volume.disposition, VolumeDisposition::Retain)
    {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    }
    Ok(acquire)
}

fn exact_success_attachment(
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    acquire: &VolumeAcquireRequest,
    success: cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess,
) -> Option<AuthorizedServingAttachment> {
    if success.version != request.version
        || success.session != request.session
        || success.cat_id != request.cat_id
        || success.desired_revision != request.desired_revision
        || success.spec_digest != request.spec_digest
        || success.placement != request.placement
    {
        return None;
    }
    let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = success.outcome else {
        return None;
    };
    let VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = acquire
    else {
        return None;
    };
    let resulting_epoch = expected_unowned_epoch.get().checked_add(1)?;
    if grant.volume_id != *volume_id
        || grant.attachment_id != *attachment_id
        || grant.attachment_epoch.get() != resulting_epoch
        || grant.size_bytes != volume.size_bytes
        || grant.durability != volume.durability
        || grant.acquire_origin
            != (AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            })
    {
        return None;
    }
    let acquire_request = NormalAcquireRequest {
        volume_id: volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_unowned_epoch: *expected_unowned_epoch,
        desired_revision: *desired_revision,
        placement_epoch: *placement_epoch,
        lease_duration_ms: *lease_duration_ms,
    };
    let acquire_result = NormalAcquireResult {
        volume_id: grant.volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: grant.attachment_id.clone(),
        resulting_epoch: grant.attachment_epoch,
        resulting_head: grant.head.clone(),
        lease_expires_at: grant.lease_expires_at,
    };
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: grant.volume_id,
            attachment_id: grant.attachment_id,
            attachment_epoch: grant.attachment_epoch,
            acquire_origin: grant.acquire_origin,
            node_id: request.placement.node_id.clone(),
            placement_epoch: request.placement.placement_epoch,
        },
        size_bytes: grant.size_bytes,
        durability: grant.durability,
        head: grant.head,
        lease_expires_at: grant.lease_expires_at,
        acquire_request,
        acquire_result,
    };
    validate_authorized_serving_attachment(&attachment)
        .is_ok()
        .then_some(attachment)
}

fn map_closed_error(
    status: u16,
    error: &RuntimeVolumeTransitionError,
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
) -> NormalAcquireAttempt {
    match (status, error.error.as_ref()) {
        (401, RuntimeVolumeTransitionErrorDetail::AuthenticationFailed)
        | (403, RuntimeVolumeTransitionErrorDetail::IdentityNotEligible) => {
            NormalAcquireAttempt::SessionReplacementRequired
        }
        (409, RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed { cat_id, .. })
            if cat_id == &request.cat_id =>
        {
            NormalAcquireAttempt::RefreshInventory
        }
        (
            409,
            RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected { volume_id, reason },
        ) if volume_id == &volume.volume_id => NormalAcquireAttempt::AuthorityRejected(*reason),
        (409, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if session_error_binds_request(contract_error.error.as_ref(), request) =>
        {
            NormalAcquireAttempt::SessionReplacementRequired
        }
        (429, RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight)
        | (500, RuntimeVolumeTransitionErrorDetail::Internal)
        | (503, RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable) => {
            NormalAcquireAttempt::RetryExact
        }
        (status, RuntimeVolumeTransitionErrorDetail::HttpRequestRejected { problem })
            if http_problem_status(*problem) == status =>
        {
            NormalAcquireAttempt::StopForLocalContract
        }
        (status, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if request_contract_error_binds(contract_error.error.as_ref())
                && matches!(status, 400 | 409 | 413) =>
        {
            NormalAcquireAttempt::StopForLocalContract
        }
        _ => NormalAcquireAttempt::Ambiguous,
    }
}

fn request_contract_error_binds(detail: &ContractErrorDetail) -> bool {
    match detail {
        ContractErrorDetail::UnsupportedVersion { contract, .. }
        | ContractErrorDetail::MalformedPayload { contract, .. }
        | ContractErrorDetail::LimitExceeded { contract, .. } => {
            *contract == ContractName::RuntimeVolumeTransitionRequest
        }
        _ => false,
    }
}

fn session_error_binds_request(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionRequest,
) -> bool {
    match detail {
        ContractErrorDetail::MissingAgentSession { node_id }
        | ContractErrorDetail::GuestConfigMismatch { node_id, .. } => {
            node_id == &request.session.node_id
        }
        ContractErrorDetail::StaleSession {
            node_id,
            presented_agent_session_epoch,
            ..
        }
        | ContractErrorDetail::SessionExpired {
            node_id,
            agent_session_epoch: presented_agent_session_epoch,
            ..
        } => {
            node_id == &request.session.node_id
                && presented_agent_session_epoch == &request.session.agent_session_epoch
        }
        ContractErrorDetail::WrongSession {
            expected,
            presented,
        } => presented == &request.session && expected.node_id == request.session.node_id,
        _ => false,
    }
}

fn http_problem_status(problem: RuntimeSpineHttpProblem) -> u16 {
    match problem {
        RuntimeSpineHttpProblem::MethodNotAllowed => 405,
        RuntimeSpineHttpProblem::QueryNotAllowed
        | RuntimeSpineHttpProblem::AuthorizationNotAllowed
        | RuntimeSpineHttpProblem::SemanticHeaderNotAllowed => 400,
        RuntimeSpineHttpProblem::ContentTypeNotAllowed
        | RuntimeSpineHttpProblem::ContentEncodingNotAllowed => 415,
        RuntimeSpineHttpProblem::AcceptNotAllowed => 406,
    }
}

#[derive(Clone)]
pub struct RuntimeVolumeTransitionHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for RuntimeVolumeTransitionHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeVolumeTransitionHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl RuntimeVolumeTransitionHttpClient {
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
            .timeout(RESPONSE_TIMEOUT)
            .build()?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }
}

impl A19SignedVolumeTransitionTransport for RuntimeVolumeTransitionHttpClient {
    fn post_a19_signed_json(
        &self,
        exact_path: &'static str,
        canonical_body: &[u8],
        success_wire_cap: usize,
        deadline: Instant,
    ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
        if exact_path != RUNTIME_VOLUME_TRANSITION_PATH
            || success_wire_cap != RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES
        {
            return Ok(SignedVolumeTransitionResponse::Ambiguous);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(VolumeTransitionTransportFailure::Timeout)?;
        let proof = self
            .signer
            .sign(RUNTIME_SPINE_METHOD, exact_path, canonical_body);
        let url = self
            .origin
            .join(exact_path)
            .expect("validated origin accepts the fixed A22 path");
        let response = self
            .client
            .post(url)
            .timeout(remaining)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(canonical_body.to_vec())
            .send();
        let response = match response {
            Ok(response) => response,
            Err(error) if error.is_timeout() => {
                return Err(VolumeTransitionTransportFailure::Timeout)
            }
            Err(_) => return Err(VolumeTransitionTransportFailure::Connection),
        };
        classify_http_response(response, success_wire_cap)
    }
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

fn classify_http_response(
    mut response: reqwest::blocking::Response,
    success_cap: usize,
) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(SignedVolumeTransitionResponse::PlainRouteNotFound);
    }
    let cap = if status == reqwest::StatusCode::OK {
        success_cap
    } else {
        RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES
    };
    if !valid_common_headers(response.headers())
        || declared_response_exceeds(response.headers(), cap)
    {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    }
    let mut body = Vec::new();
    if response
        .by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return Err(VolumeTransitionTransportFailure::Eof);
    }
    if body.len() > cap {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    }
    if status == reqwest::StatusCode::OK {
        return Ok(SignedVolumeTransitionResponse::Success(body));
    }
    let Ok(error) = decode_runtime_volume_transition_error(&body) else {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    };
    if !status_matches_error(status, response.headers(), &error) {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    }
    Ok(SignedVolumeTransitionResponse::ClosedError {
        status: status.as_u16(),
        body,
    })
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
    error: &RuntimeVolumeTransitionError,
) -> bool {
    match error.error.as_ref() {
        RuntimeVolumeTransitionErrorDetail::AuthenticationFailed => {
            status == reqwest::StatusCode::UNAUTHORIZED
                && has_one_exact_header(
                    headers,
                    reqwest::header::WWW_AUTHENTICATE,
                    NODE_AUTHENTICATE_CHALLENGE,
                )
        }
        RuntimeVolumeTransitionErrorDetail::IdentityNotEligible => {
            status == reqwest::StatusCode::FORBIDDEN
        }
        RuntimeVolumeTransitionErrorDetail::HttpRequestRejected { problem } => {
            status.as_u16() == http_problem_status(*problem)
                && (!matches!(problem, RuntimeSpineHttpProblem::MethodNotAllowed)
                    || has_one_exact_header(headers, reqwest::header::ALLOW, RUNTIME_SPINE_METHOD))
        }
        RuntimeVolumeTransitionErrorDetail::ContractError { .. }
        | RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed { .. }
        | RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected { .. }
        | RuntimeVolumeTransitionErrorDetail::VolumeAuthorizationRejected { .. } => {
            status == reqwest::StatusCode::CONFLICT
                || matches!(status.as_u16(), 400 | 413)
                    && matches!(
                        error.error.as_ref(),
                        RuntimeVolumeTransitionErrorDetail::ContractError { .. }
                    )
        }
        RuntimeVolumeTransitionErrorDetail::AuthorizationEvidenceUnavailable { .. } => false,
        RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight => {
            status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && has_one_exact_header(headers, reqwest::header::RETRY_AFTER, "1")
        }
        RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable => {
            status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && has_one_exact_header(headers, reqwest::header::RETRY_AFTER, "1")
        }
        RuntimeVolumeTransitionErrorDetail::Internal => {
            status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
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
    let url = reqwest::Url::parse(input)?;
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
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Mutex;

    use cats_api::agent_registration::{verify_request_proof, Ed25519RequestSigner};
    use cats_api::runtime_reconciliation::{
        decode_runtime_volume_transition_request, encode_runtime_volume_transition_error,
        Durability, Generation, GuestDeviceIdentity, Id, LastVolumeTransition, RemoteHead,
        RuntimeVolumeTransitionPreconditionProblem, Sha256Digest, UnixMillis,
    };

    use super::*;

    const REQUEST: &[u8] = br#"{"cat_id":"cat_01","desired_revision":7,"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","transition":{"kind":"acquire","request":{"attachment_id":"att_01","desired_revision":7,"expected_unowned_epoch":0,"kind":"normal","lease_duration_ms":60000,"placement_epoch":3,"transition_id":"22222222222222222222222222222222","volume_id":"vol_root"}},"version":1}"#;
    const SUCCESS: &[u8] = br#"{"cat_id":"cat_01","desired_revision":7,"outcome":{"grant":{"acquire_origin":{"kind":"normal","transition_id":"22222222222222222222222222222222"},"attachment_epoch":1,"attachment_id":"att_01","durability":"strict","head":{"generation":0,"root_hash":null,"root_object_id":null},"lease_expires_at":1720000060000,"size_bytes":4294967296,"volume_id":"vol_root"},"kind":"lease_granted"},"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","version":1}"#;

    struct FakeTransport {
        response: Mutex<Option<SignedVolumeTransitionResponse>>,
        seen: Mutex<Vec<(&'static str, Vec<u8>, usize)>>,
    }

    impl FakeTransport {
        fn new(response: SignedVolumeTransitionResponse) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl A19SignedVolumeTransitionTransport for FakeTransport {
        fn post_a19_signed_json(
            &self,
            exact_path: &'static str,
            canonical_body: &[u8],
            success_wire_cap: usize,
            deadline: Instant,
        ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
            assert!(deadline > Instant::now());
            self.seen
                .lock()
                .unwrap()
                .push((exact_path, canonical_body.to_vec(), success_wire_cap));
            Ok(self.response.lock().unwrap().take().unwrap())
        }
    }

    fn request() -> RuntimeVolumeTransitionRequest {
        decode_runtime_volume_transition_request(REQUEST).unwrap()
    }

    fn volume() -> VolumeIntent {
        VolumeIntent {
            volume_intent_id: Id::new("root-intent").unwrap(),
            disk_id: Id::new("root-disk").unwrap(),
            volume_id: Id::new("vol_root").unwrap(),
            attachment_id: Id::new("att_01").unwrap(),
            size_bytes: 4_294_967_296,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-root").unwrap(),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "22222222222222222222222222222222",
                )
                .unwrap(),
                expected_unowned_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(0)
                    .unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }
    }

    #[test]
    fn exact_grant_becomes_closed_authorized_attachment() {
        let transport =
            FakeTransport::new(SignedVolumeTransitionResponse::Success(SUCCESS.to_vec()));
        let client = ControlSignedNormalAcquireClient::new(transport);
        let attempt = client
            .acquire(
                &request(),
                &volume(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let NormalAcquireAttempt::Granted(attachment) = attempt else {
            panic!("expected an exact grant")
        };
        assert_eq!(attachment.identity.volume_id.as_str(), "vol_root");
        assert_eq!(attachment.identity.attachment_id.as_str(), "att_01");
        assert_eq!(attachment.identity.attachment_epoch.get(), 1);
        assert_eq!(attachment.identity.node_id.as_str(), "node_a");
        assert_eq!(attachment.acquire_request.lease_duration_ms, 60_000);
        assert_eq!(attachment.acquire_result.resulting_head, attachment.head);
        let seen = client.transport().seen.lock().unwrap();
        assert_eq!(
            seen.as_slice(),
            &[(
                RUNTIME_VOLUME_TRANSITION_PATH,
                REQUEST.to_vec(),
                RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            )]
        );
    }

    #[test]
    fn mismatched_or_malformed_success_is_ambiguous_and_never_a_grant() {
        let mut wrong = decode_runtime_volume_transition_success(SUCCESS).unwrap();
        let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = &mut wrong.outcome else {
            unreachable!()
        };
        grant.attachment_id = Id::new("other-attachment").unwrap();
        let wrong =
            cats_api::runtime_reconciliation::encode_runtime_volume_transition_success(&wrong)
                .unwrap();
        for response in [
            SignedVolumeTransitionResponse::Success(wrong),
            SignedVolumeTransitionResponse::Success(b"{}".to_vec()),
            SignedVolumeTransitionResponse::Ambiguous,
        ] {
            let attempt = ControlSignedNormalAcquireClient::new(FakeTransport::new(response))
                .acquire(
                    &request(),
                    &volume(),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            assert_eq!(attempt, NormalAcquireAttempt::Ambiguous);
        }
    }

    #[test]
    fn typed_rejections_are_bound_before_driving_retry_or_refresh() {
        let cases = [
            (
                409,
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id: Id::new("cat_01").unwrap(),
                    problem: RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
                },
                NormalAcquireAttempt::RefreshInventory,
            ),
            (
                409,
                RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected {
                    volume_id: Id::new("vol_root").unwrap(),
                    reason: RuntimeVolumeAuthorityRejection::OtherWriter,
                },
                NormalAcquireAttempt::AuthorityRejected(
                    RuntimeVolumeAuthorityRejection::OtherWriter,
                ),
            ),
            (
                503,
                RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable,
                NormalAcquireAttempt::RetryExact,
            ),
        ];
        for (status, detail, expected) in cases {
            let body = encode_runtime_volume_transition_error(&RuntimeVolumeTransitionError {
                version: cats_api::runtime_reconciliation::ContractVersion::V1,
                error: Box::new(detail),
                message: "typed test error".to_owned(),
            })
            .unwrap();
            let attempt = ControlSignedNormalAcquireClient::new(FakeTransport::new(
                SignedVolumeTransitionResponse::ClosedError { status, body },
            ))
            .acquire(
                &request(),
                &volume(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(attempt, expected);
        }

        let body = encode_runtime_volume_transition_error(&RuntimeVolumeTransitionError {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            error: Box::new(
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id: Id::new("other-cat").unwrap(),
                    problem: RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
                },
            ),
            message: "wrong Cat".to_owned(),
        })
        .unwrap();
        let attempt = ControlSignedNormalAcquireClient::new(FakeTransport::new(
            SignedVolumeTransitionResponse::ClosedError { status: 409, body },
        ))
        .acquire(
            &request(),
            &volume(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(attempt, NormalAcquireAttempt::Ambiguous);
    }

    #[test]
    fn response_loss_adopts_only_the_exact_current_authority_marker() {
        let request = request();
        let volume = volume();
        let granted = ControlSignedNormalAcquireClient::new(FakeTransport::new(
            SignedVolumeTransitionResponse::Success(SUCCESS.to_vec()),
        ))
        .acquire(&request, &volume, Instant::now() + Duration::from_secs(1))
        .unwrap();
        let NormalAcquireAttempt::Granted(attachment) = granted else {
            unreachable!()
        };
        let mut record = VolumeRecord {
            volume_id: attachment.identity.volume_id.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            admin_state: VolumeAdminState::Active,
            head: attachment.head.clone(),
            lease_owner: Some(attachment.identity.attachment_id.clone()),
            lease_epoch: attachment.identity.attachment_epoch,
            // Model a renew whose response was also lost. Recovery retains
            // the original grant expiry while proving the current owner.
            lease_expires_at: Some(UnixMillis::new(1_720_000_120_000).unwrap()),
            last_transition: Some(LastVolumeTransition::NormalAcquire {
                request: attachment.acquire_request.clone(),
                result: attachment.acquire_result.clone(),
            }),
        };
        let recovered = recover_normal_acquire_from_authority(&request, &volume, &record).unwrap();
        let NormalAcquireAuthorityRecovery::Granted(recovered) = recovered else {
            panic!("matching authority marker was not adopted")
        };
        assert_eq!(recovered, attachment);

        record.head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([7; 32])),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new("roots/provisioned").unwrap(),
            ),
        };
        let recovered = recover_normal_acquire_from_authority(&request, &volume, &record).unwrap();
        let NormalAcquireAuthorityRecovery::Granted(recovered) = recovered else {
            panic!("later exact head was not adopted")
        };
        assert_eq!(recovered.head, record.head);
        assert_eq!(
            recovered.acquire_result.resulting_head,
            attachment.acquire_result.resulting_head
        );

        let predecessor = VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: attachment.acquire_result.resulting_head.clone(),
            lease_owner: None,
            lease_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(0).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        assert_eq!(
            recover_normal_acquire_from_authority(&request, &volume, &predecessor).unwrap(),
            NormalAcquireAuthorityRecovery::RetryExact
        );

        record.lease_owner = Some(Id::new("foreign-writer").unwrap());
        assert_eq!(
            recover_normal_acquire_from_authority(&request, &volume, &record).unwrap(),
            NormalAcquireAuthorityRecovery::Blocked
        );
    }

    fn signer() -> Ed25519RequestSigner {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        Ed25519RequestSigner::from_pkcs8_der(Id::new("credential_a").unwrap(), &der).unwrap()
    }

    #[test]
    fn production_transport_signs_only_the_exact_route_and_validates_response_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert_eq!(
                request_line,
                "POST /v1/internal/runtime/volume-transitions HTTP/1.1\r\n"
            );
            let mut content_length = None;
            let mut proof_headers = std::collections::BTreeMap::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
                proof_headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
            let mut body = vec![0; content_length.unwrap()];
            reader.read_exact(&mut body).unwrap();
            assert_eq!(body, REQUEST);
            verify_request_proof(
                RUNTIME_SPINE_METHOD,
                RUNTIME_VOLUME_TRANSITION_PATH,
                &body,
                &proof_headers[NODE_CREDENTIAL_ID_HEADER],
                &proof_headers[NODE_PUBLIC_KEY_SPKI_HEADER],
                &proof_headers[NODE_SIGNATURE_HEADER],
            )
            .unwrap();
            let mut stream = reader.into_inner();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                SUCCESS.len()
            )
            .unwrap();
            stream.write_all(SUCCESS).unwrap();
        });
        let client = RuntimeVolumeTransitionHttpClient::for_loopback_test(
            &format!("http://{address}/"),
            signer(),
        )
        .unwrap();
        let response = client
            .post_a19_signed_json(
                RUNTIME_VOLUME_TRANSITION_PATH,
                REQUEST,
                RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            response,
            SignedVolumeTransitionResponse::Success(SUCCESS.to_vec())
        );
        server.join().unwrap();
    }
}

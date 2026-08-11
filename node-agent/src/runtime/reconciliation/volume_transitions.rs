//! Typed Node recovery port for ambiguous A22 authorization transitions.
//!
//! The port can only issue the exact A19-signed evidence POST. It has no
//! PostgreSQL handle and does not fall back to blockd authority reads, a
//! legacy bearer, or a second transition ledger.

use std::time::Instant;

use futures_util::future::BoxFuture;

use cats_api::runtime_reconciliation::{
    decode_runtime_volume_transition_error, decode_runtime_volume_transition_evidence_success,
    encode_runtime_volume_transition_evidence_request, AuthorizationConsumedReceipt,
    AuthorizationRecord, AuthorizationState, BeginDisposableDeleteConsumedReceipt,
    ContractErrorDetail, ContractName, DeleteCompletionReceipt, Id, LastVolumeTransition,
    RuntimeSpineHttpProblem, RuntimeVolumeTransitionError, RuntimeVolumeTransitionErrorDetail,
    RuntimeVolumeTransitionEvidenceRequest, RuntimeVolumeTransitionEvidenceSuccess,
    TakeoverConsumedReceipt, VolumeAdminState, VolumeAuthorization, VolumeRecord,
    RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
    RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES,
};
use cats_storage::authority::{
    remote_head_is_same_or_later, validate_volume_transition_evidence_bundle,
};

/// Result of strict status/header/error-envelope validation by the shared A19
/// client. The A22 client sees raw bytes only for a valid 200 JSON response;
/// malformed or mismatched HTTP is never promoted to a typed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedVolumeEvidenceResponse {
    Success(Vec<u8>),
    ClosedError { status: u16, body: Vec<u8> },
    PlainRouteNotFound,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeEvidenceTransportFailure {
    Cancelled,
    Timeout,
    Eof,
    Connection,
}

/// Adapter implemented by the shared A19 credential/signing HTTP client.
///
/// Implementations must sign the exact path and canonical body supplied here,
/// bound-read the response to `response_wire_cap + 1`, and cancel/join their
/// request when this returned future is dropped. They must not accept a caller
/// supplied credential, path alias, redirect, or unsigned fallback.
pub trait A19SignedVolumeEvidenceTransport: Send + Sync {
    fn post_a19_signed_json<'a>(
        &'a self,
        exact_path: &'static str,
        canonical_body: Vec<u8>,
        response_wire_cap: usize,
    ) -> BoxFuture<'a, Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>>;
}

/// Deadline-aware blocking transport for the reconciliation effect lane.
///
/// The async port above remains available to async callers.  Production
/// Running effects execute inside `spawn_blocking`, so they use this seam
/// directly and never create a runtime or `block_on` an async future.
pub(crate) trait A19BlockingSignedVolumeEvidenceTransport: Send + Sync {
    fn post_a19_signed_evidence_json(
        &self,
        exact_path: &'static str,
        canonical_body: &[u8],
        response_wire_cap: usize,
        deadline: Instant,
    ) -> Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeEvidenceRecoveryDecision {
    RetryOriginalAuthorization { authorization_id: Id },
    AdoptTakeover(TakeoverConsumedReceipt),
    AdoptDisposableDeleting(BeginDisposableDeleteConsumedReceipt),
    AdoptDeleteCompletion(DeleteCompletionReceipt),
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeEvidenceRecovery {
    Validated {
        evidence: Box<RuntimeVolumeTransitionEvidenceSuccess>,
        decision: Box<VolumeEvidenceRecoveryDecision>,
    },
    AuthorizationEvidenceUnavailable,
    SessionReplacementRequired,
    IdentityRepairRequired,
    RetrySameRequest,
    StopForLocalContract,
    StopForDeploymentMismatch,
    Ambiguous,
}

#[derive(Debug, thiserror::Error)]
pub enum VolumeEvidenceClientError {
    #[error("invalid local A22 evidence request: {0:?}")]
    InvalidRequest(cats_api::runtime_reconciliation::ContractError),
}

pub trait VolumeTransitionEvidencePort: Send + Sync {
    fn recover_authorization<'a>(
        &'a self,
        request: &'a RuntimeVolumeTransitionEvidenceRequest,
    ) -> BoxFuture<'a, Result<VolumeEvidenceRecovery, VolumeEvidenceClientError>>;
}

/// Synchronous signed evidence boundary used only from the blocking Runtime
/// Desired effect lane.
pub(crate) trait SignedVolumeEvidencePort: Send + Sync + 'static {
    fn recover_authorization(
        &self,
        request: &RuntimeVolumeTransitionEvidenceRequest,
        deadline: Instant,
    ) -> Result<VolumeEvidenceRecovery, VolumeEvidenceClientError>;
}

#[derive(Debug, Clone)]
pub struct ControlSignedVolumeEvidenceClient<T> {
    transport: T,
}

#[derive(Debug, Clone)]
pub(crate) struct ControlBlockingSignedVolumeEvidenceClient<T> {
    transport: T,
}

impl<T> ControlBlockingSignedVolumeEvidenceClient<T> {
    pub(crate) fn new(transport: T) -> Self {
        Self { transport }
    }

    #[cfg(test)]
    pub(crate) fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> ControlSignedVolumeEvidenceClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> VolumeTransitionEvidencePort for ControlSignedVolumeEvidenceClient<T>
where
    T: A19SignedVolumeEvidenceTransport,
{
    fn recover_authorization<'a>(
        &'a self,
        request: &'a RuntimeVolumeTransitionEvidenceRequest,
    ) -> BoxFuture<'a, Result<VolumeEvidenceRecovery, VolumeEvidenceClientError>> {
        Box::pin(async move {
            let body = encode_runtime_volume_transition_evidence_request(request)
                .map_err(VolumeEvidenceClientError::InvalidRequest)?;
            let response = self
                .transport
                .post_a19_signed_json(
                    RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
                    body,
                    RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES,
                )
                .await;
            let response = match response {
                Ok(response) => response,
                Err(_) => return Ok(VolumeEvidenceRecovery::Ambiguous),
            };
            Ok(classify_signed_evidence_response(request, response))
        })
    }
}

impl<T> SignedVolumeEvidencePort for ControlBlockingSignedVolumeEvidenceClient<T>
where
    T: A19BlockingSignedVolumeEvidenceTransport + 'static,
{
    fn recover_authorization(
        &self,
        request: &RuntimeVolumeTransitionEvidenceRequest,
        deadline: Instant,
    ) -> Result<VolumeEvidenceRecovery, VolumeEvidenceClientError> {
        let body = encode_runtime_volume_transition_evidence_request(request)
            .map_err(VolumeEvidenceClientError::InvalidRequest)?;
        let response = self.transport.post_a19_signed_evidence_json(
            RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
            &body,
            RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES,
            deadline,
        );
        Ok(match response {
            Ok(response) => classify_signed_evidence_response(request, response),
            Err(_) => VolumeEvidenceRecovery::Ambiguous,
        })
    }
}

/// One pure response classifier shared by async recovery callers and the
/// blocking production effect.  Neither transport may reinterpret malformed
/// bytes or a response bound to another session/authorization.
fn classify_signed_evidence_response(
    request: &RuntimeVolumeTransitionEvidenceRequest,
    response: SignedVolumeEvidenceResponse,
) -> VolumeEvidenceRecovery {
    match response {
        SignedVolumeEvidenceResponse::Success(body) => {
            let Ok(evidence) = decode_runtime_volume_transition_evidence_success(&body) else {
                return VolumeEvidenceRecovery::Ambiguous;
            };
            if evidence.version != request.version
                || evidence.session != request.session
                || evidence.authorization_id != request.authorization_id
            {
                return VolumeEvidenceRecovery::Ambiguous;
            }
            let Ok(decision) = classify_evidence(&evidence) else {
                return VolumeEvidenceRecovery::Ambiguous;
            };
            VolumeEvidenceRecovery::Validated {
                evidence: Box::new(evidence),
                decision: Box::new(decision),
            }
        }
        SignedVolumeEvidenceResponse::ClosedError { status, body } => {
            let Ok(error) = decode_runtime_volume_transition_error(&body) else {
                return VolumeEvidenceRecovery::Ambiguous;
            };
            map_closed_error(status, error, request)
        }
        SignedVolumeEvidenceResponse::PlainRouteNotFound => {
            VolumeEvidenceRecovery::StopForDeploymentMismatch
        }
        SignedVolumeEvidenceResponse::Ambiguous => VolumeEvidenceRecovery::Ambiguous,
    }
}

fn map_closed_error(
    status: u16,
    error: RuntimeVolumeTransitionError,
    request: &RuntimeVolumeTransitionEvidenceRequest,
) -> VolumeEvidenceRecovery {
    match (status, error.error.as_ref()) {
        (
            404,
            RuntimeVolumeTransitionErrorDetail::AuthorizationEvidenceUnavailable {
                authorization_id,
            },
        ) if authorization_id == &request.authorization_id
            && error.message == "authorization evidence is unavailable" =>
        {
            VolumeEvidenceRecovery::AuthorizationEvidenceUnavailable
        }
        (401, RuntimeVolumeTransitionErrorDetail::AuthenticationFailed)
        | (403, RuntimeVolumeTransitionErrorDetail::IdentityNotEligible) => {
            VolumeEvidenceRecovery::IdentityRepairRequired
        }
        (409, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if session_error_binds_request(contract_error.error.as_ref(), request) =>
        {
            VolumeEvidenceRecovery::SessionReplacementRequired
        }
        (429, RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight)
        | (500, RuntimeVolumeTransitionErrorDetail::Internal)
        | (503, RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable) => {
            VolumeEvidenceRecovery::RetrySameRequest
        }
        (status, RuntimeVolumeTransitionErrorDetail::HttpRequestRejected { problem })
            if http_problem_status(*problem) == status =>
        {
            VolumeEvidenceRecovery::StopForLocalContract
        }
        (status, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if contract_error_status(contract_error.error.as_ref()) == status
                && request_contract_error_binds(contract_error.error.as_ref()) =>
        {
            VolumeEvidenceRecovery::StopForLocalContract
        }
        _ => VolumeEvidenceRecovery::Ambiguous,
    }
}

fn request_contract_error_binds(detail: &ContractErrorDetail) -> bool {
    match detail {
        ContractErrorDetail::UnsupportedVersion { contract, .. }
        | ContractErrorDetail::MalformedPayload { contract, .. }
        | ContractErrorDetail::LimitExceeded { contract, .. } => {
            *contract == ContractName::RuntimeVolumeTransitionEvidenceRequest
        }
        _ => false,
    }
}

fn session_error_binds_request(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionEvidenceRequest,
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

fn contract_error_status(detail: &ContractErrorDetail) -> u16 {
    if matches!(detail, ContractErrorDetail::LimitExceeded { .. }) {
        413
    } else {
        400
    }
}

fn classify_evidence(
    evidence: &RuntimeVolumeTransitionEvidenceSuccess,
) -> Result<VolumeEvidenceRecoveryDecision, ()> {
    validate_volume_transition_evidence_bundle(
        &evidence.authorization,
        evidence.current_volume.as_ref(),
        evidence.delete_completion.as_ref(),
        evidence.direct_successor_authorization.as_ref(),
    )
    .map_err(|_| ())?;

    match (
        &evidence.authorization.authorization,
        &evidence.authorization.state,
    ) {
        (authorization, AuthorizationState::Unconsumed) => {
            if exact_unconsumed_predecessor(
                authorization,
                evidence.current_volume.as_ref(),
                evidence.delete_completion.as_ref(),
                evidence.direct_successor_authorization.as_ref(),
            ) {
                Ok(VolumeEvidenceRecoveryDecision::RetryOriginalAuthorization {
                    authorization_id: evidence.authorization_id.clone(),
                })
            } else {
                Ok(VolumeEvidenceRecoveryDecision::Blocked)
            }
        }
        (VolumeAuthorization::Takeover(_), AuthorizationState::Consumed(receipt)) => {
            let AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_ref() else {
                return Err(());
            };
            if closed_takeover_successor(evidence, receipt) {
                Ok(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                    receipt.clone(),
                ))
            } else {
                Ok(VolumeEvidenceRecoveryDecision::Blocked)
            }
        }
        (VolumeAuthorization::DisposableRootDelete(_), AuthorizationState::Consumed(receipt)) => {
            let AuthorizationConsumedReceipt::BeginDisposableDelete(receipt) = receipt.as_ref()
            else {
                return Err(());
            };
            if let Some(completion) = &evidence.delete_completion {
                Ok(VolumeEvidenceRecoveryDecision::AdoptDeleteCompletion(
                    completion.clone(),
                ))
            } else if evidence.current_volume.is_some() {
                Ok(VolumeEvidenceRecoveryDecision::AdoptDisposableDeleting(
                    receipt.clone(),
                ))
            } else {
                Ok(VolumeEvidenceRecoveryDecision::Blocked)
            }
        }
    }
}

fn exact_unconsumed_predecessor(
    authorization: &VolumeAuthorization,
    current: Option<&VolumeRecord>,
    completion: Option<&DeleteCompletionReceipt>,
    direct: Option<&AuthorizationRecord>,
) -> bool {
    if completion.is_some() || direct.is_some() {
        return false;
    }
    let Some(current) = current else {
        return false;
    };
    if !matches!(current.admin_state, VolumeAdminState::Active) {
        return false;
    }
    match authorization {
        VolumeAuthorization::Takeover(authorization) => {
            current.volume_id == authorization.volume_id
                && current.lease_owner.as_ref() == Some(&authorization.expected_attachment_id)
                && current.lease_epoch == authorization.expected_epoch
        }
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            current.volume_id == authorization.volume_id
                && current.lease_owner.as_ref() == Some(&authorization.expected_attachment_id)
                && current.lease_epoch == authorization.expected_epoch
                && current.head == authorization.expected_head
        }
    }
}

fn closed_takeover_successor(
    evidence: &RuntimeVolumeTransitionEvidenceSuccess,
    primary_receipt: &TakeoverConsumedReceipt,
) -> bool {
    if let Some(completion) = evidence.delete_completion.as_ref() {
        return match completion {
            DeleteCompletionReceipt::Normal {
                request,
                deleting_epoch,
                deleting_head,
                ..
            } => {
                request.volume_id == primary_receipt.volume_id
                    && request.expected_unowned_epoch > primary_receipt.resulting_epoch
                    && is_epoch_offset(
                        request.expected_unowned_epoch.get(),
                        deleting_epoch.get(),
                        1,
                    )
                    && remote_head_is_same_or_later(deleting_head, &primary_receipt.resulting_head)
            }
            DeleteCompletionReceipt::DisposableRoot { .. } => evidence
                .direct_successor_authorization
                .as_ref()
                .is_some_and(|direct| {
                    direct_authorization_follows_takeover(direct, primary_receipt)
                }),
        };
    }
    let Some(current) = evidence.current_volume.as_ref() else {
        return false;
    };
    match current.last_transition.as_ref() {
        Some(LastVolumeTransition::Takeover { authorization_id })
            if authorization_id == &evidence.authorization_id =>
        {
            true
        }
        Some(LastVolumeTransition::Takeover { .. })
        | Some(LastVolumeTransition::BeginDisposableDelete { .. }) => {
            evidence
                .direct_successor_authorization
                .as_ref()
                .is_some_and(|direct| {
                    direct_authorization_follows_takeover(direct, primary_receipt)
                })
                && remote_head_is_same_or_later(&current.head, &primary_receipt.resulting_head)
        }
        Some(LastVolumeTransition::Release { request, result }) => {
            ((request.attachment_id == primary_receipt.new_attachment_id
                && request.expected_epoch == primary_receipt.resulting_epoch)
                // A strictly later owner may itself have released. The
                // validated Release pair and higher expected epoch prove the
                // primary takeover was fenced without guessing the omitted
                // intervening markers. Equal epoch with another attachment
                // remains a competing branch and is blocked.
                || request.expected_epoch > primary_receipt.resulting_epoch)
                && is_epoch_offset(
                    request.expected_epoch.get(),
                    result.resulting_epoch.get(),
                    1,
                )
                && remote_head_is_same_or_later(
                    &result.resulting_head,
                    &primary_receipt.resulting_head,
                )
        }
        Some(LastVolumeTransition::BeginDelete { request, result }) => {
            request.volume_id == primary_receipt.volume_id
                && request.expected_unowned_epoch > primary_receipt.resulting_epoch
                && is_epoch_offset(
                    request.expected_unowned_epoch.get(),
                    result.resulting_epoch.get(),
                    1,
                )
                && remote_head_is_same_or_later(
                    &result.resulting_head,
                    &primary_receipt.resulting_head,
                )
        }
        Some(LastVolumeTransition::NormalAcquire { request, result }) => {
            request.volume_id == primary_receipt.volume_id
                // The primary takeover left the Volume owned at this epoch.
                // A later normal acquire therefore needs at least one closed
                // ownership transition before its Unowned predecessor. Equal
                // epoch is a competing branch, while any larger predecessor
                // remains a safe monotonic successor even if intervening
                // release/acquire markers have already been overwritten.
                && request.expected_unowned_epoch > primary_receipt.resulting_epoch
                && is_epoch_offset(
                    request.expected_unowned_epoch.get(),
                    result.resulting_epoch.get(),
                    1,
                )
                && remote_head_is_same_or_later(
                    &result.resulting_head,
                    &primary_receipt.resulting_head,
                )
        }
        None => false,
    }
}

fn is_epoch_offset(base: u64, candidate: u64, offset: u64) -> bool {
    base.checked_add(offset)
        .is_some_and(|value| value == candidate)
}

fn direct_authorization_follows_takeover(
    direct: &AuthorizationRecord,
    primary_receipt: &TakeoverConsumedReceipt,
) -> bool {
    match &direct.authorization {
        VolumeAuthorization::Takeover(authorization) => {
            authorization.volume_id == primary_receipt.volume_id
                && ((authorization.expected_attachment_id == primary_receipt.new_attachment_id
                    && authorization.expected_epoch == primary_receipt.resulting_epoch)
                    || authorization.expected_epoch > primary_receipt.resulting_epoch)
        }
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            authorization.volume_id == primary_receipt.volume_id
                && ((authorization.expected_attachment_id == primary_receipt.new_attachment_id
                    && authorization.expected_epoch == primary_receipt.resulting_epoch)
                    || authorization.expected_epoch > primary_receipt.resulting_epoch)
                && remote_head_is_same_or_later(
                    &authorization.expected_head,
                    &primary_receipt.resulting_head,
                )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use cats_api::runtime_reconciliation::{
        decode_runtime_volume_transition_evidence_request,
        encode_runtime_volume_transition_evidence_request, BeginDeleteRequest,
        DisposableDeleteIsolationBasis, DisposableRootDeleteAuthorization, Epoch, FenceEpoch,
        NormalAcquireRequest, ReleaseRequest, Revision,
    };

    use super::*;

    const REQUEST: &str = r#"{"authorization_id":"auth_01","session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;
    const SUCCESS: &str = r#"{"authorization":{"authorization":{"authorization_id":"auth_01","authorized_node_id":"node_a","desired_revision":8,"expected_attachment_id":"att_old","expected_epoch":3,"host_fence_event_id":"fence_01","kind":"takeover","lease_duration_ms":60000,"new_attachment_id":"att_new","new_placement_epoch":4,"not_after":1720000030000,"volume_id":"vol_root"},"state":{"kind":"consumed","receipt":{"authorization_id":"auth_01","consumed_at":1720000000000,"host_fence_event_id":"fence_01","kind":"takeover","new_attachment_id":"att_new","resulting_epoch":4,"resulting_head":{"generation":0,"root_hash":null,"root_object_id":null},"volume_id":"vol_root"}}},"authorization_id":"auth_01","current_volume":{"admin_state":{"kind":"active"},"durability":"strict","head":{"generation":0,"root_hash":null,"root_object_id":null},"last_transition":{"authorization_id":"auth_01","kind":"takeover"},"lease_epoch":4,"lease_expires_at":1720000060000,"lease_owner":"att_new","size_bytes":4294967296,"volume_id":"vol_root"},"delete_completion":null,"direct_successor_authorization":null,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;
    const UNAVAILABLE: &str = r#"{"error":{"authorization_id":"auth_01","code":"authorization_evidence_unavailable"},"message":"authorization evidence is unavailable","version":1}"#;

    struct FakeSignedTransport {
        response: Mutex<Option<SignedVolumeEvidenceResponse>>,
        seen: Mutex<Vec<(&'static str, Vec<u8>, usize)>>,
    }

    impl FakeSignedTransport {
        fn new(response: SignedVolumeEvidenceResponse) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl A19SignedVolumeEvidenceTransport for FakeSignedTransport {
        fn post_a19_signed_json<'a>(
            &'a self,
            exact_path: &'static str,
            canonical_body: Vec<u8>,
            response_wire_cap: usize,
        ) -> BoxFuture<'a, Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>>
        {
            Box::pin(async move {
                self.seen
                    .lock()
                    .unwrap()
                    .push((exact_path, canonical_body, response_wire_cap));
                Ok(self.response.lock().unwrap().take().unwrap())
            })
        }
    }

    struct FakeBlockingTransport {
        response:
            Mutex<Option<Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>>>,
        seen: Mutex<Vec<(&'static str, Vec<u8>, usize)>>,
    }

    impl FakeBlockingTransport {
        fn new(
            response: Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>,
        ) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl A19BlockingSignedVolumeEvidenceTransport for FakeBlockingTransport {
        fn post_a19_signed_evidence_json(
            &self,
            exact_path: &'static str,
            canonical_body: &[u8],
            response_wire_cap: usize,
            deadline: Instant,
        ) -> Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure> {
            assert!(deadline > Instant::now());
            self.seen.lock().unwrap().push((
                exact_path,
                canonical_body.to_vec(),
                response_wire_cap,
            ));
            self.response.lock().unwrap().take().unwrap()
        }
    }

    struct DropObservedFuture<'a> {
        dropped: &'a AtomicBool,
    }

    impl Future for DropObservedFuture<'_> {
        type Output = Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for DropObservedFuture<'_> {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct CancelTransport {
        dropped: AtomicBool,
    }

    impl A19SignedVolumeEvidenceTransport for CancelTransport {
        fn post_a19_signed_json<'a>(
            &'a self,
            _exact_path: &'static str,
            _canonical_body: Vec<u8>,
            _response_wire_cap: usize,
        ) -> BoxFuture<'a, Result<SignedVolumeEvidenceResponse, VolumeEvidenceTransportFailure>>
        {
            Box::pin(DropObservedFuture {
                dropped: &self.dropped,
            })
        }
    }

    fn request() -> RuntimeVolumeTransitionEvidenceRequest {
        decode_runtime_volume_transition_evidence_request(REQUEST.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn client_uses_only_the_exact_signed_route_and_adopts_closed_takeover() {
        let transport = FakeSignedTransport::new(SignedVolumeEvidenceResponse::Success(
            SUCCESS.as_bytes().to_vec(),
        ));
        let client = ControlSignedVolumeEvidenceClient::new(transport);
        let request = request();
        let recovery = client.recover_authorization(&request).await.unwrap();
        let VolumeEvidenceRecovery::Validated { decision, .. } = recovery else {
            panic!("expected validated evidence")
        };
        assert!(matches!(
            decision.as_ref(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(_)
        ));
        let seen = client.transport().seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH);
        assert_eq!(
            seen[0].1,
            encode_runtime_volume_transition_evidence_request(&request).unwrap()
        );
        assert_eq!(
            seen[0].2,
            RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES
        );
    }

    #[test]
    fn blocking_client_uses_the_same_pure_classifier_and_fixed_route() {
        let request = request();
        let client =
            ControlBlockingSignedVolumeEvidenceClient::new(FakeBlockingTransport::new(Ok(
                SignedVolumeEvidenceResponse::Success(SUCCESS.as_bytes().to_vec()),
            )));
        let recovery = SignedVolumeEvidencePort::recover_authorization(
            &client,
            &request,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            recovery,
            VolumeEvidenceRecovery::Validated { ref decision, .. }
                if matches!(decision.as_ref(), VolumeEvidenceRecoveryDecision::AdoptTakeover(_))
        ));
        let seen = client.transport().seen.lock().unwrap();
        assert_eq!(
            seen.as_slice(),
            &[(
                RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH,
                REQUEST.as_bytes().to_vec(),
                RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES
            )]
        );

        let cancelled = ControlBlockingSignedVolumeEvidenceClient::new(FakeBlockingTransport::new(
            Err(VolumeEvidenceTransportFailure::Cancelled),
        ));
        assert_eq!(
            SignedVolumeEvidencePort::recover_authorization(
                &cancelled,
                &request,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap(),
            VolumeEvidenceRecovery::Ambiguous
        );
    }

    #[test]
    fn a_consumed_direct_successor_closes_the_original_takeover() {
        let mut evidence =
            decode_runtime_volume_transition_evidence_success(SUCCESS.as_bytes()).unwrap();
        let AuthorizationState::Consumed(primary_receipt) = &evidence.authorization.state else {
            unreachable!()
        };
        let AuthorizationConsumedReceipt::Takeover(primary_receipt) = primary_receipt.as_ref()
        else {
            unreachable!()
        };
        let primary_receipt = primary_receipt.clone();
        let direct_id = Id::new("auth_02").unwrap();
        let next_attachment = Id::new("att_next").unwrap();
        evidence.direct_successor_authorization = Some(AuthorizationRecord {
            authorization: VolumeAuthorization::Takeover(
                cats_api::runtime_reconciliation::VolumeTakeoverAuthorization {
                    authorization_id: direct_id.clone(),
                    authorized_node_id: Id::new("node_b").unwrap(),
                    host_fence_event_id: Id::new("fence_02").unwrap(),
                    volume_id: primary_receipt.volume_id.clone(),
                    expected_attachment_id: primary_receipt.new_attachment_id.clone(),
                    expected_epoch: primary_receipt.resulting_epoch,
                    new_attachment_id: next_attachment.clone(),
                    desired_revision: cats_api::runtime_reconciliation::Revision::new(9).unwrap(),
                    new_placement_epoch: cats_api::runtime_reconciliation::Epoch::new(5).unwrap(),
                    lease_duration_ms: 60_000,
                    not_after: cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_040_000)
                        .unwrap(),
                },
            ),
            state: AuthorizationState::Consumed(Box::new(AuthorizationConsumedReceipt::Takeover(
                TakeoverConsumedReceipt {
                    authorization_id: direct_id.clone(),
                    host_fence_event_id: Id::new("fence_02").unwrap(),
                    volume_id: primary_receipt.volume_id.clone(),
                    new_attachment_id: next_attachment.clone(),
                    resulting_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(5).unwrap(),
                    resulting_head: primary_receipt.resulting_head.clone(),
                    consumed_at: cats_api::runtime_reconciliation::UnixMillis::new(
                        1_720_000_001_000,
                    )
                    .unwrap(),
                },
            ))),
        });
        let current = evidence.current_volume.as_mut().unwrap();
        current.lease_owner = Some(next_attachment);
        current.lease_epoch = cats_api::runtime_reconciliation::FenceEpoch::new(5).unwrap();
        current.lease_expires_at =
            Some(cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_061_000).unwrap());
        current.last_transition = Some(LastVolumeTransition::Takeover {
            authorization_id: direct_id,
        });

        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        let higher_id = Id::new("auth_03").unwrap();
        let higher_attachment = Id::new("att_higher").unwrap();
        evidence.direct_successor_authorization = Some(AuthorizationRecord {
            authorization: VolumeAuthorization::Takeover(
                cats_api::runtime_reconciliation::VolumeTakeoverAuthorization {
                    authorization_id: higher_id.clone(),
                    authorized_node_id: Id::new("node_c").unwrap(),
                    host_fence_event_id: Id::new("fence_03").unwrap(),
                    volume_id: primary_receipt.volume_id.clone(),
                    expected_attachment_id: Id::new("att_next").unwrap(),
                    expected_epoch: FenceEpoch::new(5).unwrap(),
                    new_attachment_id: higher_attachment.clone(),
                    desired_revision: Revision::new(10).unwrap(),
                    new_placement_epoch: Epoch::new(6).unwrap(),
                    lease_duration_ms: 60_000,
                    not_after: cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_050_000)
                        .unwrap(),
                },
            ),
            state: AuthorizationState::Consumed(Box::new(AuthorizationConsumedReceipt::Takeover(
                TakeoverConsumedReceipt {
                    authorization_id: higher_id.clone(),
                    host_fence_event_id: Id::new("fence_03").unwrap(),
                    volume_id: primary_receipt.volume_id.clone(),
                    new_attachment_id: higher_attachment.clone(),
                    resulting_epoch: FenceEpoch::new(6).unwrap(),
                    resulting_head: primary_receipt.resulting_head.clone(),
                    consumed_at: cats_api::runtime_reconciliation::UnixMillis::new(
                        1_720_000_002_000,
                    )
                    .unwrap(),
                },
            ))),
        });
        let current = evidence.current_volume.as_mut().unwrap();
        current.lease_owner = Some(higher_attachment);
        current.lease_epoch = FenceEpoch::new(6).unwrap();
        current.lease_expires_at =
            Some(cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_062_000).unwrap());
        current.last_transition = Some(LastVolumeTransition::Takeover {
            authorization_id: higher_id,
        });
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        // Equal epoch plus another predecessor attachment is a competing
        // branch, even when the direct authorization/receipt are otherwise
        // internally consistent.
        let direct = evidence.direct_successor_authorization.as_mut().unwrap();
        let VolumeAuthorization::Takeover(authorization) = &mut direct.authorization else {
            unreachable!()
        };
        authorization.expected_epoch = primary_receipt.resulting_epoch;
        let AuthorizationState::Consumed(receipt) = &mut direct.state else {
            unreachable!()
        };
        let AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_mut() else {
            unreachable!()
        };
        receipt.resulting_epoch =
            FenceEpoch::new(primary_receipt.resulting_epoch.get() + 1).unwrap();
        let current = evidence.current_volume.as_mut().unwrap();
        current.lease_epoch = receipt.resulting_epoch;
        assert!(
            !matches!(
                classify_evidence(&evidence),
                Ok(VolumeEvidenceRecoveryDecision::AdoptTakeover(_))
            ),
            "an equal-epoch foreign direct authorization must not close the primary takeover"
        );
    }

    fn takeover_then_normal_reacquire_evidence() -> (
        RuntimeVolumeTransitionEvidenceSuccess,
        TakeoverConsumedReceipt,
    ) {
        let mut evidence =
            decode_runtime_volume_transition_evidence_success(SUCCESS.as_bytes()).unwrap();
        let AuthorizationState::Consumed(primary_receipt) = &evidence.authorization.state else {
            unreachable!()
        };
        let AuthorizationConsumedReceipt::Takeover(primary_receipt) = primary_receipt.as_ref()
        else {
            unreachable!()
        };
        let primary_receipt = primary_receipt.clone();
        let takeover_volume = evidence.current_volume.take().unwrap();
        let (released, _) = cats_storage::authority::release(
            &takeover_volume,
            &ReleaseRequest {
                volume_id: primary_receipt.volume_id.clone(),
                transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "55555555555555555555555555555555",
                )
                .unwrap(),
                attachment_id: primary_receipt.new_attachment_id.clone(),
                expected_epoch: primary_receipt.resulting_epoch,
            },
        )
        .unwrap();
        let request = NormalAcquireRequest {
            volume_id: primary_receipt.volume_id.clone(),
            transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                "66666666666666666666666666666666",
            )
            .unwrap(),
            attachment_id: Id::new("att_reacquired").unwrap(),
            expected_unowned_epoch: released.lease_epoch,
            desired_revision: Revision::new(9).unwrap(),
            placement_epoch: Epoch::new(5).unwrap(),
            lease_duration_ms: 60_000,
        };
        let (reacquired, _) = cats_storage::authority::normal_acquire(
            &released,
            &request,
            cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_010_000).unwrap(),
        )
        .unwrap();
        evidence.current_volume = Some(reacquired);
        (evidence, primary_receipt)
    }

    #[test]
    fn takeover_release_then_normal_reacquire_closes_the_original_takeover() {
        let (evidence, primary_receipt) = takeover_then_normal_reacquire_evidence();
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt)
        );
    }

    #[test]
    fn takeover_higher_release_requires_a_strictly_later_closed_branch() {
        let (mut evidence, primary_receipt) = takeover_then_normal_reacquire_evidence();
        let reacquired = evidence.current_volume.take().unwrap();
        let (released, _) = cats_storage::authority::release(
            &reacquired,
            &ReleaseRequest {
                volume_id: primary_receipt.volume_id.clone(),
                transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "77777777777777777777777777777777",
                )
                .unwrap(),
                attachment_id: reacquired.lease_owner.clone().unwrap(),
                expected_epoch: reacquired.lease_epoch,
            },
        )
        .unwrap();
        evidence.current_volume = Some(released);
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        // Another attachment at the primary epoch is a competing branch, not
        // a historical successor. Even an internally consistent Release pair
        // must not close the primary takeover without a strictly later epoch.
        let current = evidence.current_volume.as_mut().unwrap();
        let Some(LastVolumeTransition::Release { request, result }) =
            current.last_transition.as_mut()
        else {
            unreachable!()
        };
        request.expected_epoch = primary_receipt.resulting_epoch;
        result.resulting_epoch =
            FenceEpoch::new(primary_receipt.resulting_epoch.get() + 1).unwrap();
        current.lease_epoch = result.resulting_epoch;
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::Blocked
        );
    }

    #[test]
    fn takeover_higher_normal_delete_and_completion_close_the_primary() {
        let (mut evidence, primary_receipt) = takeover_then_normal_reacquire_evidence();
        let reacquired = evidence.current_volume.take().unwrap();
        let (released, _) = cats_storage::authority::release(
            &reacquired,
            &ReleaseRequest {
                volume_id: primary_receipt.volume_id.clone(),
                transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "88888888888888888888888888888888",
                )
                .unwrap(),
                attachment_id: reacquired.lease_owner.clone().unwrap(),
                expected_epoch: reacquired.lease_epoch,
            },
        )
        .unwrap();
        let request = BeginDeleteRequest {
            delete_id: Id::new("delete_after_later_owner").unwrap(),
            disk_id: Id::new("disk_root").unwrap(),
            volume_id: primary_receipt.volume_id.clone(),
            expected_unowned_epoch: released.lease_epoch,
            expected_head: released.head.clone(),
        };
        let (deleting, _) = cats_storage::authority::begin_delete(&released, &request).unwrap();
        evidence.current_volume = Some(deleting.clone());
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        evidence.current_volume = None;
        evidence.delete_completion = Some(
            cats_storage::authority::complete_normal_delete(
                &deleting,
                cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_090_000).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        let DeleteCompletionReceipt::Normal {
            request,
            deleting_epoch,
            ..
        } = evidence.delete_completion.as_mut().unwrap()
        else {
            unreachable!()
        };
        request.expected_unowned_epoch = primary_receipt.resulting_epoch;
        *deleting_epoch = FenceEpoch::new(primary_receipt.resulting_epoch.get() + 1).unwrap();
        assert!(
            !matches!(
                classify_evidence(&evidence),
                Ok(VolumeEvidenceRecoveryDecision::AdoptTakeover(_))
            ),
            "an equal-epoch foreign delete branch must not close the primary takeover"
        );
    }

    #[test]
    fn takeover_higher_disposable_delete_and_completion_require_signed_direct_proof() {
        let (mut evidence, primary_receipt) = takeover_then_normal_reacquire_evidence();
        let predecessor = evidence.current_volume.take().unwrap();
        let authorization_id = Id::new("auth_disposable_higher").unwrap();
        let authorization = DisposableRootDeleteAuthorization {
            authorization_id: authorization_id.clone(),
            authorized_node_id: Id::new("node_c").unwrap(),
            delete_id: Id::new("delete_disposable_higher").unwrap(),
            disk_id: Id::new("disk_root").unwrap(),
            volume_id: primary_receipt.volume_id.clone(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(10).unwrap(),
            placement_epoch: Epoch::new(6).unwrap(),
            expected_attachment_id: predecessor.lease_owner.clone().unwrap(),
            expected_epoch: predecessor.lease_epoch,
            expected_head: predecessor.head.clone(),
            isolation_basis: DisposableDeleteIsolationBasis::HostFenceEvent {
                event_id: Id::new("fence_disposable_higher").unwrap(),
            },
            not_after: cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_100_000)
                .unwrap(),
        };
        let receipt = BeginDisposableDeleteConsumedReceipt {
            authorization_id: authorization_id.clone(),
            volume_id: primary_receipt.volume_id.clone(),
            disk_id: authorization.disk_id.clone(),
            cat_id: authorization.cat_id.clone(),
            delete_id: authorization.delete_id.clone(),
            prior_attachment_id: authorization.expected_attachment_id.clone(),
            resulting_epoch: FenceEpoch::new(authorization.expected_epoch.get() + 1).unwrap(),
            resulting_head: authorization.expected_head.clone(),
            consumed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_020_000)
                .unwrap(),
        };
        let direct = AuthorizationRecord {
            authorization: VolumeAuthorization::DisposableRootDelete(authorization.clone()),
            state: AuthorizationState::Consumed(Box::new(
                AuthorizationConsumedReceipt::BeginDisposableDelete(receipt.clone()),
            )),
        };
        let mut deleting = predecessor;
        deleting.admin_state = VolumeAdminState::Deleting {
            delete_id: authorization.delete_id.clone(),
        };
        deleting.lease_owner = None;
        deleting.lease_epoch = receipt.resulting_epoch;
        deleting.lease_expires_at = None;
        deleting.last_transition = Some(LastVolumeTransition::BeginDisposableDelete {
            authorization_id: authorization_id.clone(),
        });
        evidence.current_volume = Some(deleting.clone());
        evidence.direct_successor_authorization = Some(direct.clone());
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        let mut equal_epoch = evidence.clone();
        let equal_direct = equal_epoch.direct_successor_authorization.as_mut().unwrap();
        let VolumeAuthorization::DisposableRootDelete(equal_authorization) =
            &mut equal_direct.authorization
        else {
            unreachable!()
        };
        equal_authorization.expected_epoch = primary_receipt.resulting_epoch;
        let AuthorizationState::Consumed(equal_receipt) = &mut equal_direct.state else {
            unreachable!()
        };
        let AuthorizationConsumedReceipt::BeginDisposableDelete(equal_receipt) =
            equal_receipt.as_mut()
        else {
            unreachable!()
        };
        equal_receipt.resulting_epoch =
            FenceEpoch::new(primary_receipt.resulting_epoch.get() + 1).unwrap();
        equal_epoch.current_volume.as_mut().unwrap().lease_epoch = equal_receipt.resulting_epoch;
        assert!(
            !matches!(
                classify_evidence(&equal_epoch),
                Ok(VolumeEvidenceRecoveryDecision::AdoptTakeover(_))
            ),
            "equal-epoch foreign disposable authority must not close the primary takeover"
        );

        let mut regressed_head = evidence.clone();
        let AuthorizationState::Consumed(primary) = &mut regressed_head.authorization.state else {
            unreachable!()
        };
        let AuthorizationConsumedReceipt::Takeover(primary) = primary.as_mut() else {
            unreachable!()
        };
        primary.resulting_head = cats_api::runtime_reconciliation::RemoteHead {
            generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
            root_hash: Some(cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                [0x44; 32],
            )),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new("roots/primary-1").unwrap(),
            ),
        };
        assert!(
            !matches!(
                classify_evidence(&regressed_head),
                Ok(VolumeEvidenceRecoveryDecision::AdoptTakeover(_))
            ),
            "a direct disposable successor behind the primary head must be rejected"
        );

        evidence.current_volume = None;
        evidence.delete_completion = Some(
            cats_storage::authority::complete_disposable_root_delete(
                &deleting,
                &direct,
                cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_090_000).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            classify_evidence(&evidence).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt.clone())
        );

        evidence.direct_successor_authorization = None;
        assert!(
            classify_evidence(&evidence).is_err(),
            "a disposable completion is not self-authenticating without its direct authorization"
        );
    }

    #[test]
    fn takeover_normal_reacquire_requires_a_closed_monotonic_successor_chain() {
        let (mut split, _) = takeover_then_normal_reacquire_evidence();
        let current = split.current_volume.as_mut().unwrap();
        let Some(LastVolumeTransition::NormalAcquire { request, result }) =
            current.last_transition.as_mut()
        else {
            unreachable!()
        };
        request.expected_unowned_epoch = FenceEpoch::new(4).unwrap();
        result.resulting_epoch = FenceEpoch::new(5).unwrap();
        current.lease_epoch = result.resulting_epoch;
        assert_eq!(
            classify_evidence(&split).unwrap(),
            VolumeEvidenceRecoveryDecision::Blocked
        );

        let (mut nonmonotonic, _) = takeover_then_normal_reacquire_evidence();
        let current = nonmonotonic.current_volume.as_mut().unwrap();
        let Some(LastVolumeTransition::NormalAcquire { request, result }) =
            current.last_transition.as_mut()
        else {
            unreachable!()
        };
        request.expected_unowned_epoch = FenceEpoch::new(3).unwrap();
        result.resulting_epoch = FenceEpoch::new(4).unwrap();
        current.lease_epoch = result.resulting_epoch;
        assert_eq!(
            classify_evidence(&nonmonotonic).unwrap(),
            VolumeEvidenceRecoveryDecision::Blocked
        );

        let (mut later, primary_receipt) = takeover_then_normal_reacquire_evidence();
        let current = later.current_volume.as_mut().unwrap();
        let Some(LastVolumeTransition::NormalAcquire { request, result }) =
            current.last_transition.as_mut()
        else {
            unreachable!()
        };
        request.expected_unowned_epoch = FenceEpoch::new(7).unwrap();
        result.resulting_epoch = FenceEpoch::new(8).unwrap();
        current.lease_epoch = result.resulting_epoch;
        assert_eq!(
            classify_evidence(&later).unwrap(),
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt)
        );

        let (mut foreign, _) = takeover_then_normal_reacquire_evidence();
        let current = foreign.current_volume.as_mut().unwrap();
        current.volume_id = Id::new("vol_foreign").unwrap();
        let Some(LastVolumeTransition::NormalAcquire { request, result }) =
            current.last_transition.as_mut()
        else {
            unreachable!()
        };
        request.volume_id = current.volume_id.clone();
        result.volume_id = current.volume_id.clone();
        assert!(classify_evidence(&foreign).is_err());
    }

    #[tokio::test]
    async fn unavailable_is_blocked_only_when_the_typed_id_matches() {
        let request = request();
        let client = ControlSignedVolumeEvidenceClient::new(FakeSignedTransport::new(
            SignedVolumeEvidenceResponse::ClosedError {
                status: 404,
                body: UNAVAILABLE.as_bytes().to_vec(),
            },
        ));
        assert_eq!(
            client.recover_authorization(&request).await.unwrap(),
            VolumeEvidenceRecovery::AuthorizationEvidenceUnavailable
        );

        let mismatched = UNAVAILABLE.replace("auth_01", "auth_other");
        let client = ControlSignedVolumeEvidenceClient::new(FakeSignedTransport::new(
            SignedVolumeEvidenceResponse::ClosedError {
                status: 404,
                body: mismatched.into_bytes(),
            },
        ));
        assert_eq!(
            client.recover_authorization(&request).await.unwrap(),
            VolumeEvidenceRecovery::Ambiguous
        );
    }

    #[tokio::test]
    async fn self_contradictory_nested_contract_error_is_ambiguous() {
        let invalid = serde_json::json!({
            "version": 1,
            "error": {
                "code": "contract_error",
                "contract_error": {
                    "version": 1,
                    "error": {
                        "code": "stale_observation_sequence",
                        "node_id": "node_a",
                        "agent_session_epoch": 2,
                        "presented_heartbeat_sequence": 20,
                        "last_accepted_heartbeat_sequence": 19,
                    },
                    "message": "not stale",
                },
            },
            "message": "invalid nested error",
        });
        let client = ControlSignedVolumeEvidenceClient::new(FakeSignedTransport::new(
            SignedVolumeEvidenceResponse::ClosedError {
                status: 409,
                body: serde_json::to_vec(&invalid).unwrap(),
            },
        ));

        assert_eq!(
            client.recover_authorization(&request()).await.unwrap(),
            VolumeEvidenceRecovery::Ambiguous
        );
    }

    #[test]
    fn session_error_must_bind_the_presented_node_and_epoch() {
        let request = request();
        let error = |node_id: &str, presented_epoch: u64| RuntimeVolumeTransitionError {
            version: request.version,
            error: Box::new(RuntimeVolumeTransitionErrorDetail::ContractError {
                contract_error: cats_api::runtime_reconciliation::ContractError {
                    version: request.version,
                    error: Box::new(ContractErrorDetail::StaleSession {
                        node_id: Id::new(node_id).unwrap(),
                        presented_agent_session_epoch:
                            cats_api::runtime_reconciliation::Epoch::new(presented_epoch).unwrap(),
                        current_agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(
                            9,
                        )
                        .unwrap(),
                    }),
                    message: "stale session".to_owned(),
                },
            }),
            message: "stale session".to_owned(),
        };

        assert_eq!(
            map_closed_error(409, error("node_a", 2), &request),
            VolumeEvidenceRecovery::SessionReplacementRequired
        );
        assert_eq!(
            map_closed_error(409, error("node_other", 2), &request),
            VolumeEvidenceRecovery::Ambiguous
        );
        assert_eq!(
            map_closed_error(409, error("node_a", 8), &request),
            VolumeEvidenceRecovery::Ambiguous
        );
    }

    #[tokio::test]
    async fn invalid_or_mismatched_success_never_advances_recovery() {
        let request = request();
        let client = ControlSignedVolumeEvidenceClient::new(FakeSignedTransport::new(
            SignedVolumeEvidenceResponse::Success(b"{}".to_vec()),
        ));
        assert!(matches!(
            client.recover_authorization(&request).await.unwrap(),
            VolumeEvidenceRecovery::Ambiguous
        ));

        let mut success =
            decode_runtime_volume_transition_evidence_success(SUCCESS.as_bytes()).unwrap();
        success.session.agent_session_epoch =
            cats_api::runtime_reconciliation::Epoch::new(3).unwrap();
        let body =
            cats_api::runtime_reconciliation::encode_runtime_volume_transition_evidence_success(
                &success,
            )
            .unwrap();
        let client = ControlSignedVolumeEvidenceClient::new(FakeSignedTransport::new(
            SignedVolumeEvidenceResponse::Success(body),
        ));
        assert!(matches!(
            client.recover_authorization(&request).await.unwrap(),
            VolumeEvidenceRecovery::Ambiguous
        ));

        let mut success: serde_json::Value = serde_json::from_str(SUCCESS).unwrap();
        success["authorization"]["authorization"]["authorized_node_id"] = "node_other".into();
        let body = serde_json::to_vec(&success).unwrap();
        let client = ControlSignedVolumeEvidenceClient::new(FakeSignedTransport::new(
            SignedVolumeEvidenceResponse::Success(body),
        ));
        assert!(matches!(
            client.recover_authorization(&request).await.unwrap(),
            VolumeEvidenceRecovery::Ambiguous
        ));
    }

    #[test]
    fn cancelling_recovery_drops_the_in_flight_signed_transport_future() {
        let client = ControlSignedVolumeEvidenceClient::new(CancelTransport {
            dropped: AtomicBool::new(false),
        });
        let request = request();
        let mut recovery = client.recover_authorization(&request);
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            recovery.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert!(!client.transport().dropped.load(Ordering::SeqCst));
        drop(recovery);
        assert!(client.transport().dropped.load(Ordering::SeqCst));
    }
}

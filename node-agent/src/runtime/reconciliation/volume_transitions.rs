//! Typed Node recovery port for ambiguous A22 authorization transitions.
//!
//! The port can only issue the exact A19-signed evidence POST. It has no
//! PostgreSQL handle and does not fall back to blockd authority reads, a
//! legacy bearer, or a second transition ledger.

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

#[derive(Debug, Clone)]
pub struct ControlSignedVolumeEvidenceClient<T> {
    transport: T,
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
            match response {
                SignedVolumeEvidenceResponse::Success(body) => {
                    let Ok(evidence) = decode_runtime_volume_transition_evidence_success(&body)
                    else {
                        return Ok(VolumeEvidenceRecovery::Ambiguous);
                    };
                    if evidence.version != request.version
                        || evidence.session != request.session
                        || evidence.authorization_id != request.authorization_id
                    {
                        return Ok(VolumeEvidenceRecovery::Ambiguous);
                    }
                    if authorization_node_id(&evidence.authorization) != &request.session.node_id {
                        return Ok(VolumeEvidenceRecovery::Ambiguous);
                    }
                    let Ok(decision) = classify_evidence(&evidence) else {
                        return Ok(VolumeEvidenceRecovery::Ambiguous);
                    };
                    Ok(VolumeEvidenceRecovery::Validated {
                        evidence: Box::new(evidence),
                        decision: Box::new(decision),
                    })
                }
                SignedVolumeEvidenceResponse::ClosedError { status, body } => {
                    let Ok(error) = decode_runtime_volume_transition_error(&body) else {
                        return Ok(VolumeEvidenceRecovery::Ambiguous);
                    };
                    Ok(map_closed_error(status, error, request))
                }
                SignedVolumeEvidenceResponse::PlainRouteNotFound => {
                    Ok(VolumeEvidenceRecovery::StopForDeploymentMismatch)
                }
                SignedVolumeEvidenceResponse::Ambiguous => Ok(VolumeEvidenceRecovery::Ambiguous),
            }
        })
    }
}

fn authorization_node_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.authorized_node_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            &authorization.authorized_node_id
        }
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
                is_epoch_offset(
                    primary_receipt.resulting_epoch.get(),
                    request.expected_unowned_epoch.get(),
                    1,
                ) && is_epoch_offset(
                    primary_receipt.resulting_epoch.get(),
                    deleting_epoch.get(),
                    2,
                ) && remote_head_is_same_or_later(deleting_head, &primary_receipt.resulting_head)
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
        | Some(LastVolumeTransition::BeginDisposableDelete { .. }) => evidence
            .direct_successor_authorization
            .as_ref()
            .is_some_and(|direct| direct_authorization_follows_takeover(direct, primary_receipt)),
        Some(LastVolumeTransition::Release { request, result }) => {
            request.attachment_id == primary_receipt.new_attachment_id
                && request.expected_epoch == primary_receipt.resulting_epoch
                && is_epoch_offset(
                    primary_receipt.resulting_epoch.get(),
                    result.resulting_epoch.get(),
                    1,
                )
                && remote_head_is_same_or_later(
                    &result.resulting_head,
                    &primary_receipt.resulting_head,
                )
        }
        Some(LastVolumeTransition::BeginDelete { request, result }) => {
            is_epoch_offset(
                primary_receipt.resulting_epoch.get(),
                request.expected_unowned_epoch.get(),
                1,
            ) && is_epoch_offset(
                primary_receipt.resulting_epoch.get(),
                result.resulting_epoch.get(),
                2,
            ) && remote_head_is_same_or_later(
                &result.resulting_head,
                &primary_receipt.resulting_head,
            )
        }
        Some(LastVolumeTransition::NormalAcquire { .. }) | None => false,
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
                && authorization.expected_attachment_id == primary_receipt.new_attachment_id
                && authorization.expected_epoch == primary_receipt.resulting_epoch
        }
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            authorization.volume_id == primary_receipt.volume_id
                && authorization.expected_attachment_id == primary_receipt.new_attachment_id
                && authorization.expected_epoch == primary_receipt.resulting_epoch
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
        encode_runtime_volume_transition_evidence_request,
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
            VolumeEvidenceRecoveryDecision::AdoptTakeover(primary_receipt)
        );
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

        let mut success =
            decode_runtime_volume_transition_evidence_success(SUCCESS.as_bytes()).unwrap();
        let VolumeAuthorization::Takeover(authorization) = &mut success.authorization.authorization
        else {
            unreachable!()
        };
        authorization.authorized_node_id = Id::new("node_other").unwrap();
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

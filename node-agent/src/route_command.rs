//! Signed Node pull/result runner for per-Endpoint Route operations.
//!
//! Control owns the durable Route operation lane. The Node executes each
//! exact command only through the Host-global lifecycle admission registry and
//! retains its exact response in the owned runner until Control acknowledges
//! it. A process/session loss closes every registry gate, so an old response
//! cannot authorize a replacement AgentSession.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{
    AgentSession, ContractVersion, RandomId128, RouteGateBinding, Sequence, SessionBinding,
    Sha256Digest,
};
use cats_api::runtime_route::{
    decode_route_command_batch, decode_route_result_stored_ack, decode_runtime_route_error,
    encode_route_command_poll_request, encode_route_result_commit_request,
    validate_route_command_batch_for_poll, validate_route_result_stored_ack, RouteClosedResult,
    RouteCommand, RouteCommandBatch, RouteCommandEnvelope, RouteCommandPollRequest,
    RouteCommandPredecessor, RouteCommandResponse, RouteNodeResult, RouteNodeRingAck,
    RouteRejectedResult, RouteRejectionReason, RouteResultCommitRequest, RouteResultStoredAck,
    RouteServingBinding, RouteServingResult, RuntimeRouteError, ROUTE_COMMAND_BATCH_MAX_WIRE_BYTES,
    ROUTE_COMMAND_POLL_PATH, ROUTE_ERROR_MAX_WIRE_BYTES, ROUTE_INTERNAL_METHOD,
    ROUTE_RESULT_COMMIT_PATH, ROUTE_RESULT_STORED_ACK_MAX_WIRE_BYTES,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::admission::{
    DisableRoute, DisableRouteOutcome, EnableRoute, EnableRouteOutcome, RouteInterlockError,
};
use crate::admission_registry::{LifecycleAdmissionRegistry, LifecycleAdmissionRegistryError};
use crate::route_grant_v2::RouteGrantV2Verifier;

#[cfg(not(test))]
const RETRY_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const RETRY_DELAY: Duration = Duration::from_millis(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const ADMISSION_RECEIPT_DOMAIN: &[u8] = b"cats.node.route-admission-receipt.v1";

pub type RoutePollFuture =
    Pin<Box<dyn Future<Output = RouteTransportAttempt<RouteCommandBatch>> + Send + 'static>>;
pub type RouteCommitFuture =
    Pin<Box<dyn Future<Output = RouteTransportAttempt<RouteResultStoredAck>> + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTransportRetryReason {
    Transport,
    InvalidResponse,
    Backpressure,
    ServerFailure,
}

#[derive(Debug)]
pub enum RouteTransportAttempt<T> {
    Accepted(T),
    Rejected {
        status: u16,
        error: RuntimeRouteError,
    },
    RetryExact(RouteTransportRetryReason),
    RouteUnavailable,
}

pub trait RouteCommandTransport: Send + Sync + 'static {
    fn poll(&self, exact_body: Vec<u8>) -> RoutePollFuture;
    fn commit(&self, exact_body: Vec<u8>) -> RouteCommitFuture;
}

#[derive(Clone)]
pub struct RouteCommandHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::Client,
}

impl std::fmt::Debug for RouteCommandHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteCommandHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl RouteCommandHttpClient {
    pub fn for_production(
        control_plane_origin: &str,
        registration: &crate::agent_registration::AgentRegistrationConfig,
    ) -> anyhow::Result<Self> {
        let origin = reqwest::Url::parse(control_plane_origin)
            .context("parse Route command Control origin")?;
        anyhow::ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "Route command Control origin must be one HTTPS origin"
        );
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(RESPONSE_TIMEOUT)
            .build()
            .context("build Route command HTTP client")?;
        Ok(Self {
            origin,
            signer: registration.runtime_request_signer(),
            client,
        })
    }

    async fn post<T>(
        &self,
        path: &'static str,
        exact_body: Vec<u8>,
        success_cap: usize,
        decode_success: fn(&[u8]) -> Result<T, cats_api::runtime_route::RuntimeRouteContractError>,
    ) -> RouteTransportAttempt<T> {
        let proof = self.signer.sign(ROUTE_INTERNAL_METHOD, path, &exact_body);
        let url = self
            .origin
            .join(path)
            .expect("validated origin accepts fixed absolute Route path");
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(exact_body)
            .send()
            .await;
        classify_response(response, success_cap, decode_success).await
    }
}

impl RouteCommandTransport for RouteCommandHttpClient {
    fn poll(&self, exact_body: Vec<u8>) -> RoutePollFuture {
        let client = self.clone();
        Box::pin(async move {
            client
                .post(
                    ROUTE_COMMAND_POLL_PATH,
                    exact_body,
                    ROUTE_COMMAND_BATCH_MAX_WIRE_BYTES,
                    decode_route_command_batch,
                )
                .await
        })
    }

    fn commit(&self, exact_body: Vec<u8>) -> RouteCommitFuture {
        let client = self.clone();
        Box::pin(async move {
            client
                .post(
                    ROUTE_RESULT_COMMIT_PATH,
                    exact_body,
                    ROUTE_RESULT_STORED_ACK_MAX_WIRE_BYTES,
                    decode_route_result_stored_ack,
                )
                .await
        })
    }
}

#[derive(Debug, Error)]
pub enum RouteCommandRunnerError {
    #[error("invalid runtime Route contract at {context}")]
    InvalidContract { context: &'static str },
    #[error("runtime Route registry is unavailable: {0}")]
    Registry(#[from] LifecycleAdmissionRegistryError),
    #[error("runtime Route AdmissionCell is unavailable: {0}")]
    Interlock(#[from] RouteInterlockError),
    #[error("runtime Route poll sequence is exhausted")]
    SequenceExhausted,
    #[error("installed Route Grant public ring is unavailable")]
    RingUnavailable,
    #[error("runtime Route transport path is unavailable: {path}")]
    RouteUnavailable { path: &'static str },
    #[error("runtime Route transport rejected {path} with HTTP {status}: {error:?}")]
    Rejected {
        path: &'static str,
        status: u16,
        error: RuntimeRouteError,
    },
}

/// One process-owned Route delivery lane. Commands are endpoint-ordered in a
/// poll batch and each exact result is settled before the next poll.
pub struct RouteCommandRunner {
    session: AgentSession,
    transport: Arc<dyn RouteCommandTransport>,
    registry: Arc<LifecycleAdmissionRegistry>,
    verifier: Arc<RouteGrantV2Verifier>,
    request_sequence: u64,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl RouteCommandRunner {
    pub fn new(
        session: AgentSession,
        transport: Arc<dyn RouteCommandTransport>,
        registry: Arc<LifecycleAdmissionRegistry>,
        verifier: Arc<RouteGrantV2Verifier>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self, RouteCommandRunnerError> {
        if registry.current_agent_session()? != session_binding(&session) {
            return Err(RouteCommandRunnerError::InvalidContract {
                context: "registry AgentSession differs from Route runner",
            });
        }
        Ok(Self {
            session,
            transport,
            registry,
            verifier,
            request_sequence: 1,
            shutdown,
        })
    }

    pub async fn run(mut self) -> Result<(), RouteCommandRunnerError> {
        loop {
            if *self.shutdown.borrow() {
                return Ok(());
            }
            let poll = self.current_poll()?;
            let exact_poll = encode_route_command_poll_request(&poll).map_err(|_| {
                RouteCommandRunnerError::InvalidContract {
                    context: "encode Route poll",
                }
            })?;
            // The sequence, ring ACK identity and loaded-ring digest are one
            // exact signed request. A transient response must never rebuild
            // that request: Control's monotonic ACK replay guard correctly
            // treats a different body at the same sequence as a conflict.
            let batch = loop {
                match self.transport.poll(exact_poll.clone()).await {
                    RouteTransportAttempt::Accepted(batch) => {
                        validate_route_command_batch_for_poll(&batch, &poll, &self.session)
                            .map_err(|_| RouteCommandRunnerError::InvalidContract {
                                context: "validate Route batch echo",
                            })?;
                        break batch;
                    }
                    RouteTransportAttempt::RetryExact(_) => {
                        self.wait_or_shutdown().await;
                        if *self.shutdown.borrow() {
                            return Ok(());
                        }
                    }
                    RouteTransportAttempt::RouteUnavailable => {
                        return Err(RouteCommandRunnerError::RouteUnavailable {
                            path: ROUTE_COMMAND_POLL_PATH,
                        });
                    }
                    RouteTransportAttempt::Rejected { status, error } => {
                        return Err(RouteCommandRunnerError::Rejected {
                            path: ROUTE_COMMAND_POLL_PATH,
                            status,
                            error,
                        });
                    }
                }
            };
            let idle = batch.commands.is_empty();
            for command in batch.commands {
                let response = execute_route_command(&self.registry, &command);
                self.settle_exact(response).await?;
            }
            self.advance_sequence()?;
            // Control currently returns a bounded snapshot rather than a
            // held long-poll. Pace an empty lane so a healthy idle Node does
            // not spin a signed HTTP/PG transaction loop.
            if idle {
                self.wait_or_shutdown().await;
            }
        }
    }

    fn current_poll(&self) -> Result<RouteCommandPollRequest, RouteCommandRunnerError> {
        let request_sequence = Sequence::new(self.request_sequence)
            .ok_or(RouteCommandRunnerError::SequenceExhausted)?;
        let ring = self
            .verifier
            .current_ring()
            .map_err(|_| RouteCommandRunnerError::RingUnavailable)?;
        let ack_id = RandomId128::new(uuid::Uuid::new_v4().simple().to_string()).ok_or(
            RouteCommandRunnerError::InvalidContract {
                context: "construct Route ring ACK identity",
            },
        )?;
        let ack = RouteNodeRingAck::new(
            session_binding(&self.session),
            ack_id,
            request_sequence,
            ring.version(),
            ring.loaded_kids().to_vec(),
        )
        .map_err(|_| RouteCommandRunnerError::InvalidContract {
            context: "construct installed Route ring ACK",
        })?;
        RouteCommandPollRequest::new(&self.session, request_sequence, Some(ack)).map_err(|_| {
            RouteCommandRunnerError::InvalidContract {
                context: "construct Route poll",
            }
        })
    }

    async fn settle_exact(
        &mut self,
        response: RouteCommandResponse,
    ) -> Result<(), RouteCommandRunnerError> {
        let commit =
            RouteResultCommitRequest::new(&self.session, response.clone()).map_err(|_| {
                RouteCommandRunnerError::InvalidContract {
                    context: "construct exact Route result commit",
                }
            })?;
        let exact = encode_route_result_commit_request(&commit).map_err(|_| {
            RouteCommandRunnerError::InvalidContract {
                context: "encode exact Route result commit",
            }
        })?;
        loop {
            match self.transport.commit(exact.clone()).await {
                RouteTransportAttempt::Accepted(ack) if ack_matches(&ack, &commit) => return Ok(()),
                RouteTransportAttempt::Rejected {
                    error:
                        RuntimeRouteError::StaleOperation { .. }
                        | RuntimeRouteError::SupersededOperation { .. },
                    ..
                } => {
                    // Control has durably advanced or invalidated this exact
                    // Endpoint lane. Retrying can never make this response
                    // current. Close an exact locally installed Serving
                    // effect before forgetting the response; otherwise a
                    // command invalidated between poll and commit could strand
                    // a stale gate and block the next burned epoch forever.
                    self.close_superseded_serving(&response)?;
                    return Ok(());
                }
                RouteTransportAttempt::RouteUnavailable => {
                    return Err(RouteCommandRunnerError::RouteUnavailable {
                        path: ROUTE_RESULT_COMMIT_PATH,
                    });
                }
                RouteTransportAttempt::Rejected { status, error } => {
                    return Err(RouteCommandRunnerError::Rejected {
                        path: ROUTE_RESULT_COMMIT_PATH,
                        status,
                        error,
                    });
                }
                RouteTransportAttempt::Accepted(_) | RouteTransportAttempt::RetryExact(_) => {
                    if *self.shutdown.borrow() {
                        return Ok(());
                    }
                    self.wait_or_shutdown().await;
                }
            }
        }
    }

    fn advance_sequence(&mut self) -> Result<(), RouteCommandRunnerError> {
        self.request_sequence = self
            .request_sequence
            .checked_add(1)
            .ok_or(RouteCommandRunnerError::SequenceExhausted)?;
        Sequence::new(self.request_sequence).ok_or(RouteCommandRunnerError::SequenceExhausted)?;
        Ok(())
    }

    fn close_superseded_serving(
        &self,
        response: &RouteCommandResponse,
    ) -> Result<(), RouteCommandRunnerError> {
        if !matches!(response.result, RouteNodeResult::Serving(_)) {
            return Ok(());
        }
        let binding = response.result.binding();
        if let Some(cell) = self.registry.lookup(&binding.cat_id)? {
            let _ = cell.emergency_close_route(&binding.endpoint_id, &response.operation_id)?;
        }
        Ok(())
    }

    async fn wait_or_shutdown(&mut self) {
        tokio::select! {
            _ = tokio::time::sleep(RETRY_DELAY) => {}
            changed = self.shutdown.changed() => {
                if changed.is_err() {
                    self.shutdown = closed_shutdown_receiver();
                }
            }
        }
    }
}

/// Execute one exact Endpoint command against the sole Host-global cell. The
/// function performs no I/O and is the command/effect linearization boundary.
pub fn execute_route_command(
    registry: &LifecycleAdmissionRegistry,
    command: &RouteCommandEnvelope,
) -> RouteCommandResponse {
    let result = execute_route_command_inner(registry, command).unwrap_or_else(|reason| {
        RouteNodeResult::Rejected(RouteRejectedResult {
            binding: command.binding.clone(),
            reason,
            no_effect_receipt_digest: admission_receipt_digest(command, b"rejected"),
        })
    });
    RouteCommandResponse::new(command, result).unwrap_or_else(|_| RouteCommandResponse {
        version: ContractVersion::V1,
        operation_id: command.operation_id.clone(),
        endpoint_id: command.binding.endpoint_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        result: RouteNodeResult::Rejected(RouteRejectedResult {
            binding: command.binding.clone(),
            reason: RouteRejectionReason::StoredEvidenceConflict,
            no_effect_receipt_digest: admission_receipt_digest(command, b"invalid-command"),
        }),
    })
}

fn execute_route_command_inner(
    registry: &LifecycleAdmissionRegistry,
    command: &RouteCommandEnvelope,
) -> Result<RouteNodeResult, RouteRejectionReason> {
    let cell = registry
        .lookup(&command.binding.cat_id)
        .map_err(map_registry_error)?
        .ok_or(RouteRejectionReason::RuntimeUnavailable)?;
    let gate_binding = gate_binding(&command.binding);
    match command.command {
        RouteCommand::Enable => {
            let enable = EnableRoute::new(
                command.operation_id.clone(),
                command
                    .binding
                    .effective_runtime_ready
                    .source_lifecycle_operation_id
                    .clone(),
                command.binding.admission_session.clone(),
                gate_binding,
            );
            match cell.enable_route(&enable).map_err(map_interlock_error)? {
                EnableRouteOutcome::Serving(_) | EnableRouteOutcome::Replay(_) => {
                    Ok(RouteNodeResult::Serving(RouteServingResult {
                        binding: command.binding.clone(),
                        admission_cell_receipt_digest: admission_receipt_digest(
                            command, b"serving",
                        ),
                    }))
                }
            }
        }
        RouteCommand::Disable => {
            let expected_serving_operation_id = match &command.predecessor {
                RouteCommandPredecessor::Exact {
                    operation_id,
                    terminal_result_kind: cats_api::runtime_route::RouteTerminalResultKind::Serving,
                    ..
                } => operation_id.clone(),
                RouteCommandPredecessor::Genesis | RouteCommandPredecessor::Exact { .. } => {
                    return Err(RouteRejectionReason::StoredEvidenceConflict)
                }
            };
            let disable = DisableRoute::new(
                command.operation_id.clone(),
                command
                    .binding
                    .effective_runtime_ready
                    .source_lifecycle_operation_id
                    .clone(),
                command.binding.admission_session.clone(),
                expected_serving_operation_id,
                gate_binding,
            );
            match cell.disable_route(&disable).map_err(map_interlock_error)? {
                DisableRouteOutcome::Closed(_) | DisableRouteOutcome::Replay(_) => {
                    Ok(RouteNodeResult::Closed(RouteClosedResult {
                        binding: command.binding.clone(),
                        admission_cell_receipt_digest: admission_receipt_digest(command, b"closed"),
                    }))
                }
            }
        }
    }
}

fn gate_binding(binding: &RouteServingBinding) -> RouteGateBinding {
    RouteGateBinding {
        workspace_id: binding.workspace_id.clone(),
        endpoint_id: binding.endpoint_id.clone(),
        hostname: binding.hostname.clone(),
        cat_id: binding.cat_id.clone(),
        node_id: binding.placement_identity.node_id.clone(),
        runtime_incarnation: binding.effective_runtime_ready.runtime_incarnation.clone(),
        route_epoch: binding.route_epoch,
        protocol: binding.protocol,
        target_port: binding.target_port,
    }
}

fn map_registry_error(error: LifecycleAdmissionRegistryError) -> RouteRejectionReason {
    match error {
        LifecycleAdmissionRegistryError::Uninitialized
        | LifecycleAdmissionRegistryError::Unavailable
        | LifecycleAdmissionRegistryError::CatBlocked { .. } => {
            RouteRejectionReason::RuntimeUnavailable
        }
        LifecycleAdmissionRegistryError::StaleAgentSession
        | LifecycleAdmissionRegistryError::InvalidAgentSessionSuccessor => {
            RouteRejectionReason::StaleSession
        }
        LifecycleAdmissionRegistryError::CellAuthorityConflict { .. }
        | LifecycleAdmissionRegistryError::InvalidInitialTargetCommand
        | LifecycleAdmissionRegistryError::MissingSameNodeAdmissionCell { .. }
        | LifecycleAdmissionRegistryError::RuntimeReadyRecoveryAuthorityMismatch
        | LifecycleAdmissionRegistryError::UnattributedPhysicalArtifacts
        | LifecycleAdmissionRegistryError::CellInterlock { .. }
        | LifecycleAdmissionRegistryError::InvalidStartupInventory { .. }
        | LifecycleAdmissionRegistryError::InitializationConflict
        | LifecycleAdmissionRegistryError::Journal(_) => {
            RouteRejectionReason::StoredEvidenceConflict
        }
    }
}

fn map_interlock_error(error: RouteInterlockError) -> RouteRejectionReason {
    match error {
        RouteInterlockError::StaleAgentSession
        | RouteInterlockError::InvalidAgentSessionSuccessor => RouteRejectionReason::StaleSession,
        RouteInterlockError::StaleLifecycleSource
        | RouteInterlockError::StaleLifecycleClose
        | RouteInterlockError::StaleRuntimeReadySuccessor => {
            RouteRejectionReason::StaleLifecycleSource
        }
        RouteInterlockError::Unavailable | RouteInterlockError::CounterExhausted => {
            RouteRejectionReason::RuntimeUnavailable
        }
        RouteInterlockError::WrongCat
        | RouteInterlockError::WrongNode
        | RouteInterlockError::WrongRuntimeIncarnation
        | RouteInterlockError::StaleRouteOperation
        | RouteInterlockError::RouteEpochNotAdvanced
        | RouteInterlockError::EndpointAlreadyServing
        | RouteInterlockError::ActiveRouteGuards
        | RouteInterlockError::RouteNotServing => RouteRejectionReason::StaleEndpointBinding,
        RouteInterlockError::RouteOperationConflict => RouteRejectionReason::StoredEvidenceConflict,
    }
}

fn admission_receipt_digest(command: &RouteCommandEnvelope, outcome: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_RECEIPT_DOMAIN);
    hasher.update((command.operation_id.as_str().len() as u64).to_be_bytes());
    hasher.update(command.operation_id.as_str().as_bytes());
    hasher.update(command.request_fingerprint.as_str().as_bytes());
    hasher.update((outcome.len() as u64).to_be_bytes());
    hasher.update(outcome);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn ack_matches(ack: &RouteResultStoredAck, commit: &RouteResultCommitRequest) -> bool {
    validate_route_result_stored_ack(ack).is_ok()
        && ack.node_id == commit.session.node_id
        && ack.endpoint_id == commit.response.endpoint_id
        && ack.operation_id == commit.response.operation_id
        && ack.request_fingerprint == commit.response.request_fingerprint
        && ack.terminal_result_digest == commit.terminal_result_digest
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn closed_shutdown_receiver() -> tokio::sync::watch::Receiver<bool> {
    let (_sender, receiver) = tokio::sync::watch::channel(true);
    receiver
}

async fn classify_response<T>(
    response: Result<reqwest::Response, reqwest::Error>,
    success_cap: usize,
    decode_success: fn(&[u8]) -> Result<T, cats_api::runtime_route::RuntimeRouteContractError>,
) -> RouteTransportAttempt<T> {
    let mut response = match response {
        Ok(response) => response,
        Err(_) => return RouteTransportAttempt::RetryExact(RouteTransportRetryReason::Transport),
    };
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return RouteTransportAttempt::RouteUnavailable;
    }
    let cap = if status == reqwest::StatusCode::OK {
        success_cap
    } else {
        ROUTE_ERROR_MAX_WIRE_BYTES
    };
    if !valid_headers(response.headers()) || declared_response_exceeds(response.headers(), cap) {
        return RouteTransportAttempt::RetryExact(RouteTransportRetryReason::InvalidResponse);
    }
    let Some(body) = read_bounded_body(&mut response, cap).await else {
        return RouteTransportAttempt::RetryExact(RouteTransportRetryReason::InvalidResponse);
    };
    if status == reqwest::StatusCode::OK {
        return decode_success(&body).map_or_else(
            |_| RouteTransportAttempt::RetryExact(RouteTransportRetryReason::InvalidResponse),
            RouteTransportAttempt::Accepted,
        );
    }
    let Ok(error) = decode_runtime_route_error(&body) else {
        return RouteTransportAttempt::RetryExact(RouteTransportRetryReason::InvalidResponse);
    };
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
    {
        RouteTransportAttempt::RetryExact(RouteTransportRetryReason::Backpressure)
    } else if status.is_server_error() {
        RouteTransportAttempt::RetryExact(RouteTransportRetryReason::ServerFailure)
    } else if status == reqwest::StatusCode::UNAUTHORIZED
        && !has_one_exact_header(
            response.headers(),
            reqwest::header::WWW_AUTHENTICATE,
            NODE_AUTHENTICATE_CHALLENGE,
        )
    {
        RouteTransportAttempt::RetryExact(RouteTransportRetryReason::InvalidResponse)
    } else {
        RouteTransportAttempt::Rejected {
            status: status.as_u16(),
            error,
        }
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

fn valid_headers(headers: &reqwest::header::HeaderMap) -> bool {
    !headers.contains_key(reqwest::header::CONTENT_ENCODING)
        && has_one_exact_header(headers, reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
}

fn has_one_exact_header(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn declared_response_exceeds(headers: &reqwest::header::HeaderMap, cap: usize) -> bool {
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
        .is_none_or(|length| length > cap as u64)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cats_api::runtime_lifecycle::{
        EffectiveRuntimeReady as WireEffectiveRuntimeReady, PlacementIdentity,
    };
    use cats_api::runtime_reconciliation::{Epoch, Id, NodeBootId, UnixMillis};

    use super::*;
    use crate::admission::{
        EffectiveRuntimeReady as LocalEffectiveRuntimeReady, LifecycleRouteAdmission,
        LifecycleRouteAdmissionCell,
    };
    use crate::route_grant_v2::RouteGrantV2KeyRing;

    struct RetryPollTransport {
        poll_bodies: Mutex<Vec<Vec<u8>>>,
        shutdown: tokio::sync::watch::Sender<bool>,
    }

    impl RouteCommandTransport for RetryPollTransport {
        fn poll(&self, exact_body: Vec<u8>) -> RoutePollFuture {
            let attempt = {
                let mut bodies = self.poll_bodies.lock().unwrap();
                bodies.push(exact_body.clone());
                if bodies.len() == 1 {
                    RouteTransportAttempt::RetryExact(RouteTransportRetryReason::Transport)
                } else {
                    let poll =
                        cats_api::runtime_route::decode_route_command_poll_request(&exact_body)
                            .unwrap();
                    self.shutdown.send(true).unwrap();
                    RouteTransportAttempt::Accepted(RouteCommandBatch {
                        version: ContractVersion::V1,
                        session: poll.session,
                        request_sequence: poll.request_sequence,
                        commands: Vec::new(),
                    })
                }
            };
            Box::pin(async move { attempt })
        }

        fn commit(&self, _exact_body: Vec<u8>) -> RouteCommitFuture {
            Box::pin(async { panic!("empty Route command batch must not attempt a result commit") })
        }
    }

    #[tokio::test]
    async fn transient_poll_retries_the_identical_sequence_and_ring_ack_body() {
        let session = session();
        let binding = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(binding);
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let transport = Arc::new(RetryPollTransport {
            poll_bodies: Mutex::new(Vec::new()),
            shutdown,
        });
        let runner =
            RouteCommandRunner::new(session, transport.clone(), registry, verifier, shutdown_rx)
                .unwrap();

        runner.run().await.unwrap();

        let bodies = transport.poll_bodies.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], bodies[1]);
    }

    struct SupersededCommitTransport {
        endpoint_id: Id,
    }

    impl RouteCommandTransport for SupersededCommitTransport {
        fn poll(&self, _exact_body: Vec<u8>) -> RoutePollFuture {
            Box::pin(async { panic!("direct settlement test must not poll") })
        }

        fn commit(&self, _exact_body: Vec<u8>) -> RouteCommitFuture {
            let endpoint_id = self.endpoint_id.clone();
            Box::pin(async move {
                RouteTransportAttempt::Rejected {
                    status: 409,
                    error: RuntimeRouteError::SupersededOperation {
                        endpoint_id,
                        current_operation_id: None,
                    },
                }
            })
        }
    }

    #[tokio::test]
    async fn superseded_serving_commit_closes_the_exact_local_gate() {
        let session = session();
        let admission_session = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(admission_session.clone());
        let source_operation_id = Id::new("lifecycle_start_route_test").unwrap();
        let incarnation = RandomId128::new("12".repeat(16)).unwrap();
        let cat_id = Id::new("cat-route-command-test").unwrap();
        let endpoint_id = Id::new("endpoint-route-command-test").unwrap();
        let cell = LifecycleRouteAdmissionCell::new(
            cat_id.clone(),
            admission_session.clone(),
            LifecycleRouteAdmission::RuntimeReady(LocalEffectiveRuntimeReady::new(
                source_operation_id.clone(),
                incarnation.clone(),
                cats_api::runtime_reconciliation::Ipv4Address::new("10.0.0.2").unwrap(),
            )),
        );
        registry.insert_cell_for_machine_test(cell.clone()).unwrap();
        let command = RouteCommandEnvelope::new(
            Id::new("route_enable_route_test").unwrap(),
            RouteServingBinding {
                workspace_id: Id::new("workspace-route-command-test").unwrap(),
                endpoint_id: endpoint_id.clone(),
                hostname: cats_api::runtime_reconciliation::Hostname::new(
                    "route-command.example.test",
                )
                .unwrap(),
                cat_id,
                placement_identity: PlacementIdentity {
                    node_id: admission_session.node_id.clone(),
                    placement_epoch: Epoch::new(1).unwrap(),
                },
                effective_runtime_ready: WireEffectiveRuntimeReady {
                    source_lifecycle_operation_id: source_operation_id,
                    runtime_incarnation: incarnation,
                    runtime_config_digest: Sha256Digest::from_bytes([3; 32]),
                    runtime_ready_receipt_digest: Sha256Digest::from_bytes([4; 32]),
                },
                route_epoch: Epoch::new(7).unwrap(),
                admission_session,
                protocol: cats_api::runtime_reconciliation::HttpProtocol::Http,
                target_port: 8080,
            },
            RouteCommandPredecessor::Genesis,
            RouteCommand::Enable,
        )
        .unwrap();
        let response = execute_route_command(&registry, &command);
        assert!(matches!(response.result, RouteNodeResult::Serving(_)));
        assert!(cell.current_serving_route(&endpoint_id).unwrap().is_some());

        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = RouteCommandRunner::new(
            session,
            Arc::new(SupersededCommitTransport {
                endpoint_id: endpoint_id.clone(),
            }),
            registry,
            verifier,
            shutdown_rx,
        )
        .unwrap();

        runner.settle_exact(response).await.unwrap();
        assert_eq!(cell.current_serving_route(&endpoint_id).unwrap(), None);
    }

    fn session() -> AgentSession {
        AgentSession {
            version: ContractVersion::V1,
            node_id: Id::new("node-route-command-test").unwrap(),
            immutable_host_id: Id::new("host-route-command-test").unwrap(),
            node_boot_id: NodeBootId::new("ab".repeat(16)).unwrap(),
            agent_instance_id: RandomId128::new("cd".repeat(16)).unwrap(),
            agent_session_epoch: Epoch::new(1).unwrap(),
            registration_attempt_id: RandomId128::new("ef".repeat(16)).unwrap(),
            guest_config_digest: Sha256Digest::from_bytes([1; 32]),
            lease_deadline_unix_ms: UnixMillis::new(60_000).unwrap(),
        }
    }
}

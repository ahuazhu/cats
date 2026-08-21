//! Signed Node pull/result runner for per-Endpoint Route operations.
//!
//! Control owns the durable Route operation lane. The Node executes each
//! exact command only through the Host-global lifecycle admission registry and
//! retains its exact response in the owned runner until Control acknowledges
//! it. A process/session loss closes every registry gate, so an old response
//! cannot authorize a replacement AgentSession.

use std::collections::BTreeMap;
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
    AgentSession, ContractVersion, Id, RandomId128, RouteGateBinding, Sequence, SessionBinding,
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

struct ActiveRouteWorker {
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    installed_serving: Option<InstalledServing>,
    task: tokio::task::JoinHandle<Result<(), RouteCommandRunnerError>>,
}

struct InstalledServing {
    cat_id: Id,
    endpoint_id: Id,
    operation_id: Id,
}

struct RouteWorkerCompletion {
    endpoint_id: Id,
    completed: tokio::sync::mpsc::UnboundedSender<Id>,
}

impl Drop for RouteWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.completed.send(self.endpoint_id.clone());
    }
}

/// One process-owned Route delivery lane. Polling remains Node-scoped, but
/// every Endpoint owns an independent result-settlement worker so one Cat's
/// unavailable or corrupt Control row cannot serialize unrelated gates.
pub struct RouteCommandRunner {
    session: AgentSession,
    transport: Arc<dyn RouteCommandTransport>,
    registry: Arc<LifecycleAdmissionRegistry>,
    verifier: Arc<RouteGrantV2Verifier>,
    request_sequence: u64,
    blocked: BTreeMap<Id, String>,
    workers: BTreeMap<Id, ActiveRouteWorker>,
    worker_finished_tx: tokio::sync::mpsc::UnboundedSender<Id>,
    worker_finished_rx: tokio::sync::mpsc::UnboundedReceiver<Id>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    worker_shutdown: tokio::sync::watch::Sender<bool>,
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
        let (worker_shutdown, _) = tokio::sync::watch::channel(false);
        let (worker_finished_tx, worker_finished_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            session,
            transport,
            registry,
            verifier,
            request_sequence: 1,
            blocked: BTreeMap::new(),
            workers: BTreeMap::new(),
            worker_finished_tx,
            worker_finished_rx,
            shutdown,
            worker_shutdown,
        })
    }

    pub async fn run(mut self) -> Result<(), RouteCommandRunnerError> {
        let run_result = self.run_loop().await;
        let _ = self.worker_shutdown.send(true);
        let shutdown_result = self.finish_shutdown().await;
        match (run_result, shutdown_result) {
            (Err(error), _) => Err(error),
            (Ok(()), result) => result,
        }
    }

    async fn run_loop(&mut self) -> Result<(), RouteCommandRunnerError> {
        loop {
            self.reap_finished().await?;
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
                let poll_attempt = self.transport.poll(exact_poll.clone());
                tokio::pin!(poll_attempt);
                let event = tokio::select! {
                    biased;
                    endpoint_id = self.worker_finished_rx.recv() => {
                        RoutePollEvent::WorkerFinished(endpoint_id)
                    }
                    changed = self.shutdown.changed() => RoutePollEvent::Shutdown(changed),
                    attempt = &mut poll_attempt => RoutePollEvent::Attempt(attempt),
                };
                let attempt = match event {
                    RoutePollEvent::Attempt(attempt) => attempt,
                    RoutePollEvent::WorkerFinished(Some(endpoint_id)) => {
                        self.reap_worker(&endpoint_id).await?;
                        continue;
                    }
                    RoutePollEvent::WorkerFinished(None) => return Ok(()),
                    RoutePollEvent::Shutdown(changed) => {
                        if changed.is_err() {
                            self.shutdown = closed_shutdown_receiver();
                        }
                        if *self.shutdown.borrow() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                match attempt {
                    RouteTransportAttempt::Accepted(batch) => {
                        validate_route_command_batch_for_poll(&batch, &poll, &self.session)
                            .map_err(|_| RouteCommandRunnerError::InvalidContract {
                                context: "validate Route batch echo",
                            })?;
                        break batch;
                    }
                    RouteTransportAttempt::RetryExact(_) => {
                        self.wait_or_shutdown().await?;
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
            let made_progress = self.dispatch_batch(batch.commands)?;
            self.advance_sequence()?;
            // Control currently returns a bounded snapshot rather than a
            // held long-poll. Pace an empty lane so a healthy idle Node does
            // not spin a signed HTTP/PG transaction loop.
            if idle || !made_progress {
                self.wait_or_shutdown().await?;
            }
        }
    }

    fn dispatch_batch(
        &mut self,
        commands: Vec<RouteCommandEnvelope>,
    ) -> Result<bool, RouteCommandRunnerError> {
        let mut made_progress = false;
        for command in commands {
            let endpoint_id = command.binding.endpoint_id.clone();
            if self.blocked.contains_key(&endpoint_id) {
                continue;
            }
            if let Some(active) = self.workers.get(&endpoint_id) {
                if active.operation_id == command.operation_id
                    && active.request_fingerprint == command.request_fingerprint
                {
                    continue;
                }
                // Control repeats the exact successor after this Endpoint's
                // current response settles. Never run two effects for one
                // Endpoint merely because polling and settlement overlap.
                continue;
            }

            let response = execute_route_command(&self.registry, &command);
            let installed_serving = match &response.result {
                RouteNodeResult::Serving(serving) => Some(InstalledServing {
                    cat_id: serving.binding.cat_id.clone(),
                    endpoint_id: serving.binding.endpoint_id.clone(),
                    operation_id: response.operation_id.clone(),
                }),
                RouteNodeResult::Closed(_) | RouteNodeResult::Rejected(_) => None,
            };
            let transport = Arc::clone(&self.transport);
            let registry = Arc::clone(&self.registry);
            let session = self.session.clone();
            let shutdown = self.worker_shutdown.subscribe();
            let completion = RouteWorkerCompletion {
                endpoint_id: endpoint_id.clone(),
                completed: self.worker_finished_tx.clone(),
            };
            let task = tokio::spawn(async move {
                let _completion = completion;
                settle_exact_response(registry, transport, session, response, shutdown).await
            });
            self.workers.insert(
                endpoint_id,
                ActiveRouteWorker {
                    operation_id: command.operation_id,
                    request_fingerprint: command.request_fingerprint,
                    installed_serving,
                    task,
                },
            );
            made_progress = true;
        }
        Ok(made_progress)
    }

    async fn reap_finished(&mut self) -> Result<(), RouteCommandRunnerError> {
        let finished = self
            .workers
            .iter()
            .filter_map(|(endpoint_id, worker)| {
                worker.task.is_finished().then_some(endpoint_id.clone())
            })
            .collect::<Vec<_>>();
        let mut global_error = None;
        for endpoint_id in finished {
            if let Err(error) = self.reap_worker(&endpoint_id).await {
                if global_error.is_none() {
                    global_error = Some(error);
                }
            }
        }
        global_error.map_or(Ok(()), Err)
    }

    async fn reap_worker(&mut self, endpoint_id: &Id) -> Result<(), RouteCommandRunnerError> {
        let Some(worker) = self.workers.remove(endpoint_id) else {
            return Ok(());
        };
        match worker.task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if route_worker_error_is_node_global(&error) => Err(error),
            Ok(Err(error)) => {
                tracing::error!(
                    endpoint_id = %endpoint_id,
                    %error,
                    "blocking one failed Endpoint Route lane without stopping siblings"
                );
                self.blocked.insert(endpoint_id.clone(), error.to_string());
                Ok(())
            }
            Err(error) => {
                self.close_installed_serving(worker.installed_serving.as_ref())?;
                tracing::error!(
                    endpoint_id = %endpoint_id,
                    %error,
                    "closed and blocked one panicked Endpoint Route lane without stopping siblings"
                );
                self.blocked.insert(endpoint_id.clone(), error.to_string());
                Ok(())
            }
        }
    }

    async fn finish_shutdown(&mut self) -> Result<(), RouteCommandRunnerError> {
        let mut first_global_error = None;
        for (endpoint_id, worker) in std::mem::take(&mut self.workers) {
            match worker.task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if route_worker_error_is_node_global(&error) => {
                    if first_global_error.is_none() {
                        first_global_error = Some(error);
                    }
                }
                Ok(Err(error)) => {
                    tracing::error!(
                        endpoint_id = %endpoint_id,
                        %error,
                        "one Endpoint Route lane failed while shutdown joined its siblings"
                    );
                }
                Err(error) => {
                    if let Err(close_error) =
                        self.close_installed_serving(worker.installed_serving.as_ref())
                    {
                        if first_global_error.is_none() {
                            first_global_error = Some(close_error);
                        }
                    }
                    tracing::error!(
                        endpoint_id = %endpoint_id,
                        %error,
                        "join Route settlement worker during shutdown"
                    );
                }
            }
        }
        first_global_error.map_or(Ok(()), Err)
    }

    fn close_installed_serving(
        &self,
        installed: Option<&InstalledServing>,
    ) -> Result<(), RouteCommandRunnerError> {
        let Some(installed) = installed else {
            return Ok(());
        };
        if let Some(cell) = self.registry.lookup(&installed.cat_id)? {
            let _ = cell.emergency_close_route(&installed.endpoint_id, &installed.operation_id)?;
        }
        Ok(())
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

    #[cfg(test)]
    async fn settle_exact(
        &mut self,
        response: RouteCommandResponse,
    ) -> Result<(), RouteCommandRunnerError> {
        settle_exact_response(
            Arc::clone(&self.registry),
            Arc::clone(&self.transport),
            self.session.clone(),
            response,
            self.shutdown.clone(),
        )
        .await
    }

    fn advance_sequence(&mut self) -> Result<(), RouteCommandRunnerError> {
        self.request_sequence = self
            .request_sequence
            .checked_add(1)
            .ok_or(RouteCommandRunnerError::SequenceExhausted)?;
        Sequence::new(self.request_sequence).ok_or(RouteCommandRunnerError::SequenceExhausted)?;
        Ok(())
    }

    async fn wait_or_shutdown(&mut self) -> Result<(), RouteCommandRunnerError> {
        let event = tokio::select! {
            biased;
            endpoint_id = self.worker_finished_rx.recv() => {
                RouteWaitEvent::WorkerFinished(endpoint_id)
            }
            changed = self.shutdown.changed() => RouteWaitEvent::Shutdown(changed),
            _ = tokio::time::sleep(RETRY_DELAY) => RouteWaitEvent::Elapsed,
        };
        match event {
            RouteWaitEvent::Elapsed => {}
            RouteWaitEvent::WorkerFinished(Some(endpoint_id)) => {
                self.reap_worker(&endpoint_id).await?;
            }
            RouteWaitEvent::WorkerFinished(None) => {
                self.shutdown = closed_shutdown_receiver();
            }
            RouteWaitEvent::Shutdown(changed) => {
                if changed.is_err() {
                    self.shutdown = closed_shutdown_receiver();
                }
            }
        }
        Ok(())
    }
}

enum RoutePollEvent {
    Attempt(RouteTransportAttempt<RouteCommandBatch>),
    WorkerFinished(Option<Id>),
    Shutdown(Result<(), tokio::sync::watch::error::RecvError>),
}

enum RouteWaitEvent {
    Elapsed,
    WorkerFinished(Option<Id>),
    Shutdown(Result<(), tokio::sync::watch::error::RecvError>),
}

async fn settle_exact_response(
    registry: Arc<LifecycleAdmissionRegistry>,
    transport: Arc<dyn RouteCommandTransport>,
    session: AgentSession,
    response: RouteCommandResponse,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), RouteCommandRunnerError> {
    let commit = RouteResultCommitRequest::new(&session, response.clone()).map_err(|_| {
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
        match transport.commit(exact.clone()).await {
            RouteTransportAttempt::Accepted(ack) if ack_matches(&ack, &commit) => return Ok(()),
            RouteTransportAttempt::Rejected {
                error:
                    RuntimeRouteError::StaleOperation { .. }
                    | RuntimeRouteError::SupersededOperation { .. },
                ..
            } => {
                // Control has durably advanced or invalidated this exact
                // Endpoint lane. Retrying can never make this response
                // current. Close an exact locally installed Serving effect
                // before forgetting the response; otherwise a command
                // invalidated between poll and commit could strand a stale
                // gate and block the next burned epoch forever.
                close_superseded_serving(&registry, &response)?;
                return Ok(());
            }
            RouteTransportAttempt::RouteUnavailable => {
                return Err(RouteCommandRunnerError::RouteUnavailable {
                    path: ROUTE_RESULT_COMMIT_PATH,
                });
            }
            RouteTransportAttempt::Rejected { status, error } => {
                // A definitive rejection means Control did not accept this
                // exact terminal projection.  Keep the failure Endpoint-local,
                // but never retain a Serving gate whose result has no matching
                // Control authority. Closed/Rejected results have no local
                // Serving effect, so the same exact close is a no-op for them.
                close_superseded_serving(&registry, &response)?;
                return Err(RouteCommandRunnerError::Rejected {
                    path: ROUTE_RESULT_COMMIT_PATH,
                    status,
                    error,
                });
            }
            RouteTransportAttempt::Accepted(_) | RouteTransportAttempt::RetryExact(_) => {
                if *shutdown.borrow() {
                    return Ok(());
                }
                tokio::select! {
                    _ = tokio::time::sleep(RETRY_DELAY) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

fn close_superseded_serving(
    registry: &LifecycleAdmissionRegistry,
    response: &RouteCommandResponse,
) -> Result<(), RouteCommandRunnerError> {
    if !matches!(response.result, RouteNodeResult::Serving(_)) {
        return Ok(());
    }
    let binding = response.result.binding();
    if let Some(cell) = registry.lookup(&binding.cat_id)? {
        let _ = cell.emergency_close_route(&binding.endpoint_id, &response.operation_id)?;
    }
    Ok(())
}

fn route_worker_error_is_node_global(error: &RouteCommandRunnerError) -> bool {
    matches!(
        error,
        RouteCommandRunnerError::RouteUnavailable { .. }
            | RouteCommandRunnerError::Rejected {
                error: RuntimeRouteError::AuthenticationFailed
                    | RuntimeRouteError::WrongNode { .. },
                ..
            }
            | RouteCommandRunnerError::Registry(
                LifecycleAdmissionRegistryError::Unavailable
                    | LifecycleAdmissionRegistryError::Uninitialized
                    | LifecycleAdmissionRegistryError::InitializationConflict
                    | LifecycleAdmissionRegistryError::InvalidStartupInventory { .. }
                    | LifecycleAdmissionRegistryError::StaleAgentSession
                    | LifecycleAdmissionRegistryError::UnattributedPhysicalArtifacts
                    | LifecycleAdmissionRegistryError::InvalidAgentSessionSuccessor
            )
            | RouteCommandRunnerError::SequenceExhausted
            | RouteCommandRunnerError::RingUnavailable
    )
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    struct IsolatedCommitTransport {
        blocked_endpoint_id: Id,
        blocked_started: Arc<tokio::sync::Notify>,
        release_blocked: Arc<tokio::sync::Notify>,
        healthy_committed: Arc<tokio::sync::Notify>,
    }

    struct DefinitiveRejectTransport {
        rejected_endpoint_id: Id,
    }

    struct AuthenticationRejectTransport;

    struct AuthenticationRejectedWhilePollRetriesTransport {
        command: RouteCommandEnvelope,
        poll_calls: AtomicUsize,
        retry_poll_started: Arc<tokio::sync::Notify>,
    }

    struct PanicAfterEnableCommitTransport {
        panicked_endpoint_id: Id,
        healthy_committed: Arc<tokio::sync::Notify>,
    }

    impl RouteCommandTransport for DefinitiveRejectTransport {
        fn poll(&self, _exact_body: Vec<u8>) -> RoutePollFuture {
            Box::pin(async { panic!("direct dispatch test must not poll") })
        }

        fn commit(&self, exact_body: Vec<u8>) -> RouteCommitFuture {
            let commit = cats_api::runtime_route::decode_route_result_commit_request(&exact_body)
                .expect("runner emits one exact canonical commit");
            if commit.response.endpoint_id == self.rejected_endpoint_id {
                let operation_id = commit.response.operation_id;
                return Box::pin(async move {
                    RouteTransportAttempt::Rejected {
                        status: 409,
                        error: RuntimeRouteError::ConflictingTerminalResult { operation_id },
                    }
                });
            }
            let acknowledgement = RouteResultStoredAck {
                version: ContractVersion::V1,
                node_id: commit.session.node_id,
                endpoint_id: commit.response.endpoint_id.clone(),
                operation_id: commit.response.operation_id.clone(),
                request_fingerprint: commit.response.request_fingerprint.clone(),
                terminal_result_digest: commit.terminal_result_digest,
            };
            Box::pin(async move { RouteTransportAttempt::Accepted(acknowledgement) })
        }
    }

    impl RouteCommandTransport for AuthenticationRejectTransport {
        fn poll(&self, _exact_body: Vec<u8>) -> RoutePollFuture {
            Box::pin(async { panic!("direct dispatch test must not poll") })
        }

        fn commit(&self, _exact_body: Vec<u8>) -> RouteCommitFuture {
            Box::pin(async {
                RouteTransportAttempt::Rejected {
                    status: 401,
                    error: RuntimeRouteError::AuthenticationFailed,
                }
            })
        }
    }

    impl RouteCommandTransport for AuthenticationRejectedWhilePollRetriesTransport {
        fn poll(&self, exact_body: Vec<u8>) -> RoutePollFuture {
            let poll = cats_api::runtime_route::decode_route_command_poll_request(&exact_body)
                .expect("runner emits one exact canonical poll");
            if self.poll_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let command = self.command.clone();
                return Box::pin(async move {
                    RouteTransportAttempt::Accepted(RouteCommandBatch {
                        version: ContractVersion::V1,
                        session: poll.session,
                        request_sequence: poll.request_sequence,
                        commands: vec![command],
                    })
                });
            }
            self.retry_poll_started.notify_one();
            Box::pin(async {
                RouteTransportAttempt::RetryExact(RouteTransportRetryReason::Transport)
            })
        }

        fn commit(&self, _exact_body: Vec<u8>) -> RouteCommitFuture {
            let retry_poll_started = Arc::clone(&self.retry_poll_started);
            Box::pin(async move {
                retry_poll_started.notified().await;
                RouteTransportAttempt::Rejected {
                    status: 401,
                    error: RuntimeRouteError::AuthenticationFailed,
                }
            })
        }
    }

    impl RouteCommandTransport for PanicAfterEnableCommitTransport {
        fn poll(&self, _exact_body: Vec<u8>) -> RoutePollFuture {
            Box::pin(async { panic!("direct dispatch test must not poll") })
        }

        fn commit(&self, exact_body: Vec<u8>) -> RouteCommitFuture {
            let commit = cats_api::runtime_route::decode_route_result_commit_request(&exact_body)
                .expect("runner emits one exact canonical commit");
            if commit.response.endpoint_id == self.panicked_endpoint_id {
                return Box::pin(async move {
                    panic!("injected panic after the Enable result reached Control")
                });
            }
            let healthy_committed = Arc::clone(&self.healthy_committed);
            let acknowledgement = RouteResultStoredAck {
                version: ContractVersion::V1,
                node_id: commit.session.node_id,
                endpoint_id: commit.response.endpoint_id.clone(),
                operation_id: commit.response.operation_id.clone(),
                request_fingerprint: commit.response.request_fingerprint.clone(),
                terminal_result_digest: commit.terminal_result_digest,
            };
            Box::pin(async move {
                healthy_committed.notify_one();
                RouteTransportAttempt::Accepted(acknowledgement)
            })
        }
    }

    impl RouteCommandTransport for IsolatedCommitTransport {
        fn poll(&self, _exact_body: Vec<u8>) -> RoutePollFuture {
            Box::pin(async { panic!("direct dispatch test must not poll") })
        }

        fn commit(&self, exact_body: Vec<u8>) -> RouteCommitFuture {
            let commit = cats_api::runtime_route::decode_route_result_commit_request(&exact_body)
                .expect("runner emits one exact canonical commit");
            let is_blocked = commit.response.endpoint_id == self.blocked_endpoint_id;
            let release_blocked = Arc::clone(&self.release_blocked);
            let healthy_committed = Arc::clone(&self.healthy_committed);
            if is_blocked {
                self.blocked_started.notify_one();
            }
            let acknowledgement = RouteResultStoredAck {
                version: ContractVersion::V1,
                node_id: commit.session.node_id,
                endpoint_id: commit.response.endpoint_id.clone(),
                operation_id: commit.response.operation_id.clone(),
                request_fingerprint: commit.response.request_fingerprint.clone(),
                terminal_result_digest: commit.terminal_result_digest,
            };
            Box::pin(async move {
                if is_blocked {
                    release_blocked.notified().await;
                } else {
                    healthy_committed.notify_one();
                }
                RouteTransportAttempt::Accepted(acknowledgement)
            })
        }
    }

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

    #[tokio::test]
    async fn blocked_endpoint_commit_does_not_block_a_sibling_endpoint() {
        let session = session();
        let admission_session = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(admission_session.clone());
        let (blocked_command, blocked_endpoint_id) =
            enable_command(&registry, &admission_session, "blocked", 7);
        let (healthy_command, healthy_endpoint_id) =
            enable_command(&registry, &admission_session, "healthy", 11);
        let blocked_started = Arc::new(tokio::sync::Notify::new());
        let release_blocked = Arc::new(tokio::sync::Notify::new());
        let healthy_committed = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(IsolatedCommitTransport {
            blocked_endpoint_id: blocked_endpoint_id.clone(),
            blocked_started: Arc::clone(&blocked_started),
            release_blocked: Arc::clone(&release_blocked),
            healthy_committed: Arc::clone(&healthy_committed),
        });
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner =
            RouteCommandRunner::new(session, transport, registry, verifier, shutdown_rx).unwrap();

        assert!(runner
            .dispatch_batch(vec![blocked_command, healthy_command])
            .unwrap());
        tokio::time::timeout(Duration::from_secs(1), blocked_started.notified())
            .await
            .expect("blocked Endpoint reached its independent commit worker");
        tokio::time::timeout(Duration::from_secs(1), healthy_committed.notified())
            .await
            .expect("healthy sibling committed while the first Endpoint remained blocked");

        runner.reap_finished().await.unwrap();
        assert!(runner.workers.contains_key(&blocked_endpoint_id));
        assert!(!runner.workers.contains_key(&healthy_endpoint_id));

        release_blocked.notify_one();
        tokio::time::timeout(Duration::from_secs(1), runner.finish_shutdown())
            .await
            .expect("blocked Endpoint worker joined after its commit was released")
            .unwrap();
    }

    #[tokio::test]
    async fn definitive_rejection_closes_only_that_endpoint_and_siblings_finish() {
        let session = session();
        let admission_session = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(admission_session.clone());
        let (failed_command, failed_endpoint) =
            enable_command(&registry, &admission_session, "definitive-failure", 17);
        let failed_cat = failed_command.binding.cat_id.clone();
        let failed_operation = failed_command.operation_id.clone();
        let (healthy_command, healthy_endpoint) =
            enable_command(&registry, &admission_session, "definitive-healthy", 19);
        let healthy_cat = healthy_command.binding.cat_id.clone();
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let transport = Arc::new(DefinitiveRejectTransport {
            rejected_endpoint_id: failed_endpoint.clone(),
        });
        let mut runner =
            RouteCommandRunner::new(session, transport, registry, verifier, shutdown_rx).unwrap();

        assert!(runner
            .dispatch_batch(vec![failed_command, healthy_command])
            .unwrap());
        tokio::time::timeout(Duration::from_secs(1), async {
            while runner
                .workers
                .values()
                .any(|worker| !worker.task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both Endpoint commits reached terminal outcomes");
        runner
            .reap_finished()
            .await
            .expect("one Endpoint-local failure does not fail the Node lane");
        assert!(runner.blocked.contains_key(&failed_endpoint));
        assert!(!runner.blocked.contains_key(&healthy_endpoint));
        assert_eq!(
            runner
                .registry
                .lookup(&failed_cat)
                .unwrap()
                .unwrap()
                .current_serving_route(&failed_endpoint)
                .unwrap(),
            None,
            "definitively rejected Serving result retained a local gate"
        );
        assert!(runner
            .registry
            .lookup(&healthy_cat)
            .unwrap()
            .unwrap()
            .current_serving_route(&healthy_endpoint)
            .unwrap()
            .is_some());
        assert!(runner.blocked[&failed_endpoint].contains(failed_operation.as_str()));
        runner.finish_shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn node_authentication_rejection_stops_the_route_runner() {
        let session = session();
        let admission_session = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(admission_session.clone());
        let (command, endpoint_id) =
            enable_command(&registry, &admission_session, "authentication-failure", 23);
        let cat_id = command.binding.cat_id.clone();
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = RouteCommandRunner::new(
            session,
            Arc::new(AuthenticationRejectTransport),
            registry,
            verifier,
            shutdown_rx,
        )
        .unwrap();

        assert!(runner.dispatch_batch(vec![command]).unwrap());
        tokio::time::timeout(Duration::from_secs(1), async {
            while runner
                .workers
                .values()
                .any(|worker| !worker.task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Route commit reached the authentication rejection");
        assert!(matches!(
            runner.reap_finished().await,
            Err(RouteCommandRunnerError::Rejected {
                error: RuntimeRouteError::AuthenticationFailed,
                ..
            })
        ));
        assert!(runner.blocked.is_empty());
        assert_eq!(
            runner
                .registry
                .lookup(&cat_id)
                .unwrap()
                .unwrap()
                .current_serving_route(&endpoint_id)
                .unwrap(),
            None,
            "an unaccepted Serving result retained a local gate"
        );
    }

    #[tokio::test]
    async fn authentication_rejection_interrupts_a_permanently_retrying_poll() {
        let session = session();
        let admission_session = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(admission_session.clone());
        let (command, endpoint_id) =
            enable_command(&registry, &admission_session, "auth-during-poll", 29);
        let cat_id = command.binding.cat_id.clone();
        let retry_poll_started = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(AuthenticationRejectedWhilePollRetriesTransport {
            command,
            poll_calls: AtomicUsize::new(0),
            retry_poll_started,
        });
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner = RouteCommandRunner::new(
            session,
            transport.clone(),
            registry.clone(),
            verifier,
            shutdown_rx,
        )
        .unwrap();

        let error = tokio::time::timeout(Duration::from_secs(1), runner.run())
            .await
            .expect("Node-global commit rejection did not interrupt the retrying poll")
            .expect_err("authentication rejection must stop the Route runner");
        assert!(matches!(
            error,
            RouteCommandRunnerError::Rejected {
                error: RuntimeRouteError::AuthenticationFailed,
                ..
            }
        ));
        assert!(transport.poll_calls.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            registry
                .lookup(&cat_id)
                .unwrap()
                .unwrap()
                .current_serving_route(&endpoint_id)
                .unwrap(),
            None,
            "the authentication-rejected Serving result retained its gate"
        );
    }

    #[tokio::test]
    async fn panicked_enable_settlement_closes_only_its_exact_gate() {
        let session = session();
        let admission_session = session_binding(&session);
        let registry = LifecycleAdmissionRegistry::for_machine_test(admission_session.clone());
        let (panicked_command, panicked_endpoint) =
            enable_command(&registry, &admission_session, "panic-after-enable", 31);
        let panicked_cat = panicked_command.binding.cat_id.clone();
        let (healthy_command, healthy_endpoint) =
            enable_command(&registry, &admission_session, "panic-healthy", 37);
        let healthy_cat = healthy_command.binding.cat_id.clone();
        let healthy_committed = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(PanicAfterEnableCommitTransport {
            panicked_endpoint_id: panicked_endpoint.clone(),
            healthy_committed: Arc::clone(&healthy_committed),
        });
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), Vec::new()).unwrap(),
        ));
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner =
            RouteCommandRunner::new(session, transport, registry.clone(), verifier, shutdown_rx)
                .unwrap();

        assert!(runner
            .dispatch_batch(vec![panicked_command, healthy_command])
            .unwrap());
        tokio::time::timeout(Duration::from_secs(1), healthy_committed.notified())
            .await
            .expect("healthy sibling did not settle around the panicked worker");
        tokio::time::timeout(Duration::from_secs(1), async {
            while runner
                .workers
                .values()
                .any(|worker| !worker.task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Route workers did not reach terminal join states");
        runner.reap_finished().await.unwrap();

        assert!(runner.blocked.contains_key(&panicked_endpoint));
        assert!(!runner.blocked.contains_key(&healthy_endpoint));
        assert_eq!(
            registry
                .lookup(&panicked_cat)
                .unwrap()
                .unwrap()
                .current_serving_route(&panicked_endpoint)
                .unwrap(),
            None,
            "panicked Enable settlement retained its installed gate"
        );
        assert!(registry
            .lookup(&healthy_cat)
            .unwrap()
            .unwrap()
            .current_serving_route(&healthy_endpoint)
            .unwrap()
            .is_some());
        runner.finish_shutdown().await.unwrap();
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

    fn enable_command(
        registry: &LifecycleAdmissionRegistry,
        admission_session: &SessionBinding,
        suffix: &str,
        route_epoch: u64,
    ) -> (RouteCommandEnvelope, Id) {
        let source_operation_id = Id::new(format!("lifecycle_start_{suffix}")).unwrap();
        let incarnation = RandomId128::new(format!("{route_epoch:02}").repeat(16)).unwrap();
        let cat_id = Id::new(format!("cat_route_{suffix}")).unwrap();
        let endpoint_id = Id::new(format!("endpoint_route_{suffix}")).unwrap();
        let cell = LifecycleRouteAdmissionCell::new(
            cat_id.clone(),
            admission_session.clone(),
            LifecycleRouteAdmission::RuntimeReady(LocalEffectiveRuntimeReady::new(
                source_operation_id.clone(),
                incarnation.clone(),
                cats_api::runtime_reconciliation::Ipv4Address::new(format!(
                    "10.0.0.{}",
                    route_epoch + 1
                ))
                .unwrap(),
            )),
        );
        registry.insert_cell_for_machine_test(cell).unwrap();
        let command = RouteCommandEnvelope::new(
            Id::new(format!("route_enable_{suffix}")).unwrap(),
            RouteServingBinding {
                workspace_id: Id::new("workspace_route_isolation").unwrap(),
                endpoint_id: endpoint_id.clone(),
                hostname: cats_api::runtime_reconciliation::Hostname::new(format!(
                    "{suffix}.route-command.example.test"
                ))
                .unwrap(),
                cat_id,
                placement_identity: PlacementIdentity {
                    node_id: admission_session.node_id.clone(),
                    placement_epoch: Epoch::new(1).unwrap(),
                },
                effective_runtime_ready: WireEffectiveRuntimeReady {
                    source_lifecycle_operation_id: source_operation_id,
                    runtime_incarnation: incarnation,
                    runtime_config_digest: Sha256Digest::from_bytes([route_epoch as u8; 32]),
                    runtime_ready_receipt_digest: Sha256Digest::from_bytes(
                        [route_epoch as u8 + 1; 32],
                    ),
                },
                route_epoch: Epoch::new(route_epoch).unwrap(),
                admission_session: admission_session.clone(),
                protocol: cats_api::runtime_reconciliation::HttpProtocol::Http,
                target_port: 8080,
            },
            RouteCommandPredecessor::Genesis,
            RouteCommand::Enable,
        )
        .unwrap();
        (command, endpoint_id)
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

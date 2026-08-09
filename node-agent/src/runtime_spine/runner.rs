//! One-step orchestration for the durable signed Node spine.

use std::io;
use std::sync::{mpsc, Arc};
use std::time::Instant;

use cats_api::runtime_reconciliation::{
    inventory_digest, AgentSession, ContractError, ContractErrorDetail, ContractVersion,
    DesiredReadRequest, DesiredReadSnapshot, Epoch, InventorySource, KeyId, NodeObservation,
    NodeResidue, ObservationAcceptance, ObservedRuntimeStatus, RandomId128, RuntimeSpineError,
    RuntimeSpineErrorDetail, Sha256Digest, UnixMillis,
};
use thiserror::Error;

use crate::state_directory::StateDirectory;

use super::{
    DurableRuntimeSpineRequest, RuntimeSpineAttempt, RuntimeSpineDesiredWork, RuntimeSpineFullScan,
    RuntimeSpineHttpClient, RuntimeSpineJournal, RuntimeSpineJournalError, RuntimeSpineRetryReason,
};

/// Performs one bounded scan of every physical source required by Runtime §6.
///
/// The runner, not the scanner, owns protocol identities and the inventory
/// digest. Scanner implementations are read-only and must report every source
/// outage as `Incomplete`; an unavailable source is never an empty success.
pub trait RuntimeInventoryScanner: Send + Sync + 'static {
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome>;
}

#[derive(Debug, Clone)]
pub struct RuntimeInventoryScanContext {
    pub coordinates: RuntimeSpineFullScan,
    pub deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryKeyRing {
    Unavailable,
    Loaded {
        version: Epoch,
        digest: Sha256Digest,
        kids: Vec<KeyId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRuntimeInventory {
    pub observed_at_unix_ms: UnixMillis,
    pub key_ring: RuntimeInventoryKeyRing,
    pub runtimes: Vec<ObservedRuntimeStatus>,
    pub residue: Vec<NodeResidue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryScanOutcome {
    Complete(CompleteRuntimeInventory),
    Incomplete {
        unavailable_sources: Vec<InventorySource>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSpineRunRetry {
    Transport(RuntimeSpineRetryReason),
    DesiredReadInProgress,
}

/// Observable result of one bounded runner iteration.
#[derive(Debug)]
pub enum RuntimeSpineRunStep {
    DesiredAccepted,
    ObservationAccepted,
    RetryExact(RuntimeSpineRunRetry),
    /// A definite server result made the retained Desired cursor unusable.
    DesiredInvalidated {
        status: u16,
        error: RuntimeSpineError,
    },
    /// The current registration/session can no longer authorize new work.
    SessionInvalid {
        status: u16,
        error: RuntimeSpineError,
    },
    /// A definite rejection that cannot safely be repaired by guessing.
    Rejected {
        status: u16,
        error: RuntimeSpineError,
    },
    RouteUnavailable,
    ScanUnavailable(anyhow::Error),
    ScanIncomplete {
        unavailable_sources: Vec<InventorySource>,
    },
    ScanDeadlineExceeded,
}

#[derive(Debug, Error)]
pub enum RuntimeSpineRunError {
    #[error(transparent)]
    Journal(#[from] RuntimeSpineJournalError),
    #[error("runtime-spine canonical request is invalid: {0}")]
    Contract(#[from] ContractError),
    #[error("start runtime-spine {worker} worker: {source}")]
    WorkerStart {
        worker: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("runtime-spine blocking worker stopped: {0}")]
    WorkerStopped(String),
    #[error("runtime-spine scanner returned an invalid outcome: {0}")]
    InvalidScan(&'static str),
}

enum PendingWork {
    Desired(DurableRuntimeSpineRequest<DesiredReadRequest>),
    Observation(DurableRuntimeSpineRequest<NodeObservation>),
    Scan(RuntimeSpineFullScan),
}

enum JournalCommand {
    Next(tokio::sync::oneshot::Sender<Result<PendingWork, RuntimeSpineJournalError>>),
    AcceptDesired {
        snapshot: DesiredReadSnapshot,
        bytes: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>,
    },
    PrepareObservation {
        candidate: NodeObservation,
        reply: tokio::sync::oneshot::Sender<
            Result<DurableRuntimeSpineRequest<NodeObservation>, RuntimeSpineJournalError>,
        >,
    },
    AcceptObservation {
        acceptance: ObservationAcceptance,
        bytes: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>,
    },
    InvalidateDesired(tokio::sync::oneshot::Sender<Result<(), RuntimeSpineJournalError>>),
}

struct JournalLane {
    sender: Option<mpsc::Sender<JournalCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl JournalLane {
    fn start(
        state_directory: StateDirectory,
        registered_session: AgentSession,
    ) -> Result<Self, RuntimeSpineRunError> {
        let (sender, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let guard_state = state_directory.clone();
        let guard_session = registered_session.clone();
        let thread = std::thread::Builder::new()
            .name("cats-runtime-spine-journal".to_owned())
            .spawn(move || {
                let _lane_guard =
                    match RuntimeSpineJournal::open_exclusive(&guard_state, guard_session) {
                        Ok(guard) => {
                            let _ = ready_sender.send(Ok(()));
                            guard
                        }
                        Err(error) => {
                            let _ = ready_sender.send(Err(error));
                            return;
                        }
                    };
                while let Ok(command) = receiver.recv() {
                    match command {
                        JournalCommand::Next(reply) => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    if let Some(pending) = journal.pending_observation() {
                                        return Ok(PendingWork::Observation(pending));
                                    }
                                    match journal.desired_work()? {
                                        RuntimeSpineDesiredWork::Request(request) => {
                                            Ok(PendingWork::Desired(request))
                                        }
                                        RuntimeSpineDesiredWork::Scan(_) => {
                                            Ok(PendingWork::Scan(journal.full_scan()?))
                                        }
                                    }
                                });
                            let _ = reply.send(result);
                        }
                        JournalCommand::AcceptDesired {
                            snapshot,
                            bytes,
                            reply,
                        } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| journal.accept_desired(snapshot, &bytes));
                            let _ = reply.send(result);
                        }
                        JournalCommand::PrepareObservation { candidate, reply } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| journal.prepare_observation(candidate));
                            let _ = reply.send(result);
                        }
                        JournalCommand::AcceptObservation {
                            acceptance,
                            bytes,
                            reply,
                        } => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    journal.accept_observation(acceptance, &bytes)
                                });
                            let _ = reply.send(result);
                        }
                        JournalCommand::InvalidateDesired(reply) => {
                            let result = open_journal(&state_directory, &registered_session)
                                .and_then(|mut journal| {
                                    journal.invalidate_desired_after_observation_rejection()
                                });
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|source| RuntimeSpineRunError::WorkerStart {
                worker: "journal",
                source,
            })?;
        ready_receiver
            .recv()
            .map_err(|_| RuntimeSpineRunError::WorkerStopped("journal startup".to_owned()))??;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    async fn next(&self) -> Result<PendingWork, RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::Next(reply))?;
        receive("journal", received).await
    }

    async fn accept_desired(
        &self,
        snapshot: DesiredReadSnapshot,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::AcceptDesired {
            snapshot,
            bytes,
            reply,
        })?;
        receive("journal", received).await
    }

    async fn prepare_observation(
        &self,
        candidate: NodeObservation,
    ) -> Result<DurableRuntimeSpineRequest<NodeObservation>, RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::PrepareObservation { candidate, reply })?;
        receive("journal", received).await
    }

    async fn accept_observation(
        &self,
        acceptance: ObservationAcceptance,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::AcceptObservation {
            acceptance,
            bytes,
            reply,
        })?;
        receive("journal", received).await
    }

    async fn invalidate_desired(&self) -> Result<(), RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.send(JournalCommand::InvalidateDesired(reply))?;
        receive("journal", received).await
    }

    fn send(&self, command: JournalCommand) -> Result<(), RuntimeSpineRunError> {
        self.sender
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("journal".to_owned()))?
            .send(command)
            .map_err(|_| RuntimeSpineRunError::WorkerStopped("journal".to_owned()))
    }

    async fn shutdown(mut self) -> Result<(), RuntimeSpineRunError> {
        self.sender.take();
        join_worker("journal", self.thread.take()).await
    }
}

fn open_journal(
    state_directory: &StateDirectory,
    registered_session: &AgentSession,
) -> Result<RuntimeSpineJournal, RuntimeSpineJournalError> {
    RuntimeSpineJournal::open(state_directory, registered_session.clone())
}

enum ScanCommand {
    Complete {
        context: RuntimeInventoryScanContext,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<RuntimeInventoryScanOutcome>>,
    },
}

struct ScanLane {
    sender: Option<mpsc::Sender<ScanCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScanLane {
    fn start(scanner: Arc<dyn RuntimeInventoryScanner>) -> Result<Self, RuntimeSpineRunError> {
        let (sender, receiver) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("cats-runtime-spine-scan".to_owned())
            .spawn(move || {
                while let Ok(ScanCommand::Complete { context, reply }) = receiver.recv() {
                    let _ = reply.send(scanner.scan_complete(context));
                }
            })
            .map_err(|source| RuntimeSpineRunError::WorkerStart {
                worker: "inventory scan",
                source,
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    async fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> Result<anyhow::Result<RuntimeInventoryScanOutcome>, RuntimeSpineRunError> {
        let (reply, received) = tokio::sync::oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| RuntimeSpineRunError::WorkerStopped("inventory scan".to_owned()))?
            .send(ScanCommand::Complete { context, reply })
            .map_err(|_| RuntimeSpineRunError::WorkerStopped("inventory scan".to_owned()))?;
        received
            .await
            .map_err(|_| RuntimeSpineRunError::WorkerStopped("inventory scan".to_owned()))
    }

    async fn shutdown(mut self) -> Result<(), RuntimeSpineRunError> {
        self.sender.take();
        join_worker("inventory scan", self.thread.take()).await
    }
}

async fn join_worker(
    worker: &'static str,
    thread: Option<std::thread::JoinHandle<()>>,
) -> Result<(), RuntimeSpineRunError> {
    let Some(thread) = thread else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || thread.join())
        .await
        .map_err(|error| RuntimeSpineRunError::WorkerStopped(format!("{worker}: {error}")))?
        .map_err(|_| RuntimeSpineRunError::WorkerStopped(format!("{worker} panicked")))
}

async fn receive<T>(
    worker: &'static str,
    received: tokio::sync::oneshot::Receiver<Result<T, RuntimeSpineJournalError>>,
) -> Result<T, RuntimeSpineRunError> {
    received
        .await
        .map_err(|_| RuntimeSpineRunError::WorkerStopped(worker.to_owned()))?
        .map_err(RuntimeSpineRunError::from)
}

/// Drives the signed spine without doing filesystem or inventory work on the
/// async executor. Calling `run_once_until` concurrently is intentionally
/// prevented by its `&mut self` receiver.
pub struct RuntimeSpineRunner {
    state_directory: StateDirectory,
    registered_session: AgentSession,
    client: RuntimeSpineHttpClient,
    journal_lane: JournalLane,
    scan_lane: ScanLane,
}

impl std::fmt::Debug for RuntimeSpineRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeSpineRunner")
            .field("state_directory", &self.state_directory)
            .field("registered_session", &self.registered_session)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl RuntimeSpineRunner {
    pub fn new(
        state_directory: StateDirectory,
        registered_session: AgentSession,
        client: RuntimeSpineHttpClient,
        scanner: Arc<dyn RuntimeInventoryScanner>,
    ) -> Result<Self, RuntimeSpineRunError> {
        let journal_lane = JournalLane::start(state_directory.clone(), registered_session.clone())?;
        let scan_lane = ScanLane::start(scanner)?;
        Ok(Self {
            state_directory,
            registered_session,
            client,
            journal_lane,
            scan_lane,
        })
    }

    pub async fn run_once_until(
        &mut self,
        scan_deadline: Instant,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        let work = self.journal_lane.next().await?;

        match work {
            PendingWork::Desired(request) => self.send_desired(request).await,
            PendingWork::Observation(request) => self.send_observation(request).await,
            PendingWork::Scan(scan) => {
                let context = RuntimeInventoryScanContext {
                    coordinates: scan,
                    deadline: scan_deadline,
                };
                let outcome = match self.scan_lane.scan_complete(context.clone()).await? {
                    Ok(outcome) => outcome,
                    Err(error) => return Ok(RuntimeSpineRunStep::ScanUnavailable(error)),
                };
                if Instant::now() >= scan_deadline {
                    return Ok(RuntimeSpineRunStep::ScanDeadlineExceeded);
                }
                let inventory = match outcome {
                    RuntimeInventoryScanOutcome::Complete(inventory) => inventory,
                    RuntimeInventoryScanOutcome::Incomplete {
                        unavailable_sources,
                    } => {
                        if unavailable_sources.is_empty() {
                            return Err(RuntimeSpineRunError::InvalidScan(
                                "an incomplete scan has no unavailable source",
                            ));
                        }
                        return Ok(RuntimeSpineRunStep::ScanIncomplete {
                            unavailable_sources,
                        });
                    }
                };
                let candidate = build_full_observation(context.coordinates, inventory)?;
                let request = self.journal_lane.prepare_observation(candidate).await?;
                self.send_observation(request).await
            }
        }
    }

    /// Stops both ordered workers and waits until no late filesystem or scan
    /// action can outlive this runner. Production session replacement and
    /// process shutdown must use this boundary before constructing a successor.
    pub async fn shutdown(self) -> Result<(), RuntimeSpineRunError> {
        let Self {
            journal_lane,
            scan_lane,
            ..
        } = self;
        journal_lane.shutdown().await?;
        scan_lane.shutdown().await
    }

    async fn send_desired(
        &self,
        request: DurableRuntimeSpineRequest<DesiredReadRequest>,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        match self.client.desired_read(request.bytes()).await? {
            RuntimeSpineAttempt::Accepted(accepted) => {
                self.journal_lane
                    .accept_desired(accepted.value, accepted.bytes)
                    .await?;
                Ok(RuntimeSpineRunStep::DesiredAccepted)
            }
            RuntimeSpineAttempt::RetryExact(reason) => Ok(RuntimeSpineRunStep::RetryExact(
                RuntimeSpineRunRetry::Transport(reason),
            )),
            RuntimeSpineAttempt::RouteUnavailable => Ok(RuntimeSpineRunStep::RouteUnavailable),
            RuntimeSpineAttempt::Rejected { status, error } => {
                if desired_in_progress(&error) {
                    Ok(RuntimeSpineRunStep::RetryExact(
                        RuntimeSpineRunRetry::DesiredReadInProgress,
                    ))
                } else if invalid_session(&error) {
                    Ok(RuntimeSpineRunStep::SessionInvalid { status, error })
                } else {
                    Ok(RuntimeSpineRunStep::Rejected { status, error })
                }
            }
        }
    }

    async fn send_observation(
        &self,
        request: DurableRuntimeSpineRequest<NodeObservation>,
    ) -> Result<RuntimeSpineRunStep, RuntimeSpineRunError> {
        match self.client.observation(request.bytes()).await? {
            RuntimeSpineAttempt::Accepted(accepted) => {
                self.journal_lane
                    .accept_observation(accepted.value, accepted.bytes)
                    .await?;
                Ok(RuntimeSpineRunStep::ObservationAccepted)
            }
            RuntimeSpineAttempt::RetryExact(reason) => Ok(RuntimeSpineRunStep::RetryExact(
                RuntimeSpineRunRetry::Transport(reason),
            )),
            RuntimeSpineAttempt::RouteUnavailable => Ok(RuntimeSpineRunStep::RouteUnavailable),
            RuntimeSpineAttempt::Rejected { status, error } => {
                if invalidates_desired(&error) {
                    self.journal_lane.invalidate_desired().await?;
                    Ok(RuntimeSpineRunStep::DesiredInvalidated { status, error })
                } else if invalid_session(&error) {
                    Ok(RuntimeSpineRunStep::SessionInvalid { status, error })
                } else {
                    Ok(RuntimeSpineRunStep::Rejected { status, error })
                }
            }
        }
    }
}

fn build_full_observation(
    scan: RuntimeSpineFullScan,
    inventory: CompleteRuntimeInventory,
) -> Result<NodeObservation, ContractError> {
    let (key_ring_version, key_ring_digest, loaded_kids) = match inventory.key_ring {
        RuntimeInventoryKeyRing::Unavailable => (None, None, Vec::new()),
        RuntimeInventoryKeyRing::Loaded {
            version,
            digest,
            kids,
        } => (Some(version), Some(digest), kids),
    };
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .expect("a simple UUID is a valid RandomId128"),
        node_id: scan.session.node_id,
        node_boot_id: scan.session.node_boot_id,
        agent_instance_id: scan.session.agent_instance_id,
        agent_session_epoch: scan.session.agent_session_epoch,
        heartbeat_sequence: scan.heartbeat_sequence,
        observed_at_unix_ms: inventory.observed_at_unix_ms,
        complete_inventory: true,
        inventory_epoch: scan.inventory_epoch,
        inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
        inventory_read_position: Some(scan.desired.read_position),
        key_ring_version,
        key_ring_digest,
        loaded_kids,
        runtimes: inventory.runtimes,
        residue: inventory.residue,
    };
    observation.inventory_digest = Some(inventory_digest(&observation)?);
    Ok(observation)
}

fn desired_in_progress(error: &RuntimeSpineError) -> bool {
    matches!(
        error.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(
                contract_error.error.as_ref(),
                ContractErrorDetail::DesiredReadInProgress { .. }
            )
    )
}

fn invalidates_desired(error: &RuntimeSpineError) -> bool {
    matches!(
        error.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(
                contract_error.error.as_ref(),
                ContractErrorDetail::InventoryReadPositionExpired { .. }
                    | ContractErrorDetail::AssignedSetChanged { .. }
            )
    )
}

fn invalid_session(error: &RuntimeSpineError) -> bool {
    match error.error.as_ref() {
        RuntimeSpineErrorDetail::AuthenticationFailed
        | RuntimeSpineErrorDetail::IdentityNotEligible => true,
        RuntimeSpineErrorDetail::ContractError { contract_error } => matches!(
            contract_error.error.as_ref(),
            ContractErrorDetail::MissingAgentSession { .. }
                | ContractErrorDetail::StaleSession { .. }
                | ContractErrorDetail::WrongSession { .. }
                | ContractErrorDetail::SessionExpired { .. }
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
    use cats_api::runtime_reconciliation::{
        decode_agent_session, decode_node_observation, encode_observation_acceptance,
        encode_runtime_spine_error, AdmissionInventoryAttestation, ContractVersion, Id,
        ObservationAcceptance, ObservationInventoryAcceptance, RuntimeSpineErrorDetail,
        SessionBinding, UnixMillis, NODE_OBSERVATION_MAX_WIRE_BYTES,
    };

    use super::*;

    const SESSION: &[u8] = br#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","immutable_host_id":"host_a","lease_deadline_unix_ms":1720000060000,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","registration_attempt_id":"55555555555555555555555555555555","version":1}"#;
    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    struct EmptyScanner {
        calls: AtomicUsize,
    }

    impl RuntimeInventoryScanner for EmptyScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(Instant::now() < context.deadline);
            Ok(RuntimeInventoryScanOutcome::Complete(
                CompleteRuntimeInventory {
                    observed_at_unix_ms: UnixMillis::new(1_720_000_004_000).unwrap(),
                    key_ring: RuntimeInventoryKeyRing::Unavailable,
                    runtimes: Vec::new(),
                    residue: Vec::new(),
                },
            ))
        }
    }

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
    async fn response_loss_replays_the_durable_observation_without_rescanning() {
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let observed_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let serving_calls = Arc::clone(&observation_calls);
        let serving_bodies = Arc::clone(&observed_bodies);
        let app = Router::new()
            .route(
                cats_api::runtime_reconciliation::DESIRED_READ_PATH,
                post(|| async { wire_response(StatusCode::OK, SNAPSHOT.to_vec()) }),
            )
            .route(
                cats_api::runtime_reconciliation::OBSERVATION_PATH,
                post(move |request: Request<Body>| {
                    let calls = Arc::clone(&serving_calls);
                    let bodies = Arc::clone(&serving_bodies);
                    async move {
                        let body = to_bytes(request.into_body(), NODE_OBSERVATION_MAX_WIRE_BYTES)
                            .await
                            .unwrap()
                            .to_vec();
                        bodies.lock().unwrap().push(body.clone());
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            let error = RuntimeSpineError {
                                version: ContractVersion::V1,
                                error: Box::new(RuntimeSpineErrorDetail::TemporarilyUnavailable),
                                message: "retry".to_owned(),
                            };
                            let mut response = wire_response(
                                StatusCode::SERVICE_UNAVAILABLE,
                                encode_runtime_spine_error(&error).unwrap(),
                            );
                            response
                                .headers_mut()
                                .insert(header::RETRY_AFTER, "1".parse().unwrap());
                            return response;
                        }
                        let observation = decode_node_observation(&body).unwrap();
                        let accepted_at = UnixMillis::new(1_720_000_005_000).unwrap();
                        let acceptance = ObservationAcceptance {
                            version: ContractVersion::V1,
                            session: SessionBinding {
                                node_id: observation.node_id.clone(),
                                node_boot_id: observation.node_boot_id.clone(),
                                agent_instance_id: observation.agent_instance_id.clone(),
                                agent_session_epoch: observation.agent_session_epoch,
                            },
                            observation_id: observation.observation_id.clone(),
                            heartbeat_sequence: observation.heartbeat_sequence,
                            accepted_at_unix_ms: accepted_at,
                            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
                            inventory: ObservationInventoryAcceptance::Full {
                                attestation: AdmissionInventoryAttestation {
                                    version: ContractVersion::V1,
                                    node_id: observation.node_id.clone(),
                                    agent_session_epoch: observation.agent_session_epoch,
                                    inventory_epoch: observation.inventory_epoch,
                                    inventory_digest: observation.inventory_digest.clone().unwrap(),
                                    inventory_read_position: observation
                                        .inventory_read_position
                                        .unwrap(),
                                    accepted_at_unix_ms: accepted_at,
                                },
                            },
                        };
                        wire_response(
                            StatusCode::OK,
                            encode_observation_acceptance(&acceptance).unwrap(),
                        )
                    }
                }),
            );
        let (origin, server) = spawn(app).await;
        let scanner = Arc::new(EmptyScanner {
            calls: AtomicUsize::new(0),
        });
        let scanner_port: Arc<dyn RuntimeInventoryScanner> = scanner.clone();
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let registered = decode_agent_session(SESSION).unwrap();
        let client = RuntimeSpineHttpClient::for_loopback_test(&origin, signer()).unwrap();
        let mut runner = RuntimeSpineRunner::new(
            state.clone(),
            registered.clone(),
            client.clone(),
            scanner_port,
        )
        .unwrap();
        let duplicate_scanner: Arc<dyn RuntimeInventoryScanner> = scanner.clone();
        assert!(matches!(
            RuntimeSpineRunner::new(
                state.clone(),
                registered.clone(),
                client.clone(),
                duplicate_scanner,
            ),
            Err(RuntimeSpineRunError::Journal(
                RuntimeSpineJournalError::Io { .. }
            ))
        ));

        assert!(matches!(
            runner
                .run_once_until(Instant::now() + std::time::Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::DesiredAccepted
        ));
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + std::time::Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::RetryExact(RuntimeSpineRunRetry::Transport(
                RuntimeSpineRetryReason::Backpressure
            ))
        ));
        assert!(matches!(
            runner
                .run_once_until(Instant::now() + std::time::Duration::from_secs(5))
                .await
                .unwrap(),
            RuntimeSpineRunStep::ObservationAccepted
        ));

        assert_eq!(scanner.calls.load(Ordering::SeqCst), 1);
        {
            let bodies = observed_bodies.lock().unwrap();
            assert_eq!(bodies.len(), 2);
            assert_eq!(bodies[0], bodies[1]);
        }
        let recovered = RuntimeSpineJournal::open(&state, registered).unwrap();
        assert!(recovered.full_observation().is_some());
        drop(recovered);
        runner.shutdown().await.unwrap();
        let successor_scanner: Arc<dyn RuntimeInventoryScanner> = scanner;
        let successor = RuntimeSpineRunner::new(
            state,
            decode_agent_session(SESSION).unwrap(),
            client,
            successor_scanner,
        )
        .unwrap();
        successor.shutdown().await.unwrap();
        server.abort();
    }
}

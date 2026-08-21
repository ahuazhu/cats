//! Signed pull/result runner for the atomic per-Cat lifecycle protocol.
//!
//! Polling is only a delivery mechanism. Every command is first admitted to
//! its descriptor-safe per-Cat journal, and an owned Cat worker is then the
//! only caller of the physical executor. Transport ambiguity can therefore
//! delay delivery or settlement, but it cannot revoke an accepted command or
//! cause a terminal command to execute again.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_lifecycle::{
    decode_atomic_lifecycle_error, decode_lifecycle_command_batch,
    decode_lifecycle_result_stored_ack, encode_lifecycle_command_poll_request,
    encode_lifecycle_result_commit_request, validate_lifecycle_command_batch_for_poll,
    validate_lifecycle_result_stored_ack_for_response, AtomicLifecycleError, LifecycleCommand,
    LifecycleCommandBatch, LifecycleCommandEnvelope, LifecycleCommandPollRequest,
    LifecycleCommandResponse, LifecycleResultCommitRequest, LifecycleResultStoredAck,
    ATOMIC_LIFECYCLE_ERROR_MAX_WIRE_BYTES, LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES,
    LIFECYCLE_COMMAND_POLL_PATH, LIFECYCLE_INTERNAL_METHOD, LIFECYCLE_RESULT_COMMIT_PATH,
    LIFECYCLE_RESULT_STORED_ACK_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    AgentSession, ContractVersion, Id, Sequence, SessionBinding, Sha256Digest,
};
use thiserror::Error;

use crate::admission_registry::{LifecycleAdmissionRegistry, LifecycleAdmissionRegistryError};
use crate::runtime_inventory::{StartupInventoryCache, StartupInventoryCacheError};
use crate::state_directory::StateDirectory;

#[cfg(test)]
use super::journal::LIFECYCLE_JOURNAL_DIRECTORY_NAME;
use super::journal::{
    AdmitCommandOutcome, CommandJournalState, FileLifecycleCommandJournal, GenesisLocalInventory,
    LifecycleJournalError, LifecycleJournalRecord, LifecycleJournalStartupInventory,
    StartupJournalEntry, StartupPhysicalInventory, StoredLifecycleJournal,
};

#[cfg(not(test))]
const RETRY_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const RETRY_DELAY: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const IDLE_POLL_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const IDLE_POLL_DELAY: Duration = Duration::from_millis(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Owned execution future. Once returned, the runner moves this future into a
/// Cat task and never polls cancellation against it. Graceful shutdown waits
/// for the current bounded executor call before releasing the Host lock.
pub type LifecycleExecutionFuture = Pin<
    Box<
        dyn Future<Output = Result<StoredLifecycleJournal, LifecycleExecutionError>>
            + Send
            + 'static,
    >,
>;

/// One complete union-inventory scan plus provider-private recovery evidence.
///
/// The physical projection is the only value shared with telemetry and Route
/// admission. Provider evidence is retained from that same scan so an
/// executor can bind exact local progress to the sole journal enumeration
/// without rescanning or exposing provider DTOs through the runner.
#[derive(Clone)]
pub struct LifecyclePhysicalInventorySnapshot {
    physical: StartupPhysicalInventory,
    provider_evidence: Arc<dyn Any + Send + Sync>,
}

impl LifecyclePhysicalInventorySnapshot {
    pub fn new<E>(physical: StartupPhysicalInventory, provider_evidence: E) -> Self
    where
        E: Any + Send + Sync,
    {
        Self {
            physical,
            provider_evidence: Arc::new(provider_evidence),
        }
    }

    pub fn physical_only(physical: StartupPhysicalInventory) -> Self {
        Self::new(physical, ())
    }

    pub fn physical(&self) -> &StartupPhysicalInventory {
        &self.physical
    }

    pub fn provider_evidence<E>(&self) -> Option<&E>
    where
        E: Any + Send + Sync,
    {
        self.provider_evidence.as_ref().downcast_ref::<E>()
    }
}

/// One complete union-inventory scan performed before any command recovery,
/// admission, or physical effect in this process.
pub type LifecycleInventoryFuture = Pin<
    Box<
        dyn Future<Output = Result<LifecyclePhysicalInventorySnapshot, LifecycleExecutionError>>
            + Send
            + 'static,
    >,
>;

/// Exact startup join between the sole journal enumeration and provider
/// evidence retained by the sole physical scan. Per-Cat inconsistencies are
/// returned as non-executable or terminal-only quarantines so healthy
/// siblings remain recoverable; only a malformed/global provider snapshot
/// fails the whole startup.
pub type LifecycleStartupBindingFuture = Pin<
    Box<
        dyn Future<Output = Result<LifecycleJournalStartupInventory, LifecycleExecutionError>>
            + Send
            + 'static,
    >,
>;

/// Observation-only startup recovery for a durable terminal command. It may
/// reopen only the process-local effective RuntimeReady projection after
/// verifying the exact same startup scan; failure keeps admission Closed and
/// must not alter or suppress exact terminal result repost.
pub type LifecycleTerminalAdmissionRecoveryFuture =
    Pin<Box<dyn Future<Output = Result<(), LifecycleExecutionError>> + Send + 'static>>;

/// Provider-neutral physical command boundary. The concrete executor owns
/// all six command handlers and their system adapters; the runner owns only
/// durable admission, restart, transport retry, and settlement.
pub trait LifecycleCommandExecutor: Send + Sync + 'static {
    fn physical_inventory(&self) -> LifecycleInventoryFuture;

    fn bind_startup_inventory(
        &self,
        startup: LifecycleJournalStartupInventory,
        snapshot: Arc<LifecyclePhysicalInventorySnapshot>,
    ) -> LifecycleStartupBindingFuture;

    fn recover_terminal_admission(
        &self,
        session: SessionBinding,
        current: StoredLifecycleJournal,
        startup_inventory: Arc<StartupPhysicalInventory>,
    ) -> LifecycleTerminalAdmissionRecoveryFuture;

    fn execute(
        &self,
        journal: Arc<FileLifecycleCommandJournal>,
        current: StoredLifecycleJournal,
    ) -> LifecycleExecutionFuture;
}

#[derive(Debug, Error)]
pub enum LifecycleExecutionError {
    #[error(transparent)]
    Journal(#[from] LifecycleJournalError),
    #[error(transparent)]
    Handler(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleTransportRetryReason {
    Transport,
    InvalidResponse,
    Backpressure,
    ServerFailure,
}

#[derive(Debug)]
pub enum LifecycleTransportAttempt<T> {
    Accepted(T),
    Rejected {
        status: u16,
        error: AtomicLifecycleError,
    },
    RetryExact(LifecycleTransportRetryReason),
    RouteUnavailable,
}

pub type LifecyclePollFuture = Pin<
    Box<dyn Future<Output = LifecycleTransportAttempt<LifecycleCommandBatch>> + Send + 'static>,
>;
pub type LifecycleCommitFuture = Pin<
    Box<dyn Future<Output = LifecycleTransportAttempt<LifecycleResultStoredAck>> + Send + 'static>,
>;

/// Injectable exact-body transport used by the production signed client and
/// by crash/ambiguity characterization tests.
pub trait LifecycleCommandTransport: Send + Sync + 'static {
    fn poll(&self, exact_body: Vec<u8>) -> LifecyclePollFuture;
    fn commit(&self, exact_body: Vec<u8>) -> LifecycleCommitFuture;
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

/// No-redirect signed client for the two frozen lifecycle internal routes.
#[derive(Clone)]
pub struct LifecycleCommandHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::Client,
}

impl std::fmt::Debug for LifecycleCommandHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LifecycleCommandHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl LifecycleCommandHttpClient {
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
            .context("build atomic lifecycle HTTP client")?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }

    async fn post<T>(
        &self,
        path: &'static str,
        exact_body: Vec<u8>,
        success_cap: usize,
        decode_success: fn(
            &[u8],
        )
            -> Result<T, cats_api::runtime_lifecycle::RuntimeLifecycleContractError>,
    ) -> LifecycleTransportAttempt<T> {
        let proof = self
            .signer
            .sign(LIFECYCLE_INTERNAL_METHOD, path, &exact_body);
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
            .body(exact_body)
            .send()
            .await;
        classify_response(response, success_cap, decode_success).await
    }
}

impl LifecycleCommandTransport for LifecycleCommandHttpClient {
    fn poll(&self, exact_body: Vec<u8>) -> LifecyclePollFuture {
        let client = self.clone();
        Box::pin(async move {
            client
                .post(
                    LIFECYCLE_COMMAND_POLL_PATH,
                    exact_body,
                    LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES,
                    decode_lifecycle_command_batch,
                )
                .await
        })
    }

    fn commit(&self, exact_body: Vec<u8>) -> LifecycleCommitFuture {
        let client = self.clone();
        Box::pin(async move {
            client
                .post(
                    LIFECYCLE_RESULT_COMMIT_PATH,
                    exact_body,
                    LIFECYCLE_RESULT_STORED_ACK_MAX_WIRE_BYTES,
                    decode_lifecycle_result_stored_ack,
                )
                .await
        })
    }
}

#[derive(Debug, Error)]
pub enum LifecycleRunnerError {
    #[error("invalid atomic lifecycle contract: {context}")]
    InvalidContract { context: &'static str },
    #[error("atomic lifecycle journal for Cat {cat_id} is blocked: {reason}")]
    CatBlocked { cat_id: Id, reason: String },
    #[error("atomic lifecycle transport route is unavailable: {path}")]
    RouteUnavailable { path: &'static str },
    #[error(
        "atomic lifecycle transport definitely rejected {operation} with HTTP {status}: {error:?}"
    )]
    Rejected {
        operation: &'static str,
        status: u16,
        error: AtomicLifecycleError,
    },
    #[error("atomic lifecycle poll request sequence exhausted")]
    SequenceExhausted,
    #[error("atomic lifecycle worker for Cat {cat_id} failed: {source}")]
    Worker {
        cat_id: Id,
        #[source]
        source: Box<LifecycleRunnerError>,
    },
    #[error("atomic lifecycle executor for Cat {cat_id} failed: {source}")]
    Execution {
        cat_id: Id,
        #[source]
        source: LifecycleExecutionError,
    },
    #[error("atomic lifecycle journal operation failed: {0}")]
    Journal(#[from] LifecycleJournalError),
    #[error("atomic lifecycle admission registry startup failed: {0}")]
    AdmissionRegistry(#[from] LifecycleAdmissionRegistryError),
    #[error("atomic lifecycle startup inventory handoff failed: {0}")]
    StartupInventory(#[from] StartupInventoryCacheError),
    #[error("join atomic lifecycle Cat worker: {0}")]
    Join(#[from] tokio::task::JoinError),
}

struct ActiveCatWorker {
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    task: tokio::task::JoinHandle<Result<(), LifecycleRunnerError>>,
}

/// One process-owned signed lifecycle runner. It is deliberately independent
/// of observation settlement and keeps one owned worker at most per Cat.
pub struct LifecycleCommandRunner {
    state_directory: StateDirectory,
    session: AgentSession,
    transport: Arc<dyn LifecycleCommandTransport>,
    executor: Arc<dyn LifecycleCommandExecutor>,
    admission_registry: Arc<LifecycleAdmissionRegistry>,
    startup_inventory: Arc<StartupPhysicalInventory>,
    request_sequence: u64,
    physical_residue: BTreeSet<Id>,
    unattributed_physical_residue: bool,
    blocked: BTreeMap<Id, String>,
    startup_terminal_quarantine: BTreeMap<Id, String>,
    pending_recovery: Vec<StartupJournalEntry>,
    workers: BTreeMap<Id, ActiveCatWorker>,
    external_shutdown: tokio::sync::watch::Receiver<bool>,
    worker_shutdown: tokio::sync::watch::Sender<bool>,
}

impl LifecycleCommandRunner {
    pub async fn open(
        state_directory: StateDirectory,
        session: AgentSession,
        transport: Arc<dyn LifecycleCommandTransport>,
        executor: Arc<dyn LifecycleCommandExecutor>,
        admission_registry: Arc<LifecycleAdmissionRegistry>,
        startup_inventory_cache: Arc<StartupInventoryCache>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self, LifecycleRunnerError> {
        let physical_snapshot = executor.physical_inventory().await.map_err(|source| {
            LifecycleRunnerError::Execution {
                cat_id: Id::new("complete_inventory")
                    .expect("static lifecycle inventory ID is valid"),
                source,
            }
        })?;
        let physical_snapshot = Arc::new(physical_snapshot);
        let physical_inventory = Arc::new(physical_snapshot.physical().clone());
        startup_inventory_cache.initialize_physical(&session, &physical_inventory)?;
        let physical_residue = physical_inventory.physical_cat_ids()?;
        let unattributed_physical_residue = physical_inventory.has_unattributed_artifacts();
        // The registry, executor and Route listener share one process-global
        // handle. Initialize it from this exact scan before any Cat worker or
        // Route listener can observe a cell; the returned startup enumeration
        // is also the sole recovery input for this runner.
        let startup = admission_registry.initialize_fail_closed_once(
            session_binding(&session),
            &state_directory,
            &physical_inventory,
        )?;
        let enumerated_startup = startup.clone();
        let startup = executor
            .bind_startup_inventory(startup, Arc::clone(&physical_snapshot))
            .await
            .map_err(|source| LifecycleRunnerError::Execution {
                cat_id: Id::new("bind_startup_inventory")
                    .expect("static lifecycle startup binding ID is valid"),
                source,
            })?;
        validate_startup_binding(&enumerated_startup, &startup)?;
        admission_registry.apply_startup_binding_fail_closed(&startup)?;
        startup_inventory_cache.join_and_publish_once(&session, &startup)?;
        let LifecycleJournalStartupInventory {
            recoverable,
            blocked,
            quarantined_commands,
            quarantined_terminals,
        } = startup;
        let mut blocked_cats = blocked
            .into_iter()
            .map(|blocked| (blocked.cat_id, blocked.reason))
            .collect::<BTreeMap<_, _>>();
        blocked_cats.extend(
            quarantined_commands
                .into_iter()
                .map(|quarantined| (quarantined.entry.cat_id, quarantined.reason)),
        );
        let (worker_shutdown, _) = tokio::sync::watch::channel(false);
        Ok(Self {
            state_directory,
            session,
            transport,
            executor,
            admission_registry,
            startup_inventory: physical_inventory,
            request_sequence: 1,
            physical_residue,
            unattributed_physical_residue,
            blocked: blocked_cats,
            startup_terminal_quarantine: quarantined_terminals
                .into_iter()
                .map(|quarantined| (quarantined.cat_id, quarantined.reason))
                .collect(),
            pending_recovery: recoverable,
            workers: BTreeMap::new(),
            external_shutdown: shutdown,
            worker_shutdown,
        })
    }

    pub fn blocked_cats(&self) -> &BTreeMap<Id, String> {
        &self.blocked
    }

    pub fn quarantined_terminal_cats(&self) -> &BTreeMap<Id, String> {
        &self.startup_terminal_quarantine
    }

    pub async fn run(mut self) -> Result<(), LifecycleRunnerError> {
        let startup_result = self.start_pending_recovery();
        let run_result = match startup_result {
            Ok(()) => self.run_loop().await,
            Err(error) => Err(error),
        };
        let _ = self.worker_shutdown.send(true);
        let shutdown_result = self.finish_shutdown().await;
        match (run_result, shutdown_result) {
            (Err(error), _) => Err(error),
            (Ok(()), result) => result,
        }
    }

    async fn run_loop(&mut self) -> Result<(), LifecycleRunnerError> {
        loop {
            self.reap_finished().await;
            if *self.external_shutdown.borrow() {
                return Ok(());
            }

            let poll = self.current_poll()?;
            let exact_poll = encode_lifecycle_command_poll_request(&poll).map_err(|_| {
                LifecycleRunnerError::InvalidContract {
                    context: "encode current lifecycle poll",
                }
            })?;
            match self.transport.poll(exact_poll).await {
                LifecycleTransportAttempt::Accepted(batch) => {
                    validate_lifecycle_command_batch_for_poll(&batch, &poll, &self.session)
                        .map_err(|_| LifecycleRunnerError::InvalidContract {
                            context: "validate exact lifecycle batch echo",
                        })?;
                    let empty = batch.commands.is_empty();
                    let made_progress = self.dispatch_batch(batch.commands)?;
                    self.advance_sequence()?;
                    if empty || !made_progress {
                        // A level-triggered repeat for an already-owned Cat is
                        // not work. Back off so an immediately-ready transport
                        // cannot starve that Cat worker, shutdown, or timers on
                        // a single-thread Tokio runtime.
                        self.wait_or_shutdown(IDLE_POLL_DELAY).await;
                    } else {
                        // The transport may also be an immediately-ready local
                        // implementation. Give the newly-owned worker one
                        // scheduling edge before polling again.
                        tokio::task::yield_now().await;
                    }
                }
                LifecycleTransportAttempt::RetryExact(reason) => {
                    tracing::warn!(?reason, "retrying exact atomic lifecycle poll");
                    self.wait_or_shutdown(RETRY_DELAY).await;
                }
                LifecycleTransportAttempt::RouteUnavailable => {
                    return Err(LifecycleRunnerError::RouteUnavailable {
                        path: LIFECYCLE_COMMAND_POLL_PATH,
                    })
                }
                LifecycleTransportAttempt::Rejected { status, error } => {
                    return Err(LifecycleRunnerError::Rejected {
                        operation: "command poll",
                        status,
                        error,
                    })
                }
            }
        }
    }

    fn current_poll(&self) -> Result<LifecycleCommandPollRequest, LifecycleRunnerError> {
        let request_sequence =
            Sequence::new(self.request_sequence).ok_or(LifecycleRunnerError::SequenceExhausted)?;
        Ok(LifecycleCommandPollRequest {
            version: ContractVersion::V1,
            session: session_binding(&self.session),
            request_sequence,
        })
    }

    fn advance_sequence(&mut self) -> Result<(), LifecycleRunnerError> {
        let next = self
            .request_sequence
            .checked_add(1)
            .ok_or(LifecycleRunnerError::SequenceExhausted)?;
        Sequence::new(next).ok_or(LifecycleRunnerError::SequenceExhausted)?;
        self.request_sequence = next;
        Ok(())
    }

    fn start_recovered(
        &mut self,
        enumerated: StartupJournalEntry,
    ) -> Result<(), LifecycleRunnerError> {
        let cat_id = enumerated.cat_id;
        if self.blocked.contains_key(&cat_id) {
            return Ok(());
        }
        let journal = match FileLifecycleCommandJournal::open_in_state_directory(
            &self.state_directory,
            &cat_id,
        ) {
            Ok(journal) => Arc::new(journal),
            Err(error) => {
                self.blocked.insert(cat_id, error.to_string());
                return Ok(());
            }
        };
        let current = match journal.load() {
            Ok(Some(current)) => current,
            Ok(None) => {
                self.blocked.insert(
                    cat_id,
                    "startup lifecycle journal disappeared after its sole enumeration".into(),
                );
                return Ok(());
            }
            Err(error) => {
                self.blocked.insert(cat_id, error.to_string());
                return Ok(());
            }
        };
        if current.content_digest() != &enumerated.journal_digest
            || current.record() != &enumerated.record
        {
            self.blocked.insert(
                cat_id,
                "startup lifecycle journal changed after its sole enumeration".into(),
            );
            return Ok(());
        }
        let recover_terminal_admission = !self.startup_terminal_quarantine.contains_key(&cat_id);
        self.spawn_worker(cat_id, journal, current, recover_terminal_admission)
    }

    fn start_pending_recovery(&mut self) -> Result<(), LifecycleRunnerError> {
        for entry in std::mem::take(&mut self.pending_recovery) {
            self.start_recovered(entry)?;
        }
        Ok(())
    }

    fn dispatch_batch(
        &mut self,
        commands: Vec<LifecycleCommandEnvelope>,
    ) -> Result<bool, LifecycleRunnerError> {
        let mut made_progress = false;
        for command in commands {
            let cat_id = command.cat_id.clone();
            if self.blocked.contains_key(&cat_id) {
                continue;
            }
            if let Some(active) = self.workers.get(&cat_id) {
                if active.operation_id == command.operation_id
                    && active.request_fingerprint == command.request_fingerprint
                {
                    continue;
                }
                // Result settlement and level-triggered polling are separate
                // tasks. Control can durably accept the predecessor result
                // and expose its successor in the narrow window before this
                // loop observes that the predecessor worker returned. The
                // owned worker remains the sole local effect authority, so
                // defer the successor and let Control repeat it after reap;
                // the journal will then validate the exact terminal edge.
                continue;
            }

            let journal = match FileLifecycleCommandJournal::open_in_state_directory(
                &self.state_directory,
                &cat_id,
            ) {
                Ok(journal) => Arc::new(journal),
                Err(error) => {
                    self.blocked.insert(cat_id, error.to_string());
                    continue;
                }
            };
            let genesis_inventory = if self.physical_residue.contains(&cat_id) {
                GenesisLocalInventory::PhysicalResidue {
                    description: "complete startup inventory found Cat-owned physical residue"
                        .into(),
                }
            } else if self.unattributed_physical_residue {
                GenesisLocalInventory::PhysicalResidue {
                    description:
                        "complete startup inventory contains unattributed physical artifacts".into(),
                }
            } else {
                GenesisLocalInventory::ConfirmedEmpty
            };
            match journal.admit_api(&command, genesis_inventory) {
                Ok(AdmitCommandOutcome::Accepted(current))
                | Ok(AdmitCommandOutcome::Replay(current)) => {
                    if matches!(&command.command, LifecycleCommand::Start(_)) {
                        if let Err(error) = self
                            .admission_registry
                            .ensure_initial_target_fail_closed(&command)
                        {
                            self.blocked.insert(cat_id, error.to_string());
                            continue;
                        }
                    }
                    self.spawn_worker(cat_id, journal, current, false)?;
                    made_progress = true;
                }
                Ok(AdmitCommandOutcome::Superseded { .. }) => {
                    // A delayed predecessor batch is observation-only. Its
                    // successor already owns the sole local effect authority.
                }
                Err(error) => {
                    self.blocked.insert(cat_id, error.to_string());
                }
            }
        }
        Ok(made_progress)
    }

    fn spawn_worker(
        &mut self,
        cat_id: Id,
        journal: Arc<FileLifecycleCommandJournal>,
        current: StoredLifecycleJournal,
        recover_terminal_admission: bool,
    ) -> Result<(), LifecycleRunnerError> {
        if self.workers.contains_key(&cat_id) {
            return Err(LifecycleRunnerError::CatBlocked {
                cat_id,
                reason: "attempted to start a second local Cat worker".into(),
            });
        }
        let operation_id = current.record().operation_id().clone();
        let request_fingerprint = current.record().request_fingerprint().clone();
        let executor = Arc::clone(&self.executor);
        let startup_inventory = Arc::clone(&self.startup_inventory);
        let transport = Arc::clone(&self.transport);
        let session = self.session.clone();
        let worker_shutdown = self.worker_shutdown.subscribe();
        let worker_cat = cat_id.clone();
        let task = tokio::spawn(async move {
            run_cat_worker(CatWorkerContext {
                cat_id: worker_cat,
                journal,
                current,
                session,
                transport,
                executor,
                startup_inventory,
                recover_terminal_admission,
                shutdown: worker_shutdown,
            })
            .await
        });
        self.workers.insert(
            cat_id,
            ActiveCatWorker {
                operation_id,
                request_fingerprint,
                task,
            },
        );
        Ok(())
    }

    async fn reap_finished(&mut self) {
        let finished = self
            .workers
            .iter()
            .filter_map(|(cat_id, worker)| worker.task.is_finished().then_some(cat_id.clone()))
            .collect::<Vec<_>>();
        for cat_id in finished {
            let worker = self
                .workers
                .remove(&cat_id)
                .expect("finished Cat worker remained present");
            match worker.task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.blocked.insert(cat_id, error.to_string());
                }
                Err(error) => {
                    self.blocked.insert(cat_id, error.to_string());
                }
            }
        }
    }

    async fn finish_shutdown(&mut self) -> Result<(), LifecycleRunnerError> {
        let mut first_error = None;
        for (cat_id, worker) in std::mem::take(&mut self.workers) {
            match worker.task.await {
                Ok(Ok(())) => {}
                Ok(Err(source)) if first_error.is_none() => {
                    first_error = Some(LifecycleRunnerError::Worker {
                        cat_id,
                        source: Box::new(source),
                    });
                }
                Err(source) if first_error.is_none() => {
                    first_error = Some(LifecycleRunnerError::Worker {
                        cat_id,
                        source: Box::new(LifecycleRunnerError::Join(source)),
                    });
                }
                Ok(Err(_)) | Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn wait_or_shutdown(&mut self, duration: Duration) {
        if *self.external_shutdown.borrow() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(duration) => {}
            changed = self.external_shutdown.changed() => {
                if changed.is_err() {
                    // Sender loss is equivalent to process shutdown.
                    self.external_shutdown = closed_shutdown_receiver();
                }
            }
        }
    }
}

struct CatWorkerContext {
    cat_id: Id,
    journal: Arc<FileLifecycleCommandJournal>,
    current: StoredLifecycleJournal,
    session: AgentSession,
    transport: Arc<dyn LifecycleCommandTransport>,
    executor: Arc<dyn LifecycleCommandExecutor>,
    startup_inventory: Arc<StartupPhysicalInventory>,
    recover_terminal_admission: bool,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

async fn run_cat_worker(worker: CatWorkerContext) -> Result<(), LifecycleRunnerError> {
    let CatWorkerContext {
        cat_id,
        journal,
        mut current,
        session,
        transport,
        executor,
        startup_inventory,
        recover_terminal_admission,
        mut shutdown,
    } = worker;
    if recover_terminal_admission && terminal_response(&current)?.is_some() {
        if let Err(error) = executor
            .recover_terminal_admission(
                session_binding(&session),
                current.clone(),
                startup_inventory,
            )
            .await
        {
            tracing::warn!(
                cat_id = %cat_id,
                error = %error,
                "startup terminal admission remained Closed after physical verification"
            );
        }
    }
    loop {
        let response = terminal_response(&current)?;
        if let Some(response) = response {
            return settle_terminal(
                &cat_id,
                &journal,
                &session,
                transport.as_ref(),
                response,
                &mut shutdown,
            )
            .await;
        }

        if *shutdown.borrow() {
            return Ok(());
        }
        let expected_operation = current.record().operation_id().clone();
        let expected_fingerprint = current.record().request_fingerprint().clone();
        // Do not select this owned future against shutdown. Cancellation may
        // request that no *new* effect begins, but cannot revoke the accepted
        // command or drop a bounded effect at an ambiguous physical boundary.
        match executor.execute(Arc::clone(&journal), current).await {
            Ok(next) => {
                if next.record().operation_id() != &expected_operation
                    || next.record().request_fingerprint() != &expected_fingerprint
                {
                    return Err(LifecycleRunnerError::InvalidContract {
                        context: "executor returned another command identity",
                    });
                }
                current = next;
                if terminal_response(&current)?.is_none() {
                    return Err(LifecycleRunnerError::InvalidContract {
                        context: "executor returned before a durable terminal record",
                    });
                }
            }
            Err(source) => {
                tracing::warn!(
                    cat_id = %cat_id,
                    error = %source,
                    "atomic lifecycle executor retained its journal for exact retry"
                );
                if *shutdown.borrow() {
                    return Ok(());
                }
                tokio::time::sleep(RETRY_DELAY).await;
                current = journal
                    .load()?
                    .ok_or(LifecycleRunnerError::InvalidContract {
                        context: "accepted command journal disappeared after executor error",
                    })?;
            }
        }
    }
}

fn terminal_response(
    current: &StoredLifecycleJournal,
) -> Result<Option<LifecycleCommandResponse>, LifecycleRunnerError> {
    match current.record() {
        LifecycleJournalRecord::Command {
            state: CommandJournalState::Terminal { result, .. },
            ..
        } => result
            .decode_api()
            .map(Some)
            .map_err(LifecycleRunnerError::Journal),
        LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } => {
            Ok(Some((*receipt.terminal_response).clone()))
        }
        LifecycleJournalRecord::Command { .. } => Ok(None),
    }
}

async fn settle_terminal(
    cat_id: &Id,
    journal: &FileLifecycleCommandJournal,
    session: &AgentSession,
    transport: &dyn LifecycleCommandTransport,
    response: LifecycleCommandResponse,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), LifecycleRunnerError> {
    let commit = LifecycleResultCommitRequest::new(session, response.clone()).map_err(|_| {
        LifecycleRunnerError::InvalidContract {
            context: "construct exact lifecycle result commit",
        }
    })?;
    let exact_commit = encode_lifecycle_result_commit_request(&commit).map_err(|_| {
        LifecycleRunnerError::InvalidContract {
            context: "encode exact lifecycle result commit",
        }
    })?;
    loop {
        match transport.commit(exact_commit.clone()).await {
            LifecycleTransportAttempt::Accepted(ack) => {
                if validate_lifecycle_result_stored_ack_for_response(&ack, &response).is_err() {
                    tracing::warn!(
                        cat_id = %cat_id,
                        "ignoring mismatched lifecycle result-stored acknowledgement and reposting the exact result"
                    );
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
                if matches!(
                    journal.load()?.as_ref().map(StoredLifecycleJournal::record),
                    Some(LifecycleJournalRecord::CompletedDeleteReceipt { .. })
                ) {
                    journal.acknowledge_delete(&ack)?;
                }
                return Ok(());
            }
            LifecycleTransportAttempt::RetryExact(reason) => {
                tracing::warn!(
                    cat_id = %cat_id,
                    ?reason,
                    "reposting exact durable lifecycle terminal result"
                );
                if *shutdown.borrow() {
                    return Ok(());
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
            LifecycleTransportAttempt::RouteUnavailable => {
                tracing::error!(
                    cat_id = %cat_id,
                    path = LIFECYCLE_RESULT_COMMIT_PATH,
                    "lifecycle result route is unavailable; retaining and reposting the exact terminal result"
                );
                if *shutdown.borrow() {
                    return Ok(());
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
            LifecycleTransportAttempt::Rejected { status, error } => {
                tracing::error!(
                    cat_id = %cat_id,
                    status,
                    ?error,
                    "lifecycle result commit was rejected; retaining and reposting the exact terminal result"
                );
                if *shutdown.borrow() {
                    return Ok(());
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn validate_startup_binding(
    enumerated: &LifecycleJournalStartupInventory,
    bound: &LifecycleJournalStartupInventory,
) -> Result<(), LifecycleRunnerError> {
    fn entries(
        startup: &LifecycleJournalStartupInventory,
    ) -> Option<BTreeMap<Id, StartupJournalEntry>> {
        let recoverable_sorted = startup
            .recoverable
            .windows(2)
            .all(|pair| pair[0].cat_id < pair[1].cat_id);
        let quarantined_sorted = startup
            .quarantined_commands
            .windows(2)
            .all(|pair| pair[0].entry.cat_id < pair[1].entry.cat_id);
        if !recoverable_sorted || !quarantined_sorted {
            return None;
        }
        let mut entries = BTreeMap::new();
        for entry in &startup.recoverable {
            if entries
                .insert(entry.cat_id.clone(), entry.clone())
                .is_some()
            {
                return None;
            }
        }
        for quarantined in &startup.quarantined_commands {
            if journal_record_is_terminal(&quarantined.entry.record)
                || entries
                    .insert(quarantined.entry.cat_id.clone(), quarantined.entry.clone())
                    .is_some()
            {
                return None;
            }
        }
        Some(entries)
    }

    let Some(enumerated_entries) = entries(enumerated) else {
        return Err(LifecycleRunnerError::InvalidContract {
            context: "sole startup journal enumeration is not a canonical partition",
        });
    };
    let Some(bound_entries) = entries(bound) else {
        return Err(LifecycleRunnerError::InvalidContract {
            context: "startup physical binding is not a canonical journal partition",
        });
    };
    if enumerated.blocked != bound.blocked || enumerated_entries != bound_entries {
        return Err(LifecycleRunnerError::InvalidContract {
            context: "startup physical binding changed or dropped the sole journal enumeration",
        });
    }

    let original_terminal_quarantine = enumerated
        .quarantined_terminals
        .iter()
        .map(|entry| entry.cat_id.clone())
        .collect::<BTreeSet<_>>();
    let mut terminal_quarantine = BTreeSet::new();
    for quarantined in &bound.quarantined_terminals {
        if !terminal_quarantine.insert(quarantined.cat_id.clone())
            || bound
                .recoverable
                .iter()
                .find(|entry| entry.cat_id == quarantined.cat_id)
                .is_none_or(|entry| !journal_record_is_terminal(&entry.record))
        {
            return Err(LifecycleRunnerError::InvalidContract {
                context: "startup physical binding returned an invalid terminal quarantine",
            });
        }
    }
    if !original_terminal_quarantine.is_subset(&terminal_quarantine)
        || bound
            .quarantined_terminals
            .windows(2)
            .any(|pair| pair[0].cat_id >= pair[1].cat_id)
    {
        return Err(LifecycleRunnerError::InvalidContract {
            context: "startup physical binding removed or reordered terminal quarantine",
        });
    }
    Ok(())
}

fn journal_record_is_terminal(record: &LifecycleJournalRecord) -> bool {
    matches!(
        record,
        LifecycleJournalRecord::Command {
            state: CommandJournalState::Terminal { .. },
            ..
        } | LifecycleJournalRecord::CompletedDeleteReceipt { .. }
    )
}

fn closed_shutdown_receiver() -> tokio::sync::watch::Receiver<bool> {
    let (_sender, receiver) = tokio::sync::watch::channel(true);
    receiver
}

async fn classify_response<T>(
    response: Result<reqwest::Response, reqwest::Error>,
    success_cap: usize,
    decode_success: fn(
        &[u8],
    )
        -> Result<T, cats_api::runtime_lifecycle::RuntimeLifecycleContractError>,
) -> LifecycleTransportAttempt<T> {
    let mut response = match response {
        Ok(response) => response,
        Err(_) => {
            return LifecycleTransportAttempt::RetryExact(LifecycleTransportRetryReason::Transport)
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return LifecycleTransportAttempt::RouteUnavailable;
    }
    let cap = if status == reqwest::StatusCode::OK {
        success_cap
    } else {
        ATOMIC_LIFECYCLE_ERROR_MAX_WIRE_BYTES
    };
    if !valid_common_headers(response.headers())
        || declared_response_exceeds(response.headers(), cap)
    {
        return LifecycleTransportAttempt::RetryExact(
            LifecycleTransportRetryReason::InvalidResponse,
        );
    }
    let Some(body) = read_bounded_body(&mut response, cap).await else {
        return LifecycleTransportAttempt::RetryExact(
            LifecycleTransportRetryReason::InvalidResponse,
        );
    };
    if status == reqwest::StatusCode::OK {
        return match decode_success(&body) {
            Ok(value) => LifecycleTransportAttempt::Accepted(value),
            Err(_) => LifecycleTransportAttempt::RetryExact(
                LifecycleTransportRetryReason::InvalidResponse,
            ),
        };
    }
    let error = match decode_atomic_lifecycle_error(&body) {
        Ok(error) => error,
        Err(_) => {
            return LifecycleTransportAttempt::RetryExact(
                LifecycleTransportRetryReason::InvalidResponse,
            )
        }
    };
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
    {
        LifecycleTransportAttempt::RetryExact(LifecycleTransportRetryReason::Backpressure)
    } else if status.is_server_error() {
        LifecycleTransportAttempt::RetryExact(LifecycleTransportRetryReason::ServerFailure)
    } else if status == reqwest::StatusCode::UNAUTHORIZED
        && !has_one_exact_header(
            response.headers(),
            reqwest::header::WWW_AUTHENTICATE,
            NODE_AUTHENTICATE_CHALLENGE,
        )
    {
        LifecycleTransportAttempt::RetryExact(LifecycleTransportRetryReason::InvalidResponse)
    } else {
        LifecycleTransportAttempt::Rejected {
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

fn valid_common_headers(headers: &reqwest::header::HeaderMap) -> bool {
    !headers.contains_key(reqwest::header::CONTENT_ENCODING)
        && has_one_header_ows_case_insensitive(
            headers,
            reqwest::header::CONTENT_TYPE,
            JSON_CONTENT_TYPE,
        )
        && has_one_exact_header(headers, reqwest::header::CACHE_CONTROL, "no-store")
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
        TransportMode::ProductionHttps => anyhow::ensure!(
            url.scheme() == "https",
            "production Control Plane origin must use HTTPS"
        ),
        TransportMode::LoopbackTest => anyhow::ensure!(
            url.scheme() == "http"
                && url
                    .host_str()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")),
            "test Control Plane origin must be loopback HTTP"
        ),
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use cats_api::agent_registration::verify_request_proof;
    use cats_api::runtime_inventory::{ObservedCatRuntimeTelemetry, ObservedRuntimePhysicalState};
    use cats_api::runtime_lifecycle::{
        decode_lifecycle_command_poll_request, decode_lifecycle_result_commit_request,
        encode_lifecycle_command_batch, DiskRole, ExecutionAbsenceProof, ImmutableRuntimeConfig,
        KilledResult, LifecycleCommand, LifecyclePredecessor, NodeResult, PlacementIdentity,
        RetainedEvidence, RuntimeNetworkConfig, RuntimeReadyResult, RuntimeVolumeAuthorityInput,
        RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StartSource, StartSpec,
        StartVolumeAuthority, StopSpec, TerminalResultKind, VolumeTerminalReceipt,
    };
    use cats_api::runtime_reconciliation::{
        Durability, Epoch, FenceEpoch, Generation, Ipv4Address, MacAddress, NodeBootId,
        RandomId128, UnixMillis,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::lifecycle_command::journal::{
        ExactBytes, ExactCommandResult, ExecutionStep, LifecycleJournalRecord,
        QuarantinedStartupJournalEntry, QuarantinedTerminalStartupCat,
    };

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).expect("valid test random ID")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn empty_physical_inventory() -> StartupPhysicalInventory {
        StartupPhysicalInventory::Complete {
            scan_id: random(90),
            collected_at_unix_ms: UnixMillis::new(1_000).expect("valid collection time"),
            cats: Vec::new(),
            unattributed_artifacts: Vec::new(),
        }
    }

    fn session() -> AgentSession {
        AgentSession {
            version: ContractVersion::V1,
            node_id: id("node_runner"),
            immutable_host_id: id("host_runner"),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111")
                .expect("valid boot ID"),
            agent_instance_id: random(2),
            agent_session_epoch: Epoch::new(1).expect("positive session epoch"),
            registration_attempt_id: random(3),
            guest_config_digest: digest(4),
            lease_deadline_unix_ms: UnixMillis::new(9_000_000).expect("valid session deadline"),
        }
    }

    fn signer() -> Ed25519RequestSigner {
        let mut der =
            hex::decode("302e020100300506032b657004220420").expect("valid Ed25519 PKCS#8 prefix");
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .expect("valid Ed25519 test key"),
        );
        Ed25519RequestSigner::from_pkcs8_der(id("credential_runner"), &der)
            .expect("valid request signer")
    }

    async fn spawn_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback server");
        let address = listener.local_addr().expect("loopback address");
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve loopback lifecycle endpoint")
        });
        (format!("http://{address}/"), task)
    }

    fn wire_response(body: Vec<u8>) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .expect("valid lifecycle response")
    }

    fn runtime_config(cat_id: &str) -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id(&format!("config_{cat_id}")),
            digest(5),
            2,
            512 * 1024 * 1024,
            digest(6),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id(&format!("network_{cat_id}")),
                guest_mac: MacAddress::new("02:00:00:00:00:11").expect("valid MAC"),
                guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid gateway IP"),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id(&format!("volume_{cat_id}_root")),
                disk_id: id(&format!("disk_{cat_id}_root")),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("runner_root_serial"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .expect("valid runtime config")
    }

    fn command_for(
        operation_id: &str,
        cat_id: &str,
        cat_creation_id: &str,
    ) -> LifecycleCommandEnvelope {
        let placement = PlacementIdentity {
            node_id: id("node_runner"),
            placement_epoch: Epoch::new(1).expect("positive placement epoch"),
        };
        let runtime_config = runtime_config(cat_id);
        let root_volume_id = runtime_config.volumes[0].volume_id.clone();
        let root_disk_id = runtime_config.volumes[0].disk_id.clone();
        LifecycleCommandEnvelope::new(
            id(operation_id),
            id("workspace_runner"),
            id(cat_id),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id(cat_creation_id),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: root_volume_id,
                    disk_id: root_disk_id,
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).expect("zero fence epoch"),
                        transition_id: random(7),
                    },
                }],
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000).expect("valid effect deadline"),
            })),
        )
        .expect("valid Genesis Start")
    }

    fn command() -> LifecycleCommandEnvelope {
        command_for("operation_runner_start", "cat_runner", "creation_runner")
    }

    fn stop_command_for(
        operation_id: &str,
        predecessor_command: &LifecycleCommandEnvelope,
        predecessor_response: &LifecycleCommandResponse,
    ) -> LifecycleCommandEnvelope {
        let terminal_result_digest =
            LifecycleResultCommitRequest::new(&session(), predecessor_response.clone())
                .expect("valid predecessor commit")
                .terminal_result_digest;
        LifecycleCommandEnvelope::new(
            id(operation_id),
            predecessor_response.workspace_id.clone(),
            predecessor_response.cat_id.clone(),
            predecessor_response.node_id.clone(),
            predecessor_response.placement_identity.clone(),
            predecessor_command.runtime_config().clone(),
            Some(predecessor_response.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor_response.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest,
                node_id: predecessor_response.node_id.clone(),
                placement_identity: predecessor_response.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(9_000_000)
                    .expect("valid Stop grace deadline"),
            }),
        )
        .expect("valid Stop successor")
    }

    fn ready_response(command: &LifecycleCommandEnvelope) -> LifecycleCommandResponse {
        let root = &command.runtime_config.volumes[0];
        LifecycleCommandResponse::new(
            command,
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: random(8),
                runtime_config_digest: command.runtime_config.config_digest.clone(),
                execution_receipt_digest: digest(9),
                guest_ready_receipt_digest: digest(10),
                volume_receipts: vec![VolumeTerminalReceipt {
                    volume_id: root.volume_id.clone(),
                    disk_id: root.disk_id.clone(),
                    disk_role: DiskRole::Root,
                    attachment_id: id(&format!("attachment_{}_root", command.cat_id)),
                    attachment_epoch: FenceEpoch::new(1).expect("positive fence epoch"),
                    local_durable_generation: Generation::new(1).expect("valid generation"),
                    remote_durable_generation: Generation::new(1).expect("valid generation"),
                    authority_receipt_digest: Some(digest(11)),
                }],
            })),
        )
        .expect("valid RuntimeReady result")
    }

    fn killed_response(command: &LifecycleCommandEnvelope) -> LifecycleCommandResponse {
        LifecycleCommandResponse::new(
            command,
            NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: Some(random(8)),
                execution_absence: ExecutionAbsenceProof {
                    stop_fence_receipt_digest: digest(44),
                    admission_closed_receipt_digest: digest(45),
                    dedicated_scope_absence_receipt_digest: digest(46),
                    frontend_absence_receipt_digest: digest(47),
                    restart_source_absence_receipt_digest: digest(48),
                },
                stop_fence_receipt_digest: digest(44),
                retained_volume_receipts: Vec::new(),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(49),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 0,
                    quarantined_count: 0,
                },
            })),
        )
        .expect("valid Killed result")
    }

    fn terminal_response(command: &LifecycleCommandEnvelope) -> LifecycleCommandResponse {
        match command.command {
            LifecycleCommand::Start(_) => ready_response(command),
            LifecycleCommand::Stop(_) => killed_response(command),
            _ => panic!("test executor supports only Start and Stop"),
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum PollPlan {
        Echo,
        WrongSequence,
    }

    struct FakeTransport {
        command: Option<LifecycleCommandEnvelope>,
        poll_plan: PollPlan,
        poll_bodies: Mutex<Vec<Vec<u8>>>,
        commit_bodies: Mutex<Vec<Vec<u8>>>,
        commit_retries: Mutex<VecDeque<LifecycleTransportRetryReason>>,
        result_stored: AtomicBool,
        settled: tokio::sync::Notify,
    }

    impl FakeTransport {
        fn new(command: Option<LifecycleCommandEnvelope>) -> Arc<Self> {
            Arc::new(Self {
                command,
                poll_plan: PollPlan::Echo,
                poll_bodies: Mutex::new(Vec::new()),
                commit_bodies: Mutex::new(Vec::new()),
                commit_retries: Mutex::new(VecDeque::new()),
                result_stored: AtomicBool::new(false),
                settled: tokio::sync::Notify::new(),
            })
        }

        fn wrong_sequence(command: LifecycleCommandEnvelope) -> Arc<Self> {
            Arc::new(Self {
                command: Some(command),
                poll_plan: PollPlan::WrongSequence,
                poll_bodies: Mutex::new(Vec::new()),
                commit_bodies: Mutex::new(Vec::new()),
                commit_retries: Mutex::new(VecDeque::new()),
                result_stored: AtomicBool::new(false),
                settled: tokio::sync::Notify::new(),
            })
        }

        fn retry_one_commit(&self) {
            self.commit_retries
                .lock()
                .expect("fake commit retry mutex")
                .push_back(LifecycleTransportRetryReason::Transport);
        }
    }

    impl LifecycleCommandTransport for FakeTransport {
        fn poll(&self, exact_body: Vec<u8>) -> LifecyclePollFuture {
            self.poll_bodies
                .lock()
                .expect("fake poll body mutex")
                .push(exact_body.clone());
            let poll = decode_lifecycle_command_poll_request(&exact_body)
                .expect("runner emitted a canonical poll");
            let request_sequence = match self.poll_plan {
                PollPlan::Echo => poll.request_sequence,
                PollPlan::WrongSequence => Sequence::new(poll.request_sequence.get() + 1)
                    .expect("test sequence remains valid"),
            };
            let batch = LifecycleCommandBatch {
                version: ContractVersion::V1,
                session: poll.session,
                request_sequence,
                commands: if self.result_stored.load(Ordering::SeqCst) {
                    Vec::new()
                } else {
                    self.command.clone().into_iter().collect()
                },
            };
            Box::pin(async move { LifecycleTransportAttempt::Accepted(batch) })
        }

        fn commit(&self, exact_body: Vec<u8>) -> LifecycleCommitFuture {
            self.commit_bodies
                .lock()
                .expect("fake commit body mutex")
                .push(exact_body.clone());
            if let Some(reason) = self
                .commit_retries
                .lock()
                .expect("fake commit retry mutex")
                .pop_front()
            {
                return Box::pin(async move { LifecycleTransportAttempt::RetryExact(reason) });
            }
            let commit = decode_lifecycle_result_commit_request(&exact_body)
                .expect("runner emitted a canonical result commit");
            let ack = LifecycleResultStoredAck {
                version: ContractVersion::V1,
                node_id: commit.response.node_id.clone(),
                cat_id: commit.response.cat_id.clone(),
                operation_id: commit.response.operation_id.clone(),
                request_fingerprint: commit.response.request_fingerprint.clone(),
                terminal_result_digest: commit.terminal_result_digest,
            };
            // A successful result commit settles the operation at Control;
            // subsequent polls must no longer echo it. RetryExact leaves the
            // command visible so the same canonical bytes are reposted.
            self.result_stored.store(true, Ordering::SeqCst);
            self.settled.notify_one();
            Box::pin(async move { LifecycleTransportAttempt::Accepted(ack) })
        }
    }

    struct ReadyExecutor {
        executions: AtomicUsize,
        terminal_recoveries: AtomicUsize,
        fail_terminal_recovery: bool,
    }

    impl ReadyExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                executions: AtomicUsize::new(0),
                terminal_recoveries: AtomicUsize::new(0),
                fail_terminal_recovery: false,
            })
        }

        fn failing_terminal_recovery() -> Arc<Self> {
            Arc::new(Self {
                executions: AtomicUsize::new(0),
                terminal_recoveries: AtomicUsize::new(0),
                fail_terminal_recovery: true,
            })
        }
    }

    impl LifecycleCommandExecutor for ReadyExecutor {
        fn physical_inventory(&self) -> LifecycleInventoryFuture {
            Box::pin(async {
                Ok(LifecyclePhysicalInventorySnapshot::physical_only(
                    empty_physical_inventory(),
                ))
            })
        }

        fn bind_startup_inventory(
            &self,
            startup: LifecycleJournalStartupInventory,
            _snapshot: Arc<LifecyclePhysicalInventorySnapshot>,
        ) -> LifecycleStartupBindingFuture {
            Box::pin(async move { Ok(startup) })
        }

        fn recover_terminal_admission(
            &self,
            _session: SessionBinding,
            _current: StoredLifecycleJournal,
            _startup_inventory: Arc<StartupPhysicalInventory>,
        ) -> LifecycleTerminalAdmissionRecoveryFuture {
            self.terminal_recoveries.fetch_add(1, Ordering::SeqCst);
            let fail = self.fail_terminal_recovery;
            Box::pin(async move {
                if fail {
                    Err(LifecycleExecutionError::Handler(anyhow::anyhow!(
                        "physical RuntimeReady proof did not match"
                    )))
                } else {
                    Ok(())
                }
            })
        }

        fn execute(
            &self,
            journal: Arc<FileLifecycleCommandJournal>,
            current: StoredLifecycleJournal,
        ) -> LifecycleExecutionFuture {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let LifecycleJournalRecord::Command { command, .. } = current.record() else {
                    return Err(LifecycleExecutionError::Handler(anyhow::anyhow!(
                        "completed Delete receipt reached executor"
                    )));
                };
                let command = command.decode_api()?;
                let result = ExactCommandResult::from_api(&ready_response(&command))?;
                journal.complete(&current, result).map_err(Into::into)
            })
        }
    }

    struct BlockingExecutor {
        executions: AtomicUsize,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    struct OneCatBlockingExecutor {
        blocked_cat_id: Id,
        blocked_started: Arc<tokio::sync::Notify>,
        release_blocked: Arc<tokio::sync::Notify>,
        executed_cats: Mutex<Vec<Id>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct StartupScanMarker {
        scan_id: RandomId128,
    }

    struct StartupBindingExecutor {
        blocked_cat_id: Id,
        physical: StartupPhysicalInventory,
        physical_calls: AtomicUsize,
        binding_calls: AtomicUsize,
        terminal_recoveries: AtomicUsize,
        executed_cats: Mutex<Vec<Id>>,
    }

    impl StartupBindingExecutor {
        fn new(blocked_cat_id: Id, cat_ids: impl IntoIterator<Item = Id>) -> Arc<Self> {
            let mut cats = cat_ids
                .into_iter()
                .map(|cat_id| ObservedCatRuntimeTelemetry {
                    cat_id,
                    observed_placement: PlacementIdentity {
                        node_id: id("node_runner"),
                        placement_epoch: Epoch::new(1).expect("positive placement epoch"),
                    },
                    observed_command_journal: None,
                    observed_physical_state: ObservedRuntimePhysicalState::Executing,
                    observed_runtime_incarnation: Some(random(79)),
                    observed_artifact_manifest_digest: digest(80),
                    observed_artifact_classifications: Vec::new(),
                    observed_volumes: Vec::new(),
                    observed_conditions: Vec::new(),
                })
                .collect::<Vec<_>>();
            cats.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
            Self {
                blocked_cat_id,
                physical: StartupPhysicalInventory::Complete {
                    scan_id: random(81),
                    collected_at_unix_ms: UnixMillis::new(1_001)
                        .expect("valid inventory collection time"),
                    cats,
                    unattributed_artifacts: Vec::new(),
                },
                physical_calls: AtomicUsize::new(0),
                binding_calls: AtomicUsize::new(0),
                terminal_recoveries: AtomicUsize::new(0),
                executed_cats: Mutex::new(Vec::new()),
            }
            .into()
        }
    }

    impl LifecycleCommandExecutor for StartupBindingExecutor {
        fn physical_inventory(&self) -> LifecycleInventoryFuture {
            self.physical_calls.fetch_add(1, Ordering::SeqCst);
            let physical = self.physical.clone();
            let scan_id = match &physical {
                StartupPhysicalInventory::Complete { scan_id, .. } => scan_id.clone(),
                StartupPhysicalInventory::Incomplete { .. } => {
                    unreachable!("test startup inventory is complete")
                }
            };
            Box::pin(async move {
                Ok(LifecyclePhysicalInventorySnapshot::new(
                    physical,
                    StartupScanMarker { scan_id },
                ))
            })
        }

        fn bind_startup_inventory(
            &self,
            mut startup: LifecycleJournalStartupInventory,
            snapshot: Arc<LifecyclePhysicalInventorySnapshot>,
        ) -> LifecycleStartupBindingFuture {
            self.binding_calls.fetch_add(1, Ordering::SeqCst);
            let blocked_cat_id = self.blocked_cat_id.clone();
            let expected_scan_id = match &self.physical {
                StartupPhysicalInventory::Complete { scan_id, .. } => scan_id.clone(),
                StartupPhysicalInventory::Incomplete { .. } => {
                    unreachable!("test startup inventory is complete")
                }
            };
            Box::pin(async move {
                let marker = snapshot
                    .provider_evidence::<StartupScanMarker>()
                    .ok_or_else(|| {
                        LifecycleExecutionError::Handler(anyhow::anyhow!(
                            "sole-scan provider evidence was lost"
                        ))
                    })?;
                if marker.scan_id != expected_scan_id {
                    return Err(LifecycleExecutionError::Handler(anyhow::anyhow!(
                        "provider evidence belongs to another physical scan"
                    )));
                }
                let mut recoverable = Vec::new();
                for entry in startup.recoverable {
                    if entry.cat_id == blocked_cat_id {
                        if journal_record_is_terminal(&entry.record) {
                            startup
                                .quarantined_terminals
                                .push(QuarantinedTerminalStartupCat {
                                    cat_id: entry.cat_id.clone(),
                                    reason:
                                        "exact startup progress does not match its terminal journal"
                                            .into(),
                                });
                            recoverable.push(entry);
                        } else {
                            startup
                                .quarantined_commands
                                .push(QuarantinedStartupJournalEntry {
                                    entry,
                                    reason: "exact startup progress does not match its journal"
                                        .into(),
                                });
                        }
                    } else {
                        recoverable.push(entry);
                    }
                }
                startup.recoverable = recoverable;
                startup
                    .blocked
                    .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
                startup
                    .quarantined_commands
                    .sort_by(|left, right| left.entry.cat_id.cmp(&right.entry.cat_id));
                startup
                    .quarantined_terminals
                    .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
                Ok(startup)
            })
        }

        fn recover_terminal_admission(
            &self,
            _session: SessionBinding,
            _current: StoredLifecycleJournal,
            _startup_inventory: Arc<StartupPhysicalInventory>,
        ) -> LifecycleTerminalAdmissionRecoveryFuture {
            self.terminal_recoveries.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn execute(
            &self,
            journal: Arc<FileLifecycleCommandJournal>,
            current: StoredLifecycleJournal,
        ) -> LifecycleExecutionFuture {
            let LifecycleJournalRecord::Command { command, .. } = current.record() else {
                return Box::pin(async {
                    Err(LifecycleExecutionError::Handler(anyhow::anyhow!(
                        "completed Delete receipt reached executor"
                    )))
                });
            };
            let command = match command.decode_api() {
                Ok(command) => command,
                Err(error) => return Box::pin(async move { Err(error.into()) }),
            };
            self.executed_cats
                .lock()
                .expect("executed Cat mutex")
                .push(command.cat_id.clone());
            Box::pin(async move {
                let result = ExactCommandResult::from_api(&ready_response(&command))?;
                journal.complete(&current, result).map_err(Into::into)
            })
        }
    }

    impl BlockingExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                executions: AtomicUsize::new(0),
                started: Arc::new(tokio::sync::Notify::new()),
                release: Arc::new(tokio::sync::Notify::new()),
            })
        }
    }

    impl OneCatBlockingExecutor {
        fn new(blocked_cat_id: Id) -> Arc<Self> {
            Arc::new(Self {
                blocked_cat_id,
                blocked_started: Arc::new(tokio::sync::Notify::new()),
                release_blocked: Arc::new(tokio::sync::Notify::new()),
                executed_cats: Mutex::new(Vec::new()),
            })
        }
    }

    impl LifecycleCommandExecutor for BlockingExecutor {
        fn physical_inventory(&self) -> LifecycleInventoryFuture {
            Box::pin(async {
                Ok(LifecyclePhysicalInventorySnapshot::physical_only(
                    empty_physical_inventory(),
                ))
            })
        }

        fn bind_startup_inventory(
            &self,
            startup: LifecycleJournalStartupInventory,
            _snapshot: Arc<LifecyclePhysicalInventorySnapshot>,
        ) -> LifecycleStartupBindingFuture {
            Box::pin(async move { Ok(startup) })
        }

        fn recover_terminal_admission(
            &self,
            _session: SessionBinding,
            _current: StoredLifecycleJournal,
            _startup_inventory: Arc<StartupPhysicalInventory>,
        ) -> LifecycleTerminalAdmissionRecoveryFuture {
            Box::pin(async { Ok(()) })
        }

        fn execute(
            &self,
            journal: Arc<FileLifecycleCommandJournal>,
            current: StoredLifecycleJournal,
        ) -> LifecycleExecutionFuture {
            self.executions.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                release.notified().await;
                let LifecycleJournalRecord::Command { command, .. } = current.record() else {
                    return Err(LifecycleExecutionError::Handler(anyhow::anyhow!(
                        "completed Delete receipt reached executor"
                    )));
                };
                let command = command.decode_api()?;
                let result = ExactCommandResult::from_api(&ready_response(&command))?;
                journal.complete(&current, result).map_err(Into::into)
            })
        }
    }

    impl LifecycleCommandExecutor for OneCatBlockingExecutor {
        fn physical_inventory(&self) -> LifecycleInventoryFuture {
            Box::pin(async {
                Ok(LifecyclePhysicalInventorySnapshot::physical_only(
                    empty_physical_inventory(),
                ))
            })
        }

        fn bind_startup_inventory(
            &self,
            startup: LifecycleJournalStartupInventory,
            _snapshot: Arc<LifecyclePhysicalInventorySnapshot>,
        ) -> LifecycleStartupBindingFuture {
            Box::pin(async move { Ok(startup) })
        }

        fn recover_terminal_admission(
            &self,
            _session: SessionBinding,
            _current: StoredLifecycleJournal,
            _startup_inventory: Arc<StartupPhysicalInventory>,
        ) -> LifecycleTerminalAdmissionRecoveryFuture {
            Box::pin(async { Ok(()) })
        }

        fn execute(
            &self,
            journal: Arc<FileLifecycleCommandJournal>,
            current: StoredLifecycleJournal,
        ) -> LifecycleExecutionFuture {
            let LifecycleJournalRecord::Command { command, .. } = current.record() else {
                return Box::pin(async {
                    Err(LifecycleExecutionError::Handler(anyhow::anyhow!(
                        "completed Delete receipt reached executor"
                    )))
                });
            };
            let command = match command.decode_api() {
                Ok(command) => command,
                Err(error) => return Box::pin(async move { Err(error.into()) }),
            };
            let blocked = command.cat_id == self.blocked_cat_id;
            if blocked {
                self.blocked_started.notify_one();
            }
            self.executed_cats
                .lock()
                .expect("executed Cat mutex")
                .push(command.cat_id.clone());
            let release_blocked = Arc::clone(&self.release_blocked);
            Box::pin(async move {
                if blocked {
                    release_blocked.notified().await;
                }
                let result = ExactCommandResult::from_api(&terminal_response(&command))?;
                if matches!(&command.command, LifecycleCommand::Stop(_)) {
                    let (fenced, token) = journal.record_stop_fence(
                        &current,
                        ExecutionStep {
                            name: id("runner_test_strong_stop"),
                            recovery_payload: ExactBytes::new(b"runtime-stopped".to_vec()),
                        },
                        ExactBytes::new(b"runner-test-stop-fence".to_vec()),
                    )?;
                    journal
                        .complete_after_stop(&fenced, &token, result)
                        .map_err(Into::into)
                } else {
                    journal.complete(&current, result).map_err(Into::into)
                }
            })
        }
    }

    async fn open_runner(
        directory: &TempDir,
        transport: Arc<FakeTransport>,
        executor: Arc<dyn LifecycleCommandExecutor>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> LifecycleCommandRunner {
        LifecycleCommandRunner::open(
            StateDirectory::unanchored(directory.path().to_path_buf()),
            session(),
            transport,
            executor,
            LifecycleAdmissionRegistry::new_uninitialized(),
            StartupInventoryCache::new(),
            shutdown,
        )
        .await
        .expect("open lifecycle runner")
    }

    #[tokio::test]
    async fn accepted_command_is_durable_once_and_commit_retry_reposts_exact_bytes() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let transport = FakeTransport::new(Some(command()));
        transport.retry_one_commit();
        let executor = ReadyExecutor::new();
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner =
            open_runner(&directory, transport.clone(), executor.clone(), shutdown_rx).await;
        let task = tokio::spawn(runner.run());

        tokio::time::timeout(Duration::from_secs(2), transport.settled.notified())
            .await
            .expect("terminal result settled");
        shutdown.send(true).expect("request runner shutdown");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner joined")
            .expect("runner task joined")
            .expect("runner shutdown succeeded");

        assert_eq!(executor.executions.load(Ordering::SeqCst), 1);
        let commits = transport
            .commit_bodies
            .lock()
            .expect("fake commit body mutex");
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0], commits[1]);
        drop(commits);
        let journal = FileLifecycleCommandJournal::open(
            &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
            &id("cat_runner"),
        )
        .expect("reopen terminal journal");
        assert!(matches!(
            journal.load().expect("load terminal").unwrap().record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal { .. },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn shutdown_never_cancels_an_owned_accepted_executor() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let transport = FakeTransport::new(Some(command()));
        let executor = BlockingExecutor::new();
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner = open_runner(
            &directory,
            Arc::clone(&transport),
            executor.clone(),
            shutdown_rx,
        )
        .await;
        let task = tokio::spawn(runner.run());

        tokio::time::timeout(Duration::from_secs(2), executor.started.notified())
            .await
            .expect("executor started");
        shutdown.send(true).expect("request runner shutdown");
        // FakeTransport repeats the active command from an immediately-ready
        // future. This timer is the regression oracle for the zero-progress
        // poll loop: it cannot fire if that loop starves the current thread.
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !task.is_finished(),
            "shutdown cancelled the accepted executor"
        );
        executor.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner joined after executor")
            .expect("runner task joined")
            .expect("runner shutdown succeeded");
        assert_eq!(executor.executions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn noncooperative_cat_is_fenced_without_occupying_a_sibling_lane() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let blocked = command_for(
            "operation_runner_blocked",
            "cat_runner_blocked",
            "creation_runner_blocked",
        );
        let healthy_predecessor = command_for(
            "operation_runner_healthy_sibling_ready",
            "cat_runner_healthy_sibling",
            "creation_runner_healthy_sibling",
        );
        let healthy_ready = ready_response(&healthy_predecessor);
        let healthy = stop_command_for(
            "operation_runner_healthy_sibling",
            &healthy_predecessor,
            &healthy_ready,
        );
        let transport = FakeTransport::new(None);
        let executor = OneCatBlockingExecutor::new(blocked.cat_id.clone());
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = open_runner(
            &directory,
            Arc::clone(&transport),
            executor.clone(),
            shutdown_rx,
        )
        .await;

        // The Stop has a real locally durable RuntimeReady predecessor. It is
        // written after startup enumeration so only the Stop worker is under
        // test; Control has already accepted the predecessor result.
        let healthy_journal = FileLifecycleCommandJournal::open(
            &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
            &healthy.cat_id,
        )
        .expect("open healthy sibling journal");
        let healthy_current = match healthy_journal
            .admit_api(&healthy_predecessor, GenesisLocalInventory::ConfirmedEmpty)
            .expect("admit healthy RuntimeReady predecessor")
        {
            AdmitCommandOutcome::Accepted(current) => current,
            outcome => panic!("unexpected predecessor admission: {outcome:?}"),
        };
        healthy_journal
            .complete(
                &healthy_current,
                ExactCommandResult::from_api(&healthy_ready)
                    .expect("canonical healthy RuntimeReady result"),
            )
            .expect("persist healthy RuntimeReady predecessor");
        drop(healthy_journal);

        assert!(runner
            .dispatch_batch(vec![blocked.clone(), healthy.clone()])
            .expect("dispatch independent Cat workers"));
        assert!(
            runner.workers.contains_key(&healthy.cat_id),
            "healthy Stop was not admitted: {:?}",
            runner.blocked.get(&healthy.cat_id)
        );
        tokio::time::timeout(Duration::from_secs(1), executor.blocked_started.notified())
            .await
            .expect("blocked Cat entered its provider call");
        if tokio::time::timeout(Duration::from_secs(1), transport.settled.notified())
            .await
            .is_err()
        {
            runner.reap_finished().await;
            panic!(
                "healthy sibling did not settle while the first Cat remained blocked: {:?}",
                runner.blocked.get(&healthy.cat_id)
            );
        }
        runner.reap_finished().await;
        assert!(runner.workers.contains_key(&blocked.cat_id));
        assert!(!runner.workers.contains_key(&healthy.cat_id));

        let mut successor = blocked.clone();
        successor.operation_id = id("operation_runner_blocked_successor");
        successor.request_fingerprint = digest(42);
        assert!(
            !runner
                .dispatch_batch(vec![successor])
                .expect("same-Cat successor remains fenced"),
            "an owned noncooperative Cat must retain its sole local effect lane"
        );
        assert!(runner.workers.contains_key(&blocked.cat_id));
        assert!(!runner.blocked.contains_key(&healthy.cat_id));

        let mut shutdown_join = Box::pin(runner.finish_shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), shutdown_join.as_mut())
                .await
                .is_err(),
            "shutdown released the Host while an accepted physical effect was still owned"
        );
        executor.release_blocked.notify_one();
        tokio::time::timeout(Duration::from_secs(1), shutdown_join)
            .await
            .expect("shutdown joined the released Cat worker")
            .expect("all Cat workers joined cleanly");

        let executed = executor.executed_cats.lock().expect("executed Cat mutex");
        assert!(executed.contains(&blocked.cat_id));
        assert!(executed.contains(&healthy.cat_id));
        assert_eq!(
            executed.len(),
            2,
            "same-Cat successor never reached execute"
        );
        let commits = transport.commit_bodies.lock().expect("commit body mutex");
        let healthy_commit = commits
            .iter()
            .map(|body| {
                decode_lifecycle_result_commit_request(body)
                    .expect("executor committed canonical terminal bytes")
            })
            .find(|commit| commit.response.cat_id == healthy.cat_id)
            .expect("healthy Stop settled while sibling Start was blocked");
        assert!(matches!(
            healthy_commit.response.result,
            NodeResult::Killed(_)
        ));
    }

    #[tokio::test]
    async fn startup_terminal_is_reposted_without_reexecuting_the_command() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let request = command();
        {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &request.cat_id,
            )
            .expect("open lifecycle journal");
            let accepted = match journal
                .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
                .expect("admit command")
            {
                AdmitCommandOutcome::Accepted(stored) => stored,
                _ => panic!("Genesis must be accepted"),
            };
            journal
                .complete(
                    &accepted,
                    ExactCommandResult::from_api(&ready_response(&request))
                        .expect("exact terminal result"),
                )
                .expect("persist terminal result");
        }
        let transport = FakeTransport::new(None);
        let executor = ReadyExecutor::new();
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner = open_runner(
            &directory,
            Arc::clone(&transport),
            executor.clone(),
            shutdown_rx,
        )
        .await;
        let task = tokio::spawn(runner.run());
        tokio::time::timeout(Duration::from_secs(2), transport.settled.notified())
            .await
            .expect("startup terminal reposted");
        shutdown.send(true).expect("request runner shutdown");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner joined")
            .expect("runner task joined")
            .expect("runner shutdown succeeded");
        assert_eq!(executor.executions.load(Ordering::SeqCst), 0);
        assert_eq!(executor.terminal_recoveries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn startup_recovery_blocks_a_journal_changed_after_sole_enumeration() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let request = command();
        {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &request.cat_id,
            )
            .expect("open lifecycle journal");
            assert!(matches!(
                journal
                    .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
                    .expect("admit command"),
                AdmitCommandOutcome::Accepted(_)
            ));
        }

        let transport = FakeTransport::new(None);
        let executor = ReadyExecutor::new();
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = open_runner(&directory, transport, executor.clone(), shutdown_rx).await;

        // The registry and startup telemetry seed now retain the exact
        // Accepted record. Simulate a local writer replacing it before the
        // recovery worker acquires the per-Cat lock.
        {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &request.cat_id,
            )
            .expect("reopen lifecycle journal");
            let accepted = journal
                .load()
                .expect("load accepted journal")
                .expect("accepted journal exists");
            journal
                .record_execution(
                    &accepted,
                    ExecutionStep {
                        name: id("changed_after_startup_enumeration"),
                        recovery_payload: ExactBytes::new(b"changed".to_vec()),
                    },
                    None,
                )
                .expect("replace startup journal");
        }

        runner
            .start_pending_recovery()
            .expect("one changed Cat does not stop sibling recovery");
        assert!(runner
            .blocked_cats()
            .get(&request.cat_id)
            .is_some_and(|reason| reason.contains("changed after its sole enumeration")));
        assert!(runner.workers.is_empty());
        assert_eq!(executor.executions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn startup_binding_must_preserve_every_exact_enumerated_journal() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let request = command();
        let journal = FileLifecycleCommandJournal::open(
            &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
            &request.cat_id,
        )
        .expect("open lifecycle journal");
        let current = match journal
            .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
            .expect("admit startup command")
        {
            AdmitCommandOutcome::Accepted(current) => current,
            other => panic!("unexpected admission outcome: {other:?}"),
        };
        let entry = StartupJournalEntry {
            cat_id: request.cat_id.clone(),
            record: current.record().clone(),
            journal_digest: current.content_digest().clone(),
        };
        let enumerated = LifecycleJournalStartupInventory {
            recoverable: vec![entry.clone()],
            ..LifecycleJournalStartupInventory::default()
        };
        assert!(matches!(
            validate_startup_binding(&enumerated, &LifecycleJournalStartupInventory::default()),
            Err(LifecycleRunnerError::InvalidContract {
                context: "startup physical binding changed or dropped the sole journal enumeration"
            })
        ));

        let quarantined = LifecycleJournalStartupInventory {
            quarantined_commands: vec![QuarantinedStartupJournalEntry {
                entry,
                reason: "exact provider mismatch".into(),
            }],
            ..LifecycleJournalStartupInventory::default()
        };
        validate_startup_binding(&enumerated, &quarantined)
            .expect("exact non-terminal quarantine preserves the enumeration");
    }

    #[tokio::test]
    async fn startup_progress_binding_quarantines_only_the_mismatched_cat() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let healthy = command_for(
            "operation_runner_healthy",
            "cat_runner_healthy",
            "creation_runner_healthy",
        );
        let mismatched = command_for(
            "operation_runner_mismatch",
            "cat_runner_mismatch",
            "creation_runner_mismatch",
        );
        for command in [&healthy, &mismatched] {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &command.cat_id,
            )
            .expect("open lifecycle journal");
            assert!(matches!(
                journal
                    .admit_api(command, GenesisLocalInventory::ConfirmedEmpty)
                    .expect("admit startup command"),
                AdmitCommandOutcome::Accepted(_)
            ));
        }

        let transport = FakeTransport::new(None);
        let executor =
            StartupBindingExecutor::new(mismatched.cat_id.clone(), [healthy.cat_id.clone()]);
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = open_runner(&directory, transport, executor.clone(), shutdown_rx).await;

        assert_eq!(executor.physical_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.binding_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.pending_recovery.len(), 1);
        assert_eq!(runner.pending_recovery[0].cat_id, healthy.cat_id);
        assert!(runner
            .blocked_cats()
            .get(&mismatched.cat_id)
            .is_some_and(|reason| reason.contains("does not match its journal")));
        assert!(matches!(
            runner.admission_registry.lookup(&mismatched.cat_id),
            Err(LifecycleAdmissionRegistryError::CatBlocked { cat_id, reason })
                if cat_id == mismatched.cat_id && reason.contains("does not match its journal")
        ));

        runner
            .start_pending_recovery()
            .expect("start healthy sibling recovery");
        runner
            .finish_shutdown()
            .await
            .expect("healthy sibling worker completed");
        assert_eq!(
            executor
                .executed_cats
                .lock()
                .expect("executed Cat mutex")
                .as_slice(),
            [healthy.cat_id]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_bad_startup_cat_does_not_block_one_hundred_siblings_or_cat_101() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let healthy = (1..=100)
            .map(|number| {
                command_for(
                    &format!("operation_runner_{number:03}"),
                    &format!("cat_runner_{number:03}"),
                    &format!("creation_runner_{number:03}"),
                )
            })
            .collect::<Vec<_>>();
        let mismatched = command_for(
            "operation_runner_bad",
            "cat_runner_bad",
            "creation_runner_bad",
        );
        for command in &healthy {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &command.cat_id,
            )
            .expect("open lifecycle journal");
            let accepted = match journal
                .admit_api(command, GenesisLocalInventory::ConfirmedEmpty)
                .expect("admit startup command")
            {
                AdmitCommandOutcome::Accepted(accepted) => accepted,
                other => panic!("healthy Running fixture was not admitted: {other:?}"),
            };
            journal
                .complete(
                    &accepted,
                    ExactCommandResult::from_api(&ready_response(command))
                        .expect("construct exact RuntimeReady result"),
                )
                .expect("persist healthy Running terminal");
        }
        let mismatched_journal = FileLifecycleCommandJournal::open(
            &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
            &mismatched.cat_id,
        )
        .expect("open mismatched lifecycle journal");
        assert!(matches!(
            mismatched_journal
                .admit_api(&mismatched, GenesisLocalInventory::ConfirmedEmpty)
                .expect("admit mismatched startup command"),
            AdmitCommandOutcome::Accepted(_)
        ));

        let transport = FakeTransport::new(None);
        let executor = StartupBindingExecutor::new(
            mismatched.cat_id.clone(),
            healthy
                .iter()
                .map(|command| command.cat_id.clone())
                .chain(std::iter::once(mismatched.cat_id.clone())),
        );
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        let cache = StartupInventoryCache::new();
        let mut runner = LifecycleCommandRunner::open(
            StateDirectory::unanchored(directory.path().to_path_buf()),
            session(),
            transport.clone(),
            executor.clone(),
            Arc::clone(&registry),
            Arc::clone(&cache),
            shutdown_rx,
        )
        .await
        .expect("open lifecycle runner");

        assert_eq!(runner.pending_recovery.len(), 100);
        assert!(runner.blocked_cats().contains_key(&mismatched.cat_id));
        let joined = cache.take_joined().expect("take joined startup telemetry");
        let bad_telemetry = joined
            .cats
            .iter()
            .find(|cat| cat.cat_id == mismatched.cat_id)
            .expect("quarantined Cat remains observable");
        assert!(bad_telemetry.observed_conditions.iter().any(|condition| {
            condition.kind == cats_api::runtime_inventory::ObservedRuntimeConditionKind::Quarantined
        }));
        assert!(matches!(
            registry.lookup(&mismatched.cat_id),
            Err(LifecycleAdmissionRegistryError::CatBlocked { .. })
        ));
        runner
            .start_pending_recovery()
            .expect("start every healthy Running terminal repost");
        runner
            .finish_shutdown()
            .await
            .expect("join every healthy Running terminal repost");
        assert_eq!(executor.terminal_recoveries.load(Ordering::SeqCst), 100);
        assert!(executor
            .executed_cats
            .lock()
            .expect("executed Cat mutex")
            .is_empty());

        let newcomer = command_for(
            "operation_runner_101",
            "cat_runner_101",
            "creation_runner_101",
        );
        assert!(runner
            .dispatch_batch(vec![newcomer.clone()])
            .expect("new Cat obtains an independent effect worker"));
        runner
            .finish_shutdown()
            .await
            .expect("new Cat settles independently");

        let executed = executor
            .executed_cats
            .lock()
            .expect("executed Cat mutex")
            .clone();
        assert_eq!(executed, vec![newcomer.cat_id]);
        assert!(!executed.contains(&mismatched.cat_id));
        assert_eq!(
            transport
                .commit_bodies
                .lock()
                .expect("commit body mutex")
                .len(),
            101,
            "100 Running terminals and Cat 101 settle independently"
        );
    }

    #[tokio::test]
    async fn terminal_physical_mismatch_reposts_without_effect_or_admission_recovery() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let request = command_for(
            "operation_runner_terminal_mismatch",
            "cat_runner_terminal_mismatch",
            "creation_runner_terminal_mismatch",
        );
        let persisted_response = ready_response(&request);
        let expected_commit = encode_lifecycle_result_commit_request(
            &LifecycleResultCommitRequest::new(&session(), persisted_response.clone())
                .expect("construct exact persisted terminal commit"),
        )
        .expect("encode exact persisted terminal commit");
        {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &request.cat_id,
            )
            .expect("open lifecycle journal");
            let accepted = match journal
                .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
                .expect("admit terminal startup command")
            {
                AdmitCommandOutcome::Accepted(current) => current,
                other => panic!("unexpected admission outcome: {other:?}"),
            };
            journal
                .complete(
                    &accepted,
                    ExactCommandResult::from_api(&persisted_response)
                        .expect("exact terminal response"),
                )
                .expect("persist terminal response");
        }

        let transport = FakeTransport::new(None);
        let executor =
            StartupBindingExecutor::new(request.cat_id.clone(), [request.cat_id.clone()]);
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        let cache = StartupInventoryCache::new();
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner = LifecycleCommandRunner::open(
            StateDirectory::unanchored(directory.path().to_path_buf()),
            session(),
            transport.clone(),
            executor.clone(),
            Arc::clone(&registry),
            Arc::clone(&cache),
            shutdown_rx,
        )
        .await
        .expect("open lifecycle runner");

        assert!(runner.blocked_cats().is_empty());
        assert!(runner
            .quarantined_terminal_cats()
            .get(&request.cat_id)
            .is_some_and(|reason| reason.contains("terminal journal")));
        assert_eq!(runner.pending_recovery.len(), 1);
        let joined = cache.take_joined().expect("take quarantined startup seed");
        let joined_cat = joined
            .cats
            .iter()
            .find(|cat| cat.cat_id == request.cat_id)
            .expect("joined terminal Cat");
        assert!(joined_cat
            .observed_conditions
            .iter()
            .any(|condition| condition.kind
                == cats_api::runtime_inventory::ObservedRuntimeConditionKind::Quarantined));
        assert_eq!(
            registry
                .lookup(&request.cat_id)
                .expect("lookup fail-closed cell")
                .expect("terminal journal has a cell")
                .effective_runtime_ready()
                .expect("inspect admission"),
            None
        );

        let task = tokio::spawn(runner.run());
        tokio::time::timeout(Duration::from_secs(2), transport.settled.notified())
            .await
            .expect("quarantined terminal response reposted");
        shutdown.send(true).expect("request runner shutdown");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner joined")
            .expect("runner task joined")
            .expect("runner shutdown succeeded");

        assert!(executor
            .executed_cats
            .lock()
            .expect("executed Cat mutex")
            .is_empty());
        assert_eq!(executor.terminal_recoveries.load(Ordering::SeqCst), 0);
        let commits = transport.commit_bodies.lock().expect("commit bodies mutex");
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0], expected_commit);
    }

    #[tokio::test]
    async fn failed_startup_admission_recovery_does_not_suppress_exact_result_repost() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let request = command();
        {
            let journal = FileLifecycleCommandJournal::open(
                &directory.path().join(LIFECYCLE_JOURNAL_DIRECTORY_NAME),
                &request.cat_id,
            )
            .expect("open lifecycle journal");
            let accepted = match journal
                .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
                .expect("admit command")
            {
                AdmitCommandOutcome::Accepted(stored) => stored,
                _ => panic!("Genesis must be accepted"),
            };
            journal
                .complete(
                    &accepted,
                    ExactCommandResult::from_api(&ready_response(&request))
                        .expect("exact terminal result"),
                )
                .expect("persist terminal result");
        }
        let transport = FakeTransport::new(None);
        let executor = ReadyExecutor::failing_terminal_recovery();
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner = open_runner(
            &directory,
            Arc::clone(&transport),
            executor.clone(),
            shutdown_rx,
        )
        .await;
        let task = tokio::spawn(runner.run());
        tokio::time::timeout(Duration::from_secs(2), transport.settled.notified())
            .await
            .expect("terminal result reposted despite admission recovery failure");
        shutdown.send(true).expect("request runner shutdown");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner joined")
            .expect("runner task joined")
            .expect("runner shutdown succeeded");
        assert_eq!(executor.executions.load(Ordering::SeqCst), 0);
        assert_eq!(executor.terminal_recoveries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mismatched_batch_sequence_is_rejected_before_admission_or_effect() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let transport = FakeTransport::wrong_sequence(command());
        let executor = ReadyExecutor::new();
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let runner = open_runner(&directory, transport, executor.clone(), shutdown_rx).await;
        assert!(matches!(
            runner.run().await,
            Err(LifecycleRunnerError::InvalidContract {
                context: "validate exact lifecycle batch echo"
            })
        ));
        assert_eq!(executor.executions.load(Ordering::SeqCst), 0);
        assert!(
            !directory
                .path()
                .join(LIFECYCLE_JOURNAL_DIRECTORY_NAME)
                .join("cat-cat_runner.lifecycle-command.json")
                .exists(),
            "invalid batch reached durable command admission"
        );
    }

    #[tokio::test]
    async fn accepted_poll_sequences_advance_monotonically_within_the_session() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let transport = FakeTransport::new(None);
        let executor = ReadyExecutor::new();
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = open_runner(&directory, transport, executor, shutdown_rx).await;
        let first = runner.current_poll().expect("first poll");
        runner.advance_sequence().expect("advance poll sequence");
        let second = runner.current_poll().expect("second poll");
        assert_eq!(first.session, second.session);
        assert_eq!(first.request_sequence.get(), 1);
        assert_eq!(second.request_sequence.get(), 2);
    }

    #[tokio::test]
    async fn successor_seen_before_predecessor_worker_reap_is_deferred_not_blocked() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let transport = FakeTransport::new(None);
        let executor = ReadyExecutor::new();
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut runner = open_runner(&directory, transport, executor, shutdown_rx).await;
        let predecessor = command();
        let cat_id = predecessor.cat_id.clone();
        let task = tokio::spawn(std::future::pending::<Result<(), LifecycleRunnerError>>());
        runner.workers.insert(
            cat_id.clone(),
            ActiveCatWorker {
                operation_id: predecessor.operation_id,
                request_fingerprint: predecessor.request_fingerprint,
                task,
            },
        );

        let mut successor = command();
        successor.operation_id = id("operation_runner_successor");
        successor.request_fingerprint = digest(42);
        assert!(!runner
            .dispatch_batch(vec![successor])
            .expect("active predecessor defers its successor"));

        assert!(!runner.blocked.contains_key(&cat_id));
        let worker = runner
            .workers
            .remove(&cat_id)
            .expect("predecessor worker remains owned");
        worker.task.abort();
    }

    #[tokio::test]
    async fn http_poll_signs_the_exact_frozen_method_path_and_body() {
        let session = session();
        let poll = LifecycleCommandPollRequest {
            version: ContractVersion::V1,
            session: session_binding(&session),
            request_sequence: Sequence::new(1).expect("positive sequence"),
        };
        let exact_poll =
            encode_lifecycle_command_poll_request(&poll).expect("canonical lifecycle poll");
        let batch = LifecycleCommandBatch {
            version: ContractVersion::V1,
            session: poll.session.clone(),
            request_sequence: poll.request_sequence,
            commands: vec![command()],
        };
        let exact_batch =
            encode_lifecycle_command_batch(&batch).expect("canonical lifecycle batch");
        let expected_poll = exact_poll.clone();
        let app = Router::new().route(
            LIFECYCLE_COMMAND_POLL_PATH,
            post(move |request: Request<Body>| {
                let expected_poll = expected_poll.clone();
                let exact_batch = exact_batch.clone();
                async move {
                    let headers = request.headers().clone();
                    let body = to_bytes(request.into_body(), expected_poll.len())
                        .await
                        .expect("bounded poll body");
                    assert_eq!(body.as_ref(), expected_poll.as_slice());
                    let authenticated = verify_request_proof(
                        LIFECYCLE_INTERNAL_METHOD,
                        LIFECYCLE_COMMAND_POLL_PATH,
                        &body,
                        headers
                            .get(NODE_CREDENTIAL_ID_HEADER)
                            .expect("credential header")
                            .to_str()
                            .expect("ASCII credential"),
                        headers
                            .get(NODE_PUBLIC_KEY_SPKI_HEADER)
                            .expect("public key header")
                            .to_str()
                            .expect("ASCII public key"),
                        headers
                            .get(NODE_SIGNATURE_HEADER)
                            .expect("signature header")
                            .to_str()
                            .expect("ASCII signature"),
                    )
                    .expect("valid signed lifecycle poll");
                    assert_eq!(authenticated.credential_id(), &id("credential_runner"));
                    wire_response(exact_batch)
                }
            }),
        );
        let (origin, server) = spawn_server(app).await;
        let client = LifecycleCommandHttpClient::for_loopback_test(&origin, signer())
            .expect("loopback lifecycle client");
        let LifecycleTransportAttempt::Accepted(observed) = client.poll(exact_poll).await else {
            panic!("signed canonical poll was not accepted")
        };
        assert_eq!(observed, batch);
        server.abort();
    }
}

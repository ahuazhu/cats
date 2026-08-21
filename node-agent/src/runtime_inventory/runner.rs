//! Owned async sender for the clean runtime inventory contract.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_inventory::{
    decode_runtime_inventory_acceptance, decode_runtime_inventory_error,
    decode_runtime_inventory_report, ObservedArtifactClassification, ObservedCatRuntimeTelemetry,
    ObservedCommandJournal, RuntimeInventoryAcceptance, RuntimeInventoryAcceptanceKind,
    RuntimeInventoryAttestation, RuntimeInventoryBody, RuntimeInventoryError,
    RuntimeInventoryReport, RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES,
    RUNTIME_INVENTORY_ERROR_MAX_WIRE_BYTES, RUNTIME_INVENTORY_MAX_CATS, RUNTIME_INVENTORY_METHOD,
    RUNTIME_INVENTORY_PATH,
};
use cats_api::runtime_reconciliation::{AgentSession, Id, RandomId128, SessionBinding, UnixMillis};
use thiserror::Error;

use crate::lifecycle_command::journal::{
    CommandJournalState, LifecycleJournalRecord, StoredLifecycleJournal,
};
use crate::state_directory::StateDirectory;

use super::attestation::{complete_post_stop_request, ForceFullRequest};
use super::journal::{new_full_report, new_partial_report, FullReportInput};
use super::{
    RuntimeInventoryForceFullCoordinator, RuntimeInventoryForceFullError, RuntimeInventoryJournal,
    RuntimeInventoryJournalError, StartupInventoryCache, StartupInventoryCacheError,
};

#[cfg(not(test))]
const RETRY_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const RETRY_DELAY: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const PARTIAL_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const PARTIAL_INTERVAL: Duration = Duration::from_millis(20);
#[cfg(not(test))]
const FULL_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(test)]
const FULL_REFRESH_INTERVAL: Duration = Duration::from_millis(80);
// Control's authoritative Full freshness window is 60 seconds. Local health
// closes conservatively before that DB-time boundary if refresh cannot land.
#[cfg(not(test))]
const LOCAL_ATTESTED_READINESS_MAX_AGE: Duration = Duration::from_secs(45);
#[cfg(test)]
const LOCAL_ATTESTED_READINESS_MAX_AGE: Duration = Duration::from_millis(120);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub type RuntimeFullInventoryFuture = Pin<
    Box<
        dyn Future<Output = Result<RuntimeFullInventoryScan, RuntimeInventoryCollectionError>>
            + Send
            + 'static,
    >,
>;
pub type RuntimePartialInventoryFuture = Pin<
    Box<
        dyn Future<Output = Result<RuntimePartialInventoryScan, RuntimeInventoryCollectionError>>
            + Send
            + 'static,
    >,
>;

/// One complete physical scan. The source, not the runner, owns scan identity
/// and collection time because both must bracket the physical probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFullInventoryScan {
    pub scan_id: RandomId128,
    pub collected_at_unix_ms: UnixMillis,
    pub cats: Vec<ObservedCatRuntimeTelemetry>,
    pub unattributed_artifacts: Vec<ObservedArtifactClassification>,
}

/// One incremental telemetry sample for a subset of the accepted Full set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePartialInventoryScan {
    pub collected_at_unix_ms: UnixMillis,
    pub cats: Vec<ObservedCatRuntimeTelemetry>,
}

/// Exact accepted-Full association passed to a Partial collector. It carries
/// no Desired state and cannot expand the complete membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePartialInventoryContext {
    pub inventory_epoch: cats_api::runtime_reconciliation::Epoch,
    pub full_cat_ids: Vec<Id>,
}

/// Async collection boundary used by the owned sender.
pub trait RuntimeInventorySource: Send + Sync + 'static {
    fn collect_full(&self) -> RuntimeFullInventoryFuture;

    fn collect_partial(
        &self,
        context: RuntimePartialInventoryContext,
    ) -> RuntimePartialInventoryFuture;
}

/// Synchronous provider/Host probe boundary. A production implementation must
/// scan the complete union of lifecycle journals and physical artifacts; it
/// may not synthesize an empty Full when any source is unavailable.
pub trait RuntimeInventoryCollectionPort: Send + Sync + 'static {
    fn collect_full(&self) -> anyhow::Result<RuntimeFullInventoryScan>;

    fn collect_partial(
        &self,
        context: &RuntimePartialInventoryContext,
    ) -> anyhow::Result<RuntimePartialInventoryScan>;
}

/// Owned blocking adapter for the production synchronous probe set.
pub struct ProductionRuntimeInventorySource {
    startup: Arc<StartupInventoryCache>,
    startup_consumed: Mutex<bool>,
    port: Arc<dyn RuntimeInventoryCollectionPort>,
}

impl std::fmt::Debug for ProductionRuntimeInventorySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionRuntimeInventorySource")
            .finish_non_exhaustive()
    }
}

impl ProductionRuntimeInventorySource {
    pub fn new(
        startup: Arc<StartupInventoryCache>,
        port: Arc<dyn RuntimeInventoryCollectionPort>,
    ) -> Arc<Self> {
        Arc::new(Self {
            startup,
            startup_consumed: Mutex::new(false),
            port,
        })
    }
}

impl RuntimeInventorySource for ProductionRuntimeInventorySource {
    fn collect_full(&self) -> RuntimeFullInventoryFuture {
        let startup = Arc::clone(&self.startup);
        let startup_result = match self.startup_consumed.lock() {
            Ok(mut consumed) if !*consumed => {
                let result = startup
                    .take_joined()
                    .map_err(|error| RuntimeInventoryCollectionError::Startup(Box::new(error)));
                if result.is_ok() {
                    *consumed = true;
                }
                Some(result)
            }
            Ok(_) => None,
            Err(_) => {
                return Box::pin(async {
                    Err(RuntimeInventoryCollectionError::StartupStateUnavailable)
                });
            }
        };
        if let Some(startup_result) = startup_result {
            return Box::pin(async move { startup_result });
        }
        let port = Arc::clone(&self.port);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || port.collect_full())
                .await
                .map_err(|error| RuntimeInventoryCollectionError::Worker(error.to_string()))?
                .map_err(RuntimeInventoryCollectionError::Source)
        })
    }

    fn collect_partial(
        &self,
        context: RuntimePartialInventoryContext,
    ) -> RuntimePartialInventoryFuture {
        let port = Arc::clone(&self.port);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || port.collect_partial(&context))
                .await
                .map_err(|error| RuntimeInventoryCollectionError::Worker(error.to_string()))?
                .map_err(RuntimeInventoryCollectionError::Source)
        })
    }
}

#[derive(Debug, Error)]
pub enum RuntimeInventoryCollectionError {
    #[error("startup runtime inventory is unavailable: {0}")]
    Startup(#[source] Box<StartupInventoryCacheError>),
    #[error("startup runtime inventory source mutex is unavailable")]
    StartupStateUnavailable,
    #[error("runtime inventory collection failed: {0}")]
    Source(anyhow::Error),
    #[error("runtime inventory collection worker failed: {0}")]
    Worker(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryTransportRetryReason {
    Transport,
    InvalidResponse,
    Backpressure,
    ServerFailure,
}

#[derive(Debug)]
pub enum RuntimeInventoryTransportAttempt {
    Accepted {
        acceptance: RuntimeInventoryAcceptance,
        exact_body: Vec<u8>,
    },
    Rejected {
        status: u16,
        error: RuntimeInventoryError,
    },
    RetryExact(RuntimeInventoryTransportRetryReason),
    RouteUnavailable,
}

pub type RuntimeInventoryTransportFuture =
    Pin<Box<dyn Future<Output = RuntimeInventoryTransportAttempt> + Send + 'static>>;

/// Injectable exact-body transport. The runner prepares and fsyncs a report
/// before this method can observe it.
pub trait RuntimeInventoryTransport: Send + Sync + 'static {
    fn send(&self, exact_body: Vec<u8>) -> RuntimeInventoryTransportFuture;
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

/// No-redirect signed client for the sole runtime inventory route.
#[derive(Clone)]
pub struct RuntimeInventoryHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::Client,
}

impl std::fmt::Debug for RuntimeInventoryHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInventoryHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl RuntimeInventoryHttpClient {
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
            .context("build runtime inventory HTTP client")?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }

    async fn post(&self, exact_body: Vec<u8>) -> RuntimeInventoryTransportAttempt {
        let report = match decode_runtime_inventory_report(&exact_body) {
            Ok(report) => report,
            Err(_) => {
                return RuntimeInventoryTransportAttempt::RetryExact(
                    RuntimeInventoryTransportRetryReason::InvalidResponse,
                )
            }
        };
        let proof = self.signer.sign(
            RUNTIME_INVENTORY_METHOD,
            RUNTIME_INVENTORY_PATH,
            &exact_body,
        );
        let url = self
            .origin
            .join(RUNTIME_INVENTORY_PATH)
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
        classify_response(response, &report).await
    }
}

impl RuntimeInventoryTransport for RuntimeInventoryHttpClient {
    fn send(&self, exact_body: Vec<u8>) -> RuntimeInventoryTransportFuture {
        let client = self.clone();
        Box::pin(async move { client.post(exact_body).await })
    }
}

/// Cloneable local health signal. It is never a lifecycle, Route, or volume
/// authority; Control independently checks the persisted attestation using DB
/// time. The runner closes this signal conservatively if refresh stalls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryReadiness {
    AwaitingFull,
    Attested {
        attestation: Box<RuntimeInventoryAttestation>,
    },
}

#[derive(Debug, Error)]
pub enum RuntimeInventoryRunnerError {
    #[error(transparent)]
    Journal(#[from] RuntimeInventoryJournalError),
    #[error("runtime inventory journal worker failed: {0}")]
    JournalWorker(String),
    #[error("runtime inventory journal mutex is unavailable")]
    JournalUnavailable,
    #[error(transparent)]
    ForceFull(#[from] RuntimeInventoryForceFullError),
    #[error("runtime inventory transport route is unavailable: {path}")]
    RouteUnavailable { path: &'static str },
    #[error("runtime inventory was definitely rejected with HTTP {status}: {error:?}")]
    Rejected {
        status: u16,
        error: RuntimeInventoryError,
    },
    #[error("invalid runtime inventory runner contract: {context}")]
    InvalidContract { context: &'static str },
}

/// Independent owned telemetry task. `open` only restores the durable sender
/// and returns a readiness observer; the mandatory startup Full runs inside
/// `run`, so an unavailable telemetry source cannot block lifecycle startup.
pub struct RuntimeInventoryRunner {
    journal: Arc<Mutex<RuntimeInventoryJournal>>,
    source: Arc<dyn RuntimeInventorySource>,
    transport: Arc<dyn RuntimeInventoryTransport>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    readiness: tokio::sync::watch::Sender<RuntimeInventoryReadiness>,
    force_full: Arc<RuntimeInventoryForceFullCoordinator>,
    session: SessionBinding,
    force_full_waiters: Vec<Arc<ForceFullRequest>>,
    forced_report: Option<ForcedFullReport>,
    startup_full_required: bool,
    next_partial_at: Instant,
    full_refresh_at: Instant,
    readiness_expires_at: Option<Instant>,
}

struct ForcedFullReport {
    report_id: RandomId128,
    requests: Vec<Arc<ForceFullRequest>>,
}

impl RuntimeInventoryRunner {
    pub async fn open(
        state_directory: StateDirectory,
        session: AgentSession,
        transport: Arc<dyn RuntimeInventoryTransport>,
        source: Arc<dyn RuntimeInventorySource>,
        force_full: Arc<RuntimeInventoryForceFullCoordinator>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<
        (
            Self,
            tokio::sync::watch::Receiver<RuntimeInventoryReadiness>,
        ),
        RuntimeInventoryRunnerError,
    > {
        let session_binding = session_binding(&session);
        let journal = tokio::task::spawn_blocking(move || {
            RuntimeInventoryJournal::open(&state_directory, &session)
        })
        .await
        .map_err(|error| RuntimeInventoryRunnerError::JournalWorker(error.to_string()))??;
        force_full.bind_once(&session_binding)?;
        let (readiness, observer) =
            tokio::sync::watch::channel(RuntimeInventoryReadiness::AwaitingFull);
        let now = Instant::now();
        Ok((
            Self {
                journal: Arc::new(Mutex::new(journal)),
                source,
                transport,
                shutdown,
                readiness,
                force_full,
                session: session_binding,
                force_full_waiters: Vec::new(),
                forced_report: None,
                startup_full_required: true,
                next_partial_at: now,
                full_refresh_at: now,
                readiness_expires_at: None,
            },
            observer,
        ))
    }

    pub async fn run(mut self) -> Result<(), RuntimeInventoryRunnerError> {
        let result = self.run_loop().await;
        self.readiness
            .send_replace(RuntimeInventoryReadiness::AwaitingFull);
        result
    }

    async fn run_loop(&mut self) -> Result<(), RuntimeInventoryRunnerError> {
        loop {
            self.take_force_full_requests()?;
            self.expire_force_full_requests();
            self.expire_local_readiness();
            if *self.shutdown.borrow() {
                return Ok(());
            }

            if let Some((report, exact_body)) = self
                .with_journal(|journal| journal.pending_report())
                .await?
            {
                if self
                    .forced_report
                    .as_ref()
                    .is_some_and(|forced| forced.report_id != report.report_id)
                {
                    return Err(RuntimeInventoryRunnerError::InvalidContract {
                        context: "pending report differs from forced Full association",
                    });
                }
                match self.transport.send(exact_body).await {
                    RuntimeInventoryTransportAttempt::Accepted {
                        acceptance,
                        exact_body,
                    } => {
                        let stored = self
                            .with_journal(move |journal| journal.accept_pending(exact_body))
                            .await?;
                        if stored != acceptance {
                            return Err(RuntimeInventoryRunnerError::InvalidContract {
                                context: "transport acceptance bytes changed after decode",
                            });
                        }
                        if matches!(report.inventory, RuntimeInventoryBody::Full { .. }) {
                            let RuntimeInventoryAcceptanceKind::Full { attestation } =
                                stored.inventory
                            else {
                                return Err(RuntimeInventoryRunnerError::InvalidContract {
                                    context: "Full report received Partial acceptance",
                                });
                            };
                            let attestation = *attestation;
                            self.accept_full(attestation.clone());
                            if let Some(forced) = self.forced_report.take() {
                                if forced.report_id != report.report_id {
                                    return Err(RuntimeInventoryRunnerError::InvalidContract {
                                        context: "accepted Full differs from forced report",
                                    });
                                }
                                for request in forced.requests {
                                    if Instant::now() >= request.deadline() {
                                        request.complete(Err(
                                            RuntimeInventoryForceFullError::DeadlineExpired,
                                        ));
                                    } else {
                                        complete_post_stop_request(&request, &report, &attestation);
                                    }
                                }
                            }
                        } else {
                            if self.forced_report.is_some() {
                                return Err(RuntimeInventoryRunnerError::InvalidContract {
                                    context: "forced Full association reached a Partial report",
                                });
                            }
                            self.next_partial_at = Instant::now() + PARTIAL_INTERVAL;
                        }
                    }
                    RuntimeInventoryTransportAttempt::RetryExact(reason) => {
                        tracing::warn!(?reason, "retrying exact runtime inventory report");
                        self.wait_or_shutdown(RETRY_DELAY).await;
                    }
                    RuntimeInventoryTransportAttempt::RouteUnavailable => {
                        return Err(RuntimeInventoryRunnerError::RouteUnavailable {
                            path: RUNTIME_INVENTORY_PATH,
                        })
                    }
                    RuntimeInventoryTransportAttempt::Rejected { status, error } => {
                        return Err(RuntimeInventoryRunnerError::Rejected { status, error })
                    }
                }
                continue;
            }
            if self.forced_report.is_some() {
                return Err(RuntimeInventoryRunnerError::InvalidContract {
                    context: "forced Full association has no durable pending report",
                });
            }

            let now = Instant::now();
            // The startup Full comes from the pre-worker Joined seed and can
            // never satisfy a post-Stop request. Keep queued callers pending
            // until that Full is accepted, then begin a fresh provider scan.
            let force_full_required =
                !self.startup_full_required && !self.force_full_waiters.is_empty();
            let collect_full =
                self.startup_full_required || force_full_required || now >= self.full_refresh_at;
            if !collect_full && now < self.next_partial_at {
                let mut wake_at = std::cmp::min(self.next_partial_at, self.full_refresh_at);
                if let Some(expires_at) = self.readiness_expires_at {
                    wake_at = std::cmp::min(wake_at, expires_at);
                }
                self.wait_until_or_shutdown(wake_at).await;
                continue;
            }

            if collect_full {
                match self.source.collect_full().await {
                    Ok(scan) => {
                        let report_id = self.prepare_full(scan).await?;
                        if force_full_required {
                            self.expire_force_full_requests();
                            let requests = std::mem::take(&mut self.force_full_waiters);
                            if !requests.is_empty() {
                                self.forced_report = Some(ForcedFullReport {
                                    report_id,
                                    requests,
                                });
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "runtime Full inventory collection failed");
                        self.wait_or_shutdown(RETRY_DELAY).await;
                    }
                }
            } else {
                let context = self.partial_context().await?;
                match self.source.collect_partial(context).await {
                    Ok(scan) => self.prepare_partial(scan).await?,
                    Err(error) => {
                        tracing::warn!(%error, "runtime Partial telemetry collection failed");
                        self.next_partial_at = Instant::now() + RETRY_DELAY;
                    }
                }
            }
        }
    }

    async fn prepare_full(
        &self,
        scan: RuntimeFullInventoryScan,
    ) -> Result<RandomId128, RuntimeInventoryRunnerError> {
        let report_id = random_id()?;
        let stored_report_id = report_id.clone();
        self.with_journal(move |journal| {
            let report = new_full_report(FullReportInput {
                session: journal.session().clone(),
                report_id,
                sequence: journal.next_sequence()?,
                collected_at_unix_ms: scan.collected_at_unix_ms,
                inventory_epoch: journal.next_full_epoch()?,
                scan_id: scan.scan_id,
                cats: scan.cats,
                unattributed_artifacts: scan.unattributed_artifacts,
            })?;
            journal.prepare_report(report).map(|_| stored_report_id)
        })
        .await
    }

    async fn prepare_partial(
        &self,
        scan: RuntimePartialInventoryScan,
    ) -> Result<(), RuntimeInventoryRunnerError> {
        let report_id = random_id()?;
        self.with_journal(move |journal| {
            let epoch = journal
                .current_full_epoch()?
                .ok_or(RuntimeInventoryJournalError::MissingFullInventory)?;
            let report = new_partial_report(
                journal.session().clone(),
                report_id,
                journal.next_sequence()?,
                scan.collected_at_unix_ms,
                epoch,
                scan.cats,
            );
            journal.prepare_report(report).map(|_| ())
        })
        .await
    }

    async fn partial_context(
        &self,
    ) -> Result<RuntimePartialInventoryContext, RuntimeInventoryRunnerError> {
        self.with_journal(|journal| {
            Ok(RuntimePartialInventoryContext {
                inventory_epoch: journal
                    .current_full_epoch()?
                    .ok_or(RuntimeInventoryJournalError::MissingFullInventory)?,
                full_cat_ids: journal.full_cat_ids()?,
            })
        })
        .await
    }

    fn take_force_full_requests(&mut self) -> Result<(), RuntimeInventoryRunnerError> {
        let pending = self.force_full.take_pending(&self.session)?;
        let available = RUNTIME_INVENTORY_MAX_CATS.saturating_sub(self.force_full_waiters.len());
        let mut pending = pending.into_iter();
        self.force_full_waiters
            .extend(pending.by_ref().take(available));
        for request in pending {
            request.complete(Err(RuntimeInventoryForceFullError::CapacityExceeded));
        }
        Ok(())
    }

    fn expire_force_full_requests(&mut self) {
        let now = Instant::now();
        let mut active = Vec::with_capacity(self.force_full_waiters.len());
        for request in self.force_full_waiters.drain(..) {
            if now >= request.deadline() {
                request.complete(Err(RuntimeInventoryForceFullError::DeadlineExpired));
            } else {
                active.push(request);
            }
        }
        self.force_full_waiters = active;
    }

    fn accept_full(&mut self, attestation: RuntimeInventoryAttestation) {
        let now = Instant::now();
        self.startup_full_required = false;
        self.next_partial_at = now + PARTIAL_INTERVAL;
        self.full_refresh_at = now + FULL_REFRESH_INTERVAL;
        self.readiness_expires_at = Some(now + LOCAL_ATTESTED_READINESS_MAX_AGE);
        self.readiness
            .send_replace(RuntimeInventoryReadiness::Attested {
                attestation: Box::new(attestation),
            });
    }

    fn expire_local_readiness(&mut self) {
        if self
            .readiness_expires_at
            .is_some_and(|expires_at| Instant::now() >= expires_at)
        {
            self.readiness_expires_at = None;
            self.readiness
                .send_replace(RuntimeInventoryReadiness::AwaitingFull);
        }
    }

    async fn with_journal<T, F>(&self, operation: F) -> Result<T, RuntimeInventoryRunnerError>
    where
        T: Send + 'static,
        F: FnOnce(&mut RuntimeInventoryJournal) -> Result<T, RuntimeInventoryJournalError>
            + Send
            + 'static,
    {
        let journal = Arc::clone(&self.journal);
        tokio::task::spawn_blocking(move || {
            let mut journal = journal
                .lock()
                .map_err(|_| RuntimeInventoryRunnerError::JournalUnavailable)?;
            operation(&mut journal).map_err(RuntimeInventoryRunnerError::Journal)
        })
        .await
        .map_err(|error| RuntimeInventoryRunnerError::JournalWorker(error.to_string()))?
    }

    async fn wait_or_shutdown(&mut self, duration: Duration) {
        self.wait_until_or_shutdown(Instant::now() + duration).await;
    }

    async fn wait_until_or_shutdown(&mut self, deadline: Instant) {
        if *self.shutdown.borrow() {
            return;
        }
        let force_full = Arc::clone(&self.force_full);
        tokio::select! {
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            () = force_full.notified() => {}
            changed = self.shutdown.changed() => {
                if changed.is_err() {
                    self.shutdown = closed_shutdown_receiver();
                }
            }
        }
    }
}

impl Drop for RuntimeInventoryRunner {
    fn drop(&mut self) {
        for request in self.force_full_waiters.drain(..) {
            request.complete(Err(RuntimeInventoryForceFullError::Closed));
        }
        if let Some(forced) = self.forced_report.take() {
            for request in forced.requests {
                request.complete(Err(RuntimeInventoryForceFullError::Closed));
            }
        }
        self.force_full.close();
    }
}

/// Project the sole durable lifecycle journal without granting telemetry any
/// command or settlement power.
pub fn observed_command_journal(
    stored: &StoredLifecycleJournal,
) -> Result<ObservedCommandJournal, RuntimeInventoryCollectionError> {
    observed_command_journal_record(stored.record(), stored.content_digest())
}

pub(crate) fn observed_command_journal_record(
    record: &LifecycleJournalRecord,
    journal_digest: &cats_api::runtime_reconciliation::Sha256Digest,
) -> Result<ObservedCommandJournal, RuntimeInventoryCollectionError> {
    let journal_digest = journal_digest.clone();
    Ok(match record {
        LifecycleJournalRecord::Command { command, state, .. } => match state {
            CommandJournalState::Accepted { .. } => ObservedCommandJournal::Accepted {
                operation_id: command.operation_id().clone(),
                command_kind: command.command_kind(),
                request_fingerprint: command.request_fingerprint().clone(),
                journal_digest,
            },
            CommandJournalState::Executing { .. } => ObservedCommandJournal::Executing {
                operation_id: command.operation_id().clone(),
                command_kind: command.command_kind(),
                request_fingerprint: command.request_fingerprint().clone(),
                journal_digest,
            },
            CommandJournalState::Terminal { result, .. } => ObservedCommandJournal::Terminal {
                operation_id: command.operation_id().clone(),
                command_kind: command.command_kind(),
                request_fingerprint: command.request_fingerprint().clone(),
                journal_digest,
                terminal_result_digest: result.result_digest().clone(),
            },
        },
        LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } => {
            ObservedCommandJournal::CompletedDeleteReceipt {
                operation_id: receipt.operation_id.clone(),
                request_fingerprint: receipt.request_fingerprint.clone(),
                journal_digest,
                terminal_result_digest: receipt.terminal_result_digest.clone(),
                completed_receipt_digest: receipt.completed_receipt_digest.clone(),
            }
        }
    })
}

async fn classify_response(
    response: Result<reqwest::Response, reqwest::Error>,
    report: &RuntimeInventoryReport,
) -> RuntimeInventoryTransportAttempt {
    let mut response = match response {
        Ok(response) => response,
        Err(_) => {
            return RuntimeInventoryTransportAttempt::RetryExact(
                RuntimeInventoryTransportRetryReason::Transport,
            )
        }
    };
    let status = response.status();
    if matches!(
        status,
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
    ) {
        return RuntimeInventoryTransportAttempt::RouteUnavailable;
    }
    let cap = if status == reqwest::StatusCode::OK {
        RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES
    } else {
        RUNTIME_INVENTORY_ERROR_MAX_WIRE_BYTES
    };
    if !valid_common_headers(response.headers())
        || declared_response_exceeds(response.headers(), cap)
    {
        return RuntimeInventoryTransportAttempt::RetryExact(
            RuntimeInventoryTransportRetryReason::InvalidResponse,
        );
    }
    let Some(body) = read_bounded_body(&mut response, cap).await else {
        return RuntimeInventoryTransportAttempt::RetryExact(
            RuntimeInventoryTransportRetryReason::InvalidResponse,
        );
    };
    if status == reqwest::StatusCode::OK {
        return match decode_runtime_inventory_acceptance(&body) {
            Ok(acceptance) if acceptance_matches_report(&acceptance, report) => {
                RuntimeInventoryTransportAttempt::Accepted {
                    acceptance,
                    exact_body: body,
                }
            }
            Ok(_) | Err(_) => RuntimeInventoryTransportAttempt::RetryExact(
                RuntimeInventoryTransportRetryReason::InvalidResponse,
            ),
        };
    }
    let error = match decode_runtime_inventory_error(&body) {
        Ok(error) => error,
        Err(_) => {
            return RuntimeInventoryTransportAttempt::RetryExact(
                RuntimeInventoryTransportRetryReason::InvalidResponse,
            )
        }
    };
    if matches!(
        status,
        reqwest::StatusCode::TOO_MANY_REQUESTS | reqwest::StatusCode::SERVICE_UNAVAILABLE
    ) {
        RuntimeInventoryTransportAttempt::RetryExact(
            RuntimeInventoryTransportRetryReason::Backpressure,
        )
    } else if status.is_server_error() {
        RuntimeInventoryTransportAttempt::RetryExact(
            RuntimeInventoryTransportRetryReason::ServerFailure,
        )
    } else if status == reqwest::StatusCode::UNAUTHORIZED
        && !has_one_exact_header(
            response.headers(),
            reqwest::header::WWW_AUTHENTICATE,
            NODE_AUTHENTICATE_CHALLENGE,
        )
    {
        RuntimeInventoryTransportAttempt::RetryExact(
            RuntimeInventoryTransportRetryReason::InvalidResponse,
        )
    } else {
        RuntimeInventoryTransportAttempt::Rejected {
            status: status.as_u16(),
            error,
        }
    }
}

fn acceptance_matches_report(
    acceptance: &RuntimeInventoryAcceptance,
    report: &RuntimeInventoryReport,
) -> bool {
    if acceptance.session != report.session
        || acceptance.report_id != report.report_id
        || acceptance.sequence != report.sequence
    {
        return false;
    }
    match (&report.inventory, &acceptance.inventory) {
        (
            RuntimeInventoryBody::Full {
                inventory_epoch,
                scan_id,
                inventory_digest,
                ..
            },
            RuntimeInventoryAcceptanceKind::Full { attestation },
        ) => {
            attestation.session == report.session
                && attestation.inventory_epoch == *inventory_epoch
                && attestation.scan_id == *scan_id
                && attestation.inventory_digest == *inventory_digest
                && attestation.source_report_id == report.report_id
                && attestation.source_sequence == report.sequence
                && attestation.accepted_at_unix_ms == acceptance.accepted_at_unix_ms
        }
        (
            RuntimeInventoryBody::Partial {
                inventory_epoch, ..
            },
            RuntimeInventoryAcceptanceKind::Partial {
                inventory_epoch: accepted_epoch,
            },
        ) => inventory_epoch == accepted_epoch,
        _ => false,
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

fn random_id() -> Result<RandomId128, RuntimeInventoryRunnerError> {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string()).ok_or(
        RuntimeInventoryRunnerError::InvalidContract {
            context: "generate report ID",
        },
    )
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
    let (sender, receiver) = tokio::sync::watch::channel(true);
    drop(sender);
    receiver
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use cats_api::runtime_inventory::encode_runtime_inventory_acceptance;
    use cats_api::runtime_inventory::ObservedRuntimePhysicalState;
    use cats_api::runtime_lifecycle::{
        DeleteSpec, DiskRole, ImmutableRuntimeConfig, LifecycleCommand, LifecycleCommandEnvelope,
        LifecyclePredecessor, PlacementIdentity, RequestedVolumeDisposition, RuntimeNetworkConfig,
        RuntimeVolumeConfig, RuntimeVolumeGuestBinding, TerminalResultKind,
    };
    use cats_api::runtime_reconciliation::{
        ContractVersion, Durability, Epoch, Ipv4Address, MacAddress, NodeBootId, SessionBinding,
        Sha256Digest,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::lifecycle_command::journal::{
        LifecycleJournalStartupInventory, StartupPhysicalInventory,
    };

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).expect("valid test random ID")
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn session() -> AgentSession {
        AgentSession {
            version: ContractVersion::V1,
            node_id: id("node_inventory_runner"),
            immutable_host_id: id("host_inventory_runner"),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111")
                .expect("valid boot ID"),
            agent_instance_id: random(1),
            agent_session_epoch: Epoch::new(1).expect("positive session epoch"),
            registration_attempt_id: random(2),
            guest_config_digest: digest(3),
            lease_deadline_unix_ms: UnixMillis::new(50_000).expect("positive lease deadline"),
        }
    }

    fn delete_command() -> LifecycleCommandEnvelope {
        let grace_deadline = deadline_after(Duration::from_secs(8));
        let convergence_deadline = deadline_after(Duration::from_secs(10));
        let placement = PlacementIdentity {
            node_id: id("node_inventory_runner"),
            placement_epoch: Epoch::new(1).expect("positive placement epoch"),
        };
        let runtime_config = ImmutableRuntimeConfig::new(
            id("config_inventory_force_full"),
            digest(11),
            2,
            512 * 1024 * 1024,
            digest(12),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_inventory_force_full"),
                guest_mac: MacAddress::new("02:00:00:00:00:41").expect("valid MAC"),
                guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid gateway IP"),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_inventory_root"),
                disk_id: id("disk_inventory_root"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("inventory_root"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .expect("valid runtime config");
        LifecycleCommandEnvelope::new(
            id("operation_inventory_delete"),
            id("workspace_inventory"),
            id("cat_inventory"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            Some(id("operation_inventory_ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation_inventory_ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(13),
                node_id: placement.node_id.clone(),
                placement_identity: placement,
            },
            LifecycleCommand::Delete(DeleteSpec {
                delete_id: id("delete_inventory"),
                grace_deadline_unix_ms: grace_deadline,
                convergence_deadline_unix_ms: convergence_deadline,
                volume_dispositions: vec![RequestedVolumeDisposition::DiscardWithCat {
                    volume_id: id("volume_inventory_root"),
                    disk_id: id("disk_inventory_root"),
                    disk_role: DiskRole::Root,
                }],
            }),
        )
        .expect("valid Delete command")
    }

    fn deadline_after(duration: Duration) -> UnixMillis {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock follows Unix epoch");
        let deadline = now
            .checked_add(duration)
            .expect("test deadline is representable");
        UnixMillis::new(u64::try_from(deadline.as_millis()).expect("test deadline fits wire type"))
            .expect("positive test deadline")
    }

    #[derive(Default)]
    struct StaticSource {
        full_calls: Arc<AtomicUsize>,
        partial_calls: Arc<AtomicUsize>,
    }

    impl RuntimeInventorySource for StaticSource {
        fn collect_full(&self) -> RuntimeFullInventoryFuture {
            let calls = Arc::clone(&self.full_calls);
            Box::pin(async move {
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(RuntimeFullInventoryScan {
                    scan_id: random(100 + call as u128),
                    collected_at_unix_ms: UnixMillis::new(1_000 + call as u64)
                        .expect("positive collection time"),
                    cats: Vec::new(),
                    unattributed_artifacts: Vec::new(),
                })
            })
        }

        fn collect_partial(
            &self,
            context: RuntimePartialInventoryContext,
        ) -> RuntimePartialInventoryFuture {
            let calls = Arc::clone(&self.partial_calls);
            Box::pin(async move {
                assert!(context.full_cat_ids.is_empty());
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(RuntimePartialInventoryScan {
                    collected_at_unix_ms: UnixMillis::new(2_000).expect("positive collection time"),
                    cats: Vec::new(),
                })
            })
        }
    }

    type RecordedAttempts = Arc<Mutex<Vec<Vec<u8>>>>;

    struct RecordingTransport {
        attempts: RecordedAttempts,
        retry_first: bool,
        partial_accepted: Arc<tokio::sync::Notify>,
    }

    impl RuntimeInventoryTransport for RecordingTransport {
        fn send(&self, exact_body: Vec<u8>) -> RuntimeInventoryTransportFuture {
            let attempts = Arc::clone(&self.attempts);
            let retry_first = self.retry_first;
            let partial_accepted = Arc::clone(&self.partial_accepted);
            Box::pin(async move {
                let attempt = {
                    let mut attempts = attempts.lock().expect("transport attempt lock");
                    attempts.push(exact_body.clone());
                    attempts.len()
                };
                if retry_first && attempt == 1 {
                    return RuntimeInventoryTransportAttempt::RetryExact(
                        RuntimeInventoryTransportRetryReason::Transport,
                    );
                }
                let report = decode_runtime_inventory_report(&exact_body)
                    .expect("runner sends canonical report");
                let acceptance = acceptance(&report);
                let exact_acceptance =
                    encode_runtime_inventory_acceptance(&acceptance).expect("encode acceptance");
                if matches!(report.inventory, RuntimeInventoryBody::Partial { .. }) {
                    partial_accepted.notify_one();
                }
                RuntimeInventoryTransportAttempt::Accepted {
                    acceptance,
                    exact_body: exact_acceptance,
                }
            })
        }
    }

    fn transport(retry_first: bool) -> (Arc<RecordingTransport>, RecordedAttempts) {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(RecordingTransport {
                attempts: Arc::clone(&attempts),
                retry_first,
                partial_accepted: Arc::new(tokio::sync::Notify::new()),
            }),
            attempts,
        )
    }

    fn acceptance(report: &RuntimeInventoryReport) -> RuntimeInventoryAcceptance {
        let accepted_at_unix_ms =
            UnixMillis::new(10_000 + report.sequence.get()).expect("positive acceptance time");
        let inventory = match &report.inventory {
            RuntimeInventoryBody::Full {
                inventory_epoch,
                scan_id,
                inventory_digest,
                ..
            } => RuntimeInventoryAcceptanceKind::Full {
                attestation: Box::new(RuntimeInventoryAttestation {
                    version: ContractVersion::V1,
                    session: report.session.clone(),
                    inventory_epoch: *inventory_epoch,
                    scan_id: scan_id.clone(),
                    inventory_digest: inventory_digest.clone(),
                    source_report_id: report.report_id.clone(),
                    source_sequence: report.sequence,
                    accepted_at_unix_ms,
                }),
            },
            RuntimeInventoryBody::Partial {
                inventory_epoch, ..
            } => RuntimeInventoryAcceptanceKind::Partial {
                inventory_epoch: *inventory_epoch,
            },
        };
        RuntimeInventoryAcceptance {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: report.session.node_id.clone(),
                node_boot_id: report.session.node_boot_id.clone(),
                agent_instance_id: report.session.agent_instance_id.clone(),
                agent_session_epoch: report.session.agent_session_epoch,
            },
            report_id: report.report_id.clone(),
            sequence: report.sequence,
            accepted_at_unix_ms,
            lease_deadline_unix_ms: UnixMillis::new(20_000).expect("positive lease deadline"),
            inventory,
        }
    }

    async fn open_runner(
        root: &TempDir,
        transport: Arc<dyn RuntimeInventoryTransport>,
        source: Arc<dyn RuntimeInventorySource>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> (
        RuntimeInventoryRunner,
        tokio::sync::watch::Receiver<RuntimeInventoryReadiness>,
    ) {
        open_runner_with_force_full(
            root,
            transport,
            source,
            RuntimeInventoryForceFullCoordinator::new(),
            shutdown,
        )
        .await
    }

    async fn open_runner_with_force_full(
        root: &TempDir,
        transport: Arc<dyn RuntimeInventoryTransport>,
        source: Arc<dyn RuntimeInventorySource>,
        force_full: Arc<RuntimeInventoryForceFullCoordinator>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> (
        RuntimeInventoryRunner,
        tokio::sync::watch::Receiver<RuntimeInventoryReadiness>,
    ) {
        RuntimeInventoryRunner::open(
            StateDirectory::unanchored(root.path().to_path_buf()),
            session(),
            transport,
            source,
            force_full,
            shutdown,
        )
        .await
        .expect("open runtime inventory runner")
    }

    async fn wait_for_attested(
        readiness: &mut tokio::sync::watch::Receiver<RuntimeInventoryReadiness>,
    ) -> RuntimeInventoryAttestation {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let RuntimeInventoryReadiness::Attested { attestation } = &*readiness.borrow() {
                    return attestation.as_ref().clone();
                }
                readiness
                    .changed()
                    .await
                    .expect("readiness sender remains live");
            }
        })
        .await
        .expect("Full acceptance makes readiness attested")
    }

    #[tokio::test]
    async fn ambiguous_transport_retries_the_exact_durable_full() {
        let root = TempDir::new().expect("temporary directory");
        let source = Arc::new(StaticSource::default());
        let (transport, attempts) = transport(true);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (runner, mut readiness) = open_runner(&root, transport, source, shutdown_rx).await;
        let task = tokio::spawn(runner.run());

        let attestation = wait_for_attested(&mut readiness).await;
        assert_eq!(attestation.inventory_epoch.get(), 1);
        {
            let attempts = attempts.lock().expect("transport attempt lock");
            assert!(attempts.len() >= 2);
            assert_eq!(attempts[0], attempts[1]);
        }

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner shuts down")
            .expect("runner task joins")
            .expect("runner exits successfully");
    }

    #[tokio::test]
    async fn accepted_partial_is_sent_without_replacing_full_readiness() {
        let root = TempDir::new().expect("temporary directory");
        let source = Arc::new(StaticSource::default());
        let (transport, attempts) = transport(false);
        let partial_accepted = Arc::clone(&transport.partial_accepted);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (runner, mut readiness) =
            open_runner(&root, transport, source.clone(), shutdown_rx).await;
        let task = tokio::spawn(runner.run());

        let full_attestation = wait_for_attested(&mut readiness).await;
        tokio::time::timeout(Duration::from_secs(2), partial_accepted.notified())
            .await
            .expect("Partial is accepted");
        assert!(source.partial_calls.load(Ordering::SeqCst) >= 1);
        assert_eq!(
            *readiness.borrow(),
            RuntimeInventoryReadiness::Attested {
                attestation: Box::new(full_attestation),
            }
        );
        let reports: Vec<RuntimeInventoryReport> = attempts
            .lock()
            .expect("transport attempt lock")
            .iter()
            .map(|bytes| decode_runtime_inventory_report(bytes).expect("canonical report"))
            .collect();
        assert!(matches!(
            reports.first().map(|report| &report.inventory),
            Some(RuntimeInventoryBody::Full { .. })
        ));
        assert!(reports
            .iter()
            .any(|report| matches!(&report.inventory, RuntimeInventoryBody::Partial { .. })));

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner shuts down")
            .expect("runner task joins")
            .expect("runner exits successfully");
    }

    struct PostStopFullSource {
        command: LifecycleCommandEnvelope,
        full_calls: Arc<AtomicUsize>,
    }

    impl RuntimeInventorySource for PostStopFullSource {
        fn collect_full(&self) -> RuntimeFullInventoryFuture {
            let command = self.command.clone();
            let calls = Arc::clone(&self.full_calls);
            Box::pin(async move {
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                let cats = if call == 1 {
                    Vec::new()
                } else {
                    vec![ObservedCatRuntimeTelemetry {
                        cat_id: command.cat_id.clone(),
                        observed_placement: command.placement_identity.clone(),
                        observed_command_journal: Some(ObservedCommandJournal::Executing {
                            operation_id: command.operation_id.clone(),
                            command_kind: command.command_kind(),
                            request_fingerprint: command.request_fingerprint.clone(),
                            journal_digest: digest(21),
                        }),
                        observed_physical_state: ObservedRuntimePhysicalState::Absent,
                        observed_runtime_incarnation: None,
                        observed_artifact_manifest_digest: digest(22),
                        observed_artifact_classifications: Vec::new(),
                        observed_volumes: Vec::new(),
                        observed_conditions: Vec::new(),
                    }]
                };
                Ok(RuntimeFullInventoryScan {
                    scan_id: random(300 + call as u128),
                    collected_at_unix_ms: UnixMillis::new(3_000 + call as u64)
                        .expect("positive collection time"),
                    cats,
                    unattributed_artifacts: Vec::new(),
                })
            })
        }

        fn collect_partial(
            &self,
            _context: RuntimePartialInventoryContext,
        ) -> RuntimePartialInventoryFuture {
            Box::pin(async {
                Ok(RuntimePartialInventoryScan {
                    collected_at_unix_ms: UnixMillis::new(4_000).expect("positive collection time"),
                    cats: Vec::new(),
                })
            })
        }
    }

    #[tokio::test]
    async fn force_full_waits_for_a_fresh_post_stop_full_acceptance() {
        use crate::runtime_inventory::RuntimeInventoryAttestationPort as _;

        let root = TempDir::new().expect("temporary directory");
        let command = delete_command();
        let full_calls = Arc::new(AtomicUsize::new(0));
        let source = Arc::new(PostStopFullSource {
            command: command.clone(),
            full_calls: Arc::clone(&full_calls),
        });
        let force_full = RuntimeInventoryForceFullCoordinator::new();
        let (transport, _) = transport(false);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (runner, mut readiness) = open_runner_with_force_full(
            &root,
            transport,
            source,
            Arc::clone(&force_full),
            shutdown_rx,
        )
        .await;
        let task = tokio::spawn(runner.run());

        let startup_attestation = wait_for_attested(&mut readiness).await;
        assert_eq!(startup_attestation.scan_id, random(301));
        let waiter = tokio::task::spawn_blocking(move || {
            force_full.force_full_and_wait(&command, deadline_after(Duration::from_secs(5)))
        });
        let post_stop_attestation = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("fresh Full is accepted before the caller deadline")
            .expect("blocking waiter joins")
            .expect("post-Stop Full proves exact absence");

        assert_ne!(post_stop_attestation.scan_id, startup_attestation.scan_id);
        assert!(full_calls.load(Ordering::SeqCst) >= 2);

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner shuts down")
            .expect("runner task joins")
            .expect("runner exits successfully");
    }

    #[tokio::test]
    async fn force_full_queued_before_run_waits_past_the_startup_full() {
        use crate::runtime_inventory::RuntimeInventoryAttestationPort as _;

        let root = TempDir::new().expect("temporary directory");
        let command = delete_command();
        let full_calls = Arc::new(AtomicUsize::new(0));
        let source = Arc::new(PostStopFullSource {
            command: command.clone(),
            full_calls: Arc::clone(&full_calls),
        });
        let force_full = RuntimeInventoryForceFullCoordinator::new();
        let (transport, _) = transport(false);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (runner, mut readiness) = open_runner_with_force_full(
            &root,
            transport,
            source,
            Arc::clone(&force_full),
            shutdown_rx,
        )
        .await;

        let waiter_force_full = Arc::clone(&force_full);
        let waiter = tokio::task::spawn_blocking(move || {
            waiter_force_full.force_full_and_wait(&command, deadline_after(Duration::from_secs(5)))
        });
        tokio::time::timeout(Duration::from_secs(2), force_full.notified())
            .await
            .expect("force-Full request is queued before the runner starts");

        let task = tokio::spawn(runner.run());
        let startup_attestation = wait_for_attested(&mut readiness).await;
        assert_eq!(startup_attestation.scan_id, random(301));
        let post_stop_attestation = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("fresh Full is accepted before the caller deadline")
            .expect("blocking waiter joins")
            .expect("post-Stop Full proves exact absence");

        assert_eq!(post_stop_attestation.scan_id, random(302));
        assert_eq!(full_calls.load(Ordering::SeqCst), 2);

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("runner shuts down")
            .expect("runner task joins")
            .expect("runner exits successfully");
    }

    #[tokio::test]
    async fn dropping_runner_wakes_an_active_force_full_waiter_closed() {
        use crate::runtime_inventory::RuntimeInventoryAttestationPort as _;

        let root = TempDir::new().expect("temporary directory");
        let force_full = RuntimeInventoryForceFullCoordinator::new();
        let (transport, _) = transport(false);
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (mut runner, _readiness) = open_runner_with_force_full(
            &root,
            transport,
            Arc::new(StaticSource::default()),
            Arc::clone(&force_full),
            shutdown_rx,
        )
        .await;
        let command = delete_command();
        let waiter = tokio::task::spawn_blocking(move || {
            force_full.force_full_and_wait(&command, deadline_after(Duration::from_secs(5)))
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                runner
                    .take_force_full_requests()
                    .expect("take force-Full request");
                if !runner.force_full_waiters.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking caller enqueues request");
        drop(runner);

        let error = waiter
            .await
            .expect("blocking waiter joins")
            .expect_err("closed runner cannot attest inventory");
        assert_eq!(
            error.downcast_ref::<RuntimeInventoryForceFullError>(),
            Some(&RuntimeInventoryForceFullError::Closed)
        );
    }

    struct FailingSource {
        attempts: Arc<AtomicUsize>,
        attempted: Arc<tokio::sync::Notify>,
    }

    impl RuntimeInventorySource for FailingSource {
        fn collect_full(&self) -> RuntimeFullInventoryFuture {
            let attempts = Arc::clone(&self.attempts);
            let attempted = Arc::clone(&self.attempted);
            Box::pin(async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                attempted.notify_one();
                Err(RuntimeInventoryCollectionError::Source(anyhow::anyhow!(
                    "injected complete-scan failure"
                )))
            })
        }

        fn collect_partial(
            &self,
            _context: RuntimePartialInventoryContext,
        ) -> RuntimePartialInventoryFuture {
            unreachable!("Partial collection requires an accepted Full")
        }
    }

    struct UnexpectedTransport;

    impl RuntimeInventoryTransport for UnexpectedTransport {
        fn send(&self, _exact_body: Vec<u8>) -> RuntimeInventoryTransportFuture {
            panic!("failed collection must not send telemetry")
        }
    }

    #[tokio::test]
    async fn collection_failure_stays_unattested_and_does_not_wedge_shutdown() {
        let root = TempDir::new().expect("temporary directory");
        let attempted = Arc::new(tokio::sync::Notify::new());
        let source = Arc::new(FailingSource {
            attempts: Arc::new(AtomicUsize::new(0)),
            attempted: Arc::clone(&attempted),
        });
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (runner, readiness) =
            open_runner(&root, Arc::new(UnexpectedTransport), source, shutdown_rx).await;
        let task = tokio::spawn(runner.run());

        tokio::time::timeout(Duration::from_secs(2), attempted.notified())
            .await
            .expect("collection is attempted");
        assert_eq!(*readiness.borrow(), RuntimeInventoryReadiness::AwaitingFull);
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("failed telemetry task observes shutdown")
            .expect("runner task joins")
            .expect("collection failure remains retryable");
    }

    struct RefreshPort {
        full_calls: Arc<AtomicUsize>,
    }

    impl RuntimeInventoryCollectionPort for RefreshPort {
        fn collect_full(&self) -> anyhow::Result<RuntimeFullInventoryScan> {
            self.full_calls.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeFullInventoryScan {
                scan_id: random(902),
                collected_at_unix_ms: UnixMillis::new(902)
                    .expect("positive refresh collection time"),
                cats: Vec::new(),
                unattributed_artifacts: Vec::new(),
            })
        }

        fn collect_partial(
            &self,
            _context: &RuntimePartialInventoryContext,
        ) -> anyhow::Result<RuntimePartialInventoryScan> {
            unreachable!("this test does not collect Partial telemetry")
        }
    }

    #[tokio::test]
    async fn production_source_uses_joined_startup_seed_before_installed_refresh() {
        let registered = session();
        let cache = StartupInventoryCache::new();
        cache
            .initialize_physical(
                &registered,
                &StartupPhysicalInventory::Complete {
                    scan_id: random(901),
                    collected_at_unix_ms: UnixMillis::new(901)
                        .expect("positive startup collection time"),
                    cats: Vec::new(),
                    unattributed_artifacts: Vec::new(),
                },
            )
            .expect("initialize startup physical scan");
        cache
            .join_and_publish_once(&registered, &LifecycleJournalStartupInventory::default())
            .expect("publish joined startup seed");
        let full_calls = Arc::new(AtomicUsize::new(0));
        let source = ProductionRuntimeInventorySource::new(
            cache,
            Arc::new(RefreshPort {
                full_calls: Arc::clone(&full_calls),
            }),
        );

        let startup = source.collect_full().await.expect("collect startup seed");
        assert_eq!(startup.scan_id, random(901));
        assert_eq!(full_calls.load(Ordering::SeqCst), 0);
        let refresh = source
            .collect_full()
            .await
            .expect("collect installed refresh");
        assert_eq!(refresh.scan_id, random(902));
        assert_eq!(full_calls.load(Ordering::SeqCst), 1);
    }
}

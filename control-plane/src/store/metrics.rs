//! Process-local, low-cardinality control-store executor metrics.
//!
//! These counters deliberately never touch PostgreSQL. In particular, the
//! `/metrics` handler can observe a saturated lane or a stuck blocking call
//! without first joining the same queue it is trying to diagnose.

use std::error::Error as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::*;

#[derive(Clone, Copy)]
pub(super) enum ExecutorKind {
    Normal,
    Leadership,
}

#[derive(Clone, Copy)]
pub(super) enum RejectionKind {
    Admission,
    NormalQueue,
    LeadershipQueue,
    NormalCleanup,
    LeadershipCleanup,
    SingletonConnection,
    OciConnection,
    ObservationAdmission,
    ObservationQueue,
}

static ADMISSION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static NORMAL_QUEUE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static LEADERSHIP_QUEUE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static NORMAL_CLEANUP_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static LEADERSHIP_CLEANUP_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static SINGLETON_CONNECTION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static OCI_CONNECTION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static OBSERVATION_ADMISSION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static OBSERVATION_QUEUE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static LANE_ACQUIRE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static POSTGRES_STATEMENT_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static POSTGRES_IO_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_COMMITTED: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_DOMAIN_REJECTED: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_BACKEND_FAILED: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_SERIALIZATION_RETRIES: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_DEADLOCK_RETRIES: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_CONNECTION_RETRIES: AtomicU64 = AtomicU64::new(0);
static NORMAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static NORMAL_REQUEST_MICROS: AtomicU64 = AtomicU64::new(0);
static LEADERSHIP_REQUESTS: AtomicU64 = AtomicU64::new(0);
static LEADERSHIP_REQUEST_MICROS: AtomicU64 = AtomicU64::new(0);

pub(super) struct RequestTimer {
    kind: ExecutorKind,
    started: Instant,
}

impl RequestTimer {
    pub(super) fn new(kind: ExecutorKind) -> Self {
        Self {
            kind,
            started: Instant::now(),
        }
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        let micros = self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let (requests, elapsed) = match self.kind {
            ExecutorKind::Normal => (&NORMAL_REQUESTS, &NORMAL_REQUEST_MICROS),
            ExecutorKind::Leadership => (&LEADERSHIP_REQUESTS, &LEADERSHIP_REQUEST_MICROS),
        };
        requests.fetch_add(1, Ordering::Relaxed);
        elapsed.fetch_add(micros, Ordering::Relaxed);
    }
}

pub(super) fn record_rejection(kind: RejectionKind) {
    let counter = match kind {
        RejectionKind::Admission => &ADMISSION_REJECTIONS,
        RejectionKind::NormalQueue => &NORMAL_QUEUE_REJECTIONS,
        RejectionKind::LeadershipQueue => &LEADERSHIP_QUEUE_REJECTIONS,
        RejectionKind::NormalCleanup => &NORMAL_CLEANUP_REJECTIONS,
        RejectionKind::LeadershipCleanup => &LEADERSHIP_CLEANUP_REJECTIONS,
        RejectionKind::SingletonConnection => &SINGLETON_CONNECTION_REJECTIONS,
        RejectionKind::OciConnection => &OCI_CONNECTION_REJECTIONS,
        RejectionKind::ObservationAdmission => &OBSERVATION_ADMISSION_REJECTIONS,
        RejectionKind::ObservationQueue => &OBSERVATION_QUEUE_REJECTIONS,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
pub(super) fn rejection_count(kind: RejectionKind) -> u64 {
    let counter = match kind {
        RejectionKind::Admission => &ADMISSION_REJECTIONS,
        RejectionKind::NormalQueue => &NORMAL_QUEUE_REJECTIONS,
        RejectionKind::LeadershipQueue => &LEADERSHIP_QUEUE_REJECTIONS,
        RejectionKind::NormalCleanup => &NORMAL_CLEANUP_REJECTIONS,
        RejectionKind::LeadershipCleanup => &LEADERSHIP_CLEANUP_REJECTIONS,
        RejectionKind::SingletonConnection => &SINGLETON_CONNECTION_REJECTIONS,
        RejectionKind::OciConnection => &OCI_CONNECTION_REJECTIONS,
        RejectionKind::ObservationAdmission => &OBSERVATION_ADMISSION_REJECTIONS,
        RejectionKind::ObservationQueue => &OBSERVATION_QUEUE_REJECTIONS,
    };
    counter.load(Ordering::Relaxed)
}

pub(super) fn record_lane_acquire_timeout() {
    LANE_ACQUIRE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
pub(super) enum AuthorityOutcome {
    Committed,
    DomainRejected,
    BackendFailed,
}

pub(super) fn record_authority_outcome(outcome: AuthorityOutcome) {
    let counter = match outcome {
        AuthorityOutcome::Committed => &AUTHORITY_COMMITTED,
        AuthorityOutcome::DomainRejected => &AUTHORITY_DOMAIN_REJECTED,
        AuthorityOutcome::BackendFailed => &AUTHORITY_BACKEND_FAILED,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
pub(super) enum AuthorityRetryReason {
    Serialization,
    Deadlock,
    Connection,
}

pub(super) fn record_authority_retry(reason: AuthorityRetryReason) {
    let counter = match reason {
        AuthorityRetryReason::Serialization => &AUTHORITY_SERIALIZATION_RETRIES,
        AuthorityRetryReason::Deadlock => &AUTHORITY_DEADLOCK_RETRIES,
        AuthorityRetryReason::Connection => &AUTHORITY_CONNECTION_RETRIES,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Count server-enforced statement/lock deadlines and established-session I/O
/// deadlines without attaching SQL text, resource ids, or error messages.
pub(super) fn record_postgres_error(error: &postgres::Error) {
    if matches!(
        error.code(),
        Some(&postgres::error::SqlState::QUERY_CANCELED)
            | Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE)
    ) {
        POSTGRES_STATEMENT_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut source = error.source();
    while let Some(current) = source {
        if current
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
        {
            POSTGRES_IO_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        source = current.source();
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExecutorSnapshot {
    pub active: usize,
    pub queued: usize,
    pub cleanup_queued: usize,
    pub workers: usize,
    pub queue_capacity: usize,
    pub cleanup_capacity: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StoreMetricsSnapshot {
    pub normal: ExecutorSnapshot,
    pub leadership: ExecutorSnapshot,
    pub admission_depth: usize,
    pub admission_capacity: usize,
    pub admission_rejections: u64,
    pub normal_queue_rejections: u64,
    pub leadership_queue_rejections: u64,
    pub normal_cleanup_rejections: u64,
    pub leadership_cleanup_rejections: u64,
    pub singleton_connection_rejections: u64,
    pub oci_connection_rejections: u64,
    pub observation_admission_rejections: u64,
    pub observation_queue_rejections: u64,
    pub lane_acquire_timeouts: u64,
    pub postgres_statement_timeouts: u64,
    pub postgres_io_timeouts: u64,
    pub authority_committed: u64,
    pub authority_domain_rejected: u64,
    pub authority_backend_failed: u64,
    pub authority_serialization_retries: u64,
    pub authority_deadlock_retries: u64,
    pub authority_connection_retries: u64,
    pub normal_requests: u64,
    pub normal_request_micros: u64,
    pub leadership_requests: u64,
    pub leadership_request_micros: u64,
    pub normal_connections: usize,
    pub singleton_connections: usize,
    pub oci_connections: usize,
}

fn executor_snapshot(
    slot: &OnceLock<std::result::Result<executor::BlockingExecutor, String>>,
    limits: executor::Limits,
) -> ExecutorSnapshot {
    let snapshot = slot
        .get()
        .and_then(|result| result.as_ref().ok())
        .map(executor::BlockingExecutor::snapshot);
    ExecutorSnapshot {
        active: snapshot.map_or(0, |value| value.active),
        queued: snapshot.map_or(0, |value| value.queued),
        cleanup_queued: snapshot.map_or(0, |value| value.cleanup_queued),
        workers: limits.workers,
        queue_capacity: limits.queue_capacity,
        cleanup_capacity: limits.cleanup_capacity,
    }
}

pub(crate) fn snapshot(store: &Store) -> StoreMetricsSnapshot {
    let admission_capacity = CONTROL_STORE_BLOCKING_WORKERS + CONTROL_STORE_QUEUE_CAPACITY;
    let admission_depth = CONTROL_STORE_ADMISSION.get().map_or(0, |admission| {
        admission_capacity - admission.available_permits()
    });
    StoreMetricsSnapshot {
        normal: executor_snapshot(&CONTROL_STORE_EXECUTOR, CONTROL_STORE_EXECUTOR_LIMITS),
        leadership: executor_snapshot(
            &CONTROL_STORE_LEADERSHIP_EXECUTOR,
            CONTROL_STORE_LEADERSHIP_EXECUTOR_LIMITS,
        ),
        admission_depth,
        admission_capacity,
        admission_rejections: ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        normal_queue_rejections: NORMAL_QUEUE_REJECTIONS.load(Ordering::Relaxed),
        leadership_queue_rejections: LEADERSHIP_QUEUE_REJECTIONS.load(Ordering::Relaxed),
        normal_cleanup_rejections: NORMAL_CLEANUP_REJECTIONS.load(Ordering::Relaxed),
        leadership_cleanup_rejections: LEADERSHIP_CLEANUP_REJECTIONS.load(Ordering::Relaxed),
        singleton_connection_rejections: SINGLETON_CONNECTION_REJECTIONS.load(Ordering::Relaxed),
        oci_connection_rejections: OCI_CONNECTION_REJECTIONS.load(Ordering::Relaxed),
        observation_admission_rejections: OBSERVATION_ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        observation_queue_rejections: OBSERVATION_QUEUE_REJECTIONS.load(Ordering::Relaxed),
        lane_acquire_timeouts: LANE_ACQUIRE_TIMEOUTS.load(Ordering::Relaxed),
        postgres_statement_timeouts: POSTGRES_STATEMENT_TIMEOUTS.load(Ordering::Relaxed),
        postgres_io_timeouts: POSTGRES_IO_TIMEOUTS.load(Ordering::Relaxed),
        authority_committed: AUTHORITY_COMMITTED.load(Ordering::Relaxed),
        authority_domain_rejected: AUTHORITY_DOMAIN_REJECTED.load(Ordering::Relaxed),
        authority_backend_failed: AUTHORITY_BACKEND_FAILED.load(Ordering::Relaxed),
        authority_serialization_retries: AUTHORITY_SERIALIZATION_RETRIES.load(Ordering::Relaxed),
        authority_deadlock_retries: AUTHORITY_DEADLOCK_RETRIES.load(Ordering::Relaxed),
        authority_connection_retries: AUTHORITY_CONNECTION_RETRIES.load(Ordering::Relaxed),
        normal_requests: NORMAL_REQUESTS.load(Ordering::Relaxed),
        normal_request_micros: NORMAL_REQUEST_MICROS.load(Ordering::Relaxed),
        leadership_requests: LEADERSHIP_REQUESTS.load(Ordering::Relaxed),
        leadership_request_micros: LEADERSHIP_REQUEST_MICROS.load(Ordering::Relaxed),
        normal_connections: match store.client.try_lock() {
            Ok(client) => usize::from(client.is_some()),
            Err(std::sync::TryLockError::WouldBlock) => CONTROL_STORE_CONNECTIONS,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                usize::from(poisoned.into_inner().is_some())
            }
        },
        singleton_connections: CONTROL_STORE_SINGLETON_CONNECTIONS_IN_USE.load(Ordering::Acquire),
        oci_connections: CONTROL_STORE_OCI_CONNECTIONS_IN_USE.load(Ordering::Acquire),
    }
}

impl StoreMetricsSnapshot {
    pub(crate) fn append_prometheus(self, body: &mut String) {
        use std::fmt::Write as _;

        for (name, snapshot) in [("normal", self.normal), ("leadership", self.leadership)] {
            let _ = writeln!(
                body,
                "cats_control_store_blocking_jobs_active{{executor=\"{name}\"}} {}",
                snapshot.active
            );
            let _ = writeln!(
                body,
                "cats_control_store_blocking_queue_depth{{executor=\"{name}\"}} {}",
                snapshot.queued
            );
            let _ = writeln!(
                body,
                "cats_control_store_blocking_workers{{executor=\"{name}\"}} {}",
                snapshot.workers
            );
            let _ = writeln!(
                body,
                "cats_control_store_blocking_queue_capacity{{executor=\"{name}\"}} {}",
                snapshot.queue_capacity
            );
            let _ = writeln!(
                body,
                "cats_control_store_blocking_cleanup_queue_depth{{executor=\"{name}\"}} {}",
                snapshot.cleanup_queued
            );
            let _ = writeln!(
                body,
                "cats_control_store_blocking_cleanup_queue_capacity{{executor=\"{name}\"}} {}",
                snapshot.cleanup_capacity
            );
        }
        let _ = writeln!(
            body,
            "cats_control_store_admission_depth {}",
            self.admission_depth
        );
        let _ = writeln!(
            body,
            "cats_control_store_admission_capacity {}",
            self.admission_capacity
        );
        for (boundary, value) in [
            ("admission", self.admission_rejections),
            ("normal_queue", self.normal_queue_rejections),
            ("leadership_queue", self.leadership_queue_rejections),
            ("normal_cleanup", self.normal_cleanup_rejections),
            ("leadership_cleanup", self.leadership_cleanup_rejections),
            ("singleton_connection", self.singleton_connection_rejections),
            ("oci_connection", self.oci_connection_rejections),
            (
                "observation_admission",
                self.observation_admission_rejections,
            ),
            ("observation_queue", self.observation_queue_rejections),
        ] {
            let _ = writeln!(
                body,
                "cats_control_store_rejections_total{{boundary=\"{boundary}\"}} {value}"
            );
        }
        for (kind, value) in [
            ("lane_acquire", self.lane_acquire_timeouts),
            ("statement_or_lock", self.postgres_statement_timeouts),
            ("established_io", self.postgres_io_timeouts),
        ] {
            let _ = writeln!(
                body,
                "cats_control_store_timeouts_total{{kind=\"{kind}\"}} {value}"
            );
        }
        for (executor, count, micros) in [
            ("normal", self.normal_requests, self.normal_request_micros),
            (
                "leadership",
                self.leadership_requests,
                self.leadership_request_micros,
            ),
        ] {
            let _ = writeln!(
                body,
                "cats_control_store_request_latency_seconds_count{{executor=\"{executor}\"}} {count}"
            );
            let _ = writeln!(
                body,
                "cats_control_store_request_latency_seconds_sum{{executor=\"{executor}\"}} {:.6}",
                micros as f64 / 1_000_000.0
            );
        }
        for (outcome, value) in [
            ("committed", self.authority_committed),
            ("domain_rejected", self.authority_domain_rejected),
            ("backend_failed", self.authority_backend_failed),
        ] {
            let _ = writeln!(
                body,
                "cats_control_store_authority_transactions_total{{outcome=\"{outcome}\"}} {value}"
            );
        }
        for (reason, value) in [
            ("serialization", self.authority_serialization_retries),
            ("deadlock", self.authority_deadlock_retries),
            ("connection", self.authority_connection_retries),
        ] {
            let _ = writeln!(
                body,
                "cats_control_store_authority_transaction_retries_total{{reason=\"{reason}\"}} {value}"
            );
        }
        for (kind, count, limit) in [
            ("normal", self.normal_connections, CONTROL_STORE_CONNECTIONS),
            (
                "singleton",
                self.singleton_connections,
                CONTROL_STORE_SINGLETON_CONNECTIONS,
            ),
            ("oci", self.oci_connections, CONTROL_STORE_OCI_CONNECTIONS),
        ] {
            let _ = writeln!(
                body,
                "cats_control_store_connections{{kind=\"{kind}\"}} {count}"
            );
            let _ = writeln!(
                body,
                "cats_control_store_connection_limit{{kind=\"{kind}\"}} {limit}"
            );
        }
    }
}

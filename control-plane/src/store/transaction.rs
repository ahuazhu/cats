//! One bounded PostgreSQL transaction boundary for runtime authority changes.

use std::error::Error as _;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::error::{ApiError, ErrorCode};
use cats_storage::authority::AuthorityError;
use postgres::error::SqlState;
use postgres::IsolationLevel;

use super::*;

const AUTHORITY_TRANSACTION_ATTEMPTS: usize = 3;
static RETRY_JITTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Cancellation/deadline state shared by an HTTP request and the blocking
/// authority worker that may outlive its async caller.
///
/// A queued worker observes it before opening a transaction. A started worker
/// checks it immediately before commit, so dropping or timing out the handler
/// cannot cause a delayed mutation. Cancellation racing an already-started
/// PostgreSQL COMMIT remains an intentionally ambiguous result recovered by
/// the domain's exact replay key.
#[derive(Clone)]
pub(crate) struct AuthorityRequestContext {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    commit_attempted: Arc<AtomicBool>,
}

impl AuthorityRequestContext {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
            commit_attempted: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn must_rollback(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }

    fn remaining_timeout_millis(&self) -> Option<u64> {
        if self.cancelled.load(Ordering::Acquire) {
            return None;
        }
        let remaining = self.deadline.checked_duration_since(Instant::now())?;
        let millis = remaining.as_millis().min(i32::MAX as u128) as u64;
        (millis > 0).then_some(millis)
    }

    fn begin_commit(&self) {
        self.commit_attempted.store(true, Ordering::Release);
    }

    /// A serialization or deadlock error returned by PostgreSQL from COMMIT
    /// proves that attempt did not commit. Clear the per-attempt phase before
    /// the closed transaction is replayed so an exhausted definite retry is
    /// not mislabeled as an unknown commit result by the HTTP owner.
    fn reset_after_definite_commit_failure(&self) {
        self.commit_attempted.store(false, Ordering::Release);
    }

    /// True after COMMIT may have reached PostgreSQL. Even when the blocking
    /// worker already knows it committed, a concurrent HTTP deadline can fire
    /// before that result crosses the executor channel; such a response must
    /// still close and let exact replay resolve what the client observed.
    pub(crate) fn commit_was_attempted(&self) -> bool {
        self.commit_attempted.load(Ordering::Acquire)
    }
}

pub(super) type AuthorityTxResult<T> = std::result::Result<T, AuthorityTransactionError>;

/// The closed result of an authenticated runtime request transaction.
///
/// A wire-visible rejection is a read-only decision: it must explicitly roll
/// back and can never enter PostgreSQL COMMIT or the ambiguous-response path.
/// Only an accepted mutation is allowed to cross the commit-send boundary.
pub(super) enum AuthorityRequestDisposition<T> {
    Commit(T),
    Reject(T),
}

pub(super) enum AuthorityTransactionError {
    Domain(AuthorityError),
    Application(ApiError),
    CandidateCollision,
    PlacementStale,
    Postgres(postgres::Error),
}

pub(super) enum AuthorityExecutionError {
    Store(ApiError),
    CandidateCollision,
    PlacementStale,
}

impl From<AuthorityError> for AuthorityTransactionError {
    fn from(error: AuthorityError) -> Self {
        Self::Domain(error)
    }
}

impl From<postgres::Error> for AuthorityTransactionError {
    fn from(error: postgres::Error) -> Self {
        Self::Postgres(error)
    }
}

impl From<ApiError> for AuthorityTransactionError {
    fn from(error: ApiError) -> Self {
        Self::Application(error)
    }
}

enum AttemptFailure {
    Domain(AuthorityError),
    Application(ApiError),
    CandidateCollision,
    PlacementStale,
    Postgres(postgres::Error),
    Commit(postgres::Error),
    Rollback(postgres::Error),
    Infrastructure(ApiError),
}

#[derive(Clone, Copy)]
#[allow(
    dead_code,
    reason = "read-only variant is consumed by the F3c composition"
)]
enum AuthorityTransactionMode {
    ReadWrite,
    RepeatableRead,
    RepeatableReadOnly,
}

impl Store {
    #[cfg(test)]
    pub(super) fn inject_committed_response_loss_once(&self) {
        self.commit_response_loss_once
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn inject_committed_response_loss_once_after(&self, delay: Duration) {
        self.commit_response_loss_delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
        self.inject_committed_response_loss_once();
    }

    /// Arm only the commit belonging to an HTTP authority request. Read-only
    /// credential lookup happens earlier in the same handler and must not
    /// consume this deterministic response-loss fixture.
    #[cfg(test)]
    pub(crate) fn inject_request_committed_response_loss_once_after(&self, delay: Duration) {
        self.commit_response_loss_delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
        self.request_commit_response_loss_once
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn request_committed_response_loss_is_armed(&self) -> bool {
        self.request_commit_response_loss_once
            .load(Ordering::Acquire)
    }

    /// Runs one complete authority closure in one fresh PostgreSQL
    /// transaction. Retriable database failures replay the whole closure;
    /// domain conflicts are rolled back and returned exactly once.
    pub(super) fn authority_transaction<T: Send>(
        &self,
        operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
    ) -> Result<T> {
        match self.authority_transaction_outcome(operation) {
            Ok(value) => Ok(value),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
            Err(AuthorityExecutionError::CandidateCollision) => Err(internal(
                "unexpected candidate-collision marker outside a covered create",
            )),
            Err(AuthorityExecutionError::PlacementStale) => Err(internal(
                "unexpected placement-stale marker outside a covered create",
            )),
        }
    }

    pub(super) fn authority_request_transaction<T: Send>(
        &self,
        request: &AuthorityRequestContext,
        operation: impl FnMut(
                &mut postgres::Transaction<'_>,
            ) -> AuthorityTxResult<AuthorityRequestDisposition<T>>
            + Send,
    ) -> Result<T> {
        match self.authority_transaction_outcome_with_hook(
            operation,
            AuthorityTransactionMode::ReadWrite,
            Some(request),
            || {},
        ) {
            Ok(value) => Ok(value),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
            Err(AuthorityExecutionError::CandidateCollision) => Err(internal(
                "unexpected candidate-collision marker in an authority request",
            )),
            Err(AuthorityExecutionError::PlacementStale) => Err(internal(
                "unexpected placement-stale marker in an authority request",
            )),
        }
    }

    /// Runs a complete authority facts loader in one PostgreSQL snapshot.
    /// Consumers must receive either the complete mutually-consistent fact set
    /// or no fact set at all, so this deliberately shares the retry and
    /// fail-closed error policy of mutation transactions.
    #[allow(dead_code, reason = "consumed by F3c planner/signer facts loaders")]
    pub(super) fn authority_read_snapshot<T: Send>(
        &self,
        operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
    ) -> Result<T> {
        match self.authority_transaction_outcome_with(
            operation,
            AuthorityTransactionMode::RepeatableReadOnly,
            None,
        ) {
            Ok(value) => Ok(value),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
            Err(AuthorityExecutionError::CandidateCollision) => Err(internal(
                "unexpected candidate-collision marker in an authority read snapshot",
            )),
            Err(AuthorityExecutionError::PlacementStale) => Err(internal(
                "unexpected placement-stale marker in an authority read snapshot",
            )),
        }
    }

    /// Runs a logically read-only authority closure in one repeatable-read
    /// snapshot that may acquire `FOR SHARE` locks. PostgreSQL forbids row
    /// locks in a transaction declared `READ ONLY`, so A22 uses this mode for
    /// the A23 NodeIdentity/credential-lineage retirement barrier while still
    /// performing no domain write or session renewal.
    #[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
    pub(super) fn authority_locking_read_snapshot<T: Send>(
        &self,
        operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
    ) -> Result<T> {
        match self.authority_transaction_outcome_with(
            operation,
            AuthorityTransactionMode::RepeatableRead,
            None,
        ) {
            Ok(value) => Ok(value),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
            Err(AuthorityExecutionError::CandidateCollision) => Err(internal(
                "unexpected candidate-collision marker in a locking authority snapshot",
            )),
            Err(AuthorityExecutionError::PlacementStale) => Err(internal(
                "unexpected placement-stale marker in a locking authority snapshot",
            )),
        }
    }

    pub(super) fn authority_transaction_outcome<T: Send>(
        &self,
        operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
    ) -> std::result::Result<T, AuthorityExecutionError> {
        self.authority_transaction_outcome_with(
            operation,
            AuthorityTransactionMode::ReadWrite,
            None,
        )
    }

    /// Cat-create exposes its commit-send phase to an async cancellation
    /// owner. A serialization/deadlock failure is a definite non-commit and
    /// therefore permits that owner to reset its per-attempt phase before the
    /// closed transaction is replayed. Connection failures stay ambiguous and
    /// deliberately do not invoke this hook.
    pub(super) fn authority_transaction_outcome_with_definite_retry<T: Send>(
        &self,
        mut operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
        on_definite_retry: impl FnMut() + Send,
    ) -> std::result::Result<T, AuthorityExecutionError> {
        self.authority_transaction_outcome_with_hook(
            move |transaction| operation(transaction).map(AuthorityRequestDisposition::Commit),
            AuthorityTransactionMode::ReadWrite,
            None,
            on_definite_retry,
        )
    }

    fn authority_transaction_outcome_with<T: Send>(
        &self,
        mut operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
        mode: AuthorityTransactionMode,
        request: Option<&AuthorityRequestContext>,
    ) -> std::result::Result<T, AuthorityExecutionError> {
        self.authority_transaction_outcome_with_hook(
            move |transaction| operation(transaction).map(AuthorityRequestDisposition::Commit),
            mode,
            request,
            || {},
        )
    }

    fn authority_transaction_outcome_with_hook<T: Send>(
        &self,
        mut operation: impl FnMut(
                &mut postgres::Transaction<'_>,
            ) -> AuthorityTxResult<AuthorityRequestDisposition<T>>
            + Send,
        mode: AuthorityTransactionMode,
        request: Option<&AuthorityRequestContext>,
        mut on_definite_retry: impl FnMut() + Send,
    ) -> std::result::Result<T, AuthorityExecutionError> {
        for attempt in 0..AUTHORITY_TRANSACTION_ATTEMPTS {
            if request.is_some_and(AuthorityRequestContext::must_rollback) {
                return Err(AuthorityExecutionError::Store(ApiError::unavailable(
                    "runtime authority request was cancelled or exceeded its deadline",
                )));
            }
            let outcome = self.enter(|client| {
                let client = client.map_err(AttemptFailure::Infrastructure)?;
                let mut transaction = match mode {
                    AuthorityTransactionMode::ReadWrite => client.transaction(),
                    AuthorityTransactionMode::RepeatableRead => client
                        .build_transaction()
                        .isolation_level(IsolationLevel::RepeatableRead)
                        .start(),
                    AuthorityTransactionMode::RepeatableReadOnly => client
                        .build_transaction()
                        .isolation_level(IsolationLevel::RepeatableRead)
                        .read_only(true)
                        .start(),
                }
                .map_err(AttemptFailure::Postgres)?;
                if let Some(request) = request {
                    let Some(timeout_ms) = request.remaining_timeout_millis() else {
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        return Err(AttemptFailure::Application(ApiError::unavailable(
                            "runtime authority request was cancelled or exceeded its deadline",
                        )));
                    };
                    let lock_timeout_ms = timeout_ms.min(2_000);
                    if let Err(error) = transaction.batch_execute(&format!(
                        "SET LOCAL statement_timeout = '{timeout_ms}ms'; \
                         SET LOCAL lock_timeout = '{lock_timeout_ms}ms'"
                    )) {
                        if let Err(rollback_error) = transaction.rollback() {
                            if client.is_closed() && authority_retry_reason(&error).is_some() {
                                return Err(AttemptFailure::Postgres(error));
                            }
                            return Err(AttemptFailure::Rollback(rollback_error));
                        }
                        return Err(AttemptFailure::Postgres(error));
                    }
                }
                match operation(&mut transaction) {
                    Ok(AuthorityRequestDisposition::Reject(value)) => {
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Ok(AuthorityRequestDisposition::Reject(value))
                    }
                    Ok(AuthorityRequestDisposition::Commit(_value))
                        if request.is_some_and(AuthorityRequestContext::must_rollback) =>
                    {
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Err(AttemptFailure::Application(ApiError::unavailable(
                            "runtime authority request was cancelled or exceeded its deadline",
                        )))
                    }
                    Ok(AuthorityRequestDisposition::Commit(value)) => {
                        if let Some(request) = request {
                            request.begin_commit();
                        }
                        match transaction.commit() {
                            Ok(()) => {
                                #[cfg(test)]
                                {
                                    let inject_response_loss = self
                                        .commit_response_loss_once
                                        .swap(false, Ordering::AcqRel)
                                        || (request.is_some()
                                            && self
                                                .request_commit_response_loss_once
                                                .swap(false, Ordering::AcqRel));
                                    if inject_response_loss {
                                        let delay_ms = self
                                            .commit_response_loss_delay_ms
                                            .swap(0, Ordering::AcqRel);
                                        if delay_ms != 0 {
                                            std::thread::sleep(Duration::from_millis(delay_ms));
                                        }
                                        return Err(AttemptFailure::Infrastructure(
                                            ApiError::unavailable(
                                                "injected loss of a successful PostgreSQL commit response",
                                            ),
                                        ));
                                    }
                                }
                                Ok(AuthorityRequestDisposition::Commit(value))
                            }
                            Err(error) => Err(AttemptFailure::Commit(error)),
                        }
                    }
                    Err(AuthorityTransactionError::Domain(error)) => {
                        // A domain rejection is never replayed. If its explicit
                        // rollback fails, the transaction outcome is unknown
                        // and must fail closed instead of being mislabeled as
                        // a retriable serialization/connection error.
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Err(AttemptFailure::Domain(error))
                    }
                    Err(AuthorityTransactionError::Application(error)) => {
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Err(AttemptFailure::Application(error))
                    }
                    Err(AuthorityTransactionError::CandidateCollision) => {
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Err(AttemptFailure::CandidateCollision)
                    }
                    Err(AuthorityTransactionError::PlacementStale) => {
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Err(AttemptFailure::PlacementStale)
                    }
                    Err(AuthorityTransactionError::Postgres(error)) => {
                        if let Err(rollback_error) = transaction.rollback() {
                            // A closed PostgreSQL session has already lost its
                            // transaction. Retrying the original explicitly
                            // transient error on a fresh connection is safe;
                            // every authority mutation is a closed replay.
                            if client.is_closed() && authority_retry_reason(&error).is_some() {
                                return Err(AttemptFailure::Postgres(error));
                            }
                            return Err(AttemptFailure::Rollback(rollback_error));
                        }
                        Err(AttemptFailure::Postgres(error))
                    }
                }
            });

            match outcome {
                Ok(AuthorityRequestDisposition::Commit(value)) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::Committed);
                    return Ok(value);
                }
                Ok(AuthorityRequestDisposition::Reject(value)) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::DomainRejected);
                    return Ok(value);
                }
                Err(AttemptFailure::Domain(error)) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::DomainRejected);
                    return Err(AuthorityExecutionError::Store(authority_rejection(error)));
                }
                Err(AttemptFailure::Application(error)) => {
                    metrics::record_authority_outcome(if error.code == ErrorCode::Internal {
                        metrics::AuthorityOutcome::BackendFailed
                    } else {
                        metrics::AuthorityOutcome::DomainRejected
                    });
                    return Err(AuthorityExecutionError::Store(error));
                }
                Err(AttemptFailure::CandidateCollision) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::DomainRejected);
                    return Err(AuthorityExecutionError::CandidateCollision);
                }
                Err(AttemptFailure::PlacementStale) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::DomainRejected);
                    return Err(AuthorityExecutionError::PlacementStale);
                }
                Err(AttemptFailure::Infrastructure(error)) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(AuthorityExecutionError::Store(error));
                }
                Err(AttemptFailure::Rollback(error)) => {
                    metrics::record_postgres_error(&error);
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(AuthorityExecutionError::Store(internal(format!(
                        "runtime authority PostgreSQL rollback failed: {error}"
                    ))));
                }
                Err(AttemptFailure::Postgres(error)) => {
                    metrics::record_postgres_error(&error);
                    if request.is_some() && request_timeout(&error) {
                        metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                        return Err(AuthorityExecutionError::Store(ApiError::unavailable(
                            "runtime authority request exceeded its PostgreSQL deadline",
                        )));
                    }
                    let retry_reason = authority_retry_reason(&error);
                    if attempt + 1 < AUTHORITY_TRANSACTION_ATTEMPTS {
                        if let Some(reason) = retry_reason {
                            if authority_retry_is_definite(&error) {
                                on_definite_retry();
                            }
                            metrics::record_authority_retry(reason);
                            std::thread::sleep(retry_delay(attempt));
                            continue;
                        }
                    }

                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(AuthorityExecutionError::Store(match retry_reason {
                        Some(_) => ApiError::unavailable(format!(
                            "runtime authority transaction did not commit after {AUTHORITY_TRANSACTION_ATTEMPTS} attempts"
                        )),
                        None
                            if matches!(
                                error.code(),
                                Some(&SqlState::QUERY_CANCELED)
                                    | Some(&SqlState::LOCK_NOT_AVAILABLE)
                            ) =>
                        {
                            ApiError::unavailable(
                                "runtime authority PostgreSQL statement or lock deadline elapsed",
                            )
                        }
                        None => internal(format!(
                            "runtime authority PostgreSQL transaction failed: {error}"
                        )),
                    }));
                }
                Err(AttemptFailure::Commit(error)) => {
                    metrics::record_postgres_error(&error);

                    // A request owner must never replay a transaction after a
                    // connection-class COMMIT failure: PostgreSQL may have
                    // durably committed it even though this process lost the
                    // response. Leave the phase marked attempted so HTTP
                    // closes the response and the Node performs exact replay.
                    // Serialization and deadlock failures are the opposite:
                    // PostgreSQL guarantees non-commit, so reset that attempt
                    // before the bounded transaction replay.
                    if let Some(request) = request {
                        if authority_retry_is_definite(&error) {
                            request.reset_after_definite_commit_failure();
                            on_definite_retry();
                            if attempt + 1 < AUTHORITY_TRANSACTION_ATTEMPTS {
                                let reason = authority_retry_reason(&error)
                                    .expect("definite COMMIT failures are retriable");
                                metrics::record_authority_retry(reason);
                                std::thread::sleep(retry_delay(attempt));
                                continue;
                            }
                            metrics::record_authority_outcome(
                                metrics::AuthorityOutcome::BackendFailed,
                            );
                            return Err(AuthorityExecutionError::Store(ApiError::unavailable(
                                format!(
                                    "runtime authority transaction did not commit after \
                                     {AUTHORITY_TRANSACTION_ATTEMPTS} attempts"
                                ),
                            )));
                        }

                        metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                        return Err(AuthorityExecutionError::Store(ApiError::unavailable(
                            "runtime authority PostgreSQL COMMIT result is unknown",
                        )));
                    }

                    // Non-request authority callers retain the historical
                    // bounded replay policy. Their higher-level contracts own
                    // any required exact-replay key.
                    let retry_reason = authority_retry_reason(&error);
                    if attempt + 1 < AUTHORITY_TRANSACTION_ATTEMPTS {
                        if let Some(reason) = retry_reason {
                            if authority_retry_is_definite(&error) {
                                on_definite_retry();
                            }
                            metrics::record_authority_retry(reason);
                            std::thread::sleep(retry_delay(attempt));
                            continue;
                        }
                    }
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(AuthorityExecutionError::Store(match retry_reason {
                        Some(_) => ApiError::unavailable(format!(
                            "runtime authority transaction did not commit after \
                             {AUTHORITY_TRANSACTION_ATTEMPTS} attempts"
                        )),
                        None if matches!(
                            error.code(),
                            Some(&SqlState::QUERY_CANCELED) | Some(&SqlState::LOCK_NOT_AVAILABLE)
                        ) =>
                        {
                            ApiError::unavailable(
                                "runtime authority PostgreSQL statement or lock deadline elapsed",
                            )
                        }
                        None => internal(format!(
                            "runtime authority PostgreSQL COMMIT failed: {error}"
                        )),
                    }));
                }
            }
        }
        unreachable!("the bounded authority transaction loop always returns")
    }
}

fn authority_retry_is_definite(error: &postgres::Error) -> bool {
    matches!(
        error.code(),
        Some(&SqlState::T_R_SERIALIZATION_FAILURE | &SqlState::T_R_DEADLOCK_DETECTED)
    )
}

fn authority_rejection(error: AuthorityError) -> ApiError {
    let message = format!("volume authority rejected the transition: {error}");
    match error {
        AuthorityError::NotFound => ApiError::not_found("volume"),
        AuthorityError::OtherWriter
        | AuthorityError::StaleTransition
        | AuthorityError::HeadConflict
        | AuthorityError::SnapshotInUse => ApiError::conflict(message),
        AuthorityError::Fenced => ApiError::new(ErrorCode::StaleEpoch, message),
        AuthorityError::InvalidLeaseDuration => ApiError::invalid(message),
        AuthorityError::EpochExhausted
        | AuthorityError::AdminBusy
        | AuthorityError::InvalidAuthorization => ApiError::failed_precondition(message),
        AuthorityError::BackendUnknown => ApiError::internal(message),
    }
}

fn authority_retry_reason(error: &postgres::Error) -> Option<metrics::AuthorityRetryReason> {
    if error.is_closed() {
        return Some(metrics::AuthorityRetryReason::Connection);
    }
    match error.code() {
        Some(code) if code == &SqlState::T_R_SERIALIZATION_FAILURE => {
            return Some(metrics::AuthorityRetryReason::Serialization);
        }
        Some(code) if code == &SqlState::T_R_DEADLOCK_DETECTED => {
            return Some(metrics::AuthorityRetryReason::Deadlock);
        }
        Some(code) if code.code().starts_with("08") => {
            return Some(metrics::AuthorityRetryReason::Connection);
        }
        Some(
            &SqlState::ADMIN_SHUTDOWN | &SqlState::CRASH_SHUTDOWN | &SqlState::CANNOT_CONNECT_NOW,
        ) => {
            return Some(metrics::AuthorityRetryReason::Connection);
        }
        _ => {}
    }

    let mut source = error.source();
    while let Some(current) = source {
        if current
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| is_transient_connection_kind(io.kind()))
        {
            return Some(metrics::AuthorityRetryReason::Connection);
        }
        source = current.source();
    }
    None
}

fn request_timeout(error: &postgres::Error) -> bool {
    matches!(
        error.code(),
        Some(&SqlState::QUERY_CANCELED) | Some(&SqlState::LOCK_NOT_AVAILABLE)
    )
}

fn is_transient_connection_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
    )
}

fn retry_delay(attempt: usize) -> Duration {
    let jitter = RETRY_JITTER_SEQUENCE.fetch_add(1, Ordering::Relaxed) % 5;
    let base = u64::try_from(attempt + 1).unwrap_or(1) * 3;
    Duration::from_millis(base + jitter)
}

#[cfg(test)]
pub(super) const fn authority_transaction_attempts() -> usize {
    AUTHORITY_TRANSACTION_ATTEMPTS
}

#[cfg(test)]
mod request_context_tests {
    use super::*;

    #[test]
    fn commit_attempt_stays_visible_to_a_racing_http_deadline() {
        let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(1));
        assert!(!context.commit_was_attempted());
        context.begin_commit();
        assert!(context.commit_was_attempted());
    }

    #[test]
    fn definite_commit_failure_resets_only_the_failed_attempt() {
        let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(1));
        context.begin_commit();
        context.reset_after_definite_commit_failure();
        assert!(!context.commit_was_attempted());
        context.begin_commit();
        assert!(context.commit_was_attempted());
    }
}

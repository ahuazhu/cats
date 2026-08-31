//! One bounded PostgreSQL transaction boundary for runtime authority changes.

use std::error::Error as _;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
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
/// A queued worker observes it before opening a transaction. Immediately before
/// calling PostgreSQL COMMIT, the worker atomically claims irreversible send
/// ownership. Cancellation wins by changing `Open` to `Cancelled` before that
/// claim; afterward it remains sticky without revoking the commit owner, and
/// the domain's exact replay key resolves any ambiguous response.
#[derive(Clone)]
pub(crate) struct AuthorityRequestContext {
    deadline: Instant,
    phase: Arc<AtomicU8>,
    #[cfg(test)]
    before_commit_claim: Arc<std::sync::Mutex<Option<CommitClaimBarrier>>>,
    #[cfg(test)]
    after_commit_claim: Arc<std::sync::Mutex<Option<CommitClaimBarrier>>>,
    #[cfg(test)]
    before_definite_commit_reset: Arc<std::sync::Mutex<Option<CommitClaimBarrier>>>,
}

#[cfg(test)]
#[derive(Clone)]
struct CommitClaimBarrier {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum AuthorityRequestPhase {
    Open = 0,
    Cancelled = 1,
    CommitOwned = 2,
    CommitOwnedCancelled = 3,
}

impl AuthorityRequestPhase {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Open,
            1 => Self::Cancelled,
            2 => Self::CommitOwned,
            3 => Self::CommitOwnedCancelled,
            _ => {
                unreachable!("authority request phase is written only by the closed state machine")
            }
        }
    }

    const fn raw(self) -> u8 {
        self as u8
    }

    const fn is_commit_owned(self) -> bool {
        matches!(self, Self::CommitOwned | Self::CommitOwnedCancelled)
    }
}

trait AuthorityPhaseAtomic {
    fn load_phase(&self, order: Ordering) -> u8;

    fn compare_exchange_phase(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> std::result::Result<u8, u8>;
}

impl AuthorityPhaseAtomic for AtomicU8 {
    fn load_phase(&self, order: Ordering) -> u8 {
        self.load(order)
    }

    fn compare_exchange_phase(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> std::result::Result<u8, u8> {
        self.compare_exchange(current, new, success, failure)
    }
}

#[cfg(test)]
impl AuthorityPhaseAtomic for loom::sync::atomic::AtomicU8 {
    fn load_phase(&self, order: Ordering) -> u8 {
        self.load(order)
    }

    fn compare_exchange_phase(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> std::result::Result<u8, u8> {
        self.compare_exchange(current, new, success, failure)
    }
}

fn request_cancel<A: AuthorityPhaseAtomic>(phase: &A) {
    let mut current = AuthorityRequestPhase::from_raw(phase.load_phase(Ordering::Acquire));
    loop {
        let next = match current {
            AuthorityRequestPhase::Open => AuthorityRequestPhase::Cancelled,
            AuthorityRequestPhase::CommitOwned => AuthorityRequestPhase::CommitOwnedCancelled,
            AuthorityRequestPhase::Cancelled | AuthorityRequestPhase::CommitOwnedCancelled => {
                return;
            }
        };
        match phase.compare_exchange_phase(
            current.raw(),
            next.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = AuthorityRequestPhase::from_raw(observed),
        }
    }
}

fn try_claim_commit<A: AuthorityPhaseAtomic>(phase: &A) -> bool {
    phase
        .compare_exchange_phase(
            AuthorityRequestPhase::Open.raw(),
            AuthorityRequestPhase::CommitOwned.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

fn reset_definite_commit<A: AuthorityPhaseAtomic>(phase: &A) -> bool {
    let mut current = AuthorityRequestPhase::from_raw(phase.load_phase(Ordering::Acquire));
    loop {
        let next = match current {
            AuthorityRequestPhase::CommitOwned => AuthorityRequestPhase::Open,
            AuthorityRequestPhase::CommitOwnedCancelled => AuthorityRequestPhase::Cancelled,
            AuthorityRequestPhase::Open | AuthorityRequestPhase::Cancelled => return false,
        };
        match phase.compare_exchange_phase(
            current.raw(),
            next.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = AuthorityRequestPhase::from_raw(observed),
        }
    }
}

fn load_request_phase<A: AuthorityPhaseAtomic>(phase: &A) -> AuthorityRequestPhase {
    AuthorityRequestPhase::from_raw(phase.load_phase(Ordering::Acquire))
}

impl AuthorityRequestContext {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            phase: Arc::new(AtomicU8::new(AuthorityRequestPhase::Open.raw())),
            #[cfg(test)]
            before_commit_claim: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            after_commit_claim: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            before_definite_commit_reset: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub(crate) fn cancel(&self) {
        request_cancel(self.phase.as_ref());
    }

    fn must_rollback(&self) -> bool {
        if Instant::now() >= self.deadline {
            self.cancel();
        }
        load_request_phase(self.phase.as_ref()) == AuthorityRequestPhase::Cancelled
    }

    fn remaining_timeout_millis(&self) -> Option<u64> {
        if self.must_rollback() {
            return None;
        }
        let remaining = self.deadline.checked_duration_since(Instant::now())?;
        let millis = remaining.as_millis().min(i32::MAX as u128) as u64;
        (millis > 0).then_some(millis)
    }

    /// Cancellation checkpoint for a bounded multi-page PostgreSQL request.
    ///
    /// Each page shortens both transaction-local timeouts to the request's
    /// current remaining budget. This prevents a page submitted late in the
    /// request from inheriting the larger timeout installed at `BEGIN`, and a
    /// dropped HTTP request is observed before the next page is issued.
    pub(super) fn refresh_transaction_deadline(
        &self,
        transaction: &mut postgres::Transaction<'_>,
    ) -> AuthorityTxResult<()> {
        let Some(timeout_ms) = self.remaining_timeout_millis() else {
            return Err(AuthorityTransactionError::Application(
                ApiError::unavailable(
                    "runtime authority request was cancelled or exceeded its deadline",
                ),
            ));
        };
        let lock_timeout_ms = timeout_ms.min(2_000);
        transaction
            .batch_execute(&format!(
                "SET LOCAL statement_timeout = '{timeout_ms}ms'; \
                 SET LOCAL lock_timeout = '{lock_timeout_ms}ms'"
            ))
            .map_err(AuthorityTransactionError::Postgres)
    }

    /// Atomically choose the pre-COMMIT winner. `Open -> CommitOwned` is the
    /// irreversible send-owner linearization point. Any later cancellation is
    /// sticky but cannot make this worker roll back instead of calling COMMIT.
    fn try_begin_commit(&self) -> bool {
        if self.must_rollback() {
            return false;
        }
        #[cfg(test)]
        self.wait_at_commit_barrier(&self.before_commit_claim);
        if Instant::now() >= self.deadline {
            self.cancel();
        }
        if !try_claim_commit(self.phase.as_ref()) {
            return false;
        }
        #[cfg(test)]
        self.wait_at_commit_barrier(&self.after_commit_claim);
        true
    }

    /// A serialization or deadlock error returned by PostgreSQL from COMMIT
    /// proves that attempt did not commit. Clear the per-attempt phase before
    /// the closed transaction is replayed so an exhausted definite retry is
    /// not mislabeled as an unknown commit result by the HTTP owner.
    fn reset_after_definite_commit_failure(&self) {
        #[cfg(test)]
        self.wait_at_commit_barrier(&self.before_definite_commit_reset);
        let reset = reset_definite_commit(self.phase.as_ref());
        debug_assert!(reset, "only a claimed COMMIT attempt can reset");
        if Instant::now() >= self.deadline {
            self.cancel();
        }
    }

    /// True after COMMIT may have reached PostgreSQL. Even when the blocking
    /// worker already knows it committed, a concurrent HTTP deadline can fire
    /// before that result crosses the executor channel; such a response must
    /// still close and let exact replay resolve what the client observed.
    pub(crate) fn commit_was_attempted(&self) -> bool {
        load_request_phase(self.phase.as_ref()).is_commit_owned()
    }

    #[cfg(test)]
    fn wait_at_commit_barrier(&self, barrier: &std::sync::Mutex<Option<CommitClaimBarrier>>) {
        let barrier = barrier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(barrier) = barrier {
            barrier.entered.wait();
            barrier.release.wait();
        }
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

#[derive(Debug)]
pub(super) enum AuthorityTransactionError {
    Domain(AuthorityError),
    Application(ApiError),
    Postgres(postgres::Error),
}

pub(super) enum AuthorityExecutionError {
    Store(ApiError),
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
    Postgres(postgres::Error),
    Commit(postgres::Error),
    Rollback(postgres::Error),
    Infrastructure(ApiError),
}

#[derive(Clone, Copy)]
enum AuthorityTransactionMode {
    ReadWrite,
    RepeatableRead,
    RepeatableReadOnly,
}

impl Store {
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
        }
    }

    /// Runs a complete authority facts loader in one PostgreSQL snapshot.
    /// Consumers must receive either the complete mutually-consistent fact set
    /// or no fact set at all, so this deliberately shares the retry and
    /// fail-closed error policy of mutation transactions.
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
        }
    }

    /// Deadline-bound A22 logical read. The value is returned through the
    /// explicit rollback disposition so the transaction never enters the
    /// mutation commit/ambiguity phase, while PostgreSQL statement and lock
    /// timeouts still follow the request's one absolute deadline.
    pub(super) fn authority_request_locking_read_snapshot<T: Send>(
        &self,
        request: &AuthorityRequestContext,
        mut operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
    ) -> Result<T> {
        match self.authority_transaction_outcome_with_hook(
            move |transaction| operation(transaction).map(AuthorityRequestDisposition::Reject),
            AuthorityTransactionMode::RepeatableRead,
            Some(request),
            || {},
        ) {
            Ok(value) => Ok(value),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
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
            let outcome = self.enter_with_retirement(|client| {
                let client = match client {
                    Ok(client) => client,
                    Err(error) => return (Err(AttemptFailure::Infrastructure(error)), false),
                };
                (
                    run_authority_transaction_attempt(client, &mut operation, mode, request, self),
                    false,
                )
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

fn run_authority_transaction_attempt<T: Send>(
    client: &mut postgres::Client,
    operation: &mut impl FnMut(
        &mut postgres::Transaction<'_>,
    ) -> AuthorityTxResult<AuthorityRequestDisposition<T>>,
    mode: AuthorityTransactionMode,
    request: Option<&AuthorityRequestContext>,
    store: &Store,
) -> std::result::Result<AuthorityRequestDisposition<T>, AttemptFailure> {
    #[cfg(not(test))]
    let _ = store;
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
        if let Err(error) = request.refresh_transaction_deadline(&mut transaction) {
            let error = match error {
                AuthorityTransactionError::Application(error) => {
                    transaction.rollback().map_err(AttemptFailure::Rollback)?;
                    return Err(AttemptFailure::Application(error));
                }
                AuthorityTransactionError::Postgres(error) => error,
                AuthorityTransactionError::Domain(_) => {
                    unreachable!("request deadline refresh has only application/PostgreSQL errors")
                }
            };
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
        Ok(AuthorityRequestDisposition::Commit(value)) => {
            if request.is_some_and(|request| !request.try_begin_commit()) {
                transaction.rollback().map_err(AttemptFailure::Rollback)?;
                return Err(AttemptFailure::Application(ApiError::unavailable(
                    "runtime authority request was cancelled or exceeded its deadline",
                )));
            }
            match transaction.commit() {
                Ok(()) => {
                    #[cfg(test)]
                    {
                        let inject_response_loss = store
                            .commit_response_loss_once
                            .swap(false, Ordering::AcqRel)
                            || (request.is_some()
                                && store
                                    .request_commit_response_loss_once
                                    .swap(false, Ordering::AcqRel));
                        if inject_response_loss {
                            let delay_ms = store
                                .commit_response_loss_delay_ms
                                .swap(0, Ordering::AcqRel);
                            if delay_ms != 0 {
                                std::thread::sleep(Duration::from_millis(delay_ms));
                            }
                            return Err(AttemptFailure::Infrastructure(ApiError::unavailable(
                                "injected loss of a successful PostgreSQL commit response",
                            )));
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
}

fn authority_retry_is_definite(error: &postgres::Error) -> bool {
    matches!(
        error.code(),
        Some(&SqlState::T_R_SERIALIZATION_FAILURE | &SqlState::T_R_DEADLOCK_DETECTED)
    )
}

pub(super) fn authority_rejection(error: AuthorityError) -> ApiError {
    let message = format!("volume authority rejected the transition: {error}");
    match error {
        AuthorityError::NotFound => ApiError::not_found("volume"),
        AuthorityError::OtherWriter
        | AuthorityError::StaleTransition
        | AuthorityError::HeadConflict => ApiError::conflict(message),
        AuthorityError::Fenced => ApiError::new(ErrorCode::StaleEpoch, message),
        AuthorityError::InvalidLeaseDuration | AuthorityError::InvalidDurability => {
            ApiError::invalid(message)
        }
        AuthorityError::EpochExhausted
        | AuthorityError::GenerationExhausted
        | AuthorityError::AdminBusy => ApiError::failed_precondition(message),
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
mod request_context_tests {
    use super::*;

    #[test]
    fn commit_attempt_stays_visible_to_a_racing_http_deadline() {
        let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(1));
        assert!(!context.commit_was_attempted());
        assert!(context.try_begin_commit());
        context.cancel();
        assert!(context.commit_was_attempted());
    }

    #[test]
    fn definite_commit_failure_resets_only_the_failed_attempt() {
        let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(1));
        assert!(context.try_begin_commit());
        context.reset_after_definite_commit_failure();
        assert!(!context.commit_was_attempted());
        assert!(context.try_begin_commit());
        assert!(context.commit_was_attempted());
    }

    #[test]
    fn definite_commit_failure_does_not_erase_a_racing_cancellation() {
        let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(1));
        assert!(context.try_begin_commit());
        context.cancel();
        assert!(context.commit_was_attempted());
        context.reset_after_definite_commit_failure();
        assert!(!context.commit_was_attempted());
        assert!(context.must_rollback());
        assert!(!context.try_begin_commit());
    }

    #[test]
    fn loom_cancel_and_commit_claim_have_exactly_one_winner() {
        loom::model(|| {
            let phase = loom::sync::Arc::new(loom::sync::atomic::AtomicU8::new(
                AuthorityRequestPhase::Open.raw(),
            ));
            let cancel_phase = loom::sync::Arc::clone(&phase);
            let cancel = loom::thread::spawn(move || request_cancel(cancel_phase.as_ref()));
            let claim_phase = loom::sync::Arc::clone(&phase);
            let claim = loom::thread::spawn(move || try_claim_commit(claim_phase.as_ref()));

            let claimed = claim.join().unwrap();
            cancel.join().unwrap();
            let final_phase = load_request_phase(phase.as_ref());
            if claimed {
                assert_eq!(final_phase, AuthorityRequestPhase::CommitOwnedCancelled);
            } else {
                assert_eq!(final_phase, AuthorityRequestPhase::Cancelled);
            }
        });
    }

    #[test]
    fn loom_definite_reset_cannot_lose_a_racing_cancellation() {
        loom::model(|| {
            let phase = loom::sync::Arc::new(loom::sync::atomic::AtomicU8::new(
                AuthorityRequestPhase::CommitOwned.raw(),
            ));
            let cancel_phase = loom::sync::Arc::clone(&phase);
            let cancel = loom::thread::spawn(move || request_cancel(cancel_phase.as_ref()));
            let reset_phase = loom::sync::Arc::clone(&phase);
            let reset = loom::thread::spawn(move || reset_definite_commit(reset_phase.as_ref()));

            cancel.join().unwrap();
            assert!(reset.join().unwrap());
            assert_eq!(
                load_request_phase(phase.as_ref()),
                AuthorityRequestPhase::Cancelled
            );
        });
    }
}

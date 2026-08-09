//! One bounded PostgreSQL transaction boundary for runtime authority changes.

use std::error::Error as _;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cats_api::error::{ApiError, ErrorCode};
use cats_storage::authority::AuthorityError;
use postgres::error::SqlState;

use super::*;

const AUTHORITY_TRANSACTION_ATTEMPTS: usize = 3;
static RETRY_JITTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) type AuthorityTxResult<T> = std::result::Result<T, AuthorityTransactionError>;

pub(super) enum AuthorityTransactionError {
    Domain(AuthorityError),
    Postgres(postgres::Error),
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

enum AttemptFailure {
    Domain(AuthorityError),
    Postgres(postgres::Error),
    Rollback(postgres::Error),
    Infrastructure(ApiError),
}

impl Store {
    /// Runs one complete authority closure in one fresh PostgreSQL
    /// transaction. Retriable database failures replay the whole closure;
    /// domain conflicts are rolled back and returned exactly once.
    pub(super) fn authority_transaction<T: Send>(
        &self,
        mut operation: impl FnMut(&mut postgres::Transaction<'_>) -> AuthorityTxResult<T> + Send,
    ) -> Result<T> {
        for attempt in 0..AUTHORITY_TRANSACTION_ATTEMPTS {
            let outcome = self.enter(|client| {
                let client = client.map_err(AttemptFailure::Infrastructure)?;
                let mut transaction = client.transaction().map_err(AttemptFailure::Postgres)?;
                match operation(&mut transaction) {
                    Ok(value) => transaction
                        .commit()
                        .map(|()| value)
                        .map_err(AttemptFailure::Postgres),
                    Err(AuthorityTransactionError::Domain(error)) => {
                        // A domain rejection is never replayed. If its explicit
                        // rollback fails, the transaction outcome is unknown
                        // and must fail closed instead of being mislabeled as
                        // a retriable serialization/connection error.
                        transaction.rollback().map_err(AttemptFailure::Rollback)?;
                        Err(AttemptFailure::Domain(error))
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
                Ok(value) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::Committed);
                    return Ok(value);
                }
                Err(AttemptFailure::Domain(error)) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::DomainRejected);
                    return Err(authority_rejection(error));
                }
                Err(AttemptFailure::Infrastructure(error)) => {
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(error);
                }
                Err(AttemptFailure::Rollback(error)) => {
                    metrics::record_postgres_error(&error);
                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(internal(format!(
                        "volume authority PostgreSQL rollback failed: {error}"
                    )));
                }
                Err(AttemptFailure::Postgres(error)) => {
                    metrics::record_postgres_error(&error);
                    let retry_reason = authority_retry_reason(&error);
                    if attempt + 1 < AUTHORITY_TRANSACTION_ATTEMPTS {
                        if let Some(reason) = retry_reason {
                            metrics::record_authority_retry(reason);
                            std::thread::sleep(retry_delay(attempt));
                            continue;
                        }
                    }

                    metrics::record_authority_outcome(metrics::AuthorityOutcome::BackendFailed);
                    return Err(match retry_reason {
                        Some(_) => ApiError::unavailable(format!(
                            "volume authority transaction did not commit after {AUTHORITY_TRANSACTION_ATTEMPTS} attempts"
                        )),
                        None => internal(format!(
                            "volume authority PostgreSQL transaction failed: {error}"
                        )),
                    });
                }
            }
        }
        unreachable!("the bounded authority transaction loop always returns")
    }
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

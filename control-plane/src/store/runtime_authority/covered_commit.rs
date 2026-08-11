//! Shared request/commit ownership for covered Workspace product mutations.
//!
//! A request may be cancelled only before PostgreSQL commit is sent. Once the
//! commit boundary is crossed, a registered owner must retain the blocking
//! Store job and resolve the exact durable `ApiIdempotencyResult`, even when
//! the HTTP handler or process shutdown path has stopped waiting for it.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_api::error::ApiError;
use postgres::Transaction;

use crate::store::transaction::AuthorityTxResult;

const PRE_COMMIT: u8 = 0;
const COMMIT_SENT: u8 = 1;
const CANCELLED: u8 = 2;

struct CommitShared {
    phase: AtomicU8,
    cancel_requested: AtomicBool,
    cancelled: tokio::sync::Notify,
    operation_name: &'static str,
}

impl CommitShared {
    fn mark_cancelled(&self) {
        let _ =
            self.phase
                .compare_exchange(PRE_COMMIT, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
        if self.phase.load(Ordering::Acquire) == CANCELLED {
            self.cancelled.notify_waiters();
        }
    }

    fn unavailable(&self, suffix: &str) -> ApiError {
        ApiError::unavailable(format!("{} {suffix}", self.operation_name))
    }
}

/// Request-lifetime half of a covered mutation's commit boundary.
///
/// Dropping it cancels only work that has not crossed into PostgreSQL commit.
/// After that point the registered owner is responsible for exact resolution.
pub(super) struct CoveredCommitCancellation(Arc<CommitShared>);

#[derive(Clone)]
pub(super) struct CoveredCommitState {
    shared: Arc<CommitShared>,
    absolute_deadline: Instant,
}

impl CoveredCommitCancellation {
    pub(super) fn new(
        operation_name: &'static str,
        absolute_deadline: Instant,
    ) -> (Self, CoveredCommitState) {
        let shared = Arc::new(CommitShared {
            phase: AtomicU8::new(PRE_COMMIT),
            cancel_requested: AtomicBool::new(false),
            cancelled: tokio::sync::Notify::new(),
            operation_name,
        });
        (
            Self(Arc::clone(&shared)),
            CoveredCommitState {
                shared,
                absolute_deadline,
            },
        )
    }

    /// Atomically cancel only work that has not crossed commit-send.
    /// `false` means the registered owner must resolve the durable outcome.
    pub(super) fn cancel_before_commit(&self) -> bool {
        self.0.cancel_requested.store(true, Ordering::Release);
        self.0.mark_cancelled();
        match self.0.phase.load(Ordering::Acquire) {
            CANCELLED => true,
            COMMIT_SENT => false,
            _ => true,
        }
    }
}

impl Drop for CoveredCommitCancellation {
    fn drop(&mut self) {
        self.0.cancel_requested.store(true, Ordering::Release);
        self.0.mark_cancelled();
    }
}

impl CoveredCommitState {
    pub(super) fn commit_was_sent(&self) -> bool {
        self.shared.phase.load(Ordering::Acquire) == COMMIT_SENT
    }

    pub(super) async fn cancelled_before_commit(&self) {
        loop {
            let cancelled = self.shared.cancelled.notified();
            if self.shared.phase.load(Ordering::Acquire) == CANCELLED {
                return;
            }
            cancelled.await;
        }
    }

    pub(in crate::store) fn checkpoint(
        &self,
        transaction: &mut Transaction<'_>,
    ) -> AuthorityTxResult<()> {
        if self.shared.cancel_requested.load(Ordering::Acquire) {
            self.shared.mark_cancelled();
        }
        match self.shared.phase.load(Ordering::Acquire) {
            CANCELLED => {
                return Err(self
                    .shared
                    .unavailable("was cancelled before PostgreSQL commit")
                    .into());
            }
            COMMIT_SENT => return Ok(()),
            PRE_COMMIT => {}
            _ => return Err(ApiError::internal("invalid covered commit state").into()),
        }
        let Some(remaining) = self
            .absolute_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
        else {
            self.shared.mark_cancelled();
            return Err(self.shared.unavailable("deadline elapsed").into());
        };
        let statement_ms = remaining.as_millis().clamp(1, 5_000);
        let lock_ms = remaining.as_millis().clamp(1, 2_000);
        transaction.query_one(
            "SELECT set_config('statement_timeout', $1, true),
                    set_config('lock_timeout', $2, true)",
            &[&format!("{statement_ms}ms"), &format!("{lock_ms}ms")],
        )?;
        Ok(())
    }

    pub(in crate::store) fn begin_commit(
        &self,
        transaction: &mut Transaction<'_>,
    ) -> AuthorityTxResult<()> {
        self.checkpoint(transaction)?;
        match self.shared.phase.compare_exchange(
            PRE_COMMIT,
            COMMIT_SENT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // `checkpoint` performs SQL and its response can cross the
                // wall-clock deadline. This CAS remains provisional until the
                // post-CAS clock/cancellation check succeeds; PostgreSQL has
                // not received COMMIT yet.
                if self.shared.cancel_requested.load(Ordering::Acquire)
                    || Instant::now() >= self.absolute_deadline
                {
                    if self
                        .shared
                        .phase
                        .compare_exchange(
                            COMMIT_SENT,
                            CANCELLED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.shared.cancelled.notify_waiters();
                    }
                    return Err(self
                        .shared
                        .unavailable("deadline elapsed before PostgreSQL commit")
                        .into());
                }
                Ok(())
            }
            Err(COMMIT_SENT) => Ok(()),
            Err(CANCELLED) => Err(self
                .shared
                .unavailable("was cancelled before PostgreSQL commit")
                .into()),
            Err(_) => Err(ApiError::internal("invalid covered commit state").into()),
        }
    }

    pub(super) fn reset_after_definite_retry(&self) {
        let _ = self.shared.phase.compare_exchange(
            COMMIT_SENT,
            PRE_COMMIT,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if self.shared.cancel_requested.load(Ordering::Acquire)
            || Instant::now() >= self.absolute_deadline
        {
            self.shared.mark_cancelled();
        }
    }
}

#[derive(Default)]
pub(super) struct CommitResolutionRegistry {
    active: AtomicUsize,
    changed: tokio::sync::Notify,
}

pub(super) struct ActiveCommitResolution(Arc<CommitResolutionRegistry>);

impl CommitResolutionRegistry {
    pub(super) fn begin(self: &Arc<Self>) -> ActiveCommitResolution {
        self.active.fetch_add(1, Ordering::AcqRel);
        ActiveCommitResolution(Arc::clone(self))
    }

    pub(super) async fn wait_empty(&self) {
        loop {
            let changed = self.changed.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }

    pub(super) fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

impl Drop for ActiveCommitResolution {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

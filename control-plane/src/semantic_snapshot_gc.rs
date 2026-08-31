//! Control-owned orchestration for offline, snapshot-aware volume GC.
//!
//! The PostgreSQL claim is committed before this module calls a BlobStore
//! walker. Object I/O is deliberately synchronous behind `spawn_blocking`;
//! neither PostgreSQL transactions nor Tokio request workers are held for a
//! potentially long mark-and-sweep pass.

use std::sync::Arc;
use std::time::Duration;

use crate::store::runtime_authority::snapshot_gc::{
    SnapshotGcClaim, SnapshotGcRoot, SnapshotGcSettlement,
};
use crate::store::Store;

/// Result of the provider-neutral graph validation and selective sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SnapshotGcSweepStats {
    pub(crate) live_data_objects: usize,
    pub(crate) deleted_data_objects: usize,
    pub(crate) live_map_objects: usize,
    pub(crate) deleted_map_objects: usize,
}

/// Blocking storage operation used only after Control commits a GC claim.
///
/// Implementations must fully trace and validate every root before the first
/// DELETE, use bounded cursor LIST for both private volume prefixes, and verify
/// that every object remaining after the sweep belongs to the marked union.
pub(crate) trait SnapshotGcSweeper: Send + Sync + 'static {
    fn sweep(
        &self,
        volume_id: &cats_api::runtime_reconciliation::Id,
        roots: &[SnapshotGcRoot],
    ) -> std::result::Result<SnapshotGcSweepStats, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotGcPass {
    Idle,
    Completed {
        claim: SnapshotGcClaim,
        stats: SnapshotGcSweepStats,
    },
    Failed {
        claim: SnapshotGcClaim,
        error: String,
    },
    Stale {
        claim: SnapshotGcClaim,
    },
}

#[derive(Clone)]
pub(crate) struct SnapshotGcService {
    store: Arc<Store>,
    sweeper: Arc<dyn SnapshotGcSweeper>,
}

impl SnapshotGcService {
    pub(crate) fn new(store: Arc<Store>, sweeper: Arc<dyn SnapshotGcSweeper>) -> Self {
        Self { store, sweeper }
    }

    /// Execute at most one claim. Callers use this bounded unit in tests and
    /// the production level-triggered loop.
    pub(crate) async fn run_one(&self) -> crate::store::Result<SnapshotGcPass> {
        let claim = self
            .store
            .execute(|store| store.claim_next_snapshot_gc())
            .await?;
        let Some(claim) = claim else {
            return Ok(SnapshotGcPass::Idle);
        };

        let sweep_claim = claim.clone();
        let sweeper = Arc::clone(&self.sweeper);
        let sweep = tokio::task::spawn_blocking(move || {
            sweeper.sweep(&sweep_claim.volume_id, &sweep_claim.roots)
        })
        .await;

        match sweep {
            Ok(Ok(stats)) => {
                let completion = claim.clone();
                match self
                    .store
                    .execute(move |store| store.complete_snapshot_gc(&completion))
                    .await?
                {
                    SnapshotGcSettlement::Settled => Ok(SnapshotGcPass::Completed { claim, stats }),
                    SnapshotGcSettlement::Stale => Ok(SnapshotGcPass::Stale { claim }),
                }
            }
            Ok(Err(error)) => self.abort_failed_claim(claim, error).await,
            Err(error) => {
                self.abort_failed_claim(claim, format!("snapshot GC worker failed: {error}"))
                    .await
            }
        }
    }

    async fn abort_failed_claim(
        &self,
        claim: SnapshotGcClaim,
        error: String,
    ) -> crate::store::Result<SnapshotGcPass> {
        let abort = claim.clone();
        match self
            .store
            .execute(move |store| store.abort_snapshot_gc(&abort))
            .await?
        {
            SnapshotGcSettlement::Settled => Ok(SnapshotGcPass::Failed { claim, error }),
            SnapshotGcSettlement::Stale => Ok(SnapshotGcPass::Stale { claim }),
        }
    }

    /// Level-triggered production loop. Crash/cancellation while the blocking
    /// sweep is in flight leaves the durable `garbage_collecting` claim; the
    /// next elected Control resumes the same `gc_id` from the beginning.
    pub(crate) async fn run(&self, cadence: Duration) {
        let cadence = if cadence.is_zero() {
            Duration::from_millis(1)
        } else {
            cadence
        };
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match self.run_one().await {
                Ok(SnapshotGcPass::Idle) => {}
                Ok(SnapshotGcPass::Completed { claim, stats }) => tracing::info!(
                    volume_id = %claim.volume_id,
                    gc_id = %claim.gc_id,
                    live_data_objects = stats.live_data_objects,
                    deleted_data_objects = stats.deleted_data_objects,
                    live_map_objects = stats.live_map_objects,
                    deleted_map_objects = stats.deleted_map_objects,
                    "snapshot-aware volume GC completed"
                ),
                Ok(SnapshotGcPass::Failed { claim, error }) => tracing::warn!(
                    volume_id = %claim.volume_id,
                    gc_id = %claim.gc_id,
                    %error,
                    "snapshot-aware volume GC failed; claim was aborted for retry"
                ),
                Ok(SnapshotGcPass::Stale { claim }) => tracing::warn!(
                    volume_id = %claim.volume_id,
                    gc_id = %claim.gc_id,
                    "snapshot-aware volume GC result did not match its current authority claim"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    "snapshot-aware volume GC authority pass failed"
                ),
            }
        }
    }
}

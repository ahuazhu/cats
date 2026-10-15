//! Control-owned orchestration for offline, snapshot-aware volume GC.
//!
//! The PostgreSQL claim is committed before this module calls a BlobStore
//! walker. Object I/O is deliberately synchronous behind `spawn_blocking`;
//! neither PostgreSQL transactions nor Tokio request workers are held for a
//! potentially long mark-and-sweep pass.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_blockd::gc::{
    collect_garbage_with_cancellation, GarbageCollectionClaim, GcError, RetainedRoot,
    RetainedRootSource,
};
use cats_storage::{BlobStore, BLOB_LIST_PAGE_MAX_KEYS};

use crate::store::runtime_authority::snapshot_gc::{SnapshotGcClaim, SnapshotGcSettlement};
use crate::store::Store;

/// Result of the provider-neutral graph validation and selective sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SnapshotGcSweepStats {
    pub(crate) live_data_objects: usize,
    pub(crate) deleted_data_objects: usize,
    pub(crate) live_map_objects: usize,
    pub(crate) deleted_map_objects: usize,
}

/// Process-local stop signal for one elected GC pass.
///
/// The durable PostgreSQL claim remains the writer exclusion authority. This
/// signal only makes the transaction-external object walk stop before another
/// DELETE when the Control instance loses singleton leadership.
#[derive(Clone, Default)]
pub(crate) struct SnapshotGcCancellation(Arc<AtomicBool>);

impl SnapshotGcCancellation {
    fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotGcSweepError {
    Cancelled,
    Failed(String),
}

/// Blocking storage operation used only after Control commits a GC claim.
///
/// Implementations must fully trace and validate every root before the first
/// DELETE, use bounded cursor LIST for both private volume prefixes, and verify
/// that every object remaining after the sweep belongs to the marked union.
pub(crate) trait SnapshotGcSweeper: Send + Sync + 'static {
    fn sweep(
        &self,
        claim: &SnapshotGcClaim,
        cancellation: &SnapshotGcCancellation,
        deadline: Instant,
    ) -> std::result::Result<SnapshotGcSweepStats, SnapshotGcSweepError>;
}

pub(crate) struct ChunkStoreSnapshotGcSweeper {
    blob: Arc<dyn BlobStore>,
}

impl ChunkStoreSnapshotGcSweeper {
    pub(crate) fn new(blob: Arc<dyn BlobStore>) -> Self {
        Self { blob }
    }
}

impl SnapshotGcSweeper for ChunkStoreSnapshotGcSweeper {
    fn sweep(
        &self,
        claim: &SnapshotGcClaim,
        cancellation: &SnapshotGcCancellation,
        deadline: Instant,
    ) -> std::result::Result<SnapshotGcSweepStats, SnapshotGcSweepError> {
        let size_bytes = claim
            .roots
            .first()
            .map(|root| root.size_bytes)
            .ok_or_else(|| {
                SnapshotGcSweepError::Failed(
                    "snapshot GC claim omitted its current root".to_owned(),
                )
            })?;
        let roots = claim
            .roots
            .iter()
            .map(|root| RetainedRoot {
                source: match &root.snapshot_id {
                    Some(snapshot_id) => RetainedRootSource::Snapshot {
                        snapshot_id: snapshot_id.clone(),
                    },
                    None => RetainedRootSource::Current,
                },
                head: root.head.clone(),
            })
            .collect();
        let data_claim = GarbageCollectionClaim::new(
            claim.gc_id.clone(),
            claim.volume_id.clone(),
            size_bytes,
            roots,
        )
        .map_err(|error| SnapshotGcSweepError::Failed(error.to_string()))?;
        let stats = collect_garbage_with_cancellation(
            self.blob.as_ref(),
            &data_claim,
            BLOB_LIST_PAGE_MAX_KEYS,
            deadline,
            || cancellation.is_cancelled(),
        )
        .map_err(|error| match error {
            GcError::Cancelled => SnapshotGcSweepError::Cancelled,
            error => SnapshotGcSweepError::Failed(error.to_string()),
        })?;
        Ok(SnapshotGcSweepStats {
            live_data_objects: stats.data_objects_live,
            deleted_data_objects: stats.data_objects_deleted,
            live_map_objects: stats.map_objects_live,
            deleted_map_objects: stats.map_objects_deleted,
        })
    }
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
    Cancelled {
        claim: SnapshotGcClaim,
    },
}

#[derive(Clone)]
pub(crate) struct SnapshotGcService {
    store: Arc<Store>,
    sweeper: Arc<dyn SnapshotGcSweeper>,
    pass_deadline: Duration,
    execution_lease: Duration,
}

impl SnapshotGcService {
    pub(crate) fn new(
        store: Arc<Store>,
        sweeper: Arc<dyn SnapshotGcSweeper>,
        pass_deadline: Duration,
        execution_lease: Duration,
    ) -> Self {
        assert!(
            !pass_deadline.is_zero() && execution_lease > pass_deadline,
            "snapshot GC execution lease must exceed its object-I/O deadline"
        );
        Self {
            store,
            sweeper,
            pass_deadline,
            execution_lease,
        }
    }

    /// Execute at most one claim. Callers use this bounded unit in tests and
    /// the production level-triggered loop.
    pub(crate) async fn run_one(&self) -> crate::store::Result<SnapshotGcPass> {
        self.run_one_with_cancellation(SnapshotGcCancellation::default())
            .await
    }

    async fn run_one_with_cancellation(
        &self,
        cancellation: SnapshotGcCancellation,
    ) -> crate::store::Result<SnapshotGcPass> {
        // Anchor the destructive deadline before asking PostgreSQL for the
        // execution occurrence. A process paused after the transaction commits
        // therefore cannot resume with a fresh local budget after its durable
        // lease has expired.
        let pass_started = Instant::now();
        let execution_lease = self.execution_lease;
        let claim = self
            .store
            .execute(move |store| store.claim_next_snapshot_gc(execution_lease))
            .await?;
        let Some(claim) = claim else {
            return Ok(SnapshotGcPass::Idle);
        };

        if cancellation.is_cancelled() {
            return Ok(SnapshotGcPass::Cancelled { claim });
        }

        let sweep_claim = claim.clone();
        let sweeper = Arc::clone(&self.sweeper);
        let sweep_cancellation = cancellation.clone();
        let deadline = pass_started + self.pass_deadline;
        let sweep = tokio::task::spawn_blocking(move || {
            sweeper.sweep(&sweep_claim, &sweep_cancellation, deadline)
        })
        .await;

        // Cancellation represents singleton leadership loss, not a failed GC
        // pass. Leave the durable claim in maintenance for the next elected
        // Control instead of clearing it from an instance that no longer owns
        // the role.
        if cancellation.is_cancelled() {
            return Ok(SnapshotGcPass::Cancelled { claim });
        }

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
            Ok(Err(SnapshotGcSweepError::Cancelled)) => {
                Ok(SnapshotGcPass::Cancelled { claim })
            }
            Ok(Err(SnapshotGcSweepError::Failed(error))) => {
                self.abort_failed_claim(claim, error).await
            }
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
    pub(crate) async fn run(
        &self,
        cadence: Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let cadence = if cadence.is_zero() {
            Duration::from_millis(1)
        } else {
            cadence
        };
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = wait_for_cancellation(&mut shutdown) => return,
            }
            let cancellation = SnapshotGcCancellation::default();
            let pass = self.run_one_with_cancellation(cancellation.clone());
            tokio::pin!(pass);
            let result = tokio::select! {
                result = &mut pass => result,
                _ = wait_for_cancellation(&mut shutdown) => {
                    cancellation.cancel();
                    // `spawn_blocking` cannot be aborted after it starts. Keep
                    // owning and joining this pass until the cooperative walker
                    // has observed cancellation and exited.
                    (&mut pass).await
                }
            };
            match result {
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
                Ok(SnapshotGcPass::Cancelled { claim }) => {
                    tracing::info!(
                        volume_id = %claim.volume_id,
                        gc_id = %claim.gc_id,
                        "snapshot-aware volume GC stopped after singleton leadership loss"
                    );
                    return;
                }
                Err(error) => tracing::warn!(
                    %error,
                    "snapshot-aware volume GC authority pass failed"
                ),
            }
        }
    }
}

async fn wait_for_cancellation(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

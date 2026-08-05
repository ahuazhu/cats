//! Level-triggered reconciler: converges every cat's observed state to its
//! desired state by dispatching idempotent jobs to node agents, handles node
//! loss detection, explicit Host fencing, and operation completion.
//!
//! Invariants owned here (arch doc §6/§8, ADR-0002/0003):
//! - heartbeat expiry only marks a Host lost and preserves its claims;
//! - a cat moves off a lost Host only after external fencing is explicitly
//!   confirmed and every stale volume lease has been revoked;
//! - Suspended/Warm failures always converge to a clean Cold fallback;
//! - Suspended/Warm on a lost host are discarded and cold-started elsewhere;
//! - route epochs bump on every publish/unbind.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cats_api::error::ErrorBody;
use cats_api::nodejob::{
    self, JobPhase, NodeJob, NodeJobAction, NodeJobResult, StopCatDisposition, VolumeGrant,
};
use cats_api::resources::*;
use cats_storage::{MetaError, MetadataStore};
use futures_util::StreamExt;

use crate::store::{
    now_ms, DiskChangeMode, LegacyLifecycleBegin, LifecycleDispatch, Store, TopologyAction,
    TopologyClaim, VolumeLeaseAuthority,
};

/// How many Cats one reconcile tick drives at once.
///
/// Bounded because each one holds a node-agent request open for the length of a
/// launch; unbounded fan-out would let one tick open a request per Cat in the
/// fleet. The node agent has its own launch ceiling underneath this.
const MAX_CONCURRENT_RECONCILES: usize = 32;

/// Time-based automatic deeper-sleep policy. `None` disables that boundary.
/// The timers begin only after the corresponding stable observed state has
/// been persisted.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoTierPolicy {
    pub warm_after_ms: Option<i64>,
    pub cold_after_ms: Option<i64>,
}

pub struct Controller {
    pub store: Arc<Store>,
    pub storage_meta: Arc<dyn MetadataStore>,
    pub http: reqwest::Client,
    pub notify: Arc<tokio::sync::Notify>,
    pub node_lease_timeout_ms: i64,
    pub auth_token: String,
    pub auto_tier_policy: AutoTierPolicy,
    /// A freshly started control plane gives persisted Nodes two lease
    /// intervals to reconnect. The second interval covers the worker's
    /// in-flight request timeout during a Recreate deployment gap.
    node_fencing_starts_at_ms: i64,
    /// Start attempts per (cat, generation): after 3 failures -> Failed.
    attempts: Mutex<HashMap<String, u32>>,
    /// Earliest next attempt per (cat, generation) for a source-preserving
    /// retry, with the consecutive-failure count that set it.
    ///
    /// A transition that fails without changing the Cat's state is retried for
    /// as long as it keeps failing, so it needs a delay of its own. Without one
    /// the reconciler re-dispatched immediately and a persistent failure --
    /// notably a stop blocked behind a backing-off final usage delivery --
    /// became a hot loop: measured ~288 dispatches per second against one node
    /// agent, which pushed a no-op `exec` on an unrelated Cat from
    /// milliseconds to over a minute.
    retry_after: Mutex<HashMap<String, (u32, std::time::Instant)>>,
}

/// First delay after a source-preserving transition failure.
const RETRY_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Ceiling for the exponential retry delay. A stop blocked on an external
/// dependency should keep retrying, just not faster than the dependency can
/// plausibly recover.
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(60);

impl Controller {
    pub fn new(
        store: Arc<Store>,
        storage_meta: Arc<dyn MetadataStore>,
        notify: Arc<tokio::sync::Notify>,
        node_lease_timeout_ms: i64,
        auth_token: String,
        auto_tier_policy: AutoTierPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            storage_meta,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
            notify,
            node_lease_timeout_ms,
            auth_token,
            auto_tier_policy,
            node_fencing_starts_at_ms: now_ms()
                .saturating_add(node_lease_timeout_ms.max(0).saturating_mul(2)),
            attempts: Mutex::new(HashMap::new()),
            retry_after: Mutex::new(HashMap::new()),
        })
    }

    pub async fn run(self: Arc<Self>, interval: Duration) {
        loop {
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(interval) => {}
            }
            if let Err(e) = self.tick().await {
                tracing::warn!("reconcile tick failed: {e}");
            }
        }
    }

    pub async fn tick(&self) -> anyhow::Result<()> {
        self.detect_lost_nodes()?;
        self.converge_confirmed_fences().await?;
        self.drain_nodes().await?;
        self.reconcile_legacy_topology().await?;
        for cat_id in self.store.auto_suspend_candidates()? {
            self.maybe_auto_suspend(&cat_id)?;
        }
        for cat_id in self.store.auto_tier_candidates(
            self.auto_tier_policy.warm_after_ms,
            self.auto_tier_policy.cold_after_ms,
        )? {
            self.maybe_auto_tier(&cat_id)?;
        }
        // Absolute expiry: converge each expired Cat to Deleted exactly as an
        // API delete would. One failure must not starve the other candidates.
        for cat_id in self.store.expired_cat_candidates()? {
            if let Err(e) =
                self.store
                    .set_desired(&cat_id, DesiredState::Deleted, None, "cat.expire")
            {
                tracing::warn!(cat_id, "expiry delete failed: {e}");
            }
        }
        // Reconcile Cats concurrently. A flow spends nearly all of its time in one
        // blocking dispatch to a node agent -- a cold start is ~6 s of VM boot --
        // so awaiting them one at a time turned ten concurrent creates into a
        // ten-deep queue: measured 61.6 s of wall clock for 10, as a 6 s-per-Cat
        // ramp, with the storage part of all ten adding up to 167 ms.
        //
        // Different Cats are independent: node jobs are idempotent and keyed per
        // Cat, the node agent already serializes per Cat, and placement is an
        // atomic claim (`Store::claim_node_for`), so concurrent flows cannot
        // overcommit a node between deciding and recording.
        let cats = self.store.cats_needing_work()?;
        futures_util::stream::iter(cats)
            .for_each_concurrent(MAX_CONCURRENT_RECONCILES, |cat| async move {
                if let Err(e) = self.reconcile_cat(&cat).await {
                    tracing::warn!(cat = %cat.id, "reconcile failed: {e}");
                }
            })
            .await;
        Ok(())
    }

    /// After every old topology handler is drained, make each Running Host
    /// match the frozen database binding set. This resolves both legacy crash
    /// windows: mount committed before AttachDisk, and DetachDisk succeeded
    /// before legacy unmount removed its binding. A distinct epoch-scoped job
    /// id ensures the latter really reattaches even if the original mount job
    /// is already journaled on the node.
    async fn reconcile_legacy_topology(&self) -> anyhow::Result<()> {
        let Some(epoch) = self.store.legacy_topology_reconciliation_epoch()? else {
            return Ok(());
        };
        let candidates = self.store.legacy_topology_reconciliation_candidates()?;
        let mut cursor = 0;
        while cursor < candidates.len() {
            let cat = &candidates[cursor].0;
            let start = cursor;
            while cursor < candidates.len() && candidates[cursor].0.id == cat.id {
                cursor += 1;
            }
            let bindings = &candidates[start..cursor];
            for (_, binding) in bindings {
                if !self.store.legacy_topology_binding_matches(cat, binding)? {
                    return Ok(());
                }
            }
            let Some(node_id) = cat.node_id.as_deref() else {
                return Ok(());
            };
            let node = self.store.get_node(node_id)?;
            if matches!(node.state, NodeState::Lost | NodeState::Fenced) {
                return Ok(());
            }

            // AttachDisk is a hot operation. Temporarily wake a stable
            // host-bound sleep state, repair every binding for the Cat, then
            // restore the exact physical state without changing database
            // lifecycle authority or publishing a route.
            let wake_action = match cat.observed_state {
                ObservedState::Suspended => Some(NodeJobAction::ResumeCat {
                    cat_id: cat.id.clone(),
                }),
                ObservedState::Warm => Some(NodeJobAction::RestoreCat {
                    cat_id: cat.id.clone(),
                }),
                ObservedState::Running => None,
                _ => unreachable!("legacy topology candidate is host-bound and stable"),
            };
            if let Some(action) = wake_action {
                let job = NodeJob {
                    job_id: nodejob::job_id(
                        &cat.id,
                        cat.generation,
                        &format!("topology_reconcile_{epoch}_wake"),
                    ),
                    cat_generation: cat.generation,
                    action,
                };
                let result = self.dispatch(&node.agent_url, &job).await?;
                if result.job_id != job.job_id
                    || result.phase != JobPhase::Succeeded
                    || result.observed_state != ObservedState::Running
                {
                    anyhow::bail!("legacy topology wake failed for {}", cat.id);
                }
            }

            for (_, binding) in bindings {
                let disk = self.store.get_disk(&cat.workspace_id, &binding.disk_id)?;
                let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
                match self.storage_meta.create_volume(&disk.volume_id, size) {
                    Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
                    Err(error) => return Err(error.into()),
                }
                let job = NodeJob {
                    job_id: nodejob::job_id(
                        &cat.id,
                        cat.generation,
                        &format!("topology_reconcile_{epoch}_{}", disk.id),
                    ),
                    cat_generation: cat.generation,
                    action: NodeJobAction::AttachDisk {
                        cat_id: cat.id.clone(),
                        volume: VolumeGrant {
                            disk_id: disk.id.clone(),
                            volume_id: disk.volume_id.clone(),
                            attachment_id: format!("att_{}_{}_{}", cat.id, disk.id, cat.generation),
                            epoch: 0,
                            size_bytes: size,
                            mount_path: binding.mount_path.clone(),
                            durability: disk.durability,
                        },
                    },
                };
                let result = self.dispatch(&node.agent_url, &job).await?;
                if result.job_id != job.job_id || result.phase != JobPhase::Succeeded {
                    anyhow::bail!(
                        "legacy topology reconciliation {} failed: {}",
                        binding.id,
                        result.error.unwrap_or_else(|| "node job failed".into())
                    );
                }
            }

            let sleep_action = match cat.observed_state {
                ObservedState::Suspended => Some((
                    NodeJobAction::SuspendCat {
                        cat_id: cat.id.clone(),
                        work_fence: Some(self.store.suspend_work_fence(&cat.id)?),
                    },
                    ObservedState::Suspended,
                )),
                ObservedState::Warm => Some((
                    NodeJobAction::WarmCat {
                        cat_id: cat.id.clone(),
                    },
                    ObservedState::Warm,
                )),
                ObservedState::Running => None,
                _ => unreachable!("legacy topology candidate is host-bound and stable"),
            };
            if let Some((action, expected)) = sleep_action {
                let job = NodeJob {
                    job_id: nodejob::job_id(
                        &cat.id,
                        cat.generation,
                        &format!("topology_reconcile_{epoch}_sleep"),
                    ),
                    cat_generation: cat.generation,
                    action,
                };
                let result = self.dispatch(&node.agent_url, &job).await?;
                if result.job_id != job.job_id
                    || result.phase != JobPhase::Succeeded
                    || result.observed_state != expected
                {
                    anyhow::bail!("legacy topology sleep restore failed for {}", cat.id);
                }
            }
            for (_, binding) in bindings {
                if !self.store.legacy_topology_binding_matches(cat, binding)? {
                    return Ok(());
                }
            }
        }
        if self.store.mark_legacy_topology_reconciled(epoch)? {
            tracing::info!(epoch, "legacy disk topology reconciliation completed");
        }
        Ok(())
    }

    /// Event/tick entry for the work-driven policy. The Store transaction is
    /// the linearization point for `work_count == 0 -> desired Suspended`.
    pub fn maybe_auto_suspend(&self, cat_id: &str) -> crate::store::Result<bool> {
        let operation = self
            .store
            .try_auto_suspend(cat_id, self.node_lease_timeout_ms)?;
        if operation.is_some() {
            self.notify.notify_one();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Event/tick entry for time-based Suspended -> Warm -> Cold demotion.
    /// The Store transaction rechecks the persisted state age and live work
    /// leases before changing desired state.
    pub fn maybe_auto_tier(&self, cat_id: &str) -> crate::store::Result<bool> {
        let operation = self.store.try_auto_tier(
            cat_id,
            self.auto_tier_policy.warm_after_ms,
            self.auto_tier_policy.cold_after_ms,
        )?;
        if let Some(operation) = operation {
            tracing::info!(
                cat = cat_id,
                operation = %operation.kind,
                generation = operation.resource_generation,
                "automatic lifecycle tier requested"
            );
            self.notify.notify_one();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ------------------------------------------------------------------
    // Node loss detection / explicit fencing
    // ------------------------------------------------------------------

    fn detect_lost_nodes(&self) -> anyhow::Result<()> {
        let now = now_ms();
        if now < self.node_fencing_starts_at_ms {
            return Ok(());
        }
        for node in self.store.list_nodes()? {
            let fresh = now - node.last_heartbeat_unix * 1000 <= self.node_lease_timeout_ms;
            if node.state == NodeState::Lost || fresh {
                continue;
            }
            if node.state == NodeState::Fenced {
                continue;
            }
            tracing::warn!(
                node = %node.id,
                "node heartbeat expired; preserving claims until explicit fencing"
            );
            self.store.set_node_state(&node.id, NodeState::Lost)?;
            for cat in self.store.cats_on_node(&node.id)? {
                // Lost means unreachable, not dead. Keep placement, routes,
                // and storage epochs so a transient partition cannot turn a
                // healthy Guest's root disk read-only.
                self.store.set_observed(&cat.id, ObservedState::Unknown)?;
            }
        }
        Ok(())
    }

    /// Complete a lost-Host handoff after an external actor has proved that
    /// the old Host is stopped or isolated. The API owns that explicit safety
    /// confirmation; this method performs the idempotent state transition.
    pub(crate) async fn confirm_node_fenced(&self, node_id: &str) -> anyhow::Result<()> {
        let node = self.store.get_node(node_id)?;
        anyhow::ensure!(
            matches!(node.state, NodeState::Lost | NodeState::Fenced),
            "node {node_id} is neither Lost nor an idempotent Fenced retry"
        );

        // Persist the terminal, unschedulable identity before revoking any
        // Cat. If a later volume operation fails, retrying the same action can
        // finish the remaining Cats without reviving this Host identity.
        self.store.set_node_state(node_id, NodeState::Fenced)?;
        tracing::warn!(
            node = node_id,
            "external Host fencing confirmed; revoking Cat claims"
        );
        self.converge_fenced_node(node_id).await?;
        self.notify.notify_one();
        Ok(())
    }

    /// Resume any handoff whose external fencing confirmation was persisted
    /// before a controller crash or metadata outage interrupted convergence.
    async fn converge_confirmed_fences(&self) -> anyhow::Result<()> {
        for node in self
            .store
            .list_nodes()?
            .into_iter()
            .filter(|node| node.state == NodeState::Fenced)
        {
            self.converge_fenced_node(&node.id).await?;
        }
        Ok(())
    }

    async fn converge_fenced_node(&self, node_id: &str) -> anyhow::Result<()> {
        // API confirmations and singleton retries can overlap on different
        // replicas. Snapshot and revoke only while this dedicated per-node
        // session lock is held, then re-read the terminal node state.
        let Some(mut fence_lease) = self.store.node_fence_lease(node_id)? else {
            return Ok(());
        };
        fence_lease.check()?;
        if self.store.get_node(node_id)?.state != NodeState::Fenced {
            return Ok(());
        }
        for cat in self.store.cats_on_node(node_id)? {
            let original = self.capture_cat_volume_leases(&cat)?;
            fence_lease.check()?;
            if let Some(claim) = self.store.topology_claim(&cat.id)? {
                anyhow::ensure!(
                    claim.node_id.as_deref() == Some(node_id)
                        && claim.cat_generation == cat.generation,
                    "Cat {} topology authority changed during node fence",
                    cat.id
                );
                self.revoke_fenced_topology_leases(&claim, node_id, &original)?;
                fence_lease.check()?;
                match claim.action {
                    TopologyAction::Mount { .. } => {
                        self.store.rollback_topology_claim(&claim)?;
                    }
                    TopologyAction::Unmount { .. } => {
                        self.store.complete_topology_claim(&claim)?;
                    }
                }
            } else {
                self.revoke_fenced_cat_leases(&cat, node_id, &original)?;
            }
            fence_lease.check()?;
            if self.store.converge_fenced_cat(&cat.id, node_id)? {
                fence_lease.check()?;
                self.complete_ops_if_converged(&cat.id).await?;
            }
        }
        Ok(())
    }

    fn capture_cat_volume_leases(&self, cat: &Cat) -> anyhow::Result<Vec<VolumeLeaseAuthority>> {
        let mut leases = Vec::new();
        for disk in self.store.list_disks_for_cat(&cat.id)? {
            let head = match self.storage_meta.load_head(&disk.volume_id) {
                Ok(head) => head,
                Err(MetaError::NotFound(_)) => continue,
                Err(e) => return Err(e.into()),
            };
            let Some(owner) = head.lease_owner else {
                continue;
            };
            leases.push(VolumeLeaseAuthority {
                volume_id: disk.volume_id,
                attachment_id: owner,
                epoch: head.lease_epoch,
            });
        }
        Ok(leases)
    }

    fn revoke_captured_leases(
        &self,
        cat_id: &str,
        leases: &[VolumeLeaseAuthority],
        mut authority_matches: impl FnMut() -> crate::store::Result<bool>,
    ) -> anyhow::Result<()> {
        for lease in leases {
            anyhow::ensure!(
                authority_matches()?,
                "Cat {cat_id} fencing authority changed before lease revoke"
            );
            match self.storage_meta.revoke_lease_if_matches(
                &lease.volume_id,
                &lease.attachment_id,
                lease.epoch,
            ) {
                Ok(true) | Err(MetaError::NotFound(_)) => {}
                Ok(false) => {
                    let head = self.storage_meta.load_head(&lease.volume_id)?;
                    let already_fenced = head.lease_owner.is_none()
                        || (head.lease_owner.as_deref() == Some(lease.attachment_id.as_str())
                            && head.lease_epoch > lease.epoch);
                    if !already_fenced {
                        anyhow::bail!(
                            "volume {} writer changed while fencing Cat {cat_id}; retaining authority",
                            lease.volume_id
                        );
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::ensure!(
            authority_matches()?,
            "Cat {cat_id} fencing authority changed after lease revoke"
        );
        Ok(())
    }

    fn revoke_dispatch_leases(&self, dispatch: &LifecycleDispatch) -> anyhow::Result<()> {
        self.revoke_captured_leases(
            dispatch.job.action.cat_id(),
            &dispatch.volume_leases,
            || self.store.lifecycle_dispatch_authority_matches(dispatch),
        )
    }

    fn revoke_unclaimed_cat_leases(
        &self,
        cat: &Cat,
        leases: &[VolumeLeaseAuthority],
    ) -> anyhow::Result<()> {
        self.revoke_captured_leases(&cat.id, leases, || {
            self.store.unclaimed_cat_authority_matches(
                &cat.id,
                cat.generation,
                cat.node_id.as_deref(),
            )
        })
    }

    fn revoke_fenced_cat_leases(
        &self,
        cat: &Cat,
        node_id: &str,
        leases: &[VolumeLeaseAuthority],
    ) -> anyhow::Result<()> {
        self.revoke_captured_leases(&cat.id, leases, || {
            self.store
                .fenced_cat_authority_matches(&cat.id, node_id, cat.generation)
        })
    }

    fn revoke_fenced_topology_leases(
        &self,
        claim: &TopologyClaim,
        node_id: &str,
        leases: &[VolumeLeaseAuthority],
    ) -> anyhow::Result<()> {
        self.revoke_captured_leases(&claim.cat_id, leases, || {
            self.store.fenced_topology_authority_matches(claim, node_id)
        })
    }

    /// Evacuate every Cat from nodes explicitly placed in Draining. Desired
    /// Cat state is preserved: Running Cats cold-start elsewhere, while
    /// Suspended/Warm Cats re-establish their requested host-bound state on a
    /// healthy node.
    ///
    /// The node's own reported inventory is drained too: a Cat the agent
    /// reports without a matching assignment (an orphan, issue #98) gets a
    /// Cold stop by its reported identity. Cold is the safe verb -- whether
    /// the runtime may publish is decided by storage fencing, not here. A
    /// drain only becomes Cordoned once placement is empty AND the latest
    /// report carries no orphans, so "cordoned, cats=0" again means what the
    /// deploy runbook needs it to mean.
    async fn drain_nodes(&self) -> anyhow::Result<()> {
        for node in self
            .store
            .list_nodes()?
            .into_iter()
            .filter(|node| node.state == NodeState::Draining)
        {
            for cat in self.store.cats_on_node(&node.id)? {
                if self.store.lifecycle_dispatch(&cat.id)?.is_some() {
                    // Per-Cat reconciliation owns the already-persisted job.
                    // Draining must not overwrite or race that physical action.
                    continue;
                }
                self.stop_flow(&cat, StopCatDisposition::Cold).await?;
            }
            for orphan in self.store.orphan_reported_cats(&node.id)? {
                let key = format!("{}@{}", orphan.cat_id, orphan.generation);
                if self.retry_deferred_key(&key) {
                    continue;
                }
                let job = NodeJob {
                    job_id: nodejob::job_id(
                        &orphan.cat_id,
                        orphan.generation,
                        "drain_stop_orphan_cat",
                    ),
                    cat_generation: orphan.generation,
                    action: NodeJobAction::StopCat {
                        cat_id: orphan.cat_id.clone(),
                        disposition: StopCatDisposition::Cold,
                    },
                };
                match self.dispatch(&node.agent_url, &job).await {
                    Ok(result) if result.phase == JobPhase::Succeeded => {
                        // Nothing to update: there is no record. The agent
                        // drops the Cat from its next heartbeat and the
                        // stored report converges on its own.
                        self.clear_retry_backoff_key(&key);
                        tracing::info!(
                            node = %node.id,
                            cat = %orphan.cat_id,
                            "drain stopped an orphan runtime the control plane had no assignment for"
                        );
                    }
                    Ok(result) => {
                        // A fencing refusal (root CAS conflict) never succeeds
                        // on retry; back off instead of hammering the metadata
                        // store every tick. Whether a stale journal may be
                        // discarded is an explicit operator decision
                        // (ADR-0030), never made here.
                        let delay = self.defer_retry_key(key);
                        tracing::warn!(
                            node = %node.id,
                            cat = %orphan.cat_id,
                            error = ?result.error,
                            ?delay,
                            "orphan drain stop failed; deferring retry"
                        );
                    }
                    Err(error) => {
                        let delay = self.defer_retry_key(key);
                        tracing::warn!(
                            node = %node.id,
                            cat = %orphan.cat_id,
                            %error,
                            ?delay,
                            "orphan drain dispatch failed; deferring retry"
                        );
                    }
                }
            }
            if self.store.cats_on_node(&node.id)?.is_empty()
                && self.store.orphan_reported_cats(&node.id)?.is_empty()
            {
                self.store.set_node_state(&node.id, NodeState::Cordoned)?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Per-cat reconcile
    // ------------------------------------------------------------------

    /// Delay the next attempt for a transition that failed without changing the
    /// Cat's state, and report how long the caller is waiting.
    ///
    /// Deliberately does *not* notify the reconciler: the whole point is to let
    /// the tick pick this Cat up later instead of immediately.
    fn defer_retry_key(&self, key: String) -> Duration {
        let mut deferred = self.retry_after.lock().unwrap();
        let now = std::time::Instant::now();
        let entry = deferred.entry(key).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        let delay = RETRY_BACKOFF_BASE
            .saturating_mul(1u32 << entry.0.saturating_sub(1).min(6))
            .min(RETRY_BACKOFF_MAX);
        entry.1 = now + delay;
        delay
    }

    /// True while a previously failed transition for this Cat is still waiting.
    fn retry_deferred(&self, cat: &Cat) -> bool {
        self.retry_deferred_key(&attempt_key(cat))
    }

    fn retry_deferred_key(&self, key: &str) -> bool {
        let deferred = self.retry_after.lock().unwrap();
        deferred
            .get(key)
            .is_some_and(|(_, at)| std::time::Instant::now() < *at)
    }

    fn clear_retry_backoff_key(&self, key: &str) {
        self.retry_after.lock().unwrap().remove(key);
    }

    async fn reconcile_cat(&self, cat: &Cat) -> anyhow::Result<()> {
        let provenance_writes_enabled = self.store.lifecycle_provenance_writes_enabled()?;
        if let Some(claim) = self.store.topology_claim(&cat.id)? {
            self.drive_topology_claim(&claim).await?;
            return Ok(());
        }
        // A persisted dispatch owns the physical runtime even when a newer API
        // request has changed desired_state/generation.  Settle that exact job
        // before interpreting the newer desired state; otherwise Starting is
        // ambiguous between StartCat, ResumeCat and RestoreCat.
        if let Some(dispatch) = self.store.lifecycle_dispatch(&cat.id)? {
            if matches!(
                &dispatch.job.action,
                NodeJobAction::StopCat {
                    disposition: StopCatDisposition::Destroy { .. },
                    ..
                }
            ) && cat.desired_state == DesiredState::Deleted
                && cat.node_id.is_none()
                && matches!(
                    cat.observed_state,
                    ObservedState::Cold | ObservedState::Deleted
                )
            {
                return self.delete_flow_authorized(cat, &dispatch).await;
            }
            return self.drive_lifecycle_dispatch(cat, &dispatch).await;
        }
        if matches!(
            cat.observed_state,
            ObservedState::Starting
                | ObservedState::Suspending
                | ObservedState::Warming
                | ObservedState::Stopping
        ) {
            // A phase-A cold launch has independent durable provenance in its
            // current-generation operation row. Replaying its deterministic
            // StartCat is safe and is required after an ambiguous response;
            // `start_flow` deliberately preserves the live epoch when the row
            // is already Starting. Resume/Restore also use Starting, so they
            // may never enter this exception: their operation kind leaves the
            // row fail-closed for the old owner or an operator to settle.
            if !provenance_writes_enabled
                && cat.observed_state == ObservedState::Starting
                && cat.desired_state == DesiredState::Running
            {
                let operations = self.store.pending_lifecycle_operations_for(&cat.id)?;
                let current = operations
                    .iter()
                    .filter(|operation| operation.resource_generation == cat.generation)
                    .collect::<Vec<_>>();
                if !current.is_empty()
                    && current.iter().all(|operation| {
                        matches!(operation.kind.as_str(), "cat.create" | "cat.start")
                    })
                {
                    return self.start_flow(cat).await;
                }
            }
            // Phase-A StopCat has one unambiguous transitional state and one
            // generation-derived job id. An exact current-generation stop or
            // delete operation therefore supplies enough durable provenance
            // to replay a lost response after the old controller disappears.
            // This is deliberately narrower than Starting, which can mean
            // StartCat, ResumeCat or RestoreCat.
            if !provenance_writes_enabled && cat.observed_state == ObservedState::Stopping {
                let operations = self.store.pending_lifecycle_operations_for(&cat.id)?;
                let current = operations
                    .iter()
                    .filter(|operation| operation.resource_generation == cat.generation)
                    .collect::<Vec<_>>();
                let authorized = match cat.desired_state {
                    DesiredState::Cold => {
                        !current.is_empty()
                            && current.iter().all(|operation| {
                                matches!(
                                    operation.kind.as_str(),
                                    "cat.stop" | "cat.auto_cold" | "cat.credit_exhausted"
                                )
                            })
                    }
                    DesiredState::Deleted => {
                        !current.is_empty()
                            && current.iter().all(|operation| {
                                matches!(operation.kind.as_str(), "cat.delete" | "cat.expire")
                            })
                    }
                    _ => false,
                };
                if authorized {
                    return match cat.desired_state {
                        DesiredState::Cold => self.stop_flow(cat, StopCatDisposition::Cold).await,
                        DesiredState::Deleted => self.delete_flow(cat).await,
                        _ => unreachable!("authorized Phase-A StopCat target"),
                    };
                }
            }
            let legacy_key = format!("legacy-transition:{}@{}", cat.id, cat.generation);
            if self.retry_deferred_key(&legacy_key) {
                return Ok(());
            }
            let retry_in = self.defer_retry_key(legacy_key);
            // Upgrade fail-closed rule for a row written by an older replica.
            // This applies in Phase A too: the database maintenance freeze
            // leaves pre-freeze jobs able to settle, but a replacement reader
            // cannot infer whether Starting means Start, Resume, or Restore.
            // Starting alone cannot prove whether the physical action was
            // StartCat, ResumeCat or RestoreCat.  Guessing StartCat can discard
            // the only authoritative Relaxed journal.  New writers publish the
            // state and marker atomically, so only legacy/inconsistent rows land
            // here and require inventory/operator recovery.
            tracing::error!(
                cat = %cat.id,
                generation = cat.generation,
                ?cat.observed_state,
                retry_in_ms = retry_in.as_millis(),
                "transitional Cat has no lifecycle provenance; refusing to infer a node job"
            );
            return Ok(());
        }
        if let Some(node_id) = &cat.node_id {
            let node = self.store.get_node(node_id)?;
            if matches!(node.state, NodeState::Lost | NodeState::Fenced) {
                // Heartbeat recovery or an explicit fence must resolve
                // ownership before even an idempotent generation-alignment
                // action is sent to this Host.
                return Ok(());
            }
        }
        // A stable state name alone is not convergence: an older dispatch may
        // have reached the same state requested by a newer generation.  Prove
        // the node adopted the current generation with an idempotent lifecycle
        // action before completing its Operation.
        if lifecycle_converged(cat) {
            return self.align_converged_generation(cat).await;
        }
        // A source-preserving failure leaves the Cat exactly as it was, so the
        // next tick would re-dispatch the identical job. Honour its backoff
        // before doing anything, or a persistent failure spins.
        if self.retry_deferred(cat) {
            return Ok(());
        }
        use DesiredState as D;
        use ObservedState as O;
        match (cat.desired_state, cat.observed_state) {
            (D::Deleted, _) => self.delete_flow(cat).await,
            (D::Cold, O::Creating | O::Failed) if cat.node_id.is_none() => {
                self.store
                    .set_observed_for_generation(&cat.id, O::Cold, cat.generation)?;
                self.complete_ops_if_converged(&cat.id).await
            }
            // Anything that needs compute first goes through the start flow.
            (D::Running | D::Suspended | D::Warm, O::Creating | O::Cold | O::Starting) => {
                self.start_flow(cat).await
            }
            (D::Running | D::Suspended | D::Warm, O::Failed) => {
                // Failed is a stable terminal result for this generation.
                // A user action creates a new-generation pending Operation,
                // which explicitly authorizes a retry.
                let retry_requested = self
                    .store
                    .pending_operations_for(&cat.id)?
                    .into_iter()
                    .any(|operation| operation.resource_generation == cat.generation);
                if retry_requested {
                    self.start_flow(cat).await
                } else {
                    Ok(())
                }
            }
            (D::Running, O::Suspended) => self.simple_transition(cat, "resume").await,
            (D::Running, O::Warm) => self.simple_transition(cat, "restore").await,
            (D::Suspended | D::Warm, O::Running | O::Suspending) => {
                // Suspending is the durable dispatch boundary. A reconciler
                // leader can disappear after the node applied SuspendCat but
                // before its response was recorded, so its successor must
                // replay the same generation-derived job on the same node.
                self.simple_transition(cat, "suspend").await
            }
            (D::Warm, O::Suspended | O::Warming) => self.simple_transition(cat, "warm").await,
            (D::Suspended, O::Warm) => self.simple_transition(cat, "restore").await,
            (D::Cold, O::Running | O::Suspended | O::Warm) => {
                self.stop_flow(cat, StopCatDisposition::Cold).await
            }
            (D::Cold, O::Starting | O::Suspending | O::Warming | O::Stopping)
                if !provenance_writes_enabled =>
            {
                self.stop_flow(cat, StopCatDisposition::Cold).await
            }
            // Unknown clears when the owning node reports a complete,
            // same-generation inventory or an explicit Host fence converges
            // the Cat through Cold.
            _ => Ok(()),
        }
    }

    async fn align_converged_generation(&self, cat: &Cat) -> anyhow::Result<()> {
        if self.store.observed_generation(&cat.id)? == cat.generation {
            return self.complete_ops_if_converged(&cat.id).await;
        }
        match cat.observed_state {
            // These actions are deliberately idempotent in the node runtime.
            // Their success advances its runtime generation even when the
            // physical state already equals the requested state.
            ObservedState::Running => self.simple_transition(cat, "resume").await,
            ObservedState::Suspended => self.simple_transition(cat, "suspend").await,
            ObservedState::Warm => self.simple_transition(cat, "warm").await,
            ObservedState::Cold => {
                // Cold with no in-flight marker means there is no runtime whose
                // generation must be aligned.
                self.store.set_observed_for_generation(
                    &cat.id,
                    ObservedState::Cold,
                    cat.generation,
                )?;
                self.complete_ops_if_converged(&cat.id).await
            }
            _ => Ok(()),
        }
    }

    fn job_url(&self, agent_url: &str) -> String {
        format!("{}/v1/jobs", agent_url.trim_end_matches('/'))
    }

    async fn dispatch(&self, agent_url: &str, job: &NodeJob) -> anyhow::Result<NodeJobResult> {
        let resp = self
            .http
            .post(self.job_url(agent_url))
            .bearer_auth(&self.auth_token)
            .json(job)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("node agent returned {}", resp.status());
        }
        Ok(resp.json::<NodeJobResult>().await?)
    }

    /// Replay one durable disk topology claim. API cancellation only drops the
    /// waiter; this level-triggered driver retains the provisional binding and
    /// exact node/generation authority until it can commit or roll back.
    pub async fn drive_topology_claim(&self, claim: &TopologyClaim) -> anyhow::Result<bool> {
        if !self.store.topology_claim_matches(claim)? {
            return Ok(false);
        }
        if claim.mode == DiskChangeMode::OfflineCold {
            // No node detach is needed, but an offline unmount still owns the
            // exact writer observed when the claim began. Revoke only that
            // pair; a replacement writer is preserved and does not prevent
            // the database topology from settling.
            if let TopologyAction::Unmount {
                original_lease: Some(original),
                ..
            } = &claim.action
            {
                match self.storage_meta.revoke_lease_if_matches(
                    &original.volume_id,
                    &original.attachment_id,
                    original.epoch,
                ) {
                    Ok(_) | Err(MetaError::NotFound(_)) => {}
                    Err(error) => return Err(error.into()),
                }
                if !self.store.topology_claim_matches(claim)? {
                    return Ok(false);
                }
            }
            return self
                .store
                .complete_topology_claim(claim)
                .map_err(Into::into);
        }
        let Some(node_id) = claim.node_id.as_deref() else {
            anyhow::bail!("hot topology claim {} has no node", claim.claim_id);
        };
        let node = self.store.get_node(node_id)?;
        if matches!(node.state, NodeState::Lost | NodeState::Fenced) {
            return Ok(false);
        }
        let cat = self.store.must_get_cat_by_id(&claim.cat_id)?;
        let binding = claim.binding();
        let disk = self.store.get_disk(&cat.workspace_id, &binding.disk_id)?;
        let action = match &claim.action {
            TopologyAction::Mount { binding } => {
                let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
                match self.storage_meta.create_volume(&disk.volume_id, size) {
                    Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
                    Err(error) => return Err(error.into()),
                }
                NodeJobAction::AttachDisk {
                    cat_id: claim.cat_id.clone(),
                    volume: VolumeGrant {
                        disk_id: disk.id.clone(),
                        volume_id: disk.volume_id.clone(),
                        attachment_id: format!(
                            "att_{}_{}_{}",
                            claim.cat_id, disk.id, claim.cat_generation
                        ),
                        epoch: 0,
                        size_bytes: size,
                        mount_path: binding.mount_path.clone(),
                        durability: disk.durability,
                    },
                }
            }
            TopologyAction::Unmount { .. } => NodeJobAction::DetachDisk {
                cat_id: claim.cat_id.clone(),
                disk_id: disk.id.clone(),
            },
        };
        let job = NodeJob {
            job_id: nodejob::job_id(
                &claim.cat_id,
                claim.cat_generation,
                &format!("topology_{}", claim.claim_id),
            ),
            cat_generation: claim.cat_generation,
            action,
        };
        let result = self.dispatch(&node.agent_url, &job).await?;
        if result.job_id != job.job_id {
            anyhow::bail!(
                "topology claim {} received mismatched result {}",
                claim.claim_id,
                result.job_id
            );
        }
        if result.phase != JobPhase::Succeeded {
            self.store.rollback_topology_claim(claim)?;
            anyhow::bail!(
                "topology claim {} failed: {}",
                claim.claim_id,
                result.error.unwrap_or_else(|| "node job failed".into())
            );
        }
        // The request above is the cancellation/replica-handoff window. Never
        // let its late response act under a replacement lifecycle/topology
        // authority.
        if !self.store.topology_claim_matches(claim)? {
            return Ok(false);
        }
        if let TopologyAction::Unmount {
            original_lease: Some(original),
            ..
        } = &claim.action
        {
            self.revoke_original_topology_lease(claim, original)?;
        }
        if !self.store.topology_claim_matches(claim)? {
            return Ok(false);
        }
        self.store
            .complete_topology_claim(claim)
            .map_err(Into::into)
    }

    fn revoke_original_topology_lease(
        &self,
        claim: &TopologyClaim,
        original: &VolumeLeaseAuthority,
    ) -> anyhow::Result<()> {
        match self.storage_meta.revoke_lease_if_matches(
            &original.volume_id,
            &original.attachment_id,
            original.epoch,
        ) {
            Ok(true) | Err(MetaError::NotFound(_)) => Ok(()),
            Ok(false) => {
                let head = self.storage_meta.load_head(&original.volume_id)?;
                if head.lease_owner.is_none()
                    || (head.lease_owner.as_deref() == Some(original.attachment_id.as_str())
                        && head.lease_epoch > original.epoch)
                {
                    Ok(())
                } else {
                    anyhow::bail!(
                        "volume {} writer changed while topology claim {} was detached; retaining claim",
                        original.volume_id,
                        claim.claim_id
                    )
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn volume_grants(&self, cat: &Cat) -> anyhow::Result<Vec<VolumeGrant>> {
        let mut grants = Vec::new();
        let bindings = self.store.bindings_for_cat(&cat.id)?;
        for b in &bindings {
            let disk = self.store.get_disk(&cat.workspace_id, &b.disk_id)?;
            let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
            match self.storage_meta.create_volume(&disk.volume_id, size) {
                Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
                Err(e) => return Err(e.into()),
            }
            grants.push(VolumeGrant {
                disk_id: disk.id.clone(),
                volume_id: disk.volume_id.clone(),
                attachment_id: format!("att_{}_{}_{}", cat.id, disk.id, cat.generation),
                epoch: 0,
                size_bytes: size,
                mount_path: b.mount_path.clone(),
                durability: disk.durability,
            });
        }
        // Root disk first (mount path "/").
        grants.sort_by_key(|g| g.mount_path != "/");
        Ok(grants)
    }

    async fn start_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        let node = if let Some(node_id) = &cat.node_id {
            self.store.get_node(node_id)?
        } else {
            // Choosing a node and claiming its capacity is one step, so several
            // start flows can run at once without overcommitting one node.
            let Some(node) = self.store.claim_node_for(
                &cat.id,
                cat.spec.cpus,
                cat.spec.memory_mib,
                self.node_lease_timeout_ms,
                now_ms(),
            )?
            else {
                tracing::info!(cat = %cat.id, "no schedulable node; will retry");
                return Ok(());
            };
            node
        };

        let cat = self.store.must_get_cat_by_id(&cat.id)?;
        let grants = self.volume_grants(&cat).await?;
        let provenance_writes_enabled = self.store.lifecycle_provenance_writes_enabled()?;
        // Fence stale writers before atomically publishing the exact job and
        // Starting boundary.  After that commit the marker, including these
        // exact grants, is the only payload a successor may replay.
        //
        // During phase A, however, an existing markerless Starting row is the
        // legacy durable boundary.  Its StartCat may already own the epoch, so
        // replay must preserve that claim exactly as the pre-provenance writer
        // did.  Activation cannot race this exception: the global gate refuses
        // to enable while a markerless transitional row exists.
        if provenance_writes_enabled || cat.observed_state != ObservedState::Starting {
            let original = self.capture_cat_volume_leases(&cat)?;
            self.revoke_unclaimed_cat_leases(&cat, &original)?;
        }
        let volume_leases = self.capture_cat_volume_leases(&cat)?;
        let job = NodeJob {
            job_id: nodejob::job_id(&cat.id, cat.generation, "start_cat"),
            cat_generation: cat.generation,
            action: NodeJobAction::StartCat {
                cat_id: cat.id.clone(),
                image: cat.image.clone(),
                cpus: cat.spec.cpus,
                memory_mib: cat.spec.memory_mib,
                volumes: grants,
            },
        };
        if !provenance_writes_enabled {
            return self
                .drive_legacy_lifecycle(
                    &cat,
                    &node,
                    job,
                    ObservedState::Starting,
                    ObservedState::Running,
                    volume_leases,
                )
                .await;
        }
        let Some(dispatch) = self.store.begin_lifecycle_dispatch(
            &cat.id,
            &node.id,
            cat.observed_state,
            ObservedState::Starting,
            ObservedState::Running,
            volume_leases,
            job,
        )?
        else {
            return Ok(());
        };
        self.drive_lifecycle_dispatch(&cat, &dispatch).await
    }

    /// suspend / resume / warm / restore on the current node, with the
    /// ADR-0002 rule: any resume/restore failure falls back to Cold.
    async fn simple_transition(&self, cat: &Cat, action: &str) -> anyhow::Result<()> {
        let transition_started = std::time::Instant::now();
        let Some(node_id) = &cat.node_id else {
            // Placement lost (e.g. host fenced) - converge through Cold.
            self.store
                .set_observed_for_generation(&cat.id, ObservedState::Cold, cat.generation)?;
            return Ok(());
        };
        let node = self
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| &n.id == node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} missing"))?;

        let (job_action, transitional, target): (NodeJobAction, ObservedState, ObservedState) =
            match action {
                "suspend" => (
                    NodeJobAction::SuspendCat {
                        cat_id: cat.id.clone(),
                        work_fence: Some(self.store.suspend_work_fence(&cat.id)?),
                    },
                    ObservedState::Suspending,
                    ObservedState::Suspended,
                ),
                "resume" => (
                    NodeJobAction::ResumeCat {
                        cat_id: cat.id.clone(),
                    },
                    ObservedState::Starting,
                    ObservedState::Running,
                ),
                "warm" => (
                    NodeJobAction::WarmCat {
                        cat_id: cat.id.clone(),
                    },
                    ObservedState::Warming,
                    ObservedState::Warm,
                ),
                "restore" => (
                    NodeJobAction::RestoreCat {
                        cat_id: cat.id.clone(),
                    },
                    ObservedState::Starting,
                    ObservedState::Running,
                ),
                _ => unreachable!("unknown transition"),
            };
        let job = NodeJob {
            job_id: nodejob::job_id(&cat.id, cat.generation, job_action.kind()),
            cat_generation: cat.generation,
            action: job_action,
        };
        let volume_leases = self.capture_cat_volume_leases(cat)?;
        if !self.store.lifecycle_provenance_writes_enabled()? {
            return self
                .drive_legacy_lifecycle(cat, &node, job, transitional, target, volume_leases)
                .await;
        }
        let Some(dispatch) = self.store.begin_lifecycle_dispatch(
            &cat.id,
            &node.id,
            cat.observed_state,
            transitional,
            target,
            volume_leases,
            job,
        )?
        else {
            return Ok(());
        };
        tracing::info!(
            cat = %cat.id,
            action,
            setup_us = transition_started.elapsed().as_micros(),
            "lifecycle transition provenance persisted"
        );
        self.drive_lifecycle_dispatch(cat, &dispatch).await
    }

    async fn drive_lifecycle_dispatch(
        &self,
        cat: &Cat,
        dispatch: &LifecycleDispatch,
    ) -> anyhow::Result<()> {
        if self.retry_deferred_key(&dispatch.dispatch_id) {
            return Ok(());
        }
        let node = self.store.get_node(&dispatch.node_id)?;
        if matches!(node.state, NodeState::Lost | NodeState::Fenced) {
            return Ok(());
        }
        let result = match self.dispatch(&node.agent_url, &dispatch.job).await {
            Ok(result) if result.job_id == dispatch.job.job_id => result,
            Ok(result) => {
                let retry_in = self.defer_retry_key(dispatch.dispatch_id.clone());
                tracing::warn!(
                    cat = %cat.id,
                    expected_job = %dispatch.job.job_id,
                    returned_job = %result.job_id,
                    retry_in_ms = retry_in.as_millis(),
                    "node returned a mismatched lifecycle result; retaining exact dispatch"
                );
                return Ok(());
            }
            Err(error) => {
                // The Host may have committed the job before its response was
                // lost.  No control-plane field changes at an ambiguous
                // transport boundary; the same marker is replayed later.
                let retry_in = self.defer_retry_key(dispatch.dispatch_id.clone());
                tracing::warn!(
                    cat = %cat.id,
                    job = %dispatch.job.job_id,
                    retry_in_ms = retry_in.as_millis(),
                    "lifecycle result unknown: {error}; retaining exact dispatch"
                );
                return Ok(());
            }
        };

        if result.phase == JobPhase::Succeeded {
            if matches!(&dispatch.job.action, NodeJobAction::StopCat { .. }) {
                // These steps are idempotent and precede marker settlement.  A
                // crash replays the already-successful StopCat, then repeats
                // the cleanup; it never exposes Cold while a writable lease or
                // route is still published.
                self.revoke_dispatch_leases(dispatch)?;
            }
            let running_route = (dispatch.target_state == ObservedState::Running)
                .then_some((node.id.as_str(), node.gateway_url.as_str()));
            let release_placement = matches!(&dispatch.job.action, NodeJobAction::StopCat { .. });
            let retain_destroy_authority = matches!(
                &dispatch.job.action,
                NodeJobAction::StopCat {
                    disposition: StopCatDisposition::Destroy { .. },
                    ..
                }
            );
            let settled = self.store.settle_lifecycle_dispatch(
                dispatch,
                dispatch.target_state,
                !retain_destroy_authority,
                None,
                running_route,
                release_placement,
            )?;
            if settled {
                self.attempts.lock().unwrap().remove(&dispatch.dispatch_id);
                self.clear_retry_backoff_key(&dispatch.dispatch_id);
                self.complete_ops_if_converged(&cat.id).await?;
                self.notify.notify_one();
            }
            return Ok(());
        }

        if result.phase == JobPhase::Rejected
            && matches!(&dispatch.job.action, NodeJobAction::SuspendCat { .. })
        {
            let error = ErrorBody::new(
                cats_api::error::ErrorCode::Conflict,
                "work arrived while preparing to suspend",
            );
            if self.store.settle_lifecycle_dispatch(
                dispatch,
                ObservedState::Running,
                true,
                Some(&error),
                None,
                false,
            )? {
                self.store
                    .cancel_rejected_suspend(&cat.id, dispatch.job.cat_generation)?;
            }
            self.clear_retry_backoff_key(&dispatch.dispatch_id);
            self.notify.notify_one();
            return Ok(());
        }

        let error = result
            .error
            .unwrap_or_else(|| "node lifecycle job failed".into());
        match &dispatch.job.action {
            NodeJobAction::WarmCat { .. }
            | NodeJobAction::StopCat { .. }
            | NodeJobAction::SuspendCat { .. } => {
                // These are source-preserving or mandatory-drain transitions.
                // A failure may leave the unique Relaxed journal on this Host;
                // never replace it with a destructive Cold start.
                let source_state = match &dispatch.job.action {
                    NodeJobAction::WarmCat { .. } => matches!(
                        result.observed_state,
                        ObservedState::Running | ObservedState::Suspended
                    ),
                    NodeJobAction::SuspendCat { .. } => {
                        result.observed_state == ObservedState::Running
                    }
                    NodeJobAction::StopCat { .. } => matches!(
                        result.observed_state,
                        ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
                    ),
                    _ => false,
                };
                let retained = if source_state {
                    result.observed_state
                } else {
                    dispatch.transitional_state
                };
                self.store
                    .settle_lifecycle_dispatch(dispatch, retained, false, None, None, false)?;
                let retry_in = self.defer_retry_key(dispatch.dispatch_id.clone());
                tracing::warn!(
                    cat = %cat.id,
                    job = %dispatch.job.job_id,
                    ?retained,
                    retry_in_ms = retry_in.as_millis(),
                    "source-preserving lifecycle job failed: {error}"
                );
            }
            NodeJobAction::StartCat { .. } => {
                if result.observed_state == ObservedState::Running {
                    self.store.settle_lifecycle_dispatch(
                        dispatch,
                        dispatch.transitional_state,
                        false,
                        None,
                        None,
                        false,
                    )?;
                    let retry_in = self.defer_retry_key(dispatch.dispatch_id.clone());
                    tracing::warn!(
                        cat = %cat.id,
                        retry_in_ms = retry_in.as_millis(),
                        "StartCat reached Running but failed its post-action boundary; retaining exact job"
                    );
                    return Ok(());
                }
                let give_up = {
                    let mut attempts = self.attempts.lock().unwrap();
                    let count = attempts.entry(dispatch.dispatch_id.clone()).or_insert(0);
                    *count += 1;
                    *count >= 3
                };
                if give_up {
                    let terminal = ErrorBody::new(
                        cats_api::error::ErrorCode::Unavailable,
                        format!("start failed after retries: {error}"),
                    );
                    let current_leases = self.capture_cat_volume_leases(cat)?;
                    let Some(fencing_dispatch) = self
                        .store
                        .persist_lifecycle_fence_leases(dispatch, current_leases)?
                    else {
                        return Ok(());
                    };
                    self.revoke_dispatch_leases(&fencing_dispatch)?;
                    self.store.settle_lifecycle_dispatch(
                        &fencing_dispatch,
                        ObservedState::Failed,
                        true,
                        Some(&terminal),
                        None,
                        true,
                    )?;
                    self.attempts.lock().unwrap().remove(&dispatch.dispatch_id);
                } else {
                    self.store.settle_lifecycle_dispatch(
                        dispatch,
                        dispatch.transitional_state,
                        false,
                        None,
                        None,
                        false,
                    )?;
                    let retry_in = self.defer_retry_key(dispatch.dispatch_id.clone());
                    tracing::warn!(
                        cat = %cat.id,
                        retry_in_ms = retry_in.as_millis(),
                        "StartCat failed: {error}; retaining exact job for retry"
                    );
                }
            }
            NodeJobAction::ResumeCat { .. } | NodeJobAction::RestoreCat { .. } => {
                // ADR-0002: failed wake converges through an explicit clean
                // Cold fallback. StopCat(Cold) first prevents new writes and
                // then performs the mandatory remote drain; CleanupCat would
                // discard the only acknowledged Relaxed journal. Do not clear
                // the original marker unless the drain is confirmed.
                let fallback = NodeJob {
                    job_id: nodejob::job_id(
                        &cat.id,
                        dispatch.job.cat_generation,
                        "wake_fallback_stop_cat",
                    ),
                    cat_generation: dispatch.job.cat_generation,
                    action: NodeJobAction::StopCat {
                        cat_id: cat.id.clone(),
                        disposition: StopCatDisposition::Cold,
                    },
                };
                match self.dispatch(&node.agent_url, &fallback).await {
                    Ok(cleaned)
                        if cleaned.job_id == fallback.job_id
                            && cleaned.phase == JobPhase::Succeeded =>
                    {
                        self.revoke_dispatch_leases(dispatch)?;
                        self.store.settle_lifecycle_dispatch(
                            dispatch,
                            ObservedState::Cold,
                            true,
                            None,
                            None,
                            true,
                        )?;
                        self.clear_retry_backoff_key(&dispatch.dispatch_id);
                        self.notify.notify_one();
                    }
                    other => {
                        let retry_in = self.defer_retry_key(dispatch.dispatch_id.clone());
                        tracing::warn!(
                            cat = %cat.id,
                            retry_in_ms = retry_in.as_millis(),
                            fallback_result = ?other,
                            "wake failed ({error}); durable Cold fallback is unconfirmed, retaining exact dispatch"
                        );
                    }
                }
            }
            _ => unreachable!("non-lifecycle action stored as lifecycle provenance"),
        }
        Ok(())
    }

    /// Phase-A writer used only while older replicas may still regain the
    /// singleton lock. It deliberately persists the historical transitional
    /// state without the new column, so old binaries remain able to reconcile
    /// rows written during that rollout. The same binary always prefers and
    /// replays a marker when one already exists, which is what makes it a
    /// compatible reader before phase B enables marker writes fleet-wide.
    async fn drive_legacy_lifecycle(
        &self,
        cat: &Cat,
        node: &Node,
        job: NodeJob,
        transitional: ObservedState,
        target: ObservedState,
        original_leases: Vec<VolumeLeaseAuthority>,
    ) -> anyhow::Result<()> {
        match self.store.begin_legacy_lifecycle(
            &cat.id,
            &node.id,
            job.cat_generation,
            cat.observed_state,
            transitional,
        )? {
            LegacyLifecycleBegin::Begun => {}
            LegacyLifecycleBegin::Stale => return Ok(()),
            LegacyLifecycleBegin::GateEnabled => {
                let Some(dispatch) = self.store.begin_lifecycle_dispatch(
                    &cat.id,
                    &node.id,
                    cat.observed_state,
                    transitional,
                    target,
                    original_leases,
                    job,
                )?
                else {
                    return Ok(());
                };
                return self.drive_lifecycle_dispatch(cat, &dispatch).await;
            }
        }
        let result = match self.dispatch(&node.agent_url, &job).await {
            Ok(result) if result.job_id == job.job_id => result,
            Ok(result) => {
                if matches!(
                    &job.action,
                    NodeJobAction::ResumeCat { .. } | NodeJobAction::RestoreCat { .. }
                ) {
                    self.store.set_observed(&cat.id, cat.observed_state)?;
                    self.defer_retry_key(attempt_key(cat));
                }
                tracing::warn!(
                    cat = %cat.id,
                    expected_job = %job.job_id,
                    returned_job = %result.job_id,
                    "phase-A node returned mismatched lifecycle result"
                );
                return Ok(());
            }
            Err(error) => {
                if matches!(
                    &job.action,
                    NodeJobAction::ResumeCat { .. } | NodeJobAction::RestoreCat { .. }
                ) {
                    // A phase-A Starting row has no action provenance. Restore
                    // the known host-bound source before retrying, otherwise a
                    // later tick would infer cold StartCat and discard the only
                    // Relaxed journal after an ambiguous wake response.
                    self.store.set_observed(&cat.id, cat.observed_state)?;
                    self.defer_retry_key(attempt_key(cat));
                }
                tracing::warn!(cat = %cat.id, job = %job.job_id, "phase-A lifecycle result unknown: {error}");
                return Ok(());
            }
        };
        if result.phase == JobPhase::Succeeded {
            if matches!(&job.action, NodeJobAction::StopCat { .. }) {
                self.revoke_unclaimed_cat_leases(cat, &original_leases)?;
                self.store.unbind_routes(&cat.id)?;
                self.store.set_placement(&cat.id, None)?;
            } else if target == ObservedState::Running {
                self.store
                    .publish_routes(&cat.id, &node.id, &node.gateway_url)?;
            }
            self.store
                .set_observed_for_generation(&cat.id, target, job.cat_generation)?;
            self.complete_ops_if_converged(&cat.id).await?;
            self.notify.notify_one();
            return Ok(());
        }
        if result.phase == JobPhase::Rejected
            && matches!(&job.action, NodeJobAction::SuspendCat { .. })
        {
            self.store.set_observed_for_generation(
                &cat.id,
                ObservedState::Running,
                job.cat_generation,
            )?;
            self.store
                .cancel_rejected_suspend(&cat.id, job.cat_generation)?;
            self.notify.notify_one();
            return Ok(());
        }

        match &job.action {
            NodeJobAction::WarmCat { .. }
            | NodeJobAction::StopCat { .. }
            | NodeJobAction::SuspendCat { .. } => {
                let retained = match result.observed_state {
                    ObservedState::Running | ObservedState::Suspended | ObservedState::Warm => {
                        result.observed_state
                    }
                    _ => transitional,
                };
                self.store.set_observed(&cat.id, retained)?;
                self.defer_retry_key(attempt_key(cat));
            }
            NodeJobAction::StartCat { .. } => {
                let give_up = {
                    let mut attempts = self.attempts.lock().unwrap();
                    let count = attempts.entry(attempt_key(cat)).or_insert(0);
                    *count += 1;
                    *count >= 3
                };
                if give_up {
                    let current_leases = self.capture_cat_volume_leases(cat)?;
                    self.revoke_unclaimed_cat_leases(cat, &current_leases)?;
                    self.store.unbind_routes(&cat.id)?;
                    self.store.set_placement(&cat.id, None)?;
                    self.store.set_observed(&cat.id, ObservedState::Failed)?;
                    let error = ErrorBody::new(
                        cats_api::error::ErrorCode::Unavailable,
                        "phase-A StartCat failed after retries",
                    );
                    for operation in self.store.pending_operations_for(&cat.id)? {
                        if operation.resource_generation == job.cat_generation {
                            self.store.finish_operation(&operation.id, Some(&error))?;
                        }
                    }
                }
            }
            NodeJobAction::ResumeCat { .. } | NodeJobAction::RestoreCat { .. } => {
                let fallback = NodeJob {
                    job_id: nodejob::job_id(&cat.id, job.cat_generation, "wake_fallback_stop_cat"),
                    cat_generation: job.cat_generation,
                    action: NodeJobAction::StopCat {
                        cat_id: cat.id.clone(),
                        disposition: StopCatDisposition::Cold,
                    },
                };
                match self.dispatch(&node.agent_url, &fallback).await {
                    Ok(cleaned)
                        if cleaned.job_id == fallback.job_id
                            && cleaned.phase == JobPhase::Succeeded =>
                    {
                        self.revoke_unclaimed_cat_leases(cat, &original_leases)?;
                        self.store.unbind_routes(&cat.id)?;
                        self.store.set_placement(&cat.id, None)?;
                        self.store.set_observed_for_generation(
                            &cat.id,
                            ObservedState::Cold,
                            job.cat_generation,
                        )?;
                        self.notify.notify_one();
                    }
                    other => {
                        self.store.set_observed(&cat.id, cat.observed_state)?;
                        let retry_in = self.defer_retry_key(attempt_key(cat));
                        tracing::warn!(
                            cat = %cat.id,
                            retry_in_ms = retry_in.as_millis(),
                            fallback_result = ?other,
                            "phase-A wake fallback is unconfirmed; restored source state for safe retry"
                        );
                    }
                }
            }
            _ => unreachable!("non-lifecycle action in phase-A lifecycle writer"),
        }
        Ok(())
    }

    async fn stop_flow(&self, cat: &Cat, disposition: StopCatDisposition) -> anyhow::Result<()> {
        let Some(node_id) = &cat.node_id else {
            self.store
                .set_observed_for_generation(&cat.id, ObservedState::Cold, cat.generation)?;
            self.complete_ops_if_converged(&cat.id).await?;
            return Ok(());
        };
        let node = self.store.get_node(node_id)?;
        let job = NodeJob {
            job_id: nodejob::job_id(&cat.id, cat.generation, "stop_cat"),
            cat_generation: cat.generation,
            action: NodeJobAction::StopCat {
                cat_id: cat.id.clone(),
                disposition,
            },
        };
        let volume_leases = self.capture_cat_volume_leases(cat)?;
        if !self.store.lifecycle_provenance_writes_enabled()? {
            return self
                .drive_legacy_lifecycle(
                    cat,
                    &node,
                    job,
                    ObservedState::Stopping,
                    ObservedState::Cold,
                    volume_leases,
                )
                .await;
        }
        let Some(dispatch) = self.store.begin_lifecycle_dispatch(
            &cat.id,
            &node.id,
            cat.observed_state,
            ObservedState::Stopping,
            ObservedState::Cold,
            volume_leases,
            job,
        )?
        else {
            return Ok(());
        };
        self.drive_lifecycle_dispatch(cat, &dispatch).await
    }

    async fn delete_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        if cat.node_id.is_some() {
            // Stop first (also fences + unbinds routes). The RootDisk is being
            // deleted, so the node may discard only its local journal/cache;
            // PersistentDisks still cross the mandatory remote-drain boundary.
            let mut disposable_root_disk_ids = Vec::new();
            let mut retained_persistent_disk_ids = Vec::new();
            for disk in self.store.list_disks_for_cat(&cat.id)? {
                match disk.kind {
                    DiskKind::Root => disposable_root_disk_ids.push(disk.id),
                    DiskKind::Persistent => retained_persistent_disk_ids.push(disk.id),
                }
            }
            self.stop_flow(
                cat,
                StopCatDisposition::Destroy {
                    disposable_root_disk_ids,
                    retained_persistent_disk_ids,
                },
            )
            .await?;
            // Stop success retains its exact Destroy marker. A later reconcile
            // claims that authority before any destructive metadata call.
            return Ok(());
        }
        // A Cat that was already Cold has no node job to prove. Its desired
        // generation remains terminal, so direct cleanup uses the guarded
        // cold-row path below.
        self.delete_flow_cold(cat).await
    }

    async fn delete_flow_authorized(
        &self,
        cat: &Cat,
        dispatch: &LifecycleDispatch,
    ) -> anyhow::Result<()> {
        if self.retry_deferred(cat) {
            return Ok(());
        }
        let Some(_cleanup_lease) = self.store.destroy_cleanup_lease(&cat.id)? else {
            return Ok(());
        };
        if !self.store.claim_destroy_cleanup(dispatch)? {
            return Ok(());
        }
        self.run_delete_cleanup(cat, Some(dispatch)).await
    }

    async fn delete_flow_cold(&self, cat: &Cat) -> anyhow::Result<()> {
        if self.retry_deferred(cat) {
            return Ok(());
        }
        let Some(_cleanup_lease) = self.store.destroy_cleanup_lease(&cat.id)? else {
            return Ok(());
        };
        if !self
            .store
            .claim_cold_delete_cleanup(&cat.id, cat.generation)?
        {
            return Ok(());
        }
        self.run_delete_cleanup(cat, None).await
    }

    async fn run_delete_cleanup(
        &self,
        cat: &Cat,
        dispatch: Option<&LifecycleDispatch>,
    ) -> anyhow::Result<()> {
        match self.delete_metadata_and_rows(cat, dispatch).await {
            Ok(()) => {
                self.clear_retry_backoff_key(&attempt_key(cat));
                Ok(())
            }
            Err(error) => {
                let retry_in = self.defer_retry_key(attempt_key(cat));
                tracing::warn!(
                    cat = %cat.id,
                    retry_in_ms = retry_in.as_millis(),
                    "delete cleanup failed after its durable boundary: {error}"
                );
                Err(error)
            }
        }
    }

    async fn delete_metadata_and_rows(
        &self,
        cat: &Cat,
        dispatch: Option<&LifecycleDispatch>,
    ) -> anyhow::Result<()> {
        // Root disk dies with the cat; persistent disks return to Available.
        for binding in self.store.bindings_for_cat(&cat.id)? {
            let disk = self.store.get_disk(&cat.workspace_id, &binding.disk_id)?;
            self.store.unbind_disk(&disk.id)?;
        }
        // The binding may already have been removed by a crashed prior retry;
        // root_disk_id remains the authoritative cleanup key until Cat deletion.
        if let Ok(root) = self.store.get_disk(&cat.workspace_id, &cat.root_disk_id) {
            match self.storage_meta.delete_volume(&root.volume_id) {
                Ok(()) | Err(MetaError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
            self.store.delete_disk_row(&root.id)?;
        }
        match dispatch {
            Some(dispatch) => {
                self.store.delete_cat_if_destroy_authorized(dispatch)?;
            }
            None => {
                self.store
                    .delete_cat_if_cold_delete_authorized(&cat.id, cat.generation)?;
            }
        }
        Ok(())
    }

    async fn complete_ops_if_converged(&self, cat_id: &str) -> anyhow::Result<()> {
        let cat = self.store.must_get_cat_by_id(cat_id)?;
        if lifecycle_converged(&cat)
            && self.store.lifecycle_dispatch(cat_id)?.is_none()
            && self.store.observed_generation(cat_id)? == cat.generation
        {
            for op in self.store.pending_lifecycle_operations_for(cat_id)? {
                if op.resource_generation == cat.generation {
                    self.store.finish_operation(&op.id, None)?;
                } else if op.resource_generation < cat.generation {
                    self.store.finish_operation(
                        &op.id,
                        Some(&ErrorBody::new(
                            cats_api::error::ErrorCode::Conflict,
                            "superseded by a newer Cat generation",
                        )),
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn lifecycle_converged(cat: &Cat) -> bool {
    matches!(
        (cat.desired_state, cat.observed_state),
        (DesiredState::Running, ObservedState::Running)
            | (DesiredState::Suspended, ObservedState::Suspended)
            | (DesiredState::Warm, ObservedState::Warm)
            | (DesiredState::Cold, ObservedState::Cold)
    )
}

fn attempt_key(cat: &Cat) -> String {
    format!("{}@{}", cat.id, cat.generation)
}

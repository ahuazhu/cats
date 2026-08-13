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

use cats_api::error::{ApiError, ErrorBody};
use cats_api::nodejob::{
    self, JobPhase, NodeJob, NodeJobAction, NodeJobResult, StopCatDisposition, VolumeGrant,
};
use cats_api::resources::*;
use cats_storage::{MetaError, MetadataStore};
use futures_util::StreamExt;

use crate::store::{now_ms, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeLivenessAuthority {
    SignedSession,
    LegacyHeartbeatForTests,
}

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
    retired_storage_meta_for_tests: Option<Arc<dyn MetadataStore>>,
    pub http: reqwest::Client,
    pub notify: Arc<tokio::sync::Notify>,
    pub node_lease_timeout_ms: i64,
    pub auth_token: String,
    pub auto_tier_policy: AutoTierPolicy,
    node_liveness_authority: NodeLivenessAuthority,
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
    pub(crate) fn new_with_liveness_authority(
        store: Arc<Store>,
        retired_storage_meta_for_tests: Option<Arc<dyn MetadataStore>>,
        notify: Arc<tokio::sync::Notify>,
        node_lease_timeout_ms: i64,
        auth_token: String,
        auto_tier_policy: AutoTierPolicy,
        node_liveness_authority: NodeLivenessAuthority,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            retired_storage_meta_for_tests,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
            notify,
            node_lease_timeout_ms,
            auth_token,
            auto_tier_policy,
            node_liveness_authority,
            node_fencing_starts_at_ms: now_ms()
                .saturating_add(node_lease_timeout_ms.max(0).saturating_mul(2)),
            attempts: Mutex::new(HashMap::new()),
            retry_after: Mutex::new(HashMap::new()),
        })
    }

    fn retired_storage_meta(&self) -> anyhow::Result<&dyn MetadataStore> {
        self.retired_storage_meta_for_tests
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("legacy storage authority is not composed"))
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
        self.detect_lost_nodes().await?;
        self.converge_confirmed_fences().await?;
        self.drain_nodes().await?;
        let auto_suspend_candidates = self
            .store
            .execute(|store| store.auto_suspend_candidates())
            .await?;
        for cat_id in auto_suspend_candidates {
            self.maybe_auto_suspend(&cat_id).await?;
        }
        let warm_after_ms = self.auto_tier_policy.warm_after_ms;
        let cold_after_ms = self.auto_tier_policy.cold_after_ms;
        let auto_tier_candidates = self
            .store
            .execute(move |store| store.auto_tier_candidates(warm_after_ms, cold_after_ms))
            .await?;
        for cat_id in auto_tier_candidates {
            self.maybe_auto_tier(&cat_id).await?;
        }
        // Absolute expiry: converge each expired Cat to Deleted exactly as an
        // API delete would. One failure must not starve the other candidates.
        let expired_cat_candidates = self
            .store
            .execute(|store| store.expired_cat_candidates())
            .await?;
        for cat_id in expired_cat_candidates {
            let expire_cat_id = cat_id.clone();
            if let Err(e) = self
                .store
                .execute(move |store| {
                    store.set_desired(&expire_cat_id, DesiredState::Deleted, None, "cat.expire")
                })
                .await
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
        let cats = self
            .store
            .execute(|store| store.cats_needing_work())
            .await?;
        futures_util::stream::iter(cats)
            .for_each_concurrent(MAX_CONCURRENT_RECONCILES, |cat| async move {
                if let Err(e) = self.reconcile_cat(&cat).await {
                    tracing::warn!(cat = %cat.id, "reconcile failed: {e}");
                }
            })
            .await;
        Ok(())
    }

    /// Event/tick entry for the work-driven policy. The Store transaction is
    /// the linearization point for `work_count == 0 -> desired Suspended`.
    pub async fn maybe_auto_suspend(&self, cat_id: &str) -> crate::store::Result<bool> {
        let cat_id = cat_id.to_string();
        let node_lease_timeout_ms = self.node_lease_timeout_ms;
        let operation = self
            .store
            .execute(move |store| store.try_auto_suspend(&cat_id, node_lease_timeout_ms))
            .await?;
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
    pub async fn maybe_auto_tier(&self, cat_id: &str) -> crate::store::Result<bool> {
        let cat_id = cat_id.to_string();
        let query_cat_id = cat_id.clone();
        let warm_after_ms = self.auto_tier_policy.warm_after_ms;
        let cold_after_ms = self.auto_tier_policy.cold_after_ms;
        let operation = self
            .store
            .execute(move |store| store.try_auto_tier(&query_cat_id, warm_after_ms, cold_after_ms))
            .await?;
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

    async fn detect_lost_nodes(&self) -> anyhow::Result<()> {
        if self.node_liveness_authority == NodeLivenessAuthority::SignedSession {
            return self.observe_signed_node_liveness().await;
        }
        self.detect_legacy_lost_nodes_for_tests().await
    }

    /// Production liveness is the current signed AgentSession deadline,
    /// evaluated against the PostgreSQL clock. Expiry closes admission but is
    /// not Host fencing, so this observer never rewrites legacy Node/Cat rows
    /// or revokes storage claims.
    async fn observe_signed_node_liveness(&self) -> anyhow::Result<()> {
        let mut after = None;
        loop {
            let page_after = after.clone();
            let page = self
                .store
                .execute(move |store| store.list_runtime_node_liveness_after(page_after.as_ref()))
                .await?;
            for node in page.nodes {
                if node.live {
                    continue;
                }
                tracing::warn!(
                    node = %node.node_id,
                    session = ?node.session,
                    lease_deadline_unix_ms = ?node.lease_deadline_unix_ms.map(|value| value.get()),
                    evaluated_at_unix_ms = node.evaluated_at_unix_ms.get(),
                    last_accepted_observation_at_unix_ms = ?node.last_accepted_observation_at_unix_ms.map(|value| value.get()),
                    "signed Node session is absent or expired; admission remains closed until a current session accepts a new observation"
                );
            }
            let Some(next_after) = page.next_after else {
                return Ok(());
            };
            after = Some(next_after);
        }
    }

    /// Explicit compatibility harness for pre-cutover integration tests. The
    /// production server never selects this legacy heartbeat authority.
    async fn detect_legacy_lost_nodes_for_tests(&self) -> anyhow::Result<()> {
        let now = now_ms();
        if now < self.node_fencing_starts_at_ms {
            return Ok(());
        }
        let node_lease_timeout_ms = self.node_lease_timeout_ms;
        self.store
            .execute(move |store| {
                for node in store.list_nodes()? {
                    let fresh = now - node.last_heartbeat_unix * 1000 <= node_lease_timeout_ms;
                    if matches!(node.state, NodeState::Lost | NodeState::Fenced) || fresh {
                        continue;
                    }
                    tracing::warn!(
                        node = %node.id,
                        "node heartbeat expired; preserving claims until explicit fencing"
                    );
                    store.set_node_state(&node.id, NodeState::Lost)?;
                    for cat in store.cats_on_node(&node.id)? {
                        // Lost means unreachable, not dead. Keep placement, routes,
                        // and storage epochs so a transient partition cannot turn a
                        // healthy Guest's root disk read-only.
                        store.set_observed(&cat.id, ObservedState::Unknown)?;
                    }
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Complete a lost-Host handoff after an external actor has proved that
    /// the old Host is stopped or isolated. The API owns that explicit safety
    /// confirmation; this method performs the idempotent state transition.
    pub(crate) async fn confirm_node_fenced(&self, node_id: &str) -> anyhow::Result<()> {
        let node_id = node_id.to_string();
        let converge_node_id = node_id.clone();
        self.store
            .execute(move |store| {
                let node = store.get_node(&node_id)?;
                if !matches!(node.state, NodeState::Lost | NodeState::Fenced) {
                    return Err(ApiError::failed_precondition(format!(
                        "node {node_id} is neither Lost nor an idempotent Fenced retry"
                    )));
                }
                // Persist the terminal, unschedulable identity before revoking any
                // Cat. If a later volume operation fails, retrying the same action can
                // finish the remaining Cats without reviving this Host identity.
                store.set_node_state(&node_id, NodeState::Fenced)
            })
            .await?;
        tracing::warn!(
            node = converge_node_id,
            "external Host fencing confirmed; revoking Cat claims"
        );
        self.converge_fenced_node(&converge_node_id).await?;
        self.notify.notify_one();
        Ok(())
    }

    /// Resume any handoff whose external fencing confirmation was persisted
    /// before a controller crash or metadata outage interrupted convergence.
    async fn converge_confirmed_fences(&self) -> anyhow::Result<()> {
        let nodes = self.store.execute(|store| store.list_nodes()).await?;
        for node in nodes
            .into_iter()
            .filter(|node| node.state == NodeState::Fenced)
        {
            self.converge_fenced_node(&node.id).await?;
        }
        Ok(())
    }

    async fn converge_fenced_node(&self, node_id: &str) -> anyhow::Result<()> {
        let node_id = node_id.to_string();
        let cats = self
            .store
            .execute(move |store| store.cats_on_node(&node_id))
            .await?;
        for cat in cats {
            let cat_id = cat.id.clone();
            self.store
                .execute(move |store| store.set_observed(&cat_id, ObservedState::Unknown))
                .await?;
            let cat_id = cat.id;
            self.store
                .execute(move |store| {
                    store.unbind_routes(&cat_id)?;
                    store.set_placement(&cat_id, None)?;
                    store.set_observed(&cat_id, ObservedState::Cold)
                })
                .await?;
        }
        Ok(())
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
        let nodes = self.store.execute(|store| store.list_nodes()).await?;
        for node in nodes
            .into_iter()
            .filter(|node| node.state == NodeState::Draining)
        {
            let node_id = node.id.clone();
            let cats = self
                .store
                .execute(move |store| store.cats_on_node(&node_id))
                .await?;
            for cat in cats {
                let job = NodeJob {
                    job_id: nodejob::job_id(&cat.id, cat.generation, "drain_stop_cat"),
                    cat_generation: cat.generation,
                    action: NodeJobAction::StopCat {
                        cat_id: cat.id.clone(),
                        disposition: StopCatDisposition::Cold,
                    },
                };
                match self.dispatch(&node.agent_url, &job).await {
                    Ok(result) if result.phase == JobPhase::Succeeded => {
                        let cat_id = cat.id.clone();
                        self.store
                            .execute(move |store| store.unbind_routes(&cat_id))
                            .await?;
                        let cat_id = cat.id;
                        self.store
                            .execute(move |store| {
                                store.set_placement(&cat_id, None)?;
                                store.set_observed(&cat_id, ObservedState::Cold)
                            })
                            .await?;
                    }
                    Ok(result) => tracing::warn!(
                        node = %node.id,
                        cat = %cat.id,
                        error = ?result.error,
                        "node drain stop failed; will retry"
                    ),
                    Err(error) => tracing::warn!(
                        node = %node.id,
                        cat = %cat.id,
                        %error,
                        "node drain dispatch failed; will retry"
                    ),
                }
            }
            let node_id = node.id.clone();
            let orphans = self
                .store
                .execute(move |store| store.orphan_reported_cats(&node_id))
                .await?;
            for orphan in orphans {
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
                        // store every tick. Whether a stale local durability
                        // journal may be discarded is an explicit operator
                        // decision, never made by V1 reconciliation.
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
            let node_id = node.id;
            self.store
                .execute(move |store| {
                    if store.cats_on_node(&node_id)?.is_empty()
                        && store.orphan_reported_cats(&node_id)?.is_empty()
                    {
                        store.set_node_state(&node_id, NodeState::Cordoned)?;
                    }
                    Ok(())
                })
                .await?;
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
    fn defer_retry(&self, cat: &Cat) -> Duration {
        self.defer_retry_key(attempt_key(cat))
    }

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

    /// Forget any backoff for this Cat, because it made progress.
    fn clear_retry_backoff(&self, cat: &Cat) {
        self.clear_retry_backoff_key(&attempt_key(cat));
    }

    fn clear_retry_backoff_key(&self, key: &str) {
        self.retry_after.lock().unwrap().remove(key);
    }

    async fn reconcile_cat(&self, cat: &Cat) -> anyhow::Result<()> {
        // Stable state and operation completion are separate transactions.
        // A leader can disappear between them, so the Store deliberately
        // returns a converged Cat whose current-generation operation is still
        // active. Finish that operation without replaying physical node work.
        if lifecycle_converged(cat) {
            self.complete_ops_if_converged(&cat.id).await?;
            return Ok(());
        }
        // A source-preserving failure leaves the Cat exactly as it was, so the
        // next tick would re-dispatch the identical job. Honour its backoff
        // before doing anything, or a persistent failure spins.
        if self.retry_deferred(cat) {
            return Ok(());
        }
        if let Some(node_id) = &cat.node_id {
            let node_id = node_id.clone();
            let node = self
                .store
                .execute(move |store| store.get_node(&node_id))
                .await?;
            if matches!(node.state, NodeState::Lost | NodeState::Fenced) {
                // The owner remains authoritative while merely Lost. A
                // confirmed fence clears placement itself; until then no
                // lifecycle request may implicitly hand the Cat to a peer.
                return Ok(());
            }
        }
        use DesiredState as D;
        use ObservedState as O;
        match (cat.desired_state, cat.observed_state) {
            (D::Deleted, _) => self.delete_flow(cat).await,
            // Anything that needs compute first goes through the start flow.
            (D::Running | D::Suspended | D::Warm, O::Creating | O::Cold | O::Starting) => {
                self.start_flow(cat).await
            }
            (D::Running | D::Suspended | D::Warm, O::Failed) => {
                // Failed is a stable terminal result for this generation.
                // A user action creates a new-generation pending Operation,
                // which explicitly authorizes a retry.
                let cat_id = cat.id.clone();
                let retry_requested = self
                    .store
                    .execute(move |store| store.pending_operations_for(&cat_id))
                    .await?
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
            (D::Cold, O::Running | O::Suspended | O::Warm | O::Starting | O::Stopping) => {
                self.stop_flow(cat, StopCatDisposition::Cold).await
            }
            // Unknown clears when the owning node reports a complete,
            // same-generation inventory or an explicit Host fence converges
            // the Cat through Cold.
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

    async fn volume_grants(&self, cat: &Cat) -> anyhow::Result<Vec<VolumeGrant>> {
        let cat_id = cat.id.clone();
        let workspace_id = cat.workspace_id.clone();
        let bindings = self
            .store
            .execute(move |store| {
                store
                    .bindings_for_cat(&cat_id)?
                    .into_iter()
                    .map(|binding| {
                        let disk = store.get_disk(&workspace_id, &binding.disk_id)?;
                        Ok((binding, disk))
                    })
                    .collect::<crate::store::Result<Vec<_>>>()
            })
            .await?;
        let mut grants = Vec::with_capacity(bindings.len());
        for (binding, disk) in bindings {
            let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
            match self
                .retired_storage_meta()?
                .create_volume(&disk.volume_id, size)
            {
                Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
                Err(e) => return Err(e.into()),
            }
            grants.push(VolumeGrant {
                disk_id: disk.id.clone(),
                volume_id: disk.volume_id.clone(),
                attachment_id: format!("att_{}_{}_{}", cat.id, disk.id, cat.generation),
                epoch: 0,
                size_bytes: size,
                mount_path: binding.mount_path,
                durability: disk.durability,
            });
        }
        // Root disk first (mount path "/").
        grants.sort_by_key(|g| g.mount_path != "/");
        Ok(grants)
    }

    async fn start_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        // `Starting` is the durable dispatch boundary. Once it is persisted, a
        // StartCat may already be running (or its successful response may have
        // been lost), so replay only the same deterministic job on the same
        // claimed node and never revoke its newly acquired disk epoch.
        let replaying_dispatch =
            cat.observed_state == ObservedState::Starting && cat.node_id.is_some();
        let node = if let Some(node_id) = &cat.node_id {
            let node_id = node_id.clone();
            self.store
                .execute(move |store| store.get_node(&node_id))
                .await?
        } else {
            // Choosing a node and claiming its capacity is one step, so several
            // start flows can run at once without overcommitting one node.
            let cat_id = cat.id.clone();
            let cpus = cat.spec.cpus;
            let memory_mib = cat.spec.memory_mib;
            let node_lease_timeout_ms = self.node_lease_timeout_ms;
            let Some(node) = self
                .store
                .execute(move |store| {
                    store.claim_node_for(&cat_id, cpus, memory_mib, node_lease_timeout_ms, now_ms())
                })
                .await?
            else {
                tracing::info!(cat = %cat.id, "no schedulable node; will retry");
                return Ok(());
            };
            node
        };

        let grants = self.volume_grants(cat).await?;
        if !replaying_dispatch {
            let cat_id = cat.id.clone();
            self.store
                .execute(move |store| store.set_observed(&cat_id, ObservedState::Starting))
                .await?;
        }

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
        match self.dispatch(&node.agent_url, &job).await {
            Ok(res) if res.phase == JobPhase::Succeeded => {
                let cat_id = cat.id.clone();
                let node_id = node.id;
                let gateway_url = node.gateway_url;
                self.store
                    .execute(move |store| {
                        store.set_observed(&cat_id, ObservedState::Running)?;
                        store.publish_routes(&cat_id, &node_id, &gateway_url)
                    })
                    .await?;
                self.attempts.lock().unwrap().remove(&attempt_key(cat));
                self.clear_retry_backoff(cat);
                self.complete_ops_if_converged(&cat.id).await?;
                Ok(())
            }
            Ok(res) => self.start_failed(cat, res.error.unwrap_or_default()).await,
            Err(error) => {
                // Transport/protocol failure is ambiguous: the Host may have
                // completed StartCat. Keep placement + Starting and replay the
                // same idempotent job next tick; moving elsewhere would revoke
                // a live root-disk epoch and turn the old Guest read-only.
                tracing::warn!(
                    cat = %cat.id,
                    node = %node.id,
                    %error,
                    "StartCat result unknown; retaining claim for same-node retry"
                );
                Ok(())
            }
        }
    }

    async fn start_failed(&self, cat: &Cat, error: String) -> anyhow::Result<()> {
        tracing::warn!(cat = %cat.id, "start failed: {error}");
        let give_up = {
            let mut attempts = self.attempts.lock().unwrap();
            let n = attempts.entry(attempt_key(cat)).or_insert(0);
            *n += 1;
            *n >= 3
        };
        let cat_id = cat.id.clone();
        self.store
            .execute(move |store| {
                store.set_placement(&cat_id, None)?;
                if give_up {
                    store.set_observed(&cat_id, ObservedState::Failed)?;
                    for operation in store.pending_operations_for(&cat_id)? {
                        store.finish_operation(
                            &operation.id,
                            Some(&ErrorBody::new(
                                cats_api::error::ErrorCode::Unavailable,
                                format!("start failed after retries: {error}"),
                            )),
                        )?;
                    }
                } else {
                    store.set_observed(&cat_id, ObservedState::Cold)?;
                }
                Ok(())
            })
            .await?;
        if !give_up {
            self.notify.notify_one();
        }
        Ok(())
    }

    /// suspend / resume / warm / restore on the current node, with the
    /// ADR-0002 rule: any resume/restore failure falls back to Cold.
    async fn simple_transition(&self, cat: &Cat, action: &str) -> anyhow::Result<()> {
        let transition_started = std::time::Instant::now();
        let Some(node_id) = &cat.node_id else {
            // Placement lost (e.g. host fenced) - converge through Cold.
            let cat_id = cat.id.clone();
            self.store
                .execute(move |store| store.set_observed(&cat_id, ObservedState::Cold))
                .await?;
            return Ok(());
        };
        let query_node_id = node_id.clone();
        let query_cat_id = cat.id.clone();
        let needs_work_fence = action == "suspend";
        let node = self
            .store
            .execute(move |store| {
                let node = store
                    .list_nodes()?
                    .into_iter()
                    .find(|node| node.id == query_node_id)
                    .ok_or_else(|| ApiError::not_found(format!("node {query_node_id}")))?;
                let work_fence = needs_work_fence
                    .then(|| store.suspend_work_fence(&query_cat_id))
                    .transpose()?;
                Ok((node, work_fence))
            })
            .await?;
        let (node, work_fence) = node;

        let (job_action, transitional, target): (NodeJobAction, ObservedState, ObservedState) =
            match action {
                "suspend" => (
                    NodeJobAction::SuspendCat {
                        cat_id: cat.id.clone(),
                        work_fence,
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
        if cat.observed_state != transitional {
            let cat_id = cat.id.clone();
            self.store
                .execute(move |store| store.set_observed(&cat_id, transitional))
                .await?;
        }
        let job = NodeJob {
            job_id: nodejob::job_id(&cat.id, cat.generation, job_action.kind()),
            cat_generation: cat.generation,
            action: job_action,
        };
        let dispatch_started = std::time::Instant::now();
        let dispatched = self.dispatch(&node.agent_url, &job).await;
        tracing::info!(
            cat = %cat.id,
            action,
            setup_us = dispatch_started.duration_since(transition_started).as_micros(),
            dispatch_us = dispatch_started.elapsed().as_micros(),
            "lifecycle transition dispatch timings"
        );
        match dispatched {
            Ok(res) if res.phase == JobPhase::Succeeded => {
                let cat_id = cat.id.clone();
                let node_id = node.id.clone();
                let gateway_url = node.gateway_url.clone();
                self.store
                    .execute(move |store| {
                        let recorded = store.finish_transition(&cat_id, transitional, target)?;
                        if recorded && target == ObservedState::Running {
                            store.publish_routes(&cat_id, &node_id, &gateway_url)?;
                        }
                        Ok(())
                    })
                    .await?;
                self.clear_retry_backoff(cat);
                self.complete_ops_if_converged(&cat.id).await?;
                self.notify.notify_one();
                Ok(())
            }
            Ok(res) if res.phase == JobPhase::Rejected && action == "suspend" => {
                tracing::info!(cat = %cat.id, "suspend cancelled because work changed");
                let cat_id = cat.id.clone();
                let generation = cat.generation;
                self.store
                    .execute(move |store| store.cancel_rejected_suspend(&cat_id, generation))
                    .await?;
                self.notify.notify_one();
                Ok(())
            }
            Ok(res) if action == "warm" => {
                let err = res.error.unwrap_or_default();
                // Warm creation is a source-preserving transition. In
                // particular, a failed mandatory relaxed drain must keep the
                // Host-local journal and lease alive for retry; a destructive
                // Cold fallback here would turn a remote outage into data loss.
                // Trust only the legal pre-Warm state reported by the node. A
                // failure after the VM reached Warm must remain Warming so a
                // later retry can finish the same generation-derived job.
                let retained = if res.observed_state == ObservedState::Suspended {
                    ObservedState::Suspended
                } else {
                    transitional
                };
                let cat_id = cat.id.clone();
                self.store
                    .execute(move |store| store.set_observed(&cat_id, retained))
                    .await?;
                let retry_in = self.defer_retry(cat);
                tracing::warn!(
                    cat = %cat.id,
                    ?retained,
                    retry_in_ms = retry_in.as_millis(),
                    "warm transition failed: {err}; retaining source state for retry"
                );
                Ok(())
            }
            Err(e) if action == "warm" => {
                // The node may have completed Warm before the response was
                // lost. Preserve the durable dispatch boundary and replay the
                // same job id; reverting to Suspended would claim more than the
                // control plane knows.
                let retry_in = self.defer_retry(cat);
                tracing::warn!(
                    cat = %cat.id,
                    retry_in_ms = retry_in.as_millis(),
                    "warm dispatch failed: {e}; retaining Warming for retry"
                );
                Ok(())
            }
            other => {
                let err = match other {
                    Ok(res) => res.error.unwrap_or_default(),
                    Err(e) => e.to_string(),
                };
                tracing::warn!(cat = %cat.id, action, "transition failed: {err}; falling back to Cold");
                // ADR-0002: converge to a clean Cold fallback.
                let cleanup = NodeJob {
                    job_id: nodejob::job_id(&cat.id, cat.generation, "cleanup_cat"),
                    cat_generation: cat.generation,
                    action: NodeJobAction::CleanupCat {
                        cat_id: cat.id.clone(),
                    },
                };
                let _ = self.dispatch(&node.agent_url, &cleanup).await;
                let cat_id = cat.id.clone();
                self.store
                    .execute(move |store| {
                        store.unbind_routes(&cat_id)?;
                        store.set_placement(&cat_id, None)?;
                        store.set_observed(&cat_id, ObservedState::Cold)
                    })
                    .await?;
                self.clear_retry_backoff(cat);
                self.notify.notify_one();
                Ok(())
            }
        }
    }

    async fn stop_flow(&self, cat: &Cat, disposition: StopCatDisposition) -> anyhow::Result<()> {
        let Some(node_id) = &cat.node_id else {
            let cat_id = cat.id.clone();
            self.store
                .execute(move |store| store.set_observed(&cat_id, ObservedState::Cold))
                .await?;
            self.complete_ops_if_converged(&cat.id).await?;
            return Ok(());
        };
        let query_node_id = node_id.clone();
        let node = self
            .store
            .execute(move |store| {
                Ok(store
                    .list_nodes()?
                    .into_iter()
                    .find(|node| node.id == query_node_id))
            })
            .await?;
        if cat.observed_state != ObservedState::Stopping {
            let cat_id = cat.id.clone();
            self.store
                .execute(move |store| store.set_observed(&cat_id, ObservedState::Stopping))
                .await?;
        }
        if let Some(node) = node {
            let job = NodeJob {
                job_id: nodejob::job_id(&cat.id, cat.generation, "stop_cat"),
                cat_generation: cat.generation,
                action: NodeJobAction::StopCat {
                    cat_id: cat.id.clone(),
                    disposition,
                },
            };
            match self.dispatch(&node.agent_url, &job).await {
                Ok(res) if res.phase == JobPhase::Succeeded => {}
                Ok(res) => {
                    // Restore only a stable state that can be the source of a
                    // StopCat request. Anything else may mean the Host stopped
                    // the VM before returning a failed result, so retain the
                    // durable Stopping boundary and retry the same job id.
                    let retained = match res.observed_state {
                        ObservedState::Running | ObservedState::Suspended | ObservedState::Warm => {
                            res.observed_state
                        }
                        _ => ObservedState::Stopping,
                    };
                    let cat_id = cat.id.clone();
                    self.store
                        .execute(move |store| store.set_observed(&cat_id, retained))
                        .await?;
                    let retry_in = self.defer_retry(cat);
                    tracing::warn!(
                        cat = %cat.id,
                        ?retained,
                        retry_in_ms = retry_in.as_millis(),
                        "stop job failed: {:?}; retaining source state for retry",
                        res.error
                    );
                    return Ok(());
                }
                Err(e) => {
                    // A lost response is ambiguous: the node may have already
                    // stopped the Cat. Keep Stopping so a successor replays the
                    // deterministic job instead of asserting the stale source.
                    let retry_in = self.defer_retry(cat);
                    tracing::warn!(
                        cat = %cat.id,
                        retry_in_ms = retry_in.as_millis(),
                        "stop dispatch failed: {e}; retaining Stopping for retry"
                    );
                    return Ok(());
                }
            }
        }
        let cat_id = cat.id.clone();
        self.store
            .execute(move |store| store.unbind_routes(&cat_id))
            .await?;
        let cat_id = cat.id.clone();
        self.store
            .execute(move |store| {
                store.set_placement(&cat_id, None)?;
                store.set_observed(&cat_id, ObservedState::Cold)
            })
            .await?;
        self.clear_retry_backoff(cat);
        self.complete_ops_if_converged(&cat.id).await?;
        Ok(())
    }

    async fn delete_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        if cat.node_id.is_some() {
            // Stop first (also unbinds routes). The RootDisk is being
            // deleted, so the node may discard only its local journal/cache;
            // PersistentDisks still cross the mandatory remote-drain boundary.
            let mut disposable_root_disk_ids = Vec::new();
            let mut retained_persistent_disk_ids = Vec::new();
            let cat_id = cat.id.clone();
            let disks = self
                .store
                .execute(move |store| store.list_disks_for_cat(&cat_id))
                .await?;
            for disk in disks {
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
            let cat_id = cat.id.clone();
            let current = self
                .store
                .execute(move |store| store.must_get_cat_by_id(&cat_id))
                .await?;
            if current.node_id.is_some() || current.observed_state != ObservedState::Cold {
                // Graceful stop (including its mandatory remote drain) has not
                // completed. Keep every disk and retry the delete flow later.
                return Ok(());
            }
        }
        // Root disk dies with the cat; persistent disks return to Available.
        let cat_id = cat.id.clone();
        let workspace_id = cat.workspace_id.clone();
        let disks = self
            .store
            .execute(move |store| {
                store
                    .bindings_for_cat(&cat_id)?
                    .into_iter()
                    .map(|binding| {
                        let disk = store.get_disk(&workspace_id, &binding.disk_id)?;
                        store.unbind_disk(&disk.id)?;
                        Ok(disk)
                    })
                    .collect::<crate::store::Result<Vec<_>>>()
            })
            .await?;
        for disk in disks {
            if disk.kind == DiskKind::Root {
                match self.retired_storage_meta()?.delete_volume(&disk.volume_id) {
                    Ok(()) | Err(MetaError::NotFound(_)) => {}
                    Err(e) => return Err(e.into()),
                }
                let disk_id = disk.id;
                self.store
                    .execute(move |store| store.delete_disk_row(&disk_id))
                    .await?;
            }
        }
        let cat_id = cat.id.clone();
        self.store
            .execute(move |store| {
                for operation in store.pending_operations_for(&cat_id)? {
                    store.finish_operation(&operation.id, None)?;
                }
                store.delete_cat_row(&cat_id)
            })
            .await?;
        Ok(())
    }

    async fn complete_ops_if_converged(&self, cat_id: &str) -> anyhow::Result<()> {
        let cat_id = cat_id.to_string();
        self.store
            .execute(move |store| {
                let cat = store.must_get_cat_by_id(&cat_id)?;
                if lifecycle_converged(&cat) {
                    for operation in store.pending_lifecycle_operations_for(&cat_id)? {
                        if operation.resource_generation <= cat.generation {
                            store.finish_operation(&operation.id, None)?;
                        }
                    }
                }
                Ok(())
            })
            .await?;
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

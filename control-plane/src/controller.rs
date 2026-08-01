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
use cats_api::nodejob::{self, JobPhase, NodeJob, NodeJobAction, NodeJobResult, VolumeGrant};
use cats_api::resources::*;
use cats_storage::{MetaError, MetadataStore};
use futures_util::StreamExt;

use crate::store::{now_ms, Store};

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
}

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
        for cat in self.store.cats_on_node(node_id)? {
            self.store.set_observed(&cat.id, ObservedState::Unknown)?;
            self.fence_cat_volumes(&cat).await?;
            self.store.unbind_routes(&cat.id)?;
            self.store.set_placement(&cat.id, None)?;
            self.store.set_observed(&cat.id, ObservedState::Cold)?;
        }
        Ok(())
    }

    async fn fence_cat_volumes(&self, cat: &Cat) -> anyhow::Result<()> {
        for disk in self.store.list_disks_for_cat(&cat.id)? {
            match self.storage_meta.revoke_lease(&disk.volume_id) {
                Ok(()) | Err(MetaError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Evacuate every Cat from nodes explicitly placed in Draining. Desired
    /// Cat state is preserved: Running Cats cold-start elsewhere, while
    /// Suspended/Warm Cats re-establish their requested host-bound state on a
    /// healthy node. A drain only becomes Cordoned after placement is empty.
    async fn drain_nodes(&self) -> anyhow::Result<()> {
        for node in self
            .store
            .list_nodes()?
            .into_iter()
            .filter(|node| node.state == NodeState::Draining)
        {
            for cat in self.store.cats_on_node(&node.id)? {
                let job = NodeJob {
                    job_id: nodejob::job_id(&cat.id, cat.generation, "drain_stop_cat"),
                    cat_generation: cat.generation,
                    action: NodeJobAction::StopCat {
                        cat_id: cat.id.clone(),
                    },
                };
                match self.dispatch(&node.agent_url, &job).await {
                    Ok(result) if result.phase == JobPhase::Succeeded => {
                        self.store.unbind_routes(&cat.id)?;
                        self.fence_cat_volumes(&cat).await?;
                        self.store.set_placement(&cat.id, None)?;
                        self.store.set_observed(&cat.id, ObservedState::Cold)?;
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
            if self.store.cats_on_node(&node.id)?.is_empty() {
                self.store.set_node_state(&node.id, NodeState::Cordoned)?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Per-cat reconcile
    // ------------------------------------------------------------------

    async fn reconcile_cat(&self, cat: &Cat) -> anyhow::Result<()> {
        if let Some(node_id) = &cat.node_id {
            let node = self.store.get_node(node_id)?;
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
            (D::Suspended, O::Running) => self.simple_transition(cat, "suspend").await,
            (D::Warm, O::Running) => self.simple_transition(cat, "suspend").await,
            (D::Warm, O::Suspended) => self.simple_transition(cat, "warm").await,
            (D::Suspended, O::Warm) => self.simple_transition(cat, "restore").await,
            (D::Cold, O::Running | O::Suspended | O::Warm | O::Starting) => {
                self.stop_flow(cat).await
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
        // `Starting` is the durable dispatch boundary. Once it is persisted, a
        // StartCat may already be running (or its successful response may have
        // been lost), so replay only the same deterministic job on the same
        // claimed node and never revoke its newly acquired disk epoch.
        let replaying_dispatch =
            cat.observed_state == ObservedState::Starting && cat.node_id.is_some();
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

        let grants = self.volume_grants(cat).await?;
        if !replaying_dispatch {
            // Fence stale writers before crossing the durable dispatch
            // boundary. A crash before `Starting` can safely repeat this step;
            // a crash after it must preserve the epoch a live blockd may hold.
            self.fence_cat_volumes(cat).await?;
            self.store.set_observed(&cat.id, ObservedState::Starting)?;
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
                self.store.set_observed(&cat.id, ObservedState::Running)?;
                self.store
                    .publish_routes(&cat.id, &node.id, &node.gateway_url)?;
                self.attempts.lock().unwrap().remove(&attempt_key(cat));
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
        let mut attempts = self.attempts.lock().unwrap();
        let n = attempts.entry(attempt_key(cat)).or_insert(0);
        *n += 1;
        let give_up = *n >= 3;
        drop(attempts);
        self.store.set_placement(&cat.id, None)?;
        if give_up {
            self.store.set_observed(&cat.id, ObservedState::Failed)?;
            for op in self.store.pending_operations_for(&cat.id)? {
                self.store.finish_operation(
                    &op.id,
                    Some(&ErrorBody::new(
                        cats_api::error::ErrorCode::Unavailable,
                        format!("start failed after retries: {error}"),
                    )),
                )?;
            }
        } else {
            self.store.set_observed(&cat.id, ObservedState::Cold)?;
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
            self.store.set_observed(&cat.id, ObservedState::Cold)?;
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
        self.store.set_observed(&cat.id, transitional)?;
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
                let recorded = self
                    .store
                    .finish_transition(&cat.id, transitional, target)?;
                if recorded && target == ObservedState::Running {
                    self.store
                        .publish_routes(&cat.id, &node.id, &node.gateway_url)?;
                }
                self.complete_ops_if_converged(&cat.id).await?;
                self.notify.notify_one();
                Ok(())
            }
            Ok(res) if res.phase == JobPhase::Rejected && action == "suspend" => {
                tracing::info!(cat = %cat.id, "suspend cancelled because work changed");
                self.store
                    .cancel_rejected_suspend(&cat.id, cat.generation)?;
                self.notify.notify_one();
                Ok(())
            }
            other if action == "warm" => {
                let err = match other {
                    Ok(res) => res.error.unwrap_or_default(),
                    Err(e) => e.to_string(),
                };
                // Warm creation is a source-preserving transition. In
                // particular, a failed mandatory relaxed drain must keep the
                // Host-local journal and lease alive for retry; a destructive
                // Cold fallback here would turn a remote outage into data loss.
                tracing::warn!(
                    cat = %cat.id,
                    "warm transition failed: {err}; retaining source state for retry"
                );
                self.store.set_observed(&cat.id, cat.observed_state)?;
                self.notify.notify_one();
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
                self.fence_cat_volumes(cat).await?;
                self.store.unbind_routes(&cat.id)?;
                self.store.set_placement(&cat.id, None)?;
                self.store.set_observed(&cat.id, ObservedState::Cold)?;
                self.notify.notify_one();
                Ok(())
            }
        }
    }

    async fn stop_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        let Some(node_id) = &cat.node_id else {
            self.store.set_observed(&cat.id, ObservedState::Cold)?;
            self.complete_ops_if_converged(&cat.id).await?;
            return Ok(());
        };
        let node = self
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| &n.id == node_id);
        self.store.set_observed(&cat.id, ObservedState::Stopping)?;
        if let Some(node) = node {
            let job = NodeJob {
                job_id: nodejob::job_id(&cat.id, cat.generation, "stop_cat"),
                cat_generation: cat.generation,
                action: NodeJobAction::StopCat {
                    cat_id: cat.id.clone(),
                },
            };
            match self.dispatch(&node.agent_url, &job).await {
                Ok(res) if res.phase == JobPhase::Succeeded => {}
                Ok(res) => {
                    tracing::warn!(cat = %cat.id, "stop job failed: {:?}; retaining source state for retry", res.error);
                    self.store.set_observed(&cat.id, cat.observed_state)?;
                    self.notify.notify_one();
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(cat = %cat.id, "stop dispatch failed: {e}; retrying next tick");
                    self.store.set_observed(&cat.id, cat.observed_state)?;
                    self.notify.notify_one();
                    return Ok(());
                }
            }
        }
        self.store.unbind_routes(&cat.id)?;
        self.fence_cat_volumes(cat).await?;
        self.store.set_placement(&cat.id, None)?;
        self.store.set_observed(&cat.id, ObservedState::Cold)?;
        self.complete_ops_if_converged(&cat.id).await?;
        Ok(())
    }

    async fn delete_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        if cat.node_id.is_some() {
            // Stop first (also fences + unbinds routes).
            self.stop_flow(cat).await?;
            let current = self.store.must_get_cat_by_id(&cat.id)?;
            if current.node_id.is_some() || current.observed_state != ObservedState::Cold {
                // Graceful stop (including its mandatory remote drain) has not
                // completed. Keep every disk and retry the delete flow later.
                return Ok(());
            }
        }
        // Root disk dies with the cat; persistent disks return to Available.
        for binding in self.store.bindings_for_cat(&cat.id)? {
            let disk = self.store.get_disk(&cat.workspace_id, &binding.disk_id)?;
            self.store.unbind_disk(&disk.id)?;
            if disk.kind == DiskKind::Root {
                match self.storage_meta.delete_volume(&disk.volume_id) {
                    Ok(()) | Err(MetaError::NotFound(_)) => {}
                    Err(e) => return Err(e.into()),
                }
                self.store.delete_disk_row(&disk.id)?;
            }
        }
        for op in self.store.pending_operations_for(&cat.id)? {
            self.store.finish_operation(&op.id, None)?;
        }
        self.store.delete_cat_row(&cat.id)?;
        Ok(())
    }

    async fn complete_ops_if_converged(&self, cat_id: &str) -> anyhow::Result<()> {
        let cat = self.store.must_get_cat_by_id(cat_id)?;
        let converged = matches!(
            (cat.desired_state, cat.observed_state),
            (DesiredState::Running, ObservedState::Running)
                | (DesiredState::Suspended, ObservedState::Suspended)
                | (DesiredState::Warm, ObservedState::Warm)
                | (DesiredState::Cold, ObservedState::Cold)
        );
        if converged {
            for op in self.store.pending_operations_for(cat_id)? {
                if op.resource_generation <= cat.generation {
                    self.store.finish_operation(&op.id, None)?;
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Scheduler: filter + least-loaded score (arch doc §13.2, minimal)
    // ------------------------------------------------------------------

    /// Which node *would* take this Cat, without claiming anything. Placement
    /// itself goes through `Store::claim_node_for`, which decides and claims in
    /// one step; this is for callers that only want to look.
    pub fn schedule(&self, cat: &Cat) -> crate::store::Result<Option<Node>> {
        let now = now_ms();
        let mut candidates = Vec::new();
        for node in self.store.list_nodes()? {
            if node.state != NodeState::Ready {
                continue;
            }
            if now - node.last_heartbeat_unix * 1000 > self.node_lease_timeout_ms {
                continue;
            }
            let mut used_cpus = 0u32;
            let mut used_mem = 0u64;
            for c in self.store.cats_on_node(&node.id)? {
                if c.id == cat.id {
                    continue;
                }
                used_cpus += c.spec.cpus;
                used_mem += c.spec.memory_mib;
            }
            if used_cpus + cat.spec.cpus <= node.capacity.cpus
                && used_mem + cat.spec.memory_mib <= node.capacity.memory_mib
            {
                candidates.push((used_mem, node));
            }
        }
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
        Ok(candidates.into_iter().next().map(|(_, n)| n))
    }
}

fn attempt_key(cat: &Cat) -> String {
    format!("{}@{}", cat.id, cat.generation)
}

//! Level-triggered reconciler: converges every cat's observed state to its
//! desired state by dispatching idempotent jobs to node agents, handles node
//! loss with lease fencing, and completes operations.
//!
//! Invariants owned here (arch doc §6/§8, ADR-0002/0003):
//! - a cat is started on a node only after every one of its volumes' stale
//!   leases has been revoked (fence before double-start);
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

use crate::store::{now_ms, Store};

pub struct Controller {
    pub store: Arc<Store>,
    pub storage_meta: Arc<dyn MetadataStore>,
    pub http: reqwest::Client,
    pub notify: Arc<tokio::sync::Notify>,
    pub node_lease_timeout_ms: i64,
    pub auth_token: String,
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
        self.fence_lost_nodes().await?;
        let cats = self.store.cats_needing_work()?;
        for cat in cats {
            if let Err(e) = self.reconcile_cat(&cat).await {
                tracing::warn!(cat = %cat.id, "reconcile failed: {e}");
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Node loss / fencing
    // ------------------------------------------------------------------

    async fn fence_lost_nodes(&self) -> anyhow::Result<()> {
        let now = now_ms();
        for node in self.store.list_nodes()? {
            let fresh = now - node.last_heartbeat_unix * 1000 <= self.node_lease_timeout_ms;
            if node.state == NodeState::Lost || fresh {
                continue;
            }
            tracing::warn!(node = %node.id, "node lease expired; fencing");
            self.store.set_node_state(&node.id, NodeState::Lost)?;
            for cat in self.store.cats_on_node(&node.id)? {
                // Memory states die with the host (ADR-0002): fence the
                // volumes, drop the placement, converge through Cold.
                self.store.set_observed(&cat.id, ObservedState::Unknown)?;
                self.fence_cat_volumes(&cat).await?;
                self.store.unbind_routes(&cat.id)?;
                self.store.set_placement(&cat.id, None)?;
                self.store.set_observed(&cat.id, ObservedState::Cold)?;
            }
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

    // ------------------------------------------------------------------
    // Per-cat reconcile
    // ------------------------------------------------------------------

    async fn reconcile_cat(&self, cat: &Cat) -> anyhow::Result<()> {
        use DesiredState as D;
        use ObservedState as O;
        match (cat.desired_state, cat.observed_state) {
            (D::Deleted, _) => self.delete_flow(cat).await,
            // Anything that needs compute first goes through the start flow.
            (
                D::Running | D::Suspended | D::Warm,
                O::Creating | O::Cold | O::Failed | O::Starting,
            ) => self.start_flow(cat).await,
            (D::Running, O::Suspended) => self.simple_transition(cat, "resume").await,
            (D::Running, O::Warm) => self.simple_transition(cat, "restore").await,
            (D::Suspended, O::Running) => self.simple_transition(cat, "suspend").await,
            (D::Warm, O::Running) => self.simple_transition(cat, "suspend").await,
            (D::Warm, O::Suspended) => self.simple_transition(cat, "warm").await,
            (D::Suspended, O::Warm) => self.simple_transition(cat, "restore").await,
            (D::Cold, O::Running | O::Suspended | O::Warm | O::Starting) => {
                self.stop_flow(cat).await
            }
            // Unknown clears via fence_lost_nodes; transitional states are
            // re-driven by their owning flow on the next tick.
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
            let disk = self.store.get_disk(&cat.project, &b.disk_id)?;
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
            });
        }
        // Root disk first (mount path "/").
        grants.sort_by_key(|g| g.mount_path != "/");
        Ok(grants)
    }

    async fn start_flow(&self, cat: &Cat) -> anyhow::Result<()> {
        let Some(node) = self.schedule(cat)? else {
            tracing::info!(cat = %cat.id, "no schedulable node; will retry");
            return Ok(());
        };
        self.store.set_placement(&cat.id, Some(&node.id))?;
        self.store.set_observed(&cat.id, ObservedState::Starting)?;

        let grants = self.volume_grants(cat).await?;
        // Fence any stale writer before handing the volumes to a new node.
        self.fence_cat_volumes(cat).await?;

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
            Err(e) => self.start_failed(cat, e.to_string()).await,
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
        match self.dispatch(&node.agent_url, &job).await {
            Ok(res) if res.phase == JobPhase::Succeeded => {
                self.store.set_observed(&cat.id, target)?;
                if target == ObservedState::Running {
                    self.store
                        .publish_routes(&cat.id, &node.id, &node.gateway_url)?;
                }
                self.complete_ops_if_converged(&cat.id).await?;
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
                Ok(res) => tracing::warn!(cat = %cat.id, "stop job failed: {:?}", res.error),
                Err(e) => {
                    tracing::warn!(cat = %cat.id, "stop dispatch failed: {e}; retrying next tick");
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
        }
        // Root disk dies with the cat; persistent disks return to Available.
        for binding in self.store.bindings_for_cat(&cat.id)? {
            let disk = self.store.get_disk(&cat.project, &binding.disk_id)?;
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

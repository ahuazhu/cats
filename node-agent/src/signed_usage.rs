//! Usage sampling bound to accepted signed Runtime observations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::metering::{CatUsageCheckpoint, USAGE_CHECKPOINTS_PATH};
use cats_api::runtime_reconciliation::{
    AgentSession, DesiredRuntimeSpec, NodeObservation, ProcessRole, SessionBinding, StableState,
};
use cats_metering::{RuntimeMeterAccumulator, RuntimeMeterAccumulatorSnapshot};

use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
};
use crate::usage_delivery::{deliver_usage_batches, session_binding, UsageDeliveryState};
use crate::usage_spool::{PendingUsageFinal, UsageSpool};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(10);
const DELIVERY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedMeterTarget {
    cat_id: String,
    generation: i64,
    source_epoch: String,
    cgroups: Vec<PathBuf>,
}

struct PendingFinalCandidate {
    cat_id: String,
    target_json: String,
    accumulator: RuntimeMeterAccumulatorSnapshot,
    checkpoints: Vec<CatUsageCheckpoint>,
}

struct SignedMeterState {
    target: SignedMeterTarget,
    accumulator: RuntimeMeterAccumulator,
    last_checkpoint_at: Option<Instant>,
    active: bool,
}

struct SignedUsageSampler {
    node_id: String,
    session: SessionBinding,
    systemd_cgroup_root: PathBuf,
    meters: BTreeMap<String, SignedMeterState>,
}

impl SignedUsageSampler {
    fn new(session: SessionBinding, systemd_cgroup_root: PathBuf) -> Self {
        Self {
            node_id: session.node_id.to_string(),
            session,
            systemd_cgroup_root,
            meters: BTreeMap::new(),
        }
    }

    fn update_observation(
        &mut self,
        observation: &NodeObservation,
        spool: &UsageSpool,
    ) -> anyhow::Result<(Vec<CatUsageCheckpoint>, bool)> {
        anyhow::ensure!(
            observation.complete_inventory
                && observation.node_id == self.session.node_id
                && observation.node_boot_id == self.session.node_boot_id
                && observation.agent_instance_id == self.session.agent_instance_id
                && observation.agent_session_epoch == self.session.agent_session_epoch,
            "usage target update is not bound to the accepted complete AgentSession inventory"
        );
        let mut next = BTreeMap::new();
        for runtime in &observation.runtimes {
            let Some(target) = self.target_for_runtime(runtime)? else {
                continue;
            };
            anyhow::ensure!(
                next.insert(target.cat_id.clone(), target).is_none(),
                "accepted observation contains duplicate usage targets"
            );
        }
        let now = Instant::now();
        let observed_at_unix_ms = now_unix_ms()?;
        let mut checkpoints = Vec::new();
        let promoted_pending = self.resolve_pending(&next, spool)?;
        for (cat_id, meter) in &mut self.meters {
            let remains_same = next
                .get(cat_id)
                .is_some_and(|target| target == &meter.target);
            if meter.active && !remains_same {
                checkpoints.extend(sample_meter(meter, now, observed_at_unix_ms, true)?);
                meter.active = false;
            }
        }
        for (cat_id, target) in next {
            match self.meters.get_mut(&cat_id) {
                Some(meter) if meter.target == target => meter.active = true,
                Some(meter) => {
                    *meter = new_meter(&self.node_id, target)?;
                }
                None => {
                    self.meters
                        .insert(cat_id, new_meter(&self.node_id, target)?);
                }
            }
        }
        Ok((checkpoints, promoted_pending))
    }

    fn resolve_pending(
        &mut self,
        next: &BTreeMap<String, SignedMeterTarget>,
        spool: &UsageSpool,
    ) -> anyhow::Result<bool> {
        for target in next.values() {
            let source_id = format!("node/{}/cat/{}", self.node_id, target.cat_id);
            anyhow::ensure!(
                !spool.source_was_promoted(&source_id, &target.source_epoch)?,
                "accepted observation attempted to reopen promoted Usage source epoch {}",
                target.source_epoch
            );
        }
        let mut promoted_pending = false;
        for pending in spool.pending_finals()? {
            let target: SignedMeterTarget = serde_json::from_str(&pending.target_json)
                .context("decode pending signed Usage target")?;
            anyhow::ensure!(
                target.cat_id == pending.cat_id,
                "pending signed Usage target Cat does not match its key"
            );
            let remains_same = next
                .get(&pending.cat_id)
                .is_some_and(|candidate| candidate == &target);
            if remains_same {
                match self.meters.get_mut(&pending.cat_id) {
                    Some(meter) => {
                        anyhow::ensure!(
                            meter.target == target
                                && meter.accumulator.snapshot() == pending.accumulator,
                            "pending signed Usage resume conflicts with the live accumulator"
                        );
                    }
                    None => {
                        self.meters.insert(
                            pending.cat_id.clone(),
                            restored_meter(&self.node_id, target, &pending)?,
                        );
                    }
                }
                spool.cancel_pending_final(&pending.cat_id, &pending.target_json)?;
                self.meters
                    .get_mut(&pending.cat_id)
                    .context("resumed signed Usage meter vanished")?
                    .active = true;
            } else {
                anyhow::ensure!(
                    spool.promote_pending_final(&pending.cat_id, &pending.target_json)?,
                    "pending signed Usage final vanished before accepted postcondition"
                );
                promoted_pending = true;
                if let Some(meter) = self.meters.get_mut(&pending.cat_id) {
                    if meter.target == target {
                        meter.active = false;
                    }
                }
            }
        }
        Ok(promoted_pending)
    }

    fn sample(&mut self) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
        let now = Instant::now();
        let observed_at_unix_ms = now_unix_ms()?;
        let mut checkpoints = Vec::new();
        for meter in self.meters.values_mut().filter(|meter| meter.active) {
            checkpoints.extend(sample_meter(meter, now, observed_at_unix_ms, false)?);
        }
        Ok(checkpoints)
    }

    fn finalize_shutdown(&mut self) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
        let now = Instant::now();
        let observed_at_unix_ms = now_unix_ms()?;
        let mut checkpoints = Vec::new();
        for meter in self.meters.values_mut().filter(|meter| meter.active) {
            checkpoints.extend(sample_meter(meter, now, observed_at_unix_ms, true)?);
        }
        Ok(checkpoints)
    }

    fn stage_cat_before_effect(
        &mut self,
        cat_id: &str,
    ) -> anyhow::Result<Option<PendingFinalCandidate>> {
        let Some(meter) = self.meters.get_mut(cat_id) else {
            return Ok(None);
        };
        if !meter.active {
            return Ok(None);
        }
        observe_meter(meter, now_unix_ms()?)?;
        let accumulator = meter.accumulator.snapshot();
        let checkpoints = meter.accumulator.final_checkpoint_candidate()?.into();
        let target_json = serde_json::to_string(&meter.target)?;
        meter.active = false;
        Ok(Some(PendingFinalCandidate {
            cat_id: meter.target.cat_id.clone(),
            target_json,
            accumulator,
            checkpoints,
        }))
    }

    fn target_for_runtime(
        &self,
        runtime: &cats_api::runtime_reconciliation::ObservedRuntimeStatus,
    ) -> anyhow::Result<Option<SignedMeterTarget>> {
        if !matches!(
            runtime.stable_state,
            Some(StableState::Running | StableState::Suspended)
        ) {
            return Ok(None);
        }
        let Some(applied) = runtime.applied_desired.as_ref() else {
            return Ok(None);
        };
        let Some(runtime_incarnation) = runtime.runtime_incarnation.as_ref() else {
            return Ok(None);
        };
        let generation = i64::try_from(applied.desired_revision.get())
            .context("accepted Desired revision exceeds the usage generation range")?;
        let mut process_identity = Vec::new();
        for process in &runtime.processes {
            let role = match &process.role {
                ProcessRole::Vmm {
                    runtime_incarnation: process_incarnation,
                } if process_incarnation == runtime_incarnation => "vmm",
                ProcessRole::Blockd { .. } => "blockd",
                _ => continue,
            };
            process_identity.push((
                process.scope_id.to_string(),
                process.process_id,
                process.process_start_time_ticks.get(),
                role,
            ));
        }
        process_identity.sort();
        if process_identity.is_empty() {
            return Ok(None);
        }
        let cgroups = process_identity
            .iter()
            .map(|(scope_id, _, _, _)| self.systemd_cgroup_root.join(scope_id))
            .collect();
        let process_epoch = process_identity
            .iter()
            .map(|(scope_id, process_id, start_ticks, role)| {
                format!("{role}:{scope_id}:{process_id}:{start_ticks}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let source_epoch = signed_source_epoch(
            &self.session,
            applied.desired_revision.get(),
            runtime_incarnation.as_str(),
            &process_epoch,
        );
        Ok(Some(SignedMeterTarget {
            cat_id: runtime.cat_id.to_string(),
            generation,
            source_epoch,
            cgroups,
        }))
    }
}

fn signed_source_epoch(
    session: &SessionBinding,
    desired_revision: u64,
    runtime_incarnation: &str,
    process_epoch: &str,
) -> String {
    format!(
        "session:{}:{}:desired:{desired_revision}:runtime:{runtime_incarnation}:processes:{process_epoch}",
        session.agent_instance_id,
        session.agent_session_epoch.get(),
    )
}

fn new_meter(node_id: &str, target: SignedMeterTarget) -> anyhow::Result<SignedMeterState> {
    let accumulator = RuntimeMeterAccumulator::new(
        format!("node/{node_id}/cat/{}", target.cat_id),
        target.source_epoch.clone(),
        target.cat_id.clone(),
        target.generation,
    )?;
    Ok(SignedMeterState {
        target,
        accumulator,
        last_checkpoint_at: None,
        active: true,
    })
}

fn restored_meter(
    node_id: &str,
    target: SignedMeterTarget,
    pending: &PendingUsageFinal,
) -> anyhow::Result<SignedMeterState> {
    anyhow::ensure!(
        pending.accumulator.source_id == format!("node/{node_id}/cat/{}", target.cat_id)
            && pending.accumulator.source_epoch == target.source_epoch
            && pending.accumulator.cat_id == target.cat_id
            && pending.accumulator.cat_generation == target.generation,
        "pending signed Usage accumulator does not bind its runtime target"
    );
    Ok(SignedMeterState {
        target,
        accumulator: RuntimeMeterAccumulator::from_snapshot(pending.accumulator.clone())?,
        // Force a fresh open checkpoint quickly after recovery. If the process
        // crashes before then, the still-durable pending row can be evaluated
        // again by the next accepted inventory.
        last_checkpoint_at: None,
        active: false,
    })
}

fn observe_meter(meter: &mut SignedMeterState, observed_at_unix_ms: i64) -> anyhow::Result<()> {
    let (cpu_usage_usec, memory_current_bytes) = read_cgroup_usage(&meter.target.cgroups)?;
    if meter
        .accumulator
        .last_observed_at_unix_ms()
        .is_none_or(|last| observed_at_unix_ms > last)
    {
        meter
            .accumulator
            .observe(observed_at_unix_ms, cpu_usage_usec, memory_current_bytes)?;
    }
    Ok(())
}

fn sample_meter(
    meter: &mut SignedMeterState,
    now: Instant,
    observed_at_unix_ms: i64,
    force_checkpoint: bool,
) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
    observe_meter(meter, observed_at_unix_ms)?;
    let due = force_checkpoint
        || meter
            .last_checkpoint_at
            .is_none_or(|last| now.duration_since(last) >= CHECKPOINT_INTERVAL);
    if !due {
        return Ok(Vec::new());
    }
    let checkpoints = if force_checkpoint {
        meter.accumulator.final_checkpoint()?
    } else {
        meter.accumulator.checkpoint()?
    };
    meter.last_checkpoint_at = Some(now);
    Ok(checkpoints.into())
}

fn read_cgroup_usage(cgroups: &[PathBuf]) -> anyhow::Result<(u64, u64)> {
    let mut cpu_usage_usec = 0_u64;
    let mut memory_current_bytes = 0_u64;
    for cgroup in cgroups {
        let cpu = std::fs::read_to_string(cgroup.join("cpu.stat"))
            .with_context(|| format!("read signed Runtime CPU counter at {}", cgroup.display()))?;
        let cpu = cpu
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next()? == "usage_usec")
                    .then(|| fields.next()?.parse::<u64>().ok())
                    .flatten()
            })
            .with_context(|| format!("parse signed Runtime CPU counter at {}", cgroup.display()))?;
        let memory = std::fs::read_to_string(cgroup.join("memory.current"))
            .with_context(|| format!("read signed Runtime memory counter at {}", cgroup.display()))?
            .trim()
            .parse::<u64>()
            .with_context(|| {
                format!(
                    "parse signed Runtime memory counter at {}",
                    cgroup.display()
                )
            })?;
        cpu_usage_usec = cpu_usage_usec
            .checked_add(cpu)
            .context("signed Runtime CPU counter sum overflow")?;
        memory_current_bytes = memory_current_bytes
            .checked_add(memory)
            .context("signed Runtime memory counter sum overflow")?;
    }
    Ok((cpu_usage_usec, memory_current_bytes))
}

fn now_unix_ms() -> anyhow::Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(elapsed.as_millis()).context("current Unix time exceeds i64 milliseconds")
}

pub(crate) struct SignedUsagePipeline {
    sampler: Mutex<SignedUsageSampler>,
    spool: UsageSpool,
    delivery: tokio::sync::Mutex<UsageDeliveryState>,
    delivery_wake: tokio::sync::Notify,
    client: reqwest::Client,
    endpoint: String,
    signer: Ed25519RequestSigner,
    session: SessionBinding,
}

impl SignedUsagePipeline {
    pub(crate) fn open(
        session: &AgentSession,
        signer: Ed25519RequestSigner,
        control_plane_url: &str,
        state_directory: &Path,
        metering_cgroup_root: &Path,
    ) -> anyhow::Result<Self> {
        let service_cgroup = metering_cgroup_root
            .parent()
            .context("metering cgroup root has no service parent")?;
        let systemd_cgroup_root = service_cgroup
            .parent()
            .context("metering service cgroup has no systemd slice parent")?
            .to_path_buf();
        anyhow::ensure!(
            systemd_cgroup_root
                .file_name()
                .is_some_and(|name| name == "system.slice"),
            "metering cgroup root is not beneath system.slice"
        );
        let session = session_binding(session);
        let endpoint = format!(
            "{}{}",
            control_plane_url.trim_end_matches('/'),
            USAGE_CHECKPOINTS_PATH
        );
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .context("build signed usage HTTP client")?;
        Ok(Self {
            sampler: Mutex::new(SignedUsageSampler::new(
                session.clone(),
                systemd_cgroup_root,
            )),
            spool: UsageSpool::open(&state_directory.join("usage-spool.sqlite3"))?,
            delivery: tokio::sync::Mutex::new(UsageDeliveryState::default()),
            delivery_wake: tokio::sync::Notify::new(),
            client,
            endpoint,
            signer,
            session,
        })
    }

    pub(crate) fn update_observation(&self, observation: &NodeObservation) -> anyhow::Result<()> {
        let (checkpoints, promoted_pending) = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .update_observation(observation, &self.spool)?;
        self.persist(checkpoints)?;
        if promoted_pending {
            self.delivery_wake.notify_one();
        }
        Ok(())
    }

    pub(crate) fn sample(&self) -> anyhow::Result<()> {
        let checkpoints = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sample()?;
        self.persist(checkpoints)
    }

    fn finalize_shutdown(&self) -> anyhow::Result<()> {
        let checkpoints = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .finalize_shutdown()?;
        self.persist(checkpoints)
    }

    pub(crate) fn stage_before_effect(&self, desired: &DesiredRuntimeSpec) -> anyhow::Result<()> {
        self.stage_cat_before_effect(desired.cat_id.as_str())
    }

    fn stage_cat_before_effect(&self, cat_id: &str) -> anyhow::Result<()> {
        let existing = self
            .spool
            .pending_finals()?
            .into_iter()
            .find(|pending| pending.cat_id == cat_id);
        let mut sampler = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = existing {
            let target: SignedMeterTarget = serde_json::from_str(&existing.target_json)
                .context("decode retried pending signed Usage target")?;
            let meter = sampler
                .meters
                .get_mut(cat_id)
                .context("pending signed Usage effect has no live meter")?;
            anyhow::ensure!(
                meter.target == target && meter.accumulator.snapshot() == existing.accumulator,
                "retried signed Usage effect conflicts with its pending final candidate"
            );
            meter.active = false;
            return Ok(());
        }
        let Some(candidate) = sampler.stage_cat_before_effect(cat_id)? else {
            return Ok(());
        };
        if let Err(error) = self.spool.stage_pending_final(
            &candidate.cat_id,
            &candidate.target_json,
            &candidate.accumulator,
            &candidate.checkpoints,
        ) {
            if let Some(meter) = sampler.meters.get_mut(&candidate.cat_id) {
                meter.active = true;
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn cancel_pending_effect(&self, desired: &DesiredRuntimeSpec) -> anyhow::Result<()> {
        self.cancel_pending_cat(desired.cat_id.as_str())
    }

    fn cancel_pending_cat(&self, cat_id: &str) -> anyhow::Result<()> {
        let Some(pending) = self
            .spool
            .pending_finals()?
            .into_iter()
            .find(|pending| pending.cat_id == cat_id)
        else {
            return Ok(());
        };
        let target: SignedMeterTarget = serde_json::from_str(&pending.target_json)
            .context("decode cancelled pending signed Usage target")?;
        let mut sampler = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = sampler
            .meters
            .get_mut(cat_id)
            .context("cancelled pending signed Usage effect has no live meter")?;
        anyhow::ensure!(
            meter.target == target && meter.accumulator.snapshot() == pending.accumulator,
            "cancelled signed Usage effect conflicts with its pending final candidate"
        );
        self.spool
            .cancel_pending_final(&pending.cat_id, &pending.target_json)?;
        meter.active = true;
        Ok(())
    }

    fn persist(&self, checkpoints: Vec<CatUsageCheckpoint>) -> anyhow::Result<()> {
        self.spool.enqueue(&checkpoints)?;
        if !checkpoints.is_empty() {
            self.delivery_wake.notify_one();
        }
        Ok(())
    }

    pub(crate) async fn deliver_pending(&self) -> anyhow::Result<()> {
        deliver_usage_batches(
            &self.client,
            &self.endpoint,
            &self.signer,
            &self.session,
            &self.spool,
            &self.delivery,
        )
        .await
    }

    pub(crate) async fn deliver_pending_for_shutdown(&self) -> anyhow::Result<()> {
        // The periodic lane may be in exponential backoff. Graceful shutdown
        // gets one immediate bounded attempt; failure still leaves the exact
        // ordered prefix in the durable spool for the next process.
        self.delivery.lock().await.retry_not_before = None;
        self.deliver_pending().await
    }
}

pub(crate) struct MeteredRuntimeDesiredEffect {
    inner: Arc<dyn RuntimeDesiredEffect>,
    usage: Arc<SignedUsagePipeline>,
}

impl MeteredRuntimeDesiredEffect {
    pub(crate) fn new(
        inner: Arc<dyn RuntimeDesiredEffect>,
        usage: Arc<SignedUsagePipeline>,
    ) -> Self {
        Self { inner, usage }
    }
}

impl RuntimeDesiredEffect for MeteredRuntimeDesiredEffect {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        self.usage.stage_before_effect(desired)?;
        match self.inner.apply(context, desired) {
            Ok(outcome) => {
                if !matches!(
                    outcome,
                    RuntimeDesiredEffectOutcome::RetryExact
                        | RuntimeDesiredEffectOutcome::RefreshInventory
                ) {
                    self.usage.cancel_pending_effect(desired)?;
                }
                Ok(outcome)
            }
            Err(error) => {
                self.usage.cancel_pending_effect(desired)?;
                Err(error)
            }
        }
    }
}

pub(crate) async fn run_sampler(
    pipeline: Arc<SignedUsagePipeline>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let pipeline = Arc::clone(&pipeline);
                    tokio::task::spawn_blocking(move || pipeline.finalize_shutdown())
                        .await
                        .context("join final signed usage sample")??;
                    return Ok(());
                }
                continue;
            }
        }
        let pipeline = Arc::clone(&pipeline);
        tokio::task::spawn_blocking(move || pipeline.sample())
            .await
            .context("join signed usage sampler")??;
    }
}

pub(crate) async fn run_delivery(
    pipeline: Arc<SignedUsagePipeline>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(DELIVERY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = pipeline.delivery_wake.notified() => {}
            _ = wait_for_usage_shutdown(&mut shutdown) => return Ok(()),
        }
        tokio::select! {
            result = pipeline.deliver_pending() => {
                if let Err(error) = result {
                    tracing::warn!(
                        error = format!("{error:#}"),
                        "signed usage delivery will retry"
                    );
                }
            }
            // Dropping an in-flight delivery before its exact ACK keeps that
            // prefix in the durable spool. The runner joins the sampler first,
            // then gives the complete spool one separately bounded final try.
            _ = wait_for_usage_shutdown(&mut shutdown) => return Ok(()),
        }
    }
}

async fn wait_for_usage_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use cats_api::agent_registration::Ed25519RequestSigner;
    use cats_api::metering::{
        CatUsageCheckpoint, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse,
        UsageEpochMarker, UsageMetric, MAX_USAGE_CHECKPOINTS_PER_REQUEST,
    };
    use cats_api::runtime_reconciliation::{Epoch, Id, NodeBootId, RandomId128, SessionBinding};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use tokio::sync::{oneshot, Semaphore};

    use super::{
        new_meter, run_delivery, run_sampler, signed_source_epoch, SignedMeterTarget,
        SignedUsagePipeline, SignedUsageSampler,
    };
    use crate::usage_delivery::UsageDeliveryState;
    use crate::usage_spool::UsageSpool;

    fn test_session() -> SessionBinding {
        SessionBinding {
            node_id: Id::new("node-a").unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: Epoch::new(3).unwrap(),
        }
    }

    fn test_pipeline_with_meter(directory: &Path) -> (SignedUsagePipeline, SignedMeterTarget) {
        let cgroup = directory.join("cat-a.service");
        std::fs::create_dir(&cgroup).unwrap();
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 41\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "4096\n").unwrap();
        let session = test_session();
        let target = SignedMeterTarget {
            cat_id: "cat-a".to_owned(),
            generation: 7,
            source_epoch: signed_source_epoch(
                &session,
                7,
                "33333333333333333333333333333333",
                "vmm:cat-a.service:41:99",
            ),
            cgroups: vec![cgroup],
        };
        let mut sampler = SignedUsageSampler::new(session.clone(), PathBuf::new());
        sampler.meters.insert(
            target.cat_id.clone(),
            new_meter("node-a", target.clone()).unwrap(),
        );
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519RequestSigner::from_pkcs8_der(
            Id::new("credential-a").unwrap(),
            document.as_ref(),
        )
        .unwrap();
        (
            SignedUsagePipeline {
                sampler: Mutex::new(sampler),
                spool: UsageSpool::open(&directory.join("usage-spool.sqlite3")).unwrap(),
                delivery: tokio::sync::Mutex::new(UsageDeliveryState::default()),
                delivery_wake: tokio::sync::Notify::new(),
                client: reqwest::Client::new(),
                endpoint: "http://127.0.0.1/unused".to_owned(),
                signer,
                session,
            },
            target,
        )
    }

    #[test]
    fn desired_revision_separates_accumulator_epochs_after_counter_reset() {
        let session = SessionBinding {
            node_id: Id::new("node-a").unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: Epoch::new(3).unwrap(),
        };
        let first = signed_source_epoch(&session, 7, "runtime-a", "vmm:scope:41:99");
        let next = signed_source_epoch(&session, 8, "runtime-a", "vmm:scope:41:99");

        assert_ne!(first, next);
        assert!(first.contains(":desired:7:"));
        assert!(next.contains(":desired:8:"));
    }

    #[test]
    fn effect_failure_cancels_pending_final_without_publishing_terminal_usage() {
        let directory = tempfile::tempdir().unwrap();
        let (pipeline, _) = test_pipeline_with_meter(directory.path());

        pipeline.stage_cat_before_effect("cat-a").unwrap();
        assert_eq!(pipeline.spool.pending_final_len().unwrap(), 1);
        assert_eq!(pipeline.spool.len().unwrap(), 0);
        pipeline.cancel_pending_cat("cat-a").unwrap();

        assert_eq!(pipeline.spool.pending_final_len().unwrap(), 0);
        assert_eq!(pipeline.spool.len().unwrap(), 0);
        assert!(
            pipeline
                .sampler
                .lock()
                .unwrap()
                .meters
                .get("cat-a")
                .unwrap()
                .active
        );
    }

    #[test]
    fn same_target_observation_resumes_pending_accumulator_without_a_final_event() {
        let directory = tempfile::tempdir().unwrap();
        let (pipeline, target) = test_pipeline_with_meter(directory.path());
        pipeline.stage_cat_before_effect("cat-a").unwrap();
        let next = BTreeMap::from([("cat-a".to_owned(), target)]);

        let promoted = pipeline
            .sampler
            .lock()
            .unwrap()
            .resolve_pending(&next, &pipeline.spool)
            .unwrap();

        assert!(!promoted);
        assert_eq!(pipeline.spool.pending_final_len().unwrap(), 0);
        assert_eq!(pipeline.spool.len().unwrap(), 0);
        assert!(
            pipeline
                .sampler
                .lock()
                .unwrap()
                .meters
                .get("cat-a")
                .unwrap()
                .active
        );
    }

    #[test]
    fn crash_pending_candidate_resumes_or_promotes_only_from_accepted_inventory() {
        let resume_directory = tempfile::tempdir().unwrap();
        let (resume_pipeline, resume_target) = test_pipeline_with_meter(resume_directory.path());
        resume_pipeline.stage_cat_before_effect("cat-a").unwrap();
        let mut recovered = SignedUsageSampler::new(test_session(), PathBuf::new());
        assert!(!recovered
            .resolve_pending(
                &BTreeMap::from([("cat-a".to_owned(), resume_target)]),
                &resume_pipeline.spool,
            )
            .unwrap());
        assert!(recovered.meters.get("cat-a").unwrap().active);
        assert_eq!(resume_pipeline.spool.len().unwrap(), 0);

        let promote_directory = tempfile::tempdir().unwrap();
        let (promote_pipeline, _) = test_pipeline_with_meter(promote_directory.path());
        promote_pipeline.stage_cat_before_effect("cat-a").unwrap();
        let mut recovered = SignedUsageSampler::new(test_session(), PathBuf::new());
        assert!(recovered
            .resolve_pending(&BTreeMap::new(), &promote_pipeline.spool)
            .unwrap());
        let final_events = promote_pipeline.spool.peek(10).unwrap();
        assert_eq!(final_events.len(), 2);
        assert!(final_events
            .iter()
            .all(|checkpoint| checkpoint.epoch_marker == UsageEpochMarker::Final));
    }

    #[test]
    fn promoted_final_source_epoch_cannot_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let (pipeline, target) = test_pipeline_with_meter(directory.path());
        pipeline.stage_cat_before_effect("cat-a").unwrap();
        let mut recovered = SignedUsageSampler::new(test_session(), PathBuf::new());
        assert!(recovered
            .resolve_pending(&BTreeMap::new(), &pipeline.spool)
            .unwrap());

        let error = recovered
            .resolve_pending(
                &BTreeMap::from([("cat-a".to_owned(), target)]),
                &pipeline.spool,
            )
            .unwrap_err();
        assert!(error.to_string().contains("attempted to reopen promoted"));
        assert_eq!(pipeline.spool.len().unwrap(), 2);
    }

    #[derive(Clone)]
    struct SlowIngestion {
        request_sizes: Arc<Mutex<Vec<usize>>>,
        request_number: Arc<AtomicUsize>,
        first_started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release_first: Arc<Semaphore>,
    }

    async fn ingest_slow_first(
        State(state): State<SlowIngestion>,
        body: Bytes,
    ) -> Json<IngestUsageCheckpointsResponse> {
        let request: IngestUsageCheckpointsRequest = serde_json::from_slice(&body).unwrap();
        state
            .request_sizes
            .lock()
            .unwrap()
            .push(request.checkpoints.len());
        if state.request_number.fetch_add(1, Ordering::SeqCst) == 0 {
            if let Some(started) = state.first_started.lock().unwrap().take() {
                let _ = started.send(());
            }
            state.release_first.acquire().await.unwrap().forget();
        }
        Json(IngestUsageCheckpointsResponse {
            accepted: request.checkpoints.len() as u64,
            duplicates: 0,
            rejected: Vec::new(),
            results: request
                .checkpoints
                .into_iter()
                .map(
                    |checkpoint| cats_api::metering::UsageCheckpointIngestResult {
                        event_id: checkpoint.event_id,
                        outcome: cats_api::metering::UsageCheckpointIngestOutcome::Accepted,
                        reason: None,
                    },
                )
                .collect(),
        })
    }

    fn queued_checkpoint(sequence: u64) -> CatUsageCheckpoint {
        CatUsageCheckpoint {
            event_id: format!("queued-{sequence:04}"),
            source_id: "node/node-a/cat/cat-a".to_owned(),
            source_epoch: "queued-epoch".to_owned(),
            sequence,
            observed_at_unix_ms: 1_000 + i64::try_from(sequence).unwrap(),
            cat_id: "cat-a".to_owned(),
            cat_generation: 1,
            metric: UsageMetric::CpuUsec,
            epoch_marker: cats_api::metering::UsageEpochMarker::Open,
            cumulative_quantity: u128::from(sequence),
        }
    }

    #[tokio::test]
    async fn shutdown_cancels_backlog_delivery_then_persists_and_replays_final_sample() {
        let (first_started, first_started_rx) = oneshot::channel();
        let ingestion = SlowIngestion {
            request_sizes: Arc::new(Mutex::new(Vec::new())),
            request_number: Arc::new(AtomicUsize::new(0)),
            first_started: Arc::new(Mutex::new(Some(first_started))),
            release_first: Arc::new(Semaphore::new(0)),
        };
        let app = Router::new()
            .route("/", post(ingest_slow_first))
            .with_state(ingestion.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let directory = tempfile::tempdir().unwrap();
        let cgroup = directory.path().join("cat-a.service");
        std::fs::create_dir(&cgroup).unwrap();
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 41\n").unwrap();
        std::fs::write(cgroup.join("memory.current"), "4096\n").unwrap();
        let session = SessionBinding {
            node_id: Id::new("node-a").unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: Epoch::new(3).unwrap(),
        };
        let mut sampler = SignedUsageSampler::new(session.clone(), PathBuf::new());
        sampler.meters = BTreeMap::from([(
            "cat-a".to_owned(),
            new_meter(
                "node-a",
                SignedMeterTarget {
                    cat_id: "cat-a".to_owned(),
                    generation: 7,
                    source_epoch: "final-epoch".to_owned(),
                    cgroups: vec![cgroup],
                },
            )
            .unwrap(),
        )]);
        let spool = UsageSpool::open(&directory.path().join("usage-spool.sqlite3")).unwrap();
        let queued = u64::try_from(MAX_USAGE_CHECKPOINTS_PER_REQUEST).unwrap() + 1;
        spool
            .enqueue(&(0..queued).map(queued_checkpoint).collect::<Vec<_>>())
            .unwrap();
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519RequestSigner::from_pkcs8_der(
            Id::new("credential-a").unwrap(),
            document.as_ref(),
        )
        .unwrap();
        let pipeline = Arc::new(SignedUsagePipeline {
            sampler: Mutex::new(sampler),
            spool,
            delivery: tokio::sync::Mutex::new(UsageDeliveryState::default()),
            delivery_wake: tokio::sync::Notify::new(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            endpoint,
            signer,
            session,
        });

        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let usage_task = tokio::spawn({
            let sampler = Arc::clone(&pipeline);
            let delivery = Arc::clone(&pipeline);
            let sampler_shutdown = shutdown_rx.clone();
            async move {
                tokio::try_join!(
                    run_sampler(sampler, sampler_shutdown),
                    run_delivery(delivery, shutdown_rx),
                )
            }
        });
        tokio::time::timeout(Duration::from_secs(2), first_started_rx)
            .await
            .expect("ordinary delivery never reached its first slow ACK")
            .unwrap();
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), usage_task)
            .await
            .expect("ordinary backlog delivery made shutdown unbounded")
            .unwrap()
            .unwrap();

        assert_eq!(
            pipeline.spool.len().unwrap(),
            queued + 2,
            "the unACKed prefix and final two-metric sample must remain durable"
        );
        ingestion.release_first.add_permits(1);
        tokio::time::timeout(
            Duration::from_secs(2),
            pipeline.deliver_pending_for_shutdown(),
        )
        .await
        .expect("the single bounded final attempt did not finish")
        .unwrap();
        assert!(pipeline.spool.is_empty().unwrap());
        assert_eq!(
            *ingestion.request_sizes.lock().unwrap(),
            vec![
                MAX_USAGE_CHECKPOINTS_PER_REQUEST,
                MAX_USAGE_CHECKPOINTS_PER_REQUEST,
                3,
            ],
            "final delivery must replay the cancelled prefix before the final sample"
        );
        server.abort();
    }
}

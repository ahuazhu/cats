//! Usage sampling bound to accepted signed Runtime observations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _};
use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::metering::{CatUsageCheckpoint, USAGE_CHECKPOINTS_PATH};
use cats_api::runtime_reconciliation::{
    AgentSession, DesiredRuntimeSpec, NodeObservation, ProcessRole, SessionBinding, StableState,
};
use cats_metering::RuntimeMeterAccumulator;

use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
};
use crate::usage_delivery::{deliver_usage_batches, session_binding, UsageDeliveryState};
use crate::usage_spool::UsageSpool;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(10);
const DELIVERY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedMeterTarget {
    cat_id: String,
    generation: i64,
    source_epoch: String,
    cgroups: Vec<PathBuf>,
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
    ) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
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
        Ok(checkpoints)
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

    fn finalize_before_effect(
        &mut self,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
        let Some(meter) = self.meters.get_mut(desired.cat_id.as_str()) else {
            return Ok(Vec::new());
        };
        if !meter.active {
            return Ok(Vec::new());
        }
        let checkpoints = sample_meter(meter, Instant::now(), now_unix_ms()?, true)?;
        meter.active = false;
        Ok(checkpoints)
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
        let source_epoch = format!(
            "session:{}:{}:runtime:{}:processes:{}",
            self.session.agent_instance_id,
            self.session.agent_session_epoch.get(),
            runtime_incarnation,
            process_epoch
        );
        Ok(Some(SignedMeterTarget {
            cat_id: runtime.cat_id.to_string(),
            generation,
            source_epoch,
            cgroups,
        }))
    }
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

fn sample_meter(
    meter: &mut SignedMeterState,
    now: Instant,
    observed_at_unix_ms: i64,
    force_checkpoint: bool,
) -> anyhow::Result<Vec<CatUsageCheckpoint>> {
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
    let due = force_checkpoint
        || meter
            .last_checkpoint_at
            .is_none_or(|last| now.duration_since(last) >= CHECKPOINT_INTERVAL);
    if !due {
        return Ok(Vec::new());
    }
    let checkpoints = meter.accumulator.checkpoint()?;
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
        let checkpoints = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .update_observation(observation)?;
        self.persist(checkpoints)
    }

    pub(crate) fn sample(&self) -> anyhow::Result<()> {
        let checkpoints = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sample()?;
        self.persist(checkpoints)
    }

    pub(crate) fn finalize_before_effect(
        &self,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<()> {
        let checkpoints = self
            .sampler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .finalize_before_effect(desired)?;
        self.persist(checkpoints)
    }

    fn persist(&self, checkpoints: Vec<CatUsageCheckpoint>) -> anyhow::Result<()> {
        self.spool.enqueue(&checkpoints)?;
        if !checkpoints.is_empty() {
            self.delivery_wake.notify_one();
        }
        Ok(())
    }

    async fn deliver_pending(&self) -> anyhow::Result<()> {
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
        self.usage.finalize_before_effect(desired)?;
        self.inner.apply(context, desired)
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
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
        }
        if let Err(error) = pipeline.deliver_pending().await {
            tracing::warn!(
                error = format!("{error:#}"),
                "signed usage delivery will retry"
            );
        }
    }
}

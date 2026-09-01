//! Per-Cat cgroup v2 usage metering for the semantic Node.
//!
//! ADR-0011 makes the Node-read monotonic counter the only raw billing fact:
//! neither the scheduler's desired allocation nor an instantaneous telemetry
//! gauge proves what a customer consumed. This module owns the Node half of
//! that contract — one delegated cgroup per Cat runtime, a 1 s sample cadence,
//! a 10 s cumulative checkpoint cadence — and hands finished checkpoints to
//! the Control ingestion route.
//!
//! Metering never gates a runtime effect. A cgroup that cannot be created or
//! read is reported and skipped; it must not stop a Cat from starting.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_metering::RuntimeMeterAccumulator;
use cats_protocol::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, MAX_USAGE_CHECKPOINTS_PER_REQUEST,
};
use cats_protocol::runtime_reconciliation::{Epoch, Id, NodeBootId, RandomId128, SessionBinding};

use crate::semantic_node_client::SemanticNodeTransport;

/// Target sampling cadence for the cumulative cgroup counters.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Target cadence at which a sampled meter publishes a cumulative checkpoint.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(10);
/// Cadence at which finished checkpoints are pushed to Control.
pub const DELIVERY_INTERVAL: Duration = Duration::from_secs(5);
/// Backoff bounds for a Control ingestion route that is failing.
const DELIVERY_MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Total time the final delivery attempt may hold up a Node shutdown.
const SHUTDOWN_FLUSH_BUDGET: Duration = Duration::from_secs(5);

/// Bound on undelivered checkpoints held in Node memory.
///
/// Every sample round publishes two cumulative checkpoints per Cat, so this
/// covers hours of a full Host with Control unreachable. Overflow drops the
/// oldest entry: cumulative counters mean a later checkpoint carries the same
/// total, so dropping the oldest can only lose the baseline of a window, never
/// double-bill it.
const MAX_PENDING_CHECKPOINTS: usize = 8192;

/// The semantic Control/Node protocol has no Desired revision. `cat_generation`
/// and the producer binding's revision must agree with each other in the
/// checkpoint contract, so both stay at this one immutable value; usage
/// identity is carried by `(source_id, source_epoch, metric, sequence)`.
const SEMANTIC_CAT_GENERATION: i64 = 1;

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
/// Leaf the Node agent moves itself into. cgroup v2 refuses to enable
/// controllers for the children of a cgroup that still holds processes, so the
/// delegated root has to become an inner node before any Cat can be metered.
const AGENT_LEAF: &str = "agent";
/// Leaf holding one cgroup per metered Cat runtime.
const CATS_LEAF: &str = "cats";

/// The delegated cgroup v2 subtree this Node meters Cats in.
#[derive(Debug, Clone)]
pub struct MeteringCgroupRoot {
    cats: PathBuf,
}

/// Resolve the systemd-delegated cgroup this process runs in.
///
/// `Delegate=cpu memory` on the unit is what makes the subtree writable; this
/// only discovers where that subtree is.
pub fn detect_delegated_cgroup() -> Result<PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup")
        .context("read /proc/self/cgroup for the delegated metering subtree")?;
    let relative = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("no cgroup v2 membership in /proc/self/cgroup")?
        .trim();
    anyhow::ensure!(
        relative.starts_with('/') && !relative.contains(".."),
        "cgroup v2 membership {relative} is not an absolute in-hierarchy path"
    );
    Ok(Path::new(CGROUP_MOUNT).join(relative.trim_start_matches('/')))
}

impl MeteringCgroupRoot {
    /// Turn the delegated cgroup into a metering root: move this process into
    /// its own leaf, enable the CPU and memory controllers for children, and
    /// create the leaf that holds one cgroup per Cat.
    ///
    /// Idempotent across restarts: an already-prepared subtree converges
    /// without moving anything twice.
    pub fn initialize(delegated: &Path) -> Result<Self> {
        let process_id = std::process::id().to_string();
        let agent = delegated.join(AGENT_LEAF);
        if !cgroup_contains_process(&agent, &process_id)? {
            anyhow::ensure!(
                cgroup_contains_process(delegated, &process_id)?,
                "node agent is not a member of delegated cgroup {}",
                delegated.display()
            );
            create_cgroup(&agent)?;
            write_cgroup_file(&agent.join("cgroup.procs"), &process_id)
                .with_context(|| format!("move node agent into {}", agent.display()))?;
        }
        // The kernel is the authority on whether the delegated cgroup may
        // become an inner node: enabling controllers fails while any process
        // still sits in it.
        enable_cgroup_controllers(delegated)?;
        let cats = delegated.join(CATS_LEAF);
        create_cgroup(&cats)?;
        enable_cgroup_controllers(&cats)?;
        Ok(Self { cats })
    }

    /// Root for tests and for callers that manage the subtree themselves.
    pub fn from_prepared_cats_root(cats: PathBuf) -> Self {
        Self { cats }
    }

    /// A cgroup name is a single path component. `Id` permits `.` and `:`, so
    /// `..` is a syntactically valid resource ID; letting it through would aim
    /// a create, a `cgroup.procs` write and an rmdir at the delegated root
    /// itself instead of a Cat leaf.
    fn cat_cgroup(&self, cat_id: &str) -> Result<PathBuf> {
        anyhow::ensure!(
            !cat_id.is_empty()
                && cat_id != "."
                && cat_id != ".."
                && !cat_id.contains('/')
                && !cat_id.contains('\0'),
            "Cat ID {cat_id:?} is not a single cgroup path component"
        );
        Ok(self.cats.join(cat_id))
    }

    /// Create the cgroup for one Cat runtime. A leftover cgroup from a previous
    /// runtime is removed first so the new source epoch starts from its own
    /// counters instead of inheriting a stale total.
    fn open_cat(&self, cat_id: &str) -> Result<PathBuf> {
        let cgroup = self.cat_cgroup(cat_id)?;
        if cgroup.is_dir() {
            let _ = std::fs::remove_dir(&cgroup);
        }
        create_cgroup(&cgroup)?;
        Ok(cgroup)
    }

    fn remove_cat(&self, cat_id: &str) {
        let Ok(cgroup) = self.cat_cgroup(cat_id) else {
            return;
        };
        if let Err(error) = std::fs::remove_dir(&cgroup) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    cat_id,
                    cgroup = %cgroup.display(),
                    %error,
                    "could not remove metered Cat cgroup"
                );
            }
        }
    }
}

fn create_cgroup(cgroup: &Path) -> Result<()> {
    match std::fs::create_dir(cgroup) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("create cgroup {}", cgroup.display())),
    }
}

fn write_cgroup_file(path: &Path, value: &str) -> Result<()> {
    std::fs::write(path, value).with_context(|| format!("write {}", path.display()))
}

fn read_cgroup_processes(cgroup: &Path) -> Result<Vec<String>> {
    let path = cgroup.join("cgroup.procs");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read cgroup process list {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

fn cgroup_contains_process(cgroup: &Path, process_id: &str) -> Result<bool> {
    if !cgroup.is_dir() {
        return Ok(false);
    }
    Ok(read_cgroup_processes(cgroup)?
        .iter()
        .any(|line| line == process_id))
}

fn enable_cgroup_controllers(cgroup: &Path) -> Result<()> {
    let controllers_path = cgroup.join("cgroup.controllers");
    let available = std::fs::read_to_string(&controllers_path)
        .with_context(|| format!("read cgroup controllers {}", controllers_path.display()))?;
    let available = available.split_whitespace().collect::<Vec<_>>();
    for required in ["cpu", "memory"] {
        anyhow::ensure!(
            available.contains(&required),
            "cgroup {} does not expose the {required} controller; the unit needs \
             Delegate=cpu memory",
            cgroup.display()
        );
    }
    let subtree = cgroup.join("cgroup.subtree_control");
    let enabled =
        std::fs::read_to_string(&subtree).with_context(|| format!("read {}", subtree.display()))?;
    let enabled = enabled.split_whitespace().collect::<Vec<_>>();
    let mut request = String::new();
    for required in ["cpu", "memory"] {
        if !enabled.contains(&required) {
            if !request.is_empty() {
                request.push(' ');
            }
            request.push('+');
            request.push_str(required);
        }
    }
    if request.is_empty() {
        return Ok(());
    }
    write_cgroup_file(&subtree, &request).with_context(|| {
        format!(
            "enable {request} for the children of {}; a busy subtree means a \
             process other than the agent leaf is still a member",
            cgroup.display()
        )
    })
}

/// Read the cumulative CPU and instantaneous memory counters of one cgroup.
fn read_cgroup_counters(cgroup: &Path) -> Result<(u64, u64)> {
    let cpu_path = cgroup.join("cpu.stat");
    let cpu = std::fs::read_to_string(&cpu_path)
        .with_context(|| format!("read CPU counter {}", cpu_path.display()))?;
    let cpu_usage_usec = cpu
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "usage_usec")
                .then(|| fields.next()?.parse::<u64>().ok())
                .flatten()
        })
        .with_context(|| format!("parse usage_usec from {}", cpu_path.display()))?;
    let memory_path = cgroup.join("memory.current");
    let memory_current_bytes = std::fs::read_to_string(&memory_path)
        .with_context(|| format!("read memory counter {}", memory_path.display()))?
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parse {}", memory_path.display()))?;
    Ok((cpu_usage_usec, memory_current_bytes))
}

struct MeterLane {
    cgroup: PathBuf,
    accumulator: RuntimeMeterAccumulator,
    last_checkpoint_at: Option<Instant>,
}

/// Node-wide metering state: one lane per live Cat runtime plus the queue of
/// checkpoints waiting for Control.
pub struct CatUsageMeters {
    node_id: Id,
    producer: SessionBinding,
    root: Option<MeteringCgroupRoot>,
    lanes: Mutex<BTreeMap<String, MeterLane>>,
    pending: Mutex<VecDeque<CatUsageCheckpoint>>,
    dropped: AtomicU64,
}

impl CatUsageMeters {
    /// `root` is `None` when the Host has no delegated metering subtree. The
    /// Node keeps serving; nothing is metered and the sampler says so.
    pub fn new(node_id: Id, root: Option<MeteringCgroupRoot>) -> Result<Self> {
        let boot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        let producer = SessionBinding {
            node_id: node_id.clone(),
            node_boot_id: NodeBootId::new(fresh_random_hex())
                .context("generated Node boot identity is invalid")?,
            agent_instance_id: RandomId128::new(fresh_random_hex())
                .context("generated agent instance identity is invalid")?,
            // The semantic protocol has no AgentSession fence. Process start
            // time is a real, monotonically increasing session ordinal, which
            // is what this field is read for.
            agent_session_epoch: Epoch::new(boot.max(1))
                .context("Node session epoch is outside the wire range")?,
        };
        Ok(Self {
            node_id,
            producer,
            root,
            lanes: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.root.is_some()
    }

    pub fn producer(&self) -> &SessionBinding {
        &self.producer
    }

    fn lanes(&self) -> MutexGuard<'_, BTreeMap<String, MeterLane>> {
        self.lanes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn pending(&self) -> MutexGuard<'_, VecDeque<CatUsageCheckpoint>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Open the meter for one Cat runtime and return the cgroup its processes
    /// belong in. `source_epoch` is the Cat's runtime incarnation: a replaced
    /// runtime is a new epoch with its own baseline.
    pub fn open(&self, cat_id: &Id, source_epoch: &RandomId128) -> Result<Option<PathBuf>> {
        let Some(root) = self.root.as_ref() else {
            return Ok(None);
        };
        let cgroup = root.open_cat(cat_id.as_str())?;
        let accumulator = RuntimeMeterAccumulator::new(
            source_id(&self.node_id, cat_id.as_str()),
            source_epoch.as_str().to_owned(),
            cat_id.as_str().to_owned(),
            SEMANTIC_CAT_GENERATION,
        )
        .context("open Cat usage accumulator")?;
        self.lanes().insert(
            cat_id.as_str().to_owned(),
            MeterLane {
                cgroup: cgroup.clone(),
                accumulator,
                last_checkpoint_at: None,
            },
        );
        Ok(Some(cgroup))
    }

    /// Charge one process to the Cat's cgroup. Called for every VMM the Cat
    /// launches, including a Warm restore into the same runtime epoch.
    pub fn place(&self, cat_id: &str, process_id: u32) -> Result<()> {
        let cgroup = match self.lanes().get(cat_id) {
            Some(lane) => lane.cgroup.clone(),
            None => return Ok(()),
        };
        write_cgroup_file(&cgroup.join("cgroup.procs"), &process_id.to_string())
            .with_context(|| format!("charge process {process_id} to {}", cgroup.display()))
    }

    /// Close the meter for a Cat runtime: publish the final cumulative sample
    /// for the epoch and release the cgroup.
    pub fn close(&self, cat_id: &str) {
        let Some(mut lane) = self.lanes().remove(cat_id) else {
            return;
        };
        match final_checkpoints(&mut lane) {
            Ok(checkpoints) => self.enqueue(checkpoints),
            Err(error) => tracing::warn!(
                cat_id,
                error = %format!("{error:#}"),
                "could not publish the final usage checkpoint for a Cat runtime"
            ),
        }
        if let Some(root) = self.root.as_ref() {
            root.remove_cat(cat_id);
        }
    }

    /// One sampling round over every open lane.
    pub fn sample(&self) {
        let now = Instant::now();
        let observed_at_unix_ms = match unix_millis() {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "usage sampling has no usable clock");
                return;
            }
        };
        let mut published = Vec::new();
        {
            let mut lanes = self.lanes();
            for (cat_id, lane) in lanes.iter_mut() {
                match sample_lane(lane, now, observed_at_unix_ms) {
                    Ok(checkpoints) => published.extend(checkpoints),
                    Err(error) => tracing::warn!(
                        cat_id = cat_id.as_str(),
                        error = %format!("{error:#}"),
                        "could not sample a metered Cat runtime"
                    ),
                }
            }
        }
        self.enqueue(published);
    }

    fn enqueue(&self, checkpoints: Vec<CatUsageCheckpoint>) {
        if checkpoints.is_empty() {
            return;
        }
        let mut pending = self.pending();
        for checkpoint in checkpoints {
            if pending.len() >= MAX_PENDING_CHECKPOINTS {
                pending.pop_front();
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    tracing::error!(
                        dropped,
                        "usage checkpoint queue is full; Control ingestion is not keeping up"
                    );
                }
            }
            pending.push_back(checkpoint);
        }
    }

    /// Take the next ordered delivery batch.
    pub fn take_batch(&self) -> Vec<CatUsageCheckpoint> {
        let mut pending = self.pending();
        let take = pending.len().min(MAX_USAGE_CHECKPOINTS_PER_REQUEST);
        pending.drain(..take).collect()
    }

    /// Return an undelivered batch to the front of the queue in order.
    pub fn requeue(&self, checkpoints: Vec<CatUsageCheckpoint>) {
        let mut pending = self.pending();
        for checkpoint in checkpoints.into_iter().rev() {
            if pending.len() >= MAX_PENDING_CHECKPOINTS {
                pending.pop_back();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            pending.push_front(checkpoint);
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending().len()
    }
}

fn sample_lane(
    lane: &mut MeterLane,
    now: Instant,
    observed_at_unix_ms: i64,
) -> Result<Vec<CatUsageCheckpoint>> {
    observe_lane(lane, observed_at_unix_ms)?;
    let due = lane
        .last_checkpoint_at
        .is_none_or(|last| now.duration_since(last) >= CHECKPOINT_INTERVAL);
    if !due {
        return Ok(Vec::new());
    }
    let checkpoints = lane
        .accumulator
        .checkpoint()
        .context("publish a cumulative usage checkpoint")?;
    lane.last_checkpoint_at = Some(now);
    Ok(checkpoints.into())
}

fn observe_lane(lane: &mut MeterLane, observed_at_unix_ms: i64) -> Result<()> {
    let (cpu_usage_usec, memory_current_bytes) = read_cgroup_counters(&lane.cgroup)?;
    if lane
        .accumulator
        .last_observed_at_unix_ms()
        .is_none_or(|last| observed_at_unix_ms > last)
    {
        lane.accumulator
            .observe(observed_at_unix_ms, cpu_usage_usec, memory_current_bytes)
            .context("accumulate a cgroup usage sample")?;
    }
    Ok(())
}

fn final_checkpoints(lane: &mut MeterLane) -> Result<Vec<CatUsageCheckpoint>> {
    // A removed cgroup is the normal case when the runtime already exited; the
    // last accumulated sample is still the epoch's terminal total.
    if let Err(error) = observe_lane(lane, unix_millis()?) {
        tracing::debug!(
            error = %format!("{error:#}"),
            "final usage sample used the last readable counters"
        );
    }
    if lane.accumulator.last_observed_at_unix_ms().is_none() {
        return Ok(Vec::new());
    }
    Ok(lane
        .accumulator
        .final_checkpoint()
        .context("publish the final usage checkpoint")?
        .into())
}

fn source_id(node_id: &Id, cat_id: &str) -> String {
    format!("node/{node_id}/cat/{cat_id}")
}

fn fresh_random_hex() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn unix_millis() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(elapsed.as_millis()).context("current Unix time exceeds i64 milliseconds")
}

/// Sample every open meter until shutdown.
pub async fn run_usage_sampler(
    meters: Arc<CatUsageMeters>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    if !meters.is_enabled() {
        tracing::error!(
            "Cat usage metering is disabled on this Node; no compute usage will be billed"
        );
        return Ok(());
    }
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let sampler = Arc::clone(&meters);
                tokio::task::spawn_blocking(move || sampler.sample())
                    .await
                    .context("join usage sampling round")?;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Deliver finished checkpoints to Control until shutdown.
pub async fn run_usage_delivery(
    meters: Arc<CatUsageMeters>,
    transport: Arc<dyn SemanticNodeTransport>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    if !meters.is_enabled() {
        return Ok(());
    }
    let mut backoff = DELIVERY_INTERVAL;
    loop {
        let delay = tokio::time::sleep(backoff);
        tokio::select! {
            _ = delay => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    // A planned restart is the common case, so the tail that
                    // has already been sampled is worth one bounded attempt.
                    // Dropping it on every deploy would under-bill the whole
                    // fleet on a schedule.
                    flush_before_shutdown(&meters, transport.as_ref()).await;
                    return Ok(());
                }
            }
        }
        let checkpoints = meters.take_batch();
        if checkpoints.is_empty() {
            backoff = DELIVERY_INTERVAL;
            continue;
        }
        let count = checkpoints.len();
        let request = IngestUsageCheckpointsRequest {
            session: meters.producer().clone(),
            node_id: meters.producer().node_id.as_str().to_owned(),
            checkpoints: checkpoints.clone(),
        };
        match transport.report_usage(request).await {
            Ok(response) => {
                backoff = DELIVERY_INTERVAL;
                if !response.rejected.is_empty() {
                    tracing::warn!(
                        rejected = response.rejected.len(),
                        first = %response.rejected[0].reason,
                        "Control rejected usage checkpoints"
                    );
                }
                tracing::debug!(
                    accepted = response.accepted,
                    duplicates = response.duplicates,
                    pending = meters.pending_len(),
                    "delivered usage checkpoints"
                );
            }
            Err(error) => {
                meters.requeue(checkpoints);
                backoff = (backoff * 2).min(DELIVERY_MAX_BACKOFF);
                tracing::warn!(
                    count,
                    retry_in_ms = backoff.as_millis(),
                    error = %format!("{error:#}"),
                    "usage checkpoint delivery failed"
                );
            }
        }
    }
}

/// Best-effort final delivery. One pass, no retry, one overall deadline: the
/// Node is stopping and a slow Control must not hold the shutdown open.
async fn flush_before_shutdown(meters: &CatUsageMeters, transport: &dyn SemanticNodeTransport) {
    let deadline = tokio::time::Instant::now() + SHUTDOWN_FLUSH_BUDGET;
    loop {
        let checkpoints = meters.take_batch();
        if checkpoints.is_empty() {
            return;
        }
        let request = IngestUsageCheckpointsRequest {
            session: meters.producer().clone(),
            node_id: meters.producer().node_id.as_str().to_owned(),
            checkpoints: checkpoints.clone(),
        };
        match tokio::time::timeout_at(deadline, transport.report_usage(request)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                meters.requeue(checkpoints);
                tracing::warn!(
                    pending = meters.pending_len(),
                    error = %format!("{error:#}"),
                    "usage checkpoints were not delivered before shutdown"
                );
                return;
            }
            Err(_) => {
                meters.requeue(checkpoints);
                tracing::warn!(
                    pending = meters.pending_len(),
                    "usage checkpoint shutdown flush ran out of budget"
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_protocol::metering::UsageMetric;

    fn prepared_root(base: &Path) -> MeteringCgroupRoot {
        let cats = base.join("cats");
        std::fs::create_dir_all(&cats).unwrap();
        MeteringCgroupRoot::from_prepared_cats_root(cats)
    }

    fn write_counters(cgroup: &Path, cpu_usec: u64, memory_bytes: u64) {
        std::fs::write(
            cgroup.join("cpu.stat"),
            format!("usage_usec {cpu_usec}\nuser_usec 1\nsystem_usec 2\n"),
        )
        .unwrap();
        std::fs::write(cgroup.join("memory.current"), format!("{memory_bytes}\n")).unwrap();
    }

    fn meters(base: &Path) -> CatUsageMeters {
        CatUsageMeters::new(Id::new("node_metal-1").unwrap(), Some(prepared_root(base))).unwrap()
    }

    #[test]
    fn sampling_publishes_cumulative_cpu_and_memory_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let meters = meters(dir.path());
        let cat_id = Id::new("cat_d207de919a91").unwrap();
        let epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        let cgroup = meters.open(&cat_id, &epoch).unwrap().expect("cgroup");
        write_counters(&cgroup, 1_000, 2 * 1024 * 1024);
        meters.sample();
        let first = meters.take_batch();
        assert_eq!(first.len(), 2, "one checkpoint per metric");
        assert!(first
            .iter()
            .any(|checkpoint| checkpoint.metric == UsageMetric::CpuUsec
                && checkpoint.cumulative_quantity == 1_000));
        assert_eq!(first[0].source_id, "node/node_metal-1/cat/cat_d207de919a91");
        assert_eq!(first[0].source_epoch, epoch.as_str());

        // The next round is inside the checkpoint cadence: it observes without
        // publishing, so the CPU total only advances at the next publication.
        // The accumulator rejects two samples in the same millisecond, which
        // the 1 s production cadence never produces.
        std::thread::sleep(Duration::from_millis(2));
        write_counters(&cgroup, 9_000, 4 * 1024 * 1024);
        meters.sample();
        assert!(meters.take_batch().is_empty());

        std::thread::sleep(Duration::from_millis(2));
        meters.close(cat_id.as_str());
        let last = meters.take_batch();
        assert_eq!(last.len(), 2);
        let cpu = last
            .iter()
            .find(|checkpoint| checkpoint.metric == UsageMetric::CpuUsec)
            .expect("CPU checkpoint");
        assert_eq!(cpu.cumulative_quantity, 9_000);
        assert_eq!(cpu.sequence, 1, "the epoch's cumulative sequence advances");
        assert_eq!(
            cpu.epoch_marker,
            cats_protocol::metering::UsageEpochMarker::Final
        );
        let memory = last
            .iter()
            .find(|checkpoint| checkpoint.metric == UsageMetric::MemoryByteMillis)
            .expect("memory checkpoint");
        assert!(
            memory.cumulative_quantity > 0,
            "the memory integral advances over sampled wall clock"
        );

        // A closed runtime has no lane left, so later rounds bill nothing.
        std::thread::sleep(Duration::from_millis(2));
        write_counters(&cgroup, 99_000, 8 * 1024 * 1024);
        meters.sample();
        assert!(meters.take_batch().is_empty());
    }

    #[test]
    fn a_replaced_runtime_starts_a_new_source_epoch_from_a_fresh_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let meters = meters(dir.path());
        let cat_id = Id::new("cat_d207de919a91").unwrap();
        let first_epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        let cgroup = meters.open(&cat_id, &first_epoch).unwrap().unwrap();
        write_counters(&cgroup, 5_000, 1024);
        meters.sample();
        assert_eq!(meters.take_batch().len(), 2);
        meters.close(cat_id.as_str());
        meters.take_batch();

        let second_epoch = RandomId128::new("1a2b3c4d5e6f708192a3b4c5d6e7f809").unwrap();
        let cgroup = meters.open(&cat_id, &second_epoch).unwrap().unwrap();
        write_counters(&cgroup, 7, 1024);
        meters.sample();
        let batch = meters.take_batch();
        let cpu = batch
            .iter()
            .find(|checkpoint| checkpoint.metric == UsageMetric::CpuUsec)
            .expect("CPU checkpoint");
        assert_eq!(cpu.source_epoch, second_epoch.as_str());
        assert_eq!(cpu.sequence, 0, "a new epoch restarts at its own baseline");
        assert_eq!(cpu.cumulative_quantity, 7);
    }

    #[test]
    fn an_unreadable_cgroup_does_not_stop_other_cats() {
        let dir = tempfile::tempdir().unwrap();
        let meters = meters(dir.path());
        let broken = Id::new("cat_0000000000ff").unwrap();
        let healthy = Id::new("cat_d207de919a91").unwrap();
        let epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        meters.open(&broken, &epoch).unwrap();
        let cgroup = meters.open(&healthy, &epoch).unwrap().unwrap();
        write_counters(&cgroup, 1_234, 1024);
        meters.sample();
        let batch = meters.take_batch();
        assert_eq!(batch.len(), 2);
        assert!(batch
            .iter()
            .all(|checkpoint| checkpoint.cat_id == healthy.as_str()));
    }

    #[test]
    fn a_traversing_resource_id_can_never_name_a_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let root = prepared_root(dir.path());
        for rejected in ["..", ".", "", "cat_a/../..", "cat_a/b"] {
            let error = root
                .cat_cgroup(rejected)
                .expect_err("a traversing Cat ID must be refused");
            assert!(
                format!("{error:#}").contains("single cgroup path component"),
                "{error:#}"
            );
        }
        assert_eq!(
            root.cat_cgroup("cat_d207de919a91").unwrap(),
            dir.path().join("cats").join("cat_d207de919a91")
        );
    }

    #[test]
    fn a_disabled_meter_never_blocks_a_runtime() {
        let meters = CatUsageMeters::new(Id::new("node_metal-1").unwrap(), None).unwrap();
        assert!(!meters.is_enabled());
        let cat_id = Id::new("cat_d207de919a91").unwrap();
        let epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        assert!(meters.open(&cat_id, &epoch).unwrap().is_none());
        meters.place(cat_id.as_str(), 1).unwrap();
        meters.sample();
        meters.close(cat_id.as_str());
        assert!(meters.take_batch().is_empty());
    }

    #[test]
    fn the_pending_queue_is_bounded_and_keeps_delivery_order() {
        let dir = tempfile::tempdir().unwrap();
        let meters = meters(dir.path());
        let batch = meters.take_batch();
        assert!(batch.is_empty());
        let cat_id = Id::new("cat_d207de919a91").unwrap();
        let epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        let cgroup = meters.open(&cat_id, &epoch).unwrap().unwrap();
        for round in 1..=(MAX_PENDING_CHECKPOINTS + 8) {
            write_counters(&cgroup, round as u64 * 10, 1024);
            {
                let mut lanes = meters.lanes();
                let lane = lanes.get_mut(cat_id.as_str()).unwrap();
                lane.last_checkpoint_at = None;
            }
            meters.sample();
        }
        assert!(meters.pending_len() <= MAX_PENDING_CHECKPOINTS);
        let batch = meters.take_batch();
        assert_eq!(batch.len(), MAX_USAGE_CHECKPOINTS_PER_REQUEST);
        let sequences = batch.iter().map(|c| c.sequence).collect::<Vec<_>>();
        let mut sorted = sequences.clone();
        sorted.sort_unstable();
        assert_eq!(sequences, sorted, "delivery order stays monotonic");
        meters.requeue(batch.clone());
        assert_eq!(meters.take_batch()[0].event_id, batch[0].event_id);
    }

    #[test]
    fn initialize_moves_the_agent_and_enables_child_controllers() {
        let dir = tempfile::tempdir().unwrap();
        let delegated = dir.path().join("cats-worker.service");
        std::fs::create_dir_all(&delegated).unwrap();
        std::fs::write(
            delegated.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        std::fs::write(delegated.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(delegated.join("cgroup.subtree_control"), "").unwrap();
        // The agent leaf and the cats leaf are created by initialize(); the
        // kernel would populate their control files, so the fixture seeds the
        // ones initialize() reads back.
        let agent = delegated.join(AGENT_LEAF);
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("cgroup.procs"), "").unwrap();
        let cats = delegated.join(CATS_LEAF);
        std::fs::create_dir_all(&cats).unwrap();
        std::fs::write(cats.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(cats.join("cgroup.subtree_control"), "").unwrap();

        let root = MeteringCgroupRoot::initialize(&delegated).expect("prepare metering root");
        assert_eq!(
            std::fs::read_to_string(agent.join("cgroup.procs")).unwrap(),
            std::process::id().to_string()
        );
        assert_eq!(
            std::fs::read_to_string(delegated.join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory"
        );
        assert_eq!(
            std::fs::read_to_string(cats.join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory"
        );
        assert_eq!(root.cats, cats);
    }

    struct RecordingTransport {
        delivered: Mutex<Vec<Vec<String>>>,
        fail_first: AtomicU64,
    }

    impl crate::semantic_node_client::SemanticNodeTransport for RecordingTransport {
        fn register(
            &self,
            _request: cats_protocol::semantic_control::NodeRegistrationRequest,
        ) -> crate::semantic_node_client::NodeClientFuture<
            cats_protocol::semantic_control::NodeRegistrationResponse,
        > {
            Box::pin(async { anyhow::bail!("registration is not part of usage delivery") })
        }

        fn heartbeat(
            &self,
            _request: cats_protocol::semantic_control::NodeHeartbeatRequest,
        ) -> crate::semantic_node_client::NodeClientFuture<
            cats_protocol::semantic_control::NodeHeartbeatResponse,
        > {
            Box::pin(async { anyhow::bail!("heartbeat is not part of usage delivery") })
        }

        fn report_usage(
            &self,
            request: IngestUsageCheckpointsRequest,
        ) -> crate::semantic_node_client::NodeClientFuture<
            cats_protocol::metering::IngestUsageCheckpointsResponse,
        > {
            if self.fail_first.fetch_sub(1, Ordering::SeqCst) > 0 {
                return Box::pin(async { anyhow::bail!("Control is unreachable") });
            }
            self.delivered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(
                    request
                        .checkpoints
                        .iter()
                        .map(|checkpoint| checkpoint.event_id.clone())
                        .collect(),
                );
            let accepted = request.checkpoints.len() as u64;
            Box::pin(async move {
                Ok(cats_protocol::metering::IngestUsageCheckpointsResponse {
                    accepted,
                    duplicates: 0,
                    rejected: Vec::new(),
                    results: Vec::new(),
                })
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delivery_retries_the_exact_batch_after_a_transport_failure() {
        let dir = tempfile::tempdir().unwrap();
        let meters = Arc::new(meters(dir.path()));
        let cat_id = Id::new("cat_d207de919a91").unwrap();
        let epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        let cgroup = meters.open(&cat_id, &epoch).unwrap().unwrap();
        write_counters(&cgroup, 4_242, 1024);
        meters.sample();
        let queued = meters.pending_len();
        assert_eq!(queued, 2);

        let transport = Arc::new(RecordingTransport {
            delivered: Mutex::new(Vec::new()),
            // The first attempt fails: the batch must return to the queue in
            // order rather than being lost.
            fail_first: AtomicU64::new(1),
        });
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_usage_delivery(
            Arc::clone(&meters),
            Arc::clone(&transport) as Arc<_>,
            shutdown_rx,
        ));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if !transport
                .delivered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
            {
                break;
            }
            assert!(Instant::now() < deadline, "delivery never retried");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        shutdown.send_replace(true);
        task.await.unwrap().unwrap();
        let delivered = transport
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert_eq!(delivered.len(), 1, "the retry delivered one batch");
        assert_eq!(delivered[0].len(), queued);
        assert_eq!(
            meters.pending_len(),
            0,
            "a delivered batch leaves the queue"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_delivers_the_already_sampled_tail() {
        let dir = tempfile::tempdir().unwrap();
        let meters = Arc::new(meters(dir.path()));
        let cat_id = Id::new("cat_d207de919a91").unwrap();
        let epoch = RandomId128::new("0f7a2c1d9b3e4f5061728394a5b6c7d8").unwrap();
        let cgroup = meters.open(&cat_id, &epoch).unwrap().unwrap();
        write_counters(&cgroup, 7_777, 1024);
        meters.sample();
        assert_eq!(meters.pending_len(), 2);

        let transport = Arc::new(RecordingTransport {
            delivered: Mutex::new(Vec::new()),
            fail_first: AtomicU64::new(0),
        });
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_usage_delivery(
            Arc::clone(&meters),
            Arc::clone(&transport) as Arc<_>,
            shutdown_rx,
        ));
        // Shut down inside the first delivery interval, so the only path that
        // can publish this tail is the shutdown flush.
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("delivery stopped")
            .unwrap()
            .unwrap();
        assert_eq!(meters.pending_len(), 0, "the sampled tail was delivered");
        assert_eq!(
            transport
                .delivered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sampler_and_delivery_stop_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let meters = Arc::new(meters(dir.path()));
        let transport = Arc::new(RecordingTransport {
            delivered: Mutex::new(Vec::new()),
            fail_first: AtomicU64::new(0),
        });
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let sampler = tokio::spawn(run_usage_sampler(Arc::clone(&meters), shutdown_rx.clone()));
        let delivery = tokio::spawn(run_usage_delivery(
            meters,
            Arc::clone(&transport) as Arc<_>,
            shutdown_rx,
        ));
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(30), sampler)
            .await
            .expect("sampler stopped")
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), delivery)
            .await
            .expect("delivery stopped")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn initialize_rejects_a_subtree_that_is_not_delegated() {
        let dir = tempfile::tempdir().unwrap();
        let delegated = dir.path().join("cats-worker.service");
        std::fs::create_dir_all(&delegated).unwrap();
        std::fs::write(delegated.join("cgroup.procs"), "1\n").unwrap();
        let error = MeteringCgroupRoot::initialize(&delegated).expect_err("not a member");
        assert!(
            format!("{error:#}").contains("not a member of delegated cgroup"),
            "{error:#}"
        );
    }
}

//! Per-node runtime: executes NodeJobs by supervising one guest-agent
//! process ("the VM") and one cats-blockd process per attachment.
//!
//! VMM seam: this file implements the FakeVmm — a host process stands in
//! for Cloud Hypervisor, SIGSTOP/SIGCONT stand in for vCPU pause/resume,
//! and the guest state file stands in for the memory snapshot. Every block
//! byte still flows through the real cats-blockd engine, so storage
//! semantics (leases, FLUSH durability, cold restore) are exercised for
//! real. The Cloud Hypervisor mode (`VmmMode::CloudHypervisor`, Linux+KVM)
//! is implemented in `ch.rs`: direct-kernel boot, kernel-NBD block path,
//! vsock guest control, vm.pause/resume and vm.snapshot/--restore.
//!
//! Job idempotency: results are journaled by job_id and replayed for
//! duplicate submissions (arch doc §17.4). The journal is in-memory; a node
//! restart loses it, which is safe because every action is itself
//! idempotent at the process level.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult, SuspendWorkFence, VolumeGrant};

use crate::admission::{resume_commitment_bytes, WakeAdmission, WakeBudget, WakeLoad};
use cats_api::requests::{ProxyHttpRequest, ProxyHttpResponse};
use cats_api::resources::{NodeTelemetry, ObservedState};
use cats_guest_agent::DiskMapEntry;
use cats_storage::AdapterSelection;

use crate::ch::{self, BlockPath, ChConfig, ChRuntime, GUEST_VSOCK_PORT};
use crate::guest_client::{GuestClient, GuestShell};

/// Which VMM this node runs.
#[derive(Debug, Clone)]
// Exactly one VmmMode exists per node agent, stored in `NodeConfig` and always
// matched by reference, so the size gap between the variants costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum VmmMode {
    /// Host-process guest (dev/tests on any OS).
    Fake,
    /// Real microVMs via Cloud Hypervisor (Linux + KVM).
    CloudHypervisor(ChConfig),
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub state_dir: PathBuf,
    pub blockd_bin: PathBuf,
    pub guest_agent_bin: PathBuf,
    /// Opaque selections passed to blockd without interpreting provider data.
    pub metadata_store: AdapterSelection,
    pub object_store: AdapterSelection,
    pub blockd_lease_ttl_ms: i64,
    /// Delegated cgroup v2 subtree used for authoritative per-Cat billing
    /// counters. When absent, monitoring remains available but billing
    /// checkpoints are deliberately not produced.
    pub metering_cgroup_root: Option<PathBuf>,
    pub vmm: VmmMode,
    /// Ceiling on concurrent Suspended/Warm wakes (ADR-0002 §8). The
    /// 2026-07-21 concurrency run showed the limit is Guest memory page
    /// read-back, not the VMM, so the budget is accounted in bytes.
    pub wake_budget: WakeBudget,
}

#[derive(Debug, Clone)]
struct RuntimeMetering {
    cgroup_path: PathBuf,
    source_epoch: String,
}

struct BlockdProc {
    child: Child,
    /// NBD socket: readiness probe, golden-root seeding and recovery tooling.
    /// Always present, on both block paths.
    socket: PathBuf,
    /// vhost-user socket the VMM consumes, when the Cat runs on that path.
    vhost_user_socket: Option<PathBuf>,
    /// Control socket for host-side commands (`drain`, ADR-0021).
    control_socket: PathBuf,
    grant: VolumeGrant,
}

impl BlockdProc {
    /// Publish everything the engine has staged. The forced flush points of
    /// the relaxed contract call this after the guest-side flush; on a strict
    /// volume the queue is already empty and it returns immediately.
    fn drain(&self) -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(&self.control_socket)
            .with_context(|| format!("connect blockd control for {}", self.grant.disk_id))?;
        stream.write_all(b"drain\n")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        match line.trim().strip_prefix("OK ") {
            Some(_generation) => Ok(()),
            None => bail!("drain of {} failed: {}", self.grant.disk_id, line.trim()),
        }
    }
}

struct CatRuntime {
    generation: i64,
    cpus: u32,
    memory_mib: u64,
    state: ObservedState,
    guest: Option<Child>,
    boot_id: Option<String>,
    blockds: HashMap<String, BlockdProc>,
    /// Grants remembered for Warm restore.
    volumes: Vec<VolumeGrant>,
    dir: PathBuf,
    /// Short bind paths (see `short_socket_path`).
    ctl_sock: PathBuf,
    web_sock: PathBuf,
    runtime_sock: PathBuf,
    activity: Arc<RuntimeActivity>,
    metering: Option<RuntimeMetering>,
    /// Present only in Cloud Hypervisor mode.
    ch: Option<ChRuntime>,
}

#[derive(Debug, thiserror::Error)]
#[error("activity changed while preparing to suspend")]
struct ActivityChanged;

pub(crate) fn is_activity_changed(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ActivityChanged>().is_some()
        || format!("{error:#}").contains("activity_changed")
}

#[derive(Default)]
struct RuntimeActivityInner {
    sequence: u64,
    active: u32,
    quiescing: bool,
}

#[derive(Default)]
struct RuntimeActivity {
    inner: Mutex<RuntimeActivityInner>,
}

impl RuntimeActivity {
    fn acquire(self: &Arc<Self>) -> Result<RuntimeActivityGuard> {
        let mut inner = self.inner.lock().unwrap();
        if inner.quiescing {
            inner.sequence = inner.sequence.saturating_add(1);
            return Err(ActivityChanged.into());
        }
        inner.active = inner.active.saturating_add(1);
        inner.sequence = inner.sequence.saturating_add(1);
        Ok(RuntimeActivityGuard {
            activity: self.clone(),
        })
    }

    fn prepare(&self) -> Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        if inner.quiescing || inner.active != 0 {
            return Err(ActivityChanged.into());
        }
        inner.quiescing = true;
        Ok(inner.sequence)
    }

    fn unchanged_since(&self, sequence: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.quiescing && inner.active == 0 && inner.sequence == sequence
    }

    fn open(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.quiescing = false;
        inner.sequence = inner.sequence.saturating_add(1);
    }
}

pub(crate) struct RuntimeActivityGuard {
    activity: Arc<RuntimeActivity>,
}

/// Network target for a streaming endpoint connection. FakeVmm exposes the
/// guest workload on a Unix socket; real Cats use the guest tap address.
pub(crate) enum ProxyTarget {
    Unix(PathBuf),
    Tcp(std::net::SocketAddr),
}

/// Process and filesystem identities used by the heartbeat sampler to
/// attribute host resource use to one Cat.
#[derive(Clone)]
pub(crate) struct CatTelemetryTarget {
    pub cat_id: String,
    pub generation: i64,
    pub process_ids: Vec<u32>,
    pub runtime_dir: PathBuf,
    pub metering: Option<CatMeteringTarget>,
}

#[derive(Debug, Clone)]
pub(crate) struct CatMeteringTarget {
    pub cgroup_path: PathBuf,
    pub source_epoch: String,
}

pub(crate) trait UsageFinalizer: Send + Sync {
    fn finalize(&self, target: CatTelemetryTarget) -> Result<()>;
}

impl Drop for RuntimeActivityGuard {
    fn drop(&mut self) {
        let mut inner = self.activity.inner.lock().unwrap();
        inner.active = inner.active.saturating_sub(1);
        inner.sequence = inner.sequence.saturating_add(1);
    }
}

/// How to reach a cat's guest agent (cloneable so locks can be dropped
/// before the potentially slow connect/health exchange).
#[derive(Debug, Clone)]
pub enum GuestConn {
    Unix(PathBuf),
    Vsock(PathBuf, u32),
}

impl GuestConn {
    /// For `exec`: no read timeout, because a command may be silent for a long
    /// time. Health probes use `connect`, which keeps its bound.
    pub fn connect_long_running(&self) -> Result<GuestClient> {
        match self {
            GuestConn::Unix(path) => GuestClient::connect_long_running(path),
            GuestConn::Vsock(path, port) => {
                GuestClient::connect_hybrid_vsock_long_running(path, *port)
            }
        }
    }

    pub fn connect(&self) -> Result<GuestClient> {
        match self {
            GuestConn::Unix(path) => GuestClient::connect(path),
            GuestConn::Vsock(path, port) => GuestClient::connect_hybrid_vsock(path, *port),
        }
    }

    pub fn connect_shell(&self) -> Result<GuestClient> {
        match self {
            GuestConn::Unix(path) => GuestClient::connect_shell(path),
            GuestConn::Vsock(path, port) => GuestClient::connect_hybrid_vsock_shell(path, *port),
        }
    }
}

impl CatRuntime {
    /// Guest control connection: hybrid vsock in CH mode, unix otherwise.
    fn conn(&self) -> GuestConn {
        match &self.ch {
            Some(chrt) => GuestConn::Vsock(chrt.vsock_sock.clone(), GUEST_VSOCK_PORT),
            None => GuestConn::Unix(self.ctl_sock.clone()),
        }
    }
    fn ctl_socket(&self) -> PathBuf {
        self.ctl_sock.clone()
    }
    fn web_socket(&self) -> PathBuf {
        self.web_sock.clone()
    }
    fn runtime_socket(&self) -> PathBuf {
        self.runtime_sock.clone()
    }
    fn disk_map_path(&self) -> PathBuf {
        self.dir.join("disk-map.json")
    }
    fn state_file(&self) -> PathBuf {
        self.dir.join("warm-state.json")
    }

    fn telemetry_target(&self, cat_id: &str) -> CatTelemetryTarget {
        self.telemetry_target_with_metering(cat_id, self.state != ObservedState::Warm)
    }

    /// Lifecycle boundaries need one last authoritative cgroup sample even
    /// after the runtime has entered Warm. Regular heartbeats must not see
    /// that meter: Warm has no resident compute runtime (ADR-0002).
    fn lifecycle_telemetry_target(&self, cat_id: &str) -> CatTelemetryTarget {
        self.telemetry_target_with_metering(cat_id, true)
    }

    fn telemetry_target_with_metering(
        &self,
        cat_id: &str,
        include_metering: bool,
    ) -> CatTelemetryTarget {
        let mut process_ids = Vec::with_capacity(self.blockds.len() + 1);
        if let Some(guest) = &self.guest {
            process_ids.push(guest.id());
        }
        process_ids.extend(self.blockds.values().map(|blockd| blockd.child.id()));
        CatTelemetryTarget {
            cat_id: cat_id.to_string(),
            generation: self.generation,
            process_ids,
            runtime_dir: self.dir.clone(),
            metering: if include_metering {
                self.metering.as_ref().map(|metering| CatMeteringTarget {
                    cgroup_path: metering.cgroup_path.clone(),
                    source_epoch: metering.source_epoch.clone(),
                })
            } else {
                None
            },
        }
    }
}

/// AF_UNIX `sun_path` is limited to ~104 bytes on macOS (108 on Linux), and
/// tempdir + resource-id paths blow past it. All sockets are therefore bound
/// under a short base directory with hashed names; human-readable symlinks
/// are left in the cat directory (`ctl.sock`, `web.sock`) for tooling.
fn short_socket_path(state_dir: &Path, cat_id: &str, kind: &str) -> PathBuf {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let base = std::env::var_os("CATS_SOCK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/cats-sock"));
    let _ = std::fs::create_dir_all(&base);
    let mut h = DefaultHasher::new();
    // state_dir is unique per node instance (tests use fresh tempdirs), so
    // parallel nodes/tests can never collide on a socket path.
    (state_dir, cat_id, kind).hash(&mut h);
    base.join(format!("{:016x}.sock", h.finish()))
}

fn symlink_socket(link: &Path, target: &Path) {
    let _ = std::fs::remove_file(link);
    let _ = std::os::unix::fs::symlink(target, link);
}

pub struct NodeRuntime {
    pub cfg: NodeConfig,
    /// Serializes job execution; jobs are rare and idempotent. Held by every
    /// action except `ResumeCat`, which allocates no node-global resource and
    /// instead serializes per Cat so several Cats can wake in parallel.
    ops: Mutex<()>,
    /// Per-Cat execution locks for the concurrent wake path. Keeps the
    /// existing "one job per Cat at a time" idempotency guarantee while
    /// dropping the node-wide serialization.
    cat_ops: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    cats: Mutex<HashMap<String, CatRuntime>>,
    journal: Mutex<HashMap<String, NodeJobResult>>,
    usage_finalizer: Option<Arc<dyn UsageFinalizer>>,
    /// Bounds concurrent wakes so a wake storm degrades linearly instead of
    /// collapsing the way 10× concurrency on EBS did (19.05 s vs 0.53 s).
    admission: WakeAdmission,
    /// Image id of the golden root, published once per node rather than once per
    /// launch. Publishing uploads the whole image; a launch must not pay for that
    /// (and must not hold a volume lease across it), so the node does it up front
    /// and every launch then provisions by reference.
    seed_image_id: Mutex<Option<String>>,
    /// Bounds concurrent cold launches, which no longer serialize node-wide.
    ///
    /// Separate from `admission` on purpose: the wake budget is sized in
    /// resume-commitment bytes because a wake reads Guest RAM back off the
    /// medium, and a node whose wake budget is smaller than one Cat legitimately
    /// refuses to wake it. A cold launch has no snapshot to read, so it must not
    /// be refused for the same reason — only counted. Same configured
    /// concurrency, byte ceiling removed.
    launch_admission: WakeAdmission,
}

impl NodeRuntime {
    pub fn new(cfg: NodeConfig) -> Self {
        let cfg_wake_budget = cfg.wake_budget;
        Self {
            cfg,
            ops: Mutex::new(()),
            cats: Mutex::new(HashMap::new()),
            cat_ops: Mutex::new(HashMap::new()),
            journal: Mutex::new(HashMap::new()),
            usage_finalizer: None,
            seed_image_id: Mutex::new(None),
            admission: WakeAdmission::new(cfg_wake_budget),
            launch_admission: WakeAdmission::new(WakeBudget {
                commitment_bytes: u64::MAX,
                ..cfg_wake_budget
            }),
        }
    }

    /// Current wake saturation, for heartbeats and tests.
    pub fn wake_load(&self) -> WakeLoad {
        self.admission.load()
    }

    pub(crate) fn with_usage_finalizer(mut self, finalizer: Arc<dyn UsageFinalizer>) -> Self {
        self.usage_finalizer = Some(finalizer);
        self
    }

    /// Snapshot for heartbeats: (cat_id, generation, state).
    pub fn snapshot(&self) -> Vec<(String, i64, ObservedState)> {
        self.cats
            .lock()
            .unwrap()
            .iter()
            .map(|(id, rt)| (id.clone(), rt.generation, rt.state))
            .collect()
    }

    /// Running guests watched by the event-driven work-status loop.
    pub fn activity_targets(&self) -> Vec<(String, i64, GuestConn)> {
        self.cats
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, runtime)| runtime.state == ObservedState::Running)
            .map(|(id, runtime)| (id.clone(), runtime.generation, runtime.conn()))
            .collect()
    }

    /// FakeVmm/testing access to the guest-local user work API.
    pub fn runtime_socket_for(&self, cat_id: &str) -> Option<PathBuf> {
        self.cats
            .lock()
            .unwrap()
            .get(cat_id)
            .filter(|runtime| runtime.ch.is_none())
            .map(CatRuntime::runtime_socket)
    }

    /// Allocation telemetry reported with heartbeats. These values come from
    /// the runtime inventory (actual node ownership), not control-plane intent.
    pub fn telemetry(&self) -> NodeTelemetry {
        // Sample the wake gate before taking `cats`: the two locks are never
        // held together anywhere, and this keeps it that way.
        let wake = self.admission.load();
        let cats = self.cats.lock().unwrap();
        NodeTelemetry {
            observed_cats: cats.len() as u64,
            allocated_cpus: cats.values().map(|runtime| runtime.cpus).sum(),
            allocated_memory_mib: cats.values().map(|runtime| runtime.memory_mib).sum(),
            wake_in_flight: wake.wakes as u64,
            wake_commitment_bytes: wake.commitment_bytes,
            wake_peak_in_flight: wake.peak_wakes as u64,
            wake_commitment_budget_bytes: self.admission.budget().commitment_bytes,
            ..NodeTelemetry::default()
        }
    }

    /// Runtime identities for actual per-Cat host resource sampling.
    pub(crate) fn telemetry_targets(&self) -> Vec<CatTelemetryTarget> {
        self.cats
            .lock()
            .unwrap()
            .iter()
            .map(|(cat_id, runtime)| runtime.telemetry_target(cat_id))
            .collect()
    }

    fn cat_lock(&self, cat_id: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            self.cat_ops
                .lock()
                .unwrap()
                .entry(cat_id.to_string())
                .or_default(),
        )
    }

    pub fn execute(&self, job: NodeJob) -> NodeJobResult {
        if let Some(prev) = self.journal.lock().unwrap().get(&job.job_id) {
            return prev.clone();
        }
        // Suspended resume is the one action that allocates no node-global
        // resource: it resumes a VMM that is already up (no blockd child, no
        // NBD device, no tap). It therefore runs under a per-Cat lock so that
        // several Cats wake in parallel, bounded by the wake admission budget
        // (ADR-0002 §8). The 2026-07-21 run measured ten concurrent restores
        // at 0.53 s versus 0.380 s for one, so node-wide serialization costs
        // roughly 7x on a wake storm for no correctness benefit.
        //
        // Everything else keeps the node-wide lock. In particular Warm
        // `RestoreCat` goes through `start_cat`, which allocates node-global
        // NBD devices and tap slots; making those concurrency-safe is separate
        // work. Warm is still charged its resume commitment, so the ceiling is
        // already in place for when that lands.
        // The per-Cat lock is unconditional: it is what keeps "one job per Cat at
        // a time" true, so a stop can never interleave with a start of the same
        // Cat. The node-wide lock is then layered on top only for actions that
        // touch node-global state. The order is always per-Cat then node-wide, so
        // a thread holding the node-wide lock never waits for a per-Cat lock and
        // the pair cannot deadlock.
        let needs_node_lock = match &job.action {
            NodeJobAction::ResumeCat { .. } => false,
            // A launch is independent of other Cats unless it has to pick a
            // node-global resource; see `launch_allocates_node_global_state`.
            NodeJobAction::StartCat { .. } | NodeJobAction::RestoreCat { .. } => {
                self.launch_allocates_node_global_state()
            }
            _ => true,
        };
        let per_cat = self.cat_lock(job.action.cat_id());
        let _cat_guard = per_cat.lock().unwrap();
        let _node_guard = needs_node_lock.then(|| self.ops.lock().unwrap());
        self.execute_locked(job)
    }

    /// Whether starting a Cat competes with other Cats for node-global state.
    ///
    /// Only the kernel-NBD block path does: `nbd_attach` takes a host-wide lock
    /// and scans for a free `/dev/nbdN`. Everything else a launch allocates is
    /// derived from the Cat and disk id — the vhost-user socket path, the tap
    /// name and its /30, the per-Cat state directory and metering cgroup — so
    /// two launches cannot collide. Keeping the node-wide lock for the NBD path
    /// is what makes that path's device allocation safe.
    fn launch_allocates_node_global_state(&self) -> bool {
        matches!(
            &self.cfg.vmm,
            VmmMode::CloudHypervisor(chc) if chc.block_path == BlockPath::KernelNbd
        )
    }

    fn execute_locked(&self, job: NodeJob) -> NodeJobResult {
        // Re-check after acquiring the execution lock.
        if let Some(prev) = self.journal.lock().unwrap().get(&job.job_id) {
            return prev.clone();
        }
        let job_id = job.job_id.clone();
        let cat_id = job.action.cat_id().to_string();
        let result = match self.run_action(&job) {
            Ok(observed) => {
                let lifecycle_boundary = if observed == ObservedState::Warm {
                    self.retire_warm_metering(&cat_id)
                } else {
                    Ok(())
                };
                match lifecycle_boundary
                    .and_then(|()| self.set_runtime_generation(&cat_id, job.cat_generation))
                {
                    Ok(()) => NodeJobResult::ok(&job_id, observed),
                    Err(error) => {
                        tracing::error!(
                            job = %job_id,
                            cat = %cat_id,
                            %error,
                            "final usage checkpoint failed; lifecycle job failed closed"
                        );
                        NodeJobResult::fail(
                            &job_id,
                            self.observed_of(&cat_id),
                            format!("final usage checkpoint failed: {error:#}"),
                            true,
                        )
                    }
                }
            }
            Err(e) => {
                tracing::warn!(job = %job_id, "job failed: {e:#}");
                let observed = self.observed_of(&cat_id);
                if is_activity_changed(&e) {
                    // A rejected suspend still consumed this lifecycle job:
                    // keep the work-status watcher on the control-plane
                    // generation used for cancellation/retry.
                    if let Err(finalize_error) =
                        self.set_runtime_generation(&cat_id, job.cat_generation)
                    {
                        NodeJobResult::fail(
                            &job_id,
                            observed,
                            format!("final usage checkpoint failed: {finalize_error:#}"),
                            true,
                        )
                    } else {
                        NodeJobResult::rejected(&job_id, observed, format!("{e:#}"))
                    }
                } else {
                    NodeJobResult::fail(&job_id, observed, format!("{e:#}"), true)
                }
            }
        };
        self.journal.lock().unwrap().insert(job_id, result.clone());
        result
    }

    fn set_runtime_generation(&self, cat_id: &str, generation: i64) -> Result<()> {
        let target = {
            let cats = self.cats.lock().unwrap();
            let Some(runtime) = cats.get(cat_id) else {
                return Ok(());
            };
            if runtime.generation == generation {
                return Ok(());
            }
            runtime.lifecycle_telemetry_target(cat_id)
        };
        self.finalize_usage(target)?;
        let mut cats = self.cats.lock().unwrap();
        let Some(runtime) = cats.get_mut(cat_id) else {
            return Ok(());
        };
        if runtime.generation == generation {
            return Ok(());
        }
        runtime.generation = generation;
        if let Some(metering) = &mut runtime.metering {
            // A generation change is a new attribution epoch even when the
            // same cgroup counter continues monotonically. The first sample
            // in the new epoch establishes a fresh baseline.
            metering.source_epoch = uuid::Uuid::new_v4().simple().to_string();
        }
        Ok(())
    }

    fn retire_warm_metering(&self, cat_id: &str) -> Result<()> {
        let target = {
            let cats = self.cats.lock().unwrap();
            let runtime = cats
                .get(cat_id)
                .context("warm runtime vanished before usage finalization")?;
            anyhow::ensure!(
                runtime.state == ObservedState::Warm,
                "cannot retire compute metering from {:?}",
                runtime.state
            );
            runtime.lifecycle_telemetry_target(cat_id)
        };
        let Some(expected_metering) = target.metering.clone() else {
            return Ok(());
        };

        // The Warm state already hides this epoch from heartbeat sampling.
        // Persist its final checkpoint before dropping the cgroup identity so
        // a failed lifecycle job can retry without inventing an interval.
        self.finalize_usage(target)?;

        let retired = {
            let mut cats = self.cats.lock().unwrap();
            cats.get_mut(cat_id).and_then(|runtime| {
                let still_same_epoch = runtime.state == ObservedState::Warm
                    && runtime.metering.as_ref().is_some_and(|metering| {
                        metering.source_epoch == expected_metering.source_epoch
                    });
                if still_same_epoch {
                    runtime.metering.take()
                } else {
                    None
                }
            })
        };
        Self::remove_metering_cgroup(retired.as_ref());
        Ok(())
    }

    fn finalize_usage(&self, target: CatTelemetryTarget) -> Result<()> {
        if target.metering.is_none() {
            return Ok(());
        }
        if let Some(finalizer) = &self.usage_finalizer {
            finalizer.finalize(target)?;
        }
        Ok(())
    }

    fn observed_of(&self, cat_id: &str) -> ObservedState {
        self.cats
            .lock()
            .unwrap()
            .get(cat_id)
            .map(|rt| rt.state)
            .unwrap_or(ObservedState::Cold)
    }

    fn run_action(&self, job: &NodeJob) -> Result<ObservedState> {
        match &job.action {
            NodeJobAction::StartCat {
                cat_id,
                volumes,
                cpus,
                memory_mib,
                ..
            } => {
                // Launches are no longer serialized node-wide, so they need
                // their own ceiling; see `launch_admission`. Warm restore
                // charges the wake budget inside `restore_cat`, so this stays on
                // the StartCat action only.
                let _permit = self
                    .launch_admission
                    .acquire(resume_commitment_bytes(*memory_mib))
                    .with_context(|| format!("admit launch of cat {cat_id}"))?;
                self.start_cat(
                    cat_id,
                    job.cat_generation,
                    volumes.clone(),
                    *cpus,
                    *memory_mib,
                    false,
                )
            }
            NodeJobAction::StopCat { cat_id } => self.stop_cat(cat_id, true),
            NodeJobAction::SuspendCat { cat_id, work_fence } => {
                self.suspend_cat(cat_id, work_fence.as_ref())
            }
            NodeJobAction::ResumeCat { cat_id } => self.resume_cat(cat_id),
            NodeJobAction::WarmCat { cat_id } => self.warm_cat(cat_id),
            NodeJobAction::RestoreCat { cat_id } => self.restore_cat(cat_id, job.cat_generation),
            NodeJobAction::AttachDisk { cat_id, volume } => {
                self.attach_disk(cat_id, volume.clone())
            }
            NodeJobAction::DetachDisk { cat_id, disk_id } => self.detach_disk(cat_id, disk_id),
            NodeJobAction::SyncCat { cat_id } => self.sync_cat(cat_id),
            NodeJobAction::CleanupCat { cat_id } => self.stop_cat(cat_id, false),
        }
    }

    // ------------------------------------------------------------------
    // Start / restore
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn start_cat(
        &self,
        cat_id: &str,
        generation: i64,
        volumes: Vec<VolumeGrant>,
        cpus: u32,
        memory_mib: u64,
        warm_restore: bool,
    ) -> Result<ObservedState> {
        if let Some(rt) = self.cats.lock().unwrap().get(cat_id) {
            if rt.state == ObservedState::Running {
                return Ok(ObservedState::Running);
            }
        }
        if !warm_restore {
            // A Cold fallback can arrive while this Node still owns a stale
            // Suspended/Warm runtime (for example after a control-plane
            // reconnect). Tear it down before removing/recreating its runtime
            // directory; otherwise the old VMM keeps the API socket and
            // memory backing open and the new VMM cannot start.
            let existing = self.cats.lock().unwrap().remove(cat_id);
            if let Some(mut runtime) = existing {
                if matches!(
                    runtime.state,
                    ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
                ) {
                    if let Err(error) =
                        self.finalize_usage(runtime.lifecycle_telemetry_target(cat_id))
                    {
                        self.cats
                            .lock()
                            .unwrap()
                            .insert(cat_id.to_string(), runtime);
                        return Err(error);
                    }
                }
                self.teardown(&mut runtime, false);
                let _ = std::fs::remove_dir_all(&runtime.dir);
            }
        }
        if let VmmMode::CloudHypervisor(chc) = &self.cfg.vmm {
            return self.start_cat_ch(
                &chc.clone(),
                cat_id,
                generation,
                volumes,
                cpus,
                memory_mib,
                warm_restore,
            );
        }
        let dir = self.cfg.state_dir.join("cats").join(cat_id);
        if !warm_restore {
            // Cold boot: no residue may leak process identity or cache.
            let _ = std::fs::remove_dir_all(&dir);
        }
        std::fs::create_dir_all(&dir)?;

        let ctl_sock = short_socket_path(&self.cfg.state_dir, cat_id, "ctl");
        let web_sock = short_socket_path(&self.cfg.state_dir, cat_id, "web");
        let runtime_sock = short_socket_path(&self.cfg.state_dir, cat_id, "runtime");
        symlink_socket(&dir.join("ctl.sock"), &ctl_sock);
        symlink_socket(&dir.join("web.sock"), &web_sock);
        let metering = self.prepare_metering(cat_id)?;
        let mut rt = CatRuntime {
            generation,
            cpus,
            memory_mib,
            state: ObservedState::Starting,
            guest: None,
            boot_id: None,
            blockds: HashMap::new(),
            volumes: volumes.clone(),
            dir: dir.clone(),
            ctl_sock,
            web_sock,
            runtime_sock,
            activity: Arc::new(RuntimeActivity::default()),
            metering,
            ch: None,
        };
        let launch = (|| -> Result<String> {
            for grant in &volumes {
                // FakeVmm never consumes vhost-user; NBD is its only frontend.
                let proc = self.spawn_blockd(cat_id, &dir, grant, 1, None)?;
                let process_id = proc.child.id();
                rt.blockds.insert(grant.disk_id.clone(), proc);
                self.attach_to_metering(&rt, process_id)?;
            }
            self.write_disk_map(&rt)?;
            let state_file = rt.state_file();
            let guest = self.spawn_guest(&rt, warm_restore.then_some(state_file.as_path()))?;
            let process_id = guest.id();
            rt.guest = Some(guest);
            self.attach_to_metering(&rt, process_id)?;
            let boot_id = self.wait_guest_ready(&rt)?;
            Ok(boot_id)
        })();

        match launch {
            Ok(boot_id) => {
                if warm_restore
                    && rt.boot_id.is_some()
                    && rt.boot_id.as_deref() != Some(boot_id.as_str())
                {
                    self.teardown(&mut rt, false);
                    bail!("warm restore produced a different boot id");
                }
                rt.boot_id = Some(boot_id);
                rt.state = ObservedState::Running;
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                Ok(ObservedState::Running)
            }
            Err(e) => {
                self.teardown(&mut rt, true);
                Err(e)
            }
        }
    }

    /// Cloud Hypervisor start/restore: blockd -> (seed) -> block attach
    /// (kernel NBD device or vhost-user socket) -> CH direct-kernel boot (or
    /// snapshot restore) -> vsock health.
    #[allow(clippy::too_many_arguments)]
    fn start_cat_ch(
        &self,
        chc: &ChConfig,
        cat_id: &str,
        generation: i64,
        volumes: Vec<VolumeGrant>,
        cpus: u32,
        memory_mib: u64,
        warm_restore: bool,
    ) -> Result<ObservedState> {
        let restore_started = Instant::now();
        let dir = self.cfg.state_dir.join("cats").join(cat_id);
        // Warm restore reuses local state (snapshot + nbd mapping).
        let previous = if warm_restore {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            anyhow::ensure!(
                rt.state == ObservedState::Warm,
                "cannot restore from {:?}",
                rt.state
            );
            rt.ch
                .as_ref()
                .map(|c| {
                    (
                        c.nbd.clone(),
                        c.snapshot_dir.clone(),
                        rt.boot_id.clone(),
                        c.network.clone(),
                    )
                })
                .context("warm state missing CH runtime")?
        } else {
            let _ = std::fs::remove_dir_all(&dir);
            (HashMap::new(), None, None, None)
        };
        let (prev_nbd, snapshot_dir, expected_boot, previous_network) = previous;
        if warm_restore {
            if let Some(previous_runtime) = self.cats.lock().unwrap().remove(cat_id) {
                Self::remove_metering_cgroup(previous_runtime.metering.as_ref());
            }
        }
        std::fs::create_dir_all(&dir)?;
        let memory_file = dir.join(ch::GUEST_MEMORY_FILE);
        if warm_restore {
            anyhow::ensure!(
                memory_file.is_file(),
                "warm state is missing Guest memory backing"
            );
        } else {
            ch::prepare_memory_backing(&memory_file, memory_mib)?;
        }

        let mut chrt = ChRuntime {
            api_sock: short_socket_path(&self.cfg.state_dir, cat_id, "chapi"),
            vsock_sock: short_socket_path(&self.cfg.state_dir, cat_id, "vsock"),
            memory_file,
            nbd: HashMap::new(),
            snapshot_dir: None,
            network: previous_network,
        };
        let metering = self.prepare_metering(cat_id)?;
        let mut rt = CatRuntime {
            generation,
            cpus,
            memory_mib,
            state: ObservedState::Starting,
            guest: None,
            boot_id: None,
            blockds: HashMap::new(),
            volumes: volumes.clone(),
            dir: dir.clone(),
            ctl_sock: short_socket_path(&self.cfg.state_dir, cat_id, "ctl"),
            web_sock: short_socket_path(&self.cfg.state_dir, cat_id, "web"),
            runtime_sock: short_socket_path(&self.cfg.state_dir, cat_id, "runtime"),
            activity: Arc::new(RuntimeActivity::default()),
            metering,
            ch: None,
        };
        // Warm may already own a tap from the preserved runtime. Publish the
        // partial CH state immediately so every failure path can tear it down.
        rt.ch = Some(chrt.clone());

        let launch = (|| -> Result<String> {
            // 1. Block backends.
            let blockd_started = Instant::now();
            // Cloud Hypervisor refuses num_queues > boot vCPUs, and the backend
            // must expose exactly the queues the VMM will configure.
            let vhost_user_queues = ch::vhost_user_queues_for(chc, cpus);
            // The root disk is provisioned from the shared golden image instead of
            // streaming a private copy of the rootfs through the block frontend
            // (ADR-0017). Publishing happens once per node, not per launch.
            let seed_image_id = match (&chc.seed_image, warm_restore) {
                (Some(image), false) => Some(self.ensure_image_published(image)?),
                _ => None,
            };
            for grant in &volumes {
                // Data disks have no image.
                let seed = seed_image_id
                    .as_deref()
                    .filter(|_| grant.mount_path == "/");
                let proc = self.spawn_blockd(cat_id, &dir, grant, vhost_user_queues, seed)?;
                let process_id = proc.child.id();
                rt.blockds.insert(grant.disk_id.clone(), proc);
                self.attach_to_metering(&rt, process_id)?;
            }
            let blockd_us = blockd_started.elapsed().as_micros();
            // 2. Block attach (root first => /dev/vda). On a kernel-NBD restore
            //    the device indices must match the snapshot exactly; vhost-user
            //    sockets are derived from the Cat and disk id, so they are
            //    already stable across a Warm restore.
            let mut ordered: Vec<&VolumeGrant> = volumes.iter().collect();
            ordered.sort_by_key(|g| g.mount_path != "/");
            let mut disks = Vec::new();
            let block_attach_started = Instant::now();
            for grant in ordered {
                let proc = &rt.blockds[&grant.disk_id];
                match chc.block_path {
                    BlockPath::KernelNbd => {
                        let want = prev_nbd.get(&grant.disk_id).map(|s| s.as_str());
                        let dev = ch::nbd_attach(chc, &proc.socket, want)?;
                        chrt.nbd.insert(grant.disk_id.clone(), dev.clone());
                        // Record the attachment before any later fallible setup
                        // so the shared failure teardown cannot leak it.
                        rt.ch = Some(chrt.clone());
                        disks.push(ch::file_disk_arg(&dev, chc.block_direct));
                    }
                    BlockPath::VhostUser => {
                        let socket = proc
                            .vhost_user_socket
                            .as_ref()
                            .context("blockd was started without a vhost-user socket")?;
                        disks.push(ch::vhost_user_disk_arg(
                            socket,
                            vhost_user_queues,
                            chc.vhost_user_queue_size,
                        )?);
                    }
                }
            }
            let block_attach_us = block_attach_started.elapsed().as_micros();
            rt.ch = Some(chrt.clone());
            if !warm_restore {
                chrt.network = ch::prepare_network(chc, cat_id)?;
                rt.ch = Some(chrt.clone());
            }
            // 3. VMM. Store the child in `rt` immediately so a failure in
            //    readiness/health still lets `teardown` kill it (no orphan
            //    holding the api socket).
            let serial_log = dir.join("serial.log");
            let vmm_spawn_started = Instant::now();
            let vmm = ch::spawn_vmm(&ch::ChSpawn {
                cfg: chc,
                api_sock: &chrt.api_sock,
                vsock_sock: &chrt.vsock_sock,
                serial_log: &serial_log,
                cpus,
                memory_mib,
                memory_file: Some(&chrt.memory_file),
                disks: &disks,
                restore_from: snapshot_dir.as_deref(),
                network: chrt.network.as_ref(),
            })?;
            let process_id = vmm.id();
            rt.guest = Some(vmm);
            self.attach_to_metering(&rt, process_id)?;
            let vmm_spawn_us = vmm_spawn_started.elapsed().as_micros();
            rt.ch = Some(chrt.clone());
            let api_ready_started = Instant::now();
            ch::wait_api_ready(&chrt.api_sock, rt.guest.as_mut().unwrap())?;
            let api_ready_us = api_ready_started.elapsed().as_micros();
            let resume_started = Instant::now();
            if warm_restore {
                ch::resume(&chrt.api_sock)?;
            }
            let resume_us = resume_started.elapsed().as_micros();
            // 4. Guest agent over vsock.
            let conn = GuestConn::Vsock(chrt.vsock_sock.clone(), GUEST_VSOCK_PORT);
            // Keep this below the control plane's 60-second node-job timeout
            // so a failed start tears down its partial VMM before the control
            // plane can retry the Cat on the same node.
            let deadline = Instant::now() + Duration::from_secs(30);
            let guest_health_started = Instant::now();
            loop {
                if let Ok(mut client) = conn.connect() {
                    if let Ok((boot_id, _)) = client.health() {
                        if warm_restore {
                            tracing::info!(
                                cat = cat_id,
                                block_path = chc.block_path.as_str(),
                                total_us = restore_started.elapsed().as_micros(),
                                blockd_us,
                                block_attach_us,
                                vmm_spawn_us,
                                api_ready_us,
                                resume_us,
                                guest_health_us = guest_health_started.elapsed().as_micros(),
                                "warm restore phase timings"
                            );
                        }
                        return Ok(boot_id);
                    }
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "guest never became healthy over vsock"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        })();

        match launch {
            Ok(boot_id) => {
                if warm_restore
                    && expected_boot.is_some()
                    && expected_boot.as_deref() != Some(&boot_id)
                {
                    rt.ch = Some(chrt);
                    self.teardown(&mut rt, false);
                    bail!("warm restore produced a different kernel boot id");
                }
                rt.boot_id = Some(boot_id);
                rt.state = ObservedState::Running;
                rt.ch = Some(chrt);
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                Ok(ObservedState::Running)
            }
            Err(e) => {
                rt.ch = Some(chrt);
                self.teardown(&mut rt, false);
                Err(e)
            }
        }
    }

    /// Publish the golden root once and return its image id (ADR-0017).
    ///
    /// Runs `cats-blockd --publish-image`, which needs only the object store, so
    /// the node needs no object-store wiring of its own and publishing stays in
    /// the one component that already speaks every adapter. Idempotent, so a
    /// second node — or a restart — costs one manifest HEAD.
    fn ensure_image_published(&self, image: &Path) -> Result<String> {
        let mut cached = self.seed_image_id.lock().unwrap();
        if let Some(image_id) = cached.as_ref() {
            return Ok(image_id.clone());
        }
        let started = Instant::now();
        let mut cmd = Command::new(&self.cfg.blockd_bin);
        cmd.arg("--publish-image")
            .arg(image)
            .arg("--object-store-adapter")
            .arg(&self.cfg.object_store.name);
        for option in self.cfg.object_store.config.to_cli() {
            cmd.arg("--object-store-option").arg(option);
        }
        let output = cmd.output().context("run cats-blockd --publish-image")?;
        if !output.status.success() {
            bail!(
                "publishing {} failed: {} {}",
                image.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .last()
                    .unwrap_or_default()
            );
        }
        let image_id = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("IMAGE ").map(|id| id.trim().to_string()))
            .context("cats-blockd --publish-image printed no image id")?;
        tracing::info!(
            image = %image.display(),
            image_id = %image_id,
            publish_ms = started.elapsed().as_millis(),
            "published the golden root"
        );
        *cached = Some(image_id.clone());
        Ok(image_id)
    }

    fn spawn_blockd(
        &self,
        cat_id: &str,
        cat_dir: &Path,
        grant: &VolumeGrant,
        vhost_user_queues: usize,
        seed_image_id: Option<&str>,
    ) -> Result<BlockdProc> {
        let socket = short_socket_path(
            &self.cfg.state_dir,
            cat_id,
            &format!("nbd-{}", grant.disk_id),
        );
        symlink_socket(
            &cat_dir.join(format!("nbd-{}.sock", grant.disk_id)),
            &socket,
        );
        // The Guest's data path. Both frontends serve one engine in one
        // process, so seeding and recovery keep using NBD while the VMM uses
        // vhost-user (spec §7.1).
        let vhost_user_socket = match &self.cfg.vmm {
            VmmMode::CloudHypervisor(chc) if chc.block_path == BlockPath::VhostUser => {
                let socket = short_socket_path(
                    &self.cfg.state_dir,
                    cat_id,
                    &format!("vhu-{}", grant.disk_id),
                );
                symlink_socket(
                    &cat_dir.join(format!("vhu-{}.sock", grant.disk_id)),
                    &socket,
                );
                Some(socket)
            }
            _ => None,
        };
        let data_dir = cat_dir.join(format!("vol-{}", grant.disk_id));
        let mut cmd = Command::new(&self.cfg.blockd_bin);
        cmd.arg("--volume-id")
            .arg(&grant.volume_id)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--attachment-id")
            .arg(&grant.attachment_id)
            .arg("--metadata-store-adapter")
            .arg(&self.cfg.metadata_store.name)
            .arg("--object-store-adapter")
            .arg(&self.cfg.object_store.name)
            .arg("--listen-unix")
            .arg(&socket)
            .arg("--create-volume-size")
            .arg(grant.size_bytes.to_string())
            .arg("--lease-ttl-ms")
            .arg(self.cfg.blockd_lease_ttl_ms.to_string());
        let control_socket = short_socket_path(
            &self.cfg.state_dir,
            cat_id,
            &format!("ctl-{}", grant.disk_id),
        );
        symlink_socket(
            &cat_dir.join(format!("ctl-{}.sock", grant.disk_id)),
            &control_socket,
        );
        cmd.arg("--listen-control").arg(&control_socket);
        if grant.durability == cats_api::resources::DiskDurability::Relaxed {
            cmd.arg("--durability").arg("relaxed");
        }
        if let Some(image_id) = seed_image_id {
            // Provision from the already-published image: one manifest GET plus a
            // map write, no data bytes (ADR-0017). Safe unconditionally, because a
            // volume that already has a generation is left alone.
            cmd.arg("--seed-image-id").arg(image_id);
        }
        if let (Some(socket), VmmMode::CloudHypervisor(chc)) = (&vhost_user_socket, &self.cfg.vmm) {
            cmd.arg("--listen-vhost-user")
                .arg(socket)
                .arg("--vhost-user-queues")
                .arg(vhost_user_queues.to_string())
                .arg("--vhost-user-queue-size")
                .arg(chc.vhost_user_queue_size.to_string());
        }
        let log = std::fs::File::create(cat_dir.join(format!("blockd-{}.log", grant.disk_id)))
            .context("create blockd log")?;
        for option in self.cfg.metadata_store.config.to_cli() {
            cmd.arg("--metadata-store-option").arg(option);
        }
        for option in self.cfg.object_store.config.to_cli() {
            cmd.arg("--object-store-option").arg(option);
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(log)
            .env_remove("CATS_CRASH_POINT")
            .spawn()
            .context("spawn cats-blockd")?;
        let mut proc = BlockdProc {
            child,
            socket,
            vhost_user_socket,
            control_socket,
            grant: grant.clone(),
        };
        self.wait_blockd_ready(&mut proc)
            .with_context(|| format!("blockd for {} never became ready", grant.disk_id))?;
        Ok(proc)
    }

    fn prepare_metering(&self, cat_id: &str) -> Result<Option<RuntimeMetering>> {
        let Some(root) = &self.cfg.metering_cgroup_root else {
            return Ok(None);
        };
        let source_epoch = uuid::Uuid::new_v4().simple().to_string();
        let node_dir = root.join(&self.cfg.node_id);
        std::fs::create_dir_all(&node_dir)
            .with_context(|| format!("create node metering cgroup {}", node_dir.display()))?;
        enable_cgroup_controllers(&node_dir)?;
        let cgroup_path = node_dir.join(format!("{cat_id}-{source_epoch}"));
        std::fs::create_dir_all(&cgroup_path)
            .with_context(|| format!("create metering cgroup {}", cgroup_path.display()))?;
        for required in ["cgroup.procs", "cpu.stat", "memory.current"] {
            if !cgroup_path.join(required).is_file() {
                let _ = std::fs::remove_dir(&cgroup_path);
                bail!(
                    "metering cgroup {} lacks {required}; configure a delegated cgroup v2 subtree with CPU and memory accounting",
                    cgroup_path.display()
                );
            }
        }
        Ok(Some(RuntimeMetering {
            cgroup_path,
            source_epoch,
        }))
    }

    fn attach_to_metering(&self, runtime: &CatRuntime, process_id: u32) -> Result<()> {
        let Some(metering) = &runtime.metering else {
            return Ok(());
        };
        std::fs::write(
            metering.cgroup_path.join("cgroup.procs"),
            process_id.to_string(),
        )
        .with_context(|| {
            format!(
                "move process {process_id} into metering cgroup {}",
                metering.cgroup_path.display()
            )
        })
    }

    fn remove_metering_cgroup(metering: Option<&RuntimeMetering>) {
        if let Some(metering) = metering {
            let _ = std::fs::remove_dir(&metering.cgroup_path);
        }
    }

    fn wait_blockd_ready(&self, proc: &mut BlockdProc) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(client) = cats_blockd::nbd::NbdClient::connect_unix(&proc.socket) {
                let _ = client.disconnect();
                return Ok(());
            }
            if let Some(status) = proc.child.try_wait()? {
                bail!("cats-blockd exited during startup: {status} (lease held or bad config?)");
            }
            if Instant::now() > deadline {
                bail!("timed out waiting for blockd socket");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn write_disk_map(&self, rt: &CatRuntime) -> Result<()> {
        let map: HashMap<String, DiskMapEntry> = rt
            .blockds
            .iter()
            .map(|(disk_id, p)| {
                (
                    disk_id.clone(),
                    DiskMapEntry {
                        socket: p.socket.clone(),
                        mount_path: p.grant.mount_path.clone(),
                    },
                )
            })
            .collect();
        let tmp = rt.disk_map_path().with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&map)?)?;
        std::fs::rename(&tmp, rt.disk_map_path())?;
        Ok(())
    }

    fn spawn_guest(&self, rt: &CatRuntime, state_file: Option<&Path>) -> Result<Child> {
        let mut cmd = Command::new(&self.cfg.guest_agent_bin);
        cmd.arg("--control-socket")
            .arg(rt.ctl_socket())
            .arg("--disk-map")
            .arg(rt.disk_map_path())
            .arg("--web-socket")
            .arg(rt.web_socket())
            // FakeVmm runs the Guest Agent as a host process, so the Node
            // supplies an isolated test socket. A real VMM never opens the
            // Guest's /run/cats/runtime.sock.
            .arg("--runtime-socket")
            .arg(rt.runtime_socket())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(rt.dir.join("guest.log")).context("create guest log")?);
        if let Some(sf) = state_file {
            cmd.arg("--state-file").arg(sf);
        }
        cmd.spawn().context("spawn cats-guest-agent")
    }

    fn wait_guest_ready(&self, rt: &CatRuntime) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(mut client) = rt.conn().connect() {
                if let Ok((boot_id, _)) = client.health() {
                    return Ok(boot_id);
                }
            }
            if Instant::now() > deadline {
                bail!("guest agent never became healthy");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // ------------------------------------------------------------------
    // Stop / cleanup
    // ------------------------------------------------------------------

    fn stop_cat(&self, cat_id: &str, graceful: bool) -> Result<ObservedState> {
        let Some(mut rt) = self.cats.lock().unwrap().remove(cat_id) else {
            // Idempotent: also sweep any residue from a previous life.
            let dir = self.cfg.state_dir.join("cats").join(cat_id);
            let _ = std::fs::remove_dir_all(&dir);
            return Ok(ObservedState::Cold);
        };
        if matches!(
            rt.state,
            ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
        ) {
            if let Err(error) = self.finalize_usage(rt.lifecycle_telemetry_target(cat_id)) {
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                return Err(error);
            }
        }
        self.teardown(&mut rt, graceful);
        let _ = std::fs::remove_dir_all(&rt.dir);
        Ok(ObservedState::Cold)
    }

    /// Best-effort teardown: durable flush (graceful), then kill children.
    fn teardown(&self, rt: &mut CatRuntime, graceful: bool) {
        if graceful && rt.guest.is_some() {
            if rt.state == ObservedState::Suspended {
                // A paused guest cannot flush; wake it first.
                match &rt.ch {
                    Some(chrt) => {
                        let _ = ch::resume(&chrt.api_sock);
                    }
                    None => {
                        if let Some(g) = &rt.guest {
                            signal(g, libc::SIGCONT);
                        }
                    }
                }
            }
            if let Ok(mut client) = rt.conn().connect() {
                let _ = client.syncfs();
                if rt.ch.is_none() {
                    let _ = client.shutdown();
                }
            }
        }
        let was_graceful = graceful && rt.guest.is_some();
        if let Some(mut vmm) = rt.guest.take() {
            match &rt.ch {
                Some(chrt) => ch::shutdown_vmm(&chrt.api_sock, &mut vmm),
                None => {
                    let _ = vmm.kill();
                    let _ = vmm.wait();
                }
            }
        }
        if was_graceful {
            // syncfs pushed the guest page cache into the engines; on relaxed
            // volumes that only stages. A stop is a forced flush point
            // (ADR-0021), so publish before the backends die — and only now,
            // with the VMM gone, can no late fsync slip in behind the drain.
            for proc in rt.blockds.values() {
                if let Err(e) = proc.drain() {
                    tracing::warn!("teardown drain: {e:#}");
                }
            }
        }
        if let (Some(chrt), VmmMode::CloudHypervisor(chc)) = (&rt.ch, &self.cfg.vmm) {
            for dev in chrt.nbd.values() {
                ch::nbd_detach(chc, dev);
            }
            if let Some(network) = &chrt.network {
                ch::remove_network(chc, network);
            }
        }
        for (_, mut p) in rt.blockds.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
            let _ = std::fs::remove_file(&p.socket);
            if let Some(socket) = &p.vhost_user_socket {
                let _ = std::fs::remove_file(socket);
            }
        }
        if let Some(chrt) = &mut rt.ch {
            let _ = std::fs::remove_file(&chrt.api_sock);
            let _ = std::fs::remove_file(&chrt.vsock_sock);
            chrt.nbd.clear();
            chrt.network = None;
        }
        let _ = std::fs::remove_file(rt.ctl_socket());
        let _ = std::fs::remove_file(rt.web_socket());
        let _ = std::fs::remove_file(rt.runtime_socket());
        Self::remove_metering_cgroup(rt.metering.as_ref());
        rt.state = ObservedState::Cold;
    }

    // ------------------------------------------------------------------
    // Suspend / resume (pause + page-out)
    // ------------------------------------------------------------------

    fn suspend_cat(
        &self,
        cat_id: &str,
        work_fence: Option<&SuspendWorkFence>,
    ) -> Result<ObservedState> {
        let (conn, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if rt.state == ObservedState::Suspended {
                return Ok(ObservedState::Suspended);
            }
            if rt.state != ObservedState::Running {
                bail!("cannot suspend from {:?}", rt.state);
            }
            (rt.conn(), rt.activity.clone())
        };

        // Close the Node proxy/exec gate before asking the Guest Agent to
        // close its user-work gate. Any rejected arrival increments the local
        // sequence and cancels this suspend.
        let node_sequence = activity.prepare()?;
        let attempt = (|| -> Result<()> {
            let mut client = conn.connect()?;
            let expected_guest_sequence = match work_fence {
                Some(fence) => fence.guest_lease_sequence,
                None => client.work_status(None, 0)?.lease_sequence,
            };
            client.prepare_suspend(expected_guest_sequence)?;

            // ADR-0002 order: quiesce + durable FLUSH before pausing.
            client.syncfs()?;
            let guest_status = client.work_status(None, 0)?;
            if guest_status.lease_sequence != expected_guest_sequence
                || !activity.unchanged_since(node_sequence)
            {
                let _ = client.abort_suspend();
                return Err(ActivityChanged.into());
            }

            let mut cats = self.cats.lock().unwrap();
            let rt = cats
                .get_mut(cat_id)
                .context("cat vanished during suspend")?;
            if rt.state != ObservedState::Running {
                let _ = client.abort_suspend();
                return Err(ActivityChanged.into());
            }
            match &rt.ch {
                Some(chrt) => ch::pause(&chrt.api_sock)?,
                None => {
                    let guest = rt.guest.as_ref().context("guest process missing")?;
                    signal(guest, libc::SIGSTOP);
                }
            }
            let page_out_target = match &rt.ch {
                Some(chrt) => Some((
                    rt.guest.as_ref().context("VMM process missing")?.id(),
                    chrt.memory_file.clone(),
                )),
                None => None,
            };
            rt.state = ObservedState::Suspended;
            drop(cats);

            // A proxy/exec can arrive in the tiny pause window. It never
            // enters the guest, but it does invalidate the gate. Resume now;
            // the control plane will retry after the work event is visible.
            if !activity.unchanged_since(node_sequence) {
                let mut cats = self.cats.lock().unwrap();
                let rt = cats.get_mut(cat_id).context("cat vanished after pause")?;
                match &rt.ch {
                    Some(chrt) => ch::resume(&chrt.api_sock)?,
                    None => {
                        let guest = rt.guest.as_ref().context("guest process missing")?;
                        signal(guest, libc::SIGCONT);
                    }
                }
                rt.state = ObservedState::Running;
                drop(cats);
                let mut resumed = conn.connect()?;
                let _ = resumed.abort_suspend();
                return Err(ActivityChanged.into());
            }
            if let Some((vmm_pid, memory_file)) = page_out_target {
                match ch::page_out_memory(vmm_pid, &memory_file) {
                    Ok(stats) => tracing::info!(
                        cat = %cat_id,
                        vmm_pid,
                        ranges = stats.ranges,
                        advised_bytes = stats.bytes_advised,
                        rss_before_bytes = stats.rss_before_bytes,
                        rss_after_bytes = stats.rss_after_bytes,
                        "paged out suspended Guest memory"
                    ),
                    Err(error) => {
                        // Never report a pause-only Cat as Suspended. Return it
                        // to Running and let the controller retry or demote it.
                        let mut cats = self.cats.lock().unwrap();
                        let rt = cats
                            .get_mut(cat_id)
                            .context("cat vanished after page-out failure")?;
                        let chrt = rt.ch.as_ref().context("CH runtime missing")?;
                        ch::resume(&chrt.api_sock)?;
                        rt.state = ObservedState::Running;
                        bail!("Guest memory page-out failed: {error:#}");
                    }
                }
            }
            Ok(())
        })();

        if attempt.is_err() {
            activity.open();
            if let Ok(mut client) = conn.connect() {
                let _ = client.abort_suspend();
            }
        }
        attempt.map(|()| ObservedState::Suspended)
    }

    fn resume_cat(&self, cat_id: &str) -> Result<ObservedState> {
        // Read the commitment and drop the lock: `acquire` may block on other
        // wakes, and holding `cats` across that wait would deadlock every
        // other job on this node.
        let memory_mib = {
            let cats = self.cats.lock().unwrap();
            let rt = cats.get(cat_id).context("cat is not on this node")?;
            if rt.state == ObservedState::Running {
                return Ok(ObservedState::Running);
            }
            if rt.state != ObservedState::Suspended {
                bail!("cannot resume from {:?}", rt.state);
            }
            rt.memory_mib
        };
        // Held until this wake finishes; released on every exit path.
        let _permit = self
            .admission
            .acquire(resume_commitment_bytes(memory_mib))
            .with_context(|| format!("admit resume of cat {cat_id}"))?;

        let mut cats = self.cats.lock().unwrap();
        // The Cat may have moved while this wake sat in the queue.
        let rt = cats.get_mut(cat_id).context("cat is not on this node")?;
        if rt.state == ObservedState::Running {
            return Ok(ObservedState::Running);
        }
        if rt.state != ObservedState::Suspended {
            bail!("cannot resume from {:?}", rt.state);
        }
        match &rt.ch {
            Some(chrt) => ch::resume(&chrt.api_sock)?,
            None => {
                let guest = rt.guest.as_ref().context("guest process missing")?;
                signal(guest, libc::SIGCONT);
            }
        }
        let expected = rt.boot_id.clone();
        let conn = rt.conn();
        drop(cats);
        // The resumed guest must be the same one (boot_id preserved).
        let mut client = conn.connect()?;
        let (boot_id, _) = client.health()?;
        if expected.as_deref() != Some(boot_id.as_str()) {
            bail!("resume produced a different boot id");
        }
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat vanished during resume")?;
        rt.state = ObservedState::Running;
        rt.activity.open();
        let conn = rt.conn();
        drop(cats);
        if let Ok(mut client) = conn.connect() {
            let _ = client.abort_suspend();
        }
        Ok(ObservedState::Running)
    }

    // ------------------------------------------------------------------
    // Warm (snapshot + exit) / restore
    // ------------------------------------------------------------------

    fn warm_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat is not on this node")?;
        match rt.state {
            ObservedState::Warm => return Ok(ObservedState::Warm),
            ObservedState::Suspended | ObservedState::Running => {}
            other => bail!("cannot warm from {other:?}"),
        }
        // CH mode: real memory snapshot, then everything exits (ADR-0002).
        if rt.ch.is_some() {
            let api = rt.ch.as_ref().expect("checked").api_sock.clone();
            if rt.state != ObservedState::Suspended {
                // Not paused yet: durable flush first, then pause.
                let mut client = rt.conn().connect()?;
                client.syncfs()?;
                ch::pause(&api)?;
            }
            // Warm is a forced flush point (ADR-0021): the VMM exits and a
            // restore may happen after this host is long gone.
            for proc in rt.blockds.values() {
                proc.drain()?;
            }
            let memory_file = rt.ch.as_ref().expect("checked").memory_file.clone();
            ch::sync_memory_backing(&memory_file)?;
            let snap_dir = rt.dir.join("snapshot");
            let _ = std::fs::remove_dir_all(&snap_dir);
            ch::snapshot(&api, &snap_dir)?;
            if let Some(mut vmm) = rt.guest.take() {
                ch::shutdown_vmm(&api, &mut vmm);
            }
            let nbd_devices: Vec<String> = rt
                .ch
                .as_ref()
                .expect("checked")
                .nbd
                .values()
                .cloned()
                .collect();
            if let VmmMode::CloudHypervisor(chc) = &self.cfg.vmm {
                for dev in &nbd_devices {
                    ch::nbd_detach(chc, dev);
                }
            }
            for (_, mut p) in rt.blockds.drain() {
                let _ = p.child.kill();
                let _ = p.child.wait();
            }
            if let Some(chrt) = &mut rt.ch {
                chrt.snapshot_dir = Some(snap_dir);
            }
            rt.state = ObservedState::Warm;
            return Ok(ObservedState::Warm);
        }
        if let Some(g) = &rt.guest {
            signal(g, libc::SIGCONT); // wake a suspended guest to snapshot it
        }
        let mut client = rt.conn().connect()?;
        // Durable point, then persist the process identity ("snapshot"),
        // then exit the VMM and the block backends (ADR-0002 Warm).
        client.syncfs()?;
        client.save_state(&rt.state_file())?;
        let _ = client.shutdown();
        if let Some(mut g) = rt.guest.take() {
            let _ = g.kill();
            let _ = g.wait();
        }
        for (_, mut p) in rt.blockds.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
        }
        rt.state = ObservedState::Warm;
        Ok(ObservedState::Warm)
    }

    fn restore_cat(&self, cat_id: &str, generation: i64) -> Result<ObservedState> {
        let (volumes, expected_boot_id, cpus, memory_mib) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            if rt.state != ObservedState::Warm {
                bail!("cannot restore from {:?}", rt.state);
            }
            match &rt.ch {
                Some(chrt) => {
                    anyhow::ensure!(
                        chrt.snapshot_dir.as_ref().is_some_and(|d| d.exists()),
                        "warm snapshot is missing"
                    );
                }
                None => anyhow::ensure!(rt.state_file().exists(), "warm snapshot is missing"),
            }
            (
                rt.volumes.clone(),
                rt.boot_id.clone(),
                rt.cpus,
                rt.memory_mib,
            )
        };
        // Warm reads Guest RAM back out of the snapshot, so it is charged the
        // same resume commitment as Suspended (ADR-0002 §8). Acquired before
        // any state is torn down so a queued restore stays restorable.
        let _permit = self
            .admission
            .acquire(resume_commitment_bytes(memory_mib))
            .with_context(|| format!("admit warm restore of cat {cat_id}"))?;
        {
            // Re-validate: the Cat may have moved while queued.
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            if rt.state != ObservedState::Warm {
                bail!("cannot restore from {:?}", rt.state);
            }
        }
        self.retire_warm_metering(cat_id)?;
        // CH mode keeps the runtime entry (start_cat_ch consumes it).
        if matches!(self.cfg.vmm, VmmMode::Fake) {
            self.cats.lock().unwrap().remove(cat_id);
        }
        // Re-launch on the preserved local state (cache + snapshot). The
        // fake VMM re-acquires the volume leases; the production vhost
        // implementation keeps the lease alive across Warm instead.
        let observed = self.start_cat(cat_id, generation, volumes, cpus, memory_mib, true)?;
        // A real VMM snapshot preserves the Guest Agent's quiescing bit.
        // Restoring is a committed wake, so reopen the Guest-side admission
        // gate before reporting Running. FakeVmm restores a fresh registry;
        // AbortSuspend is harmless there too.
        if let Some(conn) = self.cats.lock().unwrap().get(cat_id).map(CatRuntime::conn) {
            if let Ok(mut client) = conn.connect() {
                client.abort_suspend()?;
            }
        }
        let now_boot = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .and_then(|rt| rt.boot_id.clone());
        if expected_boot_id.is_some() && now_boot != expected_boot_id {
            let _ = self.stop_cat(cat_id, false);
            bail!("warm restore lost process identity");
        }
        Ok(observed)
    }

    // ------------------------------------------------------------------
    // Hot attach / detach
    // ------------------------------------------------------------------

    fn attach_disk(&self, cat_id: &str, grant: VolumeGrant) -> Result<ObservedState> {
        let activity = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .context("cat is not running on this node")?
            .activity
            .clone();
        let _activity = activity.acquire()?;
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        if rt.state != ObservedState::Running {
            bail!("hot attach requires a running cat");
        }
        if rt.ch.is_some() {
            // vm.add-disk hotplug lands with the vhost-user milestone; cold
            // cats pick bindings up at the next start.
            bail!("hot attach is not supported in Cloud Hypervisor mode yet");
        }
        if rt.blockds.contains_key(&grant.disk_id) {
            return Ok(ObservedState::Running); // idempotent
        }
        let dir = rt.dir.clone();
        // Unreachable in Cloud Hypervisor mode (hot attach is rejected above).
        let proc = self.spawn_blockd(cat_id, &dir, &grant, 1, None)?;
        let process_id = proc.child.id();
        rt.blockds.insert(grant.disk_id.clone(), proc);
        if let Err(error) = self.attach_to_metering(rt, process_id) {
            if let Some(mut proc) = rt.blockds.remove(&grant.disk_id) {
                let _ = proc.child.kill();
                let _ = proc.child.wait();
            }
            return Err(error);
        }
        rt.volumes.push(grant);
        self.write_disk_map(rt)?;
        Ok(ObservedState::Running)
    }

    /// `cats sync`: everything acknowledged inside the guest becomes durable
    /// in the object store before this returns (ADR-0021). Guest page cache
    /// first, then every engine's staged packs.
    fn sync_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let activity = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .context("cat is not running on this node")?
            .activity
            .clone();
        let _activity = activity.acquire()?;
        let cats = self.cats.lock().unwrap();
        let rt = cats
            .get(cat_id)
            .context("cat is not running on this node")?;
        rt.conn().connect()?.syncfs().context("guest syncfs")?;
        for proc in rt.blockds.values() {
            proc.drain()?;
        }
        Ok(rt.state)
    }

    fn detach_disk(&self, cat_id: &str, disk_id: &str) -> Result<ObservedState> {
        let activity = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .context("cat is not running on this node")?
            .activity
            .clone();
        let _activity = activity.acquire()?;
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        let Some(mut proc) = rt.blockds.remove(disk_id) else {
            return Ok(rt.state); // idempotent
        };
        rt.volumes.retain(|v| v.disk_id != disk_id);
        // Final durable flush through the guest before the backend exits.
        if let Ok(mut client) = rt.conn().connect() {
            let _ = client.flush_disk(disk_id);
        }
        // Detach is a forced flush point (ADR-0021): on a relaxed disk the
        // guest flush above only staged.
        if let Err(e) = proc.drain() {
            tracing::warn!("detach drain of {disk_id}: {e:#}");
        }
        self.write_disk_map(rt)?;
        let _ = proc.child.kill();
        let _ = proc.child.wait();
        Ok(rt.state)
    }

    // ------------------------------------------------------------------
    // Exec / proxy passthrough
    // ------------------------------------------------------------------

    pub fn exec(&self, cat_id: &str, command: Vec<String>) -> Result<(i32, String, String)> {
        self.exec_with_input(cat_id, command, Default::default(), Vec::new())
    }

    pub fn exec_with_input(
        &self,
        cat_id: &str,
        command: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        stdin: Vec<u8>,
    ) -> Result<(i32, String, String)> {
        let (conn, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not running (state {:?})", rt.state);
            }
            (rt.conn(), rt.activity.clone())
        };
        let _guard = activity.acquire()?;
        let mut client = conn.connect_long_running()?;
        client.exec_with_input(command, env, stdin)
    }

    pub(crate) fn open_shell(
        &self,
        cat_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<(GuestShell, RuntimeActivityGuard)> {
        let (conn, activity) = {
            let cats = self.cats.lock().unwrap();
            let runtime = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if runtime.state != ObservedState::Running {
                bail!("cat is not running (state {:?})", runtime.state);
            }
            (runtime.conn(), runtime.activity.clone())
        };
        let guard = activity.acquire()?;
        let shell = conn.connect_shell()?.start_shell(rows, cols)?;
        Ok((shell, guard))
    }

    /// Forward an HTTP request to the guest service. In Cloud Hypervisor mode
    /// this is a direct host-tap -> guest-IP connection; FakeVmm uses its
    /// Unix test workload. Errors with "not active" when the Cat is not
    /// running here, which the gateway treats as a stale route.
    pub fn proxy_http(
        &self,
        cat_id: &str,
        request: &ProxyHttpRequest,
    ) -> Result<ProxyHttpResponse> {
        use std::io::{Read, Write};
        anyhow::ensure!(
            request.target_port > 0,
            "endpoint target port must be non-zero"
        );
        let (target, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats.get(cat_id).context("cat is not active on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not active on this node (state {:?})", rt.state);
            }
            let target = match rt.ch.as_ref() {
                Some(chrt) => {
                    let network = chrt.network.as_ref().context("cat has no guest network")?;
                    let ip = network
                        .guest_ip
                        .split('/')
                        .next()
                        .context("invalid guest address")?
                        .parse::<std::net::IpAddr>()
                        .context("invalid guest IP")?;
                    ProxyTarget::Tcp(std::net::SocketAddr::new(ip, request.target_port))
                }
                None => ProxyTarget::Unix(rt.web_socket()),
            };
            (target, rt.activity.clone())
        };
        let _guard = activity.acquire()?;
        let raw_request = build_guest_http_request(request)?;
        let mut buf = Vec::new();
        match target {
            ProxyTarget::Unix(path) => {
                let mut stream = std::os::unix::net::UnixStream::connect(&path)?;
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                stream.write_all(&raw_request)?;
                stream
                    .take((MAX_PROXY_RESPONSE_BYTES + 1) as u64)
                    .read_to_end(&mut buf)?;
            }
            ProxyTarget::Tcp(address) => {
                let mut stream =
                    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                        .with_context(|| format!("connect guest service {address}"))?;
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                stream.write_all(&raw_request)?;
                stream
                    .take((MAX_PROXY_RESPONSE_BYTES + 1) as u64)
                    .read_to_end(&mut buf)?;
            }
        }
        anyhow::ensure!(
            buf.len() <= MAX_PROXY_RESPONSE_BYTES,
            "guest response exceeds {MAX_PROXY_RESPONSE_BYTES} bytes"
        );
        parse_guest_http_response(&buf)
    }

    /// Resolve a streaming endpoint and hold the runtime activity fence for
    /// the entire connection. Callers must keep the returned guard alive.
    pub(crate) fn open_proxy_target(
        &self,
        cat_id: &str,
        target_port: u16,
    ) -> Result<(ProxyTarget, RuntimeActivityGuard)> {
        anyhow::ensure!(target_port > 0, "endpoint target port must be non-zero");
        let (target, activity) = {
            let cats = self.cats.lock().unwrap();
            let runtime = cats.get(cat_id).context("cat is not active on this node")?;
            if runtime.state != ObservedState::Running {
                bail!("cat is not active on this node (state {:?})", runtime.state);
            }
            let target = match runtime.ch.as_ref() {
                Some(ch_runtime) => {
                    let network = ch_runtime
                        .network
                        .as_ref()
                        .context("cat has no guest network")?;
                    let ip = network
                        .guest_ip
                        .split('/')
                        .next()
                        .context("invalid guest address")?
                        .parse::<std::net::IpAddr>()
                        .context("invalid guest IP")?;
                    ProxyTarget::Tcp(std::net::SocketAddr::new(ip, target_port))
                }
                None => ProxyTarget::Unix(runtime.web_socket()),
            };
            (target, runtime.activity.clone())
        };
        let guard = activity.acquire()?;
        Ok((target, guard))
    }
}

/// Prepare the delegated cgroup v2 hierarchy before any Cat runtime starts.
///
/// A systemd service initially places its own process in the delegated unit
/// cgroup. cgroup v2 does not allow CPU or memory controllers to be enabled
/// for children while that parent contains a process, so the node agent first
/// moves itself into a sibling leaf and leaves the configured metering root
/// empty for per-Cat descendants.
pub(crate) fn initialize_metering_cgroup(cfg: &NodeConfig) -> Result<()> {
    let Some(root) = &cfg.metering_cgroup_root else {
        return Ok(());
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        bail!("authoritative cgroup v2 billing is supported only on Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let delegated_root = root.parent().with_context(|| {
            format!(
                "metering cgroup root {} must have a delegated parent",
                root.display()
            )
        })?;
        let delegated_processes = delegated_root.join("cgroup.procs");
        let process_id = std::process::id().to_string();
        let current_processes =
            std::fs::read_to_string(&delegated_processes).with_context(|| {
                format!(
                    "read delegated cgroup process list {}",
                    delegated_processes.display()
                )
            })?;
        anyhow::ensure!(
            current_processes.lines().any(|line| line == process_id),
            "node agent is not running in configured delegated cgroup {}",
            delegated_root.display()
        );

        let agent_leaf = delegated_root.join("agent");
        std::fs::create_dir_all(&agent_leaf)
            .with_context(|| format!("create node-agent cgroup {}", agent_leaf.display()))?;
        std::fs::write(agent_leaf.join("cgroup.procs"), &process_id)
            .with_context(|| format!("move node agent into {}", agent_leaf.display()))?;
        let remaining_processes =
            std::fs::read_to_string(&delegated_processes).with_context(|| {
                format!(
                    "re-read delegated cgroup process list {}",
                    delegated_processes.display()
                )
            })?;
        anyhow::ensure!(
            remaining_processes.lines().all(|line| line.is_empty()),
            "delegated cgroup {} contains processes other than the node agent",
            delegated_root.display()
        );

        enable_cgroup_controllers(delegated_root)?;
        std::fs::create_dir_all(root)
            .with_context(|| format!("create metering cgroup root {}", root.display()))?;
        enable_cgroup_controllers(root)?;
        Ok(())
    }
}

fn enable_cgroup_controllers(cgroup: &Path) -> Result<()> {
    let controllers_path = cgroup.join("cgroup.controllers");
    let controllers = std::fs::read_to_string(&controllers_path)
        .with_context(|| format!("read cgroup controllers {}", controllers_path.display()))?;
    let available = controllers
        .split_whitespace()
        .collect::<std::collections::HashSet<_>>();
    for required in ["cpu", "memory"] {
        anyhow::ensure!(
            available.contains(required),
            "delegated cgroup {} does not expose the {required} controller",
            cgroup.display()
        );
    }
    let subtree_control = cgroup.join("cgroup.subtree_control");
    std::fs::write(&subtree_control, "+cpu +memory").with_context(|| {
        format!(
            "enable cpu and memory controllers in {}",
            subtree_control.display()
        )
    })
}

const MAX_PROXY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn build_guest_http_request(request: &ProxyHttpRequest) -> Result<Vec<u8>> {
    use std::io::Write as _;

    anyhow::ensure!(is_http_token(&request.method), "invalid HTTP method");
    anyhow::ensure!(
        request.path.starts_with('/')
            && !request.path.contains('\r')
            && !request.path.contains('\n'),
        "invalid HTTP request path"
    );
    let guest_host = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-host"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("guest");
    anyhow::ensure!(
        !guest_host.contains('\r') && !guest_host.contains('\n'),
        "invalid forwarded host"
    );
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nhost: {guest_host}\r\n",
        request.method, request.path
    )
    .into_bytes();
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || hop_by_hop_header(name)
        {
            continue;
        }
        anyhow::ensure!(
            is_http_token(name) && !value.contains('\r') && !value.contains('\n'),
            "invalid HTTP header"
        );
        write!(&mut raw, "{name}: {value}\r\n")?;
    }
    write!(
        &mut raw,
        "x-cats-route-epoch: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        request.route_epoch,
        request.body.len()
    )?;
    raw.extend_from_slice(&request.body);
    Ok(raw)
}

fn parse_guest_http_response(raw: &[u8]) -> Result<ProxyHttpResponse> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("guest returned malformed HTTP response")?;
    let head = std::str::from_utf8(&raw[..head_end]).context("guest returned non-UTF8 headers")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("guest response is missing status")?
        .parse::<u16>()
        .context("invalid guest response status")?;
    anyhow::ensure!((100..=599).contains(&status), "invalid guest HTTP status");

    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("malformed guest response header")?;
        let name = name.trim();
        let value = value.trim();
        anyhow::ensure!(
            is_http_token(name) && !value.contains('\r') && !value.contains('\n'),
            "invalid guest response header"
        );
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .context("invalid guest Content-Length")?,
            );
        }
        if !hop_by_hop_header(name) && !name.eq_ignore_ascii_case("content-length") {
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let encoded_body = &raw[head_end + 4..];
    let body = if chunked {
        decode_chunked_body(encoded_body)?
    } else if let Some(length) = content_length {
        anyhow::ensure!(
            encoded_body.len() >= length,
            "truncated guest HTTP response body"
        );
        encoded_body[..length].to_vec()
    } else {
        encoded_body.to_vec()
    };
    Ok(ProxyHttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked_body(mut encoded: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .context("malformed chunked response")?;
        let size_line =
            std::str::from_utf8(&encoded[..line_end]).context("invalid chunk size line")?;
        let size =
            usize::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)
                .context("invalid chunk size")?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        anyhow::ensure!(
            encoded.len() >= size + 2 && &encoded[size..size + 2] == b"\r\n",
            "truncated chunked response"
        );
        decoded.extend_from_slice(&encoded[..size]);
        anyhow::ensure!(
            decoded.len() <= MAX_PROXY_RESPONSE_BYTES,
            "guest response exceeds {MAX_PROXY_RESPONSE_BYTES} bytes"
        );
        encoded = &encoded[size + 2..];
    }
}

fn signal(child: &Child, sig: i32) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: `pid` comes from the live `Child`; `kill` copies both scalar
        // arguments and does not retain any borrowed memory.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[derive(Default)]
    struct RecordingUsageFinalizer {
        targets: Mutex<Vec<CatTelemetryTarget>>,
    }

    impl UsageFinalizer for RecordingUsageFinalizer {
        fn finalize(&self, target: CatTelemetryTarget) -> Result<()> {
            self.targets.lock().unwrap().push(target);
            Ok(())
        }
    }

    fn test_runtime(state: ObservedState, cgroup_path: PathBuf) -> CatRuntime {
        CatRuntime {
            generation: 1,
            cpus: 1,
            memory_mib: 256,
            state,
            guest: None,
            boot_id: Some("boot-a".to_string()),
            blockds: HashMap::new(),
            volumes: Vec::new(),
            dir: PathBuf::from("/tmp/cats-metering-test"),
            ctl_sock: PathBuf::from("/tmp/cats-metering-test-ctl"),
            web_sock: PathBuf::from("/tmp/cats-metering-test-web"),
            runtime_sock: PathBuf::from("/tmp/cats-metering-test-runtime"),
            activity: Arc::new(RuntimeActivity::default()),
            metering: Some(RuntimeMetering {
                cgroup_path,
                source_epoch: "epoch-a".to_string(),
            }),
            ch: None,
        }
    }

    #[test]
    fn warm_hides_compute_meter_while_suspended_keeps_it() {
        let mut runtime = test_runtime(
            ObservedState::Suspended,
            PathBuf::from("/sys/fs/cgroup/cats/cat-a"),
        );

        assert!(runtime.telemetry_target("cat-a").metering.is_some());
        runtime.state = ObservedState::Warm;
        assert!(runtime.telemetry_target("cat-a").metering.is_none());
        assert!(runtime
            .lifecycle_telemetry_target("cat-a")
            .metering
            .is_some());
    }

    #[test]
    fn warm_retirement_finalizes_then_drops_the_metering_cgroup() {
        let temp = tempfile::tempdir().unwrap();
        let cgroup = temp.path().join("cat-a");
        std::fs::create_dir(&cgroup).unwrap();
        let adapter = AdapterSelection::new("unused", cats_storage::AdapterConfig::default());
        let finalizer = Arc::new(RecordingUsageFinalizer::default());
        let runtime = NodeRuntime::new(NodeConfig {
            node_id: "node-a".to_string(),
            state_dir: temp.path().to_path_buf(),
            blockd_bin: PathBuf::from("unused-blockd"),
            guest_agent_bin: PathBuf::from("unused-guest-agent"),
            metadata_store: adapter.clone(),
            object_store: adapter,
            blockd_lease_ttl_ms: 1_000,
            metering_cgroup_root: None,
            vmm: VmmMode::Fake,
            wake_budget: WakeBudget::default(),
        })
        .with_usage_finalizer(finalizer.clone());
        runtime.cats.lock().unwrap().insert(
            "cat-a".to_string(),
            test_runtime(ObservedState::Warm, cgroup.clone()),
        );

        runtime.retire_warm_metering("cat-a").unwrap();

        let targets = finalizer.targets.lock().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].metering.as_ref().unwrap().source_epoch,
            "epoch-a"
        );
        drop(targets);
        assert!(
            runtime
                .cats
                .lock()
                .unwrap()
                .get("cat-a")
                .unwrap()
                .metering
                .is_none()
        );
        assert!(!cgroup.exists());
    }

    #[test]
    fn proxy_request_preserves_method_path_headers_and_body() {
        let request = ProxyHttpRequest {
            method: "POST".to_string(),
            path: "/api/items?q=one".to_string(),
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("connection".to_string(), "keep-alive".to_string()),
            ],
            body: br#"{"name":"cat"}"#.to_vec(),
            target_port: 8080,
            route_epoch: 7,
        };
        let raw = build_guest_http_request(&request).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("POST /api/items?q=one HTTP/1.1\r\n"));
        assert!(text.contains("host: guest\r\n"));
        assert!(text.contains("content-type: application/json\r\n"));
        assert!(text.contains("x-cats-route-epoch: 7\r\n"));
        assert!(!text.contains("keep-alive"));
        assert!(text.ends_with(r#"{"name":"cat"}"#));
    }

    #[test]
    fn proxy_response_preserves_status_headers_and_decodes_chunks() {
        let raw = b"HTTP/1.1 201 Created\r\n\
                    content-type: text/plain\r\n\
                    transfer-encoding: chunked\r\n\
                    connection: close\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = parse_guest_http_response(raw).unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"hello world");
        assert_eq!(
            response.headers,
            vec![("content-type".to_string(), "text/plain".to_string())]
        );
    }
}

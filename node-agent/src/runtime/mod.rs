//! Per-node runtime: executes NodeJobs by supervising one guest-agent
//! process ("the VM") and one cats-blockd process per attachment.
//!
//! VMM seam: this module implements the FakeVmm — a host process stands in
//! for Cloud Hypervisor, SIGSTOP/SIGCONT stand in for vCPU pause/resume,
//! and the guest state file stands in for the memory snapshot. Every block
//! byte still flows through the real cats-blockd engine, so storage
//! semantics (leases, FLUSH durability, cold restore) are exercised for
//! real. The Cloud Hypervisor mode (`VmmMode::CloudHypervisor`, Linux+KVM)
//! is implemented in `ch.rs`: direct-kernel boot, kernel-NBD block path,
//! vsock guest control, vm.pause/resume and vm.snapshot/--restore.
//!
//! Job idempotency: completed results are journaled by job_id and replayed
//! for duplicate submissions (arch doc §17.4); failures are not journaled,
//! so resubmitting a failed job's id retries it for real. The journal is
//! in-memory; a node restart loses it, which is safe because every action
//! is itself idempotent at the process level.

/// Crate-visible, unlike its sibling modules: the startup path that scans the
/// local inventory before registering with the control plane (ADR-0028 §5)
/// lives outside `runtime`.
pub(crate) mod adopt;
mod blockd_control;
mod fake;
mod ledger;
mod lifecycle;
mod metering;
mod proxy;
mod residue;
mod supervisor;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use cats_api::guest::DiskMapEntry;
use cats_api::nodejob::{
    JobPhase, NodeJob, NodeJobAction, NodeJobResult, StopCatDisposition, SuspendWorkFence,
    VolumeGrant,
};
use cats_api::requests::{ProxyHttpRequest, ProxyHttpResponse};
use cats_api::resources::{DiskDurabilityTelemetry, NodeTelemetry, ObservedState};
use cats_storage::AdapterSelection;

use crate::admission::{resume_commitment_bytes, WakeAdmission, WakeBudget, WakeLoad};
use crate::ch::{self, BlockPath, ChConfig, ChRuntime, GUEST_VSOCK_PORT};
use crate::guest_client::{GuestClient, GuestShell};
use crate::proc::ProcHandle;

use blockd_control::{blockd_log_path, BlockdProc};
use ledger::Ledger;
use metering::RuntimeMetering;
use proxy::{ActivityChanged, RuntimeActivity};
use residue::RuntimeResidue;

pub(crate) use residue::allocated_tree_bytes;

#[cfg(test)]
use blockd_control::BLOCKD_STATUS_TIMEOUT;
#[cfg(test)]
use proxy::{build_guest_http_request, parse_guest_http_response};

pub(crate) use metering::initialize_metering_cgroup;
pub(crate) use proxy::{is_activity_changed, ProxyTarget, RuntimeActivityGuard};

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
    pub blockd_max_staged_bytes: u64,
    pub blockd_max_staged_packs: usize,
    pub blockd_max_local_bytes: u64,
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

struct CatRuntime {
    generation: i64,
    cpus: u32,
    memory_mib: u64,
    state: ObservedState,
    guest: Option<ProcHandle>,
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

/// Process and filesystem identities used by the heartbeat sampler to
/// attribute host resource use to one Cat.
#[derive(Clone)]
pub(crate) struct CatTelemetryTarget {
    pub cat_id: String,
    pub generation: i64,
    pub process_ids: Vec<u32>,
    pub runtime_dir: PathBuf,
    pub metering: Option<CatMeteringTarget>,
    pub disk_durability: Vec<DiskDurabilityTelemetry>,
}

#[derive(Debug, Clone)]
pub(crate) struct CatMeteringTarget {
    pub cgroup_path: PathBuf,
    pub source_epoch: String,
}

pub(crate) trait UsageFinalizer: Send + Sync {
    fn finalize(&self, target: CatTelemetryTarget) -> Result<()>;
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
        warm_state_file(&self.dir)
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
            disk_durability: Vec::new(),
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

/// Directory-name prefix of one volume's blockd journal and cache.
const VOLUME_DIR_PREFIX: &str = "vol-";

/// The `--data-dir` the blockd serving `disk_id` for this Cat was given.
///
/// Spawn, teardown, the runtime ledger and re-adoption all name this directory,
/// and re-adoption only accepts a record whose recorded `data_dir` still exists
/// (ADR-0028 §3 step 4). Four independent spellings of the same `format!` would
/// make that check silently vacuous the first time one of them drifted, so
/// there is exactly one.
fn volume_data_dir(cat_dir: &Path, disk_id: &str) -> PathBuf {
    cat_dir.join(format!("{VOLUME_DIR_PREFIX}{disk_id}"))
}

/// Where a FakeVmm Cat's Guest state is saved when it goes Warm.
///
/// Written by `warm_cat`, required by `restore_cat` before it will restore, and
/// checked by re-adoption's Warm proof (ADR-0028 §3) — one spelling, for the
/// same reason [`volume_data_dir`] has one.
fn warm_state_file(cat_dir: &Path) -> PathBuf {
    cat_dir.join("warm-state.json")
}

pub struct NodeRuntime {
    pub cfg: NodeConfig,
    /// Conservative node-wide serialization for lifecycle/hot-plug paths that
    /// have not yet been made concurrent, plus kernel-NBD allocation. Stop and
    /// Resume are explicitly exempt; every action still holds its per-Cat lock.
    ops: Mutex<()>,
    /// Per-Cat execution locks for the concurrent wake path. Keeps the
    /// existing "one job per Cat at a time" idempotency guarantee while
    /// dropping the node-wide serialization.
    cat_ops: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    cats: Mutex<HashMap<String, CatRuntime>>,
    /// On-disk mirror of `cats`, rewritten once per job after the final state
    /// has settled (ADR-0028 §1). Local recovery aid only: it never grants a
    /// storage write right and is never consulted for authority.
    ledger: Ledger,
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
    /// Remote Stop/Cold drains may run across Cats, but an expiry wave must not
    /// create unbounded S3/PostgreSQL fan-out.
    stop_admission: StopAdmission,
    /// What the last runtime-directory sweep left behind (issue #99).
    ///
    /// Held rather than measured per heartbeat: the answer needs a walk of the
    /// whole state directory and a Unix-socket probe per abandoned Cat, and
    /// billing telemetry must not start paying for that every few seconds.
    /// `None` until the first sweep lands, so "not measured yet" stays
    /// distinguishable from "nothing to reclaim".
    residue: Mutex<Option<RuntimeResidue>>,
}

const MAX_CONCURRENT_STOPS: usize = 4;

#[derive(Debug)]
struct StopAdmission {
    limit: usize,
    in_flight: Mutex<usize>,
    released: Condvar,
}

impl StopAdmission {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: Mutex::new(0),
            released: Condvar::new(),
        }
    }

    fn acquire(&self) -> StopPermit<'_> {
        let mut in_flight = self.in_flight.lock().expect("stop admission mutex");
        while *in_flight >= self.limit {
            in_flight = self.released.wait(in_flight).expect("stop admission mutex");
        }
        *in_flight += 1;
        StopPermit { admission: self }
    }

    fn release(&self) {
        let mut in_flight = self.in_flight.lock().expect("stop admission mutex");
        *in_flight = in_flight.saturating_sub(1);
        drop(in_flight);
        self.released.notify_one();
    }
}

struct StopPermit<'a> {
    admission: &'a StopAdmission,
}

impl Drop for StopPermit<'_> {
    fn drop(&mut self) {
        self.admission.release();
    }
}

impl NodeRuntime {
    pub fn new(cfg: NodeConfig) -> Result<Self> {
        let cfg_wake_budget = cfg.wake_budget;
        let ledger = Ledger::open(&cfg.state_dir.join("runtime-ledger"))?;
        Ok(Self {
            cfg,
            ops: Mutex::new(()),
            cats: Mutex::new(HashMap::new()),
            ledger,
            cat_ops: Mutex::new(HashMap::new()),
            journal: Mutex::new(HashMap::new()),
            usage_finalizer: None,
            seed_image_id: Mutex::new(None),
            admission: WakeAdmission::new(cfg_wake_budget),
            launch_admission: WakeAdmission::new(WakeBudget {
                commitment_bytes: u64::MAX,
                ..cfg_wake_budget
            }),
            stop_admission: StopAdmission::new(MAX_CONCURRENT_STOPS),
            residue: Mutex::new(None),
        })
    }

    /// Current wake saturation, for heartbeats and tests.
    pub fn wake_load(&self) -> WakeLoad {
        self.admission.load()
    }

    /// Reclaim kernel NBD devices left connected to a server that is gone.
    ///
    /// Runs once at boot, before the agent registers and can be given a
    /// `StartCat`. Nothing else ever reclaims such a device, so without this
    /// pass the pool only shrinks: one `systemctl stop` of the worker kills
    /// every blockd in the unit cgroup, and each one leaves its device behind
    /// (issue #79).
    pub fn reclaim_leaked_block_devices(&self) {
        let VmmMode::CloudHypervisor(chc) = &self.cfg.vmm else {
            return;
        };
        // Deliberately not gated on the configured block path: a node moved to
        // vhost-user still has to clear what its kernel-NBD past left behind,
        // and a pool with nothing leaked runs no `nbd-client` at all.
        match ch::reclaim_leaked_nbd_devices(chc) {
            Ok(reclaim) if reclaim.reclaimed.is_empty() && reclaim.unreclaimed.is_empty() => {}
            Ok(reclaim) => tracing::warn!(
                reclaimed = ?reclaim.reclaimed,
                unreclaimed = ?reclaim.unreclaimed,
                "reclaimed kernel NBD devices left behind by an earlier node agent"
            ),
            Err(error) => tracing::error!(
                error = format!("{error:#}"),
                "could not sweep kernel NBD devices; leaked ones stay unusable"
            ),
        }
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
        // Sample the wake gate and the device pool before taking `cats`: the
        // two locks are never held together anywhere, and this keeps it that
        // way.
        let wake = self.admission.load();
        let (leaked_nbd_devices, nbd_devices_total) = match &self.cfg.vmm {
            VmmMode::CloudHypervisor(chc) => (
                Some(ch::leaked_nbd_device_count(chc)),
                Some(u64::from(chc.nbd_devices)),
            ),
            VmmMode::Fake => (None, None),
        };
        let residue = self.last_runtime_residue();
        let cats = self.cats.lock().unwrap();
        NodeTelemetry {
            leaked_nbd_devices,
            nbd_devices_total,
            unsupervised_runtime_dirs: residue.map(|residue| residue.dirs),
            unsupervised_runtime_bytes: residue.map(|residue| residue.bytes),
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
}

//! Resource wire types served by the control plane.
//!
//! Lifecycle states follow ADR-0002: Running / Suspended / Warm / Cold are the
//! product states; observed states add transitional phases. Suspended and Warm
//! are host-bound; any restore failure converges to Cold.

use serde::{Deserialize, Serialize};

/// States a user (or the auto-tier policy) can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    Running,
    Suspended,
    Warm,
    Cold,
    Deleted,
}

/// States the platform reports for a Cat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedState {
    Creating,
    Starting,
    Running,
    Suspending,
    Suspended,
    Warming,
    Warm,
    Stopping,
    Cold,
    Failed,
    Deleted,
    /// Node lease lost; actual state unknown until fencing completes.
    Unknown,
}

impl ObservedState {
    /// Whether a wake request must go through a full cold start.
    pub fn requires_cold_start(self) -> bool {
        matches!(
            self,
            ObservedState::Cold | ObservedState::Failed | ObservedState::Unknown
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatSpec {
    pub cpus: u32,
    pub memory_mib: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cat {
    pub id: String,
    /// Immutable resource-isolation owner and the only ownership key.
    pub workspace_id: String,
    pub name: String,
    pub image: String,
    pub spec: CatSpec,
    pub root_disk_id: String,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    /// Monotonic; bumped on every desired-state/spec mutation.
    pub generation: i64,
    /// Work-driven auto-suspend. When enabled, the last work lease release
    /// immediately requests Suspended; there is no business idle timeout.
    #[serde(default)]
    pub auto_suspend: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub created_at_unix: i64,
    /// Persisted time at which `observed_state` last changed. Automatic
    /// deeper-sleep tiers use this value, so control-plane restarts do not
    /// reset the Suspended/Warm retention clock.
    #[serde(default)]
    pub observed_state_since_unix_ms: i64,
    /// Absolute wall-clock expiry (unix seconds). Once this passes, the
    /// control plane converges the Cat to Deleted exactly as an API delete
    /// would. Absent = the Cat never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
}

/// Sources that can hold a Cat Running. Guest leases are created explicitly
/// by user programs; the Guest Agent never infers them from resource usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    Gateway,
    Exec,
    Guest,
    Pin,
    Control,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkLease {
    pub id: String,
    pub cat_id: String,
    pub kind: WorkKind,
    pub owner_id: String,
    pub label: String,
    pub expires_at_unix_ms: i64,
}

/// Explainable work state exposed to users and used by the auto-suspend
/// controller. `can_suspend_now` means the control-plane snapshot is eligible;
/// the Node/Guest quiesce barrier is still the final arbiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatWorkStatus {
    pub cat_id: String,
    pub auto_suspend: bool,
    pub work_version: i64,
    pub active_work_count: u32,
    pub leases: Vec<WorkLease>,
    pub guest_signal_fresh: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_signal_age_ms: Option<u64>,
    pub can_suspend_now: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Root,
    Persistent,
}

/// What a guest fsync acknowledgment promises for this disk (ADR-0021).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskDurability {
    /// fsync returns only once the data is durable in the object store; an
    /// acknowledged write survives losing the host outright.
    #[default]
    Strict,
    /// fsync returns after a local commit; data reaches the object store
    /// within the drain window. On unclean host loss, the most recent writes
    /// — including acknowledged fsyncs — may be lost. Lifecycle transitions
    /// (stop, suspend, warm, detach) and `cats sync` force a full drain.
    Relaxed,
}

impl DiskDurability {
    pub fn as_str(self) -> &'static str {
        match self {
            DiskDurability::Strict => "strict",
            DiskDurability::Relaxed => "relaxed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "strict" => Some(DiskDurability::Strict),
            "relaxed" => Some(DiskDurability::Relaxed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskState {
    Creating,
    /// No active attachment; persistent disks can be mounted from here.
    Available,
    /// Bound to a cat via a mount binding (attachment may or may not be live).
    Bound,
    Deleting,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    pub id: String,
    /// Immutable resource-isolation owner and the only ownership key.
    pub workspace_id: String,
    pub name: String,
    pub kind: DiskKind,
    pub size_bytes: u64,
    pub state: DiskState,
    /// What an fsync acknowledgment promises (ADR-0021). Immutable for now:
    /// changing it on a live attachment would change the meaning of acks the
    /// guest already received.
    #[serde(default)]
    pub durability: DiskDurability,
    /// Internal volume id; exposed for diagnostics, not part of the stable API.
    pub volume_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_cat_id: Option<String>,
    pub created_at_unix: i64,
}

/// Persistent association between a disk and a cat (survives Cold).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountBinding {
    pub id: String,
    pub disk_id: String,
    pub cat_id: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Attaching,
    Attached,
    Detaching,
    Detached,
    /// Fenced by a newer epoch; must never publish writes again.
    Fenced,
}

/// Runtime attachment of a disk on a node. Exactly one non-final attachment
/// may exist per disk (RWO), enforced by the control plane store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub disk_id: String,
    pub cat_id: String,
    pub node_id: String,
    /// Fencing epoch, monotonic per disk. Stale epochs must fail closed.
    pub epoch: i64,
    pub state: AttachmentState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Ready,
    Cordoned,
    /// Existing Cats are being stopped and rescheduled; no new placements.
    Draining,
    /// Heartbeats are stale. Existing Cat and disk claims are preserved until
    /// the Host recovers or an administrator confirms external fencing.
    Lost,
    /// The old Host was confirmed stopped or isolated and its Cat/disk claims
    /// were revoked. This node identity must not become schedulable again.
    Fenced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub cpus: u32,
    pub memory_mib: u64,
}

/// Actual host resources attributed to one Cat by its owning node.
///
/// CPU is expressed as logical CPU cores consumed during the latest sample
/// interval (1.0 means one fully busy logical CPU). Memory is the aggregate
/// RSS of the Cat's supervised runtime processes. Disk is the allocated host
/// footprint under the Cat runtime directory, including cache and snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatResourceTelemetry {
    pub cat_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_usage_cores: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_disk_used_bytes: Option<u64>,
    /// Per-volume local/remote durability watermarks. This is deliberately a
    /// list rather than a Cat-wide aggregate: one unhealthy PersistentDisk
    /// must not be hidden by an up-to-date RootDisk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disk_durability: Vec<DiskDurabilityTelemetry>,
}

/// One block engine's local-first replication state as observed by its node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskDurabilityTelemetry {
    pub disk_id: String,
    pub mode: String,
    pub local_durable_generation: i64,
    pub remote_durable_generation: i64,
    pub unpublished_generations: u64,
    pub unpublished_bytes: u64,
    pub oldest_unpublished_age_ms: u64,
    pub max_unpublished_generations: u64,
    pub max_unpublished_bytes: u64,
    pub local_allocated_bytes: u64,
    #[serde(default)]
    pub local_accounted_bytes: u64,
    pub max_local_bytes: u64,
    pub evicted_cache_chunks: u64,
    pub backpressured: bool,
    pub fenced: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_publish_error: Option<String>,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Last telemetry sample reported by a node agent. Host-level values are
/// optional so development nodes on non-Linux systems can still heartbeat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeTelemetry {
    pub observed_cats: u64,
    pub allocated_cpus: u32,
    pub allocated_memory_mib: u64,
    /// Wakes currently admitted by the node's concurrent-wake gate, and the
    /// resume commitment they hold (ADR-0002 §8). Operators need these to see
    /// wake queueing instead of inferring it from latency.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub wake_in_flight: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub wake_commitment_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub wake_peak_in_flight: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub wake_commitment_budget_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cat_resources: Vec<CatResourceTelemetry>,
    /// Kernel NBD devices the host holds connected to a server that is gone,
    /// and the size of the pool they come from. Absent off the kernel-NBD
    /// path. Nothing reported these before, so a pool two thirds leaked looked
    /// exactly like a pool two thirds busy until the host deadlocked on it
    /// (issue #79); the total is reported alongside so an alarm can be a
    /// fraction of the pool rather than a bare count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaked_nbd_devices: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbd_devices_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_logical_cpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_cpu_usage_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_average_1m: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_memory_total_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_memory_available_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_disk_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_disk_available_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    /// Base URL of the node agent job API, e.g. `http://127.0.0.1:7301`.
    pub agent_url: String,
    /// Base URL of the node gateway for guest traffic.
    pub gateway_url: String,
    pub state: NodeState,
    pub capacity: NodeCapacity,
    pub last_heartbeat_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<NodeTelemetry>,
}

/// Administrator-facing node view combining declared capacity, placement
/// accounting and the most recent agent telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSummary {
    pub node: Node,
    pub assigned_cats: u64,
    pub assigned_cpus: u32,
    pub assigned_memory_mib: u64,
    pub heartbeat_age_seconds: u64,
    /// Cats the agent reported in its latest heartbeat that the control plane
    /// does not have assigned to this node. Non-zero means the node runs
    /// workloads no operator surface would otherwise show, and a drain will
    /// not cordon until it reaches zero.
    #[serde(default)]
    pub orphan_cats: u64,
}

/// Administrator-facing Cat row within one worker node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCatSummary {
    pub cat: Cat,
    /// Provisioned logical capacity across the RootDisk and every bound
    /// PersistentDisk. This is a request/allocation, not measured usage.
    pub requested_disk_bytes: u64,
    /// Missing when the node has not yet published a matching Cat sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<CatResourceTelemetry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Pending,
    Running,
    Succeeded,
    Failed,
}

impl OperationPhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, OperationPhase::Succeeded | OperationPhase::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    /// Immutable ownership is persisted so authorization still works after
    /// the target resource has been deleted.
    pub workspace_id: String,
    pub kind: String,
    pub resource_id: String,
    pub resource_generation: i64,
    pub phase: OperationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::error::ErrorBody>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatStateCounts {
    pub total: u64,
    pub running: u64,
    pub suspended: u64,
    pub warm: u64,
    pub cold: u64,
    pub transitional: u64,
    pub failed_or_unknown: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStateCounts {
    pub total: u64,
    pub ready: u64,
    pub cordoned: u64,
    pub draining: u64,
    pub lost: u64,
    #[serde(default)]
    pub fenced: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationCounts {
    pub pending: u64,
    pub running: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetCapacity {
    pub total_cpus: u64,
    pub assigned_cpus: u64,
    pub total_memory_mib: u64,
    pub assigned_memory_mib: u64,
}

/// Actual host resource use aggregated from the latest node heartbeats.
/// Missing samples remain `None` rather than being presented as zero use.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_cpus: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_usage_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_used_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_used_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total_bytes: Option<u64>,
}

/// JSON monitoring snapshot exposed to administrators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringOverview {
    pub generated_at_unix: i64,
    pub cats: CatStateCounts,
    pub nodes: NodeStateCounts,
    pub operations: OperationCounts,
    pub capacity: FleetCapacity,
    pub usage: FleetUsage,
    /// Fleet-wide total of agent-reported Cats without a matching assignment,
    /// summed over the latest heartbeat of every node.
    #[serde(default)]
    pub orphan_cats: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakePolicy {
    /// Requests to the endpoint wake a non-running cat.
    WakeOnRequest,
    /// Requests fail fast with 503 while the cat is not running.
    NoWake,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub cat_id: String,
    pub name: String,
    /// Stable public hostname, e.g. `dev-a1b2c3d4e5f6.cats.run`.
    pub hostname: String,
    pub target_port: u16,
    pub protocol: String,
    pub wake_policy: WakePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub disk_id: String,
    /// Committed volume generation captured by this snapshot.
    pub generation: i64,
    pub root_hash_hex: String,
    pub created_at_unix: i64,
}

/// Route binding published to gateways.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBinding {
    pub hostname: String,
    pub workspace_id: String,
    pub cat_id: String,
    pub node_id: String,
    pub gateway_url: String,
    pub target_port: u16,
    /// Route epoch, monotonic per endpoint. Gateways re-validate on every hop.
    pub epoch: i64,
    pub wake_policy: WakePolicy,
}

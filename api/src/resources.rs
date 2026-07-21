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
    pub project: String,
    pub name: String,
    pub image: String,
    pub spec: CatSpec,
    pub root_disk_id: String,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    /// Monotonic; bumped on every desired-state/spec mutation.
    pub generation: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Root,
    Persistent,
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
    pub project: String,
    pub name: String,
    pub kind: DiskKind,
    pub size_bytes: u64,
    pub state: DiskState,
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
    Lost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub cpus: u32,
    pub memory_mib: u64,
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
    pub kind: String,
    pub resource_id: String,
    pub resource_generation: i64,
    pub phase: OperationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::error::ErrorBody>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
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
    /// Stable hostname, e.g. `web.dev.default.cats.local`.
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
    pub project: String,
    pub cat_id: String,
    pub node_id: String,
    pub gateway_url: String,
    pub target_port: u16,
    /// Route epoch, monotonic per endpoint. Gateways re-validate on every hop.
    pub epoch: i64,
    pub wake_policy: WakePolicy,
}

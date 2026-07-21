//! Request/response bodies for the versioned control-plane HTTP API.
//!
//! Conventions (architecture doc §4/§17):
//! - every mutation accepts `Idempotency-Key`; retries return the original
//!   operation instead of creating duplicate resources;
//! - long mutations return `202 Accepted` with an `Operation`;
//! - `If-Match: "<generation>"` guards concurrent modification.

use serde::{Deserialize, Serialize};

use crate::resources::{Cat, Disk, Endpoint, Operation, WakePolicy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCatRequest {
    pub name: String,
    pub image: String,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u64,
    #[serde(default = "default_root_size")]
    pub root_size_bytes: u64,
    /// Optional persistent disk created and mounted at create time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<CreateCatDisk>,
}

fn default_cpus() -> u32 {
    2
}
fn default_memory_mib() -> u64 {
    2048
}
fn default_root_size() -> u64 {
    crate::chunk::DEFAULT_ROOT_DISK_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCatDisk {
    pub name: String,
    pub size_bytes: u64,
    pub mount_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDiskRequest {
    pub name: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountDiskRequest {
    pub cat_id: String,
    pub mount_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmountDiskRequest {
    pub cat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResizeDiskRequest {
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEndpointRequest {
    pub name: String,
    pub target_port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_wake_policy")]
    pub wake_policy: WakePolicy,
}

fn default_protocol() -> String {
    "http".to_string()
}
fn default_wake_policy() -> WakePolicy {
    WakePolicy::WakeOnRequest
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Response wrapper for mutations: the operation plus the (possibly still
/// converging) resource snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatOperationResponse {
    pub operation: Operation,
    pub cat: Cat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskOperationResponse {
    pub operation: Operation,
    pub disk: Disk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResponse {
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
}

/// Node registration/heartbeat payloads (node-agent -> control plane).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    pub node_id: String,
    pub agent_url: String,
    pub gateway_url: String,
    pub cpus: u32,
    pub memory_mib: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    /// Cats currently running on the node with their observed runtime state.
    pub cats: Vec<HeartbeatCat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatCat {
    pub cat_id: String,
    pub generation: i64,
    pub state: crate::resources::ObservedState,
}

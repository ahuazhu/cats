//! Request/response bodies for the versioned control-plane HTTP API.
//!
//! Conventions (architecture doc §4/§17):
//! - every mutation accepts `Idempotency-Key`; retries return the original
//!   operation instead of creating duplicate resources;
//! - long mutations return `202 Accepted` with an `Operation`;
//! - `If-Match: "<generation>"` guards concurrent modification.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::guest::GuestWorkLease;
use crate::resources::{
    Cat, CatWorkStatus, DiskDurability, Endpoint, NodeTelemetry, Operation, WakePolicy, WorkKind,
    WorkLease,
};

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
    /// Work-driven auto-suspend is enabled for new Cats unless explicitly disabled.
    #[serde(default = "default_auto_suspend")]
    pub auto_suspend: bool,
    /// Optional persistent disk created and mounted at create time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<CreateCatDisk>,
    /// Optional absolute expiry (unix seconds). Once it passes, the control
    /// plane deletes the Cat automatically. Omitted = the Cat never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
    /// Durability of the disks this request creates — the root disk and the
    /// optional `disk` (ADR-0021). Omitted = strict.
    #[serde(default)]
    pub durability: DiskDurability,
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
fn default_auto_suspend() -> bool {
    true
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
    #[serde(default)]
    pub durability: DiskDurability,
}

/// Explicit authorization for destructive lost-Host fencing.
///
/// A stale heartbeat is not sufficient evidence: the caller must first prove
/// through an external mechanism that the old Host can no longer execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FenceNodeRequest {
    pub confirm_host_stopped_or_isolated: bool,
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
    /// Environment additions for the child process. Values travel in the
    /// authenticated request body instead of argv, so deploy credentials do
    /// not appear in process listings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional bytes connected to the child process' standard input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stdin: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWorkspaceTokenRequest {
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceToken {
    pub id: String,
    pub workspace_id: String,
    pub label: String,
    pub created_at_unix: i64,
}

/// Returned only once when a workspace token is created. Cats stores only
/// the SHA-256 digest of `token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedWorkspaceToken {
    pub access_token: WorkspaceToken,
    pub token: String,
}

/// Internal gateway -> owning-node HTTP proxy request.
///
/// The gateway resolves the endpoint and supplies the route's target port.
/// The node still fails closed unless the Cat is currently running there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub target_port: u16,
    pub route_epoch: i64,
    /// Public hostname whose active binding authorized this hop.
    #[serde(default)]
    pub hostname: String,
    /// Opaque EdDSA JWS issued by the control plane (ADR-0033).
    #[serde(default)]
    pub route_grant: String,
}

/// Guest HTTP response returned by the owning node to the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// JSON control messages carried in WebSocket text frames. PTY input/output
/// uses binary WebSocket frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShellClientControl {
    Resize { rows: u16, cols: u16 },
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShellServerControl {
    Exit { exit_code: i32 },
    Error { message: String },
}

/// Terminal messages are intentionally small. This caps public and internal
/// WebSocket buffering before data reaches the Guest protocol's own bound.
pub const MAX_SHELL_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAutoSuspendRequest {
    pub enabled: bool,
}

/// `PUT /cats/{cat}/expiry`. `expires_at_unix: null` clears the expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateExpiryRequest {
    #[serde(default)]
    pub expires_at_unix: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::{CreateCatRequest, RegisterNodeRequest};

    #[test]
    fn create_cat_defaults_to_auto_suspend() {
        let request: CreateCatRequest = serde_json::from_value(serde_json::json!({
            "name": "worker",
            "image": "ubuntu-24.04"
        }))
        .unwrap();
        assert!(request.auto_suspend);
    }

    #[test]
    fn legacy_node_registration_defaults_to_ready_admission() {
        let request: RegisterNodeRequest = serde_json::from_str(
            r#"{
                "node_id":"node-a",
                "agent_url":"http://127.0.0.1:7301",
                "gateway_url":"http://127.0.0.1:7301",
                "cpus":4,
                "memory_mib":4096
            }"#,
        )
        .expect("deserialize the legacy registration payload");

        assert!(!request.initially_cordoned);
        assert!(request.route_grant_public_key_sha256.is_none());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSuspendResponse {
    pub cat: Cat,
    pub work: CatWorkStatus,
}

/// Internal platform work lease. Gateway and exec acquire before waking or
/// entering the guest, then release on every completion/error path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquireWorkRequest {
    pub cat_id: String,
    pub kind: WorkKind,
    pub owner_id: String,
    pub label: String,
    pub ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquireWorkResponse {
    pub lease: WorkLease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseWorkRequest {
    pub lease_id: String,
}

/// Event-driven Guest lease update from the owning Node Agent. A periodic
/// identical update refreshes freshness and repairs a lost event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeWorkStatusRequest {
    pub node_id: String,
    pub cat_id: String,
    pub generation: i64,
    pub guest_source_epoch: String,
    pub guest_lease_sequence: u64,
    pub leases: Vec<GuestWorkLease>,
}

/// Response wrapper for mutations: the operation plus the (possibly still
/// converging) resource snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatOperationResponse {
    pub operation: Operation,
    pub cat: Cat,
}

/// `202 Accepted` body for an OCI deployment that outran the synchronous wait.
///
/// A deploy that finishes inside the wait answers `200` with a bare
/// [`crate::oci::OciDeployment`] instead, so a caller that predates operations
/// keeps working. `deployment` is populated once the operation reaches
/// `Succeeded`, which lets one poll carry both the phase and the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciDeploymentOperationResponse {
    pub operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<crate::oci::OciDeployment>,
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
    /// Stable identity of the Ed25519 verifier key this Node actually loaded.
    /// Absent only for pre-Route-Grant Nodes during the additive rollout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_grant_public_key_sha256: Option<String>,
    /// Only controls the scheduling state of a node the control plane has
    /// never seen. Re-registration preserves the administrator's existing
    /// cordon decision.
    #[serde(default)]
    pub initially_cordoned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    /// Cats currently running on the node with their observed runtime state.
    pub cats: Vec<HeartbeatCat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<NodeTelemetry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatCat {
    pub cat_id: String,
    pub generation: i64,
    pub state: crate::resources::ObservedState,
}

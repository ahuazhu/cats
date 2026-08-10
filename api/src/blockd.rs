//! Host-side control protocol shared by `cats-blockd` and the node agent.
//!
//! The control socket remains a line-oriented protocol: one `drain` or
//! `status` command per connection and one `OK ...` or `ERR ...` response.
//! The status payload is stable JSON described by [`DurabilityStatus`].
//!
//! One piece of blockd's on-disk layout is shared here too: the pending-pack
//! journal is what tells an outside reader whether a volume directory still
//! holds acknowledged writes nobody has published (ADR-0021/0022), and the
//! node agent has to answer that about a directory whose blockd is long gone
//! before it may reclaim the bytes (issue #99). Two independent spellings of
//! the same path would make that check silently vacuous the first time one of
//! them drifted, so there is one.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::runtime_reconciliation::{
    AcquireOrigin, Epoch, FenceEpoch, Id, RandomId128, RemoteHead,
};

/// Directory under a blockd `--data-dir` holding locally durable, remotely
/// unpublished packs.
pub const PENDING_PACK_DIR: &str = "pending";

/// Suffix of a complete pack file in [`PENDING_PACK_DIR`]. A file without it is
/// a torn write that was never renamed into place.
pub const PACK_FILE_SUFFIX: &str = ".pack";

/// Default per-volume local replication backlog.
///
/// This is an admission boundary, not an RPO promise: while remote
/// publication is unavailable, acknowledged relaxed FLUSHes remain durable on
/// this Host and consume this reservation.
pub const DEFAULT_MAX_STAGED_BYTES: u64 = 8 << 30;

/// Bound for workloads made entirely of tiny durability barriers.
pub const DEFAULT_MAX_STAGED_PACKS: usize = 4_096;

/// Default per-volume physical cache plus pending-journal footprint ceiling.
pub const DEFAULT_MAX_LOCAL_BYTES: u64 = 16 << 30;

/// A request accepted by the blockd host-control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockdControlCommand {
    Drain,
    Status,
}

impl BlockdControlCommand {
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Drain => "drain",
            Self::Status => "status",
        }
    }
}

impl fmt::Display for BlockdControlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_wire())
    }
}

impl FromStr for BlockdControlCommand {
    type Err = UnknownBlockdControlCommand;

    fn from_str(command: &str) -> Result<Self, Self::Err> {
        match command {
            "drain" => Ok(Self::Drain),
            "status" => Ok(Self::Status),
            other => Err(UnknownBlockdControlCommand(other.to_string())),
        }
    }
}

/// An unrecognized blockd control command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownBlockdControlCommand(String);

impl UnknownBlockdControlCommand {
    pub fn command(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownBlockdControlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown blockd control command {:?}", self.0)
    }
}

impl std::error::Error for UnknownBlockdControlCommand {}

/// A response returned by the blockd host-control socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockdControlResponse {
    Ok(String),
    Error(String),
}

impl BlockdControlResponse {
    pub fn ok(payload: impl Into<String>) -> Self {
        Self::Ok(payload.into())
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error(message.into())
    }

    /// Encode exactly one response line, preserving the existing wire format.
    pub fn to_wire(&self) -> String {
        match self {
            Self::Ok(payload) => format!("OK {payload}\n"),
            Self::Error(message) => format!("ERR {message}\n"),
        }
    }

    /// Decode one response line. Leading/trailing whitespace is treated the
    /// same way as the original node client.
    pub fn parse_wire(line: &str) -> Result<Self, InvalidBlockdControlResponse> {
        let line = line.trim();
        if let Some(payload) = line.strip_prefix("OK ") {
            return Ok(Self::Ok(payload.to_string()));
        }
        if let Some(message) = line.strip_prefix("ERR ") {
            return Ok(Self::Error(message.to_string()));
        }
        Err(InvalidBlockdControlResponse(line.to_string()))
    }
}

/// A response line that has neither the `OK ` nor `ERR ` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBlockdControlResponse(String);

impl InvalidBlockdControlResponse {
    pub fn line(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InvalidBlockdControlResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid blockd control response {:?}", self.0)
    }
}

impl std::error::Error for InvalidBlockdControlResponse {}

/// Observable local/remote durability watermarks for one attached volume.
///
/// `local_durable_generation` is what a relaxed Guest FLUSH has reached on the
/// Host NVMe. `remote_durable_generation` is the latest object-store plus
/// metadata-CAS generation and therefore the restore point after permanent
/// Host loss.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurabilityStatus {
    /// The volume this blockd was configured to serve.
    ///
    /// Empty means the payload came from a `cats-blockd` that predates this
    /// field, so the process cannot prove which volume it holds. A node agent
    /// must then treat it as not adoptable rather than binding a live blockd to
    /// a volume on a PID match alone; refusing to adopt is the safe default.
    #[serde(default)]
    pub volume_id: String,
    /// The attachment this blockd was configured to serve. Empty carries the
    /// same "identity unproven, do not adopt" meaning as [`Self::volume_id`].
    #[serde(default)]
    pub attachment_id: String,
    /// Complete target-authority lineage is present only for a blockd that
    /// adopted a Node-supplied exact grant. Missing means unproven legacy
    /// status and must never be inferred from the process arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_epoch: Option<FenceEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acquire_origin: Option<AcquireOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_epoch: Option<Epoch>,
    /// Exact Guest-I/O gate state for the target path. Missing is legacy and
    /// therefore not proof that a frontend is either open or closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_io_enabled: Option<bool>,
    /// Immutable physical volume size reported by the running engine. Missing
    /// is legacy and cannot satisfy a Runtime process handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Checkpointed transient-unit identity supplied by the signed Runtime.
    /// The Node must also prove actual cgroup membership; this echo alone is
    /// never systemd authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<Id>,
    /// Fresh process-attempt token fsynced before spawn. Missing/corrupt values
    /// are not adoptable and must never be reconstructed from a unit name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_identity_token: Option<RandomId128>,
    /// Fresh Guest-device token fsynced with the serving launch. For
    /// vhost-user this identifies the listener atomically created by the
    /// serving process; missing is legacy/unproven and cannot be adopted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_ownership_token: Option<RandomId128>,
    /// Exact process mode. Missing means legacy; `guest_io_enabled=false`
    /// alone is not proof that the process exposes only Host control I/O.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_only: Option<bool>,
    /// Complete authoritative head loaded by a signed target-authority
    /// process. Missing is legacy/unproven; a generation counter alone cannot
    /// distinguish the checkpointed image root from an unrelated commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_head: Option<RemoteHead>,
    pub mode: String,
    pub local_durable_generation: i64,
    pub remote_durable_generation: i64,
    pub unpublished_generations: usize,
    pub unpublished_bytes: u64,
    pub oldest_unpublished_age_ms: u64,
    pub max_unpublished_generations: usize,
    pub max_unpublished_bytes: u64,
    pub local_allocated_bytes: u64,
    /// Physical bytes plus space reserved to stage the current dirty set.
    #[serde(default)]
    pub local_accounted_bytes: u64,
    pub max_local_bytes: u64,
    pub evicted_cache_chunks: u64,
    pub backpressured: bool,
    pub fenced: bool,
    pub last_publish_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_lines_are_byte_stable() {
        assert_eq!(BlockdControlCommand::Drain.as_wire(), "drain");
        assert_eq!(BlockdControlCommand::Status.as_wire(), "status");
        assert_eq!(
            BlockdControlResponse::ok("42").to_wire().as_bytes(),
            b"OK 42\n"
        );
        assert_eq!(
            BlockdControlResponse::error("remote unavailable")
                .to_wire()
                .as_bytes(),
            b"ERR remote unavailable\n"
        );
        assert_eq!(
            BlockdControlResponse::parse_wire("OK {\"mode\":\"strict\"}\n").unwrap(),
            BlockdControlResponse::Ok("{\"mode\":\"strict\"}".to_string())
        );
    }

    /// A payload byte-for-byte as an older `cats-blockd` emitted it, before the
    /// status carried any volume identity.
    const LEGACY_STATUS_JSON: &str = "{\"mode\":\"relaxed\",\"local_durable_generation\":7,\"remote_durable_generation\":5,\"unpublished_generations\":2,\"unpublished_bytes\":65536,\"oldest_unpublished_age_ms\":250,\"max_unpublished_generations\":4096,\"max_unpublished_bytes\":8589934592,\"local_allocated_bytes\":131072,\"local_accounted_bytes\":196608,\"max_local_bytes\":17179869184,\"evicted_cache_chunks\":3,\"backpressured\":false,\"fenced\":false,\"last_publish_error\":\"timeout\"}";

    #[test]
    fn durability_status_json_is_byte_stable() {
        let status = DurabilityStatus {
            volume_id: "vol_x".to_string(),
            attachment_id: "att_x".to_string(),
            attachment_epoch: None,
            acquire_origin: None,
            node_id: None,
            placement_epoch: None,
            guest_io_enabled: None,
            size_bytes: None,
            scope_id: None,
            process_identity_token: None,
            device_ownership_token: None,
            control_only: None,
            remote_head: None,
            mode: "relaxed".to_string(),
            local_durable_generation: 7,
            remote_durable_generation: 5,
            unpublished_generations: 2,
            unpublished_bytes: 65_536,
            oldest_unpublished_age_ms: 250,
            max_unpublished_generations: 4_096,
            max_unpublished_bytes: 8_589_934_592,
            local_allocated_bytes: 131_072,
            local_accounted_bytes: 196_608,
            max_local_bytes: 17_179_869_184,
            evicted_cache_chunks: 3,
            backpressured: false,
            fenced: false,
            last_publish_error: Some("timeout".to_string()),
        };
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            "{\"volume_id\":\"vol_x\",\"attachment_id\":\"att_x\",\"mode\":\"relaxed\",\"local_durable_generation\":7,\"remote_durable_generation\":5,\"unpublished_generations\":2,\"unpublished_bytes\":65536,\"oldest_unpublished_age_ms\":250,\"max_unpublished_generations\":4096,\"max_unpublished_bytes\":8589934592,\"local_allocated_bytes\":131072,\"local_accounted_bytes\":196608,\"max_local_bytes\":17179869184,\"evicted_cache_chunks\":3,\"backpressured\":false,\"fenced\":false,\"last_publish_error\":\"timeout\"}"
        );
        assert_eq!(
            serde_json::from_str::<DurabilityStatus>(&serde_json::to_string(&status).unwrap())
                .unwrap(),
            status,
            "identity fields round-trip"
        );
    }

    #[test]
    fn status_without_identity_deserializes_as_unproven() {
        let status: DurabilityStatus = serde_json::from_str(LEGACY_STATUS_JSON).unwrap();
        // An older blockd cannot prove which volume it holds; empty identity is
        // what the node agent must read as "not adoptable".
        assert_eq!(status.volume_id, "");
        assert_eq!(status.attachment_id, "");
        // Every pre-existing field keeps its value and meaning.
        assert_eq!(status.mode, "relaxed");
        assert_eq!(status.local_durable_generation, 7);
        assert_eq!(status.remote_durable_generation, 5);
        assert_eq!(status.unpublished_generations, 2);
        assert_eq!(status.local_accounted_bytes, 196_608);
        assert_eq!(status.last_publish_error.as_deref(), Some("timeout"));
    }

    #[test]
    fn unknown_fields_are_ignored_so_old_readers_survive_new_payloads() {
        // The same tolerance an older node agent relies on when a newer blockd
        // adds fields it has never heard of.
        let forward = LEGACY_STATUS_JSON.replace(
            "{\"mode\"",
            "{\"a_field_from_the_future\":{\"nested\":[1]},\"mode\"",
        );
        let status: DurabilityStatus = serde_json::from_str(&forward).unwrap();
        assert_eq!(status.mode, "relaxed");
        assert_eq!(status.volume_id, "");
    }
}

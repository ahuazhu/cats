//! Host-side control protocol shared by `cats-blockd` and the node agent.
//!
//! The control socket remains a line-oriented protocol: one `drain` or
//! `status` command per connection and one `OK ...` or `ERR ...` response.
//! The status payload is stable JSON described by [`DurabilityStatus`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

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

    #[test]
    fn durability_status_json_is_byte_stable() {
        let status = DurabilityStatus {
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
            "{\"mode\":\"relaxed\",\"local_durable_generation\":7,\"remote_durable_generation\":5,\"unpublished_generations\":2,\"unpublished_bytes\":65536,\"oldest_unpublished_age_ms\":250,\"max_unpublished_generations\":4096,\"max_unpublished_bytes\":8589934592,\"local_allocated_bytes\":131072,\"local_accounted_bytes\":196608,\"max_local_bytes\":17179869184,\"evicted_cache_chunks\":3,\"backpressured\":false,\"fenced\":false,\"last_publish_error\":\"timeout\"}"
        );
    }
}

//! Guest agent protocol.
//!
//! Transport: length-prefixed JSON frames (`u32` big-endian length + body)
//! over AF_VSOCK in production and a unix socket in dev/tests. Each request
//! carries an id echoed in the response; commands are argument arrays, never
//! shell strings (arch doc §7.2).

use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestRequest {
    pub id: u64,
    #[serde(flatten)]
    pub body: GuestRequestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuestRequestBody {
    /// Liveness + boot identity. `boot_id` distinguishes resume (same id)
    /// from cold boot (new id) — the correctness oracle from the experiments.
    Health,
    /// Run a command inside the guest.
    Exec { command: Vec<String>, #[serde(default)] timeout_ms: Option<u64> },
    /// Flush guest filesystems (fake guest: flush volume writers).
    Syncfs,
    /// Read from an attached volume (fake guest block I/O path).
    ReadBlock { disk_id: String, offset: u64, len: u32 },
    /// Write to an attached volume. Data is hex-encoded to stay in JSON.
    WriteBlock { disk_id: String, offset: u64, data_hex: String },
    /// Issue a durable FLUSH on an attached volume.
    FlushDisk { disk_id: String },
    /// Graceful shutdown of the guest agent.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestResponse {
    pub id: u64,
    #[serde(flatten)]
    pub body: GuestResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum GuestResponseBody {
    Health { boot_id: String, uptime_ms: u64, disks: Vec<String> },
    Exec { exit_code: i32, stdout: String, stderr: String },
    Ok,
    Data { data_hex: String },
    Error { message: String },
}

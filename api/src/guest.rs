//! Guest agent protocol.
//!
//! Transport: length-prefixed JSON frames (`u32` big-endian length + body)
//! over AF_VSOCK in production and a unix socket in dev/tests. Each request
//! carries an id echoed in the response; commands are argument arrays, never
//! shell strings (arch doc §7.2).

use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

pub const DEFAULT_WORK_LEASE_TTL_MS: u64 = 5 * 60 * 1000;
pub const MAX_WORK_LEASE_TTL_MS: u64 = 60 * 60 * 1000;
pub const MAX_WORK_LEASES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestWorkLease {
    pub id: String,
    pub label: String,
    /// Remaining duration measured by the Guest Agent's monotonic clock.
    pub remaining_ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestWorkStatus {
    pub source_epoch: String,
    pub lease_sequence: u64,
    pub quiescing: bool,
    pub leases: Vec<GuestWorkLease>,
}

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
    /// Current user-program work leases. When `after_sequence` is supplied,
    /// wait until the sequence changes or the bounded timeout elapses.
    WorkStatus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after_sequence: Option<u64>,
        #[serde(default)]
        wait_timeout_ms: u64,
    },
    /// Close the Guest task gate before sync/pause. The expected sequence is
    /// the control plane's activity fence.
    PrepareSuspend { expected_lease_sequence: u64 },
    /// Re-open the Guest task gate after a rejected suspend or resume.
    AbortSuspend,
    /// Run a command inside the guest.
    Exec {
        command: Vec<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Flush guest filesystems (fake guest: flush volume writers).
    Syncfs,
    /// Read from an attached volume (fake guest block I/O path).
    ReadBlock {
        disk_id: String,
        offset: u64,
        len: u32,
    },
    /// Write to an attached volume. Data is hex-encoded to stay in JSON.
    WriteBlock {
        disk_id: String,
        offset: u64,
        data_hex: String,
    },
    /// Issue a durable FLUSH on an attached volume.
    FlushDisk { disk_id: String },
    /// Persist process identity/state to a file (Warm snapshot carrier in the
    /// fake VMM; the real VMM snapshots memory instead).
    SaveState { path: String },
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
    Health {
        boot_id: String,
        uptime_ms: u64,
        disks: Vec<String>,
    },
    WorkStatus {
        status: GuestWorkStatus,
    },
    SuspendPrepared {
        source_epoch: String,
        lease_sequence: u64,
    },
    Exec {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    Ok,
    Data {
        data_hex: String,
    },
    Error {
        message: String,
    },
}

/// Guest-local user program protocol over `/run/cats/work.sock` (or the
/// FakeVmm-provided path). It intentionally carries no Cat/control-plane id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestLocalWorkRequest {
    pub id: u64,
    #[serde(flatten)]
    pub body: GuestLocalWorkRequestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuestLocalWorkRequestBody {
    Acquire { label: String, ttl_ms: u64 },
    Renew { lease_id: String, ttl_ms: u64 },
    Release { lease_id: String },
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestLocalWorkResponse {
    pub id: u64,
    #[serde(flatten)]
    pub body: GuestLocalWorkResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum GuestLocalWorkResponseBody {
    Lease { lease: GuestWorkLease },
    Status { status: GuestWorkStatus },
    Ok,
    Error { message: String },
}

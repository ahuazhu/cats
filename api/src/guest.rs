//! Guest agent protocol.
//!
//! Host control transport: length-prefixed JSON frames (`u32` big-endian
//! length + body) over AF_VSOCK in production and a unix socket in dev/tests.
//! Guest user programs use the separate HTTP/1.1 API on
//! `/run/cats/runtime.sock` (ADR-0007). Host control requests carry an id
//! echoed in the response; commands are argument arrays, never shell strings.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::oci::{DeployOciRequest, OciDeployment};

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// Stable Guest ABI endpoint. The Guest Agent serves HTTP/1.1 over this Unix
/// socket; no TCP/UDP port or Cats SDK is required.
pub const GUEST_RUNTIME_SOCKET_PATH: &str = "/run/cats/runtime.sock";
pub const GUEST_WORK_LEASES_PATH: &str = "/v1/work-leases";
pub const DEFAULT_WORK_LEASE_TTL_MS: u64 = 5 * 60 * 1000;
pub const MAX_WORK_LEASE_TTL_MS: u64 = 60 * 60 * 1000;
pub const MAX_WORK_LEASES: usize = 64;

/// Write one bounded `u32` big-endian length-prefixed JSON frame.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(|_| std::io::Error::other("oversized frame"))?;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("oversized frame"));
    }
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

/// Read one bounded `u32` big-endian length-prefixed JSON frame.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("oversized frame"));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(std::io::Error::other)
}

pub fn default_work_lease_ttl_ms() -> u64 {
    DEFAULT_WORK_LEASE_TTL_MS
}

/// One FakeVmm disk attachment written by the node and consumed by the Guest
/// Agent. Real Guests discover the corresponding standard virtio block
/// devices instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskMapEntry {
    pub socket: PathBuf,
    pub mount_path: String,
}

pub type DiskMap = HashMap<String, DiskMapEntry>;

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
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        stdin: Vec<u8>,
    },
    /// Pull, verify, flatten and start a digest-pinned OCI application.
    DeployOci { deploy: DeployOciRequest },
    /// Start an interactive login shell attached to a pseudoterminal. After
    /// `ShellReady`, this control connection switches to `GuestShellFrame`
    /// messages until the shell exits or the caller closes it.
    Shell { rows: u16, cols: u16 },
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
    OciDeployed {
        deployment: OciDeployment,
    },
    ShellReady,
    Ok,
    Data {
        data_hex: String,
    },
    Error {
        message: String,
    },
}

/// Bidirectional frames used after a `Shell`/`ShellReady` handshake. They use
/// the same bounded length-prefixed JSON codec as the control protocol. Raw
/// PTY bytes remain bytes so terminal escape sequences and UTF-8 fragments
/// survive without lossy conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestShellFrame {
    Input { data: Vec<u8> },
    Resize { rows: u16, cols: u16 },
    Output { data: Vec<u8> },
    Exit { exit_code: i32 },
    Close,
}

/// JSON body for `POST /v1/work-leases` on the Guest runtime socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquireGuestWorkLeaseRequest {
    pub label: String,
    #[serde(default = "default_work_lease_ttl_ms")]
    pub ttl_ms: u64,
}

/// JSON body for `PUT /v1/work-leases/{lease_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewGuestWorkLeaseRequest {
    #[serde(default = "default_work_lease_ttl_ms")]
    pub ttl_ms: u64,
}

/// Stable JSON error envelope for the Guest-local HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestRuntimeApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestRuntimeApiErrorResponse {
    pub error: GuestRuntimeApiError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_health_frame_is_byte_stable() {
        let request = GuestRequest {
            id: 7,
            body: GuestRequestBody::Health,
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();
        assert_eq!(bytes, b"\0\0\0\x16{\"id\":7,\"op\":\"health\"}");

        let decoded: GuestRequest = read_frame(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.id, 7);
        assert!(matches!(decoded.body, GuestRequestBody::Health));
    }

    #[test]
    fn guest_framing_rejects_an_oversized_length_before_allocating() {
        let bytes = (MAX_FRAME_BYTES + 1).to_be_bytes();
        let error = read_frame::<_, GuestRequest>(&mut &bytes[..]).unwrap_err();
        assert_eq!(error.to_string(), "oversized frame");
    }

    #[test]
    fn fake_guest_disk_map_json_is_byte_stable() {
        let map = DiskMap::from([(
            "root".to_string(),
            DiskMapEntry {
                socket: PathBuf::from("/run/cats/root.sock"),
                mount_path: "/".to_string(),
            },
        )]);
        assert_eq!(
            serde_json::to_string(&map).unwrap(),
            "{\"root\":{\"socket\":\"/run/cats/root.sock\",\"mount_path\":\"/\"}}"
        );
    }
}

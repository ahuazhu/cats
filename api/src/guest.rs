//! Guest agent protocol.
//!
//! Host control transport: length-prefixed JSON frames (`u32` big-endian
//! length + body) over AF_VSOCK in production and a unix socket in dev/tests.
//! Guest user programs use the separate HTTP/1.1 API on
//! `/run/cats/runtime.sock` (ADR-0007). Host control requests carry an id
//! echoed in the response; commands are argument arrays, never shell strings.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::oci::{DeployOciRequest, OciDeployment};
use crate::runtime_reconciliation::{
    FilesystemInitialization, GuestBootId, GuestDeviceIdentity, HostPath, Id, MountAccess,
    PersistentFilesystemBinding, RandomId128, RemoteHead, GUEST_DEVICE_SERIAL_MAX_BYTES_V1,
};

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;
/// Frozen host-control protocol carried by the production Guest Agent V1
/// vsock listener.
pub const GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1: u16 = 1;
/// The only production Guest Agent AF_VSOCK port in Runtime Reconciliation V1.
pub const GUEST_HOST_CONTROL_VSOCK_PORT_V1: u32 = 5_000;
/// RuntimeReady is deliberately much smaller than exec/deploy traffic.  Both
/// peers reject the length prefix before allocating the JSON body.
pub const RUNTIME_READY_REQUEST_MAX_FRAME_BYTES_V1: u32 = 4 * 1024;
/// Covers the frozen 64-device/64-mount shape even when each observed path is
/// at the shared HostPath boundary and needs JSON escaping, while remaining an
/// independent quarter of the generic Guest control allocation ceiling.
pub const RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1: u32 = 4 * 1024 * 1024;
/// Reserved non-JSON leading byte for one canonical RuntimeReady request.
/// The byte is included in the outer length and lets the shared Guest receiver
/// select the 4 KiB cap before allocating or waiting for the JSON body.
pub const RUNTIME_READY_REQUEST_FRAME_TAG_V1: u8 = 0x01;
/// Reserved non-JSON leading byte for one canonical RuntimeReady response.
pub const RUNTIME_READY_RESPONSE_FRAME_TAG_V1: u8 = 0x02;
/// Filesystem control is a separate ABI from RuntimeReady: in particular a
/// pre-format probe can report a blank device and may never be decoded through
/// the ready-state path.
pub const FILESYSTEM_CONTROL_REQUEST_FRAME_TAG_V1: u8 = 0x03;
pub const FILESYSTEM_CONTROL_RESPONSE_FRAME_TAG_V1: u8 = 0x04;
pub const FILESYSTEM_CONTROL_REQUEST_MAX_FRAME_BYTES_V1: u32 = 16 * 1024;
pub const FILESYSTEM_CONTROL_RESPONSE_MAX_FRAME_BYTES_V1: u32 = 64 * 1024;
pub const FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1: u32 = 120_000;
pub const FILESYSTEM_CONTROL_MAX_MOUNTS_V1: usize = 4;
/// Matches the frozen Runtime Reconciliation V1 maximum of Root plus 63
/// Persistent volumes. RuntimeReady must not narrow an otherwise legal
/// Desired/StartRuntime device set.
pub const RUNTIME_READY_MAX_DEVICES_V1: usize = 64;
pub const RUNTIME_READY_MAX_MOUNTS_V1: usize = 64;

/// Stable Guest ABI endpoint. The Guest Agent serves HTTP/1.1 over this Unix
/// socket; no TCP/UDP port or Cats SDK is required.
pub const GUEST_RUNTIME_SOCKET_PATH: &str = "/run/cats/runtime.sock";
pub const GUEST_WORK_LEASES_PATH: &str = "/v1/work-leases";
pub const DEFAULT_WORK_LEASE_TTL_MS: u64 = 5 * 60 * 1000;
pub const MAX_WORK_LEASE_TTL_MS: u64 = 60 * 60 * 1000;
pub const MAX_WORK_LEASES: usize = 64;

/// Write one bounded `u32` big-endian length-prefixed JSON frame.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> std::io::Result<()> {
    write_frame_with_limit(writer, value, MAX_FRAME_BYTES)
}

/// Write a JSON frame whose contract has a tighter cap than the generic Guest
/// control transport.  The length prefix is never emitted for an oversized
/// value.
pub fn write_frame_with_limit<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    max_frame_bytes: u32,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(|_| std::io::Error::other("oversized frame"))?;
    if len > max_frame_bytes {
        return Err(std::io::Error::other("oversized frame"));
    }
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

/// Read one bounded `u32` big-endian length-prefixed JSON frame.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> std::io::Result<T> {
    read_frame_with_limit(reader, MAX_FRAME_BYTES)
}

/// Read a JSON frame with a caller-selected hard cap.  The prefix is checked
/// before allocating or reading any body byte.
pub fn read_frame_with_limit<R: Read, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    max_frame_bytes: u32,
) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > max_frame_bytes {
        return Err(std::io::Error::other("oversized frame"));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(std::io::Error::other)
}

fn canonical_json<T: Serialize>(value: &T) -> std::io::Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(std::io::Error::other)?;
    Ok(crate::runtime_reconciliation::canonical_json_value_bytes(
        &value,
    ))
}

fn decode_canonical_json<T: DeserializeOwned>(body: &[u8]) -> std::io::Result<T> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(std::io::Error::other)?;
    if crate::runtime_reconciliation::canonical_json_value_bytes(&value) != body {
        return Err(std::io::Error::other("non-canonical RuntimeReady JSON"));
    }
    serde_json::from_value(value).map_err(std::io::Error::other)
}

fn write_runtime_ready_tagged_frame<W: Write, T: Serialize>(
    writer: &mut W,
    tag: u8,
    value: &T,
    max_frame_bytes: u32,
) -> std::io::Result<()> {
    let body = canonical_json(value)?;
    let len = body
        .len()
        .checked_add(1)
        .and_then(|len| u32::try_from(len).ok())
        .ok_or_else(|| std::io::Error::other("oversized RuntimeReady frame"))?;
    if len > max_frame_bytes {
        return Err(std::io::Error::other("oversized RuntimeReady frame"));
    }
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&[tag])?;
    writer.write_all(&body)?;
    writer.flush()
}

fn read_runtime_ready_tagged_frame<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    expected_tag: u8,
    max_frame_bytes: u32,
) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Err(std::io::Error::other("missing RuntimeReady frame tag"));
    }
    if len > max_frame_bytes {
        return Err(std::io::Error::other("oversized RuntimeReady frame"));
    }
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag)?;
    if tag[0] != expected_tag {
        return Err(std::io::Error::other("unexpected RuntimeReady frame tag"));
    }
    let mut body = vec![0u8; len as usize - 1];
    reader.read_exact(&mut body)?;
    decode_canonical_json(&body)
}

/// Write one canonical, independently tagged RuntimeReady request. Untagged
/// JSON is not a valid encoding of this ABI.
pub fn write_runtime_ready_request_frame<W: Write>(
    writer: &mut W,
    request: &GuestRequest,
) -> std::io::Result<()> {
    let GuestRequestBody::RuntimeReady { ready } = &request.body else {
        return Err(std::io::Error::other(
            "RuntimeReady request codec received another operation",
        ));
    };
    ready.validate().map_err(std::io::Error::other)?;
    write_runtime_ready_tagged_frame(
        writer,
        RUNTIME_READY_REQUEST_FRAME_TAG_V1,
        request,
        RUNTIME_READY_REQUEST_MAX_FRAME_BYTES_V1,
    )
}

/// Write one canonical, independently capped Persistent filesystem request.
/// The reserved tag is part of the length-prefixed frame and therefore lets
/// the Guest reject an oversized prefix before allocating its JSON body.
pub fn write_filesystem_control_request_frame<W: Write>(
    writer: &mut W,
    request: &GuestRequest,
) -> std::io::Result<()> {
    let GuestRequestBody::FilesystemControl { filesystem } = &request.body else {
        return Err(std::io::Error::other(
            "filesystem request codec received another operation",
        ));
    };
    filesystem.validate().map_err(std::io::Error::other)?;
    write_runtime_ready_tagged_frame(
        writer,
        FILESYSTEM_CONTROL_REQUEST_FRAME_TAG_V1,
        request,
        FILESYSTEM_CONTROL_REQUEST_MAX_FRAME_BYTES_V1,
    )
}

/// Read the shared Guest request envelope. A RuntimeReady tag selects the
/// independent 4 KiB cap after reading only the fixed prefix and tag; all
/// other requests retain the generic 16 MiB JSON contract.
pub fn read_guest_request_frame<R: Read>(reader: &mut R) -> std::io::Result<GuestRequest> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Err(std::io::Error::other("empty Guest request frame"));
    }
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::other("oversized frame"));
    }

    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    if first[0] == RUNTIME_READY_REQUEST_FRAME_TAG_V1 {
        if len > RUNTIME_READY_REQUEST_MAX_FRAME_BYTES_V1 {
            return Err(std::io::Error::other("oversized RuntimeReady frame"));
        }
        let mut body = vec![0u8; len as usize - 1];
        reader.read_exact(&mut body)?;
        let request: GuestRequest = decode_canonical_json(&body)?;
        let GuestRequestBody::RuntimeReady { ready } = &request.body else {
            return Err(std::io::Error::other(
                "RuntimeReady request tag carried another operation",
            ));
        };
        ready.validate().map_err(std::io::Error::other)?;
        return Ok(request);
    }
    if first[0] == FILESYSTEM_CONTROL_REQUEST_FRAME_TAG_V1 {
        if len > FILESYSTEM_CONTROL_REQUEST_MAX_FRAME_BYTES_V1 {
            return Err(std::io::Error::other("oversized filesystem control frame"));
        }
        let mut body = vec![0u8; len as usize - 1];
        reader.read_exact(&mut body)?;
        let request: GuestRequest = decode_canonical_json(&body)?;
        let GuestRequestBody::FilesystemControl { filesystem } = &request.body else {
            return Err(std::io::Error::other(
                "filesystem request tag carried another operation",
            ));
        };
        filesystem.validate().map_err(std::io::Error::other)?;
        return Ok(request);
    }
    if first[0] == RUNTIME_READY_RESPONSE_FRAME_TAG_V1 {
        return Err(std::io::Error::other(
            "RuntimeReady response tag on request stream",
        ));
    }
    if first[0] == FILESYSTEM_CONTROL_RESPONSE_FRAME_TAG_V1 {
        return Err(std::io::Error::other(
            "filesystem response tag on request stream",
        ));
    }

    let mut body = vec![0u8; len as usize];
    body[0] = first[0];
    reader.read_exact(&mut body[1..])?;
    let request: GuestRequest = serde_json::from_slice(&body).map_err(std::io::Error::other)?;
    if matches!(&request.body, GuestRequestBody::RuntimeReady { .. }) {
        return Err(std::io::Error::other(
            "untagged RuntimeReady request is forbidden",
        ));
    }
    if matches!(&request.body, GuestRequestBody::FilesystemControl { .. }) {
        return Err(std::io::Error::other(
            "untagged filesystem control request is forbidden",
        ));
    }
    Ok(request)
}

/// Write one canonical, independently tagged response to a RuntimeReady
/// request. A bounded Error response uses the same tag so the client never
/// falls back to the generic response decoder.
pub fn write_runtime_ready_response_frame<W: Write>(
    writer: &mut W,
    response: &GuestResponse,
) -> std::io::Result<()> {
    if !matches!(
        &response.body,
        GuestResponseBody::RuntimeReady { .. } | GuestResponseBody::Error { .. }
    ) {
        return Err(std::io::Error::other(
            "RuntimeReady response codec received another result",
        ));
    }
    write_runtime_ready_tagged_frame(
        writer,
        RUNTIME_READY_RESPONSE_FRAME_TAG_V1,
        response,
        RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1,
    )
}

/// Read one canonical tagged RuntimeReady response. Generic JSON and request
/// tags are rejected rather than accepted as equivalent encodings.
pub fn read_runtime_ready_response_frame<R: Read>(
    reader: &mut R,
) -> std::io::Result<GuestResponse> {
    let response: GuestResponse = read_runtime_ready_tagged_frame(
        reader,
        RUNTIME_READY_RESPONSE_FRAME_TAG_V1,
        RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1,
    )?;
    if !matches!(
        &response.body,
        GuestResponseBody::RuntimeReady { .. } | GuestResponseBody::Error { .. }
    ) {
        return Err(std::io::Error::other(
            "RuntimeReady response tag carried another result",
        ));
    }
    Ok(response)
}

pub fn write_filesystem_control_response_frame<W: Write>(
    writer: &mut W,
    response: &GuestResponse,
) -> std::io::Result<()> {
    match &response.body {
        GuestResponseBody::FilesystemControl { filesystem } => {
            filesystem.validate().map_err(std::io::Error::other)?;
        }
        GuestResponseBody::Error { .. } => {}
        _ => {
            return Err(std::io::Error::other(
                "filesystem response codec received another result",
            ));
        }
    }
    write_runtime_ready_tagged_frame(
        writer,
        FILESYSTEM_CONTROL_RESPONSE_FRAME_TAG_V1,
        response,
        FILESYSTEM_CONTROL_RESPONSE_MAX_FRAME_BYTES_V1,
    )
}

pub fn read_filesystem_control_response_frame<R: Read>(
    reader: &mut R,
) -> std::io::Result<GuestResponse> {
    let response: GuestResponse = read_runtime_ready_tagged_frame(
        reader,
        FILESYSTEM_CONTROL_RESPONSE_FRAME_TAG_V1,
        FILESYSTEM_CONTROL_RESPONSE_MAX_FRAME_BYTES_V1,
    )?;
    match &response.body {
        GuestResponseBody::FilesystemControl { filesystem } => {
            filesystem.validate().map_err(std::io::Error::other)?;
        }
        GuestResponseBody::Error { .. } => {}
        _ => {
            return Err(std::io::Error::other(
                "filesystem response tag carried another result",
            ));
        }
    }
    Ok(response)
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
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestRequestBody {
    /// Liveness + boot identity. `boot_id` distinguishes resume (same id)
    /// from cold boot (new id) — the correctness oracle from the experiments.
    Health,
    /// Fresh, challenge-bound physical readiness projection.  The nested
    /// closed object keeps this new frozen ABI strict without changing the
    /// legacy flattened request shapes.
    RuntimeReady { ready: RuntimeReadyRequestV1 },
    /// Dedicated PersistentDisk filesystem probe/effect ABI. This may not be
    /// sent as generic JSON or decoded as RuntimeReady.
    FilesystemControl {
        filesystem: FilesystemControlRequestV1,
    },
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
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestResponseBody {
    Health {
        boot_id: String,
        uptime_ms: u64,
        disks: Vec<String>,
    },
    RuntimeReady {
        ready: RuntimeReadyResponseV1,
    },
    FilesystemControl {
        filesystem: FilesystemControlResponseV1,
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

/// One fresh RuntimeReady challenge.  `expected_*` values come only from the
/// retained VMM launch authority; the Guest echoes them but cannot make them
/// authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReadyRequestV1 {
    pub version: u16,
    pub challenge: RandomId128,
    pub runtime_incarnation: RandomId128,
    pub expected_guest_cid: u32,
    pub expected_guest_port: u32,
    pub expected_guest_agent_protocol_version: u16,
}

/// Exact virtio-blk identity and ext4 identity observed inside the Guest.
/// Device order is canonical `(slot, serial)` order and every identity is
/// unique within one response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReadyDeviceV1 {
    pub guest_device: GuestDeviceIdentity,
    pub device_path: HostPath,
    pub device_major: u32,
    pub device_minor: u32,
    pub size_bytes: u64,
    pub filesystem_uuid: RandomId128,
}

/// Mount facts decoded from the Guest Agent's own `/proc/self/mountinfo`.
/// Only mounts backed by a reported virtio-blk device are included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReadyMountV1 {
    pub device_major: u32,
    pub device_minor: u32,
    pub source_path: HostPath,
    pub filesystem_uuid: RandomId128,
    pub mount_root: HostPath,
    pub mount_path: HostPath,
    pub filesystem_type: Id,
    pub access: MountAccess,
}

/// Challenge-bound Guest projection.  The Node must still bracket this value
/// with retained VMM/systemd/process/API/socket and storage/device authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReadyResponseV1 {
    pub version: u16,
    pub challenge: RandomId128,
    pub runtime_incarnation: RandomId128,
    pub expected_guest_cid: u32,
    pub expected_guest_port: u32,
    pub expected_guest_agent_protocol_version: u16,
    pub actual_guest_cid: u32,
    pub actual_guest_port: u32,
    pub actual_guest_agent_protocol_version: u16,
    pub guest_boot_id: GuestBootId,
    pub devices: Vec<RuntimeReadyDeviceV1>,
    pub mounts: Vec<RuntimeReadyMountV1>,
}

/// One bounded operation on exactly one PersistentDisk. `filesystem` is the
/// checkpointed identity; `expected_head` is the current storage authority at
/// the call boundary. Neither value becomes authoritative merely because the
/// Guest echoes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemControlRequestV1 {
    pub version: u16,
    pub challenge: RandomId128,
    pub timeout_ms: u32,
    pub operation: FilesystemControlOperationV1,
    pub filesystem: Box<PersistentFilesystemBinding>,
    pub expected_head: RemoteHead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemControlOperationV1 {
    Probe,
    FormatExt4,
    FlushDevice,
    MountExt4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilesystemIdentityV1 {
    Blank,
    Ext4 { filesystem_uuid: RandomId128 },
    Foreign,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentFilesystemMountV1 {
    pub device_major: u32,
    pub device_minor: u32,
    pub source_path: HostPath,
    pub mount_root: HostPath,
    pub mount_path: HostPath,
    pub filesystem_type: Id,
    pub access: MountAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentFilesystemObservationV1 {
    pub guest_device: GuestDeviceIdentity,
    pub device_path: HostPath,
    pub device_major: u32,
    pub device_minor: u32,
    pub size_bytes: u64,
    pub filesystem: FilesystemIdentityV1,
    pub mounts: Vec<PersistentFilesystemMountV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemControlOutcomeV1 {
    Exact,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemControlResponseV1 {
    pub version: u16,
    pub request: Box<FilesystemControlRequestV1>,
    pub outcome: FilesystemControlOutcomeV1,
    pub observation: PersistentFilesystemObservationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FilesystemControlContractError {
    #[error("filesystem control version is not the frozen V1 value")]
    Version,
    #[error("filesystem control timeout is outside the frozen V1 bound")]
    Timeout,
    #[error("filesystem control binding is not a canonical PersistentDisk contract")]
    Binding,
    #[error("filesystem control operation is incompatible with its initialization branch")]
    Operation,
    #[error("filesystem control RemoteHead is incomplete or incompatible with the operation")]
    Head,
    #[error("filesystem control response does not exactly echo its request")]
    RequestEcho,
    #[error("filesystem control observation does not match the challenged device")]
    Device,
    #[error("filesystem control mount projection is not canonical")]
    Mount,
    #[error("filesystem control exact outcome does not satisfy the requested postcondition")]
    Postcondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeReadyContractError {
    #[error("RuntimeReady version is not the frozen V1 value")]
    Version,
    #[error("RuntimeReady Guest CID is outside the assignable V1 range")]
    GuestCid,
    #[error("RuntimeReady Guest port is not the fixed V1 port")]
    GuestPort,
    #[error("RuntimeReady Guest Agent protocol is not V1")]
    GuestProtocol,
    #[error("RuntimeReady response did not exactly echo its challenge")]
    ChallengeEcho,
    #[error("RuntimeReady response did not exactly echo its runtime incarnation")]
    RuntimeIncarnationEcho,
    #[error("RuntimeReady response did not exactly echo its expected transport")]
    ExpectedTransportEcho,
    #[error("RuntimeReady observed transport did not match the challenged transport")]
    ActualTransportMismatch,
    #[error("RuntimeReady device list exceeds its V1 bound")]
    TooManyDevices,
    #[error("RuntimeReady mount list exceeds its V1 bound")]
    TooManyMounts,
    #[error("RuntimeReady device list is not strictly sorted and unique")]
    DeviceOrder,
    #[error("RuntimeReady device contains an invalid physical fact")]
    DeviceFact,
    #[error("RuntimeReady mount list is not strictly sorted and unique")]
    MountOrder,
    #[error("RuntimeReady mount does not join exactly one reported device")]
    MountDevice,
}

fn assignable_guest_cid(cid: u32) -> bool {
    (3..=u32::MAX - 1).contains(&cid)
}

fn complete_remote_head(head: &RemoteHead) -> bool {
    if head.generation.get() == 0 {
        head.root_hash.is_none() && head.root_object_id.is_none()
    } else {
        head.root_hash.is_some() && head.root_object_id.is_some()
    }
}

impl FilesystemControlRequestV1 {
    pub fn validate(&self) -> Result<(), FilesystemControlContractError> {
        if self.version != GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1 {
            return Err(FilesystemControlContractError::Version);
        }
        if self.timeout_ms == 0 || self.timeout_ms > FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1 {
            return Err(FilesystemControlContractError::Timeout);
        }
        let filesystem = self.filesystem.as_ref();
        if filesystem.size_bytes == 0
            || filesystem.mount_path.as_str() == "/"
            || filesystem.guest_device.serial.as_str().len() > GUEST_DEVICE_SERIAL_MAX_BYTES_V1
        {
            return Err(FilesystemControlContractError::Binding);
        }
        if !complete_remote_head(&self.expected_head) {
            return Err(FilesystemControlContractError::Head);
        }
        match (&filesystem.initialization, self.operation) {
            (
                FilesystemInitialization::Initialize {
                    initialization_token,
                    expected_blank_head,
                },
                operation,
            ) => {
                if !complete_remote_head(expected_blank_head)
                    || expected_blank_head.generation.get() != 0
                    || initialization_token == &filesystem.filesystem_uuid
                {
                    return Err(FilesystemControlContractError::Binding);
                }
                match operation {
                    FilesystemControlOperationV1::FormatExt4
                    | FilesystemControlOperationV1::FlushDevice
                        if self.expected_head != *expected_blank_head =>
                    {
                        return Err(FilesystemControlContractError::Head);
                    }
                    FilesystemControlOperationV1::MountExt4
                        if self.expected_head.generation.get() == 0 =>
                    {
                        return Err(FilesystemControlContractError::Head);
                    }
                    _ => {}
                }
            }
            (FilesystemInitialization::Existing, FilesystemControlOperationV1::Probe) => {
                if self.expected_head.generation.get() == 0 {
                    return Err(FilesystemControlContractError::Head);
                }
            }
            (FilesystemInitialization::Existing, FilesystemControlOperationV1::MountExt4) => {
                if self.expected_head.generation.get() == 0 {
                    return Err(FilesystemControlContractError::Head);
                }
            }
            (FilesystemInitialization::Existing, _) => {
                return Err(FilesystemControlContractError::Operation);
            }
        }
        Ok(())
    }
}

impl FilesystemControlResponseV1 {
    pub fn validate(&self) -> Result<(), FilesystemControlContractError> {
        self.request.validate()?;
        if self.version != GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1 {
            return Err(FilesystemControlContractError::Version);
        }
        let request = self.request.as_ref();
        let expected = request.filesystem.as_ref();
        let observation = &self.observation;
        if observation.guest_device != expected.guest_device
            || observation.size_bytes != expected.size_bytes
            || (observation.device_major == 0 && observation.device_minor == 0)
        {
            return Err(FilesystemControlContractError::Device);
        }
        if observation.mounts.len() > FILESYSTEM_CONTROL_MAX_MOUNTS_V1 {
            return Err(FilesystemControlContractError::Mount);
        }
        let mut prior: Option<(&str, &str)> = None;
        let mut paths = BTreeSet::new();
        for mount in &observation.mounts {
            let key = (mount.mount_path.as_str(), mount.source_path.as_str());
            if prior.is_some_and(|prior| prior >= key)
                || !paths.insert(mount.mount_path.as_str())
                || mount.device_major != observation.device_major
                || mount.device_minor != observation.device_minor
                || mount.source_path != observation.device_path
            {
                return Err(FilesystemControlContractError::Mount);
            }
            prior = Some(key);
        }
        if self.outcome == FilesystemControlOutcomeV1::Conflict {
            return Ok(());
        }

        let expected_uuid = &expected.filesystem_uuid;
        let exact_ext4 = matches!(
            &observation.filesystem,
            FilesystemIdentityV1::Ext4 { filesystem_uuid } if filesystem_uuid == expected_uuid
        );
        let exact_mount = || {
            observation.mounts.as_slice().first().is_some_and(|mount| {
                observation.mounts.len() == 1
                    && mount.mount_root.as_str() == "/"
                    && mount.mount_path == expected.mount_path
                    && mount.filesystem_type.as_str() == "ext4"
                    && mount.access == MountAccess::ReadWrite
            })
        };
        let postcondition = match request.operation {
            FilesystemControlOperationV1::Probe => match &expected.initialization {
                FilesystemInitialization::Initialize { .. } => {
                    observation.mounts.is_empty()
                        && (matches!(observation.filesystem, FilesystemIdentityV1::Blank)
                            || exact_ext4)
                }
                FilesystemInitialization::Existing => {
                    exact_ext4 && (observation.mounts.is_empty() || exact_mount())
                }
            },
            FilesystemControlOperationV1::FormatExt4
            | FilesystemControlOperationV1::FlushDevice => {
                exact_ext4 && observation.mounts.is_empty()
            }
            FilesystemControlOperationV1::MountExt4 => exact_ext4 && exact_mount(),
        };
        if !postcondition {
            return Err(FilesystemControlContractError::Postcondition);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        request: &FilesystemControlRequestV1,
    ) -> Result<(), FilesystemControlContractError> {
        if self.request.as_ref() != request {
            return Err(FilesystemControlContractError::RequestEcho);
        }
        self.validate()
    }
}

impl RuntimeReadyRequestV1 {
    pub fn validate(&self) -> Result<(), RuntimeReadyContractError> {
        if self.version != GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1 {
            return Err(RuntimeReadyContractError::Version);
        }
        if !assignable_guest_cid(self.expected_guest_cid) {
            return Err(RuntimeReadyContractError::GuestCid);
        }
        if self.expected_guest_port != GUEST_HOST_CONTROL_VSOCK_PORT_V1 {
            return Err(RuntimeReadyContractError::GuestPort);
        }
        if self.expected_guest_agent_protocol_version != GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1 {
            return Err(RuntimeReadyContractError::GuestProtocol);
        }
        Ok(())
    }
}

impl RuntimeReadyResponseV1 {
    pub fn validate_against(
        &self,
        request: &RuntimeReadyRequestV1,
    ) -> Result<(), RuntimeReadyContractError> {
        request.validate()?;
        if self.version != GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1 {
            return Err(RuntimeReadyContractError::Version);
        }
        if self.challenge != request.challenge {
            return Err(RuntimeReadyContractError::ChallengeEcho);
        }
        if self.runtime_incarnation != request.runtime_incarnation {
            return Err(RuntimeReadyContractError::RuntimeIncarnationEcho);
        }
        if self.expected_guest_cid != request.expected_guest_cid
            || self.expected_guest_port != request.expected_guest_port
            || self.expected_guest_agent_protocol_version
                != request.expected_guest_agent_protocol_version
        {
            return Err(RuntimeReadyContractError::ExpectedTransportEcho);
        }
        if self.actual_guest_cid != request.expected_guest_cid
            || self.actual_guest_port != request.expected_guest_port
            || self.actual_guest_agent_protocol_version
                != request.expected_guest_agent_protocol_version
        {
            return Err(RuntimeReadyContractError::ActualTransportMismatch);
        }
        if self.devices.len() > RUNTIME_READY_MAX_DEVICES_V1 {
            return Err(RuntimeReadyContractError::TooManyDevices);
        }
        if self.mounts.len() > RUNTIME_READY_MAX_MOUNTS_V1 {
            return Err(RuntimeReadyContractError::TooManyMounts);
        }

        let mut device_paths = BTreeSet::new();
        let mut device_numbers = BTreeSet::new();
        let mut device_uuids = BTreeSet::new();
        let mut device_slots = BTreeSet::new();
        let mut device_serials = BTreeSet::new();
        let mut previous_device: Option<(u16, &str)> = None;
        for device in &self.devices {
            let key = (
                device.guest_device.slot,
                device.guest_device.serial.as_str(),
            );
            if previous_device.is_some_and(|previous| previous >= key) {
                return Err(RuntimeReadyContractError::DeviceOrder);
            }
            previous_device = Some(key);
            if device.guest_device.serial.as_str().len() > GUEST_DEVICE_SERIAL_MAX_BYTES_V1
                || device.size_bytes == 0
                || !device_slots.insert(device.guest_device.slot)
                || !device_serials.insert(device.guest_device.serial.as_str())
                || !device_paths.insert(device.device_path.as_str())
                || !device_numbers.insert((device.device_major, device.device_minor))
                || !device_uuids.insert(device.filesystem_uuid.as_str())
            {
                return Err(RuntimeReadyContractError::DeviceFact);
            }
        }

        let mut previous_mount: Option<(&str, &str)> = None;
        let mut mount_paths = BTreeSet::new();
        for mount in &self.mounts {
            let key = (mount.mount_path.as_str(), mount.source_path.as_str());
            if previous_mount.is_some_and(|previous| previous >= key)
                || !mount_paths.insert(mount.mount_path.as_str())
            {
                return Err(RuntimeReadyContractError::MountOrder);
            }
            previous_mount = Some(key);
            let matching_devices = self
                .devices
                .iter()
                .filter(|device| {
                    device.device_major == mount.device_major
                        && device.device_minor == mount.device_minor
                        && device.device_path == mount.source_path
                        && device.filesystem_uuid == mount.filesystem_uuid
                })
                .count();
            if matching_devices != 1 {
                return Err(RuntimeReadyContractError::MountDevice);
            }
        }
        Ok(())
    }
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

    fn ready_request() -> RuntimeReadyRequestV1 {
        RuntimeReadyRequestV1 {
            version: 1,
            challenge: RandomId128::new("11111111111111111111111111111111").unwrap(),
            runtime_incarnation: RandomId128::new("22222222222222222222222222222222").unwrap(),
            expected_guest_cid: 3,
            expected_guest_port: 5_000,
            expected_guest_agent_protocol_version: 1,
        }
    }

    fn ready_response(request: &RuntimeReadyRequestV1) -> RuntimeReadyResponseV1 {
        RuntimeReadyResponseV1 {
            version: 1,
            challenge: request.challenge.clone(),
            runtime_incarnation: request.runtime_incarnation.clone(),
            expected_guest_cid: request.expected_guest_cid,
            expected_guest_port: request.expected_guest_port,
            expected_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
            actual_guest_cid: 3,
            actual_guest_port: 5_000,
            actual_guest_agent_protocol_version: 1,
            guest_boot_id: GuestBootId::new("33333333333333333333333333333333").unwrap(),
            devices: vec![RuntimeReadyDeviceV1 {
                guest_device: GuestDeviceIdentity {
                    serial: Id::new("cats-root").unwrap(),
                    slot: 0,
                },
                device_path: HostPath::new("/dev/vda").unwrap(),
                device_major: 252,
                device_minor: 0,
                size_bytes: 4_294_967_296,
                filesystem_uuid: RandomId128::new("44444444444444444444444444444444").unwrap(),
            }],
            mounts: vec![RuntimeReadyMountV1 {
                device_major: 252,
                device_minor: 0,
                source_path: HostPath::new("/dev/vda").unwrap(),
                filesystem_uuid: RandomId128::new("44444444444444444444444444444444").unwrap(),
                mount_root: HostPath::new("/").unwrap(),
                mount_path: HostPath::new("/").unwrap(),
                filesystem_type: Id::new("ext4").unwrap(),
                access: MountAccess::ReadWrite,
            }],
        }
    }

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: crate::runtime_reconciliation::Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn initialized_head() -> RemoteHead {
        RemoteHead {
            generation: crate::runtime_reconciliation::Generation::new(2).unwrap(),
            root_hash: Some(
                crate::runtime_reconciliation::Sha256Digest::new(format!(
                    "sha256:{}",
                    "55".repeat(32)
                ))
                .unwrap(),
            ),
            root_object_id: Some(
                crate::runtime_reconciliation::AsciiText::new("volumes/data/roots/2").unwrap(),
            ),
        }
    }

    fn filesystem_request(operation: FilesystemControlOperationV1) -> FilesystemControlRequestV1 {
        let expected_blank_head = blank_head();
        FilesystemControlRequestV1 {
            version: 1,
            challenge: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            timeout_ms: 30_000,
            operation,
            filesystem: Box::new(PersistentFilesystemBinding {
                runtime_incarnation: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                volume_intent_id: Id::new("intent-data").unwrap(),
                disk_id: Id::new("disk-data").unwrap(),
                volume_id: Id::new("volume-data").unwrap(),
                attachment_id: Id::new("attachment-data").unwrap(),
                attachment_epoch: crate::runtime_reconciliation::FenceEpoch::new(4).unwrap(),
                size_bytes: 4_294_967_296,
                guest_device: GuestDeviceIdentity {
                    serial: Id::new("cats-data").unwrap(),
                    slot: 1,
                },
                filesystem_uuid: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
                mount_path: HostPath::new("/data").unwrap(),
                initialization: FilesystemInitialization::Initialize {
                    initialization_token: RandomId128::new("dddddddddddddddddddddddddddddddd")
                        .unwrap(),
                    expected_blank_head: expected_blank_head.clone(),
                },
            }),
            expected_head: match operation {
                FilesystemControlOperationV1::MountExt4 => initialized_head(),
                _ => expected_blank_head,
            },
        }
    }

    fn filesystem_response(request: &FilesystemControlRequestV1) -> FilesystemControlResponseV1 {
        let mounted = request.operation == FilesystemControlOperationV1::MountExt4;
        FilesystemControlResponseV1 {
            version: 1,
            request: Box::new(request.clone()),
            outcome: FilesystemControlOutcomeV1::Exact,
            observation: PersistentFilesystemObservationV1 {
                guest_device: request.filesystem.guest_device.clone(),
                device_path: HostPath::new("/dev/vdb").unwrap(),
                device_major: 252,
                device_minor: 16,
                size_bytes: request.filesystem.size_bytes,
                filesystem: FilesystemIdentityV1::Ext4 {
                    filesystem_uuid: request.filesystem.filesystem_uuid.clone(),
                },
                mounts: if mounted {
                    vec![PersistentFilesystemMountV1 {
                        device_major: 252,
                        device_minor: 16,
                        source_path: HostPath::new("/dev/vdb").unwrap(),
                        mount_root: HostPath::new("/").unwrap(),
                        mount_path: request.filesystem.mount_path.clone(),
                        filesystem_type: Id::new("ext4").unwrap(),
                        access: MountAccess::ReadWrite,
                    }]
                } else {
                    Vec::new()
                },
            },
        }
    }

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
    fn runtime_ready_request_frame_has_one_frozen_canonical_encoding() {
        let request = GuestRequest {
            id: 7,
            body: GuestRequestBody::RuntimeReady {
                ready: ready_request(),
            },
        };
        let canonical = br#"{"id":7,"op":"runtime_ready","ready":{"challenge":"11111111111111111111111111111111","expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#;
        let mut expected = vec![0, 0, 0, 0xf8, RUNTIME_READY_REQUEST_FRAME_TAG_V1];
        expected.extend_from_slice(canonical);

        let mut encoded = Vec::new();
        write_runtime_ready_request_frame(&mut encoded, &request).unwrap();
        assert_eq!(encoded, expected);
        let decoded = read_guest_request_frame(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.id, 7);
        assert!(matches!(
            decoded.body,
            GuestRequestBody::RuntimeReady { .. }
        ));
    }

    #[test]
    fn runtime_ready_response_frame_has_one_frozen_canonical_encoding() {
        let request = ready_request();
        let mut ready = ready_response(&request);
        ready.devices.clear();
        ready.mounts.clear();
        let response = GuestResponse {
            id: 7,
            body: GuestResponseBody::RuntimeReady { ready },
        };
        let canonical = br#"{"id":7,"ready":{"actual_guest_agent_protocol_version":1,"actual_guest_cid":3,"actual_guest_port":5000,"challenge":"11111111111111111111111111111111","devices":[],"expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"guest_boot_id":"33333333333333333333333333333333","mounts":[],"runtime_incarnation":"22222222222222222222222222222222","version":1},"result":"runtime_ready"}"#;
        let mut expected = vec![0, 0, 1, 0x9e, RUNTIME_READY_RESPONSE_FRAME_TAG_V1];
        expected.extend_from_slice(canonical);

        let mut encoded = Vec::new();
        write_runtime_ready_response_frame(&mut encoded, &response).unwrap();
        assert_eq!(encoded, expected);
        let decoded = read_runtime_ready_response_frame(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.id, 7);
        assert!(matches!(
            decoded.body,
            GuestResponseBody::RuntimeReady { .. }
        ));
    }

    #[test]
    fn filesystem_control_frames_have_frozen_directional_canonical_encodings() {
        use sha2::{Digest as _, Sha256};

        let request = filesystem_request(FilesystemControlOperationV1::FormatExt4);
        let envelope = GuestRequest {
            id: 9,
            body: GuestRequestBody::FilesystemControl {
                filesystem: request.clone(),
            },
        };
        let mut encoded_request = Vec::new();
        write_filesystem_control_request_frame(&mut encoded_request, &envelope).unwrap();
        assert_eq!(encoded_request[4], FILESYSTEM_CONTROL_REQUEST_FRAME_TAG_V1);
        assert_eq!(
            u32::from_be_bytes(encoded_request[..4].try_into().unwrap()) as usize,
            encoded_request.len() - 4
        );
        assert_eq!(
            hex::encode(Sha256::digest(&encoded_request)),
            "629eb8830ebf6ab9aef01d4efad850d804028c30d973b2450a5d9a2120c09c54"
        );
        let decoded_request = read_guest_request_frame(&mut &encoded_request[..]).unwrap();
        assert_eq!(decoded_request.id, envelope.id);
        let GuestRequestBody::FilesystemControl { filesystem } = decoded_request.body else {
            panic!("filesystem request vector decoded as another operation")
        };
        assert_eq!(filesystem, request);

        let response = GuestResponse {
            id: 9,
            body: GuestResponseBody::FilesystemControl {
                filesystem: filesystem_response(&request),
            },
        };
        let mut encoded_response = Vec::new();
        write_filesystem_control_response_frame(&mut encoded_response, &response).unwrap();
        assert_eq!(
            encoded_response[4],
            FILESYSTEM_CONTROL_RESPONSE_FRAME_TAG_V1
        );
        assert_eq!(
            u32::from_be_bytes(encoded_response[..4].try_into().unwrap()) as usize,
            encoded_response.len() - 4
        );
        assert_eq!(
            hex::encode(Sha256::digest(&encoded_response)),
            "49c365817c6491415ae8487e0c4c6eba1cd379bf3b7abf6a901d61c8c06538c6"
        );
        let decoded_response =
            read_filesystem_control_response_frame(&mut &encoded_response[..]).unwrap();
        assert_eq!(decoded_response.id, response.id);
        let GuestResponseBody::FilesystemControl { filesystem } = decoded_response.body else {
            panic!("filesystem response vector decoded as another result")
        };
        assert_eq!(filesystem, filesystem_response(&request));
    }

    #[test]
    fn filesystem_control_contract_is_checkpoint_bound_and_fail_closed() {
        let format = filesystem_request(FilesystemControlOperationV1::FormatExt4);
        format.validate().unwrap();
        filesystem_response(&format)
            .validate_against(&format)
            .unwrap();

        let mut existing_format = format.clone();
        existing_format.filesystem.initialization = FilesystemInitialization::Existing;
        assert_eq!(
            existing_format.validate(),
            Err(FilesystemControlContractError::Operation)
        );

        let mut wrong_blank = format.clone();
        wrong_blank.expected_head = initialized_head();
        assert_eq!(
            wrong_blank.validate(),
            Err(FilesystemControlContractError::Head)
        );

        let mount = filesystem_request(FilesystemControlOperationV1::MountExt4);
        let mut response = filesystem_response(&mount);
        response.validate_against(&mount).unwrap();
        response.request.filesystem.attachment_epoch =
            crate::runtime_reconciliation::FenceEpoch::new(5).unwrap();
        assert_eq!(
            response.validate_against(&mount),
            Err(FilesystemControlContractError::RequestEcho)
        );

        let mut response = filesystem_response(&mount);
        response.observation.mounts[0].mount_path = HostPath::new("/foreign").unwrap();
        assert_eq!(
            response.validate_against(&mount),
            Err(FilesystemControlContractError::Postcondition)
        );

        let mut conflict = filesystem_response(&mount);
        conflict.outcome = FilesystemControlOutcomeV1::Conflict;
        conflict.observation.filesystem = FilesystemIdentityV1::Foreign;
        conflict.observation.mounts.clear();
        conflict.validate_against(&mount).unwrap();
    }

    #[test]
    fn filesystem_control_prefix_tag_and_canonical_failures_do_not_fallback() {
        let mut oversized = (FILESYSTEM_CONTROL_REQUEST_MAX_FRAME_BYTES_V1 + 1)
            .to_be_bytes()
            .to_vec();
        oversized.push(FILESYSTEM_CONTROL_REQUEST_FRAME_TAG_V1);
        assert_eq!(
            read_guest_request_frame(&mut &oversized[..])
                .unwrap_err()
                .to_string(),
            "oversized filesystem control frame"
        );

        let request = GuestRequest {
            id: 9,
            body: GuestRequestBody::FilesystemControl {
                filesystem: filesystem_request(FilesystemControlOperationV1::Probe),
            },
        };
        let mut untagged = Vec::new();
        write_frame(&mut untagged, &request).unwrap();
        assert_eq!(
            read_guest_request_frame(&mut &untagged[..])
                .unwrap_err()
                .to_string(),
            "untagged filesystem control request is forbidden"
        );

        let mut tagged = Vec::new();
        write_filesystem_control_request_frame(&mut tagged, &request).unwrap();
        tagged[4] = FILESYSTEM_CONTROL_RESPONSE_FRAME_TAG_V1;
        assert_eq!(
            read_guest_request_frame(&mut &tagged[..])
                .unwrap_err()
                .to_string(),
            "filesystem response tag on request stream"
        );

        let canonical = canonical_json(&request).unwrap();
        let mut noncanonical = Vec::new();
        noncanonical
            .extend_from_slice(&(u32::try_from(canonical.len()).unwrap() + 2).to_be_bytes());
        noncanonical.push(FILESYSTEM_CONTROL_REQUEST_FRAME_TAG_V1);
        noncanonical.push(b' ');
        noncanonical.extend_from_slice(&canonical);
        assert!(read_guest_request_frame(&mut &noncanonical[..])
            .unwrap_err()
            .to_string()
            .contains("non-canonical"));
    }

    #[test]
    fn runtime_ready_codec_rejects_equivalent_noncanonical_json() {
        let canonical = br#"{"id":7,"op":"runtime_ready","ready":{"challenge":"11111111111111111111111111111111","expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#;
        let variants: [&[u8]; 4] = [
            br#"{ "id":7,"op":"runtime_ready","ready":{"challenge":"11111111111111111111111111111111","expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#,
            br#"{"op":"runtime_ready","id":7,"ready":{"challenge":"11111111111111111111111111111111","expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#,
            br#"{"id":7,"op":"runtime\u005fready","ready":{"challenge":"11111111111111111111111111111111","expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#,
            br#"{"id":7,"id":7,"op":"runtime_ready","ready":{"challenge":"11111111111111111111111111111111","expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#,
        ];
        for body in variants {
            assert_ne!(body, canonical);
            let mut frame = Vec::new();
            frame.extend_from_slice(&(u32::try_from(body.len()).unwrap() + 1).to_be_bytes());
            frame.push(RUNTIME_READY_REQUEST_FRAME_TAG_V1);
            frame.extend_from_slice(body);
            assert_eq!(
                read_guest_request_frame(&mut &frame[..])
                    .unwrap_err()
                    .to_string(),
                "non-canonical RuntimeReady JSON"
            );
        }

        let response_variants: [&[u8]; 3] = [
            br#"{ "id":7,"ready":{"actual_guest_agent_protocol_version":1,"actual_guest_cid":3,"actual_guest_port":5000,"challenge":"11111111111111111111111111111111","devices":[],"expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"guest_boot_id":"33333333333333333333333333333333","mounts":[],"runtime_incarnation":"22222222222222222222222222222222","version":1},"result":"runtime_ready"}"#,
            br#"{"result":"runtime_ready","id":7,"ready":{"actual_guest_agent_protocol_version":1,"actual_guest_cid":3,"actual_guest_port":5000,"challenge":"11111111111111111111111111111111","devices":[],"expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"guest_boot_id":"33333333333333333333333333333333","mounts":[],"runtime_incarnation":"22222222222222222222222222222222","version":1}}"#,
            br#"{"id":7,"ready":{"actual_guest_agent_protocol_version":1,"actual_guest_cid":3,"actual_guest_port":5000,"challenge":"11111111111111111111111111111111","devices":[],"expected_guest_agent_protocol_version":1,"expected_guest_cid":3,"expected_guest_port":5000,"guest_boot_id":"33333333333333333333333333333333","mounts":[],"runtime_incarnation":"22222222222222222222222222222222","version":1},"result":"runtime\u005fready"}"#,
        ];
        for body in response_variants {
            let mut frame = Vec::new();
            frame.extend_from_slice(&(u32::try_from(body.len()).unwrap() + 1).to_be_bytes());
            frame.push(RUNTIME_READY_RESPONSE_FRAME_TAG_V1);
            frame.extend_from_slice(body);
            assert_eq!(
                read_runtime_ready_response_frame(&mut &frame[..])
                    .unwrap_err()
                    .to_string(),
                "non-canonical RuntimeReady JSON"
            );
        }
    }

    #[test]
    fn runtime_ready_tags_are_mandatory_directional_and_truncation_closed() {
        let request = GuestRequest {
            id: 7,
            body: GuestRequestBody::RuntimeReady {
                ready: ready_request(),
            },
        };
        let mut untagged_request = Vec::new();
        write_frame(&mut untagged_request, &request).unwrap();
        assert_eq!(
            read_guest_request_frame(&mut &untagged_request[..])
                .unwrap_err()
                .to_string(),
            "untagged RuntimeReady request is forbidden"
        );

        let mut tagged_request = Vec::new();
        write_runtime_ready_request_frame(&mut tagged_request, &request).unwrap();
        assert!(read_frame::<_, GuestRequest>(&mut &tagged_request[..]).is_err());
        let mut wrong_direction = tagged_request.clone();
        wrong_direction[4] = RUNTIME_READY_RESPONSE_FRAME_TAG_V1;
        assert_eq!(
            read_guest_request_frame(&mut &wrong_direction[..])
                .unwrap_err()
                .to_string(),
            "RuntimeReady response tag on request stream"
        );

        assert_eq!(
            read_guest_request_frame(&mut &tagged_request[..4])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_guest_request_frame(&mut &tagged_request[..5])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        let response = GuestResponse {
            id: 7,
            body: GuestResponseBody::RuntimeReady {
                ready: ready_response(&ready_request()),
            },
        };
        let mut untagged_response = Vec::new();
        write_frame(&mut untagged_response, &response).unwrap();
        assert_eq!(
            read_runtime_ready_response_frame(&mut &untagged_response[..])
                .unwrap_err()
                .to_string(),
            "unexpected RuntimeReady frame tag"
        );
        let mut tagged_response = Vec::new();
        write_runtime_ready_response_frame(&mut tagged_response, &response).unwrap();
        let mut wrong_response_direction = tagged_response.clone();
        wrong_response_direction[4] = RUNTIME_READY_REQUEST_FRAME_TAG_V1;
        assert_eq!(
            read_runtime_ready_response_frame(&mut &wrong_response_direction[..])
                .unwrap_err()
                .to_string(),
            "unexpected RuntimeReady frame tag"
        );
        assert_eq!(
            read_runtime_ready_response_frame(&mut &tagged_response[..4])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_runtime_ready_response_frame(&mut &tagged_response[..5])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn shared_receiver_rejects_ready_cap_after_prefix_and_tag_only() {
        let mut frame = (RUNTIME_READY_REQUEST_MAX_FRAME_BYTES_V1 + 1)
            .to_be_bytes()
            .to_vec();
        frame.push(RUNTIME_READY_REQUEST_FRAME_TAG_V1);
        assert_eq!(
            read_guest_request_frame(&mut &frame[..])
                .unwrap_err()
                .to_string(),
            "oversized RuntimeReady frame"
        );
    }

    #[test]
    fn shared_receiver_preserves_large_generic_request_contract() {
        let request = GuestRequest {
            id: 8,
            body: GuestRequestBody::Exec {
                command: vec!["true".to_owned()],
                timeout_ms: None,
                env: BTreeMap::new(),
                stdin: vec![0x5a; RUNTIME_READY_REQUEST_MAX_FRAME_BYTES_V1 as usize],
            },
        };
        let mut frame = Vec::new();
        write_frame(&mut frame, &request).unwrap();
        assert!(
            u32::from_be_bytes(frame[..4].try_into().unwrap())
                > RUNTIME_READY_REQUEST_MAX_FRAME_BYTES_V1
        );
        let decoded = read_guest_request_frame(&mut &frame[..]).unwrap();
        assert!(matches!(decoded.body, GuestRequestBody::Exec { .. }));
    }

    #[test]
    fn runtime_ready_v1_is_challenge_bound_and_physically_closed() {
        let request = ready_request();
        let response = ready_response(&request);
        request.validate().unwrap();
        response.validate_against(&request).unwrap();

        let mut wrong = response.clone();
        wrong.challenge = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(
            wrong.validate_against(&request),
            Err(RuntimeReadyContractError::ChallengeEcho)
        );

        let mut wrong_actual_cid = response.clone();
        wrong_actual_cid.actual_guest_cid = request.expected_guest_cid + 1;
        assert_eq!(
            wrong_actual_cid.validate_against(&request),
            Err(RuntimeReadyContractError::ActualTransportMismatch)
        );

        let mut duplicate = response.clone();
        duplicate.devices.push(duplicate.devices[0].clone());
        assert_eq!(
            duplicate.validate_against(&request),
            Err(RuntimeReadyContractError::DeviceOrder)
        );

        let mut duplicate_slot = response.clone();
        let mut second = duplicate_slot.devices[0].clone();
        second.guest_device.serial = Id::new("cats-second").unwrap();
        second.device_path = HostPath::new("/dev/vdb").unwrap();
        second.device_minor = 16;
        second.filesystem_uuid = RandomId128::new("55555555555555555555555555555555").unwrap();
        duplicate_slot.devices.push(second);
        assert_eq!(
            duplicate_slot.validate_against(&request),
            Err(RuntimeReadyContractError::DeviceFact)
        );

        let mut duplicate_serial = response.clone();
        let mut second = duplicate_serial.devices[0].clone();
        second.guest_device.slot = 1;
        second.device_path = HostPath::new("/dev/vdb").unwrap();
        second.device_minor = 16;
        second.filesystem_uuid = RandomId128::new("55555555555555555555555555555555").unwrap();
        duplicate_serial.devices.push(second);
        assert_eq!(
            duplicate_serial.validate_against(&request),
            Err(RuntimeReadyContractError::DeviceFact)
        );

        let mut drifted_mount = response;
        drifted_mount.mounts[0].filesystem_uuid =
            RandomId128::new("55555555555555555555555555555555").unwrap();
        assert_eq!(
            drifted_mount.validate_against(&request),
            Err(RuntimeReadyContractError::MountDevice)
        );
    }

    #[test]
    fn runtime_ready_v1_enforces_cloud_hypervisor_serial_bound() {
        let request = ready_request();
        let mut response = ready_response(&request);
        response.devices[0].guest_device.serial = Id::new("12345678901234567890").unwrap();
        response.validate_against(&request).unwrap();

        response.devices[0].guest_device.serial = Id::new("123456789012345678901").unwrap();
        assert_eq!(
            response.validate_against(&request),
            Err(RuntimeReadyContractError::DeviceFact)
        );
    }

    #[test]
    fn runtime_ready_v1_rejects_unknown_duplicate_and_malformed_fields() {
        let valid = br#"{"id":1,"op":"runtime_ready","ready":{"version":1,"challenge":"11111111111111111111111111111111","runtime_incarnation":"22222222222222222222222222222222","expected_guest_cid":3,"expected_guest_port":5000,"expected_guest_agent_protocol_version":1}}"#;
        let decoded: GuestRequest = serde_json::from_slice(valid).unwrap();
        assert!(matches!(
            decoded.body,
            GuestRequestBody::RuntimeReady { .. }
        ));

        let unknown_nested = br#"{"id":1,"op":"runtime_ready","ready":{"version":1,"challenge":"11111111111111111111111111111111","runtime_incarnation":"22222222222222222222222222222222","expected_guest_cid":3,"expected_guest_port":5000,"expected_guest_agent_protocol_version":1,"extra":true}}"#;
        assert!(serde_json::from_slice::<GuestRequest>(unknown_nested).is_err());

        let unknown_top = br#"{"id":1,"op":"runtime_ready","ready":{"version":1,"challenge":"11111111111111111111111111111111","runtime_incarnation":"22222222222222222222222222222222","expected_guest_cid":3,"expected_guest_port":5000,"expected_guest_agent_protocol_version":1},"extra":true}"#;
        assert!(serde_json::from_slice::<GuestRequest>(unknown_top).is_err());

        let duplicate = br#"{"id":1,"op":"runtime_ready","ready":{"version":1,"version":1,"challenge":"11111111111111111111111111111111","runtime_incarnation":"22222222222222222222222222222222","expected_guest_cid":3,"expected_guest_port":5000,"expected_guest_agent_protocol_version":1}}"#;
        assert!(serde_json::from_slice::<GuestRequest>(duplicate).is_err());

        let malformed = br#"{"id":1,"op":"runtime_ready","ready":{"version":1,"challenge":"NOT_CANONICAL","runtime_incarnation":"22222222222222222222222222222222","expected_guest_cid":3,"expected_guest_port":5000,"expected_guest_agent_protocol_version":1}}"#;
        assert!(serde_json::from_slice::<GuestRequest>(malformed).is_err());
    }

    #[test]
    fn runtime_ready_small_frame_cap_is_checked_before_body_allocation() {
        let bytes = (RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1 + 1).to_be_bytes();
        let error = read_runtime_ready_response_frame(&mut &bytes[..]).unwrap_err();
        assert_eq!(error.to_string(), "oversized RuntimeReady frame");
    }

    #[test]
    fn runtime_ready_response_cap_covers_the_maximum_legal_path_shape() {
        fn maximum_path(index: usize) -> HostPath {
            let suffix = format!("{index:02}");
            let body = format!("{}{}", "\\".repeat(4_096 - 1 - suffix.len()), suffix);
            HostPath::new(format!("/{body}")).unwrap()
        }

        let request = ready_request();
        let mut response = ready_response(&request);
        response.devices.clear();
        response.mounts.clear();
        for index in 0..RUNTIME_READY_MAX_DEVICES_V1 {
            let filesystem_uuid = RandomId128::new(format!("{:032x}", index + 1)).unwrap();
            let source_path = maximum_path(index);
            let device_major = u32::MAX;
            let device_minor = u32::MAX - u32::try_from(index).unwrap();
            response.devices.push(RuntimeReadyDeviceV1 {
                guest_device: GuestDeviceIdentity {
                    serial: Id::new(format!("serial{index:014}")).unwrap(),
                    slot: u16::MAX
                        - u16::try_from(RUNTIME_READY_MAX_DEVICES_V1 - 1 - index).unwrap(),
                },
                device_path: source_path.clone(),
                device_major,
                device_minor,
                size_bytes: u64::MAX,
                filesystem_uuid: filesystem_uuid.clone(),
            });
            response.mounts.push(RuntimeReadyMountV1 {
                device_major,
                device_minor,
                source_path,
                filesystem_uuid,
                mount_root: maximum_path(index),
                mount_path: maximum_path(index),
                filesystem_type: Id::new("x".repeat(128)).unwrap(),
                access: MountAccess::ReadWrite,
            });
        }
        response.validate_against(&request).unwrap();

        let envelope = GuestResponse {
            id: 1,
            body: GuestResponseBody::RuntimeReady { ready: response },
        };
        let body = canonical_json(&envelope).unwrap();
        assert!(body.len() > 64 * 1024);
        assert!(body.len() < RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1 as usize);
        write_runtime_ready_response_frame(&mut Vec::new(), &envelope).unwrap();
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

//! Guest agent protocol.
//!
//! Host control transport: length-prefixed JSON frames (`u32` big-endian
//! length + body) over AF_VSOCK in production and a unix socket in dev/tests.
//! Guest user programs use the separate HTTP/1.1 API on
//! `/run/cats/runtime.sock` (ADR-0007). Host control requests carry an id
//! echoed in the response; commands are argument arrays, never shell strings.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::oci::{DeployOciRequest, OciDeployment};
use crate::runtime_reconciliation::{
    GuestBootId, GuestDeviceIdentity, HostPath, Id, MountAccess, RandomId128,
    GUEST_DEVICE_SERIAL_MAX_BYTES_V1,
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
        if !assignable_guest_cid(self.actual_guest_cid) {
            return Err(RuntimeReadyContractError::GuestCid);
        }
        if self.actual_guest_port != GUEST_HOST_CONTROL_VSOCK_PORT_V1 {
            return Err(RuntimeReadyContractError::GuestPort);
        }
        if self.actual_guest_agent_protocol_version != GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1 {
            return Err(RuntimeReadyContractError::GuestProtocol);
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
        let error = read_frame_with_limit::<_, GuestResponse>(
            &mut &bytes[..],
            RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "oversized frame");
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
        let body = serde_json::to_vec(&envelope).unwrap();
        assert!(body.len() > 64 * 1024);
        assert!(body.len() <= RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1 as usize);
        write_frame_with_limit(
            &mut Vec::new(),
            &envelope,
            RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1,
        )
        .unwrap();
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

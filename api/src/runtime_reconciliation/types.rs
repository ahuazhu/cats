use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const MAX_WIRE_INTEGER: u64 = i64::MAX as u64;

macro_rules! integer_newtype {
    ($name:ident, $minimum:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Option<Self> {
                (($minimum..=MAX_WIRE_INTEGER).contains(&value)).then_some(Self(value))
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = u64::deserialize(deserializer)?;
                Self::new(value)
                    .ok_or_else(|| serde::de::Error::custom("integer outside the wire range"))
            }
        }
    };
}

integer_newtype!(ContractVersion, 0);
integer_newtype!(Revision, 1);
integer_newtype!(Epoch, 1);
integer_newtype!(Sequence, 1);
integer_newtype!(WireU64, 0);
integer_newtype!(Generation, 0);
integer_newtype!(FenceEpoch, 0);
integer_newtype!(UnixMillis, 0);

impl ContractVersion {
    pub const V1: Self = Self(1);
}

macro_rules! string_newtype {
    ($name:ident, $validator:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Option<Self> {
                let value = value.into();
                $validator(&value).then_some(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).ok_or_else(|| serde::de::Error::custom("invalid string value"))
            }
        }
    };
}

pub(crate) fn valid_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

pub(crate) fn valid_ascii_text(value: &str) -> bool {
    (1..=512).contains(&value.len()) && printable_ascii(value)
}

pub(crate) fn valid_json_pointer(value: &str) -> bool {
    if value.len() > 512 || !printable_ascii(value) {
        return false;
    }
    if value.is_empty() {
        return true;
    }
    if !value.starts_with('/') {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if index + 1 == bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                return false;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    true
}

pub(crate) fn valid_random_id(value: &str) -> bool {
    value.len() == 32 && lowercase_hex(value) && value.bytes().any(|byte| byte != b'0')
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && lowercase_hex(&value[7..])
}

pub(crate) fn valid_key_id(value: &str) -> bool {
    value.len() == 64 && lowercase_hex(value)
}

pub(crate) fn valid_host_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.bytes().any(|byte| byte <= 0x1f || byte == 0x7f)
    {
        return false;
    }
    if value == "/" {
        return true;
    }
    value.starts_with('/')
        && !value.ends_with('/')
        && value[1..]
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

pub(crate) fn valid_hostname(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

pub(crate) fn valid_ipv4(value: &str) -> bool {
    value
        .parse::<Ipv4Addr>()
        .is_ok_and(|address| address.to_string() == value)
}

pub(crate) fn valid_mac(value: &str) -> bool {
    let mut parts = value.split(':');
    (0..6).all(|_| {
        parts
            .next()
            .is_some_and(|part| part.len() == 2 && lowercase_hex(part))
    }) && parts.next().is_none()
}

pub(crate) fn printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

string_newtype!(Id, valid_id);
string_newtype!(AsciiText, valid_ascii_text);
string_newtype!(JsonPointer, valid_json_pointer);
string_newtype!(RandomId128, valid_random_id);
string_newtype!(NodeBootId, valid_random_id);
string_newtype!(GuestBootId, valid_random_id);
string_newtype!(KeyId, valid_key_id);
string_newtype!(HostPath, valid_host_path);
string_newtype!(Hostname, valid_hostname);
string_newtype!(Ipv4Address, valid_ipv4);
string_newtype!(MacAddress, valid_mac);

#[derive(Clone)]
pub struct Sha256Digest {
    wire: String,
    bytes: [u8; 32],
}

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let wire = value.into();
        if !valid_digest(&wire) {
            return None;
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(&wire[7..], &mut bytes).ok()?;
        Some(Self { wire, bytes })
    }

    pub fn as_str(&self) -> &str {
        &self.wire
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            wire: format!("sha256:{}", hex::encode(bytes)),
            bytes,
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.wire)
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.wire)
    }
}

impl PartialEq for Sha256Digest {
    fn eq(&self, other: &Self) -> bool {
        self.bytes
            .iter()
            .zip(other.bytes.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }
}

impl Eq for Sha256Digest {}

impl Hash for Sha256Digest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.wire)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| serde::de::Error::custom("invalid SHA-256 digest"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    pub version: ContractVersion,
    pub node_id: Id,
    pub immutable_host_id: Id,
    pub credential_id: Id,
    pub credential_binding: CredentialBinding,
    pub state_path_id: Id,
    pub state: NodeIdentityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialBinding {
    PublicKey {
        public_key_spki_sha256: Sha256Digest,
    },
    ProviderPrincipal {
        provider: Id,
        principal: AsciiText,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeIdentityState {
    Provisioned,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistrationAttempt {
    pub version: ContractVersion,
    pub node_id: Id,
    pub immutable_host_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub registration_attempt_id: RandomId128,
    pub expected_agent_session_epoch: Option<Epoch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    pub version: ContractVersion,
    pub node_id: Id,
    pub immutable_host_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub agent_session_epoch: Epoch,
    pub registration_attempt_id: RandomId128,
    pub lease_deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionInventoryAttestation {
    pub version: ContractVersion,
    pub node_id: Id,
    pub agent_session_epoch: Epoch,
    pub inventory_epoch: Epoch,
    pub inventory_digest: Sha256Digest,
    pub inventory_read_position: Sequence,
    pub accepted_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredRuntimeSpec {
    pub version: ContractVersion,
    pub workspace_id: Id,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub target: RuntimeTarget,
    pub placement: AssignedPlacement,
    pub runtime: RuntimeConfig,
    pub volumes: Vec<VolumeIntent>,
    pub endpoints: Vec<EndpointIntent>,
    pub transition: RuntimeTransition,
    pub spec_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedPlacement {
    pub kind: AssignedKind,
    pub node_id: Id,
    pub placement_epoch: Epoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignedKind {
    Assigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTarget {
    Running,
    Suspended,
    Warm,
    Cold,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub guest_config_digest: Sha256Digest,
    pub network_config: NetworkConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub kind: IsolatedIpv4Kind,
    pub network_id: Id,
    pub guest_mac: MacAddress,
    pub guest_ipv4: Ipv4Address,
    pub prefix_length: u8,
    pub gateway_ipv4: Ipv4Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolatedIpv4Kind {
    IsolatedIpv4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeTransition {
    CancelAndDrain,
    RequireIdle {
        attempt_id: RandomId128,
        source_revision: Revision,
        source_runtime_incarnation: RandomId128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeIntent {
    pub volume_intent_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub size_bytes: u64,
    pub disk_kind: DiskKind,
    pub access: VolumeAccess,
    pub durability: Durability,
    pub guest_device: GuestDeviceIdentity,
    pub acquire: VolumeAcquire,
    pub disposition: VolumeDisposition,
    pub mount: Option<Ext4MountIntent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Root,
    Persistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeAccess {
    ReadWriteOnce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Strict,
    Relaxed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestDeviceIdentity {
    pub serial: Id,
    pub slot: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAcquire {
    Normal {
        transition_id: RandomId128,
        expected_unowned_epoch: FenceEpoch,
    },
    Takeover {
        authorization_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeDisposition {
    Retain,
    DetachRetained,
    DeleteDisposableRoot { delete_id: Id },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ext4MountIntent {
    pub filesystem_uuid: RandomId128,
    pub mount_path: HostPath,
    pub initialization: FilesystemInitialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilesystemInitialization {
    Existing,
    Initialize {
        initialization_token: RandomId128,
        expected_blank_head: RemoteHead,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIntent {
    pub endpoint_id: Id,
    pub hostname: Hostname,
    pub route_epoch: Epoch,
    pub protocol: HttpProtocol,
    pub target_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpProtocol {
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StableState {
    Running,
    Suspended,
    Warm,
    Cold,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAdmission {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCheckpoint {
    pub version: ContractVersion,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_epoch: Epoch,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub runtime_incarnation: Option<RandomId128>,
    pub stable_state: Option<StableState>,
    pub step: ReconcileStep,
    pub processes: Vec<ProcessEvidence>,
    pub volumes: Vec<ObservedVolume>,
    pub mounts: Vec<ObservedMount>,
    pub networks: Vec<ObservedNetwork>,
    pub guest_transport: GuestTransportEvidence,
    pub warm_snapshot: WarmSnapshotEvidence,
    pub lifecycle_admission: LifecycleAdmission,
    pub route_gates: Vec<CheckpointRouteGate>,
    pub require_idle: RequireIdleCheckpoint,
    pub updated_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRouteGate {
    pub binding: RouteGateBinding,
    pub gate: RouteGateState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteGateState {
    Active,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequireIdleCheckpoint {
    NotApplicable,
    Armed {
        attempt_id: RandomId128,
        source_revision: Revision,
        source_runtime_incarnation: RandomId128,
    },
    Busy {
        attempt_id: RandomId128,
        source_revision: Revision,
        source_runtime_incarnation: RandomId128,
        gate_closed: bool,
        platform_guards: u32,
        endpoint_guards: Vec<EndpointGuardCount>,
    },
    Closed {
        attempt_id: RandomId128,
        source_revision: Revision,
        source_runtime_incarnation: RandomId128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointGuardCount {
    pub endpoint_id: Id,
    pub active_guards: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCleanupCheckpoint {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cleanup: CleanupRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReconcileStep {
    InspectInventory {
        inventory_epoch: Epoch,
    },
    Stable {
        state: StableState,
    },
    CloseAdmission {
        require_idle_attempt_id: Option<RandomId128>,
    },
    CloseGate {
        endpoint_id: Id,
        route_epoch: Epoch,
    },
    AcquireVolume {
        request: VolumeAcquireRequest,
    },
    PrepareDevice {
        volume_id: Id,
        guest_device: GuestDeviceIdentity,
        ownership_token: RandomId128,
    },
    FormatFilesystem {
        volume_id: Id,
        attachment_id: Id,
        filesystem_uuid: RandomId128,
        initialization_token: RandomId128,
        expected_blank_head: RemoteHead,
    },
    DrainInitialization {
        volume_id: Id,
        attachment_epoch: FenceEpoch,
        local_generation: Generation,
        remote_generation: Generation,
    },
    CommitInitialized {
        volume_id: Id,
        initialization_token: RandomId128,
        expected_blank_head: RemoteHead,
        new_remote_head: RemoteHead,
    },
    MountFilesystem {
        volume_id: Id,
        guest_device: GuestDeviceIdentity,
        filesystem_uuid: RandomId128,
        mount_path: HostPath,
    },
    StartRuntime {
        runtime_incarnation: RandomId128,
        scope_id: Id,
        process_identity_token: RandomId128,
    },
    DrainPublish {
        volume_id: Id,
        attachment_epoch: FenceEpoch,
        local_generation: Generation,
        remote_generation: Generation,
    },
    PauseRuntime {
        runtime_incarnation: RandomId128,
        process_start_time_ticks: WireU64,
    },
    SnapshotWarmRuntime {
        runtime_incarnation: RandomId128,
        snapshot_id: Id,
        temporary_path: HostPath,
        source_heads: Vec<VolumeHeadEvidence>,
    },
    StopRuntime {
        runtime_incarnation: RandomId128,
        process_start_time_ticks: WireU64,
        scope_id: Id,
    },
    CleanupRelease {
        cleanup: CleanupRelease,
    },
    DeleteDisposableRoot {
        authorization_id: Id,
    },
    InstallGate {
        endpoint_id: Id,
        route_epoch: Epoch,
    },
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAcquireRequest {
    Normal {
        volume_id: Id,
        transition_id: RandomId128,
        attachment_id: Id,
        expected_unowned_epoch: FenceEpoch,
        desired_revision: Revision,
        placement_epoch: Epoch,
        lease_duration_ms: u64,
    },
    Takeover {
        authorization_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupRelease {
    pub target: CleanupTarget,
    pub inventory_session: SessionBinding,
    pub inventory_epoch: Epoch,
    pub inventory_read_position: Sequence,
    pub desired_read_position: Sequence,
    pub volume_release: Option<VolumeReleaseReplay>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeReleaseReplay {
    pub release_transition_id: RandomId128,
    pub generation: Generation,
    pub disposition: VolumeDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CleanupTarget {
    Volume {
        volume_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
    },
    Device {
        volume_id: Id,
        ownership_token: RandomId128,
    },
    Network {
        network_id: Id,
        ownership_token: RandomId128,
    },
    WarmSnapshot {
        snapshot_id: Id,
    },
    Scope {
        scope_id: Id,
        process_start_time_ticks: WireU64,
    },
    OrphanScope {
        scope_id: Id,
        cgroup_path: HostPath,
        ownership_token: RandomId128,
    },
    ControlSocket {
        socket_path: HostPath,
        ownership_token: RandomId128,
    },
    CheckpointFile {
        checkpoint_path: HostPath,
        content_digest: Sha256Digest,
        cat_id: Id,
        node_id: Id,
        placement_epoch: Epoch,
        desired_revision: Revision,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeHeadEvidence {
    pub volume_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteHead {
    pub generation: Generation,
    pub root_hash: Option<Sha256Digest>,
    pub root_object_id: Option<AsciiText>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    pub node_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub agent_session_epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    pub role: ProcessRole,
    pub process_id: u32,
    pub process_start_time_ticks: WireU64,
    pub executable_path: HostPath,
    pub scope_id: Id,
    pub control_socket_path: HostPath,
    pub state: ProcessState,
    pub ownership_token: OwnershipTokenEvidence,
    pub control_handshake: ControlHandshakeEvidence,
    pub observed_vm_shape: Option<ObservedVmShape>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessRole {
    Vmm {
        runtime_incarnation: RandomId128,
    },
    Blockd {
        volume_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVmShape {
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub guest_config_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlHandshakeEvidence {
    Unavailable,
    Malformed { raw_response_digest: Sha256Digest },
    Verified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestTransportEvidence {
    Unavailable,
    Malformed {
        raw_response_digest: Sha256Digest,
    },
    VsockReady {
        runtime_incarnation: RandomId128,
        guest_cid: u32,
        guest_port: u16,
        guest_agent_protocol_version: ContractVersion,
        guest_boot_id: GuestBootId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnershipTokenEvidence {
    Missing,
    Corrupt { raw_content_digest: Sha256Digest },
    Valid { ownership_token: RandomId128 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVolume {
    pub volume_intent_id: Option<Id>,
    pub disk_id: Option<Id>,
    pub volume_id: Id,
    pub disk_kind: ObservedDiskKind,
    pub size_bytes: Option<u64>,
    pub durability: Option<Durability>,
    pub authority: VolumeAuthorityEvidence,
    pub local_lineages: Vec<LocalVolumeLineage>,
    pub devices: Vec<ObservedDevice>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedDiskKind {
    Root,
    Persistent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAuthorityEvidence {
    Unavailable,
    Absent,
    Unowned {
        attachment_epoch: FenceEpoch,
        head: RemoteHead,
    },
    Owned {
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
        head: RemoteHead,
    },
    Deleting {
        delete_id: Id,
        attachment_epoch: FenceEpoch,
        head: RemoteHead,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVolumeLineage {
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    pub node_id: Id,
    pub placement_epoch: Epoch,
    pub local_durable_generation: Generation,
    pub remote_durable_generation: Generation,
    pub data_directory: HostPath,
    pub pending_pack_count: WireU64,
    pub fenced: bool,
    pub state: LocalLineageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcquireOrigin {
    Normal { transition_id: RandomId128 },
    Takeover { authorization_id: Id },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalLineageState {
    Active,
    Released,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedDevice {
    KernelNbd {
        guest_device: GuestDeviceIdentity,
        device_path: HostPath,
        ownership_token: OwnershipTokenEvidence,
    },
    VhostUserBlk {
        guest_device: GuestDeviceIdentity,
        socket_path: HostPath,
        ownership_token: OwnershipTokenEvidence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedMount {
    pub volume_id: Id,
    pub guest_device: GuestDeviceIdentity,
    pub source_path: HostPath,
    pub filesystem_uuid: RandomId128,
    pub mount_path: HostPath,
    pub access: MountAccess,
    pub instance_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountAccess {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedNetwork {
    pub kind: IsolatedIpv4Kind,
    pub network_id: Id,
    pub guest_mac: MacAddress,
    pub guest_ipv4: Ipv4Address,
    pub prefix_length: u8,
    pub gateway_ipv4: Ipv4Address,
    pub tap_name: Id,
    pub ownership_token: OwnershipTokenEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WarmSnapshotEvidence {
    Absent,
    Present {
        snapshot_id: Id,
        runtime_incarnation: RandomId128,
        path: HostPath,
        file_size_bytes: WireU64,
        file_digest: Sha256Digest,
        source_heads: Vec<VolumeHeadEvidence>,
        durable_rename_complete: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRouteGate {
    pub binding: RouteGateBinding,
    pub gate: RouteGateState,
    pub active_guards: u32,
    pub cancellation_pending: bool,
    pub instance_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGateBinding {
    pub workspace_id: Id,
    pub endpoint_id: Id,
    pub hostname: Hostname,
    pub cat_id: Id,
    pub node_id: Id,
    pub runtime_incarnation: RandomId128,
    pub route_epoch: Epoch,
    pub protocol: HttpProtocol,
    pub target_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteBindingEvidence {
    Missing,
    Corrupt { raw_content_digest: Sha256Digest },
    Valid { binding: RouteGateBinding },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeResidue {
    Process {
        process_id: u32,
        process_start_time_ticks: WireU64,
        executable_path: HostPath,
        scope_id: Option<Id>,
        control_socket_path: Option<HostPath>,
        role_hint: Option<ProcessRole>,
        ownership_token: OwnershipTokenEvidence,
        control_handshake: ControlHandshakeEvidence,
    },
    SystemdScope {
        scope_id: Id,
        cgroup_path: HostPath,
        ownership_token: OwnershipTokenEvidence,
    },
    ControlSocket {
        socket_path: HostPath,
        role_hint: Option<ProcessRole>,
        ownership_token: OwnershipTokenEvidence,
    },
    CheckpointFile {
        checkpoint_path: HostPath,
        evidence: ResidueCheckpointFileEvidence,
    },
    KernelNbd {
        volume_id_hint: Option<Id>,
        guest_device: Option<GuestDeviceIdentity>,
        device_path: HostPath,
        ownership_token: OwnershipTokenEvidence,
    },
    VhostUserBlk {
        volume_id_hint: Option<Id>,
        guest_device: Option<GuestDeviceIdentity>,
        socket_path: HostPath,
        ownership_token: OwnershipTokenEvidence,
    },
    NetworkTap {
        network_id_hint: Option<Id>,
        tap_name: Id,
        ownership_token: OwnershipTokenEvidence,
    },
    DataDirectory {
        volume_id_hint: Option<Id>,
        data_directory: HostPath,
        ownership_token: OwnershipTokenEvidence,
        lineage: ResidueLineageEvidence,
    },
    Mount {
        volume_id_hint: Option<Id>,
        source_path: HostPath,
        mount_path: HostPath,
        instance_count: u64,
    },
    WarmSnapshot {
        snapshot_id_hint: Option<Id>,
        path: HostPath,
        file_size_bytes: WireU64,
        file_digest: Option<Sha256Digest>,
    },
    RouteGate {
        binding: RouteBindingEvidence,
        gate: RouteGateState,
        active_guards: u32,
        cancellation_pending: bool,
        instance_count: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResidueLineageEvidence {
    Unreadable,
    Readable {
        attachment_id_hint: Option<Id>,
        attachment_epoch_hint: Option<FenceEpoch>,
        local_durable_generation: Generation,
        remote_durable_generation: Generation,
        pending_pack_count: WireU64,
        fenced: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResidueCheckpointFileEvidence {
    Corrupt {
        raw_content_digest: Sha256Digest,
    },
    Valid {
        content_digest: Sha256Digest,
        version: ContractVersion,
        cat_id: Id,
        node_id: Id,
        placement_epoch: Epoch,
        desired_revision: Revision,
        spec_digest: Sha256Digest,
        runtime_incarnation: Option<RandomId128>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeObservation {
    pub version: ContractVersion,
    pub observation_id: RandomId128,
    pub node_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub agent_session_epoch: Epoch,
    pub heartbeat_sequence: Sequence,
    pub observed_at_unix_ms: UnixMillis,
    pub complete_inventory: bool,
    pub inventory_epoch: Epoch,
    pub inventory_digest: Option<Sha256Digest>,
    pub inventory_read_position: Option<Sequence>,
    pub key_ring_version: Option<Epoch>,
    pub key_ring_digest: Option<Sha256Digest>,
    pub loaded_kids: Vec<KeyId>,
    pub runtimes: Vec<ObservedRuntimeStatus>,
    pub residue: Vec<NodeResidue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRuntimeStatus {
    pub cat_id: Id,
    pub applied_desired: Option<AppliedDesiredEvidence>,
    pub runtime_incarnation: Option<RandomId128>,
    pub stable_state: Option<StableState>,
    pub step: ReconcileStep,
    pub checkpoint: CheckpointEvidence,
    pub processes: Vec<ProcessEvidence>,
    pub volumes: Vec<ObservedVolume>,
    pub mounts: Vec<ObservedMount>,
    pub networks: Vec<ObservedNetwork>,
    pub guest_transport: GuestTransportEvidence,
    pub warm_snapshot: WarmSnapshotEvidence,
    pub lifecycle_admission: LifecycleAdmission,
    pub routes: Vec<ObservedRouteGate>,
    pub platform_guards: u32,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedDesiredEvidence {
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub placement: AssignedPlacement,
    pub target: RuntimeTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointEvidence {
    Missing {
        checkpoint_path: HostPath,
    },
    Corrupt {
        checkpoint_path: HostPath,
        raw_content_digest: Sha256Digest,
    },
    Valid {
        checkpoint_path: HostPath,
        content_digest: Sha256Digest,
        version: ContractVersion,
        cat_id: Id,
        node_id: Id,
        desired_revision: Revision,
        spec_digest: Sha256Digest,
        placement_epoch: Epoch,
        runtime_incarnation: Option<RandomId128>,
        stable_state: Option<StableState>,
        step: Box<ReconcileStep>,
        require_idle: Box<RequireIdleCheckpoint>,
        updated_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Ready { reason: ReadyReason },
    Progressing { reason: ProgressingReason },
    Blocked { reason: BlockedReason },
    PreconditionFailed { reason: PreconditionFailureReason },
    Degraded { reason: DegradedReason },
    Quarantined { reason: QuarantineReason },
    DataLossPossible { reason: DataLossReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReadyReason {
    PostconditionSatisfied { target: RuntimeTarget },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgressingReason {
    ReconcileStep { step: ReconcileStep },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySource {
    Checkpoint,
    Systemd,
    Process,
    ControlSocket,
    BlockFrontend,
    Network,
    DataDirectory,
    PendingPack,
    WarmSnapshot,
    MetadataStore,
    GuestMount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BlockedReason {
    IncompleteInventory {
        unavailable_sources: Vec<InventorySource>,
    },
    SupersededByAnotherNode {
        volume_id: Id,
        owner_node_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
    },
    ActiveGuards {
        platform_guards: u32,
        endpoint_guards: Vec<EndpointGuardCount>,
    },
    VolumeAuthorityUnavailable {
        volume_ids: Vec<Id>,
    },
    RemoteDurabilityLag {
        volume_id: Id,
        attachment_epoch: FenceEpoch,
        local_generation: Generation,
        remote_generation: Generation,
    },
    AuthorizationUnavailable {
        volume_id: Id,
        authorization_id: Id,
    },
    HostRejoinPending {
        host_fence_event_id: Id,
    },
    ControlPlaneUnavailable {
        last_desired_revision: Option<Revision>,
    },
    KeyRingUnavailable {
        expected_version: Epoch,
        expected_digest: Sha256Digest,
        loaded_version: Option<Epoch>,
        loaded_digest: Option<Sha256Digest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreconditionFailureReason {
    Busy {
        attempt_id: RandomId128,
        gate_closed: bool,
        platform_guards: u32,
        endpoint_guards: Vec<EndpointGuardCount>,
    },
    MustBeCold {
        observed_state: Option<StableState>,
    },
    PlacementRejected {
        node_id: Id,
        placement_epoch: Epoch,
        reason: PlacementRejectionReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementRejectionReason {
    InsufficientVcpus,
    InsufficientMemory,
    UnsupportedBlockPath,
    UnsupportedNetwork,
    UnsupportedGuestCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedSource {
    ControlStore,
    MetadataStore,
    Checkpoint,
    Systemd,
    Process,
    ControlSocket,
    BlockFrontend,
    Network,
    DataDirectory,
    PendingPack,
    WarmSnapshot,
    GuestMount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DegradedReason {
    SourceUnavailable {
        sources: Vec<DegradedSource>,
        since_unix_ms: UnixMillis,
    },
    AttestationRefreshFailed {
        inventory_epoch: Epoch,
        since_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuarantineReason {
    SpecDigestConflict {
        desired_revision: Revision,
        expected_digest: Sha256Digest,
        observed_digest: Sha256Digest,
    },
    CheckpointCorrupt {
        raw_content_digest: Sha256Digest,
    },
    RuntimeIdentityConflict {
        expected_incarnation: RandomId128,
        observed_incarnations: Vec<RandomId128>,
    },
    DuplicateRuntime {
        observed_incarnations: Vec<RandomId128>,
    },
    ProcessIdentityConflict {
        role: ProcessRole,
        process_ids: Vec<u32>,
    },
    VolumeIdentityConflict {
        volume_id: Id,
        expected_attachment_id: Id,
        expected_attachment_epoch: FenceEpoch,
        observed_attachment_id: Id,
        observed_attachment_epoch: FenceEpoch,
    },
    LocalLineageConflict {
        volume_id: Id,
        data_directory: HostPath,
        expected_attachment_id: Id,
        observed_attachment_id: Option<Id>,
    },
    LocalLineageCorrupt {
        volume_id: Id,
        data_directory: HostPath,
        problem: LocalLineageProblem,
    },
    DuplicateWriter {
        volume_id: Id,
        observed_attachments: Vec<AttachmentIdentity>,
    },
    DuplicateDevice {
        volume_id: Id,
        observed_device_count: WireU64,
    },
    DuplicateMount {
        volume_id: Id,
        mount_path: HostPath,
        observed_instance_count: WireU64,
    },
    DuplicateNetwork {
        network_id: Id,
        observed_tap_count: WireU64,
    },
    DuplicateRoute {
        endpoint_id: Id,
        observed_instance_count: WireU64,
    },
    InvalidOwnershipToken {
        resource: OwnershipTokenResource,
        evidence: OwnershipTokenEvidence,
    },
    UnattributedNodeResidue {
        residue: NodeResidue,
    },
    FilesystemIdentityConflict {
        volume_id: Id,
        expected_filesystem_uuid: RandomId128,
        observed_filesystem_uuid: Option<RandomId128>,
    },
    UnknownPersistentDisk {
        volume_id: Id,
        data_directory: Option<HostPath>,
    },
    WarmSnapshotConflict {
        snapshot_id: Id,
        expected_digest: Sha256Digest,
        observed_digest: Option<Sha256Digest>,
    },
    RouteGateConflict {
        endpoint_id: Id,
        expected_binding: RouteGateBinding,
        observed_binding: RouteGateBinding,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalLineageProblem {
    IdentityMissing,
    PendingPackGap,
    PendingPackCorrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentIdentity {
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnershipTokenResource {
    Process {
        process_id: u32,
        process_start_time_ticks: WireU64,
    },
    KernelNbd {
        device_path: HostPath,
    },
    VhostUserBlk {
        socket_path: HostPath,
    },
    NetworkTap {
        tap_name: Id,
    },
    DataDirectory {
        data_directory: HostPath,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DataLossReason {
    RemoteTailUnavailable {
        volume_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
        local_generation: Generation,
        remote_generation: Generation,
        host_fence_event_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub workspace_id: Id,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub desired_spec_digest: Sha256Digest,
    pub placement: AssignedPlacement,
    pub target: RuntimeTarget,
    pub phase: OperationPhase,
    pub terminal: Option<OperationTerminal>,
    pub created_at_unix_ms: UnixMillis,
    pub updated_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Pending,
    Succeeded,
    Failed,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationTerminal {
    Succeeded {
        result: OperationSuccess,
        completed_at_unix_ms: UnixMillis,
    },
    Failed {
        error: Box<OperationFailure>,
        completed_at_unix_ms: UnixMillis,
    },
    Superseded {
        superseded_by_revision: Revision,
        superseded_by_operation_id: Id,
        completed_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSuccess {
    pub observation_id: RandomId128,
    pub node_id: Id,
    pub agent_session_epoch: Epoch,
    pub heartbeat_sequence: Sequence,
    pub observed_target: RuntimeTarget,
    pub runtime_incarnation: Option<RandomId128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationFailure {
    PreconditionFailed {
        reason: PreconditionFailureReason,
    },
    HostLost {
        node_id: Id,
        agent_session_epoch: Epoch,
        host_fence_event_id: Id,
    },
    Quarantined {
        reason: Box<QuarantineReason>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractError {
    pub version: ContractVersion,
    pub error: Box<ContractErrorDetail>,
    pub message: String,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContractErrorDetail {
    StaleSession {
        node_id: Id,
        presented_agent_session_epoch: Epoch,
        current_agent_session_epoch: Epoch,
    },
    WrongSession {
        expected: SessionBinding,
        presented: SessionBinding,
    },
    RegistrationAttemptConflict {
        node_id: Id,
        registration_attempt_id: RandomId128,
        expected: RegistrationAttemptBinding,
        presented: RegistrationAttemptBinding,
    },
    StaleObservationSequence {
        node_id: Id,
        agent_session_epoch: Epoch,
        presented_heartbeat_sequence: Sequence,
        last_accepted_heartbeat_sequence: Sequence,
    },
    ObservationSequenceConflict {
        node_id: Id,
        agent_session_epoch: Epoch,
        heartbeat_sequence: Sequence,
        accepted_observation_id: RandomId128,
        presented_observation_id: RandomId128,
    },
    StaleRevision {
        cat_id: Id,
        presented_revision: Revision,
        current_revision: Revision,
    },
    WrongRevision {
        cat_id: Id,
        expected_revision: Revision,
        presented_revision: Revision,
    },
    RevisionDigestConflict {
        cat_id: Id,
        desired_revision: Revision,
        expected_digest: Sha256Digest,
        presented_digest: Sha256Digest,
    },
    WrongPlacement {
        cat_id: Id,
        desired_revision: Revision,
        expected: AssignedPlacement,
        presented: AssignedPlacement,
    },
    UnsupportedVersion {
        contract: ContractName,
        supported_version: ContractVersion,
        presented_version: ContractVersion,
    },
    MalformedPayload {
        contract: ContractName,
        json_pointer: JsonPointer,
        problem: MalformedProblem,
    },
    LimitExceeded {
        contract: ContractName,
        json_pointer: JsonPointer,
        limit: LimitKind,
        maximum: WireU64,
        observed_at_least: WireU64,
    },
    IdempotencyConflict {
        authenticated_workspace_id: Id,
        canonical_route: AsciiText,
        idempotency_key: AsciiText,
        expected_request_fingerprint: Sha256Digest,
        presented_request_fingerprint: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationAttemptBinding {
    pub immutable_host_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub expected_agent_session_epoch: Option<Epoch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractName {
    NodeIdentity,
    AgentRegistrationAttempt,
    AgentSession,
    AdmissionInventoryAttestation,
    DesiredRuntimeSpec,
    RuntimeCheckpoint,
    NodeCleanupCheckpoint,
    NodeObservation,
    Operation,
    ContractError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedProblem {
    InvalidUtf8,
    InvalidJson,
    MissingField,
    UnknownField,
    DuplicateField,
    InvalidType,
    InvalidValue,
    DuplicateIdentity,
    NonCanonicalOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    WireBytes,
    ArrayItems,
}

#[cfg(test)]
mod tests {
    use super::Sha256Digest;

    #[test]
    fn digest_equality_uses_the_decoded_bytes_at_both_ends() {
        let zero = Sha256Digest::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let first = Sha256Digest::new(format!("sha256:1{}", "0".repeat(63))).unwrap();
        let last = Sha256Digest::new(format!("sha256:{}1", "0".repeat(63))).unwrap();

        assert_eq!(zero, zero.clone());
        assert_ne!(zero, first);
        assert_ne!(zero, last);
    }
}

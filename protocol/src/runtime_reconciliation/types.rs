use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const MAX_WIRE_INTEGER: u64 = i64::MAX as u64;

/// Fixed Guest Agent AF_VSOCK port for the clean-slate V1 runtime contract.
pub const GUEST_AGENT_VSOCK_PORT_V1: u16 = 5_000;
/// Cloud Hypervisor v53 copies at most `VIRTIO_BLK_ID_BYTES` bytes into the
/// Guest-visible virtio-blk serial. Every Runtime Reconciliation V1 carrier of
/// `GuestDeviceIdentity` therefore shares this stricter bound than a general
/// `Id`.
pub const GUEST_DEVICE_SERIAL_MAX_BYTES_V1: usize = 20;

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
integer_newtype!(AllocatableMemoryBytes, 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AllocatableVcpus(u32);

impl AllocatableVcpus {
    pub fn new(value: u32) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for AllocatableVcpus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value)
            .ok_or_else(|| serde::de::Error::custom("allocatable vCPU count must be positive"))
    }
}

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

pub(crate) fn valid_base64url_no_pad(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value.contains('=') {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| URL_SAFE_NO_PAD.encode(decoded) == value)
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
string_newtype!(Base64UrlNoPad, valid_base64url_no_pad);

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
pub struct ProviderScope {
    pub provider: Id,
    pub partition: Id,
    pub account_id: Id,
    pub region: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    pub version: ContractVersion,
    pub node_id: Id,
    /// Provider scope plus `immutable_host_id` is the complete immutable Host
    /// identity. Provider instance IDs are never interpreted globally.
    pub provider_scope: ProviderScope,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSchedulingState {
    Cordoned,
    Schedulable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePlacementVmm {
    CloudHypervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePlacementBlockFrontend {
    KernelNbd,
    VhostUserBlk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePlacementGuestNetwork {
    IsolatedIpv4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePlacementGuestTransport {
    Vsock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePlacementCapabilities {
    pub vmm: RuntimePlacementVmm,
    pub block_frontend: RuntimePlacementBlockFrontend,
    pub guest_network: RuntimePlacementGuestNetwork,
    pub guest_transport: RuntimePlacementGuestTransport,
    pub guest_agent_protocol_version: ContractVersion,
    pub guest_config_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestIpv4PoolKind {
    PrivateIpv4_16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestIpv4Pool {
    pub kind: GuestIpv4PoolKind,
    pub network_address: Ipv4Address,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePlacementPolicy {
    pub version: ContractVersion,
    pub node_id: Id,
    pub policy_revision: Epoch,
    pub scheduling_state: RuntimeSchedulingState,
    pub allocatable_vcpus: AllocatableVcpus,
    pub allocatable_memory_bytes: AllocatableMemoryBytes,
    pub capabilities: RuntimePlacementCapabilities,
    pub guest_ipv4_pool: GuestIpv4Pool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicKeyCredentialBinding {
    PublicKey {
        public_key_spki_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeNodeAuthorityApply {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub node_id: Id,
    pub mutation: RuntimeNodeAuthorityMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeNodeAuthorityMutation {
    Provision {
        node_identity: Box<NodeIdentity>,
        placement_policy: Box<NodePlacementPolicy>,
    },
    UpdatePolicy {
        expected_policy_revision: Epoch,
        placement_policy: Box<NodePlacementPolicy>,
    },
    RotateCredential {
        expected_policy_revision: Epoch,
        expected_credential_id: Id,
        expected_credential_binding: PublicKeyCredentialBinding,
        new_credential_id: Id,
        new_credential_binding: PublicKeyCredentialBinding,
    },
    Retire {
        expected_policy_revision: Epoch,
        expected_credential_id: Id,
        expected_credential_binding: PublicKeyCredentialBinding,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNodeAuthorityOutcome {
    Provisioned,
    PolicyUpdated,
    CredentialRotated,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeNodeAuthorityApplyResult {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub node_id: Id,
    pub outcome: RuntimeNodeAuthorityOutcome,
    pub identity_state: NodeIdentityState,
    pub policy_revision: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeNodeAuthorityStoredOutcome {
    Applied {
        response: RuntimeNodeAuthorityApplyResult,
    },
    AuthorityPreconditionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProvisionerExpectedPrevious {
    pub trust_revision: Epoch,
    pub active_set_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProvisionerCredential {
    pub credential_id: Id,
    pub public_key_spki: Base64UrlNoPad,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProvisionerTrustBundle {
    pub version: ContractVersion,
    pub deployment_id: Id,
    pub trust_revision: Epoch,
    pub expected_previous: Option<RuntimeProvisionerExpectedPrevious>,
    pub credentials: Vec<RuntimeProvisionerCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProvisionerActiveSet {
    pub version: ContractVersion,
    pub deployment_id: Id,
    pub credentials: Vec<RuntimeProvisionerCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FleetPolicyPrincipal {
    DeploymentProvisioner {
        deployment_id: Id,
        credential_id: Id,
        public_key_spki: Base64UrlNoPad,
        public_key_spki_sha256: Sha256Digest,
    },
    WorkosFleetAdministrator {
        subject: Id,
        organization_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeNodeAuthorityApplyRecord {
    pub apply_id: RandomId128,
    pub request: Box<RuntimeNodeAuthorityApply>,
    pub request_sha256: Sha256Digest,
    pub principal: FleetPolicyPrincipal,
    pub outcome: RuntimeNodeAuthorityStoredOutcome,
    pub committed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRuntimeProfileReceipt {
    pub version: ContractVersion,
    pub kernel_digest: Sha256Digest,
    pub initramfs_digest: Option<Sha256Digest>,
    pub kernel_cmdline: AsciiText,
    pub guest_agent_protocol_version: ContractVersion,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Root,
    Persistent,
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
pub enum FilesystemInitialization {
    Existing,
    Initialize {
        initialization_token: RandomId128,
        expected_blank_head: RemoteHead,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpProtocol {
    Http,
}

/// The durable identity reserved before creating or adopting one Host tap.
///
/// The ownership token is independent from the logical network ID and from
/// every process/device token.  The full network configuration is retained so
/// a later VMM launch never has to reconstruct Guest addressing from a tap
/// name or from Node-local defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeNetworkIdentity {
    pub network_config: NetworkConfig,
    pub tap_name: Id,
    pub ownership_token: RandomId128,
}

/// Exact PersistentDisk filesystem identity retained by every atomic
/// lifecycle filesystem phase after the VMM has started.
///
/// This deliberately pairs one attachment's exact identity — runtime
/// incarnation, volume, attachment epoch and Guest device — with its immutable
/// mount contract. The Node joins it back to the runtime launch identity
/// before issuing a Guest effect; the Guest echo is physical evidence, never
/// storage or attachment authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentFilesystemBinding {
    pub runtime_incarnation: RandomId128,
    pub volume_intent_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub size_bytes: u64,
    pub guest_device: GuestDeviceIdentity,
    pub filesystem_uuid: RandomId128,
    pub mount_path: HostPath,
    pub initialization: FilesystemInitialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteHead {
    pub generation: Generation,
    pub root_hash: Option<Sha256Digest>,
    pub root_object_id: Option<AsciiText>,
}

/// The Volume Authority uses the same closed durability literals as runtime
/// intent and physical observation.  Keeping one wire type prevents the A22
/// transport from inventing a second spelling of the storage contract.
pub type VolumeDurability = Durability;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAdminState {
    Active,
    Deleting {
        delete_id: Id,
    },
    GarbageCollecting {
        gc_id: Id,
        roots_digest: Sha256Digest,
        started_at: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeRecord {
    pub volume_id: Id,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub admin_state: VolumeAdminState,
    /// True when a committed head change may have left unreachable private
    /// objects that require a snapshot-aware GC pass.
    pub gc_required: bool,
    pub head: RemoteHead,
    pub lease_owner: Option<Id>,
    pub lease_epoch: FenceEpoch,
    pub lease_expires_at: Option<UnixMillis>,
    pub last_transition: Option<LastVolumeTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LastVolumeTransition {
    NormalAcquire {
        request: NormalAcquireRequest,
        result: NormalAcquireResult,
    },
    Release {
        request: ReleaseRequest,
        result: ReleaseResult,
    },
    BeginDelete {
        request: BeginDeleteRequest,
        result: BeginDeleteResult,
    },
    SnapshotRestore {
        request: SnapshotRestoreRequest,
        result: SnapshotRestoreResult,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalAcquireRequest {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub expected_unowned_epoch: FenceEpoch,
    pub placement_epoch: Epoch,
    pub lease_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalAcquireResult {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub lease_expires_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub expected_epoch: FenceEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResult {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub released_attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDeleteRequest {
    pub delete_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub expected_unowned_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDeleteResult {
    pub delete_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

/// One exact same-disk snapshot-restore occurrence.
///
/// The complete predecessor authority tuple is the occurrence identity. The
/// Workspace caller supplies only an expected generation; the Control Store
/// expands it to the locked current head and epoch after joining the exact
/// snapshot, disk and volume rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRestoreRequest {
    pub snapshot_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub expected_size_bytes: u64,
    pub expected_unowned_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
    pub snapshot_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRestoreResult {
    pub snapshot_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRootImageRequest {
    pub provision_transition_id: RandomId128,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub size_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub expected_blank_head: RemoteHead,
    pub expected_provisioned_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRootImageResult {
    pub provision_transition_id: RandomId128,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProvisionRootImageError {
    Retryable {
        provision_transition_id: RandomId128,
        volume_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
        problem: ProvisionRootImageRetryableProblem,
    },
    DefiniteConflict {
        provision_transition_id: RandomId128,
        volume_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
        problem: ProvisionRootImageDefiniteConflictProblem,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionRootImageRetryableProblem {
    ImageUnavailable,
    ObjectStoreUnavailable,
    AuthorityUnavailable,
    LocalIoUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionRootImageDefiniteConflictProblem {
    RequestBinding,
    ImageManifest,
    TargetMismatch,
    LocalState,
    ImmutableObject,
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcquireOrigin {
    Normal { transition_id: RandomId128 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountAccess {
    ReadWrite,
    ReadOnly,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractName {
    NodeIdentity,
    NodePlacementPolicy,
    RuntimeNodeAuthorityApply,
    RuntimeNodeAuthorityApplyResult,
    RuntimeProvisionerTrustBundle,
    RuntimeProvisionerActiveSet,
    GuestRuntimeProfileReceipt,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionRootImageWireDecodeError {
    Malformed {
        json_pointer: JsonPointer,
        problem: MalformedProblem,
    },
    WireBytesLimitExceeded {
        maximum: WireU64,
        observed_at_least: WireU64,
    },
}

impl fmt::Display for ProvisionRootImageWireDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("root image provision payload validation failed")
    }
}

impl std::error::Error for ProvisionRootImageWireDecodeError {}

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

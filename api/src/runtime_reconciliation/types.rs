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

pub(crate) fn valid_guest_device_serial(value: &str) -> bool {
    valid_id(value) && value.len() <= GUEST_DEVICE_SERIAL_MAX_BYTES_V1
}

pub(crate) fn valid_ascii_text(value: &str) -> bool {
    (1..=512).contains(&value.len()) && printable_ascii(value)
}

/// The closed shape of an assigned object-write writer-authority ID: the one
/// version prefix followed by the SHA-256 of its exact binding preimage.
pub(crate) fn valid_object_write_writer_authority_id(value: &str) -> bool {
    value
        .strip_prefix("owa1_")
        .is_some_and(|digest| digest.len() == 64 && lowercase_hex(digest))
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

fn ipv4_number_like_hostname(value: &str) -> bool {
    value.split('.').all(|component| {
        component.bytes().all(|byte| byte.is_ascii_digit())
            || component
                .strip_prefix("0x")
                .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
    })
}

pub(crate) fn valid_node_transport_target(value: &str) -> bool {
    if !(1..=512).contains(&value.len()) {
        return false;
    }
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return false;
    }
    let Some((hostname, port)) = authority.rsplit_once(':') else {
        return false;
    };
    valid_hostname(hostname)
        && hostname.parse::<Ipv4Addr>().is_err()
        && !ipv4_number_like_hostname(hostname)
        && port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .is_some_and(|parsed| parsed.to_string() == port)
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
string_newtype!(NodeTransportTarget, valid_node_transport_target);
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
    pub node_transport_target: NodeTransportTarget,
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
    /// Opens the one Host-scoped object-write writer authority this Node's
    /// attachment credentials register against. The operator states only the
    /// object-store side of the binding; Control derives the Host identity,
    /// the assigned authority ID and the empty accepted-sequence state from
    /// the Node's own provisioned identity.
    ProvisionObjectWriteAuthority {
        expected_policy_revision: Epoch,
        object_provider_scope: ProviderScope,
        workload_principal_id: AsciiText,
        object_store_scope_id: AsciiText,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNodeAuthorityOutcome {
    Provisioned,
    PolicyUpdated,
    CredentialRotated,
    Retired,
    ObjectWriteAuthorityProvisioned,
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
    /// Present exactly for [`RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned`].
    /// Control assigns this ID and no caller may choose it. The Node cannot
    /// derive it either, so it reads its own assigned authority back from
    /// Control rather than carrying it as configuration.
    #[serde(default)]
    pub writer_authority_id: Option<Id>,
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
pub struct AgentRegistrationAttempt {
    pub version: ContractVersion,
    pub node_id: Id,
    pub immutable_host_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub registration_attempt_id: RandomId128,
    pub guest_config_digest: Sha256Digest,
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
    pub guest_config_digest: Sha256Digest,
    pub lease_deadline_unix_ms: UnixMillis,
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
pub struct DesiredReadRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub request_sequence: Sequence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredReadSnapshot {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub request_sequence: Sequence,
    pub read_position: Sequence,
    pub issued_at_unix_ms: UnixMillis,
    pub expires_at_unix_ms: UnixMillis,
    pub desired_specs: Vec<DesiredRuntimeSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAcceptance {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub observation_id: RandomId128,
    pub heartbeat_sequence: Sequence,
    pub accepted_at_unix_ms: UnixMillis,
    pub lease_deadline_unix_ms: UnixMillis,
    pub inventory: ObservationInventoryAcceptance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationInventoryAcceptance {
    Full {
        attestation: AdmissionInventoryAttestation,
    },
    Partial {
        inventory_epoch: Epoch,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpineError {
    pub version: ContractVersion,
    pub error: Box<RuntimeSpineErrorDetail>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeSpineErrorDetail {
    AuthenticationFailed,
    IdentityNotEligible,
    HttpRequestRejected { problem: RuntimeSpineHttpProblem },
    ContractError { contract_error: ContractError },
    NodeRequestInFlight,
    TemporarilyUnavailable,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSpineHttpProblem {
    MethodNotAllowed,
    QueryNotAllowed,
    ContentTypeNotAllowed,
    ContentEncodingNotAllowed,
    AuthorizationNotAllowed,
    AcceptNotAllowed,
    SemanticHeaderNotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignedSetLimit {
    DesiredSpecs,
    WireBytes,
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
    /// Closed, durable launch authority for every live VMM phase.
    ///
    /// This is deliberately not an `Option`: a checkpoint must state whether
    /// no launch exists or retain the complete identity that originally
    /// authorized `StartRuntime`.
    pub runtime_launch: RuntimeLaunch,
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

/// Descriptor-stable identity of the sealed record bridging root provisioning
/// to serving blockd startup.
///
/// The content digest alone is insufficient: device/inode/length bind the
/// exact no-replace publication and reject rename/recreate ABA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootServingHandoffRecordIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
}

/// Durable bridge from the final target-control checkpoint to PrepareDevice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootServingHandoff {
    pub predecessor_checkpoint_content_digest: Sha256Digest,
    pub record: RootServingHandoffRecordIdentity,
}

/// Descriptor-stable identity of the exact authorized-serving artifact used
/// when no root-provision process participates in this attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectAuthorizedAttachmentIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
}

/// Closed reason why a direct authorized attachment may enter PrepareDevice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectAuthorizedAttachmentPurpose {
    ExistingRoot,
    PersistentInitialized,
    PersistentUninitialized,
}

/// Exact provenance for the serving authorization consumed by PrepareDevice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServingAuthorityProvenance {
    AfterRootProvision {
        handoff: RootServingHandoff,
    },
    DirectAuthorizedAttachment {
        authorization: DirectAuthorizedAttachmentIdentity,
        purpose: DirectAuthorizedAttachmentPurpose,
    },
}

/// Exact identity to checkpoint before starting the serving blockd process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingBlockdIdentity {
    pub scope_id: Id,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub executable_path: HostPath,
    pub process_identity_token: RandomId128,
}

/// Closed physical frontend plan owned by one PrepareDevice checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrepareDeviceFrontend {
    KernelNbd {
        listener_socket_path: HostPath,
        device_path: HostPath,
        direct: bool,
    },
    VhostUserBlk {
        socket_path: HostPath,
        queues: u16,
        queue_size: u16,
    },
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

/// Immutable identity of one Host file consumed by a VMM launch.
///
/// The path is the canonical installed path selected by the Node's runtime
/// configuration.  Length and content digest make the checkpoint usable after
/// an Agent restart without treating that mutable path as sufficient proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchArtifact {
    pub path: HostPath,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
}

/// Exact executable and Guest boot bytes selected for one fresh VMM boot.
///
/// This is deliberately independent of any particular installer or release
/// manifest.  The producer records the files actually selected by its
/// installed runtime configuration and a fixed safe reader must re-open and
/// compare all members before launch or adoption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmmBootProvenance {
    pub vmm_executable: RuntimeLaunchArtifact,
    pub kernel: RuntimeLaunchArtifact,
    pub initramfs: Option<RuntimeLaunchArtifact>,
    pub kernel_cmdline: AsciiText,
}

/// Complete, restart-safe identity of one VMM launch.
///
/// `ReconcileStep::StartRuntime` carries the same fields for the narrow start
/// effect.  The checkpoint-level copy survives later Guest/admission steps so
/// replacing the step can never erase the only exact launch expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchIdentity {
    pub runtime_incarnation: RandomId128,
    pub scope_id: Id,
    pub launcher_executable: Box<RuntimeLaunchArtifact>,
    pub boot: Box<VmmBootProvenance>,
    pub process_identity_token: RandomId128,
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub guest_config_digest: Sha256Digest,
    pub api_socket_path: HostPath,
    pub vsock_socket_path: HostPath,
    pub guest_cid: u32,
    pub memory_file_path: HostPath,
    pub serial_log_path: HostPath,
    pub vmm_log_path: HostPath,
    pub network: Box<RuntimeNetworkIdentity>,
    pub devices: Vec<PreparedDeviceInput>,
}

/// Closed checkpoint state for the retained VMM launch authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "identity",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RuntimeLaunch {
    Absent,
    Present(Box<RuntimeLaunchIdentity>),
}

impl RuntimeLaunch {
    pub fn identity(&self) -> Option<&RuntimeLaunchIdentity> {
        match self {
            Self::Absent => None,
            Self::Present(identity) => Some(identity),
        }
    }
}

/// One exact PrepareDevice expectation retained by every later launch phase.
///
/// Public process/device observations are only projections of this authority:
/// direct/queue settings and sealed serving provenance cannot be reconstructed
/// from them after an Agent restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDeviceInput {
    pub volume_intent_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub disk_kind: DiskKind,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    pub expected_head: RemoteHead,
    pub size_bytes: u64,
    pub durability: Durability,
    pub guest_device: GuestDeviceIdentity,
    pub ownership_token: RandomId128,
    pub serving_authority: Box<ServingAuthorityProvenance>,
    pub serving_process: ServingBlockdIdentity,
    pub frontend: PrepareDeviceFrontend,
}

/// Exact PersistentDisk filesystem identity retained by every filesystem
/// reconciliation step after the VMM has started.
///
/// This is deliberately a projection of one [`PreparedDeviceInput`] plus the
/// current Desired mount contract.  The Node must join it back to the
/// immutable top-level [`RuntimeLaunch`] before issuing a Guest effect; the
/// Guest echo is physical evidence, never storage or attachment authority.
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
    ProvisionRootImage {
        provision_transition_id: RandomId128,
        volume_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
        scope_id: Id,
        control_socket_path: HostPath,
        data_directory: HostPath,
        process_identity_token: RandomId128,
        size_bytes: u64,
        boot_image_digest: Sha256Digest,
        expected_blank_head: RemoteHead,
        expected_provisioned_head: RemoteHead,
    },
    PrepareDevice {
        /// The complete canonical Guest device set.  The first
        /// PrepareDevice checkpoint publishes this vector atomically after
        /// every Desired volume has exact retained serving authorization; it
        /// is never an append-only progress accumulator.
        devices: Vec<PreparedDeviceInput>,
    },
    PrepareNetwork {
        network: RuntimeNetworkIdentity,
        devices: Vec<PreparedDeviceInput>,
    },
    FormatFilesystem {
        filesystem: Box<PersistentFilesystemBinding>,
    },
    DrainInitialization {
        filesystem: Box<PersistentFilesystemBinding>,
        local_generation: Generation,
        remote_generation: Generation,
    },
    CommitInitialized {
        filesystem: Box<PersistentFilesystemBinding>,
        new_remote_head: RemoteHead,
    },
    MountFilesystem {
        filesystem: Box<PersistentFilesystemBinding>,
        expected_head: RemoteHead,
    },
    StartRuntime {
        runtime_incarnation: RandomId128,
        scope_id: Id,
        /// Boxed only to keep the closed ReconcileStep/Condition enums bounded;
        /// serde still emits the exact nested object defined by the wire spec.
        launcher_executable: Box<RuntimeLaunchArtifact>,
        boot: Box<VmmBootProvenance>,
        process_identity_token: RandomId128,
        vcpus: u32,
        memory_bytes: u64,
        boot_image_digest: Sha256Digest,
        guest_config_digest: Sha256Digest,
        api_socket_path: HostPath,
        vsock_socket_path: HostPath,
        guest_cid: u32,
        memory_file_path: HostPath,
        serial_log_path: HostPath,
        vmm_log_path: HostPath,
        network: Box<RuntimeNetworkIdentity>,
        devices: Vec<PreparedDeviceInput>,
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
    /// Checkpoint-first lifecycle admission for a Ready Running runtime whose
    /// complete Desired contains no Endpoint gates to install.
    OpenAdmission {
        runtime_incarnation: RandomId128,
    },
    InstallGate {
        endpoint_id: Id,
        route_epoch: Epoch,
    },
    Quarantined,
}

impl ReconcileStep {
    /// Projects the complete launch identity carried by `StartRuntime`.
    ///
    /// Callers use this at the single predecessor -> successor boundary; all
    /// later phases must retain the resulting value verbatim at checkpoint
    /// top level rather than trying to reconstruct it from public evidence.
    pub fn start_runtime_launch_identity(&self) -> Option<RuntimeLaunchIdentity> {
        let Self::StartRuntime {
            runtime_incarnation,
            scope_id,
            launcher_executable,
            boot,
            process_identity_token,
            vcpus,
            memory_bytes,
            boot_image_digest,
            guest_config_digest,
            api_socket_path,
            vsock_socket_path,
            guest_cid,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            network,
            devices,
        } = self
        else {
            return None;
        };
        Some(RuntimeLaunchIdentity {
            runtime_incarnation: runtime_incarnation.clone(),
            scope_id: scope_id.clone(),
            launcher_executable: launcher_executable.clone(),
            boot: boot.clone(),
            process_identity_token: process_identity_token.clone(),
            vcpus: *vcpus,
            memory_bytes: *memory_bytes,
            boot_image_digest: boot_image_digest.clone(),
            guest_config_digest: guest_config_digest.clone(),
            api_socket_path: api_socket_path.clone(),
            vsock_socket_path: vsock_socket_path.clone(),
            guest_cid: *guest_cid,
            memory_file_path: memory_file_path.clone(),
            serial_log_path: serial_log_path.clone(),
            vmm_log_path: vmm_log_path.clone(),
            network: network.clone(),
            devices: devices.clone(),
        })
    }
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

/// The Volume Authority uses the same closed durability literals as runtime
/// intent and physical observation.  Keeping one wire type prevents the A22
/// transport from inventing a second spelling of the storage contract.
pub type VolumeDurability = Durability;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAdminState {
    Active,
    Deleting { delete_id: Id },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeRecord {
    pub volume_id: Id,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub admin_state: VolumeAdminState,
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
    Takeover {
        authorization_id: Id,
    },
    BeginDelete {
        request: BeginDeleteRequest,
        result: BeginDeleteResult,
    },
    BeginDisposableDelete {
        authorization_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalAcquireRequest {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub expected_unowned_epoch: FenceEpoch,
    pub desired_revision: Revision,
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
pub struct VolumeTakeoverAuthorization {
    pub authorization_id: Id,
    pub authorized_node_id: Id,
    pub host_fence_event_id: Id,
    pub volume_id: Id,
    pub expected_attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
    pub new_attachment_id: Id,
    pub desired_revision: Revision,
    pub new_placement_epoch: Epoch,
    pub lease_duration_ms: u64,
    pub not_after: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakeoverConsumedReceipt {
    pub authorization_id: Id,
    pub host_fence_event_id: Id,
    pub volume_id: Id,
    pub new_attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub consumed_at: UnixMillis,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableRootDeleteAuthorization {
    pub authorization_id: Id,
    pub authorized_node_id: Id,
    pub delete_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub placement_epoch: Epoch,
    pub expected_attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
    pub isolation_basis: DisposableDeleteIsolationBasis,
    pub not_after: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisposableDeleteIsolationBasis {
    RuntimeStopped {
        node_id: Id,
        agent_session_epoch: Epoch,
        runtime_incarnation: RandomId128,
        observation_id: RandomId128,
    },
    HostFenceEvent {
        event_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDisposableDeleteConsumedReceipt {
    pub authorization_id: Id,
    pub volume_id: Id,
    pub disk_id: Id,
    pub cat_id: Id,
    pub delete_id: Id,
    pub prior_attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub consumed_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAuthorization {
    Takeover(VolumeTakeoverAuthorization),
    DisposableRootDelete(DisposableRootDeleteAuthorization),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationConsumedReceipt {
    Takeover(TakeoverConsumedReceipt),
    BeginDisposableDelete(BeginDisposableDeleteConsumedReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AuthorizationState {
    Unconsumed,
    Consumed(Box<AuthorizationConsumedReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    pub authorization: VolumeAuthorization,
    pub state: AuthorizationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeleteCompletionReceipt {
    Normal {
        request: BeginDeleteRequest,
        deleting_epoch: FenceEpoch,
        deleting_head: RemoteHead,
        completed_at: UnixMillis,
    },
    DisposableRoot {
        disk_id: Id,
        volume_id: Id,
        delete_id: Id,
        authorization_id: Id,
        prior_attachment_id: Id,
        deleting_epoch: FenceEpoch,
        deleting_head: RemoteHead,
        completed_at: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumeTransitionRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub placement: AssignedPlacement,
    pub transition: RuntimeVolumeTransition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeVolumeTransition {
    Acquire {
        request: VolumeAcquireRequest,
    },
    Release {
        cleanup: CleanupRelease,
    },
    DeleteDisposableRoot {
        authorization_id: Id,
    },
    CommitInitialized {
        filesystem: Box<PersistentFilesystemBinding>,
        new_remote_head: RemoteHead,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumeTransitionSuccess {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub placement: AssignedPlacement,
    pub outcome: RuntimeVolumeTransitionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeVolumeTransitionOutcome {
    LeaseGranted {
        grant: VolumeLeaseGrant,
    },
    Released {
        release: ReleaseResult,
    },
    DisposableRootDeleting {
        receipt: BeginDisposableDeleteConsumedReceipt,
    },
    PersistentInitialized {
        receipt: PersistentInitializationReceipt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentInitializationReceipt {
    pub disk_id: Id,
    pub volume_id: Id,
    pub initialization_token: RandomId128,
    pub filesystem_uuid: RandomId128,
    pub expected_blank_head: RemoteHead,
    pub initialized_head: RemoteHead,
    pub initialized_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeLeaseGrant {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub head: RemoteHead,
    pub lease_expires_at: UnixMillis,
    pub acquire_origin: AcquireOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumeTransitionEvidenceRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub authorization_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumeTransitionEvidenceSuccess {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub authorization_id: Id,
    pub authorization: AuthorizationRecord,
    pub current_volume: Option<VolumeRecord>,
    pub delete_completion: Option<DeleteCompletionReceipt>,
    pub direct_successor_authorization: Option<AuthorizationRecord>,
}

/// Immutable, complete Control receipt which created one serving attachment.
///
/// The residue contract carries this exact value (plus its domain-separated
/// digest) instead of reconstructing authority from path or identifier hints.
#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizedServingAcquire {
    Normal {
        request: NormalAcquireRequest,
        result: NormalAcquireResult,
    },
    Takeover {
        authorization: VolumeTakeoverAuthorization,
        receipt: TakeoverConsumedReceipt,
    },
}

/// One exact local block-data lineage presented for read-only reclaim
/// qualification.  This is physical evidence, not ownership authority.  The
/// Control Plane must bind it to the current PostgreSQL authority snapshot and
/// return one of the closed proofs below before the Node may delete any byte.
#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidueDataDirectoryLineage {
    pub workspace_id: Id,
    pub cat_id: Id,
    pub disk_id: Id,
    pub disk_kind: DiskKind,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    pub node_id: Id,
    /// Current Desired coordinate under which Control is asked to qualify
    /// reclamation. The immutable acquire receipt below carries its own
    /// historical revision and placement.
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub placement: AssignedPlacement,
    pub placement_epoch: Epoch,
    pub acquisition: AuthorizedServingAcquire,
    pub acquisition_digest: Sha256Digest,
    pub local_durable_generation: Generation,
    pub remote_durable_generation: Generation,
    pub remote_head: RemoteHead,
    pub pending_pack_count: WireU64,
    pub fenced: bool,
}

#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResidueAuthorityRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub lineage: ResidueDataDirectoryLineage,
}

#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResidueAuthoritySuccess {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub lineage: ResidueDataDirectoryLineage,
    pub outcome: RuntimeResidueAuthorityOutcome,
}

/// A read-only Control decision from one repeatable-read authority snapshot.
/// `Retained` is diagnostic only.  `Reclaimable` contains the complete proof
/// that a Node must independently validate against its retained descriptor.
#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeResidueAuthorityOutcome {
    Retained {
        reason: ResidueAuthorityRetentionReason,
    },
    Reclaimable {
        proof: Box<ResidueReclaimProof>,
    },
}

#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidueAuthorityRetentionReason {
    NoAuthorityRecord,
    CurrentOrNewerOwner,
    ReleaseNotRecorded,
    DeleteIncomplete,
    LineageMismatch,
    UniqueLocalTail,
    UnsupportedDiskKind,
}

#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResidueReclaimProof {
    OrdinaryRelease {
        current_volume: VolumeRecord,
    },
    NormalDeleteCompletion {
        completion: DeleteCompletionReceipt,
    },
    DisposableRootDeleteCompletion {
        completion: DeleteCompletionReceipt,
        consumed_authorization: AuthorizationRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumeTransitionError {
    pub version: ContractVersion,
    pub error: Box<RuntimeVolumeTransitionErrorDetail>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeVolumeTransitionErrorDetail {
    AuthenticationFailed,
    IdentityNotEligible,
    HttpRequestRejected {
        problem: RuntimeVolumeTransitionHttpProblem,
    },
    ContractError {
        contract_error: ContractError,
    },
    TransitionPreconditionFailed {
        cat_id: Id,
        problem: RuntimeVolumeTransitionPreconditionProblem,
    },
    VolumeAuthorityRejected {
        volume_id: Id,
        reason: RuntimeVolumeAuthorityRejection,
    },
    VolumeAuthorizationRejected {
        authorization_id: Id,
        reason: RuntimeVolumeAuthorizationRejection,
    },
    AuthorizationEvidenceUnavailable {
        authorization_id: Id,
    },
    NodeRequestInFlight,
    TemporarilyUnavailable,
    Internal,
}

pub type RuntimeVolumeTransitionHttpProblem = RuntimeSpineHttpProblem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeVolumeTransitionPreconditionProblem {
    InventorySessionReplaced,
    InventoryStale,
    VolumeIntentMismatch,
    CleanupEvidenceMismatch,
    AuthorizationBranchConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeVolumeAuthorityRejection {
    OtherWriter,
    Fenced,
    StaleTransition,
    InvalidLeaseDuration,
    EpochExhausted,
    AdminBusy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeVolumeAuthorizationRejection {
    InvalidAuthorization,
    InvalidLeaseDuration,
    SnapshotInUse,
    EpochExhausted,
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
        #[cfg(feature = "proposed-node-residue-reclamation")]
        cat_id_hint: Option<Id>,
        #[cfg(feature = "proposed-node-residue-reclamation")]
        disk_id_hint: Option<Id>,
        volume_id_hint: Option<Id>,
        data_directory: HostPath,
        #[cfg(feature = "proposed-node-residue-reclamation")]
        allocated_bytes: WireU64,
        #[cfg(feature = "proposed-node-residue-reclamation")]
        retention_reason: DataDirectoryRetentionReason,
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
        #[cfg(feature = "proposed-node-residue-reclamation")]
        lineage: Box<ResidueDataDirectoryLineage>,
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        attachment_id_hint: Option<Id>,
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        attachment_epoch_hint: Option<FenceEpoch>,
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        local_durable_generation: Generation,
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        remote_durable_generation: Generation,
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        pending_pack_count: WireU64,
        #[cfg(not(feature = "proposed-node-residue-reclamation"))]
        fenced: bool,
    },
}

/// Scanner/reconciler explanation for keeping one directory.  This field is
/// observation-only and is deliberately absent from every reclaim proof.
#[cfg(feature = "proposed-node-residue-reclamation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataDirectoryRetentionReason {
    CurrentDesiredAttachment,
    SupersededDesiredAttachment,
    UnassignedCat,
    UnreadableIdentity,
    IncompletePhysicalInventory,
    AuthorityProofPending,
    AuthorityDoesNotAuthorizeReclaim,
    UniqueLocalTail,
    PersistentDiskRetained,
    RootDiskRetained,
    ExactReclaimPending,
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
        runtime_launch: Box<RuntimeLaunch>,
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
    RootImageUnavailable {
        boot_image_digest: Sha256Digest,
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
    RootProvisionConflict {
        volume_id: Id,
        provision_transition_id: RandomId128,
        problem: RootProvisionConflictProblem,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootProvisionConflictProblem {
    ControlProcessIdentity,
    RequestBinding,
    ImageManifest,
    TargetMismatch,
    LocalState,
    ImmutableObject,
    HeadConflict,
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
    MissingAgentSession {
        node_id: Id,
    },
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
    GuestConfigMismatch {
        node_id: Id,
        expected_guest_config_digest: Sha256Digest,
        presented_guest_config_digest: Sha256Digest,
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
    SessionExpired {
        node_id: Id,
        agent_session_epoch: Epoch,
        lease_deadline_unix_ms: UnixMillis,
        server_time_unix_ms: UnixMillis,
    },
    StaleDesiredReadSequence {
        node_id: Id,
        agent_session_epoch: Epoch,
        presented_request_sequence: Sequence,
        last_request_sequence: Sequence,
    },
    WrongDesiredReadSequence {
        node_id: Id,
        agent_session_epoch: Epoch,
        expected_request_sequence: Sequence,
        presented_request_sequence: Sequence,
    },
    DesiredReadInProgress {
        node_id: Id,
        agent_session_epoch: Epoch,
        request_sequence: Sequence,
        read_position: Sequence,
        expires_at_unix_ms: UnixMillis,
    },
    AssignedSetLimitExceeded {
        node_id: Id,
        limit: AssignedSetLimit,
        maximum: WireU64,
        observed_at_least: WireU64,
    },
    MissingInventoryReadPosition {
        node_id: Id,
        agent_session_epoch: Epoch,
    },
    StaleInventoryReadPosition {
        node_id: Id,
        agent_session_epoch: Epoch,
        presented_read_position: Sequence,
        current_read_position: Sequence,
    },
    WrongInventoryReadPosition {
        node_id: Id,
        agent_session_epoch: Epoch,
        current_read_position: Sequence,
        presented_read_position: Sequence,
    },
    InventoryReadPositionExpired {
        node_id: Id,
        agent_session_epoch: Epoch,
        read_position: Sequence,
        expires_at_unix_ms: UnixMillis,
        server_time_unix_ms: UnixMillis,
    },
    InventoryReadPositionConsumed {
        node_id: Id,
        agent_session_epoch: Epoch,
        read_position: Sequence,
        accepted_observation_id: RandomId128,
        accepted_heartbeat_sequence: Sequence,
    },
    AssignedSetChanged {
        node_id: Id,
        agent_session_epoch: Epoch,
        read_position: Sequence,
    },
    IncompleteAssignedInventory {
        node_id: Id,
        agent_session_epoch: Epoch,
        read_position: Sequence,
        missing_cat_id: Id,
    },
    AssignedRuntimeBindingMismatch {
        node_id: Id,
        agent_session_epoch: Epoch,
        read_position: Sequence,
        cat_id: Id,
        expected: AppliedDesiredEvidence,
        presented: Option<AppliedDesiredEvidence>,
    },
    MissingInventoryAttestation {
        node_id: Id,
        agent_session_epoch: Epoch,
    },
    StaleInventoryEpoch {
        node_id: Id,
        agent_session_epoch: Epoch,
        presented_inventory_epoch: Epoch,
        current_inventory_epoch: Epoch,
    },
    WrongInventoryEpoch {
        node_id: Id,
        agent_session_epoch: Epoch,
        expected_inventory_epoch: Epoch,
        presented_inventory_epoch: Epoch,
    },
    PartialCatNotInFullInventory {
        node_id: Id,
        agent_session_epoch: Epoch,
        inventory_epoch: Epoch,
        cat_id: Id,
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
    pub guest_config_digest: Sha256Digest,
    pub expected_agent_session_epoch: Option<Epoch>,
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
    RuntimeNodeAuthorityApplyRecord,
    AgentRegistrationAttempt,
    AgentSession,
    GuestRuntimeProfileReceipt,
    AdmissionInventoryAttestation,
    DesiredReadRequest,
    DesiredReadSnapshot,
    DesiredRuntimeSpec,
    RuntimeCheckpoint,
    NodeCleanupCheckpoint,
    NodeObservation,
    ObservationAcceptance,
    RuntimeSpineError,
    RuntimeVolumeTransitionRequest,
    RuntimeVolumeTransitionSuccess,
    RuntimeVolumeTransitionEvidenceRequest,
    RuntimeVolumeTransitionEvidenceSuccess,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    RuntimeResidueAuthorityRequest,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    RuntimeResidueAuthoritySuccess,
    RuntimeVolumeTransitionError,
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

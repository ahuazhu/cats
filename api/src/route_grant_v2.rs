//! Frozen Route Grant v2 compact-JWS schema and strict parsing boundary.
//!
//! The control plane owns private-key signing, the Node owns admission and
//! public-key verification, and the Gateway treats the resulting token as an
//! opaque capability. This module is the single wire/schema implementation
//! shared by those components. In particular, claims are not decoded until a
//! caller has verified the signature over [`RouteGrantV2Compact::signing_input`].

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_reconciliation::{
    key_ring_digest, Base64UrlNoPad, ContractVersion, Epoch, Hostname, HttpProtocol, Id, KeyId,
    NodeTransportTarget, RandomId128, Sha256Digest,
};

pub const ROUTE_GRANT_V2_VERSION: u8 = 2;
pub const ROUTE_GRANT_V2_ISSUER: &str = "cats-control-plane";
pub const ROUTE_GRANT_V2_AUDIENCE: &str = "cats-node-agent";
pub const ROUTE_GRANT_V2_TYPE: &str = "cats-route-grant+jwt";
pub const DEFAULT_ROUTE_GRANT_V2_TTL_SECONDS: u64 = 120;
pub const MAX_ROUTE_GRANT_V2_TTL_SECONDS: u64 = 300;
pub const MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS: u64 = 5;
pub const MAX_ROUTE_GRANT_V2_COMPACT_BYTES: usize = 4096;
pub const MAX_ROUTE_GRANT_V2_HEADER_BYTES: usize = 512;
pub const MAX_ROUTE_GRANT_V2_PAYLOAD_BYTES: usize = 2048;

/// Exact Control resolve method once a Gateway machine-auth transport is
/// composed around the handler.
pub const ROUTE_RESOLVE_V2_METHOD: &str = "POST";
/// Exact Control resolve path. It is deliberately disjoint from the retired
/// `/v1/routes/resolve` public/shared-bearer surface.
pub const ROUTE_RESOLVE_V2_PATH: &str = "/v1/internal/routes/resolve";
pub const ROUTE_V2_JSON_CONTENT_TYPE: &str = "application/json";
pub const ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES: usize = 512;
pub const ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES: usize = 8192;
pub const ROUTE_RESOLVE_V2_DEADLINE_MILLIS: u64 = 2_000;
/// Exact Node machine-ingress method. A successful request upgrades this same
/// authenticated HTTP/1.1 exchange into the public-request byte tunnel; it is
/// not a separate Grant preflight.
pub const ROUTE_TUNNEL_V2_METHOD: &str = "POST";
pub const ROUTE_TUNNEL_V2_PATH: &str = "/v1/internal/routes/tunnel";
pub const ROUTE_TUNNEL_V2_UPGRADE: &str = "cats-route-v2-tunnel";
pub const ROUTE_TUNNEL_V2_REQUEST_MAX_WIRE_BYTES: usize = 5_120;
pub const ROUTE_TUNNEL_V2_FAILURE_MAX_WIRE_BYTES: usize = 256;
pub const ROUTE_TUNNEL_V2_CONNECT_DEADLINE_MILLIS: u64 = 2_000;
pub const MAX_ROUTE_GRANT_V2_RING_KEYS: usize = 8;
pub const ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES: usize = 16_384;
pub const ROUTE_GRANT_V2_ARTIFACT_DIRECTORY: &str = "/etc/cats/route-v2";
pub const ROUTE_GRANT_V2_SIGNER_REFERENCE_PATH: &str = "/etc/cats/route-v2/signer.v1.json";
pub const ROUTE_GRANT_V2_SIGNER_PRIVATE_KEY_PATH: &str =
    "/etc/cats/route-v2/signer-private-key.pem";
pub const ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH: &str = "/etc/cats/route-v2/public-key-ring.v1.json";
pub const NODE_ROUTE_V2_SERVER_CERTIFICATE_PATH: &str =
    "/etc/cats/route-v2/node-machine-server-certificate.pem";
pub const NODE_ROUTE_V2_SERVER_PRIVATE_KEY_PATH: &str =
    "/etc/cats/route-v2/node-machine-server-private-key.pem";
pub const NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH: &str =
    "/etc/cats/route-v2/node-server-ca-bundle.pem";
pub const GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH: &str =
    "/etc/cats/route-v2/gateway-machine-client-certificate.pem";
pub const GATEWAY_ROUTE_V2_CLIENT_PRIVATE_KEY_PATH: &str =
    "/etc/cats/route-v2/gateway-machine-client-private-key.pem";
pub const ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES: usize = 65_536;
pub const ROUTE_V2_PRIVATE_KEY_MAX_WIRE_BYTES: usize = 16_384;

/// Exact previous public-ring pointer used by the installer to reject a stale,
/// conflicting or skipped rotation before replacing the current artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2PublicKeyRingExpectedPrevious {
    pub ring_version: Epoch,
    pub key_ring_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2PublicKeyEntry {
    pub kid: KeyId,
    pub public_key_spki: Base64UrlNoPad,
}

/// Canonical, non-secret public-key ring installed on Control and every Node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2PublicKeyRingArtifact {
    pub version: ContractVersion,
    pub ring_version: Epoch,
    pub expected_previous: Option<RouteGrantV2PublicKeyRingExpectedPrevious>,
    pub keys: Vec<RouteGrantV2PublicKeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2SignerExpectedPrevious {
    pub signer_revision: Epoch,
    pub signer_reference_sha256: Sha256Digest,
}

/// The private-key selection is explicit so emergency disable never depends
/// on deleting a secret file or interpreting an absent local value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteGrantV2SignerSelection {
    Disabled,
    Active {
        active_kid: KeyId,
        secret_reference_id: Id,
    },
}

/// Canonical, non-secret Control artifact naming one independent Route v2
/// signer lineage and the exact public ring distributed to Nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2SignerReference {
    pub version: ContractVersion,
    pub deployment_id: Id,
    pub signer_revision: Epoch,
    pub expected_previous: Option<RouteGrantV2SignerExpectedPrevious>,
    pub signer: RouteGrantV2SignerSelection,
    pub public_key_ring_version: Epoch,
    pub public_key_ring_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteGrantV2ArtifactError {
    #[error("Route Grant v2 artifact exceeds its wire-byte limit")]
    WireTooLarge,
    #[error("Route Grant v2 artifact is malformed")]
    Malformed,
    #[error("Route Grant v2 artifact is not the canonical encoding")]
    NonCanonical,
    #[error("Route Grant v2 artifact version or previous pointer is invalid")]
    InvalidLineage,
    #[error("Route Grant v2 public-key ring exceeds its key bound")]
    TooManyKeys,
    #[error("Route Grant v2 public-key ring is not strictly ordered")]
    InvalidKeyOrder,
    #[error("Route Grant v2 public key is not canonical Ed25519 SPKI")]
    InvalidPublicKey,
    #[error("Route Grant v2 public key does not match its kid")]
    KeyIdMismatch,
    #[error("Route Grant v2 signer does not bind the exact installed public ring")]
    RingMismatch,
    #[error("Route Grant v2 active signer kid is absent from the installed public ring")]
    ActiveKeyMissing,
}

impl RouteGrantV2PublicKeyRingArtifact {
    pub fn validate(&self) -> Result<(), RouteGrantV2ArtifactError> {
        if self.version != ContractVersion::V1 || !previous_ring_is_adjacent(self) {
            return Err(RouteGrantV2ArtifactError::InvalidLineage);
        }
        if self.keys.len() > MAX_ROUTE_GRANT_V2_RING_KEYS {
            return Err(RouteGrantV2ArtifactError::TooManyKeys);
        }
        let mut previous_kid: Option<&KeyId> = None;
        for entry in &self.keys {
            if previous_kid.is_some_and(|previous| previous >= &entry.kid) {
                return Err(RouteGrantV2ArtifactError::InvalidKeyOrder);
            }
            let public = RouteGrantV2PublicKey::from_base64url_spki(&entry.public_key_spki)
                .map_err(|_| RouteGrantV2ArtifactError::InvalidPublicKey)?;
            if public.kid() != &entry.kid {
                return Err(RouteGrantV2ArtifactError::KeyIdMismatch);
            }
            previous_kid = Some(&entry.kid);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Sha256Digest, RouteGrantV2ArtifactError> {
        self.validate()?;
        let loaded_kids = self
            .keys
            .iter()
            .map(|entry| entry.kid.clone())
            .collect::<Vec<_>>();
        key_ring_digest(self.ring_version, &loaded_kids)
            .map_err(|_| RouteGrantV2ArtifactError::InvalidKeyOrder)
    }

    pub fn public_keys(&self) -> Result<Vec<RouteGrantV2PublicKey>, RouteGrantV2ArtifactError> {
        self.validate()?;
        self.keys
            .iter()
            .map(|entry| {
                RouteGrantV2PublicKey::from_base64url_spki(&entry.public_key_spki)
                    .map_err(|_| RouteGrantV2ArtifactError::InvalidPublicKey)
            })
            .collect()
    }

    pub fn key(&self, kid: &KeyId) -> Option<&RouteGrantV2PublicKeyEntry> {
        self.keys
            .binary_search_by(|entry| entry.kid.cmp(kid))
            .ok()
            .map(|index| &self.keys[index])
    }
}

impl RouteGrantV2SignerReference {
    pub fn validate(&self) -> Result<(), RouteGrantV2ArtifactError> {
        if self.version != ContractVersion::V1 || !previous_signer_is_adjacent(self) {
            return Err(RouteGrantV2ArtifactError::InvalidLineage);
        }
        Ok(())
    }

    pub fn validate_ring(
        &self,
        ring: &RouteGrantV2PublicKeyRingArtifact,
    ) -> Result<(), RouteGrantV2ArtifactError> {
        self.validate()?;
        ring.validate()?;
        if self.public_key_ring_version != ring.ring_version
            || self.public_key_ring_digest != ring.digest()?
        {
            return Err(RouteGrantV2ArtifactError::RingMismatch);
        }
        if let RouteGrantV2SignerSelection::Active { active_kid, .. } = &self.signer {
            if ring.key(active_kid).is_none() {
                return Err(RouteGrantV2ArtifactError::ActiveKeyMissing);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Sha256Digest, RouteGrantV2ArtifactError> {
        let bytes = encode_route_grant_v2_signer_reference(self)?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
    }
}

fn previous_ring_is_adjacent(ring: &RouteGrantV2PublicKeyRingArtifact) -> bool {
    match (ring.ring_version.get(), &ring.expected_previous) {
        (1, None) => true,
        (1, Some(_)) | (_, None) => false,
        (revision, Some(previous)) => previous
            .ring_version
            .get()
            .checked_add(1)
            .is_some_and(|next| next == revision),
    }
}

fn previous_signer_is_adjacent(reference: &RouteGrantV2SignerReference) -> bool {
    match (
        reference.signer_revision.get(),
        &reference.expected_previous,
    ) {
        (1, None) => true,
        (1, Some(_)) | (_, None) => false,
        (revision, Some(previous)) => previous
            .signer_revision
            .get()
            .checked_add(1)
            .is_some_and(|next| next == revision),
    }
}

pub fn encode_route_grant_v2_public_key_ring(
    value: &RouteGrantV2PublicKeyRingArtifact,
) -> Result<Vec<u8>, RouteGrantV2ArtifactError> {
    value.validate()?;
    encode_route_artifact(value)
}

pub fn decode_route_grant_v2_public_key_ring(
    bytes: &[u8],
) -> Result<RouteGrantV2PublicKeyRingArtifact, RouteGrantV2ArtifactError> {
    let value: RouteGrantV2PublicKeyRingArtifact = decode_route_artifact(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn encode_route_grant_v2_signer_reference(
    value: &RouteGrantV2SignerReference,
) -> Result<Vec<u8>, RouteGrantV2ArtifactError> {
    value.validate()?;
    encode_route_artifact(value)
}

pub fn decode_route_grant_v2_signer_reference(
    bytes: &[u8],
) -> Result<RouteGrantV2SignerReference, RouteGrantV2ArtifactError> {
    let value: RouteGrantV2SignerReference = decode_route_artifact(bytes)?;
    value.validate()?;
    Ok(value)
}

fn encode_route_artifact<T: Serialize>(value: &T) -> Result<Vec<u8>, RouteGrantV2ArtifactError> {
    let bytes = serde_json::to_vec(value).map_err(|_| RouteGrantV2ArtifactError::Malformed)?;
    if bytes.len() > ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES {
        return Err(RouteGrantV2ArtifactError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_route_artifact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, RouteGrantV2ArtifactError> {
    if bytes.len() > ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES {
        return Err(RouteGrantV2ArtifactError::WireTooLarge);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| RouteGrantV2ArtifactError::Malformed)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| RouteGrantV2ArtifactError::Malformed)?;
    if canonical != bytes {
        return Err(RouteGrantV2ArtifactError::NonCanonical);
    }
    Ok(value)
}

/// Canonical, body-bound input to the authenticated Control resolve service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResolveV2Request {
    pub version: u8,
    pub hostname: Hostname,
}

/// Positive authenticated Control envelope. `opaque_grant` is intentionally
/// a string rather than [`RouteGrantV2Compact`]: Gateway must never parse it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResolveV2Success {
    pub version: u8,
    pub cat_id: Id,
    pub endpoint_id: Id,
    pub node_transport_target: NodeTransportTarget,
    pub expires_at_unix_seconds: u64,
    pub opaque_grant: String,
    pub grant_sha256: Sha256Digest,
}

/// Canonical admission frame for one Gateway-to-Node tunnel. The public HTTP
/// request starts only after the authenticated Node returns `101`; therefore
/// these fields can never be confused with application headers or body bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTunnelV2Request {
    pub version: u8,
    pub cat_id: Id,
    pub endpoint_id: Id,
    pub hostname: Hostname,
    pub opaque_grant: String,
    pub grant_sha256: Sha256Digest,
}

impl std::fmt::Debug for RouteTunnelV2Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteTunnelV2Request")
            .field("version", &self.version)
            .field("cat_id", &self.cat_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("hostname", &self.hostname)
            .field("opaque_grant", &"[redacted]")
            .field("grant_sha256", &self.grant_sha256)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteResolveV2RejectionCode {
    AuthenticationFailed,
    InvalidRequest,
    NotFound,
    Gone,
    RunRequired,
    Pending,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResolveV2Rejection {
    pub version: u8,
    pub code: RouteResolveV2RejectionCode,
}

/// Closed Node-to-Gateway failure set. Every value except
/// `UpstreamUnavailable` is a pre-admission result and therefore proves that
/// no guard was acquired and no Guest byte was touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAdmissionV2Reason {
    Expired,
    NotYetValid,
    BindingMismatch,
    GateClosed,
    RuntimeNotReady,
    UnknownKey,
    InvalidSignature,
    InvalidClaims,
    UpstreamUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAdmissionV2Failure {
    pub version: u8,
    pub guard_acquired: bool,
    pub reason: RouteAdmissionV2Reason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteV2EnvelopeError {
    #[error("Route v2 envelope exceeds its wire-byte limit")]
    WireTooLarge,
    #[error("Route v2 envelope is malformed")]
    Malformed,
    #[error("Route v2 envelope is not the canonical encoding")]
    NonCanonical,
    #[error("Route v2 envelope fields are invalid")]
    Invalid,
}

impl RouteResolveV2Request {
    pub fn new(hostname: Hostname) -> Self {
        Self {
            version: ROUTE_GRANT_V2_VERSION,
            hostname,
        }
    }
}

impl RouteResolveV2Success {
    pub fn new(
        cat_id: Id,
        endpoint_id: Id,
        node_transport_target: NodeTransportTarget,
        expires_at_unix_seconds: u64,
        opaque_grant: String,
    ) -> Result<Self, RouteV2EnvelopeError> {
        let grant_sha256 = Sha256Digest::from_bytes(Sha256::digest(opaque_grant.as_bytes()).into());
        let value = Self {
            version: ROUTE_GRANT_V2_VERSION,
            cat_id,
            endpoint_id,
            node_transport_target,
            expires_at_unix_seconds,
            opaque_grant,
            grant_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RouteV2EnvelopeError> {
        if self.version != ROUTE_GRANT_V2_VERSION
            || self.expires_at_unix_seconds > i64::MAX as u64
            || self.opaque_grant.is_empty()
            || self.opaque_grant.len() > MAX_ROUTE_GRANT_V2_COMPACT_BYTES
            || !self.opaque_grant.is_ascii()
            || self.grant_sha256
                != Sha256Digest::from_bytes(Sha256::digest(self.opaque_grant.as_bytes()).into())
        {
            return Err(RouteV2EnvelopeError::Invalid);
        }
        Ok(())
    }
}

impl RouteTunnelV2Request {
    pub fn new(
        cat_id: Id,
        endpoint_id: Id,
        hostname: Hostname,
        opaque_grant: String,
    ) -> Result<Self, RouteV2EnvelopeError> {
        let grant_sha256 = Sha256Digest::from_bytes(Sha256::digest(opaque_grant.as_bytes()).into());
        let value = Self {
            version: ROUTE_GRANT_V2_VERSION,
            cat_id,
            endpoint_id,
            hostname,
            opaque_grant,
            grant_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RouteV2EnvelopeError> {
        if self.version != ROUTE_GRANT_V2_VERSION
            || self.opaque_grant.is_empty()
            || self.opaque_grant.len() > MAX_ROUTE_GRANT_V2_COMPACT_BYTES
            || !self.opaque_grant.is_ascii()
            || self.grant_sha256
                != Sha256Digest::from_bytes(Sha256::digest(self.opaque_grant.as_bytes()).into())
        {
            return Err(RouteV2EnvelopeError::Invalid);
        }
        Ok(())
    }
}

impl RouteResolveV2Rejection {
    pub const fn new(code: RouteResolveV2RejectionCode) -> Self {
        Self {
            version: ROUTE_GRANT_V2_VERSION,
            code,
        }
    }
}

impl RouteAdmissionV2Failure {
    pub const fn pre_admission(reason: RouteAdmissionV2Reason) -> Option<Self> {
        match reason {
            RouteAdmissionV2Reason::UpstreamUnavailable => None,
            _ => Some(Self {
                version: ROUTE_GRANT_V2_VERSION,
                guard_acquired: false,
                reason,
            }),
        }
    }

    pub const fn upstream_unavailable() -> Self {
        Self {
            version: ROUTE_GRANT_V2_VERSION,
            guard_acquired: true,
            reason: RouteAdmissionV2Reason::UpstreamUnavailable,
        }
    }

    fn validate(&self) -> Result<(), RouteV2EnvelopeError> {
        let guard_matches_reason = match self.reason {
            RouteAdmissionV2Reason::UpstreamUnavailable => self.guard_acquired,
            _ => !self.guard_acquired,
        };
        if self.version != ROUTE_GRANT_V2_VERSION || !guard_matches_reason {
            return Err(RouteV2EnvelopeError::Invalid);
        }
        Ok(())
    }
}

pub fn encode_route_resolve_v2_request(
    value: &RouteResolveV2Request,
) -> Result<Vec<u8>, RouteV2EnvelopeError> {
    if value.version != ROUTE_GRANT_V2_VERSION {
        return Err(RouteV2EnvelopeError::Invalid);
    }
    encode_canonical(value, ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES)
}

pub fn decode_route_resolve_v2_request(
    bytes: &[u8],
) -> Result<RouteResolveV2Request, RouteV2EnvelopeError> {
    let value: RouteResolveV2Request =
        decode_canonical(bytes, ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES)?;
    if value.version != ROUTE_GRANT_V2_VERSION {
        return Err(RouteV2EnvelopeError::Invalid);
    }
    Ok(value)
}

pub fn encode_route_resolve_v2_success(
    value: &RouteResolveV2Success,
) -> Result<Vec<u8>, RouteV2EnvelopeError> {
    value.validate()?;
    encode_canonical(value, ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES)
}

pub fn decode_route_resolve_v2_success(
    bytes: &[u8],
) -> Result<RouteResolveV2Success, RouteV2EnvelopeError> {
    let value: RouteResolveV2Success =
        decode_canonical(bytes, ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES)?;
    value.validate()?;
    Ok(value)
}

pub fn encode_route_tunnel_v2_request(
    value: &RouteTunnelV2Request,
) -> Result<Vec<u8>, RouteV2EnvelopeError> {
    value.validate()?;
    encode_canonical(value, ROUTE_TUNNEL_V2_REQUEST_MAX_WIRE_BYTES)
}

pub fn decode_route_tunnel_v2_request(
    bytes: &[u8],
) -> Result<RouteTunnelV2Request, RouteV2EnvelopeError> {
    let value: RouteTunnelV2Request =
        decode_canonical(bytes, ROUTE_TUNNEL_V2_REQUEST_MAX_WIRE_BYTES)?;
    value.validate()?;
    Ok(value)
}

pub fn encode_route_resolve_v2_rejection(
    value: &RouteResolveV2Rejection,
) -> Result<Vec<u8>, RouteV2EnvelopeError> {
    if value.version != ROUTE_GRANT_V2_VERSION {
        return Err(RouteV2EnvelopeError::Invalid);
    }
    encode_canonical(value, ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES)
}

pub fn decode_route_resolve_v2_rejection(
    bytes: &[u8],
) -> Result<RouteResolveV2Rejection, RouteV2EnvelopeError> {
    let value: RouteResolveV2Rejection =
        decode_canonical(bytes, ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES)?;
    if value.version != ROUTE_GRANT_V2_VERSION {
        return Err(RouteV2EnvelopeError::Invalid);
    }
    Ok(value)
}

pub fn encode_route_admission_v2_failure(
    value: &RouteAdmissionV2Failure,
) -> Result<Vec<u8>, RouteV2EnvelopeError> {
    value.validate()?;
    encode_canonical(value, ROUTE_TUNNEL_V2_FAILURE_MAX_WIRE_BYTES)
}

pub fn decode_route_admission_v2_failure(
    bytes: &[u8],
) -> Result<RouteAdmissionV2Failure, RouteV2EnvelopeError> {
    let value: RouteAdmissionV2Failure =
        decode_canonical(bytes, ROUTE_TUNNEL_V2_FAILURE_MAX_WIRE_BYTES)?;
    value.validate()?;
    Ok(value)
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, RouteV2EnvelopeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| RouteV2EnvelopeError::Invalid)?;
    if bytes.len() > maximum {
        return Err(RouteV2EnvelopeError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, RouteV2EnvelopeError> {
    if bytes.len() > maximum {
        return Err(RouteV2EnvelopeError::WireTooLarge);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| RouteV2EnvelopeError::Malformed)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| RouteV2EnvelopeError::Malformed)?;
    if canonical != bytes {
        return Err(RouteV2EnvelopeError::NonCanonical);
    }
    Ok(value)
}

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const ED25519_SIGNATURE_SEGMENT_BYTES: usize = 86;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2ProtectedHeader {
    pub alg: RouteGrantV2Algorithm,
    pub typ: RouteGrantV2Type,
    pub kid: KeyId,
}

impl RouteGrantV2ProtectedHeader {
    pub fn new(kid: KeyId) -> Self {
        Self {
            alg: RouteGrantV2Algorithm::EdDsa,
            typ: RouteGrantV2Type::CatsRouteGrantJwt,
            kid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteGrantV2Algorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteGrantV2Type {
    #[serde(rename = "cats-route-grant+jwt")]
    CatsRouteGrantJwt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2Claims {
    pub version: u8,
    pub iss: String,
    pub aud: String,
    pub workspace_id: Id,
    pub endpoint_id: Id,
    pub hostname: Hostname,
    pub cat_id: Id,
    pub node_id: Id,
    pub runtime_incarnation: RandomId128,
    pub route_epoch: Epoch,
    pub protocol: HttpProtocol,
    pub target_port: u16,
    /// Exact CA-verified Gateway leaf that obtained this Grant from Control.
    /// Node compares it with the leaf on the same mTLS tunnel before admission.
    pub gateway_public_key_spki_sha256: Sha256Digest,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
}

impl RouteGrantV2Claims {
    pub fn validate(&self) -> Result<(), RouteGrantV2Error> {
        if self.version != ROUTE_GRANT_V2_VERSION
            || self.iss != ROUTE_GRANT_V2_ISSUER
            || self.aud != ROUTE_GRANT_V2_AUDIENCE
            || self.protocol != HttpProtocol::Http
            || self.target_port == 0
            || self.iat > i64::MAX as u64
            || self.nbf > i64::MAX as u64
            || self.exp > i64::MAX as u64
            || self.iat > self.nbf
            || self.nbf >= self.exp
        {
            return Err(RouteGrantV2Error::InvalidClaims);
        }
        let lifetime = self
            .exp
            .checked_sub(self.iat)
            .ok_or(RouteGrantV2Error::InvalidClaims)?;
        if !(1..=MAX_ROUTE_GRANT_V2_TTL_SECONDS).contains(&lifetime) {
            return Err(RouteGrantV2Error::InvalidClaims);
        }
        Ok(())
    }

    pub fn time_verdict(
        &self,
        now_unix_seconds: u64,
    ) -> Result<RouteGrantV2TimeVerdict, RouteGrantV2Error> {
        self.validate()?;
        if now_unix_seconds > i64::MAX as u64 {
            return Err(RouteGrantV2Error::InvalidClaims);
        }
        let latest_early_time = now_unix_seconds
            .checked_add(MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS)
            .ok_or(RouteGrantV2Error::InvalidClaims)?;
        let earliest_late_time = now_unix_seconds
            .checked_sub(MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS)
            .ok_or(RouteGrantV2Error::InvalidClaims)?;
        if latest_early_time < self.nbf {
            return Ok(RouteGrantV2TimeVerdict::NotYetValid);
        }
        if earliest_late_time >= self.exp {
            return Ok(RouteGrantV2TimeVerdict::Expired);
        }
        Ok(RouteGrantV2TimeVerdict::Valid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteGrantV2TimeVerdict {
    Valid,
    NotYetValid,
    Expired,
}

/// Parsed compact structure whose claims bytes remain opaque until the
/// signature has been verified. This ordering prevents an unauthenticated
/// token from receiving a narrower binding/time rejection classification.
pub struct RouteGrantV2Compact {
    header: RouteGrantV2ProtectedHeader,
    payload: Vec<u8>,
    signature: [u8; ED25519_SIGNATURE_BYTES],
    signing_input: Vec<u8>,
}

impl RouteGrantV2Compact {
    pub fn parse(token: &str) -> Result<Self, RouteGrantV2Error> {
        if token.is_empty() || token.len() > MAX_ROUTE_GRANT_V2_COMPACT_BYTES || !token.is_ascii() {
            return Err(RouteGrantV2Error::InvalidCompact);
        }
        let mut segments = token.split('.');
        let protected = segments.next().ok_or(RouteGrantV2Error::InvalidCompact)?;
        let payload = segments.next().ok_or(RouteGrantV2Error::InvalidCompact)?;
        let signature = segments.next().ok_or(RouteGrantV2Error::InvalidCompact)?;
        if protected.is_empty()
            || payload.is_empty()
            || signature.is_empty()
            || segments.next().is_some()
            || protected.len() > maximum_base64url_bytes(MAX_ROUTE_GRANT_V2_HEADER_BYTES)
            || payload.len() > maximum_base64url_bytes(MAX_ROUTE_GRANT_V2_PAYLOAD_BYTES)
            || signature.len() != ED25519_SIGNATURE_SEGMENT_BYTES
        {
            return Err(RouteGrantV2Error::InvalidCompact);
        }

        let protected_bytes = decode_canonical_segment(protected)?;
        let payload_bytes = decode_canonical_segment(payload)?;
        let signature_bytes = decode_canonical_segment(signature)?;
        if protected_bytes.len() > MAX_ROUTE_GRANT_V2_HEADER_BYTES
            || payload_bytes.len() > MAX_ROUTE_GRANT_V2_PAYLOAD_BYTES
            || signature_bytes.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(RouteGrantV2Error::InvalidCompact);
        }
        let header: RouteGrantV2ProtectedHeader = serde_json::from_slice(&protected_bytes)
            .map_err(|_| RouteGrantV2Error::InvalidHeader)?;
        let signature: [u8; ED25519_SIGNATURE_BYTES] = signature_bytes
            .try_into()
            .map_err(|_| RouteGrantV2Error::InvalidCompact)?;
        Ok(Self {
            header,
            payload: payload_bytes,
            signature,
            signing_input: format!("{protected}.{payload}").into_bytes(),
        })
    }

    pub fn header(&self) -> &RouteGrantV2ProtectedHeader {
        &self.header
    }

    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    pub fn signature(&self) -> &[u8; ED25519_SIGNATURE_BYTES] {
        &self.signature
    }

    fn decode_claims(&self) -> Result<RouteGrantV2Claims, RouteGrantV2Error> {
        let claims: RouteGrantV2Claims =
            serde_json::from_slice(&self.payload).map_err(|_| RouteGrantV2Error::InvalidClaims)?;
        claims.validate()?;
        Ok(claims)
    }
}

/// Canonical protected-header and payload bytes ready for the control-plane
/// signer. The private key is intentionally absent from this API type.
pub struct RouteGrantV2SigningInput {
    compact_prefix: String,
}

impl RouteGrantV2SigningInput {
    pub fn new(
        header: &RouteGrantV2ProtectedHeader,
        claims: &RouteGrantV2Claims,
    ) -> Result<Self, RouteGrantV2Error> {
        claims.validate()?;
        let protected = serde_json::to_vec(header).map_err(|_| RouteGrantV2Error::InvalidHeader)?;
        let payload = serde_json::to_vec(claims).map_err(|_| RouteGrantV2Error::InvalidClaims)?;
        if protected.len() > MAX_ROUTE_GRANT_V2_HEADER_BYTES
            || payload.len() > MAX_ROUTE_GRANT_V2_PAYLOAD_BYTES
        {
            return Err(RouteGrantV2Error::InvalidCompact);
        }
        let compact_prefix = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(protected),
            URL_SAFE_NO_PAD.encode(payload)
        );
        Ok(Self { compact_prefix })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.compact_prefix.as_bytes()
    }

    pub fn finish(
        self,
        signature: &[u8; ED25519_SIGNATURE_BYTES],
    ) -> Result<String, RouteGrantV2Error> {
        self.finish_encoded_signature(&URL_SAFE_NO_PAD.encode(signature))
    }

    /// Finishes a compact token from a cryptographic provider's canonical
    /// base64url-no-pad Ed25519 signature output.
    pub fn finish_encoded_signature(
        self,
        encoded_signature: &str,
    ) -> Result<String, RouteGrantV2Error> {
        if encoded_signature.len() != ED25519_SIGNATURE_SEGMENT_BYTES
            || decode_canonical_segment(encoded_signature)?.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(RouteGrantV2Error::InvalidCompact);
        }
        let token = format!("{}.{}", self.compact_prefix, encoded_signature);
        if token.len() > MAX_ROUTE_GRANT_V2_COMPACT_BYTES {
            return Err(RouteGrantV2Error::InvalidCompact);
        }
        Ok(token)
    }
}

#[derive(Clone)]
pub struct RouteGrantV2PublicKey {
    kid: KeyId,
    raw_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

impl RouteGrantV2PublicKey {
    pub fn from_base64url_spki(
        public_key_spki: &Base64UrlNoPad,
    ) -> Result<Self, RouteGrantV2Error> {
        let der = URL_SAFE_NO_PAD
            .decode(public_key_spki.as_str())
            .map_err(|_| RouteGrantV2Error::InvalidPublicKey)?;
        Self::from_spki_der(&der)
    }

    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self, RouteGrantV2Error> {
        let raw_public_key = spki_der
            .strip_prefix(&ED25519_SPKI_PREFIX)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(RouteGrantV2Error::InvalidPublicKey)?;
        let kid = KeyId::new(hex::encode(Sha256::digest(spki_der)))
            .ok_or(RouteGrantV2Error::InvalidPublicKey)?;
        Ok(Self {
            kid,
            raw_public_key,
        })
    }

    pub fn from_public_key_pem(public_key_pem: &[u8]) -> Result<Self, RouteGrantV2Error> {
        let text =
            std::str::from_utf8(public_key_pem).map_err(|_| RouteGrantV2Error::InvalidPublicKey)?;
        let lines: Vec<_> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if lines.first() != Some(&"-----BEGIN PUBLIC KEY-----")
            || lines.last() != Some(&"-----END PUBLIC KEY-----")
            || lines.len() < 3
        {
            return Err(RouteGrantV2Error::InvalidPublicKey);
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(lines[1..lines.len() - 1].join(""))
            .map_err(|_| RouteGrantV2Error::InvalidPublicKey)?;
        Self::from_spki_der(&der)
    }

    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    pub fn spki_der(&self) -> [u8; ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_BYTES] {
        let mut spki_der = [0_u8; ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_BYTES];
        spki_der[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
        spki_der[ED25519_SPKI_PREFIX.len()..].copy_from_slice(&self.raw_public_key);
        spki_der
    }

    /// Exact Ed25519 verification bytes carried by the canonical SPKI. This
    /// lets a Control-only loader compare the public half derived from a
    /// private key without accepting another public-key encoding.
    pub fn verification_key_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTES] {
        &self.raw_public_key
    }

    pub fn verify<'a>(
        &self,
        compact: &'a RouteGrantV2Compact,
    ) -> Result<VerifiedRouteGrantV2<'a>, RouteGrantV2Error> {
        if compact.header.kid != self.kid {
            return Err(RouteGrantV2Error::UnknownKey);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, self.raw_public_key)
            .verify(compact.signing_input(), compact.signature())
            .map_err(|_| RouteGrantV2Error::InvalidSignature)?;
        Ok(VerifiedRouteGrantV2 { compact })
    }
}

/// Unforgeable proof that the compact signing input was verified with the
/// selected `kid`. Claims decoding is intentionally available only here.
pub struct VerifiedRouteGrantV2<'a> {
    compact: &'a RouteGrantV2Compact,
}

impl VerifiedRouteGrantV2<'_> {
    pub fn claims(&self) -> Result<RouteGrantV2Claims, RouteGrantV2Error> {
        self.compact.decode_claims()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteGrantV2Error {
    #[error("Route Grant v2 compact token is malformed or exceeds its bound")]
    InvalidCompact,
    #[error("Route Grant v2 protected header is invalid")]
    InvalidHeader,
    #[error("Route Grant v2 claims are invalid")]
    InvalidClaims,
    #[error("Route Grant v2 key is unknown")]
    UnknownKey,
    #[error("Route Grant v2 signature is invalid")]
    InvalidSignature,
    #[error("Route Grant v2 public key is not canonical Ed25519 SPKI")]
    InvalidPublicKey,
}

fn decode_canonical_segment(segment: &str) -> Result<Vec<u8>, RouteGrantV2Error> {
    if segment.contains('=') {
        return Err(RouteGrantV2Error::InvalidCompact);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| RouteGrantV2Error::InvalidCompact)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != segment {
        return Err(RouteGrantV2Error::InvalidCompact);
    }
    Ok(decoded)
}

const fn maximum_base64url_bytes(decoded_bytes: usize) -> usize {
    decoded_bytes.saturating_mul(4).saturating_add(2) / 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_v2_private_ed25519.pem");
    const PUBLIC_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_v2_public_ed25519.pem");
    const PUBLIC_KEY_SPKI: &str = "MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To";
    const PUBLIC_KEY_KID: &str = "2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99";

    fn public_ring() -> RouteGrantV2PublicKeyRingArtifact {
        RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(1).unwrap(),
            expected_previous: None,
            keys: vec![RouteGrantV2PublicKeyEntry {
                kid: KeyId::new(PUBLIC_KEY_KID).unwrap(),
                public_key_spki: Base64UrlNoPad::new(PUBLIC_KEY_SPKI).unwrap(),
            }],
        }
    }

    fn generated_public_entry() -> RouteGrantV2PublicKeyEntry {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        let public = RouteGrantV2PublicKey::from_spki_der(&spki).unwrap();
        RouteGrantV2PublicKeyEntry {
            kid: public.kid().clone(),
            public_key_spki: Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(public.spki_der()))
                .unwrap(),
        }
    }

    fn signer_reference() -> RouteGrantV2SignerReference {
        RouteGrantV2SignerReference {
            version: ContractVersion::V1,
            deployment_id: Id::new("route_deployment_a").unwrap(),
            signer_revision: Epoch::new(1).unwrap(),
            expected_previous: None,
            signer: RouteGrantV2SignerSelection::Active {
                active_kid: KeyId::new(PUBLIC_KEY_KID).unwrap(),
                secret_reference_id: Id::new("route_secret_a").unwrap(),
            },
            public_key_ring_version: Epoch::new(1).unwrap(),
            public_key_ring_digest: public_ring().digest().unwrap(),
        }
    }

    fn claims() -> RouteGrantV2Claims {
        RouteGrantV2Claims {
            version: ROUTE_GRANT_V2_VERSION,
            iss: ROUTE_GRANT_V2_ISSUER.to_owned(),
            aud: ROUTE_GRANT_V2_AUDIENCE.to_owned(),
            workspace_id: Id::new("ws_01").unwrap(),
            endpoint_id: Id::new("ep_01").unwrap(),
            hostname: Hostname::new("app.cats.run").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            node_id: Id::new("node-a").unwrap(),
            runtime_incarnation: RandomId128::new("11111111111111111111111111111111").unwrap(),
            route_epoch: Epoch::new(7).unwrap(),
            protocol: HttpProtocol::Http,
            target_port: 8080,
            gateway_public_key_spki_sha256: Sha256Digest::from_bytes([0_u8; 32]),
            iat: 1_786_156_800,
            nbf: 1_786_156_800,
            exp: 1_786_156_920,
        }
    }

    fn private_key_der() -> Vec<u8> {
        let text = std::str::from_utf8(PRIVATE_KEY).unwrap();
        let body = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("-----"))
            .collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }

    fn key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(&private_key_der()).unwrap()
    }

    fn sign_raw(protected: &[u8], payload: &[u8]) -> String {
        let prefix = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(protected),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = key_pair().sign(prefix.as_bytes());
        format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    fn signed_token(claims: &RouteGrantV2Claims) -> (String, RouteGrantV2PublicKey) {
        let public = RouteGrantV2PublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();
        let key = key_pair();
        assert_eq!(key.public_key().as_ref(), public.raw_public_key);
        let input = RouteGrantV2SigningInput::new(
            &RouteGrantV2ProtectedHeader::new(public.kid().clone()),
            claims,
        )
        .unwrap();
        let signature: [u8; ED25519_SIGNATURE_BYTES] =
            key.sign(input.as_bytes()).as_ref().try_into().unwrap();
        (input.finish(&signature).unwrap(), public)
    }

    #[test]
    fn exact_compact_vector_verifies_before_claims_decode() {
        let expected = claims();
        let (token, public) = signed_token(&expected);
        assert_eq!(
            token,
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImNhdHMtcm91dGUtZ3JhbnQrand0Iiwia2lkIjoiMjI4MWEwMmE3ZjQyZDkyZmE5Y2FhNWI3OTA3YjI5YzJmMDYwY2IwMDE5NmJlMjgwYWYzM2ZiN2JjOGUyN2U5OSJ9.eyJ2ZXJzaW9uIjoyLCJpc3MiOiJjYXRzLWNvbnRyb2wtcGxhbmUiLCJhdWQiOiJjYXRzLW5vZGUtYWdlbnQiLCJ3b3Jrc3BhY2VfaWQiOiJ3c18wMSIsImVuZHBvaW50X2lkIjoiZXBfMDEiLCJob3N0bmFtZSI6ImFwcC5jYXRzLnJ1biIsImNhdF9pZCI6ImNhdF8wMSIsIm5vZGVfaWQiOiJub2RlLWEiLCJydW50aW1lX2luY2FybmF0aW9uIjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJyb3V0ZV9lcG9jaCI6NywicHJvdG9jb2wiOiJodHRwIiwidGFyZ2V0X3BvcnQiOjgwODAsImdhdGV3YXlfcHVibGljX2tleV9zcGtpX3NoYTI1NiI6InNoYTI1NjowMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiaWF0IjoxNzg2MTU2ODAwLCJuYmYiOjE3ODYxNTY4MDAsImV4cCI6MTc4NjE1NjkyMH0.iXeD5dSKty7QnCEvTfwZLQ9IGkZBpZnQgmTGNKOR0o3hr8-o87PPlBpRboonIIZFWWSzR7CZGFrCUE5z3dFYDg"
        );
        let compact = RouteGrantV2Compact::parse(&token).unwrap();
        assert_eq!(compact.header().kid, *public.kid());
        let verified = public.verify(&compact).unwrap();
        assert_eq!(verified.claims().unwrap(), expected);
    }

    #[test]
    fn rejects_duplicate_unknown_oversize_and_tampered_tokens() {
        let (token, public) = signed_token(&claims());
        let compact = RouteGrantV2Compact::parse(&token).unwrap();
        public.verify(&compact).unwrap();

        let mut tampered = token.into_bytes();
        let payload = tampered.iter().position(|byte| *byte == b'.').unwrap() + 2;
        tampered[payload] = if tampered[payload] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = std::str::from_utf8(&tampered).unwrap();
        let compact = RouteGrantV2Compact::parse(tampered).unwrap();
        assert!(matches!(
            public.verify(&compact),
            Err(RouteGrantV2Error::InvalidSignature)
        ));

        for json in [
            br#"{"alg":"EdDSA","alg":"EdDSA","typ":"cats-route-grant+jwt","kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99"}"#.as_slice(),
            br#"{"alg":"EdDSA","typ":"cats-route-grant+jwt","kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","extra":1}"#.as_slice(),
        ] {
            let token = format!(
                "{}.e30.{}",
                URL_SAFE_NO_PAD.encode(json),
                URL_SAFE_NO_PAD.encode([0_u8; ED25519_SIGNATURE_BYTES])
            );
            assert_eq!(
                RouteGrantV2Compact::parse(&token).err(),
                Some(RouteGrantV2Error::InvalidHeader)
            );
        }

        let oversized = format!("{}.e30.{}", "A".repeat(4090), "A".repeat(86));
        assert_eq!(
            RouteGrantV2Compact::parse(&oversized).err(),
            Some(RouteGrantV2Error::InvalidCompact)
        );
    }

    #[test]
    fn rejects_wrong_header_key_and_signed_malformed_claims() {
        let public = RouteGrantV2PublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();
        let payload = serde_json::to_vec(&claims()).unwrap();
        for header in [
            br#"{"alg":"HS256","typ":"cats-route-grant+jwt","kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99"}"#.as_slice(),
            br#"{"alg":"EdDSA","typ":"JWT","kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99"}"#.as_slice(),
        ] {
            assert_eq!(
                RouteGrantV2Compact::parse(&sign_raw(header, &payload)).err(),
                Some(RouteGrantV2Error::InvalidHeader)
            );
        }

        let wrong_kid = RouteGrantV2ProtectedHeader::new(
            KeyId::new("0".repeat(64)).expect("zero is a syntactically valid unknown kid"),
        );
        let protected = serde_json::to_vec(&wrong_kid).unwrap();
        let compact = RouteGrantV2Compact::parse(&sign_raw(&protected, &payload)).unwrap();
        assert!(matches!(
            public.verify(&compact),
            Err(RouteGrantV2Error::UnknownKey)
        ));

        let protected =
            serde_json::to_vec(&RouteGrantV2ProtectedHeader::new(public.kid().clone())).unwrap();
        let mut duplicate = br#"{"version":2,"#.to_vec();
        duplicate.extend_from_slice(&payload[1..]);
        let mut unknown = payload.clone();
        assert_eq!(unknown.pop(), Some(b'}'));
        unknown.extend_from_slice(br#", "extra":1}"#);
        let mut wrong_version = claims();
        wrong_version.version = 1;
        let mut zero_port = claims();
        zero_port.target_port = 0;
        for invalid_payload in [
            duplicate,
            unknown,
            serde_json::to_vec(&wrong_version).unwrap(),
            serde_json::to_vec(&zero_port).unwrap(),
        ] {
            let compact = RouteGrantV2Compact::parse(&sign_raw(&protected, &invalid_payload))
                .expect("the compact signature and bounds are valid");
            let verified = public.verify(&compact).expect("raw payload was signed");
            assert_eq!(verified.claims(), Err(RouteGrantV2Error::InvalidClaims));
        }
    }

    #[test]
    fn validates_checked_claim_and_time_boundaries() {
        let valid = claims();
        assert_eq!(
            valid.time_verdict(valid.nbf).unwrap(),
            RouteGrantV2TimeVerdict::Valid
        );
        assert_eq!(
            valid.time_verdict(valid.nbf - 6).unwrap(),
            RouteGrantV2TimeVerdict::NotYetValid
        );
        assert_eq!(
            valid.time_verdict(valid.exp + 5).unwrap(),
            RouteGrantV2TimeVerdict::Expired
        );

        let mut invalid = valid.clone();
        invalid.exp = invalid.iat + MAX_ROUTE_GRANT_V2_TTL_SECONDS + 1;
        assert_eq!(invalid.validate(), Err(RouteGrantV2Error::InvalidClaims));
        invalid = valid.clone();
        invalid.nbf = invalid.exp;
        assert_eq!(invalid.validate(), Err(RouteGrantV2Error::InvalidClaims));
        assert_eq!(valid.time_verdict(4), Err(RouteGrantV2Error::InvalidClaims));
        invalid = valid;
        invalid.exp = i64::MAX as u64 + 1;
        assert_eq!(invalid.validate(), Err(RouteGrantV2Error::InvalidClaims));
    }

    #[test]
    fn resolve_and_admission_envelopes_have_exact_canonical_vectors() {
        let request = RouteResolveV2Request::new(Hostname::new("app.cats.run").unwrap());
        let request_bytes = encode_route_resolve_v2_request(&request).unwrap();
        assert_eq!(request_bytes, br#"{"version":2,"hostname":"app.cats.run"}"#);
        assert_eq!(
            decode_route_resolve_v2_request(&request_bytes).unwrap(),
            request
        );

        let success = RouteResolveV2Success::new(
            Id::new("cat_01").unwrap(),
            Id::new("ep_01").unwrap(),
            NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
            1_786_156_920,
            "opaque-grant-v2".to_owned(),
        )
        .unwrap();
        let success_bytes = encode_route_resolve_v2_success(&success).unwrap();
        assert_eq!(
            success_bytes,
            br#"{"version":2,"cat_id":"cat_01","endpoint_id":"ep_01","node_transport_target":"https://node-a.internal:7301","expires_at_unix_seconds":1786156920,"opaque_grant":"opaque-grant-v2","grant_sha256":"sha256:535211e38407e27449db1cd21b6e5e3e82c3fe1fd6aa55fc59308dd8bc6d293a"}"#
        );
        assert_eq!(
            decode_route_resolve_v2_success(&success_bytes).unwrap(),
            success
        );

        let tunnel = RouteTunnelV2Request::new(
            Id::new("cat_01").unwrap(),
            Id::new("ep_01").unwrap(),
            Hostname::new("app.cats.run").unwrap(),
            "opaque-grant-v2".to_owned(),
        )
        .unwrap();
        let tunnel_bytes = encode_route_tunnel_v2_request(&tunnel).unwrap();
        assert_eq!(
            tunnel_bytes,
            br#"{"version":2,"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.cats.run","opaque_grant":"opaque-grant-v2","grant_sha256":"sha256:535211e38407e27449db1cd21b6e5e3e82c3fe1fd6aa55fc59308dd8bc6d293a"}"#
        );
        assert_eq!(
            decode_route_tunnel_v2_request(&tunnel_bytes).unwrap(),
            tunnel
        );
        assert!(!format!("{tunnel:?}").contains("opaque-grant-v2"));

        let rejection = RouteResolveV2Rejection::new(RouteResolveV2RejectionCode::Pending);
        assert_eq!(
            encode_route_resolve_v2_rejection(&rejection).unwrap(),
            br#"{"version":2,"code":"pending"}"#
        );
        let run_required = RouteResolveV2Rejection::new(RouteResolveV2RejectionCode::RunRequired);
        let run_required_bytes = encode_route_resolve_v2_rejection(&run_required).unwrap();
        assert_eq!(
            run_required_bytes,
            br#"{"version":2,"code":"run_required"}"#
        );
        assert_eq!(
            decode_route_resolve_v2_rejection(&run_required_bytes).unwrap(),
            run_required
        );
        assert!(
            decode_route_resolve_v2_rejection(br#"{"version":2,"code":"wake_required"}"#).is_err()
        );
        let expired =
            RouteAdmissionV2Failure::pre_admission(RouteAdmissionV2Reason::Expired).unwrap();
        assert_eq!(
            encode_route_admission_v2_failure(&expired).unwrap(),
            br#"{"version":2,"guard_acquired":false,"reason":"expired"}"#
        );
        assert_eq!(
            encode_route_admission_v2_failure(&RouteAdmissionV2Failure::upstream_unavailable())
                .unwrap(),
            br#"{"version":2,"guard_acquired":true,"reason":"upstream_unavailable"}"#
        );
    }

    #[test]
    fn envelope_decoders_reject_noncanonical_duplicate_unknown_and_cross_field_values() {
        for malformed in [
            br#"{"hostname":"app.cats.run","version":2}"#.as_slice(),
            br#"{"version":2,"version":2,"hostname":"app.cats.run"}"#.as_slice(),
            br#"{"version":2,"hostname":"app.cats.run","extra":1}"#.as_slice(),
        ] {
            assert!(decode_route_resolve_v2_request(malformed).is_err());
        }
        assert_eq!(
            decode_route_resolve_v2_request(&vec![
                b'x';
                ROUTE_RESOLVE_V2_REQUEST_MAX_WIRE_BYTES + 1
            ]),
            Err(RouteV2EnvelopeError::WireTooLarge)
        );

        let inconsistent = br#"{"version":2,"guard_acquired":true,"reason":"expired"}"#;
        assert_eq!(
            decode_route_admission_v2_failure(inconsistent),
            Err(RouteV2EnvelopeError::Invalid)
        );
        let wrong_digest = br#"{"version":2,"cat_id":"cat_01","endpoint_id":"ep_01","node_transport_target":"https://node-a.internal:7301","expires_at_unix_seconds":1786156920,"opaque_grant":"opaque-grant-v2","grant_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#;
        assert_eq!(
            decode_route_resolve_v2_success(wrong_digest),
            Err(RouteV2EnvelopeError::Invalid)
        );
    }

    #[test]
    fn public_key_requires_exact_ed25519_spki() {
        let public = RouteGrantV2PublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();
        assert_eq!(
            public.kid().as_str(),
            "2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99"
        );
        assert_eq!(
            RouteGrantV2PublicKey::from_spki_der(&[0_u8; 44]).err(),
            Some(RouteGrantV2Error::InvalidPublicKey)
        );
        let from_artifact = RouteGrantV2PublicKey::from_base64url_spki(
            &Base64UrlNoPad::new(PUBLIC_KEY_SPKI).unwrap(),
        )
        .unwrap();
        assert_eq!(from_artifact.kid(), public.kid());
        assert_eq!(
            RouteGrantV2PublicKey::from_spki_der(&from_artifact.spki_der())
                .unwrap()
                .kid(),
            public.kid()
        );
    }

    #[test]
    fn signing_authority_artifacts_have_exact_canonical_vectors() {
        let ring = public_ring();
        let ring_bytes = encode_route_grant_v2_public_key_ring(&ring).unwrap();
        assert_eq!(ring_bytes.len(), 219);
        assert_eq!(
            ring_bytes,
            br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#
        );
        assert_eq!(
            ring.digest().unwrap().as_str(),
            "sha256:7c7e324d7be6c6ee71735c900ce1041de63af7cc08fb39b6800853f966e81e34"
        );
        assert_eq!(
            Sha256Digest::from_bytes(Sha256::digest(&ring_bytes).into()).as_str(),
            "sha256:c3b1840a4ee7bd38425adb5f77cc7c32efdf306bb733e06dba2802851dbfc5a9"
        );
        assert_eq!(
            decode_route_grant_v2_public_key_ring(&ring_bytes).unwrap(),
            ring
        );

        let reference = signer_reference();
        reference.validate_ring(&ring).unwrap();
        let reference_bytes = encode_route_grant_v2_signer_reference(&reference).unwrap();
        assert_eq!(reference_bytes.len(), 369);
        assert_eq!(
            reference_bytes,
            br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:7c7e324d7be6c6ee71735c900ce1041de63af7cc08fb39b6800853f966e81e34"}"#
        );
        assert_eq!(
            reference.digest().unwrap().as_str(),
            "sha256:2e9c1e3de14fc1154123d9b0be6f0415bf76eb58a3be1244885a6676668898b0"
        );
        assert_eq!(
            decode_route_grant_v2_signer_reference(&reference_bytes).unwrap(),
            reference
        );
    }

    #[test]
    fn signing_authority_artifacts_reject_open_or_conflicting_lineage() {
        let mut empty = public_ring();
        empty.keys.clear();
        decode_route_grant_v2_public_key_ring(
            &encode_route_grant_v2_public_key_ring(&empty).unwrap(),
        )
        .unwrap();
        let mut maximum = public_ring();
        maximum.keys = (0..MAX_ROUTE_GRANT_V2_RING_KEYS)
            .map(|_| generated_public_entry())
            .collect();
        maximum.keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        maximum.validate().unwrap();
        let mut oversized = maximum.clone();
        oversized.keys.push(generated_public_entry());
        assert_eq!(
            oversized.validate(),
            Err(RouteGrantV2ArtifactError::TooManyKeys)
        );

        let mut ring = public_ring();
        ring.ring_version = Epoch::new(2).unwrap();
        assert_eq!(
            ring.validate(),
            Err(RouteGrantV2ArtifactError::InvalidLineage)
        );
        ring.expected_previous = Some(RouteGrantV2PublicKeyRingExpectedPrevious {
            ring_version: Epoch::new(1).unwrap(),
            key_ring_digest: public_ring().digest().unwrap(),
        });
        ring.validate().unwrap();
        let mut gap = ring.clone();
        gap.ring_version = Epoch::new(3).unwrap();
        assert_eq!(
            gap.validate(),
            Err(RouteGrantV2ArtifactError::InvalidLineage)
        );

        let other = RouteGrantV2PublicKeyEntry {
            kid: KeyId::new("47ff3f28dd2cc185ac432f34ecc346a121c52934b16993ab9fb7fcb92a3406f8")
                .unwrap(),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk",
            )
            .unwrap(),
        };
        ring.keys.push(other.clone());
        ring.keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        ring.validate().unwrap();
        ring.keys.swap(0, 1);
        assert_eq!(
            ring.validate(),
            Err(RouteGrantV2ArtifactError::InvalidKeyOrder)
        );
        ring.keys = vec![other; MAX_ROUTE_GRANT_V2_RING_KEYS + 1];
        assert_eq!(ring.validate(), Err(RouteGrantV2ArtifactError::TooManyKeys));

        let mut wrong_kid = public_ring();
        wrong_kid.keys[0].kid = KeyId::new("0".repeat(64)).unwrap();
        assert_eq!(
            wrong_kid.validate(),
            Err(RouteGrantV2ArtifactError::KeyIdMismatch)
        );
        let mut wrong_spki = public_ring();
        wrong_spki.keys[0].public_key_spki = Base64UrlNoPad::new("AA").unwrap();
        assert_eq!(
            wrong_spki.validate(),
            Err(RouteGrantV2ArtifactError::InvalidPublicKey)
        );

        let mut reference = signer_reference();
        reference.public_key_ring_digest = Sha256Digest::from_bytes([0; 32]);
        assert_eq!(
            reference.validate_ring(&public_ring()),
            Err(RouteGrantV2ArtifactError::RingMismatch)
        );
        reference = signer_reference();
        reference.signer = RouteGrantV2SignerSelection::Active {
            active_kid: KeyId::new("0".repeat(64)).unwrap(),
            secret_reference_id: Id::new("route_secret_b").unwrap(),
        };
        assert_eq!(
            reference.validate_ring(&public_ring()),
            Err(RouteGrantV2ArtifactError::ActiveKeyMissing)
        );
        reference = signer_reference();
        reference.signer_revision = Epoch::new(2).unwrap();
        assert_eq!(
            reference.validate(),
            Err(RouteGrantV2ArtifactError::InvalidLineage)
        );
        let previous_reference = signer_reference();
        reference.expected_previous = Some(RouteGrantV2SignerExpectedPrevious {
            signer_revision: Epoch::new(1).unwrap(),
            signer_reference_sha256: previous_reference.digest().unwrap(),
        });
        reference.validate().unwrap();
        reference
            .expected_previous
            .as_mut()
            .unwrap()
            .signer_revision = Epoch::new(2).unwrap();
        assert_eq!(
            reference.validate(),
            Err(RouteGrantV2ArtifactError::InvalidLineage)
        );

        let noncanonical = br#"{"ring_version":1,"version":1,"expected_previous":null,"keys":[]}"#;
        assert_eq!(
            decode_route_grant_v2_public_key_ring(noncanonical),
            Err(RouteGrantV2ArtifactError::NonCanonical)
        );
        // `jq -cS` emits lexicographic object-key order, which is not the
        // frozen schema order above. Installers must reuse this decoder rather
        // than bless a second, incompatible representation as canonical.
        let jq_sorted = br#"{"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}],"ring_version":1,"version":1}"#;
        assert_eq!(
            decode_route_grant_v2_public_key_ring(jq_sorted),
            Err(RouteGrantV2ArtifactError::NonCanonical)
        );
        let duplicate =
            br#"{"version":1,"version":1,"ring_version":1,"expected_previous":null,"keys":[]}"#;
        assert_eq!(
            decode_route_grant_v2_public_key_ring(duplicate),
            Err(RouteGrantV2ArtifactError::Malformed)
        );
        let unknown =
            br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[],"unknown":true}"#;
        assert_eq!(
            decode_route_grant_v2_public_key_ring(unknown),
            Err(RouteGrantV2ArtifactError::Malformed)
        );
        assert_eq!(
            decode_route_grant_v2_public_key_ring(&vec![
                b'x';
                ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES + 1
            ]),
            Err(RouteGrantV2ArtifactError::WireTooLarge)
        );
    }
}

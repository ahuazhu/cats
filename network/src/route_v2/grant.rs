use std::collections::BTreeMap;
use std::time::Duration;

use cats_api::route_grant_v2::{
    RouteGrantV2Compact, RouteGrantV2Error, RouteGrantV2PublicKey, RouteGrantV2TimeVerdict,
};
use cats_api::runtime_reconciliation::{Epoch, Hostname, Id, KeyId, NodeTransportTarget};
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

const MAX_KEY_RING_KEYS: usize = 64;
const MAX_PUBLIC_KEY_PEM_BYTES: usize = 1_024;

/// Exact positive result supplied by a future machine-authenticated Control
/// resolve adapter.
///
/// This is deliberately an in-process type, not a declaration of an HTTP path
/// or JSON wire. The Control-to-Gateway identity and response wire are not yet
/// frozen. A transport adapter may construct this value only after it has
/// authenticated the Control peer, classified the response as positive and
/// measured the bounded encoded response body supplied as `response_bytes`.
#[derive(Clone)]
pub struct AuthenticatedResolveEnvelope {
    endpoint_id: String,
    placement_node_id: String,
    node_transport_target: String,
    opaque_grant: String,
    expires_at_unix_seconds: u64,
    response_bytes: usize,
}

impl AuthenticatedResolveEnvelope {
    pub fn from_authenticated_transport(
        endpoint_id: impl Into<String>,
        placement_node_id: impl Into<String>,
        node_transport_target: impl Into<String>,
        opaque_grant: impl Into<String>,
        expires_at_unix_seconds: u64,
        response_bytes: usize,
    ) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            placement_node_id: placement_node_id.into(),
            node_transport_target: node_transport_target.into(),
            opaque_grant: opaque_grant.into(),
            expires_at_unix_seconds,
            response_bytes,
        }
    }
}

impl std::fmt::Debug for AuthenticatedResolveEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedResolveEnvelope")
            .field("endpoint_id", &self.endpoint_id)
            .field("placement_node_id", &self.placement_node_id)
            .field("node_transport_target", &self.node_transport_target)
            .field("opaque_grant", &"[redacted]")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("response_bytes", &self.response_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantDigest([u8; 32]);

impl GrantDigest {
    fn for_opaque_grant(grant: &str) -> Self {
        Self(Sha256::digest(grant.as_bytes()).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A positive route that has passed canonical compact parsing, key selection,
/// Ed25519 verification, claim validation, exact envelope binding and expiry.
///
/// It is still only a cached capability. The Node's current gate and atomic
/// guard remain the final admission authority.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRoute {
    hostname: Hostname,
    endpoint_id: Id,
    placement_node_id: Id,
    node_transport_target: NodeTransportTarget,
    opaque_grant: String,
    grant_digest: GrantDigest,
    expires_at: Instant,
    response_bytes: usize,
}

impl VerifiedRoute {
    pub fn hostname(&self) -> &Hostname {
        &self.hostname
    }

    pub fn endpoint_id(&self) -> &Id {
        &self.endpoint_id
    }

    pub fn placement_node_id(&self) -> &Id {
        &self.placement_node_id
    }

    pub fn node_transport_target(&self) -> &NodeTransportTarget {
        &self.node_transport_target
    }

    pub fn opaque_grant(&self) -> &str {
        &self.opaque_grant
    }

    pub fn grant_digest(&self) -> GrantDigest {
        self.grant_digest
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub(crate) fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

impl std::fmt::Debug for VerifiedRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRoute")
            .field("hostname", &self.hostname)
            .field("endpoint_id", &self.endpoint_id)
            .field("placement_node_id", &self.placement_node_id)
            .field("node_transport_target", &self.node_transport_target)
            .field("opaque_grant", &"[redacted]")
            .field("grant_digest", &self.grant_digest)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteGrantKeyRingError {
    TooManyKeys,
    DuplicateKey(KeyId),
    InvalidPublicKey,
}

impl std::fmt::Display for RouteGrantKeyRingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyKeys => write!(
                formatter,
                "Route Grant key ring exceeds {MAX_KEY_RING_KEYS} public keys"
            ),
            Self::DuplicateKey(kid) => write!(formatter, "duplicate Route Grant key {kid}"),
            Self::InvalidPublicKey => formatter.write_str("invalid Route Grant Ed25519 public key"),
        }
    }
}

impl std::error::Error for RouteGrantKeyRingError {}

/// Immutable, versioned and bounded Route Grant public-key ring.
///
/// Rotation composes immutable rings in verifier-first order. There is no
/// fallback key: the compact header's exact `kid` selects exactly one key.
pub struct RouteGrantKeyRing {
    version: Epoch,
    keys: BTreeMap<KeyId, RouteGrantV2PublicKey>,
}

impl RouteGrantKeyRing {
    pub fn from_public_keys(
        version: Epoch,
        keys: impl IntoIterator<Item = RouteGrantV2PublicKey>,
    ) -> Result<Self, RouteGrantKeyRingError> {
        let mut ring = BTreeMap::new();
        for key in keys {
            if ring.len() == MAX_KEY_RING_KEYS {
                return Err(RouteGrantKeyRingError::TooManyKeys);
            }
            let kid = key.kid().clone();
            if ring.insert(kid.clone(), key).is_some() {
                return Err(RouteGrantKeyRingError::DuplicateKey(kid));
            }
        }
        Ok(Self {
            version,
            keys: ring,
        })
    }

    pub fn from_public_key_pems<'a>(
        version: Epoch,
        public_key_pems: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, RouteGrantKeyRingError> {
        let mut keys = Vec::new();
        for pem in public_key_pems {
            if keys.len() == MAX_KEY_RING_KEYS {
                return Err(RouteGrantKeyRingError::TooManyKeys);
            }
            if pem.len() > MAX_PUBLIC_KEY_PEM_BYTES {
                return Err(RouteGrantKeyRingError::InvalidPublicKey);
            }
            keys.push(
                RouteGrantV2PublicKey::from_public_key_pem(pem)
                    .map_err(|_| RouteGrantKeyRingError::InvalidPublicKey)?,
            );
        }
        Self::from_public_keys(version, keys)
    }

    pub const fn version(&self) -> Epoch {
        self.version
    }

    pub fn loaded_kids(&self) -> impl ExactSizeIterator<Item = &KeyId> {
        self.keys.keys()
    }

    pub fn verify(
        &self,
        hostname: &Hostname,
        envelope: AuthenticatedResolveEnvelope,
        now_unix_seconds: u64,
        now: Instant,
    ) -> Result<VerifiedRoute, RouteGrantVerificationError> {
        let endpoint_id = Id::new(envelope.endpoint_id)
            .ok_or(RouteGrantVerificationError::InvalidEnvelopeIdentity)?;
        let placement_node_id = Id::new(envelope.placement_node_id)
            .ok_or(RouteGrantVerificationError::InvalidEnvelopeIdentity)?;
        let node_transport_target = NodeTransportTarget::new(envelope.node_transport_target)
            .ok_or(RouteGrantVerificationError::InvalidNodeTransportTarget)?;
        if envelope.response_bytes < envelope.opaque_grant.len() {
            return Err(RouteGrantVerificationError::InvalidResponseSize);
        }

        let compact = RouteGrantV2Compact::parse(&envelope.opaque_grant)
            .map_err(RouteGrantVerificationError::from_grant_error)?;
        let key = self
            .keys
            .get(&compact.header().kid)
            .ok_or(RouteGrantVerificationError::UnknownKey)?;
        let claims = key
            .verify(&compact)
            .map_err(RouteGrantVerificationError::from_grant_error)?
            .claims()
            .map_err(RouteGrantVerificationError::from_grant_error)?;

        if claims.hostname != *hostname
            || claims.endpoint_id != endpoint_id
            || claims.node_id != placement_node_id
        {
            return Err(RouteGrantVerificationError::BindingMismatch);
        }
        if claims.exp != envelope.expires_at_unix_seconds {
            return Err(RouteGrantVerificationError::ExpiryMismatch);
        }
        match claims
            .time_verdict(now_unix_seconds)
            .map_err(RouteGrantVerificationError::from_grant_error)?
        {
            RouteGrantV2TimeVerdict::Valid => {}
            RouteGrantV2TimeVerdict::NotYetValid => {
                return Err(RouteGrantVerificationError::NotYetValid)
            }
            RouteGrantV2TimeVerdict::Expired => return Err(RouteGrantVerificationError::Expired),
        }

        // The cache never admits past the explicit expiry, even inside the
        // Node verifier's clock-skew window.
        let remaining = claims
            .exp
            .checked_sub(now_unix_seconds)
            .filter(|remaining| *remaining > 0)
            .ok_or(RouteGrantVerificationError::Expired)?;
        let expires_at = now
            .checked_add(Duration::from_secs(remaining))
            .ok_or(RouteGrantVerificationError::DeadlineOverflow)?;
        let grant_digest = GrantDigest::for_opaque_grant(&envelope.opaque_grant);

        Ok(VerifiedRoute {
            hostname: hostname.clone(),
            endpoint_id,
            placement_node_id,
            node_transport_target,
            opaque_grant: envelope.opaque_grant,
            grant_digest,
            expires_at,
            response_bytes: envelope.response_bytes,
        })
    }
}

impl std::fmt::Debug for RouteGrantKeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteGrantKeyRing")
            .field("version", &self.version)
            .field("loaded_kids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteGrantVerificationError {
    InvalidEnvelopeIdentity,
    InvalidNodeTransportTarget,
    InvalidGrant,
    UnknownKey,
    InvalidSignature,
    BindingMismatch,
    ExpiryMismatch,
    NotYetValid,
    Expired,
    DeadlineOverflow,
    InvalidResponseSize,
}

impl RouteGrantVerificationError {
    fn from_grant_error(error: RouteGrantV2Error) -> Self {
        match error {
            RouteGrantV2Error::UnknownKey => Self::UnknownKey,
            RouteGrantV2Error::InvalidSignature => Self::InvalidSignature,
            RouteGrantV2Error::InvalidCompact
            | RouteGrantV2Error::InvalidHeader
            | RouteGrantV2Error::InvalidClaims
            | RouteGrantV2Error::InvalidPublicKey => Self::InvalidGrant,
        }
    }
}

impl std::fmt::Display for RouteGrantVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvelopeIdentity => {
                formatter.write_str("Route resolve envelope identity is invalid")
            }
            Self::InvalidNodeTransportTarget => {
                formatter.write_str("Route resolve Node transport target is not canonical HTTPS")
            }
            Self::InvalidGrant => formatter.write_str("Route Grant v2 is malformed"),
            Self::UnknownKey => formatter.write_str("Route Grant v2 key is not loaded"),
            Self::InvalidSignature => formatter.write_str("Route Grant v2 signature is invalid"),
            Self::BindingMismatch => {
                formatter.write_str("Route Grant v2 does not match the authenticated resolve")
            }
            Self::ExpiryMismatch => {
                formatter.write_str("Route Grant v2 expiry does not match the resolve envelope")
            }
            Self::NotYetValid => formatter.write_str("Route Grant v2 is not yet valid"),
            Self::Expired => formatter.write_str("Route Grant v2 is expired"),
            Self::DeadlineOverflow => formatter.write_str("Route Grant v2 deadline overflow"),
            Self::InvalidResponseSize => {
                formatter.write_str("Route resolve response size is inconsistent")
            }
        }
    }
}

impl std::error::Error for RouteGrantVerificationError {}

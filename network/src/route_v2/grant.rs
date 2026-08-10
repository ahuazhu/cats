use std::sync::Arc;
use std::time::Duration;

use cats_api::route_grant_v2::{
    MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS, MAX_ROUTE_GRANT_V2_COMPACT_BYTES,
    MAX_ROUTE_GRANT_V2_TTL_SECONDS,
};
use cats_api::runtime_reconciliation::{Hostname, Id, NodeTransportTarget};
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

/// SHA-256 of the opaque Grant bytes returned by authenticated Control.
///
/// This digest supports exact compare-and-delete after a typed Node rejection.
/// It does not authenticate the Grant; only the Node verifies the Grant's
/// signature and claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantDigest([u8; 32]);

impl GrantDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn for_opaque_grant(grant: &[u8]) -> Self {
        Self(Sha256::digest(grant).into())
    }
}

/// Typed positive result supplied by a future machine-authenticated Control
/// resolve adapter.
///
/// This is deliberately an in-process port type, not an HTTP/JSON wire. The
/// adapter must authenticate Control before constructing it and must supply
/// the exact bounded encoded response-body size. Endpoint and target parsing
/// happen at that transport boundary. The Grant remains opaque bytes here.
#[derive(Clone)]
pub struct AuthenticatedResolveEnvelope {
    endpoint_id: Id,
    node_transport_target: NodeTransportTarget,
    expires_at_unix_seconds: u64,
    opaque_grant: Vec<u8>,
    grant_digest: GrantDigest,
    response_bytes: usize,
}

impl AuthenticatedResolveEnvelope {
    pub fn from_authenticated_transport(
        endpoint_id: Id,
        node_transport_target: NodeTransportTarget,
        expires_at_unix_seconds: u64,
        opaque_grant: Vec<u8>,
        grant_digest: GrantDigest,
        response_bytes: usize,
    ) -> Self {
        Self {
            endpoint_id,
            node_transport_target,
            expires_at_unix_seconds,
            opaque_grant,
            grant_digest,
            response_bytes,
        }
    }

    /// Validate only the authenticated envelope and cache boundaries.
    ///
    /// This function intentionally never parses the compact Grant, selects a
    /// `kid`, verifies a signature, or decodes claims. Those are exclusively
    /// Node admission responsibilities under ADR-0041.
    pub fn validate_for_hostname(
        self,
        hostname: &Hostname,
        now_unix_seconds: u64,
        now: Instant,
    ) -> Result<ResolvedRoute, ResolveEnvelopeError> {
        if self.opaque_grant.is_empty() {
            return Err(ResolveEnvelopeError::EmptyOpaqueGrant);
        }
        if self.opaque_grant.len() > MAX_ROUTE_GRANT_V2_COMPACT_BYTES {
            return Err(ResolveEnvelopeError::OpaqueGrantTooLarge);
        }
        if self.response_bytes < self.opaque_grant.len() {
            return Err(ResolveEnvelopeError::InvalidResponseSize);
        }
        if GrantDigest::for_opaque_grant(&self.opaque_grant) != self.grant_digest {
            return Err(ResolveEnvelopeError::GrantDigestMismatch);
        }
        if now_unix_seconds > i64::MAX as u64 {
            return Err(ResolveEnvelopeError::InvalidClock);
        }
        let remaining_seconds = self
            .expires_at_unix_seconds
            .checked_sub(now_unix_seconds)
            .filter(|remaining| *remaining > 0)
            .ok_or(ResolveEnvelopeError::Expired)?;
        let maximum_remaining_seconds = MAX_ROUTE_GRANT_V2_TTL_SECONDS
            .checked_add(MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS)
            .ok_or(ResolveEnvelopeError::DeadlineOverflow)?;
        if remaining_seconds > maximum_remaining_seconds {
            return Err(ResolveEnvelopeError::ExpiryTooFar);
        }
        let expires_at = now
            .checked_add(Duration::from_secs(remaining_seconds))
            .ok_or(ResolveEnvelopeError::DeadlineOverflow)?;

        Ok(ResolvedRoute {
            hostname: hostname.clone(),
            endpoint_id: self.endpoint_id,
            node_transport_target: self.node_transport_target,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            opaque_grant: Arc::from(self.opaque_grant),
            grant_digest: self.grant_digest,
            expires_at,
            response_bytes: self.response_bytes,
        })
    }
}

impl std::fmt::Debug for AuthenticatedResolveEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedResolveEnvelope")
            .field("endpoint_id", &self.endpoint_id)
            .field("node_transport_target", &self.node_transport_target)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("opaque_grant", &"[redacted]")
            .field("grant_digest", &self.grant_digest)
            .field("response_bytes", &self.response_bytes)
            .finish()
    }
}

/// Cacheable route validated from authenticated Control envelope fields.
///
/// The name deliberately does not imply that the opaque Grant itself has been
/// verified. Node admission remains the sole signature/claims verifier and
/// final gate/guard authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedRoute {
    hostname: Hostname,
    endpoint_id: Id,
    node_transport_target: NodeTransportTarget,
    expires_at_unix_seconds: u64,
    opaque_grant: Arc<[u8]>,
    grant_digest: GrantDigest,
    expires_at: Instant,
    response_bytes: usize,
}

impl ResolvedRoute {
    pub fn hostname(&self) -> &Hostname {
        &self.hostname
    }

    pub fn endpoint_id(&self) -> &Id {
        &self.endpoint_id
    }

    pub fn node_transport_target(&self) -> &NodeTransportTarget {
        &self.node_transport_target
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub fn opaque_grant(&self) -> &[u8] {
        &self.opaque_grant
    }

    pub const fn grant_digest(&self) -> GrantDigest {
        self.grant_digest
    }

    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub(crate) const fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

impl std::fmt::Debug for ResolvedRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedRoute")
            .field("hostname", &self.hostname)
            .field("endpoint_id", &self.endpoint_id)
            .field("node_transport_target", &self.node_transport_target)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("opaque_grant", &"[redacted]")
            .field("grant_digest", &self.grant_digest)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveEnvelopeError {
    EmptyOpaqueGrant,
    OpaqueGrantTooLarge,
    GrantDigestMismatch,
    InvalidResponseSize,
    InvalidClock,
    Expired,
    ExpiryTooFar,
    DeadlineOverflow,
}

impl std::fmt::Display for ResolveEnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOpaqueGrant => formatter.write_str("Route Grant is empty"),
            Self::OpaqueGrantTooLarge => {
                formatter.write_str("opaque Route Grant exceeds its byte limit")
            }
            Self::GrantDigestMismatch => {
                formatter.write_str("Route Grant digest does not match its opaque bytes")
            }
            Self::InvalidResponseSize => {
                formatter.write_str("Route resolve response size is inconsistent")
            }
            Self::InvalidClock => formatter.write_str("Gateway clock is outside the wire range"),
            Self::Expired => formatter.write_str("Route resolve response is expired"),
            Self::ExpiryTooFar => {
                formatter.write_str("Route resolve expiry exceeds the Grant lifetime bound")
            }
            Self::DeadlineOverflow => formatter.write_str("Route resolve deadline overflow"),
        }
    }
}

impl std::error::Error for ResolveEnvelopeError {}

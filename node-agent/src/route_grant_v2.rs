//! Node-only Route Grant v2 verification and pre-I/O admission core.
//!
//! The machine listener supplies an unforgeable in-process Gateway transport
//! proof. This module first verifies the complete signed request binding and
//! returns a non-wire-constructible claims/time proof. Only that proof's Cat
//! identity may select the live [`AdmissionCell`], where admission and guard
//! acquisition are then atomic.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use cats_api::route_grant_v2::{
    RouteAdmissionV2Failure, RouteAdmissionV2Reason, RouteGrantV2Compact, RouteGrantV2Error,
    RouteGrantV2PublicKey, RouteGrantV2PublicKeyRingArtifact, MAX_ROUTE_GRANT_V2_RING_KEYS,
    ROUTE_GRANT_V2_VERSION,
};
use cats_api::runtime_reconciliation::{
    key_ring_digest, Epoch, Hostname, HttpProtocol, Id, Ipv4Address, KeyId, Sha256Digest,
};
use thiserror::Error;

use crate::runtime::reconciliation::{AdmissionCell, RouteAdmissionGuard};

#[derive(Clone)]
pub struct RouteGrantV2KeyRing {
    version: Epoch,
    keys: BTreeMap<KeyId, RouteGrantV2PublicKey>,
    loaded_kids: Vec<KeyId>,
    digest: Sha256Digest,
}

impl std::fmt::Debug for RouteGrantV2KeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteGrantV2KeyRing")
            .field("version", &self.version)
            .field("loaded_kids", &self.loaded_kids)
            .field("digest", &self.digest)
            .finish()
    }
}

impl RouteGrantV2KeyRing {
    /// Convert one already pinned and decoded installation artifact into the
    /// complete in-process replacement. Publication remains the caller's
    /// separate atomic step; no filesystem scan or listener is composed here.
    pub fn from_artifact(
        artifact: &RouteGrantV2PublicKeyRingArtifact,
    ) -> Result<Self, RouteGrantV2KeyRingError> {
        artifact
            .validate()
            .map_err(|_| RouteGrantV2KeyRingError::InvalidArtifact)?;
        let ring = Self::new(
            artifact.ring_version,
            artifact
                .public_keys()
                .map_err(|_| RouteGrantV2KeyRingError::InvalidArtifact)?,
        )?;
        if ring.digest()
            != &artifact
                .digest()
                .map_err(|_| RouteGrantV2KeyRingError::InvalidArtifact)?
        {
            return Err(RouteGrantV2KeyRingError::InvalidArtifact);
        }
        Ok(ring)
    }

    /// Builds a complete replacement before it can be published. Empty is a
    /// valid loaded ring but admits no Grant; duplicate or oversized input is
    /// rejected without changing the verifier's current snapshot.
    pub fn new(
        version: Epoch,
        public_keys: Vec<RouteGrantV2PublicKey>,
    ) -> Result<Self, RouteGrantV2KeyRingError> {
        if public_keys.len() > MAX_ROUTE_GRANT_V2_RING_KEYS {
            return Err(RouteGrantV2KeyRingError::TooManyKeys);
        }
        let mut keys = BTreeMap::new();
        for key in public_keys {
            let kid = key.kid().clone();
            if keys.insert(kid.clone(), key).is_some() {
                return Err(RouteGrantV2KeyRingError::DuplicateKey { kid });
            }
        }
        let loaded_kids = keys.keys().cloned().collect::<Vec<_>>();
        let digest = key_ring_digest(version, &loaded_kids)
            .map_err(|_| RouteGrantV2KeyRingError::InvalidKeySet)?;
        Ok(Self {
            version,
            keys,
            loaded_kids,
            digest,
        })
    }

    pub fn version(&self) -> Epoch {
        self.version
    }

    pub fn loaded_kids(&self) -> &[KeyId] {
        &self.loaded_kids
    }

    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    fn key(&self, kid: &KeyId) -> Option<&RouteGrantV2PublicKey> {
        self.keys.get(kid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteGrantV2KeyRingError {
    #[error("Route Grant v2 installed key-ring artifact is invalid")]
    InvalidArtifact,
    #[error("Route Grant v2 key ring exceeds its key bound")]
    TooManyKeys,
    #[error("Route Grant v2 key ring repeats kid {kid}")]
    DuplicateKey { kid: KeyId },
    #[error("Route Grant v2 key ring has an invalid ordered key set")]
    InvalidKeySet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteGrantV2RingInstallOutcome {
    Installed,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteGrantV2RingInstallError {
    #[error("Route Grant v2 key ring is unavailable")]
    Unavailable,
    #[error("Route Grant v2 key ring version moved backwards")]
    StaleVersion,
    #[error("Route Grant v2 key ring version was reused for another key set")]
    VersionConflict,
    #[error("Route Grant v2 key ring does not name the exact current predecessor")]
    LineageMismatch,
}

/// Proof supplied only by the future trusted Node machine-transport adapter.
/// No HTTP header or external crate can construct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGatewayPrincipal {
    public_key_spki_sha256: Sha256Digest,
}

impl AuthenticatedGatewayPrincipal {
    pub(crate) fn from_verified_spki_sha256(public_key_spki_sha256: Sha256Digest) -> Self {
        Self {
            public_key_spki_sha256,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::from_verified_spki_sha256(Sha256Digest::from_bytes([0_u8; 32]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdmissionV2RequestBinding {
    pub local_node_id: Id,
    pub cat_id: Id,
    pub endpoint_id: Id,
    pub canonical_hostname: Hostname,
    pub protocol: HttpProtocol,
}

/// Signed claims and time evidence for one exact machine request.
///
/// All fields are private so neither the tunnel frame nor another crate can
/// manufacture the proof used for registry selection or admission. The only
/// constructor is [`RouteGrantV2Verifier::verify_request`].
#[derive(Debug)]
pub(crate) struct VerifiedRouteV2Request {
    claims: cats_api::route_grant_v2::RouteGrantV2Claims,
    time_verdict: cats_api::route_grant_v2::RouteGrantV2TimeVerdict,
}

impl VerifiedRouteV2Request {
    pub(crate) fn cat_id(&self) -> &Id {
        &self.claims.cat_id
    }

    /// Atomically compares the verified claims with one exact cell and
    /// acquires its Endpoint guard. No I/O is performed in this operation.
    pub(crate) fn admit(
        self,
        admission_cell: &Arc<AdmissionCell>,
    ) -> Result<AdmittedRouteV2, RouteAdmissionV2Failure> {
        let (guard, guest_ipv4) = admission_cell
            .acquire_verified_route(&self.claims, self.time_verdict)
            .map_err(pre_admission)?;
        Ok(AdmittedRouteV2 {
            claims: self.claims,
            guard,
            guest_ipv4,
        })
    }
}

#[derive(Debug)]
pub struct AdmittedRouteV2 {
    claims: cats_api::route_grant_v2::RouteGrantV2Claims,
    guard: RouteAdmissionGuard,
    guest_ipv4: Ipv4Address,
}

impl AdmittedRouteV2 {
    pub fn claims(&self) -> &cats_api::route_grant_v2::RouteGrantV2Claims {
        &self.claims
    }

    pub fn guard(&self) -> &RouteAdmissionGuard {
        &self.guard
    }

    pub fn guest_ipv4(&self) -> &Ipv4Address {
        &self.guest_ipv4
    }

    pub(crate) async fn cancelled(&mut self) {
        self.guard.cancelled().await;
    }

    pub fn into_parts(
        self,
    ) -> (
        cats_api::route_grant_v2::RouteGrantV2Claims,
        RouteAdmissionGuard,
        Ipv4Address,
    ) {
        (self.claims, self.guard, self.guest_ipv4)
    }
}

/// Atomically swappable verifier. A request snapshots one complete ring;
/// rotation never exposes a partial key set and never falls back to another
/// key when the exact protected-header `kid` fails verification.
pub struct RouteGrantV2Verifier {
    ring: RwLock<Arc<RouteGrantV2KeyRing>>,
}

impl std::fmt::Debug for RouteGrantV2Verifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("RouteGrantV2Verifier");
        match self.ring.read() {
            Ok(ring) => debug.field("ring", &ring),
            Err(_) => debug.field("ring", &"unavailable"),
        };
        debug.finish()
    }
}

impl RouteGrantV2Verifier {
    pub fn new(initial_ring: RouteGrantV2KeyRing) -> Self {
        Self {
            ring: RwLock::new(Arc::new(initial_ring)),
        }
    }

    pub fn current_ring(&self) -> Result<Arc<RouteGrantV2KeyRing>, RouteGrantV2RingInstallError> {
        self.ring
            .read()
            .map(|ring| Arc::clone(&ring))
            .map_err(|_| RouteGrantV2RingInstallError::Unavailable)
    }

    pub(crate) fn replace_ring(
        &self,
        replacement: RouteGrantV2KeyRing,
    ) -> Result<RouteGrantV2RingInstallOutcome, RouteGrantV2RingInstallError> {
        let mut current = self
            .ring
            .write()
            .map_err(|_| RouteGrantV2RingInstallError::Unavailable)?;
        if replacement.version() < current.version() {
            return Err(RouteGrantV2RingInstallError::StaleVersion);
        }
        if replacement.version() == current.version() {
            return if replacement.loaded_kids() == current.loaded_kids() {
                Ok(RouteGrantV2RingInstallOutcome::Replay)
            } else {
                Err(RouteGrantV2RingInstallError::VersionConflict)
            };
        }
        *current = Arc::new(replacement);
        Ok(RouteGrantV2RingInstallOutcome::Installed)
    }

    /// Publish one decoded artifact only when it is an exact successor of the
    /// complete in-process ring. The filesystem installer invokes this only
    /// after the same artifact is durable at the fixed path.
    pub(crate) fn replace_artifact(
        &self,
        artifact: &RouteGrantV2PublicKeyRingArtifact,
    ) -> Result<RouteGrantV2RingInstallOutcome, RouteGrantV2RingInstallError> {
        let replacement = RouteGrantV2KeyRing::from_artifact(artifact)
            .map_err(|_| RouteGrantV2RingInstallError::VersionConflict)?;
        let mut current = self
            .ring
            .write()
            .map_err(|_| RouteGrantV2RingInstallError::Unavailable)?;
        if replacement.version() < current.version() {
            return Err(RouteGrantV2RingInstallError::StaleVersion);
        }
        if replacement.version() == current.version() {
            return if replacement.digest() == current.digest()
                && replacement.loaded_kids() == current.loaded_kids()
            {
                Ok(RouteGrantV2RingInstallOutcome::Replay)
            } else {
                Err(RouteGrantV2RingInstallError::VersionConflict)
            };
        }
        let Some(previous) = artifact.expected_previous.as_ref() else {
            return Err(RouteGrantV2RingInstallError::LineageMismatch);
        };
        if current.version().get().checked_add(1) != Some(replacement.version().get())
            || previous.ring_version != current.version()
            || &previous.key_ring_digest != current.digest()
        {
            return Err(RouteGrantV2RingInstallError::LineageMismatch);
        }
        *current = Arc::new(replacement);
        Ok(RouteGrantV2RingInstallOutcome::Installed)
    }

    /// Verifies the cryptographic token and its complete machine-request
    /// binding before any per-Cat registry lookup is allowed.
    pub(crate) fn verify_request(
        &self,
        principal: &AuthenticatedGatewayPrincipal,
        opaque_grant: &str,
        request: &RouteAdmissionV2RequestBinding,
        now_unix_seconds: u64,
    ) -> Result<VerifiedRouteV2Request, RouteAdmissionV2Failure> {
        let compact = RouteGrantV2Compact::parse(opaque_grant)
            .map_err(|error| pre_admission(map_unverified_error(error)))?;
        let ring = self
            .current_ring()
            .map_err(|_| pre_admission(RouteAdmissionV2Reason::UnknownKey))?;
        let key = ring
            .key(&compact.header().kid)
            .ok_or_else(|| pre_admission(RouteAdmissionV2Reason::UnknownKey))?;
        let verified = key
            .verify(&compact)
            .map_err(|error| pre_admission(map_verification_error(error)))?;
        let claims = verified
            .claims()
            .map_err(|_| pre_admission(RouteAdmissionV2Reason::InvalidClaims))?;
        if claims.gateway_public_key_spki_sha256 != principal.public_key_spki_sha256 {
            return Err(pre_admission(RouteAdmissionV2Reason::BindingMismatch));
        }
        let time_verdict = claims
            .time_verdict(now_unix_seconds)
            .map_err(|_| pre_admission(RouteAdmissionV2Reason::InvalidClaims))?;
        if claims.node_id != request.local_node_id
            || claims.cat_id != request.cat_id
            || claims.endpoint_id != request.endpoint_id
            || claims.hostname != request.canonical_hostname
            || claims.protocol != request.protocol
        {
            return Err(pre_admission(RouteAdmissionV2Reason::BindingMismatch));
        }
        Ok(VerifiedRouteV2Request {
            claims,
            time_verdict,
        })
    }

    #[cfg(test)]
    fn verify_and_admit(
        &self,
        principal: &AuthenticatedGatewayPrincipal,
        opaque_grant: &str,
        request: &RouteAdmissionV2RequestBinding,
        now_unix_seconds: u64,
        admission_cell: &Arc<AdmissionCell>,
    ) -> Result<AdmittedRouteV2, RouteAdmissionV2Failure> {
        self.verify_request(principal, opaque_grant, request, now_unix_seconds)?
            .admit(admission_cell)
    }
}

fn map_unverified_error(error: RouteGrantV2Error) -> RouteAdmissionV2Reason {
    match error {
        RouteGrantV2Error::UnknownKey => RouteAdmissionV2Reason::UnknownKey,
        RouteGrantV2Error::InvalidSignature => RouteAdmissionV2Reason::InvalidSignature,
        RouteGrantV2Error::InvalidCompact
        | RouteGrantV2Error::InvalidHeader
        | RouteGrantV2Error::InvalidClaims
        | RouteGrantV2Error::InvalidPublicKey => RouteAdmissionV2Reason::InvalidClaims,
    }
}

fn map_verification_error(error: RouteGrantV2Error) -> RouteAdmissionV2Reason {
    match error {
        RouteGrantV2Error::UnknownKey => RouteAdmissionV2Reason::UnknownKey,
        RouteGrantV2Error::InvalidSignature => RouteAdmissionV2Reason::InvalidSignature,
        _ => RouteAdmissionV2Reason::InvalidClaims,
    }
}

fn pre_admission(reason: RouteAdmissionV2Reason) -> RouteAdmissionV2Failure {
    RouteAdmissionV2Failure {
        version: ROUTE_GRANT_V2_VERSION,
        guard_acquired: false,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use cats_api::route_grant_v2::{
        decode_route_grant_v2_public_key_ring, RouteGrantV2Claims, RouteGrantV2ProtectedHeader,
        RouteGrantV2SigningInput, ROUTE_GRANT_V2_AUDIENCE, ROUTE_GRANT_V2_ISSUER,
    };
    use cats_api::runtime_reconciliation::{
        AssignedKind, AssignedPlacement, CheckpointRouteGate, Ipv4Address, LifecycleAdmission,
        RandomId128, Revision, RouteGateBinding, RouteGateState,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;
    use crate::runtime::reconciliation::{
        AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult,
    };

    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    const INSTALLED_RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#;

    #[test]
    fn installed_artifact_converts_to_one_exact_bounded_ring() {
        let artifact = decode_route_grant_v2_public_key_ring(INSTALLED_RING).unwrap();
        let ring = RouteGrantV2KeyRing::from_artifact(&artifact).unwrap();
        assert_eq!(ring.version(), artifact.ring_version);
        assert_eq!(ring.digest(), &artifact.digest().unwrap());
        assert_eq!(ring.loaded_kids(), &[artifact.keys[0].kid.clone()]);

        let mut invalid = artifact;
        invalid.keys[0].kid = KeyId::new("0".repeat(64)).unwrap();
        assert!(matches!(
            RouteGrantV2KeyRing::from_artifact(&invalid),
            Err(RouteGrantV2KeyRingError::InvalidArtifact)
        ));
    }

    fn generated_key() -> (RouteGrantV2PublicKey, Ed25519KeyPair) {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        (RouteGrantV2PublicKey::from_spki_der(&spki).unwrap(), pair)
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

    fn sign(
        key: &Ed25519KeyPair,
        public: &RouteGrantV2PublicKey,
        claims: &RouteGrantV2Claims,
    ) -> String {
        let input = RouteGrantV2SigningInput::new(
            &RouteGrantV2ProtectedHeader::new(public.kid().clone()),
            claims,
        )
        .unwrap();
        let signature: [u8; 64] = key.sign(input.as_bytes()).as_ref().try_into().unwrap();
        input.finish(&signature).unwrap()
    }

    fn request(claims: &RouteGrantV2Claims) -> RouteAdmissionV2RequestBinding {
        RouteAdmissionV2RequestBinding {
            local_node_id: claims.node_id.clone(),
            cat_id: claims.cat_id.clone(),
            endpoint_id: claims.endpoint_id.clone(),
            canonical_hostname: claims.hostname.clone(),
            protocol: claims.protocol,
        }
    }

    fn snapshot(
        claims: &RouteGrantV2Claims,
        gate: RouteGateState,
        lifecycle: LifecycleAdmission,
    ) -> AdmissionSnapshot {
        snapshot_many(std::slice::from_ref(claims), gate, lifecycle)
    }

    fn snapshot_many(
        claims: &[RouteGrantV2Claims],
        gate: RouteGateState,
        lifecycle: LifecycleAdmission,
    ) -> AdmissionSnapshot {
        let first = claims.first().unwrap();
        with_guest_target(AdmissionSnapshot::new(
            Revision::new(11).unwrap(),
            Sha256Digest::from_bytes([0x11; 32]),
            AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: first.node_id.clone(),
                placement_epoch: Epoch::new(3).unwrap(),
            },
            Some(first.runtime_incarnation.clone()),
            lifecycle,
            claims
                .iter()
                .map(|claims| CheckpointRouteGate {
                    binding: RouteGateBinding {
                        workspace_id: claims.workspace_id.clone(),
                        endpoint_id: claims.endpoint_id.clone(),
                        hostname: claims.hostname.clone(),
                        cat_id: claims.cat_id.clone(),
                        node_id: claims.node_id.clone(),
                        runtime_incarnation: claims.runtime_incarnation.clone(),
                        route_epoch: claims.route_epoch,
                        protocol: claims.protocol,
                        target_port: claims.target_port,
                    },
                    gate,
                })
                .collect(),
        ))
    }

    fn with_guest_target(snapshot: AdmissionSnapshot) -> AdmissionSnapshot {
        with_guest_target_at(snapshot, "10.240.0.6")
    }

    fn with_guest_target_at(snapshot: AdmissionSnapshot, address: &str) -> AdmissionSnapshot {
        snapshot.with_guest_ipv4(Ipv4Address::new(address).unwrap())
    }

    fn reason(error: RouteAdmissionV2Failure) -> RouteAdmissionV2Reason {
        assert!(!error.guard_acquired);
        error.reason
    }

    #[test]
    fn exact_kid_rotation_is_atomic_bounded_and_has_no_fallback() {
        let (old_public, old_private) = generated_key();
        let (new_public, new_private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![old_public.clone()]).unwrap(),
        );
        let claims = claims();
        let cell = AdmissionCell::new(snapshot(
            &claims,
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let old = sign(&old_private, &old_public, &claims);
        let new = sign(&new_private, &new_public, &claims);
        drop(
            verifier
                .verify_and_admit(&principal, &old, &request(&claims), claims.nbf, &cell)
                .unwrap(),
        );

        assert_eq!(
            verifier
                .replace_ring(
                    RouteGrantV2KeyRing::new(
                        Epoch::new(2).unwrap(),
                        vec![new_public.clone(), old_public.clone()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            RouteGrantV2RingInstallOutcome::Installed
        );
        for token in [&old, &new] {
            drop(
                verifier
                    .verify_and_admit(&principal, token, &request(&claims), claims.nbf, &cell)
                    .unwrap(),
            );
        }

        verifier
            .replace_ring(
                RouteGrantV2KeyRing::new(Epoch::new(3).unwrap(), vec![new_public.clone()]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(&principal, &old, &request(&claims), claims.nbf, &cell)
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::UnknownKey
        );
        drop(
            verifier
                .verify_and_admit(&principal, &new, &request(&claims), claims.nbf, &cell)
                .unwrap(),
        );

        assert_eq!(
            verifier
                .replace_ring(
                    RouteGrantV2KeyRing::new(Epoch::new(3).unwrap(), vec![old_public.clone()])
                        .unwrap()
                )
                .unwrap_err(),
            RouteGrantV2RingInstallError::VersionConflict
        );
        assert_eq!(
            verifier.current_ring().unwrap().loaded_kids(),
            &[new_public.kid().clone()]
        );

        let too_many = (0..=MAX_ROUTE_GRANT_V2_RING_KEYS)
            .map(|_| generated_key().0)
            .collect();
        assert_eq!(
            RouteGrantV2KeyRing::new(Epoch::new(4).unwrap(), too_many).unwrap_err(),
            RouteGrantV2KeyRingError::TooManyKeys
        );
    }

    #[test]
    fn binding_and_gate_precede_expiry_and_backend_work() {
        let (public, private) = generated_key();
        let (_, wrong_private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![public.clone()]).unwrap(),
        );
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let claims = claims();
        let token = sign(&private, &public, &claims);
        let invalid_signature = sign(&wrong_private, &public, &claims);

        let mut wrong_target_claims = claims.clone();
        wrong_target_claims.target_port = 8081;
        let wrong_target_cell = AdmissionCell::new(snapshot(
            &wrong_target_claims,
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(
                        &principal,
                        &token,
                        &request(&claims),
                        claims.exp + 100,
                        &wrong_target_cell,
                    )
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::BindingMismatch
        );

        let closed = AdmissionCell::new(snapshot(
            &claims,
            RouteGateState::Closed,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(
                        &principal,
                        &token,
                        &request(&claims),
                        claims.exp + 100,
                        &closed,
                    )
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::GateClosed
        );

        let active = AdmissionCell::new(snapshot(
            &claims,
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(
                        &principal,
                        &invalid_signature,
                        &request(&claims),
                        claims.nbf,
                        &active,
                    )
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::InvalidSignature
        );
        let mut wrong_hostname = request(&claims);
        wrong_hostname.canonical_hostname = Hostname::new("wrong.cats.run").unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(&principal, &token, &wrong_hostname, claims.nbf, &active,)
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::BindingMismatch
        );
        let mut wrong_cat_request = request(&claims);
        wrong_cat_request.cat_id = Id::new("cat_02").unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_request(&principal, &token, &wrong_cat_request, claims.nbf)
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::BindingMismatch
        );
        let mut wrong_cat_claims = claims.clone();
        wrong_cat_claims.cat_id = Id::new("cat_02").unwrap();
        let wrong_cat_cell = AdmissionCell::new(snapshot(
            &wrong_cat_claims,
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(
                        &principal,
                        &token,
                        &request(&claims),
                        claims.nbf,
                        &wrong_cat_cell,
                    )
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::BindingMismatch
        );
        let backend_called = AtomicBool::new(false);
        let result = verifier.verify_and_admit(
            &principal,
            &token,
            &request(&claims),
            claims.exp + 100,
            &active,
        );
        if result.is_ok() {
            backend_called.store(true, Ordering::SeqCst);
        }
        assert_eq!(reason(result.unwrap_err()), RouteAdmissionV2Reason::Expired);
        assert!(!backend_called.load(Ordering::SeqCst));
        assert_eq!(active.active_guards(&claims.endpoint_id), Some(0));

        let mut incoherent = snapshot(&claims, RouteGateState::Active, LifecycleAdmission::Open);
        let wrong_placement = AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: Id::new("node-b").unwrap(),
            placement_epoch: Epoch::new(3).unwrap(),
        };
        incoherent = with_guest_target(AdmissionSnapshot::new(
            incoherent.applied_desired_revision(),
            incoherent.spec_digest().clone(),
            wrong_placement,
            incoherent.runtime_incarnation().cloned(),
            incoherent.lifecycle_admission(),
            incoherent.endpoints().to_vec(),
        ));
        assert!(matches!(
            AdmissionCell::new(incoherent),
            Err(crate::runtime::reconciliation::AdmissionCellBuildError::WrongPlacement { .. })
        ));
    }

    #[tokio::test]
    async fn guard_releases_on_drop_panic_and_task_cancellation() {
        let (public, private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![public.clone()]).unwrap(),
        );
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let claims = claims();
        let token = sign(&private, &public, &claims);
        let cell = AdmissionCell::new(snapshot(
            &claims,
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();

        let admitted = verifier
            .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell)
            .unwrap();
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(1));
        drop(admitted);
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(0));

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _admitted = verifier
                .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell)
                .unwrap();
            panic!("simulated proxy panic");
        }));
        assert!(panic_result.is_err());
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(0));

        let admitted = verifier
            .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell)
            .unwrap();
        let task = tokio::spawn(async move {
            let _admitted = admitted;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(1));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(0));
    }

    #[test]
    fn require_idle_busy_is_non_mutating_then_closes_at_zero_guards() {
        let (public, private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![public.clone()]).unwrap(),
        );
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let claims = claims();
        let token = sign(&private, &public, &claims);
        let cell = AdmissionCell::new(snapshot(
            &claims,
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        let route_guard = verifier
            .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell)
            .unwrap();
        let platform_guard = cell.try_acquire_platform().unwrap();
        let expected = cell.snapshot();
        let mut closed_routes = expected.endpoints().to_vec();
        for route in &mut closed_routes {
            route.gate = RouteGateState::Closed;
        }
        let replacement = with_guest_target(AdmissionSnapshot::new(
            Revision::new(12).unwrap(),
            Sha256Digest::from_bytes([0x12; 32]),
            expected.placement().clone(),
            expected.runtime_incarnation().cloned(),
            LifecycleAdmission::Closed,
            closed_routes,
        ));
        let mut port = cell.port();
        assert_eq!(
            port.try_close_all_if_idle(&expected, &replacement).unwrap(),
            IdleCloseResult::Busy {
                platform_guards: 1,
                endpoint_guards: vec![cats_api::runtime_reconciliation::EndpointGuardCount {
                    endpoint_id: claims.endpoint_id.clone(),
                    active_guards: 1,
                }],
            }
        );
        assert_eq!(cell.snapshot(), expected);
        drop(route_guard);
        drop(platform_guard);
        assert_eq!(
            port.try_close_all_if_idle(&expected, &replacement).unwrap(),
            IdleCloseResult::Closed
        );
        assert_eq!(cell.snapshot(), replacement);
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell,)
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::GateClosed
        );
    }

    #[test]
    fn close_and_admission_share_one_linearization_point() {
        let (public, private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![public.clone()]).unwrap(),
        );
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let claims = claims();
        let mut claims_b = claims.clone();
        claims_b.endpoint_id = Id::new("ep_02").unwrap();
        claims_b.hostname = Hostname::new("other.cats.run").unwrap();
        claims_b.route_epoch = Epoch::new(9).unwrap();
        claims_b.target_port = 8081;
        let token = sign(&private, &public, &claims);
        let token_b = sign(&private, &public, &claims_b);
        let cell = AdmissionCell::new(snapshot_many(
            &[claims.clone(), claims_b.clone()],
            RouteGateState::Active,
            LifecycleAdmission::Open,
        ))
        .unwrap();
        let admitted = verifier
            .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell)
            .unwrap();
        let expected = cell.snapshot();
        let stale_expected = with_guest_target(AdmissionSnapshot::new(
            Revision::new(10).unwrap(),
            Sha256Digest::from_bytes([0x10; 32]),
            expected.placement().clone(),
            expected.runtime_incarnation().cloned(),
            expected.lifecycle_admission(),
            expected.endpoints().to_vec(),
        ));
        let mut stale_routes = stale_expected.endpoints().to_vec();
        stale_routes[0].gate = RouteGateState::Closed;
        let stale_replacement = with_guest_target(AdmissionSnapshot::new(
            stale_expected.applied_desired_revision(),
            stale_expected.spec_digest().clone(),
            stale_expected.placement().clone(),
            stale_expected.runtime_incarnation().cloned(),
            stale_expected.lifecycle_admission(),
            stale_routes,
        ));
        let mut port = cell.port();
        assert_eq!(
            port.close_gate(&stale_expected, &stale_replacement, &claims.endpoint_id),
            Err(crate::runtime::reconciliation::GatePortError::StateMismatch)
        );
        assert_eq!(cell.snapshot(), expected);
        let mut routes = expected.endpoints().to_vec();
        routes[0].gate = RouteGateState::Closed;
        let replacement = with_guest_target(AdmissionSnapshot::new(
            expected.applied_desired_revision(),
            expected.spec_digest().clone(),
            expected.placement().clone(),
            expected.runtime_incarnation().cloned(),
            expected.lifecycle_admission(),
            routes,
        ));
        port.close_gate(&expected, &replacement, &claims.endpoint_id)
            .unwrap();
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(1));
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(&principal, &token, &request(&claims), claims.nbf, &cell,)
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::GateClosed
        );
        let admitted_b = verifier
            .verify_and_admit(
                &principal,
                &token_b,
                &request(&claims_b),
                claims_b.nbf,
                &cell,
            )
            .unwrap();
        assert_eq!(cell.active_guards(&claims_b.endpoint_id), Some(1));
        drop(admitted);
        drop(admitted_b);
        assert_eq!(cell.active_guards(&claims.endpoint_id), Some(0));
        assert_eq!(cell.active_guards(&claims_b.endpoint_id), Some(0));
    }

    #[test]
    fn same_incarnation_transitions_reject_guest_ipv4_only_drift() {
        #[derive(Debug, Clone, Copy)]
        enum Transition {
            Open,
            Install,
            Close,
            Remove,
            CloseAll,
            TryClose,
            TryCloseBusy,
        }

        let a = claims();
        let mut b = a.clone();
        b.endpoint_id = Id::new("ep_02").unwrap();
        b.hostname = Hostname::new("other.cats.run").unwrap();
        b.route_epoch = Epoch::new(9).unwrap();
        b.target_port = 8081;

        for transition in [
            Transition::Open,
            Transition::Install,
            Transition::Close,
            Transition::Remove,
            Transition::CloseAll,
            Transition::TryClose,
            Transition::TryCloseBusy,
        ] {
            let (expected, replacement, endpoint_id) = match transition {
                Transition::Open => {
                    let expected = with_guest_target(AdmissionSnapshot::new(
                        Revision::new(11).unwrap(),
                        Sha256Digest::from_bytes([0x11; 32]),
                        AssignedPlacement {
                            kind: AssignedKind::Assigned,
                            node_id: a.node_id.clone(),
                            placement_epoch: Epoch::new(3).unwrap(),
                        },
                        Some(a.runtime_incarnation.clone()),
                        LifecycleAdmission::Closed,
                        Vec::new(),
                    ));
                    let replacement = with_guest_target_at(
                        AdmissionSnapshot::new(
                            expected.applied_desired_revision(),
                            expected.spec_digest().clone(),
                            expected.placement().clone(),
                            expected.runtime_incarnation().cloned(),
                            LifecycleAdmission::Open,
                            Vec::new(),
                        ),
                        "10.240.0.10",
                    );
                    (expected, replacement, a.endpoint_id.clone())
                }
                Transition::Install => {
                    let expected = snapshot_many(
                        std::slice::from_ref(&b),
                        RouteGateState::Active,
                        LifecycleAdmission::Open,
                    );
                    let replacement = with_guest_target_at(
                        AdmissionSnapshot::new(
                            expected.applied_desired_revision(),
                            expected.spec_digest().clone(),
                            expected.placement().clone(),
                            expected.runtime_incarnation().cloned(),
                            expected.lifecycle_admission(),
                            snapshot_many(
                                &[a.clone(), b.clone()],
                                RouteGateState::Active,
                                LifecycleAdmission::Open,
                            )
                            .endpoints()
                            .to_vec(),
                        ),
                        "10.240.0.10",
                    );
                    (expected, replacement, a.endpoint_id.clone())
                }
                Transition::Close => {
                    let expected = snapshot_many(
                        &[a.clone(), b.clone()],
                        RouteGateState::Active,
                        LifecycleAdmission::Open,
                    );
                    let mut routes = expected.endpoints().to_vec();
                    routes[0].gate = RouteGateState::Closed;
                    let replacement = with_guest_target_at(
                        AdmissionSnapshot::new(
                            expected.applied_desired_revision(),
                            expected.spec_digest().clone(),
                            expected.placement().clone(),
                            expected.runtime_incarnation().cloned(),
                            expected.lifecycle_admission(),
                            routes,
                        ),
                        "10.240.0.10",
                    );
                    (expected, replacement, a.endpoint_id.clone())
                }
                Transition::Remove => {
                    let mut expected = snapshot_many(
                        &[a.clone(), b.clone()],
                        RouteGateState::Active,
                        LifecycleAdmission::Open,
                    );
                    let mut expected_routes = expected.endpoints().to_vec();
                    expected_routes[0].gate = RouteGateState::Closed;
                    expected = with_guest_target(AdmissionSnapshot::new(
                        expected.applied_desired_revision(),
                        expected.spec_digest().clone(),
                        expected.placement().clone(),
                        expected.runtime_incarnation().cloned(),
                        expected.lifecycle_admission(),
                        expected_routes,
                    ));
                    let replacement = with_guest_target_at(
                        AdmissionSnapshot::new(
                            expected.applied_desired_revision(),
                            expected.spec_digest().clone(),
                            expected.placement().clone(),
                            expected.runtime_incarnation().cloned(),
                            expected.lifecycle_admission(),
                            vec![expected.endpoints()[1].clone()],
                        ),
                        "10.240.0.10",
                    );
                    (expected, replacement, a.endpoint_id.clone())
                }
                Transition::CloseAll | Transition::TryClose | Transition::TryCloseBusy => {
                    let expected = snapshot_many(
                        &[a.clone(), b.clone()],
                        RouteGateState::Active,
                        LifecycleAdmission::Open,
                    );
                    let mut routes = expected.endpoints().to_vec();
                    for route in &mut routes {
                        route.gate = RouteGateState::Closed;
                    }
                    let replacement = with_guest_target_at(
                        AdmissionSnapshot::new(
                            Revision::new(12).unwrap(),
                            Sha256Digest::from_bytes([0x12; 32]),
                            expected.placement().clone(),
                            expected.runtime_incarnation().cloned(),
                            LifecycleAdmission::Closed,
                            routes,
                        ),
                        "10.240.0.10",
                    );
                    (expected, replacement, a.endpoint_id.clone())
                }
            };
            let cell = AdmissionCell::new(expected.clone()).unwrap();
            let busy_guard = matches!(transition, Transition::TryCloseBusy)
                .then(|| cell.try_acquire_platform().unwrap());
            let mut port = cell.port();
            let result = match transition {
                Transition::Open => port.open_lifecycle(&expected, &replacement),
                Transition::Install => port.install_gate(&expected, &replacement, &endpoint_id),
                Transition::Close => port.close_gate(&expected, &replacement, &endpoint_id),
                Transition::Remove => {
                    port.remove_closed_gate(&expected, &replacement, &endpoint_id)
                }
                Transition::CloseAll => port.close_all(&expected, &replacement),
                Transition::TryClose | Transition::TryCloseBusy => port
                    .try_close_all_if_idle(&expected, &replacement)
                    .map(|_| ()),
            };
            assert_eq!(
                result,
                Err(GatePortError::Unavailable),
                "{transition:?} accepted an IP-only target change"
            );
            assert_eq!(cell.snapshot(), expected, "{transition:?} mutated the cell");
            drop(busy_guard);
        }
    }

    #[test]
    fn closing_endpoint_a_cannot_retarget_active_endpoint_b() {
        let (public, private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![public.clone()]).unwrap(),
        );
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let a = claims();
        let mut b = a.clone();
        b.endpoint_id = Id::new("ep_02").unwrap();
        b.hostname = Hostname::new("other.cats.run").unwrap();
        b.route_epoch = Epoch::new(9).unwrap();
        b.target_port = 8081;
        let expected = snapshot_many(
            &[a.clone(), b.clone()],
            RouteGateState::Active,
            LifecycleAdmission::Open,
        );
        let cell = AdmissionCell::new(expected.clone()).unwrap();
        let mut routes = expected.endpoints().to_vec();
        routes[0].gate = RouteGateState::Closed;
        let retargeted = with_guest_target_at(
            AdmissionSnapshot::new(
                expected.applied_desired_revision(),
                expected.spec_digest().clone(),
                expected.placement().clone(),
                expected.runtime_incarnation().cloned(),
                expected.lifecycle_admission(),
                routes.clone(),
            ),
            "10.240.0.10",
        );
        let mut port = cell.port();
        assert_eq!(
            port.close_gate(&expected, &retargeted, &a.endpoint_id),
            Err(GatePortError::Unavailable)
        );
        assert_eq!(cell.snapshot(), expected);

        let closed = with_guest_target(AdmissionSnapshot::new(
            expected.applied_desired_revision(),
            expected.spec_digest().clone(),
            expected.placement().clone(),
            expected.runtime_incarnation().cloned(),
            expected.lifecycle_admission(),
            routes,
        ));
        port.close_gate(&expected, &closed, &a.endpoint_id).unwrap();
        let admitted_b = verifier
            .verify_and_admit(
                &principal,
                &sign(&private, &public, &b),
                &request(&b),
                b.nbf,
                &cell,
            )
            .unwrap();
        assert_eq!(
            admitted_b.guest_ipv4(),
            &Ipv4Address::new("10.240.0.6").unwrap()
        );
        assert_eq!(cell.active_guards(&b.endpoint_id), Some(1));
        drop(admitted_b);
    }

    #[test]
    fn higher_epoch_install_and_remove_preserve_unrelated_endpoint_guard() {
        let (public, private) = generated_key();
        let verifier = RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![public.clone()]).unwrap(),
        );
        let principal = AuthenticatedGatewayPrincipal::for_test();
        let old_a = claims();
        let mut b = old_a.clone();
        b.endpoint_id = Id::new("ep_02").unwrap();
        b.hostname = Hostname::new("other.cats.run").unwrap();
        b.route_epoch = Epoch::new(4).unwrap();
        b.target_port = 8081;
        let mut initial = snapshot_many(
            &[old_a.clone(), b.clone()],
            RouteGateState::Active,
            LifecycleAdmission::Open,
        );
        let mut initial_routes = initial.endpoints().to_vec();
        initial_routes[0].gate = RouteGateState::Closed;
        initial = with_guest_target(AdmissionSnapshot::new(
            initial.applied_desired_revision(),
            initial.spec_digest().clone(),
            initial.placement().clone(),
            initial.runtime_incarnation().cloned(),
            initial.lifecycle_admission(),
            initial_routes,
        ));
        let cell = AdmissionCell::new(initial.clone()).unwrap();
        let b_guard = verifier
            .verify_and_admit(
                &principal,
                &sign(&private, &public, &b),
                &request(&b),
                b.nbf,
                &cell,
            )
            .unwrap();

        let mut new_a = old_a.clone();
        new_a.route_epoch = Epoch::new(8).unwrap();
        new_a.target_port = 8082;
        let mut installed_routes = initial.endpoints().to_vec();
        installed_routes[0] = snapshot(&new_a, RouteGateState::Active, LifecycleAdmission::Open)
            .endpoints()[0]
            .clone();
        let installed = with_guest_target(AdmissionSnapshot::new(
            Revision::new(12).unwrap(),
            Sha256Digest::from_bytes([0x12; 32]),
            initial.placement().clone(),
            initial.runtime_incarnation().cloned(),
            initial.lifecycle_admission(),
            installed_routes,
        ));
        let mut port = cell.port();
        port.install_gate(&initial, &installed, &old_a.endpoint_id)
            .unwrap();
        assert_eq!(cell.active_guards(&b.endpoint_id), Some(1));
        assert_eq!(
            reason(
                verifier
                    .verify_and_admit(
                        &principal,
                        &sign(&private, &public, &old_a),
                        &request(&old_a),
                        old_a.nbf,
                        &cell,
                    )
                    .unwrap_err()
            ),
            RouteAdmissionV2Reason::BindingMismatch
        );
        drop(
            verifier
                .verify_and_admit(
                    &principal,
                    &sign(&private, &public, &new_a),
                    &request(&new_a),
                    new_a.nbf,
                    &cell,
                )
                .unwrap(),
        );

        let mut closed_routes = installed.endpoints().to_vec();
        closed_routes[0].gate = RouteGateState::Closed;
        let closed = with_guest_target(AdmissionSnapshot::new(
            installed.applied_desired_revision(),
            installed.spec_digest().clone(),
            installed.placement().clone(),
            installed.runtime_incarnation().cloned(),
            installed.lifecycle_admission(),
            closed_routes,
        ));
        port.close_gate(&installed, &closed, &new_a.endpoint_id)
            .unwrap();
        let absent = with_guest_target(AdmissionSnapshot::new(
            closed.applied_desired_revision(),
            closed.spec_digest().clone(),
            closed.placement().clone(),
            closed.runtime_incarnation().cloned(),
            closed.lifecycle_admission(),
            vec![closed.endpoints()[1].clone()],
        ));
        port.remove_closed_gate(&closed, &absent, &new_a.endpoint_id)
            .unwrap();
        assert_eq!(cell.active_guards(&new_a.endpoint_id), None);
        assert_eq!(cell.active_guards(&b.endpoint_id), Some(1));
        assert_eq!(cell.snapshot(), absent);
        drop(b_guard);
        assert_eq!(cell.active_guards(&b.endpoint_id), Some(0));
    }
}

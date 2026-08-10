//! Control-plane-only Ed25519 signer for Route Grant v2.
//!
//! PostgreSQL authority is loaded separately by
//! [`crate::store::runtime_authority::route_signer`].  This type owns only the
//! active private key and converts one already-closed authority snapshot into
//! the frozen compact token.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::route_grant_v2::{
    RouteGrantV2Claims, RouteGrantV2ProtectedHeader, RouteGrantV2PublicKey,
    RouteGrantV2PublicKeyRingArtifact, RouteGrantV2SignerReference, RouteGrantV2SignerSelection,
    RouteGrantV2SigningInput, MAX_ROUTE_GRANT_V2_TTL_SECONDS, ROUTE_GRANT_V2_AUDIENCE,
    ROUTE_GRANT_V2_ISSUER, ROUTE_GRANT_V2_VERSION,
};
use cats_api::runtime_artifacts::InstalledRouteGrantV2Signer;
use cats_api::runtime_reconciliation::KeyId;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use crate::store::runtime_authority::route_signer::RouteGrantV2AuthoritySnapshot;
use crate::store::runtime_authority::route_signing_authority::RouteGrantV2SignerBinding;

#[derive(Clone)]
pub(crate) struct RouteGrantV2Signer {
    key: Arc<EncodingKey>,
    kid: KeyId,
    ttl_seconds: u64,
}

/// One startup-pinned signer artifact set after the descriptor/ring and, for
/// an active selection, private/public pair have all been validated. The Store
/// accepts only this type for initial PG installation, so descriptor bytes
/// cannot become current before their private pair is proven.
pub(crate) struct InstalledRouteGrantV2SigningAuthority {
    binding: RouteGrantV2SignerBinding,
    signer: Option<RouteGrantV2Signer>,
}

impl std::fmt::Debug for InstalledRouteGrantV2SigningAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledRouteGrantV2SigningAuthority")
            .field("binding", &self.binding)
            .field("signer", &self.signer)
            .finish()
    }
}

impl InstalledRouteGrantV2SigningAuthority {
    pub(crate) fn from_installed_artifacts(
        installed: &InstalledRouteGrantV2Signer,
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        Self::from_authority_artifacts(
            installed.reference(),
            installed.exact_reference_bytes(),
            installed.ring().ring(),
            installed.private_key_pem(),
            ttl_seconds,
        )
    }

    pub(crate) fn from_authority_artifacts(
        reference: &RouteGrantV2SignerReference,
        exact_reference_bytes: &[u8],
        ring: &RouteGrantV2PublicKeyRingArtifact,
        private_key_pem: Option<&[u8]>,
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        let signer = RouteGrantV2Signer::from_authority_artifacts(
            reference,
            ring,
            private_key_pem,
            ttl_seconds,
        )?;
        let binding = RouteGrantV2SignerBinding::from_authority_artifacts(
            reference,
            exact_reference_bytes,
            ring,
        )?;
        Ok(Self { binding, signer })
    }

    pub(crate) fn binding(&self) -> &RouteGrantV2SignerBinding {
        &self.binding
    }

    pub(crate) fn signer(&self) -> Option<&RouteGrantV2Signer> {
        self.signer.as_ref()
    }
}

impl std::fmt::Debug for RouteGrantV2Signer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteGrantV2Signer")
            .field("kid", &self.kid)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuedRouteGrantV2 {
    pub token: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl RouteGrantV2Signer {
    fn from_authority_artifacts(
        reference: &RouteGrantV2SignerReference,
        ring: &RouteGrantV2PublicKeyRingArtifact,
        private_key_pem: Option<&[u8]>,
        ttl_seconds: u64,
    ) -> anyhow::Result<Option<Self>> {
        reference
            .validate_ring(ring)
            .context("validate Route Grant v2 signer and public-ring binding")?;
        let active_kid = match &reference.signer {
            RouteGrantV2SignerSelection::Disabled => {
                anyhow::ensure!(
                    private_key_pem.is_none(),
                    "disabled Route Grant v2 signer must not carry private material"
                );
                return Ok(None);
            }
            RouteGrantV2SignerSelection::Active { active_kid, .. } => active_kid,
        };
        anyhow::ensure!(
            (1..=MAX_ROUTE_GRANT_V2_TTL_SECONDS).contains(&ttl_seconds),
            "Route Grant v2 TTL must be within 1..={MAX_ROUTE_GRANT_V2_TTL_SECONDS} seconds"
        );
        let private_key_pem = private_key_pem
            .context("active Route Grant v2 signer descriptor has no installed private material")?;
        let entry = ring
            .key(active_kid)
            .context("active Route Grant v2 kid is absent from the installed public ring")?;
        let public = RouteGrantV2PublicKey::from_base64url_spki(&entry.public_key_spki)
            .context("parse active Route Grant v2 public key")?;
        let key = checked_encoding_key(private_key_pem, &public)?;
        Ok(Some(Self {
            key: Arc::new(key),
            kid: active_kid.clone(),
            ttl_seconds,
        }))
    }

    #[cfg(test)]
    pub(crate) fn from_ed25519_pem(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=MAX_ROUTE_GRANT_V2_TTL_SECONDS).contains(&ttl_seconds),
            "Route Grant v2 TTL must be within 1..={MAX_ROUTE_GRANT_V2_TTL_SECONDS} seconds"
        );
        let public = RouteGrantV2PublicKey::from_public_key_pem(public_key_pem)
            .context("parse Route Grant v2 Ed25519 public key")?;
        let key = checked_encoding_key(private_key_pem, &public)?;
        Ok(Self {
            key: Arc::new(key),
            kid: public.kid().clone(),
            ttl_seconds,
        })
    }

    pub(crate) fn kid(&self) -> &KeyId {
        &self.kid
    }

    pub(crate) fn issue(
        &self,
        snapshot: &RouteGrantV2AuthoritySnapshot,
    ) -> anyhow::Result<IssuedRouteGrantV2> {
        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        self.issue_at_wall_clock(snapshot, wall_now)
    }

    fn issue_at_wall_clock(
        &self,
        snapshot: &RouteGrantV2AuthoritySnapshot,
        wall_now_unix_seconds: u64,
    ) -> anyhow::Result<IssuedRouteGrantV2> {
        let issued_at_unix_seconds = snapshot.evaluated_at_unix_ms.get() / 1_000;
        let expires_at_unix_seconds = issued_at_unix_seconds
            .checked_add(self.ttl_seconds)
            .filter(|value| *value <= i64::MAX as u64)
            .context("Route Grant v2 expiry overflow")?;
        let claims = RouteGrantV2Claims {
            version: ROUTE_GRANT_V2_VERSION,
            iss: ROUTE_GRANT_V2_ISSUER.to_owned(),
            aud: ROUTE_GRANT_V2_AUDIENCE.to_owned(),
            workspace_id: snapshot.workspace_id.clone(),
            endpoint_id: snapshot.endpoint_id.clone(),
            hostname: snapshot.hostname.clone(),
            cat_id: snapshot.cat_id.clone(),
            node_id: snapshot.node_id.clone(),
            runtime_incarnation: snapshot.runtime_incarnation.clone(),
            route_epoch: snapshot.route_epoch,
            protocol: snapshot.protocol,
            target_port: snapshot.target_port,
            iat: issued_at_unix_seconds,
            nbf: issued_at_unix_seconds,
            exp: expires_at_unix_seconds,
        };
        let input = RouteGrantV2SigningInput::new(
            &RouteGrantV2ProtectedHeader::new(self.kid.clone()),
            &claims,
        )
        .context("encode Route Grant v2 signing input")?;
        let signature = jsonwebtoken::crypto::sign(input.as_bytes(), &self.key, Algorithm::EdDSA)
            .context("sign Route Grant v2 compact input")?;
        let token = input
            .finish_encoded_signature(&signature)
            .context("encode Route Grant v2 compact token")?;
        anyhow::ensure!(
            wall_now_unix_seconds < expires_at_unix_seconds,
            "Route Grant v2 authority snapshot expired before response"
        );
        Ok(IssuedRouteGrantV2 {
            token,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        })
    }
}

fn checked_encoding_key(
    private_key_pem: &[u8],
    public: &RouteGrantV2PublicKey,
) -> anyhow::Result<EncodingKey> {
    let key = EncodingKey::from_ed_pem(private_key_pem)
        .context("parse Route Grant v2 PKCS#8 Ed25519 private key")?;
    let derived = Ed25519KeyPair::from_pkcs8_maybe_unchecked(key.inner())
        .map_err(|_| anyhow::anyhow!("derive Route Grant v2 Ed25519 public key"))?;
    anyhow::ensure!(
        derived.public_key().as_ref() == public.verification_key_bytes(),
        "Route Grant v2 public key does not match the private signing key"
    );

    let proof = b"cats.route-grant.v2.key-pair-proof";
    let signature = jsonwebtoken::crypto::sign(proof, &key, Algorithm::EdDSA)
        .context("sign Route Grant v2 key-pair proof")?;
    let verifier = DecodingKey::from_ed_der(public.verification_key_bytes());
    anyhow::ensure!(
        jsonwebtoken::crypto::verify(&signature, proof, &verifier, Algorithm::EdDSA)
            .context("verify Route Grant v2 key-pair proof")?,
        "Route Grant v2 public key does not match the private signing key"
    );
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::route_grant_v2::{
        decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
        RouteGrantV2Compact, RouteGrantV2PublicKey, RouteGrantV2PublicKeyEntry,
    };
    use cats_api::runtime_reconciliation::{
        Base64UrlNoPad, Epoch, Hostname, HttpProtocol, Id, NodeTransportTarget, RandomId128,
        UnixMillis,
    };

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem");
    const WRONG_ALGORITHM_KEY: &[u8] = include_bytes!("../tests/fixtures/workos_test_private.pem");
    const INSTALLED_RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","public_key_spki":"MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"}]}"#;
    const INSTALLED_SIGNER: &[u8] = br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:4e6fec49756e03044438af279f7bfd9507f06cf065ff0673447bd6377cd07ac0"}"#;

    fn snapshot() -> RouteGrantV2AuthoritySnapshot {
        RouteGrantV2AuthoritySnapshot {
            workspace_id: Id::new("ws_01").unwrap(),
            endpoint_id: Id::new("ep_01").unwrap(),
            hostname: Hostname::new("app.cats.run").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            node_id: Id::new("node-a").unwrap(),
            runtime_incarnation: RandomId128::new("11111111111111111111111111111111").unwrap(),
            route_epoch: Epoch::new(7).unwrap(),
            protocol: HttpProtocol::Http,
            target_port: 8080,
            node_transport_target: NodeTransportTarget::new("https://node-a.internal:7301")
                .unwrap(),
            evaluated_at_unix_ms: UnixMillis::new(1_786_156_800_000).unwrap(),
        }
    }

    #[test]
    fn signer_matches_the_shared_fixed_vector() {
        let signer = RouteGrantV2Signer::from_ed25519_pem(PRIVATE_KEY, PUBLIC_KEY, 120).unwrap();
        let grant = signer
            .issue_at_wall_clock(&snapshot(), 1_786_156_800)
            .unwrap();
        assert_eq!(
            grant.token,
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImNhdHMtcm91dGUtZ3JhbnQrand0Iiwia2lkIjoiZmQ1NmZlZDMyNTE0NjNlZmYwMDYzMTY5YTdmOGZhOWRjZTU4NWI2ZWVlNDI5NTgxMjY0Mjk3Yzk4ZWM1OGJjYiJ9.eyJ2ZXJzaW9uIjoyLCJpc3MiOiJjYXRzLWNvbnRyb2wtcGxhbmUiLCJhdWQiOiJjYXRzLW5vZGUtYWdlbnQiLCJ3b3Jrc3BhY2VfaWQiOiJ3c18wMSIsImVuZHBvaW50X2lkIjoiZXBfMDEiLCJob3N0bmFtZSI6ImFwcC5jYXRzLnJ1biIsImNhdF9pZCI6ImNhdF8wMSIsIm5vZGVfaWQiOiJub2RlLWEiLCJydW50aW1lX2luY2FybmF0aW9uIjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJyb3V0ZV9lcG9jaCI6NywicHJvdG9jb2wiOiJodHRwIiwidGFyZ2V0X3BvcnQiOjgwODAsImlhdCI6MTc4NjE1NjgwMCwibmJmIjoxNzg2MTU2ODAwLCJleHAiOjE3ODYxNTY5MjB9.3Gry0VCwbWEypf9oCgQrT6DUWtb5bgBHYYE9KCbABm73M8OOh71HCvsFsoemyJ_v-WeIM6gb7I0O0Pb_zHyZAQ"
        );
        let compact = RouteGrantV2Compact::parse(&grant.token).unwrap();
        let public = RouteGrantV2PublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();
        assert_eq!(
            public
                .verify(&compact)
                .unwrap()
                .claims()
                .unwrap()
                .cat_id
                .as_str(),
            "cat_01"
        );
    }

    #[test]
    fn installed_authority_requires_exact_private_public_pair_or_explicit_disable() {
        let mut ring = decode_route_grant_v2_public_key_ring(INSTALLED_RING).unwrap();
        let mut reference = decode_route_grant_v2_signer_reference(INSTALLED_SIGNER).unwrap();
        let signer =
            RouteGrantV2Signer::from_authority_artifacts(&reference, &ring, Some(PRIVATE_KEY), 120)
                .unwrap()
                .unwrap();
        assert_eq!(signer.kid(), &ring.keys[0].kid);

        let other_kid =
            KeyId::new("47ff3f28dd2cc185ac432f34ecc346a121c52934b16993ab9fb7fcb92a3406f8").unwrap();
        ring.keys[0] = RouteGrantV2PublicKeyEntry {
            kid: other_kid.clone(),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk",
            )
            .unwrap(),
        };
        reference.public_key_ring_digest = ring.digest().unwrap();
        reference.signer = RouteGrantV2SignerSelection::Active {
            active_kid: other_kid,
            secret_reference_id: Id::new("route_secret_b").unwrap(),
        };
        assert!(RouteGrantV2Signer::from_authority_artifacts(
            &reference,
            &ring,
            Some(PRIVATE_KEY),
            120,
        )
        .is_err());

        ring = decode_route_grant_v2_public_key_ring(INSTALLED_RING).unwrap();
        reference = decode_route_grant_v2_signer_reference(INSTALLED_SIGNER).unwrap();
        let installed = InstalledRouteGrantV2SigningAuthority::from_authority_artifacts(
            &reference,
            INSTALLED_SIGNER,
            &ring,
            Some(PRIVATE_KEY),
            120,
        )
        .unwrap();
        assert!(installed.signer().is_some());
        assert_eq!(installed.binding().reference(), &reference);
        assert!(
            InstalledRouteGrantV2SigningAuthority::from_authority_artifacts(
                &reference,
                INSTALLED_SIGNER,
                &ring,
                Some(WRONG_ALGORITHM_KEY),
                120,
            )
            .is_err()
        );
        assert!(RouteGrantV2Signer::from_authority_artifacts(
            &reference,
            &ring,
            Some(b"not a private key"),
            120,
        )
        .is_err());
        assert!(RouteGrantV2Signer::from_authority_artifacts(
            &reference,
            &ring,
            Some(WRONG_ALGORITHM_KEY),
            120,
        )
        .is_err());
        reference.signer = RouteGrantV2SignerSelection::Disabled;
        assert!(
            RouteGrantV2Signer::from_authority_artifacts(&reference, &ring, None, 0)
                .unwrap()
                .is_none()
        );
        assert!(RouteGrantV2Signer::from_authority_artifacts(
            &reference,
            &ring,
            Some(b"must not be inspected"),
            0,
        )
        .is_err());
    }

    #[test]
    fn startup_rejects_mismatch_ttl_and_expired_snapshot() {
        let other = include_bytes!("../../tests/fixtures/route_grant_other_public_ed25519.pem");
        assert!(RouteGrantV2Signer::from_ed25519_pem(PRIVATE_KEY, other, 120).is_err());
        assert!(RouteGrantV2Signer::from_ed25519_pem(PRIVATE_KEY, PUBLIC_KEY, 0).is_err());
        let signer = RouteGrantV2Signer::from_ed25519_pem(PRIVATE_KEY, PUBLIC_KEY, 120).unwrap();
        assert!(signer
            .issue_at_wall_clock(&snapshot(), 1_786_156_920)
            .is_err());
    }
}

//! Control-plane-only Ed25519 signer for Route Grant v2.
//!
//! PostgreSQL authority is loaded separately by
//! [`crate::store::runtime_authority::route_signer`].  This type owns only the
//! active private key and converts one already-closed authority snapshot into
//! the frozen compact token.

#![allow(
    dead_code,
    reason = "the v2 signer is composed with the machine-authenticated resolve route after the Node transport target authority lands"
)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::route_grant_v2::{
    RouteGrantV2Claims, RouteGrantV2ProtectedHeader, RouteGrantV2PublicKey,
    RouteGrantV2SigningInput, DEFAULT_ROUTE_GRANT_V2_TTL_SECONDS, MAX_ROUTE_GRANT_V2_TTL_SECONDS,
    ROUTE_GRANT_V2_AUDIENCE, ROUTE_GRANT_V2_ISSUER, ROUTE_GRANT_V2_VERSION,
};
use cats_api::runtime_reconciliation::KeyId;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

use crate::store::runtime_authority::route_signer::RouteGrantV2AuthoritySnapshot;

#[derive(Clone)]
pub(crate) struct RouteGrantV2Signer {
    key: Arc<EncodingKey>,
    kid: KeyId,
    ttl_seconds: u64,
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
    pub(crate) fn from_ed25519_pem(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=MAX_ROUTE_GRANT_V2_TTL_SECONDS).contains(&ttl_seconds),
            "Route Grant v2 TTL must be within 1..={MAX_ROUTE_GRANT_V2_TTL_SECONDS} seconds"
        );
        let key = EncodingKey::from_ed_pem(private_key_pem)
            .context("parse Route Grant v2 PKCS#8 Ed25519 private key")?;
        let verifier = DecodingKey::from_ed_pem(public_key_pem)
            .context("parse Route Grant v2 Ed25519 public key")?;
        let public = RouteGrantV2PublicKey::from_public_key_pem(public_key_pem)
            .context("parse Route Grant v2 Ed25519 public key")?;
        let proof = b"cats.route-grant.v2.key-pair-proof";
        let signature = jsonwebtoken::crypto::sign(proof, &key, Algorithm::EdDSA)
            .context("sign Route Grant v2 key-pair proof")?;
        anyhow::ensure!(
            jsonwebtoken::crypto::verify(&signature, proof, &verifier, Algorithm::EdDSA)
                .context("verify Route Grant v2 key-pair proof")?,
            "Route Grant v2 public key does not match the private signing key"
        );
        Ok(Self {
            key: Arc::new(key),
            kid: public.kid().clone(),
            ttl_seconds,
        })
    }

    pub(crate) fn with_default_ttl(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> anyhow::Result<Self> {
        Self::from_ed25519_pem(
            private_key_pem,
            public_key_pem,
            DEFAULT_ROUTE_GRANT_V2_TTL_SECONDS,
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::route_grant_v2::{RouteGrantV2Compact, RouteGrantV2PublicKey};
    use cats_api::runtime_reconciliation::{
        Epoch, Hostname, HttpProtocol, Id, NodeTransportTarget, RandomId128, UnixMillis,
    };

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem");

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

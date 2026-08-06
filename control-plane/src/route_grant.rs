//! Control-plane-only signing for Endpoint Route Grants (ADR-0033).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use cats_api::resources::RouteBinding;
pub use cats_api::route_grant::DEFAULT_ROUTE_GRANT_TTL_SECONDS;
use cats_api::route_grant::{
    route_grant_public_key_sha256, RouteGrantClaims, MAX_ROUTE_GRANT_TTL_SECONDS,
    ROUTE_GRANT_AUDIENCE, ROUTE_GRANT_ISSUER, ROUTE_GRANT_VERSION,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[derive(Clone)]
pub struct RouteGrantSigner {
    key: EncodingKey,
    public_key_sha256: String,
    ttl_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct IssuedRouteGrant {
    pub token: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl RouteGrantSigner {
    pub fn from_ed25519_pem(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(ttl_seconds > 0, "route grant TTL must be positive");
        anyhow::ensure!(
            ttl_seconds <= MAX_ROUTE_GRANT_TTL_SECONDS,
            "route grant TTL must not exceed {MAX_ROUTE_GRANT_TTL_SECONDS} seconds"
        );
        let key = EncodingKey::from_ed_pem(private_key_pem)
            .context("parse route grant Ed25519 private key")?;
        let public_key = DecodingKey::from_ed_pem(public_key_pem)
            .context("parse route grant Ed25519 public key")?;
        let public_key_sha256 = route_grant_public_key_sha256(public_key_pem)
            .context("fingerprint Route Grant public key")?;

        // Parsing both halves proves only that they are Ed25519 keys. Sign and
        // verify one fixed, non-secret challenge so a mismatched but valid pair
        // fails before the control-plane process can become Ready.
        let mut proof_header = Header::new(Algorithm::EdDSA);
        proof_header.typ = Some("JWT".to_string());
        proof_header.kid = Some(public_key_sha256.clone());
        let proof = jsonwebtoken::encode(
            &proof_header,
            &serde_json::json!({"route_grant_key_pair_proof": 1}),
            &key,
        )
        .context("sign Route Grant key-pair proof")?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        jsonwebtoken::decode::<serde_json::Value>(&proof, &public_key, &validation)
            .context("Route Grant public key does not match the private signing key")?;

        Ok(Self {
            key,
            public_key_sha256,
            ttl_seconds,
        })
    }

    pub fn public_key_sha256(&self) -> &str {
        &self.public_key_sha256
    }

    pub fn issue(
        &self,
        binding: &RouteBinding,
        cat_generation: i64,
    ) -> anyhow::Result<IssuedRouteGrant> {
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        self.issue_at(binding, cat_generation, issued_at)
    }

    fn issue_at(
        &self,
        binding: &RouteBinding,
        cat_generation: i64,
        issued_at: u64,
    ) -> anyhow::Result<IssuedRouteGrant> {
        anyhow::ensure!(!binding.hostname.is_empty(), "route hostname is empty");
        anyhow::ensure!(!binding.workspace_id.is_empty(), "route workspace is empty");
        anyhow::ensure!(!binding.cat_id.is_empty(), "route Cat is empty");
        anyhow::ensure!(cat_generation > 0, "route Cat generation must be positive");
        anyhow::ensure!(!binding.node_id.is_empty(), "route Node is empty");
        anyhow::ensure!(binding.epoch > 0, "route epoch must be positive");
        anyhow::ensure!(
            binding.target_port > 0,
            "route target port must be non-zero"
        );
        let expires_at_unix = issued_at
            .checked_add(self.ttl_seconds)
            .context("route grant expiry overflow")?;
        let claims = RouteGrantClaims {
            version: ROUTE_GRANT_VERSION,
            iss: ROUTE_GRANT_ISSUER.to_string(),
            aud: ROUTE_GRANT_AUDIENCE.to_string(),
            hostname: binding.hostname.clone(),
            workspace_id: binding.workspace_id.clone(),
            cat_id: binding.cat_id.clone(),
            cat_generation,
            node_id: binding.node_id.clone(),
            route_epoch: binding.epoch,
            target_port: binding.target_port,
            iat: issued_at,
            exp: expires_at_unix,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());
        header.kid = Some(self.public_key_sha256.clone());
        let token = jsonwebtoken::encode(&header, &claims, &self.key)
            .context("sign Endpoint Route Grant")?;
        Ok(IssuedRouteGrant {
            token,
            issued_at_unix: issued_at,
            expires_at_unix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::decode_header;
    use jsonwebtoken::{DecodingKey, Validation};

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem");

    fn binding() -> RouteBinding {
        RouteBinding {
            hostname: "dev-123.cats.run".to_string(),
            workspace_id: "ws_1".to_string(),
            cat_id: "cat_1".to_string(),
            node_id: "node-a".to_string(),
            gateway_url: "https://gateway.cats.run".to_string(),
            target_port: 8080,
            epoch: 9,
            wake_policy: cats_api::resources::WakePolicy::WakeOnRequest,
        }
    }

    #[test]
    fn signs_every_route_authority_field() {
        let signer = RouteGrantSigner::from_ed25519_pem(PRIVATE_KEY, PUBLIC_KEY, 120).unwrap();
        let grant = signer.issue_at(&binding(), 7, 1_000).unwrap();
        assert_eq!(
            decode_header(&grant.token).unwrap().kid.as_deref(),
            Some(signer.public_key_sha256())
        );
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.set_audience(&[ROUTE_GRANT_AUDIENCE]);
        validation.set_issuer(&[ROUTE_GRANT_ISSUER]);
        let decoded = jsonwebtoken::decode::<RouteGrantClaims>(
            &grant.token,
            &DecodingKey::from_ed_pem(PUBLIC_KEY).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(
            decoded.claims,
            RouteGrantClaims {
                version: 1,
                iss: ROUTE_GRANT_ISSUER.to_string(),
                aud: ROUTE_GRANT_AUDIENCE.to_string(),
                hostname: "dev-123.cats.run".to_string(),
                workspace_id: "ws_1".to_string(),
                cat_id: "cat_1".to_string(),
                cat_generation: 7,
                node_id: "node-a".to_string(),
                route_epoch: 9,
                target_port: 8080,
                iat: 1_000,
                exp: 1_120,
            }
        );
        assert_eq!(grant.issued_at_unix, 1_000);
        assert_eq!(grant.expires_at_unix, 1_120);
    }

    #[test]
    fn refuses_unbounded_lifetime() {
        assert!(RouteGrantSigner::from_ed25519_pem(
            PRIVATE_KEY,
            PUBLIC_KEY,
            MAX_ROUTE_GRANT_TTL_SECONDS + 1
        )
        .is_err());
    }

    #[test]
    fn refuses_a_valid_but_mismatched_public_key() {
        let other_public =
            include_bytes!("../../tests/fixtures/route_grant_other_public_ed25519.pem");
        let error = RouteGrantSigner::from_ed25519_pem(PRIVATE_KEY, other_public, 120)
            .err()
            .expect("mismatched key halves must stop control-plane startup");
        assert!(
            error
                .to_string()
                .contains("does not match the private signing key"),
            "unexpected error: {error:#}"
        );
    }
}

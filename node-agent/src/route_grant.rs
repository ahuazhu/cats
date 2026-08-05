//! Node-only verification for control-plane signed Endpoint Route Grants.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use cats_api::route_grant::{
    RouteGrantClaims, MAX_ROUTE_GRANT_TTL_SECONDS, ROUTE_GRANT_AUDIENCE, ROUTE_GRANT_ISSUER,
    ROUTE_GRANT_VERSION,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

#[derive(Clone)]
pub struct RouteGrantVerifier {
    key: DecodingKey,
}

pub struct ExpectedRouteGrant<'a> {
    pub hostname: &'a str,
    pub cat_id: &'a str,
    pub node_id: &'a str,
    pub route_epoch: i64,
    pub target_port: u16,
}

impl RouteGrantVerifier {
    pub fn from_ed25519_pem(public_key_pem: &[u8]) -> anyhow::Result<Self> {
        let key = DecodingKey::from_ed_pem(public_key_pem)
            .context("parse route grant Ed25519 public key")?;
        Ok(Self { key })
    }

    pub fn verify(
        &self,
        token: &str,
        expected: ExpectedRouteGrant<'_>,
    ) -> anyhow::Result<RouteGrantClaims> {
        anyhow::ensure!(!token.is_empty(), "missing Endpoint Route Grant");
        let header = jsonwebtoken::decode_header(token).context("decode Route Grant header")?;
        anyhow::ensure!(
            header.alg == Algorithm::EdDSA,
            "Route Grant algorithm is not EdDSA"
        );
        anyhow::ensure!(
            header.typ.as_deref() == Some("JWT"),
            "Route Grant type is not JWT"
        );

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0;
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[ROUTE_GRANT_ISSUER]);
        validation.set_audience(&[ROUTE_GRANT_AUDIENCE]);
        let claims = jsonwebtoken::decode::<RouteGrantClaims>(token, &self.key, &validation)
            .context("verify Endpoint Route Grant")?
            .claims;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        anyhow::ensure!(
            claims.version == ROUTE_GRANT_VERSION,
            "unsupported Route Grant version"
        );
        anyhow::ensure!(
            claims.iat <= now.saturating_add(5),
            "Route Grant was issued in the future"
        );
        anyhow::ensure!(claims.exp > now, "Endpoint Route Grant has expired");
        anyhow::ensure!(
            claims.exp > claims.iat,
            "Route Grant expiry precedes issue time"
        );
        anyhow::ensure!(
            claims.exp - claims.iat <= MAX_ROUTE_GRANT_TTL_SECONDS,
            "Route Grant lifetime exceeds the authorization bound"
        );
        anyhow::ensure!(
            !claims.workspace_id.is_empty(),
            "Route Grant workspace is empty"
        );
        anyhow::ensure!(
            claims.hostname == expected.hostname,
            "Route Grant hostname mismatch"
        );
        anyhow::ensure!(claims.cat_id == expected.cat_id, "Route Grant Cat mismatch");
        anyhow::ensure!(
            claims.cat_generation > 0,
            "Route Grant Cat generation is invalid"
        );
        anyhow::ensure!(
            claims.node_id == expected.node_id,
            "Route Grant Node mismatch"
        );
        anyhow::ensure!(
            claims.route_epoch == expected.route_epoch && claims.route_epoch > 0,
            "Route Grant epoch mismatch"
        );
        anyhow::ensure!(
            claims.target_port == expected.target_port && claims.target_port > 0,
            "Route Grant target port mismatch"
        );
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem");

    fn claims() -> RouteGrantClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        RouteGrantClaims {
            version: ROUTE_GRANT_VERSION,
            iss: ROUTE_GRANT_ISSUER.to_string(),
            aud: ROUTE_GRANT_AUDIENCE.to_string(),
            hostname: "dev-123.cats.run".to_string(),
            workspace_id: "ws_1".to_string(),
            cat_id: "cat_1".to_string(),
            cat_generation: 7,
            node_id: "node-a".to_string(),
            route_epoch: 9,
            target_port: 8080,
            iat: now,
            exp: now + 120,
        }
    }

    fn sign(claims: &RouteGrantClaims) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());
        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn expected() -> ExpectedRouteGrant<'static> {
        ExpectedRouteGrant {
            hostname: "dev-123.cats.run",
            cat_id: "cat_1",
            node_id: "node-a",
            route_epoch: 9,
            target_port: 8080,
        }
    }

    #[test]
    fn accepts_only_the_exact_signed_binding() {
        let verifier = RouteGrantVerifier::from_ed25519_pem(PUBLIC_KEY).unwrap();
        let token = sign(&claims());
        assert_eq!(
            verifier.verify(&token, expected()).unwrap().cat_generation,
            7
        );

        let mismatches = [
            ExpectedRouteGrant {
                hostname: "other.cats.run",
                ..expected()
            },
            ExpectedRouteGrant {
                cat_id: "cat_2",
                ..expected()
            },
            ExpectedRouteGrant {
                node_id: "node-b",
                ..expected()
            },
            ExpectedRouteGrant {
                route_epoch: 10,
                ..expected()
            },
            ExpectedRouteGrant {
                target_port: 8081,
                ..expected()
            },
        ];
        for mismatch in mismatches {
            assert!(verifier.verify(&token, mismatch).is_err());
        }
    }

    #[test]
    fn rejects_expired_and_tampered_grants() {
        let verifier = RouteGrantVerifier::from_ed25519_pem(PUBLIC_KEY).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired = RouteGrantClaims {
            iat: now - 10,
            exp: now - 1,
            ..claims()
        };
        assert!(verifier.verify(&sign(&expired), expected()).is_err());

        let mut token = sign(&claims()).into_bytes();
        let last = token.last_mut().unwrap();
        *last = if *last == b'a' { b'b' } else { b'a' };
        assert!(verifier
            .verify(std::str::from_utf8(&token).unwrap(), expected())
            .is_err());
    }
}

//! Versioned claims carried by a control-plane signed Endpoint Route Grant.
//!
//! This crate owns only the wire shape. Private-key signing belongs to the
//! control plane and public-key verification belongs to the Node agent; the
//! Gateway deliberately treats the compact JWS as opaque (ADR-0033).

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ROUTE_GRANT_VERSION: u8 = 1;
pub const ROUTE_GRANT_ISSUER: &str = "cats-control-plane";
pub const ROUTE_GRANT_AUDIENCE: &str = "cats-node-agent";
pub const DEFAULT_ROUTE_GRANT_TTL_SECONDS: u64 = 120;
pub const MAX_ROUTE_GRANT_TTL_SECONDS: u64 = 300;
pub const MAX_ROUTE_GRANT_CLOCK_SKEW_SECONDS: u64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum RouteGrantPublicKeyError {
    #[error("Route Grant public key is not UTF-8")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Route Grant public key is not a PEM public key")]
    InvalidPem,
    #[error("Route Grant public key has invalid base64 material")]
    InvalidBase64(#[from] base64::DecodeError),
}

/// Stable, non-secret identity for one Route Grant verifier key.
///
/// Blank lines, line wrapping, surrounding whitespace and CRLF/LF encoding do
/// not create a different identity. The digest covers the decoded DER public
/// key, which is also what OpenSSL deployment gates hash. Cryptographic key
/// algorithm validation remains the signer/verifier's responsibility.
pub fn route_grant_public_key_sha256(
    public_key_pem: &[u8],
) -> Result<String, RouteGrantPublicKeyError> {
    let text = std::str::from_utf8(public_key_pem)?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.first() != Some(&"-----BEGIN PUBLIC KEY-----")
        || lines.last() != Some(&"-----END PUBLIC KEY-----")
        || lines.len() < 3
    {
        return Err(RouteGrantPublicKeyError::InvalidPem);
    }
    let der =
        base64::engine::general_purpose::STANDARD.decode(lines[1..lines.len() - 1].join(""))?;
    if der.is_empty() {
        return Err(RouteGrantPublicKeyError::InvalidPem);
    }
    Ok(hex::encode(Sha256::digest(der)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantClaims {
    pub version: u8,
    pub iss: String,
    pub aud: String,
    pub hostname: String,
    pub workspace_id: String,
    pub cat_id: String,
    pub cat_generation: i64,
    pub node_id: String,
    pub route_epoch: i64,
    pub target_port: u16,
    pub iat: u64,
    pub exp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_fingerprint_is_stable_across_pem_whitespace() {
        let compact = b"-----BEGIN PUBLIC KEY-----\nYWJj\n-----END PUBLIC KEY-----\n";
        let spaced =
            b"\n -----BEGIN PUBLIC KEY----- \r\n\r\n YWJj \r\n -----END PUBLIC KEY-----\r\n";
        assert_eq!(
            route_grant_public_key_sha256(compact).unwrap(),
            route_grant_public_key_sha256(spaced).unwrap()
        );
        assert!(route_grant_public_key_sha256(b"not a PEM").is_err());
    }
}

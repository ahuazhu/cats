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
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_reconciliation::{Epoch, Hostname, HttpProtocol, Id, KeyId, RandomId128};

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
        let token = format!(
            "{}.{}",
            self.compact_prefix,
            URL_SAFE_NO_PAD.encode(signature)
        );
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
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem");

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
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImNhdHMtcm91dGUtZ3JhbnQrand0Iiwia2lkIjoiZmQ1NmZlZDMyNTE0NjNlZmYwMDYzMTY5YTdmOGZhOWRjZTU4NWI2ZWVlNDI5NTgxMjY0Mjk3Yzk4ZWM1OGJjYiJ9.eyJ2ZXJzaW9uIjoyLCJpc3MiOiJjYXRzLWNvbnRyb2wtcGxhbmUiLCJhdWQiOiJjYXRzLW5vZGUtYWdlbnQiLCJ3b3Jrc3BhY2VfaWQiOiJ3c18wMSIsImVuZHBvaW50X2lkIjoiZXBfMDEiLCJob3N0bmFtZSI6ImFwcC5jYXRzLnJ1biIsImNhdF9pZCI6ImNhdF8wMSIsIm5vZGVfaWQiOiJub2RlLWEiLCJydW50aW1lX2luY2FybmF0aW9uIjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJyb3V0ZV9lcG9jaCI6NywicHJvdG9jb2wiOiJodHRwIiwidGFyZ2V0X3BvcnQiOjgwODAsImlhdCI6MTc4NjE1NjgwMCwibmJmIjoxNzg2MTU2ODAwLCJleHAiOjE3ODYxNTY5MjB9.3Gry0VCwbWEypf9oCgQrT6DUWtb5bgBHYYE9KCbABm73M8OOh71HCvsFsoemyJ_v-WeIM6gb7I0O0Pb_zHyZAQ"
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
            br#"{"alg":"EdDSA","alg":"EdDSA","typ":"cats-route-grant+jwt","kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb"}"#.as_slice(),
            br#"{"alg":"EdDSA","typ":"cats-route-grant+jwt","kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","extra":1}"#.as_slice(),
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
            br#"{"alg":"HS256","typ":"cats-route-grant+jwt","kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb"}"#.as_slice(),
            br#"{"alg":"EdDSA","typ":"JWT","kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb"}"#.as_slice(),
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
    fn public_key_requires_exact_ed25519_spki() {
        let public = RouteGrantV2PublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();
        assert_eq!(
            public.kid().as_str(),
            "fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb"
        );
        assert_eq!(
            RouteGrantV2PublicKey::from_spki_der(&[0_u8; 44]).err(),
            Some(RouteGrantV2Error::InvalidPublicKey)
        );
    }
}

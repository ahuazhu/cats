//! Independent machine authority for Route Grant v2 signer transitions.
//!
//! The operator signatures authenticate one immutable command and any public
//! ring successor carried by it. They are deliberately unrelated to A19,
//! A23, Gateway, Workspace, WorkOS, administrator bearer, and Route Grant
//! signing credentials.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::agent_registration::Ed25519RequestSigner;
use crate::route_grant_v2::{RouteGrantV2PublicKeyRingArtifact, RouteGrantV2SignerReference};
use crate::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, ContractVersion, Epoch, Id, RandomId128,
    Sha256Digest, UnixMillis,
};

pub const ROUTE_V2_ROTATION_OPERATOR_TRUST_PATH: &str =
    "/etc/cats/route-v2/rotation-operator-trust.v1.json";
pub const ROUTE_V2_ROTATION_OPERATOR_TRUST_MAX_WIRE_BYTES: usize = 16_384;
pub const ROUTE_V2_SIGNING_COMMAND_PATH: &str = "/v1/internal/route-v2/signing-authority-commands";
pub const ROUTE_V2_SIGNING_COMMAND_METHOD: &str = "POST";
pub const ROUTE_V2_RING_SUCCESSOR_PATH: &str = "/v1/internal/route-v2/public-ring-successors";
pub const ROUTE_V2_RING_SUCCESSOR_METHOD: &str = "GET";
pub const ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES: usize = 65_536;
pub const ROUTE_V2_SIGNING_COMMAND_RESPONSE_MAX_WIRE_BYTES: usize = 16_384;
pub const ROUTE_V2_RING_SUCCESSOR_RESPONSE_MAX_WIRE_BYTES: usize =
    ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES;
pub const ROUTE_V2_ROTATION_OPERATOR_JSON_CONTENT_TYPE: &str = "application/json";
pub const ROUTE_V2_ROTATION_OPERATOR_MAX_CREDENTIALS: usize = 8;
pub const ROUTE_V2_ROTATION_OPERATOR_MAX_COMMAND_LIFETIME_MILLIS: u64 = 10 * 60 * 1_000;

const SIGNATURE_DOMAIN: &[u8] = b"cats.route-v2.rotation-operator.command.v1";
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteV2RotationOperatorCredential {
    pub credential_id: Id,
    pub public_key_spki: Base64UrlNoPad,
    pub public_key_spki_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteV2RotationOperatorTrust {
    pub version: ContractVersion,
    pub authority_id: Id,
    /// The one Route v2 deployment this operator may transition and deliver.
    pub route_deployment_id: Id,
    /// Exact lowercase 40-hex source commit embedded in every release binary.
    pub release_commit_sha: String,
    pub threshold: u16,
    pub credentials: Vec<RouteV2RotationOperatorCredential>,
}

impl RouteV2RotationOperatorTrust {
    pub fn validate(&self) -> Result<(), RouteV2RotationOperatorError> {
        if self.version.get() != 1
            || !valid_release_commit_sha(&self.release_commit_sha)
            || self.credentials.is_empty()
            || self.credentials.len() > ROUTE_V2_ROTATION_OPERATOR_MAX_CREDENTIALS
            || self.threshold == 0
            || usize::from(self.threshold) > self.credentials.len()
        {
            return Err(RouteV2RotationOperatorError::InvalidTrust);
        }
        let mut previous_id: Option<&str> = None;
        let mut public_digests = std::collections::BTreeSet::new();
        for credential in &self.credentials {
            if previous_id.is_some_and(|previous| previous >= credential.credential_id.as_str()) {
                return Err(RouteV2RotationOperatorError::InvalidTrust);
            }
            previous_id = Some(credential.credential_id.as_str());
            let digest = canonical_ed25519_spki_sha256(&credential.public_key_spki)
                .ok_or(RouteV2RotationOperatorError::InvalidTrust)?;
            if digest != credential.public_key_spki_sha256
                || !public_digests.insert(digest.as_str().to_owned())
            {
                return Err(RouteV2RotationOperatorError::InvalidTrust);
            }
        }
        Ok(())
    }

    pub fn credential(&self, id: &Id) -> Option<&RouteV2RotationOperatorCredential> {
        self.credentials
            .binary_search_by(|credential| credential.credential_id.cmp(id))
            .ok()
            .map(|index| &self.credentials[index])
    }

    pub fn exact_digest(&self) -> Result<Sha256Digest, RouteV2RotationOperatorError> {
        let bytes = encode_route_v2_rotation_operator_trust(self)?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteGrantV2SigningAuthorityCommandKind {
    PublishOverlap {
        successor_ring: RouteGrantV2PublicKeyRingArtifact,
        new_secret_reference_id: Id,
    },
    SwitchActive,
    PublishNewOnly {
        successor_ring: RouteGrantV2PublicKeyRingArtifact,
    },
    Retire,
    Disable {
        successor_ring: RouteGrantV2PublicKeyRingArtifact,
    },
    Activate,
}

impl RouteGrantV2SigningAuthorityCommandKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PublishOverlap { .. } => "publish_overlap",
            Self::SwitchActive => "switch_active",
            Self::PublishNewOnly { .. } => "publish_new_only",
            Self::Retire => "retire",
            Self::Disable { .. } => "disable",
            Self::Activate => "activate",
        }
    }

    pub fn successor_ring(&self) -> Option<&RouteGrantV2PublicKeyRingArtifact> {
        match self {
            Self::PublishOverlap { successor_ring, .. }
            | Self::PublishNewOnly { successor_ring }
            | Self::Disable { successor_ring } => Some(successor_ring),
            Self::SwitchActive | Self::Retire | Self::Activate => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantV2SigningAuthorityCommand {
    pub successor: RouteGrantV2SignerReference,
    pub kind: RouteGrantV2SigningAuthorityCommandKind,
}

impl RouteGrantV2SigningAuthorityCommand {
    pub fn validate(&self) -> Result<(), RouteV2RotationOperatorError> {
        self.successor
            .validate()
            .map_err(|_| RouteV2RotationOperatorError::InvalidCommand)?;
        if let Some(ring) = self.kind.successor_ring() {
            self.successor
                .validate_ring(ring)
                .map_err(|_| RouteV2RotationOperatorError::InvalidCommand)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteV2SigningCommandPayload {
    pub version: ContractVersion,
    pub authority_id: Id,
    pub release_commit_sha: String,
    pub command_id: RandomId128,
    pub issued_at_unix_ms: UnixMillis,
    pub expires_at_unix_ms: UnixMillis,
    pub command: RouteGrantV2SigningAuthorityCommand,
}

impl RouteV2SigningCommandPayload {
    pub fn validate(&self) -> Result<(), RouteV2RotationOperatorError> {
        let lifetime = self
            .expires_at_unix_ms
            .get()
            .checked_sub(self.issued_at_unix_ms.get())
            .filter(|lifetime| {
                *lifetime > 0 && *lifetime <= ROUTE_V2_ROTATION_OPERATOR_MAX_COMMAND_LIFETIME_MILLIS
            })
            .ok_or(RouteV2RotationOperatorError::InvalidCommand)?;
        let _ = lifetime;
        if self.version.get() != 1 || !valid_release_commit_sha(&self.release_commit_sha) {
            return Err(RouteV2RotationOperatorError::InvalidCommand);
        }
        self.command.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteV2RotationOperatorProof {
    pub credential_id: Id,
    pub signature: Base64UrlNoPad,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRouteV2SigningCommand {
    pub payload: RouteV2SigningCommandPayload,
    pub proofs: Vec<RouteV2RotationOperatorProof>,
}

impl SignedRouteV2SigningCommand {
    pub fn validate_shape(&self) -> Result<(), RouteV2RotationOperatorError> {
        self.payload.validate()?;
        if self.proofs.is_empty() || self.proofs.len() > ROUTE_V2_ROTATION_OPERATOR_MAX_CREDENTIALS
        {
            return Err(RouteV2RotationOperatorError::InvalidCommand);
        }
        let mut previous: Option<&str> = None;
        for proof in &self.proofs {
            if previous.is_some_and(|value| value >= proof.credential_id.as_str()) {
                return Err(RouteV2RotationOperatorError::InvalidCommand);
            }
            previous = Some(proof.credential_id.as_str());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRouteV2RotationOperatorPrincipal {
    pub authority_id: Id,
    pub route_deployment_id: Id,
    pub release_commit_sha: String,
    pub trust_sha256: Sha256Digest,
    pub credential_ids: Vec<Id>,
    pub credential_set_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteGrantV2SigningAuthorityCommandResult {
    Applied {
        signer_revision: Epoch,
        public_key_ring_version: Epoch,
    },
    AuthorityPreconditionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteV2SigningCommandReceipt {
    pub version: ContractVersion,
    pub authority_id: Id,
    pub release_commit_sha: String,
    pub command_id: RandomId128,
    pub exact_command_sha256: Sha256Digest,
    pub result: RouteGrantV2SigningAuthorityCommandResult,
    pub committed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteV2RotationOperatorError {
    #[error("Route v2 rotation operator trust is invalid")]
    InvalidTrust,
    #[error("Route v2 signing command is invalid")]
    InvalidCommand,
    #[error("Route v2 signing command is not canonical")]
    NonCanonical,
    #[error("Route v2 signing command authentication failed")]
    AuthenticationFailed,
    #[error("Route v2 signing command release does not match")]
    ReleaseMismatch,
}

pub fn encode_route_v2_rotation_operator_trust(
    trust: &RouteV2RotationOperatorTrust,
) -> Result<Vec<u8>, RouteV2RotationOperatorError> {
    trust.validate()?;
    serde_json::to_vec(trust).map_err(|_| RouteV2RotationOperatorError::InvalidTrust)
}

pub fn decode_route_v2_rotation_operator_trust(
    bytes: &[u8],
) -> Result<RouteV2RotationOperatorTrust, RouteV2RotationOperatorError> {
    if bytes.is_empty() || bytes.len() > ROUTE_V2_ROTATION_OPERATOR_TRUST_MAX_WIRE_BYTES {
        return Err(RouteV2RotationOperatorError::InvalidTrust);
    }
    let trust: RouteV2RotationOperatorTrust =
        serde_json::from_slice(bytes).map_err(|_| RouteV2RotationOperatorError::InvalidTrust)?;
    let canonical = encode_route_v2_rotation_operator_trust(&trust)?;
    if canonical != bytes {
        return Err(RouteV2RotationOperatorError::NonCanonical);
    }
    Ok(trust)
}

pub fn encode_signed_route_v2_signing_command(
    command: &SignedRouteV2SigningCommand,
) -> Result<Vec<u8>, RouteV2RotationOperatorError> {
    command.validate_shape()?;
    let bytes =
        serde_json::to_vec(command).map_err(|_| RouteV2RotationOperatorError::InvalidCommand)?;
    if bytes.len() > ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES {
        return Err(RouteV2RotationOperatorError::InvalidCommand);
    }
    Ok(bytes)
}

pub fn decode_signed_route_v2_signing_command(
    bytes: &[u8],
) -> Result<SignedRouteV2SigningCommand, RouteV2RotationOperatorError> {
    if bytes.is_empty() || bytes.len() > ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES {
        return Err(RouteV2RotationOperatorError::InvalidCommand);
    }
    let command: SignedRouteV2SigningCommand =
        serde_json::from_slice(bytes).map_err(|_| RouteV2RotationOperatorError::InvalidCommand)?;
    let canonical = encode_signed_route_v2_signing_command(&command)?;
    if canonical != bytes {
        return Err(RouteV2RotationOperatorError::NonCanonical);
    }
    Ok(command)
}

pub fn encode_route_v2_signing_command_receipt(
    receipt: &RouteV2SigningCommandReceipt,
) -> Result<Vec<u8>, RouteV2RotationOperatorError> {
    let bytes =
        serde_json::to_vec(receipt).map_err(|_| RouteV2RotationOperatorError::InvalidCommand)?;
    if bytes.is_empty() || bytes.len() > ROUTE_V2_SIGNING_COMMAND_RESPONSE_MAX_WIRE_BYTES {
        return Err(RouteV2RotationOperatorError::InvalidCommand);
    }
    Ok(bytes)
}

pub fn decode_route_v2_signing_command_receipt(
    bytes: &[u8],
) -> Result<RouteV2SigningCommandReceipt, RouteV2RotationOperatorError> {
    if bytes.is_empty() || bytes.len() > ROUTE_V2_SIGNING_COMMAND_RESPONSE_MAX_WIRE_BYTES {
        return Err(RouteV2RotationOperatorError::InvalidCommand);
    }
    let receipt: RouteV2SigningCommandReceipt =
        serde_json::from_slice(bytes).map_err(|_| RouteV2RotationOperatorError::InvalidCommand)?;
    if encode_route_v2_signing_command_receipt(&receipt)? != bytes {
        return Err(RouteV2RotationOperatorError::NonCanonical);
    }
    Ok(receipt)
}

/// Canonical, percent-free discovery query. All three value alphabets exclude
/// `&`, `=` and `%`, so intermediaries cannot create a second interpretation.
pub fn route_v2_ring_successor_query(
    deployment_id: &Id,
    current_ring_version: Epoch,
    current_ring_digest: &Sha256Digest,
) -> String {
    let digest_hex = current_ring_digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("Sha256Digest always has its typed prefix");
    format!(
        "deployment_id={}&current_ring_version={}&current_key_ring_sha256={digest_hex}",
        deployment_id.as_str(),
        current_ring_version.get(),
    )
}

pub fn sign_route_v2_signing_command(
    payload: &RouteV2SigningCommandPayload,
    signer: &Ed25519RequestSigner,
) -> Result<RouteV2RotationOperatorProof, RouteV2RotationOperatorError> {
    payload.validate()?;
    let payload_bytes = canonical_payload(payload)?;
    let framed = signed_frame(&payload_bytes);
    Ok(RouteV2RotationOperatorProof {
        credential_id: signer.credential_id().clone(),
        signature: Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.sign_framed(&framed)))
            .ok_or(RouteV2RotationOperatorError::InvalidCommand)?,
    })
}

pub fn verify_signed_route_v2_signing_command(
    trust: &RouteV2RotationOperatorTrust,
    expected_release_commit_sha: &str,
    signed: &SignedRouteV2SigningCommand,
) -> Result<VerifiedRouteV2RotationOperatorPrincipal, RouteV2RotationOperatorError> {
    trust.validate()?;
    signed.validate_shape()?;
    if signed.payload.authority_id != trust.authority_id
        || signed.payload.command.successor.deployment_id != trust.route_deployment_id
        || signed.payload.release_commit_sha != trust.release_commit_sha
        || signed.payload.release_commit_sha != expected_release_commit_sha
    {
        return Err(RouteV2RotationOperatorError::ReleaseMismatch);
    }
    let payload = canonical_payload(&signed.payload)?;
    let framed = signed_frame(&payload);
    let mut accepted = Vec::new();
    for proof in &signed.proofs {
        let credential = trust
            .credential(&proof.credential_id)
            .ok_or(RouteV2RotationOperatorError::AuthenticationFailed)?;
        verify_proof(credential, &framed, &proof.signature)?;
        accepted.push(proof.credential_id.clone());
    }
    if accepted.len() < usize::from(trust.threshold) {
        return Err(RouteV2RotationOperatorError::AuthenticationFailed);
    }
    let mut digest_input = Vec::new();
    for id in &accepted {
        digest_input.extend_from_slice(&(id.as_str().len() as u64).to_be_bytes());
        digest_input.extend_from_slice(id.as_str().as_bytes());
    }
    Ok(VerifiedRouteV2RotationOperatorPrincipal {
        authority_id: trust.authority_id.clone(),
        route_deployment_id: trust.route_deployment_id.clone(),
        release_commit_sha: trust.release_commit_sha.clone(),
        trust_sha256: trust.exact_digest()?,
        credential_ids: accepted,
        credential_set_sha256: Sha256Digest::from_bytes(Sha256::digest(digest_input).into()),
    })
}

fn canonical_payload(
    payload: &RouteV2SigningCommandPayload,
) -> Result<Vec<u8>, RouteV2RotationOperatorError> {
    serde_json::to_vec(payload).map_err(|_| RouteV2RotationOperatorError::InvalidCommand)
}

fn signed_frame(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + 8 + payload.len());
    output.extend_from_slice(SIGNATURE_DOMAIN);
    output.push(0);
    output.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    output.extend_from_slice(payload);
    output
}

fn verify_proof(
    credential: &RouteV2RotationOperatorCredential,
    framed: &[u8],
    encoded_signature: &Base64UrlNoPad,
) -> Result<(), RouteV2RotationOperatorError> {
    let spki = URL_SAFE_NO_PAD
        .decode(credential.public_key_spki.as_str())
        .map_err(|_| RouteV2RotationOperatorError::AuthenticationFailed)?;
    if spki.len() != ED25519_SPKI_LEN || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(RouteV2RotationOperatorError::AuthenticationFailed);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature.as_str())
        .map_err(|_| RouteV2RotationOperatorError::AuthenticationFailed)?;
    if signature.len() != 64 {
        return Err(RouteV2RotationOperatorError::AuthenticationFailed);
    }
    UnparsedPublicKey::new(&ED25519, &spki[ED25519_SPKI_PREFIX.len()..])
        .verify(framed, &signature)
        .map_err(|_| RouteV2RotationOperatorError::AuthenticationFailed)
}

fn valid_release_commit_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_grant_v2::{
        RouteGrantV2PublicKeyEntry, RouteGrantV2PublicKeyRingExpectedPrevious,
        RouteGrantV2SignerExpectedPrevious, RouteGrantV2SignerSelection,
    };
    use crate::runtime_reconciliation::KeyId;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    fn signer(id: &str) -> Ed25519RequestSigner {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519RequestSigner::from_pkcs8_der(Id::new(id.to_owned()).unwrap(), document.as_ref())
            .unwrap()
    }

    fn credential(signer: &Ed25519RequestSigner) -> RouteV2RotationOperatorCredential {
        let public_key_spki =
            Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der())).unwrap();
        RouteV2RotationOperatorCredential {
            credential_id: signer.credential_id().clone(),
            public_key_spki_sha256: canonical_ed25519_spki_sha256(&public_key_spki).unwrap(),
            public_key_spki,
        }
    }

    fn payload() -> RouteV2SigningCommandPayload {
        let key = RouteGrantV2PublicKeyEntry {
            kid: KeyId::new("11".repeat(32)).unwrap(),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To".to_owned(),
            )
            .unwrap(),
        };
        let ring = RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(2).unwrap(),
            expected_previous: Some(RouteGrantV2PublicKeyRingExpectedPrevious {
                ring_version: Epoch::new(1).unwrap(),
                key_ring_digest: Sha256Digest::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            }),
            keys: vec![key],
        };
        let successor = RouteGrantV2SignerReference {
            version: ContractVersion::V1,
            deployment_id: Id::new("route_deployment".to_owned()).unwrap(),
            signer_revision: Epoch::new(2).unwrap(),
            expected_previous: Some(RouteGrantV2SignerExpectedPrevious {
                signer_revision: Epoch::new(1).unwrap(),
                signer_reference_sha256: Sha256Digest::new(format!("sha256:{}", "33".repeat(32)))
                    .unwrap(),
            }),
            signer: RouteGrantV2SignerSelection::Disabled,
            public_key_ring_version: ring.ring_version,
            public_key_ring_digest: ring.digest().unwrap(),
        };
        RouteV2SigningCommandPayload {
            version: ContractVersion::V1,
            authority_id: Id::new("route_operator".to_owned()).unwrap(),
            release_commit_sha: "a".repeat(40),
            command_id: RandomId128::new("11".repeat(16)).unwrap(),
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(2_000).unwrap(),
            command: RouteGrantV2SigningAuthorityCommand {
                successor,
                kind: RouteGrantV2SigningAuthorityCommandKind::Disable {
                    successor_ring: ring,
                },
            },
        }
    }

    #[test]
    fn threshold_proofs_are_independent_and_canonical() {
        let first = signer("operator_a");
        let second = signer("operator_b");
        let trust = RouteV2RotationOperatorTrust {
            version: ContractVersion::V1,
            authority_id: Id::new("route_operator".to_owned()).unwrap(),
            route_deployment_id: payload().command.successor.deployment_id,
            release_commit_sha: "a".repeat(40),
            threshold: 2,
            credentials: vec![credential(&first), credential(&second)],
        };
        let payload = payload();
        let signed = SignedRouteV2SigningCommand {
            proofs: vec![
                sign_route_v2_signing_command(&payload, &first).unwrap(),
                sign_route_v2_signing_command(&payload, &second).unwrap(),
            ],
            payload,
        };
        let bytes = encode_signed_route_v2_signing_command(&signed).unwrap();
        let decoded = decode_signed_route_v2_signing_command(&bytes).unwrap();
        let principal =
            verify_signed_route_v2_signing_command(&trust, &"a".repeat(40), &decoded).unwrap();
        assert_eq!(principal.credential_ids.len(), 2);

        let mut one_proof = decoded.clone();
        one_proof.proofs.pop();
        assert_eq!(
            verify_signed_route_v2_signing_command(&trust, &"a".repeat(40), &one_proof),
            Err(RouteV2RotationOperatorError::AuthenticationFailed)
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert_eq!(
            decode_signed_route_v2_signing_command(&noncanonical),
            Err(RouteV2RotationOperatorError::NonCanonical)
        );
    }
}

//! Shared Node identity and Ed25519 key-material primitives.
//!
//! The semantic Node register/heartbeat protocol uses its own service-token
//! transport. This module retains only the independent A23 identity material
//! and signing key used by provisioner authorities; it does not define an
//! AgentSession or registration request protocol.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use crate::runtime_reconciliation::{
    decode_node_identity, encode_node_identity, CredentialBinding, Id, NodeIdentity,
    NodeIdentityState, Sha256Digest,
};

pub const JSON_CONTENT_TYPE: &str = "application/json";

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Rejects the two F0 `Id` values that are navigation components when the Id
/// selects one directory beneath `/var/lib/cats/node`.
pub fn validate_state_path_component(value: &Id) -> Result<(), StatePathComponentError> {
    if matches!(value.as_str(), "." | "..") {
        Err(StatePathComponentError)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("state_path_id is not a safe path component")]
pub struct StatePathComponentError;

#[derive(Debug, thiserror::Error)]
pub enum RequestSignerError {
    #[error("Node identity private key is not valid PKCS#8 Ed25519")]
    InvalidPrivateKey,
    #[error("Node identity private key PEM is malformed")]
    InvalidPrivateKeyPem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeIdentityMaterialError {
    #[error("NodeIdentity artifact is invalid")]
    InvalidIdentity,
    #[error("NodeIdentity artifact is not canonical")]
    NonCanonicalIdentity,
    #[error("NodeIdentity is not provisioned")]
    IdentityNotProvisioned,
    #[error("NodeIdentity state_path_id is not a safe path component")]
    UnsafeStatePath,
    #[error("credential ID file does not exactly match NodeIdentity")]
    CredentialIdMismatch,
    #[error("Node identity private key is invalid")]
    InvalidPrivateKey,
    #[error("NodeIdentity credential binding is not an Ed25519 public key")]
    UnsupportedCredentialBinding,
    #[error("Node identity private key does not match NodeIdentity binding")]
    PrivateKeyMismatch,
}

/// Reusable Ed25519 signer with one canonical SPKI representation.
#[derive(Clone)]
pub struct Ed25519RequestSigner {
    credential_id: Id,
    key_pair: Arc<Ed25519KeyPair>,
    spki_der: [u8; ED25519_SPKI_LEN],
}

impl std::fmt::Debug for Ed25519RequestSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ed25519RequestSigner")
            .field("credential_id", &self.credential_id)
            .field("public_key_spki_sha256", &self.public_key_spki_sha256())
            .finish_non_exhaustive()
    }
}

impl Ed25519RequestSigner {
    pub fn from_pkcs8_der(
        credential_id: Id,
        private_key_der: &[u8],
    ) -> Result<Self, RequestSignerError> {
        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key_der)
            .map_err(|_| RequestSignerError::InvalidPrivateKey)?;
        Self::from_key_pair(credential_id, key_pair)
    }

    pub fn from_pkcs8_pem(
        credential_id: Id,
        private_key_pem: &[u8],
    ) -> Result<Self, RequestSignerError> {
        let der = decode_pkcs8_pem(private_key_pem)?;
        Self::from_pkcs8_der(credential_id, &der)
    }

    /// Parses a strict PKCS#8 v2 Ed25519 private key and verifies its embedded
    /// public half. Provisioning tools use this narrower constructor for newly
    /// generated keys; the runtime reader retains the v1-or-v2 constructor for
    /// already provisioned identity material.
    pub fn from_pkcs8_v2_pem(
        credential_id: Id,
        private_key_pem: &[u8],
    ) -> Result<Self, RequestSignerError> {
        let der = decode_pkcs8_pem(private_key_pem)?;
        let key_pair =
            Ed25519KeyPair::from_pkcs8(&der).map_err(|_| RequestSignerError::InvalidPrivateKey)?;
        if encode_canonical_pkcs8_pem(&der).as_slice() != private_key_pem {
            return Err(RequestSignerError::InvalidPrivateKeyPem);
        }
        Self::from_key_pair(credential_id, key_pair)
    }

    fn from_key_pair(
        credential_id: Id,
        key_pair: Ed25519KeyPair,
    ) -> Result<Self, RequestSignerError> {
        let public_key = key_pair.public_key().as_ref();
        if public_key.len() != 32 {
            return Err(RequestSignerError::InvalidPrivateKey);
        }
        let mut spki_der = [0_u8; ED25519_SPKI_LEN];
        spki_der[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
        spki_der[ED25519_SPKI_PREFIX.len()..].copy_from_slice(public_key);
        Ok(Self {
            credential_id,
            key_pair: Arc::new(key_pair),
            spki_der,
        })
    }

    pub fn credential_id(&self) -> &Id {
        &self.credential_id
    }

    pub fn public_key_spki_der(&self) -> &[u8; ED25519_SPKI_LEN] {
        &self.spki_der
    }

    pub fn public_key_spki_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(self.spki_der).into())
    }

    /// Sign bytes already framed by one closed Cats protocol.
    pub(crate) fn sign_framed(&self, framed: &[u8]) -> [u8; 64] {
        self.key_pair
            .sign(framed)
            .as_ref()
            .try_into()
            .expect("ring Ed25519 signatures are exactly 64 octets")
    }
}

/// Decode and cross-check the one frozen local Node identity/key/credential
/// set. Filesystem ownership, link and descriptor-stability checks remain the
/// responsibility of the caller that opened the three files.
pub fn validate_node_identity_material(
    identity_bytes: &[u8],
    private_key_pem: &[u8],
    credential_id_bytes: &[u8],
) -> Result<(NodeIdentity, Ed25519RequestSigner), NodeIdentityMaterialError> {
    let identity = decode_node_identity(identity_bytes)
        .map_err(|_| NodeIdentityMaterialError::InvalidIdentity)?;
    if encode_node_identity(&identity).ok().as_deref() != Some(identity_bytes) {
        return Err(NodeIdentityMaterialError::NonCanonicalIdentity);
    }
    if identity.state != NodeIdentityState::Provisioned {
        return Err(NodeIdentityMaterialError::IdentityNotProvisioned);
    }
    validate_state_path_component(&identity.state_path_id)
        .map_err(|_| NodeIdentityMaterialError::UnsafeStatePath)?;
    let expected_credential = format!("{}\n", identity.credential_id);
    if credential_id_bytes != expected_credential.as_bytes() {
        return Err(NodeIdentityMaterialError::CredentialIdMismatch);
    }
    let signer =
        Ed25519RequestSigner::from_pkcs8_pem(identity.credential_id.clone(), private_key_pem)
            .map_err(|_| NodeIdentityMaterialError::InvalidPrivateKey)?;
    let CredentialBinding::PublicKey {
        public_key_spki_sha256,
    } = &identity.credential_binding
    else {
        return Err(NodeIdentityMaterialError::UnsupportedCredentialBinding);
    };
    if public_key_spki_sha256 != &signer.public_key_spki_sha256() {
        return Err(NodeIdentityMaterialError::PrivateKeyMismatch);
    }
    Ok((identity, signer))
}

fn decode_pkcs8_pem(input: &[u8]) -> Result<Vec<u8>, RequestSignerError> {
    let text = std::str::from_utf8(input).map_err(|_| RequestSignerError::InvalidPrivateKeyPem)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let body = text
        .strip_prefix("-----BEGIN PRIVATE KEY-----\n")
        .and_then(|value| value.strip_suffix("\n-----END PRIVATE KEY-----"))
        .ok_or(RequestSignerError::InvalidPrivateKeyPem)?;
    if body.is_empty()
        || body.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'\n'))
        })
    {
        return Err(RequestSignerError::InvalidPrivateKeyPem);
    }
    let compact: String = body.lines().collect();
    let der = STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| RequestSignerError::InvalidPrivateKeyPem)?;
    if STANDARD.encode(&der) != compact {
        return Err(RequestSignerError::InvalidPrivateKeyPem);
    }
    Ok(der)
}

fn encode_canonical_pkcs8_pem(der: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(der);
    let mut pem = Vec::with_capacity(encoded.len() + 80);
    pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_reconciliation::{ContractVersion, ProviderScope};
    use ring::rand::SystemRandom;

    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn pem(der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(der)
        )
        .into_bytes()
    }

    #[test]
    fn strict_pkcs8_v2_requires_embedded_public_key_and_canonical_pem() {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let canonical = encode_canonical_pkcs8_pem(document.as_ref());
        let credential_id = || Id::new("credential_a").unwrap();
        assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(credential_id(), &canonical).is_ok());

        let mut mismatched = document.as_ref().to_vec();
        *mismatched.last_mut().unwrap() ^= 1;
        assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(
            credential_id(),
            &encode_canonical_pkcs8_pem(&mismatched),
        )
        .is_err());

        let mut v1 = hex::decode("302e020100300506032b657004220420").unwrap();
        v1.extend_from_slice(&hex::decode(SEED).unwrap());
        assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(
            credential_id(),
            &encode_canonical_pkcs8_pem(&v1),
        )
        .is_err());
        assert!(Ed25519RequestSigner::from_pkcs8_pem(credential_id(), &pem(&v1)).is_ok());

        let mut no_final_lf = canonical.clone();
        assert_eq!(no_final_lf.pop(), Some(b'\n'));
        let encoded = STANDARD.encode(document.as_ref());
        let reflowed =
            format!("-----BEGIN PRIVATE KEY-----\n{encoded}\n-----END PRIVATE KEY-----\n")
                .into_bytes();
        let crlf = String::from_utf8(canonical.clone())
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes();
        let mut extra_lf = canonical;
        extra_lf.push(b'\n');
        for malformed in [no_final_lf, reflowed, crlf, extra_lf] {
            assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(credential_id(), &malformed).is_err());
        }
    }

    #[test]
    fn shared_node_identity_material_validator_closes_all_three_files() {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(&hex::decode(SEED).unwrap());
        let key = pem(&der);
        let signer =
            Ed25519RequestSigner::from_pkcs8_pem(Id::new("credential_a").unwrap(), &key).unwrap();
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new("node_a").unwrap(),
            provider_scope: ProviderScope {
                provider: Id::new("test_provider").unwrap(),
                partition: Id::new("test_partition").unwrap(),
                account_id: Id::new("test_account").unwrap(),
                region: Id::new("test_region").unwrap(),
            },
            immutable_host_id: Id::new("host_a").unwrap(),
            credential_id: Id::new("credential_a").unwrap(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new("state_path_a").unwrap(),
            state: NodeIdentityState::Provisioned,
        };
        let identity_bytes = encode_node_identity(&identity).unwrap();
        assert_eq!(
            validate_node_identity_material(&identity_bytes, &key, b"credential_a\n")
                .unwrap()
                .0,
            identity
        );
        assert!(
            validate_node_identity_material(&identity_bytes, &key, b"credential_a\n\n").is_err()
        );
        let mut noncanonical = identity_bytes;
        noncanonical.push(b'\n');
        assert!(validate_node_identity_material(&noncanonical, &key, b"credential_a\n").is_err());
    }
}

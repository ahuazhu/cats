//! Shared, framework-neutral Agent registration transport primitives.
//!
//! HTTP adapters own route/header admission and bounded body reads. This
//! module owns the one Ed25519 request-proof dialect and the endpoint-local
//! typed error envelope consumed by both Control and Node.

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime_reconciliation::{
    decode_node_identity, encode_contract_error, encode_node_identity, ContractError,
    ContractVersion, CredentialBinding, Epoch, Id, NodeIdentity, NodeIdentityState, Sha256Digest,
};

pub const REGISTRATION_PATH: &str = "/v1/internal/runtime/agent-sessions";
pub const REGISTRATION_METHOD: &str = "POST";
pub const JSON_CONTENT_TYPE: &str = "application/json";
pub const REGISTRATION_REQUEST_MAX_WIRE_BYTES: usize = 16_384;
pub const REGISTRATION_SUCCESS_MAX_WIRE_BYTES: usize = 16_384;
pub const NODE_CREDENTIAL_ID_HEADER: &str = "cats-node-credential-id";
pub const NODE_PUBLIC_KEY_SPKI_HEADER: &str = "cats-node-public-key-spki";
pub const NODE_SIGNATURE_HEADER: &str = "cats-node-signature";
pub const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-registration\"";
pub const REGISTRATION_ERROR_MAX_WIRE_BYTES: usize = 20_480;
pub const REGISTRATION_ERROR_MESSAGE_MAX_BYTES: usize = 1_024;
pub const AGENT_SESSION_LEASE_MS: u64 = 60_000;

const SIGNATURE_DOMAIN: &[u8] = b"cats.internal-runtime.request.v1";
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

/// The sole process-internal identity output of a verified per-Node proof.
///
/// It intentionally contains no Node or Host identity. Store selection still
/// starts at the provisioned credential ID and exact credential binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedNodeCredential {
    credential_id: Id,
    binding: CredentialBinding,
}

impl AuthenticatedNodeCredential {
    /// Constructs the value at an authenticated adapter boundary.
    ///
    /// Production HTTP code obtains it through [`verify_request_proof`]. The
    /// constructor is also the narrow seam for non-HTTP authenticated adapters
    /// and Store contract tests.
    pub fn new(credential_id: Id, binding: CredentialBinding) -> Self {
        Self {
            credential_id,
            binding,
        }
    }

    pub fn credential_id(&self) -> &Id {
        &self.credential_id
    }

    pub fn binding(&self) -> &CredentialBinding {
        &self.binding
    }
}

/// Exact proof header values ready for an HTTP client to attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRequestProof {
    pub credential_id: String,
    pub public_key_spki: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestSignerError {
    #[error("Node registration private key is not valid PKCS#8 Ed25519")]
    InvalidPrivateKey,
    #[error("Node registration private key PEM is malformed")]
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
    #[error("Node registration private key is invalid")]
    InvalidPrivateKey,
    #[error("NodeIdentity credential binding is not an Ed25519 public key")]
    UnsupportedCredentialBinding,
    #[error("Node registration private key does not match NodeIdentity binding")]
    PrivateKeyMismatch,
}

/// Reusable per-Node Ed25519 signer with one canonical SPKI representation.
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
    /// the already frozen A19 compatibility boundary.
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

    pub fn sign(&self, method: &str, path: &str, body: &[u8]) -> NodeRequestProof {
        let signed = signed_request(
            method,
            path,
            self.credential_id.as_str(),
            &self.spki_der,
            body,
        );
        NodeRequestProof {
            credential_id: self.credential_id.to_string(),
            public_key_spki: URL_SAFE_NO_PAD.encode(self.spki_der),
            signature: URL_SAFE_NO_PAD.encode(self.key_pair.sign(&signed).as_ref()),
        }
    }

    /// Sign bytes already framed by another closed Cats protocol.
    ///
    /// This remains crate-private so callers cannot accidentally invent a
    /// second public signing dialect. Protocol modules expose typed wrappers
    /// around their one frozen frame instead.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Node request authentication failed")]
pub struct RequestProofError;

/// Verifies one request proof without depending on HTTP or framework types.
pub fn verify_request_proof(
    method: &str,
    path: &str,
    body: &[u8],
    credential_id: &str,
    public_key_spki: &str,
    signature: &str,
) -> Result<AuthenticatedNodeCredential, RequestProofError> {
    let credential_id = Id::new(credential_id.to_owned()).ok_or(RequestProofError)?;
    let spki = decode_base64url_exact::<ED25519_SPKI_LEN>(public_key_spki)?;
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(RequestProofError);
    }
    let signature = decode_base64url_exact::<64>(signature)?;
    let signed = signed_request(method, path, credential_id.as_str(), &spki, body);
    UnparsedPublicKey::new(&ED25519, &spki[ED25519_SPKI_PREFIX.len()..])
        .verify(&signed, &signature)
        .map_err(|_| RequestProofError)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(spki).into());
    Ok(AuthenticatedNodeCredential::new(
        credential_id,
        CredentialBinding::PublicKey {
            public_key_spki_sha256: digest,
        },
    ))
}

/// Verify a frame owned by another closed internal protocol while reusing the
/// one provisioned A19 credential lineage. The caller's domain-separated
/// frame must bind its method, path, content type and complete request
/// metadata; this helper only decodes the canonical proof headers.
pub(crate) fn verify_framed_request_proof(
    framed: &[u8],
    credential_id: &str,
    public_key_spki: &str,
    signature: &str,
) -> Result<AuthenticatedNodeCredential, RequestProofError> {
    let credential_id = Id::new(credential_id.to_owned()).ok_or(RequestProofError)?;
    let spki = decode_base64url_exact::<ED25519_SPKI_LEN>(public_key_spki)?;
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(RequestProofError);
    }
    let signature = decode_base64url_exact::<64>(signature)?;
    UnparsedPublicKey::new(&ED25519, &spki[ED25519_SPKI_PREFIX.len()..])
        .verify(framed, &signature)
        .map_err(|_| RequestProofError)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(spki).into());
    Ok(AuthenticatedNodeCredential::new(
        credential_id,
        CredentialBinding::PublicKey {
            public_key_spki_sha256: digest,
        },
    ))
}

fn signed_request(
    method: &str,
    path: &str,
    credential_id: &str,
    spki_der: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(
        SIGNATURE_DOMAIN.len()
            + 1
            + 8 * 6
            + method.len()
            + path.len()
            + JSON_CONTENT_TYPE.len()
            + credential_id.len()
            + spki_der.len()
            + 32,
    );
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.push(0);
    append_frame(&mut signed, method.as_bytes());
    append_frame(&mut signed, path.as_bytes());
    append_frame(&mut signed, JSON_CONTENT_TYPE.as_bytes());
    append_frame(&mut signed, credential_id.as_bytes());
    append_frame(&mut signed, spki_der);
    signed.extend_from_slice(&(body.len() as u64).to_be_bytes());
    signed.extend_from_slice(&Sha256::digest(body));
    signed
}

fn append_frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_base64url_exact<const N: usize>(value: &str) -> Result<[u8; N], RequestProofError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err(RequestProofError);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RequestProofError)?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(RequestProofError);
    }
    decoded.try_into().map_err(|_| RequestProofError)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistrationError {
    pub version: ContractVersion,
    pub error: AgentRegistrationErrorDetail,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentRegistrationErrorDetail {
    AuthenticationFailed,
    IdentityNotEligible,
    SessionEpochMismatch {
        current_agent_session_epoch: Option<Epoch>,
        presented_expected_agent_session_epoch: Option<Epoch>,
    },
    HttpRequestRejected {
        problem: HttpRequestRejection,
    },
    ContractError {
        contract_error: ContractError,
    },
    TemporarilyUnavailable,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpRequestRejection {
    MethodNotAllowed,
    QueryNotAllowed,
    ContentTypeNotAllowed,
    ContentEncodingNotAllowed,
    AuthorizationNotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentRegistrationErrorWireError {
    #[error("Agent registration error wire exceeds its byte limit")]
    LimitExceeded,
    #[error("Agent registration error wire is malformed")]
    Malformed,
    #[error("Agent registration error wire is not canonical")]
    NonCanonical,
}

pub fn encode_agent_registration_error(
    value: &AgentRegistrationError,
) -> Result<Vec<u8>, AgentRegistrationErrorWireError> {
    validate_registration_error(value)?;
    let json =
        serde_json::to_value(value).map_err(|_| AgentRegistrationErrorWireError::Malformed)?;
    let bytes = crate::runtime_reconciliation::canonical_json_value_bytes(&json);
    if bytes.len() > REGISTRATION_ERROR_MAX_WIRE_BYTES {
        return Err(AgentRegistrationErrorWireError::LimitExceeded);
    }
    Ok(bytes)
}

pub fn decode_agent_registration_error(
    bytes: &[u8],
) -> Result<AgentRegistrationError, AgentRegistrationErrorWireError> {
    if bytes.len() > REGISTRATION_ERROR_MAX_WIRE_BYTES {
        return Err(AgentRegistrationErrorWireError::LimitExceeded);
    }
    let value: AgentRegistrationError =
        serde_json::from_slice(bytes).map_err(|_| AgentRegistrationErrorWireError::Malformed)?;
    let canonical = encode_agent_registration_error(&value)?;
    if canonical != bytes {
        return Err(AgentRegistrationErrorWireError::NonCanonical);
    }
    Ok(value)
}

fn validate_registration_error(
    value: &AgentRegistrationError,
) -> Result<(), AgentRegistrationErrorWireError> {
    if value.version != ContractVersion::V1
        || value.message.len() > REGISTRATION_ERROR_MESSAGE_MAX_BYTES
    {
        return Err(AgentRegistrationErrorWireError::Malformed);
    }
    if let AgentRegistrationErrorDetail::ContractError { contract_error } = &value.error {
        encode_contract_error(contract_error)
            .map_err(|_| AgentRegistrationErrorWireError::Malformed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const BODY: &[u8] = br#"{"agent_instance_id":"44444444444444444444444444444444","expected_agent_session_epoch":null,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","immutable_host_id":"host_a","node_boot_id":"33333333333333333333333333333333","node_id":"node_a","registration_attempt_id":"55555555555555555555555555555555","version":1}"#;

    fn vector_signer() -> Ed25519RequestSigner {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(&hex::decode(SEED).unwrap());
        Ed25519RequestSigner::from_pkcs8_der(Id::new("credential_a").unwrap(), &der).unwrap()
    }

    fn pem(der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(der)
        )
        .into_bytes()
    }

    fn canonical_pem(der: &[u8]) -> Vec<u8> {
        encode_canonical_pkcs8_pem(der)
    }

    #[test]
    fn strict_pkcs8_v2_requires_and_checks_the_embedded_public_key() {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let strict = Ed25519RequestSigner::from_pkcs8_v2_pem(
            Id::new("credential_a").unwrap(),
            &canonical_pem(document.as_ref()),
        )
        .unwrap();
        assert_eq!(strict.public_key_spki_der().len(), ED25519_SPKI_LEN);

        let mut mismatched_public_half = document.as_ref().to_vec();
        *mismatched_public_half.last_mut().unwrap() ^= 1;
        assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(
            Id::new("credential_a").unwrap(),
            &canonical_pem(&mismatched_public_half),
        )
        .is_err());

        let mut v1 = hex::decode("302e020100300506032b657004220420").unwrap();
        v1.extend_from_slice(&hex::decode(SEED).unwrap());
        assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(
            Id::new("credential_a").unwrap(),
            &canonical_pem(&v1),
        )
        .is_err());
        assert!(
            Ed25519RequestSigner::from_pkcs8_pem(Id::new("credential_a").unwrap(), &pem(&v1),)
                .is_ok()
        );
    }

    #[test]
    fn strict_pkcs8_v2_requires_the_generator_pem_encoding() {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let canonical = canonical_pem(document.as_ref());
        let credential_id = || Id::new("credential_a").unwrap();
        assert!(Ed25519RequestSigner::from_pkcs8_v2_pem(credential_id(), &canonical).is_ok());

        let mut no_final_lf = canonical.clone();
        assert_eq!(no_final_lf.pop(), Some(b'\n'));

        let encoded = STANDARD.encode(document.as_ref());
        let reflowed =
            format!("-----BEGIN PRIVATE KEY-----\n{encoded}\n-----END PRIVATE KEY-----\n")
                .into_bytes();

        let mut blank_line = canonical.clone();
        let body_offset = b"-----BEGIN PRIVATE KEY-----\n".len();
        blank_line.insert(body_offset, b'\n');

        let crlf = String::from_utf8(canonical.clone())
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes();

        let mut extra_lf = canonical.clone();
        extra_lf.push(b'\n');

        for malformed in [no_final_lf, reflowed, blank_line, crlf, extra_lf] {
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
            immutable_host_id: Id::new("host_a").unwrap(),
            credential_id: Id::new("credential_a").unwrap(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new("state_path_a").unwrap(),
            state: NodeIdentityState::Provisioned,
        };
        let identity_bytes = encode_node_identity(&identity).unwrap();
        let validated =
            validate_node_identity_material(&identity_bytes, &key, b"credential_a\n").unwrap();
        assert_eq!(validated.0, identity);
        assert!(
            validate_node_identity_material(&identity_bytes, &key, b"credential_a\n\n",).is_err()
        );
        let mut noncanonical = identity_bytes.clone();
        noncanonical.push(b'\n');
        assert!(validate_node_identity_material(&noncanonical, &key, b"credential_a\n",).is_err());
    }

    #[test]
    fn proof_fixed_vector_and_all_bound_fields() {
        let signer = vector_signer();
        let proof = signer.sign(REGISTRATION_METHOD, REGISTRATION_PATH, BODY);
        assert_eq!(BODY.len(), 359);
        assert_eq!(
            proof.public_key_spki,
            "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        );
        assert_eq!(
            signer.public_key_spki_sha256().as_str(),
            "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"
        );
        assert_eq!(
            proof.signature,
            "X0xnGNt7Yux9_i9-T4LaBjP-E0KXsjGmOuGtJ2-ATmYLivVTILs2kD4_mWScT1YNyS1GGjw9_b_rJxmPoziuBg"
        );
        let authenticated = verify_request_proof(
            REGISTRATION_METHOD,
            REGISTRATION_PATH,
            BODY,
            &proof.credential_id,
            &proof.public_key_spki,
            &proof.signature,
        )
        .unwrap();
        assert_eq!(authenticated.credential_id().as_str(), "credential_a");
        assert_eq!(
            authenticated.binding(),
            &CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            }
        );

        let mut changed_body = BODY.to_vec();
        changed_body[0] ^= 1;
        for candidate in [
            verify_request_proof(
                "GET",
                REGISTRATION_PATH,
                BODY,
                &proof.credential_id,
                &proof.public_key_spki,
                &proof.signature,
            ),
            verify_request_proof(
                REGISTRATION_METHOD,
                "/v1/internal/runtime/other",
                BODY,
                &proof.credential_id,
                &proof.public_key_spki,
                &proof.signature,
            ),
            verify_request_proof(
                REGISTRATION_METHOD,
                REGISTRATION_PATH,
                BODY,
                "credential_b",
                &proof.public_key_spki,
                &proof.signature,
            ),
            verify_request_proof(
                REGISTRATION_METHOD,
                REGISTRATION_PATH,
                &changed_body,
                &proof.credential_id,
                &proof.public_key_spki,
                &proof.signature,
            ),
        ] {
            assert_eq!(candidate.unwrap_err(), RequestProofError);
        }
    }

    #[test]
    fn proof_decoder_rejects_noncanonical_and_wrong_length_values() {
        let signer = vector_signer();
        let proof = signer.sign(REGISTRATION_METHOD, REGISTRATION_PATH, BODY);
        let mut different_canonical_spki = *signer.public_key_spki_der();
        different_canonical_spki[ED25519_SPKI_LEN - 1] ^= 1;
        for spki in [
            format!("{}=", proof.public_key_spki),
            STANDARD.encode(signer.public_key_spki_der()),
            URL_SAFE_NO_PAD.encode([0_u8; ED25519_SPKI_LEN]),
            URL_SAFE_NO_PAD.encode(different_canonical_spki),
        ] {
            assert!(verify_request_proof(
                REGISTRATION_METHOD,
                REGISTRATION_PATH,
                BODY,
                &proof.credential_id,
                &spki,
                &proof.signature,
            )
            .is_err());
        }
        assert!(verify_request_proof(
            REGISTRATION_METHOD,
            REGISTRATION_PATH,
            BODY,
            &proof.credential_id,
            &proof.public_key_spki,
            &format!("{}=", proof.signature),
        )
        .is_err());
    }

    #[test]
    fn endpoint_error_wire_is_closed_and_canonical() {
        let value = AgentRegistrationError {
            version: ContractVersion::V1,
            error: AgentRegistrationErrorDetail::SessionEpochMismatch {
                current_agent_session_epoch: Epoch::new(7),
                presented_expected_agent_session_epoch: None,
            },
            message: "session epoch did not match".to_owned(),
        };
        let encoded = encode_agent_registration_error(&value).unwrap();
        assert_eq!(decode_agent_registration_error(&encoded).unwrap(), value);
        let spaced = String::from_utf8(encoded)
            .unwrap()
            .replacen('{', "{ ", 1)
            .into_bytes();
        assert_eq!(
            decode_agent_registration_error(&spaced).unwrap_err(),
            AgentRegistrationErrorWireError::NonCanonical
        );
        assert_eq!(
            decode_agent_registration_error(
                br#"{"error":{"code":"internal"},"extra":1,"message":"x","version":1}"#,
            )
            .unwrap_err(),
            AgentRegistrationErrorWireError::Malformed
        );
        assert_eq!(
            decode_agent_registration_error(
                br#"{"error":{"code":"internal"},"message":"x","message":"y","version":1}"#,
            )
            .unwrap_err(),
            AgentRegistrationErrorWireError::Malformed
        );
    }
}

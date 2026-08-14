//! Streaming block data-plane to object-write-gateway contract.
//!
//! The descriptor is canonical JSON carried in one bounded header. The body
//! remains raw bytes and is streamed to a durable spool; its declared length
//! and SHA-256 are signed by one attachment-scoped key and then independently
//! recomputed by the gateway. The Node A19 key only registers that public key;
//! it is never available to blockd.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::agent_registration::{
    verify_framed_request_proof, verify_request_proof, AuthenticatedNodeCredential,
    Ed25519RequestSigner, NodeRequestProof, RequestProofError,
};
use crate::runtime_reconciliation::{
    AsciiText, Base64UrlNoPad, ContractVersion, FenceEpoch, Generation, Id, RandomId128,
    SessionBinding, Sha256Digest, UnixMillis, WireU64,
};

pub const OBJECT_WRITE_GATEWAY_PATH: &str = "/v1/internal/runtime/object-writes";
pub const OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH: &str =
    "/v1/internal/runtime/object-write-credentials";
pub const OBJECT_WRITE_GATEWAY_METHOD: &str = "POST";
pub const OBJECT_WRITE_GATEWAY_CONTENT_TYPE: &str = "application/octet-stream";
pub const OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE: &str = "application/json";
pub const OBJECT_WRITE_DESCRIPTOR_HEADER: &str = "cats-object-write-descriptor";
pub const OBJECT_WRITE_DESCRIPTOR_MAX_BYTES: usize = 16 * 1024;
pub const OBJECT_WRITE_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;

const WRITE_SIGNATURE_DOMAIN: &[u8] = b"cats.internal-object-write.request.v1";
const REGISTRATION_POP_SIGNATURE_DOMAIN: &[u8] =
    b"cats.internal-object-write-credential.registration-pop.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeDataObjectKind {
    Base,
    Delta,
}

/// Closed immutable ChunkStore key classes writable by an attachment key.
/// Metadata heads, Control records, image keys and arbitrary prefixes are not
/// representable in this contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteImmutableKey {
    VolumeData {
        transaction_id: RandomId128,
        chunk_index: WireU64,
        object_kind: VolumeDataObjectKind,
    },
    VolumeMap,
    VolumeCommit {
        generation: Generation,
        transaction_id: RandomId128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteIngressDescriptor {
    pub version: ContractVersion,
    pub volume_id: Id,
    pub key: ObjectWriteImmutableKey,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteRequestProof {
    pub descriptor: String,
    pub credential: NodeRequestProof,
}

/// The only object-write credential material allowed in an
/// AuthorizedServing/checkpoint/inventory artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteCredentialReference {
    pub credential_id: Id,
    pub public_key_spki_sha256: Sha256Digest,
}

/// A19-authenticated registration of a key generated and durably persisted by
/// the Node before this request. Control derives Host identity and validates
/// the session and current Volume owner; no private key crosses this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteCredentialRegistration {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub writer_authority_id: Id,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub credential: ObjectWriteCredentialReference,
    pub public_key_spki: Base64UrlNoPad,
    pub private_artifact_id: Id,
    pub private_file_fsync_receipt_id: AsciiText,
    pub private_directory_fsync_receipt_id: AsciiText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteCredentialRegistrationProof {
    pub body: Vec<u8>,
    pub node: NodeRequestProof,
    pub attachment_key: NodeRequestProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteCredentialRegistrationReceipt {
    pub version: ContractVersion,
    pub writer_authority_id: Id,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub credential: ObjectWriteCredentialReference,
    pub registered_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteGatewayReceipt {
    pub version: ContractVersion,
    pub writer_authority_id: Id,
    pub request_id: Sha256Digest,
    pub accepted_sequence: WireU64,
    pub terminal: ObjectWriteGatewayTerminalReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteGatewayTerminalReceipt {
    SucceededVisible {
        put_receipt_id: AsciiText,
        put_completed_at_unix_ms: UnixMillis,
        visibility_receipt_id: AsciiText,
        visible_at_unix_ms: UnixMillis,
    },
    PermanentlyFailed {
        failure_receipt_id: AsciiText,
        failed_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObjectWriteGatewayContractError {
    #[error("object-write descriptor is malformed")]
    MalformedDescriptor,
    #[error("object-write descriptor is noncanonical")]
    NonCanonicalDescriptor,
    #[error("object-write descriptor exceeds its bound")]
    DescriptorTooLarge,
    #[error("object-write body exceeds its bound")]
    BodyTooLarge,
    #[error("object-write request proof is invalid")]
    InvalidProof,
    #[error("object-write credential registration is malformed or noncanonical")]
    InvalidCredentialRegistration,
    #[error("object-write receipt is malformed or noncanonical")]
    InvalidReceipt,
}

impl From<RequestProofError> for ObjectWriteGatewayContractError {
    fn from(_: RequestProofError) -> Self {
        Self::InvalidProof
    }
}

pub fn encode_object_write_descriptor(
    descriptor: &ObjectWriteIngressDescriptor,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_descriptor(descriptor)?;
    let bytes = serde_json::to_vec(descriptor)
        .map_err(|_| ObjectWriteGatewayContractError::MalformedDescriptor)?;
    if bytes.len() > OBJECT_WRITE_DESCRIPTOR_MAX_BYTES {
        return Err(ObjectWriteGatewayContractError::DescriptorTooLarge);
    }
    Ok(bytes)
}

pub fn decode_object_write_descriptor(
    bytes: &[u8],
) -> Result<ObjectWriteIngressDescriptor, ObjectWriteGatewayContractError> {
    if bytes.len() > OBJECT_WRITE_DESCRIPTOR_MAX_BYTES {
        return Err(ObjectWriteGatewayContractError::DescriptorTooLarge);
    }
    let descriptor: ObjectWriteIngressDescriptor = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::MalformedDescriptor)?;
    validate_descriptor(&descriptor)?;
    if serde_json::to_vec(&descriptor)
        .map_err(|_| ObjectWriteGatewayContractError::MalformedDescriptor)?
        != bytes
    {
        return Err(ObjectWriteGatewayContractError::NonCanonicalDescriptor);
    }
    Ok(descriptor)
}

pub fn sign_object_write_request(
    signer: &Ed25519RequestSigner,
    descriptor: &ObjectWriteIngressDescriptor,
) -> Result<ObjectWriteRequestProof, ObjectWriteGatewayContractError> {
    let descriptor_bytes = encode_object_write_descriptor(descriptor)?;
    let credential_id = signer.credential_id().to_string();
    let public_key_spki = URL_SAFE_NO_PAD.encode(signer.public_key_spki_der());
    let framed = signature_frame(&descriptor_bytes, &credential_id, &public_key_spki);
    let signature = URL_SAFE_NO_PAD.encode(signer.sign_framed(&framed));
    Ok(ObjectWriteRequestProof {
        descriptor: URL_SAFE_NO_PAD.encode(descriptor_bytes),
        credential: NodeRequestProof {
            credential_id,
            public_key_spki,
            signature,
        },
    })
}

pub fn verify_object_write_request(
    descriptor_header: &str,
    credential_id: &str,
    public_key_spki: &str,
    signature: &str,
) -> Result<
    (AuthenticatedNodeCredential, ObjectWriteIngressDescriptor),
    ObjectWriteGatewayContractError,
> {
    if descriptor_header.is_empty()
        || descriptor_header.len() > encoded_descriptor_maximum()
        || descriptor_header
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err(ObjectWriteGatewayContractError::MalformedDescriptor);
    }
    let descriptor_bytes = URL_SAFE_NO_PAD
        .decode(descriptor_header)
        .map_err(|_| ObjectWriteGatewayContractError::MalformedDescriptor)?;
    if URL_SAFE_NO_PAD.encode(&descriptor_bytes) != descriptor_header {
        return Err(ObjectWriteGatewayContractError::NonCanonicalDescriptor);
    }
    let descriptor = decode_object_write_descriptor(&descriptor_bytes)?;
    let framed = signature_frame(&descriptor_bytes, credential_id, public_key_spki);
    let authenticated =
        verify_framed_request_proof(&framed, credential_id, public_key_spki, signature)?;
    Ok((authenticated, descriptor))
}

pub fn encode_object_write_gateway_receipt(
    receipt: &ObjectWriteGatewayReceipt,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_receipt(receipt)?;
    serde_json::to_vec(receipt).map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)
}

pub fn decode_object_write_gateway_receipt(
    bytes: &[u8],
) -> Result<ObjectWriteGatewayReceipt, ObjectWriteGatewayContractError> {
    let receipt: ObjectWriteGatewayReceipt = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?;
    validate_receipt(&receipt)?;
    if serde_json::to_vec(&receipt).map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?
        != bytes
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(receipt)
}

pub fn encode_object_write_credential_registration(
    registration: &ObjectWriteCredentialRegistration,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_credential_registration(registration)?;
    serde_json::to_vec(registration)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidCredentialRegistration)
}

pub fn decode_object_write_credential_registration(
    bytes: &[u8],
) -> Result<ObjectWriteCredentialRegistration, ObjectWriteGatewayContractError> {
    let registration: ObjectWriteCredentialRegistration = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidCredentialRegistration)?;
    validate_credential_registration(&registration)?;
    if encode_object_write_credential_registration(&registration)? != bytes {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    Ok(registration)
}

pub fn sign_object_write_credential_registration(
    node_signer: &Ed25519RequestSigner,
    attachment_signer: &Ed25519RequestSigner,
    registration: &ObjectWriteCredentialRegistration,
) -> Result<ObjectWriteCredentialRegistrationProof, ObjectWriteGatewayContractError> {
    if attachment_signer.credential_id() != &registration.credential.credential_id
        || attachment_signer.public_key_spki_sha256()
            != registration.credential.public_key_spki_sha256
        || URL_SAFE_NO_PAD.encode(attachment_signer.public_key_spki_der())
            != registration.public_key_spki.as_str()
    {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    let body = encode_object_write_credential_registration(registration)?;
    let node = node_signer.sign(
        OBJECT_WRITE_GATEWAY_METHOD,
        OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH,
        &body,
    );
    let public_key_spki = registration.public_key_spki.as_str().to_owned();
    let attachment_key = NodeRequestProof {
        credential_id: attachment_signer.credential_id().to_string(),
        signature: URL_SAFE_NO_PAD.encode(attachment_signer.sign_framed(&registration_pop_frame(
            &body,
            attachment_signer.credential_id().as_str(),
            &public_key_spki,
        ))),
        public_key_spki,
    };
    Ok(ObjectWriteCredentialRegistrationProof {
        body,
        node,
        attachment_key,
    })
}

pub fn verify_object_write_credential_registration(
    body: &[u8],
    node_proof: &NodeRequestProof,
    attachment_proof: &NodeRequestProof,
) -> Result<
    (
        AuthenticatedNodeCredential,
        AuthenticatedNodeCredential,
        ObjectWriteCredentialRegistration,
    ),
    ObjectWriteGatewayContractError,
> {
    let registration = decode_object_write_credential_registration(body)?;
    if attachment_proof.credential_id != registration.credential.credential_id.as_str()
        || attachment_proof.public_key_spki != registration.public_key_spki.as_str()
    {
        return Err(ObjectWriteGatewayContractError::InvalidProof);
    }
    let node = verify_request_proof(
        OBJECT_WRITE_GATEWAY_METHOD,
        OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH,
        body,
        &node_proof.credential_id,
        &node_proof.public_key_spki,
        &node_proof.signature,
    )?;
    let attachment = verify_framed_request_proof(
        &registration_pop_frame(
            body,
            &attachment_proof.credential_id,
            &attachment_proof.public_key_spki,
        ),
        &attachment_proof.credential_id,
        &attachment_proof.public_key_spki,
        &attachment_proof.signature,
    )?;
    match attachment.binding() {
        crate::runtime_reconciliation::CredentialBinding::PublicKey {
            public_key_spki_sha256,
        } if public_key_spki_sha256 == &registration.credential.public_key_spki_sha256 => {}
        _ => return Err(ObjectWriteGatewayContractError::InvalidProof),
    }
    Ok((node, attachment, registration))
}

pub fn object_write_key(
    volume_id: &Id,
    key: &ObjectWriteImmutableKey,
    content_sha256: &Sha256Digest,
) -> Result<String, ObjectWriteGatewayContractError> {
    let rendered = match key {
        ObjectWriteImmutableKey::VolumeData {
            transaction_id,
            chunk_index,
            object_kind,
        } => {
            let suffix = match object_kind {
                VolumeDataObjectKind::Base => "",
                VolumeDataObjectKind::Delta => "-d",
            };
            format!(
                "volumes/{volume_id}/data/{transaction_id}-c{}{suffix}",
                chunk_index.get()
            )
        }
        ObjectWriteImmutableKey::VolumeMap => {
            let digest = content_sha256
                .as_str()
                .strip_prefix("sha256:")
                .ok_or(ObjectWriteGatewayContractError::MalformedDescriptor)?;
            format!("volumes/{volume_id}/maps/{digest}.node")
        }
        ObjectWriteImmutableKey::VolumeCommit {
            generation,
            transaction_id,
        } => format!(
            "volumes/{volume_id}/commits/{}-{transaction_id}.json",
            generation.get()
        ),
    };
    Ok(rendered)
}

fn validate_descriptor(
    descriptor: &ObjectWriteIngressDescriptor,
) -> Result<(), ObjectWriteGatewayContractError> {
    if descriptor.version != ContractVersion::V1 {
        return Err(ObjectWriteGatewayContractError::MalformedDescriptor);
    }
    if matches!(
        descriptor.key,
        ObjectWriteImmutableKey::VolumeCommit { generation, .. } if generation.get() == 0
    ) {
        return Err(ObjectWriteGatewayContractError::MalformedDescriptor);
    }
    object_write_key(
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
    )?;
    let maximum = u64::try_from(OBJECT_WRITE_BODY_MAX_BYTES)
        .map_err(|_| ObjectWriteGatewayContractError::BodyTooLarge)?;
    if descriptor.content_length.get() > maximum {
        return Err(ObjectWriteGatewayContractError::BodyTooLarge);
    }
    Ok(())
}

fn validate_credential_registration(
    registration: &ObjectWriteCredentialRegistration,
) -> Result<(), ObjectWriteGatewayContractError> {
    if registration.version != ContractVersion::V1
        || registration.attachment_epoch.get() == 0
        || registration.private_artifact_id == registration.credential.credential_id
    {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    let spki = URL_SAFE_NO_PAD
        .decode(registration.public_key_spki.as_str())
        .map_err(|_| ObjectWriteGatewayContractError::InvalidCredentialRegistration)?;
    if Sha256Digest::from_bytes(sha2::Sha256::digest(&spki).into())
        != registration.credential.public_key_spki_sha256
    {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &ObjectWriteGatewayReceipt,
) -> Result<(), ObjectWriteGatewayContractError> {
    if receipt.version != ContractVersion::V1 || receipt.accepted_sequence.get() == 0 {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    match &receipt.terminal {
        ObjectWriteGatewayTerminalReceipt::SucceededVisible {
            put_completed_at_unix_ms,
            visible_at_unix_ms,
            ..
        } if put_completed_at_unix_ms > visible_at_unix_ms => {
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        }
        _ => Ok(()),
    }
}

fn signature_frame(descriptor_bytes: &[u8], credential_id: &str, public_key_spki: &str) -> Vec<u8> {
    let mut framed = Vec::new();
    framed.extend_from_slice(WRITE_SIGNATURE_DOMAIN);
    framed.push(0);
    for value in [
        OBJECT_WRITE_GATEWAY_METHOD.as_bytes(),
        OBJECT_WRITE_GATEWAY_PATH.as_bytes(),
        OBJECT_WRITE_GATEWAY_CONTENT_TYPE.as_bytes(),
        credential_id.as_bytes(),
        public_key_spki.as_bytes(),
        descriptor_bytes,
    ] {
        framed.extend_from_slice(&(value.len() as u64).to_be_bytes());
        framed.extend_from_slice(value);
    }
    framed
}

fn registration_pop_frame(body: &[u8], credential_id: &str, public_key_spki: &str) -> Vec<u8> {
    let mut framed = Vec::new();
    framed.extend_from_slice(REGISTRATION_POP_SIGNATURE_DOMAIN);
    framed.push(0);
    for value in [
        OBJECT_WRITE_GATEWAY_METHOD.as_bytes(),
        OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH.as_bytes(),
        OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE.as_bytes(),
        credential_id.as_bytes(),
        public_key_spki.as_bytes(),
        body,
    ] {
        framed.extend_from_slice(&(value.len() as u64).to_be_bytes());
        framed.extend_from_slice(value);
    }
    framed
}

const fn encoded_descriptor_maximum() -> usize {
    OBJECT_WRITE_DESCRIPTOR_MAX_BYTES.div_ceil(3) * 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_reconciliation::{Epoch, NodeBootId, RandomId128};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn signer(credential_id: &str, seed: u8) -> Ed25519RequestSigner {
        let mut private_key = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        private_key.extend(std::iter::repeat_n(seed, 32));
        Ed25519RequestSigner::from_pkcs8_der(id(credential_id), &private_key).unwrap()
    }

    fn registration(attachment: &Ed25519RequestSigner) -> ObjectWriteCredentialRegistration {
        ObjectWriteCredentialRegistration {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: id("node_a"),
                node_boot_id: NodeBootId::new("1".repeat(32)).unwrap(),
                agent_instance_id: RandomId128::new("2".repeat(32)).unwrap(),
                agent_session_epoch: Epoch::new(7).unwrap(),
            },
            writer_authority_id: id("writer_a"),
            volume_id: id("volume_a"),
            attachment_id: id("attachment_a"),
            attachment_epoch: FenceEpoch::new(9).unwrap(),
            credential: ObjectWriteCredentialReference {
                credential_id: attachment.credential_id().clone(),
                public_key_spki_sha256: attachment.public_key_spki_sha256(),
            },
            public_key_spki: Base64UrlNoPad::new(
                URL_SAFE_NO_PAD.encode(attachment.public_key_spki_der()),
            )
            .unwrap(),
            private_artifact_id: id("object-write-private-attachment-a"),
            private_file_fsync_receipt_id: AsciiText::new("fsync-file-a").unwrap(),
            private_directory_fsync_receipt_id: AsciiText::new("fsync-directory-a").unwrap(),
        }
    }

    #[test]
    fn attachment_key_registration_requires_a19_and_exact_proof_of_possession() {
        let node = signer("node_credential_a", 1);
        let attachment = signer("object_write_credential_a", 2);
        let registration = registration(&attachment);
        let proof =
            sign_object_write_credential_registration(&node, &attachment, &registration).unwrap();
        let (authenticated_node, authenticated_attachment, decoded) =
            verify_object_write_credential_registration(
                &proof.body,
                &proof.node,
                &proof.attachment_key,
            )
            .unwrap();
        assert_eq!(authenticated_node.credential_id(), node.credential_id());
        assert_eq!(
            authenticated_attachment.credential_id(),
            attachment.credential_id()
        );
        assert_eq!(decoded, registration);

        let other_key = signer("object_write_credential_a", 3);
        assert!(
            sign_object_write_credential_registration(&node, &other_key, &registration).is_err()
        );
    }

    #[test]
    fn descriptor_only_renders_exact_volume_immutable_key_classes() {
        let digest = Sha256Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let transaction_id = RandomId128::new("b".repeat(32)).unwrap();
        let data = ObjectWriteImmutableKey::VolumeData {
            transaction_id: transaction_id.clone(),
            chunk_index: WireU64::new(12).unwrap(),
            object_kind: VolumeDataObjectKind::Delta,
        };
        assert_eq!(
            object_write_key(&id("volume_a"), &data, &digest).unwrap(),
            format!("volumes/volume_a/data/{transaction_id}-c12-d")
        );
        assert_ne!(
            object_write_key(&id("volume_a"), &data, &digest).unwrap(),
            object_write_key(&id("volume_b"), &data, &digest).unwrap()
        );
        assert_eq!(
            object_write_key(
                &id("volume_a"),
                &ObjectWriteImmutableKey::VolumeMap,
                &digest
            )
            .unwrap(),
            format!("volumes/volume_a/maps/{}.node", "a".repeat(64))
        );
        let commit = ObjectWriteImmutableKey::VolumeCommit {
            generation: Generation::new(1).unwrap(),
            transaction_id,
        };
        let encoded = encode_object_write_descriptor(&ObjectWriteIngressDescriptor {
            version: ContractVersion::V1,
            volume_id: id("volume_a"),
            key: commit,
            content_sha256: digest,
            content_length: WireU64::new(128).unwrap(),
        })
        .unwrap();
        assert!(!String::from_utf8(encoded).unwrap().contains("metadata"));
    }
}

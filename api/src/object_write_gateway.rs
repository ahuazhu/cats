//! Streaming Node-to-object-write-gateway request contract.
//!
//! The descriptor is canonical JSON carried in one bounded header. The body
//! remains raw bytes and is streamed to a private spool; its declared length
//! and SHA-256 are signed and then independently recomputed by the gateway.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::agent_registration::{
    verify_framed_request_proof, AuthenticatedNodeCredential, Ed25519RequestSigner,
    NodeRequestProof, RequestProofError,
};
use crate::runtime_reconciliation::{
    AsciiText, ContractVersion, Id, SessionBinding, Sha256Digest, UnixMillis, WireU64,
};

pub const OBJECT_WRITE_GATEWAY_PATH: &str = "/v1/internal/runtime/object-writes";
pub const OBJECT_WRITE_GATEWAY_METHOD: &str = "POST";
pub const OBJECT_WRITE_GATEWAY_CONTENT_TYPE: &str = "application/octet-stream";
pub const OBJECT_WRITE_DESCRIPTOR_HEADER: &str = "cats-object-write-descriptor";
pub const OBJECT_WRITE_DESCRIPTOR_MAX_BYTES: usize = 16 * 1024;
pub const OBJECT_WRITE_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"cats.internal-object-write.request.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteIngressDescriptor {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub writer_authority_id: Id,
    pub object_key: String,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteRequestProof {
    pub descriptor: String,
    pub node: NodeRequestProof,
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
        node: NodeRequestProof {
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

fn validate_descriptor(
    descriptor: &ObjectWriteIngressDescriptor,
) -> Result<(), ObjectWriteGatewayContractError> {
    if descriptor.version != ContractVersion::V1
        || descriptor.object_key.is_empty()
        || descriptor.object_key.len() > 4_096
        || !descriptor.object_key.is_ascii()
        || descriptor
            .object_key
            .bytes()
            .any(|byte| byte <= 0x20 || byte == 0x7f)
        || descriptor.object_key.starts_with('/')
        || descriptor
            .object_key
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(ObjectWriteGatewayContractError::MalformedDescriptor);
    }
    let maximum = u64::try_from(OBJECT_WRITE_BODY_MAX_BYTES)
        .map_err(|_| ObjectWriteGatewayContractError::BodyTooLarge)?;
    if descriptor.content_length.get() > maximum {
        return Err(ObjectWriteGatewayContractError::BodyTooLarge);
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
    framed.extend_from_slice(SIGNATURE_DOMAIN);
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

const fn encoded_descriptor_maximum() -> usize {
    ((OBJECT_WRITE_DESCRIPTOR_MAX_BYTES + 2) / 3) * 4
}

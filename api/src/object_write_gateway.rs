//! Streaming block data-plane to object-write-gateway contract.
//!
//! The descriptor is canonical JSON carried in one bounded header. The body
//! remains raw bytes and is streamed to a durable spool; its declared length
//! and SHA-256 are signed by one attachment-scoped key and then independently
//! recomputed by the gateway. The Node A19 key only registers that public key;
//! it is never available to blockd.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::agent_registration::{
    verify_framed_request_proof, verify_request_proof, AuthenticatedNodeCredential,
    Ed25519RequestSigner, NodeRequestProof, RequestProofError,
};
use crate::runtime_reconciliation::{
    AsciiText, Base64UrlNoPad, ContractVersion, Epoch, FenceEpoch, Generation, Id, ProviderScope,
    RandomId128, SessionBinding, Sha256Digest, UnixMillis, WireU64,
};

pub const OBJECT_WRITE_GATEWAY_PATH: &str = "/v1/internal/runtime/object-writes";
pub const OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH: &str =
    "/v1/internal/runtime/object-write-credentials";
pub const OBJECT_WRITE_GATEWAY_METHOD: &str = "POST";
pub const OBJECT_WRITE_GATEWAY_CONTENT_TYPE: &str = "application/octet-stream";
pub const OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE: &str = "application/json";
pub const OBJECT_WRITE_DESCRIPTOR_HEADER: &str = "cats-object-write-descriptor";
pub const OBJECT_WRITE_CREDENTIAL_ID_HEADER: &str = "cats-object-write-credential-id";
pub const OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER: &str = "cats-object-write-public-key-spki";
pub const OBJECT_WRITE_SIGNATURE_HEADER: &str = "cats-object-write-signature";
pub const OBJECT_WRITE_DESCRIPTOR_MAX_BYTES: usize = 16 * 1024;
pub const OBJECT_WRITE_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;
pub const OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES: usize = 32 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_AUTHORIZATION_MAX_BYTES: usize = 16 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_RESPONSE_LOSS_MAX_BYTES: usize = 32 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_AMBIGUITY_RECEIPT_MAX_BYTES: usize = 48 * 1024;
pub const OBJECT_WRITE_GATEWAY_RECEIPT_MAX_BYTES: usize = 64 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_CONTROL_SCHEMA_VERSION: u64 = 16;
pub const OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME: &str = "object-write-credentials";
pub const OBJECT_WRITE_PRIVATE_KEY_FILE_SUFFIX: &str = ".pk8";
pub const OBJECT_WRITE_PREPARED_REGISTRATION_FILE_SUFFIX: &str = ".prepared.v1.json";
pub const OBJECT_WRITE_REGISTERED_ARTIFACT_FILE_SUFFIX: &str = ".registered.v1.json";

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

/// The only production-mutation admission class this protocol may consume.
///
/// This value maps one-for-one to E13's
/// `ProductionQualificationMutationClass::ObjectWriteAmbiguity`. Keeping the
/// exact wire spelling in the provider-neutral contract prevents a generic
/// qualification guard from authorizing another product mutation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWriteQualificationMutationClassV1 {
    ObjectWriteAmbiguity,
}

/// Attachment-signed request for one deterministic qualification-only fault.
///
/// `None` on the enclosing descriptor is the ordinary production path. A
/// caller cannot turn this marker into authority: the gateway must obtain a
/// live E13 transaction guard immediately around the real provider effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteQualificationFaultV1 {
    SuccessfulPutResponseLoss {
        qualification_id: Id,
        fault_id: RandomId128,
        qualification_catalog_sha256: Sha256Digest,
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
    /// Required in canonical JSON even when absent (`null`). The exact fault
    /// is therefore covered by the attachment signature and request digest.
    pub qualification_fault: Option<ObjectWriteQualificationFaultV1>,
}

/// Provider-neutral projection submitted to the mandatory qualification
/// authority. Workspace and release identity are deliberately absent: the
/// authority derives them from current Control state and returns them in the
/// authorization while holding the admission singleton lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationAuthorizationRequestV1 {
    pub version: ContractVersion,
    pub mutation_class: ObjectWriteQualificationMutationClassV1,
    pub request_id: Sha256Digest,
    pub writer_authority_id: Id,
    pub credential: ObjectWriteCredentialReference,
    pub provider_attempt_id: AsciiText,
    pub fault: ObjectWriteQualificationFaultV1,
    pub object_provider_scope: ProviderScope,
    pub object_store_scope_id: AsciiText,
    pub canonical_logical_key: String,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
}

/// Exact E13 authority returned with a transaction guard that remains live
/// through the successful provider PUT and durable response-loss receipt.
/// This is server-derived evidence, never a caller-supplied decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationAuthorizationV1 {
    pub version: ContractVersion,
    pub mutation_class: ObjectWriteQualificationMutationClassV1,
    pub qualification_id: Id,
    pub workspace_id: Id,
    pub deployment_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    pub control_schema_version: WireU64,
    pub qualification_catalog_sha256: Sha256Digest,
    pub admission_binding_sha256: Sha256Digest,
    pub admission_revision: Epoch,
    pub request: ObjectWriteQualificationAuthorizationRequestV1,
    pub authorized_at_unix_ms: UnixMillis,
    pub qualification_expires_at_unix_ms: UnixMillis,
}

/// Provider-returned request identity and checksum observation. This is an
/// observation, not authority and not a substitute for the exact HEAD oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteProviderRequestObservationV1 {
    pub request_id: AsciiText,
    pub extended_request_id: Option<AsciiText>,
    pub content_sha256: Sha256Digest,
    /// PUT responses may omit length; the terminal HEAD must provide it.
    pub content_length: Option<WireU64>,
    pub entity_tag: Option<AsciiText>,
    pub version_id: Option<AsciiText>,
}

/// Provider-neutral evidence returned only for a real successful conditional
/// PUT. Exact-replay visibility is a different outcome and cannot populate
/// this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteSuccessfulPutV1 {
    pub provider_attempt_id: AsciiText,
    pub put_receipt_id: AsciiText,
    pub provider_request: ObjectWriteProviderRequestObservationV1,
    pub completed_at_unix_ms: UnixMillis,
}

/// Durable proof that the guarded qualification transaction observed a real
/// successful PUT and committed the deliberate response-loss injection before
/// releasing the E13 shared lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationResponseLossV1 {
    pub version: ContractVersion,
    pub authorization: ObjectWriteQualificationAuthorizationV1,
    pub successful_put: ObjectWriteSuccessfulPutV1,
    pub injection_receipt_id: AsciiText,
    pub injected_at_unix_ms: UnixMillis,
}

/// Fresh exact visibility evidence obtained after the durable response-loss
/// state. The recovery state machine is HEAD-only from that boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationHeadEvidenceV1 {
    pub provider_attempt_id: AsciiText,
    pub visibility_receipt_id: AsciiText,
    pub provider_request: ObjectWriteProviderRequestObservationV1,
    pub observed_at_unix_ms: UnixMillis,
}

/// Closed proof for one deliberately lost successful PUT response followed by
/// exact HEAD discovery. It cannot be synthesized from an ordinary timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationAmbiguityReceiptV1 {
    pub version: ContractVersion,
    pub response_loss: ObjectWriteQualificationResponseLossV1,
    pub head: ObjectWriteQualificationHeadEvidenceV1,
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
        /// `Some` is valid only for a signed, admitted response-loss fault.
        /// Ordinary production success always carries explicit `null`.
        qualification_ambiguity: Option<Box<ObjectWriteQualificationAmbiguityReceiptV1>>,
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
    encode_bounded_receipt(receipt, OBJECT_WRITE_GATEWAY_RECEIPT_MAX_BYTES)
}

pub fn decode_object_write_gateway_receipt(
    bytes: &[u8],
) -> Result<ObjectWriteGatewayReceipt, ObjectWriteGatewayContractError> {
    if bytes.len() > OBJECT_WRITE_GATEWAY_RECEIPT_MAX_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
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

pub fn encode_object_write_qualification_authorization(
    authorization: &ObjectWriteQualificationAuthorizationV1,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_qualification_authorization(authorization)?;
    encode_bounded_receipt(
        authorization,
        OBJECT_WRITE_QUALIFICATION_AUTHORIZATION_MAX_BYTES,
    )
}

pub fn decode_object_write_qualification_authorization(
    bytes: &[u8],
) -> Result<ObjectWriteQualificationAuthorizationV1, ObjectWriteGatewayContractError> {
    decode_bounded_receipt(
        bytes,
        OBJECT_WRITE_QUALIFICATION_AUTHORIZATION_MAX_BYTES,
        validate_qualification_authorization,
    )
}

pub fn encode_object_write_qualification_response_loss(
    response_loss: &ObjectWriteQualificationResponseLossV1,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_qualification_response_loss(response_loss)?;
    encode_bounded_receipt(
        response_loss,
        OBJECT_WRITE_QUALIFICATION_RESPONSE_LOSS_MAX_BYTES,
    )
}

pub fn decode_object_write_qualification_response_loss(
    bytes: &[u8],
) -> Result<ObjectWriteQualificationResponseLossV1, ObjectWriteGatewayContractError> {
    decode_bounded_receipt(
        bytes,
        OBJECT_WRITE_QUALIFICATION_RESPONSE_LOSS_MAX_BYTES,
        validate_qualification_response_loss,
    )
}

pub fn encode_object_write_qualification_ambiguity_receipt(
    receipt: &ObjectWriteQualificationAmbiguityReceiptV1,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_qualification_ambiguity_receipt(receipt)?;
    encode_bounded_receipt(
        receipt,
        OBJECT_WRITE_QUALIFICATION_AMBIGUITY_RECEIPT_MAX_BYTES,
    )
}

pub fn decode_object_write_qualification_ambiguity_receipt(
    bytes: &[u8],
) -> Result<ObjectWriteQualificationAmbiguityReceiptV1, ObjectWriteGatewayContractError> {
    decode_bounded_receipt(
        bytes,
        OBJECT_WRITE_QUALIFICATION_AMBIGUITY_RECEIPT_MAX_BYTES,
        validate_qualification_ambiguity_receipt,
    )
}

pub fn object_write_qualification_authorization_sha256(
    authorization: &ObjectWriteQualificationAuthorizationV1,
) -> Result<Sha256Digest, ObjectWriteGatewayContractError> {
    let bytes = encode_object_write_qualification_authorization(authorization)?;
    let mut hasher = sha2::Sha256::new();
    hash_evidence_frame(
        &mut hasher,
        b"cats.object-write-qualification-authorization.v1",
    );
    hash_evidence_frame(&mut hasher, &bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

/// Content-addressed ID for the record committed by the still-held E13 guard.
/// Recomputing it makes drift in any qualification, Workspace, release,
/// request, writer, credential, provider-attempt or fault field fail closed.
pub fn object_write_qualification_injection_receipt_id(
    authorization: &ObjectWriteQualificationAuthorizationV1,
    successful_put: &ObjectWriteSuccessfulPutV1,
    injected_at_unix_ms: UnixMillis,
) -> Result<AsciiText, ObjectWriteGatewayContractError> {
    validate_qualification_authorization(authorization)?;
    validate_successful_put(authorization, successful_put)?;
    if successful_put.completed_at_unix_ms < authorization.authorized_at_unix_ms
        || injected_at_unix_ms < successful_put.completed_at_unix_ms
        || injected_at_unix_ms >= authorization.qualification_expires_at_unix_ms
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    let authorization_sha256 = object_write_qualification_authorization_sha256(authorization)?;
    let put_bytes = encode_bounded_receipt(
        successful_put,
        OBJECT_WRITE_QUALIFICATION_RESPONSE_LOSS_MAX_BYTES,
    )?;
    let mut hasher = sha2::Sha256::new();
    hash_evidence_frame(
        &mut hasher,
        b"cats.object-write-qualification-response-loss-injection.v1",
    );
    hash_evidence_frame(&mut hasher, authorization_sha256.as_str().as_bytes());
    hash_evidence_frame(&mut hasher, &put_bytes);
    hash_evidence_frame(&mut hasher, &injected_at_unix_ms.get().to_be_bytes());
    AsciiText::new(format!("owqinj1_{}", digest_hex(hasher)))
        .ok_or(ObjectWriteGatewayContractError::InvalidReceipt)
}

pub fn encode_object_write_credential_registration_receipt(
    receipt: &ObjectWriteCredentialRegistrationReceipt,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    if receipt.version != ContractVersion::V1 || receipt.attachment_epoch.get() == 0 {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    serde_json::to_vec(receipt).map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)
}

pub fn decode_object_write_credential_registration_receipt(
    bytes: &[u8],
) -> Result<ObjectWriteCredentialRegistrationReceipt, ObjectWriteGatewayContractError> {
    let receipt: ObjectWriteCredentialRegistrationReceipt = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?;
    if encode_object_write_credential_registration_receipt(&receipt)? != bytes {
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

fn validate_registered_artifact(
    artifact: &ObjectWriteCredentialRegisteredArtifact,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_credential_registration(&artifact.registration)?;
    if artifact.version != ContractVersion::V1
        || artifact.receipt.version != ContractVersion::V1
        || artifact.receipt.volume_id != artifact.registration.volume_id
        || artifact.receipt.attachment_id != artifact.registration.attachment_id
        || artifact.receipt.attachment_epoch != artifact.registration.attachment_epoch
        || artifact.receipt.credential != artifact.registration.credential
    {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    Ok(())
}

fn derived_attachment_id(
    domain: &[u8],
    prefix: &str,
    session: &SessionBinding,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
) -> Id {
    let mut hasher = sha2::Sha256::new();
    frame(&mut hasher, domain);
    frame(&mut hasher, session.node_id.as_str().as_bytes());
    frame(&mut hasher, session.node_boot_id.as_str().as_bytes());
    frame(&mut hasher, session.agent_instance_id.as_str().as_bytes());
    frame(
        &mut hasher,
        &session.agent_session_epoch.get().to_be_bytes(),
    );
    frame(&mut hasher, volume_id.as_str().as_bytes());
    frame(&mut hasher, attachment_id.as_str().as_bytes());
    frame(&mut hasher, &attachment_epoch.get().to_be_bytes());
    let value = format!("{prefix}{}", digest_hex(hasher));
    Id::new(value).expect("framed SHA-256 attachment IDs satisfy the Id contract")
}

fn derived_ascii(prefix: &str, hasher: sha2::Sha256) -> AsciiText {
    AsciiText::new(format!("{prefix}{}", digest_hex(hasher)))
        .expect("framed SHA-256 receipt IDs satisfy the AsciiText contract")
}

fn digest_hex(hasher: sha2::Sha256) -> String {
    let digest = Sha256Digest::from_bytes(hasher.finalize().into());
    digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("Sha256Digest always has the frozen prefix")
        .to_owned()
}

fn frame(hasher: &mut sha2::Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hash_evidence_frame(hasher: &mut sha2::Sha256, value: &[u8]) {
    frame(hasher, value);
}

fn validate_receipt(
    receipt: &ObjectWriteGatewayReceipt,
) -> Result<(), ObjectWriteGatewayContractError> {
    if receipt.version != ContractVersion::V1 || receipt.accepted_sequence.get() == 0 {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    match &receipt.terminal {
        ObjectWriteGatewayTerminalReceipt::SucceededVisible {
            put_receipt_id,
            put_completed_at_unix_ms,
            visibility_receipt_id,
            visible_at_unix_ms,
            qualification_ambiguity,
        } => {
            if put_completed_at_unix_ms > visible_at_unix_ms {
                return Err(ObjectWriteGatewayContractError::InvalidReceipt);
            }
            if let Some(ambiguity) = qualification_ambiguity {
                validate_qualification_ambiguity_receipt(ambiguity)?;
                let request = &ambiguity.response_loss.authorization.request;
                let put = &ambiguity.response_loss.successful_put;
                let head = &ambiguity.head;
                if request.request_id != receipt.request_id
                    || request.writer_authority_id != receipt.writer_authority_id
                    || put.put_receipt_id != *put_receipt_id
                    || put.completed_at_unix_ms != *put_completed_at_unix_ms
                    || head.visibility_receipt_id != *visibility_receipt_id
                    || head.observed_at_unix_ms != *visible_at_unix_ms
                {
                    return Err(ObjectWriteGatewayContractError::InvalidReceipt);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_qualification_authorization_request(
    request: &ObjectWriteQualificationAuthorizationRequestV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    let expected_provider_attempt = request
        .request_id
        .as_str()
        .strip_prefix("sha256:")
        .and_then(|value| AsciiText::new(format!("owpa1_{value}")))
        .ok_or(ObjectWriteGatewayContractError::InvalidReceipt)?;
    let key_is_canonical = (1..=1_024).contains(&request.canonical_logical_key.len())
        && request.canonical_logical_key.starts_with("volumes/")
        && !request.canonical_logical_key.starts_with('/')
        && !request.canonical_logical_key.ends_with('/')
        && !request.canonical_logical_key.contains("//")
        && !request
            .canonical_logical_key
            .split('/')
            .any(|part| part == "..")
        && request.canonical_logical_key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b':' | b'-')
        });
    if request.version != ContractVersion::V1
        || request.mutation_class != ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity
        || request.provider_attempt_id != expected_provider_attempt
        || request.content_length.get() > OBJECT_WRITE_BODY_MAX_BYTES as u64
        || !key_is_canonical
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn validate_qualification_authorization(
    authorization: &ObjectWriteQualificationAuthorizationV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_qualification_authorization_request(&authorization.request)?;
    let ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
        qualification_id,
        qualification_catalog_sha256,
        ..
    } = &authorization.request.fault;
    let source_commit_is_canonical = authorization.source_commit_sha.len() == 40
        && authorization
            .source_commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if authorization.version != ContractVersion::V1
        || authorization.mutation_class
            != ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity
        || authorization.mutation_class != authorization.request.mutation_class
        || authorization.qualification_id != *qualification_id
        || authorization.qualification_catalog_sha256 != *qualification_catalog_sha256
        || authorization.control_schema_version.get()
            != OBJECT_WRITE_QUALIFICATION_CONTROL_SCHEMA_VERSION
        || authorization.authorized_at_unix_ms >= authorization.qualification_expires_at_unix_ms
        || !source_commit_is_canonical
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn validate_provider_request_observation(
    observation: &ObjectWriteProviderRequestObservationV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    if observation
        .content_length
        .is_some_and(|length| length.get() > OBJECT_WRITE_BODY_MAX_BYTES as u64)
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn validate_qualification_response_loss(
    response_loss: &ObjectWriteQualificationResponseLossV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_qualification_authorization(&response_loss.authorization)?;
    validate_successful_put(&response_loss.authorization, &response_loss.successful_put)?;
    let authorization = &response_loss.authorization;
    let put = &response_loss.successful_put;
    if response_loss.version != ContractVersion::V1
        || put.completed_at_unix_ms < authorization.authorized_at_unix_ms
        || response_loss.injected_at_unix_ms < put.completed_at_unix_ms
        || response_loss.injected_at_unix_ms >= authorization.qualification_expires_at_unix_ms
        || response_loss.injection_receipt_id
            != object_write_qualification_injection_receipt_id(
                authorization,
                put,
                response_loss.injected_at_unix_ms,
            )?
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn validate_successful_put(
    authorization: &ObjectWriteQualificationAuthorizationV1,
    put: &ObjectWriteSuccessfulPutV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_provider_request_observation(&put.provider_request)?;
    let request = &authorization.request;
    if put.provider_attempt_id != request.provider_attempt_id
        || put.provider_request.content_sha256 != request.content_sha256
        || put
            .provider_request
            .content_length
            .is_some_and(|length| length != request.content_length)
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn validate_qualification_ambiguity_receipt(
    receipt: &ObjectWriteQualificationAmbiguityReceiptV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_qualification_response_loss(&receipt.response_loss)?;
    validate_provider_request_observation(&receipt.head.provider_request)?;
    let request = &receipt.response_loss.authorization.request;
    let put = &receipt.response_loss.successful_put;
    let head = &receipt.head;
    let etag_matches = put
        .provider_request
        .entity_tag
        .as_ref()
        .is_none_or(|value| head.provider_request.entity_tag.as_ref() == Some(value));
    let version_matches = put
        .provider_request
        .version_id
        .as_ref()
        .is_none_or(|value| head.provider_request.version_id.as_ref() == Some(value));
    if receipt.version != ContractVersion::V1
        || head.provider_attempt_id != request.provider_attempt_id
        || head.provider_request.request_id == put.provider_request.request_id
        || head.provider_request.content_sha256 != request.content_sha256
        || head.provider_request.content_length != Some(request.content_length)
        || head.observed_at_unix_ms < receipt.response_loss.injected_at_unix_ms
        || head.visibility_receipt_id == put.put_receipt_id
        || !etag_matches
        || !version_matches
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn encode_bounded_receipt<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?;
    if bytes.len() > maximum {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(bytes)
}

fn decode_bounded_receipt<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
    validate: fn(&T) -> Result<(), ObjectWriteGatewayContractError>,
) -> Result<T, ObjectWriteGatewayContractError> {
    if bytes.len() > maximum {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?;
    validate(&value)?;
    if encode_bounded_receipt(&value, maximum)? != bytes {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(value)
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

    fn ascii(value: &str) -> AsciiText {
        AsciiText::new(value).unwrap()
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn provider_scope() -> ProviderScope {
        ProviderScope {
            provider: id("object-provider"),
            partition: id("partition-a"),
            account_id: id("account-a"),
            region: id("region-a"),
        }
    }

    fn qualification_ambiguity_receipt() -> ObjectWriteQualificationAmbiguityReceiptV1 {
        let request_id = Sha256Digest::from_bytes([4; 32]);
        let provider_attempt_id = ascii(&format!(
            "owpa1_{}",
            request_id.as_str().strip_prefix("sha256:").unwrap()
        ));
        let content_sha256 = Sha256Digest::from_bytes([5; 32]);
        let fault = ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
            qualification_id: id("qualification-a"),
            fault_id: RandomId128::new("6".repeat(32)).unwrap(),
            qualification_catalog_sha256: Sha256Digest::from_bytes([7; 32]),
        };
        let request = ObjectWriteQualificationAuthorizationRequestV1 {
            version: ContractVersion::V1,
            mutation_class: ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity,
            request_id,
            writer_authority_id: id("writer-a"),
            credential: ObjectWriteCredentialReference {
                credential_id: id("credential-a"),
                public_key_spki_sha256: Sha256Digest::from_bytes([8; 32]),
            },
            provider_attempt_id: provider_attempt_id.clone(),
            fault,
            object_provider_scope: provider_scope(),
            object_store_scope_id: ascii("object-store-scope-a"),
            canonical_logical_key: "volumes/volume-a/maps/object.node".to_owned(),
            content_sha256: content_sha256.clone(),
            content_length: WireU64::new(64).unwrap(),
        };
        let authorization = ObjectWriteQualificationAuthorizationV1 {
            version: ContractVersion::V1,
            mutation_class: ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity,
            qualification_id: id("qualification-a"),
            workspace_id: id("workspace-a"),
            deployment_id: id("deployment-a"),
            release_id: id("release-a"),
            source_commit_sha: "a".repeat(40),
            control_schema_version: WireU64::new(16).unwrap(),
            qualification_catalog_sha256: Sha256Digest::from_bytes([7; 32]),
            admission_binding_sha256: Sha256Digest::from_bytes([9; 32]),
            admission_revision: Epoch::new(3).unwrap(),
            request,
            authorized_at_unix_ms: millis(10),
            qualification_expires_at_unix_ms: millis(100),
        };
        let successful_put = ObjectWriteSuccessfulPutV1 {
            provider_attempt_id: provider_attempt_id.clone(),
            put_receipt_id: ascii("put-receipt-a"),
            provider_request: ObjectWriteProviderRequestObservationV1 {
                request_id: ascii("provider-put-request-a"),
                extended_request_id: Some(ascii("provider-put-extended-a")),
                content_sha256: content_sha256.clone(),
                content_length: None,
                entity_tag: Some(ascii("entity-tag-a")),
                version_id: Some(ascii("version-a")),
            },
            completed_at_unix_ms: millis(20),
        };
        let injected_at_unix_ms = millis(21);
        let injection_receipt_id = object_write_qualification_injection_receipt_id(
            &authorization,
            &successful_put,
            injected_at_unix_ms,
        )
        .unwrap();
        ObjectWriteQualificationAmbiguityReceiptV1 {
            version: ContractVersion::V1,
            response_loss: ObjectWriteQualificationResponseLossV1 {
                version: ContractVersion::V1,
                authorization,
                successful_put,
                injection_receipt_id,
                injected_at_unix_ms,
            },
            head: ObjectWriteQualificationHeadEvidenceV1 {
                provider_attempt_id,
                visibility_receipt_id: ascii("visibility-receipt-a"),
                provider_request: ObjectWriteProviderRequestObservationV1 {
                    request_id: ascii("provider-head-request-a"),
                    extended_request_id: Some(ascii("provider-head-extended-a")),
                    content_sha256,
                    content_length: Some(WireU64::new(64).unwrap()),
                    entity_tag: Some(ascii("entity-tag-a")),
                    version_id: Some(ascii("version-a")),
                },
                observed_at_unix_ms: millis(30),
            },
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
            qualification_fault: None,
        })
        .unwrap();
        assert!(!String::from_utf8(encoded).unwrap().contains("metadata"));
    }

    #[test]
    fn descriptor_fault_is_explicit_null_or_exact_signed_closed_shape() {
        let ordinary = ObjectWriteIngressDescriptor {
            version: ContractVersion::V1,
            volume_id: id("volume-a"),
            key: ObjectWriteImmutableKey::VolumeMap,
            content_sha256: Sha256Digest::from_bytes([1; 32]),
            content_length: WireU64::new(64).unwrap(),
            qualification_fault: None,
        };
        let ordinary_bytes = encode_object_write_descriptor(&ordinary).unwrap();
        let ordinary_json = String::from_utf8(ordinary_bytes.clone()).unwrap();
        assert!(ordinary_json.ends_with("\"qualification_fault\":null}"));
        let omitted = ordinary_json.replace(",\"qualification_fault\":null", "");
        assert_eq!(
            decode_object_write_descriptor(omitted.as_bytes()),
            Err(ObjectWriteGatewayContractError::NonCanonicalDescriptor)
        );

        let mut qualified = ordinary;
        qualified.qualification_fault =
            Some(ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
                qualification_id: id("qualification-a"),
                fault_id: RandomId128::new("2".repeat(32)).unwrap(),
                qualification_catalog_sha256: Sha256Digest::from_bytes([3; 32]),
            });
        let qualified_bytes = encode_object_write_descriptor(&qualified).unwrap();
        let qualified_json = String::from_utf8(qualified_bytes.clone()).unwrap();
        assert!(qualified_json.contains("\"kind\":\"successful_put_response_loss\""));
        assert!(qualified_json.contains("\"fault_id\":\"22222222222222222222222222222222\""));
        assert_ne!(ordinary_bytes, qualified_bytes);
        let unknown = qualified_json.replacen(
            "\"qualification_id\"",
            "\"unknown\":true,\"qualification_id\"",
            1,
        );
        assert_eq!(
            decode_object_write_descriptor(unknown.as_bytes()),
            Err(ObjectWriteGatewayContractError::MalformedDescriptor)
        );
    }

    #[test]
    fn qualification_evidence_codecs_are_canonical_bounded_and_exactly_bound() {
        let receipt = qualification_ambiguity_receipt();
        let authorization = &receipt.response_loss.authorization;
        let authorization_bytes =
            encode_object_write_qualification_authorization(authorization).unwrap();
        assert_eq!(
            decode_object_write_qualification_authorization(&authorization_bytes).unwrap(),
            authorization.clone()
        );
        assert!(String::from_utf8(authorization_bytes.clone())
            .unwrap()
            .contains("\"mutation_class\":\"object_write_ambiguity\""));
        let response_loss_bytes =
            encode_object_write_qualification_response_loss(&receipt.response_loss).unwrap();
        assert_eq!(
            decode_object_write_qualification_response_loss(&response_loss_bytes).unwrap(),
            receipt.response_loss
        );
        let receipt_bytes = encode_object_write_qualification_ambiguity_receipt(&receipt).unwrap();
        assert_eq!(
            decode_object_write_qualification_ambiguity_receipt(&receipt_bytes).unwrap(),
            receipt
        );
        let pretty = serde_json::to_vec_pretty(&receipt).unwrap();
        assert_eq!(
            decode_object_write_qualification_ambiguity_receipt(&pretty),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );
        assert_eq!(
            decode_object_write_qualification_ambiguity_receipt(&vec![
                b'x';
                OBJECT_WRITE_QUALIFICATION_AMBIGUITY_RECEIPT_MAX_BYTES
                    + 1
            ]),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );
    }

    #[test]
    fn ambiguity_receipt_rejects_binding_or_head_drift() {
        let receipt = qualification_ambiguity_receipt();
        let request_id = receipt
            .response_loss
            .authorization
            .request
            .request_id
            .clone();
        let outer = ObjectWriteGatewayReceipt {
            version: ContractVersion::V1,
            writer_authority_id: id("writer-a"),
            request_id,
            accepted_sequence: WireU64::new(1).unwrap(),
            terminal: ObjectWriteGatewayTerminalReceipt::SucceededVisible {
                put_receipt_id: receipt.response_loss.successful_put.put_receipt_id.clone(),
                put_completed_at_unix_ms: receipt.response_loss.successful_put.completed_at_unix_ms,
                visibility_receipt_id: receipt.head.visibility_receipt_id.clone(),
                visible_at_unix_ms: receipt.head.observed_at_unix_ms,
                qualification_ambiguity: Some(Box::new(receipt.clone())),
            },
        };
        encode_object_write_gateway_receipt(&outer).unwrap();

        let mut wrong_workspace = receipt.clone();
        wrong_workspace.response_loss.authorization.workspace_id = id("workspace-b");
        assert_eq!(
            encode_object_write_qualification_ambiguity_receipt(&wrong_workspace),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );

        let mut wrong_head = receipt.clone();
        wrong_head.head.provider_request.content_length = Some(WireU64::new(63).unwrap());
        assert_eq!(
            encode_object_write_qualification_ambiguity_receipt(&wrong_head),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );

        let mut wrong_catalog = receipt;
        wrong_catalog
            .response_loss
            .authorization
            .qualification_catalog_sha256 = Sha256Digest::from_bytes([11; 32]);
        assert_eq!(
            encode_object_write_qualification_ambiguity_receipt(&wrong_catalog),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );
    }
}

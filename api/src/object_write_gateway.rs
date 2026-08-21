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
/// Exact Control route on which one authenticated Node reads its *own*
/// object-write writer authority. It is a Control management route, not a
/// Gateway route: the row lives in Control and the Node authenticates with the
/// same A19 proof it uses for every other `/v1/internal/runtime/...` call.
pub const OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH: &str =
    "/v1/internal/runtime/object-write-authority-reads";
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
pub const OBJECT_WRITE_WRITER_AUTHORITY_READ_MAX_WIRE_BYTES: usize = 4 * 1024;
pub const OBJECT_WRITE_WRITER_AUTHORITY_VIEW_MAX_WIRE_BYTES: usize = 4 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_AUTHORIZATION_MAX_BYTES: usize = 16 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_RESPONSE_LOSS_MAX_BYTES: usize = 32 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_HEAD_EVIDENCE_MAX_BYTES: usize = 16 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_SEALED_REQUEST_MAX_BYTES: usize = 32 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_UNPROVEN_RECEIPT_MAX_BYTES: usize = 48 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_AMBIGUITY_RECEIPT_MAX_BYTES: usize = 48 * 1024;
pub const OBJECT_WRITE_GATEWAY_RECEIPT_MAX_BYTES: usize = 64 * 1024;
pub const OBJECT_WRITE_QUALIFICATION_CONTROL_SCHEMA_VERSION: u64 = 18;
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

/// Provider-neutral classification of a conditional request which did not
/// create another object. The provider adapter may retain its opaque request
/// IDs, but no SDK error or provider-specific status crosses this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWriteConditionalRequestOutcomeV1 {
    PreconditionFailed,
}

/// Optional evidence that a legacy/already-issued retry observed the
/// immutable key's create precondition before the fresh exact HEAD. New
/// recovery code HEADs first and therefore normally leaves this `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteConditionalRequestEvidenceV1 {
    pub provider_attempt_id: AsciiText,
    pub outcome: ObjectWriteConditionalRequestOutcomeV1,
    pub provider_request: ObjectWriteProviderRequestObservationV1,
    pub observed_at_unix_ms: UnixMillis,
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

/// Fresh exact visibility evidence obtained after durable response-loss
/// discovery. A committed receipt makes recovery HEAD-only; an absent receipt
/// plus exact visibility closes as qualification-unproven without another PUT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationHeadEvidenceV1 {
    pub provider_attempt_id: AsciiText,
    pub visibility_receipt_id: AsciiText,
    /// `Some` only records a conditional precondition observed before this
    /// HEAD. It never proves that a successful PUT response was received.
    pub preceding_conditional_request: Option<Box<ObjectWriteConditionalRequestEvidenceV1>>,
    pub provider_request: ObjectWriteProviderRequestObservationV1,
    pub observed_at_unix_ms: UnixMillis,
}

/// A visible exact object can safely close the writer while still failing the
/// qualification: no durable guarded response-loss receipt exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWriteQualificationUnprovenReasonV1 {
    ResponseLossReceiptAbsent,
}

/// Full accepted request context sealed by the qualification resolution.
///
/// The signed ingress descriptor retains the structured immutable key and
/// fault marker. The server-derived authorization request independently binds
/// writer, credential and provider/store scope. Validation recomputes their
/// shared request identity instead of trusting either projection in isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationSealedRequestV1 {
    pub version: ContractVersion,
    pub accepted_sequence: WireU64,
    pub ingress_descriptor: ObjectWriteIngressDescriptor,
    pub authorization_request: ObjectWriteQualificationAuthorizationRequestV1,
    pub accepted_at_unix_ms: UnixMillis,
    pub issued_at_unix_ms: UnixMillis,
}

/// Durable fail-closed resolution for an exact-visible fault request which
/// has no committed successful-PUT response-loss receipt.
///
/// `resolved_at_unix_ms` and `resolution_receipt_id` are minted only by the
/// qualification authority while its per-request exclusive transaction is
/// still held. This is not an ambiguity qualification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteQualificationUnprovenVisibleReceiptV1 {
    pub version: ContractVersion,
    pub sealed_request: ObjectWriteQualificationSealedRequestV1,
    pub reason: ObjectWriteQualificationUnprovenReasonV1,
    pub head_evidence: ObjectWriteQualificationHeadEvidenceV1,
    pub resolution_receipt_id: AsciiText,
    pub resolved_at_unix_ms: UnixMillis,
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

/// Durable public registration artifact consumed by the Node and its exact
/// blockd child. It deliberately contains no private key bytes or ambient
/// filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteCredentialRegisteredArtifact {
    pub version: ContractVersion,
    pub registration: ObjectWriteCredentialRegistration,
    pub receipt: ObjectWriteCredentialRegistrationReceipt,
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
    QualificationUnprovenVisible {
        receipt: Box<ObjectWriteQualificationUnprovenVisibleReceiptV1>,
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
    #[error("object-write writer authority read or view is malformed or noncanonical")]
    InvalidWriterAuthorityRead,
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

pub fn encode_object_write_qualification_head_evidence(
    evidence: &ObjectWriteQualificationHeadEvidenceV1,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_qualification_head_evidence(evidence)?;
    encode_bounded_receipt(evidence, OBJECT_WRITE_QUALIFICATION_HEAD_EVIDENCE_MAX_BYTES)
}

pub fn decode_object_write_qualification_head_evidence(
    bytes: &[u8],
) -> Result<ObjectWriteQualificationHeadEvidenceV1, ObjectWriteGatewayContractError> {
    decode_bounded_receipt(
        bytes,
        OBJECT_WRITE_QUALIFICATION_HEAD_EVIDENCE_MAX_BYTES,
        validate_qualification_head_evidence,
    )
}

pub fn encode_object_write_qualification_sealed_request(
    request: &ObjectWriteQualificationSealedRequestV1,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_qualification_sealed_request(request)?;
    encode_bounded_receipt(request, OBJECT_WRITE_QUALIFICATION_SEALED_REQUEST_MAX_BYTES)
}

pub fn decode_object_write_qualification_sealed_request(
    bytes: &[u8],
) -> Result<ObjectWriteQualificationSealedRequestV1, ObjectWriteGatewayContractError> {
    decode_bounded_receipt(
        bytes,
        OBJECT_WRITE_QUALIFICATION_SEALED_REQUEST_MAX_BYTES,
        validate_qualification_sealed_request,
    )
}

pub fn encode_object_write_qualification_unproven_visible_receipt(
    receipt: &ObjectWriteQualificationUnprovenVisibleReceiptV1,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_qualification_unproven_visible_receipt(receipt)?;
    encode_bounded_receipt(
        receipt,
        OBJECT_WRITE_QUALIFICATION_UNPROVEN_RECEIPT_MAX_BYTES,
    )
}

pub fn decode_object_write_qualification_unproven_visible_receipt(
    bytes: &[u8],
) -> Result<ObjectWriteQualificationUnprovenVisibleReceiptV1, ObjectWriteGatewayContractError> {
    decode_bounded_receipt(
        bytes,
        OBJECT_WRITE_QUALIFICATION_UNPROVEN_RECEIPT_MAX_BYTES,
        validate_qualification_unproven_visible_receipt,
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

/// Content-addressed ID for the exclusive fail-closed visibility resolution.
/// The complete accepted descriptor projection, credential/scope projection,
/// HEAD evidence and PostgreSQL resolution time are all covered.
pub fn object_write_qualification_unproven_resolution_receipt_id(
    sealed_request: &ObjectWriteQualificationSealedRequestV1,
    reason: ObjectWriteQualificationUnprovenReasonV1,
    head_evidence: &ObjectWriteQualificationHeadEvidenceV1,
    resolved_at_unix_ms: UnixMillis,
) -> Result<AsciiText, ObjectWriteGatewayContractError> {
    validate_qualification_sealed_request(sealed_request)?;
    validate_qualification_unproven_head(sealed_request, reason, head_evidence)?;
    if resolved_at_unix_ms < head_evidence.observed_at_unix_ms {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    let sealed_bytes = encode_bounded_receipt(
        sealed_request,
        OBJECT_WRITE_QUALIFICATION_SEALED_REQUEST_MAX_BYTES,
    )?;
    let head_bytes = encode_bounded_receipt(
        head_evidence,
        OBJECT_WRITE_QUALIFICATION_HEAD_EVIDENCE_MAX_BYTES,
    )?;
    let mut hasher = sha2::Sha256::new();
    hash_evidence_frame(
        &mut hasher,
        b"cats.object-write-qualification-unproven-visible.v1",
    );
    hash_evidence_frame(&mut hasher, &sealed_bytes);
    hash_evidence_frame(&mut hasher, b"response-loss-receipt-absent");
    hash_evidence_frame(&mut hasher, &head_bytes);
    hash_evidence_frame(&mut hasher, &resolved_at_unix_ms.get().to_be_bytes());
    AsciiText::new(format!("owqunp1_{}", digest_hex(hasher)))
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

pub fn encode_object_write_credential_registered_artifact(
    artifact: &ObjectWriteCredentialRegisteredArtifact,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_registered_artifact(artifact)?;
    let bytes = serde_json::to_vec(artifact)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidCredentialRegistration)?;
    if bytes.len() > OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    Ok(bytes)
}

pub fn decode_object_write_credential_registered_artifact(
    bytes: &[u8],
) -> Result<ObjectWriteCredentialRegisteredArtifact, ObjectWriteGatewayContractError> {
    if bytes.len() > OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    let artifact: ObjectWriteCredentialRegisteredArtifact = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidCredentialRegistration)?;
    validate_registered_artifact(&artifact)?;
    if encode_object_write_credential_registered_artifact(&artifact)? != bytes {
        return Err(ObjectWriteGatewayContractError::InvalidCredentialRegistration);
    }
    Ok(artifact)
}

/// One Node asking Control which object-write writer authority its *own*
/// attachment credentials register under.
///
/// The request names only the asking Node's current Agent session. It carries
/// no authority ID, no Host identity and no other Node: Control derives the
/// answer from the authenticated A19 credential and refuses a session that is
/// not this credential's exact current one. A Node therefore cannot read
/// another Node's authority, and cannot assert an authority it was configured
/// with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteWriterAuthorityRead {
    pub version: ContractVersion,
    pub session: SessionBinding,
}

/// The complete closed set of answers to that read.
///
/// `Absent` is a typed answer, not an error: an operator has not run
/// `object-write-authority provision` for this Host yet. Every non-`Open`
/// answer must fail an object-write credential path closed; only `Open`
/// accepts a registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteWriterAuthorityStateV1 {
    Absent,
    Open { writer_authority_id: Id },
    CutoffPending { writer_authority_id: Id },
    CutoffComplete { writer_authority_id: Id },
}

impl ObjectWriteWriterAuthorityStateV1 {
    /// The authority ID a registration may name. `None` for every state in
    /// which Control would refuse the registration anyway, so a caller cannot
    /// accidentally publish under a cut-off writer.
    pub fn open_writer_authority_id(&self) -> Option<&Id> {
        match self {
            Self::Open {
                writer_authority_id,
            } => Some(writer_authority_id),
            Self::Absent | Self::CutoffPending { .. } | Self::CutoffComplete { .. } => None,
        }
    }

    /// Stable lowercase wire spelling of the state, for an operator-facing
    /// message. It never carries the authority ID.
    pub fn state_name(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Open { .. } => "open",
            Self::CutoffPending { .. } => "cutoff_pending",
            Self::CutoffComplete { .. } => "cutoff_complete",
        }
    }
}

/// Control's answer, echoing the exact session it was resolved for so a caller
/// can reject a response that belongs to another session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteWriterAuthorityView {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub authority: ObjectWriteWriterAuthorityStateV1,
}

fn validate_writer_authority_read(
    request: &ObjectWriteWriterAuthorityRead,
) -> Result<(), ObjectWriteGatewayContractError> {
    if request.version != ContractVersion::V1 {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    Ok(())
}

fn validate_writer_authority_view(
    view: &ObjectWriteWriterAuthorityView,
) -> Result<(), ObjectWriteGatewayContractError> {
    if view.version != ContractVersion::V1 {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    let assigned = match &view.authority {
        ObjectWriteWriterAuthorityStateV1::Absent => None,
        ObjectWriteWriterAuthorityStateV1::Open {
            writer_authority_id,
        }
        | ObjectWriteWriterAuthorityStateV1::CutoffPending {
            writer_authority_id,
        }
        | ObjectWriteWriterAuthorityStateV1::CutoffComplete {
            writer_authority_id,
        } => Some(writer_authority_id),
    };
    // Only Control assigns this ID and its shape is closed, so a value that is
    // not `owa1_<64 lowercase hex>` cannot have come from the derivation.
    if assigned.is_some_and(|id| {
        !crate::runtime_reconciliation::valid_object_write_writer_authority_id(id.as_str())
    }) {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    Ok(())
}

pub fn encode_object_write_writer_authority_read(
    request: &ObjectWriteWriterAuthorityRead,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_writer_authority_read(request)?;
    let bytes = serde_json::to_vec(request)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidWriterAuthorityRead)?;
    if bytes.len() > OBJECT_WRITE_WRITER_AUTHORITY_READ_MAX_WIRE_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    Ok(bytes)
}

pub fn decode_object_write_writer_authority_read(
    bytes: &[u8],
) -> Result<ObjectWriteWriterAuthorityRead, ObjectWriteGatewayContractError> {
    if bytes.len() > OBJECT_WRITE_WRITER_AUTHORITY_READ_MAX_WIRE_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    let request: ObjectWriteWriterAuthorityRead = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidWriterAuthorityRead)?;
    validate_writer_authority_read(&request)?;
    if encode_object_write_writer_authority_read(&request)? != bytes {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    Ok(request)
}

pub fn encode_object_write_writer_authority_view(
    view: &ObjectWriteWriterAuthorityView,
) -> Result<Vec<u8>, ObjectWriteGatewayContractError> {
    validate_writer_authority_view(view)?;
    let bytes = serde_json::to_vec(view)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidWriterAuthorityRead)?;
    if bytes.len() > OBJECT_WRITE_WRITER_AUTHORITY_VIEW_MAX_WIRE_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    Ok(bytes)
}

pub fn decode_object_write_writer_authority_view(
    bytes: &[u8],
) -> Result<ObjectWriteWriterAuthorityView, ObjectWriteGatewayContractError> {
    if bytes.len() > OBJECT_WRITE_WRITER_AUTHORITY_VIEW_MAX_WIRE_BYTES {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    let view: ObjectWriteWriterAuthorityView = serde_json::from_slice(bytes)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidWriterAuthorityRead)?;
    validate_writer_authority_view(&view)?;
    if encode_object_write_writer_authority_view(&view)? != bytes {
        return Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead);
    }
    Ok(view)
}

/// Stable credential identity for one exact session-bound attachment.
/// Random key bytes are generated and persisted separately; they are never
/// derived from this identifier.
pub fn object_write_credential_id(
    session: &SessionBinding,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
) -> Id {
    derived_attachment_id(
        b"cats.object-write.attachment-credential-id.v1",
        "owcred1_",
        session,
        volume_id,
        attachment_id,
        attachment_epoch,
    )
}

/// Stable root-only private artifact identity for the same attachment.
pub fn object_write_private_artifact_id(
    session: &SessionBinding,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
) -> Id {
    derived_attachment_id(
        b"cats.object-write.private-artifact-id.v1",
        "owpriv1_",
        session,
        volume_id,
        attachment_id,
        attachment_epoch,
    )
}

pub fn object_write_private_file_fsync_receipt_id(
    private_artifact_id: &Id,
    credential: &ObjectWriteCredentialReference,
) -> AsciiText {
    let mut hasher = sha2::Sha256::new();
    frame(&mut hasher, b"cats.object-write.private-file-fsync.v1");
    frame(&mut hasher, private_artifact_id.as_str().as_bytes());
    frame(&mut hasher, credential.credential_id.as_str().as_bytes());
    frame(
        &mut hasher,
        credential.public_key_spki_sha256.as_str().as_bytes(),
    );
    derived_ascii("owfilefsync1_", hasher)
}

pub fn object_write_private_directory_fsync_receipt_id(
    private_artifact_id: &Id,
    file_receipt_id: &AsciiText,
) -> AsciiText {
    let mut hasher = sha2::Sha256::new();
    frame(&mut hasher, b"cats.object-write.private-directory-fsync.v1");
    frame(&mut hasher, private_artifact_id.as_str().as_bytes());
    frame(&mut hasher, file_receipt_id.as_str().as_bytes());
    derived_ascii("owdirfsync1_", hasher)
}

pub fn object_write_private_key_file_name(private_artifact_id: &Id) -> String {
    format!(
        "{}{OBJECT_WRITE_PRIVATE_KEY_FILE_SUFFIX}",
        private_artifact_id.as_str()
    )
}

/// Stable locator for one attachment/epoch's pre-registration sidecar. It
/// excludes the Agent session so a replacement Agent can recover the exact
/// body after external registration commits.
pub fn object_write_prepared_registration_file_name(
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
) -> String {
    let mut hasher = sha2::Sha256::new();
    frame(
        &mut hasher,
        b"cats.object-write.prepared-registration-file.v1",
    );
    frame(&mut hasher, volume_id.as_str().as_bytes());
    frame(&mut hasher, attachment_id.as_str().as_bytes());
    frame(&mut hasher, &attachment_epoch.get().to_be_bytes());
    format!(
        "owprepared1_{}{OBJECT_WRITE_PREPARED_REGISTRATION_FILE_SUFFIX}",
        digest_hex(hasher)
    )
}

pub fn object_write_registered_artifact_file_name(credential_id: &Id) -> String {
    format!(
        "{}{OBJECT_WRITE_REGISTERED_ARTIFACT_FILE_SUFFIX}",
        credential_id.as_str()
    )
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
        ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible { receipt: unproven } => {
            validate_qualification_unproven_visible_receipt(unproven)?;
            let sealed = &unproven.sealed_request;
            if sealed.authorization_request.request_id != receipt.request_id
                || sealed.authorization_request.writer_authority_id != receipt.writer_authority_id
                || sealed.accepted_sequence != receipt.accepted_sequence
            {
                return Err(ObjectWriteGatewayContractError::InvalidReceipt);
            }
            Ok(())
        }
        ObjectWriteGatewayTerminalReceipt::PermanentlyFailed { .. } => Ok(()),
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

fn validate_qualification_sealed_request(
    sealed: &ObjectWriteQualificationSealedRequestV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_descriptor(&sealed.ingress_descriptor)
        .map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?;
    validate_qualification_authorization_request(&sealed.authorization_request)?;
    let ingress = &sealed.ingress_descriptor;
    let request = &sealed.authorization_request;
    let Some(fault) = ingress.qualification_fault.as_ref() else {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    };
    let canonical_logical_key =
        object_write_key(&ingress.volume_id, &ingress.key, &ingress.content_sha256)
            .map_err(|_| ObjectWriteGatewayContractError::InvalidReceipt)?;
    if sealed.version != ContractVersion::V1
        || sealed.accepted_sequence.get() == 0
        || sealed.issued_at_unix_ms < sealed.accepted_at_unix_ms
        || request.fault != *fault
        || request.canonical_logical_key != canonical_logical_key
        || request.content_sha256 != ingress.content_sha256
        || request.content_length != ingress.content_length
        || request.request_id != qualification_sealed_request_id(sealed)?
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn qualification_sealed_request_id(
    sealed: &ObjectWriteQualificationSealedRequestV1,
) -> Result<Sha256Digest, ObjectWriteGatewayContractError> {
    let ingress = &sealed.ingress_descriptor;
    let request = &sealed.authorization_request;
    let canonical_logical_key =
        object_write_key(&ingress.volume_id, &ingress.key, &ingress.content_sha256)?;
    if request.canonical_logical_key != canonical_logical_key {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    let mut hasher = sha2::Sha256::new();
    hash_evidence_frame(&mut hasher, b"cats.object-write-request.v1");
    hash_evidence_frame(&mut hasher, request.writer_authority_id.as_str().as_bytes());
    hash_evidence_frame(
        &mut hasher,
        request.object_provider_scope.provider.as_str().as_bytes(),
    );
    hash_evidence_frame(
        &mut hasher,
        request.object_provider_scope.partition.as_str().as_bytes(),
    );
    hash_evidence_frame(
        &mut hasher,
        request.object_provider_scope.account_id.as_str().as_bytes(),
    );
    hash_evidence_frame(
        &mut hasher,
        request.object_provider_scope.region.as_str().as_bytes(),
    );
    hash_evidence_frame(
        &mut hasher,
        request.object_store_scope_id.as_str().as_bytes(),
    );
    hash_evidence_frame(&mut hasher, ingress.volume_id.as_str().as_bytes());
    hash_evidence_frame(&mut hasher, canonical_logical_key.as_bytes());
    hash_evidence_frame(&mut hasher, ingress.content_sha256.as_str().as_bytes());
    hash_evidence_frame(&mut hasher, &ingress.content_length.get().to_be_bytes());
    let ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
        qualification_id,
        fault_id,
        qualification_catalog_sha256,
    } = &request.fault;
    hash_evidence_frame(&mut hasher, b"qualification-credential");
    hash_evidence_frame(
        &mut hasher,
        request.credential.credential_id.as_str().as_bytes(),
    );
    hash_evidence_frame(
        &mut hasher,
        request
            .credential
            .public_key_spki_sha256
            .as_str()
            .as_bytes(),
    );
    hash_evidence_frame(
        &mut hasher,
        b"qualification-fault:successful-put-response-loss",
    );
    hash_evidence_frame(&mut hasher, qualification_id.as_str().as_bytes());
    hash_evidence_frame(&mut hasher, fault_id.as_str().as_bytes());
    hash_evidence_frame(
        &mut hasher,
        qualification_catalog_sha256.as_str().as_bytes(),
    );
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
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

fn validate_qualification_head_evidence(
    evidence: &ObjectWriteQualificationHeadEvidenceV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_provider_request_observation(&evidence.provider_request)?;
    let Some(head_length) = evidence.provider_request.content_length else {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    };
    if let Some(conditional) = &evidence.preceding_conditional_request {
        validate_provider_request_observation(&conditional.provider_request)?;
        if conditional.provider_attempt_id != evidence.provider_attempt_id
            || conditional.outcome != ObjectWriteConditionalRequestOutcomeV1::PreconditionFailed
            || conditional.provider_request.request_id == evidence.provider_request.request_id
            || conditional.provider_request.content_sha256
                != evidence.provider_request.content_sha256
            || conditional
                .provider_request
                .content_length
                .is_some_and(|length| length != head_length)
            || conditional.observed_at_unix_ms > evidence.observed_at_unix_ms
        {
            return Err(ObjectWriteGatewayContractError::InvalidReceipt);
        }
    }
    Ok(())
}

fn validate_qualification_unproven_head(
    sealed_request: &ObjectWriteQualificationSealedRequestV1,
    reason: ObjectWriteQualificationUnprovenReasonV1,
    head_evidence: &ObjectWriteQualificationHeadEvidenceV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    validate_qualification_sealed_request(sealed_request)?;
    validate_qualification_head_evidence(head_evidence)?;
    let request = &sealed_request.authorization_request;
    if reason != ObjectWriteQualificationUnprovenReasonV1::ResponseLossReceiptAbsent
        || head_evidence.provider_attempt_id != request.provider_attempt_id
        || head_evidence.provider_request.content_sha256 != request.content_sha256
        || head_evidence.provider_request.content_length != Some(request.content_length)
        || head_evidence.observed_at_unix_ms < sealed_request.issued_at_unix_ms
        || head_evidence
            .preceding_conditional_request
            .as_ref()
            .is_some_and(|conditional| {
                conditional.observed_at_unix_ms < sealed_request.issued_at_unix_ms
            })
    {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    Ok(())
}

fn validate_qualification_unproven_visible_receipt(
    receipt: &ObjectWriteQualificationUnprovenVisibleReceiptV1,
) -> Result<(), ObjectWriteGatewayContractError> {
    if receipt.version != ContractVersion::V1 {
        return Err(ObjectWriteGatewayContractError::InvalidReceipt);
    }
    validate_qualification_unproven_head(
        &receipt.sealed_request,
        receipt.reason,
        &receipt.head_evidence,
    )?;
    if receipt.resolved_at_unix_ms < receipt.head_evidence.observed_at_unix_ms
        || receipt.resolution_receipt_id
            != object_write_qualification_unproven_resolution_receipt_id(
                &receipt.sealed_request,
                receipt.reason,
                &receipt.head_evidence,
                receipt.resolved_at_unix_ms,
            )?
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
    validate_qualification_head_evidence(&receipt.head)?;
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
        || head.preceding_conditional_request.is_some()
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
            control_schema_version: WireU64::new(OBJECT_WRITE_QUALIFICATION_CONTROL_SCHEMA_VERSION)
                .unwrap(),
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
                preceding_conditional_request: None,
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

    fn qualification_unproven_receipt() -> ObjectWriteQualificationUnprovenVisibleReceiptV1 {
        let content_sha256 = Sha256Digest::from_bytes([5; 32]);
        let fault = ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
            qualification_id: id("qualification-a"),
            fault_id: RandomId128::new("6".repeat(32)).unwrap(),
            qualification_catalog_sha256: Sha256Digest::from_bytes([7; 32]),
        };
        let ingress_descriptor = ObjectWriteIngressDescriptor {
            version: ContractVersion::V1,
            volume_id: id("volume-a"),
            key: ObjectWriteImmutableKey::VolumeMap,
            content_sha256: content_sha256.clone(),
            content_length: WireU64::new(64).unwrap(),
            qualification_fault: Some(fault.clone()),
        };
        let placeholder_request_id = Sha256Digest::from_bytes([0; 32]);
        let authorization_request = ObjectWriteQualificationAuthorizationRequestV1 {
            version: ContractVersion::V1,
            mutation_class: ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity,
            request_id: placeholder_request_id.clone(),
            writer_authority_id: id("writer-a"),
            credential: ObjectWriteCredentialReference {
                credential_id: id("credential-a"),
                public_key_spki_sha256: Sha256Digest::from_bytes([8; 32]),
            },
            provider_attempt_id: ascii(&format!(
                "owpa1_{}",
                placeholder_request_id
                    .as_str()
                    .strip_prefix("sha256:")
                    .unwrap()
            )),
            fault,
            object_provider_scope: provider_scope(),
            object_store_scope_id: ascii("object-store-scope-a"),
            canonical_logical_key: object_write_key(
                &ingress_descriptor.volume_id,
                &ingress_descriptor.key,
                &ingress_descriptor.content_sha256,
            )
            .unwrap(),
            content_sha256: content_sha256.clone(),
            content_length: ingress_descriptor.content_length,
        };
        let mut sealed_request = ObjectWriteQualificationSealedRequestV1 {
            version: ContractVersion::V1,
            accepted_sequence: WireU64::new(1).unwrap(),
            ingress_descriptor,
            authorization_request,
            accepted_at_unix_ms: millis(12),
            issued_at_unix_ms: millis(13),
        };
        let request_id = qualification_sealed_request_id(&sealed_request).unwrap();
        sealed_request.authorization_request.request_id = request_id.clone();
        sealed_request.authorization_request.provider_attempt_id = ascii(&format!(
            "owpa1_{}",
            request_id.as_str().strip_prefix("sha256:").unwrap()
        ));
        let head_evidence = ObjectWriteQualificationHeadEvidenceV1 {
            provider_attempt_id: sealed_request
                .authorization_request
                .provider_attempt_id
                .clone(),
            visibility_receipt_id: ascii("visibility-unproven-a"),
            preceding_conditional_request: Some(Box::new(
                ObjectWriteConditionalRequestEvidenceV1 {
                    provider_attempt_id: sealed_request
                        .authorization_request
                        .provider_attempt_id
                        .clone(),
                    outcome: ObjectWriteConditionalRequestOutcomeV1::PreconditionFailed,
                    provider_request: ObjectWriteProviderRequestObservationV1 {
                        request_id: ascii("provider-conditional-request-a"),
                        extended_request_id: Some(ascii("provider-conditional-extended-a")),
                        content_sha256: content_sha256.clone(),
                        content_length: Some(WireU64::new(64).unwrap()),
                        entity_tag: None,
                        version_id: None,
                    },
                    observed_at_unix_ms: millis(29),
                },
            )),
            provider_request: ObjectWriteProviderRequestObservationV1 {
                request_id: ascii("provider-head-unproven-a"),
                extended_request_id: Some(ascii("provider-head-unproven-extended-a")),
                content_sha256,
                content_length: Some(WireU64::new(64).unwrap()),
                entity_tag: Some(ascii("entity-tag-unproven-a")),
                version_id: Some(ascii("version-unproven-a")),
            },
            observed_at_unix_ms: millis(30),
        };
        let reason = ObjectWriteQualificationUnprovenReasonV1::ResponseLossReceiptAbsent;
        let resolved_at_unix_ms = millis(31);
        let resolution_receipt_id = object_write_qualification_unproven_resolution_receipt_id(
            &sealed_request,
            reason,
            &head_evidence,
            resolved_at_unix_ms,
        )
        .unwrap();
        ObjectWriteQualificationUnprovenVisibleReceiptV1 {
            version: ContractVersion::V1,
            sealed_request,
            reason,
            head_evidence,
            resolution_receipt_id,
            resolved_at_unix_ms,
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
        let head_bytes = encode_object_write_qualification_head_evidence(&receipt.head).unwrap();
        assert_eq!(
            decode_object_write_qualification_head_evidence(&head_bytes).unwrap(),
            receipt.head
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
        assert_eq!(
            decode_object_write_qualification_head_evidence(&vec![
                b'x';
                OBJECT_WRITE_QUALIFICATION_HEAD_EVIDENCE_MAX_BYTES
                    + 1
            ]),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );
        let unproven = qualification_unproven_receipt();
        let sealed_bytes =
            encode_object_write_qualification_sealed_request(&unproven.sealed_request).unwrap();
        assert_eq!(
            decode_object_write_qualification_sealed_request(&sealed_bytes).unwrap(),
            unproven.sealed_request
        );
        let unproven_bytes =
            encode_object_write_qualification_unproven_visible_receipt(&unproven).unwrap();
        assert_eq!(
            decode_object_write_qualification_unproven_visible_receipt(&unproven_bytes).unwrap(),
            unproven
        );
        assert_eq!(
            decode_object_write_qualification_unproven_visible_receipt(&vec![
                b'x';
                OBJECT_WRITE_QUALIFICATION_UNPROVEN_RECEIPT_MAX_BYTES
                    + 1
            ]),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );
    }

    #[test]
    fn unproven_visible_is_a_distinct_bounded_terminal_without_ambiguity_proof() {
        let unproven = qualification_unproven_receipt();
        let request = &unproven.sealed_request.authorization_request;
        let receipt = ObjectWriteGatewayReceipt {
            version: ContractVersion::V1,
            writer_authority_id: request.writer_authority_id.clone(),
            request_id: request.request_id.clone(),
            accepted_sequence: unproven.sealed_request.accepted_sequence,
            terminal: ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible {
                receipt: Box::new(unproven.clone()),
            },
        };
        let bytes = encode_object_write_gateway_receipt(&receipt).unwrap();
        assert_eq!(
            decode_object_write_gateway_receipt(&bytes).unwrap(),
            receipt
        );
        let wire = String::from_utf8(bytes).unwrap();
        assert!(wire.contains("\"kind\":\"qualification_unproven_visible\""));
        assert!(wire.contains("\"reason\":\"response_loss_receipt_absent\""));
        assert!(!wire.contains("qualification_ambiguity"));

        let mut wrong_attempt = receipt.clone();
        let ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible { receipt: unproven } =
            &mut wrong_attempt.terminal
        else {
            unreachable!("fixture is the unproven terminal")
        };
        unproven.head_evidence.provider_attempt_id = ascii("owpa1_wrong");
        assert_eq!(
            encode_object_write_gateway_receipt(&wrong_attempt),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );

        let mut wrong_conditional = qualification_unproven_receipt().head_evidence;
        wrong_conditional
            .preceding_conditional_request
            .as_mut()
            .unwrap()
            .provider_request
            .request_id = wrong_conditional.provider_request.request_id.clone();
        assert_eq!(
            encode_object_write_qualification_head_evidence(&wrong_conditional),
            Err(ObjectWriteGatewayContractError::InvalidReceipt)
        );
    }

    #[test]
    fn unproven_receipt_rejects_every_sealed_request_binding_drift() {
        fn assert_invalid(receipt: ObjectWriteQualificationUnprovenVisibleReceiptV1) {
            assert_eq!(
                encode_object_write_qualification_unproven_visible_receipt(&receipt),
                Err(ObjectWriteGatewayContractError::InvalidReceipt)
            );
        }

        let valid = qualification_unproven_receipt();

        let mut wrong_sha = valid.clone();
        wrong_sha.sealed_request.ingress_descriptor.content_sha256 =
            Sha256Digest::from_bytes([10; 32]);
        assert_invalid(wrong_sha);

        let mut wrong_length = valid.clone();
        wrong_length
            .sealed_request
            .authorization_request
            .content_length = WireU64::new(65).unwrap();
        assert_invalid(wrong_length);

        let mut wrong_credential = valid.clone();
        wrong_credential
            .sealed_request
            .authorization_request
            .credential
            .credential_id = id("credential-b");
        assert_invalid(wrong_credential);

        let mut wrong_fault = valid.clone();
        let ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss { fault_id, .. } =
            &mut wrong_fault.sealed_request.authorization_request.fault;
        *fault_id = RandomId128::new("a".repeat(32)).unwrap();
        assert_invalid(wrong_fault);

        let mut wrong_provider_scope = valid.clone();
        wrong_provider_scope
            .sealed_request
            .authorization_request
            .object_provider_scope
            .region = id("region-b");
        assert_invalid(wrong_provider_scope);

        let mut wrong_store_scope = valid.clone();
        wrong_store_scope
            .sealed_request
            .authorization_request
            .object_store_scope_id = ascii("object-store-scope-b");
        assert_invalid(wrong_store_scope);

        let mut wrong_key = valid;
        wrong_key.sealed_request.ingress_descriptor.key = ObjectWriteImmutableKey::VolumeCommit {
            generation: Generation::new(1).unwrap(),
            transaction_id: RandomId128::new("b".repeat(32)).unwrap(),
        };
        assert_invalid(wrong_key);
    }

    #[test]
    fn credential_drift_with_coordinated_inner_rehash_still_fails_accepted_request_anchor() {
        let original = qualification_unproven_receipt();
        let mut gateway = ObjectWriteGatewayReceipt {
            version: ContractVersion::V1,
            writer_authority_id: original
                .sealed_request
                .authorization_request
                .writer_authority_id
                .clone(),
            request_id: original
                .sealed_request
                .authorization_request
                .request_id
                .clone(),
            accepted_sequence: original.sealed_request.accepted_sequence,
            terminal: ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible {
                receipt: Box::new(original),
            },
        };
        let ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible { receipt } =
            &mut gateway.terminal
        else {
            unreachable!("fixture is unproven");
        };
        receipt
            .sealed_request
            .authorization_request
            .credential
            .credential_id = id("credential-b");
        let rehashed_request_id = qualification_sealed_request_id(&receipt.sealed_request).unwrap();
        let rehashed_attempt = ascii(&format!(
            "owpa1_{}",
            rehashed_request_id
                .as_str()
                .strip_prefix("sha256:")
                .unwrap()
        ));
        receipt.sealed_request.authorization_request.request_id = rehashed_request_id;
        receipt
            .sealed_request
            .authorization_request
            .provider_attempt_id = rehashed_attempt.clone();
        receipt.head_evidence.provider_attempt_id = rehashed_attempt.clone();
        receipt
            .head_evidence
            .preceding_conditional_request
            .as_mut()
            .unwrap()
            .provider_attempt_id = rehashed_attempt;
        receipt.resolution_receipt_id = object_write_qualification_unproven_resolution_receipt_id(
            &receipt.sealed_request,
            receipt.reason,
            &receipt.head_evidence,
            receipt.resolved_at_unix_ms,
        )
        .unwrap();

        assert_eq!(
            encode_object_write_gateway_receipt(&gateway),
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

    fn session_binding(epoch: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("1".repeat(32)).unwrap(),
            agent_instance_id: RandomId128::new("2".repeat(32)).unwrap(),
            agent_session_epoch: Epoch::new(epoch).unwrap(),
        }
    }

    fn assigned_authority_id() -> Id {
        id(&format!("owa1_{}", "5b".repeat(32)))
    }

    /// The read is only a session; there is deliberately no field in which a
    /// caller could assert an authority ID or another Node.
    #[test]
    fn a_writer_authority_read_round_trips_and_rejects_noncanonical_bytes() {
        let request = ObjectWriteWriterAuthorityRead {
            version: ContractVersion::V1,
            session: session_binding(7),
        };
        let bytes = encode_object_write_writer_authority_read(&request).unwrap();
        assert_eq!(
            decode_object_write_writer_authority_read(&bytes).unwrap(),
            request
        );

        let mut padded = bytes.clone();
        padded.push(b' ');
        assert_eq!(
            decode_object_write_writer_authority_read(&padded),
            Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead)
        );
        assert_eq!(
            decode_object_write_writer_authority_read(
                br#"{"version":"v1","session":null,"writer_authority_id":"owa1_x"}"#
            ),
            Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead),
            "the read contract has no authority field to assert"
        );
        assert_eq!(
            decode_object_write_writer_authority_read(&[]),
            Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead)
        );
    }

    /// Every closed answer round-trips, and only Control's derived ID shape is
    /// representable: a caller-chosen value is not decodable at all.
    #[test]
    fn every_writer_authority_state_round_trips_and_only_open_yields_an_id() {
        for authority in [
            ObjectWriteWriterAuthorityStateV1::Absent,
            ObjectWriteWriterAuthorityStateV1::Open {
                writer_authority_id: assigned_authority_id(),
            },
            ObjectWriteWriterAuthorityStateV1::CutoffPending {
                writer_authority_id: assigned_authority_id(),
            },
            ObjectWriteWriterAuthorityStateV1::CutoffComplete {
                writer_authority_id: assigned_authority_id(),
            },
        ] {
            let open = matches!(authority, ObjectWriteWriterAuthorityStateV1::Open { .. });
            let view = ObjectWriteWriterAuthorityView {
                version: ContractVersion::V1,
                session: session_binding(7),
                authority: authority.clone(),
            };
            let bytes = encode_object_write_writer_authority_view(&view).unwrap();
            assert_eq!(
                decode_object_write_writer_authority_view(&bytes).unwrap(),
                view
            );
            assert_eq!(
                authority.open_writer_authority_id().is_some(),
                open,
                "only an open authority may hand out an ID to register under"
            );
            assert!(bytes
                .windows(authority.state_name().len())
                .any(|window| window == authority.state_name().as_bytes()));
        }
    }

    #[test]
    fn a_view_whose_authority_id_is_not_controls_derivation_is_refused() {
        for rejected in [
            "writer_a",
            "owa1_",
            &format!("owa1_{}", "5B".repeat(32)),
            &format!("owa1_{}", "5b".repeat(31)),
        ] {
            let view = ObjectWriteWriterAuthorityView {
                version: ContractVersion::V1,
                session: session_binding(7),
                authority: ObjectWriteWriterAuthorityStateV1::Open {
                    writer_authority_id: id(rejected),
                },
            };
            assert_eq!(
                encode_object_write_writer_authority_view(&view),
                Err(ObjectWriteGatewayContractError::InvalidWriterAuthorityRead),
                "{rejected} is not an assigned writer authority ID"
            );
        }
        // Calibration: the derived shape encodes.
        assert!(
            encode_object_write_writer_authority_view(&ObjectWriteWriterAuthorityView {
                version: ContractVersion::V1,
                session: session_binding(7),
                authority: ObjectWriteWriterAuthorityStateV1::Open {
                    writer_authority_id: assigned_authority_id(),
                },
            })
            .is_ok()
        );
    }
}

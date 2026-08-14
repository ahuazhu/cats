//! Provider-neutral authority for Host-scoped immutable object writes.
//!
//! The gateway first durably spools and verifies a body, then records its
//! acceptance before invoking a provider. It is the only process that owns
//! object-store write credentials. Closing an authority snapshots only the
//! assigned accepted sequence and prevents any later acceptance.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use cats_api::object_write_gateway::{
    encode_object_write_qualification_ambiguity_receipt,
    encode_object_write_qualification_authorization,
    encode_object_write_qualification_response_loss,
    encode_object_write_qualification_sealed_request,
    encode_object_write_qualification_unproven_visible_receipt, object_write_key,
    object_write_qualification_authorization_sha256, ObjectWriteConditionalRequestEvidenceV1,
    ObjectWriteCredentialReference, ObjectWriteCredentialRegistration, ObjectWriteImmutableKey,
    ObjectWriteIngressDescriptor, ObjectWriteProviderRequestObservationV1,
    ObjectWriteQualificationAmbiguityReceiptV1, ObjectWriteQualificationAuthorizationRequestV1,
    ObjectWriteQualificationAuthorizationV1, ObjectWriteQualificationFaultV1,
    ObjectWriteQualificationHeadEvidenceV1, ObjectWriteQualificationMutationClassV1,
    ObjectWriteQualificationResponseLossV1, ObjectWriteQualificationSealedRequestV1,
    ObjectWriteQualificationUnprovenVisibleReceiptV1, ObjectWriteSuccessfulPutV1,
};
use cats_api::runtime_reconciliation::{
    AsciiText, Base64UrlNoPad, ContractVersion, Epoch, FenceEpoch, Id, NodeBootId, ProviderScope,
    RandomId128, Sha256Digest, UnixMillis, WireU64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blob::validate_key;
use crate::image_manifest::IMAGE_MANIFEST_MAX_BYTES;

pub const OBJECT_WRITE_REQUEST_MAX_BYTES: usize = IMAGE_MANIFEST_MAX_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriterIdentity {
    pub authority_id: Id,
    pub host_provider_scope: ProviderScope,
    pub immutable_host_id: Id,
    pub node_id: Id,
    pub object_provider_scope: ProviderScope,
    pub workload_principal_id: AsciiText,
    pub object_store_scope_id: AsciiText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteAuthorityState {
    Open,
    CutoffPending {
        fence_attempt_id: Id,
        cutoff_sequence: WireU64,
        cutoff_effective_at_unix_ms: UnixMillis,
    },
    CutoffComplete {
        receipt: ObjectWriteCutoffReceipt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteAuthority {
    pub writer: ObjectWriterIdentity,
    pub state: ObjectWriteAuthorityState,
    pub max_accepted_sequence: WireU64,
    pub terminal_prefix_sequence: WireU64,
    pub terminal_prefix_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteCutoffReceipt {
    pub writer_authority_id: Id,
    pub fence_attempt_id: Id,
    pub cutoff_receipt_id: AsciiText,
    pub cutoff_effective_at_unix_ms: UnixMillis,
    pub cutoff_sequence: WireU64,
    pub accepted_put_terminal_receipt_id: AsciiText,
    pub accepted_puts_terminal_at_unix_ms: UnixMillis,
    pub terminal_sequence: WireU64,
    pub terminal_prefix_sha256: Sha256Digest,
    pub successful_put_visibility_receipt_id: AsciiText,
    pub successful_puts_visible_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteTarget {
    pub object_provider_scope: ProviderScope,
    pub object_store_scope_id: AsciiText,
    pub canonical_logical_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteCredentialRetirementCause {
    ParentCutoff { fence_attempt_id: Id },
    ExactRelease { release_transition_id: Id },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteCredentialState {
    Active,
    Retired {
        cause: ObjectWriteCredentialRetirementCause,
        retirement_receipt_id: AsciiText,
        retired_at_unix_ms: UnixMillis,
    },
}

/// Public-key authority for one exact AuthorizedServing attachment. The
/// private key is never represented by this type or stored in Control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteCredentialBinding {
    pub credential: ObjectWriteCredentialReference,
    pub public_key_spki: Base64UrlNoPad,
    pub writer_authority_id: Id,
    pub host_provider_scope: ProviderScope,
    pub immutable_host_id: Id,
    pub node_id: Id,
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub agent_session_epoch: Epoch,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub private_artifact_id: Id,
    pub private_file_fsync_receipt_id: AsciiText,
    pub private_directory_fsync_receipt_id: AsciiText,
    pub registered_at_unix_ms: UnixMillis,
    pub state: ObjectWriteCredentialState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectPutDescriptor {
    pub writer_authority_id: Id,
    pub accepted_sequence: WireU64,
    pub request_id: Sha256Digest,
    pub credential: ObjectWriteCredentialReference,
    pub volume_id: Id,
    pub key: ObjectWriteImmutableKey,
    pub target: ObjectWriteTarget,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
    pub qualification_fault: Option<ObjectWriteQualificationFaultV1>,
    pub provider_attempt_id: AsciiText,
    pub accepted_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteIngress {
    pub writer_authority_id: Id,
    pub request_id: Sha256Digest,
    pub credential: ObjectWriteCredentialReference,
    pub volume_id: Id,
    pub key: ObjectWriteImmutableKey,
    pub target: ObjectWriteTarget,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
    pub qualification_fault: Option<ObjectWriteQualificationFaultV1>,
    pub receiving_started_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableObjectWriteSpoolReceipt {
    /// Opaque stable identifier resolved only by the configured durable spool
    /// adapter. It is never an ambient or caller-selected filesystem path.
    pub spool_id: AsciiText,
    pub request_id: Sha256Digest,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
    pub file_fsync_receipt_id: AsciiText,
    pub directory_fsync_receipt_id: AsciiText,
    pub durable_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteIngressState {
    /// Provisional only: it has no accepted sequence and is outside every
    /// writer cutoff prefix.
    Receiving,
    /// The exact body is now crash-safe and reopenable by another gateway
    /// replica, but still has no accepted sequence.
    DurableSpooled {
        spool: DurableObjectWriteSpoolReceipt,
    },
    /// The authority closed before the transaction could assign a sequence.
    /// This body must never be sent to the object provider.
    RejectedBeforeAccept {
        spool: DurableObjectWriteSpoolReceipt,
        reason: ObjectWriteRejectionReason,
        rejection_receipt_id: AsciiText,
        rejected_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWriteRejectionReason {
    WriterClosed,
    ObjectKeyConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteIngressAttempt {
    pub ingress: ObjectWriteIngress,
    pub state: ObjectWriteIngressState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectPutTerminalState {
    SucceededVisible {
        put_receipt_id: AsciiText,
        put_completed_at_unix_ms: UnixMillis,
        visibility_receipt_id: AsciiText,
        visible_at_unix_ms: UnixMillis,
        qualification_ambiguity: Option<Box<ObjectWriteQualificationAmbiguityReceiptV1>>,
    },
    PermanentlyFailed {
        failure_receipt_id: AsciiText,
        failed_at_unix_ms: UnixMillis,
    },
    /// The exact object is visible, but the guarded successful-PUT
    /// response-loss receipt was absent. This closes the immutable request
    /// without claiming the qualification ambiguity.
    QualificationUnprovenVisible {
        receipt: Box<ObjectWriteQualificationUnprovenVisibleReceiptV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectPutState {
    AcceptedSpooled {
        spool: DurableObjectWriteSpoolReceipt,
    },
    ProviderIssued {
        spool: DurableObjectWriteSpoolReceipt,
        issued_at_unix_ms: UnixMillis,
    },
    /// The E13 shared-lock guard committed this exact response-loss receipt
    /// after a real provider PUT success. Recovery is HEAD-only from here.
    QualificationResponseLost {
        spool: DurableObjectWriteSpoolReceipt,
        issued_at_unix_ms: UnixMillis,
        response_loss: Box<ObjectWriteQualificationResponseLossV1>,
    },
    Terminal {
        outcome: ObjectPutTerminalState,
        spool: TerminalObjectWriteSpool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectPutAttempt {
    pub descriptor: ObjectPutDescriptor,
    pub state: ObjectPutState,
}

/// One persisted request across the provisional and accepted phases. The
/// provisional variant is outside every cutoff prefix; only the accepted
/// variant has an assigned writer sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredObjectWriteAttempt {
    Ingress(ObjectWriteIngressAttempt),
    Accepted(ObjectPutAttempt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectWriteAcceptanceOutcome {
    Accepted(ObjectPutAttempt),
    RejectedBeforeAccept(ObjectWriteIngressAttempt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKeyAcceptance {
    Vacant,
    ExactReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalObjectWriteSpool {
    Retained {
        spool: DurableObjectWriteSpoolReceipt,
    },
    Removed {
        spool: DurableObjectWriteSpoolReceipt,
        removal_receipt_id: AsciiText,
        removed_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteDownstreamPut {
    pub descriptor: ObjectPutDescriptor,
    /// A durable, cross-replica handle. The provider adapter reopens the exact
    /// body for every retry; the core never passes a process-local file.
    pub spool: DurableObjectWriteSpoolReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectWriteDownstreamPutOutcome {
    Succeeded {
        provider_attempt_id: AsciiText,
        put_receipt_id: AsciiText,
        completed_at_unix_ms: UnixMillis,
    },
    PermanentlyFailed {
        provider_attempt_id: AsciiText,
        failure_receipt_id: AsciiText,
        failed_at_unix_ms: UnixMillis,
    },
}

/// Non-cloneable fault-bearing provider capability. Only core can construct
/// it after both the per-request exclusive guard and E13 admission guard are
/// live. Provider adapters can inspect the immutable request and spool but
/// cannot mint this capability or any qualified terminal outcome.
pub struct ObjectWriteQualificationPut {
    downstream: ObjectWriteDownstreamPut,
}

impl ObjectWriteQualificationPut {
    pub fn descriptor(&self) -> &ObjectPutDescriptor {
        &self.downstream.descriptor
    }

    pub fn spool(&self) -> &DurableObjectWriteSpoolReceipt {
        &self.downstream.spool
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectWriteQualificationPutOutcome {
    /// A real conditional provider PUT returned success.
    SuccessfulPut(Box<ObjectWriteSuccessfulPutV1>),
    /// The conditional create observed its precondition and a subsequent
    /// fresh HEAD found the exact requested immutable bytes.
    PreconditionFailedExactVisible(Box<ObjectWriteQualificationHeadEvidenceV1>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectWriteVisibilityOutcome {
    VisibleExact {
        provider_attempt_id: AsciiText,
        visibility_receipt_id: AsciiText,
        provider_request: Box<ObjectWriteProviderRequestObservationV1>,
        /// Optional provider-neutral evidence from a legacy/already-issued
        /// conditional retry. Fresh fault recovery HEADs before any retry.
        preceding_conditional_request: Option<Box<ObjectWriteConditionalRequestEvidenceV1>>,
        observed_at_unix_ms: UnixMillis,
    },
    NotVisible,
    ConflictingObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObjectWriteAuthorityError {
    #[error("object writer authority is closed")]
    WriterClosed,
    #[error("object writer identity or request is invalid")]
    InvalidRequest,
    #[error("object write sequence is exhausted")]
    SequenceExhausted,
    #[error("object write attempt does not match its authority")]
    BindingMismatch,
    #[error("object write attempt is stale or reused with another payload")]
    StaleAttempt,
    #[error("object key was already accepted with different immutable bytes")]
    ObjectKeyConflict,
    #[error("object write body does not have an exact durable spool receipt")]
    SpoolNotDurable,
    #[error("object write state transition is invalid")]
    InvalidTransition,
    #[error("object write terminal state is not a contiguous prefix")]
    NonContiguousTerminalPrefix,
    #[error("object write cutoff is not ready")]
    CutoffNotReady,
    #[error("stored object write authority is inconsistent")]
    CorruptState,
}

pub fn empty_terminal_prefix_sha256() -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(b"cats.object-write-terminal-prefix.v1").into())
}

pub fn validate_object_write_authority(
    authority: &ObjectWriteAuthority,
) -> Result<(), ObjectWriteAuthorityError> {
    if authority.terminal_prefix_sequence.get() > authority.max_accepted_sequence.get() {
        return Err(ObjectWriteAuthorityError::CorruptState);
    }
    match &authority.state {
        ObjectWriteAuthorityState::Open => {}
        ObjectWriteAuthorityState::CutoffPending {
            cutoff_sequence, ..
        } => {
            if *cutoff_sequence != authority.max_accepted_sequence {
                return Err(ObjectWriteAuthorityError::CorruptState);
            }
        }
        ObjectWriteAuthorityState::CutoffComplete { receipt } => {
            if receipt.writer_authority_id != authority.writer.authority_id
                || receipt.cutoff_sequence != authority.max_accepted_sequence
                || receipt.terminal_sequence != authority.terminal_prefix_sequence
                || receipt.terminal_prefix_sha256 != authority.terminal_prefix_sha256
                || receipt.cutoff_sequence != receipt.terminal_sequence
                || receipt.cutoff_effective_at_unix_ms > receipt.accepted_puts_terminal_at_unix_ms
                || receipt.accepted_puts_terminal_at_unix_ms
                    > receipt.successful_puts_visible_at_unix_ms
            {
                return Err(ObjectWriteAuthorityError::CorruptState);
            }
        }
    }
    Ok(())
}

pub fn register_object_write_credential(
    authority: &ObjectWriteAuthority,
    registration: &ObjectWriteCredentialRegistration,
    registered_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteCredentialBinding, ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    if !matches!(authority.state, ObjectWriteAuthorityState::Open) {
        return Err(ObjectWriteAuthorityError::WriterClosed);
    }
    if registration.writer_authority_id != authority.writer.authority_id
        || registration.session.node_id != authority.writer.node_id
        || registration.attachment_epoch.get() == 0
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    let binding = ObjectWriteCredentialBinding {
        credential: registration.credential.clone(),
        public_key_spki: registration.public_key_spki.clone(),
        writer_authority_id: registration.writer_authority_id.clone(),
        host_provider_scope: authority.writer.host_provider_scope.clone(),
        immutable_host_id: authority.writer.immutable_host_id.clone(),
        node_id: registration.session.node_id.clone(),
        node_boot_id: registration.session.node_boot_id.clone(),
        agent_instance_id: registration.session.agent_instance_id.clone(),
        agent_session_epoch: registration.session.agent_session_epoch,
        volume_id: registration.volume_id.clone(),
        attachment_id: registration.attachment_id.clone(),
        attachment_epoch: registration.attachment_epoch,
        private_artifact_id: registration.private_artifact_id.clone(),
        private_file_fsync_receipt_id: registration.private_file_fsync_receipt_id.clone(),
        private_directory_fsync_receipt_id: registration.private_directory_fsync_receipt_id.clone(),
        registered_at_unix_ms,
        state: ObjectWriteCredentialState::Active,
    };
    validate_object_write_credential(authority, &binding)?;
    Ok(binding)
}

pub fn validate_object_write_credential(
    authority: &ObjectWriteAuthority,
    binding: &ObjectWriteCredentialBinding,
) -> Result<(), ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    if binding.writer_authority_id != authority.writer.authority_id
        || binding.host_provider_scope != authority.writer.host_provider_scope
        || binding.immutable_host_id != authority.writer.immutable_host_id
        || binding.node_id != authority.writer.node_id
        || binding.attachment_epoch.get() == 0
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    if matches!(binding.state, ObjectWriteCredentialState::Active)
        && !matches!(authority.state, ObjectWriteAuthorityState::Open)
    {
        return Err(ObjectWriteAuthorityError::CorruptState);
    }
    Ok(())
}

pub fn authorize_object_write_ingress(
    authority: &ObjectWriteAuthority,
    binding: &ObjectWriteCredentialBinding,
    authenticated_credential: &ObjectWriteCredentialReference,
    descriptor: &ObjectWriteIngressDescriptor,
    receiving_started_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteIngressAttempt, ObjectWriteAuthorityError> {
    validate_object_write_credential(authority, binding)?;
    if !matches!(binding.state, ObjectWriteCredentialState::Active)
        || &binding.credential != authenticated_credential
        || binding.volume_id != descriptor.volume_id
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    let object_key = object_write_key(
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
    )
    .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    let target = ObjectWriteTarget {
        object_provider_scope: authority.writer.object_provider_scope.clone(),
        object_store_scope_id: authority.writer.object_store_scope_id.clone(),
        canonical_logical_key: object_key.clone(),
    };
    let request_id = object_put_request_id(
        &authority.writer.authority_id,
        &target,
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
        descriptor.content_length,
        descriptor
            .qualification_fault
            .as_ref()
            .map(|fault| (authenticated_credential, fault)),
    )?;
    let attempt = ObjectWriteIngressAttempt {
        ingress: ObjectWriteIngress {
            writer_authority_id: authority.writer.authority_id.clone(),
            request_id,
            credential: authenticated_credential.clone(),
            volume_id: descriptor.volume_id.clone(),
            key: descriptor.key.clone(),
            target,
            content_sha256: descriptor.content_sha256.clone(),
            content_length: descriptor.content_length,
            qualification_fault: descriptor.qualification_fault.clone(),
            receiving_started_at_unix_ms,
        },
        state: ObjectWriteIngressState::Receiving,
    };
    validate_key(&object_key).map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    validate_object_write_ingress_attempt(&attempt)?;
    Ok(attempt)
}

pub fn retire_object_write_credential_for_release(
    authority: &ObjectWriteAuthority,
    binding: &ObjectWriteCredentialBinding,
    release_transition_id: &Id,
    released_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteCredentialBinding, ObjectWriteAuthorityError> {
    validate_object_write_credential(authority, binding)?;
    let cause = ObjectWriteCredentialRetirementCause::ExactRelease {
        release_transition_id: release_transition_id.clone(),
    };
    retire_object_write_credential(binding, cause, released_at_unix_ms)
}

pub fn validate_object_put_attempt(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
) -> Result<(), ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    let descriptor = &attempt.descriptor;
    if descriptor.writer_authority_id != authority.writer.authority_id
        || descriptor.accepted_sequence.get() == 0
        || descriptor.accepted_sequence.get() > authority.max_accepted_sequence.get()
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    let expected_key = object_write_key(
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
    )
    .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if descriptor.target.canonical_logical_key != expected_key
        || descriptor.target.object_provider_scope != authority.writer.object_provider_scope
        || descriptor.target.object_store_scope_id != authority.writer.object_store_scope_id
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    validate_key(&descriptor.target.canonical_logical_key)
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if descriptor.request_id
        != object_put_request_id(
            &descriptor.writer_authority_id,
            &descriptor.target,
            &descriptor.volume_id,
            &descriptor.key,
            &descriptor.content_sha256,
            descriptor.content_length,
            descriptor
                .qualification_fault
                .as_ref()
                .map(|fault| (&descriptor.credential, fault)),
        )?
        || descriptor.provider_attempt_id != object_put_provider_attempt_id(&descriptor.request_id)?
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    match &attempt.state {
        ObjectPutState::AcceptedSpooled { spool }
        | ObjectPutState::ProviderIssued { spool, .. }
        | ObjectPutState::QualificationResponseLost { spool, .. } => {
            validate_durable_spool_receipt(spool, descriptor)?;
            if let ObjectPutState::ProviderIssued {
                issued_at_unix_ms, ..
            } = &attempt.state
            {
                if *issued_at_unix_ms < descriptor.accepted_at_unix_ms {
                    return Err(ObjectWriteAuthorityError::CorruptState);
                }
            }
            if let ObjectPutState::QualificationResponseLost {
                issued_at_unix_ms,
                response_loss,
                ..
            } = &attempt.state
            {
                validate_qualification_response_loss(
                    descriptor,
                    *issued_at_unix_ms,
                    response_loss,
                )?;
            }
        }
        ObjectPutState::Terminal { outcome, spool } => {
            match spool {
                TerminalObjectWriteSpool::Retained { spool } => {
                    validate_durable_spool_receipt(spool, descriptor)?;
                }
                TerminalObjectWriteSpool::Removed {
                    spool,
                    removed_at_unix_ms,
                    ..
                } => {
                    validate_durable_spool_receipt(spool, descriptor)?;
                    if *removed_at_unix_ms < terminal_at(outcome) {
                        return Err(ObjectWriteAuthorityError::CorruptState);
                    }
                }
            }
            match outcome {
                ObjectPutTerminalState::SucceededVisible {
                    put_completed_at_unix_ms,
                    visible_at_unix_ms,
                    ..
                } if put_completed_at_unix_ms > visible_at_unix_ms => {
                    return Err(ObjectWriteAuthorityError::CorruptState);
                }
                ObjectPutTerminalState::SucceededVisible {
                    put_receipt_id,
                    put_completed_at_unix_ms,
                    visibility_receipt_id,
                    visible_at_unix_ms,
                    qualification_ambiguity: Some(ambiguity),
                } => {
                    validate_qualification_ambiguity(descriptor, ambiguity)?;
                    if ambiguity.response_loss.successful_put.put_receipt_id != *put_receipt_id
                        || ambiguity.response_loss.successful_put.completed_at_unix_ms
                            != *put_completed_at_unix_ms
                        || ambiguity.head.visibility_receipt_id != *visibility_receipt_id
                        || ambiguity.head.observed_at_unix_ms != *visible_at_unix_ms
                    {
                        return Err(ObjectWriteAuthorityError::CorruptState);
                    }
                }
                ObjectPutTerminalState::SucceededVisible {
                    qualification_ambiguity: None,
                    ..
                } if descriptor.qualification_fault.is_some() => {
                    return Err(ObjectWriteAuthorityError::CorruptState);
                }
                ObjectPutTerminalState::QualificationUnprovenVisible { receipt } => {
                    validate_qualification_unproven_visible(descriptor, None, receipt)?;
                }
                ObjectPutTerminalState::PermanentlyFailed { .. }
                    if descriptor.qualification_fault.is_some() =>
                {
                    return Err(ObjectWriteAuthorityError::CorruptState);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn validate_object_write_ingress_attempt(
    attempt: &ObjectWriteIngressAttempt,
) -> Result<(), ObjectWriteAuthorityError> {
    let ingress = &attempt.ingress;
    let expected_key = object_write_key(&ingress.volume_id, &ingress.key, &ingress.content_sha256)
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if ingress.target.canonical_logical_key != expected_key {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    let maximum = u64::try_from(OBJECT_WRITE_REQUEST_MAX_BYTES)
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if ingress.content_length.get() > maximum
        || ingress.request_id
            != object_put_request_id(
                &ingress.writer_authority_id,
                &ingress.target,
                &ingress.volume_id,
                &ingress.key,
                &ingress.content_sha256,
                ingress.content_length,
                ingress
                    .qualification_fault
                    .as_ref()
                    .map(|fault| (&ingress.credential, fault)),
            )?
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    match &attempt.state {
        ObjectWriteIngressState::Receiving => {}
        ObjectWriteIngressState::DurableSpooled { spool }
        | ObjectWriteIngressState::RejectedBeforeAccept { spool, .. } => {
            validate_ingress_spool_receipt(spool, ingress)?;
        }
    }
    if let ObjectWriteIngressState::RejectedBeforeAccept {
        rejected_at_unix_ms,
        spool,
        ..
    } = &attempt.state
    {
        if *rejected_at_unix_ms < spool.durable_at_unix_ms {
            return Err(ObjectWriteAuthorityError::CorruptState);
        }
    }
    Ok(())
}

/// Classify the writer-scoped object-key uniqueness lookup made while holding
/// the authority row lock. A key can name one immutable payload forever; a
/// different digest/length request is rejected before sequence allocation.
pub fn classify_object_key_acceptance(
    existing: Option<&ObjectPutAttempt>,
    proposed: &ObjectWriteIngressAttempt,
) -> Result<ObjectKeyAcceptance, ObjectWriteAuthorityError> {
    validate_object_write_ingress_attempt(proposed)?;
    let Some(existing) = existing else {
        return Ok(ObjectKeyAcceptance::Vacant);
    };
    let proposed_key = object_write_key(
        &proposed.ingress.volume_id,
        &proposed.ingress.key,
        &proposed.ingress.content_sha256,
    )
    .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if existing.descriptor.writer_authority_id != proposed.ingress.writer_authority_id
        || existing.descriptor.target.canonical_logical_key != proposed_key
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    if existing.descriptor.request_id == proposed.ingress.request_id
        && existing.descriptor.volume_id == proposed.ingress.volume_id
        && existing.descriptor.key == proposed.ingress.key
        && existing.descriptor.content_sha256 == proposed.ingress.content_sha256
        && existing.descriptor.content_length == proposed.ingress.content_length
        && existing.descriptor.credential == proposed.ingress.credential
        && existing.descriptor.qualification_fault == proposed.ingress.qualification_fault
    {
        Ok(ObjectKeyAcceptance::ExactReplay)
    } else {
        Err(ObjectWriteAuthorityError::ObjectKeyConflict)
    }
}

pub fn object_put_request_id(
    writer_authority_id: &Id,
    target: &ObjectWriteTarget,
    volume_id: &Id,
    key: &ObjectWriteImmutableKey,
    content_sha256: &Sha256Digest,
    content_length: WireU64,
    qualification: Option<(
        &ObjectWriteCredentialReference,
        &ObjectWriteQualificationFaultV1,
    )>,
) -> Result<Sha256Digest, ObjectWriteAuthorityError> {
    let object_key = object_write_key(volume_id, key, content_sha256)
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if target.canonical_logical_key != object_key {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    validate_key(&object_key).map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.object-write-request.v1")?;
    hash_frame(&mut hasher, writer_authority_id.as_str().as_bytes())?;
    hash_frame(
        &mut hasher,
        target.object_provider_scope.provider.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        target.object_provider_scope.partition.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        target.object_provider_scope.account_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        target.object_provider_scope.region.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        target.object_store_scope_id.as_str().as_bytes(),
    )?;
    hash_frame(&mut hasher, volume_id.as_str().as_bytes())?;
    hash_frame(&mut hasher, object_key.as_bytes())?;
    hash_frame(&mut hasher, content_sha256.as_str().as_bytes())?;
    hash_frame(&mut hasher, &content_length.get().to_be_bytes())?;
    if let Some((
        credential,
        ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
            qualification_id,
            fault_id,
            qualification_catalog_sha256,
        },
    )) = qualification
    {
        hash_frame(&mut hasher, b"qualification-credential")?;
        hash_frame(&mut hasher, credential.credential_id.as_str().as_bytes())?;
        hash_frame(
            &mut hasher,
            credential.public_key_spki_sha256.as_str().as_bytes(),
        )?;
        hash_frame(
            &mut hasher,
            b"qualification-fault:successful-put-response-loss",
        )?;
        hash_frame(&mut hasher, qualification_id.as_str().as_bytes())?;
        hash_frame(&mut hasher, fault_id.as_str().as_bytes())?;
        hash_frame(
            &mut hasher,
            qualification_catalog_sha256.as_str().as_bytes(),
        )?;
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

pub fn object_put_provider_attempt_id(
    request_id: &Sha256Digest,
) -> Result<AsciiText, ObjectWriteAuthorityError> {
    let value = request_id
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(ObjectWriteAuthorityError::InvalidRequest)?;
    AsciiText::new(format!("owpa1_{value}")).ok_or(ObjectWriteAuthorityError::InvalidRequest)
}

/// Build the exact server-side request passed to E13's
/// `ObjectWriteAmbiguity` gate. `None` is deliberately allocation- and
/// authority-free so ordinary writer/cutoff semantics remain unchanged.
pub fn object_write_qualification_authorization_request(
    descriptor: &ObjectPutDescriptor,
) -> Result<Option<ObjectWriteQualificationAuthorizationRequestV1>, ObjectWriteAuthorityError> {
    let Some(fault) = descriptor.qualification_fault.as_ref() else {
        return Ok(None);
    };
    let request_id = object_put_request_id(
        &descriptor.writer_authority_id,
        &descriptor.target,
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
        descriptor.content_length,
        Some((&descriptor.credential, fault)),
    )?;
    if request_id != descriptor.request_id
        || object_put_provider_attempt_id(&request_id)? != descriptor.provider_attempt_id
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    Ok(Some(ObjectWriteQualificationAuthorizationRequestV1 {
        version: ContractVersion::V1,
        mutation_class: ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity,
        request_id,
        writer_authority_id: descriptor.writer_authority_id.clone(),
        credential: descriptor.credential.clone(),
        provider_attempt_id: descriptor.provider_attempt_id.clone(),
        fault: fault.clone(),
        object_provider_scope: descriptor.target.object_provider_scope.clone(),
        object_store_scope_id: descriptor.target.object_store_scope_id.clone(),
        canonical_logical_key: descriptor.target.canonical_logical_key.clone(),
        content_sha256: descriptor.content_sha256.clone(),
        content_length: descriptor.content_length,
    }))
}

fn validate_qualification_authorization_for_descriptor(
    descriptor: &ObjectPutDescriptor,
    authorization: &ObjectWriteQualificationAuthorizationV1,
) -> Result<(), ObjectWriteAuthorityError> {
    let Some(expected) = object_write_qualification_authorization_request(descriptor)? else {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    };
    encode_object_write_qualification_authorization(authorization)
        .map_err(|_| ObjectWriteAuthorityError::BindingMismatch)?;
    if authorization.request != expected
        || authorization.mutation_class
            != ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    Ok(())
}

fn validate_qualification_response_loss(
    descriptor: &ObjectPutDescriptor,
    issued_at_unix_ms: UnixMillis,
    response_loss: &ObjectWriteQualificationResponseLossV1,
) -> Result<(), ObjectWriteAuthorityError> {
    validate_qualification_authorization_for_descriptor(descriptor, &response_loss.authorization)?;
    encode_object_write_qualification_response_loss(response_loss)
        .map_err(|_| ObjectWriteAuthorityError::BindingMismatch)?;
    if response_loss.successful_put.completed_at_unix_ms < issued_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    Ok(())
}

fn object_write_qualification_sealed_request(
    descriptor: &ObjectPutDescriptor,
    issued_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteQualificationSealedRequestV1, ObjectWriteAuthorityError> {
    let authorization_request = object_write_qualification_authorization_request(descriptor)?
        .ok_or(ObjectWriteAuthorityError::BindingMismatch)?;
    let sealed = ObjectWriteQualificationSealedRequestV1 {
        version: ContractVersion::V1,
        accepted_sequence: descriptor.accepted_sequence,
        ingress_descriptor: ObjectWriteIngressDescriptor {
            version: ContractVersion::V1,
            volume_id: descriptor.volume_id.clone(),
            key: descriptor.key.clone(),
            content_sha256: descriptor.content_sha256.clone(),
            content_length: descriptor.content_length,
            qualification_fault: descriptor.qualification_fault.clone(),
        },
        authorization_request,
        accepted_at_unix_ms: descriptor.accepted_at_unix_ms,
        issued_at_unix_ms,
    };
    encode_object_write_qualification_sealed_request(&sealed)
        .map_err(|_| ObjectWriteAuthorityError::BindingMismatch)?;
    Ok(sealed)
}

fn validate_qualification_unproven_visible(
    descriptor: &ObjectPutDescriptor,
    expected_issued_at_unix_ms: Option<UnixMillis>,
    receipt: &ObjectWriteQualificationUnprovenVisibleReceiptV1,
) -> Result<(), ObjectWriteAuthorityError> {
    encode_object_write_qualification_unproven_visible_receipt(receipt)
        .map_err(|_| ObjectWriteAuthorityError::BindingMismatch)?;
    let expected = object_write_qualification_sealed_request(
        descriptor,
        receipt.sealed_request.issued_at_unix_ms,
    )?;
    if receipt.sealed_request != expected
        || expected_issued_at_unix_ms
            .is_some_and(|issued| receipt.sealed_request.issued_at_unix_ms != issued)
    {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    Ok(())
}

fn validate_qualification_ambiguity(
    descriptor: &ObjectPutDescriptor,
    receipt: &ObjectWriteQualificationAmbiguityReceiptV1,
) -> Result<(), ObjectWriteAuthorityError> {
    validate_qualification_response_loss(
        descriptor,
        descriptor.accepted_at_unix_ms,
        &receipt.response_loss,
    )?;
    encode_object_write_qualification_ambiguity_receipt(receipt)
        .map_err(|_| ObjectWriteAuthorityError::BindingMismatch)?;
    Ok(())
}

pub type QualificationFaultAuthorityFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, QualificationFaultAuthorityError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationFaultAuthorityError {
    #[error("qualification fault authorization deadline elapsed")]
    DeadlineExceeded,
    #[error("qualification fault is not authorized by the active exact binding")]
    NotAuthorized,
    #[error("qualification fault authority is unavailable")]
    Unavailable,
    #[error("qualification fault request conflicts with durable evidence")]
    Conflict,
    #[error("qualification fault authority returned invalid or corrupt evidence")]
    InvalidEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectWriteQualificationDurableResolution {
    ResponseLoss(Box<ObjectWriteQualificationResponseLossV1>),
    UnprovenVisible(Box<ObjectWriteQualificationUnprovenVisibleReceiptV1>),
}

/// Opaque per-request transaction guard. Production implementations acquire
/// one exclusive row/advisory lock keyed by the exact authorization request,
/// load its immutable resolution in that same transaction, and retain the
/// lock through HEAD and one resolution commit. Dropping it rolls back.
pub trait QualificationFaultRequestGuard: Send {
    fn request(&self) -> &ObjectWriteQualificationAuthorizationRequestV1;

    fn durable_resolution(&self) -> Option<&ObjectWriteQualificationDurableResolution>;

    /// Commit the sole fail-closed resolution. The authority, not the caller,
    /// supplies `resolved_at_unix_ms` from PostgreSQL clock and derives the
    /// content-addressed receipt ID in this transaction.
    fn commit_unproven_visible<'a>(
        self: Box<Self>,
        sealed_request: ObjectWriteQualificationSealedRequestV1,
        head_evidence: ObjectWriteQualificationHeadEvidenceV1,
        absolute_deadline: Instant,
    ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
    where
        Self: 'a;

    /// Acquire E13 `ObjectWriteAmbiguity` `FOR SHARE` in this same transaction.
    /// The returned guard continues to own both locks.
    fn authorize_put<'a>(
        self: Box<Self>,
        absolute_deadline: Instant,
    ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultAuthorizationGuard + 'a>>
    where
        Self: 'a;
}

/// Opaque live transaction guard retaining both the exact-request exclusive
/// lock and E13 singleton `FOR SHARE`. A provider call is allowed only while
/// this guard is owned by an `ObjectWriteQualificationPutDispatch`.
pub trait QualificationFaultAuthorizationGuard: Send {
    fn authorization(&self) -> &ObjectWriteQualificationAuthorizationV1;

    fn commit_response_loss<'a>(
        self: Box<Self>,
        successful_put: ObjectWriteSuccessfulPutV1,
        absolute_deadline: Instant,
    ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationResponseLossV1>
    where
        Self: 'a;

    /// Settle a conditional precondition followed by exact HEAD without
    /// claiming that the successful-PUT response-loss injection occurred.
    fn commit_unproven_visible<'a>(
        self: Box<Self>,
        sealed_request: ObjectWriteQualificationSealedRequestV1,
        head_evidence: ObjectWriteQualificationHeadEvidenceV1,
        absolute_deadline: Instant,
    ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
    where
        Self: 'a;
}

/// Mandatory injected authority for fault-bearing writes. There is no
/// unavailable/no-op implementation in core and no optional authority
/// argument. Ordinary writes bypass both methods in the preparation helper.
pub trait QualificationFaultAuthority: Send + Sync {
    /// Acquire the exact-request exclusive transaction and load its immutable
    /// resolution before consulting current admission. Production code must
    /// clamp PostgreSQL lock/statement timeouts to the original monotonic
    /// deadline and return `DeadlineExceeded` before any late commit.
    fn lock_request<'a>(
        &'a self,
        request: ObjectWriteQualificationAuthorizationRequestV1,
        absolute_deadline: Instant,
    ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultRequestGuard + 'a>>;
}

pub enum ObjectWriteQualificationPreparation<'a> {
    Ordinary,
    StoredResponseLoss(ObjectWriteQualificationResponseLossCommit),
    StoredUnprovenVisible(ObjectWriteQualificationUnprovenCommit),
    /// The request resolution row is exclusively locked and durably absent.
    /// This token owns that live transaction throughout the recovery HEAD.
    DiscoverIssuedVisibility(Box<ObjectWriteQualificationHeadProbe<'a>>),
    /// Fresh AcceptedSpooled request authorized before ProviderIssued is
    /// persisted. The caller must persist ProviderIssued, then consume this
    /// capability with `seal_object_write_qualification_put`.
    Authorized(ObjectWriteQualificationAuthorizationCapability<'a>),
}

pub struct ObjectWriteQualificationResponseLossCommit {
    response_loss: ObjectWriteQualificationResponseLossV1,
}

impl ObjectWriteQualificationResponseLossCommit {
    pub fn receipt(&self) -> &ObjectWriteQualificationResponseLossV1 {
        &self.response_loss
    }
}

pub struct ObjectWriteQualificationUnprovenCommit {
    receipt: ObjectWriteQualificationUnprovenVisibleReceiptV1,
}

impl ObjectWriteQualificationUnprovenCommit {
    pub fn receipt(&self) -> &ObjectWriteQualificationUnprovenVisibleReceiptV1 {
        &self.receipt
    }
}

pub struct ObjectWriteQualificationAuthorizationCapability<'a> {
    guard: Box<dyn QualificationFaultAuthorizationGuard + 'a>,
}

impl ObjectWriteQualificationAuthorizationCapability<'_> {
    pub fn authorization(&self) -> &ObjectWriteQualificationAuthorizationV1 {
        self.guard.authorization()
    }
}

pub struct ObjectWriteQualificationPutDispatch<'a> {
    request: ObjectWriteQualificationPut,
    sealed_request: ObjectWriteQualificationSealedRequestV1,
    guard: Box<dyn QualificationFaultAuthorizationGuard + 'a>,
}

impl ObjectWriteQualificationPutDispatch<'_> {
    pub fn request(&self) -> &ObjectWriteQualificationPut {
        &self.request
    }

    pub fn authorization(&self) -> &ObjectWriteQualificationAuthorizationV1 {
        self.guard.authorization()
    }
}

pub struct ObjectWriteQualificationHeadProbe<'a> {
    sealed_request: ObjectWriteQualificationSealedRequestV1,
    guard: Box<dyn QualificationFaultRequestGuard + 'a>,
}

pub enum ObjectWriteQualificationHeadResolution<'a> {
    QualificationUnprovenVisible(Box<ObjectWriteQualificationUnprovenCommit>),
    Authorized(Box<ObjectWriteQualificationPutDispatch<'a>>),
    ConflictingObject,
}

/// Prepare one provider dispatch or the mandatory recovery HEAD. A
/// fault-bearing request cannot conditionally fall back to the ordinary path:
/// it returns stored evidence, a discovery token, a live guard, or an error.
pub async fn prepare_object_write_qualification<'a>(
    authority: &'a dyn QualificationFaultAuthority,
    attempt: &ObjectPutAttempt,
    absolute_deadline: Instant,
) -> Result<ObjectWriteQualificationPreparation<'a>, QualificationFaultAuthorityError> {
    let descriptor = &attempt.descriptor;
    let request = object_write_qualification_authorization_request(descriptor)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    let Some(request) = request else {
        return Ok(ObjectWriteQualificationPreparation::Ordinary);
    };
    let issued_at_unix_ms = match &attempt.state {
        ObjectPutState::AcceptedSpooled { .. } => None,
        ObjectPutState::ProviderIssued {
            issued_at_unix_ms, ..
        } => Some(*issued_at_unix_ms),
        ObjectPutState::QualificationResponseLost {
            issued_at_unix_ms,
            response_loss,
            ..
        } => {
            validate_qualification_response_loss(descriptor, *issued_at_unix_ms, response_loss)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            return Ok(ObjectWriteQualificationPreparation::StoredResponseLoss(
                ObjectWriteQualificationResponseLossCommit {
                    response_loss: response_loss.as_ref().clone(),
                },
            ));
        }
        ObjectPutState::Terminal { .. } => {
            return Err(QualificationFaultAuthorityError::Conflict);
        }
    };
    let guard = authority
        .lock_request(request.clone(), absolute_deadline)
        .await?;
    if guard.request() != &request {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    if let Some(stored) = guard.durable_resolution() {
        let issued_at_unix_ms =
            issued_at_unix_ms.ok_or(QualificationFaultAuthorityError::InvalidEvidence)?;
        return match stored {
            ObjectWriteQualificationDurableResolution::ResponseLoss(stored) => {
                validate_qualification_response_loss(descriptor, issued_at_unix_ms, stored)
                    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
                Ok(ObjectWriteQualificationPreparation::StoredResponseLoss(
                    ObjectWriteQualificationResponseLossCommit {
                        response_loss: stored.as_ref().clone(),
                    },
                ))
            }
            ObjectWriteQualificationDurableResolution::UnprovenVisible(stored) => {
                validate_qualification_unproven_visible(
                    descriptor,
                    Some(issued_at_unix_ms),
                    stored,
                )
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
                Ok(ObjectWriteQualificationPreparation::StoredUnprovenVisible(
                    ObjectWriteQualificationUnprovenCommit {
                        receipt: stored.as_ref().clone(),
                    },
                ))
            }
        };
    }
    if let Some(issued_at_unix_ms) = issued_at_unix_ms {
        let sealed_request =
            object_write_qualification_sealed_request(descriptor, issued_at_unix_ms)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
        return Ok(
            ObjectWriteQualificationPreparation::DiscoverIssuedVisibility(Box::new(
                ObjectWriteQualificationHeadProbe {
                    sealed_request,
                    guard,
                },
            )),
        );
    }
    let guard = guard.authorize_put(absolute_deadline).await?;
    validate_qualification_authorization_for_descriptor(descriptor, guard.authorization())
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if guard.authorization().request != request {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    Ok(ObjectWriteQualificationPreparation::Authorized(
        ObjectWriteQualificationAuthorizationCapability { guard },
    ))
}

/// Bind a fresh authorization capability to the exact durable ProviderIssued
/// state. Neither the ordinary downstream request nor this qualified request
/// can be constructed by an adapter.
pub fn seal_object_write_qualification_put<'a>(
    attempt: &ObjectPutAttempt,
    capability: ObjectWriteQualificationAuthorizationCapability<'a>,
) -> Result<ObjectWriteQualificationPutDispatch<'a>, ObjectWriteAuthorityError> {
    let ObjectPutState::ProviderIssued {
        spool,
        issued_at_unix_ms,
    } = &attempt.state
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    validate_qualification_authorization_for_descriptor(
        &attempt.descriptor,
        capability.guard.authorization(),
    )?;
    let sealed_request =
        object_write_qualification_sealed_request(&attempt.descriptor, *issued_at_unix_ms)?;
    let downstream = ObjectWriteDownstreamPut {
        descriptor: attempt.descriptor.clone(),
        spool: spool.clone(),
    };
    validate_qualification_downstream_put_binding(&downstream)?;
    Ok(ObjectWriteQualificationPutDispatch {
        request: ObjectWriteQualificationPut { downstream },
        sealed_request,
        guard: capability.guard,
    })
}

/// Continue recovery only while the opaque request-exclusive token above is
/// still held. Exact visibility settles without consulting current admission,
/// so End or Close cannot strand an already-visible immutable write. HEAD
/// NotVisible upgrades this same transaction through the current E13 gate.
pub async fn resolve_object_write_qualification_after_head<'a>(
    attempt: &ObjectPutAttempt,
    probe: Box<ObjectWriteQualificationHeadProbe<'a>>,
    visibility: ObjectWriteVisibilityOutcome,
    absolute_deadline: Instant,
) -> Result<ObjectWriteQualificationHeadResolution<'a>, QualificationFaultAuthorityError> {
    let ObjectPutState::ProviderIssued {
        issued_at_unix_ms, ..
    } = &attempt.state
    else {
        return Err(QualificationFaultAuthorityError::Conflict);
    };
    let expected_sealed =
        object_write_qualification_sealed_request(&attempt.descriptor, *issued_at_unix_ms)
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if probe.sealed_request != expected_sealed
        || probe.guard.request() != &expected_sealed.authorization_request
        || probe.guard.durable_resolution().is_some()
    {
        return Err(QualificationFaultAuthorityError::Conflict);
    }
    match visibility {
        ObjectWriteVisibilityOutcome::VisibleExact {
            provider_attempt_id,
            visibility_receipt_id,
            provider_request,
            preceding_conditional_request,
            observed_at_unix_ms,
        } => {
            let head_evidence = ObjectWriteQualificationHeadEvidenceV1 {
                provider_attempt_id,
                visibility_receipt_id,
                preceding_conditional_request,
                provider_request: *provider_request,
                observed_at_unix_ms,
            };
            let receipt = probe
                .guard
                .commit_unproven_visible(probe.sealed_request, head_evidence, absolute_deadline)
                .await?;
            validate_qualification_unproven_visible(
                &attempt.descriptor,
                Some(*issued_at_unix_ms),
                &receipt,
            )
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            Ok(
                ObjectWriteQualificationHeadResolution::QualificationUnprovenVisible(Box::new(
                    ObjectWriteQualificationUnprovenCommit { receipt },
                )),
            )
        }
        ObjectWriteVisibilityOutcome::NotVisible => {
            let guard = probe.guard.authorize_put(absolute_deadline).await?;
            validate_qualification_authorization_for_descriptor(
                &attempt.descriptor,
                guard.authorization(),
            )
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            if guard.authorization().request != probe.sealed_request.authorization_request {
                return Err(QualificationFaultAuthorityError::InvalidEvidence);
            }
            let downstream = ObjectWriteDownstreamPut {
                descriptor: attempt.descriptor.clone(),
                spool: match &attempt.state {
                    ObjectPutState::ProviderIssued { spool, .. } => spool.clone(),
                    _ => unreachable!("ProviderIssued was matched above"),
                },
            };
            validate_qualification_downstream_put_binding(&downstream)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            Ok(ObjectWriteQualificationHeadResolution::Authorized(
                Box::new(ObjectWriteQualificationPutDispatch {
                    request: ObjectWriteQualificationPut { downstream },
                    sealed_request: probe.sealed_request,
                    guard,
                }),
            ))
        }
        ObjectWriteVisibilityOutcome::ConflictingObject => {
            Ok(ObjectWriteQualificationHeadResolution::ConflictingObject)
        }
    }
}

pub fn object_write_spool_id(
    request_id: &Sha256Digest,
) -> Result<AsciiText, ObjectWriteAuthorityError> {
    let value = request_id
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(ObjectWriteAuthorityError::InvalidRequest)?;
    AsciiText::new(format!("owsp1_{value}")).ok_or(ObjectWriteAuthorityError::InvalidRequest)
}

pub fn validate_durable_spool_receipt(
    spool: &DurableObjectWriteSpoolReceipt,
    descriptor: &ObjectPutDescriptor,
) -> Result<(), ObjectWriteAuthorityError> {
    validate_spool_receipt_fields(
        spool,
        &descriptor.request_id,
        &descriptor.content_sha256,
        descriptor.content_length,
    )?;
    if spool.durable_at_unix_ms > descriptor.accepted_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    Ok(())
}

fn validate_ingress_spool_receipt(
    spool: &DurableObjectWriteSpoolReceipt,
    ingress: &ObjectWriteIngress,
) -> Result<(), ObjectWriteAuthorityError> {
    validate_spool_receipt_fields(
        spool,
        &ingress.request_id,
        &ingress.content_sha256,
        ingress.content_length,
    )?;
    if spool.durable_at_unix_ms < ingress.receiving_started_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    Ok(())
}

fn validate_spool_receipt_fields(
    spool: &DurableObjectWriteSpoolReceipt,
    request_id: &Sha256Digest,
    content_sha256: &Sha256Digest,
    content_length: WireU64,
) -> Result<(), ObjectWriteAuthorityError> {
    if spool.spool_id != object_write_spool_id(request_id)?
        || &spool.request_id != request_id
        || &spool.content_sha256 != content_sha256
        || spool.content_length != content_length
    {
        return Err(ObjectWriteAuthorityError::SpoolNotDurable);
    }
    let maximum = u64::try_from(OBJECT_WRITE_REQUEST_MAX_BYTES)
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if content_length.get() > maximum {
        return Err(ObjectWriteAuthorityError::InvalidRequest);
    }
    Ok(())
}

fn terminal_at(outcome: &ObjectPutTerminalState) -> UnixMillis {
    match outcome {
        ObjectPutTerminalState::SucceededVisible {
            visible_at_unix_ms, ..
        } => *visible_at_unix_ms,
        ObjectPutTerminalState::PermanentlyFailed {
            failed_at_unix_ms, ..
        } => *failed_at_unix_ms,
        ObjectPutTerminalState::QualificationUnprovenVisible { receipt } => {
            receipt.resolved_at_unix_ms
        }
    }
}

/// Record that the exact request body is reopenable after a process or
/// replica crash. This still does not assign an accepted sequence.
pub fn mark_object_write_spool_durable(
    ingress_attempt: &ObjectWriteIngressAttempt,
    spool: DurableObjectWriteSpoolReceipt,
) -> Result<ObjectWriteIngressAttempt, ObjectWriteAuthorityError> {
    validate_object_write_ingress_attempt(ingress_attempt)?;
    match &ingress_attempt.state {
        ObjectWriteIngressState::Receiving => {}
        ObjectWriteIngressState::DurableSpooled { spool: existing } if existing == &spool => {
            return Ok(ingress_attempt.clone());
        }
        ObjectWriteIngressState::DurableSpooled { .. }
        | ObjectWriteIngressState::RejectedBeforeAccept { .. } => {
            return Err(ObjectWriteAuthorityError::StaleAttempt);
        }
    }
    validate_ingress_spool_receipt(&spool, &ingress_attempt.ingress)?;
    let updated = ObjectWriteIngressAttempt {
        ingress: ingress_attempt.ingress.clone(),
        state: ObjectWriteIngressState::DurableSpooled { spool },
    };
    validate_object_write_ingress_attempt(&updated)?;
    Ok(updated)
}

/// Assign the accepted sequence only after the exact body has a stable,
/// cross-replica durable spool receipt. The caller persists the returned
/// authority and attempt in one transaction while holding the authority row
/// lock; observing a cutoff state therefore rejects before provider issue.
pub fn accept_durable_object_write(
    authority: &ObjectWriteAuthority,
    ingress_attempt: &ObjectWriteIngressAttempt,
    accepted_at_unix_ms: UnixMillis,
) -> Result<(ObjectWriteAuthority, ObjectPutAttempt), ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    validate_object_write_ingress_attempt(ingress_attempt)?;
    if !matches!(authority.state, ObjectWriteAuthorityState::Open) {
        return Err(ObjectWriteAuthorityError::WriterClosed);
    }
    if ingress_attempt.ingress.writer_authority_id != authority.writer.authority_id {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    let ObjectWriteIngressState::DurableSpooled { spool } = &ingress_attempt.state else {
        return Err(ObjectWriteAuthorityError::SpoolNotDurable);
    };
    if accepted_at_unix_ms < spool.durable_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    let accepted_sequence = authority
        .max_accepted_sequence
        .get()
        .checked_add(1)
        .and_then(WireU64::new)
        .ok_or(ObjectWriteAuthorityError::SequenceExhausted)?;
    let ingress = &ingress_attempt.ingress;
    let descriptor = ObjectPutDescriptor {
        writer_authority_id: ingress.writer_authority_id.clone(),
        accepted_sequence,
        request_id: ingress.request_id.clone(),
        credential: ingress.credential.clone(),
        volume_id: ingress.volume_id.clone(),
        key: ingress.key.clone(),
        target: ingress.target.clone(),
        content_sha256: ingress.content_sha256.clone(),
        content_length: ingress.content_length,
        qualification_fault: ingress.qualification_fault.clone(),
        provider_attempt_id: object_put_provider_attempt_id(&ingress.request_id)?,
        accepted_at_unix_ms,
    };
    let attempt = ObjectPutAttempt {
        descriptor,
        state: ObjectPutState::AcceptedSpooled {
            spool: spool.clone(),
        },
    };
    let mut updated = authority.clone();
    updated.max_accepted_sequence = accepted_sequence;
    validate_object_put_attempt(&updated, &attempt)?;
    Ok((updated, attempt))
}

pub fn mark_object_write_provider_issued(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    issued_at_unix_ms: UnixMillis,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
    let ObjectPutState::AcceptedSpooled { spool } = &attempt.state else {
        return match &attempt.state {
            ObjectPutState::ProviderIssued { .. } => Ok(attempt.clone()),
            _ => Err(ObjectWriteAuthorityError::InvalidTransition),
        };
    };
    if issued_at_unix_ms < attempt.descriptor.accepted_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    let mut updated = attempt.clone();
    updated.state = ObjectPutState::ProviderIssued {
        spool: spool.clone(),
        issued_at_unix_ms,
    };
    validate_object_put_attempt(authority, &updated)?;
    Ok(updated)
}

/// Adopt the exact receipt already committed by the still-held E13
/// qualification guard. The transition is idempotent, and no state after it
/// can issue another PUT.
fn mark_object_write_qualification_response_lost_in(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    response_loss: ObjectWriteQualificationResponseLossV1,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
    if let ObjectPutState::QualificationResponseLost {
        response_loss: existing,
        ..
    } = &attempt.state
    {
        return if existing.as_ref() == &response_loss {
            Ok(attempt.clone())
        } else {
            Err(ObjectWriteAuthorityError::StaleAttempt)
        };
    }
    let ObjectPutState::ProviderIssued {
        spool,
        issued_at_unix_ms,
    } = &attempt.state
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    validate_qualification_response_loss(&attempt.descriptor, *issued_at_unix_ms, &response_loss)?;
    let mut updated = attempt.clone();
    updated.state = ObjectPutState::QualificationResponseLost {
        spool: spool.clone(),
        issued_at_unix_ms: *issued_at_unix_ms,
        response_loss: Box::new(response_loss),
    };
    validate_object_put_attempt(authority, &updated)?;
    Ok(updated)
}

pub fn adopt_object_write_qualification_response_lost(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    committed: ObjectWriteQualificationResponseLossCommit,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    mark_object_write_qualification_response_lost_in(authority, attempt, committed.response_loss)
}

pub fn adopt_object_write_qualification_unproven_visible(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    committed: ObjectWriteQualificationUnprovenCommit,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    complete_object_write_qualification_unproven_visible_in(authority, attempt, committed.receipt)
}

fn complete_object_write_qualification_unproven_visible_in(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    receipt: ObjectWriteQualificationUnprovenVisibleReceiptV1,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
    if let ObjectPutState::Terminal {
        outcome: ObjectPutTerminalState::QualificationUnprovenVisible { receipt: existing },
        ..
    } = &attempt.state
    {
        return if existing.as_ref() == &receipt {
            Ok(attempt.clone())
        } else {
            Err(ObjectWriteAuthorityError::StaleAttempt)
        };
    }
    let ObjectPutState::ProviderIssued {
        spool,
        issued_at_unix_ms,
    } = &attempt.state
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    validate_qualification_unproven_visible(
        &attempt.descriptor,
        Some(*issued_at_unix_ms),
        &receipt,
    )?;
    let mut updated = attempt.clone();
    updated.state = ObjectPutState::Terminal {
        outcome: ObjectPutTerminalState::QualificationUnprovenVisible {
            receipt: Box::new(receipt),
        },
        spool: TerminalObjectWriteSpool::Retained {
            spool: spool.clone(),
        },
    };
    validate_object_put_attempt(authority, &updated)?;
    Ok(updated)
}

/// Consume the non-cloneable qualified dispatch and the provider's closed raw
/// outcome. Only this function can turn those facts into durable authority
/// resolution and then an object-write state transition.
pub async fn commit_object_write_qualification_put_outcome(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    dispatch: ObjectWriteQualificationPutDispatch<'_>,
    outcome: ObjectWriteQualificationPutOutcome,
    absolute_deadline: Instant,
) -> Result<ObjectPutAttempt, QualificationFaultAuthorityError> {
    validate_object_put_attempt(authority, attempt)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    let ObjectPutState::ProviderIssued {
        spool,
        issued_at_unix_ms,
    } = &attempt.state
    else {
        return Err(QualificationFaultAuthorityError::Conflict);
    };
    let expected_sealed =
        object_write_qualification_sealed_request(&attempt.descriptor, *issued_at_unix_ms)
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if dispatch.request.downstream.descriptor != attempt.descriptor
        || dispatch.request.downstream.spool != *spool
        || dispatch.sealed_request != expected_sealed
    {
        return Err(QualificationFaultAuthorityError::Conflict);
    }
    validate_qualification_authorization_for_descriptor(
        &attempt.descriptor,
        dispatch.guard.authorization(),
    )
    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    match outcome {
        ObjectWriteQualificationPutOutcome::SuccessfulPut(successful_put) => {
            let response_loss = dispatch
                .guard
                .commit_response_loss(*successful_put, absolute_deadline)
                .await?;
            validate_qualification_response_loss(
                &attempt.descriptor,
                *issued_at_unix_ms,
                &response_loss,
            )
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            mark_object_write_qualification_response_lost_in(authority, attempt, response_loss)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)
        }
        ObjectWriteQualificationPutOutcome::PreconditionFailedExactVisible(head_evidence) => {
            if head_evidence.preceding_conditional_request.is_none() {
                return Err(QualificationFaultAuthorityError::InvalidEvidence);
            }
            let receipt = dispatch
                .guard
                .commit_unproven_visible(dispatch.sealed_request, *head_evidence, absolute_deadline)
                .await?;
            validate_qualification_unproven_visible(
                &attempt.descriptor,
                Some(*issued_at_unix_ms),
                &receipt,
            )
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            complete_object_write_qualification_unproven_visible_in(authority, attempt, receipt)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)
        }
    }
}

pub struct ObjectWriteQualificationAmbiguityCommit {
    outcome: ObjectPutTerminalState,
}

/// Convert fresh exact HEAD evidence for an already committed response-loss
/// resolution into a one-shot qualified terminal capability.
pub fn seal_object_write_qualification_ambiguity(
    attempt: &ObjectPutAttempt,
    visibility: ObjectWriteVisibilityOutcome,
) -> Result<ObjectWriteQualificationAmbiguityCommit, ObjectWriteAuthorityError> {
    let ObjectPutState::QualificationResponseLost { response_loss, .. } = &attempt.state else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    let ObjectWriteVisibilityOutcome::VisibleExact {
        provider_attempt_id,
        visibility_receipt_id,
        provider_request,
        preceding_conditional_request,
        observed_at_unix_ms,
    } = visibility
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    let ambiguity = ObjectWriteQualificationAmbiguityReceiptV1 {
        version: ContractVersion::V1,
        response_loss: response_loss.as_ref().clone(),
        head: ObjectWriteQualificationHeadEvidenceV1 {
            provider_attempt_id,
            visibility_receipt_id: visibility_receipt_id.clone(),
            preceding_conditional_request,
            provider_request: *provider_request,
            observed_at_unix_ms,
        },
    };
    validate_qualification_ambiguity(&attempt.descriptor, &ambiguity)?;
    let outcome = ObjectPutTerminalState::SucceededVisible {
        put_receipt_id: ambiguity
            .response_loss
            .successful_put
            .put_receipt_id
            .clone(),
        put_completed_at_unix_ms: ambiguity.response_loss.successful_put.completed_at_unix_ms,
        visibility_receipt_id,
        visible_at_unix_ms: observed_at_unix_ms,
        qualification_ambiguity: Some(Box::new(ambiguity)),
    };
    Ok(ObjectWriteQualificationAmbiguityCommit { outcome })
}

pub fn adopt_object_write_qualification_ambiguity(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    committed: ObjectWriteQualificationAmbiguityCommit,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
    if let ObjectPutState::Terminal {
        outcome: existing, ..
    } = &attempt.state
    {
        return if existing == &committed.outcome {
            Ok(attempt.clone())
        } else {
            Err(ObjectWriteAuthorityError::StaleAttempt)
        };
    }
    let ObjectPutState::QualificationResponseLost {
        spool,
        issued_at_unix_ms,
        response_loss,
    } = &attempt.state
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    let ObjectPutTerminalState::SucceededVisible {
        qualification_ambiguity: Some(ambiguity),
        ..
    } = &committed.outcome
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    if ambiguity.response_loss != **response_loss {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    validate_qualification_ambiguity(&attempt.descriptor, ambiguity)?;
    if terminal_at(&committed.outcome) < *issued_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    let mut updated = attempt.clone();
    updated.state = ObjectPutState::Terminal {
        outcome: committed.outcome,
        spool: TerminalObjectWriteSpool::Retained {
            spool: spool.clone(),
        },
    };
    validate_object_put_attempt(authority, &updated)?;
    Ok(updated)
}

pub fn complete_object_write_terminal(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    outcome: ObjectPutTerminalState,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
    if attempt.descriptor.qualification_fault.is_some() {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    if let ObjectPutState::Terminal {
        outcome: existing, ..
    } = &attempt.state
    {
        return if existing == &outcome {
            Ok(attempt.clone())
        } else {
            Err(ObjectWriteAuthorityError::StaleAttempt)
        };
    }
    let (spool, issued_at_unix_ms) = match &attempt.state {
        ObjectPutState::ProviderIssued {
            spool,
            issued_at_unix_ms,
        } => (spool, *issued_at_unix_ms),
        _ => return Err(ObjectWriteAuthorityError::InvalidTransition),
    };
    match &outcome {
        ObjectPutTerminalState::SucceededVisible {
            qualification_ambiguity: None,
            ..
        }
        | ObjectPutTerminalState::PermanentlyFailed { .. } => {}
        _ => return Err(ObjectWriteAuthorityError::InvalidTransition),
    }
    if terminal_at(&outcome) < issued_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    let mut updated = attempt.clone();
    updated.state = ObjectPutState::Terminal {
        outcome,
        spool: TerminalObjectWriteSpool::Retained {
            spool: spool.clone(),
        },
    };
    validate_object_put_attempt(authority, &updated)?;
    Ok(updated)
}

pub fn mark_terminal_object_write_spool_removed(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    removal_receipt_id: AsciiText,
    removed_at_unix_ms: UnixMillis,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
    let ObjectPutState::Terminal { outcome, spool } = &attempt.state else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    if matches!(spool, TerminalObjectWriteSpool::Removed { .. }) {
        return Ok(attempt.clone());
    }
    let TerminalObjectWriteSpool::Retained { spool } = spool else {
        return Err(ObjectWriteAuthorityError::CorruptState);
    };
    if removed_at_unix_ms < terminal_at(outcome) {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    let mut updated = attempt.clone();
    updated.state = ObjectPutState::Terminal {
        outcome: outcome.clone(),
        spool: TerminalObjectWriteSpool::Removed {
            spool: spool.clone(),
            removal_receipt_id,
            removed_at_unix_ms,
        },
    };
    validate_object_put_attempt(authority, &updated)?;
    Ok(updated)
}

pub fn advance_object_write_terminal_prefix(
    authority: &ObjectWriteAuthority,
    contiguous_terminal_attempts: &[ObjectPutAttempt],
) -> Result<ObjectWriteAuthority, ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    let mut updated = authority.clone();
    for attempt in contiguous_terminal_attempts {
        validate_object_put_attempt(authority, attempt)?;
        let expected = updated
            .terminal_prefix_sequence
            .get()
            .checked_add(1)
            .ok_or(ObjectWriteAuthorityError::SequenceExhausted)?;
        if attempt.descriptor.accepted_sequence.get() != expected {
            return Err(ObjectWriteAuthorityError::NonContiguousTerminalPrefix);
        }
        updated.terminal_prefix_sha256 =
            advance_terminal_prefix_sha256(&updated.terminal_prefix_sha256, attempt)?;
        updated.terminal_prefix_sequence = attempt.descriptor.accepted_sequence;
    }
    validate_object_write_authority(&updated)?;
    Ok(updated)
}

pub fn reject_object_write_before_accept(
    authority: &ObjectWriteAuthority,
    ingress_attempt: &ObjectWriteIngressAttempt,
    reason: ObjectWriteRejectionReason,
    rejection_receipt_id: AsciiText,
    rejected_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteIngressAttempt, ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    validate_object_write_ingress_attempt(ingress_attempt)?;
    if reason == ObjectWriteRejectionReason::WriterClosed
        && matches!(authority.state, ObjectWriteAuthorityState::Open)
    {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    if ingress_attempt.ingress.writer_authority_id != authority.writer.authority_id {
        return Err(ObjectWriteAuthorityError::BindingMismatch);
    }
    let ObjectWriteIngressState::DurableSpooled { spool } = &ingress_attempt.state else {
        return Err(ObjectWriteAuthorityError::SpoolNotDurable);
    };
    let rejected = ObjectWriteIngressAttempt {
        ingress: ingress_attempt.ingress.clone(),
        state: ObjectWriteIngressState::RejectedBeforeAccept {
            spool: spool.clone(),
            reason,
            rejection_receipt_id,
            rejected_at_unix_ms,
        },
    };
    validate_object_write_ingress_attempt(&rejected)?;
    Ok(rejected)
}

pub fn validate_downstream_put(
    request: &ObjectWriteDownstreamPut,
    absolute_deadline: Instant,
) -> Result<(), ObjectWriteAuthorityError> {
    if Instant::now() >= absolute_deadline {
        return Err(ObjectWriteAuthorityError::InvalidRequest);
    }
    if request.descriptor.qualification_fault.is_some() {
        return Err(ObjectWriteAuthorityError::InvalidRequest);
    }
    validate_downstream_put_binding(request)
}

pub fn validate_qualification_downstream_put(
    request: &ObjectWriteQualificationPut,
    absolute_deadline: Instant,
) -> Result<(), ObjectWriteAuthorityError> {
    if Instant::now() >= absolute_deadline {
        return Err(ObjectWriteAuthorityError::InvalidRequest);
    }
    validate_qualification_downstream_put_binding(&request.downstream)
}

fn validate_qualification_downstream_put_binding(
    request: &ObjectWriteDownstreamPut,
) -> Result<(), ObjectWriteAuthorityError> {
    if request.descriptor.qualification_fault.is_none() {
        return Err(ObjectWriteAuthorityError::InvalidRequest);
    }
    validate_downstream_put_binding(request)
}

fn validate_downstream_put_binding(
    request: &ObjectWriteDownstreamPut,
) -> Result<(), ObjectWriteAuthorityError> {
    let request_id = object_put_request_id(
        &request.descriptor.writer_authority_id,
        &request.descriptor.target,
        &request.descriptor.volume_id,
        &request.descriptor.key,
        &request.descriptor.content_sha256,
        request.descriptor.content_length,
        request
            .descriptor
            .qualification_fault
            .as_ref()
            .map(|fault| (&request.descriptor.credential, fault)),
    )?;
    if request_id != request.descriptor.request_id
        || request.descriptor.provider_attempt_id != object_put_provider_attempt_id(&request_id)?
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    validate_durable_spool_receipt(&request.spool, &request.descriptor)
}

fn retire_object_write_credential(
    binding: &ObjectWriteCredentialBinding,
    cause: ObjectWriteCredentialRetirementCause,
    retired_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteCredentialBinding, ObjectWriteAuthorityError> {
    if let ObjectWriteCredentialState::Retired {
        cause: existing, ..
    } = &binding.state
    {
        return if existing == &cause {
            Ok(binding.clone())
        } else {
            Err(ObjectWriteAuthorityError::StaleAttempt)
        };
    }
    if retired_at_unix_ms < binding.registered_at_unix_ms {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    }
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.object-write-credential-retirement.v1")?;
    hash_frame(
        &mut hasher,
        binding.credential.credential_id.as_str().as_bytes(),
    )?;
    match &cause {
        ObjectWriteCredentialRetirementCause::ParentCutoff { fence_attempt_id } => {
            hash_frame(&mut hasher, b"parent-cutoff")?;
            hash_frame(&mut hasher, fence_attempt_id.as_str().as_bytes())?;
        }
        ObjectWriteCredentialRetirementCause::ExactRelease {
            release_transition_id,
        } => {
            hash_frame(&mut hasher, b"exact-release")?;
            hash_frame(&mut hasher, release_transition_id.as_str().as_bytes())?;
        }
    }
    let retirement_receipt_id = AsciiText::new(format!("owcr1_{}", hex_lower(&hasher.finalize())))
        .ok_or(ObjectWriteAuthorityError::InvalidRequest)?;
    let mut retired = binding.clone();
    retired.state = ObjectWriteCredentialState::Retired {
        cause,
        retirement_receipt_id,
        retired_at_unix_ms,
    };
    Ok(retired)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(*byte >> 4)]));
        value.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    value
}

pub fn begin_object_writer_cutoff(
    authority: &ObjectWriteAuthority,
    credentials: &[ObjectWriteCredentialBinding],
    fence_attempt_id: &Id,
    cutoff_effective_at_unix_ms: UnixMillis,
) -> Result<(ObjectWriteAuthority, Vec<ObjectWriteCredentialBinding>), ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    for credential in credentials {
        validate_object_write_credential(authority, credential)?;
    }
    let updated = match &authority.state {
        ObjectWriteAuthorityState::Open => {
            let mut updated = authority.clone();
            updated.state = ObjectWriteAuthorityState::CutoffPending {
                fence_attempt_id: fence_attempt_id.clone(),
                cutoff_sequence: authority.max_accepted_sequence,
                cutoff_effective_at_unix_ms,
            };
            updated
        }
        ObjectWriteAuthorityState::CutoffPending {
            fence_attempt_id: existing,
            cutoff_effective_at_unix_ms: existing_at,
            ..
        } if existing == fence_attempt_id && *existing_at == cutoff_effective_at_unix_ms => {
            authority.clone()
        }
        ObjectWriteAuthorityState::CutoffComplete { receipt }
            if &receipt.fence_attempt_id == fence_attempt_id
                && receipt.cutoff_effective_at_unix_ms == cutoff_effective_at_unix_ms =>
        {
            authority.clone()
        }
        _ => return Err(ObjectWriteAuthorityError::StaleAttempt),
    };
    let cause = ObjectWriteCredentialRetirementCause::ParentCutoff {
        fence_attempt_id: fence_attempt_id.clone(),
    };
    let retired = credentials
        .iter()
        .map(|credential| {
            if matches!(credential.state, ObjectWriteCredentialState::Active) {
                retire_object_write_credential(
                    credential,
                    cause.clone(),
                    cutoff_effective_at_unix_ms,
                )
            } else {
                Ok(credential.clone())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    for credential in &retired {
        validate_object_write_credential(&updated, credential)?;
    }
    Ok((updated, retired))
}

pub fn complete_object_writer_cutoff(
    authority: &ObjectWriteAuthority,
    completed_at_unix_ms: UnixMillis,
) -> Result<(ObjectWriteAuthority, ObjectWriteCutoffReceipt), ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    if let ObjectWriteAuthorityState::CutoffComplete { receipt } = &authority.state {
        return Ok((authority.clone(), receipt.clone()));
    }
    let ObjectWriteAuthorityState::CutoffPending {
        fence_attempt_id,
        cutoff_sequence,
        cutoff_effective_at_unix_ms,
    } = &authority.state
    else {
        return Err(ObjectWriteAuthorityError::WriterClosed);
    };
    if authority.terminal_prefix_sequence != *cutoff_sequence {
        return Err(ObjectWriteAuthorityError::CutoffNotReady);
    }
    let cutoff_receipt_id = barrier_receipt_id(authority, b"cutoff", "owcut1_")?;
    let accepted_put_terminal_receipt_id =
        barrier_receipt_id(authority, b"terminal-prefix", "owterm1_")?;
    let successful_put_visibility_receipt_id =
        barrier_receipt_id(authority, b"successful-visible", "owvis1_")?;
    let receipt = ObjectWriteCutoffReceipt {
        writer_authority_id: authority.writer.authority_id.clone(),
        fence_attempt_id: fence_attempt_id.clone(),
        cutoff_receipt_id,
        cutoff_effective_at_unix_ms: *cutoff_effective_at_unix_ms,
        cutoff_sequence: *cutoff_sequence,
        accepted_put_terminal_receipt_id,
        accepted_puts_terminal_at_unix_ms: completed_at_unix_ms,
        terminal_sequence: authority.terminal_prefix_sequence,
        terminal_prefix_sha256: authority.terminal_prefix_sha256.clone(),
        successful_put_visibility_receipt_id,
        successful_puts_visible_at_unix_ms: completed_at_unix_ms,
    };
    let mut updated = authority.clone();
    updated.state = ObjectWriteAuthorityState::CutoffComplete {
        receipt: receipt.clone(),
    };
    validate_object_write_authority(&updated)?;
    Ok((updated, receipt))
}

fn barrier_receipt_id(
    authority: &ObjectWriteAuthority,
    kind: &[u8],
    prefix: &str,
) -> Result<AsciiText, ObjectWriteAuthorityError> {
    let ObjectWriteAuthorityState::CutoffPending {
        fence_attempt_id,
        cutoff_sequence,
        cutoff_effective_at_unix_ms,
    } = &authority.state
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.object-write-barrier-receipt.v1")?;
    hash_frame(&mut hasher, kind)?;
    hash_frame(
        &mut hasher,
        authority.writer.authority_id.as_str().as_bytes(),
    )?;
    hash_frame(&mut hasher, fence_attempt_id.as_str().as_bytes())?;
    hash_frame(
        &mut hasher,
        &cutoff_effective_at_unix_ms.get().to_be_bytes(),
    )?;
    hash_frame(&mut hasher, &cutoff_sequence.get().to_be_bytes())?;
    hash_frame(
        &mut hasher,
        authority.terminal_prefix_sha256.as_str().as_bytes(),
    )?;
    AsciiText::new(format!("{prefix}{}", hex_lower(&hasher.finalize())))
        .ok_or(ObjectWriteAuthorityError::InvalidRequest)
}

pub fn advance_terminal_prefix_sha256(
    previous: &Sha256Digest,
    attempt: &ObjectPutAttempt,
) -> Result<Sha256Digest, ObjectWriteAuthorityError> {
    let ObjectPutState::Terminal { outcome, .. } = &attempt.state else {
        return Err(ObjectWriteAuthorityError::NonContiguousTerminalPrefix);
    };
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.object-write-terminal-prefix.v1")?;
    hash_frame(&mut hasher, previous.as_str().as_bytes())?;
    hash_frame(
        &mut hasher,
        &attempt.descriptor.accepted_sequence.get().to_be_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        attempt.descriptor.request_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        attempt.descriptor.target.canonical_logical_key.as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        attempt.descriptor.content_sha256.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        &attempt.descriptor.content_length.get().to_be_bytes(),
    )?;
    match outcome {
        ObjectPutTerminalState::SucceededVisible {
            put_receipt_id,
            put_completed_at_unix_ms,
            visibility_receipt_id,
            visible_at_unix_ms,
            qualification_ambiguity,
        } => {
            hash_frame(&mut hasher, b"succeeded-visible")?;
            hash_frame(&mut hasher, put_receipt_id.as_str().as_bytes())?;
            hash_frame(&mut hasher, &put_completed_at_unix_ms.get().to_be_bytes())?;
            hash_frame(&mut hasher, visibility_receipt_id.as_str().as_bytes())?;
            hash_frame(&mut hasher, &visible_at_unix_ms.get().to_be_bytes())?;
            if let Some(receipt) = qualification_ambiguity {
                let authorization_sha256 = object_write_qualification_authorization_sha256(
                    &receipt.response_loss.authorization,
                )
                .map_err(|_| ObjectWriteAuthorityError::CorruptState)?;
                let receipt_bytes = encode_object_write_qualification_ambiguity_receipt(receipt)
                    .map_err(|_| ObjectWriteAuthorityError::CorruptState)?;
                let receipt_sha256 = Sha256Digest::from_bytes(Sha256::digest(receipt_bytes).into());
                hash_frame(&mut hasher, b"qualification-ambiguity")?;
                hash_frame(&mut hasher, authorization_sha256.as_str().as_bytes())?;
                hash_frame(
                    &mut hasher,
                    receipt
                        .response_loss
                        .injection_receipt_id
                        .as_str()
                        .as_bytes(),
                )?;
                hash_frame(&mut hasher, receipt_sha256.as_str().as_bytes())?;
            }
        }
        ObjectPutTerminalState::PermanentlyFailed {
            failure_receipt_id,
            failed_at_unix_ms,
        } => {
            hash_frame(&mut hasher, b"permanently-failed")?;
            hash_frame(&mut hasher, failure_receipt_id.as_str().as_bytes())?;
            hash_frame(&mut hasher, &failed_at_unix_ms.get().to_be_bytes())?;
        }
        ObjectPutTerminalState::QualificationUnprovenVisible { receipt } => {
            hash_frame(&mut hasher, b"qualification-unproven-visible")?;
            let evidence = encode_object_write_qualification_unproven_visible_receipt(receipt)
                .map_err(|_| ObjectWriteAuthorityError::CorruptState)?;
            hash_frame(&mut hasher, &evidence)?;
        }
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) -> Result<(), ObjectWriteAuthorityError> {
    let length =
        u64::try_from(value.len()).map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

pub type ObjectWriteDownstreamFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ObjectWriteDownstreamError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObjectWriteDownstreamError {
    #[error("downstream object write deadline elapsed")]
    DeadlineExceeded,
    #[error("downstream object write result is ambiguous; discover exact visibility")]
    Ambiguous,
    #[error("downstream object store is unavailable")]
    Unavailable,
    #[error("downstream object conflicts with the immutable request")]
    ConflictingObject,
    #[error("downstream request or receipt is invalid")]
    InvalidRequest,
}

/// Trusted downstream used only by the gateway service.  Provider adapters
/// never authenticate Nodes and never allocate accepted sequences.
pub trait ObjectWriteGatewayDownstream: Send + Sync {
    fn put_exact<'a>(
        &'a self,
        request: ObjectWriteDownstreamPut,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteDownstreamPutOutcome>;

    fn put_qualification_exact<'a>(
        &'a self,
        request: &'a ObjectWriteQualificationPut,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteQualificationPutOutcome>;

    fn discover_visibility<'a>(
        &'a self,
        descriptor: &'a ObjectPutDescriptor,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteVisibilityOutcome>;
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use cats_api::object_write_gateway::{
        object_write_qualification_injection_receipt_id,
        object_write_qualification_unproven_resolution_receipt_id,
        ObjectWriteQualificationUnprovenReasonV1,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn ascii(value: &str) -> AsciiText {
        AsciiText::new(value).unwrap()
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn scope() -> ProviderScope {
        ProviderScope {
            provider: id("object-provider"),
            partition: id("partition-a"),
            account_id: id("account-a"),
            region: id("region-a"),
        }
    }

    fn credential() -> ObjectWriteCredentialReference {
        ObjectWriteCredentialReference {
            credential_id: id("credential-a"),
            public_key_spki_sha256: Sha256Digest::from_bytes([2; 32]),
        }
    }

    fn authority() -> ObjectWriteAuthority {
        ObjectWriteAuthority {
            writer: ObjectWriterIdentity {
                authority_id: id("writer-a"),
                host_provider_scope: scope(),
                immutable_host_id: id("host-a"),
                node_id: id("node-a"),
                object_provider_scope: scope(),
                workload_principal_id: ascii("gateway-role-a"),
                object_store_scope_id: ascii("object-store-scope-a"),
            },
            state: ObjectWriteAuthorityState::Open,
            max_accepted_sequence: WireU64::new(1).unwrap(),
            terminal_prefix_sequence: WireU64::new(0).unwrap(),
            terminal_prefix_sha256: empty_terminal_prefix_sha256(),
        }
    }

    fn fault() -> ObjectWriteQualificationFaultV1 {
        ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
            qualification_id: id("qualification-a"),
            fault_id: RandomId128::new("3".repeat(32)).unwrap(),
            qualification_catalog_sha256: Sha256Digest::from_bytes([4; 32]),
        }
    }

    fn descriptor(
        authority: &ObjectWriteAuthority,
        qualification_fault: Option<ObjectWriteQualificationFaultV1>,
    ) -> ObjectPutDescriptor {
        let volume_id = id("volume-a");
        let key = ObjectWriteImmutableKey::VolumeMap;
        let content_sha256 = Sha256Digest::from_bytes([5; 32]);
        let target = ObjectWriteTarget {
            object_provider_scope: authority.writer.object_provider_scope.clone(),
            object_store_scope_id: authority.writer.object_store_scope_id.clone(),
            canonical_logical_key: object_write_key(&volume_id, &key, &content_sha256).unwrap(),
        };
        let credential = credential();
        let request_id = object_put_request_id(
            &authority.writer.authority_id,
            &target,
            &volume_id,
            &key,
            &content_sha256,
            WireU64::new(64).unwrap(),
            qualification_fault
                .as_ref()
                .map(|fault| (&credential, fault)),
        )
        .unwrap();
        ObjectPutDescriptor {
            writer_authority_id: authority.writer.authority_id.clone(),
            accepted_sequence: WireU64::new(1).unwrap(),
            provider_attempt_id: object_put_provider_attempt_id(&request_id).unwrap(),
            request_id,
            credential,
            volume_id,
            key,
            target,
            content_sha256,
            content_length: WireU64::new(64).unwrap(),
            qualification_fault,
            accepted_at_unix_ms: millis(11),
        }
    }

    fn spool(descriptor: &ObjectPutDescriptor) -> DurableObjectWriteSpoolReceipt {
        DurableObjectWriteSpoolReceipt {
            spool_id: object_write_spool_id(&descriptor.request_id).unwrap(),
            request_id: descriptor.request_id.clone(),
            content_sha256: descriptor.content_sha256.clone(),
            content_length: descriptor.content_length,
            file_fsync_receipt_id: ascii("file-fsync-a"),
            directory_fsync_receipt_id: ascii("directory-fsync-a"),
            durable_at_unix_ms: millis(10),
        }
    }

    fn accepted_attempt(descriptor: ObjectPutDescriptor) -> ObjectPutAttempt {
        let spool = spool(&descriptor);
        ObjectPutAttempt {
            descriptor,
            state: ObjectPutState::AcceptedSpooled { spool },
        }
    }

    fn issued_attempt(descriptor: ObjectPutDescriptor) -> ObjectPutAttempt {
        let spool = spool(&descriptor);
        ObjectPutAttempt {
            descriptor,
            state: ObjectPutState::ProviderIssued {
                spool,
                issued_at_unix_ms: millis(12),
            },
        }
    }

    fn authorization(
        request: ObjectWriteQualificationAuthorizationRequestV1,
    ) -> ObjectWriteQualificationAuthorizationV1 {
        ObjectWriteQualificationAuthorizationV1 {
            version: ContractVersion::V1,
            mutation_class: ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity,
            qualification_id: id("qualification-a"),
            workspace_id: id("workspace-a"),
            deployment_id: id("deployment-a"),
            release_id: id("release-a"),
            source_commit_sha: "a".repeat(40),
            control_schema_version: WireU64::new(16).unwrap(),
            qualification_catalog_sha256: Sha256Digest::from_bytes([4; 32]),
            admission_binding_sha256: Sha256Digest::from_bytes([6; 32]),
            admission_revision: Epoch::new(7).unwrap(),
            request,
            authorized_at_unix_ms: millis(13),
            qualification_expires_at_unix_ms: millis(100),
        }
    }

    fn successful_put(
        descriptor: &ObjectPutDescriptor,
        request_id: &str,
    ) -> ObjectWriteSuccessfulPutV1 {
        ObjectWriteSuccessfulPutV1 {
            provider_attempt_id: descriptor.provider_attempt_id.clone(),
            put_receipt_id: ascii("put-receipt-a"),
            provider_request: ObjectWriteProviderRequestObservationV1 {
                request_id: ascii(request_id),
                extended_request_id: Some(ascii("provider-put-extended-a")),
                content_sha256: descriptor.content_sha256.clone(),
                content_length: None,
                entity_tag: Some(ascii("entity-tag-a")),
                version_id: Some(ascii("version-a")),
            },
            completed_at_unix_ms: millis(20),
        }
    }

    fn response_loss(descriptor: &ObjectPutDescriptor) -> ObjectWriteQualificationResponseLossV1 {
        let request = object_write_qualification_authorization_request(descriptor)
            .unwrap()
            .unwrap();
        let authorization = authorization(request);
        let successful_put = successful_put(descriptor, "provider-put-request-a");
        let injected_at_unix_ms = millis(21);
        let injection_receipt_id = object_write_qualification_injection_receipt_id(
            &authorization,
            &successful_put,
            injected_at_unix_ms,
        )
        .unwrap();
        ObjectWriteQualificationResponseLossV1 {
            version: ContractVersion::V1,
            authorization,
            successful_put,
            injection_receipt_id,
            injected_at_unix_ms,
        }
    }

    fn head_evidence(descriptor: &ObjectPutDescriptor) -> ObjectWriteQualificationHeadEvidenceV1 {
        ObjectWriteQualificationHeadEvidenceV1 {
            provider_attempt_id: descriptor.provider_attempt_id.clone(),
            visibility_receipt_id: ascii("visibility-unproven-a"),
            preceding_conditional_request: None,
            provider_request: ObjectWriteProviderRequestObservationV1 {
                request_id: ascii("provider-head-unproven-a"),
                extended_request_id: Some(ascii("provider-head-unproven-extended-a")),
                content_sha256: descriptor.content_sha256.clone(),
                content_length: Some(descriptor.content_length),
                entity_tag: Some(ascii("entity-tag-a")),
                version_id: Some(ascii("version-a")),
            },
            observed_at_unix_ms: millis(30),
        }
    }

    fn precondition_head_evidence(
        descriptor: &ObjectPutDescriptor,
    ) -> ObjectWriteQualificationHeadEvidenceV1 {
        let mut head = head_evidence(descriptor);
        head.preceding_conditional_request =
            Some(Box::new(ObjectWriteConditionalRequestEvidenceV1 {
                provider_attempt_id: descriptor.provider_attempt_id.clone(),
                outcome: cats_api::object_write_gateway::ObjectWriteConditionalRequestOutcomeV1::PreconditionFailed,
                provider_request: ObjectWriteProviderRequestObservationV1 {
                    request_id: ascii("provider-conditional-request-a"),
                    extended_request_id: Some(ascii("provider-conditional-extended-a")),
                    content_sha256: descriptor.content_sha256.clone(),
                    content_length: Some(descriptor.content_length),
                    entity_tag: None,
                    version_id: None,
                },
                observed_at_unix_ms: millis(29),
            }));
        head
    }

    fn exact_visibility(descriptor: &ObjectPutDescriptor) -> ObjectWriteVisibilityOutcome {
        let evidence = head_evidence(descriptor);
        ObjectWriteVisibilityOutcome::VisibleExact {
            provider_attempt_id: evidence.provider_attempt_id,
            visibility_receipt_id: evidence.visibility_receipt_id,
            provider_request: Box::new(evidence.provider_request),
            preceding_conditional_request: evidence.preceding_conditional_request,
            observed_at_unix_ms: evidence.observed_at_unix_ms,
        }
    }

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test authority future unexpectedly yielded"),
        }
    }

    fn assert_pending<F: Future>(future: Pin<&mut F>) {
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.poll(&mut context), Poll::Pending));
    }

    fn unproven_receipt(
        descriptor: &ObjectPutDescriptor,
        issued_at_unix_ms: UnixMillis,
        head_evidence: ObjectWriteQualificationHeadEvidenceV1,
    ) -> ObjectWriteQualificationUnprovenVisibleReceiptV1 {
        let sealed_request =
            object_write_qualification_sealed_request(descriptor, issued_at_unix_ms).unwrap();
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

    struct TestAuthorityState {
        locked: bool,
        resolution: Option<ObjectWriteQualificationDurableResolution>,
        waiters: Vec<Waker>,
        events: Vec<&'static str>,
        rollback_drops: usize,
    }

    struct TestLease {
        shared: Arc<Mutex<TestAuthorityState>>,
        rollback_if_dropped: bool,
        committed: bool,
    }

    impl TestLease {
        fn commit(
            &mut self,
            resolution: ObjectWriteQualificationDurableResolution,
        ) -> Result<(), QualificationFaultAuthorityError> {
            let mut state = self.shared.lock().unwrap();
            if state.resolution.is_some() {
                return Err(QualificationFaultAuthorityError::Conflict);
            }
            state.resolution = Some(resolution);
            self.committed = true;
            Ok(())
        }
    }

    impl Drop for TestLease {
        fn drop(&mut self) {
            let waiters = {
                let mut state = self.shared.lock().unwrap();
                if self.rollback_if_dropped && !self.committed {
                    state.rollback_drops += 1;
                }
                state.locked = false;
                std::mem::take(&mut state.waiters)
            };
            for waiter in waiters {
                waiter.wake();
            }
        }
    }

    struct TestRequestGuard {
        request: ObjectWriteQualificationAuthorizationRequestV1,
        resolution: Option<ObjectWriteQualificationDurableResolution>,
        lease: Option<TestLease>,
    }

    impl QualificationFaultRequestGuard for TestRequestGuard {
        fn request(&self) -> &ObjectWriteQualificationAuthorizationRequestV1 {
            &self.request
        }

        fn durable_resolution(&self) -> Option<&ObjectWriteQualificationDurableResolution> {
            self.resolution.as_ref()
        }

        fn commit_unproven_visible<'a>(
            mut self: Box<Self>,
            sealed_request: ObjectWriteQualificationSealedRequestV1,
            head_evidence: ObjectWriteQualificationHeadEvidenceV1,
            absolute_deadline: Instant,
        ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
        where
            Self: 'a,
        {
            Box::pin(async move {
                if Instant::now() >= absolute_deadline || self.resolution.is_some() {
                    return Err(QualificationFaultAuthorityError::DeadlineExceeded);
                }
                let receipt = unproven_receipt(
                    &ObjectPutDescriptor {
                        writer_authority_id: sealed_request
                            .authorization_request
                            .writer_authority_id
                            .clone(),
                        accepted_sequence: sealed_request.accepted_sequence,
                        request_id: sealed_request.authorization_request.request_id.clone(),
                        credential: sealed_request.authorization_request.credential.clone(),
                        volume_id: sealed_request.ingress_descriptor.volume_id.clone(),
                        key: sealed_request.ingress_descriptor.key.clone(),
                        target: ObjectWriteTarget {
                            object_provider_scope: sealed_request
                                .authorization_request
                                .object_provider_scope
                                .clone(),
                            object_store_scope_id: sealed_request
                                .authorization_request
                                .object_store_scope_id
                                .clone(),
                            canonical_logical_key: sealed_request
                                .authorization_request
                                .canonical_logical_key
                                .clone(),
                        },
                        content_sha256: sealed_request.ingress_descriptor.content_sha256.clone(),
                        content_length: sealed_request.ingress_descriptor.content_length,
                        qualification_fault: sealed_request
                            .ingress_descriptor
                            .qualification_fault
                            .clone(),
                        provider_attempt_id: sealed_request
                            .authorization_request
                            .provider_attempt_id
                            .clone(),
                        accepted_at_unix_ms: sealed_request.accepted_at_unix_ms,
                    },
                    sealed_request.issued_at_unix_ms,
                    head_evidence,
                );
                self.lease.as_mut().unwrap().commit(
                    ObjectWriteQualificationDurableResolution::UnprovenVisible(Box::new(
                        receipt.clone(),
                    )),
                )?;
                Ok(receipt)
            })
        }

        fn authorize_put<'a>(
            mut self: Box<Self>,
            absolute_deadline: Instant,
        ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultAuthorizationGuard + 'a>>
        where
            Self: 'a,
        {
            Box::pin(async move {
                if Instant::now() >= absolute_deadline {
                    return Err(QualificationFaultAuthorityError::DeadlineExceeded);
                }
                if self.resolution.is_some() {
                    return Err(QualificationFaultAuthorityError::Conflict);
                }
                let lease = self.lease.take().unwrap();
                lease.shared.lock().unwrap().events.push("authorize");
                Ok(Box::new(TestAuthorizationGuard {
                    authorization: authorization(self.request.clone()),
                    lease: Some(lease),
                })
                    as Box<dyn QualificationFaultAuthorizationGuard>)
            })
        }
    }

    struct TestAuthorizationGuard {
        authorization: ObjectWriteQualificationAuthorizationV1,
        lease: Option<TestLease>,
    }

    impl QualificationFaultAuthorizationGuard for TestAuthorizationGuard {
        fn authorization(&self) -> &ObjectWriteQualificationAuthorizationV1 {
            &self.authorization
        }

        fn commit_response_loss<'a>(
            mut self: Box<Self>,
            successful_put: ObjectWriteSuccessfulPutV1,
            absolute_deadline: Instant,
        ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationResponseLossV1>
        where
            Self: 'a,
        {
            Box::pin(async move {
                if Instant::now() >= absolute_deadline {
                    return Err(QualificationFaultAuthorityError::DeadlineExceeded);
                }
                let injected_at_unix_ms = millis(21);
                let injection_receipt_id = object_write_qualification_injection_receipt_id(
                    &self.authorization,
                    &successful_put,
                    injected_at_unix_ms,
                )
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
                let response_loss = ObjectWriteQualificationResponseLossV1 {
                    version: ContractVersion::V1,
                    authorization: self.authorization.clone(),
                    successful_put,
                    injection_receipt_id,
                    injected_at_unix_ms,
                };
                self.lease.as_mut().unwrap().commit(
                    ObjectWriteQualificationDurableResolution::ResponseLoss(Box::new(
                        response_loss.clone(),
                    )),
                )?;
                Ok(response_loss)
            })
        }

        fn commit_unproven_visible<'a>(
            mut self: Box<Self>,
            sealed_request: ObjectWriteQualificationSealedRequestV1,
            head_evidence: ObjectWriteQualificationHeadEvidenceV1,
            absolute_deadline: Instant,
        ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
        where
            Self: 'a,
        {
            Box::pin(async move {
                if Instant::now() >= absolute_deadline {
                    return Err(QualificationFaultAuthorityError::DeadlineExceeded);
                }
                if self.authorization.request != sealed_request.authorization_request {
                    return Err(QualificationFaultAuthorityError::InvalidEvidence);
                }
                let receipt = ObjectWriteQualificationUnprovenVisibleReceiptV1 {
                    version: ContractVersion::V1,
                    reason: ObjectWriteQualificationUnprovenReasonV1::ResponseLossReceiptAbsent,
                    resolution_receipt_id:
                        object_write_qualification_unproven_resolution_receipt_id(
                            &sealed_request,
                            ObjectWriteQualificationUnprovenReasonV1::ResponseLossReceiptAbsent,
                            &head_evidence,
                            millis(31),
                        )
                        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
                    sealed_request,
                    head_evidence,
                    resolved_at_unix_ms: millis(31),
                };
                self.lease.as_mut().unwrap().commit(
                    ObjectWriteQualificationDurableResolution::UnprovenVisible(Box::new(
                        receipt.clone(),
                    )),
                )?;
                Ok(receipt)
            })
        }
    }

    struct TestAuthority {
        lock_calls: AtomicUsize,
        shared: Arc<Mutex<TestAuthorityState>>,
    }

    impl TestAuthority {
        fn new(stored: Option<ObjectWriteQualificationDurableResolution>) -> Self {
            Self {
                lock_calls: AtomicUsize::new(0),
                shared: Arc::new(Mutex::new(TestAuthorityState {
                    locked: false,
                    resolution: stored,
                    waiters: Vec::new(),
                    events: Vec::new(),
                    rollback_drops: 0,
                })),
            }
        }

        fn events(&self) -> Vec<&'static str> {
            self.shared.lock().unwrap().events.clone()
        }

        fn rollback_drops(&self) -> usize {
            self.shared.lock().unwrap().rollback_drops
        }

        fn resolution(&self) -> Option<ObjectWriteQualificationDurableResolution> {
            self.shared.lock().unwrap().resolution.clone()
        }
    }

    struct TestLockFuture {
        shared: Arc<Mutex<TestAuthorityState>>,
        request: Option<ObjectWriteQualificationAuthorizationRequestV1>,
        absolute_deadline: Instant,
    }

    impl Future for TestLockFuture {
        type Output = Result<
            Box<dyn QualificationFaultRequestGuard + 'static>,
            QualificationFaultAuthorityError,
        >;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            if Instant::now() >= self.absolute_deadline {
                return Poll::Ready(Err(QualificationFaultAuthorityError::DeadlineExceeded));
            }
            let resolution = {
                let mut state = self.shared.lock().unwrap();
                if state.locked {
                    if !state
                        .waiters
                        .iter()
                        .any(|waiter| waiter.will_wake(context.waker()))
                    {
                        state.waiters.push(context.waker().clone());
                    }
                    return Poll::Pending;
                }
                state.locked = true;
                state.events.push("lock");
                state.resolution.clone()
            };
            let request = self.request.take().unwrap();
            Poll::Ready(Ok(Box::new(TestRequestGuard {
                request,
                resolution: resolution.clone(),
                lease: Some(TestLease {
                    shared: self.shared.clone(),
                    rollback_if_dropped: resolution.is_none(),
                    committed: false,
                }),
            })))
        }
    }

    impl QualificationFaultAuthority for TestAuthority {
        fn lock_request<'a>(
            &'a self,
            request: ObjectWriteQualificationAuthorizationRequestV1,
            absolute_deadline: Instant,
        ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultRequestGuard + 'a>>
        {
            self.lock_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let guard = TestLockFuture {
                    shared: self.shared.clone(),
                    request: Some(request),
                    absolute_deadline,
                }
                .await?;
                Ok(guard as Box<dyn QualificationFaultRequestGuard + 'a>)
            })
        }
    }

    #[test]
    fn ordinary_request_preserves_digest_and_never_invokes_fault_authority() {
        let authority = authority();
        let ordinary = descriptor(&authority, None);
        let ordinary_attempt = issued_attempt(ordinary.clone());
        let fault_authority = TestAuthority::new(None);
        let preparation = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &ordinary_attempt,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        assert!(matches!(
            preparation,
            ObjectWriteQualificationPreparation::Ordinary
        ));
        assert_eq!(fault_authority.lock_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ordinary.request_id.as_str(),
            "sha256:dbb7ba05134b4e07af474f10526bdf7b405e5fba4004684eee4a744c6cce93a0"
        );
        let qualified = descriptor(&authority, Some(fault()));
        assert_eq!(
            qualified.request_id.as_str(),
            "sha256:864efe6f32df6791400787319604fa85ef8821926730c59442d838f259bf7ca8"
        );
    }

    #[test]
    fn fault_put_and_qualified_terminals_require_core_capabilities() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let accepted = accepted_attempt(descriptor.clone());
        validate_object_put_attempt(&authority, &accepted).unwrap();
        let fault_authority = TestAuthority::new(None);
        let preparation = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &accepted,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::Authorized(capability) = preparation else {
            panic!("fresh fault must return a held authorization guard");
        };
        assert_eq!(
            capability.authorization().mutation_class,
            ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity
        );
        let issued = mark_object_write_provider_issued(&authority, &accepted, millis(12)).unwrap();
        let synthetic_ordinary = ObjectWriteDownstreamPut {
            descriptor: descriptor.clone(),
            spool: spool(&descriptor),
        };
        assert_eq!(
            validate_downstream_put(&synthetic_ordinary, Instant::now() + Duration::from_secs(1)),
            Err(ObjectWriteAuthorityError::InvalidRequest)
        );
        let dispatch = seal_object_write_qualification_put(&issued, capability).unwrap();
        validate_qualification_downstream_put(
            dispatch.request(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let lost = poll_ready(commit_object_write_qualification_put_outcome(
            &authority,
            &issued,
            dispatch,
            ObjectWriteQualificationPutOutcome::SuccessfulPut(Box::new(successful_put(
                &descriptor,
                "provider-put-request-a",
            ))),
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectPutState::QualificationResponseLost { response_loss, .. } = &lost.state else {
            panic!("successful qualification PUT must commit response loss");
        };
        assert_eq!(
            mark_object_write_provider_issued(&authority, &lost, millis(22)),
            Err(ObjectWriteAuthorityError::InvalidTransition)
        );
        assert!(complete_object_write_terminal(
            &authority,
            &issued,
            ObjectPutTerminalState::SucceededVisible {
                put_receipt_id: response_loss.successful_put.put_receipt_id.clone(),
                put_completed_at_unix_ms: response_loss.successful_put.completed_at_unix_ms,
                visibility_receipt_id: ascii("visibility-receipt-a"),
                visible_at_unix_ms: millis(30),
                qualification_ambiguity: None,
            },
        )
        .is_err());
        let ambiguity =
            seal_object_write_qualification_ambiguity(&lost, exact_visibility(&descriptor))
                .unwrap();
        let terminal =
            adopt_object_write_qualification_ambiguity(&authority, &lost, ambiguity).unwrap();
        validate_object_put_attempt(&authority, &terminal).unwrap();
        assert!(matches!(
            response_loss.as_ref(),
            ObjectWriteQualificationResponseLossV1 { .. }
        ));
    }

    #[test]
    fn qualified_precondition_outcome_requires_conditional_evidence_and_commits_unproven() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let accepted = accepted_attempt(descriptor.clone());
        let issued = mark_object_write_provider_issued(&authority, &accepted, millis(12)).unwrap();

        let invalid_authority = TestAuthority::new(None);
        let invalid_preparation = poll_ready(prepare_object_write_qualification(
            &invalid_authority,
            &accepted,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::Authorized(invalid_capability) =
            invalid_preparation
        else {
            panic!("fresh fault must authorize");
        };
        let invalid_dispatch =
            seal_object_write_qualification_put(&issued, invalid_capability).unwrap();
        assert_eq!(
            poll_ready(commit_object_write_qualification_put_outcome(
                &authority,
                &issued,
                invalid_dispatch,
                ObjectWriteQualificationPutOutcome::PreconditionFailedExactVisible(Box::new(
                    head_evidence(&descriptor),
                )),
                Instant::now() + Duration::from_secs(1),
            )),
            Err(QualificationFaultAuthorityError::InvalidEvidence)
        );
        assert!(invalid_authority.resolution().is_none());

        let fault_authority = TestAuthority::new(None);
        let preparation = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &accepted,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::Authorized(capability) = preparation else {
            panic!("fresh fault must authorize");
        };
        let dispatch = seal_object_write_qualification_put(&issued, capability).unwrap();
        let terminal = poll_ready(commit_object_write_qualification_put_outcome(
            &authority,
            &issued,
            dispatch,
            ObjectWriteQualificationPutOutcome::PreconditionFailedExactVisible(Box::new(
                precondition_head_evidence(&descriptor),
            )),
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        assert!(matches!(
            terminal.state,
            ObjectPutState::Terminal {
                outcome: ObjectPutTerminalState::QualificationUnprovenVisible { .. },
                ..
            }
        ));
        assert!(matches!(
            fault_authority.resolution(),
            Some(ObjectWriteQualificationDurableResolution::UnprovenVisible(
                _
            ))
        ));
    }

    #[test]
    fn durable_resolutions_replay_before_current_admission() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let issued = issued_attempt(descriptor.clone());
        let stored = response_loss(&descriptor);
        let fault_authority = TestAuthority::new(Some(
            ObjectWriteQualificationDurableResolution::ResponseLoss(Box::new(stored.clone())),
        ));
        let preparation = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &issued,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        match preparation {
            ObjectWriteQualificationPreparation::StoredResponseLoss(found) => {
                assert_eq!(found.receipt(), &stored);
                adopt_object_write_qualification_response_lost(&authority, &issued, found).unwrap();
            }
            _ => panic!("durable response loss must force HEAD-only replay"),
        }
        assert_eq!(fault_authority.events(), vec!["lock"]);

        let unproven = unproven_receipt(&descriptor, millis(12), head_evidence(&descriptor));
        let unproven_authority = TestAuthority::new(Some(
            ObjectWriteQualificationDurableResolution::UnprovenVisible(Box::new(unproven.clone())),
        ));
        let replay = poll_ready(prepare_object_write_qualification(
            &unproven_authority,
            &issued,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::StoredUnprovenVisible(committed) = replay else {
            panic!("durable unproven resolution must exact replay");
        };
        assert_eq!(committed.receipt(), &unproven);
        adopt_object_write_qualification_unproven_visible(&authority, &issued, committed).unwrap();
    }

    #[test]
    fn issued_fault_holds_exclusive_guard_through_head_and_unproven_terminal() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let issued = issued_attempt(descriptor.clone());
        let fault_authority = TestAuthority::new(None);

        let preparation = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &issued,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::DiscoverIssuedVisibility(probe) = preparation
        else {
            panic!("an issued fault must discover durable response loss before HEAD");
        };
        assert_eq!(fault_authority.events(), vec!["lock"]);

        let resolution = poll_ready(resolve_object_write_qualification_after_head(
            &issued,
            probe,
            exact_visibility(&descriptor),
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationHeadResolution::QualificationUnprovenVisible(committed) =
            resolution
        else {
            panic!("exact HEAD without a durable response-loss receipt must be unproven");
        };
        assert_eq!(fault_authority.events(), vec!["lock"]);
        let terminal =
            adopt_object_write_qualification_unproven_visible(&authority, &issued, *committed)
                .unwrap();
        assert_eq!(
            complete_object_write_terminal(
                &authority,
                &terminal,
                ObjectPutTerminalState::PermanentlyFailed {
                    failure_receipt_id: ascii("synthetic"),
                    failed_at_unix_ms: millis(32),
                },
            ),
            Err(ObjectWriteAuthorityError::InvalidTransition)
        );

        let original_prefix = authority.terminal_prefix_sha256.clone();
        let (cutoff, retired) =
            begin_object_writer_cutoff(&authority, &[], &id("fence-a"), millis(31)).unwrap();
        assert!(retired.is_empty());
        let prefixed =
            advance_object_write_terminal_prefix(&cutoff, std::slice::from_ref(&terminal)).unwrap();
        assert_eq!(prefixed.terminal_prefix_sequence, WireU64::new(1).unwrap());
        assert_ne!(prefixed.terminal_prefix_sha256, original_prefix);
        let (_, receipt) = complete_object_writer_cutoff(&prefixed, millis(32)).unwrap();
        assert_eq!(receipt.terminal_sequence, WireU64::new(1).unwrap());
        assert_eq!(
            receipt.terminal_prefix_sha256,
            prefixed.terminal_prefix_sha256
        );

        let removed = mark_terminal_object_write_spool_removed(
            &authority,
            &terminal,
            ascii("spool-removal-a"),
            millis(33),
        )
        .unwrap();
        assert!(matches!(
            removed.state,
            ObjectPutState::Terminal {
                spool: TerminalObjectWriteSpool::Removed { .. },
                ..
            }
        ));
    }

    #[test]
    fn head_not_visible_upgrades_the_same_request_guard_before_dispatch() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let issued = issued_attempt(descriptor);
        let fault_authority = TestAuthority::new(None);
        let preparation = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &issued,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::DiscoverIssuedVisibility(probe) = preparation
        else {
            panic!("issued fault must HEAD before retry authorization");
        };
        let resolution = poll_ready(resolve_object_write_qualification_after_head(
            &issued,
            probe,
            ObjectWriteVisibilityOutcome::NotVisible,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        assert!(matches!(
            resolution,
            ObjectWriteQualificationHeadResolution::Authorized(_)
        ));
        assert_eq!(fault_authority.events(), vec!["lock", "authorize"]);
        drop(resolution);
        assert_eq!(fault_authority.rollback_drops(), 1);
    }

    #[test]
    fn two_replicas_cannot_commit_response_loss_and_unproven_for_one_request() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let accepted = accepted_attempt(descriptor.clone());
        let issued = mark_object_write_provider_issued(&authority, &accepted, millis(12)).unwrap();
        let fault_authority = TestAuthority::new(None);

        let prepared_a = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &accepted,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::Authorized(capability_a) = prepared_a else {
            panic!("replica A must own the authorization guard");
        };
        let dispatch_a = seal_object_write_qualification_put(&issued, capability_a).unwrap();
        let successful = ObjectWriteQualificationPutOutcome::SuccessfulPut(Box::new(
            successful_put(&descriptor, "provider-put-request-a"),
        ));

        let mut replica_b = std::pin::pin!(prepare_object_write_qualification(
            &fault_authority,
            &issued,
            Instant::now() + Duration::from_secs(1),
        ));
        assert_pending(replica_b.as_mut());

        let lost = poll_ready(commit_object_write_qualification_put_outcome(
            &authority,
            &issued,
            dispatch_a,
            successful,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        assert!(matches!(
            lost.state,
            ObjectPutState::QualificationResponseLost { .. }
        ));
        let replay_b = poll_ready(replica_b).unwrap();
        assert!(matches!(
            replay_b,
            ObjectWriteQualificationPreparation::StoredResponseLoss(_)
        ));
        assert!(matches!(
            fault_authority.resolution(),
            Some(ObjectWriteQualificationDurableResolution::ResponseLoss(_))
        ));
    }

    #[test]
    fn rollback_releases_request_guard_and_only_then_second_replica_can_settle() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let accepted = accepted_attempt(descriptor.clone());
        let issued = mark_object_write_provider_issued(&authority, &accepted, millis(12)).unwrap();
        let fault_authority = TestAuthority::new(None);
        let prepared_a = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &accepted,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::Authorized(capability_a) = prepared_a else {
            panic!("replica A must hold both request and E13 guards");
        };
        let dispatch_a = seal_object_write_qualification_put(&issued, capability_a).unwrap();
        let successful_put_returned = successful_put(&descriptor, "provider-put-request-a");
        let mut replica_b = std::pin::pin!(prepare_object_write_qualification(
            &fault_authority,
            &issued,
            Instant::now() + Duration::from_secs(1),
        ));
        assert_pending(replica_b.as_mut());
        assert_eq!(
            successful_put_returned.provider_attempt_id,
            descriptor.provider_attempt_id
        );
        drop(dispatch_a);
        assert_eq!(fault_authority.rollback_drops(), 1);

        let prepared_b = poll_ready(replica_b).unwrap();
        let ObjectWriteQualificationPreparation::DiscoverIssuedVisibility(probe_b) = prepared_b
        else {
            panic!("replica B may continue only after A rollback");
        };
        let resolved_b = poll_ready(resolve_object_write_qualification_after_head(
            &issued,
            probe_b,
            exact_visibility(&descriptor),
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        assert!(matches!(
            resolved_b,
            ObjectWriteQualificationHeadResolution::QualificationUnprovenVisible(_)
        ));
        assert!(matches!(
            fault_authority.resolution(),
            Some(ObjectWriteQualificationDurableResolution::UnprovenVisible(
                _
            ))
        ));
    }

    #[test]
    fn direct_synthetic_qualified_outcomes_and_binding_drift_are_rejected() {
        let authority = authority();
        let fault_descriptor = descriptor(&authority, Some(fault()));
        let issued = issued_attempt(fault_descriptor.clone());
        let valid_receipt = unproven_receipt(
            &fault_descriptor,
            millis(12),
            head_evidence(&fault_descriptor),
        );
        let synthetic = ObjectPutTerminalState::QualificationUnprovenVisible {
            receipt: Box::new(valid_receipt.clone()),
        };
        assert_eq!(
            complete_object_write_terminal(&authority, &issued, synthetic),
            Err(ObjectWriteAuthorityError::InvalidTransition)
        );

        let ordinary = descriptor(&authority, None);
        assert_eq!(
            adopt_object_write_qualification_unproven_visible(
                &authority,
                &issued_attempt(ordinary),
                ObjectWriteQualificationUnprovenCommit {
                    receipt: valid_receipt.clone(),
                },
            ),
            Err(ObjectWriteAuthorityError::BindingMismatch)
        );

        let mut wrong_head = valid_receipt;
        wrong_head.head_evidence.provider_request.content_sha256 =
            Sha256Digest::from_bytes([9; 32]);
        assert!(adopt_object_write_qualification_unproven_visible(
            &authority,
            &issued,
            ObjectWriteQualificationUnprovenCommit {
                receipt: wrong_head,
            },
        )
        .is_err());
    }

    #[test]
    fn deadline_and_drop_rollback_release_the_exclusive_request_lock() {
        let authority = authority();
        let descriptor = descriptor(&authority, Some(fault()));
        let accepted = accepted_attempt(descriptor);
        let fault_authority = TestAuthority::new(None);
        assert!(matches!(
            poll_ready(prepare_object_write_qualification(
                &fault_authority,
                &accepted,
                Instant::now(),
            )),
            Err(QualificationFaultAuthorityError::DeadlineExceeded)
        ));

        let prepared = poll_ready(prepare_object_write_qualification(
            &fault_authority,
            &accepted,
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
        let ObjectWriteQualificationPreparation::Authorized(capability) = prepared else {
            panic!("fresh request must authorize");
        };
        drop(capability);
        assert_eq!(fault_authority.rollback_drops(), 1);
        assert!(matches!(
            poll_ready(prepare_object_write_qualification(
                &fault_authority,
                &accepted,
                Instant::now() + Duration::from_secs(1),
            )),
            Ok(ObjectWriteQualificationPreparation::Authorized(_))
        ));
    }
}

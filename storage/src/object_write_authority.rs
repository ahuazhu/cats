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
    object_write_key, ObjectWriteCredentialReference, ObjectWriteCredentialRegistration,
    ObjectWriteImmutableKey, ObjectWriteIngressDescriptor,
};
use cats_api::runtime_reconciliation::{
    AsciiText, Base64UrlNoPad, Epoch, FenceEpoch, Id, NodeBootId, ProviderScope, RandomId128,
    Sha256Digest, UnixMillis, WireU64,
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
    pub volume_id: Id,
    pub key: ObjectWriteImmutableKey,
    pub target: ObjectWriteTarget,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
    pub provider_attempt_id: AsciiText,
    pub accepted_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteIngress {
    pub writer_authority_id: Id,
    pub request_id: Sha256Digest,
    pub volume_id: Id,
    pub key: ObjectWriteImmutableKey,
    pub target: ObjectWriteTarget,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
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
    },
    PermanentlyFailed {
        failure_receipt_id: AsciiText,
        failed_at_unix_ms: UnixMillis,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectWriteVisibilityOutcome {
    VisibleExact {
        provider_attempt_id: AsciiText,
        visibility_receipt_id: AsciiText,
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
    )?;
    let attempt = ObjectWriteIngressAttempt {
        ingress: ObjectWriteIngress {
            writer_authority_id: authority.writer.authority_id.clone(),
            request_id,
            volume_id: descriptor.volume_id.clone(),
            key: descriptor.key.clone(),
            target,
            content_sha256: descriptor.content_sha256.clone(),
            content_length: descriptor.content_length,
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
        )?
        || descriptor.provider_attempt_id != object_put_provider_attempt_id(&descriptor.request_id)?
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    match &attempt.state {
        ObjectPutState::AcceptedSpooled { spool }
        | ObjectPutState::ProviderIssued { spool, .. } => {
            validate_durable_spool_receipt(spool, descriptor)?;
            if let ObjectPutState::ProviderIssued {
                issued_at_unix_ms, ..
            } = &attempt.state
            {
                if *issued_at_unix_ms < descriptor.accepted_at_unix_ms {
                    return Err(ObjectWriteAuthorityError::CorruptState);
                }
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
        volume_id: ingress.volume_id.clone(),
        key: ingress.key.clone(),
        target: ingress.target.clone(),
        content_sha256: ingress.content_sha256.clone(),
        content_length: ingress.content_length,
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

pub fn complete_object_write_terminal(
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    outcome: ObjectPutTerminalState,
) -> Result<ObjectPutAttempt, ObjectWriteAuthorityError> {
    validate_object_put_attempt(authority, attempt)?;
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
    let ObjectPutState::ProviderIssued {
        spool,
        issued_at_unix_ms,
    } = &attempt.state
    else {
        return Err(ObjectWriteAuthorityError::InvalidTransition);
    };
    if terminal_at(&outcome) < *issued_at_unix_ms {
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
    let request_id = object_put_request_id(
        &request.descriptor.writer_authority_id,
        &request.descriptor.target,
        &request.descriptor.volume_id,
        &request.descriptor.key,
        &request.descriptor.content_sha256,
        request.descriptor.content_length,
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
        } => {
            hash_frame(&mut hasher, b"succeeded-visible")?;
            hash_frame(&mut hasher, put_receipt_id.as_str().as_bytes())?;
            hash_frame(&mut hasher, &put_completed_at_unix_ms.get().to_be_bytes())?;
            hash_frame(&mut hasher, visibility_receipt_id.as_str().as_bytes())?;
            hash_frame(&mut hasher, &visible_at_unix_ms.get().to_be_bytes())?;
        }
        ObjectPutTerminalState::PermanentlyFailed {
            failure_receipt_id,
            failed_at_unix_ms,
        } => {
            hash_frame(&mut hasher, b"permanently-failed")?;
            hash_frame(&mut hasher, failure_receipt_id.as_str().as_bytes())?;
            hash_frame(&mut hasher, &failed_at_unix_ms.get().to_be_bytes())?;
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

    fn discover_visibility<'a>(
        &'a self,
        descriptor: &'a ObjectPutDescriptor,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteVisibilityOutcome>;
}

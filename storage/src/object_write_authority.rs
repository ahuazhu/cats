//! Provider-neutral authority for Host-scoped immutable object writes.
//!
//! The gateway records acceptance before invoking a provider and is the only
//! process that owns object-store write credentials.  Closing an authority
//! snapshots the maximum accepted sequence and prevents any later acceptance.

use std::fs::File;
use std::future::Future;
use std::io::{Read, Seek, SeekFrom};
use std::pin::Pin;
use std::time::Instant;

use cats_api::runtime_reconciliation::{
    AsciiText, Id, ProviderScope, Sha256Digest, UnixMillis, WireU64,
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
pub struct ObjectPutDescriptor {
    pub writer_authority_id: Id,
    pub accepted_sequence: WireU64,
    pub request_id: Sha256Digest,
    pub object_key: String,
    pub content_sha256: Sha256Digest,
    pub content_length: WireU64,
    pub provider_attempt_id: AsciiText,
    pub accepted_at_unix_ms: UnixMillis,
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
    Accepted,
    Terminal { outcome: ObjectPutTerminalState },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectPutAttempt {
    pub descriptor: ObjectPutDescriptor,
    pub state: ObjectPutState,
}

#[derive(Debug)]
pub struct ValidatedObjectWriteSpool {
    file: File,
}

impl ValidatedObjectWriteSpool {
    /// Accept an already descriptor-stable private spool. The gateway streams
    /// the HTTP body into a mode-0600 temporary file; no whole-object buffer
    /// crosses this boundary.
    pub fn from_mode_0600_file(file: File) -> Result<Self, ObjectWriteAuthorityError> {
        let metadata = file
            .metadata()
            .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
        let maximum = u64::try_from(OBJECT_WRITE_REQUEST_MAX_BYTES)
            .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
        if !metadata.is_file() || metadata.len() > maximum {
            return Err(ObjectWriteAuthorityError::InvalidRequest);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(ObjectWriteAuthorityError::InvalidRequest);
            }
        }
        Ok(Self { file })
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

#[derive(Debug)]
pub struct ObjectWriteDownstreamPut {
    pub descriptor: ObjectPutDescriptor,
    pub spool: ValidatedObjectWriteSpool,
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
    validate_key(&descriptor.object_key).map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if descriptor.request_id
        != object_put_request_id(
            &descriptor.writer_authority_id,
            &descriptor.object_key,
            &descriptor.content_sha256,
            descriptor.content_length,
        )?
        || descriptor.provider_attempt_id != object_put_provider_attempt_id(&descriptor.request_id)?
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    if let ObjectPutState::Terminal { outcome } = &attempt.state {
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
    Ok(())
}

pub fn object_put_request_id(
    writer_authority_id: &Id,
    object_key: &str,
    content_sha256: &Sha256Digest,
    content_length: WireU64,
) -> Result<Sha256Digest, ObjectWriteAuthorityError> {
    validate_key(object_key).map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.object-write-request.v1")?;
    hash_frame(&mut hasher, writer_authority_id.as_str().as_bytes())?;
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

pub fn validate_downstream_put(
    request: &mut ObjectWriteDownstreamPut,
    absolute_deadline: Instant,
) -> Result<(), ObjectWriteAuthorityError> {
    let maximum = u64::try_from(OBJECT_WRITE_REQUEST_MAX_BYTES)
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    let file = &mut request.spool.file;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= absolute_deadline {
            return Err(ObjectWriteAuthorityError::InvalidRequest);
        }
        let read = file
            .read(&mut buffer)
            .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(
                u64::try_from(read).map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?,
            )
            .ok_or(ObjectWriteAuthorityError::InvalidRequest)?;
        if observed > maximum {
            return Err(ObjectWriteAuthorityError::InvalidRequest);
        }
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ObjectWriteAuthorityError::InvalidRequest)?;
    if request.descriptor.content_length.get() != observed
        || request.descriptor.content_sha256 != Sha256Digest::from_bytes(hasher.finalize().into())
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    let request_id = object_put_request_id(
        &request.descriptor.writer_authority_id,
        &request.descriptor.object_key,
        &request.descriptor.content_sha256,
        request.descriptor.content_length,
    )?;
    if request_id != request.descriptor.request_id
        || request.descriptor.provider_attempt_id != object_put_provider_attempt_id(&request_id)?
    {
        return Err(ObjectWriteAuthorityError::StaleAttempt);
    }
    Ok(())
}

pub fn begin_object_writer_cutoff(
    authority: &ObjectWriteAuthority,
    fence_attempt_id: &Id,
    cutoff_effective_at_unix_ms: UnixMillis,
) -> Result<ObjectWriteAuthority, ObjectWriteAuthorityError> {
    validate_object_write_authority(authority)?;
    match &authority.state {
        ObjectWriteAuthorityState::Open => {
            let mut updated = authority.clone();
            updated.state = ObjectWriteAuthorityState::CutoffPending {
                fence_attempt_id: fence_attempt_id.clone(),
                cutoff_sequence: authority.max_accepted_sequence,
                cutoff_effective_at_unix_ms,
            };
            Ok(updated)
        }
        ObjectWriteAuthorityState::CutoffPending {
            fence_attempt_id: existing,
            cutoff_effective_at_unix_ms: existing_at,
            ..
        } if existing == fence_attempt_id && *existing_at == cutoff_effective_at_unix_ms => {
            Ok(authority.clone())
        }
        ObjectWriteAuthorityState::CutoffComplete { receipt }
            if &receipt.fence_attempt_id == fence_attempt_id
                && receipt.cutoff_effective_at_unix_ms == cutoff_effective_at_unix_ms =>
        {
            Ok(authority.clone())
        }
        _ => Err(ObjectWriteAuthorityError::StaleAttempt),
    }
}

pub fn complete_object_writer_cutoff(
    authority: &ObjectWriteAuthority,
    cutoff_receipt_id: AsciiText,
    accepted_put_terminal_receipt_id: AsciiText,
    successful_put_visibility_receipt_id: AsciiText,
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

pub fn advance_terminal_prefix_sha256(
    previous: &Sha256Digest,
    attempt: &ObjectPutAttempt,
) -> Result<Sha256Digest, ObjectWriteAuthorityError> {
    let ObjectPutState::Terminal { outcome } = &attempt.state else {
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
    hash_frame(&mut hasher, attempt.descriptor.object_key.as_bytes())?;
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

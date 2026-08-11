//! Exact A19-signed A22 normal-acquire client.
//!
//! The client accepts only a complete, already-checkpointed mutation request.
//! It validates every success field back to that request and the exact root
//! VolumeIntent, then returns the closed grant shape consumed by blockd. It
//! never opens a metadata adapter, calls a pure Control helper, generates a
//! transition ID, or falls back to a legacy ownership route.

use std::io::Read as _;
use std::time::{Duration, Instant};

use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_volume_transition_error, decode_runtime_volume_transition_success,
    encode_runtime_volume_transition_request, AcquireOrigin, AdmissionInventoryAttestation,
    AgentSession, CleanupRelease, CleanupTarget, ContractErrorDetail, ContractName, DiskKind,
    FilesystemInitialization, LastVolumeTransition, NormalAcquireRequest, NormalAcquireResult,
    PersistentFilesystemBinding, PersistentInitializationReceipt, ReleaseRequest, ReleaseResult,
    RemoteHead, RuntimeSpineHttpProblem, RuntimeVolumeAuthorityRejection, RuntimeVolumeTransition,
    RuntimeVolumeTransitionError, RuntimeVolumeTransitionErrorDetail,
    RuntimeVolumeTransitionOutcome, RuntimeVolumeTransitionPreconditionProblem,
    RuntimeVolumeTransitionRequest, SessionBinding, VolumeAccess, VolumeAcquire,
    VolumeAcquireRequest, VolumeAdminState, VolumeDisposition, VolumeIntent, VolumeRecord,
    RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY, RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS,
    RUNTIME_SPINE_METHOD, RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES,
    RUNTIME_VOLUME_TRANSITION_PATH, RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_authorized_serving_record,
    validate_volume_record, AttachmentLineageIdentity, AuthorizedServingAttachment,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Strict HTTP result after A19 proof, response-header and bound-read checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedVolumeTransitionResponse {
    Success(Vec<u8>),
    ClosedError { status: u16, body: Vec<u8> },
    PlainRouteNotFound,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeTransitionTransportFailure {
    Cancelled,
    Timeout,
    Eof,
    Connection,
}

/// Narrow transport seam for the one fixed A22 mutation route.
pub trait A19SignedVolumeTransitionTransport: Send + Sync {
    fn post_a19_signed_json(
        &self,
        exact_path: &'static str,
        canonical_body: &[u8],
        success_wire_cap: usize,
        deadline: Instant,
    ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalAcquireAttempt {
    Granted(Box<AuthorizedServingAttachment>),
    RetryExact,
    RefreshInventory,
    ReplanDesired,
    SessionReplacementRequired,
    IdentityRepairRequired,
    AuthorityRejected(RuntimeVolumeAuthorityRejection),
    StopForLocalContract,
    StopForDeploymentMismatch,
    Ambiguous,
}

/// Closed result classes for the one-time PersistentDisk initialization CAS.
/// Ambiguous transport never becomes success; the exact checkpointed request
/// is retried and Control's Disk tuple provides idempotence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitInitializedAttempt {
    Committed(PersistentInitializationReceipt),
    RetryExact,
    RefreshInventory,
    ReplanDesired,
    SessionReplacementRequired,
    IdentityRepairRequired,
    AuthorityRejected(RuntimeVolumeAuthorityRejection),
    StopForLocalContract,
    StopForDeploymentMismatch,
    Ambiguous,
}

/// Closed result classes for the same signed A22 route when a checkpointed
/// stale-lineage cleanup releases its exact current owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalReleaseAttempt {
    Released(ReleaseResult),
    RetryExact,
    RefreshInventory,
    ReplanDesired,
    SessionReplacementRequired,
    IdentityRepairRequired,
    AuthorityRejected(RuntimeVolumeAuthorityRejection),
    /// Control definitively rejected this exact checkpointed cleanup. The
    /// caller must durably bind the typed problem to the exact request and
    /// checkpoint before allowing another full inventory scan.
    DefiniteCleanupConflict(RuntimeVolumeTransitionPreconditionProblem),
    StopForLocalContract,
    StopForDeploymentMismatch,
    Ambiguous,
}

/// The exact accepted A20 context against which a closed A22 rejection can be
/// interpreted. The mutation body intentionally does not duplicate these
/// session/attestation fields, so accepting a 409 without this context would
/// let a syntactically valid error for another full inventory drive this Cat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalAcquireAcceptedContext {
    pub session: AgentSession,
    pub inventory_attestation: AdmissionInventoryAttestation,
}

/// Direct strict-authority resolution after an ambiguous normal acquire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalAcquireAuthorityRecovery {
    Granted(Box<AuthorizedServingAttachment>),
    RetryExact,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalReleaseAuthorityRecovery {
    Released(ReleaseResult),
    RetryExact,
    Blocked,
}

#[derive(Debug, thiserror::Error)]
pub enum NormalAcquireClientError {
    #[error("invalid local A22 mutation request: {0:?}")]
    InvalidRequest(cats_api::runtime_reconciliation::ContractError),
    #[error("normal-acquire request is not exactly bound to the supplied root VolumeIntent")]
    InvalidVolumeBinding,
    #[error("normal-acquire request is not exactly bound to one accepted full A20 context")]
    InvalidAcceptedContext,
    #[error(
        "normal-release request is not exactly bound to the supplied root VolumeIntent and head"
    )]
    InvalidReleaseBinding,
}

#[derive(Debug, Clone)]
pub struct ControlSignedNormalAcquireClient<T> {
    transport: T,
}

impl<T> ControlSignedNormalAcquireClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> ControlSignedNormalAcquireClient<T>
where
    T: A19SignedVolumeTransitionTransport,
{
    pub fn acquire(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalAcquireAttempt, NormalAcquireClientError> {
        let body = encode_runtime_volume_transition_request(request)
            .map_err(NormalAcquireClientError::InvalidRequest)?;
        let normal = validate_local_normal_request(request, volume)?;
        validate_accepted_context(request, accepted)?;
        let response = match self.transport.post_a19_signed_json(
            RUNTIME_VOLUME_TRANSITION_PATH,
            &body,
            RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            deadline,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(NormalAcquireAttempt::Ambiguous),
        };
        match response {
            SignedVolumeTransitionResponse::Success(body) => {
                let Ok(success) = decode_runtime_volume_transition_success(&body) else {
                    return Ok(NormalAcquireAttempt::Ambiguous);
                };
                let Some(attachment) = exact_success_attachment(request, volume, normal, success)
                else {
                    return Ok(NormalAcquireAttempt::Ambiguous);
                };
                Ok(NormalAcquireAttempt::Granted(Box::new(attachment)))
            }
            SignedVolumeTransitionResponse::ClosedError { status, body } => {
                let Ok(error) = decode_runtime_volume_transition_error(&body) else {
                    return Ok(NormalAcquireAttempt::Ambiguous);
                };
                Ok(map_closed_error(status, &error, request, volume, accepted))
            }
            SignedVolumeTransitionResponse::PlainRouteNotFound => {
                Ok(NormalAcquireAttempt::StopForDeploymentMismatch)
            }
            SignedVolumeTransitionResponse::Ambiguous => Ok(NormalAcquireAttempt::Ambiguous),
        }
    }

    pub fn release(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        expected_head: &RemoteHead,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalReleaseAttempt, NormalAcquireClientError> {
        let body = encode_runtime_volume_transition_request(request)
            .map_err(NormalAcquireClientError::InvalidRequest)?;
        let cleanup = validate_local_release_request(request, volume, expected_head)?;
        validate_accepted_context(request, accepted)?;
        let response = match self.transport.post_a19_signed_json(
            RUNTIME_VOLUME_TRANSITION_PATH,
            &body,
            RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            deadline,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(NormalReleaseAttempt::Ambiguous),
        };
        match response {
            SignedVolumeTransitionResponse::Success(body) => {
                let Ok(success) = decode_runtime_volume_transition_success(&body) else {
                    return Ok(NormalReleaseAttempt::Ambiguous);
                };
                let Some(release) = exact_release_success(request, cleanup, expected_head, success)
                else {
                    return Ok(NormalReleaseAttempt::Ambiguous);
                };
                Ok(NormalReleaseAttempt::Released(release))
            }
            SignedVolumeTransitionResponse::ClosedError { status, body } => {
                let Ok(error) = decode_runtime_volume_transition_error(&body) else {
                    return Ok(NormalReleaseAttempt::Ambiguous);
                };
                Ok(map_closed_release_error(
                    status, &error, request, volume, accepted,
                ))
            }
            SignedVolumeTransitionResponse::PlainRouteNotFound => {
                Ok(NormalReleaseAttempt::StopForDeploymentMismatch)
            }
            SignedVolumeTransitionResponse::Ambiguous => Ok(NormalReleaseAttempt::Ambiguous),
        }
    }

    pub fn commit_initialized(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<CommitInitializedAttempt, NormalAcquireClientError> {
        let body = encode_runtime_volume_transition_request(request)
            .map_err(NormalAcquireClientError::InvalidRequest)?;
        let (filesystem, new_remote_head) = validate_local_commit_initialized(request, volume)?;
        validate_accepted_context(request, accepted)?;
        let response = match self.transport.post_a19_signed_json(
            RUNTIME_VOLUME_TRANSITION_PATH,
            &body,
            RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            deadline,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(CommitInitializedAttempt::Ambiguous),
        };
        match response {
            SignedVolumeTransitionResponse::Success(body) => {
                let Ok(success) = decode_runtime_volume_transition_success(&body) else {
                    return Ok(CommitInitializedAttempt::Ambiguous);
                };
                let Some(receipt) =
                    exact_commit_initialized_success(request, filesystem, new_remote_head, success)
                else {
                    return Ok(CommitInitializedAttempt::Ambiguous);
                };
                Ok(CommitInitializedAttempt::Committed(receipt))
            }
            SignedVolumeTransitionResponse::ClosedError { status, body } => {
                let Ok(error) = decode_runtime_volume_transition_error(&body) else {
                    return Ok(CommitInitializedAttempt::Ambiguous);
                };
                Ok(map_closed_commit_initialized_error(
                    status, &error, request, volume, accepted,
                ))
            }
            SignedVolumeTransitionResponse::PlainRouteNotFound => {
                Ok(CommitInitializedAttempt::StopForDeploymentMismatch)
            }
            SignedVolumeTransitionResponse::Ambiguous => Ok(CommitInitializedAttempt::Ambiguous),
        }
    }
}

/// Resolve an ambiguous release only from its exact immutable marker. An
/// Unowned record without the matching transition/result pair is not success.
pub fn recover_normal_release_from_authority(
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    expected_head: &RemoteHead,
    record: &VolumeRecord,
) -> Result<NormalReleaseAuthorityRecovery, NormalAcquireClientError> {
    let cleanup = validate_local_release_request(request, volume, expected_head)?;
    if validate_volume_record(record).is_err()
        || record.volume_id != volume.volume_id
        || record.size_bytes != volume.size_bytes
        || record.durability != volume.durability
        || !matches!(record.admin_state, VolumeAdminState::Active)
    {
        return Ok(NormalReleaseAuthorityRecovery::Blocked);
    }
    let (
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        unreachable!("local release validation accepted only a Volume replay")
    };
    if record.lease_owner.as_ref() == Some(attachment_id)
        && record.lease_epoch == *attachment_epoch
        && record.lease_expires_at.is_some()
        && record.head == *expected_head
    {
        return Ok(NormalReleaseAuthorityRecovery::RetryExact);
    }
    let Some(LastVolumeTransition::Release {
        request: stored_request,
        result,
    }) = &record.last_transition
    else {
        return Ok(NormalReleaseAuthorityRecovery::Blocked);
    };
    let expected_request = ReleaseRequest {
        volume_id: volume_id.clone(),
        transition_id: replay.release_transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_epoch: *attachment_epoch,
    };
    let Some(resulting_epoch) = attachment_epoch
        .get()
        .checked_add(1)
        .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
    else {
        return Ok(NormalReleaseAuthorityRecovery::Blocked);
    };
    if stored_request != &expected_request
        || result.volume_id != *volume_id
        || result.transition_id != replay.release_transition_id
        || result.released_attachment_id != *attachment_id
        || result.resulting_epoch != resulting_epoch
        || result.resulting_head != *expected_head
        || record.lease_owner.is_some()
        || record.lease_expires_at.is_some()
        || record.lease_epoch != resulting_epoch
        || record.head != *expected_head
    {
        return Ok(NormalReleaseAuthorityRecovery::Blocked);
    }
    Ok(NormalReleaseAuthorityRecovery::Released(result.clone()))
}

/// Resolve an unknown HTTP outcome through the exact point-read authority
/// record allowed by A22 §3. This never reads transition history or SQL. The
/// exact current predecessor permits replay; only a complete matching current
/// owner and immutable NormalAcquire marker is adopted as success.
pub fn recover_normal_acquire_from_authority(
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    record: &VolumeRecord,
) -> Result<NormalAcquireAuthorityRecovery, NormalAcquireClientError> {
    let acquire = validate_local_normal_request(request, volume)?;
    if validate_volume_record(record).is_err()
        || record.volume_id != volume.volume_id
        || record.size_bytes != volume.size_bytes
        || record.durability != volume.durability
        || !matches!(record.admin_state, VolumeAdminState::Active)
    {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    }
    let VolumeAcquireRequest::Normal {
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
        ..
    } = acquire
    else {
        unreachable!("local validation accepted only Normal")
    };
    if record.lease_owner.is_none()
        && record.lease_epoch == *expected_unowned_epoch
        && record.lease_expires_at.is_none()
    {
        return Ok(NormalAcquireAuthorityRecovery::RetryExact);
    }
    let Some(cats_api::runtime_reconciliation::LastVolumeTransition::NormalAcquire {
        request: stored_request,
        result: stored_result,
    }) = &record.last_transition
    else {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    };
    let exact_request = NormalAcquireRequest {
        volume_id: volume.volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_unowned_epoch: *expected_unowned_epoch,
        desired_revision: *desired_revision,
        placement_epoch: *placement_epoch,
        lease_duration_ms: *lease_duration_ms,
    };
    if stored_request != &exact_request
        || stored_result.volume_id != volume.volume_id
        || stored_result.transition_id != *transition_id
        || stored_result.attachment_id != *attachment_id
        || record.lease_owner.as_ref() != Some(attachment_id)
        || record.lease_epoch != stored_result.resulting_epoch
        || record.lease_expires_at.is_none()
    {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    }
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: volume.volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: stored_result.resulting_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            },
            node_id: request.placement.node_id.clone(),
            placement_epoch: request.placement.placement_epoch,
        },
        size_bytes: record.size_bytes,
        durability: record.durability,
        head: record.head.clone(),
        // Preserve the first grant. A later successful renew may advance the
        // current expiry but cannot rewrite the acquire receipt.
        lease_expires_at: stored_result.lease_expires_at,
        acquire_request: stored_request.clone(),
        acquire_result: stored_result.clone(),
    };
    if validate_authorized_serving_record(record, &attachment, None).is_err() {
        return Ok(NormalAcquireAuthorityRecovery::Blocked);
    }
    Ok(NormalAcquireAuthorityRecovery::Granted(Box::new(
        attachment,
    )))
}

fn validate_local_normal_request<'a>(
    request: &'a RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
) -> Result<&'a VolumeAcquireRequest, NormalAcquireClientError> {
    let RuntimeVolumeTransition::Acquire { request: acquire } = &request.transition else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    let VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = acquire
    else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    let VolumeAcquire::Normal {
        transition_id: intended_transition,
        expected_unowned_epoch: intended_epoch,
    } = &volume.acquire
    else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    if volume_id != &volume.volume_id
        || transition_id != intended_transition
        || attachment_id != &volume.attachment_id
        || expected_unowned_epoch != intended_epoch
        || desired_revision != &request.desired_revision
        || placement_epoch != &request.placement.placement_epoch
        || request.placement.node_id != request.session.node_id
        || *lease_duration_ms == 0
        || volume.size_bytes == 0
        || volume.disk_kind != DiskKind::Root
        || volume.access != VolumeAccess::ReadWriteOnce
        || volume.mount.is_some()
        || !matches!(volume.disposition, VolumeDisposition::Retain)
    {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    }
    Ok(acquire)
}

fn validate_local_release_request<'a>(
    request: &'a RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    expected_head: &RemoteHead,
) -> Result<&'a CleanupRelease, NormalAcquireClientError> {
    let RuntimeVolumeTransition::Release { cleanup } = &request.transition else {
        return Err(NormalAcquireClientError::InvalidReleaseBinding);
    };
    let (
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return Err(NormalAcquireClientError::InvalidReleaseBinding);
    };
    let VolumeAcquire::Normal { .. } = &volume.acquire else {
        return Err(NormalAcquireClientError::InvalidReleaseBinding);
    };
    if request.placement.node_id != request.session.node_id
        || cleanup.inventory_session != request.session
        || cleanup.desired_read_position < cleanup.inventory_read_position
        || volume_id != &volume.volume_id
        || attachment_id != &volume.attachment_id
        || replay.generation != expected_head.generation
        || replay.disposition != volume.disposition
        || volume.size_bytes == 0
        || volume.disk_kind != DiskKind::Root
        || volume.access != VolumeAccess::ReadWriteOnce
        || volume.mount.is_some()
        || !matches!(volume.disposition, VolumeDisposition::Retain)
        || attachment_epoch.get() == u64::MAX
    {
        return Err(NormalAcquireClientError::InvalidReleaseBinding);
    }
    Ok(cleanup)
}

fn validate_local_commit_initialized<'a>(
    request: &'a RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
) -> Result<(&'a PersistentFilesystemBinding, &'a RemoteHead), NormalAcquireClientError> {
    let RuntimeVolumeTransition::CommitInitialized {
        filesystem,
        new_remote_head,
    } = &request.transition
    else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    let Some(mount) = volume.mount.as_ref() else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    let FilesystemInitialization::Initialize { .. } = &mount.initialization else {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    };
    if request.placement.node_id != request.session.node_id
        || volume.disk_kind != DiskKind::Persistent
        || volume.access != VolumeAccess::ReadWriteOnce
        || !matches!(volume.disposition, VolumeDisposition::Retain)
        || filesystem.volume_intent_id != volume.volume_intent_id
        || filesystem.disk_id != volume.disk_id
        || filesystem.volume_id != volume.volume_id
        || filesystem.attachment_id != volume.attachment_id
        || filesystem.size_bytes != volume.size_bytes
        || filesystem.guest_device != volume.guest_device
        || filesystem.filesystem_uuid != mount.filesystem_uuid
        || filesystem.mount_path != mount.mount_path
        || filesystem.initialization != mount.initialization
        || new_remote_head.generation.get() == 0
        || new_remote_head.root_hash.is_none()
        || new_remote_head.root_object_id.is_none()
    {
        return Err(NormalAcquireClientError::InvalidVolumeBinding);
    }
    Ok((filesystem, new_remote_head))
}

fn validate_accepted_context(
    request: &RuntimeVolumeTransitionRequest,
    accepted: &NormalAcquireAcceptedContext,
) -> Result<(), NormalAcquireClientError> {
    let session = &accepted.session;
    let session_binding = SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    };
    let attestation = &accepted.inventory_attestation;
    if session.version != request.version
        || session_binding != request.session
        || attestation.version != request.version
        || attestation.node_id != session.node_id
        || attestation.agent_session_epoch != session.agent_session_epoch
        || attestation.accepted_at_unix_ms >= session.lease_deadline_unix_ms
    {
        return Err(NormalAcquireClientError::InvalidAcceptedContext);
    }
    Ok(())
}

fn exact_success_attachment(
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    acquire: &VolumeAcquireRequest,
    success: cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess,
) -> Option<AuthorizedServingAttachment> {
    if success.version != request.version
        || success.session != request.session
        || success.cat_id != request.cat_id
        || success.desired_revision != request.desired_revision
        || success.spec_digest != request.spec_digest
        || success.placement != request.placement
    {
        return None;
    }
    let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = success.outcome else {
        return None;
    };
    let VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = acquire
    else {
        return None;
    };
    let resulting_epoch = expected_unowned_epoch.get().checked_add(1)?;
    if grant.volume_id != *volume_id
        || grant.attachment_id != *attachment_id
        || grant.attachment_epoch.get() != resulting_epoch
        || grant.size_bytes != volume.size_bytes
        || grant.durability != volume.durability
        || grant.acquire_origin
            != (AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            })
    {
        return None;
    }
    let acquire_request = NormalAcquireRequest {
        volume_id: volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_unowned_epoch: *expected_unowned_epoch,
        desired_revision: *desired_revision,
        placement_epoch: *placement_epoch,
        lease_duration_ms: *lease_duration_ms,
    };
    let acquire_result = NormalAcquireResult {
        volume_id: grant.volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: grant.attachment_id.clone(),
        resulting_epoch: grant.attachment_epoch,
        resulting_head: grant.head.clone(),
        lease_expires_at: grant.lease_expires_at,
    };
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: grant.volume_id,
            attachment_id: grant.attachment_id,
            attachment_epoch: grant.attachment_epoch,
            acquire_origin: grant.acquire_origin,
            node_id: request.placement.node_id.clone(),
            placement_epoch: request.placement.placement_epoch,
        },
        size_bytes: grant.size_bytes,
        durability: grant.durability,
        head: grant.head,
        lease_expires_at: grant.lease_expires_at,
        acquire_request,
        acquire_result,
    };
    validate_authorized_serving_attachment(&attachment)
        .is_ok()
        .then_some(attachment)
}

fn exact_release_success(
    request: &RuntimeVolumeTransitionRequest,
    cleanup: &CleanupRelease,
    expected_head: &RemoteHead,
    success: cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess,
) -> Option<ReleaseResult> {
    if success.version != request.version
        || success.session != request.session
        || success.cat_id != request.cat_id
        || success.desired_revision != request.desired_revision
        || success.spec_digest != request.spec_digest
        || success.placement != request.placement
    {
        return None;
    }
    let RuntimeVolumeTransitionOutcome::Released { release } = success.outcome else {
        return None;
    };
    let (
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return None;
    };
    let resulting_epoch = attachment_epoch.get().checked_add(1)?;
    (release.volume_id == *volume_id
        && release.transition_id == replay.release_transition_id
        && release.released_attachment_id == *attachment_id
        && release.resulting_epoch.get() == resulting_epoch
        && release.resulting_head == *expected_head)
        .then_some(release)
}

fn exact_commit_initialized_success(
    request: &RuntimeVolumeTransitionRequest,
    filesystem: &PersistentFilesystemBinding,
    new_remote_head: &RemoteHead,
    success: cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess,
) -> Option<PersistentInitializationReceipt> {
    if success.version != request.version
        || success.session != request.session
        || success.cat_id != request.cat_id
        || success.desired_revision != request.desired_revision
        || success.spec_digest != request.spec_digest
        || success.placement != request.placement
    {
        return None;
    }
    let RuntimeVolumeTransitionOutcome::PersistentInitialized { receipt } = success.outcome else {
        return None;
    };
    let FilesystemInitialization::Initialize {
        initialization_token,
        expected_blank_head,
    } = &filesystem.initialization
    else {
        return None;
    };
    (receipt.disk_id == filesystem.disk_id
        && receipt.volume_id == filesystem.volume_id
        && receipt.initialization_token == *initialization_token
        && receipt.filesystem_uuid == filesystem.filesystem_uuid
        && receipt.expected_blank_head == *expected_blank_head
        && receipt.initialized_head == *new_remote_head)
        .then_some(receipt)
}

fn map_closed_error(
    status: u16,
    error: &RuntimeVolumeTransitionError,
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    accepted: &NormalAcquireAcceptedContext,
) -> NormalAcquireAttempt {
    match (status, error.error.as_ref()) {
        (401, RuntimeVolumeTransitionErrorDetail::AuthenticationFailed)
        | (403, RuntimeVolumeTransitionErrorDetail::IdentityNotEligible) => {
            NormalAcquireAttempt::IdentityRepairRequired
        }
        (
            409,
            RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed { cat_id, problem },
        ) if cat_id == &request.cat_id => match problem {
            RuntimeVolumeTransitionPreconditionProblem::InventorySessionReplaced
            | RuntimeVolumeTransitionPreconditionProblem::InventoryStale => {
                NormalAcquireAttempt::RefreshInventory
            }
            RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch => {
                NormalAcquireAttempt::ReplanDesired
            }
            RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch
            | RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict => {
                NormalAcquireAttempt::Ambiguous
            }
        },
        (
            409,
            RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected { volume_id, reason },
        ) if volume_id == &volume.volume_id => NormalAcquireAttempt::AuthorityRejected(*reason),
        (409, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if guest_config_error_binds_request(
                contract_error.error.as_ref(),
                request,
                accepted,
            ) =>
        {
            NormalAcquireAttempt::IdentityRepairRequired
        }
        (409, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if session_error_binds_request(contract_error.error.as_ref(), request, accepted) =>
        {
            NormalAcquireAttempt::SessionReplacementRequired
        }
        (409, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if inventory_error_binds_request(contract_error.error.as_ref(), request, accepted) =>
        {
            NormalAcquireAttempt::RefreshInventory
        }
        (409, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if desired_error_binds_request(contract_error.error.as_ref(), request) =>
        {
            NormalAcquireAttempt::ReplanDesired
        }
        (429, RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight)
        | (500, RuntimeVolumeTransitionErrorDetail::Internal)
        | (503, RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable) => {
            NormalAcquireAttempt::RetryExact
        }
        (status, RuntimeVolumeTransitionErrorDetail::HttpRequestRejected { problem })
            if http_problem_status(*problem) == status =>
        {
            NormalAcquireAttempt::StopForLocalContract
        }
        (status, RuntimeVolumeTransitionErrorDetail::ContractError { contract_error })
            if contract_error_status(contract_error.error.as_ref()) == status
                && request_contract_error_binds(contract_error.error.as_ref(), request) =>
        {
            NormalAcquireAttempt::StopForLocalContract
        }
        _ => NormalAcquireAttempt::Ambiguous,
    }
}

fn map_closed_commit_initialized_error(
    status: u16,
    error: &RuntimeVolumeTransitionError,
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    accepted: &NormalAcquireAcceptedContext,
) -> CommitInitializedAttempt {
    match map_closed_error(status, error, request, volume, accepted) {
        NormalAcquireAttempt::Granted(_) => unreachable!("closed response cannot grant a lease"),
        NormalAcquireAttempt::RetryExact => CommitInitializedAttempt::RetryExact,
        NormalAcquireAttempt::RefreshInventory => CommitInitializedAttempt::RefreshInventory,
        NormalAcquireAttempt::ReplanDesired => CommitInitializedAttempt::ReplanDesired,
        NormalAcquireAttempt::SessionReplacementRequired => {
            CommitInitializedAttempt::SessionReplacementRequired
        }
        NormalAcquireAttempt::IdentityRepairRequired => {
            CommitInitializedAttempt::IdentityRepairRequired
        }
        NormalAcquireAttempt::AuthorityRejected(reason) => {
            CommitInitializedAttempt::AuthorityRejected(reason)
        }
        NormalAcquireAttempt::StopForLocalContract => {
            CommitInitializedAttempt::StopForLocalContract
        }
        NormalAcquireAttempt::StopForDeploymentMismatch => {
            CommitInitializedAttempt::StopForDeploymentMismatch
        }
        NormalAcquireAttempt::Ambiguous => CommitInitializedAttempt::Ambiguous,
    }
}

fn map_closed_release_error(
    status: u16,
    error: &RuntimeVolumeTransitionError,
    request: &RuntimeVolumeTransitionRequest,
    volume: &VolumeIntent,
    accepted: &NormalAcquireAcceptedContext,
) -> NormalReleaseAttempt {
    if matches!(
        (status, error.error.as_ref()),
        (
            409,
            RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                cat_id,
                problem: RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch
                    | RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
            },
        ) if cat_id == &request.cat_id
    ) {
        // These are definite A20/A22 rejections, not response loss. Preserve
        // the exact typed problem so the effect can durably bind it to this
        // request before admitting another full inventory scan.
        return NormalReleaseAttempt::DefiniteCleanupConflict(match error.error.as_ref() {
            RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                problem, ..
            } => *problem,
            _ => unreachable!("the guarded shape is a transition precondition failure"),
        });
    }
    match map_closed_error(status, error, request, volume, accepted) {
        NormalAcquireAttempt::RetryExact => NormalReleaseAttempt::RetryExact,
        NormalAcquireAttempt::RefreshInventory => NormalReleaseAttempt::RefreshInventory,
        NormalAcquireAttempt::ReplanDesired => NormalReleaseAttempt::ReplanDesired,
        NormalAcquireAttempt::SessionReplacementRequired => {
            NormalReleaseAttempt::SessionReplacementRequired
        }
        NormalAcquireAttempt::IdentityRepairRequired => {
            NormalReleaseAttempt::IdentityRepairRequired
        }
        NormalAcquireAttempt::AuthorityRejected(reason) => {
            NormalReleaseAttempt::AuthorityRejected(reason)
        }
        NormalAcquireAttempt::StopForLocalContract => NormalReleaseAttempt::StopForLocalContract,
        NormalAcquireAttempt::StopForDeploymentMismatch => {
            NormalReleaseAttempt::StopForDeploymentMismatch
        }
        NormalAcquireAttempt::Ambiguous => NormalReleaseAttempt::Ambiguous,
        NormalAcquireAttempt::Granted(_) => {
            unreachable!("closed error mapping never produces an acquire grant")
        }
    }
}

fn request_contract_error_binds(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionRequest,
) -> bool {
    match detail {
        ContractErrorDetail::UnsupportedVersion {
            contract,
            presented_version,
            ..
        } => {
            *contract == ContractName::RuntimeVolumeTransitionRequest
                && *presented_version == request.version
        }
        ContractErrorDetail::MalformedPayload { contract, .. }
        | ContractErrorDetail::LimitExceeded { contract, .. } => {
            *contract == ContractName::RuntimeVolumeTransitionRequest
        }
        _ => false,
    }
}

fn session_error_binds_request(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionRequest,
    accepted: &NormalAcquireAcceptedContext,
) -> bool {
    match detail {
        ContractErrorDetail::MissingAgentSession { node_id } => node_id == &request.session.node_id,
        ContractErrorDetail::StaleSession {
            node_id,
            presented_agent_session_epoch,
            current_agent_session_epoch,
        } => {
            node_id == &request.session.node_id
                && presented_agent_session_epoch == &request.session.agent_session_epoch
                && current_agent_session_epoch > presented_agent_session_epoch
        }
        ContractErrorDetail::SessionExpired {
            node_id,
            agent_session_epoch: presented_agent_session_epoch,
            lease_deadline_unix_ms,
            server_time_unix_ms,
        } => {
            node_id == &request.session.node_id
                && presented_agent_session_epoch == &request.session.agent_session_epoch
                && lease_deadline_unix_ms == &accepted.session.lease_deadline_unix_ms
                && server_time_unix_ms >= lease_deadline_unix_ms
        }
        ContractErrorDetail::WrongSession {
            expected,
            presented,
        } => {
            presented == &request.session
                && expected.node_id == request.session.node_id
                && expected != presented
        }
        _ => false,
    }
}

fn guest_config_error_binds_request(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionRequest,
    accepted: &NormalAcquireAcceptedContext,
) -> bool {
    match detail {
        ContractErrorDetail::GuestConfigMismatch {
            node_id,
            expected_guest_config_digest,
            presented_guest_config_digest,
        } => {
            node_id == &request.session.node_id
                && presented_guest_config_digest == &accepted.session.guest_config_digest
                && expected_guest_config_digest != presented_guest_config_digest
        }
        _ => false,
    }
}

fn inventory_error_binds_request(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionRequest,
    accepted: &NormalAcquireAcceptedContext,
) -> bool {
    match detail {
        ContractErrorDetail::MissingInventoryAttestation {
            node_id,
            agent_session_epoch,
        } => {
            node_id == &request.session.node_id
                && agent_session_epoch == &request.session.agent_session_epoch
        }
        ContractErrorDetail::AssignedSetChanged {
            node_id,
            agent_session_epoch,
            read_position,
        } => {
            node_id == &request.session.node_id
                && agent_session_epoch == &request.session.agent_session_epoch
                && read_position == &accepted.inventory_attestation.inventory_read_position
        }
        _ => false,
    }
}

fn desired_error_binds_request(
    detail: &ContractErrorDetail,
    request: &RuntimeVolumeTransitionRequest,
) -> bool {
    match detail {
        ContractErrorDetail::StaleRevision {
            cat_id,
            presented_revision,
            current_revision,
        } => {
            cat_id == &request.cat_id
                && presented_revision == &request.desired_revision
                && current_revision > presented_revision
        }
        ContractErrorDetail::WrongRevision {
            cat_id,
            expected_revision,
            presented_revision,
        } => {
            cat_id == &request.cat_id
                && presented_revision == &request.desired_revision
                && expected_revision != presented_revision
        }
        ContractErrorDetail::RevisionDigestConflict {
            cat_id,
            desired_revision,
            expected_digest,
            presented_digest,
        } => {
            cat_id == &request.cat_id
                && desired_revision == &request.desired_revision
                && presented_digest == &request.spec_digest
                && expected_digest != presented_digest
        }
        ContractErrorDetail::WrongPlacement {
            cat_id,
            desired_revision,
            expected,
            presented,
        } => {
            cat_id == &request.cat_id
                && desired_revision == &request.desired_revision
                && presented == &request.placement
                && expected != presented
        }
        _ => false,
    }
}

fn contract_error_status(detail: &ContractErrorDetail) -> u16 {
    match detail {
        ContractErrorDetail::MalformedPayload { .. }
        | ContractErrorDetail::UnsupportedVersion { .. } => 400,
        ContractErrorDetail::LimitExceeded { .. } => 413,
        _ => 409,
    }
}

fn http_problem_status(problem: RuntimeSpineHttpProblem) -> u16 {
    match problem {
        RuntimeSpineHttpProblem::MethodNotAllowed => 405,
        RuntimeSpineHttpProblem::QueryNotAllowed
        | RuntimeSpineHttpProblem::AuthorizationNotAllowed
        | RuntimeSpineHttpProblem::SemanticHeaderNotAllowed => 400,
        RuntimeSpineHttpProblem::ContentTypeNotAllowed
        | RuntimeSpineHttpProblem::ContentEncodingNotAllowed => 415,
        RuntimeSpineHttpProblem::AcceptNotAllowed => 406,
    }
}

#[derive(Clone)]
pub struct RuntimeVolumeTransitionHttpClient {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for RuntimeVolumeTransitionHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeVolumeTransitionHttpClient")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl RuntimeVolumeTransitionHttpClient {
    pub fn for_production(
        control_plane_origin: &str,
        registration: &crate::agent_registration::AgentRegistrationConfig,
    ) -> anyhow::Result<Self> {
        Self::new(
            control_plane_origin,
            registration.runtime_request_signer(),
            TransportMode::ProductionHttps,
        )
    }

    #[doc(hidden)]
    pub fn for_loopback_test(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
    ) -> anyhow::Result<Self> {
        Self::new(control_plane_origin, signer, TransportMode::LoopbackTest)
    }

    fn new(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
        mode: TransportMode,
    ) -> anyhow::Result<Self> {
        let origin = validate_origin(control_plane_origin, mode)?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(RESPONSE_TIMEOUT)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }
}

impl A19SignedVolumeTransitionTransport for RuntimeVolumeTransitionHttpClient {
    fn post_a19_signed_json(
        &self,
        exact_path: &'static str,
        canonical_body: &[u8],
        success_wire_cap: usize,
        deadline: Instant,
    ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
        if exact_path != RUNTIME_VOLUME_TRANSITION_PATH
            || success_wire_cap != RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES
        {
            return Ok(SignedVolumeTransitionResponse::Ambiguous);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(VolumeTransitionTransportFailure::Timeout)?;
        let proof = self
            .signer
            .sign(RUNTIME_SPINE_METHOD, exact_path, canonical_body);
        let url = self
            .origin
            .join(exact_path)
            .expect("validated origin accepts the fixed A22 path");
        let response = self
            .client
            .post(url)
            .timeout(remaining)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(canonical_body.to_vec())
            .send();
        let response = match response {
            Ok(response) => response,
            Err(error) if error.is_timeout() => {
                return Err(VolumeTransitionTransportFailure::Timeout)
            }
            Err(_) => return Err(VolumeTransitionTransportFailure::Connection),
        };
        classify_http_response(response, success_wire_cap)
    }
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

fn classify_http_response(
    mut response: reqwest::blocking::Response,
    success_cap: usize,
) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(classify_plain_route_not_found(&mut response));
    }
    let cap = if status == reqwest::StatusCode::OK {
        success_cap
    } else {
        RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES
    };
    if !valid_common_headers(response.headers())
        || declared_response_exceeds(response.headers(), cap)
    {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    }
    let mut body = Vec::new();
    if response
        .by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return Err(VolumeTransitionTransportFailure::Eof);
    }
    if body.len() > cap {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    }
    if status == reqwest::StatusCode::OK {
        return Ok(SignedVolumeTransitionResponse::Success(body));
    }
    let Ok(error) = decode_runtime_volume_transition_error(&body) else {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    };
    if !status_matches_error(status, response.headers(), &error) {
        return Ok(SignedVolumeTransitionResponse::Ambiguous);
    }
    Ok(SignedVolumeTransitionResponse::ClosedError {
        status: status.as_u16(),
        body,
    })
}

fn classify_plain_route_not_found(
    response: &mut reqwest::blocking::Response,
) -> SignedVolumeTransitionResponse {
    let headers = response.headers();
    let forbidden_proxy_headers = ["via", "forwarded", "x-cache", "x-proxy-cache"];
    if headers.contains_key(reqwest::header::CONTENT_ENCODING)
        || !has_one_header_ows_case_insensitive(
            headers,
            reqwest::header::CONTENT_TYPE,
            JSON_CONTENT_TYPE,
        )
        || !has_one_exact_header(headers, reqwest::header::CACHE_CONTROL, "no-store")
        || !has_one_exact_header(
            headers,
            reqwest::header::HeaderName::from_static("x-robots-tag"),
            RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS,
        )
        || declared_response_exceeds(headers, RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY.len())
        || forbidden_proxy_headers
            .iter()
            .any(|name| headers.contains_key(*name))
    {
        return SignedVolumeTransitionResponse::Ambiguous;
    }
    let mut body = Vec::new();
    if response
        .by_ref()
        .take(RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY.len() as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
        || body != RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY
    {
        return SignedVolumeTransitionResponse::Ambiguous;
    }
    SignedVolumeTransitionResponse::PlainRouteNotFound
}

fn valid_common_headers(headers: &reqwest::header::HeaderMap) -> bool {
    !headers.contains_key(reqwest::header::CONTENT_ENCODING)
        && has_one_header_ows_case_insensitive(
            headers,
            reqwest::header::CONTENT_TYPE,
            JSON_CONTENT_TYPE,
        )
        && has_one_exact_header(headers, reqwest::header::CACHE_CONTROL, "no-store")
}

fn status_matches_error(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    error: &RuntimeVolumeTransitionError,
) -> bool {
    match error.error.as_ref() {
        RuntimeVolumeTransitionErrorDetail::AuthenticationFailed => {
            status == reqwest::StatusCode::UNAUTHORIZED
                && has_one_exact_header(
                    headers,
                    reqwest::header::WWW_AUTHENTICATE,
                    NODE_AUTHENTICATE_CHALLENGE,
                )
        }
        RuntimeVolumeTransitionErrorDetail::IdentityNotEligible => {
            status == reqwest::StatusCode::FORBIDDEN
        }
        RuntimeVolumeTransitionErrorDetail::HttpRequestRejected { problem } => {
            status.as_u16() == http_problem_status(*problem)
                && (!matches!(problem, RuntimeSpineHttpProblem::MethodNotAllowed)
                    || has_one_exact_header(headers, reqwest::header::ALLOW, RUNTIME_SPINE_METHOD))
        }
        RuntimeVolumeTransitionErrorDetail::ContractError { contract_error } => {
            status.as_u16() == contract_error_status(contract_error.error.as_ref())
        }
        RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed { .. }
        | RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected { .. }
        | RuntimeVolumeTransitionErrorDetail::VolumeAuthorizationRejected { .. } => {
            status == reqwest::StatusCode::CONFLICT
        }
        RuntimeVolumeTransitionErrorDetail::AuthorizationEvidenceUnavailable { .. } => false,
        RuntimeVolumeTransitionErrorDetail::NodeRequestInFlight => {
            status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && has_one_exact_header(headers, reqwest::header::RETRY_AFTER, "1")
        }
        RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable => {
            status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && has_one_exact_header(headers, reqwest::header::RETRY_AFTER, "1")
        }
        RuntimeVolumeTransitionErrorDetail::Internal => {
            status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn declared_response_exceeds(headers: &reqwest::header::HeaderMap, cap: usize) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_some()
        || value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_none_or(|length| length > cap as u64)
}

fn has_one_exact_header(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn has_one_header_ows_case_insensitive(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(expected)
        })
        && values.next().is_none()
}

fn validate_origin(input: &str, mode: TransportMode) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(input)?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Control Plane origin has userinfo"
    );
    anyhow::ensure!(url.query().is_none(), "Control Plane origin has a query");
    anyhow::ensure!(
        url.fragment().is_none(),
        "Control Plane origin has a fragment"
    );
    anyhow::ensure!(url.path() == "/", "Control Plane origin has a path");
    match mode {
        TransportMode::ProductionHttps => {
            anyhow::ensure!(
                url.scheme() == "https",
                "production Control Plane origin must use HTTPS"
            );
        }
        TransportMode::LoopbackTest => {
            anyhow::ensure!(
                url.scheme() == "http"
                    && url
                        .host_str()
                        .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")),
                "test Control Plane origin must be loopback HTTP"
            );
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Mutex;

    use cats_api::agent_registration::{verify_request_proof, Ed25519RequestSigner};
    use cats_api::runtime_reconciliation::{
        decode_runtime_volume_transition_request, encode_runtime_volume_transition_error,
        ContractError, ContractVersion, Durability, Generation, GuestDeviceIdentity, Id,
        LastVolumeTransition, RemoteHead, Revision, RuntimeVolumeTransitionPreconditionProblem,
        Sha256Digest, UnixMillis,
    };

    use super::*;

    const REQUEST: &[u8] = br#"{"cat_id":"cat_01","desired_revision":7,"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"spec_digest":"sha256:d1dc4a8ff5e5d2fa4239eb14a6ac3e825a5070bd0d646762f723507f11ec54ad","transition":{"kind":"acquire","request":{"attachment_id":"att_01","desired_revision":7,"expected_unowned_epoch":0,"kind":"normal","lease_duration_ms":60000,"placement_epoch":3,"transition_id":"22222222222222222222222222222222","volume_id":"vol_root"}},"version":1}"#;
    const SUCCESS: &[u8] = br#"{"cat_id":"cat_01","desired_revision":7,"outcome":{"grant":{"acquire_origin":{"kind":"normal","transition_id":"22222222222222222222222222222222"},"attachment_epoch":1,"attachment_id":"att_01","durability":"strict","head":{"generation":0,"root_hash":null,"root_object_id":null},"lease_expires_at":1720000060000,"size_bytes":4294967296,"volume_id":"vol_root"},"kind":"lease_granted"},"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"spec_digest":"sha256:d1dc4a8ff5e5d2fa4239eb14a6ac3e825a5070bd0d646762f723507f11ec54ad","version":1}"#;

    struct FakeTransport {
        response: Mutex<Option<SignedVolumeTransitionResponse>>,
        seen: Mutex<Vec<(&'static str, Vec<u8>, usize)>>,
    }

    impl FakeTransport {
        fn new(response: SignedVolumeTransitionResponse) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl A19SignedVolumeTransitionTransport for FakeTransport {
        fn post_a19_signed_json(
            &self,
            exact_path: &'static str,
            canonical_body: &[u8],
            success_wire_cap: usize,
            deadline: Instant,
        ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
            assert!(deadline > Instant::now());
            self.seen
                .lock()
                .unwrap()
                .push((exact_path, canonical_body.to_vec(), success_wire_cap));
            Ok(self.response.lock().unwrap().take().unwrap())
        }
    }

    fn request() -> RuntimeVolumeTransitionRequest {
        decode_runtime_volume_transition_request(REQUEST).unwrap()
    }

    fn accepted_context() -> NormalAcquireAcceptedContext {
        let request = request();
        NormalAcquireAcceptedContext {
            session: AgentSession {
                version: request.version,
                node_id: request.session.node_id.clone(),
                immutable_host_id: Id::new("host_a").unwrap(),
                node_boot_id: request.session.node_boot_id.clone(),
                agent_instance_id: request.session.agent_instance_id.clone(),
                agent_session_epoch: request.session.agent_session_epoch,
                registration_attempt_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "55555555555555555555555555555555",
                )
                .unwrap(),
                guest_config_digest: Sha256Digest::from_bytes([9; 32]),
                lease_deadline_unix_ms: UnixMillis::new(1_720_000_120_000).unwrap(),
            },
            inventory_attestation: AdmissionInventoryAttestation {
                version: request.version,
                node_id: request.session.node_id,
                agent_session_epoch: request.session.agent_session_epoch,
                inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(4).unwrap(),
                inventory_digest: Sha256Digest::from_bytes([8; 32]),
                inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(12)
                    .unwrap(),
                accepted_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
            },
        }
    }

    fn attempt_for_error(
        status: u16,
        detail: RuntimeVolumeTransitionErrorDetail,
    ) -> NormalAcquireAttempt {
        let diagnostic = format!("{detail:?}");
        let body = encode_runtime_volume_transition_error(&RuntimeVolumeTransitionError {
            version: ContractVersion::V1,
            error: Box::new(detail),
            message: "typed test error".to_owned(),
        })
        .unwrap_or_else(|error| panic!("invalid test error {diagnostic}: {error:?}"));
        ControlSignedNormalAcquireClient::new(FakeTransport::new(
            SignedVolumeTransitionResponse::ClosedError { status, body },
        ))
        .acquire(
            &request(),
            &volume(),
            &accepted_context(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
    }

    fn contract_error(detail: ContractErrorDetail) -> RuntimeVolumeTransitionErrorDetail {
        RuntimeVolumeTransitionErrorDetail::ContractError {
            contract_error: ContractError {
                version: ContractVersion::V1,
                error: Box::new(detail),
                message: "nested contract error".to_owned(),
            },
        }
    }

    fn volume() -> VolumeIntent {
        VolumeIntent {
            volume_intent_id: Id::new("root-intent").unwrap(),
            disk_id: Id::new("root-disk").unwrap(),
            volume_id: Id::new("vol_root").unwrap(),
            attachment_id: Id::new("att_01").unwrap(),
            size_bytes: 4_294_967_296,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-root").unwrap(),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "22222222222222222222222222222222",
                )
                .unwrap(),
                expected_unowned_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(0)
                    .unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }
    }

    #[test]
    fn exact_grant_becomes_closed_authorized_attachment() {
        let transport =
            FakeTransport::new(SignedVolumeTransitionResponse::Success(SUCCESS.to_vec()));
        let client = ControlSignedNormalAcquireClient::new(transport);
        let attempt = client
            .acquire(
                &request(),
                &volume(),
                &accepted_context(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let NormalAcquireAttempt::Granted(attachment) = attempt else {
            panic!("expected an exact grant")
        };
        assert_eq!(attachment.identity.volume_id.as_str(), "vol_root");
        assert_eq!(attachment.identity.attachment_id.as_str(), "att_01");
        assert_eq!(attachment.identity.attachment_epoch.get(), 1);
        assert_eq!(attachment.identity.node_id.as_str(), "node_a");
        assert_eq!(attachment.acquire_request.lease_duration_ms, 60_000);
        assert_eq!(attachment.acquire_result.resulting_head, attachment.head);
        let seen = client.transport().seen.lock().unwrap();
        assert_eq!(
            seen.as_slice(),
            &[(
                RUNTIME_VOLUME_TRANSITION_PATH,
                REQUEST.to_vec(),
                RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            )]
        );
    }

    #[test]
    fn mismatched_or_malformed_success_is_ambiguous_and_never_a_grant() {
        let mut wrong = decode_runtime_volume_transition_success(SUCCESS).unwrap();
        let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = &mut wrong.outcome else {
            unreachable!()
        };
        grant.attachment_id = Id::new("other-attachment").unwrap();
        let wrong =
            cats_api::runtime_reconciliation::encode_runtime_volume_transition_success(&wrong)
                .unwrap();
        for response in [
            SignedVolumeTransitionResponse::Success(wrong),
            SignedVolumeTransitionResponse::Success(b"{}".to_vec()),
            SignedVolumeTransitionResponse::Ambiguous,
        ] {
            let attempt = ControlSignedNormalAcquireClient::new(FakeTransport::new(response))
                .acquire(
                    &request(),
                    &volume(),
                    &accepted_context(),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            assert_eq!(attempt, NormalAcquireAttempt::Ambiguous);
        }
    }

    #[test]
    fn typed_rejections_are_bound_before_driving_retry_or_refresh() {
        let cases = [
            (
                409,
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id: Id::new("cat_01").unwrap(),
                    problem: RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
                },
                NormalAcquireAttempt::RefreshInventory,
            ),
            (
                409,
                RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected {
                    volume_id: Id::new("vol_root").unwrap(),
                    reason: RuntimeVolumeAuthorityRejection::OtherWriter,
                },
                NormalAcquireAttempt::AuthorityRejected(
                    RuntimeVolumeAuthorityRejection::OtherWriter,
                ),
            ),
            (
                503,
                RuntimeVolumeTransitionErrorDetail::TemporarilyUnavailable,
                NormalAcquireAttempt::RetryExact,
            ),
        ];
        for (status, detail, expected) in cases {
            let body = encode_runtime_volume_transition_error(&RuntimeVolumeTransitionError {
                version: cats_api::runtime_reconciliation::ContractVersion::V1,
                error: Box::new(detail),
                message: "typed test error".to_owned(),
            })
            .unwrap();
            let attempt = ControlSignedNormalAcquireClient::new(FakeTransport::new(
                SignedVolumeTransitionResponse::ClosedError { status, body },
            ))
            .acquire(
                &request(),
                &volume(),
                &accepted_context(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(attempt, expected);
        }

        let body = encode_runtime_volume_transition_error(&RuntimeVolumeTransitionError {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            error: Box::new(
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id: Id::new("other-cat").unwrap(),
                    problem: RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
                },
            ),
            message: "wrong Cat".to_owned(),
        })
        .unwrap();
        let attempt = ControlSignedNormalAcquireClient::new(FakeTransport::new(
            SignedVolumeTransitionResponse::ClosedError { status: 409, body },
        ))
        .acquire(
            &request(),
            &volume(),
            &accepted_context(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(attempt, NormalAcquireAttempt::Ambiguous);
    }

    #[test]
    fn accepted_full_context_is_required_before_any_mutation_transport() {
        let transport =
            FakeTransport::new(SignedVolumeTransitionResponse::Success(SUCCESS.to_vec()));
        let client = ControlSignedNormalAcquireClient::new(transport);
        let mut accepted = accepted_context();
        accepted.inventory_attestation.node_id = Id::new("other-node").unwrap();
        assert!(matches!(
            client.acquire(
                &request(),
                &volume(),
                &accepted,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(NormalAcquireClientError::InvalidAcceptedContext)
        ));
        assert!(client.transport().seen.lock().unwrap().is_empty());
    }

    #[test]
    fn authentication_and_identity_rejections_require_operator_identity_repair() {
        for (status, detail) in [
            (
                401,
                RuntimeVolumeTransitionErrorDetail::AuthenticationFailed,
            ),
            (403, RuntimeVolumeTransitionErrorDetail::IdentityNotEligible),
        ] {
            assert_eq!(
                attempt_for_error(status, detail),
                NormalAcquireAttempt::IdentityRepairRequired
            );
        }
    }

    #[test]
    fn session_errors_bind_every_presented_identity_field() {
        let accepted = accepted_context();
        let request = request();
        let exact_guest_mismatch = ContractErrorDetail::GuestConfigMismatch {
            node_id: request.session.node_id.clone(),
            expected_guest_config_digest: Sha256Digest::from_bytes([10; 32]),
            presented_guest_config_digest: accepted.session.guest_config_digest.clone(),
        };
        let mut expected_session = request.session.clone();
        expected_session.agent_session_epoch =
            cats_api::runtime_reconciliation::Epoch::new(1).unwrap();
        for detail in [
            ContractErrorDetail::MissingAgentSession {
                node_id: request.session.node_id.clone(),
            },
            ContractErrorDetail::StaleSession {
                node_id: request.session.node_id.clone(),
                presented_agent_session_epoch: request.session.agent_session_epoch,
                current_agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3)
                    .unwrap(),
            },
            ContractErrorDetail::WrongSession {
                expected: expected_session,
                presented: request.session.clone(),
            },
            ContractErrorDetail::SessionExpired {
                node_id: request.session.node_id.clone(),
                agent_session_epoch: request.session.agent_session_epoch,
                lease_deadline_unix_ms: accepted.session.lease_deadline_unix_ms,
                server_time_unix_ms: accepted.session.lease_deadline_unix_ms,
            },
        ] {
            assert_eq!(
                attempt_for_error(409, contract_error(detail)),
                NormalAcquireAttempt::SessionReplacementRequired
            );
        }
        assert_eq!(
            attempt_for_error(409, contract_error(exact_guest_mismatch.clone())),
            NormalAcquireAttempt::IdentityRepairRequired
        );

        let wrong_guest_digest = ContractErrorDetail::GuestConfigMismatch {
            node_id: request.session.node_id,
            expected_guest_config_digest: Sha256Digest::from_bytes([10; 32]),
            presented_guest_config_digest: Sha256Digest::from_bytes([11; 32]),
        };
        assert_eq!(
            attempt_for_error(409, contract_error(wrong_guest_digest)),
            NormalAcquireAttempt::Ambiguous
        );
    }

    #[test]
    fn inventory_and_desired_409s_bind_the_current_request_and_attestation() {
        let request = request();
        let accepted = accepted_context();
        for detail in [
            ContractErrorDetail::MissingInventoryAttestation {
                node_id: request.session.node_id.clone(),
                agent_session_epoch: request.session.agent_session_epoch,
            },
            ContractErrorDetail::AssignedSetChanged {
                node_id: request.session.node_id.clone(),
                agent_session_epoch: request.session.agent_session_epoch,
                read_position: accepted.inventory_attestation.inventory_read_position,
            },
        ] {
            assert_eq!(
                attempt_for_error(409, contract_error(detail)),
                NormalAcquireAttempt::RefreshInventory
            );
        }

        let mut expected_placement = request.placement.clone();
        expected_placement.placement_epoch =
            cats_api::runtime_reconciliation::Epoch::new(4).unwrap();
        for detail in [
            ContractErrorDetail::StaleRevision {
                cat_id: request.cat_id.clone(),
                presented_revision: request.desired_revision,
                current_revision: Revision::new(8).unwrap(),
            },
            ContractErrorDetail::WrongRevision {
                cat_id: request.cat_id.clone(),
                expected_revision: Revision::new(6).unwrap(),
                presented_revision: request.desired_revision,
            },
            ContractErrorDetail::RevisionDigestConflict {
                cat_id: request.cat_id.clone(),
                desired_revision: request.desired_revision,
                expected_digest: Sha256Digest::from_bytes([12; 32]),
                presented_digest: request.spec_digest.clone(),
            },
            ContractErrorDetail::WrongPlacement {
                cat_id: request.cat_id.clone(),
                desired_revision: request.desired_revision,
                expected: expected_placement,
                presented: request.placement.clone(),
            },
        ] {
            assert_eq!(
                attempt_for_error(409, contract_error(detail)),
                NormalAcquireAttempt::ReplanDesired
            );
        }

        assert_eq!(
            attempt_for_error(
                409,
                contract_error(ContractErrorDetail::AssignedSetChanged {
                    node_id: request.session.node_id.clone(),
                    agent_session_epoch: request.session.agent_session_epoch,
                    read_position: cats_api::runtime_reconciliation::Sequence::new(13).unwrap(),
                })
            ),
            NormalAcquireAttempt::Ambiguous
        );
        assert_eq!(
            attempt_for_error(
                409,
                contract_error(ContractErrorDetail::RevisionDigestConflict {
                    cat_id: request.cat_id,
                    desired_revision: request.desired_revision,
                    expected_digest: Sha256Digest::from_bytes([12; 32]),
                    presented_digest: Sha256Digest::from_bytes([13; 32]),
                })
            ),
            NormalAcquireAttempt::Ambiguous
        );
    }

    #[test]
    fn every_store_emittable_context_409_rejects_a_wrong_presented_identity() {
        let request = request();
        let accepted = accepted_context();
        let mut wrong_presented_session = request.session.clone();
        wrong_presented_session.agent_instance_id =
            cats_api::runtime_reconciliation::RandomId128::new("66666666666666666666666666666666")
                .unwrap();
        let mut earlier_expected_session = request.session.clone();
        earlier_expected_session.agent_session_epoch =
            cats_api::runtime_reconciliation::Epoch::new(1).unwrap();
        let mut wrong_presented_placement = request.placement.clone();
        wrong_presented_placement.placement_epoch =
            cats_api::runtime_reconciliation::Epoch::new(5).unwrap();
        let mut expected_placement = request.placement.clone();
        expected_placement.placement_epoch =
            cats_api::runtime_reconciliation::Epoch::new(4).unwrap();

        let wrong_details = [
            ContractErrorDetail::MissingAgentSession {
                node_id: Id::new("other-node").unwrap(),
            },
            ContractErrorDetail::StaleSession {
                node_id: request.session.node_id.clone(),
                presented_agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1)
                    .unwrap(),
                current_agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3)
                    .unwrap(),
            },
            ContractErrorDetail::WrongSession {
                expected: earlier_expected_session,
                presented: wrong_presented_session,
            },
            ContractErrorDetail::SessionExpired {
                node_id: request.session.node_id.clone(),
                agent_session_epoch: request.session.agent_session_epoch,
                lease_deadline_unix_ms: UnixMillis::new(1_720_000_119_999).unwrap(),
                server_time_unix_ms: UnixMillis::new(1_720_000_120_000).unwrap(),
            },
            ContractErrorDetail::MissingInventoryAttestation {
                node_id: Id::new("other-node").unwrap(),
                agent_session_epoch: request.session.agent_session_epoch,
            },
            ContractErrorDetail::AssignedSetChanged {
                node_id: request.session.node_id.clone(),
                agent_session_epoch: request.session.agent_session_epoch,
                read_position: cats_api::runtime_reconciliation::Sequence::new(13).unwrap(),
            },
            ContractErrorDetail::StaleRevision {
                cat_id: request.cat_id.clone(),
                presented_revision: Revision::new(6).unwrap(),
                current_revision: Revision::new(8).unwrap(),
            },
            ContractErrorDetail::WrongRevision {
                cat_id: request.cat_id.clone(),
                expected_revision: Revision::new(5).unwrap(),
                presented_revision: Revision::new(6).unwrap(),
            },
            ContractErrorDetail::RevisionDigestConflict {
                cat_id: request.cat_id.clone(),
                desired_revision: request.desired_revision,
                expected_digest: Sha256Digest::from_bytes([12; 32]),
                presented_digest: Sha256Digest::from_bytes([13; 32]),
            },
            ContractErrorDetail::WrongPlacement {
                cat_id: request.cat_id,
                desired_revision: request.desired_revision,
                expected: expected_placement,
                presented: wrong_presented_placement,
            },
        ];
        for detail in wrong_details {
            assert_eq!(
                attempt_for_error(409, contract_error(detail)),
                NormalAcquireAttempt::Ambiguous
            );
        }

        assert_eq!(
            accepted.inventory_attestation.inventory_read_position.get(),
            12
        );
    }

    #[test]
    fn acquire_preconditions_have_variant_specific_closed_actions() {
        for (problem, expected) in [
            (
                RuntimeVolumeTransitionPreconditionProblem::InventorySessionReplaced,
                NormalAcquireAttempt::RefreshInventory,
            ),
            (
                RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
                NormalAcquireAttempt::RefreshInventory,
            ),
            (
                RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
                NormalAcquireAttempt::ReplanDesired,
            ),
            (
                RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
                NormalAcquireAttempt::Ambiguous,
            ),
            (
                RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
                NormalAcquireAttempt::Ambiguous,
            ),
        ] {
            assert_eq!(
                attempt_for_error(
                    409,
                    RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                        cat_id: Id::new("cat_01").unwrap(),
                        problem,
                    }
                ),
                expected
            );
        }
    }

    #[test]
    fn definite_release_cleanup_conflicts_retain_the_typed_problem() {
        let request = request();
        let accepted = accepted_context();
        let volume = volume();
        for problem in [
            RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
            RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
        ] {
            let error = RuntimeVolumeTransitionError {
                version: ContractVersion::V1,
                error: Box::new(
                    RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                        cat_id: request.cat_id.clone(),
                        problem,
                    },
                ),
                message: "definite release conflict".to_owned(),
            };
            assert_eq!(
                map_closed_release_error(409, &error, &request, &volume, &accepted),
                NormalReleaseAttempt::DefiniteCleanupConflict(problem)
            );
        }

        let wrong_cat = RuntimeVolumeTransitionError {
            version: ContractVersion::V1,
            error: Box::new(
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id: Id::new("other-cat").unwrap(),
                    problem: RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
                },
            ),
            message: "wrong Cat".to_owned(),
        };
        assert_eq!(
            map_closed_release_error(409, &wrong_cat, &request, &volume, &accepted),
            NormalReleaseAttempt::Ambiguous
        );
    }

    #[test]
    fn status_and_error_detail_must_match_exactly() {
        let malformed = ContractErrorDetail::MalformedPayload {
            contract: ContractName::RuntimeVolumeTransitionRequest,
            json_pointer: cats_api::runtime_reconciliation::JsonPointer::new(String::new())
                .unwrap(),
            problem: cats_api::runtime_reconciliation::MalformedProblem::InvalidJson,
        };
        assert_eq!(
            attempt_for_error(400, contract_error(malformed.clone())),
            NormalAcquireAttempt::StopForLocalContract
        );
        for (status, detail) in [
            (409, contract_error(malformed)),
            (
                400,
                RuntimeVolumeTransitionErrorDetail::TransitionPreconditionFailed {
                    cat_id: Id::new("cat_01").unwrap(),
                    problem: RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
                },
            ),
            (
                413,
                RuntimeVolumeTransitionErrorDetail::VolumeAuthorityRejected {
                    volume_id: Id::new("vol_root").unwrap(),
                    reason: RuntimeVolumeAuthorityRejection::OtherWriter,
                },
            ),
        ] {
            assert_eq!(
                attempt_for_error(status, detail),
                NormalAcquireAttempt::Ambiguous
            );
        }
    }

    #[test]
    fn response_loss_adopts_only_the_exact_current_authority_marker() {
        let request = request();
        let volume = volume();
        let granted = ControlSignedNormalAcquireClient::new(FakeTransport::new(
            SignedVolumeTransitionResponse::Success(SUCCESS.to_vec()),
        ))
        .acquire(
            &request,
            &volume,
            &accepted_context(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let NormalAcquireAttempt::Granted(attachment) = granted else {
            unreachable!()
        };
        let mut record = VolumeRecord {
            volume_id: attachment.identity.volume_id.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            admin_state: VolumeAdminState::Active,
            head: attachment.head.clone(),
            lease_owner: Some(attachment.identity.attachment_id.clone()),
            lease_epoch: attachment.identity.attachment_epoch,
            // Model a renew whose response was also lost. Recovery retains
            // the original grant expiry while proving the current owner.
            lease_expires_at: Some(UnixMillis::new(1_720_000_120_000).unwrap()),
            last_transition: Some(LastVolumeTransition::NormalAcquire {
                request: attachment.acquire_request.clone(),
                result: attachment.acquire_result.clone(),
            }),
        };
        let recovered = recover_normal_acquire_from_authority(&request, &volume, &record).unwrap();
        let NormalAcquireAuthorityRecovery::Granted(recovered) = recovered else {
            panic!("matching authority marker was not adopted")
        };
        assert_eq!(recovered, attachment);

        record.head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([7; 32])),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new("roots/provisioned").unwrap(),
            ),
        };
        let recovered = recover_normal_acquire_from_authority(&request, &volume, &record).unwrap();
        let NormalAcquireAuthorityRecovery::Granted(recovered) = recovered else {
            panic!("later exact head was not adopted")
        };
        assert_eq!(recovered.head, record.head);
        assert_eq!(
            recovered.acquire_result.resulting_head,
            attachment.acquire_result.resulting_head
        );

        let predecessor = VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: attachment.acquire_result.resulting_head.clone(),
            lease_owner: None,
            lease_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(0).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        assert_eq!(
            recover_normal_acquire_from_authority(&request, &volume, &predecessor).unwrap(),
            NormalAcquireAuthorityRecovery::RetryExact
        );

        record.lease_owner = Some(Id::new("foreign-writer").unwrap());
        assert_eq!(
            recover_normal_acquire_from_authority(&request, &volume, &record).unwrap(),
            NormalAcquireAuthorityRecovery::Blocked
        );
    }

    fn signer() -> Ed25519RequestSigner {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        Ed25519RequestSigner::from_pkcs8_der(Id::new("credential_a").unwrap(), &der).unwrap()
    }

    fn raw_transport_response(
        raw_response: Vec<u8>,
    ) -> Result<SignedVolumeTransitionResponse, VolumeTransitionTransportFailure> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0;
            let mut accept_encoding = None;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                if name.eq_ignore_ascii_case("accept-encoding") {
                    accept_encoding = Some(value.trim().to_owned());
                }
            }
            assert_eq!(accept_encoding.as_deref(), Some("identity"));
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = reader.into_inner();
            stream.write_all(&raw_response).unwrap();
        });
        let client = RuntimeVolumeTransitionHttpClient::for_loopback_test(
            &format!("http://{address}/"),
            signer(),
        )
        .unwrap();
        let result = client.post_a19_signed_json(
            RUNTIME_VOLUME_TRANSITION_PATH,
            REQUEST,
            RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
            Instant::now() + Duration::from_secs(2),
        );
        server.join().unwrap();
        result
    }

    #[test]
    fn only_the_exact_product_router_404_is_a_deployment_mismatch() {
        let exact = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Robots-Tag: {RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS}\r\nServer: cats-test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY.len()
        )
        .into_bytes();
        let mut exact = exact;
        exact.extend_from_slice(RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY);
        assert_eq!(
            raw_transport_response(exact).unwrap(),
            SignedVolumeTransitionResponse::PlainRouteNotFound
        );

        let proxy_bodies = [
            ("text/html", b"<h1>not found</h1>".as_slice()),
            ("text/plain", b"route missing".as_slice()),
            (
                "application/json",
                b"{\"message\":\"upstream route missing\"}".as_slice(),
            ),
        ];
        for (content_type, body) in proxy_bodies {
            let mut response = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            assert_eq!(
                raw_transport_response(response).unwrap(),
                SignedVolumeTransitionResponse::Ambiguous
            );
        }

        let truncated = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Robots-Tag: {RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{\"code\":",
            RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY.len()
        )
        .into_bytes();
        assert_eq!(
            raw_transport_response(truncated).unwrap(),
            SignedVolumeTransitionResponse::Ambiguous
        );
    }

    #[test]
    fn compressed_or_proxy_marked_responses_are_always_ambiguous() {
        let gzip = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            SUCCESS.len()
        )
        .into_bytes();
        let mut gzip = gzip;
        gzip.extend_from_slice(SUCCESS);
        assert_eq!(
            raw_transport_response(gzip).unwrap(),
            SignedVolumeTransitionResponse::Ambiguous
        );

        let proxy = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Robots-Tag: {RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS}\r\nVia: 1.1 proxy\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY.len()
        )
        .into_bytes();
        let mut proxy = proxy;
        proxy.extend_from_slice(RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY);
        assert_eq!(
            raw_transport_response(proxy).unwrap(),
            SignedVolumeTransitionResponse::Ambiguous
        );
    }

    #[test]
    fn production_transport_signs_only_the_exact_route_and_validates_response_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert_eq!(
                request_line,
                "POST /v1/internal/runtime/volume-transitions HTTP/1.1\r\n"
            );
            let mut content_length = None;
            let mut proof_headers = std::collections::BTreeMap::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
                proof_headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
            let mut body = vec![0; content_length.unwrap()];
            reader.read_exact(&mut body).unwrap();
            assert_eq!(body, REQUEST);
            verify_request_proof(
                RUNTIME_SPINE_METHOD,
                RUNTIME_VOLUME_TRANSITION_PATH,
                &body,
                &proof_headers[NODE_CREDENTIAL_ID_HEADER],
                &proof_headers[NODE_PUBLIC_KEY_SPKI_HEADER],
                &proof_headers[NODE_SIGNATURE_HEADER],
            )
            .unwrap();
            assert_eq!(proof_headers["accept-encoding"], "identity");
            let mut stream = reader.into_inner();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                SUCCESS.len()
            )
            .unwrap();
            stream.write_all(SUCCESS).unwrap();
        });
        let client = RuntimeVolumeTransitionHttpClient::for_loopback_test(
            &format!("http://{address}/"),
            signer(),
        )
        .unwrap();
        let response = client
            .post_a19_signed_json(
                RUNTIME_VOLUME_TRANSITION_PATH,
                REQUEST,
                RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            response,
            SignedVolumeTransitionResponse::Success(SUCCESS.to_vec())
        );
        server.join().unwrap();
    }
}

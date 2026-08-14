//! Same-transaction authentication prefix for A22 volume authority access.
//!
//! A proof verifier can only construct [`AuthenticatedNodeCredential`].  It
//! cannot choose a Node id or manufacture one of the private transaction
//! contexts below.  Evidence and mutation entrypoints therefore have to take
//! the exact NodeIdentity, active credential lineage and current AgentSession
//! locks before they can reach an authorization or Volume row.

use cats_api::agent_registration::AuthenticatedNodeCredential;
#[cfg(feature = "proposed-node-residue-reclamation")]
use cats_api::runtime_reconciliation::{
    encode_runtime_residue_authority_request, RuntimeResidueAuthorityRequest,
    RuntimeResidueAuthoritySuccess,
};
use cats_api::runtime_reconciliation::{
    encode_runtime_volume_transition_evidence_request, encode_runtime_volume_transition_request,
    AcquireOrigin, AgentSession, AssignedPlacement, CleanupRelease, CleanupTarget, ContractError,
    ContractErrorDetail, ContractVersion, CredentialBinding, DesiredRuntimeSpec, DiskKind,
    FilesystemInitialization, Id, LocalLineageState, NodeIdentity, NodeIdentityState, NodeResidue,
    ObservedDiskKind, ObservedRuntimeStatus, PersistentFilesystemBinding,
    PersistentInitializationReceipt, ProcessRole, Revision, RuntimeTarget,
    RuntimeVolumeAuthorityRejection, RuntimeVolumeAuthorizationRejection, RuntimeVolumeTransition,
    RuntimeVolumeTransitionEvidenceRequest, RuntimeVolumeTransitionOutcome,
    RuntimeVolumeTransitionPreconditionProblem, RuntimeVolumeTransitionRequest,
    RuntimeVolumeTransitionSuccess, SessionBinding, Sha256Digest, UnixMillis, VolumeAcquire,
    VolumeAcquireRequest, VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent,
    VolumeLeaseGrant,
};
use cats_storage::authority::{
    consume_disposable_root_delete, consume_takeover, normal_acquire, release,
    replay_consumed_takeover, AuthorityError, AuthorizationRecord, AuthorizationState,
    HostFenceEvent, LastVolumeTransition, NormalAcquireRequest, ReleaseRequest, TakeoverResult,
    VolumeAuthorization, VolumeOwnerBinding, VolumeRecord,
};
use postgres::Transaction;

use super::product::{
    persistent_initialization_matches_mount, DiskAdminState, DiskRecord, DiskRole,
    PersistentDiskInitialization,
};
use super::product_rows::{
    load_any_disk_snapshot_for_update, load_cat_by_id_for_update, load_desired_for_update,
    load_disk_by_id_for_update, load_pending_operation_by_cat_for_update, update_disk,
};
#[cfg(feature = "proposed-node-residue-reclamation")]
use super::residue_authority::load_runtime_residue_authority_in;
use super::rows::{
    database_now, load_authorization_for_update, load_event_for_update,
    load_stored_volume_for_update, load_takeover_authorization_for_intent_update,
    runtime_authorization_route_for_context, takeover_authorization_is_owned_by_other_node,
    takeover_authorization_route_for_intent, update_authorization, update_volume_owner,
    volume_has_disposable_root_authorization_for_delete,
};
use super::runtime_spine::{
    lock_volume_mutation_admission_in, PlacementAdmissionSnapshot, VolumeMutationAdmissionRejection,
};
use super::volume_transition_evidence::{
    load_volume_transition_evidence_in, VolumeTransitionEvidenceLoad,
};
use crate::store::agent_sessions::{
    load_current_session_for_share, load_current_session_for_update,
    load_identity_by_credential_for_share, load_identity_by_credential_for_update,
    lock_exact_credential_lineage, CredentialLineageState,
};
use crate::store::transaction::{AuthorityRequestDisposition, AuthorityTxResult};
use crate::store::{AuthorityRequestContext, Result, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolumeTransitionStoreOutcome<T> {
    Accepted(T),
    Rejected(VolumeTransitionStoreRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolumeTransitionStoreRejection {
    IdentityNotEligible,
    Contract(ContractError),
    TransitionPreconditionFailed {
        cat_id: Id,
        problem: RuntimeVolumeTransitionPreconditionProblem,
    },
    VolumeAuthorizationRejected {
        authorization_id: Id,
        reason: RuntimeVolumeAuthorizationRejection,
    },
    VolumeAuthorityRejected {
        volume_id: Id,
        reason: RuntimeVolumeAuthorityRejection,
    },
}

/// Internal projection of an already-decoded A22 takeover request.  This is
/// not a second wire or persistence format: the future HTTP composition fills
/// it from the shared wrapper fields plus `transition.request.authorization_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeTakeoverConsumeRequest {
    pub(crate) session: SessionBinding,
    pub(crate) cat_id: Id,
    pub(crate) desired_revision: Revision,
    pub(crate) spec_digest: Sha256Digest,
    pub(crate) placement: AssignedPlacement,
    pub(crate) authorization_id: Id,
}

/// Capability for the A22 logical read path. Its fields and constructors are
/// private, and it owns the current transaction's mutable borrow, so a sibling
/// authority module can neither forge it from body data nor pair it with a
/// different transaction.
pub(super) struct EvidenceTransactionContext<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: AuthenticatedNodeTransaction,
}

/// Capability for the A22 mutation path. It is distinct from the evidence
/// context at the type level so a share-locked read prefix cannot be passed to
/// a writer accidentally.
struct AuthenticatedMutationPrefix<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: AuthenticatedNodeTransaction,
}

struct LockedMutationContext<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    node_id: Id,
    db_now: UnixMillis,
    admission: PlacementAdmissionSnapshot,
    desired: DesiredRuntimeSpec,
}

struct LockedTakeoverMutation<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    db_now: UnixMillis,
    event: HostFenceEvent,
    authorization: AuthorizationRecord,
    volume: VolumeRecord,
    owner_binding: VolumeOwnerBinding,
}

struct AuthenticatedNodeTransaction {
    node_id: Id,
    db_now: UnixMillis,
}

impl<'transaction, 'connection> EvidenceTransactionContext<'transaction, 'connection> {
    pub(super) fn into_parts(self) -> (&'transaction mut Transaction<'connection>, Id, UnixMillis) {
        (
            self.transaction,
            self.authenticated.node_id,
            self.authenticated.db_now,
        )
    }
}

impl Store {
    /// Reuses the A22 read-strength identity prefix for signed usage ingress.
    /// This is an authentication read only: no usage row or receipt is added
    /// to the Control store, and the configured UsageStore remains the one
    /// ingestion boundary.
    pub(crate) fn runtime_node_session_for_request(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        session: &SessionBinding,
        active_guest_config_digest: &Sha256Digest,
        request_context: &AuthorityRequestContext,
    ) -> Result<VolumeTransitionStoreOutcome<Id>> {
        self.authority_request_locking_read_snapshot(request_context, |transaction| {
            match authenticate_evidence_context_in(
                transaction,
                authenticated,
                session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => {
                    let (_, node_id, _) = context.into_parts();
                    Ok(VolumeTransitionStoreOutcome::Accepted(node_id))
                }
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    Ok(VolumeTransitionStoreOutcome::Rejected(rejection))
                }
            }
        })
    }

    /// Executes the complete closed A22 mutation union. Every branch starts
    /// from the same mutation-strength NodeIdentity/credential/session prefix
    /// and commits its domain rows in that one request-owned transaction.
    pub(crate) fn runtime_volume_transition(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeVolumeTransitionRequest,
        active_guest_config_digest: &Sha256Digest,
        request_context: &AuthorityRequestContext,
    ) -> Result<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionSuccess>> {
        self.runtime_volume_transition_checked(
            authenticated,
            request,
            active_guest_config_digest,
            request_context,
        )
    }

    fn runtime_volume_transition_checked(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeVolumeTransitionRequest,
        active_guest_config_digest: &Sha256Digest,
        request_context: &AuthorityRequestContext,
    ) -> Result<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionSuccess>> {
        if let Err(error) = encode_runtime_volume_transition_request(request) {
            return Ok(contract_rejected(error));
        }
        self.authority_request_transaction(request_context, |transaction| {
            let prefix = match authenticate_mutation_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(prefix) => prefix,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(AuthorityRequestDisposition::Reject(
                        VolumeTransitionStoreOutcome::Rejected(rejection),
                    ));
                }
            };
            let outcome =
                runtime_volume_transition_in(prefix, request, active_guest_config_digest)?;
            Ok(match outcome {
                accepted @ VolumeTransitionStoreOutcome::Accepted(_) => {
                    AuthorityRequestDisposition::Commit(accepted)
                }
                rejected @ VolumeTransitionStoreOutcome::Rejected(_) => {
                    AuthorityRequestDisposition::Reject(rejected)
                }
            })
        })
    }

    /// Loads one exact authorization evidence bundle under the credential and
    /// current AgentSession selected by the proof adapter.
    pub(crate) fn runtime_volume_transition_evidence(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeVolumeTransitionEvidenceRequest,
        active_guest_config_digest: &Sha256Digest,
    ) -> Result<VolumeTransitionStoreOutcome<VolumeTransitionEvidenceLoad>> {
        if let Err(error) = encode_runtime_volume_transition_evidence_request(request) {
            return Ok(VolumeTransitionStoreOutcome::Rejected(
                VolumeTransitionStoreRejection::Contract(error),
            ));
        }
        self.authority_locking_read_snapshot(|transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            load_volume_transition_evidence_in(context, request)
                .map(VolumeTransitionStoreOutcome::Accepted)
        })
    }

    pub(crate) fn runtime_volume_transition_evidence_with_context(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeVolumeTransitionEvidenceRequest,
        active_guest_config_digest: &Sha256Digest,
        request_context: &AuthorityRequestContext,
    ) -> Result<VolumeTransitionStoreOutcome<VolumeTransitionEvidenceLoad>> {
        if let Err(error) = encode_runtime_volume_transition_evidence_request(request) {
            return Ok(contract_rejected(error));
        }
        self.authority_request_locking_read_snapshot(request_context, |transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            load_volume_transition_evidence_in(context, request)
                .map(VolumeTransitionStoreOutcome::Accepted)
        })
    }

    /// Qualifies one exact retained local lineage under the current signed
    /// AgentSession and one repeatable-read PostgreSQL snapshot.
    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub(crate) fn runtime_residue_authority(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeResidueAuthorityRequest,
        active_guest_config_digest: &Sha256Digest,
    ) -> Result<VolumeTransitionStoreOutcome<Box<RuntimeResidueAuthoritySuccess>>> {
        if let Err(error) = encode_runtime_residue_authority_request(request) {
            return Ok(contract_rejected(error));
        }
        self.authority_locking_read_snapshot(|transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            load_runtime_residue_authority_in(context, request)
                .map(VolumeTransitionStoreOutcome::Accepted)
        })
    }

    #[cfg(feature = "proposed-node-residue-reclamation")]
    pub(crate) fn runtime_residue_authority_with_context(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeResidueAuthorityRequest,
        active_guest_config_digest: &Sha256Digest,
        request_context: &AuthorityRequestContext,
    ) -> Result<VolumeTransitionStoreOutcome<Box<RuntimeResidueAuthoritySuccess>>> {
        if let Err(error) = encode_runtime_residue_authority_request(request) {
            return Ok(contract_rejected(error));
        }
        self.authority_request_locking_read_snapshot(request_context, |transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            load_runtime_residue_authority_in(context, request)
                .map(VolumeTransitionStoreOutcome::Accepted)
        })
    }

    /// Consumes one takeover authorization only after the mutation-strength
    /// identity/session prefix has been locked in this same transaction.
    pub(crate) fn runtime_consume_volume_takeover(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeTakeoverConsumeRequest,
        active_guest_config_digest: &Sha256Digest,
    ) -> Result<VolumeTransitionStoreOutcome<TakeoverResult>> {
        let mut checkpoint = || Ok(());
        self.runtime_consume_volume_takeover_checked(
            authenticated,
            request,
            active_guest_config_digest,
            &mut checkpoint,
        )
    }

    fn runtime_consume_volume_takeover_checked<F>(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeTakeoverConsumeRequest,
        active_guest_config_digest: &Sha256Digest,
        checkpoint: &mut F,
    ) -> Result<VolumeTransitionStoreOutcome<TakeoverResult>>
    where
        F: FnMut() -> AuthorityTxResult<()> + Send,
    {
        self.authority_transaction(|transaction| {
            let prefix = match authenticate_mutation_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(prefix) => prefix,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            checkpoint()?;
            let locked = match lock_takeover_mutation_context(
                prefix,
                request,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(locked) => locked,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            consume_locked_takeover(locked, &request.authorization_id)
        })
    }

    #[cfg(test)]
    pub(super) fn runtime_consume_volume_takeover_with_checkpoint<F>(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeTakeoverConsumeRequest,
        active_guest_config_digest: &Sha256Digest,
        mut checkpoint: F,
    ) -> Result<VolumeTransitionStoreOutcome<TakeoverResult>>
    where
        F: FnMut() -> AuthorityTxResult<()> + Send,
    {
        self.runtime_consume_volume_takeover_checked(
            authenticated,
            request,
            active_guest_config_digest,
            &mut checkpoint,
        )
    }
}

fn runtime_volume_transition_in(
    prefix: AuthenticatedMutationPrefix<'_, '_>,
    request: &RuntimeVolumeTransitionRequest,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionSuccess>> {
    let context = match lock_common_mutation_context(prefix, request, active_guest_config_digest)? {
        VolumeTransitionStoreOutcome::Accepted(context) => context,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
        }
    };
    let outcome = match &request.transition {
        RuntimeVolumeTransition::Acquire {
            request: acquire @ VolumeAcquireRequest::Normal { .. },
        } => execute_normal_acquire(context, acquire)?,
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Takeover { authorization_id },
        } => execute_takeover(context, authorization_id)?,
        RuntimeVolumeTransition::Release { cleanup } => execute_release(context, cleanup)?,
        RuntimeVolumeTransition::DeleteDisposableRoot { authorization_id } => {
            execute_disposable_delete(context, authorization_id)?
        }
        RuntimeVolumeTransition::CommitInitialized {
            filesystem,
            new_remote_head,
        } => execute_commit_initialized(context, filesystem, new_remote_head)?,
    };
    Ok(match outcome {
        VolumeTransitionStoreOutcome::Accepted(outcome) => {
            VolumeTransitionStoreOutcome::Accepted(RuntimeVolumeTransitionSuccess {
                version: ContractVersion::V1,
                session: request.session.clone(),
                cat_id: request.cat_id.clone(),
                desired_revision: request.desired_revision,
                spec_digest: request.spec_digest.clone(),
                placement: request.placement.clone(),
                outcome,
            })
        }
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            VolumeTransitionStoreOutcome::Rejected(rejection)
        }
    })
}

fn lock_common_mutation_context<'transaction, 'connection>(
    prefix: AuthenticatedMutationPrefix<'transaction, 'connection>,
    request: &RuntimeVolumeTransitionRequest,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<LockedMutationContext<'transaction, 'connection>>>
{
    let AuthenticatedMutationPrefix {
        transaction,
        authenticated,
    } = prefix;
    let admission = match lock_volume_mutation_admission_in(
        transaction,
        &authenticated.node_id,
        active_guest_config_digest,
        authenticated.db_now,
    )? {
        Ok(admission) => *admission,
        Err(VolumeMutationAdmissionRejection::Contract(error)) => {
            return Ok(contract_rejected(error));
        }
        Err(VolumeMutationAdmissionRejection::InventorySessionReplaced) => {
            return Ok(precondition_rejected(
                request.cat_id.clone(),
                RuntimeVolumeTransitionPreconditionProblem::InventorySessionReplaced,
            ));
        }
        Err(VolumeMutationAdmissionRejection::InventoryStale) => {
            return Ok(precondition_rejected(
                request.cat_id.clone(),
                RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
            ));
        }
    };
    let Some(desired) = admission
        .assigned_desired_specs
        .iter()
        .find(|desired| desired.cat_id == request.cat_id)
        .cloned()
    else {
        return Ok(precondition_rejected(
            request.cat_id.clone(),
            RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
        ));
    };
    if let Some(error) = desired_binding_error_for_context(
        &desired,
        request.desired_revision,
        &request.spec_digest,
        &request.placement,
    ) {
        return Ok(contract_rejected(error));
    }
    if desired.placement.node_id != authenticated.node_id {
        return Ok(precondition_rejected(
            request.cat_id.clone(),
            RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
        ));
    }
    Ok(VolumeTransitionStoreOutcome::Accepted(
        LockedMutationContext {
            transaction,
            node_id: authenticated.node_id,
            db_now: authenticated.db_now,
            admission,
            desired,
        },
    ))
}

fn execute_normal_acquire(
    context: LockedMutationContext<'_, '_>,
    acquire: &VolumeAcquireRequest,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionOutcome>> {
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
        return Err(AuthorityError::BackendUnknown.into());
    };
    if context.desired.target == RuntimeTarget::Deleted {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }
    let Some(intent) = unique_intent(&context.desired, |intent| {
        intent.volume_id == *volume_id
            && intent.attachment_id == *attachment_id
            && matches!(
                &intent.acquire,
                VolumeAcquire::Normal {
                    transition_id: current,
                    expected_unowned_epoch: current_epoch,
                } if current == transition_id && current_epoch == expected_unowned_epoch
            )
    })?
    .cloned() else {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    };
    let request = NormalAcquireRequest {
        volume_id: volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_unowned_epoch: *expected_unowned_epoch,
        desired_revision: *desired_revision,
        placement_epoch: *placement_epoch,
        lease_duration_ms: *lease_duration_ms,
    };

    let stored_volume = load_stored_volume_for_update(context.transaction, volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let volume = stored_volume.record;
    let (disk, locked_desired) = lock_product_context(
        context.transaction,
        &context.desired,
        &intent,
        context.desired.target == RuntimeTarget::Deleted,
    )?;
    let Some(locked_intent) = unique_intent(&locked_desired, |candidate| candidate == &intent)?
    else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if !matches!(disk.admin_state, DiskAdminState::Active)
        || !disk_and_volume_common_identity_matches_intent(
            &disk,
            &volume,
            &locked_desired,
            locked_intent,
        )
    {
        return Err(AuthorityError::BackendUnknown.into());
    }
    if !disk_and_volume_identity_matches_intent(&disk, &volume, &locked_desired, locked_intent) {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }
    if !normal_physical_evidence_is_safe(&context, &intent, &volume, &request) {
        return Ok(precondition_rejected(
            context.desired.cat_id.clone(),
            RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
        ));
    }
    let (updated, result) = match normal_acquire(&volume, &request, context.db_now) {
        Ok(value) => value,
        Err(error) => return volume_authority_error(volume_id, error),
    };
    if updated != volume {
        let owner_binding = VolumeOwnerBinding {
            volume_id: updated.volume_id.clone(),
            owner_node_id: context.node_id.clone(),
            attachment_id: result.attachment_id.clone(),
            attachment_epoch: result.resulting_epoch,
        };
        update_volume_owner(context.transaction, &updated, Some(&owner_binding))?;
    } else if stored_volume
        .owner_binding
        .as_ref()
        .is_none_or(|binding| binding.owner_node_id != context.node_id)
    {
        return Err(AuthorityError::BackendUnknown.into());
    }
    Ok(VolumeTransitionStoreOutcome::Accepted(
        RuntimeVolumeTransitionOutcome::LeaseGranted {
            grant: VolumeLeaseGrant {
                volume_id: result.volume_id,
                attachment_id: result.attachment_id,
                attachment_epoch: result.resulting_epoch,
                size_bytes: volume.size_bytes,
                durability: volume.durability,
                head: result.resulting_head,
                lease_expires_at: result.lease_expires_at,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: result.transition_id,
                },
            },
        },
    ))
}

fn execute_commit_initialized(
    context: LockedMutationContext<'_, '_>,
    filesystem: &PersistentFilesystemBinding,
    new_remote_head: &cats_api::runtime_reconciliation::RemoteHead,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionOutcome>> {
    if context.desired.target != RuntimeTarget::Running {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }
    let Some(intent) = unique_intent(&context.desired, |intent| {
        persistent_filesystem_binding_matches_intent(filesystem, intent)
    })?
    .cloned() else {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    };

    // The data plane has already published the initialization writes.  Lock
    // the exact current Volume before the Disk/current-Desired suffix and
    // accept only that complete nonblank head as the CAS result.
    let stored_volume = load_stored_volume_for_update(context.transaction, &intent.volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let volume = stored_volume.record;
    let (mut disk, locked_desired) =
        lock_product_context(context.transaction, &context.desired, &intent, false)?;
    let Some(locked_intent) = unique_intent(&locked_desired, |candidate| candidate == &intent)?
    else {
        return Err(AuthorityError::BackendUnknown.into());
    };

    if !disk_and_volume_common_identity_matches_intent(
        &disk,
        &volume,
        &locked_desired,
        locked_intent,
    ) || !persistent_filesystem_binding_matches_intent(filesystem, locked_intent)
        || !commit_initialized_volume_authority_matches(
            &context,
            &stored_volume.owner_binding,
            &volume,
            filesystem,
            new_remote_head,
        )
        || !commit_initialized_physical_evidence_matches(
            &context,
            locked_intent,
            filesystem,
            new_remote_head,
        )
    {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }

    let (initialization_token, filesystem_uuid, expected_blank_head, initialized_at, update) =
        match &disk.role {
            DiskRole::Persistent { initialization } => match initialization.as_ref() {
                PersistentDiskInitialization::Uninitialized {
                    initialization_token,
                    filesystem_uuid,
                    expected_blank_head,
                } if persistent_disk_commit_tuple_matches(
                    filesystem,
                    initialization_token,
                    filesystem_uuid,
                    expected_blank_head,
                ) =>
                {
                    (
                        initialization_token.clone(),
                        filesystem_uuid.clone(),
                        expected_blank_head.clone(),
                        context.db_now,
                        true,
                    )
                }
                PersistentDiskInitialization::Initialized {
                    initialization_token,
                    filesystem_uuid,
                    expected_blank_head,
                    initialized_head,
                    initialized_at,
                } if persistent_disk_commit_tuple_matches(
                    filesystem,
                    initialization_token,
                    filesystem_uuid,
                    expected_blank_head,
                ) && initialized_head == new_remote_head =>
                {
                    (
                        initialization_token.clone(),
                        filesystem_uuid.clone(),
                        expected_blank_head.clone(),
                        *initialized_at,
                        false,
                    )
                }
                _ => return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id)),
            },
            DiskRole::Root { .. } => {
                return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
            }
        };

    if update {
        disk.role = DiskRole::Persistent {
            initialization: Box::new(PersistentDiskInitialization::Initialized {
                initialization_token: initialization_token.clone(),
                filesystem_uuid: filesystem_uuid.clone(),
                expected_blank_head: expected_blank_head.clone(),
                initialized_head: new_remote_head.clone(),
                initialized_at,
            }),
        };
        update_disk(context.transaction, &disk)?;
    }

    Ok(VolumeTransitionStoreOutcome::Accepted(
        RuntimeVolumeTransitionOutcome::PersistentInitialized {
            receipt: PersistentInitializationReceipt {
                disk_id: disk.disk_id,
                volume_id: volume.volume_id,
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
                initialized_head: new_remote_head.clone(),
                initialized_at,
            },
        },
    ))
}

fn execute_takeover(
    context: LockedMutationContext<'_, '_>,
    authorization_id: &Id,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionOutcome>> {
    if context.desired.target == RuntimeTarget::Deleted {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }
    let Some(intent) = takeover_intent(&context.desired, authorization_id)?.cloned() else {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    };
    let Some(event_id) = takeover_authorization_route_for_intent(
        context.transaction,
        authorization_id,
        &context.node_id,
        &intent.volume_id,
        context.desired.desired_revision,
        context.desired.placement.placement_epoch,
    )?
    else {
        if takeover_authorization_is_owned_by_other_node(
            context.transaction,
            authorization_id,
            &context.node_id,
        )? {
            return Ok(authorization_rejected(
                authorization_id.clone(),
                RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            ));
        }
        return Err(AuthorityError::BackendUnknown.into());
    };
    let event = load_event_for_update(context.transaction, &event_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let authorization = load_takeover_authorization_for_intent_update(
        context.transaction,
        authorization_id,
        &context.node_id,
        &intent.volume_id,
        context.desired.desired_revision,
        context.desired.placement.placement_epoch,
    )?
    .ok_or(AuthorityError::BackendUnknown)?;
    let VolumeAuthorization::Takeover(payload) = &authorization.authorization else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if payload.host_fence_event_id != event.event_id
        || !takeover_payload_matches_desired(payload, &context.node_id, &context.desired, &intent)
    {
        return Err(AuthorityError::BackendUnknown.into());
    }
    let stored_volume = load_stored_volume_for_update(context.transaction, &intent.volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let volume = stored_volume.record;
    let owner_binding = stored_volume
        .owner_binding
        .ok_or(AuthorityError::BackendUnknown)?;
    if matches!(authorization.state, AuthorizationState::Unconsumed)
        && owner_binding.owner_node_id != event.node_id
    {
        return Ok(authorization_rejected(
            authorization_id.clone(),
            RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
        ));
    }
    let (disk, locked_desired) =
        lock_product_context(context.transaction, &context.desired, &intent, false)?;
    let Some(locked_intent) = takeover_intent(&locked_desired, authorization_id)?.cloned() else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if locked_intent != intent
        || !disk_and_volume_match_intent(&disk, &volume, &locked_desired, &locked_intent)
    {
        return Err(AuthorityError::BackendUnknown.into());
    }
    let result = match replay_consumed_takeover(&authorization, authorization_id) {
        Ok(Some(result)) => {
            if owner_binding.owner_node_id != context.node_id {
                return Err(AuthorityError::BackendUnknown.into());
            }
            result
        }
        Ok(None) => {
            let (updated_volume, updated_authorization, result) = match consume_takeover(
                &volume,
                &event,
                &authorization,
                authorization_id,
                context.db_now,
            ) {
                Ok(value) => value,
                Err(error) => return takeover_authority_error(authorization_id, error),
            };
            let owner_binding = VolumeOwnerBinding {
                volume_id: updated_volume.volume_id.clone(),
                owner_node_id: context.node_id.clone(),
                attachment_id: result.attachment_id.clone(),
                attachment_epoch: result.resulting_epoch,
            };
            update_volume_owner(context.transaction, &updated_volume, Some(&owner_binding))?;
            update_authorization(context.transaction, &authorization, &updated_authorization)?;
            result
        }
        Err(error) => return takeover_authority_error(authorization_id, error),
    };
    Ok(VolumeTransitionStoreOutcome::Accepted(
        RuntimeVolumeTransitionOutcome::LeaseGranted {
            grant: takeover_grant(&volume, result),
        },
    ))
}

fn execute_release(
    context: LockedMutationContext<'_, '_>,
    cleanup: &CleanupRelease,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionOutcome>> {
    let (
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return Ok(precondition_rejected(
            context.desired.cat_id.clone(),
            RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
        ));
    };
    let Some(intent) = unique_intent(&context.desired, |intent| {
        intent.volume_id == *volume_id && intent.attachment_id == *attachment_id
    })?
    .cloned() else {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    };
    if intent.disposition != replay.disposition
        || !release_disposition_matches_current(&context.desired, &intent)
    {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }
    let release_request = ReleaseRequest {
        volume_id: volume_id.clone(),
        transition_id: replay.release_transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_epoch: *attachment_epoch,
    };
    let stored_volume = load_stored_volume_for_update(context.transaction, volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let volume = stored_volume.record;
    let (disk, locked_desired) = lock_product_context(
        context.transaction,
        &context.desired,
        &intent,
        context.desired.target == RuntimeTarget::Deleted,
    )?;
    let Some(locked_intent) = unique_intent(&locked_desired, |candidate| candidate == &intent)?
    else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if !disk_and_volume_match_intent(&disk, &volume, &locked_desired, locked_intent) {
        return Err(AuthorityError::BackendUnknown.into());
    }
    if !release_evidence_matches(&context, cleanup, &intent, &volume) {
        return Ok(precondition_rejected(
            context.desired.cat_id.clone(),
            RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
        ));
    }
    if let VolumeDisposition::DeleteDisposableRoot { delete_id } = &intent.disposition {
        if volume_has_disposable_root_authorization_for_delete(
            context.transaction,
            volume_id,
            delete_id,
            context.desired.desired_revision,
            context.desired.placement.placement_epoch,
        )? {
            return Ok(precondition_rejected(
                context.desired.cat_id.clone(),
                RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
            ));
        }
    }
    let (updated, result) = match release(&volume, &release_request) {
        Ok(value) => value,
        Err(error) => return volume_authority_error(volume_id, error),
    };
    if updated != volume {
        if stored_volume
            .owner_binding
            .as_ref()
            .is_none_or(|binding| binding.owner_node_id != context.node_id)
        {
            return Err(AuthorityError::BackendUnknown.into());
        }
        update_volume_owner(context.transaction, &updated, None)?;
    }
    Ok(VolumeTransitionStoreOutcome::Accepted(
        RuntimeVolumeTransitionOutcome::Released { release: result },
    ))
}

fn execute_disposable_delete(
    context: LockedMutationContext<'_, '_>,
    authorization_id: &Id,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<RuntimeVolumeTransitionOutcome>> {
    let Some(route) = runtime_authorization_route_for_context(
        context.transaction,
        authorization_id,
        &context.node_id,
        context.desired.desired_revision,
        context.desired.placement.placement_epoch,
    )?
    else {
        return Ok(authorization_rejected(
            authorization_id.clone(),
            RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
        ));
    };
    if route.kind != "disposable_root_delete" || context.desired.target != RuntimeTarget::Deleted {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    }
    let Some(intent) = unique_intent(&context.desired, |intent| {
        intent.volume_id == route.volume_id
            && intent.disk_kind == DiskKind::Root
            && matches!(
                intent.disposition,
                VolumeDisposition::DeleteDisposableRoot { .. }
            )
    })?
    .cloned() else {
        return Ok(volume_intent_rejected_for_cat(&context.desired.cat_id));
    };

    let event = match &route.host_fence_event_id {
        Some(event_id) => Some(
            load_event_for_update(context.transaction, event_id)?
                .ok_or(AuthorityError::BackendUnknown)?,
        ),
        None => None,
    };
    let authorization = load_authorization_for_update(context.transaction, authorization_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let VolumeAuthorization::DisposableRootDelete(payload) = &authorization.authorization else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    let VolumeDisposition::DeleteDisposableRoot { delete_id } = &intent.disposition else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if payload.authorization_id != *authorization_id
        || payload.authorized_node_id != context.node_id
        || payload.volume_id != intent.volume_id
        || payload.disk_id != intent.disk_id
        || payload.cat_id != context.desired.cat_id
        || payload.delete_id != *delete_id
        || payload.desired_revision != context.desired.desired_revision
        || payload.placement_epoch != context.desired.placement.placement_epoch
        || payload.expected_attachment_id != intent.attachment_id
        || disposable_event_id(&payload.isolation_basis) != route.host_fence_event_id.as_ref()
    {
        return Err(AuthorityError::BackendUnknown.into());
    }
    let stored_volume = load_stored_volume_for_update(context.transaction, &intent.volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let volume = stored_volume.record;
    let expected_owner_node_id = match &payload.isolation_basis {
        cats_storage::authority::DisposableDeleteIsolationBasis::HostFenceEvent { .. } => event
            .as_ref()
            .map(|event| &event.node_id)
            .ok_or(AuthorityError::BackendUnknown)?,
        cats_storage::authority::DisposableDeleteIsolationBasis::RuntimeStopped {
            node_id, ..
        } => node_id,
    };
    match (&authorization.state, stored_volume.owner_binding.as_ref()) {
        (AuthorizationState::Unconsumed, Some(binding))
            if binding.owner_node_id == *expected_owner_node_id => {}
        (AuthorizationState::Consumed(_), None) => {}
        _ => {
            return Ok(authorization_rejected(
                authorization_id.clone(),
                RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            ));
        }
    }
    let (mut disk, locked_desired) =
        lock_product_context(context.transaction, &context.desired, &intent, true)?;
    let Some(locked_intent) = unique_intent(&locked_desired, |candidate| candidate == &intent)?
    else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    let disk_state_matches = match (&authorization.state, &disk.admin_state) {
        (AuthorizationState::Unconsumed, DiskAdminState::Active) => true,
        (AuthorizationState::Consumed(_), DiskAdminState::Deleting { delete_id: current }) => {
            current == &payload.delete_id
        }
        _ => false,
    };
    if !disk_and_volume_identity_matches_intent(&disk, &volume, &locked_desired, locked_intent)
        || !disk_state_matches
        || !disposable_isolation_evidence_matches(
            &context,
            payload,
            &intent,
            &volume,
            event.as_ref(),
        )
    {
        return Ok(authorization_rejected(
            authorization_id.clone(),
            RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
        ));
    }
    if load_any_disk_snapshot_for_update(
        context.transaction,
        &payload.disk_id,
        &payload.volume_id,
        disk.size_bytes,
    )?
    .is_some()
    {
        return disposable_authority_error(authorization_id, AuthorityError::SnapshotInUse);
    }
    let (updated_volume, updated_authorization, receipt) = match consume_disposable_root_delete(
        &volume,
        event.as_ref(),
        &authorization,
        authorization_id,
        context.db_now,
    ) {
        Ok(value) => value,
        Err(error) => return disposable_authority_error(authorization_id, error),
    };
    let expected_disk_state = DiskAdminState::Deleting {
        delete_id: payload.delete_id.clone(),
    };
    match (&authorization.state, &disk.admin_state) {
        (AuthorizationState::Unconsumed, DiskAdminState::Active) => {
            disk.admin_state = expected_disk_state;
            update_volume_owner(context.transaction, &updated_volume, None)?;
            update_authorization(context.transaction, &authorization, &updated_authorization)?;
            update_disk(context.transaction, &disk)?;
        }
        (AuthorizationState::Consumed(_), state) if state == &expected_disk_state => {
            if updated_volume != volume || updated_authorization != authorization {
                return Err(AuthorityError::BackendUnknown.into());
            }
        }
        _ => return Err(AuthorityError::BackendUnknown.into()),
    }
    Ok(VolumeTransitionStoreOutcome::Accepted(
        RuntimeVolumeTransitionOutcome::DisposableRootDeleting { receipt },
    ))
}

fn unique_intent(
    desired: &DesiredRuntimeSpec,
    predicate: impl Fn(&VolumeIntent) -> bool,
) -> AuthorityTxResult<Option<&VolumeIntent>> {
    let mut matches = desired.volumes.iter().filter(|intent| predicate(intent));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(AuthorityError::BackendUnknown.into());
    }
    Ok(first)
}

fn lock_product_context(
    transaction: &mut Transaction<'_>,
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
    operation_required: bool,
) -> AuthorityTxResult<(DiskRecord, DesiredRuntimeSpec)> {
    let disk = load_disk_by_id_for_update(transaction, &intent.disk_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let cat = load_cat_by_id_for_update(transaction, &desired.cat_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let locked_desired = load_desired_for_update(transaction, &desired.cat_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let operation = load_pending_operation_by_cat_for_update(transaction, &desired.cat_id)?;
    if cat.cat_id != desired.cat_id
        || cat.workspace_id != desired.workspace_id
        || locked_desired != *desired
        || operation.as_ref().is_some_and(|operation| {
            operation.workspace_id != desired.workspace_id
                || operation.cat_id != desired.cat_id
                || operation.desired_revision != desired.desired_revision
                || operation.desired_spec_digest != desired.spec_digest
                || operation.placement != desired.placement
                || operation.target != desired.target
        })
        || (operation_required && operation.is_none())
    {
        return Err(AuthorityError::BackendUnknown.into());
    }
    Ok((disk, locked_desired))
}

fn persistent_filesystem_binding_matches_intent(
    filesystem: &PersistentFilesystemBinding,
    intent: &VolumeIntent,
) -> bool {
    let Some(mount) = intent.mount.as_ref() else {
        return false;
    };
    intent.disk_kind == DiskKind::Persistent
        && intent.volume_intent_id == filesystem.volume_intent_id
        && intent.disk_id == filesystem.disk_id
        && intent.volume_id == filesystem.volume_id
        && intent.attachment_id == filesystem.attachment_id
        && intent.size_bytes == filesystem.size_bytes
        && intent.guest_device == filesystem.guest_device
        && mount.filesystem_uuid == filesystem.filesystem_uuid
        && mount.mount_path == filesystem.mount_path
        && mount.initialization == filesystem.initialization
        && matches!(
            filesystem.initialization,
            FilesystemInitialization::Initialize { .. }
        )
}

fn persistent_disk_commit_tuple_matches(
    filesystem: &PersistentFilesystemBinding,
    initialization_token: &cats_api::runtime_reconciliation::RandomId128,
    filesystem_uuid: &cats_api::runtime_reconciliation::RandomId128,
    expected_blank_head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    filesystem.filesystem_uuid == *filesystem_uuid
        && matches!(
            &filesystem.initialization,
            FilesystemInitialization::Initialize {
                initialization_token: presented_token,
                expected_blank_head: presented_blank,
            } if presented_token == initialization_token
                && presented_blank == expected_blank_head
        )
}

fn commit_initialized_volume_authority_matches(
    context: &LockedMutationContext<'_, '_>,
    owner_binding: &Option<VolumeOwnerBinding>,
    volume: &VolumeRecord,
    filesystem: &PersistentFilesystemBinding,
    new_remote_head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    matches!(
        volume.admin_state,
        cats_storage::authority::VolumeAdminState::Active
    ) && volume.volume_id == filesystem.volume_id
        && volume.lease_owner.as_ref() == Some(&filesystem.attachment_id)
        && volume.lease_epoch == filesystem.attachment_epoch
        && volume.head == *new_remote_head
        && new_remote_head.generation.get() > 0
        && owner_binding.as_ref().is_some_and(|binding| {
            binding.volume_id == filesystem.volume_id
                && binding.owner_node_id == context.node_id
                && binding.attachment_id == filesystem.attachment_id
                && binding.attachment_epoch == filesystem.attachment_epoch
        })
}

fn commit_initialized_physical_evidence_matches(
    context: &LockedMutationContext<'_, '_>,
    intent: &VolumeIntent,
    filesystem: &PersistentFilesystemBinding,
    new_remote_head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    let physical = PhysicalVolumeAuthorityIndex::build(
        &context.admission.full_inventory_observation,
        &intent.volume_id,
    );
    if physical.has_residue
        || physical.volumes.len() != 1
        || physical.blockd_processes.len() != 1
        || !physical.mounts.is_empty()
    {
        return false;
    }
    let Some(runtime) = runtime_for_desired(&context.admission, &context.desired) else {
        return false;
    };
    let (observed_runtime, observed) = physical.volumes[0];
    if !std::ptr::eq(observed_runtime, runtime)
        || runtime.runtime_incarnation.as_ref() != Some(&filesystem.runtime_incarnation)
        || runtime.stable_state.is_some()
        || !observed_volume_identity_matches(observed, intent)
    {
        return false;
    }
    let expected_step = cats_api::runtime_reconciliation::ReconcileStep::CommitInitialized {
        filesystem: Box::new(filesystem.clone()),
        new_remote_head: new_remote_head.clone(),
    };
    if runtime.step != expected_step {
        return false;
    }
    let cats_api::runtime_reconciliation::CheckpointEvidence::Valid {
        cat_id,
        node_id,
        desired_revision,
        spec_digest,
        placement_epoch,
        runtime_incarnation,
        runtime_launch,
        stable_state,
        step,
        ..
    } = &runtime.checkpoint
    else {
        return false;
    };
    if cat_id != &context.desired.cat_id
        || node_id != &context.node_id
        || desired_revision != &context.desired.desired_revision
        || spec_digest != &context.desired.spec_digest
        || placement_epoch != &context.desired.placement.placement_epoch
        || runtime_incarnation.as_ref() != Some(&filesystem.runtime_incarnation)
        || stable_state.is_some()
        || step.as_ref() != &expected_step
    {
        return false;
    }
    let Some(launch) = runtime_launch.identity() else {
        return false;
    };
    if launch.runtime_incarnation != filesystem.runtime_incarnation
        || launch
            .devices
            .iter()
            .filter(|device| device.volume_intent_id == filesystem.volume_intent_id)
            .count()
            != 1
        || !launch.devices.iter().any(|device| {
            device.volume_intent_id == filesystem.volume_intent_id
                && device.disk_id == filesystem.disk_id
                && device.volume_id == filesystem.volume_id
                && device.disk_kind == DiskKind::Persistent
                && device.attachment_id == filesystem.attachment_id
                && device.attachment_epoch == filesystem.attachment_epoch
                && acquire_origin_matches_intent(&device.acquire_origin, &intent.acquire)
                && device.size_bytes == filesystem.size_bytes
                && device.durability == intent.durability
                && device.guest_device == filesystem.guest_device
                && matches!(
                    &filesystem.initialization,
                    FilesystemInitialization::Initialize {
                        expected_blank_head,
                        ..
                    } if device.expected_head == *expected_blank_head
                )
        })
    {
        return false;
    }
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    if attachment_id != &filesystem.attachment_id
        || *attachment_epoch != filesystem.attachment_epoch
        || head != new_remote_head
        || observed.local_lineages.len() != 1
        || observed.devices.len() != 1
    {
        return false;
    }
    let lineage_matches = observed.local_lineages.first().is_some_and(|lineage| {
        lineage.attachment_id == filesystem.attachment_id
            && lineage.attachment_epoch == filesystem.attachment_epoch
            && acquire_origin_matches_intent(&lineage.acquire_origin, &intent.acquire)
            && lineage.node_id == context.node_id
            && lineage.placement_epoch == context.desired.placement.placement_epoch
            && lineage.local_durable_generation == new_remote_head.generation
            && lineage.remote_durable_generation == new_remote_head.generation
            && lineage.pending_pack_count.get() == 0
            && !lineage.fenced
            && lineage.state == LocalLineageState::Active
    });
    let device_matches = observed.devices.first().is_some_and(|device| match device {
        cats_api::runtime_reconciliation::ObservedDevice::KernelNbd {
            guest_device,
            ownership_token,
            ..
        }
        | cats_api::runtime_reconciliation::ObservedDevice::VhostUserBlk {
            guest_device,
            ownership_token,
            ..
        } => {
            guest_device == &filesystem.guest_device
                && matches!(
                    ownership_token,
                    cats_api::runtime_reconciliation::OwnershipTokenEvidence::Valid { .. }
                )
        }
    });
    let blockd_matches =
        physical
            .blockd_processes
            .first()
            .is_some_and(|(process_runtime, process)| {
                std::ptr::eq(*process_runtime, runtime)
                    && blockd_process_matches(
                        process,
                        &filesystem.volume_id,
                        &filesystem.attachment_id,
                        filesystem.attachment_epoch,
                    )
            });
    lineage_matches && device_matches && blockd_matches
}

fn normal_physical_evidence_is_safe(
    context: &LockedMutationContext<'_, '_>,
    intent: &VolumeIntent,
    volume: &VolumeRecord,
    request: &NormalAcquireRequest,
) -> bool {
    let physical = PhysicalVolumeAuthorityIndex::build(
        &context.admission.full_inventory_observation,
        &intent.volume_id,
    );
    if physical.has_residue || physical.volumes.len() != 1 {
        return false;
    }
    let Some(expected_runtime) = runtime_for_desired(&context.admission, &context.desired) else {
        return false;
    };
    let (runtime, observed) = physical.volumes[0];
    if !std::ptr::eq(runtime, expected_runtime)
        || !observed_volume_identity_matches(observed, intent)
    {
        return false;
    }
    match &observed.authority {
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        } => {
            *attachment_epoch == request.expected_unowned_epoch
                && *head == volume.head
                && observed.local_lineages.is_empty()
                && physical.blockd_processes.is_empty()
                && physical.mounts.is_empty()
        }
        VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            head,
        } => {
            let Some(resulting_epoch) = request
                .expected_unowned_epoch
                .get()
                .checked_add(1)
                .and_then(cats_storage::authority::FenceEpoch::new)
            else {
                return false;
            };
            let exact_known_empty_replay = observed.local_lineages.is_empty()
                && observed.devices.is_empty()
                && runtime.processes.is_empty()
                && runtime.mounts.is_empty()
                && physical.blockd_processes.is_empty()
                && physical.mounts.is_empty()
                && volume_has_exact_normal_acquire_marker(volume, request);
            let exact_started_lineage = observed.local_lineages.len() == 1
                && observed.local_lineages.first().is_some_and(|lineage| {
                    lineage.attachment_id == request.attachment_id
                        && lineage.attachment_epoch == resulting_epoch
                        && matches!(
                            &lineage.acquire_origin,
                            AcquireOrigin::Normal { transition_id }
                                if transition_id == &request.transition_id
                        )
                        && lineage.node_id == context.node_id
                        && lineage.placement_epoch == context.desired.placement.placement_epoch
                        && !lineage.fenced
                        && lineage.state == LocalLineageState::Active
                })
                && physical.blockd_processes.len() == 1
                && physical
                    .blockd_processes
                    .first()
                    .is_some_and(|(runtime, process)| {
                        std::ptr::eq(*runtime, expected_runtime)
                            && blockd_process_matches(
                                process,
                                &intent.volume_id,
                                &request.attachment_id,
                                resulting_epoch,
                            )
                    })
                && physical
                    .mounts
                    .iter()
                    .all(|(runtime, _)| std::ptr::eq(*runtime, expected_runtime));
            attachment_id == &request.attachment_id
                && *attachment_epoch == resulting_epoch
                && head == &volume.head
                && (exact_known_empty_replay || exact_started_lineage)
        }
        VolumeAuthorityEvidence::Unavailable
        | VolumeAuthorityEvidence::Absent
        | VolumeAuthorityEvidence::Deleting { .. } => false,
    }
}

fn volume_has_exact_normal_acquire_marker(
    volume: &VolumeRecord,
    request: &NormalAcquireRequest,
) -> bool {
    matches!(
        &volume.last_transition,
        Some(LastVolumeTransition::NormalAcquire {
            request: original,
            result,
        }) if original == request
            && result.volume_id == volume.volume_id
            && result.attachment_id == request.attachment_id
            && result.resulting_epoch == volume.lease_epoch
            && result.resulting_head == volume.head
            && volume.lease_owner.as_ref() == Some(&request.attachment_id)
            && volume.lease_expires_at == Some(result.lease_expires_at)
    )
}

fn release_evidence_matches(
    context: &LockedMutationContext<'_, '_>,
    cleanup: &CleanupRelease,
    intent: &VolumeIntent,
    volume: &VolumeRecord,
) -> bool {
    let physical = PhysicalVolumeAuthorityIndex::build(
        &context.admission.full_inventory_observation,
        &intent.volume_id,
    );
    if physical.has_residue
        || cleanup.inventory_session != session_binding_from_agent(&context.admission.agent_session)
        || cleanup.inventory_epoch != context.admission.inventory_attestation.inventory_epoch
        || cleanup.inventory_read_position
            != context
                .admission
                .inventory_attestation
                .inventory_read_position
        || cleanup.desired_read_position < cleanup.inventory_read_position
        || cleanup.desired_read_position > context.admission.desired_read_position
    {
        return false;
    }
    let Some(release) = cleanup.volume_release.as_ref() else {
        return false;
    };
    let Some(runtime) = runtime_for_desired(&context.admission, &context.desired) else {
        return false;
    };
    if runtime.runtime_incarnation.is_some()
        || !runtime.processes.is_empty()
        || !runtime.mounts.is_empty()
        || !matches!(
            runtime.guest_transport,
            cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable
        )
        || !physical.blockd_processes.is_empty()
        || !physical.mounts.is_empty()
        || physical.volumes.len() != 1
        || !std::ptr::eq(physical.volumes[0].0, runtime)
    {
        return false;
    }
    let observed = physical.volumes[0].1;
    if !observed_volume_identity_matches(observed, intent) || !observed.devices.is_empty() {
        return false;
    }
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    let CleanupTarget::Volume {
        attachment_epoch: expected_epoch,
        ..
    } = &cleanup.target
    else {
        return false;
    };
    if attachment_id != &intent.attachment_id
        || attachment_epoch != expected_epoch
        || *head != volume.head
        || head.generation != release.generation
    {
        return false;
    }
    observed.local_lineages.len() == 1
        && observed.local_lineages.first().is_some_and(|lineage| {
            lineage.attachment_id == intent.attachment_id
                && lineage.attachment_epoch == *expected_epoch
                && acquire_origin_matches_intent(&lineage.acquire_origin, &intent.acquire)
                && lineage.node_id == context.node_id
                && lineage.placement_epoch == context.desired.placement.placement_epoch
                && lineage.local_durable_generation == release.generation
                && lineage.remote_durable_generation == release.generation
                && lineage.pending_pack_count.get() == 0
                && !lineage.fenced
                && lineage.state == LocalLineageState::Active
        })
}

struct PhysicalVolumeAuthorityIndex<'a> {
    volumes: Vec<(
        &'a ObservedRuntimeStatus,
        &'a cats_api::runtime_reconciliation::ObservedVolume,
    )>,
    blockd_processes: Vec<(
        &'a ObservedRuntimeStatus,
        &'a cats_api::runtime_reconciliation::ProcessEvidence,
    )>,
    mounts: Vec<(
        &'a ObservedRuntimeStatus,
        &'a cats_api::runtime_reconciliation::ObservedMount,
    )>,
    has_residue: bool,
}

impl<'a> PhysicalVolumeAuthorityIndex<'a> {
    fn build(
        observation: &'a cats_api::runtime_reconciliation::NodeObservation,
        volume_id: &Id,
    ) -> Self {
        let mut volumes = Vec::new();
        let mut blockd_processes = Vec::new();
        let mut mounts = Vec::new();
        for runtime in &observation.runtimes {
            volumes.extend(
                runtime
                    .volumes
                    .iter()
                    .filter(|volume| volume.volume_id == *volume_id)
                    .map(|volume| (runtime, volume)),
            );
            blockd_processes.extend(
                runtime
                    .processes
                    .iter()
                    .filter(|process| {
                        matches!(
                            &process.role,
                            ProcessRole::Blockd {
                                volume_id: current,
                                ..
                            } if current == volume_id
                        )
                    })
                    .map(|process| (runtime, process)),
            );
            mounts.extend(
                runtime
                    .mounts
                    .iter()
                    .filter(|mount| mount.volume_id == *volume_id)
                    .map(|mount| (runtime, mount)),
            );
        }
        Self {
            volumes,
            blockd_processes,
            mounts,
            has_residue: observation
                .residue
                .iter()
                .any(|residue| residue_may_name_volume(residue, volume_id)),
        }
    }
}

fn blockd_process_matches(
    process: &cats_api::runtime_reconciliation::ProcessEvidence,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: cats_storage::authority::FenceEpoch,
) -> bool {
    matches!(
        &process.role,
        ProcessRole::Blockd {
            volume_id: current_volume,
            attachment_id: current_attachment,
            attachment_epoch: current_epoch,
        } if current_volume == volume_id
            && current_attachment == attachment_id
            && *current_epoch == attachment_epoch
    ) && process.state == cats_api::runtime_reconciliation::ProcessState::Running
        && matches!(
            &process.ownership_token,
            cats_api::runtime_reconciliation::OwnershipTokenEvidence::Valid { .. }
        )
        && matches!(
            &process.control_handshake,
            cats_api::runtime_reconciliation::ControlHandshakeEvidence::Verified
        )
}

fn disposable_isolation_evidence_matches(
    context: &LockedMutationContext<'_, '_>,
    authorization: &cats_storage::authority::DisposableRootDeleteAuthorization,
    intent: &VolumeIntent,
    volume: &VolumeRecord,
    event: Option<&HostFenceEvent>,
) -> bool {
    let physical = PhysicalVolumeAuthorityIndex::build(
        &context.admission.full_inventory_observation,
        &intent.volume_id,
    );
    if physical.has_residue
        || !physical.blockd_processes.is_empty()
        || !physical.mounts.is_empty()
        || physical.volumes.len() != 1
    {
        return false;
    }
    let Some(expected_runtime) = runtime_for_desired(&context.admission, &context.desired) else {
        return false;
    };
    let (runtime, observed) = physical.volumes[0];
    if !std::ptr::eq(runtime, expected_runtime)
        || !observed_volume_identity_matches(observed, intent)
        || !observed.devices.is_empty()
    {
        return false;
    }
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    if attachment_id != &authorization.expected_attachment_id
        || *attachment_epoch != authorization.expected_epoch
        || *head != authorization.expected_head
        || *head != volume.head
    {
        return false;
    }
    match (&authorization.isolation_basis, event) {
        (
            cats_storage::authority::DisposableDeleteIsolationBasis::HostFenceEvent { event_id },
            Some(event),
        ) => event.event_id == *event_id && observed.local_lineages.is_empty(),
        (
            cats_storage::authority::DisposableDeleteIsolationBasis::RuntimeStopped {
                node_id,
                agent_session_epoch,
                runtime_incarnation,
                observation_id,
            },
            None,
        ) => {
            if node_id != &context.node_id
                || *agent_session_epoch != context.admission.agent_session.agent_session_epoch
                || observation_id != &context.admission.full_inventory_observation.observation_id
            {
                return false;
            }
            let checkpoint_incarnation = match &runtime.checkpoint {
                cats_api::runtime_reconciliation::CheckpointEvidence::Valid {
                    runtime_incarnation,
                    ..
                } => runtime_incarnation.as_ref(),
                _ => None,
            };
            if runtime.runtime_incarnation.as_ref() != Some(runtime_incarnation)
                || checkpoint_incarnation.is_some_and(|current| current != runtime_incarnation)
                || !runtime.processes.is_empty()
                || !runtime.mounts.is_empty()
                || !matches!(
                    runtime.guest_transport,
                    cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable
                )
            {
                return false;
            }
            observed.local_lineages.len() == 1
                && observed.local_lineages.first().is_some_and(|lineage| {
                    lineage.attachment_id == authorization.expected_attachment_id
                        && lineage.attachment_epoch == authorization.expected_epoch
                        && acquire_origin_matches_intent(&lineage.acquire_origin, &intent.acquire)
                        && lineage.node_id == context.node_id
                        && lineage.placement_epoch == context.desired.placement.placement_epoch
                        && lineage.remote_durable_generation == volume.head.generation
                        && lineage.local_durable_generation > lineage.remote_durable_generation
                        && !lineage.fenced
                        && lineage.state == LocalLineageState::Active
                })
        }
        _ => false,
    }
}

fn runtime_for_desired<'a>(
    admission: &'a PlacementAdmissionSnapshot,
    desired: &DesiredRuntimeSpec,
) -> Option<&'a ObservedRuntimeStatus> {
    let mut runtimes = admission
        .full_inventory_observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let runtime = runtimes.next()?;
    if runtimes.next().is_some()
        || runtime.applied_desired.as_ref()
            != Some(&cats_api::runtime_reconciliation::AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            })
    {
        return None;
    }
    Some(runtime)
}

fn session_binding_from_agent(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn observed_volume_identity_matches(
    observed: &cats_api::runtime_reconciliation::ObservedVolume,
    intent: &VolumeIntent,
) -> bool {
    observed.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&intent.disk_id)
        && observed.volume_id == intent.volume_id
        && matches!(
            (observed.disk_kind, intent.disk_kind),
            (ObservedDiskKind::Root, DiskKind::Root)
                | (ObservedDiskKind::Persistent, DiskKind::Persistent)
        )
        && observed.size_bytes == Some(intent.size_bytes)
        && observed.durability == Some(intent.durability)
}

fn residue_may_name_volume(residue: &NodeResidue, volume_id: &Id) -> bool {
    match residue {
        NodeResidue::Process {
            role_hint:
                Some(ProcessRole::Blockd {
                    volume_id: current, ..
                }),
            ..
        }
        | NodeResidue::ControlSocket {
            role_hint:
                Some(ProcessRole::Blockd {
                    volume_id: current, ..
                }),
            ..
        } => current == volume_id,
        NodeResidue::KernelNbd { volume_id_hint, .. }
        | NodeResidue::VhostUserBlk { volume_id_hint, .. }
        | NodeResidue::DataDirectory { volume_id_hint, .. }
        | NodeResidue::Mount { volume_id_hint, .. } => volume_id_hint
            .as_ref()
            .is_none_or(|current| current == volume_id),
        _ => false,
    }
}

fn acquire_origin_matches_intent(origin: &AcquireOrigin, acquire: &VolumeAcquire) -> bool {
    matches!(
        (origin, acquire),
        (
            AcquireOrigin::Normal {
                transition_id: left
            },
            VolumeAcquire::Normal {
                transition_id: right,
                ..
            }
        ) if left == right
    ) || matches!(
        (origin, acquire),
        (
            AcquireOrigin::Takeover {
                authorization_id: left
            },
            VolumeAcquire::Takeover {
                authorization_id: right
            }
        ) if left == right
    )
}

pub(super) fn release_disposition_matches_current(
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
) -> bool {
    matches!(
        (&intent.disk_kind, &intent.disposition, desired.target),
        (
            DiskKind::Root,
            VolumeDisposition::DeleteDisposableRoot { .. },
            RuntimeTarget::Deleted,
        ) | (
            DiskKind::Persistent,
            VolumeDisposition::Retain,
            RuntimeTarget::Cold,
        ) | (
            DiskKind::Persistent,
            VolumeDisposition::DetachRetained,
            RuntimeTarget::Deleted,
        ) | (
            DiskKind::Root,
            VolumeDisposition::Retain,
            RuntimeTarget::Cold
        )
    )
}

fn takeover_payload_matches_desired(
    payload: &cats_storage::authority::VolumeTakeoverAuthorization,
    authenticated_node_id: &Id,
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
) -> bool {
    payload.authorized_node_id == *authenticated_node_id
        && payload.volume_id == intent.volume_id
        && payload.new_attachment_id == intent.attachment_id
        && payload.desired_revision == desired.desired_revision
        && payload.new_placement_epoch == desired.placement.placement_epoch
        && desired.placement.node_id == *authenticated_node_id
}

fn takeover_grant(volume: &VolumeRecord, result: TakeoverResult) -> VolumeLeaseGrant {
    VolumeLeaseGrant {
        volume_id: result.volume_id,
        attachment_id: result.attachment_id,
        attachment_epoch: result.resulting_epoch,
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        head: result.resulting_head,
        lease_expires_at: result.lease_expires_at,
        acquire_origin: AcquireOrigin::Takeover {
            authorization_id: result.authorization_id,
        },
    }
}

fn volume_authority_error<T>(
    volume_id: &Id,
    error: AuthorityError,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<T>> {
    let reason = match error {
        AuthorityError::OtherWriter => RuntimeVolumeAuthorityRejection::OtherWriter,
        AuthorityError::Fenced => RuntimeVolumeAuthorityRejection::Fenced,
        AuthorityError::StaleTransition => RuntimeVolumeAuthorityRejection::StaleTransition,
        AuthorityError::InvalidLeaseDuration => {
            RuntimeVolumeAuthorityRejection::InvalidLeaseDuration
        }
        AuthorityError::EpochExhausted => RuntimeVolumeAuthorityRejection::EpochExhausted,
        AuthorityError::AdminBusy => RuntimeVolumeAuthorityRejection::AdminBusy,
        error => return Err(error.into()),
    };
    Ok(VolumeTransitionStoreOutcome::Rejected(
        VolumeTransitionStoreRejection::VolumeAuthorityRejected {
            volume_id: volume_id.clone(),
            reason,
        },
    ))
}

fn disposable_authority_error<T>(
    authorization_id: &Id,
    error: AuthorityError,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<T>> {
    takeover_authority_error(authorization_id, error)
}

fn disposable_event_id(
    basis: &cats_storage::authority::DisposableDeleteIsolationBasis,
) -> Option<&Id> {
    match basis {
        cats_storage::authority::DisposableDeleteIsolationBasis::RuntimeStopped { .. } => None,
        cats_storage::authority::DisposableDeleteIsolationBasis::HostFenceEvent { event_id } => {
            Some(event_id)
        }
    }
}

fn lock_takeover_mutation_context<'transaction, 'connection>(
    prefix: AuthenticatedMutationPrefix<'transaction, 'connection>,
    request: &RuntimeTakeoverConsumeRequest,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<
    VolumeTransitionStoreOutcome<LockedTakeoverMutation<'transaction, 'connection>>,
> {
    let AuthenticatedMutationPrefix {
        transaction,
        authenticated,
    } = prefix;
    let node_id = authenticated.node_id;
    let db_now = authenticated.db_now;

    let admission = match lock_volume_mutation_admission_in(
        transaction,
        &node_id,
        active_guest_config_digest,
        db_now,
    )? {
        Ok(admission) => admission,
        Err(VolumeMutationAdmissionRejection::Contract(error)) => {
            return Ok(contract_rejected(error));
        }
        Err(VolumeMutationAdmissionRejection::InventorySessionReplaced) => {
            return Ok(precondition_rejected(
                request.cat_id.clone(),
                RuntimeVolumeTransitionPreconditionProblem::InventorySessionReplaced,
            ));
        }
        Err(VolumeMutationAdmissionRejection::InventoryStale) => {
            return Ok(precondition_rejected(
                request.cat_id.clone(),
                RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
            ));
        }
    };

    let Some(desired) = admission
        .assigned_desired_specs
        .iter()
        .find(|desired| desired.cat_id == request.cat_id)
        .cloned()
    else {
        return Ok(volume_intent_rejected(request));
    };
    if let Some(error) = desired_binding_error(&desired, request) {
        return Ok(contract_rejected(error));
    }
    if desired.target == RuntimeTarget::Deleted {
        return Ok(volume_intent_rejected(request));
    }
    let Some(intent) = takeover_intent(&desired, &request.authorization_id)?.cloned() else {
        return Ok(volume_intent_rejected(request));
    };

    // This is the only pre-lock routing read. Its predicate is bounded by the
    // authenticated Node and the exact current Desired intent, so an arbitrary
    // authorization ID cannot make this transaction decode or lock another
    // Node's event/authorization/volume graph.
    let Some(event_id) = takeover_authorization_route_for_intent(
        transaction,
        &request.authorization_id,
        &node_id,
        &intent.volume_id,
        desired.desired_revision,
        desired.placement.placement_epoch,
    )?
    else {
        if takeover_authorization_is_owned_by_other_node(
            transaction,
            &request.authorization_id,
            &node_id,
        )? {
            return Ok(authorization_rejected(
                request.authorization_id.clone(),
                RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            ));
        }
        return Err(AuthorityError::BackendUnknown.into());
    };

    // Canonical protected suffix: HostFenceEvent -> AuthorizationRecord ->
    // VolumeRecord -> DiskRecord/current Desired.  The Desired was read above
    // only as a NodeIdentity-protected routing fact and is locked/revalidated
    // here after Volume as required by the global DAG.
    let event =
        load_event_for_update(transaction, &event_id)?.ok_or(AuthorityError::BackendUnknown)?;
    let authorization = load_takeover_authorization_for_intent_update(
        transaction,
        &request.authorization_id,
        &node_id,
        &intent.volume_id,
        desired.desired_revision,
        desired.placement.placement_epoch,
    )?
    .ok_or(AuthorityError::BackendUnknown)?;
    let VolumeAuthorization::Takeover(payload) = &authorization.authorization else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if payload.host_fence_event_id != event.event_id {
        return Err(AuthorityError::BackendUnknown.into());
    }
    if !takeover_payload_matches_current_intent(payload, &node_id, &desired, &intent, request) {
        return Err(AuthorityError::BackendUnknown.into());
    }

    let stored_volume = load_stored_volume_for_update(transaction, &intent.volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
    let volume = stored_volume.record;
    let owner_binding = stored_volume
        .owner_binding
        .ok_or(AuthorityError::BackendUnknown)?;
    if matches!(authorization.state, AuthorizationState::Unconsumed)
        && owner_binding.owner_node_id != event.node_id
    {
        return Ok(authorization_rejected(
            request.authorization_id.clone(),
            RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
        ));
    }
    let disk = load_disk_by_id_for_update(transaction, &intent.disk_id)?;
    let locked_desired = load_desired_for_update(transaction, &request.cat_id)?;
    let (Some(disk), Some(locked_desired)) = (disk, locked_desired) else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if locked_desired != desired {
        return Err(AuthorityError::BackendUnknown.into());
    }
    let Some(locked_intent) = takeover_intent(&locked_desired, &request.authorization_id)?.cloned()
    else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    if locked_intent != intent || !disk_and_volume_match_intent(&disk, &volume, &desired, &intent) {
        return Err(AuthorityError::BackendUnknown.into());
    }

    Ok(VolumeTransitionStoreOutcome::Accepted(
        LockedTakeoverMutation {
            transaction,
            db_now,
            event,
            authorization,
            volume,
            owner_binding,
        },
    ))
}

fn consume_locked_takeover(
    locked: LockedTakeoverMutation<'_, '_>,
    authorization_id: &Id,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<TakeoverResult>> {
    let LockedTakeoverMutation {
        transaction,
        db_now,
        event,
        authorization,
        volume,
        owner_binding,
    } = locked;
    match replay_consumed_takeover(&authorization, authorization_id) {
        Ok(Some(result)) => {
            let VolumeAuthorization::Takeover(payload) = &authorization.authorization else {
                return Err(AuthorityError::BackendUnknown.into());
            };
            if owner_binding.owner_node_id != payload.authorized_node_id {
                return Err(AuthorityError::BackendUnknown.into());
            }
            return Ok(VolumeTransitionStoreOutcome::Accepted(result));
        }
        Ok(None) => {}
        Err(error) => return takeover_authority_error(authorization_id, error),
    }
    let VolumeAuthorization::Takeover(payload) = &authorization.authorization else {
        return Err(AuthorityError::BackendUnknown.into());
    };
    let owner_node_id = payload.authorized_node_id.clone();
    let (updated_volume, updated_authorization, result) =
        match consume_takeover(&volume, &event, &authorization, authorization_id, db_now) {
            Ok(result) => result,
            Err(error) => return takeover_authority_error(authorization_id, error),
        };
    let owner_binding = VolumeOwnerBinding {
        volume_id: updated_volume.volume_id.clone(),
        owner_node_id,
        attachment_id: result.attachment_id.clone(),
        attachment_epoch: result.resulting_epoch,
    };
    update_volume_owner(transaction, &updated_volume, Some(&owner_binding))?;
    update_authorization(transaction, &authorization, &updated_authorization)?;
    Ok(VolumeTransitionStoreOutcome::Accepted(result))
}

fn takeover_authority_error<T>(
    authorization_id: &Id,
    error: AuthorityError,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<T>> {
    let reason = match error {
        AuthorityError::InvalidAuthorization => {
            RuntimeVolumeAuthorizationRejection::InvalidAuthorization
        }
        AuthorityError::InvalidLeaseDuration => {
            RuntimeVolumeAuthorizationRejection::InvalidLeaseDuration
        }
        AuthorityError::SnapshotInUse => RuntimeVolumeAuthorizationRejection::SnapshotInUse,
        AuthorityError::EpochExhausted => RuntimeVolumeAuthorizationRejection::EpochExhausted,
        error => return Err(error.into()),
    };
    Ok(authorization_rejected(authorization_id.clone(), reason))
}

fn desired_binding_error(
    desired: &DesiredRuntimeSpec,
    request: &RuntimeTakeoverConsumeRequest,
) -> Option<ContractError> {
    desired_binding_error_for_context(
        desired,
        request.desired_revision,
        &request.spec_digest,
        &request.placement,
    )
}

fn desired_binding_error_for_context(
    desired: &DesiredRuntimeSpec,
    presented_revision: Revision,
    presented_digest: &Sha256Digest,
    presented_placement: &AssignedPlacement,
) -> Option<ContractError> {
    if presented_revision != desired.desired_revision {
        return Some(if presented_revision < desired.desired_revision {
            contract(
                ContractErrorDetail::StaleRevision {
                    cat_id: desired.cat_id.clone(),
                    presented_revision,
                    current_revision: desired.desired_revision,
                },
                "runtime Desired revision is stale",
            )
        } else {
            contract(
                ContractErrorDetail::WrongRevision {
                    cat_id: desired.cat_id.clone(),
                    expected_revision: desired.desired_revision,
                    presented_revision,
                },
                "runtime Desired revision is not current",
            )
        });
    }
    if presented_digest != &desired.spec_digest {
        return Some(contract(
            ContractErrorDetail::RevisionDigestConflict {
                cat_id: desired.cat_id.clone(),
                desired_revision: desired.desired_revision,
                expected_digest: desired.spec_digest.clone(),
                presented_digest: presented_digest.clone(),
            },
            "runtime Desired digest conflicts with the current revision",
        ));
    }
    (presented_placement != &desired.placement).then(|| {
        contract(
            ContractErrorDetail::WrongPlacement {
                cat_id: desired.cat_id.clone(),
                desired_revision: desired.desired_revision,
                expected: desired.placement.clone(),
                presented: presented_placement.clone(),
            },
            "runtime placement is not current",
        )
    })
}

fn takeover_intent<'a>(
    desired: &'a DesiredRuntimeSpec,
    authorization_id: &Id,
) -> AuthorityTxResult<Option<&'a VolumeIntent>> {
    let mut matches = desired.volumes.iter().filter(|intent| {
        matches!(
            &intent.acquire,
            VolumeAcquire::Takeover { authorization_id: current }
                if current == authorization_id
        )
    });
    let first = matches.next();
    if matches.next().is_some() {
        return Err(AuthorityError::BackendUnknown.into());
    }
    Ok(first)
}

fn takeover_payload_matches_current_intent(
    payload: &cats_storage::authority::VolumeTakeoverAuthorization,
    authenticated_node_id: &Id,
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
    request: &RuntimeTakeoverConsumeRequest,
) -> bool {
    payload.authorization_id == request.authorization_id
        && payload.authorized_node_id == *authenticated_node_id
        && payload.volume_id == intent.volume_id
        && payload.new_attachment_id == intent.attachment_id
        && payload.desired_revision == desired.desired_revision
        && payload.new_placement_epoch == desired.placement.placement_epoch
        && desired.placement.node_id == *authenticated_node_id
}

fn disk_and_volume_match_intent(
    disk: &DiskRecord,
    volume: &VolumeRecord,
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
) -> bool {
    matches!(disk.admin_state, DiskAdminState::Active)
        && disk_and_volume_identity_matches_intent(disk, volume, desired, intent)
}

fn disk_and_volume_identity_matches_intent(
    disk: &DiskRecord,
    volume: &VolumeRecord,
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
) -> bool {
    disk_and_volume_common_identity_matches_intent(disk, volume, desired, intent)
        && match &disk.role {
            DiskRole::Root { .. } => true,
            DiskRole::Persistent { initialization } => persistent_initialization_matches_mount(
                initialization,
                &volume.head,
                intent.mount.as_ref(),
            ),
        }
}

fn disk_and_volume_common_identity_matches_intent(
    disk: &DiskRecord,
    volume: &VolumeRecord,
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
) -> bool {
    let role_matches = matches!(
        (&intent.disk_kind, &disk.role),
        (DiskKind::Root, DiskRole::Root { cat_id }) if cat_id == &desired.cat_id
    ) || matches!(
        (&intent.disk_kind, &disk.role),
        (DiskKind::Persistent, DiskRole::Persistent { .. })
    );
    role_matches
        && disk.disk_id == intent.disk_id
        && disk.workspace_id == desired.workspace_id
        && disk.volume_id == intent.volume_id
        && disk.size_bytes == intent.size_bytes
        && disk.durability == intent.durability
        && volume.volume_id == intent.volume_id
        && volume.size_bytes == intent.size_bytes
        && volume.durability == intent.durability
}

fn precondition_rejected<T>(
    cat_id: Id,
    problem: RuntimeVolumeTransitionPreconditionProblem,
) -> VolumeTransitionStoreOutcome<T> {
    VolumeTransitionStoreOutcome::Rejected(
        VolumeTransitionStoreRejection::TransitionPreconditionFailed { cat_id, problem },
    )
}

fn volume_intent_rejected<T>(
    request: &RuntimeTakeoverConsumeRequest,
) -> VolumeTransitionStoreOutcome<T> {
    precondition_rejected(
        request.cat_id.clone(),
        RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
    )
}

fn volume_intent_rejected_for_cat<T>(cat_id: &Id) -> VolumeTransitionStoreOutcome<T> {
    precondition_rejected(
        cat_id.clone(),
        RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
    )
}

fn authorization_rejected<T>(
    authorization_id: Id,
    reason: RuntimeVolumeAuthorizationRejection,
) -> VolumeTransitionStoreOutcome<T> {
    VolumeTransitionStoreOutcome::Rejected(
        VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
            authorization_id,
            reason,
        },
    )
}

pub(super) fn authenticate_evidence_context_in<'transaction, 'connection>(
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: &AuthenticatedNodeCredential,
    presented_session: &SessionBinding,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<
    VolumeTransitionStoreOutcome<EvidenceTransactionContext<'transaction, 'connection>>,
> {
    let Some(identity) =
        load_identity_by_credential_for_share(transaction, authenticated.credential_id())?
    else {
        return Ok(identity_rejected());
    };
    let authenticated = match authenticate_locked_identity(
        transaction,
        authenticated,
        identity,
        presented_session,
        active_guest_config_digest,
        load_current_session_for_share,
    )? {
        VolumeTransitionStoreOutcome::Accepted(authenticated) => authenticated,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
        }
    };
    Ok(VolumeTransitionStoreOutcome::Accepted(
        EvidenceTransactionContext {
            transaction,
            authenticated,
        },
    ))
}

fn authenticate_mutation_context_in<'transaction, 'connection>(
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: &AuthenticatedNodeCredential,
    presented_session: &SessionBinding,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<
    VolumeTransitionStoreOutcome<AuthenticatedMutationPrefix<'transaction, 'connection>>,
> {
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated.credential_id())?
    else {
        return Ok(identity_rejected());
    };
    let authenticated = match authenticate_locked_identity(
        transaction,
        authenticated,
        identity,
        presented_session,
        active_guest_config_digest,
        load_current_session_for_update,
    )? {
        VolumeTransitionStoreOutcome::Accepted(authenticated) => authenticated,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
        }
    };
    Ok(VolumeTransitionStoreOutcome::Accepted(
        AuthenticatedMutationPrefix {
            transaction,
            authenticated,
        },
    ))
}

fn authenticate_locked_identity(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    identity: NodeIdentity,
    presented_session: &SessionBinding,
    active_guest_config_digest: &Sha256Digest,
    load_session: fn(&mut Transaction<'_>, &Id) -> AuthorityTxResult<Option<AgentSession>>,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<AuthenticatedNodeTransaction>> {
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || !matches!(
            identity.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
    {
        return Ok(identity_rejected());
    }
    if lock_exact_credential_lineage(transaction, &identity)?
        != Some(CredentialLineageState::Active)
    {
        return Ok(identity_rejected());
    }

    let Some(session) = load_session(transaction, &identity.node_id)? else {
        return Ok(contract_rejected(contract(
            ContractErrorDetail::MissingAgentSession {
                node_id: identity.node_id,
            },
            "authenticated Node has no current AgentSession",
        )));
    };
    if let Some(error) = session_error(&session, presented_session) {
        return Ok(contract_rejected(error));
    }
    if session.guest_config_digest != *active_guest_config_digest {
        return Ok(contract_rejected(contract(
            ContractErrorDetail::GuestConfigMismatch {
                node_id: session.node_id,
                expected_guest_config_digest: active_guest_config_digest.clone(),
                presented_guest_config_digest: session.guest_config_digest,
            },
            "AgentSession Guest runtime profile does not match the active release",
        )));
    }
    let db_now = database_now(transaction)?;
    if db_now >= session.lease_deadline_unix_ms {
        return Ok(contract_rejected(contract(
            ContractErrorDetail::SessionExpired {
                node_id: session.node_id,
                agent_session_epoch: session.agent_session_epoch,
                lease_deadline_unix_ms: session.lease_deadline_unix_ms,
                server_time_unix_ms: db_now,
            },
            "AgentSession lease has expired",
        )));
    }
    Ok(VolumeTransitionStoreOutcome::Accepted(
        AuthenticatedNodeTransaction {
            node_id: identity.node_id,
            db_now,
        },
    ))
}

fn session_error(session: &AgentSession, presented: &SessionBinding) -> Option<ContractError> {
    let expected = SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    };
    if presented.agent_session_epoch < expected.agent_session_epoch {
        return Some(contract(
            ContractErrorDetail::StaleSession {
                node_id: expected.node_id,
                presented_agent_session_epoch: presented.agent_session_epoch,
                current_agent_session_epoch: expected.agent_session_epoch,
            },
            "AgentSession is stale",
        ));
    }
    (presented != &expected).then(|| {
        contract(
            ContractErrorDetail::WrongSession {
                expected,
                presented: presented.clone(),
            },
            "request is not bound to the current AgentSession",
        )
    })
}

fn identity_rejected<T>() -> VolumeTransitionStoreOutcome<T> {
    VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::IdentityNotEligible)
}

fn contract_rejected<T>(error: ContractError) -> VolumeTransitionStoreOutcome<T> {
    VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::Contract(error))
}

fn contract(detail: ContractErrorDetail, message: impl Into<String>) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(detail),
        message: message.into(),
    }
}

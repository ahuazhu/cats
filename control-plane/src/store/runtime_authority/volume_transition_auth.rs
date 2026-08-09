//! Same-transaction authentication prefix for A22 volume authority access.
//!
//! A proof verifier can only construct [`AuthenticatedNodeCredential`].  It
//! cannot choose a Node id or manufacture one of the private transaction
//! contexts below.  Evidence and mutation entrypoints therefore have to take
//! the exact NodeIdentity, active credential lineage and current AgentSession
//! locks before they can reach an authorization or Volume row.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_reconciliation::{
    encode_runtime_volume_transition_evidence_request, AgentSession, AssignedPlacement,
    ContractError, ContractErrorDetail, ContractVersion, CredentialBinding, DesiredRuntimeSpec,
    DiskKind, Id, NodeIdentity, NodeIdentityState, Revision, RuntimeTarget,
    RuntimeVolumeAuthorizationRejection, RuntimeVolumeTransitionEvidenceRequest,
    RuntimeVolumeTransitionPreconditionProblem, SessionBinding, Sha256Digest, UnixMillis,
    VolumeAcquire, VolumeIntent,
};
use cats_storage::authority::{
    consume_takeover, replay_consumed_takeover, AuthorityError, AuthorizationRecord,
    HostFenceEvent, TakeoverResult, VolumeAuthorization, VolumeRecord,
};
use postgres::Transaction;

use super::product::{DiskAdminState, DiskRecord, DiskRole};
use super::product_rows::{load_desired_for_update, load_disk_by_id_for_update};
use super::rows::{
    database_now, load_event_for_update, load_takeover_authorization_for_intent_update,
    load_volume_for_update, takeover_authorization_is_owned_by_other_node,
    takeover_authorization_route_for_intent, update_authorization, update_volume,
};
use super::runtime_spine::{lock_volume_mutation_admission_in, VolumeMutationAdmissionRejection};
use super::volume_transition_evidence::{
    load_volume_transition_evidence_in, VolumeTransitionEvidenceLoad,
};
use crate::store::agent_sessions::{
    load_current_session_for_share, load_current_session_for_update,
    load_identity_by_credential_for_share, load_identity_by_credential_for_update,
    lock_exact_credential_lineage, CredentialLineageState,
};
use crate::store::transaction::AuthorityTxResult;
use crate::store::{Result, Store};

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

struct LockedTakeoverMutation<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    db_now: UnixMillis,
    event: HostFenceEvent,
    authorization: AuthorizationRecord,
    volume: VolumeRecord,
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

    let volume = load_volume_for_update(transaction, &intent.volume_id)?
        .ok_or(AuthorityError::BackendUnknown)?;
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
    } = locked;
    match replay_consumed_takeover(&authorization, authorization_id) {
        Ok(Some(result)) => return Ok(VolumeTransitionStoreOutcome::Accepted(result)),
        Ok(None) => {}
        Err(error) => return takeover_authority_error(authorization_id, error),
    }
    let (updated_volume, updated_authorization, result) =
        match consume_takeover(&volume, &event, &authorization, authorization_id, db_now) {
            Ok(result) => result,
            Err(error) => return takeover_authority_error(authorization_id, error),
        };
    update_volume(transaction, &updated_volume)?;
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
    if request.desired_revision != desired.desired_revision {
        return Some(if request.desired_revision < desired.desired_revision {
            contract(
                ContractErrorDetail::StaleRevision {
                    cat_id: desired.cat_id.clone(),
                    presented_revision: request.desired_revision,
                    current_revision: desired.desired_revision,
                },
                "runtime Desired revision is stale",
            )
        } else {
            contract(
                ContractErrorDetail::WrongRevision {
                    cat_id: desired.cat_id.clone(),
                    expected_revision: desired.desired_revision,
                    presented_revision: request.desired_revision,
                },
                "runtime Desired revision is not current",
            )
        });
    }
    if request.spec_digest != desired.spec_digest {
        return Some(contract(
            ContractErrorDetail::RevisionDigestConflict {
                cat_id: desired.cat_id.clone(),
                desired_revision: desired.desired_revision,
                expected_digest: desired.spec_digest.clone(),
                presented_digest: request.spec_digest.clone(),
            },
            "runtime Desired digest conflicts with the current revision",
        ));
    }
    (request.placement != desired.placement).then(|| {
        contract(
            ContractErrorDetail::WrongPlacement {
                cat_id: desired.cat_id.clone(),
                desired_revision: desired.desired_revision,
                expected: desired.placement.clone(),
                presented: request.placement.clone(),
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
    let role_matches = matches!(
        (&intent.disk_kind, &disk.role),
        (DiskKind::Root, DiskRole::Root { cat_id }) if cat_id == &desired.cat_id
    ) || matches!(
        (&intent.disk_kind, &disk.role),
        (DiskKind::Persistent, DiskRole::Persistent { .. })
    );
    matches!(disk.admin_state, DiskAdminState::Active)
        && role_matches
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

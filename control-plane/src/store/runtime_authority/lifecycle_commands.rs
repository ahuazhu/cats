//! PostgreSQL authority for atomic per-Cat lifecycle commands.
//!
//! This module is intentionally command/result only.  Node observations are
//! neither read nor written here and therefore cannot settle an Operation.

use std::collections::BTreeMap;

use cats_api::agent_registration::AuthenticatedNodeCredential;
#[cfg(test)]
use cats_api::runtime_lifecycle::validate_lifecycle_command_envelope;
use cats_api::runtime_lifecycle::{
    decode_immutable_runtime_config, decode_lifecycle_command_envelope,
    decode_lifecycle_command_response, encode_lifecycle_command_envelope,
    encode_lifecycle_command_response, lifecycle_terminal_result_digest,
    validate_lifecycle_command_poll_for_session,
    validate_lifecycle_command_response_for_runtime_config, validate_lifecycle_operation,
    validate_lifecycle_result_commit_for_command, validate_lifecycle_result_commit_request,
    validate_lifecycle_result_stored_ack_for_response, validate_lifecycle_successor,
    validate_lifecycle_successor_with_predecessor_command, ColdVolumeDisposition,
    CompletedVolumeDisposition, DiskRole, EffectiveRuntimeReady, ImmutableRuntimeConfig,
    LifecycleCommand, LifecycleCommandBatch, LifecycleCommandEnvelope, LifecycleCommandKind,
    LifecycleCommandPollRequest, LifecycleCommandResponse, LifecycleOperation,
    LifecycleOperationState, LifecyclePredecessor, LifecycleResultCommitRequest,
    LifecycleResultStoredAck, LifecycleTerminalResult, NodeResult, PlacementIdentity,
    RequestedVolumeDisposition, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig,
    RuntimeVolumeGuestBinding, StartSource, StartVolumeAuthority, TerminalResultKind,
    VolumeTerminalReceipt,
};
use cats_api::runtime_reconciliation::{
    AgentSession, ContractVersion, CredentialBinding, Epoch, Id, LastVolumeTransition,
    NodeIdentityState, RandomId128, SessionBinding, Sha256Digest, UnixMillis, VolumeAdminState,
    VolumeAuthorization, VolumeRecord, VolumeTransitionSource,
};
use cats_storage::lifecycle_volume::{
    command_cold_already_unowned_receipt_digest, command_delete_already_unowned_receipt_digest,
    command_delete_already_unowned_receipt_digest_from_delete_completion,
    command_delete_completion_receipt_digest,
    command_disposable_authorization_consumed_receipt_digest_from_delete_completion,
    command_normal_release_receipt_digest,
    command_normal_release_receipt_digest_from_delete_completion,
    command_start_volume_grant_receipt_digest_for_current_owner,
    persistent_delete_dispositions_digest, CommandBoundDisposableRootAuthorization,
    CommandRootDeleteAuthorityReceipt, CommandVolumeDispositionReceipt,
    DefaultRootDiscardDisposition, DeleteCommandVolumeSet, LifecycleVolumeCommandScope,
    LifecycleVolumeIdentity, LifecycleVolumeTarget,
};
use postgres::{Row, Transaction};

use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_credential_for_update,
    lock_exact_credential_lineage, renew_current_session_deadline, CredentialLineageState,
};
use crate::store::runtime_authority::pg_codec::PgBigInt;
use crate::store::runtime_authority::product::{
    DiskAdminState as ProductDiskAdminState, DiskRecord, DiskRole as ProductDiskRole,
    PersistentDiskInitialization,
};
use crate::store::runtime_authority::product_rows::load_disk_by_id_for_update;
use crate::store::runtime_authority::route_epoch_engine::LifecycleAdmissionCloseOutcome;
use crate::store::runtime_authority::route_operations::invalidate_routes_for_lifecycle_close_in;
use crate::store::runtime_authority::rows::{
    database_now, load_authorization_for_update, load_command_already_unowned_receipt_for_update,
    load_command_delete_completion_receipt_for_update,
    load_command_disposable_authorization_consumed_receipt_for_update,
    load_command_normal_release_receipt_for_update, load_delete_completion_for_update,
    load_latest_command_start_volume_grant_receipt_for_update, load_stored_volume_for_update,
    StoredCommandAlreadyUnownedReceipt, StoredCommandNormalReleaseReceipt, StoredVolume,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{internal, Result, Store};

const RUNTIME_OPERATION_COLUMNS: &str = "
    operation_id, workspace_id, cat_id, node_id, placement_epoch,
    command_kind, canonical_request_bytes, canonical_request_sha256,
    runtime_config_id, runtime_config_sha256,
    expected_predecessor_operation_id, predecessor_kind,
    expected_predecessor_result_kind, expected_predecessor_result_sha256,
    state, terminal_source, terminal_result_kind, canonical_result_bytes,
    canonical_result_sha256, created_at_unix_ms, terminal_at_unix_ms";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleCommandAdmission {
    Admitted(LifecycleOperation),
    ExactReplay(LifecycleOperation),
    Rejected(LifecycleAdmissionRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleAdmissionRejection {
    InvalidContract,
    CatNotFound,
    WrongWorkspace,
    CatDeleted,
    LifecycleOperationInProgress {
        operation_id: Id,
        command_kind: LifecycleCommandKind,
    },
    OperationIdentityConflict {
        operation_id: Id,
    },
    StaleOperation {
        current_operation_id: Option<Id>,
    },
    IllegalSuccessor {
        predecessor_kind: Option<TerminalResultKind>,
        command_kind: LifecycleCommandKind,
    },
    /// HostFence recovery stays reserved until the #263 producer and exact
    /// event/authorization transaction are composed.  Merely naming an event
    /// or authorization in a request is not sufficient authority.
    HostFenceRecoveryUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleSessionRejection {
    IdentityNotEligible,
    MissingAgentSession {
        node_id: Id,
    },
    StaleSession {
        node_id: Id,
        presented_agent_session_epoch: Epoch,
        current_agent_session_epoch: Epoch,
    },
    WrongSession {
        expected: SessionBinding,
        presented: SessionBinding,
    },
    SessionExpired {
        node_id: Id,
        agent_session_epoch: Epoch,
        lease_deadline_unix_ms: UnixMillis,
        server_time_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleCommandPollOutcome {
    Batch(LifecycleCommandBatch),
    Rejected(LifecyclePollRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecyclePollRejection {
    InvalidContract,
    Session(LifecycleSessionRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleResultCommitOutcome {
    Stored {
        operation: LifecycleOperation,
        acknowledgement: LifecycleResultStoredAck,
    },
    ExactReplay {
        operation: LifecycleOperation,
        acknowledgement: LifecycleResultStoredAck,
    },
    Rejected(LifecycleResultCommitRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleResultCommitRejection {
    InvalidContract,
    Session(LifecycleSessionRejection),
    OperationNotFound,
    OperationNotCurrent { current_operation_id: Option<Id> },
    ConflictingTerminalResult { operation_id: Id },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LifecycleStableState {
    Running,
    Suspended,
    Warm,
    Cold,
}

impl LifecycleStableState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Warm => "warm",
            Self::Cold => "cold",
        }
    }

    fn parse(value: &str) -> AuthorityTxResult<Self> {
        match value {
            "running" => Ok(Self::Running),
            "suspended" => Ok(Self::Suspended),
            "warm" => Ok(Self::Warm),
            "cold" => Ok(Self::Cold),
            _ => Err(corrupt("stored Cat stable state is outside the closed set")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatLifecycleProjection {
    workspace_id: Id,
    cat_creation_id: Id,
    lifecycle_head_operation_id: Option<Id>,
    stable_state: Option<LifecycleStableState>,
    effective_runtime_ready_operation_id: Option<Id>,
    runtime_incarnation: Option<RandomId128>,
    current_runtime_config_id: Id,
    current_runtime_config_digest: Sha256Digest,
    deleted_at: Option<UnixMillis>,
}

/// Exact Cat/head/config context used by product mutation planning while the
/// caller retains the Cat-row lock.  Returning the decoded immutable
/// Operation avoids a second, weaker predecessor projection in API code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LifecycleAdmissionContext {
    pub(super) cat_creation_id: Id,
    pub(super) lifecycle_head: Option<LifecycleOperation>,
    pub(super) unresolved_operation: Option<LifecycleOperation>,
    pub(super) stable_state: Option<LifecycleStableState>,
    pub(super) effective_runtime_ready_operation_id: Option<Id>,
    pub(super) runtime_incarnation: Option<RandomId128>,
    pub(super) deleted_at: Option<UnixMillis>,
    pub(super) immutable_runtime_config: ImmutableRuntimeConfig,
}

/// Exact durable RuntimeReady authority retained across a non-destructive
/// `SuspendDeclined`. The source Operation contains the complete terminal
/// response; `evidence` is the closed projection consumed by Route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EffectiveRuntimeReadyAuthority {
    pub(super) evidence: EffectiveRuntimeReady,
    pub(super) source_operation: LifecycleOperation,
}

/// Observation-free lifecycle input for Route admission and signing.
///
/// The locked variant serializes lifecycle acceptance with the Route
/// controller. The snapshot variant gives the signer the same exact decoded
/// authority without manufacturing state from telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LifecycleRouteAuthority {
    pub(super) workspace_id: Id,
    pub(super) cat_id: Id,
    pub(super) lifecycle_head: Option<LifecycleOperation>,
    pub(super) effective_runtime_ready: Option<EffectiveRuntimeReadyAuthority>,
    pub(super) unresolved_operation: Option<LifecycleOperation>,
    pub(super) unresolved_leaves_running: bool,
    pub(super) stable_state: Option<LifecycleStableState>,
    pub(super) current_placement: Option<PlacementIdentity>,
    pub(super) current_runtime_config_id: Id,
    pub(super) current_runtime_config_digest: Sha256Digest,
    pub(super) deleted_at: Option<UnixMillis>,
}

impl Store {
    /// Atomically admits one exact command after validating the Cat's current
    /// terminal chain head.  The Cat row is the cross-replica serialization
    /// point; the partial unique index is the second line of defence.
    #[cfg(test)]
    pub(crate) fn admit_lifecycle_command(
        &self,
        workspace_id: &Id,
        request: &LifecycleCommandEnvelope,
    ) -> Result<LifecycleCommandAdmission> {
        if validate_lifecycle_command_envelope(request).is_err()
            || request.workspace_id != *workspace_id
        {
            return Ok(LifecycleCommandAdmission::Rejected(
                LifecycleAdmissionRejection::InvalidContract,
            ));
        }
        let canonical_request = encode_lifecycle_command_envelope(request).map_err(corrupt_api)?;
        self.authority_transaction(|transaction| {
            admit_lifecycle_command_in(transaction, workspace_id, request, &canonical_request)
        })
    }

    /// Returns the current unresolved command set for the exact authenticated
    /// Node/session. Polling is a read of already-admitted intent and cannot
    /// create or advance an Operation.
    pub(crate) fn poll_lifecycle_commands(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        poll: &LifecycleCommandPollRequest,
    ) -> Result<LifecycleCommandPollOutcome> {
        if cats_api::runtime_lifecycle::validate_lifecycle_command_poll_request(poll).is_err() {
            return Ok(LifecycleCommandPollOutcome::Rejected(
                LifecyclePollRejection::InvalidContract,
            ));
        }
        self.authority_transaction(|transaction| {
            poll_lifecycle_commands_in(transaction, authenticated, poll)
        })
    }

    /// Commits one exact authenticated Node terminal result and the Cat
    /// product projection in the same PostgreSQL transaction.  No observation
    /// table is consulted.
    pub(crate) fn commit_lifecycle_result(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        commit: &LifecycleResultCommitRequest,
    ) -> Result<LifecycleResultCommitOutcome> {
        if validate_lifecycle_result_commit_request(commit).is_err() {
            return Ok(LifecycleResultCommitOutcome::Rejected(
                LifecycleResultCommitRejection::InvalidContract,
            ));
        }
        self.authority_transaction(|transaction| {
            commit_lifecycle_result_in(transaction, authenticated, commit)
        })
    }

    /// Reads one immutable Operation for product/API replay.  This read does
    /// not infer status from Node observations.
    pub(crate) fn lifecycle_operation(
        &self,
        workspace_id: &Id,
        operation_id: &Id,
    ) -> Result<Option<LifecycleOperation>> {
        self.authority_read_snapshot(|transaction| {
            let operation = load_operation_unlocked(transaction, operation_id)?;
            Ok(operation.filter(|operation| operation.workspace_id == *workspace_id))
        })
    }
}

/// Locks and returns the one exact context from which product code may build
/// a lifecycle command.  The caller may already hold the same Cat row after
/// reserving an API idempotency key; PostgreSQL treats the repeated row lock
/// in that transaction as idempotent.
pub(super) fn load_lifecycle_admission_context_in(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Option<LifecycleAdmissionContext>> {
    let Some(cat) = load_cat_for_update(transaction, cat_id)? else {
        return Ok(None);
    };
    if cat.workspace_id != *workspace_id {
        return Ok(None);
    }
    let lifecycle_head = match &cat.lifecycle_head_operation_id {
        Some(operation_id) => {
            let operation = load_operation_for_update(transaction, operation_id)?
                .ok_or_else(|| corrupt("Cat lifecycle head Operation is missing"))?;
            if operation.workspace_id != *workspace_id
                || operation.cat_id != *cat_id
                || !matches!(operation.state, LifecycleOperationState::Terminal { .. })
            {
                return Err(corrupt(
                    "Cat lifecycle head projection is not an exact terminal row",
                ));
            }
            Some(operation)
        }
        None => None,
    };
    let unresolved_operation = load_unresolved_for_cat(transaction, cat_id)?;
    if unresolved_operation.as_ref().is_some_and(|operation| {
        operation.workspace_id != *workspace_id || operation.cat_id != *cat_id
    }) {
        return Err(corrupt(
            "Cat unresolved Operation projection crosses identity",
        ));
    }
    let immutable_runtime_config = load_exact_runtime_config_for_update(
        transaction,
        workspace_id,
        cat_id,
        &cat.current_runtime_config_id,
        &cat.current_runtime_config_digest,
    )?
    .ok_or_else(|| corrupt("Cat is missing its immutable runtime config"))?;
    Ok(Some(LifecycleAdmissionContext {
        cat_creation_id: cat.cat_creation_id,
        lifecycle_head,
        unresolved_operation,
        stable_state: cat.stable_state,
        effective_runtime_ready_operation_id: cat.effective_runtime_ready_operation_id,
        runtime_incarnation: cat.runtime_incarnation,
        deleted_at: cat.deleted_at,
        immutable_runtime_config,
    }))
}

pub(super) fn load_lifecycle_route_authority_for_update_in(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Option<LifecycleRouteAuthority>> {
    let Some(cat) = load_cat_for_update(transaction, cat_id)? else {
        return Ok(None);
    };
    if cat.workspace_id != *workspace_id {
        return Ok(None);
    }
    let head = load_projected_head(transaction, workspace_id, cat_id, &cat, true)?;
    let unresolved = load_unresolved_for_cat(transaction, cat_id)?;
    build_lifecycle_route_authority(
        transaction,
        workspace_id,
        cat_id,
        cat,
        head,
        unresolved,
        true,
    )
    .map(Some)
}

pub(super) fn load_lifecycle_route_authority_snapshot_in(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Option<LifecycleRouteAuthority>> {
    let Some(cat) = load_cat_unlocked(transaction, cat_id)? else {
        return Ok(None);
    };
    if cat.workspace_id != *workspace_id {
        return Ok(None);
    }
    let head = load_projected_head(transaction, workspace_id, cat_id, &cat, false)?;
    let unresolved = load_unresolved_for_cat_unlocked(transaction, cat_id)?;
    build_lifecycle_route_authority(
        transaction,
        workspace_id,
        cat_id,
        cat,
        head,
        unresolved,
        false,
    )
    .map(Some)
}

fn load_projected_head(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    cat: &CatLifecycleProjection,
    for_update: bool,
) -> AuthorityTxResult<Option<LifecycleOperation>> {
    let Some(operation_id) = cat.lifecycle_head_operation_id.as_ref() else {
        return Ok(None);
    };
    let operation = if for_update {
        load_operation_for_update(transaction, operation_id)?
    } else {
        load_operation_unlocked(transaction, operation_id)?
    }
    .ok_or_else(|| corrupt("Cat lifecycle head Operation is missing"))?;
    if operation.workspace_id != *workspace_id
        || operation.cat_id != *cat_id
        || !matches!(operation.state, LifecycleOperationState::Terminal { .. })
    {
        return Err(corrupt(
            "Cat lifecycle head projection is not an exact terminal Operation",
        ));
    }
    Ok(Some(operation))
}

#[allow(clippy::too_many_arguments)]
fn build_lifecycle_route_authority(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    cat: CatLifecycleProjection,
    lifecycle_head: Option<LifecycleOperation>,
    unresolved_operation: Option<LifecycleOperation>,
    for_update: bool,
) -> AuthorityTxResult<LifecycleRouteAuthority> {
    if unresolved_operation.as_ref().is_some_and(|operation| {
        operation.workspace_id != *workspace_id
            || operation.cat_id != *cat_id
            || !matches!(operation.state, LifecycleOperationState::Unresolved)
    }) {
        return Err(corrupt(
            "Cat unresolved lifecycle projection crosses identity or is terminal",
        ));
    }

    let effective_runtime_ready = match (
        cat.stable_state,
        cat.effective_runtime_ready_operation_id.as_ref(),
        cat.runtime_incarnation.as_ref(),
    ) {
        (Some(LifecycleStableState::Running), Some(source_id), Some(incarnation)) => {
            let source_operation = if lifecycle_head
                .as_ref()
                .is_some_and(|head| head.operation_id == *source_id)
            {
                lifecycle_head
                    .as_ref()
                    .ok_or_else(|| corrupt("effective source head disappeared"))?
                    .clone()
            } else if for_update {
                load_operation_for_update(transaction, source_id)?
                    .ok_or_else(|| corrupt("effective RuntimeReady source is missing"))?
            } else {
                load_operation_unlocked(transaction, source_id)?
                    .ok_or_else(|| corrupt("effective RuntimeReady source is missing"))?
            };
            if source_operation.workspace_id != *workspace_id
                || source_operation.cat_id != *cat_id
                || source_operation.runtime_config_digest
                    != source_operation
                        .canonical_request
                        .runtime_config
                        .config_digest
            {
                return Err(corrupt(
                    "effective RuntimeReady source identity/config projection is invalid",
                ));
            }
            let LifecycleOperationState::Terminal { terminal, .. } = &source_operation.state else {
                return Err(corrupt("effective RuntimeReady source is unresolved"));
            };
            let LifecycleTerminalResult::NodeResult { response } = terminal.as_ref() else {
                return Err(corrupt("effective RuntimeReady source is HostLost"));
            };
            let NodeResult::RuntimeReady(ready) = &response.result else {
                return Err(corrupt(
                    "effective RuntimeReady source has a non-RuntimeReady result",
                ));
            };
            if ready.runtime_incarnation != *incarnation
                || ready.runtime_config_digest != source_operation.runtime_config_digest
            {
                return Err(corrupt(
                    "effective RuntimeReady source evidence disagrees with Cat projection",
                ));
            }
            let evidence = EffectiveRuntimeReady {
                source_lifecycle_operation_id: source_operation.operation_id.clone(),
                runtime_incarnation: ready.runtime_incarnation.clone(),
                runtime_config_digest: ready.runtime_config_digest.clone(),
                runtime_ready_receipt_digest: ready.execution_receipt_digest.clone(),
            };
            validate_effective_runtime_ready_head(&lifecycle_head, &evidence)?;
            Some(EffectiveRuntimeReadyAuthority {
                evidence,
                source_operation,
            })
        }
        (Some(LifecycleStableState::Suspended), None, Some(_))
        | (Some(LifecycleStableState::Warm | LifecycleStableState::Cold), None, None)
        | (None, None, None) => None,
        _ => {
            return Err(corrupt(
                "Cat stable/effective RuntimeReady/incarnation projection is invalid",
            ));
        }
    };

    if cat.deleted_at.is_some() && (cat.stable_state.is_some() || effective_runtime_ready.is_some())
    {
        return Err(corrupt("Deleted Cat retains serving lifecycle authority"));
    }
    let unresolved_leaves_running = unresolved_operation.as_ref().is_some_and(|operation| {
        matches!(
            operation.command_kind,
            LifecycleCommandKind::Suspend
                | LifecycleCommandKind::Warm
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        )
    });
    let current_placement = effective_runtime_ready
        .as_ref()
        .map(|ready| ready.source_operation.placement_identity.clone())
        .or_else(|| {
            lifecycle_head
                .as_ref()
                .map(|head| head.placement_identity.clone())
        });
    Ok(LifecycleRouteAuthority {
        workspace_id: workspace_id.clone(),
        cat_id: cat_id.clone(),
        lifecycle_head,
        effective_runtime_ready,
        unresolved_operation,
        unresolved_leaves_running,
        stable_state: cat.stable_state,
        current_placement,
        current_runtime_config_id: cat.current_runtime_config_id,
        current_runtime_config_digest: cat.current_runtime_config_digest,
        deleted_at: cat.deleted_at,
    })
}

fn validate_effective_runtime_ready_head(
    lifecycle_head: &Option<LifecycleOperation>,
    evidence: &EffectiveRuntimeReady,
) -> AuthorityTxResult<()> {
    let head = lifecycle_head
        .as_ref()
        .ok_or_else(|| corrupt("Running Cat has no lifecycle head"))?;
    let LifecycleOperationState::Terminal { terminal, .. } = &head.state else {
        return Err(corrupt("Running Cat lifecycle head is unresolved"));
    };
    let LifecycleTerminalResult::NodeResult { response } = terminal.as_ref() else {
        return Err(corrupt("Running Cat lifecycle head is HostLost"));
    };
    match &response.result {
        NodeResult::RuntimeReady(ready)
            if head.operation_id == evidence.source_lifecycle_operation_id
                && ready.runtime_incarnation == evidence.runtime_incarnation
                && ready.runtime_config_digest == evidence.runtime_config_digest
                && ready.execution_receipt_digest == evidence.runtime_ready_receipt_digest =>
        {
            Ok(())
        }
        NodeResult::SuspendDeclined(declined) if declined.effective_runtime_ready == *evidence => {
            Ok(())
        }
        _ => Err(corrupt(
            "Running Cat head does not retain its exact effective RuntimeReady",
        )),
    }
}

pub(super) fn admit_lifecycle_command_in(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    request: &LifecycleCommandEnvelope,
    canonical_request: &[u8],
) -> AuthorityTxResult<LifecycleCommandAdmission> {
    let encoded_request = match encode_lifecycle_command_envelope(request) {
        Ok(encoded) => encoded,
        Err(_) => {
            return Ok(LifecycleCommandAdmission::Rejected(
                LifecycleAdmissionRejection::InvalidContract,
            ));
        }
    };
    if request.workspace_id != *workspace_id || encoded_request != canonical_request {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::InvalidContract,
        ));
    }
    let Some(cat) = load_cat_for_update(transaction, &request.cat_id)? else {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::CatNotFound,
        ));
    };
    if cat.workspace_id != *workspace_id {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::WrongWorkspace,
        ));
    }
    if let Some(existing) = load_operation_for_update(transaction, &request.operation_id)? {
        if existing.workspace_id == *workspace_id && existing.canonical_request.as_ref() == request
        {
            return Ok(LifecycleCommandAdmission::ExactReplay(existing));
        }
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::OperationIdentityConflict {
                operation_id: request.operation_id.clone(),
            },
        ));
    }

    if cat.deleted_at.is_some() {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::CatDeleted,
        ));
    }

    if let Some(unresolved) = load_unresolved_for_cat(transaction, &request.cat_id)? {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::LifecycleOperationInProgress {
                operation_id: unresolved.operation_id,
                command_kind: unresolved.command_kind,
            },
        ));
    }

    let predecessor = match &request.predecessor {
        LifecyclePredecessor::Genesis {
            cat_creation_id, ..
        } => {
            if cat.lifecycle_head_operation_id.is_some()
                || request.expected_predecessor_operation_id.is_some()
            {
                return Ok(LifecycleCommandAdmission::Rejected(
                    LifecycleAdmissionRejection::StaleOperation {
                        current_operation_id: cat.lifecycle_head_operation_id,
                    },
                ));
            }
            if cat.cat_creation_id != *cat_creation_id
                || request.command_kind() != LifecycleCommandKind::Start
                || validate_lifecycle_successor(None, request).is_err()
            {
                return Ok(LifecycleCommandAdmission::Rejected(
                    LifecycleAdmissionRejection::IllegalSuccessor {
                        predecessor_kind: None,
                        command_kind: request.command_kind(),
                    },
                ));
            }
            if any_operation_for_cat(transaction, &request.cat_id)? {
                return Err(corrupt(
                    "Cat without a lifecycle head already has a lifecycle Operation",
                ));
            }
            None
        }
        _ => {
            if cat.lifecycle_head_operation_id != request.expected_predecessor_operation_id {
                return Ok(LifecycleCommandAdmission::Rejected(
                    LifecycleAdmissionRejection::StaleOperation {
                        current_operation_id: cat.lifecycle_head_operation_id,
                    },
                ));
            }
            let Some(head_id) = cat.lifecycle_head_operation_id.as_ref() else {
                return Ok(LifecycleCommandAdmission::Rejected(
                    LifecycleAdmissionRejection::StaleOperation {
                        current_operation_id: None,
                    },
                ));
            };
            let Some(head) = load_operation_for_update(transaction, head_id)? else {
                return Err(corrupt("Cat lifecycle head Operation is missing"));
            };
            let LifecycleOperationState::Terminal { terminal, .. } = &head.state else {
                return Err(corrupt("Cat lifecycle head is not terminal"));
            };
            if matches!(
                request.predecessor,
                LifecyclePredecessor::HostFenceRecovery { .. }
            ) {
                return Ok(LifecycleCommandAdmission::Rejected(
                    LifecycleAdmissionRejection::HostFenceRecoveryUnavailable,
                ));
            }
            if validate_lifecycle_successor_with_predecessor_command(
                Some(terminal.as_ref()),
                Some(head.canonical_request.as_ref()),
                request,
            )
            .is_err()
            {
                return Ok(LifecycleCommandAdmission::Rejected(
                    LifecycleAdmissionRejection::StaleOperation {
                        current_operation_id: Some(head.operation_id),
                    },
                ));
            }
            Some(head)
        }
    };

    // Keep the borrow and validation of the predecessor alive through INSERT;
    // the deferred exact-predecessor FK independently proves the same tuple at
    // commit time.
    let _predecessor_guard = predecessor;
    if request.runtime_config.config_id != cat.current_runtime_config_id
        || request.runtime_config.config_digest != cat.current_runtime_config_digest
    {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::InvalidContract,
        ));
    }
    let runtime_config = load_exact_runtime_config_unlocked(
        transaction,
        workspace_id,
        &request.cat_id,
        &cat.current_runtime_config_id,
        &cat.current_runtime_config_digest,
    )?
    .ok_or_else(|| corrupt("Cat current runtime config history row is missing"))?;
    if request.runtime_config.as_ref() != &runtime_config
        || !command_matches_runtime_config(&request.command, &runtime_config)
    {
        return Ok(LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::InvalidContract,
        ));
    }
    if matches!(request.command, LifecycleCommand::Start(_)) {
        let Some(graph) = lock_runtime_volume_graph(
            transaction,
            workspace_id,
            &request.cat_id,
            &runtime_config,
            None,
        )?
        else {
            return Ok(LifecycleCommandAdmission::Rejected(
                LifecycleAdmissionRejection::InvalidContract,
            ));
        };
        if !validate_start_volume_authority(transaction, request, &graph)? {
            return Ok(LifecycleCommandAdmission::Rejected(
                LifecycleAdmissionRejection::InvalidContract,
            ));
        }
    } else {
        let locked_config = load_exact_runtime_config_for_update(
            transaction,
            workspace_id,
            &request.cat_id,
            &cat.current_runtime_config_id,
            &cat.current_runtime_config_digest,
        )?;
        if locked_config.as_ref() != Some(&runtime_config) {
            return Ok(LifecycleCommandAdmission::Rejected(
                LifecycleAdmissionRejection::InvalidContract,
            ));
        }
    }
    let created_at = database_now(transaction)?;
    let projections = predecessor_projection(request);
    let placement_epoch = request
        .placement_identity
        .placement_epoch
        .to_pg()
        .map_err(corrupt)?;
    let created_at_pg = created_at.to_pg().map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_operations (
            operation_id, workspace_id, cat_id, node_id, placement_epoch,
            command_kind, canonical_request_bytes, canonical_request_sha256,
            runtime_config_id, runtime_config_sha256,
            expected_predecessor_operation_id, predecessor_kind,
            expected_predecessor_result_kind, expected_predecessor_result_sha256,
            state, terminal_source, terminal_result_kind,
            canonical_result_bytes, canonical_result_sha256,
            created_at_unix_ms, terminal_at_unix_ms
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
            'unresolved',NULL,NULL,NULL,NULL,$15,NULL
         )",
        &[
            &request.operation_id.as_str(),
            &workspace_id.as_str(),
            &request.cat_id.as_str(),
            &request.node_id.as_str(),
            &placement_epoch,
            &command_kind_text(request.command_kind()),
            &canonical_request,
            &request.request_fingerprint.as_str(),
            &runtime_config.config_id.as_str(),
            &runtime_config.config_digest.as_str(),
            &request
                .expected_predecessor_operation_id
                .as_ref()
                .map(Id::as_str),
            &projections.kind,
            &projections.result_kind,
            &projections.result_digest,
            &created_at_pg,
        ],
    )?;

    let operation = LifecycleOperation {
        version: ContractVersion::V1,
        operation_id: request.operation_id.clone(),
        workspace_id: workspace_id.clone(),
        cat_id: request.cat_id.clone(),
        node_id: request.node_id.clone(),
        placement_identity: request.placement_identity.clone(),
        runtime_config_id: runtime_config.config_id.clone(),
        runtime_config_digest: runtime_config.config_digest.clone(),
        command_kind: request.command_kind(),
        canonical_request: Box::new(request.clone()),
        request_fingerprint: request.request_fingerprint.clone(),
        expected_predecessor_operation_id: request.expected_predecessor_operation_id.clone(),
        predecessor: request.predecessor.clone(),
        state: LifecycleOperationState::Unresolved,
        created_at_unix_ms: created_at,
        terminal_at_unix_ms: None,
    };
    validate_lifecycle_operation(&operation).map_err(corrupt)?;
    Ok(LifecycleCommandAdmission::Admitted(operation))
}

fn poll_lifecycle_commands_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    poll: &LifecycleCommandPollRequest,
) -> AuthorityTxResult<LifecycleCommandPollOutcome> {
    let session = match authenticate_session(transaction, authenticated, &poll.session)? {
        Ok(session) => session,
        Err(rejection) => {
            return Ok(LifecycleCommandPollOutcome::Rejected(
                LifecyclePollRejection::Session(rejection),
            ));
        }
    };
    if validate_lifecycle_command_poll_for_session(poll, &session).is_err() {
        return Ok(LifecycleCommandPollOutcome::Rejected(
            LifecyclePollRejection::InvalidContract,
        ));
    }

    // A command poll is an independent Node liveness lane.  Observation may
    // also renew a session after accepting telemetry, but a malformed sibling
    // Observation must not be able to starve lifecycle command delivery.
    let now = database_now(transaction)?;
    let candidate_deadline = now
        .get()
        .checked_add(cats_api::agent_registration::AGENT_SESSION_LEASE_MS)
        .and_then(UnixMillis::new)
        .ok_or_else(|| corrupt("lifecycle poll session lease renewal overflow"))?;
    let renewed_deadline = std::cmp::max(session.lease_deadline_unix_ms, candidate_deadline);
    let session = renew_current_session_deadline(transaction, &session, renewed_deadline)?;

    let sql = format!(
        "SELECT {RUNTIME_OPERATION_COLUMNS}
           FROM runtime_operations
          WHERE node_id=$1 AND state='unresolved'
            AND ($2::text IS NULL OR cat_id COLLATE \"C\" > $2 COLLATE \"C\")
          ORDER BY cat_id COLLATE \"C\"
          LIMIT $3"
    );
    let maximum = cats_api::runtime_lifecycle::LIFECYCLE_COMMAND_BATCH_MAX_COMMANDS;
    let page_limit = i64::try_from(maximum).expect("command batch limit fits PostgreSQL BIGINT");
    let mut commands = Vec::with_capacity(maximum);
    let mut after_cat_id: Option<String> = None;
    while commands.len() < maximum {
        let rows = transaction.query(
            &sql,
            &[
                &session.node_id.as_str(),
                &after_cat_id.as_deref(),
                &page_limit,
            ],
        )?;
        let row_count = rows.len();
        let Some(last_cat_id) = rows
            .last()
            .map(|row| row.try_get::<_, String>("cat_id"))
            .transpose()?
        else {
            break;
        };
        for row in &rows {
            let operation = match decode_operation_row(row) {
                Ok(operation) if matches!(operation.state, LifecycleOperationState::Unresolved) => {
                    operation
                }
                Ok(_) => {
                    tracing::error!(
                        cat_id = row
                            .try_get::<_, String>("cat_id")
                            .unwrap_or_else(|_| "<invalid-cat-id>".to_owned()),
                        "omitting terminal lifecycle Operation returned by unresolved poll query"
                    );
                    continue;
                }
                Err(error) => {
                    // One corrupt Cat remains unresolved and receives no effect
                    // authority, but it must not turn the Node delivery lane into
                    // a second cross-Cat lifecycle authority. Do not repair or
                    // reinterpret the row here; omit only that Cat and surface
                    // the durable corruption for operator intervention.
                    let cat_id = row
                        .try_get::<_, String>("cat_id")
                        .unwrap_or_else(|_| "<invalid-cat-id>".to_owned());
                    tracing::error!(
                        cat_id,
                        error = ?error,
                        "omitting corrupt per-Cat lifecycle Operation from command poll"
                    );
                    continue;
                }
            };
            commands.push(*operation.canonical_request);
            if commands.len() == maximum {
                break;
            }
        }
        after_cat_id = Some(last_cat_id);
        if row_count < maximum {
            break;
        }
    }
    let batch = LifecycleCommandBatch {
        version: ContractVersion::V1,
        session: poll.session.clone(),
        request_sequence: poll.request_sequence,
        commands,
    };
    cats_api::runtime_lifecycle::validate_lifecycle_command_batch_for_poll(&batch, poll, &session)
        .map_err(corrupt)?;
    Ok(LifecycleCommandPollOutcome::Batch(batch))
}

fn commit_lifecycle_result_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    commit: &LifecycleResultCommitRequest,
) -> AuthorityTxResult<LifecycleResultCommitOutcome> {
    let session = match authenticate_session(transaction, authenticated, &commit.session)? {
        Ok(session) => session,
        Err(rejection) => {
            return Ok(LifecycleResultCommitOutcome::Rejected(
                LifecycleResultCommitRejection::Session(rejection),
            ));
        }
    };

    // The first lookup is deliberately non-locking and non-authoritative. It
    // locates the Cat serialization row only; every identity and request
    // projection is reloaded and revalidated after Cat -> Operation locks are
    // held in the global order.
    let Some(locator) =
        load_operation_identity_unlocked(transaction, &commit.response.operation_id)?
    else {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::OperationNotFound,
        ));
    };
    if locator.workspace_id != commit.response.workspace_id
        || locator.cat_id != commit.response.cat_id
    {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::InvalidContract,
        ));
    }
    let Some(cat) = load_cat_for_update(transaction, &locator.cat_id)? else {
        return Err(corrupt("lifecycle Operation references a missing Cat"));
    };
    let Some(mut operation) =
        load_operation_for_update(transaction, &commit.response.operation_id)?
    else {
        return Err(corrupt(
            "lifecycle Operation disappeared after its identity lookup",
        ));
    };
    if operation.workspace_id != locator.workspace_id || operation.cat_id != locator.cat_id {
        return Err(corrupt(
            "lifecycle Operation identity changed across Cat serialization",
        ));
    }
    if validate_lifecycle_result_commit_for_command(
        commit,
        operation.canonical_request.as_ref(),
        &session,
    )
    .is_err()
    {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::InvalidContract,
        ));
    }

    if let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &operation.state
    {
        if let LifecycleTerminalResult::NodeResult { response: stored } = terminal.as_ref() {
            if stored.as_ref() == commit.response.as_ref()
                && terminal_result_digest == &commit.terminal_result_digest
            {
                let acknowledgement =
                    result_stored_ack(commit.response.as_ref(), &commit.terminal_result_digest)?;
                return Ok(LifecycleResultCommitOutcome::ExactReplay {
                    operation,
                    acknowledgement,
                });
            }
        }
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::ConflictingTerminalResult {
                operation_id: commit.response.operation_id.clone(),
            },
        ));
    }

    if cat.workspace_id != operation.workspace_id {
        return Err(corrupt("Operation and Cat workspace projections disagree"));
    }
    if cat.current_runtime_config_id != operation.runtime_config_id
        || cat.current_runtime_config_digest != operation.runtime_config_digest
    {
        return Err(corrupt(
            "unresolved Operation no longer names the Cat current runtime config",
        ));
    }
    if cat.deleted_at.is_some() {
        return Err(corrupt(
            "unresolved Operation references an already deleted Cat",
        ));
    }
    if cat.lifecycle_head_operation_id != operation.expected_predecessor_operation_id {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::OperationNotCurrent {
                current_operation_id: cat.lifecycle_head_operation_id,
            },
        ));
    }
    let Some(current_unresolved) = load_unresolved_for_cat(transaction, &operation.cat_id)? else {
        return Err(corrupt(
            "unresolved Operation disappeared during settlement",
        ));
    };
    if current_unresolved.operation_id != operation.operation_id {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::OperationNotCurrent {
                current_operation_id: Some(current_unresolved.operation_id),
            },
        ));
    }

    let Some(runtime_config) =
        validate_terminal_volume_authority_in(transaction, &operation, commit.response.as_ref())?
    else {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::InvalidContract,
        ));
    };
    validate_lifecycle_command_response_for_runtime_config(
        commit.response.as_ref(),
        &runtime_config,
    )
    .map_err(corrupt)?;
    if !validate_settlement_projection(transaction, &cat, &operation, commit.response.as_ref())? {
        return Ok(LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::InvalidContract,
        ));
    }
    invalidate_routes_for_terminal_lifecycle_result(
        transaction,
        &operation,
        commit.response.as_ref(),
    )?;
    let canonical_result =
        encode_lifecycle_command_response(commit.response.as_ref()).map_err(corrupt)?;
    let terminal_at = database_now(transaction)?;
    let terminal_at_pg = terminal_at.to_pg().map_err(corrupt)?;
    let updated = transaction.execute(
        "UPDATE runtime_operations
            SET state='terminal', terminal_source='node_result',
                terminal_result_kind=$2, canonical_result_bytes=$3,
                canonical_result_sha256=$4, terminal_at_unix_ms=$5
          WHERE operation_id=$1 AND state='unresolved'",
        &[
            &operation.operation_id.as_str(),
            &terminal_kind_text(commit.response.result.kind()),
            &canonical_result,
            &commit.terminal_result_digest.as_str(),
            &terminal_at_pg,
        ],
    )?;
    if updated != 1 {
        return Err(corrupt("exact unresolved Operation update changed no row"));
    }
    update_cat_projection(
        transaction,
        &cat,
        &operation,
        commit.response.as_ref(),
        terminal_at,
    )?;

    operation.state = LifecycleOperationState::Terminal {
        terminal: Box::new(LifecycleTerminalResult::NodeResult {
            response: commit.response.clone(),
        }),
        terminal_result_digest: commit.terminal_result_digest.clone(),
    };
    operation.terminal_at_unix_ms = Some(terminal_at);
    validate_lifecycle_operation(&operation).map_err(corrupt)?;
    let acknowledgement =
        result_stored_ack(commit.response.as_ref(), &commit.terminal_result_digest)?;
    Ok(LifecycleResultCommitOutcome::Stored {
        operation,
        acknowledgement,
    })
}

fn invalidate_routes_for_terminal_lifecycle_result(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    response: &LifecycleCommandResponse,
) -> AuthorityTxResult<()> {
    let outcome = match operation.command_kind {
        LifecycleCommandKind::Start => return Ok(()),
        LifecycleCommandKind::Suspend
            if matches!(&response.result, NodeResult::SuspendDeclined(_)) =>
        {
            LifecycleAdmissionCloseOutcome::NeverClosed
        }
        LifecycleCommandKind::Suspend
        | LifecycleCommandKind::Warm
        | LifecycleCommandKind::Cold
        | LifecycleCommandKind::Stop
        | LifecycleCommandKind::Delete => LifecycleAdmissionCloseOutcome::Closed,
    };
    invalidate_routes_for_lifecycle_close_in(
        transaction,
        &operation.workspace_id,
        &operation.cat_id,
        &operation.operation_id,
        outcome,
    )?;
    Ok(())
}

pub(super) fn authenticate_session(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    presented: &SessionBinding,
) -> AuthorityTxResult<std::result::Result<AgentSession, LifecycleSessionRejection>> {
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated.credential_id())?
    else {
        return Ok(Err(LifecycleSessionRejection::IdentityNotEligible));
    };
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || !matches!(
            identity.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
        || lock_exact_credential_lineage(transaction, &identity)?
            != Some(CredentialLineageState::Active)
    {
        return Ok(Err(LifecycleSessionRejection::IdentityNotEligible));
    }
    if presented.node_id != identity.node_id {
        let Some(current) = load_current_session_for_update(transaction, &identity.node_id)? else {
            return Ok(Err(LifecycleSessionRejection::MissingAgentSession {
                node_id: identity.node_id,
            }));
        };
        return Ok(Err(LifecycleSessionRejection::WrongSession {
            expected: session_binding(&current),
            presented: presented.clone(),
        }));
    }
    let Some(current) = load_current_session_for_update(transaction, &identity.node_id)? else {
        return Ok(Err(LifecycleSessionRejection::MissingAgentSession {
            node_id: identity.node_id,
        }));
    };
    let expected = session_binding(&current);
    if presented.agent_session_epoch < expected.agent_session_epoch {
        return Ok(Err(LifecycleSessionRejection::StaleSession {
            node_id: expected.node_id,
            presented_agent_session_epoch: presented.agent_session_epoch,
            current_agent_session_epoch: expected.agent_session_epoch,
        }));
    }
    if presented != &expected {
        return Ok(Err(LifecycleSessionRejection::WrongSession {
            expected,
            presented: presented.clone(),
        }));
    }
    let now = database_now(transaction)?;
    if now >= current.lease_deadline_unix_ms {
        return Ok(Err(LifecycleSessionRejection::SessionExpired {
            node_id: current.node_id.clone(),
            agent_session_epoch: current.agent_session_epoch,
            lease_deadline_unix_ms: current.lease_deadline_unix_ms,
            server_time_unix_ms: now,
        }));
    }
    Ok(Ok(current))
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn load_cat_for_update(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CatLifecycleProjection>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_creation_id,
                    lifecycle_head_operation_id, stable_state,
                    effective_runtime_ready_operation_id,
                    runtime_incarnation, current_runtime_config_id,
                    current_runtime_config_sha256, deleted_at
               FROM cat_records WHERE cat_id=$1 FOR UPDATE",
            &[&cat_id.as_str()],
        )?
        .map(|row| decode_cat_projection(&row))
        .transpose()
}

fn load_cat_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CatLifecycleProjection>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_creation_id,
                    lifecycle_head_operation_id, stable_state,
                    effective_runtime_ready_operation_id,
                    runtime_incarnation, current_runtime_config_id,
                    current_runtime_config_sha256, deleted_at
               FROM cat_records WHERE cat_id=$1",
            &[&cat_id.as_str()],
        )?
        .map(|row| decode_cat_projection(&row))
        .transpose()
}

fn load_exact_runtime_config_for_update(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    config_id: &Id,
    config_digest: &Sha256Digest,
) -> AuthorityTxResult<Option<ImmutableRuntimeConfig>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_id, config_id,
                    canonical_config_bytes, canonical_config_sha256
               FROM cat_runtime_configs
              WHERE workspace_id=$1 AND cat_id=$2 AND config_id=$3
                AND canonical_config_sha256=$4
              FOR UPDATE",
            &[
                &workspace_id.as_str(),
                &cat_id.as_str(),
                &config_id.as_str(),
                &config_digest.as_str(),
            ],
        )?
        .map(|row| {
            decode_immutable_runtime_config_row(
                &row,
                workspace_id,
                cat_id,
                config_id,
                config_digest,
            )
        })
        .transpose()
}

fn load_exact_runtime_config_unlocked(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    config_id: &Id,
    config_digest: &Sha256Digest,
) -> AuthorityTxResult<Option<ImmutableRuntimeConfig>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_id, config_id,
                    canonical_config_bytes, canonical_config_sha256
               FROM cat_runtime_configs
              WHERE workspace_id=$1 AND cat_id=$2 AND config_id=$3
                AND canonical_config_sha256=$4",
            &[
                &workspace_id.as_str(),
                &cat_id.as_str(),
                &config_id.as_str(),
                &config_digest.as_str(),
            ],
        )?
        .map(|row| {
            decode_immutable_runtime_config_row(
                &row,
                workspace_id,
                cat_id,
                config_id,
                config_digest,
            )
        })
        .transpose()
}

fn decode_immutable_runtime_config_row(
    row: &Row,
    workspace_id: &Id,
    cat_id: &Id,
    config_id: &Id,
    config_digest: &Sha256Digest,
) -> AuthorityTxResult<ImmutableRuntimeConfig> {
    let stored_workspace_id = parse_id(row.try_get::<_, String>("workspace_id")?)?;
    let stored_cat_id = parse_id(row.try_get::<_, String>("cat_id")?)?;
    let stored_config_id = parse_id(row.try_get::<_, String>("config_id")?)?;
    if stored_workspace_id != *workspace_id
        || stored_cat_id != *cat_id
        || stored_config_id != *config_id
    {
        return Err(corrupt(
            "Cat runtime config identity projection disagrees with its history key",
        ));
    }
    let bytes: Vec<u8> = row.try_get("canonical_config_bytes")?;
    let config = decode_immutable_runtime_config(&bytes).map_err(corrupt)?;
    let stored_digest: String = row.try_get("canonical_config_sha256")?;
    if config.config_id != *config_id
        || config.config_digest != *config_digest
        || stored_digest != config_digest.as_str()
    {
        return Err(corrupt(
            "Cat runtime config JSON and digest projection disagree",
        ));
    }
    Ok(config)
}

fn command_matches_runtime_config(
    command: &LifecycleCommand,
    config: &ImmutableRuntimeConfig,
) -> bool {
    match command {
        LifecycleCommand::Start(_) => true,
        LifecycleCommand::Delete(spec) => {
            spec.volume_dispositions.len() == config.volumes.len()
                && spec.volume_dispositions.iter().zip(&config.volumes).all(
                    |(disposition, volume)| match disposition {
                        RequestedVolumeDisposition::DiscardWithCat {
                            volume_id,
                            disk_id,
                            disk_role: DiskRole::Root,
                        } => {
                            volume.disk_role == DiskRole::Root
                                && volume.volume_id == *volume_id
                                && volume.disk_id == *disk_id
                        }
                        RequestedVolumeDisposition::RetainDetached {
                            volume_id,
                            disk_id,
                            disk_role: DiskRole::Persistent,
                        } => {
                            volume.disk_role == DiskRole::Persistent
                                && volume.volume_id == *volume_id
                                && volume.disk_id == *disk_id
                        }
                        _ => false,
                    },
                )
        }
        LifecycleCommand::Suspend(_)
        | LifecycleCommand::Warm(_)
        | LifecycleCommand::Cold(_)
        | LifecycleCommand::Stop(_) => true,
    }
}

#[derive(Debug)]
struct LockedRuntimeVolumeGraph {
    config: ImmutableRuntimeConfig,
    volumes: BTreeMap<Id, Option<StoredVolume>>,
    disks: BTreeMap<Id, Option<DiskRecord>>,
}

/// Locks the complete bounded graph in the global sorted-Volume ->
/// sorted-Disk order. `absent_root` is used only after an exact Delete
/// completion; every other config member must have both authority rows
/// present.
fn lock_runtime_volume_graph(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    discovered_config: &ImmutableRuntimeConfig,
    absent_root: Option<&Id>,
) -> AuthorityTxResult<Option<LockedRuntimeVolumeGraph>> {
    let mut volume_ids = discovered_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<Vec<_>>();
    volume_ids.sort();
    let mut volumes = BTreeMap::new();
    for volume_id in volume_ids {
        volumes.insert(
            volume_id.clone(),
            load_stored_volume_for_update(transaction, &volume_id)?,
        );
    }

    let mut disk_ids = discovered_config
        .volumes
        .iter()
        .map(|volume| volume.disk_id.clone())
        .collect::<Vec<_>>();
    disk_ids.sort();
    let mut disks = BTreeMap::new();
    for disk_id in disk_ids {
        disks.insert(
            disk_id.clone(),
            load_disk_by_id_for_update(transaction, &disk_id)?,
        );
    }

    let Some(config) = load_exact_runtime_config_for_update(
        transaction,
        workspace_id,
        cat_id,
        &discovered_config.config_id,
        &discovered_config.config_digest,
    )?
    else {
        return Ok(None);
    };
    if config != *discovered_config {
        return Ok(None);
    }

    for expected in &config.volumes {
        let current_volume = volumes
            .get(&expected.volume_id)
            .ok_or_else(|| corrupt("locked Volume graph lost a canonical member"))?;
        let current_disk = disks
            .get(&expected.disk_id)
            .ok_or_else(|| corrupt("locked Disk graph lost a canonical member"))?;
        match (current_volume, current_disk) {
            (Some(volume), Some(disk)) => {
                if !volume_and_disk_match_config(
                    workspace_id,
                    cat_id,
                    expected,
                    &volume.record,
                    disk,
                ) {
                    return Ok(None);
                }
            }
            (None, None)
                if expected.disk_role == DiskRole::Root
                    && absent_root == Some(&expected.volume_id) => {}
            _ => return Ok(None),
        }
    }

    Ok(Some(LockedRuntimeVolumeGraph {
        config,
        volumes,
        disks,
    }))
}

fn volume_and_disk_match_config(
    workspace_id: &Id,
    cat_id: &Id,
    expected: &RuntimeVolumeConfig,
    volume: &VolumeRecord,
    disk: &DiskRecord,
) -> bool {
    let admin_state_matches = matches!(
        (&volume.admin_state, &disk.admin_state),
        (VolumeAdminState::Active, ProductDiskAdminState::Active)
    ) || matches!(
        (&volume.admin_state, &disk.admin_state),
        (
            VolumeAdminState::Deleting { delete_id: volume_delete },
            ProductDiskAdminState::Deleting { delete_id: disk_delete }
        ) if volume_delete == disk_delete
    );
    let role_matches = match (&expected.disk_role, &expected.guest_binding, &disk.role) {
        (
            DiskRole::Root,
            RuntimeVolumeGuestBinding::RootBoot,
            ProductDiskRole::Root {
                cat_id: root_cat_id,
            },
        ) => root_cat_id == cat_id,
        (
            DiskRole::Persistent,
            RuntimeVolumeGuestBinding::PersistentExt4 {
                filesystem_uuid, ..
            },
            ProductDiskRole::Persistent { initialization },
        ) => match initialization.as_ref() {
            PersistentDiskInitialization::Uninitialized {
                filesystem_uuid: stored,
                ..
            }
            | PersistentDiskInitialization::Initialized {
                filesystem_uuid: stored,
                ..
            } => stored == filesystem_uuid,
        },
        _ => false,
    };
    volume.volume_id == expected.volume_id
        && volume.size_bytes == expected.size_bytes
        && volume.durability == expected.durability
        && disk.disk_id == expected.disk_id
        && disk.workspace_id == *workspace_id
        && disk.volume_id == expected.volume_id
        && disk.size_bytes == expected.size_bytes
        && disk.durability == expected.durability
        && admin_state_matches
        && role_matches
}

fn validate_start_volume_authority(
    transaction: &mut Transaction<'_>,
    request: &LifecycleCommandEnvelope,
    graph: &LockedRuntimeVolumeGraph,
) -> AuthorityTxResult<bool> {
    let LifecycleCommand::Start(spec) = &request.command else {
        return Ok(true);
    };
    if spec.volume_authorities.len() != graph.config.volumes.len() {
        return Ok(false);
    }
    for (authority, expected) in spec.volume_authorities.iter().zip(&graph.config.volumes) {
        let Some(current) = graph
            .volumes
            .get(&expected.volume_id)
            .and_then(Option::as_ref)
        else {
            return Ok(false);
        };
        if authority.volume_id != expected.volume_id
            || authority.disk_id != expected.disk_id
            || !start_authority_matches_current(&request.node_id, authority, current)
            || !start_transition_source_matches(
                transaction,
                request,
                spec.source,
                authority,
                current,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn start_authority_matches_current(
    node_id: &Id,
    authority: &StartVolumeAuthority,
    current: &StoredVolume,
) -> bool {
    if !matches!(current.record.admin_state, VolumeAdminState::Active) {
        return false;
    }
    match &authority.authority {
        RuntimeVolumeAuthorityInput::NormalUnowned {
            expected_unowned_epoch,
            ..
        } => {
            current.record.lease_owner.is_none()
                && current.record.lease_expires_at.is_none()
                && current.owner_binding.is_none()
                && current.record.lease_epoch == *expected_unowned_epoch
        }
        RuntimeVolumeAuthorityInput::SameNodeOwned {
            attachment_id,
            attachment_epoch,
        } => current.owner_binding.as_ref().is_some_and(|binding| {
            binding.owner_node_id == *node_id
                && binding.volume_id == authority.volume_id
                && binding.attachment_id == *attachment_id
                && binding.attachment_epoch == *attachment_epoch
                && current.record.lease_owner.as_ref() == Some(attachment_id)
                && current.record.lease_epoch == *attachment_epoch
                && current_attachment_id(&current.record) == Some(attachment_id)
        }),
        // HostFenceRecovery is intentionally unavailable until #263 composes
        // its event and exact takeover authorization transaction.
        RuntimeVolumeAuthorityInput::Takeover { .. } => false,
    }
}

fn start_transition_source_matches(
    transaction: &mut Transaction<'_>,
    request: &LifecycleCommandEnvelope,
    start_source: StartSource,
    authority: &StartVolumeAuthority,
    current: &StoredVolume,
) -> AuthorityTxResult<bool> {
    match &authority.authority {
        RuntimeVolumeAuthorityInput::SameNodeOwned { .. } => {
            let source = match current.record.last_transition.as_ref() {
                Some(LastVolumeTransition::NormalAcquire { source, .. })
                | Some(LastVolumeTransition::Takeover { source, .. }) => source,
                _ => return Ok(false),
            };
            let Some(source_operation) = load_lifecycle_source_operation(transaction, source)?
            else {
                return Ok(false);
            };
            Ok(lifecycle_start_source_matches_target(
                &source_operation,
                request,
            ))
        }
        RuntimeVolumeAuthorityInput::NormalUnowned { .. } => match start_source {
            StartSource::Genesis => Ok(current.record.last_transition.is_none()),
            StartSource::SameNodeCold | StartSource::ColdHandoff => {
                let Some(predecessor_id) = request.expected_predecessor_operation_id.as_ref()
                else {
                    return Ok(false);
                };
                let Some(predecessor) = load_operation_unlocked(transaction, predecessor_id)?
                else {
                    return Ok(false);
                };
                if !operation_is_successful_cold(&predecessor, request) {
                    return Ok(false);
                }
                let current_slot = request
                    .runtime_config
                    .volumes
                    .iter()
                    .find(|slot| slot.volume_id == authority.volume_id)
                    .ok_or_else(|| corrupt("Start authority omitted its runtime config slot"))?;
                let predecessor_slot = predecessor
                    .canonical_request
                    .runtime_config
                    .volumes
                    .iter()
                    .find(|slot| slot.volume_id == authority.volume_id);
                match current.record.last_transition.as_ref() {
                    // Cold-only config mutation may attach a pristine Volume
                    // which was not part of the predecessor Cold receipt set.
                    None => Ok(predecessor_slot.is_none()),
                    Some(LastVolumeTransition::Release { source, .. }) => {
                        let Some(source_operation) =
                            load_lifecycle_source_operation(transaction, source)?
                        else {
                            return Ok(false);
                        };
                        Ok(source_operation.operation_id == predecessor.operation_id
                            && predecessor_slot == Some(current_slot))
                    }
                    Some(_) => Ok(false),
                }
            }
            // A same-node retry may still see the pristine Genesis row (the
            // failed Start never acquired) or the exact lifecycle Cold release
            // from which the failed Start attempted to acquire. It may never
            // adopt an Independent release.
            StartSource::SameNodeRetry => match current.record.last_transition.as_ref() {
                None => Ok(true),
                Some(LastVolumeTransition::Release { source, .. }) => {
                    let Some(source_operation) =
                        load_lifecycle_source_operation(transaction, source)?
                    else {
                        return Ok(false);
                    };
                    let current_slot = request
                        .runtime_config
                        .volumes
                        .iter()
                        .find(|slot| slot.volume_id == authority.volume_id)
                        .ok_or_else(|| {
                            corrupt("Start retry authority omitted its runtime config slot")
                        })?;
                    Ok(source_operation.workspace_id == request.workspace_id
                        && source_operation.cat_id == request.cat_id
                        && source_operation.command_kind == LifecycleCommandKind::Cold
                        && source_operation
                            .canonical_request
                            .runtime_config
                            .volumes
                            .iter()
                            .find(|slot| slot.volume_id == authority.volume_id)
                            == Some(current_slot))
                }
                Some(_) => Ok(false),
            },
            StartSource::SameNodeSuspended
            | StartSource::SameNodeWarm
            | StartSource::SameNodeStopped
            | StartSource::HostFenceRecovery => Ok(false),
        },
        // HostFenceRecovery remains unavailable until the exact event and
        // authorization transaction is composed.
        RuntimeVolumeAuthorityInput::Takeover { .. } => Ok(false),
    }
}

fn operation_is_successful_cold(
    operation: &LifecycleOperation,
    successor: &LifecycleCommandEnvelope,
) -> bool {
    successor.expected_predecessor_operation_id.as_ref() == Some(&operation.operation_id)
        && operation.workspace_id == successor.workspace_id
        && operation.cat_id == successor.cat_id
        && operation.command_kind == LifecycleCommandKind::Cold
        && matches!(
            &operation.state,
            LifecycleOperationState::Terminal { terminal, .. }
                if matches!(
                    terminal.as_ref(),
                    LifecycleTerminalResult::NodeResult { response }
                        if matches!(&response.result, NodeResult::Cold(_))
                )
        )
}

fn load_lifecycle_source_operation(
    transaction: &mut Transaction<'_>,
    source: &VolumeTransitionSource,
) -> AuthorityTxResult<Option<LifecycleOperation>> {
    let VolumeTransitionSource::Lifecycle {
        operation_id,
        request_fingerprint,
    } = source
    else {
        return Ok(None);
    };
    let Some(operation) = load_operation_unlocked(transaction, operation_id)? else {
        return Ok(None);
    };
    Ok((operation.request_fingerprint == *request_fingerprint).then_some(operation))
}

fn lifecycle_start_source_matches_target(
    source: &LifecycleOperation,
    target: &LifecycleCommandEnvelope,
) -> bool {
    source.workspace_id == target.workspace_id
        && source.cat_id == target.cat_id
        && source.node_id == target.node_id
        && source.placement_identity == target.placement_identity
        && source.runtime_config_id == target.runtime_config.config_id
        && source.runtime_config_digest == target.runtime_config.config_digest
        && source.command_kind == LifecycleCommandKind::Start
        && matches!(
            &source.state,
            LifecycleOperationState::Terminal { terminal, .. }
                if matches!(terminal.as_ref(), LifecycleTerminalResult::NodeResult { .. })
        )
}

fn current_attachment_id(record: &VolumeRecord) -> Option<&Id> {
    match record.last_transition.as_ref()? {
        LastVolumeTransition::NormalAcquire { result, .. } => Some(&result.attachment_id),
        LastVolumeTransition::Takeover { .. } => record.lease_owner.as_ref(),
        LastVolumeTransition::Release { .. }
        | LastVolumeTransition::BeginDelete { .. }
        | LastVolumeTransition::BeginDisposableDelete { .. } => None,
    }
}

/// An owned Volume used by atomic lifecycle may never be adopted from the
/// independent/legacy authority lane. Same-node resume and retry intentionally
/// retain the original acquire/takeover transition, so the source need not be
/// the current command; it must instead name an exact immutable Start
/// Operation in the same Cat/config/placement lineage.
fn validate_owned_lifecycle_transition_source(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    record: &VolumeRecord,
) -> AuthorityTxResult<bool> {
    let Some((operation_id, request_fingerprint)) = owned_transition_source(record) else {
        return Ok(false);
    };

    if operation_id == &operation.operation_id {
        return Ok(request_fingerprint == &operation.request_fingerprint
            && operation.command_kind == LifecycleCommandKind::Start);
    }

    // The source row is already immutable terminal history. This deliberately
    // remains a non-locking point read after Volume locks rather than
    // reversing the Cat -> Operation -> Volume lock order.
    let Some(source_operation) = load_operation_unlocked(transaction, operation_id)? else {
        return Ok(false);
    };
    let source_is_terminal_node_result = matches!(
        &source_operation.state,
        LifecycleOperationState::Terminal { terminal, .. }
            if matches!(terminal.as_ref(), LifecycleTerminalResult::NodeResult { .. })
    );
    Ok(source_operation.operation_id == *operation_id
        && source_operation.request_fingerprint == *request_fingerprint
        && source_operation.workspace_id == operation.workspace_id
        && source_operation.cat_id == operation.cat_id
        && source_operation.node_id == operation.node_id
        && source_operation.placement_identity == operation.placement_identity
        && source_operation.runtime_config_id == operation.runtime_config_id
        && source_operation.runtime_config_digest == operation.runtime_config_digest
        && source_operation.command_kind == LifecycleCommandKind::Start
        && source_is_terminal_node_result)
}

fn owned_transition_source(record: &VolumeRecord) -> Option<(&Id, &Sha256Digest)> {
    let source = match record.last_transition.as_ref()? {
        LastVolumeTransition::NormalAcquire { source, .. }
        | LastVolumeTransition::Takeover { source, .. } => source,
        LastVolumeTransition::Release { .. }
        | LastVolumeTransition::BeginDelete { .. }
        | LastVolumeTransition::BeginDisposableDelete { .. } => return None,
    };
    match source {
        VolumeTransitionSource::Lifecycle {
            operation_id,
            request_fingerprint,
        } => Some((operation_id, request_fingerprint)),
        VolumeTransitionSource::Independent => None,
    }
}

fn decode_cat_projection(row: &Row) -> AuthorityTxResult<CatLifecycleProjection> {
    let stable_state = row
        .try_get::<_, Option<String>>("stable_state")?
        .as_deref()
        .map(LifecycleStableState::parse)
        .transpose()?;
    let effective_runtime_ready_operation_id = row
        .try_get::<_, Option<String>>("effective_runtime_ready_operation_id")?
        .map(parse_id)
        .transpose()?;
    let runtime_incarnation = row
        .try_get::<_, Option<String>>("runtime_incarnation")?
        .map(parse_random_id)
        .transpose()?;
    let lifecycle_shape_valid = matches!(
        (
            stable_state,
            effective_runtime_ready_operation_id.as_ref(),
            runtime_incarnation.as_ref(),
        ),
        (Some(LifecycleStableState::Running), Some(_), Some(_))
            | (Some(LifecycleStableState::Suspended), None, Some(_))
            | (
                Some(LifecycleStableState::Warm | LifecycleStableState::Cold),
                None,
                None,
            )
            | (None, None, None)
    );
    if !lifecycle_shape_valid {
        return Err(corrupt(
            "Cat stable/effective RuntimeReady/incarnation shape is inconsistent",
        ));
    }
    Ok(CatLifecycleProjection {
        workspace_id: parse_id(row.try_get::<_, String>("workspace_id")?)?,
        cat_creation_id: parse_id(row.try_get::<_, String>("cat_creation_id")?)?,
        lifecycle_head_operation_id: row
            .try_get::<_, Option<String>>("lifecycle_head_operation_id")?
            .map(parse_id)
            .transpose()?,
        stable_state,
        effective_runtime_ready_operation_id,
        runtime_incarnation,
        current_runtime_config_id: parse_id(
            row.try_get::<_, String>("current_runtime_config_id")?,
        )?,
        current_runtime_config_digest: parse_digest(
            row.try_get::<_, String>("current_runtime_config_sha256")?,
        )?,
        deleted_at: row
            .try_get::<_, Option<i64>>("deleted_at")?
            .map(UnixMillis::from_pg)
            .transpose()
            .map_err(corrupt)?,
    })
}

struct LifecycleOperationIdentityLocator {
    workspace_id: Id,
    cat_id: Id,
}

fn load_operation_identity_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<LifecycleOperationIdentityLocator>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_id
               FROM runtime_operations WHERE operation_id=$1",
            &[&operation_id.as_str()],
        )?
        .map(|row| {
            Ok(LifecycleOperationIdentityLocator {
                workspace_id: parse_id(row.try_get::<_, String>("workspace_id")?)?,
                cat_id: parse_id(row.try_get::<_, String>("cat_id")?)?,
            })
        })
        .transpose()
}

fn load_operation_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<LifecycleOperation>> {
    let sql = format!(
        "SELECT {RUNTIME_OPERATION_COLUMNS}
           FROM runtime_operations WHERE operation_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&operation_id.as_str()])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

pub(super) fn load_operation_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<LifecycleOperation>> {
    let sql = format!(
        "SELECT {RUNTIME_OPERATION_COLUMNS}
           FROM runtime_operations WHERE operation_id=$1"
    );
    transaction
        .query_opt(&sql, &[&operation_id.as_str()])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

fn load_unresolved_for_cat(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<LifecycleOperation>> {
    let sql = format!(
        "SELECT {RUNTIME_OPERATION_COLUMNS}
           FROM runtime_operations
          WHERE cat_id=$1 AND state='unresolved'
          FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

fn load_unresolved_for_cat_unlocked(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<LifecycleOperation>> {
    let sql = format!(
        "SELECT {RUNTIME_OPERATION_COLUMNS}
           FROM runtime_operations
          WHERE cat_id=$1 AND state='unresolved'"
    );
    transaction
        .query_opt(&sql, &[&cat_id.as_str()])?
        .map(|row| decode_operation_row(&row))
        .transpose()
}

fn any_operation_for_cat(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<bool> {
    Ok(transaction
        .query_opt(
            "SELECT operation_id FROM runtime_operations
              WHERE cat_id=$1 ORDER BY operation_id COLLATE \"C\" LIMIT 1
              FOR UPDATE",
            &[&cat_id.as_str()],
        )?
        .is_some())
}

fn decode_operation_row(row: &Row) -> AuthorityTxResult<LifecycleOperation> {
    let request_bytes: Vec<u8> = row.try_get("canonical_request_bytes")?;
    let request = decode_lifecycle_command_envelope(&request_bytes).map_err(corrupt)?;
    let operation_id = parse_id(row.try_get::<_, String>("operation_id")?)?;
    let workspace_id = parse_id(row.try_get::<_, String>("workspace_id")?)?;
    let cat_id = parse_id(row.try_get::<_, String>("cat_id")?)?;
    let node_id = parse_id(row.try_get::<_, String>("node_id")?)?;
    let placement_epoch = Epoch::from_pg(row.try_get("placement_epoch")?).map_err(corrupt)?;
    let command_kind = parse_command_kind(&row.try_get::<_, String>("command_kind")?)?;
    let request_digest: String = row.try_get("canonical_request_sha256")?;
    let runtime_config_id = parse_id(row.try_get::<_, String>("runtime_config_id")?)?;
    let runtime_config_digest = parse_digest(row.try_get::<_, String>("runtime_config_sha256")?)?;
    let expected_predecessor_operation_id = row
        .try_get::<_, Option<String>>("expected_predecessor_operation_id")?
        .map(parse_id)
        .transpose()?;
    let predecessor_kind: String = row.try_get("predecessor_kind")?;
    let predecessor_result_kind: Option<String> =
        row.try_get("expected_predecessor_result_kind")?;
    let predecessor_result_digest: Option<String> =
        row.try_get("expected_predecessor_result_sha256")?;
    let projections = predecessor_projection(&request);

    if operation_id != request.operation_id
        || workspace_id != request.workspace_id
        || cat_id != request.cat_id
        || node_id != request.node_id
        || request.placement_identity.node_id != node_id
        || request.placement_identity.placement_epoch != placement_epoch
        || command_kind != request.command_kind()
        || request_digest != request.request_fingerprint.as_str()
        || runtime_config_id != request.runtime_config.config_id
        || runtime_config_digest != request.runtime_config.config_digest
        || expected_predecessor_operation_id != request.expected_predecessor_operation_id
        || predecessor_kind != projections.kind
        || predecessor_result_kind.as_deref() != projections.result_kind.as_deref()
        || predecessor_result_digest.as_deref() != projections.result_digest.as_deref()
    {
        return Err(corrupt("lifecycle Operation JSON/projection mismatch"));
    }

    let created_at = UnixMillis::from_pg(row.try_get("created_at_unix_ms")?).map_err(corrupt)?;
    let terminal_at = row
        .try_get::<_, Option<i64>>("terminal_at_unix_ms")?
        .map(UnixMillis::from_pg)
        .transpose()
        .map_err(corrupt)?;
    let state_text: String = row.try_get("state")?;
    let source: Option<String> = row.try_get("terminal_source")?;
    let result_kind_text: Option<String> = row.try_get("terminal_result_kind")?;
    let result_bytes: Option<Vec<u8>> = row.try_get("canonical_result_bytes")?;
    let result_digest: Option<String> = row.try_get("canonical_result_sha256")?;
    let state = match (
        state_text.as_str(),
        source.as_deref(),
        result_kind_text.as_deref(),
        result_bytes,
        result_digest.as_deref(),
        terminal_at,
    ) {
        ("unresolved", None, None, None, None, None) => LifecycleOperationState::Unresolved,
        ("terminal", Some("node_result"), Some(kind), Some(bytes), Some(digest), Some(_)) => {
            let response = decode_lifecycle_command_response(&bytes).map_err(corrupt)?;
            let terminal = LifecycleTerminalResult::NodeResult {
                response: Box::new(response),
            };
            let terminal_result_digest =
                lifecycle_terminal_result_digest(&terminal).map_err(corrupt)?;
            if terminal_kind_text(terminal.kind()) != kind
                || terminal_result_digest.as_str() != digest
            {
                return Err(corrupt("stored Node result projection mismatch"));
            }
            LifecycleOperationState::Terminal {
                terminal: Box::new(terminal),
                terminal_result_digest,
            }
        }
        ("terminal", Some("host_lost"), Some("host_lost"), Some(bytes), Some(digest), Some(_)) => {
            let terminal: LifecycleTerminalResult =
                serde_json::from_slice(&bytes).map_err(corrupt)?;
            if !matches!(terminal, LifecycleTerminalResult::HostLost { .. }) {
                return Err(corrupt("stored HostLost source contains a Node result"));
            }
            let canonical = serde_json::to_vec(&terminal).map_err(corrupt)?;
            let terminal_result_digest =
                lifecycle_terminal_result_digest(&terminal).map_err(corrupt)?;
            if canonical != bytes || terminal_result_digest.as_str() != digest {
                return Err(corrupt("stored HostLost result projection mismatch"));
            }
            LifecycleOperationState::Terminal {
                terminal: Box::new(terminal),
                terminal_result_digest,
            }
        }
        _ => return Err(corrupt("stored lifecycle Operation state shape is invalid")),
    };

    let operation = LifecycleOperation {
        version: ContractVersion::V1,
        operation_id,
        workspace_id,
        cat_id,
        node_id,
        placement_identity: request.placement_identity.clone(),
        runtime_config_id,
        runtime_config_digest,
        command_kind,
        request_fingerprint: request.request_fingerprint.clone(),
        predecessor: request.predecessor.clone(),
        canonical_request: Box::new(request),
        expected_predecessor_operation_id,
        state,
        created_at_unix_ms: created_at,
        terminal_at_unix_ms: terminal_at,
    };
    validate_lifecycle_operation(&operation).map_err(corrupt)?;
    Ok(operation)
}

fn validate_settlement_projection(
    transaction: &mut Transaction<'_>,
    cat: &CatLifecycleProjection,
    operation: &LifecycleOperation,
    result: &LifecycleCommandResponse,
) -> AuthorityTxResult<bool> {
    if result.operation_id != operation.operation_id
        || result.workspace_id != operation.workspace_id
        || result.node_id != operation.node_id
        || result.cat_id != operation.cat_id
        || result.placement_identity != operation.placement_identity
        || result.request_fingerprint != operation.request_fingerprint
    {
        return Ok(false);
    }
    if let NodeResult::SuspendDeclined(declined) = &result.result {
        let runtime_ready = &declined.effective_runtime_ready;
        if cat.stable_state != Some(LifecycleStableState::Running)
            || cat.effective_runtime_ready_operation_id.as_ref()
                != Some(&runtime_ready.source_lifecycle_operation_id)
            || cat.runtime_incarnation.as_ref() != Some(&runtime_ready.runtime_incarnation)
        {
            return Ok(false);
        }
        let source =
            load_operation_unlocked(transaction, &runtime_ready.source_lifecycle_operation_id)?
                .ok_or_else(|| corrupt("effective RuntimeReady source Operation is missing"))?;
        let LifecycleOperationState::Terminal { terminal, .. } = &source.state else {
            return Err(corrupt("effective RuntimeReady source is unresolved"));
        };
        let LifecycleTerminalResult::NodeResult { response } = terminal.as_ref() else {
            return Err(corrupt("effective RuntimeReady source is HostLost"));
        };
        let NodeResult::RuntimeReady(ready) = &response.result else {
            return Err(corrupt(
                "effective RuntimeReady source has the wrong result kind",
            ));
        };
        if ready.runtime_incarnation != runtime_ready.runtime_incarnation
            || ready.runtime_config_digest != runtime_ready.runtime_config_digest
            || ready.execution_receipt_digest != runtime_ready.runtime_ready_receipt_digest
            || source.runtime_config_digest != runtime_ready.runtime_config_digest
        {
            return Ok(false);
        }
    }
    match &result.result {
        NodeResult::Suspended(suspended)
            if cat.stable_state != Some(LifecycleStableState::Running)
                || cat.runtime_incarnation.as_ref() != Some(&suspended.runtime_incarnation) =>
        {
            Ok(false)
        }
        NodeResult::Warm(warm)
            if cat
                .runtime_incarnation
                .as_ref()
                .is_some_and(|current| current != &warm.source_runtime_incarnation) =>
        {
            Ok(false)
        }
        NodeResult::Killed(killed)
            if cat.runtime_incarnation.as_ref().is_some_and(|current| {
                killed.stopped_runtime_incarnation.as_ref() != Some(current)
            }) =>
        {
            Ok(false)
        }
        _ => Ok(true),
    }
}

fn validate_terminal_volume_authority_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    response: &LifecycleCommandResponse,
) -> AuthorityTxResult<Option<ImmutableRuntimeConfig>> {
    let runtime_config = load_exact_runtime_config_for_update(
        transaction,
        &operation.workspace_id,
        &operation.cat_id,
        &operation.runtime_config_id,
        &operation.runtime_config_digest,
    )?
    .ok_or_else(|| corrupt("Operation runtime config history row is missing"))?;
    if runtime_config != *operation.canonical_request.runtime_config {
        return Err(corrupt(
            "Operation runtime config history disagrees with canonical request",
        ));
    }

    let valid = match &response.result {
        NodeResult::RuntimeReady(ready) => validate_owned_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &ready.volume_receipts,
            OwnedTerminalPolicy::RuntimeReady,
            true,
        )?,
        NodeResult::Suspended(suspended) => validate_owned_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &suspended.local_durability_receipts,
            OwnedTerminalPolicy::Suspended,
            true,
        )?,
        NodeResult::Warm(warm) => validate_owned_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &warm.volume_receipts,
            OwnedTerminalPolicy::Warm,
            true,
        )?,
        NodeResult::Cold(cold) => validate_cold_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &cold.volume_dispositions,
        )?,
        NodeResult::Deleted(deleted) => validate_deleted_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &deleted.volume_dispositions,
        )?,
        NodeResult::Killed(killed) => validate_owned_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &killed.retained_volume_receipts,
            OwnedTerminalPolicy::Retained,
            false,
        )?,
        NodeResult::NeedsIntervention(intervention) => validate_owned_terminal_receipts_in(
            transaction,
            operation,
            &runtime_config,
            &intervention.retained_volume_receipts,
            OwnedTerminalPolicy::Retained,
            false,
        )?,
        NodeResult::StartFailed(failed) => validate_start_failed_terminal_authority_in(
            transaction,
            operation,
            &runtime_config,
            &failed.retained_volume_receipts,
        )?,
        NodeResult::SuspendFailed(failed) | NodeResult::WarmFailed(failed) => {
            validate_owned_terminal_receipts_in(
                transaction,
                operation,
                &runtime_config,
                &failed.retained_volume_receipts,
                OwnedTerminalPolicy::Retained,
                true,
            )?
        }
        NodeResult::SuspendDeclined(_) => true,
    };
    Ok(valid.then_some(runtime_config))
}

fn validate_start_failed_terminal_authority_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    runtime_config: &ImmutableRuntimeConfig,
    receipts: &[VolumeTerminalReceipt],
) -> AuthorityTxResult<bool> {
    if !validate_owned_terminal_receipts_in(
        transaction,
        operation,
        runtime_config,
        receipts,
        OwnedTerminalPolicy::Retained,
        false,
    )? {
        return Ok(false);
    }
    let LifecycleCommand::Start(failed) = &operation.canonical_request.command else {
        return Ok(false);
    };
    if failed.volume_authorities.len() != runtime_config.volumes.len() {
        return Ok(false);
    }
    let Some(graph) = lock_runtime_volume_graph(
        transaction,
        &operation.workspace_id,
        &operation.cat_id,
        runtime_config,
        None,
    )?
    else {
        return Ok(false);
    };

    for (volume, failed_authority) in runtime_config
        .volumes
        .iter()
        .zip(&failed.volume_authorities)
    {
        if failed_authority.volume_id != volume.volume_id
            || failed_authority.disk_id != volume.disk_id
        {
            return Ok(false);
        }
        if receipts
            .binary_search_by(|receipt| receipt.volume_id.as_str().cmp(volume.volume_id.as_str()))
            .is_ok()
        {
            continue;
        }
        if !matches!(
            &failed_authority.authority,
            RuntimeVolumeAuthorityInput::NormalUnowned { .. }
        ) {
            return Ok(false);
        }
        let Some(current) = graph
            .volumes
            .get(&volume.volume_id)
            .and_then(Option::as_ref)
        else {
            return Ok(false);
        };
        // Absence from the failed command's retained subset is not authority.
        // It is accepted only while the locked current row still matches the
        // exact NormalUnowned epoch carried by that immutable Start request.
        if !start_authority_matches_current(&operation.node_id, failed_authority, current) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, Copy)]
enum OwnedTerminalPolicy {
    RuntimeReady,
    Suspended,
    Warm,
    Retained,
}

fn validate_owned_terminal_receipts_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    runtime_config: &ImmutableRuntimeConfig,
    receipts: &[VolumeTerminalReceipt],
    policy: OwnedTerminalPolicy,
    require_complete: bool,
) -> AuthorityTxResult<bool> {
    let Some(graph) = lock_runtime_volume_graph(
        transaction,
        &operation.workspace_id,
        &operation.cat_id,
        runtime_config,
        None,
    )?
    else {
        return Ok(false);
    };
    // RuntimeReady is an affirmative serving projection.  An exact owner and
    // immutable StartGrant are not enough once that owner's database lease has
    // elapsed: no Node wall clock or stale receipt may manufacture Running.
    // Retain the locked expiries and sample DB time only after every authority
    // row has been locked and validated, so lock wait cannot consume the lease
    // behind an earlier time sample. Host-bound/non-serving terminals
    // deliberately keep their Owned identity after expiry.
    let mut runtime_ready_lease_expiries = Vec::new();
    if (require_complete && receipts.len() != graph.config.volumes.len())
        || receipts.len() > graph.config.volumes.len()
    {
        return Ok(false);
    }
    for receipt in receipts {
        let Some(expected) = graph
            .config
            .volumes
            .iter()
            .find(|volume| volume.volume_id == receipt.volume_id)
        else {
            return Ok(false);
        };
        let Some(stored_volume) = graph
            .volumes
            .get(&expected.volume_id)
            .and_then(Option::as_ref)
        else {
            return Ok(false);
        };
        let volume = &stored_volume.record;
        let Some(disk) = graph.disks.get(&expected.disk_id).and_then(Option::as_ref) else {
            return Ok(false);
        };
        let Some(owner) = stored_volume.owner_binding.as_ref() else {
            return Ok(false);
        };
        if matches!(policy, OwnedTerminalPolicy::RuntimeReady) {
            let Some(lease_expires_at) = volume.lease_expires_at.as_ref() else {
                return Ok(false);
            };
            runtime_ready_lease_expiries.push(*lease_expires_at);
        }
        if receipt.volume_id != expected.volume_id
            || receipt.disk_id != expected.disk_id
            || receipt.disk_role != expected.disk_role
            || !matches!(volume.admin_state, VolumeAdminState::Active)
            || !matches!(disk.admin_state, ProductDiskAdminState::Active)
            || owner.owner_node_id != operation.node_id
            || owner.volume_id != expected.volume_id
            || owner.attachment_id != receipt.attachment_id
            || owner.attachment_epoch != receipt.attachment_epoch
            || volume.lease_epoch != receipt.attachment_epoch
            || current_attachment_id(volume) != Some(&receipt.attachment_id)
            || !validate_owned_lifecycle_transition_source(transaction, operation, volume)?
        {
            return Ok(false);
        }
        let Some((source_operation_id, source_request_fingerprint)) =
            owned_transition_source(volume)
        else {
            return Ok(false);
        };
        let Some(stored_grant) = load_latest_command_start_volume_grant_receipt_for_update(
            transaction,
            source_operation_id,
            &expected.volume_id,
        )?
        else {
            return Ok(false);
        };
        let source_scope = LifecycleVolumeCommandScope {
            operation_id: source_operation_id.clone(),
            request_fingerprint: source_request_fingerprint.clone(),
            cat_id: operation.cat_id.clone(),
            node_id: operation.node_id.clone(),
            placement_identity: operation.placement_identity.clone(),
        };
        let computed_grant_digest = command_start_volume_grant_receipt_digest_for_current_owner(
            &source_scope,
            stored_grant.receipt.grant_sequence,
            expected,
            volume,
            &stored_grant.receipt,
        );
        let Ok(computed_grant_digest) = computed_grant_digest else {
            return Ok(false);
        };
        if stored_grant.operation.operation_id != *source_operation_id
            || stored_grant.operation.request_fingerprint != *source_request_fingerprint
            || stored_grant.operation.workspace_id != operation.workspace_id
            || stored_grant.operation.cat_id != operation.cat_id
            || stored_grant.operation.node_id != operation.node_id
            || stored_grant.operation.placement_identity != operation.placement_identity
            || stored_grant.operation.runtime_config.config_id != operation.runtime_config_id
            || stored_grant.operation.runtime_config.config_digest
                != operation.runtime_config_digest
            || stored_grant.operation.command.kind() != LifecycleCommandKind::Start
            || stored_grant.receipt_digest != computed_grant_digest
            || receipt.authority_receipt_digest.as_ref() != Some(&computed_grant_digest)
        {
            return Ok(false);
        }
        let authority_remote = volume.head.generation;
        let generations_valid = match policy {
            OwnedTerminalPolicy::RuntimeReady => {
                authority_remote >= receipt.remote_durable_generation
            }
            OwnedTerminalPolicy::Suspended | OwnedTerminalPolicy::Retained => {
                authority_remote >= receipt.remote_durable_generation
                    && authority_remote <= receipt.local_durable_generation
            }
            OwnedTerminalPolicy::Warm => {
                receipt.local_durable_generation == receipt.remote_durable_generation
                    && authority_remote == receipt.remote_durable_generation
            }
        };
        if !generations_valid {
            return Ok(false);
        }
    }
    if !runtime_ready_lease_expiries.is_empty() {
        let now = database_now(transaction)?;
        if runtime_ready_lease_expiries
            .iter()
            .any(|lease_expires_at| lease_expires_at <= &now)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn lifecycle_volume_scope(operation: &LifecycleOperation) -> LifecycleVolumeCommandScope {
    LifecycleVolumeCommandScope {
        operation_id: operation.operation_id.clone(),
        request_fingerprint: operation.request_fingerprint.clone(),
        cat_id: operation.cat_id.clone(),
        node_id: operation.node_id.clone(),
        placement_identity: operation.placement_identity.clone(),
    }
}

fn lifecycle_volume_target(
    expected: &RuntimeVolumeConfig,
    receipt: &VolumeTerminalReceipt,
) -> Option<LifecycleVolumeTarget> {
    (receipt.volume_id == expected.volume_id
        && receipt.disk_id == expected.disk_id
        && receipt.disk_role == expected.disk_role)
        .then(|| LifecycleVolumeTarget {
            disk_id: receipt.disk_id.clone(),
            disk_role: receipt.disk_role,
            volume_id: receipt.volume_id.clone(),
            attachment_id: receipt.attachment_id.clone(),
            attachment_epoch: receipt.attachment_epoch,
        })
}

fn validate_cold_terminal_receipts_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    runtime_config: &ImmutableRuntimeConfig,
    dispositions: &[ColdVolumeDisposition],
) -> AuthorityTxResult<bool> {
    let Some(graph) = lock_runtime_volume_graph(
        transaction,
        &operation.workspace_id,
        &operation.cat_id,
        runtime_config,
        None,
    )?
    else {
        return Ok(false);
    };
    if dispositions.len() != graph.config.volumes.len() {
        return Ok(false);
    }
    let expected_normal = dispositions
        .iter()
        .filter(|disposition| matches!(disposition, ColdVolumeDisposition::NormallyReleased { .. }))
        .count();
    let expected_already = dispositions.len() - expected_normal;
    if !lifecycle_receipt_counts_match(
        transaction,
        &operation.operation_id,
        expected_normal,
        expected_already,
        0,
        0,
    )? {
        return Ok(false);
    }
    let scope = lifecycle_volume_scope(operation);
    for (disposition, expected) in dispositions.iter().zip(&graph.config.volumes) {
        let Some(stored_volume) = graph
            .volumes
            .get(&expected.volume_id)
            .and_then(Option::as_ref)
        else {
            return Ok(false);
        };
        let volume = &stored_volume.record;
        let Some(disk) = graph.disks.get(&expected.disk_id).and_then(Option::as_ref) else {
            return Ok(false);
        };
        if !matches!(disk.admin_state, ProductDiskAdminState::Active) {
            return Ok(false);
        }
        match disposition {
            ColdVolumeDisposition::NormallyReleased {
                volume: terminal,
                normal_release_receipt_digest,
            } => {
                let Some(target) = lifecycle_volume_target(expected, terminal) else {
                    return Ok(false);
                };
                let Some(stored) = load_command_normal_release_receipt_for_update(
                    transaction,
                    &operation.operation_id,
                    &expected.volume_id,
                )?
                else {
                    return Ok(false);
                };
                if terminal.authority_receipt_digest.as_ref() != Some(normal_release_receipt_digest)
                    || !validate_stored_normal_release(
                        operation, None, &scope, &target, volume, terminal, &stored,
                    )
                {
                    return Ok(false);
                }
            }
            ColdVolumeDisposition::AlreadyUnowned {
                volume_id,
                disk_id,
                disk_role,
                unowned_epoch,
                remote_head,
                already_unowned_receipt_digest,
            } => {
                let identity = LifecycleVolumeIdentity {
                    volume_id: volume_id.clone(),
                    disk_id: disk_id.clone(),
                    disk_role: *disk_role,
                };
                if identity.volume_id != expected.volume_id
                    || identity.disk_id != expected.disk_id
                    || identity.disk_role != expected.disk_role
                {
                    return Ok(false);
                }
                let Some(stored) = load_command_already_unowned_receipt_for_update(
                    transaction,
                    &operation.operation_id,
                    &expected.volume_id,
                )?
                else {
                    return Ok(false);
                };
                if stored.receipt.expected_epoch != *unowned_epoch
                    || stored.receipt.expected_head != *remote_head
                    || !validate_stored_already_unowned(
                        operation,
                        None,
                        &scope,
                        &identity,
                        volume,
                        already_unowned_receipt_digest,
                        &stored,
                        AlreadyUnownedReceiptPolicy::Cold,
                    )
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn validate_deleted_terminal_receipts_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    runtime_config: &ImmutableRuntimeConfig,
    dispositions: &[CompletedVolumeDisposition],
) -> AuthorityTxResult<bool> {
    let LifecycleCommand::Delete(spec) = &operation.canonical_request.command else {
        return Err(corrupt("Deleted result belongs to a non-Delete Operation"));
    };
    if dispositions.len() != runtime_config.volumes.len() {
        return Ok(false);
    }

    let mut root: Option<DeleteRootTerminal<'_>> = None;
    let mut persistent = Vec::new();
    for (completed, expected) in dispositions.iter().zip(&runtime_config.volumes) {
        match (completed, expected.disk_role) {
            (
                CompletedVolumeDisposition::PersistentRetainedDetached {
                    volume,
                    normal_release_receipt_digest,
                },
                DiskRole::Persistent,
            ) => persistent.push((
                expected,
                PersistentDeleteTerminal::NormallyReleased {
                    volume: volume.as_ref(),
                    receipt_digest: normal_release_receipt_digest,
                },
            )),
            (
                CompletedVolumeDisposition::PersistentAlreadyDetached {
                    volume_id,
                    disk_id,
                    already_unowned_receipt_digest,
                },
                DiskRole::Persistent,
            ) if volume_id == &expected.volume_id && disk_id == &expected.disk_id => {
                persistent.push((
                    expected,
                    PersistentDeleteTerminal::AlreadyUnowned {
                        receipt_digest: already_unowned_receipt_digest,
                    },
                ));
            }
            (
                CompletedVolumeDisposition::RootNormallyDeleted {
                    volume,
                    delete_completion_receipt_digest,
                },
                DiskRole::Root,
            ) if root.is_none() => {
                let Some(target) = lifecycle_volume_target(expected, volume) else {
                    return Ok(false);
                };
                root = Some(DeleteRootTerminal::Normal {
                    target,
                    volume,
                    completion_digest: delete_completion_receipt_digest,
                });
            }
            (
                CompletedVolumeDisposition::RootAlreadyUnownedDeleted {
                    volume_id,
                    disk_id,
                    already_unowned_receipt_digest,
                    delete_completion_receipt_digest,
                },
                DiskRole::Root,
            ) if root.is_none()
                && volume_id == &expected.volume_id
                && disk_id == &expected.disk_id =>
            {
                root = Some(DeleteRootTerminal::AlreadyUnowned {
                    identity: LifecycleVolumeIdentity {
                        volume_id: volume_id.clone(),
                        disk_id: disk_id.clone(),
                        disk_role: DiskRole::Root,
                    },
                    already_unowned_digest: already_unowned_receipt_digest,
                    completion_digest: delete_completion_receipt_digest,
                });
            }
            (
                CompletedVolumeDisposition::RootDisposableTailDeleted {
                    volume_id,
                    disk_id,
                    previous_attachment_id,
                    previous_attachment_epoch,
                    disposable_authorization_id,
                    authorization_consumed_receipt_digest,
                    delete_completion_receipt_digest,
                    ..
                },
                DiskRole::Root,
            ) if root.is_none()
                && volume_id == &expected.volume_id
                && disk_id == &expected.disk_id =>
            {
                root = Some(DeleteRootTerminal::Disposable {
                    target: LifecycleVolumeTarget {
                        disk_id: disk_id.clone(),
                        disk_role: DiskRole::Root,
                        volume_id: volume_id.clone(),
                        attachment_id: previous_attachment_id.clone(),
                        attachment_epoch: *previous_attachment_epoch,
                    },
                    authorization_id: disposable_authorization_id,
                    authorization_consumed_digest: authorization_consumed_receipt_digest,
                    completion_digest: delete_completion_receipt_digest,
                });
            }
            _ => return Ok(false),
        }
    }
    let Some(root) = root else {
        return Ok(false);
    };
    let root_volume_id = root.identity().volume_id.clone();
    let Some(graph) = lock_runtime_volume_graph(
        transaction,
        &operation.workspace_id,
        &operation.cat_id,
        runtime_config,
        Some(&root_volume_id),
    )?
    else {
        return Ok(false);
    };

    let scope = lifecycle_volume_scope(operation);
    let expected_command = DeleteCommandVolumeSet {
        scope: scope.clone(),
        root_disposition: DefaultRootDiscardDisposition {
            root: root.identity(),
            delete_id: spec.delete_id.clone(),
        },
        persistent_volumes: persistent
            .iter()
            .map(|(expected, _)| LifecycleVolumeIdentity {
                disk_id: expected.disk_id.clone(),
                disk_role: expected.disk_role,
                volume_id: expected.volume_id.clone(),
            })
            .collect(),
    };

    // Validate the entire retained Persistent set first. Nothing in this
    // settlement path reads or trusts Root destructive authority before all
    // Persistent dispositions have closed exactly.
    let mut current_persistent_volumes = Vec::with_capacity(persistent.len());
    let mut persistent_release_receipts = Vec::with_capacity(persistent.len());
    for ((expected, terminal), expected_identity) in
        persistent.iter().zip(&expected_command.persistent_volumes)
    {
        let Some(stored_volume) = graph
            .volumes
            .get(&expected.volume_id)
            .and_then(Option::as_ref)
        else {
            return Ok(false);
        };
        let volume = &stored_volume.record;
        let Some(disk) = graph.disks.get(&expected.disk_id).and_then(Option::as_ref) else {
            return Ok(false);
        };
        if !matches!(disk.admin_state, ProductDiskAdminState::Active) {
            return Ok(false);
        }
        let stored_disposition = match terminal {
            PersistentDeleteTerminal::NormallyReleased {
                volume: terminal,
                receipt_digest,
            } => {
                let Some(target) = lifecycle_volume_target(expected, terminal) else {
                    return Ok(false);
                };
                if target.identity() != *expected_identity
                    || terminal.authority_receipt_digest.as_ref() != Some(*receipt_digest)
                {
                    return Ok(false);
                }
                let Some(stored) = load_command_normal_release_receipt_for_update(
                    transaction,
                    &operation.operation_id,
                    &expected.volume_id,
                )?
                else {
                    return Ok(false);
                };
                if !validate_stored_normal_release(
                    operation,
                    Some(&spec.delete_id),
                    &scope,
                    &target,
                    volume,
                    terminal,
                    &stored,
                ) {
                    return Ok(false);
                }
                CommandVolumeDispositionReceipt::NormallyReleased {
                    receipt: Box::new(stored.receipt),
                }
            }
            PersistentDeleteTerminal::AlreadyUnowned { receipt_digest } => {
                let Some(stored) = load_command_already_unowned_receipt_for_update(
                    transaction,
                    &operation.operation_id,
                    &expected.volume_id,
                )?
                else {
                    return Ok(false);
                };
                if !validate_stored_already_unowned(
                    operation,
                    Some(&spec.delete_id),
                    &scope,
                    expected_identity,
                    volume,
                    receipt_digest,
                    &stored,
                    AlreadyUnownedReceiptPolicy::Delete,
                ) {
                    return Ok(false);
                }
                CommandVolumeDispositionReceipt::AlreadyUnowned {
                    receipt: Box::new(stored.receipt),
                }
            }
        };
        current_persistent_volumes.push(volume.clone());
        persistent_release_receipts.push(stored_disposition);
    }
    let Ok(persistent_dispositions_digest) = persistent_delete_dispositions_digest(
        &expected_command,
        &current_persistent_volumes,
        &persistent_release_receipts,
    ) else {
        return Ok(false);
    };

    let expected_normal_count = persistent
        .iter()
        .filter(|(_, terminal)| {
            matches!(terminal, PersistentDeleteTerminal::NormallyReleased { .. })
        })
        .count()
        + usize::from(matches!(&root, DeleteRootTerminal::Normal { .. }));
    let expected_already_count = persistent
        .iter()
        .filter(|(_, terminal)| matches!(terminal, PersistentDeleteTerminal::AlreadyUnowned { .. }))
        .count()
        + usize::from(matches!(&root, DeleteRootTerminal::AlreadyUnowned { .. }));
    let expected_disposable_count =
        usize::from(matches!(&root, DeleteRootTerminal::Disposable { .. }));
    if !lifecycle_receipt_counts_match(
        transaction,
        &operation.operation_id,
        expected_normal_count,
        expected_already_count,
        expected_disposable_count,
        1,
    )? {
        return Ok(false);
    }

    let Some(stored_completion) = load_command_delete_completion_receipt_for_update(
        transaction,
        &operation.operation_id,
        &root_volume_id,
    )?
    else {
        return Ok(false);
    };
    if stored_completion.operation != *operation.canonical_request
        || stored_completion.delete_id != spec.delete_id
        || stored_completion.receipt.command != expected_command
    {
        return Ok(false);
    }
    let Some(generic_completion) = load_delete_completion_for_update(transaction, &spec.delete_id)?
    else {
        return Ok(false);
    };
    if generic_completion != stored_completion.receipt.completion {
        return Ok(false);
    }

    match root {
        DeleteRootTerminal::Normal {
            target,
            volume,
            completion_digest,
        } => validate_normally_deleted_root_in(
            transaction,
            operation,
            &spec.delete_id,
            &expected_command,
            &target,
            volume,
            completion_digest,
            &stored_completion.receipt,
            &stored_completion.receipt_digest,
        ),
        DeleteRootTerminal::AlreadyUnowned {
            identity,
            already_unowned_digest,
            completion_digest,
        } => validate_already_unowned_deleted_root_in(
            transaction,
            operation,
            &spec.delete_id,
            &expected_command,
            &identity,
            already_unowned_digest,
            completion_digest,
            &stored_completion.receipt,
            &stored_completion.receipt_digest,
        ),
        DeleteRootTerminal::Disposable {
            target,
            authorization_id,
            authorization_consumed_digest,
            completion_digest,
        } => validate_disposable_deleted_root_in(
            transaction,
            operation,
            &spec.delete_id,
            &expected_command,
            &target,
            authorization_id,
            authorization_consumed_digest,
            completion_digest,
            &persistent_dispositions_digest,
            &stored_completion.receipt,
            &stored_completion.receipt_digest,
        ),
    }
}

enum PersistentDeleteTerminal<'a> {
    NormallyReleased {
        volume: &'a VolumeTerminalReceipt,
        receipt_digest: &'a Sha256Digest,
    },
    AlreadyUnowned {
        receipt_digest: &'a Sha256Digest,
    },
}

enum DeleteRootTerminal<'a> {
    Normal {
        target: LifecycleVolumeTarget,
        volume: &'a VolumeTerminalReceipt,
        completion_digest: &'a Sha256Digest,
    },
    AlreadyUnowned {
        identity: LifecycleVolumeIdentity,
        already_unowned_digest: &'a Sha256Digest,
        completion_digest: &'a Sha256Digest,
    },
    Disposable {
        target: LifecycleVolumeTarget,
        authorization_id: &'a Id,
        authorization_consumed_digest: &'a Sha256Digest,
        completion_digest: &'a Sha256Digest,
    },
}

impl DeleteRootTerminal<'_> {
    fn identity(&self) -> LifecycleVolumeIdentity {
        match self {
            Self::Normal { target, .. } | Self::Disposable { target, .. } => target.identity(),
            Self::AlreadyUnowned { identity, .. } => identity.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_stored_normal_release(
    operation: &LifecycleOperation,
    expected_delete_id: Option<&Id>,
    scope: &LifecycleVolumeCommandScope,
    target: &LifecycleVolumeTarget,
    current_volume: &VolumeRecord,
    terminal: &VolumeTerminalReceipt,
    stored: &StoredCommandNormalReleaseReceipt,
) -> bool {
    let Ok(computed_digest) =
        command_normal_release_receipt_digest(scope, target, current_volume, &stored.receipt)
    else {
        return false;
    };
    stored.operation == *operation.canonical_request
        && stored.delete_id.as_ref() == expected_delete_id
        && stored.receipt_digest == computed_digest
        && normal_release_terminal_projection_matches(terminal, &stored.receipt, &computed_digest)
}

#[derive(Debug, Clone, Copy)]
enum AlreadyUnownedReceiptPolicy {
    Cold,
    Delete,
}

#[allow(clippy::too_many_arguments)]
fn validate_stored_already_unowned(
    operation: &LifecycleOperation,
    expected_delete_id: Option<&Id>,
    scope: &LifecycleVolumeCommandScope,
    identity: &LifecycleVolumeIdentity,
    current_volume: &VolumeRecord,
    terminal_digest: &Sha256Digest,
    stored: &StoredCommandAlreadyUnownedReceipt,
    policy: AlreadyUnownedReceiptPolicy,
) -> bool {
    let computed = match policy {
        AlreadyUnownedReceiptPolicy::Cold => command_cold_already_unowned_receipt_digest(
            scope,
            identity,
            current_volume,
            &stored.receipt,
        ),
        AlreadyUnownedReceiptPolicy::Delete => command_delete_already_unowned_receipt_digest(
            scope,
            identity,
            current_volume,
            &stored.receipt,
        ),
    };
    let Ok(computed) = computed else {
        return false;
    };
    stored.operation == *operation.canonical_request
        && stored.delete_id.as_ref() == expected_delete_id
        && stored.receipt.scope == *scope
        && stored.receipt.volume == *identity
        && stored.receipt_digest == computed
        && terminal_digest == &computed
}

fn normal_release_terminal_projection_matches(
    terminal: &VolumeTerminalReceipt,
    receipt: &cats_storage::lifecycle_volume::CommandNormalReleaseReceipt,
    computed_digest: &Sha256Digest,
) -> bool {
    let proof = &receipt.durability;
    terminal.volume_id == proof.volume.volume_id
        && terminal.disk_id == proof.volume.disk_id
        && terminal.disk_role == proof.volume.disk_role
        && terminal.attachment_id == proof.volume.attachment_id
        && terminal.attachment_epoch == proof.volume.attachment_epoch
        && terminal.local_durable_generation == proof.local_durable_generation
        && terminal.remote_durable_generation == proof.remote_durable_generation
        && proof.remote_head.generation == terminal.remote_durable_generation
        && terminal.authority_receipt_digest.as_ref() == Some(computed_digest)
}

#[allow(clippy::too_many_arguments)]
fn validate_normally_deleted_root_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    delete_id: &Id,
    expected_command: &DeleteCommandVolumeSet,
    target: &LifecycleVolumeTarget,
    terminal: &VolumeTerminalReceipt,
    terminal_completion_digest: &Sha256Digest,
    completion: &cats_storage::lifecycle_volume::CommandDeleteCompletionReceipt,
    stored_completion_digest: &Sha256Digest,
) -> AuthorityTxResult<bool> {
    let Some(stored_release) = load_command_normal_release_receipt_for_update(
        transaction,
        &operation.operation_id,
        &target.volume_id,
    )?
    else {
        return Ok(false);
    };
    let CommandRootDeleteAuthorityReceipt::NormalRelease(nested_release) =
        &completion.root_authority
    else {
        return Ok(false);
    };
    let Ok(normal_digest) =
        command_normal_release_receipt_digest_from_delete_completion(expected_command, completion)
    else {
        return Ok(false);
    };
    let Ok(completion_digest) =
        command_delete_completion_receipt_digest(expected_command, None, None, completion)
    else {
        return Ok(false);
    };
    Ok(stored_release.operation == *operation.canonical_request
        && stored_release.delete_id.as_ref() == Some(delete_id)
        && stored_release.receipt == *nested_release
        && stored_release.receipt_digest == normal_digest
        && normal_release_terminal_projection_matches(terminal, nested_release, &normal_digest)
        && completion_digest == *stored_completion_digest
        && completion_digest == *terminal_completion_digest)
}

#[allow(clippy::too_many_arguments)]
fn validate_already_unowned_deleted_root_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    delete_id: &Id,
    expected_command: &DeleteCommandVolumeSet,
    identity: &LifecycleVolumeIdentity,
    terminal_already_digest: &Sha256Digest,
    terminal_completion_digest: &Sha256Digest,
    completion: &cats_storage::lifecycle_volume::CommandDeleteCompletionReceipt,
    stored_completion_digest: &Sha256Digest,
) -> AuthorityTxResult<bool> {
    let Some(stored_already) = load_command_already_unowned_receipt_for_update(
        transaction,
        &operation.operation_id,
        &identity.volume_id,
    )?
    else {
        return Ok(false);
    };
    let CommandRootDeleteAuthorityReceipt::AlreadyUnowned(nested_already) =
        &completion.root_authority
    else {
        return Ok(false);
    };
    let Ok(already_digest) = command_delete_already_unowned_receipt_digest_from_delete_completion(
        expected_command,
        completion,
    ) else {
        return Ok(false);
    };
    let Ok(completion_digest) =
        command_delete_completion_receipt_digest(expected_command, None, None, completion)
    else {
        return Ok(false);
    };
    Ok(stored_already.operation == *operation.canonical_request
        && stored_already.delete_id.as_ref() == Some(delete_id)
        && stored_already.receipt.volume == *identity
        && stored_already.receipt == *nested_already
        && stored_already.receipt_digest == already_digest
        && already_digest == *terminal_already_digest
        && completion_digest == *stored_completion_digest
        && completion_digest == *terminal_completion_digest)
}

#[allow(clippy::too_many_arguments)]
fn validate_disposable_deleted_root_in(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleOperation,
    delete_id: &Id,
    expected_command: &DeleteCommandVolumeSet,
    target: &LifecycleVolumeTarget,
    authorization_id: &Id,
    terminal_consumed_digest: &Sha256Digest,
    terminal_completion_digest: &Sha256Digest,
    expected_persistent_dispositions_digest: &Sha256Digest,
    completion: &cats_storage::lifecycle_volume::CommandDeleteCompletionReceipt,
    stored_completion_digest: &Sha256Digest,
) -> AuthorityTxResult<bool> {
    let Some(stored_consumed) = load_command_disposable_authorization_consumed_receipt_for_update(
        transaction,
        &operation.operation_id,
        &target.volume_id,
    )?
    else {
        return Ok(false);
    };
    let Some(authorization) = load_authorization_for_update(transaction, authorization_id)? else {
        return Ok(false);
    };
    let bound_authorization = CommandBoundDisposableRootAuthorization {
        scope: expected_command.scope.clone(),
        authorization,
    };
    let VolumeAuthorization::DisposableRootDelete(authorization) =
        &bound_authorization.authorization.authorization
    else {
        return Ok(false);
    };
    if authorization.persistent_dispositions_digest != *expected_persistent_dispositions_digest {
        return Ok(false);
    }
    let CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(nested_consumed) =
        &completion.root_authority
    else {
        return Ok(false);
    };
    let Ok(consumed_digest) =
        command_disposable_authorization_consumed_receipt_digest_from_delete_completion(
            expected_command,
            &bound_authorization,
            completion,
        )
    else {
        return Ok(false);
    };
    let Ok(completion_digest) = command_delete_completion_receipt_digest(
        expected_command,
        None,
        Some(&bound_authorization),
        completion,
    ) else {
        return Ok(false);
    };
    Ok(stored_consumed.operation == *operation.canonical_request
        && stored_consumed.delete_id == *delete_id
        && stored_consumed.receipt == *nested_consumed
        && stored_consumed.receipt.authorization_id == *authorization_id
        && stored_consumed.receipt_digest == consumed_digest
        && consumed_digest == *terminal_consumed_digest
        && completion_digest == *stored_completion_digest
        && completion_digest == *terminal_completion_digest)
}

fn lifecycle_receipt_counts_match(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    normal_release: usize,
    already_unowned: usize,
    disposable_consumed: usize,
    delete_completion: usize,
) -> AuthorityTxResult<bool> {
    let row = transaction.query_one(
        "SELECT
            count(*) FILTER (WHERE receipt_kind='normal_release'),
            count(*) FILTER (WHERE receipt_kind='already_unowned'),
            count(*) FILTER (WHERE receipt_kind='disposable_consumed'),
            count(*) FILTER (WHERE receipt_kind='delete_completion'),
            count(*)
           FROM lifecycle_volume_receipts WHERE operation_id=$1",
        &[&operation_id.as_str()],
    )?;
    let normal: i64 = row.try_get(0)?;
    let already: i64 = row.try_get(1)?;
    let disposable: i64 = row.try_get(2)?;
    let completion: i64 = row.try_get(3)?;
    let total: i64 = row.try_get(4)?;
    let expected_total = normal_release
        .checked_add(already_unowned)
        .and_then(|count| count.checked_add(disposable_consumed))
        .and_then(|count| count.checked_add(delete_completion))
        .ok_or_else(|| corrupt("lifecycle receipt count overflow"))?;
    Ok(usize::try_from(normal).ok() == Some(normal_release)
        && usize::try_from(already).ok() == Some(already_unowned)
        && usize::try_from(disposable).ok() == Some(disposable_consumed)
        && usize::try_from(completion).ok() == Some(delete_completion)
        && usize::try_from(total).ok() == Some(expected_total))
}

fn update_cat_projection(
    transaction: &mut Transaction<'_>,
    cat: &CatLifecycleProjection,
    operation: &LifecycleOperation,
    result: &LifecycleCommandResponse,
    terminal_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let (stable, effective, incarnation, deleted_at) = match &result.result {
        NodeResult::RuntimeReady(runtime_ready) => (
            Some(LifecycleStableState::Running),
            Some(operation.operation_id.as_str()),
            Some(runtime_ready.runtime_incarnation.as_str()),
            None,
        ),
        NodeResult::SuspendDeclined(_) => (
            Some(LifecycleStableState::Running),
            cat.effective_runtime_ready_operation_id
                .as_ref()
                .map(Id::as_str),
            cat.runtime_incarnation.as_ref().map(RandomId128::as_str),
            None,
        ),
        NodeResult::Suspended(suspended) => (
            Some(LifecycleStableState::Suspended),
            None,
            Some(suspended.runtime_incarnation.as_str()),
            None,
        ),
        NodeResult::Warm(_) => (Some(LifecycleStableState::Warm), None, None, None),
        NodeResult::Cold(_) => (Some(LifecycleStableState::Cold), None, None, None),
        NodeResult::Deleted(_) => (None, None, None, Some(terminal_at)),
        NodeResult::Killed(_)
        | NodeResult::NeedsIntervention(_)
        | NodeResult::StartFailed(_)
        | NodeResult::SuspendFailed(_)
        | NodeResult::WarmFailed(_) => (None, None, None, None),
    };
    let terminal_at_pg = deleted_at
        .map(PgBigInt::to_pg)
        .transpose()
        .map_err(corrupt)?;
    let stable = stable.map(LifecycleStableState::as_str);
    let updated = transaction.execute(
        "UPDATE cat_records
            SET lifecycle_head_operation_id=$2, stable_state=$3,
                effective_runtime_ready_operation_id=$4,
                runtime_incarnation=$5, deleted_at=$6
          WHERE cat_id=$1 AND deleted_at IS NULL",
        &[
            &operation.cat_id.as_str(),
            &operation.operation_id.as_str(),
            &stable,
            &effective,
            &incarnation,
            &terminal_at_pg,
        ],
    )?;
    if updated != 1 {
        return Err(corrupt(
            "exact Cat lifecycle projection update changed no row",
        ));
    }
    Ok(())
}

fn result_stored_ack(
    response: &LifecycleCommandResponse,
    terminal_result_digest: &Sha256Digest,
) -> AuthorityTxResult<LifecycleResultStoredAck> {
    let acknowledgement = LifecycleResultStoredAck {
        version: ContractVersion::V1,
        node_id: response.node_id.clone(),
        cat_id: response.cat_id.clone(),
        operation_id: response.operation_id.clone(),
        request_fingerprint: response.request_fingerprint.clone(),
        terminal_result_digest: terminal_result_digest.clone(),
    };
    validate_lifecycle_result_stored_ack_for_response(&acknowledgement, response)
        .map_err(corrupt)?;
    Ok(acknowledgement)
}

struct PredecessorProjection {
    kind: &'static str,
    result_kind: Option<String>,
    result_digest: Option<String>,
}

fn predecessor_projection(request: &LifecycleCommandEnvelope) -> PredecessorProjection {
    match &request.predecessor {
        LifecyclePredecessor::Genesis { .. } => PredecessorProjection {
            kind: "genesis",
            result_kind: None,
            result_digest: None,
        },
        LifecyclePredecessor::SameNode {
            terminal_result_kind,
            terminal_result_digest,
            ..
        } => PredecessorProjection {
            kind: "same_node",
            result_kind: Some(terminal_kind_text(*terminal_result_kind).to_owned()),
            result_digest: Some(terminal_result_digest.to_string()),
        },
        LifecyclePredecessor::CrossNodeColdHandoff {
            cold_result_digest, ..
        } => PredecessorProjection {
            kind: "cross_node_cold_handoff",
            result_kind: Some("cold".to_owned()),
            result_digest: Some(cold_result_digest.to_string()),
        },
        LifecyclePredecessor::HostFenceRecovery {
            host_lost_result_digest,
            ..
        } => PredecessorProjection {
            kind: "host_fence_recovery",
            result_kind: Some("host_lost".to_owned()),
            result_digest: Some(host_lost_result_digest.to_string()),
        },
    }
}

const fn command_kind_text(kind: LifecycleCommandKind) -> &'static str {
    match kind {
        LifecycleCommandKind::Start => "start",
        LifecycleCommandKind::Suspend => "suspend",
        LifecycleCommandKind::Warm => "warm",
        LifecycleCommandKind::Cold => "cold",
        LifecycleCommandKind::Stop => "stop",
        LifecycleCommandKind::Delete => "delete",
    }
}

fn parse_command_kind(value: &str) -> AuthorityTxResult<LifecycleCommandKind> {
    match value {
        "start" => Ok(LifecycleCommandKind::Start),
        "suspend" => Ok(LifecycleCommandKind::Suspend),
        "warm" => Ok(LifecycleCommandKind::Warm),
        "cold" => Ok(LifecycleCommandKind::Cold),
        "stop" => Ok(LifecycleCommandKind::Stop),
        "delete" => Ok(LifecycleCommandKind::Delete),
        _ => Err(corrupt(
            "stored lifecycle command kind is outside the closed set",
        )),
    }
}

const fn terminal_kind_text(kind: TerminalResultKind) -> &'static str {
    match kind {
        TerminalResultKind::RuntimeReady => "runtime_ready",
        TerminalResultKind::Suspended => "suspended",
        TerminalResultKind::SuspendDeclined => "suspend_declined",
        TerminalResultKind::Warm => "warm",
        TerminalResultKind::Cold => "cold",
        TerminalResultKind::Killed => "killed",
        TerminalResultKind::Deleted => "deleted",
        TerminalResultKind::NeedsIntervention => "needs_intervention",
        TerminalResultKind::StartFailed => "start_failed",
        TerminalResultKind::SuspendFailed => "suspend_failed",
        TerminalResultKind::WarmFailed => "warm_failed",
        TerminalResultKind::HostLost => "host_lost",
    }
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored identifier is invalid"))
}

fn parse_random_id(value: String) -> AuthorityTxResult<RandomId128> {
    RandomId128::new(value).ok_or_else(|| corrupt("stored random identifier is invalid"))
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored SHA-256 digest is invalid"))
}

fn corrupt(error: impl std::fmt::Display) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(internal(format!(
        "atomic lifecycle authority invariant failed: {error}"
    )))
}

#[cfg(test)]
fn corrupt_api(error: impl std::fmt::Display) -> crate::store::ApiError {
    internal(format!(
        "atomic lifecycle authority invariant failed before transaction: {error}"
    ))
}

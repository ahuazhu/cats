//! A22 authorization response-loss evidence from one caller-owned snapshot.
//!
//! The HTTP/A19 composition owns identity and current-session admission. Once
//! that prefix has locked the exact authenticated identity lineage for share,
//! this module performs the only authorization/completion lookup available to
//! a Node. It never accepts a volume, delete, receipt, or successor key.

use cats_api::runtime_reconciliation::{
    encode_runtime_volume_transition_evidence_success, AuthorizationConsumedReceipt,
    AuthorizationRecord, AuthorizationState, ContractVersion, Id, LastVolumeTransition,
    RuntimeVolumeTransitionError, RuntimeVolumeTransitionErrorDetail,
    RuntimeVolumeTransitionEvidenceRequest, RuntimeVolumeTransitionEvidenceSuccess, UnixMillis,
    VolumeAuthorization,
};
use cats_storage::authority::{
    validate_volume_transition_evidence_bundle, DeleteCompletionReceipt, VolumeRecord,
};

use super::rows::{
    load_authorization_for_evidence, load_authorization_unlocked,
    load_delete_completions_by_volume, load_volume_unlocked,
};
use super::volume_transition_auth::EvidenceTransactionContext;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolumeTransitionEvidenceLoad {
    Available(Box<RuntimeVolumeTransitionEvidenceSuccess>),
    Unavailable { authorization_id: Id },
}

pub(crate) fn authorization_evidence_unavailable(
    authorization_id: Id,
) -> RuntimeVolumeTransitionError {
    RuntimeVolumeTransitionError {
        version: ContractVersion::V1,
        error: Box::new(
            RuntimeVolumeTransitionErrorDetail::AuthorizationEvidenceUnavailable {
                authorization_id,
            },
        ),
        message: "authorization evidence is unavailable".to_owned(),
    }
}

/// Loads one complete bundle in the caller's repeatable-read transaction.
///
/// The caller must already have validated the exact current SessionBinding and
/// must pass the node id derived from its authenticated, provisioned identity,
/// plus the single database time read used by that validation prefix.
/// Keeping this transaction-local prevents a future transport adapter from
/// composing independently read rows or accidentally opening a second
/// authority.
pub(super) fn load_volume_transition_evidence_in(
    context: EvidenceTransactionContext<'_, '_>,
    request: &RuntimeVolumeTransitionEvidenceRequest,
) -> AuthorityTxResult<VolumeTransitionEvidenceLoad> {
    let (transaction, authenticated_node_id, db_now) = context.into_parts();
    if request.session.node_id != authenticated_node_id {
        // The unforgeable context already bound the exact current session.
        // Treat any impossible mismatch at this seam as stored/programming
        // corruption before touching the protected authorization predicate.
        return Err(corrupt());
    }
    let Some(primary) = load_authorization_for_evidence(
        transaction,
        &request.authorization_id,
        &authenticated_node_id,
    )?
    else {
        return Ok(VolumeTransitionEvidenceLoad::Unavailable {
            authorization_id: request.authorization_id.clone(),
        });
    };
    if authorization_id(&primary) != &request.authorization_id
        || authorized_node_id(&primary) != &authenticated_node_id
    {
        return Err(corrupt());
    }

    let volume_id = authorization_volume_id(&primary);
    let current_volume = load_volume_unlocked(transaction, volume_id)?;
    let mut completions = load_delete_completions_by_volume(transaction, volume_id)?;
    if completions.len() > 1 {
        return Err(corrupt());
    }
    let delete_completion = completions.pop();
    if current_volume.is_some() && delete_completion.is_some() {
        return Err(corrupt());
    }

    let direct_id = direct_successor_id(current_volume.as_ref(), delete_completion.as_ref())?;
    let direct_successor_authorization = match direct_id {
        Some(id) if id != &request.authorization_id => {
            Some(load_authorization_unlocked(transaction, id)?.ok_or_else(corrupt)?)
        }
        _ => None,
    };

    validate_volume_transition_evidence_bundle(
        &primary,
        current_volume.as_ref(),
        delete_completion.as_ref(),
        direct_successor_authorization.as_ref(),
    )
    .map_err(AuthorityTransactionError::from)?;
    validate_evidence_times(
        &primary,
        delete_completion.as_ref(),
        direct_successor_authorization.as_ref(),
        db_now,
    )?;

    let response = RuntimeVolumeTransitionEvidenceSuccess {
        version: ContractVersion::V1,
        session: request.session.clone(),
        authorization_id: request.authorization_id.clone(),
        authorization: primary,
        current_volume,
        delete_completion,
        direct_successor_authorization,
    };
    // The canonical encoder is the final size and closed-contract guard. An
    // over-cap bundle is persisted-state corruption, never a partial page.
    encode_runtime_volume_transition_evidence_success(&response).map_err(|_| corrupt())?;
    Ok(VolumeTransitionEvidenceLoad::Available(Box::new(response)))
}

fn validate_evidence_times(
    primary: &AuthorizationRecord,
    completion: Option<&DeleteCompletionReceipt>,
    direct: Option<&AuthorizationRecord>,
    db_now: UnixMillis,
) -> AuthorityTxResult<()> {
    if authorization_consumed_at(primary).is_some_and(|time| time > db_now)
        || direct
            .and_then(authorization_consumed_at)
            .is_some_and(|time| time > db_now)
        || completion
            .map(delete_completion_time)
            .is_some_and(|time| time > db_now)
    {
        return Err(corrupt());
    }
    Ok(())
}

fn authorization_consumed_at(record: &AuthorizationRecord) -> Option<UnixMillis> {
    let AuthorizationState::Consumed(receipt) = &record.state else {
        return None;
    };
    Some(match receipt.as_ref() {
        AuthorizationConsumedReceipt::Takeover(receipt) => receipt.consumed_at,
        AuthorizationConsumedReceipt::BeginDisposableDelete(receipt) => receipt.consumed_at,
    })
}

fn delete_completion_time(receipt: &DeleteCompletionReceipt) -> UnixMillis {
    match receipt {
        DeleteCompletionReceipt::Normal { completed_at, .. }
        | DeleteCompletionReceipt::DisposableRoot { completed_at, .. } => *completed_at,
    }
}

fn authorization_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.authorization_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => &authorization.authorization_id,
    }
}

fn authorized_node_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.authorized_node_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            &authorization.authorized_node_id
        }
    }
}

fn authorization_volume_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.volume_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => &authorization.volume_id,
    }
}

fn direct_successor_id<'a>(
    current_volume: Option<&'a VolumeRecord>,
    delete_completion: Option<&'a DeleteCompletionReceipt>,
) -> AuthorityTxResult<Option<&'a Id>> {
    let current_marker = current_volume.and_then(|record| match &record.last_transition {
        Some(LastVolumeTransition::Takeover { authorization_id })
        | Some(LastVolumeTransition::BeginDisposableDelete { authorization_id }) => {
            Some(authorization_id)
        }
        _ => None,
    });
    let completion_marker = delete_completion.and_then(|receipt| match receipt {
        DeleteCompletionReceipt::Normal { .. } => None,
        DeleteCompletionReceipt::DisposableRoot {
            authorization_id, ..
        } => Some(authorization_id),
    });
    match (current_marker, completion_marker) {
        (Some(left), Some(right)) if left != right => Err(corrupt()),
        (Some(id), _) | (_, Some(id)) => Ok(Some(id)),
        (None, None) => Ok(None),
    }
}

fn corrupt() -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

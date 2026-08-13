//! Exact, read-only authority qualification for one retained local lineage.
//!
//! The caller owns the authenticated current-session prefix and a single
//! repeatable-read PostgreSQL snapshot.  This module neither enumerates local
//! hints nor performs physical cleanup; it returns only the closed proof that
//! a descriptor-retained Node reclaimer may validate independently.

use cats_api::runtime_reconciliation::{
    encode_runtime_residue_authority_success, AuthorizationConsumedReceipt, AuthorizationRecord,
    AuthorizationState, ContractVersion, DeleteCompletionReceipt, RuntimeResidueAuthorityRequest,
    RuntimeResidueAuthoritySuccess, UnixMillis,
};
use cats_storage::authority::classify_residue_reclaim_authority;

use super::rows::{
    load_authorization_unlocked, load_delete_completions_by_volume, load_volume_unlocked,
};
use super::volume_transition_auth::EvidenceTransactionContext;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

pub(super) fn load_runtime_residue_authority_in(
    context: EvidenceTransactionContext<'_, '_>,
    request: &RuntimeResidueAuthorityRequest,
) -> AuthorityTxResult<Box<RuntimeResidueAuthoritySuccess>> {
    let (transaction, authenticated_node_id, db_now) = context.into_parts();
    if request.session.node_id != authenticated_node_id
        || request.lineage.node_id != authenticated_node_id
    {
        return Err(corrupt());
    }

    let current_volume = load_volume_unlocked(transaction, &request.lineage.volume_id)?;
    let mut completions =
        load_delete_completions_by_volume(transaction, &request.lineage.volume_id)?;
    if completions.len() > 1 || current_volume.is_some() && !completions.is_empty() {
        return Err(corrupt());
    }
    let delete_completion = completions.pop();
    let consumed_authorization = match &delete_completion {
        Some(DeleteCompletionReceipt::DisposableRoot {
            authorization_id, ..
        }) => load_authorization_unlocked(transaction, authorization_id)?,
        Some(DeleteCompletionReceipt::Normal { .. }) | None => None,
    };
    if delete_completion
        .as_ref()
        .is_some_and(|receipt| completion_time(receipt) > db_now)
        || consumed_authorization
            .as_ref()
            .and_then(authorization_consumed_at)
            .is_some_and(|time| time > db_now)
    {
        return Err(corrupt());
    }

    let outcome = classify_residue_reclaim_authority(
        &request.lineage,
        current_volume.as_ref(),
        delete_completion.as_ref(),
        consumed_authorization.as_ref(),
    )
    .map_err(AuthorityTransactionError::from)?;
    let response = RuntimeResidueAuthoritySuccess {
        version: ContractVersion::V1,
        session: request.session.clone(),
        lineage: request.lineage.clone(),
        outcome,
    };
    encode_runtime_residue_authority_success(&response).map_err(|_| corrupt())?;
    Ok(Box::new(response))
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

fn completion_time(receipt: &DeleteCompletionReceipt) -> UnixMillis {
    match receipt {
        DeleteCompletionReceipt::Normal { completed_at, .. }
        | DeleteCompletionReceipt::DisposableRoot { completed_at, .. } => *completed_at,
    }
}

fn corrupt() -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

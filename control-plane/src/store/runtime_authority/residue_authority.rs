//! Exact, read-only authority qualification for one retained local lineage.
//!
//! The caller owns the authenticated current-session prefix and a single
//! repeatable-read PostgreSQL snapshot.  This module neither enumerates local
//! hints nor performs physical cleanup; it returns only the closed proof that
//! a descriptor-retained Node reclaimer may validate independently.

use cats_api::runtime_reconciliation::{
    encode_runtime_residue_authority_success, AuthorizationConsumedReceipt, AuthorizationRecord,
    AuthorizationState, AuthorizedServingAcquire, ContractVersion, DeleteCompletionReceipt,
    DiskKind, RuntimeResidueAuthorityRequest, RuntimeResidueAuthoritySuccess, UnixMillis,
    VolumeAcquire,
};
use cats_storage::authority::classify_residue_reclaim_authority;

use super::product::{DiskRecord, DiskRole};
use super::product_rows::{load_desired_unlocked, load_disk_by_id_unlocked};
use super::rows::{
    load_authorization_unlocked, load_delete_completions_by_volume, load_volume_unlocked,
};
use super::volume_transition_auth::EvidenceTransactionContext;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

/// This entire Proposed Store/API seam stays mechanically unavailable until
/// the reclamation contract is accepted. Tests exercise the inner read-only
/// transaction function directly; production entrypoints check this constant.
pub(super) const PROPOSED_RESIDUE_AUTHORITY_ENABLED: bool = false;

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

    let desired =
        load_desired_unlocked(transaction, &request.lineage.cat_id)?.ok_or_else(corrupt)?;
    let disk = load_disk_by_id_unlocked(transaction, &request.lineage.disk_id)?;

    let current_volume = load_volume_unlocked(transaction, &request.lineage.volume_id)?;
    let mut completions =
        load_delete_completions_by_volume(transaction, &request.lineage.volume_id)?;
    if completions.len() > 1 || current_volume.is_some() && !completions.is_empty() {
        return Err(corrupt());
    }
    let delete_completion = completions.pop();
    if !request_matches_control_snapshot(
        request,
        &desired,
        disk.as_ref(),
        delete_completion.as_ref(),
    ) {
        // Every cross-workspace, cross-Cat and missing/mismatched product
        // coordinate closes through the same error. This read-only seam must
        // not become a metadata-existence oracle. A completed deletion may
        // have atomically removed its Disk/Volume rows; in that state the
        // exact Desired intent plus the typed completion is the retained Disk
        // binding from this same repeatable-read snapshot.
        return Err(corrupt());
    }
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

fn request_matches_control_snapshot(
    request: &RuntimeResidueAuthorityRequest,
    desired: &cats_api::runtime_reconciliation::DesiredRuntimeSpec,
    disk: Option<&DiskRecord>,
    delete_completion: Option<&DeleteCompletionReceipt>,
) -> bool {
    let lineage = &request.lineage;
    if desired.workspace_id != lineage.workspace_id
        || desired.cat_id != lineage.cat_id
        || desired.desired_revision != lineage.desired_revision
        || desired.spec_digest != lineage.spec_digest
        || desired.placement != lineage.placement
    {
        return false;
    }
    let Some(intent) = desired.volumes.iter().find(|intent| {
        intent.disk_id == lineage.disk_id
            && intent.volume_id == lineage.volume_id
            && intent.disk_kind == lineage.disk_kind
            && intent.attachment_id == lineage.attachment_id
    }) else {
        return false;
    };
    let disk_is_exact = disk.is_some_and(|disk| {
        disk.disk_id == lineage.disk_id
            && disk.workspace_id == lineage.workspace_id
            && disk.volume_id == lineage.volume_id
            && (matches!(
                (&disk.role, lineage.disk_kind),
                (DiskRole::Root { cat_id }, DiskKind::Root) if cat_id == &lineage.cat_id
            ) || matches!(
                (&disk.role, lineage.disk_kind),
                (DiskRole::Persistent { .. }, DiskKind::Persistent)
            ))
    });
    let completed_disk_is_exact = disk.is_none()
        && delete_completion.is_some_and(|completion| match completion {
            DeleteCompletionReceipt::Normal { request, .. } => {
                request.disk_id == lineage.disk_id && request.volume_id == lineage.volume_id
            }
            DeleteCompletionReceipt::DisposableRoot {
                disk_id, volume_id, ..
            } => disk_id == &lineage.disk_id && volume_id == &lineage.volume_id,
        });
    if !disk_is_exact && !completed_disk_is_exact {
        return false;
    }
    match (&intent.acquire, &lineage.acquisition) {
        (
            VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            },
            AuthorizedServingAcquire::Normal { request, .. },
        ) => {
            transition_id == &request.transition_id
                && expected_unowned_epoch == &request.expected_unowned_epoch
        }
        (
            VolumeAcquire::Takeover { authorization_id },
            AuthorizedServingAcquire::Takeover { authorization, .. },
        ) => authorization_id == &authorization.authorization_id,
        _ => false,
    }
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

//! Normal single-volume authority transactions.

use cats_storage::authority::{
    normal_acquire, release, renew_lease, replay_normal_acquire, AuthorityError, Id,
    NormalAcquireRequest, NormalAcquireResult, ReleaseRequest, ReleaseResult, RenewLeaseRequest,
    RenewLeaseResult, VolumeOwnerBinding,
};

use super::rows::{
    database_now, load_stored_volume_for_update, load_volume_for_update, update_volume,
    update_volume_owner,
};
use crate::store::Store;

impl Store {
    /// Performs one exact `Active + Unowned -> Owned` transition.
    ///
    /// Async callers submit this complete method through [`Store::execute`];
    /// it never performs object-store, filesystem, network, or sleep work
    /// while its PostgreSQL transaction is open.
    pub fn acquire_volume_authority(
        &self,
        owner_node_id: &Id,
        request: &NormalAcquireRequest,
    ) -> crate::store::Result<NormalAcquireResult> {
        self.authority_transaction(|transaction| {
            let current = load_stored_volume_for_update(transaction, &request.volume_id)?
                .ok_or(AuthorityError::NotFound)?;
            if let Some(result) = replay_normal_acquire(&current.record, request)? {
                if current
                    .owner_binding
                    .as_ref()
                    .is_none_or(|binding| binding.owner_node_id != *owner_node_id)
                {
                    return Err(AuthorityError::BackendUnknown.into());
                }
                return Ok(result);
            }
            let db_now = database_now(transaction)?;
            let (updated, result) = normal_acquire(&current.record, request, db_now)?;
            if updated != current.record {
                let owner_binding = VolumeOwnerBinding {
                    volume_id: updated.volume_id.clone(),
                    owner_node_id: owner_node_id.clone(),
                    attachment_id: result.attachment_id.clone(),
                    attachment_epoch: result.resulting_epoch,
                };
                update_volume_owner(transaction, &updated, Some(&owner_binding))?;
            }
            Ok(result)
        })
    }

    /// Renews only the exact current owner/epoch. Expiry lapse alone is not a
    /// fencing transition.
    pub fn renew_volume_authority(
        &self,
        request: &RenewLeaseRequest,
    ) -> crate::store::Result<RenewLeaseResult> {
        self.authority_transaction(|transaction| {
            let current = load_volume_for_update(transaction, &request.volume_id)?
                .ok_or(AuthorityError::NotFound)?;
            let db_now = database_now(transaction)?;
            let (updated, result) = renew_lease(&current, request, db_now)?;
            update_volume(transaction, &updated)?;
            Ok(result)
        })
    }

    /// Releases only the exact current owner/epoch and advances the fencing
    /// epoch in the same transaction as the closed replay result.
    pub fn release_volume_authority(
        &self,
        request: &ReleaseRequest,
    ) -> crate::store::Result<ReleaseResult> {
        self.authority_transaction(|transaction| {
            let current = load_stored_volume_for_update(transaction, &request.volume_id)?
                .ok_or(AuthorityError::NotFound)?;
            let (updated, result) = release(&current.record, request)?;
            if updated != current.record {
                update_volume_owner(transaction, &updated, None)?;
            }
            Ok(result)
        })
    }
}

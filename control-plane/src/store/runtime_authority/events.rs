//! Host-fence-backed takeover transaction.

use cats_storage::authority::{
    consume_takeover, replay_consumed_takeover, AuthorityError, TakeoverResult, VolumeAuthorization,
};

use super::rows::{
    authorization_hint, database_now, load_authorization_for_update, load_event_for_update,
    load_volume_for_update, update_authorization, update_volume,
};
use crate::store::Store;

impl Store {
    /// Consumes one server-side takeover authorization.
    ///
    /// The transaction locks `HostFenceEvent -> AuthorizationRecord ->
    /// VolumeRecord`. A consumed authorization replays its immutable receipt
    /// without requiring the volume to remain in the direct takeover state.
    pub fn consume_volume_takeover(
        &self,
        authorization_id: &cats_storage::authority::Id,
    ) -> crate::store::Result<TakeoverResult> {
        self.authority_transaction(|transaction| {
            // This is a non-locking routing hint. The closed row is decoded and
            // rechecked after the event lock and before any mutation.
            let (event_hint, volume_hint) = authorization_hint(transaction, authorization_id)?
                .ok_or(AuthorityError::InvalidAuthorization)?;
            let event_id = event_hint.ok_or(AuthorityError::InvalidAuthorization)?;

            let event = load_event_for_update(transaction, &event_id)?
                .ok_or(AuthorityError::BackendUnknown)?;
            let authorization = load_authorization_for_update(transaction, authorization_id)?
                .ok_or(AuthorityError::InvalidAuthorization)?;
            let VolumeAuthorization::Takeover(payload) = &authorization.authorization else {
                return Err(AuthorityError::InvalidAuthorization.into());
            };
            if payload.host_fence_event_id != event.event_id || payload.volume_id != volume_hint {
                return Err(AuthorityError::BackendUnknown.into());
            }

            if let Some(result) = replay_consumed_takeover(&authorization, authorization_id)? {
                return Ok(result);
            }

            let volume = load_volume_for_update(transaction, &payload.volume_id)?
                .ok_or(AuthorityError::InvalidAuthorization)?;
            let db_now = database_now(transaction)?;
            let (updated_volume, updated_authorization, result) =
                consume_takeover(&volume, &event, &authorization, authorization_id, db_now)?;
            update_volume(transaction, &updated_volume)?;
            update_authorization(transaction, &authorization, &updated_authorization)?;
            Ok(result)
        })
    }
}

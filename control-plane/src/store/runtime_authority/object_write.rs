//! PostgreSQL authority for attachment-scoped object-write credentials.
//!
//! The Node A19 key authenticates registration only. The attachment public
//! key is stored after proof of possession; its private key never enters
//! Control. Parent cutoff and child retirement commit in one transaction.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ApiError;
use cats_api::object_write_gateway::{
    ObjectWriteCredentialReference, ObjectWriteCredentialRegistration,
    ObjectWriteCredentialRegistrationReceipt,
};
use cats_api::runtime_reconciliation::{
    ContractVersion, CredentialBinding, Id, NodeIdentityState, UnixMillis,
};
use cats_storage::object_write_authority::{
    begin_object_writer_cutoff, register_object_write_credential, validate_object_write_authority,
    validate_object_write_credential, ObjectWriteAuthority, ObjectWriteAuthorityState,
    ObjectWriteCredentialBinding, ObjectWriteCredentialRetirementCause, ObjectWriteCredentialState,
};
use postgres::Transaction;

use super::rows::database_now;
use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_credential_for_update,
    lock_exact_credential_lineage, CredentialLineageState,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::Store;

fn application(error: ApiError) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(error)
}

fn corrupt(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

fn encode<T: serde::Serialize>(value: &T) -> AuthorityTxResult<String> {
    serde_json::to_string(value)
        .map_err(|error| corrupt(format!("encode object-write authority row: {error}")))
}

fn decode<T: serde::de::DeserializeOwned>(value: String) -> AuthorityTxResult<T> {
    serde_json::from_str(&value)
        .map_err(|error| corrupt(format!("decode object-write authority row: {error}")))
}

fn pg(value: u64) -> AuthorityTxResult<i64> {
    i64::try_from(value).map_err(|_| corrupt("object-write integer exceeds PostgreSQL BIGINT"))
}

fn authenticated_attachment_reference(
    authenticated: &AuthenticatedNodeCredential,
) -> AuthorityTxResult<ObjectWriteCredentialReference> {
    let CredentialBinding::PublicKey {
        public_key_spki_sha256,
    } = authenticated.binding()
    else {
        return Err(application(ApiError::unauthenticated(
            "object-write credential proof must be Ed25519",
        )));
    };
    Ok(ObjectWriteCredentialReference {
        credential_id: authenticated.credential_id().clone(),
        public_key_spki_sha256: public_key_spki_sha256.clone(),
    })
}

fn load_authority_for_update(
    transaction: &mut Transaction<'_>,
    writer_authority_id: &Id,
) -> AuthorityTxResult<Option<ObjectWriteAuthority>> {
    transaction
        .query_opt(
            "SELECT record::text AS record_json
               FROM object_write_authorities
              WHERE writer_authority_id=$1 FOR UPDATE",
            &[&writer_authority_id.as_str()],
        )?
        .map(|row| decode(row.get("record_json")))
        .transpose()
}

fn load_credential_for_update(
    transaction: &mut Transaction<'_>,
    credential_id: &Id,
) -> AuthorityTxResult<Option<ObjectWriteCredentialBinding>> {
    transaction
        .query_opt(
            "SELECT record::text AS record_json
               FROM object_write_credentials
              WHERE credential_id=$1 FOR UPDATE",
            &[&credential_id.as_str()],
        )?
        .map(|row| decode(row.get("record_json")))
        .transpose()
}

fn load_authority_credentials_for_update(
    transaction: &mut Transaction<'_>,
    writer_authority_id: &Id,
) -> AuthorityTxResult<Vec<ObjectWriteCredentialBinding>> {
    transaction
        .query(
            "SELECT record::text AS record_json
               FROM object_write_credentials
              WHERE writer_authority_id=$1
              ORDER BY credential_id COLLATE \"C\" FOR UPDATE",
            &[&writer_authority_id.as_str()],
        )?
        .into_iter()
        .map(|row| decode(row.get("record_json")))
        .collect()
}

fn validate_current_volume_owner(
    transaction: &mut Transaction<'_>,
    registration: &ObjectWriteCredentialRegistration,
    now: UnixMillis,
) -> AuthorityTxResult<()> {
    let Some(row) = transaction.query_opt(
        "SELECT admin_state, owner_node_id, lease_owner, lease_epoch,
                lease_expires_at
           FROM volume_records WHERE volume_id=$1 FOR SHARE",
        &[&registration.volume_id.as_str()],
    )?
    else {
        return Err(application(ApiError::not_found("Volume")));
    };
    let lease_epoch: i64 = row.try_get("lease_epoch")?;
    let lease_expires_at: Option<i64> = row.try_get("lease_expires_at")?;
    if row.try_get::<_, String>("admin_state")? != "active"
        || row
            .try_get::<_, Option<String>>("owner_node_id")?
            .as_deref()
            != Some(registration.session.node_id.as_str())
        || row.try_get::<_, Option<String>>("lease_owner")?.as_deref()
            != Some(registration.attachment_id.as_str())
        || u64::try_from(lease_epoch).ok() != Some(registration.attachment_epoch.get())
        || lease_expires_at.is_none_or(|deadline| deadline < now.get() as i64)
    {
        return Err(application(ApiError::failed_precondition(
            "object-write credential does not bind the current serving Volume owner",
        )));
    }
    Ok(())
}

fn registration_receipt(
    binding: &ObjectWriteCredentialBinding,
) -> ObjectWriteCredentialRegistrationReceipt {
    ObjectWriteCredentialRegistrationReceipt {
        version: ContractVersion::V1,
        writer_authority_id: binding.writer_authority_id.clone(),
        volume_id: binding.volume_id.clone(),
        attachment_id: binding.attachment_id.clone(),
        attachment_epoch: binding.attachment_epoch,
        credential: binding.credential.clone(),
        registered_at_unix_ms: binding.registered_at_unix_ms,
    }
}

fn insert_credential(
    transaction: &mut Transaction<'_>,
    binding: &ObjectWriteCredentialBinding,
) -> AuthorityTxResult<()> {
    let record = encode(binding)?;
    let epoch = pg(binding.agent_session_epoch.get())?;
    let attachment_epoch = pg(binding.attachment_epoch.get())?;
    let registered_at = pg(binding.registered_at_unix_ms.get())?;
    let inserted = transaction.execute(
        "INSERT INTO object_write_credentials (
            credential_id, record, public_key_spki, public_key_spki_sha256,
            writer_authority_id, host_provider, host_partition,
            host_account_id, host_region, immutable_host_id, node_id,
            node_boot_id, agent_instance_id, agent_session_epoch, volume_id,
            attachment_id, attachment_epoch, private_artifact_id,
            private_file_fsync_receipt_id,
            private_directory_fsync_receipt_id, registered_at_unix_ms, state
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, 'active'
         ) ON CONFLICT DO NOTHING",
        &[
            &binding.credential.credential_id.as_str(),
            &record,
            &binding.public_key_spki.as_str(),
            &binding.credential.public_key_spki_sha256.as_str(),
            &binding.writer_authority_id.as_str(),
            &binding.host_provider_scope.provider.as_str(),
            &binding.host_provider_scope.partition.as_str(),
            &binding.host_provider_scope.account_id.as_str(),
            &binding.host_provider_scope.region.as_str(),
            &binding.immutable_host_id.as_str(),
            &binding.node_id.as_str(),
            &binding.node_boot_id.as_str(),
            &binding.agent_instance_id.as_str(),
            &epoch,
            &binding.volume_id.as_str(),
            &binding.attachment_id.as_str(),
            &attachment_epoch,
            &binding.private_artifact_id.as_str(),
            &binding.private_file_fsync_receipt_id.as_str(),
            &binding.private_directory_fsync_receipt_id.as_str(),
            &registered_at,
        ],
    )?;
    if inserted != 1 {
        return Err(application(ApiError::conflict(
            "object-write credential or attachment already has a different active key",
        )));
    }
    Ok(())
}

fn register_in(
    transaction: &mut Transaction<'_>,
    authenticated_node: &AuthenticatedNodeCredential,
    authenticated_attachment: &AuthenticatedNodeCredential,
    registration: &ObjectWriteCredentialRegistration,
) -> AuthorityTxResult<ObjectWriteCredentialRegistrationReceipt> {
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated_node.credential_id())?
    else {
        return Err(application(ApiError::unauthenticated(
            "unknown Node credential",
        )));
    };
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated_node.credential_id()
        || identity.credential_binding != *authenticated_node.binding()
        || identity.node_id != registration.session.node_id
    {
        return Err(application(ApiError::unauthenticated(
            "Node credential is not current for object-write registration",
        )));
    }
    if lock_exact_credential_lineage(transaction, &identity)?
        != Some(CredentialLineageState::Active)
    {
        return Err(application(ApiError::unauthenticated(
            "Node credential lineage is not active",
        )));
    }
    let Some(session) = load_current_session_for_update(transaction, &identity.node_id)? else {
        return Err(application(ApiError::failed_precondition(
            "Node has no current Agent session",
        )));
    };
    let now = database_now(transaction)?;
    if session.node_id != registration.session.node_id
        || session.node_boot_id != registration.session.node_boot_id
        || session.agent_instance_id != registration.session.agent_instance_id
        || session.agent_session_epoch != registration.session.agent_session_epoch
        || session.immutable_host_id != identity.immutable_host_id
        || session.lease_deadline_unix_ms < now
    {
        return Err(application(ApiError::failed_precondition(
            "object-write registration is not bound to the exact current Agent session",
        )));
    }
    let attachment_reference = authenticated_attachment_reference(authenticated_attachment)?;
    if attachment_reference != registration.credential {
        return Err(application(ApiError::unauthenticated(
            "attachment proof does not match the registered public key",
        )));
    }
    validate_current_volume_owner(transaction, registration, now)?;
    let Some(authority) =
        load_authority_for_update(transaction, &registration.writer_authority_id)?
    else {
        return Err(application(ApiError::not_found("ObjectWriteAuthority")));
    };
    validate_object_write_authority(&authority)
        .map_err(|error| corrupt(format!("invalid object-write authority: {error}")))?;

    if let Some(existing) =
        load_credential_for_update(transaction, &registration.credential.credential_id)?
    {
        validate_object_write_credential(&authority, &existing)
            .map_err(|error| corrupt(format!("invalid object-write credential: {error}")))?;
        let candidate = register_object_write_credential(
            &authority,
            registration,
            existing.registered_at_unix_ms,
        )
        .map_err(|error| application(ApiError::conflict(error.to_string())))?;
        if existing == candidate && matches!(existing.state, ObjectWriteCredentialState::Active) {
            return Ok(registration_receipt(&existing));
        }
        return Err(application(ApiError::conflict(
            "object-write credential replay changed its key or attachment binding",
        )));
    }

    let binding = register_object_write_credential(&authority, registration, now)
        .map_err(|error| application(ApiError::failed_precondition(error.to_string())))?;
    insert_credential(transaction, &binding)?;
    Ok(registration_receipt(&binding))
}

fn persist_authority(
    transaction: &mut Transaction<'_>,
    authority: &ObjectWriteAuthority,
) -> AuthorityTxResult<()> {
    let (state, fence_attempt_id, cutoff_at, cutoff_sequence, cutoff_receipt) =
        match &authority.state {
            ObjectWriteAuthorityState::Open => ("open", None, None, None, None),
            ObjectWriteAuthorityState::CutoffPending {
                fence_attempt_id,
                cutoff_sequence,
                cutoff_effective_at_unix_ms,
            } => (
                "cutoff_pending",
                Some(fence_attempt_id.as_str()),
                Some(pg(cutoff_effective_at_unix_ms.get())?),
                Some(pg(cutoff_sequence.get())?),
                None,
            ),
            ObjectWriteAuthorityState::CutoffComplete { receipt } => (
                "cutoff_complete",
                Some(receipt.fence_attempt_id.as_str()),
                Some(pg(receipt.cutoff_effective_at_unix_ms.get())?),
                Some(pg(receipt.cutoff_sequence.get())?),
                Some(encode(receipt)?),
            ),
        };
    let record = encode(authority)?;
    let max = pg(authority.max_accepted_sequence.get())?;
    let terminal = pg(authority.terminal_prefix_sequence.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_authorities
            SET record=$2::TEXT::jsonb, state=$3, max_accepted_sequence=$4,
                terminal_prefix_sequence=$5, terminal_prefix_sha256=$6,
                fence_attempt_id=$7, cutoff_effective_at_unix_ms=$8,
                cutoff_sequence=$9, cutoff_receipt=$10::TEXT::jsonb
          WHERE writer_authority_id=$1",
        &[
            &authority.writer.authority_id.as_str(),
            &record,
            &state,
            &max,
            &terminal,
            &authority.terminal_prefix_sha256.as_str(),
            &fence_attempt_id,
            &cutoff_at,
            &cutoff_sequence,
            &cutoff_receipt,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("object-write authority disappeared while locked"));
    }
    Ok(())
}

fn persist_retired_credential(
    transaction: &mut Transaction<'_>,
    binding: &ObjectWriteCredentialBinding,
) -> AuthorityTxResult<()> {
    let ObjectWriteCredentialState::Retired {
        cause,
        retirement_receipt_id,
        retired_at_unix_ms,
    } = &binding.state
    else {
        return Ok(());
    };
    let (kind, transition_id) = match cause {
        ObjectWriteCredentialRetirementCause::ParentCutoff { fence_attempt_id } => {
            ("parent_cutoff", fence_attempt_id)
        }
        ObjectWriteCredentialRetirementCause::ExactRelease {
            release_transition_id,
        } => ("exact_release", release_transition_id),
    };
    let record = encode(binding)?;
    let retired_at = pg(retired_at_unix_ms.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_credentials
            SET record=$2::TEXT::jsonb, state='retired', retirement_kind=$3,
                retirement_transition_id=$4, retirement_receipt_id=$5,
                retired_at_unix_ms=$6
          WHERE credential_id=$1 AND state='active'",
        &[
            &binding.credential.credential_id.as_str(),
            &record,
            &kind,
            &transition_id.as_str(),
            &retirement_receipt_id.as_str(),
            &retired_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "object-write credential changed while its parent was locked",
        ));
    }
    Ok(())
}

impl Store {
    pub fn register_object_write_credential(
        &self,
        authenticated_node: &AuthenticatedNodeCredential,
        authenticated_attachment: &AuthenticatedNodeCredential,
        registration: &ObjectWriteCredentialRegistration,
    ) -> crate::store::Result<ObjectWriteCredentialRegistrationReceipt> {
        self.authority_transaction(|transaction| {
            register_in(
                transaction,
                authenticated_node,
                authenticated_attachment,
                registration,
            )
        })
    }

    /// Close the parent and every still-active attachment key in one
    /// transaction. The returned authority is pending until its accepted PUT
    /// prefix becomes terminal and successful objects are independently
    /// visible.
    pub fn begin_object_writer_cutoff(
        &self,
        writer_authority_id: &Id,
        fence_attempt_id: &Id,
        cutoff_effective_at_unix_ms: UnixMillis,
    ) -> crate::store::Result<ObjectWriteAuthority> {
        self.authority_transaction(|transaction| {
            let Some(authority) = load_authority_for_update(transaction, writer_authority_id)?
            else {
                return Err(application(ApiError::not_found("ObjectWriteAuthority")));
            };
            let credentials =
                load_authority_credentials_for_update(transaction, writer_authority_id)?;
            let (updated, retired) = begin_object_writer_cutoff(
                &authority,
                &credentials,
                fence_attempt_id,
                cutoff_effective_at_unix_ms,
            )
            .map_err(|error| application(ApiError::failed_precondition(error.to_string())))?;
            for credential in &retired {
                if matches!(credential.state, ObjectWriteCredentialState::Retired { .. })
                    && credentials.iter().any(|stored| {
                        stored.credential.credential_id == credential.credential.credential_id
                            && matches!(stored.state, ObjectWriteCredentialState::Active)
                    })
                {
                    persist_retired_credential(transaction, credential)?;
                }
            }
            persist_authority(transaction, &updated)?;
            Ok(updated)
        })
    }
}

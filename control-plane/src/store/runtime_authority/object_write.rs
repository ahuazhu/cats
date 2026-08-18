//! PostgreSQL authority for attachment-scoped object-write credentials.
//!
//! The Node A19 key authenticates registration only. The attachment public
//! key is stored after proof of possession; its private key never enters
//! Control. Parent cutoff and child retirement commit in one transaction.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ApiError;
use cats_api::object_write_gateway::{
    encode_object_write_qualification_head_evidence, ObjectWriteCredentialReference,
    ObjectWriteCredentialRegistration, ObjectWriteCredentialRegistrationReceipt,
    ObjectWriteImmutableKey, ObjectWriteIngressDescriptor,
    ObjectWriteQualificationUnprovenReasonV1,
};
use cats_api::runtime_reconciliation::{
    AsciiText, ContractVersion, CredentialBinding, Id, NodeIdentity, NodeIdentityState,
    ProviderScope, Sha256Digest, UnixMillis, WireU64,
};
use cats_storage::object_write_authority::{
    accept_durable_object_write, advance_object_write_terminal_prefix,
    authorize_object_write_ingress, begin_object_writer_cutoff, classify_object_key_acceptance,
    complete_object_write_terminal, complete_object_writer_cutoff, empty_terminal_prefix_sha256,
    mark_object_write_provider_issued, mark_object_write_spool_durable,
    mark_terminal_object_write_spool_removed, register_object_write_credential,
    reject_object_write_before_accept, validate_object_put_attempt,
    validate_object_write_authority, validate_object_write_credential,
    validate_object_write_ingress_attempt, DurableObjectWriteSpoolReceipt, ObjectKeyAcceptance,
    ObjectPutAttempt, ObjectPutState, ObjectPutTerminalState, ObjectWriteAcceptanceOutcome,
    ObjectWriteAuthority, ObjectWriteAuthorityError, ObjectWriteAuthorityState,
    ObjectWriteCredentialBinding, ObjectWriteCredentialRetirementCause, ObjectWriteCredentialState,
    ObjectWriteIngressAttempt, ObjectWriteIngressState, ObjectWriteRejectionReason,
    ObjectWriterIdentity, StoredObjectWriteAttempt, TerminalObjectWriteSpool,
};
use postgres::{Row, Transaction};

const OBJECT_WRITE_PREFIX_ADVANCE_LIMIT: i64 = 256;
const OBJECT_WRITE_RECOVERY_LIMIT: i64 = 256;

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

fn authority_error(error: ObjectWriteAuthorityError) -> AuthorityTransactionError {
    let api = match error {
        ObjectWriteAuthorityError::InvalidRequest | ObjectWriteAuthorityError::SpoolNotDurable => {
            ApiError::invalid(error.to_string())
        }
        ObjectWriteAuthorityError::StaleAttempt | ObjectWriteAuthorityError::ObjectKeyConflict => {
            ApiError::conflict(error.to_string())
        }
        ObjectWriteAuthorityError::WriterClosed
        | ObjectWriteAuthorityError::BindingMismatch
        | ObjectWriteAuthorityError::InvalidTransition
        | ObjectWriteAuthorityError::NonContiguousTerminalPrefix
        | ObjectWriteAuthorityError::CutoffNotReady => {
            ApiError::failed_precondition(error.to_string())
        }
        ObjectWriteAuthorityError::SequenceExhausted | ObjectWriteAuthorityError::CorruptState => {
            return corrupt(format!("object-write authority failure: {error}"));
        }
    };
    application(api)
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

fn load_credential_parent_id(
    transaction: &mut Transaction<'_>,
    credential_id: &Id,
) -> AuthorityTxResult<Option<Id>> {
    transaction
        .query_opt(
            "SELECT writer_authority_id
               FROM object_write_credentials
              WHERE credential_id=$1",
            &[&credential_id.as_str()],
        )?
        .map(|row| {
            Id::new(row.get::<_, String>("writer_authority_id"))
                .ok_or_else(|| corrupt("stored object-write authority ID is invalid"))
        })
        .transpose()
}

fn decode_stored_attempt(row: &Row) -> AuthorityTxResult<StoredObjectWriteAttempt> {
    let state: String = row.try_get("state")?;
    let record: String = row.try_get("record_json")?;
    if matches!(
        state.as_str(),
        "receiving" | "durable_spooled" | "rejected_before_accept"
    ) {
        let attempt: ObjectWriteIngressAttempt = decode(record)?;
        validate_object_write_ingress_attempt(&attempt)
            .map_err(|error| corrupt(format!("invalid provisional object-write row: {error}")))?;
        if ingress_state(&attempt) != state {
            return Err(corrupt(
                "object-write ingress state projection disagrees with record",
            ));
        }
        return Ok(StoredObjectWriteAttempt::Ingress(attempt));
    }
    let attempt: ObjectPutAttempt = decode(record)?;
    if accepted_state(&attempt) != state {
        return Err(corrupt(
            "object-write accepted state projection disagrees with record",
        ));
    }
    Ok(StoredObjectWriteAttempt::Accepted(attempt))
}

fn load_attempt_for_update(
    transaction: &mut Transaction<'_>,
    request_id: &Sha256Digest,
) -> AuthorityTxResult<Option<StoredObjectWriteAttempt>> {
    transaction
        .query_opt(
            "SELECT record::text AS record_json, state
               FROM object_write_attempts WHERE request_id=$1 FOR UPDATE",
            &[&request_id.as_str()],
        )?
        .as_ref()
        .map(decode_stored_attempt)
        .transpose()
}

fn ingress_state(attempt: &ObjectWriteIngressAttempt) -> &'static str {
    match attempt.state {
        ObjectWriteIngressState::Receiving => "receiving",
        ObjectWriteIngressState::DurableSpooled { .. } => "durable_spooled",
        ObjectWriteIngressState::RejectedBeforeAccept { .. } => "rejected_before_accept",
    }
}

fn accepted_state(attempt: &ObjectPutAttempt) -> &'static str {
    match &attempt.state {
        ObjectPutState::AcceptedSpooled { .. } => "accepted_spooled",
        ObjectPutState::ProviderIssued { .. } => "provider_issued",
        ObjectPutState::QualificationResponseLost { .. } => "qualification_response_lost",
        ObjectPutState::Terminal { outcome, spool } => {
            if matches!(spool, TerminalObjectWriteSpool::Removed { .. }) {
                "spool_removed"
            } else {
                match outcome {
                    ObjectPutTerminalState::SucceededVisible { .. } => "terminal_visible",
                    ObjectPutTerminalState::PermanentlyFailed { .. } => "permanent",
                    ObjectPutTerminalState::QualificationUnprovenVisible { .. } => {
                        "qualification_unproven_visible"
                    }
                }
            }
        }
    }
}

fn key_kind(key: &ObjectWriteImmutableKey) -> &'static str {
    match key {
        ObjectWriteImmutableKey::VolumeData { .. } => "volume_data",
        ObjectWriteImmutableKey::VolumeMap => "volume_map",
        ObjectWriteImmutableKey::VolumeCommit { .. } => "volume_commit",
    }
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

fn insert_ingress_attempt(
    transaction: &mut Transaction<'_>,
    credential_id: &Id,
    attempt: &ObjectWriteIngressAttempt,
) -> AuthorityTxResult<bool> {
    validate_object_write_ingress_attempt(attempt).map_err(authority_error)?;
    let ingress = &attempt.ingress;
    let record = encode(attempt)?;
    let receiving_started_at = pg(ingress.receiving_started_at_unix_ms.get())?;
    let content_length = pg(ingress.content_length.get())?;
    let inserted = transaction.execute(
        "INSERT INTO object_write_attempts (
            request_id, record, writer_authority_id, credential_id, volume_id,
            key_kind, object_provider, object_partition, object_account_id,
            object_region, object_store_scope_id, object_key, content_sha256,
            content_length, receiving_started_at_unix_ms, state
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, 'receiving'
         ) ON CONFLICT (request_id) DO NOTHING",
        &[
            &ingress.request_id.as_str(),
            &record,
            &ingress.writer_authority_id.as_str(),
            &credential_id.as_str(),
            &ingress.volume_id.as_str(),
            &key_kind(&ingress.key),
            &ingress.target.object_provider_scope.provider.as_str(),
            &ingress.target.object_provider_scope.partition.as_str(),
            &ingress.target.object_provider_scope.account_id.as_str(),
            &ingress.target.object_provider_scope.region.as_str(),
            &ingress.target.object_store_scope_id.as_str(),
            &ingress.target.canonical_logical_key,
            &ingress.content_sha256.as_str(),
            &content_length,
            &receiving_started_at,
        ],
    )?;
    Ok(inserted == 1)
}

fn persist_durable_ingress(
    transaction: &mut Transaction<'_>,
    attempt: &ObjectWriteIngressAttempt,
) -> AuthorityTxResult<()> {
    let ObjectWriteIngressState::DurableSpooled { spool } = &attempt.state else {
        return Err(corrupt(
            "durable object-write projection has the wrong state",
        ));
    };
    let record = encode(attempt)?;
    let durable_at = pg(spool.durable_at_unix_ms.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_attempts
            SET record=$2::TEXT::jsonb, state='durable_spooled', spool_id=$3,
                spool_file_fsync_receipt_id=$4,
                spool_directory_fsync_receipt_id=$5,
                spool_durable_at_unix_ms=$6
          WHERE request_id=$1 AND state='receiving'",
        &[
            &attempt.ingress.request_id.as_str(),
            &record,
            &spool.spool_id.as_str(),
            &spool.file_fsync_receipt_id.as_str(),
            &spool.directory_fsync_receipt_id.as_str(),
            &durable_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("object-write receiving row changed while locked"));
    }
    Ok(())
}

fn rejection_receipt_id(
    request_id: &Sha256Digest,
    reason: ObjectWriteRejectionReason,
) -> AuthorityTxResult<AsciiText> {
    let digest = request_id
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| corrupt("object-write request digest is invalid"))?;
    let reason = match reason {
        ObjectWriteRejectionReason::WriterClosed => "writer_closed",
        ObjectWriteRejectionReason::ObjectKeyConflict => "object_key_conflict",
    };
    AsciiText::new(format!("owrej1_{digest}_{reason}"))
        .ok_or_else(|| corrupt("object-write rejection receipt ID is invalid"))
}

fn persist_rejected_ingress(
    transaction: &mut Transaction<'_>,
    attempt: &ObjectWriteIngressAttempt,
) -> AuthorityTxResult<()> {
    let ObjectWriteIngressState::RejectedBeforeAccept {
        reason,
        rejection_receipt_id,
        rejected_at_unix_ms,
        ..
    } = &attempt.state
    else {
        return Err(corrupt(
            "rejected object-write projection has the wrong state",
        ));
    };
    let rejection_kind = match reason {
        ObjectWriteRejectionReason::WriterClosed => "writer_closed",
        ObjectWriteRejectionReason::ObjectKeyConflict => "object_key_conflict",
    };
    let record = encode(attempt)?;
    let rejected_at = pg(rejected_at_unix_ms.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_attempts
            SET record=$2::TEXT::jsonb, state='rejected_before_accept',
                rejection_kind=$3, rejection_receipt_id=$4,
                rejected_at_unix_ms=$5
          WHERE request_id=$1 AND state='durable_spooled'",
        &[
            &attempt.ingress.request_id.as_str(),
            &record,
            &rejection_kind,
            &rejection_receipt_id.as_str(),
            &rejected_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("durable object-write row changed while locked"));
    }
    Ok(())
}

fn persist_accepted_attempt(
    transaction: &mut Transaction<'_>,
    attempt: &ObjectPutAttempt,
) -> AuthorityTxResult<()> {
    let ObjectPutState::AcceptedSpooled { spool } = &attempt.state else {
        return Err(corrupt(
            "newly accepted object-write row has the wrong state",
        ));
    };
    let record = encode(attempt)?;
    let sequence = pg(attempt.descriptor.accepted_sequence.get())?;
    let accepted_at = pg(attempt.descriptor.accepted_at_unix_ms.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_attempts
            SET record=$2::TEXT::jsonb, state='accepted_spooled',
                accepted_sequence=$3, accepted_at_unix_ms=$4,
                provider_attempt_id=$5
          WHERE request_id=$1 AND state='durable_spooled'",
        &[
            &attempt.descriptor.request_id.as_str(),
            &record,
            &sequence,
            &accepted_at,
            &attempt.descriptor.provider_attempt_id.as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("durable object-write row changed while accepting"));
    }
    // The durable spool projection was persisted before acceptance and must
    // stay byte-for-byte attached to the accepted row.
    if spool.request_id != attempt.descriptor.request_id {
        return Err(corrupt("accepted object-write spool changed request"));
    }
    Ok(())
}

fn persist_provider_issued(
    transaction: &mut Transaction<'_>,
    attempt: &ObjectPutAttempt,
) -> AuthorityTxResult<()> {
    let ObjectPutState::ProviderIssued {
        issued_at_unix_ms, ..
    } = &attempt.state
    else {
        return Err(corrupt(
            "provider-issued object-write row has the wrong state",
        ));
    };
    let record = encode(attempt)?;
    let issued_at = pg(issued_at_unix_ms.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_attempts
            SET record=$2::TEXT::jsonb, state='provider_issued',
                provider_issued_at_unix_ms=$3
          WHERE request_id=$1 AND state='accepted_spooled'",
        &[&attempt.descriptor.request_id.as_str(), &record, &issued_at],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "accepted object-write row changed before provider issue",
        ));
    }
    Ok(())
}

fn persist_terminal_attempt(
    transaction: &mut Transaction<'_>,
    attempt: &ObjectPutAttempt,
) -> AuthorityTxResult<()> {
    let ObjectPutState::Terminal {
        outcome,
        spool: TerminalObjectWriteSpool::Retained { .. },
    } = &attempt.state
    else {
        return Err(corrupt("terminal object-write row has the wrong state"));
    };
    let record = encode(attempt)?;
    let (
        state,
        kind,
        put_receipt,
        put_at,
        visibility_receipt,
        visible_at,
        failure_receipt,
        failed_at,
        qualification_unproven_reason,
        qualification_head_evidence,
        qualification_unproven_at,
    ) = match outcome {
        ObjectPutTerminalState::SucceededVisible {
            put_receipt_id,
            put_completed_at_unix_ms,
            visibility_receipt_id,
            visible_at_unix_ms,
            qualification_ambiguity: _,
        } => (
            "terminal_visible",
            "succeeded_visible",
            Some(put_receipt_id.as_str()),
            Some(pg(put_completed_at_unix_ms.get())?),
            Some(visibility_receipt_id.as_str()),
            Some(pg(visible_at_unix_ms.get())?),
            None,
            None,
            None,
            None,
            None,
        ),
        ObjectPutTerminalState::PermanentlyFailed {
            failure_receipt_id,
            failed_at_unix_ms,
        } => (
            "permanent",
            "permanently_failed",
            None,
            None,
            None,
            None,
            Some(failure_receipt_id.as_str()),
            Some(pg(failed_at_unix_ms.get())?),
            None,
            None,
            None,
        ),
        ObjectPutTerminalState::QualificationUnprovenVisible { receipt } => (
            "qualification_unproven_visible",
            "qualification_unproven_visible",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(match receipt.reason {
                ObjectWriteQualificationUnprovenReasonV1::ResponseLossReceiptAbsent => {
                    "response_loss_receipt_absent"
                }
            }),
            Some(
                encode_object_write_qualification_head_evidence(&receipt.head_evidence)
                    .map_err(|_| corrupt("invalid qualification HEAD evidence"))?,
            ),
            Some(pg(receipt.resolved_at_unix_ms.get())?),
        ),
    };
    let changed = transaction.execute(
        "UPDATE object_write_attempts
            SET record=$2::TEXT::jsonb, state=$3, terminal_kind=$4,
                put_receipt_id=$5, put_completed_at_unix_ms=$6,
                visibility_receipt_id=$7, visible_at_unix_ms=$8,
                failure_receipt_id=$9, failed_at_unix_ms=$10,
                qualification_unproven_reason=$11,
                qualification_head_evidence_canonical=$12,
                qualification_unproven_at_unix_ms=$13
          WHERE request_id=$1 AND state='provider_issued'",
        &[
            &attempt.descriptor.request_id.as_str(),
            &record,
            &state,
            &kind,
            &put_receipt,
            &put_at,
            &visibility_receipt,
            &visible_at,
            &failure_receipt,
            &failed_at,
            &qualification_unproven_reason,
            &qualification_head_evidence,
            &qualification_unproven_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "provider-issued object-write row changed before settlement",
        ));
    }
    Ok(())
}

fn persist_spool_removed(
    transaction: &mut Transaction<'_>,
    attempt: &ObjectPutAttempt,
) -> AuthorityTxResult<()> {
    let ObjectPutState::Terminal {
        spool:
            TerminalObjectWriteSpool::Removed {
                removal_receipt_id,
                removed_at_unix_ms,
                ..
            },
        ..
    } = &attempt.state
    else {
        return Err(corrupt(
            "spool-removed object-write row has the wrong state",
        ));
    };
    let record = encode(attempt)?;
    let removed_at = pg(removed_at_unix_ms.get())?;
    let changed = transaction.execute(
        "UPDATE object_write_attempts
            SET record=$2::TEXT::jsonb, state='spool_removed',
                spool_removal_receipt_id=$3, spool_removed_at_unix_ms=$4
          WHERE request_id=$1 AND state IN (
              'terminal_visible', 'permanent', 'qualification_unproven_visible'
          )",
        &[
            &attempt.descriptor.request_id.as_str(),
            &record,
            &removal_receipt_id.as_str(),
            &removed_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "terminal object-write row changed before spool removal",
        ));
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

fn load_attempt_parent_id(
    transaction: &mut Transaction<'_>,
    request_id: &Sha256Digest,
) -> AuthorityTxResult<Option<Id>> {
    transaction
        .query_opt(
            "SELECT writer_authority_id
               FROM object_write_attempts WHERE request_id=$1",
            &[&request_id.as_str()],
        )?
        .map(|row| {
            Id::new(row.get::<_, String>("writer_authority_id"))
                .ok_or_else(|| corrupt("stored object-write authority ID is invalid"))
        })
        .transpose()
}

fn validate_attempt_for_authority(
    authority: &ObjectWriteAuthority,
    stored: &StoredObjectWriteAttempt,
) -> AuthorityTxResult<()> {
    match stored {
        StoredObjectWriteAttempt::Ingress(attempt) => {
            validate_object_write_ingress_attempt(attempt).map_err(authority_error)?;
            if attempt.ingress.writer_authority_id != authority.writer.authority_id {
                return Err(corrupt("provisional object-write row has the wrong parent"));
            }
        }
        StoredObjectWriteAttempt::Accepted(attempt) => {
            validate_object_put_attempt(authority, attempt).map_err(authority_error)?;
        }
    }
    Ok(())
}

fn same_ingress_request(
    left: &ObjectWriteIngressAttempt,
    right: &ObjectWriteIngressAttempt,
) -> bool {
    left.ingress.writer_authority_id == right.ingress.writer_authority_id
        && left.ingress.request_id == right.ingress.request_id
        && left.ingress.volume_id == right.ingress.volume_id
        && left.ingress.key == right.ingress.key
        && left.ingress.target == right.ingress.target
        && left.ingress.content_sha256 == right.ingress.content_sha256
        && left.ingress.content_length == right.ingress.content_length
}

fn same_spool_material(
    left: &DurableObjectWriteSpoolReceipt,
    right: &DurableObjectWriteSpoolReceipt,
) -> bool {
    left.spool_id == right.spool_id
        && left.request_id == right.request_id
        && left.content_sha256 == right.content_sha256
        && left.content_length == right.content_length
        && left.file_fsync_receipt_id == right.file_fsync_receipt_id
        && left.directory_fsync_receipt_id == right.directory_fsync_receipt_id
}

fn begin_ingress_in(
    transaction: &mut Transaction<'_>,
    authenticated_attachment: &AuthenticatedNodeCredential,
    descriptor: &ObjectWriteIngressDescriptor,
) -> AuthorityTxResult<StoredObjectWriteAttempt> {
    let credential = authenticated_attachment_reference(authenticated_attachment)?;
    let Some(writer_authority_id) =
        load_credential_parent_id(transaction, &credential.credential_id)?
    else {
        return Err(application(ApiError::unauthenticated(
            "unknown object-write attachment credential",
        )));
    };
    // Every path locks the parent before its child. Cutoff takes the same
    // order, so no request can authenticate beneath a concurrently closed
    // writer.
    let Some(authority) = load_authority_for_update(transaction, &writer_authority_id)? else {
        return Err(corrupt("object-write credential parent is missing"));
    };
    let Some(binding) = load_credential_for_update(transaction, &credential.credential_id)? else {
        return Err(corrupt(
            "object-write credential disappeared while its parent was locked",
        ));
    };
    validate_object_write_credential(&authority, &binding).map_err(authority_error)?;
    let now = database_now(transaction)?;
    let candidate =
        authorize_object_write_ingress(&authority, &binding, &credential, descriptor, now)
            .map_err(authority_error)?;
    if let Some(existing) = load_attempt_for_update(transaction, &candidate.ingress.request_id)? {
        validate_attempt_for_authority(&authority, &existing)?;
        let same = match &existing {
            StoredObjectWriteAttempt::Ingress(attempt) => same_ingress_request(attempt, &candidate),
            StoredObjectWriteAttempt::Accepted(attempt) => {
                attempt.descriptor.writer_authority_id == candidate.ingress.writer_authority_id
                    && attempt.descriptor.request_id == candidate.ingress.request_id
                    && attempt.descriptor.volume_id == candidate.ingress.volume_id
                    && attempt.descriptor.key == candidate.ingress.key
                    && attempt.descriptor.target == candidate.ingress.target
                    && attempt.descriptor.content_sha256 == candidate.ingress.content_sha256
                    && attempt.descriptor.content_length == candidate.ingress.content_length
            }
        };
        if !same {
            return Err(application(ApiError::conflict(
                "object-write request ID replay changed immutable request fields",
            )));
        }
        return Ok(existing);
    }
    if !insert_ingress_attempt(transaction, &credential.credential_id, &candidate)? {
        return Err(corrupt(
            "object-write request appeared while parent authority was locked",
        ));
    }
    Ok(StoredObjectWriteAttempt::Ingress(candidate))
}

fn load_accepted_object_key_for_update(
    transaction: &mut Transaction<'_>,
    authority: &ObjectWriteAuthority,
    object_key: &str,
) -> AuthorityTxResult<Option<ObjectPutAttempt>> {
    let stored = transaction
        .query_opt(
            "SELECT record::text AS record_json, state
               FROM object_write_attempts
              WHERE writer_authority_id=$1 AND object_key=$2
                AND accepted_sequence IS NOT NULL
              FOR UPDATE",
            &[&authority.writer.authority_id.as_str(), &object_key],
        )?
        .as_ref()
        .map(decode_stored_attempt)
        .transpose()?;
    match stored {
        Some(StoredObjectWriteAttempt::Accepted(attempt)) => {
            validate_object_put_attempt(authority, &attempt).map_err(authority_error)?;
            if attempt.descriptor.target.canonical_logical_key != object_key {
                return Err(corrupt("object-write key projection disagrees with record"));
            }
            Ok(Some(attempt))
        }
        Some(StoredObjectWriteAttempt::Ingress(_)) => Err(corrupt(
            "accepted object-write index selected a provisional row",
        )),
        None => Ok(None),
    }
}

fn accept_durable_in(
    transaction: &mut Transaction<'_>,
    request_id: &Sha256Digest,
) -> AuthorityTxResult<ObjectWriteAcceptanceOutcome> {
    let Some(writer_authority_id) = load_attempt_parent_id(transaction, request_id)? else {
        return Err(application(ApiError::not_found("ObjectWriteAttempt")));
    };
    let Some(authority) = load_authority_for_update(transaction, &writer_authority_id)? else {
        return Err(corrupt("object-write attempt parent is missing"));
    };
    let Some(stored) = load_attempt_for_update(transaction, request_id)? else {
        return Err(corrupt(
            "object-write attempt disappeared while parent was locked",
        ));
    };
    validate_attempt_for_authority(&authority, &stored)?;
    let ingress = match stored {
        StoredObjectWriteAttempt::Accepted(attempt) => {
            return Ok(ObjectWriteAcceptanceOutcome::Accepted(attempt));
        }
        StoredObjectWriteAttempt::Ingress(attempt) => attempt,
    };
    if matches!(
        ingress.state,
        ObjectWriteIngressState::RejectedBeforeAccept { .. }
    ) {
        return Ok(ObjectWriteAcceptanceOutcome::RejectedBeforeAccept(ingress));
    }
    if matches!(ingress.state, ObjectWriteIngressState::Receiving) {
        return Err(application(ApiError::failed_precondition(
            "object-write body is not durably spooled",
        )));
    }
    let now = database_now(transaction)?;
    if !matches!(authority.state, ObjectWriteAuthorityState::Open) {
        let reason = ObjectWriteRejectionReason::WriterClosed;
        let rejected = reject_object_write_before_accept(
            &authority,
            &ingress,
            reason,
            rejection_receipt_id(request_id, reason)?,
            now,
        )
        .map_err(authority_error)?;
        persist_rejected_ingress(transaction, &rejected)?;
        return Ok(ObjectWriteAcceptanceOutcome::RejectedBeforeAccept(rejected));
    }
    let object_key = &ingress.ingress.target.canonical_logical_key;
    let existing = load_accepted_object_key_for_update(transaction, &authority, object_key)?;
    match classify_object_key_acceptance(existing.as_ref(), &ingress) {
        Ok(ObjectKeyAcceptance::Vacant) => {}
        Ok(ObjectKeyAcceptance::ExactReplay) => {
            return Ok(ObjectWriteAcceptanceOutcome::Accepted(
                existing.ok_or_else(|| corrupt("exact object-write replay has no stored row"))?,
            ));
        }
        Err(ObjectWriteAuthorityError::ObjectKeyConflict) => {
            let reason = ObjectWriteRejectionReason::ObjectKeyConflict;
            let rejected = reject_object_write_before_accept(
                &authority,
                &ingress,
                reason,
                rejection_receipt_id(request_id, reason)?,
                now,
            )
            .map_err(authority_error)?;
            persist_rejected_ingress(transaction, &rejected)?;
            return Ok(ObjectWriteAcceptanceOutcome::RejectedBeforeAccept(rejected));
        }
        Err(error) => return Err(authority_error(error)),
    }
    let (updated_authority, accepted) =
        accept_durable_object_write(&authority, &ingress, now).map_err(authority_error)?;
    persist_authority(transaction, &updated_authority)?;
    persist_accepted_attempt(transaction, &accepted)?;
    Ok(ObjectWriteAcceptanceOutcome::Accepted(accepted))
}

fn advance_terminal_prefix_in(
    transaction: &mut Transaction<'_>,
    authority: &ObjectWriteAuthority,
) -> AuthorityTxResult<ObjectWriteAuthority> {
    let rows = transaction.query(
        "SELECT record::text AS record_json, state
           FROM object_write_attempts
          WHERE writer_authority_id=$1
            AND accepted_sequence > $2
            AND state IN (
                'terminal_visible', 'permanent',
                'qualification_unproven_visible', 'spool_removed'
            )
          ORDER BY accepted_sequence
          LIMIT $3",
        &[
            &authority.writer.authority_id.as_str(),
            &pg(authority.terminal_prefix_sequence.get())?,
            &OBJECT_WRITE_PREFIX_ADVANCE_LIMIT,
        ],
    )?;
    let mut expected = authority.terminal_prefix_sequence.get();
    let mut contiguous = Vec::new();
    for row in &rows {
        let StoredObjectWriteAttempt::Accepted(attempt) = decode_stored_attempt(row)? else {
            return Err(corrupt(
                "terminal prefix selected a provisional object-write row",
            ));
        };
        validate_object_put_attempt(authority, &attempt).map_err(authority_error)?;
        expected = expected
            .checked_add(1)
            .ok_or_else(|| corrupt("object-write terminal prefix overflow"))?;
        if attempt.descriptor.accepted_sequence.get() != expected {
            break;
        }
        contiguous.push(attempt);
    }
    if contiguous.is_empty() {
        return Ok(authority.clone());
    }
    let updated =
        advance_object_write_terminal_prefix(authority, &contiguous).map_err(authority_error)?;
    persist_authority(transaction, &updated)?;
    Ok(updated)
}

/// Open the one Host-scoped writer authority inside a caller-owned
/// transaction, or refuse.
///
/// The caller owns A23 authentication, apply-ID replay and the Node's
/// `node_identities` row lock; this seam owns the object-write table. Every
/// Host fact and the whole accepted-sequence state are derived from that
/// locked identity, so an operator apply can only state the object-store side
/// of the binding.
///
/// One Host never holds two writer authorities. A Host that already has any
/// authority row is refused, whether that row is `open` (already provisioned,
/// possibly with a different binding) or closed (`cutoff_pending` /
/// `cutoff_complete`). A cutoff therefore cannot be reopened, and a changed
/// binding is never silently written over the current one.
pub(super) fn open_object_write_authority_in(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
    writer_authority_id: &Id,
    object_provider_scope: &ProviderScope,
    workload_principal_id: &AsciiText,
    object_store_scope_id: &AsciiText,
) -> AuthorityTxResult<bool> {
    // Serialize two applies that would open the first authority for one Host.
    // Only this path takes this advisory, and it takes it while already
    // holding the Node identity row, so it cannot invert an existing order.
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':object-write-authority-host:' ||
            jsonb_build_array($1::TEXT,$2::TEXT,$3::TEXT,$4::TEXT,$5::TEXT)::TEXT,
            0::BIGINT))",
        &[
            &identity.provider_scope.provider.as_str(),
            &identity.provider_scope.partition.as_str(),
            &identity.provider_scope.account_id.as_str(),
            &identity.provider_scope.region.as_str(),
            &identity.immutable_host_id.as_str(),
        ],
    )?;
    let existing = transaction.query(
        "SELECT writer_authority_id FROM object_write_authorities
          WHERE host_provider=$1 AND host_partition=$2 AND host_account_id=$3
            AND host_region=$4 AND immutable_host_id=$5
          ORDER BY writer_authority_id COLLATE \"C\" LIMIT 1 FOR UPDATE",
        &[
            &identity.provider_scope.provider.as_str(),
            &identity.provider_scope.partition.as_str(),
            &identity.provider_scope.account_id.as_str(),
            &identity.provider_scope.region.as_str(),
            &identity.immutable_host_id.as_str(),
        ],
    )?;
    if !existing.is_empty() {
        return Ok(false);
    }
    // The assigned ID is derived from the Node ID rather than the Host, so a
    // reused ID would mean the same Node once named another Host. Fail closed.
    if load_authority_for_update(transaction, writer_authority_id)?.is_some() {
        return Ok(false);
    }
    let authority = ObjectWriteAuthority {
        writer: ObjectWriterIdentity {
            authority_id: writer_authority_id.clone(),
            host_provider_scope: identity.provider_scope.clone(),
            immutable_host_id: identity.immutable_host_id.clone(),
            node_id: identity.node_id.clone(),
            object_provider_scope: object_provider_scope.clone(),
            workload_principal_id: workload_principal_id.clone(),
            object_store_scope_id: object_store_scope_id.clone(),
        },
        state: ObjectWriteAuthorityState::Open,
        max_accepted_sequence: zero_sequence()?,
        terminal_prefix_sequence: zero_sequence()?,
        terminal_prefix_sha256: empty_terminal_prefix_sha256(),
    };
    validate_object_write_authority(&authority).map_err(|error| {
        corrupt(format!(
            "assembled object-write authority is invalid: {error}"
        ))
    })?;
    insert_authority(transaction, &authority)?;
    Ok(true)
}

#[cfg(test)]
pub(super) fn insert_authority_for_test(
    transaction: &mut Transaction<'_>,
    authority: &ObjectWriteAuthority,
) -> AuthorityTxResult<()> {
    insert_authority(transaction, authority)
}

fn zero_sequence() -> AuthorityTxResult<WireU64> {
    WireU64::new(0).ok_or_else(|| corrupt("zero is not a wire-safe sequence"))
}

fn insert_authority(
    transaction: &mut Transaction<'_>,
    authority: &ObjectWriteAuthority,
) -> AuthorityTxResult<()> {
    let writer = &authority.writer;
    let record = encode(authority)?;
    let max = pg(authority.max_accepted_sequence.get())?;
    let terminal = pg(authority.terminal_prefix_sequence.get())?;
    let changed = transaction.execute(
        "INSERT INTO object_write_authorities (
            writer_authority_id, record, host_provider, host_partition,
            host_account_id, host_region, immutable_host_id, node_id,
            object_provider, object_partition, object_account_id,
            object_region, workload_principal_id, object_store_scope_id,
            state, max_accepted_sequence, terminal_prefix_sequence,
            terminal_prefix_sha256
         ) VALUES (
            $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, 'open', $15, $16, $17
         )",
        &[
            &writer.authority_id.as_str(),
            &record,
            &writer.host_provider_scope.provider.as_str(),
            &writer.host_provider_scope.partition.as_str(),
            &writer.host_provider_scope.account_id.as_str(),
            &writer.host_provider_scope.region.as_str(),
            &writer.immutable_host_id.as_str(),
            &writer.node_id.as_str(),
            &writer.object_provider_scope.provider.as_str(),
            &writer.object_provider_scope.partition.as_str(),
            &writer.object_provider_scope.account_id.as_str(),
            &writer.object_provider_scope.region.as_str(),
            &writer.workload_principal_id.as_str(),
            &writer.object_store_scope_id.as_str(),
            &max,
            &terminal,
            &authority.terminal_prefix_sha256.as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("object-write authority insert changed no row"));
    }
    Ok(())
}

/// Close one exact writer authority inside a caller-owned transaction.
///
/// Host-fence queue admission must make the parent/credential cutoff and the
/// sealed provider request visible in the same PostgreSQL commit.  Keeping
/// this narrow transaction-local seam here preserves the object-write lock
/// order and transition validation without giving the provider worker raw
/// table access.
pub(super) fn begin_object_writer_cutoff_in(
    transaction: &mut Transaction<'_>,
    writer_authority_id: &Id,
    fence_attempt_id: &Id,
    cutoff_effective_at_unix_ms: UnixMillis,
) -> AuthorityTxResult<ObjectWriteAuthority> {
    let Some(authority) = load_authority_for_update(transaction, writer_authority_id)? else {
        return Err(application(ApiError::not_found("ObjectWriteAuthority")));
    };
    let credentials = load_authority_credentials_for_update(transaction, writer_authority_id)?;
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

    /// Authenticate one attachment-scoped descriptor and persist its
    /// provisional request before any body bytes become provider-visible.
    pub fn begin_object_write_ingress(
        &self,
        authenticated_attachment: &AuthenticatedNodeCredential,
        descriptor: &ObjectWriteIngressDescriptor,
    ) -> crate::store::Result<StoredObjectWriteAttempt> {
        self.authority_transaction(|transaction| {
            begin_ingress_in(transaction, authenticated_attachment, descriptor)
        })
    }

    /// Bind a stable, cross-replica spool receipt to a provisional request.
    /// An exact retry may discover that a prior call already accepted or
    /// rejected the request, so the complete stored phase is returned.
    pub fn mark_object_write_spool_durable(
        &self,
        request_id: &Sha256Digest,
        spool: &DurableObjectWriteSpoolReceipt,
    ) -> crate::store::Result<StoredObjectWriteAttempt> {
        self.authority_transaction(|transaction| {
            let Some(stored) = load_attempt_for_update(transaction, request_id)? else {
                return Err(application(ApiError::not_found("ObjectWriteAttempt")));
            };
            match stored {
                StoredObjectWriteAttempt::Accepted(attempt) => {
                    let embedded = match &attempt.state {
                        ObjectPutState::AcceptedSpooled { spool }
                        | ObjectPutState::ProviderIssued { spool, .. }
                        | ObjectPutState::QualificationResponseLost { spool, .. } => spool,
                        ObjectPutState::Terminal { spool, .. } => match spool {
                            TerminalObjectWriteSpool::Retained { spool }
                            | TerminalObjectWriteSpool::Removed { spool, .. } => spool,
                        },
                    };
                    if !same_spool_material(embedded, spool) {
                        return Err(application(ApiError::conflict(
                            "object-write durable spool replay changed its receipt",
                        )));
                    }
                    Ok(StoredObjectWriteAttempt::Accepted(attempt))
                }
                StoredObjectWriteAttempt::Ingress(attempt) => {
                    if let ObjectWriteIngressState::RejectedBeforeAccept {
                        spool: embedded, ..
                    } = &attempt.state
                    {
                        if !same_spool_material(embedded, spool) {
                            return Err(application(ApiError::conflict(
                                "object-write durable spool replay changed its receipt",
                            )));
                        }
                        return Ok(StoredObjectWriteAttempt::Ingress(attempt));
                    }
                    if let ObjectWriteIngressState::DurableSpooled { spool: embedded } =
                        &attempt.state
                    {
                        if !same_spool_material(embedded, spool) {
                            return Err(application(ApiError::conflict(
                                "object-write durable spool replay changed its receipt",
                            )));
                        }
                        return Ok(StoredObjectWriteAttempt::Ingress(attempt));
                    }
                    let mut spool = spool.clone();
                    // PostgreSQL time orders the fsync receipt after the
                    // receiving row without trusting Pod wall-clock skew.
                    spool.durable_at_unix_ms = database_now(transaction)?;
                    let updated = mark_object_write_spool_durable(&attempt, spool)
                        .map_err(authority_error)?;
                    if updated != attempt {
                        persist_durable_ingress(transaction, &updated)?;
                    }
                    Ok(StoredObjectWriteAttempt::Ingress(updated))
                }
            }
        })
    }

    /// Assign a writer sequence only after durable spooling. Closing the
    /// parent or finding a conflicting immutable object key persists a
    /// terminal pre-accept rejection and never issues a provider request.
    pub fn accept_durable_object_write(
        &self,
        request_id: &Sha256Digest,
    ) -> crate::store::Result<ObjectWriteAcceptanceOutcome> {
        self.authority_transaction(|transaction| accept_durable_in(transaction, request_id))
    }

    /// Persist provider issue before the first external PUT. Exact replay
    /// returns the existing later phase rather than issuing another attempt.
    pub fn mark_object_write_provider_issued(
        &self,
        request_id: &Sha256Digest,
    ) -> crate::store::Result<ObjectPutAttempt> {
        self.authority_transaction(|transaction| {
            let Some(writer_authority_id) = load_attempt_parent_id(transaction, request_id)? else {
                return Err(application(ApiError::not_found("ObjectWriteAttempt")));
            };
            let Some(authority) = load_authority_for_update(transaction, &writer_authority_id)?
            else {
                return Err(corrupt("object-write attempt parent is missing"));
            };
            let Some(stored) = load_attempt_for_update(transaction, request_id)? else {
                return Err(corrupt(
                    "object-write attempt disappeared while parent was locked",
                ));
            };
            let StoredObjectWriteAttempt::Accepted(attempt) = stored else {
                return Err(application(ApiError::failed_precondition(
                    "object-write request has not been accepted",
                )));
            };
            validate_object_put_attempt(&authority, &attempt).map_err(authority_error)?;
            if !matches!(attempt.state, ObjectPutState::AcceptedSpooled { .. }) {
                return Ok(attempt);
            }
            let updated =
                mark_object_write_provider_issued(&authority, &attempt, database_now(transaction)?)
                    .map_err(authority_error)?;
            persist_provider_issued(transaction, &updated)?;
            Ok(updated)
        })
    }

    /// Settle the provider attempt only after exact visibility discovery or a
    /// provider-authoritative permanent failure, then advance the contiguous
    /// terminal prefix in the same transaction.
    pub fn complete_object_write_terminal(
        &self,
        request_id: &Sha256Digest,
        outcome: &ObjectPutTerminalState,
    ) -> crate::store::Result<ObjectPutAttempt> {
        self.authority_transaction(|transaction| {
            let Some(writer_authority_id) = load_attempt_parent_id(transaction, request_id)? else {
                return Err(application(ApiError::not_found("ObjectWriteAttempt")));
            };
            let Some(authority) = load_authority_for_update(transaction, &writer_authority_id)?
            else {
                return Err(corrupt("object-write attempt parent is missing"));
            };
            let Some(stored) = load_attempt_for_update(transaction, request_id)? else {
                return Err(corrupt(
                    "object-write attempt disappeared while parent was locked",
                ));
            };
            let StoredObjectWriteAttempt::Accepted(attempt) = stored else {
                return Err(application(ApiError::failed_precondition(
                    "object-write request has not been accepted",
                )));
            };
            validate_object_put_attempt(&authority, &attempt).map_err(authority_error)?;
            if matches!(attempt.state, ObjectPutState::Terminal { .. }) {
                return Ok(attempt);
            }
            let terminal = complete_object_write_terminal(&authority, &attempt, outcome.clone())
                .map_err(authority_error)?;
            persist_terminal_attempt(transaction, &terminal)?;
            let _ = advance_terminal_prefix_in(transaction, &authority)?;
            Ok(terminal)
        })
    }

    pub fn mark_terminal_object_write_spool_removed(
        &self,
        request_id: &Sha256Digest,
        removal_receipt_id: &AsciiText,
    ) -> crate::store::Result<ObjectPutAttempt> {
        self.authority_transaction(|transaction| {
            let Some(writer_authority_id) = load_attempt_parent_id(transaction, request_id)? else {
                return Err(application(ApiError::not_found("ObjectWriteAttempt")));
            };
            let Some(authority) = load_authority_for_update(transaction, &writer_authority_id)?
            else {
                return Err(corrupt("object-write attempt parent is missing"));
            };
            let Some(stored) = load_attempt_for_update(transaction, request_id)? else {
                return Err(corrupt(
                    "object-write attempt disappeared while parent was locked",
                ));
            };
            let StoredObjectWriteAttempt::Accepted(attempt) = stored else {
                return Err(application(ApiError::failed_precondition(
                    "object-write request has not been accepted",
                )));
            };
            validate_object_put_attempt(&authority, &attempt).map_err(authority_error)?;
            if matches!(
                attempt.state,
                ObjectPutState::Terminal {
                    spool: TerminalObjectWriteSpool::Removed { .. },
                    ..
                }
            ) {
                return Ok(attempt);
            }
            let updated = mark_terminal_object_write_spool_removed(
                &authority,
                &attempt,
                removal_receipt_id.clone(),
                database_now(transaction)?,
            )
            .map_err(authority_error)?;
            persist_spool_removed(transaction, &updated)?;
            Ok(updated)
        })
    }

    /// Advance at most one bounded page. Recovery repeats this call until the
    /// returned prefix stops changing or reaches the cutoff snapshot.
    pub fn advance_object_write_terminal_prefix(
        &self,
        writer_authority_id: &Id,
    ) -> crate::store::Result<ObjectWriteAuthority> {
        self.authority_transaction(|transaction| {
            let Some(authority) = load_authority_for_update(transaction, writer_authority_id)?
            else {
                return Err(application(ApiError::not_found("ObjectWriteAuthority")));
            };
            advance_terminal_prefix_in(transaction, &authority)
        })
    }

    pub fn complete_object_writer_cutoff(
        &self,
        writer_authority_id: &Id,
    ) -> crate::store::Result<ObjectWriteAuthority> {
        self.authority_transaction(|transaction| {
            let Some(authority) = load_authority_for_update(transaction, writer_authority_id)?
            else {
                return Err(application(ApiError::not_found("ObjectWriteAuthority")));
            };
            let authority = advance_terminal_prefix_in(transaction, &authority)?;
            let cutoff_sequence = match &authority.state {
                ObjectWriteAuthorityState::CutoffPending {
                    cutoff_sequence, ..
                } => *cutoff_sequence,
                ObjectWriteAuthorityState::CutoffComplete { .. } => return Ok(authority),
                ObjectWriteAuthorityState::Open => {
                    return Err(application(ApiError::failed_precondition(
                        "object-write authority cutoff has not started",
                    )));
                }
            };
            if authority.terminal_prefix_sequence != cutoff_sequence {
                // Commit this bounded prefix page. The recovery coordinator
                // repeats the same call until it reaches the cutoff snapshot.
                return Ok(authority);
            }
            let (complete, _) =
                complete_object_writer_cutoff(&authority, database_now(transaction)?)
                    .map_err(authority_error)?;
            persist_authority(transaction, &complete)?;
            Ok(complete)
        })
    }

    /// Bounded crash-recovery page. Accepted spools, ambiguous issued PUTs,
    /// and terminal rows whose durable body has not yet been removed remain
    /// discoverable; provisional orphan spools are not accepted authority.
    pub fn recoverable_object_write_attempts(
        &self,
        after_request_id: Option<&Sha256Digest>,
    ) -> crate::store::Result<Vec<ObjectPutAttempt>> {
        self.authority_transaction(|transaction| {
            let after = after_request_id.map(Sha256Digest::as_str);
            transaction
                .query(
                    "SELECT attempt.record::text AS record_json, attempt.state,
                            authority.record::text AS authority_json
                       FROM object_write_attempts attempt
                       JOIN object_write_authorities authority
                         ON authority.writer_authority_id=attempt.writer_authority_id
                      WHERE attempt.state IN (
                        'accepted_spooled', 'provider_issued',
                        'qualification_response_lost', 'terminal_visible',
                        'permanent', 'qualification_unproven_visible'
                      )
                        AND ($1::TEXT IS NULL
                             OR attempt.request_id COLLATE \"C\" > $1 COLLATE \"C\")
                      ORDER BY attempt.request_id COLLATE \"C\"
                      LIMIT $2",
                    &[&after, &OBJECT_WRITE_RECOVERY_LIMIT],
                )?
                .iter()
                .map(|row| {
                    let authority: ObjectWriteAuthority = decode(row.try_get("authority_json")?)?;
                    validate_object_write_authority(&authority).map_err(authority_error)?;
                    let StoredObjectWriteAttempt::Accepted(attempt) = decode_stored_attempt(row)?
                    else {
                        return Err(corrupt("object-write recovery selected a provisional row"));
                    };
                    validate_object_put_attempt(&authority, &attempt).map_err(authority_error)?;
                    Ok(attempt)
                })
                .collect()
        })
    }

    /// Bounded keyset page for recovering pre-accept crash windows. A
    /// receiving row may already have a fully linked durable body when the
    /// gateway crashed before persisting its fsync receipt.
    pub fn recoverable_object_write_ingress_attempts(
        &self,
        after_request_id: Option<&Sha256Digest>,
    ) -> crate::store::Result<Vec<ObjectWriteIngressAttempt>> {
        self.authority_transaction(|transaction| {
            let after = after_request_id.map(Sha256Digest::as_str);
            transaction
                .query(
                    "SELECT record::text AS record_json, state
                       FROM object_write_attempts
                      WHERE state IN (
                        'receiving', 'durable_spooled', 'rejected_before_accept'
                      )
                        AND ($1::TEXT IS NULL OR request_id COLLATE \"C\" > $1 COLLATE \"C\")
                      ORDER BY request_id COLLATE \"C\"
                      LIMIT $2",
                    &[&after, &OBJECT_WRITE_RECOVERY_LIMIT],
                )?
                .iter()
                .map(|row| {
                    let StoredObjectWriteAttempt::Ingress(attempt) = decode_stored_attempt(row)?
                    else {
                        return Err(corrupt(
                            "provisional object-write recovery selected an accepted row",
                        ));
                    };
                    Ok(attempt)
                })
                .collect()
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
            begin_object_writer_cutoff_in(
                transaction,
                writer_authority_id,
                fence_attempt_id,
                cutoff_effective_at_unix_ms,
            )
        })
    }
}

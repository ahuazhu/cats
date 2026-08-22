//! Host-scoped object-writer root authority retained after the AgentSession
//! transport was withdrawn.
//!
//! Attachment credential and ingress methods remain archived in
//! `object_write.rs` for the semantic storage adapter.  This compiled slice is
//! intentionally limited to provisioner-owned root creation and exact Host
//! fence cutoff, neither of which needs an AgentSession row.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    AsciiText, Id, NodeIdentity, ProviderScope, UnixMillis, WireU64,
};
use cats_storage::object_write_authority::{
    begin_object_writer_cutoff, empty_terminal_prefix_sha256, validate_object_write_authority,
    ObjectWriteAuthority, ObjectWriteAuthorityState, ObjectWriteCredentialBinding,
    ObjectWriteCredentialRetirementCause, ObjectWriteCredentialState, ObjectWriterIdentity,
};
use postgres::Transaction;

use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

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

#[allow(
    dead_code,
    reason = "retained for the semantic storage adapter's exact Host-fence cutoff"
)]
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

pub(super) fn open_object_write_authority_in(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
    writer_authority_id: &Id,
    object_provider_scope: &ProviderScope,
    workload_principal_id: &AsciiText,
    object_store_scope_id: &AsciiText,
) -> AuthorityTxResult<bool> {
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
    if !transaction
        .query(
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
        )?
        .is_empty()
        || load_authority_for_update(transaction, writer_authority_id)?.is_some()
    {
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

#[allow(
    dead_code,
    reason = "retained for the semantic storage adapter's exact Host-fence cutoff"
)]
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

#[allow(
    dead_code,
    reason = "retained for the semantic storage adapter's exact Host-fence cutoff"
)]
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

#[allow(
    dead_code,
    reason = "retained for the semantic storage adapter's exact Host-fence cutoff"
)]
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

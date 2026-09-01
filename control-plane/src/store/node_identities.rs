//! Persisted provisioner-owned Node identity lineage.
//!
//! AgentSession registration was retired by the semantic cutover.  The
//! immutable machine identity and credential lineage remain because the
//! provisioner-owned Node authority still depends on them independently of
//! the semantic heartbeat transport.

use cats_protocol::node_identity::validate_state_path_component;
use cats_protocol::runtime_reconciliation::{
    decode_node_identity, encode_node_identity, CredentialBinding, Id, NodeIdentity,
    NodeIdentityState, Sha256Digest, UnixMillis,
};
use postgres::{Row, Transaction};

use super::runtime_authority::pg_codec::PgBigInt;
use super::runtime_authority::rows::database_now;
use super::transaction::{AuthorityTransactionError, AuthorityTxResult};
use super::{internal, Result, Store};

const NODE_IDENTITY_COLUMNS: &str = "
    node_id, record::text AS record_json, host_provider, host_partition,
    host_account_id, host_region, immutable_host_id, credential_id,
    credential_kind, credential_public_key_spki_sha256, credential_provider,
    credential_principal, credential_lineage_state, state_path_id, state";

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeIdentityProjection {
    node_id: String,
    host_provider: String,
    host_partition: String,
    host_account_id: String,
    host_region: String,
    immutable_host_id: String,
    credential_id: String,
    credential_kind: String,
    credential_public_key_spki_sha256: Option<String>,
    credential_provider: Option<String>,
    credential_principal: Option<String>,
    credential_lineage_state: Option<String>,
    state_path_id: String,
    state: String,
}

impl NodeIdentityProjection {
    fn from_record(record: &NodeIdentity) -> Self {
        let (credential_kind, public_key, provider, principal, lineage_state) =
            match &record.credential_binding {
                CredentialBinding::PublicKey {
                    public_key_spki_sha256,
                } => (
                    "public_key",
                    Some(public_key_spki_sha256.to_string()),
                    None,
                    None,
                    Some(match record.state {
                        NodeIdentityState::Provisioned => "active",
                        NodeIdentityState::Retired => "retired",
                    }),
                ),
                CredentialBinding::ProviderPrincipal {
                    provider,
                    principal,
                } => (
                    "provider_principal",
                    None,
                    Some(provider.to_string()),
                    Some(principal.to_string()),
                    None,
                ),
            };
        Self {
            node_id: record.node_id.to_string(),
            host_provider: record.provider_scope.provider.to_string(),
            host_partition: record.provider_scope.partition.to_string(),
            host_account_id: record.provider_scope.account_id.to_string(),
            host_region: record.provider_scope.region.to_string(),
            immutable_host_id: record.immutable_host_id.to_string(),
            credential_id: record.credential_id.to_string(),
            credential_kind: credential_kind.to_owned(),
            credential_public_key_spki_sha256: public_key,
            credential_provider: provider,
            credential_principal: principal,
            credential_lineage_state: lineage_state.map(str::to_owned),
            state_path_id: record.state_path_id.to_string(),
            state: match record.state {
                NodeIdentityState::Provisioned => "provisioned",
                NodeIdentityState::Retired => "retired",
            }
            .to_owned(),
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            node_id: row.try_get("node_id")?,
            host_provider: row.try_get("host_provider")?,
            host_partition: row.try_get("host_partition")?,
            host_account_id: row.try_get("host_account_id")?,
            host_region: row.try_get("host_region")?,
            immutable_host_id: row.try_get("immutable_host_id")?,
            credential_id: row.try_get("credential_id")?,
            credential_kind: closed_text(
                row.try_get("credential_kind")?,
                &["public_key", "provider_principal"],
            )?,
            credential_public_key_spki_sha256: row.try_get("credential_public_key_spki_sha256")?,
            credential_provider: row.try_get("credential_provider")?,
            credential_principal: row.try_get("credential_principal")?,
            credential_lineage_state: row.try_get("credential_lineage_state")?,
            state_path_id: row.try_get("state_path_id")?,
            state: closed_text(row.try_get("state")?, &["provisioned", "retired"])?,
        })
    }
}

impl Store {
    /// Idempotently inserts a provisioned identity without reviving retired
    /// Node or credential lineage.
    pub(crate) fn provision_node_identity(&self, identity: &NodeIdentity) -> Result<()> {
        if identity.state != NodeIdentityState::Provisioned {
            return Err(super::ApiError::invalid(
                "a newly provisioned NodeIdentity must be provisioned",
            ));
        }
        validate_state_path_component(&identity.state_path_id).map_err(|_| {
            super::ApiError::invalid("NodeIdentity state_path_id is not a safe path component")
        })?;
        self.authority_transaction(|transaction| {
            let committed_at = database_now(transaction)?;
            let inserted = insert_node_identity_in(transaction, identity, committed_at)?;
            if inserted == 1 {
                return Ok(());
            }
            match load_identity_by_node_for_update(transaction, &identity.node_id)? {
                Some(existing) if existing == *identity => Ok(()),
                _ => Err(AuthorityTransactionError::Application(
                    super::ApiError::conflict(
                        "NodeIdentity node, credential, or Host/state-path lineage already exists",
                    ),
                )),
            }
        })
    }
}

pub(super) fn insert_node_identity_in(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
    committed_at: UnixMillis,
) -> AuthorityTxResult<u64> {
    let record_json = encode_identity(identity)?;
    let projection = NodeIdentityProjection::from_record(identity);
    let inserted = transaction.execute(
        "INSERT INTO node_identities (
            node_id, record, host_provider, host_partition, host_account_id,
            host_region, immutable_host_id, credential_id,
            credential_kind, credential_public_key_spki_sha256,
            credential_provider, credential_principal,
            credential_lineage_state, state_path_id, state
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10,
                   $11, $12, $13, $14, $15)
         ON CONFLICT DO NOTHING",
        &[
            &projection.node_id,
            &record_json,
            &projection.host_provider,
            &projection.host_partition,
            &projection.host_account_id,
            &projection.host_region,
            &projection.immutable_host_id,
            &projection.credential_id,
            &projection.credential_kind,
            &projection.credential_public_key_spki_sha256,
            &projection.credential_provider,
            &projection.credential_principal,
            &projection.credential_lineage_state,
            &projection.state_path_id,
            &projection.state,
        ],
    )?;
    if inserted == 1 {
        if let Some(public_key) = &projection.credential_public_key_spki_sha256 {
            let committed_at = committed_at.to_pg().map_err(corrupt)?;
            exactly_one(transaction.execute(
                "INSERT INTO runtime_node_credential_lineage (
                    credential_id, node_id, public_key_spki_sha256,
                    state, first_committed_at_unix_ms, retired_at_unix_ms
                 ) VALUES ($1, $2, $3, 'active', $4, NULL)",
                &[
                    &projection.credential_id,
                    &projection.node_id,
                    public_key,
                    &committed_at,
                ],
            )?)?;
        }
    }
    Ok(inserted)
}

pub(super) fn rotate_public_key_identity_in(
    transaction: &mut Transaction<'_>,
    current: &NodeIdentity,
    new_credential_id: &Id,
    new_public_key_spki_sha256: &Sha256Digest,
    committed_at: UnixMillis,
) -> AuthorityTxResult<NodeIdentity> {
    if current.state != NodeIdentityState::Provisioned
        || !matches!(
            current.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
    {
        return Err(corrupt("only an active public-key NodeIdentity can rotate"));
    }
    let mut next = current.clone();
    next.credential_id = new_credential_id.clone();
    next.credential_binding = CredentialBinding::PublicKey {
        public_key_spki_sha256: new_public_key_spki_sha256.clone(),
    };
    let projection = NodeIdentityProjection::from_record(&next);
    let record_json = encode_identity(&next)?;
    let committed_at = committed_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "UPDATE runtime_node_credential_lineage
            SET state='retired', retired_at_unix_ms=$3
          WHERE credential_id=$1 AND node_id=$2 AND state='active'",
        &[
            &current.credential_id.as_str(),
            &current.node_id.as_str(),
            &committed_at,
        ],
    )?)?;
    exactly_one(transaction.execute(
        "INSERT INTO runtime_node_credential_lineage (
            credential_id, node_id, public_key_spki_sha256,
            state, first_committed_at_unix_ms, retired_at_unix_ms
         ) VALUES ($1, $2, $3, 'active', $4, NULL)",
        &[
            &projection.credential_id,
            &projection.node_id,
            &projection.credential_public_key_spki_sha256,
            &committed_at,
        ],
    )?)?;
    exactly_one(transaction.execute(
        "UPDATE node_identities
            SET record=$2::TEXT::jsonb, credential_id=$3,
                credential_public_key_spki_sha256=$4,
                credential_lineage_state='active'
          WHERE node_id=$1 AND state='provisioned'",
        &[
            &projection.node_id,
            &record_json,
            &projection.credential_id,
            &projection.credential_public_key_spki_sha256,
        ],
    )?)?;
    Ok(next)
}

pub(super) fn retire_node_identity_in(
    transaction: &mut Transaction<'_>,
    current: &NodeIdentity,
    retired_at: UnixMillis,
) -> AuthorityTxResult<NodeIdentity> {
    if current.state != NodeIdentityState::Provisioned {
        return Err(corrupt("only a provisioned NodeIdentity can retire"));
    }
    let mut retired = current.clone();
    retired.state = NodeIdentityState::Retired;
    let record_json = encode_identity(&retired)?;
    let retired_at = retired_at.to_pg().map_err(corrupt)?;
    if matches!(
        current.credential_binding,
        CredentialBinding::PublicKey { .. }
    ) {
        exactly_one(transaction.execute(
            "UPDATE runtime_node_credential_lineage
                SET state='retired', retired_at_unix_ms=$3
              WHERE credential_id=$1 AND node_id=$2 AND state='active'",
            &[
                &current.credential_id.as_str(),
                &current.node_id.as_str(),
                &retired_at,
            ],
        )?)?;
    }
    exactly_one(transaction.execute(
        "UPDATE node_identities
            SET record=$2::TEXT::jsonb, state='retired',
                credential_lineage_state = CASE
                    WHEN credential_kind='public_key' THEN 'retired' ELSE NULL END
          WHERE node_id=$1 AND state='provisioned'",
        &[&current.node_id.as_str(), &record_json],
    )?)?;
    Ok(retired)
}

pub(super) fn load_identity_by_node_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    let sql = format!(
        "SELECT {NODE_IDENTITY_COLUMNS} FROM node_identities
          WHERE node_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&node_id.as_str()])?
        .map(|row| decode_identity(&row))
        .transpose()
}

fn decode_identity(row: &Row) -> AuthorityTxResult<NodeIdentity> {
    let stored = NodeIdentityProjection::from_row(row)?;
    let record_json: String = row.try_get("record_json")?;
    let identity = decode_node_identity(record_json.as_bytes()).map_err(corrupt)?;
    if stored != NodeIdentityProjection::from_record(&identity) {
        return Err(corrupt("NodeIdentity JSON/projection mismatch"));
    }
    Ok(identity)
}

fn encode_identity(identity: &NodeIdentity) -> AuthorityTxResult<String> {
    let bytes = encode_node_identity(identity).map_err(corrupt)?;
    String::from_utf8(bytes).map_err(corrupt)
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt("expected exactly one changed row"))
    }
}

fn closed_text(value: String, allowed: &[&str]) -> AuthorityTxResult<String> {
    allowed
        .contains(&value.as_str())
        .then_some(value)
        .ok_or_else(|| corrupt("stored closed projection has an unknown value"))
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(internal(
        "Node identity Store persisted contract or generated value is invalid",
    ))
}

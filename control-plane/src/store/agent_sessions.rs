//! PostgreSQL authority for provisioned Node identities and Agent registration.
//!
//! The registration request never chooses its identity. An authentication
//! adapter first produces [`AuthenticatedNodeCredential`], and the Store uses
//! that credential to select and lock the provisioned `NodeIdentity` before it
//! considers any identity claimed by the registration attempt.

use cats_api::agent_registration::{
    validate_state_path_component, AuthenticatedNodeCredential, AGENT_SESSION_LEASE_MS,
};
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, decode_agent_session, decode_node_identity,
    encode_agent_registration_attempt, encode_agent_session, encode_node_identity,
    guest_config_digest, AgentRegistrationAttempt, AgentSession, ContractError,
    ContractErrorDetail, ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id,
    NodeIdentity, NodeIdentityState, RegistrationAttemptBinding, Sha256Digest, UnixMillis,
};
use postgres::{Row, Transaction};

use super::runtime_authority::pg_codec::PgBigInt;
use super::runtime_authority::rows::database_now;
use super::transaction::{AuthorityTransactionError, AuthorityTxResult};
use super::{internal, Result, Store};

const NODE_IDENTITY_COLUMNS: &str = "
    node_id, record::text AS record_json, immutable_host_id, credential_id,
    credential_kind, credential_public_key_spki_sha256, credential_provider,
    credential_principal, credential_lineage_state, state_path_id, state";
const REGISTRATION_ATTEMPT_COLUMNS: &str = "
    node_id, registration_attempt_id, attempt_record::text AS attempt_record_json,
    immutable_host_id, node_boot_id, agent_instance_id, guest_config_digest,
    expected_agent_session_epoch, session_record::text AS session_record_json,
    agent_session_epoch, lease_deadline_unix_ms";
const CURRENT_SESSION_COLUMNS: &str = "
    node_id, record::text AS record_json, immutable_host_id, node_boot_id,
    agent_instance_id, agent_session_epoch, registration_attempt_id,
    guest_config_digest, lease_deadline_unix_ms";
pub(super) const PROVISIONED_NODE_ID_PAGE_SIZE: usize = 64;
const PROVISIONED_NODE_ID_QUERY_LIMIT: i64 = PROVISIONED_NODE_ID_PAGE_SIZE as i64;

/// Process-lifetime registration policy derived from one validated release
/// artifact. The lease is the fixed V1 protocol constant, not configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSessionRegistrationPolicy {
    approved_guest_config_digest: Sha256Digest,
}

impl AgentSessionRegistrationPolicy {
    pub(crate) fn from_release_receipt(receipt: &GuestRuntimeProfileReceipt) -> Result<Self> {
        let approved_guest_config_digest = guest_config_digest(receipt).map_err(|error| {
            super::ApiError::failed_precondition(format!(
                "invalid active Guest runtime profile receipt: {error}"
            ))
        })?;
        Ok(Self {
            approved_guest_config_digest,
        })
    }

    pub(crate) fn approved_guest_config_digest(&self) -> &Sha256Digest {
        &self.approved_guest_config_digest
    }
}

/// Store-internal precondition results that do not yet have a frozen public
/// registration wire error. The public RPC slice must freeze that mapping
/// before exposing it; it must not turn these values into a fabricated
/// `ContractError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentRegistrationRejection {
    IdentityNotEligible,
    SessionEpochMismatch {
        current_agent_session_epoch: Option<Epoch>,
        presented_expected_agent_session_epoch: Option<Epoch>,
    },
    Contract(ContractError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentRegistrationOutcome {
    Registered(AgentSession),
    Rejected(AgentRegistrationRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeIdentityProjection {
    node_id: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistrationAttemptProjection {
    node_id: String,
    registration_attempt_id: String,
    immutable_host_id: String,
    node_boot_id: String,
    agent_instance_id: String,
    guest_config_digest: String,
    expected_agent_session_epoch: Option<Epoch>,
    agent_session_epoch: Epoch,
    lease_deadline_unix_ms: UnixMillis,
}

impl RegistrationAttemptProjection {
    fn from_records(
        attempt: &AgentRegistrationAttempt,
        session: &AgentSession,
    ) -> AuthorityTxResult<Self> {
        let expected_result_epoch = match attempt.expected_agent_session_epoch {
            Some(epoch) => epoch
                .get()
                .checked_add(1)
                .and_then(Epoch::new)
                .ok_or_else(|| corrupt("registration attempt expected epoch is exhausted"))?,
            None => Epoch::new(1).expect("one is a valid Agent session epoch"),
        };
        if session.version != ContractVersion::V1
            || session.node_id != attempt.node_id
            || session.immutable_host_id != attempt.immutable_host_id
            || session.node_boot_id != attempt.node_boot_id
            || session.agent_instance_id != attempt.agent_instance_id
            || session.agent_session_epoch != expected_result_epoch
            || session.registration_attempt_id != attempt.registration_attempt_id
            || session.guest_config_digest != attempt.guest_config_digest
        {
            return Err(corrupt("registration attempt/result binding mismatch"));
        }
        Ok(Self {
            node_id: attempt.node_id.to_string(),
            registration_attempt_id: attempt.registration_attempt_id.to_string(),
            immutable_host_id: attempt.immutable_host_id.to_string(),
            node_boot_id: attempt.node_boot_id.to_string(),
            agent_instance_id: attempt.agent_instance_id.to_string(),
            guest_config_digest: attempt.guest_config_digest.to_string(),
            expected_agent_session_epoch: attempt.expected_agent_session_epoch,
            agent_session_epoch: session.agent_session_epoch,
            lease_deadline_unix_ms: session.lease_deadline_unix_ms,
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            node_id: row.try_get("node_id")?,
            registration_attempt_id: row.try_get("registration_attempt_id")?,
            immutable_host_id: row.try_get("immutable_host_id")?,
            node_boot_id: row.try_get("node_boot_id")?,
            agent_instance_id: row.try_get("agent_instance_id")?,
            guest_config_digest: row.try_get("guest_config_digest")?,
            expected_agent_session_epoch: optional_from_pg(
                row.try_get("expected_agent_session_epoch")?,
            )?,
            agent_session_epoch: from_pg(row.try_get("agent_session_epoch")?)?,
            lease_deadline_unix_ms: from_pg(row.try_get("lease_deadline_unix_ms")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionProjection {
    node_id: String,
    immutable_host_id: String,
    node_boot_id: String,
    agent_instance_id: String,
    agent_session_epoch: Epoch,
    registration_attempt_id: String,
    guest_config_digest: String,
    lease_deadline_unix_ms: UnixMillis,
}

impl SessionProjection {
    fn from_record(session: &AgentSession) -> Self {
        Self {
            node_id: session.node_id.to_string(),
            immutable_host_id: session.immutable_host_id.to_string(),
            node_boot_id: session.node_boot_id.to_string(),
            agent_instance_id: session.agent_instance_id.to_string(),
            agent_session_epoch: session.agent_session_epoch,
            registration_attempt_id: session.registration_attempt_id.to_string(),
            guest_config_digest: session.guest_config_digest.to_string(),
            lease_deadline_unix_ms: session.lease_deadline_unix_ms,
        }
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            node_id: row.try_get("node_id")?,
            immutable_host_id: row.try_get("immutable_host_id")?,
            node_boot_id: row.try_get("node_boot_id")?,
            agent_instance_id: row.try_get("agent_instance_id")?,
            agent_session_epoch: from_pg(row.try_get("agent_session_epoch")?)?,
            registration_attempt_id: row.try_get("registration_attempt_id")?,
            guest_config_digest: row.try_get("guest_config_digest")?,
            lease_deadline_unix_ms: from_pg(row.try_get("lease_deadline_unix_ms")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredRegistrationAttempt {
    attempt: AgentRegistrationAttempt,
    session: AgentSession,
}

impl Store {
    /// Idempotently inserts a new provisioned identity. It never rewrites an
    /// existing identity, so a retired lineage cannot be revived.
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

    /// Permanently retires one exact identity while preserving its lineage.
    #[cfg(test)]
    pub(crate) fn retire_node_identity(&self, node_id: &Id) -> Result<()> {
        self.authority_transaction(|transaction| {
            let Some(identity) = load_identity_by_node_for_update(transaction, node_id)? else {
                return Err(AuthorityTransactionError::Application(
                    super::ApiError::not_found("NodeIdentity"),
                ));
            };
            if identity.state == NodeIdentityState::Retired {
                return Ok(());
            }
            let retired_at = database_now(transaction)?;
            retire_node_identity_in(transaction, &identity, retired_at).map(|_| ())
        })
    }

    /// Atomically registers or replaces the current Agent session.
    ///
    /// Exact attempt replay returns the first committed session, including its
    /// original deadline. A new attempt allocates epoch and deadline only
    /// after identity, replay, active-release and expected-epoch validation.
    pub(crate) fn register_agent_session(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        attempt: &AgentRegistrationAttempt,
        policy: &AgentSessionRegistrationPolicy,
    ) -> Result<AgentRegistrationOutcome> {
        if let Err(error) = encode_agent_registration_attempt(attempt) {
            return Ok(AgentRegistrationOutcome::Rejected(
                AgentRegistrationRejection::Contract(error),
            ));
        }
        self.authority_transaction(|transaction| {
            register_agent_session_in(transaction, authenticated, attempt, policy)
        })
    }
}

/// Inserts both sides of the deferred current-credential lineage invariant.
/// Callers own the node-scoped/advisory lock that makes an absent identity a
/// stable fact for their larger transaction.
pub(super) fn insert_node_identity_in(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
    committed_at: UnixMillis,
) -> AuthorityTxResult<u64> {
    let record_json = encode_identity(identity)?;
    let projection = NodeIdentityProjection::from_record(identity);
    let inserted = transaction.execute(
        "INSERT INTO node_identities (
            node_id, record, immutable_host_id, credential_id,
            credential_kind, credential_public_key_spki_sha256,
            credential_provider, credential_principal,
            credential_lineage_state, state_path_id, state
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT DO NOTHING",
        &[
            &projection.node_id,
            &record_json,
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

/// Rotates both the current NodeIdentity binding and its all-history lineage
/// in one transaction. The deferred composite foreign key rejects any partial
/// update at commit.
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
            SET record=$2::TEXT::jsonb,
                credential_id=$3,
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

/// Permanently retires one current identity and its exact credential lineage.
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
                    WHEN credential_kind='public_key' THEN 'retired'
                    ELSE NULL
                END
          WHERE node_id=$1 AND state='provisioned'",
        &[&current.node_id.as_str(), &record_json],
    )?)?;
    Ok(retired)
}

fn register_agent_session_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    attempt: &AgentRegistrationAttempt,
    policy: &AgentSessionRegistrationPolicy,
) -> AuthorityTxResult<AgentRegistrationOutcome> {
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated.credential_id())?
    else {
        return Ok(identity_rejected());
    };
    if !matches!(
        &identity.credential_binding,
        CredentialBinding::PublicKey { .. }
    ) || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || identity.node_id != attempt.node_id
    {
        return Ok(identity_rejected());
    }
    let Some(lineage_state) = lock_exact_credential_lineage(transaction, &identity)? else {
        return Ok(identity_rejected());
    };

    if let Some(stored) = load_attempt_for_update(
        transaction,
        &identity.node_id,
        &attempt.registration_attempt_id,
    )? {
        if stored.attempt == *attempt {
            return Ok(AgentRegistrationOutcome::Registered(stored.session));
        }
        return Ok(AgentRegistrationOutcome::Rejected(
            AgentRegistrationRejection::Contract(registration_attempt_conflict(
                &stored.attempt,
                attempt,
            )),
        ));
    }

    if identity.state != NodeIdentityState::Provisioned {
        return Ok(identity_rejected());
    }
    if lineage_state != CredentialLineageState::Active {
        return Ok(identity_rejected());
    }
    if identity.immutable_host_id != attempt.immutable_host_id {
        return Ok(identity_rejected());
    }
    if attempt.guest_config_digest != policy.approved_guest_config_digest {
        return Ok(AgentRegistrationOutcome::Rejected(
            AgentRegistrationRejection::Contract(guest_config_mismatch(
                attempt,
                &policy.approved_guest_config_digest,
            )),
        ));
    }

    let current = load_current_session_for_update(transaction, &identity.node_id)?;
    let current_epoch = current.as_ref().map(|session| session.agent_session_epoch);
    if attempt.expected_agent_session_epoch != current_epoch {
        return Ok(AgentRegistrationOutcome::Rejected(
            AgentRegistrationRejection::SessionEpochMismatch {
                current_agent_session_epoch: current_epoch,
                presented_expected_agent_session_epoch: attempt.expected_agent_session_epoch,
            },
        ));
    }

    let agent_session_epoch = match current_epoch {
        Some(epoch) => epoch
            .get()
            .checked_add(1)
            .and_then(Epoch::new)
            .ok_or_else(|| corrupt("Agent session epoch exhausted"))?,
        None => Epoch::new(1).expect("one is a valid Agent session epoch"),
    };
    let now = database_now(transaction)?;
    let lease_deadline_unix_ms = now
        .get()
        .checked_add(AGENT_SESSION_LEASE_MS)
        .and_then(UnixMillis::new)
        .ok_or_else(|| corrupt("Agent session lease deadline overflow"))?;
    let session = AgentSession {
        version: ContractVersion::V1,
        node_id: attempt.node_id.clone(),
        immutable_host_id: attempt.immutable_host_id.clone(),
        node_boot_id: attempt.node_boot_id.clone(),
        agent_instance_id: attempt.agent_instance_id.clone(),
        agent_session_epoch,
        registration_attempt_id: attempt.registration_attempt_id.clone(),
        guest_config_digest: attempt.guest_config_digest.clone(),
        lease_deadline_unix_ms,
    };
    insert_attempt(transaction, attempt, &session)?;
    match current_epoch {
        None => insert_current_session(transaction, &session)?,
        Some(expected) => replace_current_session(transaction, expected, &session)?,
    }
    Ok(AgentRegistrationOutcome::Registered(session))
}

pub(super) fn load_identity_by_credential_for_update(
    transaction: &mut Transaction<'_>,
    credential_id: &Id,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    let sql = format!(
        "SELECT {NODE_IDENTITY_COLUMNS} FROM node_identities
          WHERE credential_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&credential_id.as_str()])?
        .map(|row| decode_identity(&row))
        .transpose()
}

/// Locks the current identity selected by one authenticated credential for a
/// logically read-only runtime transaction. Rotation, retirement and session
/// replacement all take the same row for update, so this share lock keeps the
/// selected identity stable until the caller commits its complete snapshot.
#[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
pub(super) fn load_identity_by_credential_for_share(
    transaction: &mut Transaction<'_>,
    credential_id: &Id,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    let sql = format!(
        "SELECT {NODE_IDENTITY_COLUMNS} FROM node_identities
          WHERE credential_id=$1 FOR SHARE"
    );
    transaction
        .query_opt(&sql, &[&credential_id.as_str()])?
        .map(|row| decode_identity(&row))
        .transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialLineageState {
    Active,
    Retired,
}

/// Locks and closes the exact all-history public-key lineage referenced by a
/// locked NodeIdentity. A retired row remains readable only so registration
/// can exact-replay an immutable committed attempt before applying its new-
/// attempt eligibility gate; every other authenticated runtime path requires
/// `Active`.
pub(super) fn lock_exact_credential_lineage(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
) -> AuthorityTxResult<Option<CredentialLineageState>> {
    let CredentialBinding::PublicKey {
        public_key_spki_sha256,
    } = &identity.credential_binding
    else {
        return Ok(None);
    };
    let row = transaction.query_opt(
        "SELECT credential_id, node_id, public_key_spki_sha256, state,
                first_committed_at_unix_ms, retired_at_unix_ms
           FROM runtime_node_credential_lineage
          WHERE credential_id=$1 AND node_id=$2
            AND public_key_spki_sha256=$3 FOR SHARE",
        &[
            &identity.credential_id.as_str(),
            &identity.node_id.as_str(),
            &public_key_spki_sha256.as_str(),
        ],
    )?;
    let Some(row) = row else {
        return Err(corrupt(
            "NodeIdentity has no exact persisted credential lineage",
        ));
    };
    if row.try_get::<_, String>("credential_id")? != identity.credential_id.as_str()
        || row.try_get::<_, String>("node_id")? != identity.node_id.as_str()
        || row.try_get::<_, String>("public_key_spki_sha256")? != public_key_spki_sha256.as_str()
    {
        return Err(corrupt("credential lineage projection mismatch"));
    }
    let first: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
    let retired: Option<UnixMillis> = row
        .try_get::<_, Option<i64>>("retired_at_unix_ms")?
        .map(from_pg)
        .transpose()?;
    let state = match row.try_get::<_, String>("state")?.as_str() {
        "active" if retired.is_none() && identity.state == NodeIdentityState::Provisioned => {
            CredentialLineageState::Active
        }
        "retired"
            if retired.is_some_and(|retired_at| retired_at >= first)
                && identity.state == NodeIdentityState::Retired =>
        {
            CredentialLineageState::Retired
        }
        _ => return Err(corrupt("credential lineage state/time mismatch")),
    };
    Ok(Some(state))
}

pub(super) fn load_identity_by_credential_unlocked(
    transaction: &mut Transaction<'_>,
    credential_id: &Id,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    let sql = format!("SELECT {NODE_IDENTITY_COLUMNS} FROM node_identities WHERE credential_id=$1");
    transaction
        .query_opt(&sql, &[&credential_id.as_str()])?
        .map(|row| decode_identity(&row))
        .transpose()
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

pub(super) fn load_identity_by_node_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    let sql = format!("SELECT {NODE_IDENTITY_COLUMNS} FROM node_identities WHERE node_id=$1");
    transaction
        .query_opt(&sql, &[&node_id.as_str()])?
        .map(|row| decode_identity(&row))
        .transpose()
}

/// Returns at most one bounded keyset page from the NodeIdentity authority.
/// A full page requires one further keyset query to prove EOF; the loader must
/// never fetch or decode a larger Node than the frozen 64-row page. `state` is
/// used only to bound the candidate scan;
/// every returned row is still decoded and cross-checked against its complete
/// JSON record before it can become a planner candidate.
pub(super) fn load_provisioned_identities_after(
    transaction: &mut Transaction<'_>,
    after: Option<&Id>,
) -> AuthorityTxResult<Vec<NodeIdentity>> {
    let sql = format!(
        "SELECT {NODE_IDENTITY_COLUMNS} FROM node_identities
          WHERE state='provisioned'
            AND ($1::TEXT IS NULL OR node_id COLLATE \"C\" > $1 COLLATE \"C\")
          ORDER BY node_id COLLATE \"C\"
          LIMIT $2"
    );
    let after = after.map(Id::as_str);
    transaction
        .query(&sql, &[&after, &PROVISIONED_NODE_ID_QUERY_LIMIT])?
        .iter()
        .map(decode_identity)
        .map(|result| {
            let identity = result?;
            if identity.state != NodeIdentityState::Provisioned {
                return Err(corrupt(
                    "provisioned NodeIdentity page returned a non-provisioned record",
                ));
            }
            Ok(identity)
        })
        .collect()
}

/// Strictly decodes one bounded keyset page of the complete NodeIdentity
/// history for a fleet-wide verification snapshot. Retired rows remain in
/// the scan so projection corruption cannot hide behind a state predicate,
/// but their unbounded history never becomes a fleet cardinality limit.
pub(super) fn load_identity_history_after_for_fleet_verification(
    transaction: &mut Transaction<'_>,
    after: Option<&Id>,
) -> AuthorityTxResult<Vec<(NodeIdentity, bool, bool)>> {
    let sql = format!(
        "SELECT {NODE_IDENTITY_COLUMNS},
                EXISTS (
                    SELECT 1 FROM current_agent_sessions AS session
                     WHERE session.node_id=node_identities.node_id
                ) AS has_current_session,
                EXISTS (
                    SELECT 1 FROM runtime_admission_inventory_states AS inventory
                     WHERE inventory.node_id=node_identities.node_id
                ) AS has_admission_inventory
           FROM node_identities
          WHERE ($1::TEXT IS NULL OR node_id COLLATE \"C\" > $1 COLLATE \"C\")
          ORDER BY node_id COLLATE \"C\"
          LIMIT $2"
    );
    let after = after.map(Id::as_str);
    transaction
        .query(&sql, &[&after, &PROVISIONED_NODE_ID_QUERY_LIMIT])?
        .iter()
        .map(|row| {
            Ok((
                decode_identity(row)?,
                row.try_get("has_current_session")?,
                row.try_get("has_admission_inventory")?,
            ))
        })
        .collect()
}

/// Returns only the ordered scalar keys for one planner page. The planner
/// deliberately decodes each complete NodeIdentity only when it reaches that
/// candidate, so selecting an earlier eligible Node cannot be poisoned by a
/// malformed larger identity from the same SQL page.
pub(super) fn load_provisioned_node_keys_after(
    transaction: &mut Transaction<'_>,
    after: Option<&Id>,
) -> AuthorityTxResult<Vec<String>> {
    let after = after.map(Id::as_str);
    transaction
        .query(
            "SELECT node_id FROM node_identities
              WHERE state='provisioned'
                AND ($1::TEXT IS NULL OR node_id COLLATE \"C\" > $1 COLLATE \"C\")
              ORDER BY node_id COLLATE \"C\"
              LIMIT $2",
            &[&after, &PROVISIONED_NODE_ID_QUERY_LIMIT],
        )?
        .iter()
        .map(|row| {
            row.try_get("node_id")
                .map_err(AuthorityTransactionError::from)
        })
        .collect()
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

fn load_attempt_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    registration_attempt_id: &cats_api::runtime_reconciliation::RandomId128,
) -> AuthorityTxResult<Option<StoredRegistrationAttempt>> {
    let sql = format!(
        "SELECT {REGISTRATION_ATTEMPT_COLUMNS} FROM agent_registration_attempts
          WHERE node_id=$1 AND registration_attempt_id=$2 FOR UPDATE"
    );
    transaction
        .query_opt(
            &sql,
            &[&node_id.as_str(), &registration_attempt_id.as_str()],
        )?
        .map(|row| decode_attempt(&row))
        .transpose()
}

fn decode_attempt(row: &Row) -> AuthorityTxResult<StoredRegistrationAttempt> {
    let stored = RegistrationAttemptProjection::from_row(row)?;
    let attempt_json: String = row.try_get("attempt_record_json")?;
    let session_json: String = row.try_get("session_record_json")?;
    let attempt = decode_agent_registration_attempt(attempt_json.as_bytes()).map_err(corrupt)?;
    let session = decode_agent_session(session_json.as_bytes()).map_err(corrupt)?;
    if stored != RegistrationAttemptProjection::from_records(&attempt, &session)? {
        return Err(corrupt("registration attempt JSON/projection mismatch"));
    }
    Ok(StoredRegistrationAttempt { attempt, session })
}

pub(super) fn load_current_session_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<AgentSession>> {
    load_current_session_locked(transaction, node_id, "FOR UPDATE")
}

/// Locks the current session for a logically read-only runtime transaction.
/// The NodeIdentity share lock already serializes session replacement; this
/// additional row lock makes the exact current-session dependency explicit
/// and keeps its renewal projection stable through the evidence snapshot.
#[allow(dead_code, reason = "consumed by the A22 authenticated evidence route")]
pub(super) fn load_current_session_for_share(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<AgentSession>> {
    load_current_session_locked(transaction, node_id, "FOR SHARE")
}

fn load_current_session_locked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    lock: &'static str,
) -> AuthorityTxResult<Option<AgentSession>> {
    let sql = format!(
        "SELECT {CURRENT_SESSION_COLUMNS} FROM current_agent_sessions
          WHERE node_id=$1 {lock}"
    );
    let Some(row) = transaction.query_opt(&sql, &[&node_id.as_str()])? else {
        return Ok(None);
    };
    let session = decode_current_session(&row)?;
    // Registration attempts and their first results are database-immutable,
    // so this consistency read needs no second row lock after locking current.
    let Some(stored_attempt) = load_attempt(
        transaction,
        &session.node_id,
        &session.registration_attempt_id,
    )?
    else {
        return Err(corrupt(
            "current AgentSession has no immutable attempt result",
        ));
    };
    if !same_session_except_deadline(&stored_attempt.session, &session)
        || session.lease_deadline_unix_ms < stored_attempt.session.lease_deadline_unix_ms
    {
        return Err(corrupt(
            "current AgentSession is not a monotonic renewal of its immutable attempt result",
        ));
    }
    Ok(Some(session))
}

pub(super) fn load_current_session_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<AgentSession>> {
    let sql =
        format!("SELECT {CURRENT_SESSION_COLUMNS} FROM current_agent_sessions WHERE node_id=$1");
    let Some(row) = transaction.query_opt(&sql, &[&node_id.as_str()])? else {
        return Ok(None);
    };
    let session = decode_current_session(&row)?;
    let Some(stored_attempt) = load_attempt(
        transaction,
        &session.node_id,
        &session.registration_attempt_id,
    )?
    else {
        return Err(corrupt(
            "current AgentSession has no immutable attempt result",
        ));
    };
    if !same_session_except_deadline(&stored_attempt.session, &session)
        || session.lease_deadline_unix_ms < stored_attempt.session.lease_deadline_unix_ms
    {
        return Err(corrupt(
            "current AgentSession is not a monotonic renewal of its immutable attempt result",
        ));
    }
    Ok(Some(session))
}

fn same_session_except_deadline(left: &AgentSession, right: &AgentSession) -> bool {
    left.version == right.version
        && left.node_id == right.node_id
        && left.immutable_host_id == right.immutable_host_id
        && left.node_boot_id == right.node_boot_id
        && left.agent_instance_id == right.agent_instance_id
        && left.agent_session_epoch == right.agent_session_epoch
        && left.registration_attempt_id == right.registration_attempt_id
        && left.guest_config_digest == right.guest_config_digest
}

fn load_attempt(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    registration_attempt_id: &cats_api::runtime_reconciliation::RandomId128,
) -> AuthorityTxResult<Option<StoredRegistrationAttempt>> {
    let sql = format!(
        "SELECT {REGISTRATION_ATTEMPT_COLUMNS} FROM agent_registration_attempts
          WHERE node_id=$1 AND registration_attempt_id=$2"
    );
    transaction
        .query_opt(
            &sql,
            &[&node_id.as_str(), &registration_attempt_id.as_str()],
        )?
        .map(|row| decode_attempt(&row))
        .transpose()
}

fn decode_current_session(row: &Row) -> AuthorityTxResult<AgentSession> {
    let stored = SessionProjection::from_row(row)?;
    let record_json: String = row.try_get("record_json")?;
    let session = decode_agent_session(record_json.as_bytes()).map_err(corrupt)?;
    if stored != SessionProjection::from_record(&session) {
        return Err(corrupt("current AgentSession JSON/projection mismatch"));
    }
    Ok(session)
}

fn insert_attempt(
    transaction: &mut Transaction<'_>,
    attempt: &AgentRegistrationAttempt,
    session: &AgentSession,
) -> AuthorityTxResult<()> {
    let projection = RegistrationAttemptProjection::from_records(attempt, session)?;
    let attempt_record = encode_attempt(attempt)?;
    let session_record = encode_session(session)?;
    let expected_epoch = optional_to_pg(projection.expected_agent_session_epoch)?;
    let session_epoch = projection.agent_session_epoch.to_pg().map_err(corrupt)?;
    let deadline = projection.lease_deadline_unix_ms.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "INSERT INTO agent_registration_attempts (
            node_id, registration_attempt_id, attempt_record,
            immutable_host_id, node_boot_id, agent_instance_id,
            guest_config_digest, expected_agent_session_epoch,
            session_record, agent_session_epoch, lease_deadline_unix_ms
         ) VALUES ($1, $2, $3::TEXT::jsonb, $4, $5, $6, $7, $8, $9::TEXT::jsonb, $10, $11)",
        &[
            &projection.node_id,
            &projection.registration_attempt_id,
            &attempt_record,
            &projection.immutable_host_id,
            &projection.node_boot_id,
            &projection.agent_instance_id,
            &projection.guest_config_digest,
            &expected_epoch,
            &session_record,
            &session_epoch,
            &deadline,
        ],
    )?;
    exactly_one(changed)
}

fn insert_current_session(
    transaction: &mut Transaction<'_>,
    session: &AgentSession,
) -> AuthorityTxResult<()> {
    let projection = SessionProjection::from_record(session);
    let record = encode_session(session)?;
    let epoch = projection.agent_session_epoch.to_pg().map_err(corrupt)?;
    let deadline = projection.lease_deadline_unix_ms.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "INSERT INTO current_agent_sessions (
            node_id, record, immutable_host_id, node_boot_id,
            agent_instance_id, agent_session_epoch, registration_attempt_id,
            guest_config_digest, lease_deadline_unix_ms
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &projection.node_id,
            &record,
            &projection.immutable_host_id,
            &projection.node_boot_id,
            &projection.agent_instance_id,
            &epoch,
            &projection.registration_attempt_id,
            &projection.guest_config_digest,
            &deadline,
        ],
    )?;
    exactly_one(changed)
}

fn replace_current_session(
    transaction: &mut Transaction<'_>,
    expected_epoch: Epoch,
    session: &AgentSession,
) -> AuthorityTxResult<()> {
    let projection = SessionProjection::from_record(session);
    let record = encode_session(session)?;
    let expected_epoch = expected_epoch.to_pg().map_err(corrupt)?;
    let epoch = projection.agent_session_epoch.to_pg().map_err(corrupt)?;
    let deadline = projection.lease_deadline_unix_ms.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "UPDATE current_agent_sessions SET
            record=$2::TEXT::jsonb, immutable_host_id=$3, node_boot_id=$4,
            agent_instance_id=$5, agent_session_epoch=$6,
            registration_attempt_id=$7, guest_config_digest=$8,
            lease_deadline_unix_ms=$9
          WHERE node_id=$1 AND agent_session_epoch=$10",
        &[
            &projection.node_id,
            &record,
            &projection.immutable_host_id,
            &projection.node_boot_id,
            &projection.agent_instance_id,
            &epoch,
            &projection.registration_attempt_id,
            &projection.guest_config_digest,
            &deadline,
            &expected_epoch,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn renew_current_session_deadline(
    transaction: &mut Transaction<'_>,
    current: &AgentSession,
    deadline: UnixMillis,
) -> AuthorityTxResult<AgentSession> {
    if deadline < current.lease_deadline_unix_ms {
        return Err(corrupt("Agent session lease renewal moved backward"));
    }
    let mut renewed = current.clone();
    renewed.lease_deadline_unix_ms = deadline;
    let record = encode_session(&renewed)?;
    let deadline = deadline.to_pg().map_err(corrupt)?;
    let current_deadline = current.lease_deadline_unix_ms.to_pg().map_err(corrupt)?;
    let epoch = current.agent_session_epoch.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "UPDATE current_agent_sessions
            SET record=$4::TEXT::jsonb, lease_deadline_unix_ms=$5
          WHERE node_id=$1 AND node_boot_id=$2 AND agent_instance_id=$3
            AND agent_session_epoch=$6 AND lease_deadline_unix_ms=$7",
        &[
            &current.node_id.as_str(),
            &current.node_boot_id.as_str(),
            &current.agent_instance_id.as_str(),
            &record,
            &deadline,
            &epoch,
            &current_deadline,
        ],
    )?;
    exactly_one(changed)?;
    Ok(renewed)
}

fn encode_identity(identity: &NodeIdentity) -> AuthorityTxResult<String> {
    let bytes = encode_node_identity(identity).map_err(corrupt)?;
    String::from_utf8(bytes).map_err(corrupt)
}

fn encode_attempt(attempt: &AgentRegistrationAttempt) -> AuthorityTxResult<String> {
    let bytes = encode_agent_registration_attempt(attempt).map_err(corrupt)?;
    String::from_utf8(bytes).map_err(corrupt)
}

fn encode_session(session: &AgentSession) -> AuthorityTxResult<String> {
    let bytes = encode_agent_session(session).map_err(corrupt)?;
    String::from_utf8(bytes).map_err(corrupt)
}

fn registration_attempt_conflict(
    expected: &AgentRegistrationAttempt,
    presented: &AgentRegistrationAttempt,
) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::RegistrationAttemptConflict {
            node_id: expected.node_id.clone(),
            registration_attempt_id: expected.registration_attempt_id.clone(),
            expected: attempt_binding(expected),
            presented: attempt_binding(presented),
        }),
        message: "same registration attempt carried a different binding".to_owned(),
    }
}

fn guest_config_mismatch(
    attempt: &AgentRegistrationAttempt,
    expected_digest: &Sha256Digest,
) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::GuestConfigMismatch {
            node_id: attempt.node_id.clone(),
            expected_guest_config_digest: expected_digest.clone(),
            presented_guest_config_digest: attempt.guest_config_digest.clone(),
        }),
        message: "node does not carry the active release guest runtime profile".to_owned(),
    }
}

fn attempt_binding(attempt: &AgentRegistrationAttempt) -> RegistrationAttemptBinding {
    RegistrationAttemptBinding {
        immutable_host_id: attempt.immutable_host_id.clone(),
        node_boot_id: attempt.node_boot_id.clone(),
        agent_instance_id: attempt.agent_instance_id.clone(),
        guest_config_digest: attempt.guest_config_digest.clone(),
        expected_agent_session_epoch: attempt.expected_agent_session_epoch,
    }
}

fn identity_rejected() -> AgentRegistrationOutcome {
    AgentRegistrationOutcome::Rejected(AgentRegistrationRejection::IdentityNotEligible)
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn optional_from_pg<T: PgBigInt>(value: Option<i64>) -> AuthorityTxResult<Option<T>> {
    value.map(from_pg).transpose()
}

fn optional_to_pg<T: PgBigInt>(value: Option<T>) -> AuthorityTxResult<Option<i64>> {
    value
        .map(|value| value.to_pg().map_err(corrupt))
        .transpose()
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
        "Agent session Store persisted contract or generated value is invalid",
    ))
}

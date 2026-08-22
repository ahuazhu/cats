//! PostgreSQL authority for provisioner-owned Node placement policy.
//!
//! Transport authentication deliberately stays outside this module. The
//! Store receives one typed principal and revalidates persisted machine-key
//! lineage inside the same transaction that commits an apply result.

use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, encode_node_placement_policy,
    encode_runtime_node_authority_apply, encode_runtime_node_authority_apply_result,
    encode_runtime_provisioner_active_set, encode_runtime_provisioner_trust_bundle,
    object_write_writer_authority_id, runtime_provisioner_active_set_digest, Base64UrlNoPad,
    ContractVersion, CredentialBinding, Epoch, FleetPolicyPrincipal, Id, NodeIdentity,
    NodeIdentityState, NodePlacementPolicy, NodeTransportTarget, PublicKeyCredentialBinding,
    RuntimeNodeAuthorityApply, RuntimeNodeAuthorityApplyRecord, RuntimeNodeAuthorityApplyResult,
    RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome, RuntimeNodeAuthorityStoredOutcome,
    RuntimeProvisionerActiveSet, RuntimeProvisionerCredential, RuntimeProvisionerExpectedPrevious,
    RuntimeProvisionerTrustBundle, RuntimeSchedulingState, Sha256Digest, UnixMillis,
};
use cats_storage::authority::AuthorityError;
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest as _, Sha256};

use super::object_write_root::open_object_write_authority_in;
use super::pg_codec::PgBigInt;
use super::rows::database_now;
use crate::store::node_identities::{
    insert_node_identity_in, load_identity_by_node_for_update, retire_node_identity_in,
    rotate_public_key_identity_in,
};
use crate::store::transaction::{
    AuthorityRequestDisposition, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{ApiError, AuthorityRequestContext, Result, Store};

const POLICY_COLUMNS: &str = "
    node_id, record::text AS record_json, policy_revision, scheduling_state,
    allocatable_vcpus, allocatable_memory_bytes, guest_config_digest,
    block_frontend, guest_ipv4_network_address, node_transport_target";
const APPLY_COLUMNS: &str = "
    apply_id, request::text AS request_json, request_sha256,
    principal::text AS principal_json, principal_kind, node_id,
    outcome::text AS outcome_json, outcome_kind, committed_at_unix_ms";

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code, reason = "consumed by the A23 admin HTTP composition")]
pub(crate) enum RuntimeNodeAuthorityApplyStoreOutcome {
    Stored(RuntimeNodeAuthorityStoredOutcome),
    ApplyIdConflict,
    AuthenticationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyProjection {
    node_id: String,
    policy_revision: Epoch,
    scheduling_state: String,
    allocatable_vcpus: i64,
    allocatable_memory_bytes: i64,
    guest_config_digest: String,
    block_frontend: String,
    guest_ipv4_network_address: String,
    node_transport_target: NodeTransportTarget,
}

impl PolicyProjection {
    fn from_record(policy: &NodePlacementPolicy) -> AuthorityTxResult<Self> {
        Ok(Self {
            node_id: policy.node_id.to_string(),
            policy_revision: policy.policy_revision,
            scheduling_state: scheduling_state(policy.scheduling_state).to_owned(),
            allocatable_vcpus: i64::from(policy.allocatable_vcpus.get()),
            allocatable_memory_bytes: i64::try_from(policy.allocatable_memory_bytes.get())
                .map_err(corrupt)?,
            guest_config_digest: policy.capabilities.guest_config_digest.to_string(),
            block_frontend: match policy.capabilities.block_frontend {
                cats_api::runtime_reconciliation::RuntimePlacementBlockFrontend::KernelNbd => {
                    "kernel_nbd"
                }
                cats_api::runtime_reconciliation::RuntimePlacementBlockFrontend::VhostUserBlk => {
                    "vhost_user_blk"
                }
            }
            .to_owned(),
            guest_ipv4_network_address: policy.guest_ipv4_pool.network_address.to_string(),
            node_transport_target: policy.node_transport_target.clone(),
        })
    }

    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        Ok(Self {
            node_id: row.try_get("node_id")?,
            policy_revision: from_pg(row.try_get("policy_revision")?)?,
            scheduling_state: closed_text(
                row.try_get("scheduling_state")?,
                &["cordoned", "schedulable"],
            )?,
            allocatable_vcpus: row.try_get("allocatable_vcpus")?,
            allocatable_memory_bytes: row.try_get("allocatable_memory_bytes")?,
            guest_config_digest: row.try_get("guest_config_digest")?,
            block_frontend: closed_text(
                row.try_get("block_frontend")?,
                &["kernel_nbd", "vhost_user_blk"],
            )?,
            guest_ipv4_network_address: row.try_get("guest_ipv4_network_address")?,
            node_transport_target: NodeTransportTarget::new(
                row.try_get::<_, String>("node_transport_target")?,
            )
            .ok_or_else(|| corrupt("stored Node transport target projection is malformed"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProvisionerCredentialRow {
    credential: RuntimeProvisionerCredential,
    public_key_spki_sha256: Sha256Digest,
    state: String,
}

impl ProvisionerCredentialRow {
    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        let public_key_spki = Base64UrlNoPad::new(row.try_get::<_, String>("public_key_spki")?)
            .ok_or_else(|| corrupt("stored provisioner SPKI is malformed"))?;
        let computed = canonical_ed25519_spki_sha256(&public_key_spki)
            .ok_or_else(|| corrupt("stored provisioner SPKI is not canonical Ed25519 DER"))?;
        let persisted = parse_digest(row.try_get("public_key_spki_sha256")?)?;
        if computed != persisted {
            return Err(corrupt("stored provisioner SPKI digest mismatch"));
        }
        let state = closed_text(row.try_get("state")?, &["active", "retired"])?;
        let first_committed_at: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
        let retired_at: Option<UnixMillis> = optional_from_pg(row.try_get("retired_at_unix_ms")?)?;
        if (state == "active" && retired_at.is_some())
            || (state == "retired" && retired_at.is_none_or(|retired| retired < first_committed_at))
        {
            return Err(corrupt("stored provisioner lineage state/time mismatch"));
        }
        Ok(Self {
            credential: RuntimeProvisionerCredential {
                credential_id: parse_id(row.try_get("credential_id")?)?,
                public_key_spki,
            },
            public_key_spki_sha256: persisted,
            state,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustPointer {
    deployment_id: Id,
    trust_revision: Epoch,
    active_set_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustRevision {
    deployment_id: Id,
    trust_revision: Epoch,
    active_set_sha256: Sha256Digest,
    expected_previous: Option<RuntimeProvisionerExpectedPrevious>,
}

impl Store {
    /// Installs or exact-replays the one deployment trust bundle before the
    /// admin listener opens.
    #[allow(dead_code, reason = "consumed by the A23 Control startup composition")]
    pub(crate) fn install_runtime_provisioner_trust_bundle(
        &self,
        bundle: &RuntimeProvisionerTrustBundle,
    ) -> Result<()> {
        encode_runtime_provisioner_trust_bundle(bundle)
            .map_err(|_| ApiError::invalid("runtime provisioner trust bundle is invalid"))?;
        self.authority_transaction(|transaction| install_trust_bundle_in(transaction, bundle))
    }

    /// Applies or exact-replays one provisioner-owned Node authority mutation.
    #[allow(dead_code, reason = "consumed by the A23 admin HTTP composition")]
    pub(crate) fn apply_runtime_node_authority(
        &self,
        principal: &FleetPolicyPrincipal,
        apply: &RuntimeNodeAuthorityApply,
    ) -> Result<RuntimeNodeAuthorityApplyStoreOutcome> {
        encode_runtime_node_authority_apply(apply)
            .map_err(|_| ApiError::invalid("runtime Node authority apply is invalid"))?;
        validate_principal(principal)
            .map_err(|_| ApiError::invalid("runtime Node authority principal is invalid"))?;
        self.authority_transaction(|transaction| {
            apply_runtime_node_authority_in(transaction, principal, apply)
        })
    }

    /// Prove that the locally verified deployment key is still the exact
    /// active persisted key before the transport adapter decodes or inspects
    /// any Node/apply facts.
    pub(crate) fn authenticate_runtime_provisioner_principal(
        &self,
        principal: &FleetPolicyPrincipal,
    ) -> Result<bool> {
        validate_principal(principal)
            .map_err(|_| ApiError::invalid("runtime Node authority principal is invalid"))?;
        if !matches!(
            principal,
            FleetPolicyPrincipal::DeploymentProvisioner { .. }
        ) {
            return Ok(false);
        }
        self.authority_transaction(|transaction| {
            revalidate_machine_principal(transaction, principal)
        })
    }

    /// Deadline/cancellation-aware HTTP apply boundary. Deterministic stored
    /// success and precondition outcomes cross COMMIT; authentication and
    /// apply-ID conflicts explicitly roll back without an audit/domain write.
    pub(crate) fn apply_runtime_node_authority_request(
        &self,
        principal: &FleetPolicyPrincipal,
        apply: &RuntimeNodeAuthorityApply,
        request: &AuthorityRequestContext,
    ) -> Result<RuntimeNodeAuthorityApplyStoreOutcome> {
        encode_runtime_node_authority_apply(apply)
            .map_err(|_| ApiError::invalid("runtime Node authority apply is invalid"))?;
        validate_principal(principal)
            .map_err(|_| ApiError::invalid("runtime Node authority principal is invalid"))?;
        self.authority_request_transaction(request, |transaction| {
            let outcome = apply_runtime_node_authority_in(transaction, principal, apply)?;
            Ok(match outcome {
                RuntimeNodeAuthorityApplyStoreOutcome::Stored(_) => {
                    AuthorityRequestDisposition::Commit(outcome)
                }
                RuntimeNodeAuthorityApplyStoreOutcome::ApplyIdConflict
                | RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed => {
                    AuthorityRequestDisposition::Reject(outcome)
                }
            })
        })
    }

    /// Resolve an already-sent COMMIT without re-running domain mutation or
    /// requiring the possibly-rotated request credential. This read is only
    /// reachable from the registered commit owner after `commit_was_attempted`.
    pub(crate) fn resolve_runtime_node_authority_apply(
        &self,
        apply: &RuntimeNodeAuthorityApply,
    ) -> Result<Option<RuntimeNodeAuthorityApplyStoreOutcome>> {
        encode_runtime_node_authority_apply(apply)
            .map_err(|_| ApiError::invalid("runtime Node authority apply is invalid"))?;
        self.authority_transaction(|transaction| {
            // A connection-class COMMIT error can return to the original
            // backend before PostgreSQL has made that transaction's outcome
            // observable to a fresh connection. Serialize the resolver behind
            // the exact reservation held by the original transaction. Only a
            // post-lock miss proves that transaction rolled back.
            lock_runtime_node_authority_apply(transaction, apply.apply_id.as_str())?;
            let stored = load_apply_record(transaction, apply.apply_id.as_str())?;
            Ok(stored.map(|stored| {
                if *stored.request == *apply {
                    RuntimeNodeAuthorityApplyStoreOutcome::Stored(stored.outcome)
                } else {
                    RuntimeNodeAuthorityApplyStoreOutcome::ApplyIdConflict
                }
            }))
        })
    }
}

fn install_trust_bundle_in(
    transaction: &mut Transaction<'_>,
    bundle: &RuntimeProvisionerTrustBundle,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-provisioner-trust', 0::BIGINT))",
        &[],
    )?;
    let committed_at = database_now(transaction)?;
    let candidate_active = RuntimeProvisionerActiveSet {
        version: ContractVersion::V1,
        deployment_id: bundle.deployment_id.clone(),
        credentials: bundle.credentials.clone(),
    };
    let candidate_digest =
        runtime_provisioner_active_set_digest(&candidate_active).map_err(corrupt)?;
    let current = load_trust_pointer(transaction, "FOR UPDATE")?;
    let Some(current) = current else {
        if bundle.trust_revision.get() != 1 || bundle.expected_previous.is_some() {
            return Err(trust_rejected("initial trust bundle must be revision one"));
        }
        return insert_initial_trust(transaction, bundle, &candidate_digest, committed_at);
    };
    if current.deployment_id != bundle.deployment_id {
        return Err(trust_rejected(
            "runtime provisioner deployment identity changed",
        ));
    }
    let current_revision =
        load_trust_revision(transaction, &current.deployment_id, current.trust_revision)?
            .ok_or_else(|| corrupt("current trust pointer has no immutable revision receipt"))?;
    if current_revision.deployment_id != current.deployment_id
        || current_revision.trust_revision != current.trust_revision
        || current_revision.active_set_sha256 != current.active_set_sha256
    {
        return Err(corrupt("current trust pointer/revision mismatch"));
    }
    let current_rows = load_active_provisioner_credentials(transaction, "FOR UPDATE")?;
    let current_active = RuntimeProvisionerActiveSet {
        version: ContractVersion::V1,
        deployment_id: current.deployment_id.clone(),
        credentials: current_rows
            .iter()
            .map(|row| row.credential.clone())
            .collect(),
    };
    let rebuilt_digest = runtime_provisioner_active_set_digest(&current_active).map_err(corrupt)?;
    if rebuilt_digest != current.active_set_sha256 {
        return Err(corrupt("current trust active-set digest mismatch"));
    }

    if bundle.trust_revision == current.trust_revision {
        if candidate_digest != current.active_set_sha256
            || candidate_active != current_active
            || bundle.expected_previous != current_revision.expected_previous
        {
            return Err(trust_rejected("same trust revision is not an exact replay"));
        }
        return Ok(());
    }
    let expected_next = current
        .trust_revision
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or_else(|| trust_rejected("runtime provisioner trust revision is exhausted"))?;
    let expected_previous = RuntimeProvisionerExpectedPrevious {
        trust_revision: current.trust_revision,
        active_set_sha256: current.active_set_sha256.clone(),
    };
    if bundle.trust_revision != expected_next
        || bundle.expected_previous.as_ref() != Some(&expected_previous)
        || candidate_digest == current.active_set_sha256
    {
        return Err(trust_rejected(
            "runtime provisioner trust CAS precondition failed",
        ));
    }

    let committed_at_pg = committed_at.to_pg().map_err(corrupt)?;
    for candidate in &bundle.credentials {
        let digest = canonical_ed25519_spki_sha256(&candidate.public_key_spki)
            .ok_or_else(|| corrupt("validated provisioner SPKI became invalid"))?;
        let matching = transaction.query(
            "SELECT credential_id, public_key_spki, public_key_spki_sha256,
                    state, first_committed_at_unix_ms, retired_at_unix_ms
               FROM runtime_provisioner_credential_lineage
              WHERE credential_id=$1 OR public_key_spki=$2 OR public_key_spki_sha256=$3
              ORDER BY credential_id COLLATE \"C\" FOR UPDATE",
            &[
                &candidate.credential_id.as_str(),
                &candidate.public_key_spki.as_str(),
                &digest.as_str(),
            ],
        )?;
        if matching.is_empty() {
            exactly_one(transaction.execute(
                "INSERT INTO runtime_provisioner_credential_lineage (
                    credential_id, deployment_id, public_key_spki,
                    public_key_spki_sha256, state,
                    first_committed_at_unix_ms, retired_at_unix_ms
                 ) VALUES ($1, $2, $3, $4, 'active', $5, NULL)",
                &[
                    &candidate.credential_id.as_str(),
                    &bundle.deployment_id.as_str(),
                    &candidate.public_key_spki.as_str(),
                    &digest.as_str(),
                    &committed_at_pg,
                ],
            )?)?;
            continue;
        }
        if matching.len() != 1 {
            return Err(corrupt(
                "provisioner credential uniqueness projections diverged",
            ));
        }
        let stored = ProvisionerCredentialRow::from_row(&matching[0])?;
        if stored.credential != *candidate
            || stored.public_key_spki_sha256 != digest
            || stored.state != "active"
        {
            return Err(trust_rejected(
                "provisioner credential lineage cannot be reused",
            ));
        }
    }
    for current_row in &current_rows {
        if !bundle
            .credentials
            .iter()
            .any(|candidate| candidate == &current_row.credential)
        {
            exactly_one(transaction.execute(
                "UPDATE runtime_provisioner_credential_lineage
                    SET state='retired', retired_at_unix_ms=$3
                  WHERE credential_id=$1 AND deployment_id=$2 AND state='active'",
                &[
                    &current_row.credential.credential_id.as_str(),
                    &current.deployment_id.as_str(),
                    &committed_at_pg,
                ],
            )?)?;
        }
    }
    insert_trust_revision(transaction, bundle, &candidate_digest, committed_at)?;
    let revision = bundle.trust_revision.to_pg().map_err(corrupt)?;
    let old_revision = current.trust_revision.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "UPDATE runtime_provisioner_deployment_identity
            SET current_trust_revision=$3, current_active_set_sha256=$4
          WHERE singleton AND deployment_id=$1
            AND current_trust_revision=$2 AND current_active_set_sha256=$5",
        &[
            &current.deployment_id.as_str(),
            &old_revision,
            &revision,
            &candidate_digest.as_str(),
            &current.active_set_sha256.as_str(),
        ],
    )?)
}

fn insert_initial_trust(
    transaction: &mut Transaction<'_>,
    bundle: &RuntimeProvisionerTrustBundle,
    active_set_sha256: &Sha256Digest,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let revision = bundle.trust_revision.to_pg().map_err(corrupt)?;
    let committed_at_pg = committed_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO runtime_provisioner_deployment_identity (
            singleton, deployment_id, current_trust_revision,
            current_active_set_sha256, first_committed_at_unix_ms
         ) VALUES (TRUE, $1, $2, $3, $4)",
        &[
            &bundle.deployment_id.as_str(),
            &revision,
            &active_set_sha256.as_str(),
            &committed_at_pg,
        ],
    )?)?;
    for credential in &bundle.credentials {
        let digest = canonical_ed25519_spki_sha256(&credential.public_key_spki)
            .ok_or_else(|| corrupt("validated provisioner SPKI became invalid"))?;
        exactly_one(transaction.execute(
            "INSERT INTO runtime_provisioner_credential_lineage (
                credential_id, deployment_id, public_key_spki,
                public_key_spki_sha256, state,
                first_committed_at_unix_ms, retired_at_unix_ms
             ) VALUES ($1, $2, $3, $4, 'active', $5, NULL)",
            &[
                &credential.credential_id.as_str(),
                &bundle.deployment_id.as_str(),
                &credential.public_key_spki.as_str(),
                &digest.as_str(),
                &committed_at_pg,
            ],
        )?)?;
    }
    insert_trust_revision(transaction, bundle, active_set_sha256, committed_at)
}

fn insert_trust_revision(
    transaction: &mut Transaction<'_>,
    bundle: &RuntimeProvisionerTrustBundle,
    active_set_sha256: &Sha256Digest,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let revision = bundle.trust_revision.to_pg().map_err(corrupt)?;
    let (previous_revision, previous_digest) = match &bundle.expected_previous {
        Some(previous) => (
            Some(previous.trust_revision.to_pg().map_err(corrupt)?),
            Some(previous.active_set_sha256.as_str()),
        ),
        None => (None, None),
    };
    let committed_at = committed_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO runtime_provisioner_trust_revisions (
            deployment_id, trust_revision, active_set_sha256,
            expected_previous_trust_revision,
            expected_previous_active_set_sha256, committed_at_unix_ms
         ) VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &bundle.deployment_id.as_str(),
            &revision,
            &active_set_sha256.as_str(),
            &previous_revision,
            &previous_digest,
            &committed_at,
        ],
    )?)
}

fn load_trust_pointer(
    transaction: &mut Transaction<'_>,
    lock: &str,
) -> AuthorityTxResult<Option<TrustPointer>> {
    let sql = format!(
        "SELECT deployment_id, current_trust_revision,
                current_active_set_sha256, first_committed_at_unix_ms
           FROM runtime_provisioner_deployment_identity WHERE singleton {lock}"
    );
    transaction
        .query_opt(&sql, &[])?
        .map(|row| {
            let _: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
            Ok(TrustPointer {
                deployment_id: parse_id(row.try_get("deployment_id")?)?,
                trust_revision: from_pg(row.try_get("current_trust_revision")?)?,
                active_set_sha256: parse_digest(row.try_get("current_active_set_sha256")?)?,
            })
        })
        .transpose()
}

fn load_trust_revision(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    trust_revision: Epoch,
) -> AuthorityTxResult<Option<TrustRevision>> {
    let revision = trust_revision.to_pg().map_err(corrupt)?;
    transaction
        .query_opt(
            "SELECT deployment_id, trust_revision, active_set_sha256,
                    expected_previous_trust_revision,
                    expected_previous_active_set_sha256, committed_at_unix_ms
               FROM runtime_provisioner_trust_revisions
              WHERE deployment_id=$1 AND trust_revision=$2",
            &[&deployment_id.as_str(), &revision],
        )?
        .map(|row| {
            let previous_revision =
                optional_from_pg::<Epoch>(row.try_get("expected_previous_trust_revision")?)?;
            let previous_digest = row
                .try_get::<_, Option<String>>("expected_previous_active_set_sha256")?
                .map(parse_digest)
                .transpose()?;
            let expected_previous = match (previous_revision, previous_digest) {
                (Some(trust_revision), Some(active_set_sha256)) => {
                    Some(RuntimeProvisionerExpectedPrevious {
                        trust_revision,
                        active_set_sha256,
                    })
                }
                (None, None) => None,
                _ => return Err(corrupt("trust revision previous projection is partial")),
            };
            let _: UnixMillis = from_pg(row.try_get("committed_at_unix_ms")?)?;
            Ok(TrustRevision {
                deployment_id: parse_id(row.try_get("deployment_id")?)?,
                trust_revision: from_pg(row.try_get("trust_revision")?)?,
                active_set_sha256: parse_digest(row.try_get("active_set_sha256")?)?,
                expected_previous,
            })
        })
        .transpose()
}

fn load_active_provisioner_credentials(
    transaction: &mut Transaction<'_>,
    lock: &str,
) -> AuthorityTxResult<Vec<ProvisionerCredentialRow>> {
    let sql = format!(
        "SELECT credential_id, public_key_spki, public_key_spki_sha256,
                state, first_committed_at_unix_ms, retired_at_unix_ms
           FROM runtime_provisioner_credential_lineage
          WHERE state='active' ORDER BY credential_id COLLATE \"C\" {lock}"
    );
    transaction
        .query(&sql, &[])?
        .iter()
        .map(ProvisionerCredentialRow::from_row)
        .collect()
}

fn lock_runtime_node_authority_apply(
    transaction: &mut Transaction<'_>,
    apply_id: &str,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-node-authority-apply:' || $1, 0::BIGINT))",
        &[&apply_id],
    )?;
    Ok(())
}

fn apply_runtime_node_authority_in(
    transaction: &mut Transaction<'_>,
    principal: &FleetPolicyPrincipal,
    apply: &RuntimeNodeAuthorityApply,
) -> AuthorityTxResult<RuntimeNodeAuthorityApplyStoreOutcome> {
    lock_runtime_node_authority_apply(transaction, apply.apply_id.as_str())?;
    if !revalidate_machine_principal(transaction, principal)? {
        return Ok(RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed);
    }
    if let Some(stored) = load_apply_record(transaction, apply.apply_id.as_str())? {
        if *stored.request == *apply {
            return Ok(RuntimeNodeAuthorityApplyStoreOutcome::Stored(
                stored.outcome,
            ));
        }
        return Ok(RuntimeNodeAuthorityApplyStoreOutcome::ApplyIdConflict);
    }
    let credential_fresh = lock_and_check_fresh_node_credential(transaction, apply)?;

    let (identity, policy, node_absent, host_state_fresh) = match &apply.mutation {
        RuntimeNodeAuthorityMutation::Provision { node_identity, .. } => {
            transaction.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended(
                    current_schema() || ':runtime-node-authority:' || $1, 0::BIGINT))",
                &[&apply.node_id.as_str()],
            )?;
            let identity = load_identity_by_node_for_update(transaction, &apply.node_id)?;
            let policy = load_policy_for_update(transaction, &apply.node_id)?;
            let absent = identity.is_none() && policy.is_none();
            let host_state_fresh = if absent {
                lock_and_check_fresh_host_state(transaction, node_identity)?
            } else {
                false
            };
            (identity, policy, absent, host_state_fresh)
        }
        _ => {
            let identity = load_identity_by_node_for_update(transaction, &apply.node_id)?;
            let policy = load_policy_for_update(transaction, &apply.node_id)?;
            (identity, policy, false, true)
        }
    };
    if identity.is_some() != policy.is_some() {
        return Err(corrupt(
            "NodeIdentity and placement policy presence diverged",
        ));
    }
    let committed_at = database_now(transaction)?;
    let stored_outcome = match &apply.mutation {
        RuntimeNodeAuthorityMutation::Provision {
            node_identity,
            placement_policy,
        } if node_absent
            && credential_fresh
            && host_state_fresh
            && placement_policy.scheduling_state == RuntimeSchedulingState::Cordoned
            && identity_public_key(node_identity).is_some()
            && valid_state_path_component(&node_identity.state_path_id) =>
        {
            if insert_node_identity_in(transaction, node_identity, committed_at)? != 1 {
                return Err(corrupt(
                    "locked absent NodeIdentity insert did not change one row",
                ));
            }
            insert_policy(transaction, placement_policy)?;
            applied_result(
                apply,
                RuntimeNodeAuthorityOutcome::Provisioned,
                NodeIdentityState::Provisioned,
                placement_policy.policy_revision,
                None,
            )
        }
        RuntimeNodeAuthorityMutation::Provision { .. } => {
            RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
        }
        RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision,
            placement_policy,
        } => match (identity.as_ref(), policy.as_ref()) {
            (Some(identity), Some(current))
                if identity.state == NodeIdentityState::Provisioned
                    && current.policy_revision == *expected_policy_revision
                    && valid_policy_update(transaction, current, placement_policy)? =>
            {
                update_policy(transaction, current, placement_policy)?;
                applied_result(
                    apply,
                    RuntimeNodeAuthorityOutcome::PolicyUpdated,
                    NodeIdentityState::Provisioned,
                    placement_policy.policy_revision,
                    None,
                )
            }
            _ => RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed,
        },
        RuntimeNodeAuthorityMutation::RotateCredential {
            expected_policy_revision,
            expected_credential_id,
            expected_credential_binding,
            new_credential_id,
            new_credential_binding,
        } => match (identity.as_ref(), policy.as_ref()) {
            (Some(identity), Some(policy))
                if credential_fresh
                    && identity.state == NodeIdentityState::Provisioned
                    && policy.policy_revision == *expected_policy_revision
                    && policy.scheduling_state == RuntimeSchedulingState::Cordoned
                    && identity.credential_id == *expected_credential_id
                    && identity_matches_public_key_binding(
                        identity,
                        expected_credential_binding,
                    )
                    && rotation_or_retire_quiescent(
                        transaction,
                        &identity.node_id,
                        committed_at,
                    )? =>
            {
                rotate_public_key_identity_in(
                    transaction,
                    identity,
                    new_credential_id,
                    binding_digest(new_credential_binding),
                    committed_at,
                )?;
                applied_result(
                    apply,
                    RuntimeNodeAuthorityOutcome::CredentialRotated,
                    NodeIdentityState::Provisioned,
                    policy.policy_revision,
                    None,
                )
            }
            _ => RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed,
        },
        RuntimeNodeAuthorityMutation::Retire {
            expected_policy_revision,
            expected_credential_id,
            expected_credential_binding,
        } => match (identity.as_ref(), policy.as_ref()) {
            (Some(identity), Some(policy))
                if identity.state == NodeIdentityState::Provisioned
                    && policy.policy_revision == *expected_policy_revision
                    && policy.scheduling_state == RuntimeSchedulingState::Cordoned
                    && identity.credential_id == *expected_credential_id
                    && identity_matches_public_key_binding(
                        identity,
                        expected_credential_binding,
                    )
                    && rotation_or_retire_quiescent(
                        transaction,
                        &identity.node_id,
                        committed_at,
                    )? =>
            {
                retire_node_identity_in(transaction, identity, committed_at)?;
                applied_result(
                    apply,
                    RuntimeNodeAuthorityOutcome::Retired,
                    NodeIdentityState::Retired,
                    policy.policy_revision,
                    None,
                )
            }
            _ => RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed,
        },
        // Opening the Host's object-write writer authority needs the exact
        // provisioned identity and policy revision, but deliberately not a
        // cordoned or quiescent Node: the authority is a prerequisite for any
        // attachment credential, and opening it publishes no physical effect.
        RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
            expected_policy_revision,
            object_provider_scope,
            workload_principal_id,
            object_store_scope_id,
        } => match (identity.as_ref(), policy.as_ref()) {
            (Some(identity), Some(policy))
                if identity.state == NodeIdentityState::Provisioned
                    && policy.policy_revision == *expected_policy_revision =>
            {
                let writer_authority_id = object_write_writer_authority_id(
                    &apply.node_id,
                    object_provider_scope,
                    workload_principal_id,
                    object_store_scope_id,
                );
                if open_object_write_authority_in(
                    transaction,
                    identity,
                    &writer_authority_id,
                    object_provider_scope,
                    workload_principal_id,
                    object_store_scope_id,
                )? {
                    applied_result(
                        apply,
                        RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned,
                        NodeIdentityState::Provisioned,
                        policy.policy_revision,
                        Some(writer_authority_id),
                    )
                } else {
                    RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
                }
            }
            _ => RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed,
        },
    };
    insert_apply_record(transaction, apply, principal, &stored_outcome, committed_at)?;
    Ok(RuntimeNodeAuthorityApplyStoreOutcome::Stored(
        stored_outcome,
    ))
}

fn lock_and_check_fresh_host_state(
    transaction: &mut Transaction<'_>,
    identity: &NodeIdentity,
) -> AuthorityTxResult<bool> {
    // The Host advisory is also the missing-row lock for the clean-slate
    // one-Provisioned-identity invariant. Existing Node mutations never take
    // it after their identity row, so querying the current Host row below
    // cannot form a row/advisory lock inversion with Retire.
    // HostLost/#263 is intentionally not a production mutation path in the
    // atomic release.  Keep the immutable-Host missing-row barrier without
    // consulting the superseded Desired recovery-batch catalog.
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':host-identity-lineage:' ||
            jsonb_build_array(
                $1::TEXT,$2::TEXT,$3::TEXT,$4::TEXT,$5::TEXT
            )::TEXT,
            0::BIGINT))",
        &[
            &identity.provider_scope.provider.as_str(),
            &identity.provider_scope.partition.as_str(),
            &identity.provider_scope.account_id.as_str(),
            &identity.provider_scope.region.as_str(),
            &identity.immutable_host_id.as_str(),
        ],
    )?;
    let provisioned = transaction.query(
        "SELECT node_id FROM node_identities
          WHERE host_provider=$1 AND host_partition=$2
            AND host_account_id=$3 AND host_region=$4
            AND immutable_host_id=$5 AND state='provisioned'
          ORDER BY node_id COLLATE \"C\" LIMIT 2 FOR UPDATE",
        &[
            &identity.provider_scope.provider.as_str(),
            &identity.provider_scope.partition.as_str(),
            &identity.provider_scope.account_id.as_str(),
            &identity.provider_scope.region.as_str(),
            &identity.immutable_host_id.as_str(),
        ],
    )?;
    if provisioned.len() > 1 {
        return Err(corrupt(
            "more than one Provisioned NodeIdentity exists for one immutable Host",
        ));
    }
    if !provisioned.is_empty() {
        return Ok(false);
    }
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-node-host-state:' || $1 || ':' || $2,
            0::BIGINT))",
        &[
            &identity.immutable_host_id.as_str(),
            &identity.state_path_id.as_str(),
        ],
    )?;
    let row = transaction.query_opt(
        "SELECT node_id FROM node_identities
          WHERE immutable_host_id=$1 AND state_path_id=$2 FOR UPDATE",
        &[
            &identity.immutable_host_id.as_str(),
            &identity.state_path_id.as_str(),
        ],
    )?;
    let Some(row) = row else {
        return Ok(true);
    };
    let node_id = parse_id(row.try_get("node_id")?)?;
    let existing = load_identity_by_node_for_update(transaction, &node_id)?
        .ok_or_else(|| corrupt("Host/state-path uniqueness row disappeared"))?;
    if existing.immutable_host_id != identity.immutable_host_id
        || existing.state_path_id != identity.state_path_id
    {
        return Err(corrupt("Host/state-path uniqueness projection diverged"));
    }
    Ok(false)
}

fn valid_state_path_component(state_path_id: &Id) -> bool {
    !matches!(state_path_id.as_str(), "." | "..")
}

fn valid_policy_update(
    transaction: &mut Transaction<'_>,
    current: &NodePlacementPolicy,
    next: &NodePlacementPolicy,
) -> AuthorityTxResult<bool> {
    if current.node_id != next.node_id
        || current.policy_revision.get().checked_add(1) != Some(next.policy_revision.get())
    {
        return Ok(false);
    }
    let static_changed = current.allocatable_vcpus != next.allocatable_vcpus
        || current.allocatable_memory_bytes != next.allocatable_memory_bytes
        || current.capabilities != next.capabilities
        || current.guest_ipv4_pool != next.guest_ipv4_pool
        || current.node_transport_target != next.node_transport_target;
    if !static_changed && current.scheduling_state == next.scheduling_state {
        return Ok(false);
    }
    if static_changed
        && (current.scheduling_state != RuntimeSchedulingState::Cordoned
            || next.scheduling_state != RuntimeSchedulingState::Cordoned
            || node_has_active_runtime_bindings_for_update(transaction, &current.node_id)?)
    {
        return Ok(false);
    }
    Ok(true)
}

fn rotation_or_retire_quiescent(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    _db_now: UnixMillis,
) -> AuthorityTxResult<bool> {
    Ok(!node_has_active_runtime_bindings_for_update(
        transaction,
        node_id,
    )?)
}

/// Lock and detect current semantic Cats which still depend on one Node.
fn node_has_active_runtime_bindings_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<bool> {
    let rows = transaction.query(
        "SELECT cat_id
           FROM cats
          WHERE node_id=$1 AND destroyed_at IS NULL
            AND (state <> 'cold' OR current_action IS NOT NULL)
          ORDER BY cat_id COLLATE \"C\"
          LIMIT 1
          FOR UPDATE",
        &[&node_id.as_str()],
    )?;
    Ok(!rows.is_empty())
}

fn lock_and_check_fresh_node_credential(
    transaction: &mut Transaction<'_>,
    apply: &RuntimeNodeAuthorityApply,
) -> AuthorityTxResult<bool> {
    let candidate = match &apply.mutation {
        RuntimeNodeAuthorityMutation::Provision { node_identity, .. } => {
            identity_public_key(node_identity).map(|digest| (&node_identity.credential_id, digest))
        }
        RuntimeNodeAuthorityMutation::RotateCredential {
            new_credential_id,
            new_credential_binding,
            ..
        } => Some((new_credential_id, binding_digest(new_credential_binding))),
        _ => None,
    };
    let Some((credential_id, digest)) = candidate else {
        return Ok(true);
    };
    let mut locks = [
        ("credential_id", credential_id.as_str()),
        ("public_key_spki_sha256", digest.as_str()),
    ];
    locks.sort_unstable();
    for (kind, value) in locks {
        transaction.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':runtime-node-credential-lineage:' || $1 || ':' || $2,
                0::BIGINT))",
            &[&kind, &value],
        )?;
    }
    Ok(!transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM runtime_node_credential_lineage
                 WHERE credential_id=$1 OR public_key_spki_sha256=$2)",
            &[&credential_id.as_str(), &digest.as_str()],
        )?
        .get::<_, bool>(0))
}

fn revalidate_machine_principal(
    transaction: &mut Transaction<'_>,
    principal: &FleetPolicyPrincipal,
) -> AuthorityTxResult<bool> {
    let FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id,
        credential_id,
        public_key_spki,
        public_key_spki_sha256,
    } = principal
    else {
        return Ok(true);
    };
    let Some(pointer) = load_trust_pointer(transaction, "FOR SHARE")? else {
        return Ok(false);
    };
    if pointer.deployment_id != *deployment_id {
        return Ok(false);
    }
    let row = transaction.query_opt(
        "SELECT credential_id, public_key_spki, public_key_spki_sha256,
                state, first_committed_at_unix_ms, retired_at_unix_ms
           FROM runtime_provisioner_credential_lineage
          WHERE credential_id=$1 AND deployment_id=$2 FOR SHARE",
        &[&credential_id.as_str(), &deployment_id.as_str()],
    )?;
    let Some(row) = row else {
        return Ok(false);
    };
    let stored = ProvisionerCredentialRow::from_row(&row)?;
    Ok(stored.state == "active"
        && stored.credential.credential_id == *credential_id
        && stored.credential.public_key_spki == *public_key_spki
        && stored.public_key_spki_sha256 == *public_key_spki_sha256)
}

fn insert_policy(
    transaction: &mut Transaction<'_>,
    policy: &NodePlacementPolicy,
) -> AuthorityTxResult<()> {
    let projection = PolicyProjection::from_record(policy)?;
    let record_json = String::from_utf8(encode_node_placement_policy(policy).map_err(corrupt)?)
        .map_err(corrupt)?;
    let revision = projection.policy_revision.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO runtime_node_placement_policies (
            node_id, record, policy_revision, scheduling_state,
            allocatable_vcpus, allocatable_memory_bytes,
            guest_config_digest, block_frontend, guest_ipv4_network_address,
            node_transport_target
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &projection.node_id,
            &record_json,
            &revision,
            &projection.scheduling_state,
            &projection.allocatable_vcpus,
            &projection.allocatable_memory_bytes,
            &projection.guest_config_digest,
            &projection.block_frontend,
            &projection.guest_ipv4_network_address,
            &projection.node_transport_target.as_str(),
        ],
    )?)
}

fn update_policy(
    transaction: &mut Transaction<'_>,
    current: &NodePlacementPolicy,
    next: &NodePlacementPolicy,
) -> AuthorityTxResult<()> {
    let projection = PolicyProjection::from_record(next)?;
    let record_json =
        String::from_utf8(encode_node_placement_policy(next).map_err(corrupt)?).map_err(corrupt)?;
    let revision = projection.policy_revision.to_pg().map_err(corrupt)?;
    let expected_revision = current.policy_revision.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "UPDATE runtime_node_placement_policies
            SET record=$2::TEXT::jsonb, policy_revision=$3,
                scheduling_state=$4, allocatable_vcpus=$5,
                allocatable_memory_bytes=$6, guest_config_digest=$7,
                block_frontend=$8, guest_ipv4_network_address=$9,
                node_transport_target=$10
          WHERE node_id=$1 AND policy_revision=$11",
        &[
            &projection.node_id,
            &record_json,
            &revision,
            &projection.scheduling_state,
            &projection.allocatable_vcpus,
            &projection.allocatable_memory_bytes,
            &projection.guest_config_digest,
            &projection.block_frontend,
            &projection.guest_ipv4_network_address,
            &projection.node_transport_target.as_str(),
            &expected_revision,
        ],
    )?)
}

pub(super) fn load_policy_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<NodePlacementPolicy>> {
    let sql = format!(
        "SELECT {POLICY_COLUMNS} FROM runtime_node_placement_policies
          WHERE node_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&node_id.as_str()])?
        .map(|row| decode_policy(&row))
        .transpose()
}

#[allow(dead_code, reason = "consumed by the A23 planner snapshot loader")]
pub(super) fn load_policy_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<NodePlacementPolicy>> {
    let sql =
        format!("SELECT {POLICY_COLUMNS} FROM runtime_node_placement_policies WHERE node_id=$1");
    transaction
        .query_opt(&sql, &[&node_id.as_str()])?
        .map(|row| decode_policy(&row))
        .transpose()
}

fn decode_policy(row: &Row) -> AuthorityTxResult<NodePlacementPolicy> {
    let projection = PolicyProjection::from_row(row)?;
    let policy: NodePlacementPolicy = decode_json(row.try_get("record_json")?)?;
    encode_node_placement_policy(&policy).map_err(corrupt)?;
    if projection != PolicyProjection::from_record(&policy)? {
        return Err(corrupt("placement policy JSON/projection mismatch"));
    }
    Ok(policy)
}

fn insert_apply_record(
    transaction: &mut Transaction<'_>,
    apply: &RuntimeNodeAuthorityApply,
    principal: &FleetPolicyPrincipal,
    outcome: &RuntimeNodeAuthorityStoredOutcome,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let canonical_request = encode_runtime_node_authority_apply(apply).map_err(corrupt)?;
    let request_sha256 = Sha256Digest::from_bytes(Sha256::digest(&canonical_request).into());
    let request_json = String::from_utf8(canonical_request).map_err(corrupt)?;
    let principal_json = encode_json(principal)?;
    let outcome_json = encode_json(outcome)?;
    let principal_kind = principal_kind(principal);
    let outcome_kind = outcome_kind(outcome);
    let committed_at = committed_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO runtime_node_authority_apply_records (
            apply_id, request, request_sha256, principal, principal_kind,
            node_id, outcome, outcome_kind, committed_at_unix_ms
         ) VALUES ($1, $2::TEXT::jsonb, $3, $4::TEXT::jsonb, $5, $6,
                   $7::TEXT::jsonb, $8, $9)",
        &[
            &apply.apply_id.as_str(),
            &request_json,
            &request_sha256.as_str(),
            &principal_json,
            &principal_kind,
            &apply.node_id.as_str(),
            &outcome_json,
            &outcome_kind,
            &committed_at,
        ],
    )?)
}

fn load_apply_record(
    transaction: &mut Transaction<'_>,
    apply_id: &str,
) -> AuthorityTxResult<Option<RuntimeNodeAuthorityApplyRecord>> {
    let sql = format!(
        "SELECT {APPLY_COLUMNS} FROM runtime_node_authority_apply_records
          WHERE apply_id=$1"
    );
    transaction
        .query_opt(&sql, &[&apply_id])?
        .map(|row| decode_apply_record(&row))
        .transpose()
}

fn decode_apply_record(row: &Row) -> AuthorityTxResult<RuntimeNodeAuthorityApplyRecord> {
    let request: RuntimeNodeAuthorityApply = decode_json(row.try_get("request_json")?)?;
    let canonical_request = encode_runtime_node_authority_apply(&request).map_err(corrupt)?;
    let request_sha256 = parse_digest(row.try_get("request_sha256")?)?;
    if request_sha256 != Sha256Digest::from_bytes(Sha256::digest(canonical_request).into()) {
        return Err(corrupt("apply request digest mismatch"));
    }
    let principal: FleetPolicyPrincipal = decode_json(row.try_get("principal_json")?)?;
    validate_principal(&principal)?;
    let outcome: RuntimeNodeAuthorityStoredOutcome = decode_json(row.try_get("outcome_json")?)?;
    validate_stored_outcome(&request, &outcome)?;
    let apply_id = row.try_get::<_, String>("apply_id")?;
    if apply_id != request.apply_id.as_str()
        || row.try_get::<_, String>("node_id")? != request.node_id.as_str()
        || row.try_get::<_, String>("principal_kind")? != principal_kind(&principal)
        || row.try_get::<_, String>("outcome_kind")? != outcome_kind(&outcome)
    {
        return Err(corrupt("apply record JSON/projection mismatch"));
    }
    Ok(RuntimeNodeAuthorityApplyRecord {
        apply_id: request.apply_id.clone(),
        request: Box::new(request),
        request_sha256,
        principal,
        outcome,
        committed_at_unix_ms: from_pg(row.try_get("committed_at_unix_ms")?)?,
    })
}

fn validate_stored_outcome(
    request: &RuntimeNodeAuthorityApply,
    outcome: &RuntimeNodeAuthorityStoredOutcome,
) -> AuthorityTxResult<()> {
    if let RuntimeNodeAuthorityStoredOutcome::Applied { response } = outcome {
        encode_runtime_node_authority_apply_result(response).map_err(corrupt)?;
        if response.apply_id != request.apply_id || response.node_id != request.node_id {
            return Err(corrupt("apply result is not bound to its request"));
        }
        let (expected_outcome, expected_state, expected_revision, expected_writer) =
            match &request.mutation {
                RuntimeNodeAuthorityMutation::Provision {
                    placement_policy, ..
                } => (
                    RuntimeNodeAuthorityOutcome::Provisioned,
                    NodeIdentityState::Provisioned,
                    placement_policy.policy_revision,
                    None,
                ),
                RuntimeNodeAuthorityMutation::UpdatePolicy {
                    placement_policy, ..
                } => (
                    RuntimeNodeAuthorityOutcome::PolicyUpdated,
                    NodeIdentityState::Provisioned,
                    placement_policy.policy_revision,
                    None,
                ),
                RuntimeNodeAuthorityMutation::RotateCredential {
                    expected_policy_revision,
                    ..
                } => (
                    RuntimeNodeAuthorityOutcome::CredentialRotated,
                    NodeIdentityState::Provisioned,
                    *expected_policy_revision,
                    None,
                ),
                RuntimeNodeAuthorityMutation::Retire {
                    expected_policy_revision,
                    ..
                } => (
                    RuntimeNodeAuthorityOutcome::Retired,
                    NodeIdentityState::Retired,
                    *expected_policy_revision,
                    None,
                ),
                // A replayed writer-authority apply must return the one ID this
                // exact binding assigns. A stored result naming any other
                // authority is corrupt, not a replay.
                RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
                    expected_policy_revision,
                    object_provider_scope,
                    workload_principal_id,
                    object_store_scope_id,
                } => (
                    RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned,
                    NodeIdentityState::Provisioned,
                    *expected_policy_revision,
                    Some(object_write_writer_authority_id(
                        &request.node_id,
                        object_provider_scope,
                        workload_principal_id,
                        object_store_scope_id,
                    )),
                ),
            };
        if response.outcome != expected_outcome
            || response.identity_state != expected_state
            || response.policy_revision != expected_revision
            || response.writer_authority_id != expected_writer
        {
            return Err(corrupt("apply result does not match its mutation"));
        }
    }
    Ok(())
}

fn applied_result(
    apply: &RuntimeNodeAuthorityApply,
    outcome: RuntimeNodeAuthorityOutcome,
    identity_state: NodeIdentityState,
    policy_revision: Epoch,
    writer_authority_id: Option<Id>,
) -> RuntimeNodeAuthorityStoredOutcome {
    RuntimeNodeAuthorityStoredOutcome::Applied {
        response: RuntimeNodeAuthorityApplyResult {
            version: ContractVersion::V1,
            apply_id: apply.apply_id.clone(),
            node_id: apply.node_id.clone(),
            outcome,
            identity_state,
            policy_revision,
            writer_authority_id,
        },
    }
}

fn validate_principal(principal: &FleetPolicyPrincipal) -> AuthorityTxResult<()> {
    if let FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id,
        credential_id,
        public_key_spki,
        public_key_spki_sha256,
    } = principal
    {
        let active_set = RuntimeProvisionerActiveSet {
            version: ContractVersion::V1,
            deployment_id: deployment_id.clone(),
            credentials: vec![RuntimeProvisionerCredential {
                credential_id: credential_id.clone(),
                public_key_spki: public_key_spki.clone(),
            }],
        };
        encode_runtime_provisioner_active_set(&active_set).map_err(corrupt)?;
        if canonical_ed25519_spki_sha256(public_key_spki).as_ref() != Some(public_key_spki_sha256) {
            return Err(corrupt("provisioner principal SPKI digest mismatch"));
        }
    }
    Ok(())
}

fn identity_public_key(identity: &NodeIdentity) -> Option<&Sha256Digest> {
    match &identity.credential_binding {
        CredentialBinding::PublicKey {
            public_key_spki_sha256,
        } => Some(public_key_spki_sha256),
        CredentialBinding::ProviderPrincipal { .. } => None,
    }
}

fn identity_matches_public_key_binding(
    identity: &NodeIdentity,
    binding: &PublicKeyCredentialBinding,
) -> bool {
    identity_public_key(identity) == Some(binding_digest(binding))
}

fn binding_digest(binding: &PublicKeyCredentialBinding) -> &Sha256Digest {
    match binding {
        PublicKeyCredentialBinding::PublicKey {
            public_key_spki_sha256,
        } => public_key_spki_sha256,
    }
}

fn principal_kind(principal: &FleetPolicyPrincipal) -> &'static str {
    match principal {
        FleetPolicyPrincipal::DeploymentProvisioner { .. } => "deployment_provisioner",
        FleetPolicyPrincipal::WorkosFleetAdministrator { .. } => "workos_fleet_administrator",
    }
}

fn outcome_kind(outcome: &RuntimeNodeAuthorityStoredOutcome) -> &'static str {
    match outcome {
        RuntimeNodeAuthorityStoredOutcome::Applied { .. } => "applied",
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed => {
            "authority_precondition_failed"
        }
    }
}

fn scheduling_state(state: RuntimeSchedulingState) -> &'static str {
    match state {
        RuntimeSchedulingState::Cordoned => "cordoned",
        RuntimeSchedulingState::Schedulable => "schedulable",
    }
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored Id is malformed"))
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored digest is malformed"))
}

fn encode_json<T: Serialize>(value: &T) -> AuthorityTxResult<String> {
    serde_json::to_string(value).map_err(corrupt)
}

fn decode_json<T: DeserializeOwned>(value: String) -> AuthorityTxResult<T> {
    serde_json::from_str(&value).map_err(corrupt)
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn optional_from_pg<T: PgBigInt>(value: Option<i64>) -> AuthorityTxResult<Option<T>> {
    value.map(from_pg).transpose()
}

fn closed_text(value: String, allowed: &[&str]) -> AuthorityTxResult<String> {
    allowed
        .contains(&value.as_str())
        .then_some(value)
        .ok_or_else(|| corrupt("stored closed projection has an unknown value"))
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt("expected exactly one changed row"))
    }
}

fn trust_rejected(message: &'static str) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(ApiError::failed_precondition(message))
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

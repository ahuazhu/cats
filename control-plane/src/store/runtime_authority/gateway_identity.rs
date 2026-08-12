//! PostgreSQL source of truth for the independent Route v2 Gateway identity.
//!
//! Fixed filesystem bytes are installation candidates only. Every request
//! authenticates and later revalidates against the current exact PostgreSQL
//! revision while holding the shared authority advisory lock.

use cats_api::gateway_workload_identity::{
    decode_gateway_workload_identity_authority, encode_gateway_workload_identity_authority,
    GatewayWorkloadCredentialPolicy, GatewayWorkloadCredentialScope,
    GatewayWorkloadIdentityAuthority, GatewayWorkloadIdentityExpectedPrevious,
};
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, Epoch, Id, Sha256Digest, UnixMillis,
};
use cats_storage::authority::AuthorityError;
use postgres::{Row, Transaction};
use sha2::{Digest as _, Sha256};

use super::pg_codec::PgBigInt;
use super::rows::database_now;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{ApiError, AuthorityRequestContext, Result, Store};

/// Request-local proof derived from a CA-verified TLS leaf and a current PG
/// policy read. It is never deserialized from HTTP and must be revalidated in
/// the final route-signing snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedGatewayPrincipal {
    pub(crate) authority_id: Id,
    pub(crate) fleet_id: Id,
    pub(crate) policy_revision: Epoch,
    pub(crate) policy_sha256: Sha256Digest,
    pub(crate) credential_id: Id,
    pub(crate) public_key_spki_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayAuthorityPointer {
    authority_id: Id,
    fleet_id: Id,
    policy_revision: Epoch,
    policy_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayCredentialLineageRow {
    credential_id: Id,
    public_key_spki: Base64UrlNoPad,
    public_key_spki_sha256: Sha256Digest,
    state: String,
    first_policy_revision: Epoch,
}

impl GatewayCredentialLineageRow {
    fn from_row(row: &Row) -> AuthorityTxResult<Self> {
        let public_key_spki = Base64UrlNoPad::new(row.try_get::<_, String>("public_key_spki")?)
            .ok_or_else(|| corrupt("stored Gateway SPKI is malformed"))?;
        let computed = canonical_ed25519_spki_sha256(&public_key_spki)
            .ok_or_else(|| corrupt("stored Gateway SPKI is not canonical Ed25519 DER"))?;
        let persisted = parse_digest(row.try_get("public_key_spki_sha256")?)?;
        if computed != persisted {
            return Err(corrupt("stored Gateway SPKI digest mismatch"));
        }
        let state = closed_text(row.try_get("state")?, &["active", "revoked"])?;
        let first_policy_revision: Epoch = from_pg(row.try_get("first_policy_revision")?)?;
        let first_committed_at: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
        let revoked_at: Option<UnixMillis> = optional_from_pg(row.try_get("revoked_at_unix_ms")?)?;
        if (state == "active" && revoked_at.is_some())
            || (state == "revoked" && revoked_at.is_none_or(|revoked| revoked < first_committed_at))
        {
            return Err(corrupt("stored Gateway lineage state/time mismatch"));
        }
        Ok(Self {
            credential_id: parse_id(row.try_get("credential_id")?)?,
            public_key_spki,
            public_key_spki_sha256: persisted,
            state,
            first_policy_revision,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentGatewayAuthority {
    pointer: GatewayAuthorityPointer,
    authority: GatewayWorkloadIdentityAuthority,
    exact_bytes: Vec<u8>,
}

impl Store {
    /// Install, exact-replay, or CAS-advance the fixed bootstrap candidate.
    /// PostgreSQL remains the only runtime-current source after this returns.
    pub(crate) fn install_gateway_workload_identity_authority(
        &self,
        authority: &GatewayWorkloadIdentityAuthority,
    ) -> Result<()> {
        let exact_bytes = encode_gateway_workload_identity_authority(authority)
            .map_err(|_| ApiError::invalid("Gateway workload identity authority is invalid"))?;
        self.authority_transaction(|transaction| {
            install_gateway_authority_in(transaction, authority, &exact_bytes)
        })
    }

    /// Authenticate one CA-verified TLS leaf before the HTTP body or Route
    /// Store is read. Workspace scope is deliberately deferred.
    pub(crate) fn authenticate_gateway_tls_peer(
        &self,
        public_key_spki_sha256: &Sha256Digest,
        request: &AuthorityRequestContext,
    ) -> Result<Option<AuthenticatedGatewayPrincipal>> {
        let public_key_spki_sha256 = public_key_spki_sha256.clone();
        self.authority_request_route_v2_read_snapshot(request, |transaction| {
            authenticate_gateway_tls_peer_in(transaction, &public_key_spki_sha256)
        })
    }

    #[cfg(test)]
    pub(crate) fn authenticate_gateway_tls_peer_for_test(
        &self,
        public_key_spki_sha256: &Sha256Digest,
    ) -> Result<Option<AuthenticatedGatewayPrincipal>> {
        self.authority_locking_read_snapshot(|transaction| {
            authenticate_gateway_tls_peer_in(transaction, public_key_spki_sha256)
        })
    }

    #[cfg(test)]
    pub(crate) fn gateway_principal_authorizes_workspace_for_test(
        &self,
        principal: &AuthenticatedGatewayPrincipal,
        workspace_id: &Id,
    ) -> Result<bool> {
        self.authority_locking_read_snapshot(|transaction| {
            lock_route_v2_machine_authority_shared(transaction)?;
            revalidate_gateway_principal_for_workspace_in(transaction, principal, workspace_id)
        })
    }

    /// Deterministic writer-first race fixture: the production install has
    /// completed all writes while retaining its exclusive transaction barrier,
    /// and commits only after the test releases it.
    #[cfg(test)]
    pub(crate) fn install_gateway_authority_paused_before_commit_for_test(
        &self,
        authority: &GatewayWorkloadIdentityAuthority,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) -> Result<()> {
        let exact_bytes = encode_gateway_workload_identity_authority(authority)
            .map_err(|_| ApiError::invalid("Gateway workload identity authority is invalid"))?;
        let mut pause = Some((entered, release));
        self.authority_transaction(|transaction| {
            install_gateway_authority_in(transaction, authority, &exact_bytes)?;
            if let Some((entered, release)) = pause.take() {
                entered.wait();
                release.wait();
            }
            Ok(())
        })
    }
}

/// Acquire the shared linearization barrier used by both pre-body auth and
/// the complete Route signing snapshot. Policy writers take the exclusive
/// form of this exact key.
pub(super) fn lock_route_v2_machine_authority_shared(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock_shared(hashtextextended(
            current_schema() || ':route-v2-gateway-identity', 0::BIGINT))",
        &[],
    )?;
    Ok(())
}

/// Writers for either the Gateway credential current pointer or the Route v2
/// signer current pointer take the exclusive form of the same barrier. This
/// gives the final signing snapshot one ordering against both rotations.
pub(super) fn lock_route_v2_machine_authority_exclusive(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':route-v2-gateway-identity', 0::BIGINT))",
        &[],
    )?;
    Ok(())
}

/// Revalidate the pre-body proof and hostname-derived Workspace against the
/// current exact revision while the caller retains the shared lock.
#[cfg(test)]
pub(super) fn revalidate_gateway_principal_for_workspace_in(
    transaction: &mut Transaction<'_>,
    principal: &AuthenticatedGatewayPrincipal,
    workspace_id: &Id,
) -> AuthorityTxResult<bool> {
    Ok(
        revalidate_gateway_principal_current_in(transaction, principal)?
            .is_some_and(|scope| scope.authorizes_workspace(workspace_id)),
    )
}

/// Revalidate the exact pre-body principal without yet granting any Workspace
/// authority. The returned scope remains meaningful only inside the caller's
/// retained snapshot and shared advisory lock.
pub(super) fn revalidate_gateway_principal_current_in(
    transaction: &mut Transaction<'_>,
    principal: &AuthenticatedGatewayPrincipal,
) -> AuthorityTxResult<Option<GatewayWorkloadCredentialScope>> {
    let Some(current) = load_current_gateway_authority(transaction, "")? else {
        return Ok(None);
    };
    if current.pointer.authority_id != principal.authority_id
        || current.pointer.fleet_id != principal.fleet_id
        || current.pointer.policy_revision != principal.policy_revision
        || current.pointer.policy_sha256 != principal.policy_sha256
    {
        return Ok(None);
    }
    let Some(credential) = current
        .authority
        .credential_by_spki_sha256(&principal.public_key_spki_sha256)
    else {
        return Ok(None);
    };
    if credential.credential_id != principal.credential_id {
        return Ok(None);
    }
    Ok(Some(credential.scope.clone()))
}

fn authenticate_gateway_tls_peer_in(
    transaction: &mut Transaction<'_>,
    public_key_spki_sha256: &Sha256Digest,
) -> AuthorityTxResult<Option<AuthenticatedGatewayPrincipal>> {
    lock_route_v2_machine_authority_shared(transaction)?;
    let Some(current) = load_current_gateway_authority(transaction, "")? else {
        return Ok(None);
    };
    let Some(credential) = current
        .authority
        .credential_by_spki_sha256(public_key_spki_sha256)
    else {
        return Ok(None);
    };
    Ok(Some(AuthenticatedGatewayPrincipal {
        authority_id: current.pointer.authority_id,
        fleet_id: current.pointer.fleet_id,
        policy_revision: current.pointer.policy_revision,
        policy_sha256: current.pointer.policy_sha256,
        credential_id: credential.credential_id.clone(),
        public_key_spki_sha256: public_key_spki_sha256.clone(),
    }))
}

fn install_gateway_authority_in(
    transaction: &mut Transaction<'_>,
    authority: &GatewayWorkloadIdentityAuthority,
    exact_bytes: &[u8],
) -> AuthorityTxResult<()> {
    lock_route_v2_machine_authority_exclusive(transaction)?;
    let candidate_digest = Sha256Digest::from_bytes(Sha256::digest(exact_bytes).into());
    let current_pointer = load_gateway_authority_pointer(transaction, "FOR UPDATE")?;
    let Some(current_pointer) = current_pointer else {
        ensure_gateway_authority_tables_empty(transaction)?;
        return insert_initial_gateway_authority(
            transaction,
            authority,
            exact_bytes,
            &candidate_digest,
        );
    };
    let current = load_current_gateway_authority_for_pointer(transaction, current_pointer)?;
    if authority.authority_id != current.pointer.authority_id
        || authority.fleet_id != current.pointer.fleet_id
    {
        return Err(rejected("Gateway authority or fleet identity changed"));
    }
    if authority.policy_revision == current.pointer.policy_revision {
        if candidate_digest != current.pointer.policy_sha256
            || exact_bytes != current.exact_bytes
            || authority != &current.authority
        {
            return Err(rejected(
                "same Gateway policy revision is not an exact replay",
            ));
        }
        return Ok(());
    }
    let expected_next = current
        .pointer
        .policy_revision
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or_else(|| rejected("Gateway policy revision is exhausted"))?;
    let expected_previous = GatewayWorkloadIdentityExpectedPrevious {
        policy_revision: current.pointer.policy_revision,
        policy_sha256: current.pointer.policy_sha256.clone(),
    };
    if authority.policy_revision != expected_next
        || authority.expected_previous.as_ref() != Some(&expected_previous)
        || candidate_digest == current.pointer.policy_sha256
    {
        return Err(rejected("Gateway policy CAS precondition failed"));
    }

    let committed_at = database_now(transaction)?;
    let committed_at_pg = committed_at.to_pg().map_err(corrupt)?;
    for candidate in &authority.credentials {
        admit_gateway_credential(
            transaction,
            &authority.authority_id,
            authority.policy_revision,
            candidate,
            committed_at_pg,
        )?;
    }

    exactly_changed(
        transaction.execute("DELETE FROM route_v2_gateway_current_credentials", &[])?,
        current.authority.credentials.len() as u64,
    )?;
    for old in &current.authority.credentials {
        if !authority
            .credentials
            .iter()
            .any(|candidate| candidate.credential_id == old.credential_id)
        {
            exactly_one(transaction.execute(
                "UPDATE route_v2_gateway_credential_lineage
                    SET state='revoked', revoked_at_unix_ms=$3
                  WHERE credential_id=$1 AND authority_id=$2 AND state='active'",
                &[
                    &old.credential_id.as_str(),
                    &authority.authority_id.as_str(),
                    &committed_at_pg,
                ],
            )?)?;
        }
    }
    insert_gateway_revision(
        transaction,
        authority,
        exact_bytes,
        &candidate_digest,
        committed_at,
    )?;
    let old_revision = current.pointer.policy_revision.to_pg().map_err(corrupt)?;
    let new_revision = authority.policy_revision.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "UPDATE route_v2_gateway_identity_authority
            SET current_policy_revision=$4, current_policy_sha256=$5
          WHERE singleton AND authority_id=$1 AND fleet_id=$2
            AND current_policy_revision=$3 AND current_policy_sha256=$6",
        &[
            &authority.authority_id.as_str(),
            &authority.fleet_id.as_str(),
            &old_revision,
            &new_revision,
            &candidate_digest.as_str(),
            &current.pointer.policy_sha256.as_str(),
        ],
    )?)?;
    insert_current_gateway_credentials(transaction, authority, &candidate_digest)
}

fn ensure_gateway_authority_tables_empty(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<()> {
    let row = transaction.query_one(
        "SELECT
            (SELECT count(*) FROM route_v2_gateway_identity_revisions),
            (SELECT count(*) FROM route_v2_gateway_credential_lineage),
            (SELECT count(*) FROM route_v2_gateway_current_credentials)",
        &[],
    )?;
    let counts = [
        row.try_get::<_, i64>(0)?,
        row.try_get::<_, i64>(1)?,
        row.try_get::<_, i64>(2)?,
    ];
    if counts != [0, 0, 0] {
        return Err(corrupt(
            "Gateway authority pointer is absent with orphan rows",
        ));
    }
    Ok(())
}

fn insert_initial_gateway_authority(
    transaction: &mut Transaction<'_>,
    authority: &GatewayWorkloadIdentityAuthority,
    exact_bytes: &[u8],
    digest: &Sha256Digest,
) -> AuthorityTxResult<()> {
    if authority.policy_revision.get() != 1 || authority.expected_previous.is_some() {
        return Err(rejected("initial Gateway policy must be revision one"));
    }
    let committed_at = database_now(transaction)?;
    let committed_at_pg = committed_at.to_pg().map_err(corrupt)?;
    let revision = authority.policy_revision.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_gateway_identity_authority (
            singleton, authority_id, fleet_id, current_policy_revision,
            current_policy_sha256, first_committed_at_unix_ms
         ) VALUES (TRUE, $1, $2, $3, $4, $5)",
        &[
            &authority.authority_id.as_str(),
            &authority.fleet_id.as_str(),
            &revision,
            &digest.as_str(),
            &committed_at_pg,
        ],
    )?)?;
    for credential in &authority.credentials {
        admit_gateway_credential(
            transaction,
            &authority.authority_id,
            authority.policy_revision,
            credential,
            committed_at_pg,
        )?;
    }
    insert_gateway_revision(transaction, authority, exact_bytes, digest, committed_at)?;
    insert_current_gateway_credentials(transaction, authority, digest)
}

fn admit_gateway_credential(
    transaction: &mut Transaction<'_>,
    authority_id: &Id,
    policy_revision: Epoch,
    candidate: &GatewayWorkloadCredentialPolicy,
    committed_at_pg: i64,
) -> AuthorityTxResult<()> {
    let policy_revision_pg = policy_revision.to_pg().map_err(corrupt)?;
    let digest = canonical_ed25519_spki_sha256(&candidate.public_key_spki)
        .ok_or_else(|| corrupt("validated Gateway SPKI became invalid"))?;
    let matching = transaction.query(
        "SELECT credential_id, authority_id, public_key_spki,
                public_key_spki_sha256, state, first_policy_revision,
                first_committed_at_unix_ms,
                revoked_at_unix_ms
           FROM route_v2_gateway_credential_lineage
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
            "INSERT INTO route_v2_gateway_credential_lineage (
                credential_id, authority_id, public_key_spki,
                public_key_spki_sha256, state,
                first_policy_revision, first_committed_at_unix_ms,
                revoked_at_unix_ms
             ) VALUES ($1, $2, $3, $4, 'active', $5, $6, NULL)",
            &[
                &candidate.credential_id.as_str(),
                &authority_id.as_str(),
                &candidate.public_key_spki.as_str(),
                &digest.as_str(),
                &policy_revision_pg,
                &committed_at_pg,
            ],
        )?)?;
        return Ok(());
    }
    if matching.len() != 1 {
        return Err(rejected("Gateway credential lineage cannot be reused"));
    }
    let stored = GatewayCredentialLineageRow::from_row(&matching[0])?;
    let stored_authority = parse_id(matching[0].try_get("authority_id")?)?;
    if stored_authority != *authority_id
        || stored.credential_id != candidate.credential_id
        || stored.public_key_spki != candidate.public_key_spki
        || stored.public_key_spki_sha256 != digest
        || stored.state != "active"
        || stored.first_policy_revision > policy_revision
    {
        return Err(rejected("Gateway credential lineage cannot be reused"));
    }
    Ok(())
}

fn insert_gateway_revision(
    transaction: &mut Transaction<'_>,
    authority: &GatewayWorkloadIdentityAuthority,
    exact_bytes: &[u8],
    digest: &Sha256Digest,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let revision = authority.policy_revision.to_pg().map_err(corrupt)?;
    let (previous_revision, previous_digest) = match &authority.expected_previous {
        Some(previous) => (
            Some(previous.policy_revision.to_pg().map_err(corrupt)?),
            Some(previous.policy_sha256.as_str()),
        ),
        None => (None, None),
    };
    let committed_at = committed_at.to_pg().map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_gateway_identity_revisions (
            authority_id, fleet_id, policy_revision, policy_sha256,
            policy_bytes, expected_previous_policy_revision,
            expected_previous_policy_sha256, committed_at_unix_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &authority.authority_id.as_str(),
            &authority.fleet_id.as_str(),
            &revision,
            &digest.as_str(),
            &exact_bytes,
            &previous_revision,
            &previous_digest,
            &committed_at,
        ],
    )?)
}

fn insert_current_gateway_credentials(
    transaction: &mut Transaction<'_>,
    authority: &GatewayWorkloadIdentityAuthority,
    digest: &Sha256Digest,
) -> AuthorityTxResult<()> {
    let revision = authority.policy_revision.to_pg().map_err(corrupt)?;
    for credential in &authority.credentials {
        let public_key_digest = canonical_ed25519_spki_sha256(&credential.public_key_spki)
            .ok_or_else(|| corrupt("validated Gateway SPKI became invalid"))?;
        let scope = serde_json::to_string(&credential.scope).map_err(corrupt)?;
        exactly_one(transaction.execute(
            "INSERT INTO route_v2_gateway_current_credentials (
                credential_id, authority_id, fleet_id, policy_revision,
                policy_sha256, public_key_spki_sha256, scope, lineage_state
             ) VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT::JSONB, 'active')",
            &[
                &credential.credential_id.as_str(),
                &authority.authority_id.as_str(),
                &authority.fleet_id.as_str(),
                &revision,
                &digest.as_str(),
                &public_key_digest.as_str(),
                &scope,
            ],
        )?)?;
    }
    Ok(())
}

fn load_current_gateway_authority(
    transaction: &mut Transaction<'_>,
    pointer_lock: &str,
) -> AuthorityTxResult<Option<CurrentGatewayAuthority>> {
    let Some(pointer) = load_gateway_authority_pointer(transaction, pointer_lock)? else {
        return Ok(None);
    };
    load_current_gateway_authority_for_pointer(transaction, pointer).map(Some)
}

fn load_current_gateway_authority_for_pointer(
    transaction: &mut Transaction<'_>,
    pointer: GatewayAuthorityPointer,
) -> AuthorityTxResult<CurrentGatewayAuthority> {
    let revision = pointer.policy_revision.to_pg().map_err(corrupt)?;
    let row = transaction
        .query_opt(
            "SELECT authority_id, fleet_id, policy_revision, policy_sha256,
                    policy_bytes, expected_previous_policy_revision,
                    expected_previous_policy_sha256, committed_at_unix_ms
               FROM route_v2_gateway_identity_revisions
              WHERE authority_id=$1 AND policy_revision=$2",
            &[&pointer.authority_id.as_str(), &revision],
        )?
        .ok_or_else(|| corrupt("Gateway current pointer has no immutable revision"))?;
    let row_authority_id = parse_id(row.try_get("authority_id")?)?;
    let row_fleet_id = parse_id(row.try_get("fleet_id")?)?;
    let row_revision: Epoch = from_pg(row.try_get("policy_revision")?)?;
    let row_digest = parse_digest(row.try_get("policy_sha256")?)?;
    let exact_bytes: Vec<u8> = row.try_get("policy_bytes")?;
    let computed_digest = Sha256Digest::from_bytes(Sha256::digest(&exact_bytes).into());
    let authority = decode_gateway_workload_identity_authority(&exact_bytes)
        .map_err(|_| corrupt("stored Gateway policy bytes are invalid"))?;
    let expected_previous_revision =
        optional_from_pg::<Epoch>(row.try_get("expected_previous_policy_revision")?)?;
    let expected_previous_digest = row
        .try_get::<_, Option<String>>("expected_previous_policy_sha256")?
        .map(parse_digest)
        .transpose()?;
    let expected_previous = match (expected_previous_revision, expected_previous_digest) {
        (Some(policy_revision), Some(policy_sha256)) => {
            Some(GatewayWorkloadIdentityExpectedPrevious {
                policy_revision,
                policy_sha256,
            })
        }
        (None, None) => None,
        _ => return Err(corrupt("stored Gateway previous projection is partial")),
    };
    let _: UnixMillis = from_pg(row.try_get("committed_at_unix_ms")?)?;
    if row_authority_id != pointer.authority_id
        || row_fleet_id != pointer.fleet_id
        || row_revision != pointer.policy_revision
        || row_digest != pointer.policy_sha256
        || computed_digest != pointer.policy_sha256
        || authority.authority_id != pointer.authority_id
        || authority.fleet_id != pointer.fleet_id
        || authority.policy_revision != pointer.policy_revision
        || authority.expected_previous != expected_previous
    {
        return Err(corrupt("Gateway pointer/revision/exact bytes mismatch"));
    }
    validate_current_gateway_projections(transaction, &pointer, &authority)?;
    Ok(CurrentGatewayAuthority {
        pointer,
        authority,
        exact_bytes,
    })
}

fn validate_current_gateway_projections(
    transaction: &mut Transaction<'_>,
    pointer: &GatewayAuthorityPointer,
    authority: &GatewayWorkloadIdentityAuthority,
) -> AuthorityTxResult<()> {
    let current_rows = transaction.query(
        "SELECT credential_id, authority_id, fleet_id, policy_revision,
                policy_sha256, public_key_spki_sha256, scope::TEXT AS scope_json,
                lineage_state
           FROM route_v2_gateway_current_credentials
          ORDER BY credential_id COLLATE \"C\"",
        &[],
    )?;
    let lineage_rows = transaction.query(
        "SELECT credential_id, authority_id, public_key_spki,
                public_key_spki_sha256, state, first_policy_revision,
                first_committed_at_unix_ms,
                revoked_at_unix_ms
           FROM route_v2_gateway_credential_lineage
          WHERE state='active' ORDER BY credential_id COLLATE \"C\"",
        &[],
    )?;
    if current_rows.len() != authority.credentials.len()
        || lineage_rows.len() != authority.credentials.len()
    {
        return Err(corrupt("Gateway current credential cardinality mismatch"));
    }
    for ((current_row, lineage_row), expected) in current_rows
        .iter()
        .zip(&lineage_rows)
        .zip(&authority.credentials)
    {
        let lineage = GatewayCredentialLineageRow::from_row(lineage_row)?;
        let lineage_authority = parse_id(lineage_row.try_get("authority_id")?)?;
        let current_credential_id = parse_id(current_row.try_get("credential_id")?)?;
        let current_authority_id = parse_id(current_row.try_get("authority_id")?)?;
        let current_fleet_id = parse_id(current_row.try_get("fleet_id")?)?;
        let current_revision: Epoch = from_pg(current_row.try_get("policy_revision")?)?;
        let current_digest = parse_digest(current_row.try_get("policy_sha256")?)?;
        let current_spki_digest = parse_digest(current_row.try_get("public_key_spki_sha256")?)?;
        let current_scope: GatewayWorkloadCredentialScope =
            serde_json::from_str(&current_row.try_get::<_, String>("scope_json")?)
                .map_err(corrupt)?;
        let current_state = closed_text(current_row.try_get("lineage_state")?, &["active"])?;
        let expected_spki_digest = canonical_ed25519_spki_sha256(&expected.public_key_spki)
            .ok_or_else(|| corrupt("validated current Gateway SPKI became invalid"))?;
        if lineage_authority != pointer.authority_id
            || lineage.first_policy_revision > pointer.policy_revision
            || lineage.credential_id != expected.credential_id
            || lineage.public_key_spki != expected.public_key_spki
            || lineage.public_key_spki_sha256 != expected_spki_digest
            || lineage.state != "active"
            || current_credential_id != expected.credential_id
            || current_authority_id != pointer.authority_id
            || current_fleet_id != pointer.fleet_id
            || current_revision != pointer.policy_revision
            || current_digest != pointer.policy_sha256
            || current_spki_digest != expected_spki_digest
            || current_scope != expected.scope
            || current_state != "active"
        {
            return Err(corrupt("Gateway exact policy/current/lineage mismatch"));
        }
    }
    Ok(())
}

fn load_gateway_authority_pointer(
    transaction: &mut Transaction<'_>,
    lock: &str,
) -> AuthorityTxResult<Option<GatewayAuthorityPointer>> {
    let sql = format!(
        "SELECT authority_id, fleet_id, current_policy_revision,
                current_policy_sha256, first_committed_at_unix_ms
           FROM route_v2_gateway_identity_authority WHERE singleton {lock}"
    );
    transaction
        .query_opt(&sql, &[])?
        .map(|row| {
            let _: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
            Ok(GatewayAuthorityPointer {
                authority_id: parse_id(row.try_get("authority_id")?)?,
                fleet_id: parse_id(row.try_get("fleet_id")?)?,
                policy_revision: from_pg(row.try_get("current_policy_revision")?)?,
                policy_sha256: parse_digest(row.try_get("current_policy_sha256")?)?,
            })
        })
        .transpose()
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored Gateway identity is malformed"))
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored Gateway digest is malformed"))
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
        .ok_or_else(|| corrupt("stored Gateway closed projection is invalid"))
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    exactly_changed(changed, 1)
}

fn exactly_changed(changed: u64, expected: u64) -> AuthorityTxResult<()> {
    if changed == expected {
        Ok(())
    } else {
        Err(corrupt("unexpected Gateway authority changed-row count"))
    }
}

fn rejected(message: &'static str) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(ApiError::failed_precondition(message))
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

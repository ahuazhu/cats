//! PostgreSQL current binding for the independent Route Grant v2 signer.
//!
//! This slice deliberately supports only revision-one installation and exact
//! replay. Rotation, ACK rollout and retirement remain closed; startup must
//! never advance a persisted signer from local filesystem bytes.

use cats_api::route_grant_v2::{
    decode_route_grant_v2_signer_reference, encode_route_grant_v2_signer_reference,
    RouteGrantV2PublicKey, RouteGrantV2PublicKeyRingArtifact, RouteGrantV2SignerReference,
    RouteGrantV2SignerSelection,
};
use cats_api::runtime_reconciliation::{
    Base64UrlNoPad, Epoch, Id, KeyId, Sha256Digest, UnixMillis,
};
use cats_storage::authority::AuthorityError;
use postgres::{Row, Transaction};
use sha2::{Digest as _, Sha256};

use super::gateway_identity::lock_route_v2_machine_authority_exclusive;
#[cfg(test)]
use super::gateway_identity::lock_route_v2_machine_authority_shared;
use super::pg_codec::PgBigInt;
use super::rows::database_now;
use crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{ApiError, Result, Store};

/// Startup-pinned, non-secret signer facts compared on every resolve. The
/// private key is owned by `RouteGrantV2Signer` and is never copied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteGrantV2SignerBinding {
    reference: RouteGrantV2SignerReference,
    exact_reference_bytes: Vec<u8>,
    reference_sha256: Sha256Digest,
    active_public_key_spki: Option<Base64UrlNoPad>,
}

impl RouteGrantV2SignerBinding {
    pub(crate) fn from_authority_artifacts(
        reference: &RouteGrantV2SignerReference,
        exact_reference_bytes: &[u8],
        ring: &RouteGrantV2PublicKeyRingArtifact,
    ) -> anyhow::Result<Self> {
        reference
            .validate_ring(ring)
            .map_err(|_| anyhow::anyhow!("validate Route Grant v2 signer/ring binding"))?;
        let canonical = encode_route_grant_v2_signer_reference(reference)
            .map_err(|_| anyhow::anyhow!("encode Route Grant v2 signer reference"))?;
        anyhow::ensure!(
            canonical == exact_reference_bytes,
            "Route Grant v2 signer reference bytes are not exact canonical bytes"
        );
        let active_public_key_spki = match &reference.signer {
            RouteGrantV2SignerSelection::Disabled => None,
            RouteGrantV2SignerSelection::Active { active_kid, .. } => Some(
                ring.key(active_kid)
                    .ok_or_else(|| anyhow::anyhow!("active Route Grant v2 key is absent"))?
                    .public_key_spki
                    .clone(),
            ),
        };
        Ok(Self {
            reference: reference.clone(),
            exact_reference_bytes: canonical.clone(),
            reference_sha256: Sha256Digest::from_bytes(Sha256::digest(canonical).into()),
            active_public_key_spki,
        })
    }

    pub(crate) fn reference(&self) -> &RouteGrantV2SignerReference {
        &self.reference
    }

    pub(crate) fn reference_sha256(&self) -> &Sha256Digest {
        &self.reference_sha256
    }

    pub(crate) fn exact_reference_bytes(&self) -> &[u8] {
        &self.exact_reference_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteV2SignerPointer {
    deployment_id: Id,
    signer_revision: Epoch,
    signer_reference_sha256: Sha256Digest,
    signer_state: String,
    active_kid: String,
    public_key_ring_version: Epoch,
    public_key_ring_digest: Sha256Digest,
    secret_reference_id: String,
}

impl Store {
    /// Install revision one or prove an exact zero-write replay. A different
    /// persisted current is an ordinary startup-closed result, never a local
    /// rotation request.
    pub(crate) fn install_route_grant_v2_signer_authority(
        &self,
        installed: &InstalledRouteGrantV2SigningAuthority,
    ) -> Result<()> {
        self.authority_transaction(|transaction| {
            install_signer_in(transaction, installed.binding())
        })
    }

    #[cfg(test)]
    pub(crate) fn route_grant_v2_signer_is_current_for_test(
        &self,
        binding: &RouteGrantV2SignerBinding,
    ) -> Result<bool> {
        self.authority_locking_read_snapshot(|transaction| {
            lock_route_v2_machine_authority_shared(transaction)?;
            route_grant_v2_signer_is_current_in(transaction, binding)
        })
    }
}

/// Compare the in-process fixed signer with PG current. The caller must hold
/// the shared Route v2 machine-authority advisory lock for the whole signing
/// snapshot.
pub(super) fn route_grant_v2_signer_is_current_in(
    transaction: &mut Transaction<'_>,
    binding: &RouteGrantV2SignerBinding,
) -> AuthorityTxResult<bool> {
    let Some(current) = load_current_signer(transaction, "")? else {
        return Ok(false);
    };
    Ok(&current == binding)
}

fn install_signer_in(
    transaction: &mut Transaction<'_>,
    binding: &RouteGrantV2SignerBinding,
) -> AuthorityTxResult<()> {
    lock_route_v2_machine_authority_exclusive(transaction)?;
    let pointer = load_pointer(transaction, "FOR UPDATE")?;
    let Some(pointer) = pointer else {
        ensure_signer_tables_empty(transaction)?;
        return insert_initial_signer(transaction, binding);
    };
    let current = load_current_signer_for_pointer(transaction, pointer)?;
    if current == *binding {
        return Ok(());
    }
    Err(rejected(
        "installed Route Grant v2 signer does not exactly replay PostgreSQL current",
    ))
}

fn ensure_signer_tables_empty(transaction: &mut Transaction<'_>) -> AuthorityTxResult<()> {
    let row = transaction.query_one(
        "SELECT
            (SELECT count(*) FROM route_v2_signer_revisions),
            (SELECT count(*) FROM route_v2_signer_key_lineage)",
        &[],
    )?;
    if [row.try_get::<_, i64>(0)?, row.try_get::<_, i64>(1)?] != [0, 0] {
        return Err(corrupt(
            "Route v2 signer pointer is absent with orphan rows",
        ));
    }
    Ok(())
}

fn insert_initial_signer(
    transaction: &mut Transaction<'_>,
    binding: &RouteGrantV2SignerBinding,
) -> AuthorityTxResult<()> {
    let reference = binding.reference();
    if reference.signer_revision.get() != 1 || reference.expected_previous.is_some() {
        return Err(rejected(
            "initial Route Grant v2 signer must be revision one",
        ));
    }
    let committed_at = database_now(transaction)?;
    let committed_at_pg = committed_at.to_pg().map_err(corrupt)?;
    let revision = reference.signer_revision.to_pg().map_err(corrupt)?;
    let ring_version = reference.public_key_ring_version.to_pg().map_err(corrupt)?;
    let selection = selection_projection(&reference.signer);

    exactly_one(transaction.execute(
        "INSERT INTO route_v2_signing_authority (
            singleton, deployment_id, current_signer_revision,
            current_signer_reference_sha256, signer_state, active_kid,
            public_key_ring_version, public_key_ring_digest,
            secret_reference_id, first_committed_at_unix_ms
         ) VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &reference.deployment_id.as_str(),
            &revision,
            &binding.reference_sha256().as_str(),
            &selection.state,
            &selection.active_kid,
            &ring_version,
            &reference.public_key_ring_digest.as_str(),
            &selection.secret_reference_id,
            &committed_at_pg,
        ],
    )?)?;
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_signer_revisions (
            deployment_id, signer_revision, signer_reference_sha256,
            signer_reference_bytes, expected_previous_signer_revision,
            expected_previous_signer_reference_sha256, signer_state,
            active_kid, public_key_ring_version, public_key_ring_digest,
            secret_reference_id, committed_at_unix_ms
         ) VALUES ($1, $2, $3, $4, NULL, NULL, $5, $6, $7, $8, $9, $10)",
        &[
            &reference.deployment_id.as_str(),
            &revision,
            &binding.reference_sha256().as_str(),
            &binding.exact_reference_bytes(),
            &selection.state,
            &selection.active_kid,
            &ring_version,
            &reference.public_key_ring_digest.as_str(),
            &selection.secret_reference_id,
            &committed_at_pg,
        ],
    )?)?;

    if let RouteGrantV2SignerSelection::Active {
        active_kid,
        secret_reference_id,
    } = &reference.signer
    {
        let public_key_spki = binding
            .active_public_key_spki
            .as_ref()
            .ok_or_else(|| corrupt("active Route v2 signer has no public-key projection"))?;
        exactly_one(transaction.execute(
            "INSERT INTO route_v2_signer_key_lineage (
                kid, deployment_id, public_key_spki, secret_reference_id,
                first_signer_revision, state, first_committed_at_unix_ms,
                retired_at_unix_ms
             ) VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL)",
            &[
                &active_kid.as_str(),
                &reference.deployment_id.as_str(),
                &public_key_spki.as_str(),
                &secret_reference_id.as_str(),
                &revision,
                &committed_at_pg,
            ],
        )?)?;
    }
    Ok(())
}

fn load_current_signer(
    transaction: &mut Transaction<'_>,
    lock: &str,
) -> AuthorityTxResult<Option<RouteGrantV2SignerBinding>> {
    let Some(pointer) = load_pointer(transaction, lock)? else {
        return Ok(None);
    };
    load_current_signer_for_pointer(transaction, pointer).map(Some)
}

fn load_current_signer_for_pointer(
    transaction: &mut Transaction<'_>,
    pointer: RouteV2SignerPointer,
) -> AuthorityTxResult<RouteGrantV2SignerBinding> {
    let revision = pointer.signer_revision.to_pg().map_err(corrupt)?;
    let row = transaction
        .query_opt(
            "SELECT deployment_id, signer_revision, signer_reference_sha256,
                    signer_reference_bytes, expected_previous_signer_revision,
                    expected_previous_signer_reference_sha256, signer_state,
                    active_kid, public_key_ring_version, public_key_ring_digest,
                    secret_reference_id, committed_at_unix_ms
               FROM route_v2_signer_revisions
              WHERE deployment_id=$1 AND signer_revision=$2",
            &[&pointer.deployment_id.as_str(), &revision],
        )?
        .ok_or_else(|| corrupt("Route v2 signer current pointer has no revision"))?;
    let row_deployment_id = parse_id(row.try_get("deployment_id")?)?;
    let row_revision: Epoch = from_pg(row.try_get("signer_revision")?)?;
    let row_digest = parse_digest(row.try_get("signer_reference_sha256")?)?;
    let exact_reference_bytes: Vec<u8> = row.try_get("signer_reference_bytes")?;
    let computed_digest = Sha256Digest::from_bytes(Sha256::digest(&exact_reference_bytes).into());
    let reference = decode_route_grant_v2_signer_reference(&exact_reference_bytes)
        .map_err(|_| corrupt("stored Route v2 signer reference bytes are invalid"))?;
    let previous_revision =
        optional_from_pg::<Epoch>(row.try_get("expected_previous_signer_revision")?)?;
    let previous_digest = row
        .try_get::<_, Option<String>>("expected_previous_signer_reference_sha256")?
        .map(parse_digest)
        .transpose()?;
    let projected_previous = match (previous_revision, previous_digest) {
        (Some(signer_revision), Some(signer_reference_sha256)) => Some(
            cats_api::route_grant_v2::RouteGrantV2SignerExpectedPrevious {
                signer_revision,
                signer_reference_sha256,
            },
        ),
        (None, None) => None,
        _ => {
            return Err(corrupt(
                "stored Route v2 signer previous pointer is partial",
            ))
        }
    };
    let row_pointer = pointer_from_row(&row)?;
    let _: UnixMillis = from_pg(row.try_get("committed_at_unix_ms")?)?;
    if row_deployment_id != pointer.deployment_id
        || row_revision != pointer.signer_revision
        || row_digest != pointer.signer_reference_sha256
        || computed_digest != pointer.signer_reference_sha256
        || row_pointer != pointer
        || reference.deployment_id != pointer.deployment_id
        || reference.signer_revision != pointer.signer_revision
        || reference.expected_previous != projected_previous
        || reference.public_key_ring_version != pointer.public_key_ring_version
        || reference.public_key_ring_digest != pointer.public_key_ring_digest
        || selection_projection(&reference.signer)
            != (SelectionProjection {
                state: pointer.signer_state.clone(),
                active_kid: pointer.active_kid.clone(),
                secret_reference_id: pointer.secret_reference_id.clone(),
            })
    {
        return Err(corrupt(
            "Route v2 signer pointer/revision projection mismatch",
        ));
    }

    let active_public_key_spki = validate_current_key_lineage(transaction, &pointer, &reference)?;
    Ok(RouteGrantV2SignerBinding {
        reference,
        exact_reference_bytes,
        reference_sha256: computed_digest,
        active_public_key_spki,
    })
}

fn validate_current_key_lineage(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    reference: &RouteGrantV2SignerReference,
) -> AuthorityTxResult<Option<Base64UrlNoPad>> {
    let lineage_count: i64 = transaction
        .query_one(
            "SELECT count(*) FROM route_v2_signer_key_lineage
              WHERE deployment_id=$1",
            &[&pointer.deployment_id.as_str()],
        )?
        .try_get(0)?;
    let RouteGrantV2SignerSelection::Active {
        active_kid,
        secret_reference_id,
    } = &reference.signer
    else {
        if lineage_count != 0 {
            return Err(corrupt(
                "disabled initial Route v2 signer has unexpected key lineage",
            ));
        }
        return Ok(None);
    };
    if lineage_count != 1 {
        return Err(corrupt(
            "initial Route v2 signer key lineage cardinality mismatch",
        ));
    }
    let row = transaction
        .query_opt(
            "SELECT kid, deployment_id, public_key_spki, secret_reference_id,
                    first_signer_revision, state, first_committed_at_unix_ms,
                    retired_at_unix_ms
               FROM route_v2_signer_key_lineage WHERE kid=$1",
            &[&active_kid.as_str()],
        )?
        .ok_or_else(|| corrupt("current Route v2 signer key has no permanent lineage"))?;
    let stored_kid = parse_kid(row.try_get("kid")?)?;
    let stored_deployment = parse_id(row.try_get("deployment_id")?)?;
    let public_key_spki = Base64UrlNoPad::new(row.try_get::<_, String>("public_key_spki")?)
        .ok_or_else(|| corrupt("stored Route v2 signer SPKI is malformed"))?;
    let public = RouteGrantV2PublicKey::from_base64url_spki(&public_key_spki)
        .map_err(|_| corrupt("stored Route v2 signer SPKI is not canonical Ed25519"))?;
    let stored_secret = parse_id(row.try_get("secret_reference_id")?)?;
    let first_revision: Epoch = from_pg(row.try_get("first_signer_revision")?)?;
    let state: String = row.try_get("state")?;
    let _: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
    let retired_at: Option<UnixMillis> = optional_from_pg(row.try_get("retired_at_unix_ms")?)?;
    if stored_kid != *active_kid
        || public.kid() != active_kid
        || stored_deployment != pointer.deployment_id
        || stored_secret != *secret_reference_id
        || first_revision > pointer.signer_revision
        || state != "active"
        || retired_at.is_some()
    {
        return Err(corrupt("Route v2 signer current/key lineage mismatch"));
    }
    Ok(Some(public_key_spki))
}

fn load_pointer(
    transaction: &mut Transaction<'_>,
    lock: &str,
) -> AuthorityTxResult<Option<RouteV2SignerPointer>> {
    let sql = format!(
        "SELECT deployment_id, current_signer_revision AS signer_revision,
                current_signer_reference_sha256 AS signer_reference_sha256,
                signer_state, active_kid, public_key_ring_version,
                public_key_ring_digest, secret_reference_id,
                first_committed_at_unix_ms
           FROM route_v2_signing_authority WHERE singleton {lock}"
    );
    transaction
        .query_opt(&sql, &[])?
        .map(|row| {
            let _: UnixMillis = from_pg(row.try_get("first_committed_at_unix_ms")?)?;
            pointer_from_row(&row)
        })
        .transpose()
}

fn pointer_from_row(row: &Row) -> AuthorityTxResult<RouteV2SignerPointer> {
    let signer_state: String = row.try_get("signer_state")?;
    if !matches!(signer_state.as_str(), "active" | "disabled") {
        return Err(corrupt("stored Route v2 signer state is invalid"));
    }
    let pointer = RouteV2SignerPointer {
        deployment_id: parse_id(row.try_get("deployment_id")?)?,
        signer_revision: from_pg(row.try_get("signer_revision")?)?,
        signer_reference_sha256: parse_digest(row.try_get("signer_reference_sha256")?)?,
        signer_state,
        active_kid: row.try_get("active_kid")?,
        public_key_ring_version: from_pg(row.try_get("public_key_ring_version")?)?,
        public_key_ring_digest: parse_digest(row.try_get("public_key_ring_digest")?)?,
        secret_reference_id: row.try_get("secret_reference_id")?,
    };
    validate_selection_projection(
        &pointer.signer_state,
        &pointer.active_kid,
        &pointer.secret_reference_id,
    )?;
    Ok(pointer)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectionProjection {
    state: String,
    active_kid: String,
    secret_reference_id: String,
}

fn selection_projection(selection: &RouteGrantV2SignerSelection) -> SelectionProjection {
    match selection {
        RouteGrantV2SignerSelection::Disabled => SelectionProjection {
            state: "disabled".to_owned(),
            active_kid: String::new(),
            secret_reference_id: String::new(),
        },
        RouteGrantV2SignerSelection::Active {
            active_kid,
            secret_reference_id,
        } => SelectionProjection {
            state: "active".to_owned(),
            active_kid: active_kid.as_str().to_owned(),
            secret_reference_id: secret_reference_id.as_str().to_owned(),
        },
    }
}

fn validate_selection_projection(
    state: &str,
    active_kid: &str,
    secret_reference_id: &str,
) -> AuthorityTxResult<()> {
    match state {
        "active" => {
            parse_kid(active_kid.to_owned())?;
            parse_id(secret_reference_id.to_owned())?;
            Ok(())
        }
        "disabled" if active_kid.is_empty() && secret_reference_id.is_empty() => Ok(()),
        _ => Err(corrupt("stored Route v2 signer selection is invalid")),
    }
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored Route v2 signer identity is malformed"))
}

fn parse_kid(value: String) -> AuthorityTxResult<KeyId> {
    KeyId::new(value).ok_or_else(|| corrupt("stored Route v2 signer kid is malformed"))
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored Route v2 signer digest is malformed"))
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn optional_from_pg<T: PgBigInt>(value: Option<i64>) -> AuthorityTxResult<Option<T>> {
    value.map(from_pg).transpose()
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt("unexpected Route v2 signer changed-row count"))
    }
}

fn rejected(message: &'static str) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(ApiError::failed_precondition(message))
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

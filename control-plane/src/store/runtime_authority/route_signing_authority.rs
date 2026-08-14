//! PostgreSQL current binding for the independent Route Grant v2 signer.
//!
//! Startup remains revision-one/exact-replay only. Explicit typed commands
//! advance immutable signer and public-ring lineage under the same singleton
//! barrier held by every resolve snapshot.

use cats_api::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
    encode_route_grant_v2_public_key_ring, encode_route_grant_v2_signer_reference,
    RouteGrantV2PublicKey, RouteGrantV2PublicKeyRingArtifact, RouteGrantV2SignerReference,
    RouteGrantV2SignerSelection, MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS,
    MAX_ROUTE_GRANT_V2_TTL_SECONDS,
};
use cats_api::runtime_reconciliation::{
    key_ring_digest, Base64UrlNoPad, Epoch, Id, KeyId, LifecycleAdmission, NodeIdentityState,
    RouteGateState, RuntimeSchedulingState, Sha256Digest, UnixMillis,
};
use cats_storage::authority::AuthorityError;
use postgres::{Row, Transaction};
use sha2::{Digest as _, Sha256};

use super::gateway_identity::lock_route_v2_machine_authority_exclusive;
#[cfg(test)]
use super::gateway_identity::lock_route_v2_machine_authority_shared;
use super::pg_codec::PgBigInt;
use super::placement_policy::load_policy_unlocked;
use super::rows::database_now;
use super::rows::load_active_event_by_node_unlocked;
use super::runtime_spine::{load_placement_admission_at_in, PlacementAdmissionLoad};
use crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority;
use crate::store::agent_sessions::{
    load_identity_by_node_for_update, load_provisioned_identities_after,
    PROVISIONED_NODE_ID_PAGE_SIZE,
};
use crate::store::transaction::{
    AuthorityRequestDisposition, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{ApiError, AuthorityRequestContext, Result, Store};

pub(super) const RETENTION_MILLIS: u64 =
    (MAX_ROUTE_GRANT_V2_TTL_SECONDS + MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS) * 1_000;

/// One explicit, non-secret authority command. The caller cannot supply DB
/// time, an ACK boolean, or private bytes; all preconditions are recomputed in
/// the transaction that advances the current pointer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RouteGrantV2SigningAuthorityCommandKind {
    PublishOverlap {
        successor_ring: RouteGrantV2PublicKeyRingArtifact,
        new_secret_reference_id: Id,
    },
    SwitchActive,
    PublishNewOnly {
        successor_ring: RouteGrantV2PublicKeyRingArtifact,
    },
    Retire,
    Disable,
    Activate,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteGrantV2SigningAuthorityCommand {
    pub(crate) successor: RouteGrantV2SignerReference,
    pub(crate) kind: RouteGrantV2SigningAuthorityCommandKind,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RouteGrantV2SigningAuthorityCommandResult {
    Applied {
        signer_revision: Epoch,
        public_key_ring_version: Epoch,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteGrantV2SigningAuthorityStoreOutcome {
    Committed(RouteGrantV2SigningAuthorityCommandResult),
    PreconditionFailed,
}

/// Startup-pinned, non-secret signer facts compared on every resolve. The
/// private key is owned by `RouteGrantV2Signer` and is never copied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteGrantV2SignerBinding {
    reference: RouteGrantV2SignerReference,
    exact_reference_bytes: Vec<u8>,
    reference_sha256: Sha256Digest,
    active_public_key_spki: Option<Base64UrlNoPad>,
    ring: RouteGrantV2PublicKeyRingArtifact,
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
            ring: ring.clone(),
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

    pub(crate) fn active_kid(&self) -> Option<&KeyId> {
        match &self.reference.signer {
            RouteGrantV2SignerSelection::Disabled => None,
            RouteGrantV2SignerSelection::Active { active_kid, .. } => Some(active_kid),
        }
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

    /// Execute one bounded rotation/disable transition. This Store method is
    /// not itself an operator principal or transport; a production caller is
    /// intentionally absent until an Accepted authority can invoke it.
    #[allow(
        dead_code,
        reason = "typed G3 admin/control boundary awaiting its independent machine-auth transport"
    )]
    pub(crate) fn apply_route_grant_v2_signing_authority_command(
        &self,
        command: &RouteGrantV2SigningAuthorityCommand,
        request: &AuthorityRequestContext,
    ) -> Result<RouteGrantV2SigningAuthorityStoreOutcome> {
        validate_command(command)?;
        self.authority_request_transaction(request, |transaction| {
            let outcome = apply_command_in(transaction, command)?;
            Ok(match outcome {
                RouteGrantV2SigningAuthorityStoreOutcome::Committed(_) => {
                    AuthorityRequestDisposition::Commit(outcome)
                }
                RouteGrantV2SigningAuthorityStoreOutcome::PreconditionFailed => {
                    AuthorityRequestDisposition::Reject(outcome)
                }
            })
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

fn validate_command(command: &RouteGrantV2SigningAuthorityCommand) -> Result<()> {
    command.successor.validate().map_err(|_| {
        ApiError::invalid("Route v2 signing authority successor descriptor is invalid")
    })?;
    serde_json::to_vec(command)
        .ok()
        .filter(|bytes| !bytes.is_empty() && bytes.len() <= 65_536)
        .ok_or_else(|| ApiError::invalid("Route v2 signing authority command is invalid"))?;
    match &command.kind {
        RouteGrantV2SigningAuthorityCommandKind::PublishOverlap { successor_ring, .. }
        | RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly { successor_ring } => {
            command
                .successor
                .validate_ring(successor_ring)
                .map_err(|_| ApiError::invalid("Route v2 signing command ring is invalid"))?;
            encode_route_grant_v2_public_key_ring(successor_ring)
                .map_err(|_| ApiError::invalid("Route v2 signing command ring is invalid"))?;
        }
        _ => {}
    }
    Ok(())
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
            (SELECT count(*) FROM route_v2_signer_key_lineage),
            (SELECT count(*) FROM route_v2_public_key_ring_revisions),
            (SELECT count(*) FROM route_v2_signer_retirements)",
        &[],
    )?;
    if (0..4)
        .map(|index| row.try_get::<_, i64>(index))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .any(|count| *count != 0)
    {
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

    let ring = &binding.ring;
    match &reference.signer {
        RouteGrantV2SignerSelection::Active { active_kid, .. }
            if ring.keys.len() == 1 && ring.keys[0].kid == *active_kid => {}
        // A disabled descriptor still binds and verifies its exact public
        // ring. It owns no private-key lineage, but the public artifact may
        // intentionally retain keys while reachable routes drain.
        RouteGrantV2SignerSelection::Disabled => {}
        _ => {
            return Err(rejected(
                "initial active Route v2 ring must contain only its signer",
            ))
        }
    }
    insert_ring_revision(transaction, &reference.deployment_id, ring, committed_at)?;

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

fn apply_command_in(
    transaction: &mut Transaction<'_>,
    command: &RouteGrantV2SigningAuthorityCommand,
) -> AuthorityTxResult<RouteGrantV2SigningAuthorityStoreOutcome> {
    lock_route_v2_machine_authority_exclusive(transaction)?;
    let Some(pointer) = load_pointer(transaction, "FOR UPDATE")? else {
        return Ok(precondition_failed());
    };
    let current = load_current_signer_for_pointer(transaction, pointer.clone())?;
    if !successor_of_current(&command.successor, &current) {
        return Ok(precondition_failed());
    }
    let current_ring = &current.ring;
    let committed_at = database_now(transaction)?;

    let applied = match &command.kind {
        RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring,
            new_secret_reference_id,
        } => publish_overlap_in(
            transaction,
            &pointer,
            &current,
            current_ring,
            &command.successor,
            successor_ring,
            new_secret_reference_id,
            committed_at,
        )?,
        RouteGrantV2SigningAuthorityCommandKind::SwitchActive => switch_active_in(
            transaction,
            &pointer,
            &current,
            current_ring,
            &command.successor,
            committed_at,
        )?,
        RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly { successor_ring } => {
            publish_new_only_in(
                transaction,
                &pointer,
                &current,
                current_ring,
                &command.successor,
                successor_ring,
                committed_at,
            )?
        }
        RouteGrantV2SigningAuthorityCommandKind::Retire => retire_normal_in(
            transaction,
            &pointer,
            &current,
            current_ring,
            &command.successor,
            committed_at,
        )?,
        RouteGrantV2SigningAuthorityCommandKind::Disable => disable_in(
            transaction,
            &pointer,
            &current,
            current_ring,
            &command.successor,
            committed_at,
        )?,
        RouteGrantV2SigningAuthorityCommandKind::Activate => activate_in(
            transaction,
            &pointer,
            &current,
            current_ring,
            &command.successor,
            committed_at,
        )?,
    };
    let Some(result) = applied else {
        return Ok(precondition_failed());
    };
    Ok(RouteGrantV2SigningAuthorityStoreOutcome::Committed(result))
}

fn precondition_failed() -> RouteGrantV2SigningAuthorityStoreOutcome {
    RouteGrantV2SigningAuthorityStoreOutcome::PreconditionFailed
}

fn successor_of_current(
    successor: &RouteGrantV2SignerReference,
    current: &RouteGrantV2SignerBinding,
) -> bool {
    successor.deployment_id == current.reference.deployment_id
        && current.reference.signer_revision.get().checked_add(1)
            == Some(successor.signer_revision.get())
        && successor
            .expected_previous
            .as_ref()
            .is_some_and(|previous| {
                previous.signer_revision == current.reference.signer_revision
                    && previous.signer_reference_sha256 == current.reference_sha256
            })
}

#[allow(clippy::too_many_arguments)]
fn publish_overlap_in(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    current: &RouteGrantV2SignerBinding,
    current_ring: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2SignerReference,
    successor_ring: &RouteGrantV2PublicKeyRingArtifact,
    new_secret_reference_id: &Id,
    committed_at: UnixMillis,
) -> AuthorityTxResult<Option<RouteGrantV2SigningAuthorityCommandResult>> {
    if successor.signer != current.reference.signer
        || !ring_is_exact_successor(current_ring, successor_ring)
    {
        return Ok(None);
    }
    let new_entry = match &current.reference.signer {
        RouteGrantV2SignerSelection::Active { active_kid, .. } => {
            if current_ring.keys.len() != 1
                || current_ring.key(active_kid).is_none()
                || !load_nonretired_retirements(transaction, &pointer.deployment_id)?.is_empty()
                || successor_ring.keys.len() != 2
                || !current_ring
                    .keys
                    .iter()
                    .all(|entry| successor_ring.key(&entry.kid) == Some(entry))
            {
                return Ok(None);
            }
            let mut added = successor_ring
                .keys
                .iter()
                .filter(|entry| current_ring.key(&entry.kid).is_none());
            let Some(entry) = added.next() else {
                return Ok(None);
            };
            if added.next().is_some() {
                return Ok(None);
            }
            entry
        }
        RouteGrantV2SignerSelection::Disabled => {
            if successor_ring.keys.len() != 1 {
                return Ok(None);
            }
            if !current_ring.keys.is_empty()
                && !all_provisioned_nodes_closed_or_fenced(transaction, committed_at)?
            {
                return Ok(None);
            }
            &successor_ring.keys[0]
        }
    };
    if key_or_secret_lineage_exists(
        transaction,
        &pointer.deployment_id,
        &new_entry.kid,
        &new_entry.public_key_spki,
        new_secret_reference_id,
    )? {
        return Ok(None);
    }

    insert_signer_revision(transaction, successor, committed_at)?;
    insert_ring_revision(
        transaction,
        &pointer.deployment_id,
        successor_ring,
        committed_at,
    )?;
    insert_key_lineage(
        transaction,
        &pointer.deployment_id,
        new_entry,
        new_secret_reference_id,
        successor.signer_revision,
        committed_at,
    )?;
    update_pointer(transaction, successor)?;
    if matches!(
        current.reference.signer,
        RouteGrantV2SignerSelection::Disabled
    ) {
        mark_all_pending_retirements_ring_removed(
            transaction,
            &pointer.deployment_id,
            successor_ring.ring_version,
        )?;
    }
    Ok(Some(applied(successor)))
}

fn switch_active_in(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    current: &RouteGrantV2SignerBinding,
    current_ring: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2SignerReference,
    committed_at: UnixMillis,
) -> AuthorityTxResult<Option<RouteGrantV2SigningAuthorityCommandResult>> {
    let RouteGrantV2SignerSelection::Active {
        active_kid: old_kid,
        secret_reference_id: old_secret,
    } = &current.reference.signer
    else {
        return Ok(None);
    };
    let RouteGrantV2SignerSelection::Active {
        active_kid: new_kid,
        secret_reference_id: new_secret,
    } = &successor.signer
    else {
        return Ok(None);
    };
    if old_kid == new_kid
        || successor.public_key_ring_version != current_ring.ring_version
        || successor.public_key_ring_digest != current_ring.digest().map_err(corrupt)?
        || current_ring.keys.len() != 2
        || current_ring.key(old_kid).is_none()
        || current_ring.key(new_kid).is_none()
        || !load_nonretired_retirements(transaction, &pointer.deployment_id)?.is_empty()
        || !key_lineage_matches_active(transaction, &pointer.deployment_id, new_kid, new_secret)?
        || !all_schedulable_nodes_ack_ring(transaction, current_ring, committed_at)?
    {
        return Ok(None);
    }
    insert_signer_revision(transaction, successor, committed_at)?;
    update_pointer(transaction, successor)?;
    insert_retirement(
        transaction,
        &pointer.deployment_id,
        old_kid,
        old_secret,
        successor.signer_revision,
        committed_at,
        "normal",
    )?;
    Ok(Some(applied(successor)))
}

#[allow(clippy::too_many_arguments)]
fn publish_new_only_in(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    current: &RouteGrantV2SignerBinding,
    current_ring: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2SignerReference,
    successor_ring: &RouteGrantV2PublicKeyRingArtifact,
    committed_at: UnixMillis,
) -> AuthorityTxResult<Option<RouteGrantV2SigningAuthorityCommandResult>> {
    if successor.signer != current.reference.signer
        || !matches!(successor.signer, RouteGrantV2SignerSelection::Active { .. })
        || !ring_is_exact_successor(current_ring, successor_ring)
    {
        return Ok(None);
    }
    let retirements = load_nonretired_retirements(transaction, &pointer.deployment_id)?;
    let [retirement] = retirements.as_slice() else {
        return Ok(None);
    };
    if retirement.source != "normal"
        || retirement.state != "pending"
        || !strictly_after_retention(committed_at, retirement.last_old_issue_at)?
        || successor_ring.keys.len().saturating_add(1) != current_ring.keys.len()
        || current_ring.key(&retirement.kid).is_none()
        || successor_ring.key(&retirement.kid).is_some()
        || !successor_ring
            .keys
            .iter()
            .all(|entry| current_ring.key(&entry.kid) == Some(entry))
    {
        return Ok(None);
    }
    insert_signer_revision(transaction, successor, committed_at)?;
    insert_ring_revision(
        transaction,
        &pointer.deployment_id,
        successor_ring,
        committed_at,
    )?;
    update_pointer(transaction, successor)?;
    mark_retirement_ring_removed(
        transaction,
        &pointer.deployment_id,
        &retirement.kid,
        successor_ring.ring_version,
    )?;
    Ok(Some(applied(successor)))
}

fn retire_normal_in(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    current: &RouteGrantV2SignerBinding,
    current_ring: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2SignerReference,
    committed_at: UnixMillis,
) -> AuthorityTxResult<Option<RouteGrantV2SigningAuthorityCommandResult>> {
    if successor.signer != current.reference.signer
        || successor.public_key_ring_version != current_ring.ring_version
        || successor.public_key_ring_digest != current_ring.digest().map_err(corrupt)?
    {
        return Ok(None);
    }
    let retirements = load_nonretired_retirements(transaction, &pointer.deployment_id)?;
    let [retirement] = retirements.as_slice() else {
        return Ok(None);
    };
    if retirement.source != "normal"
        || retirement.state != "ring_removed"
        || current_ring.key(&retirement.kid).is_some()
        || !strictly_after_retention(committed_at, retirement.last_old_issue_at)?
        || !all_schedulable_nodes_ack_ring(transaction, current_ring, committed_at)?
    {
        return Ok(None);
    }
    insert_signer_revision(transaction, successor, committed_at)?;
    update_pointer(transaction, successor)?;
    retire_key(
        transaction,
        &pointer.deployment_id,
        retirement,
        successor.signer_revision,
        committed_at,
    )?;
    Ok(Some(applied(successor)))
}

fn disable_in(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    current: &RouteGrantV2SignerBinding,
    current_ring: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2SignerReference,
    committed_at: UnixMillis,
) -> AuthorityTxResult<Option<RouteGrantV2SigningAuthorityCommandResult>> {
    let RouteGrantV2SignerSelection::Active { .. } = &current.reference.signer else {
        return Ok(None);
    };
    if successor.signer != RouteGrantV2SignerSelection::Disabled
        || successor.public_key_ring_version != current_ring.ring_version
        || successor.public_key_ring_digest != current_ring.digest().map_err(corrupt)?
    {
        return Ok(None);
    }
    let mut new_retirements = Vec::new();
    for entry in &current_ring.keys {
        let Some(secret_reference_id) = active_key_lineage_secret(
            transaction,
            &pointer.deployment_id,
            &entry.kid,
            &entry.public_key_spki,
        )?
        else {
            return Ok(None);
        };
        if let Some(existing) = load_retirement(transaction, &pointer.deployment_id, &entry.kid)? {
            if existing.secret_reference_id != secret_reference_id {
                return Err(corrupt("Route v2 retirement/secret lineage mismatch"));
            }
        } else {
            new_retirements.push((entry.kid.clone(), secret_reference_id));
        }
    }
    insert_signer_revision(transaction, successor, committed_at)?;
    update_pointer(transaction, successor)?;
    for (kid, secret_reference_id) in new_retirements {
        insert_retirement(
            transaction,
            &pointer.deployment_id,
            &kid,
            &secret_reference_id,
            successor.signer_revision,
            committed_at,
            "emergency",
        )?;
    }
    Ok(Some(applied(successor)))
}

fn activate_in(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    current: &RouteGrantV2SignerBinding,
    current_ring: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2SignerReference,
    committed_at: UnixMillis,
) -> AuthorityTxResult<Option<RouteGrantV2SigningAuthorityCommandResult>> {
    let RouteGrantV2SignerSelection::Active {
        active_kid,
        secret_reference_id,
    } = &successor.signer
    else {
        return Ok(None);
    };
    if current.reference.signer != RouteGrantV2SignerSelection::Disabled
        || successor.public_key_ring_version != current_ring.ring_version
        || successor.public_key_ring_digest != current_ring.digest().map_err(corrupt)?
        || current_ring.keys.len() != 1
        || current_ring.key(active_kid).is_none()
        || !key_lineage_matches_active(
            transaction,
            &pointer.deployment_id,
            active_kid,
            secret_reference_id,
        )?
        || load_retirement(transaction, &pointer.deployment_id, active_kid)?.is_some()
        || !all_provisioned_nodes_closed_or_fenced_and_ack_ring(
            transaction,
            current_ring,
            committed_at,
        )?
    {
        return Ok(None);
    }
    let retirements = load_nonretired_retirements(transaction, &pointer.deployment_id)?;
    if retirements
        .iter()
        .any(|retirement| retirement.state != "ring_removed")
    {
        return Ok(None);
    }
    insert_signer_revision(transaction, successor, committed_at)?;
    update_pointer(transaction, successor)?;
    for retirement in &retirements {
        retire_key(
            transaction,
            &pointer.deployment_id,
            retirement,
            successor.signer_revision,
            committed_at,
        )?;
    }
    Ok(Some(applied(successor)))
}

fn applied(successor: &RouteGrantV2SignerReference) -> RouteGrantV2SigningAuthorityCommandResult {
    RouteGrantV2SigningAuthorityCommandResult::Applied {
        signer_revision: successor.signer_revision,
        public_key_ring_version: successor.public_key_ring_version,
    }
}

fn ring_is_exact_successor(
    current: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2PublicKeyRingArtifact,
) -> bool {
    current.ring_version.get().checked_add(1) == Some(successor.ring_version.get())
        && successor
            .expected_previous
            .as_ref()
            .is_some_and(|previous| {
                previous.ring_version == current.ring_version
                    && current
                        .digest()
                        .is_ok_and(|digest| previous.key_ring_digest == digest)
            })
}

fn insert_signer_revision(
    transaction: &mut Transaction<'_>,
    reference: &RouteGrantV2SignerReference,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let exact = encode_route_grant_v2_signer_reference(reference).map_err(corrupt)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(&exact).into());
    let selection = selection_projection(&reference.signer);
    let previous = reference
        .expected_previous
        .as_ref()
        .ok_or_else(|| corrupt("successor signer omitted previous pointer"))?;
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_signer_revisions (
            deployment_id, signer_revision, signer_reference_sha256,
            signer_reference_bytes, expected_previous_signer_revision,
            expected_previous_signer_reference_sha256, signer_state,
            active_kid, public_key_ring_version, public_key_ring_digest,
            secret_reference_id, committed_at_unix_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        &[
            &reference.deployment_id.as_str(),
            &reference.signer_revision.to_pg().map_err(corrupt)?,
            &digest.as_str(),
            &exact,
            &previous.signer_revision.to_pg().map_err(corrupt)?,
            &previous.signer_reference_sha256.as_str(),
            &selection.state,
            &selection.active_kid,
            &reference.public_key_ring_version.to_pg().map_err(corrupt)?,
            &reference.public_key_ring_digest.as_str(),
            &selection.secret_reference_id,
            &committed_at.to_pg().map_err(corrupt)?,
        ],
    )?)
}

fn update_pointer(
    transaction: &mut Transaction<'_>,
    reference: &RouteGrantV2SignerReference,
) -> AuthorityTxResult<()> {
    let exact = encode_route_grant_v2_signer_reference(reference).map_err(corrupt)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(exact).into());
    let selection = selection_projection(&reference.signer);
    exactly_one(transaction.execute(
        "UPDATE route_v2_signing_authority SET
            current_signer_revision=$2,
            current_signer_reference_sha256=$3,
            signer_state=$4, active_kid=$5,
            public_key_ring_version=$6, public_key_ring_digest=$7,
            secret_reference_id=$8
          WHERE singleton=TRUE AND deployment_id=$1",
        &[
            &reference.deployment_id.as_str(),
            &reference.signer_revision.to_pg().map_err(corrupt)?,
            &digest.as_str(),
            &selection.state,
            &selection.active_kid,
            &reference.public_key_ring_version.to_pg().map_err(corrupt)?,
            &reference.public_key_ring_digest.as_str(),
            &selection.secret_reference_id,
        ],
    )?)
}

fn insert_ring_revision(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    ring: &RouteGrantV2PublicKeyRingArtifact,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    let exact = encode_route_grant_v2_public_key_ring(ring).map_err(corrupt)?;
    let digest = ring.digest().map_err(corrupt)?;
    let previous_version = ring
        .expected_previous
        .as_ref()
        .map(|previous| previous.ring_version.to_pg().map_err(corrupt))
        .transpose()?;
    let previous_digest = ring
        .expected_previous
        .as_ref()
        .map(|previous| previous.key_ring_digest.as_str());
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_public_key_ring_revisions (
            deployment_id, ring_version, key_ring_digest, exact_bytes,
            expected_previous_ring_version, expected_previous_key_ring_digest,
            published_at_unix_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &deployment_id.as_str(),
            &ring.ring_version.to_pg().map_err(corrupt)?,
            &digest.as_str(),
            &exact,
            &previous_version,
            &previous_digest,
            &committed_at.to_pg().map_err(corrupt)?,
        ],
    )?)
}

fn load_ring_revision(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    ring_version: Epoch,
) -> AuthorityTxResult<RouteGrantV2PublicKeyRingArtifact> {
    let row = transaction
        .query_opt(
            "SELECT deployment_id, ring_version, key_ring_digest, exact_bytes,
                    expected_previous_ring_version, expected_previous_key_ring_digest,
                    published_at_unix_ms
               FROM route_v2_public_key_ring_revisions
              WHERE deployment_id=$1 AND ring_version=$2",
            &[
                &deployment_id.as_str(),
                &ring_version.to_pg().map_err(corrupt)?,
            ],
        )?
        .ok_or_else(|| corrupt("current Route v2 public ring revision is absent"))?;
    let stored_deployment = parse_id(row.try_get("deployment_id")?)?;
    let stored_version: Epoch = from_pg(row.try_get("ring_version")?)?;
    let stored_digest = parse_digest(row.try_get("key_ring_digest")?)?;
    let exact: Vec<u8> = row.try_get("exact_bytes")?;
    let ring = decode_route_grant_v2_public_key_ring(&exact)
        .map_err(|_| corrupt("stored Route v2 public ring bytes are invalid"))?;
    let previous_version = optional_from_pg(row.try_get("expected_previous_ring_version")?)?;
    let previous_digest = row
        .try_get::<_, Option<String>>("expected_previous_key_ring_digest")?
        .map(parse_digest)
        .transpose()?;
    let _: UnixMillis = from_pg(row.try_get("published_at_unix_ms")?)?;
    let projected_previous = match (previous_version, previous_digest) {
        (Some(ring_version), Some(key_ring_digest)) => Some(
            cats_api::route_grant_v2::RouteGrantV2PublicKeyRingExpectedPrevious {
                ring_version,
                key_ring_digest,
            },
        ),
        (None, None) => None,
        _ => return Err(corrupt("stored Route v2 ring previous pointer is partial")),
    };
    if stored_deployment != *deployment_id
        || stored_version != ring_version
        || ring.ring_version != stored_version
        || ring.expected_previous != projected_previous
        || ring.digest().map_err(corrupt)? != stored_digest
    {
        return Err(corrupt("stored Route v2 ring projection mismatch"));
    }
    Ok(ring)
}

fn insert_key_lineage(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    entry: &cats_api::route_grant_v2::RouteGrantV2PublicKeyEntry,
    secret_reference_id: &Id,
    first_signer_revision: Epoch,
    committed_at: UnixMillis,
) -> AuthorityTxResult<()> {
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_signer_key_lineage (
            kid, deployment_id, public_key_spki, secret_reference_id,
            first_signer_revision, state, first_committed_at_unix_ms,
            retired_at_unix_ms
         ) VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL)",
        &[
            &entry.kid.as_str(),
            &deployment_id.as_str(),
            &entry.public_key_spki.as_str(),
            &secret_reference_id.as_str(),
            &first_signer_revision.to_pg().map_err(corrupt)?,
            &committed_at.to_pg().map_err(corrupt)?,
        ],
    )?)
}

fn validate_ring_key_lineage(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    ring: &RouteGrantV2PublicKeyRingArtifact,
) -> AuthorityTxResult<()> {
    for entry in &ring.keys {
        let row = transaction
            .query_opt(
                "SELECT deployment_id, public_key_spki, state, retired_at_unix_ms
                   FROM route_v2_signer_key_lineage WHERE kid=$1",
                &[&entry.kid.as_str()],
            )?
            .ok_or_else(|| corrupt("published Route v2 ring key has no permanent lineage"))?;
        let stored_deployment = parse_id(row.try_get("deployment_id")?)?;
        let stored_spki = Base64UrlNoPad::new(row.try_get::<_, String>("public_key_spki")?)
            .ok_or_else(|| corrupt("stored Route v2 key SPKI is malformed"))?;
        let state: String = row.try_get("state")?;
        let retired_at: Option<UnixMillis> = optional_from_pg(row.try_get("retired_at_unix_ms")?)?;
        if stored_deployment != *deployment_id
            || stored_spki != entry.public_key_spki
            || state != "active"
            || retired_at.is_some()
        {
            return Err(corrupt("published Route v2 ring/key lineage mismatch"));
        }
    }
    Ok(())
}

fn key_or_secret_lineage_exists(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    kid: &KeyId,
    public_key_spki: &Base64UrlNoPad,
    secret_reference_id: &Id,
) -> AuthorityTxResult<bool> {
    let count: i64 = transaction
        .query_one(
            "SELECT count(*) FROM route_v2_signer_key_lineage
              WHERE deployment_id=$1 OR kid=$2 OR public_key_spki=$3
                 OR secret_reference_id=$4",
            &[
                &deployment_id.as_str(),
                &kid.as_str(),
                &public_key_spki.as_str(),
                &secret_reference_id.as_str(),
            ],
        )?
        .try_get(0)?;
    // Existing keys in this deployment are expected; only the candidate kid,
    // SPKI or secret reference must be globally fresh.
    if count == 0 {
        return Ok(false);
    }
    let conflicting: bool = transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM route_v2_signer_key_lineage
                 WHERE kid=$1 OR public_key_spki=$2 OR secret_reference_id=$3)",
            &[
                &kid.as_str(),
                &public_key_spki.as_str(),
                &secret_reference_id.as_str(),
            ],
        )?
        .try_get(0)?;
    Ok(conflicting)
}

fn key_lineage_matches_active(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    kid: &KeyId,
    secret_reference_id: &Id,
) -> AuthorityTxResult<bool> {
    let Some(row) = transaction.query_opt(
        "SELECT deployment_id, secret_reference_id, state, retired_at_unix_ms
           FROM route_v2_signer_key_lineage WHERE kid=$1",
        &[&kid.as_str()],
    )?
    else {
        return Ok(false);
    };
    Ok(parse_id(row.try_get("deployment_id")?)? == *deployment_id
        && parse_id(row.try_get("secret_reference_id")?)? == *secret_reference_id
        && row.try_get::<_, String>("state")? == "active"
        && optional_from_pg::<UnixMillis>(row.try_get("retired_at_unix_ms")?)?.is_none())
}

fn active_key_lineage_secret(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    kid: &KeyId,
    public_key_spki: &Base64UrlNoPad,
) -> AuthorityTxResult<Option<Id>> {
    let Some(row) = transaction.query_opt(
        "SELECT deployment_id, public_key_spki, secret_reference_id,
                state, retired_at_unix_ms
           FROM route_v2_signer_key_lineage WHERE kid=$1",
        &[&kid.as_str()],
    )?
    else {
        return Ok(None);
    };
    let stored_deployment = parse_id(row.try_get("deployment_id")?)?;
    let stored_spki = Base64UrlNoPad::new(row.try_get::<_, String>("public_key_spki")?)
        .ok_or_else(|| corrupt("stored Route v2 key SPKI is malformed"))?;
    let secret_reference_id = parse_id(row.try_get("secret_reference_id")?)?;
    let state: String = row.try_get("state")?;
    let retired_at: Option<UnixMillis> = optional_from_pg(row.try_get("retired_at_unix_ms")?)?;
    if stored_deployment != *deployment_id
        || stored_spki != *public_key_spki
        || state != "active"
        || retired_at.is_some()
    {
        return Ok(None);
    }
    Ok(Some(secret_reference_id))
}

#[derive(Debug, Clone)]
struct RetirementRow {
    kid: KeyId,
    secret_reference_id: Id,
    last_old_issue_at: UnixMillis,
    source: String,
    state: String,
}

fn load_nonretired_retirements(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
) -> AuthorityTxResult<Vec<RetirementRow>> {
    transaction
        .query(
            "SELECT kid, secret_reference_id, last_old_issue_at_unix_ms,
                    source, state, ring_removed_version,
                    retired_signer_revision, retired_at_unix_ms
               FROM route_v2_signer_retirements
              WHERE deployment_id=$1 AND state <> 'retired'
              ORDER BY kid COLLATE \"C\"",
            &[&deployment_id.as_str()],
        )?
        .iter()
        .map(decode_retirement)
        .collect()
}

fn load_retirement(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    kid: &KeyId,
) -> AuthorityTxResult<Option<RetirementRow>> {
    transaction
        .query_opt(
            "SELECT kid, secret_reference_id, last_old_issue_at_unix_ms,
                    source, state, ring_removed_version,
                    retired_signer_revision, retired_at_unix_ms
               FROM route_v2_signer_retirements
              WHERE deployment_id=$1 AND kid=$2",
            &[&deployment_id.as_str(), &kid.as_str()],
        )?
        .as_ref()
        .map(decode_retirement)
        .transpose()
}

fn decode_retirement(row: &Row) -> AuthorityTxResult<RetirementRow> {
    let state: String = row.try_get("state")?;
    let source: String = row.try_get("source")?;
    if !matches!(state.as_str(), "pending" | "ring_removed" | "retired")
        || !matches!(source.as_str(), "normal" | "emergency")
    {
        return Err(corrupt("stored Route v2 retirement state is invalid"));
    }
    let removed: Option<Epoch> = optional_from_pg(row.try_get("ring_removed_version")?)?;
    let retired_revision: Option<Epoch> =
        optional_from_pg(row.try_get("retired_signer_revision")?)?;
    let retired_at: Option<UnixMillis> = optional_from_pg(row.try_get("retired_at_unix_ms")?)?;
    if !matches!(
        (state.as_str(), removed, retired_revision, retired_at),
        ("pending", None, None, None)
            | ("ring_removed", Some(_), None, None)
            | ("retired", Some(_), Some(_), Some(_))
    ) {
        return Err(corrupt("stored Route v2 retirement projection is invalid"));
    }
    Ok(RetirementRow {
        kid: parse_kid(row.try_get("kid")?)?,
        secret_reference_id: parse_id(row.try_get("secret_reference_id")?)?,
        last_old_issue_at: from_pg(row.try_get("last_old_issue_at_unix_ms")?)?,
        source,
        state,
    })
}

fn insert_retirement(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    kid: &KeyId,
    secret_reference_id: &Id,
    signer_revision: Epoch,
    last_old_issue_at: UnixMillis,
    source: &'static str,
) -> AuthorityTxResult<()> {
    exactly_one(transaction.execute(
        "INSERT INTO route_v2_signer_retirements (
            deployment_id, kid, secret_reference_id,
            retirement_signer_revision, last_old_issue_at_unix_ms,
            source, state, ring_removed_version,
            retired_signer_revision, retired_at_unix_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, 'pending', NULL, NULL, NULL)",
        &[
            &deployment_id.as_str(),
            &kid.as_str(),
            &secret_reference_id.as_str(),
            &signer_revision.to_pg().map_err(corrupt)?,
            &last_old_issue_at.to_pg().map_err(corrupt)?,
            &source,
        ],
    )?)
}

fn mark_retirement_ring_removed(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    kid: &KeyId,
    ring_version: Epoch,
) -> AuthorityTxResult<()> {
    exactly_one(transaction.execute(
        "UPDATE route_v2_signer_retirements
            SET state='ring_removed', ring_removed_version=$3
          WHERE deployment_id=$1 AND kid=$2 AND state='pending'
            AND ring_removed_version IS NULL
            AND retired_signer_revision IS NULL AND retired_at_unix_ms IS NULL",
        &[
            &deployment_id.as_str(),
            &kid.as_str(),
            &ring_version.to_pg().map_err(corrupt)?,
        ],
    )?)
}

fn mark_all_pending_retirements_ring_removed(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    ring_version: Epoch,
) -> AuthorityTxResult<()> {
    let expected: i64 = transaction
        .query_one(
            "SELECT count(*) FROM route_v2_signer_retirements
              WHERE deployment_id=$1 AND state='pending'",
            &[&deployment_id.as_str()],
        )?
        .try_get(0)?;
    let changed = transaction.execute(
        "UPDATE route_v2_signer_retirements
            SET state='ring_removed', ring_removed_version=$2
          WHERE deployment_id=$1 AND state='pending'
            AND ring_removed_version IS NULL
            AND retired_signer_revision IS NULL AND retired_at_unix_ms IS NULL",
        &[
            &deployment_id.as_str(),
            &ring_version.to_pg().map_err(corrupt)?,
        ],
    )?;
    if changed != u64::try_from(expected).map_err(corrupt)? {
        return Err(corrupt("Route v2 emergency retirement set changed"));
    }
    Ok(())
}

pub(super) fn strictly_after_retention(
    now: UnixMillis,
    last_old_issue_at: UnixMillis,
) -> AuthorityTxResult<bool> {
    let deadline = last_old_issue_at
        .get()
        .checked_add(RETENTION_MILLIS)
        .ok_or_else(|| corrupt("Route v2 retirement deadline overflow"))?;
    Ok(now.get() > deadline)
}

fn retire_key(
    transaction: &mut Transaction<'_>,
    deployment_id: &Id,
    retirement: &RetirementRow,
    retired_signer_revision: Epoch,
    retired_at: UnixMillis,
) -> AuthorityTxResult<()> {
    exactly_one(transaction.execute(
        "UPDATE route_v2_signer_key_lineage
            SET state='retired', retired_at_unix_ms=$3
          WHERE kid=$1 AND deployment_id=$2 AND state='active'
            AND secret_reference_id=$4 AND retired_at_unix_ms IS NULL",
        &[
            &retirement.kid.as_str(),
            &deployment_id.as_str(),
            &retired_at.to_pg().map_err(corrupt)?,
            &retirement.secret_reference_id.as_str(),
        ],
    )?)?;
    exactly_one(transaction.execute(
        "UPDATE route_v2_signer_retirements
            SET state='retired', retired_signer_revision=$3,
                retired_at_unix_ms=$4
          WHERE deployment_id=$1 AND kid=$2 AND state='ring_removed'
            AND ring_removed_version IS NOT NULL
            AND retired_signer_revision IS NULL AND retired_at_unix_ms IS NULL",
        &[
            &deployment_id.as_str(),
            &retirement.kid.as_str(),
            &retired_signer_revision.to_pg().map_err(corrupt)?,
            &retired_at.to_pg().map_err(corrupt)?,
        ],
    )?)?;
    Ok(())
}

fn lock_current_provisioned_fleet(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<
    Vec<(
        cats_api::runtime_reconciliation::NodeIdentity,
        cats_api::runtime_reconciliation::NodePlacementPolicy,
    )>,
> {
    // The singleton Route writer lock is always acquired first. These SHARE
    // locks then close both a newly provisioned phantom and policy/session/
    // full-observation drift until the signer pointer commits.
    transaction.batch_execute(
        "LOCK TABLE node_identities, runtime_node_placement_policies,
                    current_agent_sessions, runtime_desired_read_states,
                    runtime_observation_receive_states,
                    runtime_admission_inventory_states,
                    runtime_current_cat_observations,
                    desired_runtime_specs, host_fence_events
             IN SHARE MODE",
    )?;
    let mut identities = Vec::new();
    let mut after = None;
    loop {
        let page = load_provisioned_identities_after(transaction, after.as_ref())?;
        if page.is_empty() {
            break;
        }
        let full = page.len() == PROVISIONED_NODE_ID_PAGE_SIZE;
        after = page.last().map(|identity| identity.node_id.clone());
        identities.extend(page);
        if !full {
            break;
        }
    }
    let mut fleet = Vec::with_capacity(identities.len());
    for identity in identities {
        let locked = load_identity_by_node_for_update(transaction, &identity.node_id)?
            .ok_or_else(|| corrupt("provisioned Route v2 Node disappeared"))?;
        let policy = load_policy_unlocked(transaction, &identity.node_id)?
            .ok_or_else(|| corrupt("provisioned Route v2 Node has no policy"))?;
        if locked != identity
            || identity.state != NodeIdentityState::Provisioned
            || policy.node_id != identity.node_id
        {
            return Err(corrupt("Route v2 fleet identity/policy projection changed"));
        }
        fleet.push((identity, policy));
    }
    Ok(fleet)
}

fn all_schedulable_nodes_ack_ring(
    transaction: &mut Transaction<'_>,
    ring: &RouteGrantV2PublicKeyRingArtifact,
    now: UnixMillis,
) -> AuthorityTxResult<bool> {
    let expected_digest = ring.digest().map_err(corrupt)?;
    let expected_kids = ring
        .keys
        .iter()
        .map(|entry| entry.kid.clone())
        .collect::<Vec<_>>();
    for (identity, policy) in lock_current_provisioned_fleet(transaction)? {
        if policy.scheduling_state != RuntimeSchedulingState::Schedulable {
            continue;
        }
        if load_active_event_by_node_unlocked(transaction, &identity.node_id)?.is_some() {
            return Ok(false);
        }
        let PlacementAdmissionLoad::Accepted(admission) = load_placement_admission_at_in(
            transaction,
            &identity.node_id,
            &policy.capabilities.guest_config_digest,
            now,
        )?
        else {
            return Ok(false);
        };
        let observation = &admission.full_inventory_observation;
        if admission.node_identity != identity
            || observation.key_ring_version != Some(ring.ring_version)
            || observation.key_ring_digest.as_ref() != Some(&expected_digest)
            || observation.loaded_kids != expected_kids
            || key_ring_digest(ring.ring_version, &observation.loaded_kids).map_err(corrupt)?
                != expected_digest
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn all_provisioned_nodes_closed_or_fenced(
    transaction: &mut Transaction<'_>,
    now: UnixMillis,
) -> AuthorityTxResult<bool> {
    for (identity, policy) in lock_current_provisioned_fleet(transaction)? {
        if load_active_event_by_node_unlocked(transaction, &identity.node_id)?.is_some() {
            continue;
        }
        let PlacementAdmissionLoad::Accepted(admission) = load_placement_admission_at_in(
            transaction,
            &identity.node_id,
            &policy.capabilities.guest_config_digest,
            now,
        )?
        else {
            return Ok(false);
        };
        if admission.node_identity != identity
            || !admission.full_inventory_observation.residue.is_empty()
            || admission
                .full_inventory_observation
                .runtimes
                .iter()
                .any(|runtime| {
                    runtime.lifecycle_admission != LifecycleAdmission::Closed
                        || runtime.platform_guards != 0
                        || runtime.routes.iter().any(|route| {
                            route.gate != RouteGateState::Closed
                                || route.active_guards != 0
                                || route.cancellation_pending
                        })
                })
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn all_provisioned_nodes_closed_or_fenced_and_ack_ring(
    transaction: &mut Transaction<'_>,
    ring: &RouteGrantV2PublicKeyRingArtifact,
    now: UnixMillis,
) -> AuthorityTxResult<bool> {
    let expected_digest = ring.digest().map_err(corrupt)?;
    let expected_kids = ring
        .keys
        .iter()
        .map(|entry| entry.kid.clone())
        .collect::<Vec<_>>();
    for (identity, policy) in lock_current_provisioned_fleet(transaction)? {
        if load_active_event_by_node_unlocked(transaction, &identity.node_id)?.is_some() {
            continue;
        }
        let PlacementAdmissionLoad::Accepted(admission) = load_placement_admission_at_in(
            transaction,
            &identity.node_id,
            &policy.capabilities.guest_config_digest,
            now,
        )?
        else {
            return Ok(false);
        };
        let observation = &admission.full_inventory_observation;
        if admission.node_identity != identity
            || observation.key_ring_version != Some(ring.ring_version)
            || observation.key_ring_digest.as_ref() != Some(&expected_digest)
            || observation.loaded_kids != expected_kids
            || key_ring_digest(ring.ring_version, &observation.loaded_kids).map_err(corrupt)?
                != expected_digest
            || !observation.residue.is_empty()
            || observation.runtimes.iter().any(|runtime| {
                runtime.lifecycle_admission != LifecycleAdmission::Closed
                    || runtime.platform_guards != 0
                    || runtime.routes.iter().any(|route| {
                        route.gate != RouteGateState::Closed
                            || route.active_guards != 0
                            || route.cancellation_pending
                    })
            })
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A23 holds the shared Route machine-authority barrier before invoking this
/// helper. Becoming schedulable is denied unless the same current full,
/// session-bound inventory ACKs the exact published ring.
pub(super) fn node_acks_current_published_ring_in(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    active_guest_digest: &Sha256Digest,
) -> AuthorityTxResult<bool> {
    let Some(current) = load_current_signer(transaction, "")? else {
        return Ok(false);
    };
    if !matches!(
        current.reference.signer,
        RouteGrantV2SignerSelection::Active { .. }
    ) {
        return Ok(false);
    }
    let ring = &current.ring;
    let now = database_now(transaction)?;
    let PlacementAdmissionLoad::Accepted(admission) =
        load_placement_admission_at_in(transaction, node_id, active_guest_digest, now)?
    else {
        return Ok(false);
    };
    let expected_kids = ring
        .keys
        .iter()
        .map(|entry| entry.kid.clone())
        .collect::<Vec<_>>();
    let expected_digest = ring.digest().map_err(corrupt)?;
    Ok(admission.node_identity.node_id == *node_id
        && admission.full_inventory_observation.key_ring_version == Some(ring.ring_version)
        && admission
            .full_inventory_observation
            .key_ring_digest
            .as_ref()
            == Some(&expected_digest)
        && admission.full_inventory_observation.loaded_kids == expected_kids
        && key_ring_digest(
            ring.ring_version,
            &admission.full_inventory_observation.loaded_kids,
        )
        .map_err(corrupt)?
            == expected_digest)
}

pub(super) fn load_current_signer(
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

    let ring = load_ring_revision(
        transaction,
        &pointer.deployment_id,
        pointer.public_key_ring_version,
    )?;
    reference
        .validate_ring(&ring)
        .map_err(|_| corrupt("current signer does not bind the persisted public ring"))?;
    // The frozen initial-install contract permits a disabled revision-one
    // descriptor to bind a public-only ring without inventing a private
    // secret lineage. Every active or successor revision must bind every
    // published key to the permanent rotation lineage.
    if pointer.signer_state == "disabled" && pointer.signer_revision.get() == 1 {
        let count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM route_v2_signer_key_lineage
                  WHERE deployment_id=$1",
                &[&pointer.deployment_id.as_str()],
            )?
            .try_get(0)?;
        if count != 0 {
            return Err(corrupt(
                "initial disabled Route v2 signer has unexpected key lineage",
            ));
        }
    } else {
        validate_ring_key_lineage(transaction, &pointer.deployment_id, &ring)?;
    }
    let active_public_key_spki = validate_current_key_lineage(transaction, &pointer, &reference)?;
    Ok(RouteGrantV2SignerBinding {
        reference,
        exact_reference_bytes,
        reference_sha256: computed_digest,
        active_public_key_spki,
        ring,
    })
}

fn validate_current_key_lineage(
    transaction: &mut Transaction<'_>,
    pointer: &RouteV2SignerPointer,
    reference: &RouteGrantV2SignerReference,
) -> AuthorityTxResult<Option<Base64UrlNoPad>> {
    let RouteGrantV2SignerSelection::Active {
        active_kid,
        secret_reference_id,
    } = &reference.signer
    else {
        return Ok(None);
    };
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

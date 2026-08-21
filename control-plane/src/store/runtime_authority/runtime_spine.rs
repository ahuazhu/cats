//! PostgreSQL persistence for session-bound runtime inventory telemetry.
//!
//! This module has no lifecycle-intent or Operation-settlement path. It
//! authenticates the current AgentSession, accepts one monotonically ordered
//! telemetry stream, retains one full physical-inventory attestation, and
//! maintains a bounded per-Cat read model. Full and partial reports are
//! observations only: neither can create, update, terminalize, supersede, or
//! reopen a lifecycle Operation.

use std::collections::BTreeSet;

use cats_api::agent_registration::{AuthenticatedNodeCredential, AGENT_SESSION_LEASE_MS};
use cats_api::runtime_inventory::{
    decode_runtime_inventory_acceptance, decode_runtime_inventory_report,
    encode_runtime_inventory_acceptance, encode_runtime_inventory_report,
    validate_observed_cat_runtime_telemetry, ObservedCatRuntimeTelemetry,
    RuntimeInventoryAcceptance, RuntimeInventoryAcceptanceKind, RuntimeInventoryAttestation,
    RuntimeInventoryBody, RuntimeInventoryErrorDetail, RuntimeInventoryReport,
};
use cats_api::runtime_reconciliation::{
    AgentSession, ContractVersion, CredentialBinding, Epoch, Id, NodeIdentity, NodeIdentityState,
    RandomId128, Sequence, SessionBinding, UnixMillis,
};
use postgres::{Row, Transaction};

use super::pg_codec::PgBigInt;
use super::rows::database_now;
use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_credential_for_update,
    load_identity_by_credential_unlocked, lock_exact_credential_lineage,
    renew_current_session_deadline, CredentialLineageState,
};
use crate::store::transaction::{
    AuthorityRequestDisposition, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{AuthorityRequestContext, Result, Store};

pub(crate) const PLACEMENT_INVENTORY_MAX_AGE_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeInventoryOutcome<T> {
    Accepted(T),
    Rejected(RuntimeInventoryErrorDetail),
}

fn request_disposition<T>(
    outcome: RuntimeInventoryOutcome<T>,
) -> AuthorityRequestDisposition<RuntimeInventoryOutcome<T>> {
    match outcome {
        accepted @ RuntimeInventoryOutcome::Accepted(_) => {
            AuthorityRequestDisposition::Commit(accepted)
        }
        rejected @ RuntimeInventoryOutcome::Rejected(_) => {
            AuthorityRequestDisposition::Reject(rejected)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeInventoryReceiveState {
    report: RuntimeInventoryReport,
    acceptance: RuntimeInventoryAcceptance,
}

/// The latest accepted full physical inventory for one current AgentSession.
///
/// It contains no assigned set and grants no lifecycle, route, volume,
/// settlement, or cleanup authority. A caller consuming it as one narrow
/// admission input must revalidate the current session and its own domain
/// facts in the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeFullInventoryState {
    pub(super) attestation: RuntimeInventoryAttestation,
    pub(super) full_report: RuntimeInventoryReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeTelemetrySourceKind {
    Full,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CurrentCatTelemetry {
    pub(super) telemetry: ObservedCatRuntimeTelemetry,
    pub(super) session: SessionBinding,
    pub(super) inventory_epoch: Epoch,
    pub(super) source_report_id: RandomId128,
    pub(super) sequence: Sequence,
    pub(super) accepted_at_unix_ms: UnixMillis,
    pub(super) source_kind: RuntimeTelemetrySourceKind,
}

fn resolve_runtime_node_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
) -> AuthorityTxResult<Option<Id>> {
    let Some(identity) =
        load_identity_by_credential_unlocked(transaction, authenticated.credential_id())?
    else {
        return Ok(None);
    };
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || !matches!(
            identity.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
    {
        return Ok(None);
    }
    Ok(Some(identity.node_id))
}

impl Store {
    /// Resolves a verified proof to its eligible Node before the HTTP layer
    /// selects the per-Node in-flight admission key. The mutation transaction
    /// locks and revalidates the same identity and credential lineage.
    pub(crate) fn resolve_runtime_node(
        &self,
        authenticated: &AuthenticatedNodeCredential,
    ) -> Result<Option<Id>> {
        self.authority_read_snapshot(|transaction| {
            resolve_runtime_node_in(transaction, authenticated)
        })
    }

    pub(crate) fn resolve_runtime_node_for_request(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request_context: &AuthorityRequestContext,
    ) -> Result<Option<Id>> {
        self.authority_request_locking_read_snapshot(request_context, |transaction| {
            resolve_runtime_node_in(transaction, authenticated)
        })
    }

    #[cfg(test)]
    pub(crate) fn runtime_accept_inventory(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        report: &RuntimeInventoryReport,
    ) -> Result<RuntimeInventoryOutcome<RuntimeInventoryAcceptance>> {
        if encode_runtime_inventory_report(report).is_err() {
            return Ok(rejected(RuntimeInventoryErrorDetail::MalformedPayload));
        }
        self.authority_transaction(|transaction| {
            accept_runtime_inventory_in(transaction, authenticated, report)
        })
    }

    pub(crate) fn runtime_accept_inventory_for_request(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        report: &RuntimeInventoryReport,
        request_context: &AuthorityRequestContext,
    ) -> Result<RuntimeInventoryOutcome<RuntimeInventoryAcceptance>> {
        if encode_runtime_inventory_report(report).is_err() {
            return Ok(rejected(RuntimeInventoryErrorDetail::MalformedPayload));
        }
        self.authority_request_transaction(request_context, |transaction| {
            accept_runtime_inventory_in(transaction, authenticated, report).map(request_disposition)
        })
    }

    #[cfg(test)]
    pub(super) fn load_current_full_inventory(
        &self,
        node_id: &Id,
    ) -> Result<Option<RuntimeFullInventoryState>> {
        self.authority_read_snapshot(|transaction| {
            load_runtime_full_inventory_unlocked(transaction, node_id)
        })
    }

    #[cfg(test)]
    pub(super) fn load_current_cat_telemetry(
        &self,
        node_id: &Id,
        cat_id: &Id,
    ) -> Result<Option<CurrentCatTelemetry>> {
        self.authority_read_snapshot(|transaction| {
            load_current_cat_telemetry_unlocked(transaction, node_id, cat_id)
        })
    }
}

fn authenticate_identity(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
) -> AuthorityTxResult<Option<NodeIdentity>> {
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated.credential_id())?
    else {
        return Ok(None);
    };
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || !matches!(
            identity.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
    {
        return Ok(None);
    }
    if lock_exact_credential_lineage(transaction, &identity)?
        != Some(CredentialLineageState::Active)
    {
        return Ok(None);
    }
    Ok(Some(identity))
}

fn accept_runtime_inventory_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    report: &RuntimeInventoryReport,
) -> AuthorityTxResult<RuntimeInventoryOutcome<RuntimeInventoryAcceptance>> {
    let Some(identity) = authenticate_identity(transaction, authenticated)? else {
        return Ok(rejected(RuntimeInventoryErrorDetail::IdentityNotEligible));
    };
    let Some(session) = load_current_session_for_update(transaction, &identity.node_id)? else {
        return Ok(rejected(RuntimeInventoryErrorDetail::MissingAgentSession {
            node_id: identity.node_id,
        }));
    };
    if let Some(error) = session_error(&session, &report.session) {
        return Ok(rejected(error));
    }

    let receive = load_inventory_receive_state_for_update(transaction, &session.node_id)?;
    let same_receive_session = receive
        .as_ref()
        .is_some_and(|state| state.report.session == report.session);
    if same_receive_session {
        let retained = receive.as_ref().expect("same receive-state session exists");
        if report.sequence < retained.report.sequence {
            return Ok(rejected(RuntimeInventoryErrorDetail::StaleReportSequence {
                node_id: session.node_id,
                agent_session_epoch: session.agent_session_epoch,
                presented_sequence: report.sequence,
                last_accepted_sequence: retained.report.sequence,
            }));
        }
        if report.sequence == retained.report.sequence {
            if report == &retained.report {
                return Ok(RuntimeInventoryOutcome::Accepted(
                    retained.acceptance.clone(),
                ));
            }
            return Ok(rejected(
                RuntimeInventoryErrorDetail::ReportSequenceConflict {
                    node_id: session.node_id,
                    agent_session_epoch: session.agent_session_epoch,
                    sequence: report.sequence,
                    accepted_report_id: retained.report.report_id.clone(),
                    presented_report_id: report.report_id.clone(),
                },
            ));
        }
    }

    let now = database_now(transaction)?;
    if now >= session.lease_deadline_unix_ms {
        return Ok(rejected(RuntimeInventoryErrorDetail::SessionExpired {
            node_id: session.node_id,
            agent_session_epoch: session.agent_session_epoch,
            lease_deadline_unix_ms: session.lease_deadline_unix_ms,
            server_time_unix_ms: now,
        }));
    }
    if receive
        .as_ref()
        .is_some_and(|state| now < state.acceptance.accepted_at_unix_ms)
    {
        return Err(corrupt(
            "database time moved behind the last accepted inventory report",
        ));
    }

    let current_full = load_runtime_full_inventory_for_update(transaction, &session.node_id)?;
    if let Some(error) = validate_inventory_relation(&session, report, current_full.as_ref())? {
        return Ok(rejected(error));
    }

    let candidate_deadline = checked_add_time(now, AGENT_SESSION_LEASE_MS)?;
    let renewed_deadline = std::cmp::max(session.lease_deadline_unix_ms, candidate_deadline);
    let inventory = match &report.inventory {
        RuntimeInventoryBody::Full {
            inventory_epoch,
            scan_id,
            inventory_digest,
            ..
        } => RuntimeInventoryAcceptanceKind::Full {
            attestation: Box::new(RuntimeInventoryAttestation {
                version: ContractVersion::V1,
                session: report.session.clone(),
                inventory_epoch: *inventory_epoch,
                scan_id: scan_id.clone(),
                inventory_digest: inventory_digest.clone(),
                source_report_id: report.report_id.clone(),
                source_sequence: report.sequence,
                accepted_at_unix_ms: now,
            }),
        },
        RuntimeInventoryBody::Partial {
            inventory_epoch, ..
        } => RuntimeInventoryAcceptanceKind::Partial {
            inventory_epoch: *inventory_epoch,
        },
    };
    let acceptance = RuntimeInventoryAcceptance {
        version: ContractVersion::V1,
        session: report.session.clone(),
        report_id: report.report_id.clone(),
        sequence: report.sequence,
        accepted_at_unix_ms: now,
        lease_deadline_unix_ms: renewed_deadline,
        inventory,
    };
    encode_runtime_inventory_acceptance(&acceptance).map_err(corrupt)?;

    match &acceptance.inventory {
        RuntimeInventoryAcceptanceKind::Full { attestation } => {
            upsert_runtime_full_inventory(
                transaction,
                &RuntimeFullInventoryState {
                    attestation: attestation.as_ref().clone(),
                    full_report: report.clone(),
                },
            )?;
            replace_full_cat_telemetry(transaction, report, now)?;
        }
        RuntimeInventoryAcceptanceKind::Partial { .. } => {
            // Partial reports deliberately do not write the full-inventory
            // row. The epoch is only a session-bound association and a guard
            // against expanding the attested inventory membership.
            upsert_partial_cat_telemetry(transaction, report, now)?;
        }
    }
    upsert_inventory_receive_state(
        transaction,
        &RuntimeInventoryReceiveState {
            report: report.clone(),
            acceptance: acceptance.clone(),
        },
    )?;
    renew_current_session_deadline(transaction, &session, renewed_deadline)?;
    Ok(RuntimeInventoryOutcome::Accepted(acceptance))
}

fn validate_inventory_relation(
    session: &AgentSession,
    report: &RuntimeInventoryReport,
    current_full: Option<&RuntimeFullInventoryState>,
) -> AuthorityTxResult<Option<RuntimeInventoryErrorDetail>> {
    let current_full = current_full.filter(|state| state.attestation.session == report.session);
    match &report.inventory {
        RuntimeInventoryBody::Full {
            inventory_epoch, ..
        } => {
            let expected = match current_full {
                None => Epoch::new(1).expect("one is an Epoch"),
                Some(current) => current
                    .attestation
                    .inventory_epoch
                    .get()
                    .checked_add(1)
                    .and_then(Epoch::new)
                    .ok_or_else(|| corrupt("runtime inventory epoch exhausted"))?,
            };
            if let Some(current) = current_full {
                if *inventory_epoch <= current.attestation.inventory_epoch {
                    return Ok(Some(RuntimeInventoryErrorDetail::StaleInventoryEpoch {
                        node_id: session.node_id.clone(),
                        agent_session_epoch: session.agent_session_epoch,
                        presented_inventory_epoch: *inventory_epoch,
                        current_inventory_epoch: current.attestation.inventory_epoch,
                    }));
                }
            }
            if *inventory_epoch != expected {
                return Ok(Some(RuntimeInventoryErrorDetail::WrongInventoryEpoch {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    expected_inventory_epoch: expected,
                    presented_inventory_epoch: *inventory_epoch,
                }));
            }
        }
        RuntimeInventoryBody::Partial {
            inventory_epoch,
            cats,
        } => {
            let Some(current) = current_full else {
                return Ok(Some(RuntimeInventoryErrorDetail::MissingFullInventory {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                }));
            };
            let current_epoch = current.attestation.inventory_epoch;
            if *inventory_epoch < current_epoch {
                return Ok(Some(RuntimeInventoryErrorDetail::StaleInventoryEpoch {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    presented_inventory_epoch: *inventory_epoch,
                    current_inventory_epoch: current_epoch,
                }));
            }
            if *inventory_epoch > current_epoch {
                return Ok(Some(RuntimeInventoryErrorDetail::WrongInventoryEpoch {
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    expected_inventory_epoch: current_epoch,
                    presented_inventory_epoch: *inventory_epoch,
                }));
            }
            let full_members: BTreeSet<&Id> = current
                .full_report
                .inventory
                .cats()
                .iter()
                .map(|cat| &cat.cat_id)
                .collect();
            if let Some(cat) = cats.iter().find(|cat| !full_members.contains(&cat.cat_id)) {
                return Ok(Some(
                    RuntimeInventoryErrorDetail::PartialCatNotInFullInventory {
                        node_id: session.node_id.clone(),
                        agent_session_epoch: session.agent_session_epoch,
                        inventory_epoch: *inventory_epoch,
                        cat_id: cat.cat_id.clone(),
                    },
                ));
            }
        }
    }
    Ok(None)
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn session_error(
    session: &AgentSession,
    presented: &SessionBinding,
) -> Option<RuntimeInventoryErrorDetail> {
    let expected = session_binding(session);
    if presented.agent_session_epoch < expected.agent_session_epoch {
        return Some(RuntimeInventoryErrorDetail::StaleSession {
            node_id: expected.node_id,
            presented_agent_session_epoch: presented.agent_session_epoch,
            current_agent_session_epoch: expected.agent_session_epoch,
        });
    }
    (presented != &expected).then(|| RuntimeInventoryErrorDetail::WrongSession {
        expected,
        presented: presented.clone(),
    })
}

fn checked_add_time(value: UnixMillis, increment: u64) -> AuthorityTxResult<UnixMillis> {
    value
        .get()
        .checked_add(increment)
        .and_then(UnixMillis::new)
        .ok_or_else(|| corrupt("runtime inventory timestamp overflow"))
}

fn rejected<T>(error: RuntimeInventoryErrorDetail) -> RuntimeInventoryOutcome<T> {
    RuntimeInventoryOutcome::Rejected(error)
}

fn load_inventory_receive_state_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<RuntimeInventoryReceiveState>> {
    load_inventory_receive_state(transaction, node_id, "FOR UPDATE")
}

fn load_inventory_receive_state(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    lock: &'static str,
) -> AuthorityTxResult<Option<RuntimeInventoryReceiveState>> {
    let sql = format!(
        "SELECT report::text AS report_json,
                acceptance::text AS acceptance_json, node_id, node_boot_id,
                agent_instance_id, agent_session_epoch, report_sequence,
                report_id, accepted_at_unix_ms
           FROM runtime_inventory_receive_states
          WHERE node_id=$1 {lock}"
    );
    transaction
        .query_opt(&sql, &[&node_id.as_str()])?
        .map(|row| decode_inventory_receive_state(&row))
        .transpose()
}

fn decode_inventory_receive_state(row: &Row) -> AuthorityTxResult<RuntimeInventoryReceiveState> {
    let report_json: String = row.try_get("report_json")?;
    let acceptance_json: String = row.try_get("acceptance_json")?;
    let report = decode_runtime_inventory_report(report_json.as_bytes()).map_err(corrupt)?;
    let acceptance =
        decode_runtime_inventory_acceptance(acceptance_json.as_bytes()).map_err(corrupt)?;
    let node_id: String = row.try_get("node_id")?;
    let node_boot_id: String = row.try_get("node_boot_id")?;
    let agent_instance_id: String = row.try_get("agent_instance_id")?;
    let epoch: Epoch = from_pg(row.try_get("agent_session_epoch")?)?;
    let sequence: Sequence = from_pg(row.try_get("report_sequence")?)?;
    let report_id: String = row.try_get("report_id")?;
    let accepted_at: UnixMillis = from_pg(row.try_get("accepted_at_unix_ms")?)?;
    let inventory_matches = match (&report.inventory, &acceptance.inventory) {
        (
            RuntimeInventoryBody::Full {
                inventory_epoch,
                scan_id,
                inventory_digest,
                ..
            },
            RuntimeInventoryAcceptanceKind::Full { attestation },
        ) => {
            attestation.session == report.session
                && attestation.inventory_epoch == *inventory_epoch
                && attestation.scan_id == *scan_id
                && attestation.inventory_digest == *inventory_digest
                && attestation.source_report_id == report.report_id
                && attestation.source_sequence == report.sequence
                && attestation.accepted_at_unix_ms == acceptance.accepted_at_unix_ms
        }
        (
            RuntimeInventoryBody::Partial {
                inventory_epoch, ..
            },
            RuntimeInventoryAcceptanceKind::Partial {
                inventory_epoch: accepted_epoch,
            },
        ) => inventory_epoch == accepted_epoch,
        _ => false,
    };
    if report.session.node_id.as_str() != node_id
        || report.session.node_boot_id.as_str() != node_boot_id
        || report.session.agent_instance_id.as_str() != agent_instance_id
        || report.session.agent_session_epoch != epoch
        || report.sequence != sequence
        || report.report_id.as_str() != report_id
        || acceptance.session != report.session
        || acceptance.report_id != report.report_id
        || acceptance.sequence != report.sequence
        || acceptance.accepted_at_unix_ms != accepted_at
        || !inventory_matches
    {
        return Err(corrupt(
            "runtime inventory receive-state projection mismatch",
        ));
    }
    Ok(RuntimeInventoryReceiveState { report, acceptance })
}

fn upsert_inventory_receive_state(
    transaction: &mut Transaction<'_>,
    state: &RuntimeInventoryReceiveState,
) -> AuthorityTxResult<()> {
    let report = encode_json(encode_runtime_inventory_report(&state.report).map_err(corrupt)?)?;
    let acceptance =
        encode_json(encode_runtime_inventory_acceptance(&state.acceptance).map_err(corrupt)?)?;
    let epoch = state
        .report
        .session
        .agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    let sequence = state.report.sequence.to_pg().map_err(corrupt)?;
    let accepted_at = state
        .acceptance
        .accepted_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_inventory_receive_states (
            node_id, report, acceptance, node_boot_id,
            agent_instance_id, agent_session_epoch, report_sequence,
            report_id, accepted_at_unix_ms
         ) VALUES ($1,$2::TEXT::jsonb,$3::TEXT::jsonb,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (node_id) DO UPDATE SET
            report=EXCLUDED.report, acceptance=EXCLUDED.acceptance,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            report_sequence=EXCLUDED.report_sequence,
            report_id=EXCLUDED.report_id,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms",
        &[
            &state.report.session.node_id.as_str(),
            &report,
            &acceptance,
            &state.report.session.node_boot_id.as_str(),
            &state.report.session.agent_instance_id.as_str(),
            &epoch,
            &sequence,
            &state.report.report_id.as_str(),
            &accepted_at,
        ],
    )?;
    Ok(())
}

pub(super) fn load_runtime_full_inventory_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<RuntimeFullInventoryState>> {
    load_runtime_full_inventory(transaction, node_id, "FOR UPDATE")
}

/// Checks the time/session portion of a domain consumer's admission decision.
/// The caller must have loaded and locked `session` as the current
/// AgentSession in the same transaction and must independently validate its
/// own lifecycle, placement, route, volume, or cleanup facts.
pub(super) fn runtime_full_inventory_is_fresh_at(
    state: &RuntimeFullInventoryState,
    session: &AgentSession,
    evaluated_at_unix_ms: UnixMillis,
    maximum_age_ms: u64,
) -> AuthorityTxResult<bool> {
    if state.attestation.session != session_binding(session) {
        return Ok(false);
    }
    if evaluated_at_unix_ms < state.attestation.accepted_at_unix_ms {
        return Err(corrupt(
            "database time moved behind the full-inventory attestation",
        ));
    }
    let fresh_until = checked_add_time(state.attestation.accepted_at_unix_ms, maximum_age_ms)?;
    Ok(evaluated_at_unix_ms < fresh_until)
}

#[allow(
    dead_code,
    reason = "atomic placement and diagnostics consume the clean full-inventory snapshot after legacy callers are removed"
)]
pub(super) fn load_runtime_full_inventory_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<Option<RuntimeFullInventoryState>> {
    load_runtime_full_inventory(transaction, node_id, "")
}

fn load_runtime_full_inventory(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    lock: &'static str,
) -> AuthorityTxResult<Option<RuntimeFullInventoryState>> {
    let sql = format!(
        "SELECT attestation::text AS attestation_json,
                full_report::text AS report_json, node_id, node_boot_id,
                agent_instance_id, agent_session_epoch, inventory_epoch,
                inventory_digest, scan_id, source_report_id, source_sequence,
                accepted_at_unix_ms
           FROM runtime_full_inventory_attestations
          WHERE node_id=$1 {lock}"
    );
    transaction
        .query_opt(&sql, &[&node_id.as_str()])?
        .map(|row| decode_runtime_full_inventory(&row))
        .transpose()
}

fn decode_runtime_full_inventory(row: &Row) -> AuthorityTxResult<RuntimeFullInventoryState> {
    let attestation_json: String = row.try_get("attestation_json")?;
    let report_json: String = row.try_get("report_json")?;
    let attestation =
        serde_json::from_str::<RuntimeInventoryAttestation>(&attestation_json).map_err(corrupt)?;
    let full_report = decode_runtime_inventory_report(report_json.as_bytes()).map_err(corrupt)?;
    let RuntimeInventoryBody::Full {
        inventory_epoch,
        scan_id,
        inventory_digest,
        ..
    } = &full_report.inventory
    else {
        return Err(corrupt("stored full inventory contains a partial report"));
    };
    let node_id: String = row.try_get("node_id")?;
    let node_boot_id: String = row.try_get("node_boot_id")?;
    let agent_instance_id: String = row.try_get("agent_instance_id")?;
    let session_epoch: Epoch = from_pg(row.try_get("agent_session_epoch")?)?;
    let projected_inventory_epoch: Epoch = from_pg(row.try_get("inventory_epoch")?)?;
    let projected_digest: String = row.try_get("inventory_digest")?;
    let projected_scan_id: String = row.try_get("scan_id")?;
    let report_id: String = row.try_get("source_report_id")?;
    let sequence: Sequence = from_pg(row.try_get("source_sequence")?)?;
    let accepted_at: UnixMillis = from_pg(row.try_get("accepted_at_unix_ms")?)?;
    if full_report.session.node_id.as_str() != node_id
        || full_report.session.node_boot_id.as_str() != node_boot_id
        || full_report.session.agent_instance_id.as_str() != agent_instance_id
        || full_report.session.agent_session_epoch != session_epoch
        || full_report.report_id.as_str() != report_id
        || full_report.sequence != sequence
        || *inventory_epoch != projected_inventory_epoch
        || inventory_digest.as_str() != projected_digest
        || scan_id.as_str() != projected_scan_id
        || attestation.version != ContractVersion::V1
        || attestation.session != full_report.session
        || attestation.inventory_epoch != *inventory_epoch
        || attestation.scan_id != *scan_id
        || attestation.inventory_digest != *inventory_digest
        || attestation.source_report_id != full_report.report_id
        || attestation.source_sequence != full_report.sequence
        || attestation.accepted_at_unix_ms != accepted_at
    {
        return Err(corrupt("full inventory attestation projection mismatch"));
    }
    Ok(RuntimeFullInventoryState {
        attestation,
        full_report,
    })
}

fn upsert_runtime_full_inventory(
    transaction: &mut Transaction<'_>,
    state: &RuntimeFullInventoryState,
) -> AuthorityTxResult<()> {
    let attestation = serde_json::to_string(&state.attestation).map_err(corrupt)?;
    let report =
        encode_json(encode_runtime_inventory_report(&state.full_report).map_err(corrupt)?)?;
    let epoch = state
        .attestation
        .session
        .agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    let inventory_epoch = state.attestation.inventory_epoch.to_pg().map_err(corrupt)?;
    let sequence = state.attestation.source_sequence.to_pg().map_err(corrupt)?;
    let accepted_at = state
        .attestation
        .accepted_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_full_inventory_attestations (
            node_id, attestation, full_report, node_boot_id,
            agent_instance_id, agent_session_epoch, inventory_epoch,
            inventory_digest, scan_id, source_report_id, source_sequence,
            accepted_at_unix_ms
         ) VALUES ($1,$2::TEXT::jsonb,$3::TEXT::jsonb,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (node_id) DO UPDATE SET
            attestation=EXCLUDED.attestation,
            full_report=EXCLUDED.full_report,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            inventory_epoch=EXCLUDED.inventory_epoch,
            inventory_digest=EXCLUDED.inventory_digest,
            scan_id=EXCLUDED.scan_id,
            source_report_id=EXCLUDED.source_report_id,
            source_sequence=EXCLUDED.source_sequence,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms",
        &[
            &state.attestation.session.node_id.as_str(),
            &attestation,
            &report,
            &state.attestation.session.node_boot_id.as_str(),
            &state.attestation.session.agent_instance_id.as_str(),
            &epoch,
            &inventory_epoch,
            &state.attestation.inventory_digest.as_str(),
            &state.attestation.scan_id.as_str(),
            &state.attestation.source_report_id.as_str(),
            &sequence,
            &accepted_at,
        ],
    )?;
    Ok(())
}

fn replace_full_cat_telemetry(
    transaction: &mut Transaction<'_>,
    report: &RuntimeInventoryReport,
    accepted_at: UnixMillis,
) -> AuthorityTxResult<()> {
    transaction.execute(
        "DELETE FROM runtime_current_cat_telemetry WHERE node_id=$1",
        &[&report.session.node_id.as_str()],
    )?;
    for cat in report.inventory.cats() {
        upsert_cat_telemetry(transaction, report, cat, accepted_at, "full")?;
    }
    Ok(())
}

fn upsert_partial_cat_telemetry(
    transaction: &mut Transaction<'_>,
    report: &RuntimeInventoryReport,
    accepted_at: UnixMillis,
) -> AuthorityTxResult<()> {
    for cat in report.inventory.cats() {
        upsert_cat_telemetry(transaction, report, cat, accepted_at, "partial")?;
    }
    Ok(())
}

fn upsert_cat_telemetry(
    transaction: &mut Transaction<'_>,
    report: &RuntimeInventoryReport,
    cat: &ObservedCatRuntimeTelemetry,
    accepted_at: UnixMillis,
    source_kind: &'static str,
) -> AuthorityTxResult<()> {
    let cat_json = serde_json::to_string(cat).map_err(corrupt)?;
    let session_epoch = report
        .session
        .agent_session_epoch
        .to_pg()
        .map_err(corrupt)?;
    let inventory_epoch = report
        .inventory
        .inventory_epoch()
        .to_pg()
        .map_err(corrupt)?;
    let sequence = report.sequence.to_pg().map_err(corrupt)?;
    let accepted_at = accepted_at.to_pg().map_err(corrupt)?;
    transaction.execute(
        "INSERT INTO runtime_current_cat_telemetry (
            node_id, cat_id, telemetry_record, node_boot_id,
            agent_instance_id, agent_session_epoch, inventory_epoch,
            source_report_id, report_sequence, accepted_at_unix_ms,
            source_kind
         ) VALUES ($1,$2,$3::TEXT::jsonb,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (node_id,cat_id) DO UPDATE SET
            telemetry_record=EXCLUDED.telemetry_record,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            agent_session_epoch=EXCLUDED.agent_session_epoch,
            inventory_epoch=EXCLUDED.inventory_epoch,
            source_report_id=EXCLUDED.source_report_id,
            report_sequence=EXCLUDED.report_sequence,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms,
            source_kind=EXCLUDED.source_kind",
        &[
            &report.session.node_id.as_str(),
            &cat.cat_id.as_str(),
            &cat_json,
            &report.session.node_boot_id.as_str(),
            &report.session.agent_instance_id.as_str(),
            &session_epoch,
            &inventory_epoch,
            &report.report_id.as_str(),
            &sequence,
            &accepted_at,
            &source_kind,
        ],
    )?;
    Ok(())
}

#[allow(
    dead_code,
    reason = "atomic product status and diagnostics consume telemetry after legacy product reads are removed"
)]
pub(super) fn load_current_cat_telemetry_unlocked(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CurrentCatTelemetry>> {
    load_current_cat_telemetry(transaction, node_id, cat_id, "")
}

#[allow(
    dead_code,
    reason = "domain-specific attestation consumers use this lock after the clean lifecycle transition is composed"
)]
pub(super) fn load_current_cat_telemetry_for_update(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CurrentCatTelemetry>> {
    load_current_cat_telemetry(transaction, node_id, cat_id, "FOR UPDATE")
}

fn load_current_cat_telemetry(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    cat_id: &Id,
    lock: &'static str,
) -> AuthorityTxResult<Option<CurrentCatTelemetry>> {
    let sql = format!(
        "SELECT telemetry_record::text AS telemetry_json, node_id, cat_id,
                node_boot_id, agent_instance_id, agent_session_epoch,
                inventory_epoch, source_report_id, report_sequence,
                accepted_at_unix_ms, source_kind
           FROM runtime_current_cat_telemetry
          WHERE node_id=$1 AND cat_id=$2 {lock}"
    );
    transaction
        .query_opt(&sql, &[&node_id.as_str(), &cat_id.as_str()])?
        .map(|row| decode_current_cat_telemetry(&row))
        .transpose()
}

fn decode_current_cat_telemetry(row: &Row) -> AuthorityTxResult<CurrentCatTelemetry> {
    let telemetry_json: String = row.try_get("telemetry_json")?;
    let telemetry =
        serde_json::from_str::<ObservedCatRuntimeTelemetry>(&telemetry_json).map_err(corrupt)?;
    let projected_node_id = Id::new(row.try_get::<_, String>("node_id")?)
        .ok_or_else(|| corrupt("invalid stored Node ID"))?;
    let projected_cat_id = Id::new(row.try_get::<_, String>("cat_id")?)
        .ok_or_else(|| corrupt("invalid stored Cat ID"))?;
    let session = SessionBinding {
        node_id: projected_node_id,
        node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
            row.try_get::<_, String>("node_boot_id")?,
        )
        .ok_or_else(|| corrupt("invalid stored Node boot ID"))?,
        agent_instance_id: RandomId128::new(row.try_get::<_, String>("agent_instance_id")?)
            .ok_or_else(|| corrupt("invalid stored Agent instance ID"))?,
        agent_session_epoch: from_pg(row.try_get("agent_session_epoch")?)?,
    };
    let inventory_epoch = from_pg(row.try_get("inventory_epoch")?)?;
    let source_report_id = RandomId128::new(row.try_get::<_, String>("source_report_id")?)
        .ok_or_else(|| corrupt("invalid stored inventory report ID"))?;
    let sequence = from_pg(row.try_get("report_sequence")?)?;
    let accepted_at_unix_ms = from_pg(row.try_get("accepted_at_unix_ms")?)?;
    let source_kind = match row.try_get::<_, String>("source_kind")?.as_str() {
        "full" => RuntimeTelemetrySourceKind::Full,
        "partial" => RuntimeTelemetrySourceKind::Partial,
        _ => return Err(corrupt("invalid per-Cat telemetry source kind")),
    };
    if telemetry.cat_id != projected_cat_id {
        return Err(corrupt("per-Cat telemetry projection mismatch"));
    }
    validate_observed_cat_runtime_telemetry(&telemetry, &session.node_id).map_err(corrupt)?;
    Ok(CurrentCatTelemetry {
        telemetry,
        session,
        inventory_epoch,
        source_report_id,
        sequence,
        accepted_at_unix_ms,
        source_kind,
    })
}

fn encode_json(bytes: Vec<u8>) -> AuthorityTxResult<String> {
    String::from_utf8(bytes).map_err(corrupt)
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

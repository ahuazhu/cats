//! Bounded production maintenance for the clean-slate runtime authority.
//!
//! The scanner acts only on durable facts.  An expired or missing
//! `AgentSession` is suspicion and therefore leaves an Operation Pending.  A
//! current Active `HostFenceEvent`, by contrast, is the exact authority for a
//! `HostLost` terminal.  API replay rows are retained for runtime v1 even
//! after their resource graph is collected.

use cats_api::runtime_reconciliation::{Id, OperationFailure, OperationPhase, OperationTerminal};
use cats_storage::authority::HostFenceEventState;

use super::product_rows::{
    load_cat_by_id_for_update, load_desired_for_update, load_operation_for_update, update_operation,
};
use super::rows::{database_now, load_active_event_by_node_unlocked, load_event_for_update};
use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_node_for_update,
};
use crate::store::transaction::AuthorityTxResult;
use crate::store::{AuthorityRequestContext, Result, Store};

pub(crate) const RUNTIME_MAINTENANCE_PAGE_SIZE: usize = 64;
const RUNTIME_MAINTENANCE_PAGE_LIMIT: i64 = 64;
const RUNTIME_MAINTENANCE_PAGE_FETCH: i64 = 65;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuntimeMaintenanceCursor {
    pub(crate) pending_after: Option<Id>,
    pub(crate) deleted_after: Option<Id>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuntimeMaintenanceReport {
    pub(crate) sampled_pending_operations: u64,
    pub(crate) settled_host_lost_operations: u64,
    pub(crate) retained_suspected_operations: u64,
    pub(crate) sampled_deleted_tombstones: u64,
    pub(crate) converged_disposable_root_begins: u64,
    pub(crate) sampled_retained_api_results: u64,
    pub(crate) next_cursor: RuntimeMaintenanceCursor,
}

#[derive(Debug, Clone)]
struct PendingCandidate {
    operation_id: Id,
    cat_id: Id,
    node_id: Id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOutcome {
    SettledHostLost,
    RetainedSuspicion,
    Unchanged,
}

impl Store {
    /// Run one stable-key page.  The cursor is process-local acceleration only;
    /// losing leadership merely restarts the level-triggered scan at the
    /// beginning.
    pub(crate) fn runtime_maintenance_scan_page(
        &self,
        cursor: &RuntimeMaintenanceCursor,
        request: &AuthorityRequestContext,
        active_guest_config_digest: &cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Result<RuntimeMaintenanceReport> {
        ensure_runtime_maintenance_active(request)?;
        let (pending, pending_has_more) =
            self.runtime_pending_candidates_after(cursor.pending_after.as_ref(), request)?;
        let mut report = RuntimeMaintenanceReport {
            sampled_pending_operations: u64::try_from(pending.len())
                .map_err(crate::store::internal)?,
            ..RuntimeMaintenanceReport::default()
        };
        for candidate in &pending {
            ensure_runtime_maintenance_active(request)?;
            match self.authority_transaction(|transaction| {
                settle_pending_candidate(transaction, candidate)
            })? {
                PendingOutcome::SettledHostLost => {
                    report.settled_host_lost_operations += 1;
                }
                PendingOutcome::RetainedSuspicion => {
                    report.retained_suspected_operations += 1;
                }
                PendingOutcome::Unchanged => {}
            }
        }
        report.next_cursor.pending_after = if pending_has_more {
            pending
                .last()
                .map(|candidate| candidate.operation_id.clone())
        } else {
            None
        };

        ensure_runtime_maintenance_active(request)?;
        let (deleted, deleted_has_more) =
            self.runtime_deleted_candidates_after(cursor.deleted_after.as_ref(), request)?;
        report.sampled_deleted_tombstones =
            u64::try_from(deleted.len()).map_err(crate::store::internal)?;
        // §11.1 Deleted converge: a tombstone whose released disposable Root
        // the Node already reclaimed moves to normal Deleting here so the
        // delete sweeper can finish rows and the completion receipt.
        for cat_id in &deleted {
            ensure_runtime_maintenance_active(request)?;
            if self.authority_transaction(|transaction| {
                super::normal_delete::begin_released_disposable_root_delete_in(
                    transaction,
                    cat_id,
                    active_guest_config_digest,
                    &mut |_| Ok(()),
                )
            })? {
                report.converged_disposable_root_begins += 1;
            }
        }
        report.next_cursor.deleted_after = if deleted_has_more {
            deleted.last().cloned()
        } else {
            None
        };

        ensure_runtime_maintenance_active(request)?;
        report.sampled_retained_api_results =
            self.authority_request_read_snapshot(request, |transaction| {
                let count: i64 = transaction
                    .query_one(
                        "SELECT count(*) FROM (
                        SELECT authenticated_workspace_id, canonical_route, idempotency_key
                          FROM api_idempotency_results
                         ORDER BY authenticated_workspace_id COLLATE \"C\",
                                  canonical_route COLLATE \"C\",
                                  idempotency_key COLLATE \"C\"
                         LIMIT $1
                     ) retained",
                        &[&RUNTIME_MAINTENANCE_PAGE_LIMIT],
                    )?
                    .try_get(0)?;
                count.try_into().map_err(corrupt_count)
            })?;
        Ok(report)
    }

    #[cfg(test)]
    pub(crate) fn runtime_maintenance_scan(
        &self,
        active_guest_config_digest: &cats_api::runtime_reconciliation::Sha256Digest,
    ) -> Result<RuntimeMaintenanceReport> {
        let request = AuthorityRequestContext::new(
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        );
        self.runtime_maintenance_scan_page(
            &RuntimeMaintenanceCursor::default(),
            &request,
            active_guest_config_digest,
        )
    }

    fn runtime_pending_candidates_after(
        &self,
        after: Option<&Id>,
        request: &AuthorityRequestContext,
    ) -> Result<(Vec<PendingCandidate>, bool)> {
        self.authority_request_read_snapshot(request, |transaction| {
            let after = after.map(Id::as_str);
            let rows = transaction.query(
                "SELECT operation_id, cat_id, node_id
                   FROM runtime_operations
                  WHERE (phase='pending' OR record->>'phase'='pending')
                    AND ($1::TEXT IS NULL
                         OR operation_id COLLATE \"C\" > $1 COLLATE \"C\")
                  ORDER BY operation_id COLLATE \"C\"
                  LIMIT $2",
                &[&after, &RUNTIME_MAINTENANCE_PAGE_FETCH],
            )?;
            let has_more = rows.len() > RUNTIME_MAINTENANCE_PAGE_SIZE;
            let mut candidates = Vec::with_capacity(rows.len().min(RUNTIME_MAINTENANCE_PAGE_SIZE));
            for row in rows.into_iter().take(RUNTIME_MAINTENANCE_PAGE_SIZE) {
                let operation_id = Id::new(row.try_get::<_, String>("operation_id")?)
                    .ok_or_else(|| corrupt("Pending Operation ID is malformed"))?;
                let cat_id = Id::new(row.try_get::<_, String>("cat_id")?)
                    .ok_or_else(|| corrupt("Pending Operation Cat ID is malformed"))?;
                let node_id = Id::new(row.try_get::<_, String>("node_id")?)
                    .ok_or_else(|| corrupt("Pending Operation Node ID is malformed"))?;
                candidates.push(PendingCandidate {
                    operation_id,
                    cat_id,
                    node_id,
                });
            }
            Ok((candidates, has_more))
        })
    }

    fn runtime_deleted_candidates_after(
        &self,
        after: Option<&Id>,
        request: &AuthorityRequestContext,
    ) -> Result<(Vec<Id>, bool)> {
        self.authority_request_read_snapshot(request, |transaction| {
            let after = after.map(Id::as_str);
            let rows = transaction.query(
                "SELECT cat_id
                   FROM desired_runtime_specs
                  WHERE (target='deleted' OR record->>'target'='deleted')
                    AND ($1::TEXT IS NULL OR cat_id COLLATE \"C\" > $1 COLLATE \"C\")
                  ORDER BY cat_id COLLATE \"C\"
                  LIMIT $2",
                &[&after, &RUNTIME_MAINTENANCE_PAGE_FETCH],
            )?;
            let has_more = rows.len() > RUNTIME_MAINTENANCE_PAGE_SIZE;
            let mut candidates = Vec::with_capacity(rows.len().min(RUNTIME_MAINTENANCE_PAGE_SIZE));
            for row in rows.into_iter().take(RUNTIME_MAINTENANCE_PAGE_SIZE) {
                candidates.push(
                    Id::new(row.try_get::<_, String>("cat_id")?)
                        .ok_or_else(|| corrupt("Deleted tombstone Cat ID is malformed"))?,
                );
            }
            Ok((candidates, has_more))
        })
    }
}

fn ensure_runtime_maintenance_active(request: &AuthorityRequestContext) -> Result<()> {
    if request.is_cancelled_or_expired() {
        return Err(crate::store::ApiError::unavailable(
            "runtime maintenance leadership was cancelled or exceeded its deadline",
        ));
    }
    Ok(())
}

fn settle_pending_candidate(
    transaction: &mut postgres::Transaction<'_>,
    candidate: &PendingCandidate,
) -> AuthorityTxResult<PendingOutcome> {
    // The candidate page is a hint.  Take the canonical Node -> session ->
    // HostFence prefix before locking mutable product rows, then re-read every
    // predicate in this transaction.
    let Some(identity) = load_identity_by_node_for_update(transaction, &candidate.node_id)? else {
        return Err(corrupt(
            "Pending Operation references a missing NodeIdentity",
        ));
    };
    let current_session = load_current_session_for_update(transaction, &candidate.node_id)?;
    let event = match load_active_event_by_node_unlocked(transaction, &candidate.node_id)? {
        Some(event) => Some(
            load_event_for_update(transaction, &event.event_id)?
                .ok_or_else(|| corrupt("Active HostFenceEvent disappeared while locking it"))?,
        ),
        None => None,
    };
    let Some(_cat) = load_cat_by_id_for_update(transaction, &candidate.cat_id)? else {
        return Err(corrupt("Pending Operation references a missing Cat"));
    };
    let Some(desired) = load_desired_for_update(transaction, &candidate.cat_id)? else {
        return Err(corrupt("Pending Operation references a missing Desired"));
    };
    let Some(mut operation) = load_operation_for_update(transaction, &candidate.operation_id)?
    else {
        return Ok(PendingOutcome::Unchanged);
    };
    if operation.phase != OperationPhase::Pending
        || operation.cat_id != candidate.cat_id
        || operation.placement.node_id != candidate.node_id
    {
        return Ok(PendingOutcome::Unchanged);
    }
    if operation.workspace_id != desired.workspace_id
        || operation.cat_id != desired.cat_id
        || operation.desired_revision != desired.desired_revision
        || operation.desired_spec_digest != desired.spec_digest
        || operation.placement != desired.placement
        || operation.target != desired.target
    {
        // A stale page may race a complete A1 successor transaction.  If the
        // row still says Pending, however, that transaction violated the
        // one-Pending invariant and must fail closed as stored corruption.
        return Err(corrupt(
            "Pending Operation is not bound to the current Desired",
        ));
    }

    let now = database_now(transaction)?;
    if now < operation.created_at_unix_ms || now < operation.updated_at_unix_ms {
        return Err(corrupt("database time moved behind a Pending Operation"));
    }
    let Some(event) = event else {
        return Ok(
            if current_session
                .as_ref()
                .is_none_or(|session| now >= session.lease_deadline_unix_ms)
            {
                PendingOutcome::RetainedSuspicion
            } else {
                PendingOutcome::Unchanged
            },
        );
    };
    if event.state != HostFenceEventState::Active {
        return Ok(PendingOutcome::Unchanged);
    }
    if event.node_id != candidate.node_id || event.immutable_host_id != identity.immutable_host_id {
        return Err(corrupt(
            "Active HostFenceEvent does not bind the Pending Operation lineage",
        ));
    }

    operation.phase = OperationPhase::Failed;
    operation.terminal = Some(OperationTerminal::Failed {
        error: Box::new(OperationFailure::HostLost {
            node_id: event.node_id,
            agent_session_epoch: event.expected_agent_session_epoch,
            host_fence_event_id: event.event_id,
        }),
        completed_at_unix_ms: now,
    });
    operation.updated_at_unix_ms = now;
    update_operation(transaction, &operation)?;
    Ok(PendingOutcome::SettledHostLost)
}

fn corrupt(message: &'static str) -> crate::store::transaction::AuthorityTransactionError {
    crate::store::internal(message).into()
}

fn corrupt_count(
    _: std::num::TryFromIntError,
) -> crate::store::transaction::AuthorityTransactionError {
    corrupt("runtime maintenance count is outside u64")
}

//! Production control-plane maintenance scan for the clean-slate runtime.
//!
//! This scanner deliberately has no clock-derived lifecycle authority.
//! Heartbeat/session age is suspicion, not a Host fence. A pending Operation
//! can become `HostLost` only inside the future V3 transaction that consumes a
//! current trusted HostFenceEvent and atomically publishes the replacement
//! Desired/authorization set. Deleted tombstones likewise remain until V2/V3
//! provide one of ADR-0040's exact physical-absence proofs. Committed API
//! idempotency results are retained for the lifetime of runtime v1.

use crate::store::transaction::AuthorityTxResult;
use crate::store::{Result, Store};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RuntimeMaintenanceReport {
    pub(crate) sampled_pending_operations: u64,
    pub(crate) sampled_pending_on_fenced_node: u64,
    pub(crate) sampled_deleted_tombstones: u64,
    pub(crate) sampled_retained_api_results: u64,
}

impl Store {
    /// Take one bounded, mutually-consistent maintenance snapshot. The result
    /// is observation-only until the exact V2/V3 proof-producing transaction
    /// exists; choosing a terminal result from row age would invent authority.
    pub(crate) fn runtime_maintenance_scan(&self) -> Result<RuntimeMaintenanceReport> {
        self.authority_read_snapshot(runtime_maintenance_scan_in)
    }
}

fn runtime_maintenance_scan_in(
    transaction: &mut postgres::Transaction<'_>,
) -> AuthorityTxResult<RuntimeMaintenanceReport> {
    let row = transaction.query_one(
        "SELECT
            (SELECT count(*) FROM (
                SELECT operation_id FROM runtime_operations
                 WHERE phase='pending' ORDER BY operation_id COLLATE \"C\" LIMIT 256
            ) sampled_pending),
            (SELECT count(*) FROM (
                SELECT operation.operation_id
                  FROM runtime_operations operation
                  JOIN desired_runtime_specs desired
                    ON desired.cat_id=operation.cat_id
                   AND desired.desired_revision=operation.desired_revision
                   AND desired.spec_digest=operation.desired_spec_digest
                   AND desired.node_id=operation.node_id
                   AND desired.placement_epoch=operation.placement_epoch
                  JOIN host_fence_events event
                    ON event.node_id=desired.node_id AND event.state='active'
                 WHERE operation.phase='pending'
                 ORDER BY operation.operation_id COLLATE \"C\" LIMIT 256
            ) sampled_fenced),
            (SELECT count(*) FROM (
                SELECT cat_id FROM desired_runtime_specs
                 WHERE target='deleted' OR record->>'target'='deleted'
                 ORDER BY cat_id COLLATE \"C\" LIMIT 256
            ) sampled_deleted),
            (SELECT count(*) FROM (
                SELECT authenticated_workspace_id, canonical_route, idempotency_key
                  FROM api_idempotency_results
                 ORDER BY authenticated_workspace_id COLLATE \"C\",
                          canonical_route COLLATE \"C\", idempotency_key COLLATE \"C\"
                 LIMIT 256
            ) sampled_api_results)",
        &[],
    )?;
    Ok(RuntimeMaintenanceReport {
        sampled_pending_operations: row
            .try_get::<_, i64>(0)?
            .try_into()
            .map_err(corrupt_count)?,
        sampled_pending_on_fenced_node: row
            .try_get::<_, i64>(1)?
            .try_into()
            .map_err(corrupt_count)?,
        sampled_deleted_tombstones: row
            .try_get::<_, i64>(2)?
            .try_into()
            .map_err(corrupt_count)?,
        sampled_retained_api_results: row
            .try_get::<_, i64>(3)?
            .try_into()
            .map_err(corrupt_count)?,
    })
}

fn corrupt_count(
    _: std::num::TryFromIntError,
) -> crate::store::transaction::AuthorityTransactionError {
    crate::store::internal("runtime maintenance count is outside u64").into()
}

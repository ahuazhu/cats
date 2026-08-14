//! Host-scoped recovery coordination shared by product mutation roots.
//!
//! A provider attempt is not itself product authority.  The Control recovery
//! attempt freezes one complete assigned set under the source NodeIdentity
//! lock.  While that attempt can still publish a terminal batch, ordinary
//! product mutations must not change either the frozen Cats or create a new
//! assignment on the same Node.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::Id;
use postgres::Transaction;

use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

fn application(error: ApiError) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(error)
}

fn corrupt(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

/// Requires the caller to hold this Node's `node_identities` row lock.
///
/// The missing-row case is serialized by that parent lock: recovery enqueue
/// takes the same lock before inserting its barrier.  Exact mutation replay
/// is resolved before calling this helper, so rejecting here never hides a
/// previously committed response.
pub(super) fn require_product_mutation_unblocked_in(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
) -> AuthorityTxResult<()> {
    let rows = transaction.query(
        "SELECT fence_attempt_id
           FROM trusted_host_fence_recovery_attempts_v1
          WHERE node_id=$1 AND state IN ('provider_pending', 'provider_terminal')
          ORDER BY fence_attempt_id COLLATE \"C\" LIMIT 2 FOR UPDATE",
        &[&node_id.as_str()],
    )?;
    if rows.len() > 1 {
        return Err(corrupt(
            "more than one active Host recovery attempt exists for one Node",
        ));
    }
    if !rows.is_empty() {
        return Err(application(ApiError::conflict(
            "Node is sealed by an active Host recovery attempt",
        )));
    }
    Ok(())
}

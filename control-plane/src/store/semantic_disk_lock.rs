//! Transaction-scoped exclusion shared by every product mutation that can
//! change one PersistentDisk's bindings, snapshots, lifecycle admission, or
//! GC maintenance state.

use std::collections::BTreeSet;

use postgres::Transaction;

/// Lock one immutable Disk identity before taking any of its product or
/// storage-authority row locks.
pub(crate) fn lock_semantic_disk(
    transaction: &mut Transaction<'_>,
    disk_id: &str,
) -> Result<(), postgres::Error> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':semantic-disk:disk:' || $1,
            0::BIGINT
         ))",
        &[&disk_id],
    )?;
    Ok(())
}

/// Lock a mount set in immutable-ID order. Callers that discover the set by
/// pre-read must revalidate it after taking the Cat row lock.
pub(crate) fn lock_semantic_disks<'a>(
    transaction: &mut Transaction<'_>,
    disk_ids: impl IntoIterator<Item = &'a str>,
) -> Result<(), postgres::Error> {
    for disk_id in disk_ids.into_iter().collect::<BTreeSet<_>>() {
        lock_semantic_disk(transaction, disk_id)?;
    }
    Ok(())
}

/// Non-blocking fallback for a Disk that appeared in a mount set after the
/// caller's lock-free pre-read. This is used only while the Cat row is already
/// locked: failure returns Busy and therefore cannot form a Cat↔Disk cycle.
pub(crate) fn try_lock_semantic_disk(
    transaction: &mut Transaction<'_>,
    disk_id: &str,
) -> Result<bool, postgres::Error> {
    transaction
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtextextended(
                current_schema() || ':semantic-disk:disk:' || $1,
                0::BIGINT
             ))",
            &[&disk_id],
        )?
        .try_get(0)
}

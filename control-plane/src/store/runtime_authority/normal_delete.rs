//! The transaction-local normal delete transition authority.
//!
//! Product API owners compose this function inside their covered transaction;
//! there is intentionally no independently committing Store method and no
//! Node-facing normal-delete wire operation.

#![allow(
    dead_code,
    reason = "the A2 covered lifecycle API composes this transaction-local seam"
)]

use std::collections::BTreeMap;

use cats_api::runtime_reconciliation::{Id, NodeIdentityState, Sha256Digest};
use cats_storage::authority::{
    begin_delete, AuthorityError, BeginDeleteRequest, BeginDeleteResult, VolumeAdminState,
};
use postgres::Transaction;

use super::product::{DiskAdminState, DiskRole};
use super::product_rows::{
    load_any_disk_by_id_for_update, load_any_disk_snapshot_for_update, load_desired_for_update,
    update_disk,
};
use super::rows::{load_any_volume_by_id_for_update, update_volume};
use super::runtime_spine::{
    load_placement_admission_at_in_checked, PlacementAdmissionLoad, PlacementAdmissionSnapshot,
};
use crate::store::agent_sessions::{
    load_identity_by_node_for_update, load_provisioned_identities_after,
    PROVISIONED_NODE_ID_PAGE_SIZE,
};
use crate::store::transaction::AuthorityTxResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PersistentDiskDeleteContext {
    pub(crate) authenticated_workspace_id: Id,
    pub(crate) disk_id: Id,
    pub(crate) delete_id: Id,
    pub(crate) active_guest_config_digest: Sha256Digest,
}

/// Atomically moves one unbound PersistentDisk and its Volume into the exact
/// same normal `Deleting(delete_id)` state.
///
/// The caller owns the API idempotency-key reservation and writes the exact
/// HTTP result in this transaction after this function returns.  It must pass
/// its covered cancellation checkpoint so cancellation is observed at every
/// lock/effect boundary.
pub(super) fn begin_persistent_disk_delete_in<F>(
    transaction: &mut Transaction<'_>,
    context: &PersistentDiskDeleteContext,
    checkpoint: &mut F,
) -> AuthorityTxResult<BeginDeleteResult>
where
    F: FnMut(&mut Transaction<'_>) -> AuthorityTxResult<()>,
{
    let admissions = lock_complete_fleet_inventory(
        transaction,
        &context.active_guest_config_digest,
        checkpoint,
    )?;

    checkpoint(transaction)?;
    let disk_hint = transaction.query_opt(
        "SELECT volume_id FROM disk_records WHERE disk_id=$1",
        &[&context.disk_id.as_str()],
    )?;
    let Some(disk_hint) = disk_hint else {
        return Err(AuthorityError::NotFound.into());
    };
    let hinted_volume = Id::new(disk_hint.try_get::<_, String>("volume_id")?)
        .ok_or(AuthorityError::BackendUnknown)?;

    // The global lock DAG places Volume before Control Disk. The unlocked
    // scalar lookup above is only an identity hint; both complete rows are
    // decoded and cross-checked after their canonical locks are held.
    checkpoint(transaction)?;
    let volume = load_any_volume_by_id_for_update(transaction, &hinted_volume)?
        .ok_or(AuthorityError::BackendUnknown)?;
    checkpoint(transaction)?;
    let mut disk = load_any_disk_by_id_for_update(transaction, &context.disk_id)?
        .ok_or(AuthorityError::BackendUnknown)?;

    if disk.workspace_id != context.authenticated_workspace_id
        || disk.disk_id != context.disk_id
        || disk.volume_id != volume.volume_id
        || disk.size_bytes != volume.size_bytes
        || disk.durability != volume.durability
        || !matches!(disk.role, DiskRole::Persistent { .. })
        || !matches!(disk.admin_state, DiskAdminState::Active)
        || !matches!(volume.admin_state, VolumeAdminState::Active)
    {
        return Err(AuthorityError::NotFound.into());
    }

    validate_absent_from_current_desired_and_inventory(
        &admissions,
        &disk.disk_id,
        &volume.volume_id,
    )?;

    checkpoint(transaction)?;
    lock_and_revalidate_desired_set(transaction, &admissions, &disk.disk_id, &volume.volume_id)?;
    checkpoint(transaction)?;
    if load_any_disk_snapshot_for_update(
        transaction,
        &disk.disk_id,
        &volume.volume_id,
        disk.size_bytes,
    )?
    .is_some()
    {
        return Err(AuthorityError::SnapshotInUse.into());
    }

    let request = BeginDeleteRequest {
        delete_id: context.delete_id.clone(),
        disk_id: disk.disk_id.clone(),
        volume_id: volume.volume_id.clone(),
        expected_unowned_epoch: volume.lease_epoch,
        expected_head: volume.head.clone(),
    };
    let (updated_volume, result) = begin_delete(&volume, &request)?;
    disk.admin_state = DiskAdminState::Deleting {
        delete_id: context.delete_id.clone(),
    };
    checkpoint(transaction)?;
    update_volume(transaction, &updated_volume)?;
    checkpoint(transaction)?;
    update_disk(transaction, &disk)?;
    Ok(result)
}

fn lock_complete_fleet_inventory<F>(
    transaction: &mut Transaction<'_>,
    active_guest_digest: &Sha256Digest,
    checkpoint: &mut F,
) -> AuthorityTxResult<Vec<PlacementAdmissionSnapshot>>
where
    F: FnMut(&mut Transaction<'_>) -> AuthorityTxResult<()>,
{
    // Close the phantom where a newly provisioned Node appears after fleet
    // inventory enumeration but before this delete commits.
    checkpoint(transaction)?;
    transaction.batch_execute("LOCK TABLE node_identities IN SHARE MODE")?;
    let mut identities = Vec::new();
    let mut after = None;
    loop {
        checkpoint(transaction)?;
        let page = load_provisioned_identities_after(transaction, after.as_ref())?;
        if page.is_empty() {
            break;
        }
        let page_full = page.len() == PROVISIONED_NODE_ID_PAGE_SIZE;
        after = page.last().map(|identity| identity.node_id.clone());
        identities.extend(page);
        if !page_full {
            break;
        }
    }

    // Lock every Node first in stable order, closing the absent Desired and
    // inventory race before any Volume or product row is touched.
    for identity in &identities {
        checkpoint(transaction)?;
        let locked = load_identity_by_node_for_update(transaction, &identity.node_id)?
            .ok_or(AuthorityError::BackendUnknown)?;
        if locked != *identity || locked.state != NodeIdentityState::Provisioned {
            return Err(AuthorityError::AdminBusy.into());
        }
    }

    let now = super::rows::database_now(transaction)?;
    let mut admissions = Vec::with_capacity(identities.len());
    for identity in identities {
        let admission = load_placement_admission_at_in_checked(
            transaction,
            &identity.node_id,
            active_guest_digest,
            now,
            checkpoint,
        )?;
        let PlacementAdmissionLoad::Accepted(admission) = admission else {
            return Err(AuthorityError::AdminBusy.into());
        };
        admissions.push(*admission);
    }
    Ok(admissions)
}

fn validate_absent_from_current_desired_and_inventory(
    admissions: &[PlacementAdmissionSnapshot],
    disk_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<()> {
    for admission in admissions {
        if admission.assigned_desired_specs.iter().any(|desired| {
            desired
                .volumes
                .iter()
                .any(|intent| intent.disk_id == *disk_id || intent.volume_id == *volume_id)
        }) || admission
            .full_inventory_observation
            .runtimes
            .iter()
            .any(|runtime| {
                runtime
                    .volumes
                    .iter()
                    .any(|volume| volume.volume_id == *volume_id)
                    || runtime
                        .mounts
                        .iter()
                        .any(|mount| mount.volume_id == *volume_id)
                    || runtime.processes.iter().any(|process| {
                        matches!(
                            &process.role,
                            cats_api::runtime_reconciliation::ProcessRole::Blockd {
                                volume_id: current,
                                ..
                            } if current == volume_id
                        )
                    })
            })
            || !admission.full_inventory_observation.residue.is_empty()
        {
            return Err(AuthorityError::AdminBusy.into());
        }
    }
    Ok(())
}

fn lock_and_revalidate_desired_set(
    transaction: &mut Transaction<'_>,
    admissions: &[PlacementAdmissionSnapshot],
    disk_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<()> {
    let expected: BTreeMap<&Id, _> = admissions
        .iter()
        .flat_map(|admission| admission.assigned_desired_specs.iter())
        .map(|desired| (&desired.cat_id, desired))
        .collect();
    let rows = transaction.query(
        "SELECT cat_id FROM desired_runtime_specs ORDER BY cat_id COLLATE \"C\" FOR UPDATE",
        &[],
    )?;
    if rows.len() != expected.len() {
        return Err(AuthorityError::AdminBusy.into());
    }
    for row in rows {
        let cat_id =
            Id::new(row.try_get::<_, String>("cat_id")?).ok_or(AuthorityError::BackendUnknown)?;
        let current =
            load_desired_for_update(transaction, &cat_id)?.ok_or(AuthorityError::BackendUnknown)?;
        if &current != expected[&cat_id]
            || current
                .volumes
                .iter()
                .any(|intent| intent.disk_id == *disk_id || intent.volume_id == *volume_id)
        {
            return Err(AuthorityError::AdminBusy.into());
        }
    }
    Ok(())
}

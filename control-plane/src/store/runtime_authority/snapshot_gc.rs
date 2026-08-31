//! PostgreSQL authority for offline, snapshot-aware volume garbage collection.
//!
//! A GC claim is a writer exclusion state, not a background hint. The claim is
//! committed before object-store work starts and every normal writer or
//! Snapshot mutation must reject `garbage_collecting`. This lets Control trace
//! and sweep outside the PostgreSQL transaction without relying on a blockd
//! process lock that cannot fence another Host.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    AsciiText, Generation, Id, RemoteHead, Sha256Digest, UnixMillis, VolumeAdminState,
    VolumeDurability, VolumeRecord,
};
use cats_storage::authority::{project_volume_record, validate_volume_record};
use postgres::{Row, Transaction};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result, Store};

use super::rows::database_now;

const VOLUME_COLUMNS: &str = "
    v.volume_id AS volume_id, v.record::text AS record_json,
    v.size_bytes AS size_bytes, v.durability AS durability,
    v.admin_state AS admin_state, v.delete_id AS delete_id,
    v.gc_required AS gc_required, v.gc_id AS gc_id,
    v.gc_roots_digest AS gc_roots_digest, v.gc_started_at AS gc_started_at,
    v.head_generation AS head_generation, v.head_root_hash AS head_root_hash,
    v.head_root_object_id AS head_root_object_id,
    v.lease_owner AS lease_owner, v.lease_epoch AS lease_epoch,
    v.lease_expires_at AS lease_expires_at,
    v.last_transition_kind AS last_transition_kind,
    v.last_transition_id AS last_transition_id,
    v.transition_placement_epoch AS transition_placement_epoch,
    v.transition_lease_duration_ms AS transition_lease_duration_ms";

/// One immutable root in the exact set protected by a GC claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotGcRoot {
    pub(crate) snapshot_id: Option<Id>,
    pub(crate) disk_id: Id,
    pub(crate) volume_id: Id,
    pub(crate) size_bytes: u64,
    pub(crate) head: RemoteHead,
}

/// Durable permit for one transaction-external mark and sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotGcClaim {
    pub(crate) gc_id: Id,
    pub(crate) roots_digest: Sha256Digest,
    pub(crate) started_at: UnixMillis,
    pub(crate) volume_id: Id,
    pub(crate) claimed_head: RemoteHead,
    /// Current root first, followed by live Snapshot roots in snapshot_id C
    /// order. The order is part of the digest contract.
    pub(crate) roots: Vec<SnapshotGcRoot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotGcSettlement {
    Settled,
    Stale,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshotRecord {
    snapshot_id: Id,
    disk_id: Id,
    volume_id: Id,
    size_bytes: u64,
    head: RemoteHead,
    created_at: UnixMillis,
}

impl Store {
    /// Claim or resume the next eligible Strict volume that needs GC.
    ///
    /// Eligibility is checked under the Volume row lock. Bound disks require a
    /// stable Cold Cat; an unbound initialized disk is also eligible. A prior
    /// `garbage_collecting` row is resumed with its original `gc_id`.
    pub(crate) fn claim_next_snapshot_gc(&self) -> Result<Option<SnapshotGcClaim>> {
        self.authority_transaction(|transaction| {
            let Some(row) = transaction.query_opt(
                &format!(
                    "SELECT {VOLUME_COLUMNS}, d.disk_id
                       FROM volume_records v
                       JOIN disk_records d ON d.volume_id=v.volume_id
                       JOIN persistent_disks p
                         ON p.disk_id=d.disk_id AND p.volume_id=v.volume_id
                       LEFT JOIN disk_bindings b ON b.disk_id=p.disk_id
                       LEFT JOIN cats c
                         ON c.cat_id=b.cat_id AND c.workspace_id=b.workspace_id
                      WHERE v.durability='strict'
                        AND v.lease_owner IS NULL
                        AND v.lease_expires_at IS NULL
                        AND v.owner_binding IS NULL
                        AND v.owner_node_id IS NULL
                        AND (
                            (v.admin_state='active' AND v.gc_required) OR
                            v.admin_state='garbage_collecting'
                        )
                        AND d.admin_state='active'
                        AND d.role_kind='persistent'
                        AND d.initialization_kind='initialized'
                        AND p.status='normal' AND p.deleted_at IS NULL
                        AND (
                            b.binding_id IS NULL OR
                            (c.state='cold' AND c.current_action IS NULL)
                        )
                      ORDER BY
                        (v.admin_state='garbage_collecting') DESC,
                        v.volume_id COLLATE \"C\"
                      LIMIT 1
                      FOR UPDATE OF v SKIP LOCKED"
                ),
                &[],
            )?
            else {
                return Ok(None);
            };

            let disk_id = parse_id(row.try_get::<_, String>("disk_id")?)?;
            let mut volume = decode_volume(&row)?;
            let mut roots = vec![SnapshotGcRoot {
                snapshot_id: None,
                disk_id: disk_id.clone(),
                volume_id: volume.volume_id.clone(),
                size_bytes: volume.size_bytes,
                head: volume.head.clone(),
            }];
            roots.extend(load_snapshot_roots(
                transaction,
                &disk_id,
                &volume.volume_id,
                volume.size_bytes,
            )?);
            let roots_digest = snapshot_gc_roots_digest(
                &volume.volume_id,
                volume.size_bytes,
                &volume.head,
                &roots[1..],
            )?;

            let (gc_id, started_at) = match &volume.admin_state {
                VolumeAdminState::Active if volume.gc_required => {
                    let gc_id = Id::new(format!("gc_{}", uuid::Uuid::new_v4().simple()))
                        .ok_or_else(corrupt_tx)?;
                    let started_at = database_now(transaction)?;
                    volume.admin_state = VolumeAdminState::GarbageCollecting {
                        gc_id: gc_id.clone(),
                        roots_digest: roots_digest.clone(),
                        started_at,
                    };
                    write_volume(transaction, &volume)?;
                    (gc_id, started_at)
                }
                VolumeAdminState::GarbageCollecting {
                    gc_id,
                    roots_digest: stored_digest,
                    started_at,
                } if stored_digest == &roots_digest => (gc_id.clone(), *started_at),
                _ => return Err(corrupt_tx()),
            };

            Ok(Some(SnapshotGcClaim {
                gc_id,
                roots_digest,
                started_at,
                volume_id: volume.volume_id,
                claimed_head: volume.head,
                roots,
            }))
        })
    }

    /// Clear a completed claim only if the exact head and full live Snapshot
    /// root set are still the ones swept by the worker.
    pub(crate) fn complete_snapshot_gc(
        &self,
        claim: &SnapshotGcClaim,
    ) -> Result<SnapshotGcSettlement> {
        self.authority_transaction(|transaction| {
            let Some(row) = lock_volume(transaction, &claim.volume_id)? else {
                return Ok(SnapshotGcSettlement::Stale);
            };
            let mut volume = decode_volume(&row)?;
            if !claim_matches(&volume, claim) {
                return Ok(SnapshotGcSettlement::Stale);
            }
            let disk_id = load_exact_disk_id(transaction, &volume.volume_id)?;
            let snapshots =
                load_snapshot_roots(transaction, &disk_id, &volume.volume_id, volume.size_bytes)?;
            let digest = snapshot_gc_roots_digest(
                &volume.volume_id,
                volume.size_bytes,
                &volume.head,
                &snapshots,
            )?;
            if digest != claim.roots_digest {
                return Ok(SnapshotGcSettlement::Stale);
            }
            volume.admin_state = VolumeAdminState::Active;
            volume.gc_required = false;
            write_volume(transaction, &volume)?;
            Ok(SnapshotGcSettlement::Settled)
        })
    }

    /// Abort an explicitly failed pass. Process death intentionally does not
    /// call this method: the durable claim remains for level-triggered resume.
    pub(crate) fn abort_snapshot_gc(
        &self,
        claim: &SnapshotGcClaim,
    ) -> Result<SnapshotGcSettlement> {
        self.authority_transaction(|transaction| {
            let Some(row) = lock_volume(transaction, &claim.volume_id)? else {
                return Ok(SnapshotGcSettlement::Stale);
            };
            let mut volume = decode_volume(&row)?;
            if !claim_matches(&volume, claim) {
                return Ok(SnapshotGcSettlement::Stale);
            }
            volume.admin_state = VolumeAdminState::Active;
            volume.gc_required = true;
            write_volume(transaction, &volume)?;
            Ok(SnapshotGcSettlement::Settled)
        })
    }
}

fn lock_volume(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> AuthorityTxResult<Option<Row>> {
    transaction
        .query_opt(
            &format!(
                "SELECT {VOLUME_COLUMNS}
                   FROM volume_records v
                  WHERE v.volume_id=$1
                  FOR UPDATE"
            ),
            &[&volume_id.as_str()],
        )
        .map_err(Into::into)
}

fn load_exact_disk_id(transaction: &mut Transaction<'_>, volume_id: &Id) -> AuthorityTxResult<Id> {
    let rows = transaction.query(
        "SELECT d.disk_id
           FROM disk_records d
           JOIN persistent_disks p
             ON p.disk_id=d.disk_id AND p.volume_id=d.volume_id
          WHERE d.volume_id=$1 AND d.admin_state='active'
            AND d.role_kind='persistent'
            AND p.status='normal' AND p.deleted_at IS NULL
          ORDER BY d.disk_id COLLATE \"C\"
          LIMIT 2
          FOR UPDATE OF d, p",
        &[&volume_id.as_str()],
    )?;
    if rows.len() != 1 {
        return Err(corrupt_tx());
    }
    parse_id(rows[0].try_get::<_, String>(0)?)
}

fn load_snapshot_roots(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
    volume_id: &Id,
    size_bytes: u64,
) -> AuthorityTxResult<Vec<SnapshotGcRoot>> {
    let rows = transaction.query(
        "SELECT snapshot_id, record::text AS record_json, disk_id, volume_id,
                size_bytes, head_generation, head_root_hash,
                head_root_object_id, created_at
           FROM disk_snapshot_records
          WHERE disk_id=$1 AND volume_id=$2
          ORDER BY snapshot_id COLLATE \"C\"
          FOR UPDATE",
        &[&disk_id.as_str(), &volume_id.as_str()],
    )?;
    rows.into_iter()
        .map(|row| decode_snapshot_root(&row, disk_id, volume_id, size_bytes))
        .collect()
}

fn decode_snapshot_root(
    row: &Row,
    disk_id: &Id,
    volume_id: &Id,
    expected_size: u64,
) -> AuthorityTxResult<SnapshotGcRoot> {
    let snapshot_id = parse_id(row.try_get::<_, String>("snapshot_id")?)?;
    let scalar_disk_id = parse_id(row.try_get::<_, String>("disk_id")?)?;
    let scalar_volume_id = parse_id(row.try_get::<_, String>("volume_id")?)?;
    let scalar_size = parse_u64(row.try_get::<_, i64>("size_bytes")?)?;
    let scalar_head = remote_head_from_row(row)?;
    let created_at =
        UnixMillis::new(parse_u64(row.try_get::<_, i64>("created_at")?)?).ok_or_else(corrupt_tx)?;
    let record_json: String = row.try_get("record_json")?;
    let record: StoredSnapshotRecord =
        serde_json::from_str(&record_json).map_err(|_| corrupt_tx())?;
    if record.snapshot_id != snapshot_id
        || record.disk_id != scalar_disk_id
        || record.volume_id != scalar_volume_id
        || record.size_bytes != scalar_size
        || record.head != scalar_head
        || record.created_at != created_at
        || &scalar_disk_id != disk_id
        || &scalar_volume_id != volume_id
        || scalar_size != expected_size
        || scalar_head.generation.get() == 0
    {
        return Err(corrupt_tx());
    }
    Ok(SnapshotGcRoot {
        snapshot_id: Some(snapshot_id),
        disk_id: scalar_disk_id,
        volume_id: scalar_volume_id,
        size_bytes: scalar_size,
        head: scalar_head,
    })
}

fn decode_volume(row: &Row) -> AuthorityTxResult<VolumeRecord> {
    let record_json: String = row.try_get("record_json")?;
    let record: VolumeRecord = serde_json::from_str(&record_json).map_err(|_| corrupt_tx())?;
    let projection = project_volume_record(&record).map_err(|_| corrupt_tx())?;
    let scalar_gc_started_at = row
        .try_get::<_, Option<i64>>("gc_started_at")?
        .map(parse_u64)
        .transpose()?
        .and_then(UnixMillis::new);
    let exact = row.try_get::<_, String>("volume_id")? == projection.volume_id
        && parse_u64(row.try_get::<_, i64>("size_bytes")?)? == projection.size_bytes
        && row.try_get::<_, String>("durability")? == projection.durability
        && row.try_get::<_, String>("admin_state")? == projection.admin_state
        && row.try_get::<_, Option<String>>("delete_id")? == projection.delete_id
        && row.try_get::<_, bool>("gc_required")? == projection.gc_required
        && row.try_get::<_, Option<String>>("gc_id")? == projection.gc_id
        && row.try_get::<_, Option<String>>("gc_roots_digest")? == projection.gc_roots_digest
        && scalar_gc_started_at == projection.gc_started_at
        && parse_u64(row.try_get::<_, i64>("head_generation")?)?
            == projection.head_generation.get()
        && row.try_get::<_, Option<String>>("head_root_hash")? == projection.head_root_hash
        && row.try_get::<_, Option<String>>("head_root_object_id")?
            == projection.head_root_object_id
        && row.try_get::<_, Option<String>>("lease_owner")? == projection.lease_owner
        && parse_u64(row.try_get::<_, i64>("lease_epoch")?)? == projection.lease_epoch.get()
        && row
            .try_get::<_, Option<i64>>("lease_expires_at")?
            .map(parse_u64)
            .transpose()?
            == projection.lease_expires_at.map(UnixMillis::get)
        && row
            .try_get::<_, Option<String>>("last_transition_kind")?
            .as_deref()
            == projection.last_transition_kind
        && row.try_get::<_, Option<String>>("last_transition_id")? == projection.last_transition_id
        && row
            .try_get::<_, Option<i64>>("transition_placement_epoch")?
            .map(parse_u64)
            .transpose()?
            == projection
                .transition_placement_epoch
                .map(|value| value.get())
        && row
            .try_get::<_, Option<i64>>("transition_lease_duration_ms")?
            .map(parse_u64)
            .transpose()?
            == projection.transition_lease_duration_ms;
    exact.then_some(record).ok_or_else(corrupt_tx)
}

fn remote_head_from_row(row: &Row) -> AuthorityTxResult<RemoteHead> {
    let generation = Generation::new(parse_u64(row.try_get::<_, i64>("head_generation")?)?)
        .ok_or_else(corrupt_tx)?;
    let root_hash = row
        .try_get::<_, Option<String>>("head_root_hash")?
        .map(|value| Sha256Digest::new(value).ok_or_else(corrupt_tx))
        .transpose()
        ?;
    let root_object_id = row
        .try_get::<_, Option<String>>("head_root_object_id")?
        .map(|value| AsciiText::new(value).ok_or_else(corrupt_tx))
        .transpose()
        ?;
    let head = RemoteHead {
        generation,
        root_hash,
        root_object_id,
    };
    if (head.generation.get() == 0) != head.root_hash.is_none()
        || head.root_hash.is_none() != head.root_object_id.is_none()
    {
        return Err(corrupt_tx());
    }
    Ok(head)
}

fn write_volume(transaction: &mut Transaction<'_>, record: &VolumeRecord) -> AuthorityTxResult<()> {
    validate_volume_record(record).map_err(|_| corrupt_tx())?;
    let projection = project_volume_record(record).map_err(|_| corrupt_tx())?;
    let record_json = serde_json::to_string(record).map_err(|_| corrupt_tx())?;
    let changed = transaction.execute(
        "UPDATE volume_records SET
            record=$2::TEXT::jsonb, size_bytes=$3, durability=$4,
            admin_state=$5, delete_id=$6, gc_required=$7, gc_id=$8,
            gc_roots_digest=$9, gc_started_at=$10,
            head_generation=$11, head_root_hash=$12,
            head_root_object_id=$13, lease_owner=$14, lease_epoch=$15,
            lease_expires_at=$16, last_transition_kind=$17,
            last_transition_id=$18, transition_placement_epoch=$19,
            transition_lease_duration_ms=$20
          WHERE volume_id=$1 AND owner_binding IS NULL AND owner_node_id IS NULL",
        &[
            &projection.volume_id,
            &record_json,
            &to_i64(projection.size_bytes)?,
            &projection.durability,
            &projection.admin_state,
            &projection.delete_id,
            &projection.gc_required,
            &projection.gc_id,
            &projection.gc_roots_digest,
            &projection
                .gc_started_at
                .map(|value| to_i64(value.get()))
                .transpose()?,
            &to_i64(projection.head_generation.get())?,
            &projection.head_root_hash,
            &projection.head_root_object_id,
            &projection.lease_owner,
            &to_i64(projection.lease_epoch.get())?,
            &projection
                .lease_expires_at
                .map(|value| to_i64(value.get()))
                .transpose()?,
            &projection.last_transition_kind,
            &projection.last_transition_id,
            &projection
                .transition_placement_epoch
                .map(|value| to_i64(value.get()))
                .transpose()?,
            &projection
                .transition_lease_duration_ms
                .map(to_i64)
                .transpose()?,
        ],
    )?;
    (changed == 1).then_some(()).ok_or_else(corrupt_tx)
}

fn claim_matches(volume: &VolumeRecord, claim: &SnapshotGcClaim) -> bool {
    volume.volume_id == claim.volume_id
        && volume.durability == VolumeDurability::Strict
        && volume.lease_owner.is_none()
        && volume.lease_expires_at.is_none()
        && volume.gc_required
        && volume.head == claim.claimed_head
        && matches!(
            &volume.admin_state,
            VolumeAdminState::GarbageCollecting {
                gc_id,
                roots_digest,
                started_at,
            } if gc_id == &claim.gc_id
                && roots_digest == &claim.roots_digest
                && started_at == &claim.started_at
        )
}

/// Stable product digest for the exact root set behind one GC permit.
pub(crate) fn snapshot_gc_roots_digest(
    volume_id: &Id,
    size_bytes: u64,
    current_head: &RemoteHead,
    snapshots: &[SnapshotGcRoot],
) -> AuthorityTxResult<Sha256Digest> {
    if current_head.generation.get() == 0
        || current_head.root_hash.is_none()
        || current_head.root_object_id.is_none()
        || snapshots.windows(2).any(|pair| {
            pair[0]
                .snapshot_id
                .as_ref()
                .map(Id::as_str)
                .unwrap_or_default()
                >= pair[1]
                    .snapshot_id
                    .as_ref()
                    .map(Id::as_str)
                    .unwrap_or_default()
        })
        || snapshots.iter().any(|snapshot| {
            snapshot.snapshot_id.is_none()
                || &snapshot.volume_id != volume_id
                || snapshot.size_bytes != size_bytes
                || snapshot.head.generation.get() == 0
                || snapshot.head.root_hash.is_none()
                || snapshot.head.root_object_id.is_none()
        })
    {
        return Err(corrupt_tx());
    }

    let mut digest = Sha256::new();
    digest.update(b"cats.volume-gc-roots.v1\0");
    frame(&mut digest, volume_id.as_str().as_bytes());
    frame_u64(&mut digest, size_bytes);
    frame_head(&mut digest, current_head);
    frame_u64(
        &mut digest,
        u64::try_from(snapshots.len()).map_err(|_| corrupt_tx())?,
    );
    for snapshot in snapshots {
        frame(
            &mut digest,
            snapshot
                .snapshot_id
                .as_ref()
                .expect("validated snapshot identity")
                .as_str()
                .as_bytes(),
        );
        frame(&mut digest, snapshot.disk_id.as_str().as_bytes());
        frame(&mut digest, snapshot.volume_id.as_str().as_bytes());
        frame_u64(&mut digest, snapshot.size_bytes);
        frame_head(&mut digest, &snapshot.head);
    }
    Sha256Digest::new(format!("sha256:{:x}", digest.finalize())).ok_or_else(corrupt_tx)
}

fn frame(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn frame_u64(digest: &mut Sha256, value: u64) {
    frame(digest, &value.to_be_bytes());
}

fn frame_head(digest: &mut Sha256, head: &RemoteHead) {
    frame_u64(digest, head.generation.get());
    match (&head.root_hash, &head.root_object_id) {
        (Some(root_hash), Some(root_object_id)) => {
            frame(digest, &[1]);
            frame(digest, root_hash.as_str().as_bytes());
            frame(digest, root_object_id.as_str().as_bytes());
        }
        (None, None) => frame(digest, &[0]),
        _ => {
            // An invalid head is rejected by Volume/Snapshot validation before
            // this helper is called. Keep a distinct impossible encoding so a
            // future caller cannot collide it with a valid blank head.
            frame(digest, &[0xff]);
        }
    }
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(corrupt_tx)
}

fn parse_u64(value: i64) -> AuthorityTxResult<u64> {
    u64::try_from(value).map_err(|_| corrupt_tx())
}

fn to_i64(value: u64) -> AuthorityTxResult<i64> {
    i64::try_from(value).map_err(|_| corrupt_tx())
}

fn corrupt_tx() -> AuthorityTransactionError {
    AuthorityTransactionError::Application(ApiError::internal(
        "snapshot GC authority found a corrupt or mismatched stored projection",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn head(generation: u64, byte: char) -> RemoteHead {
        RemoteHead {
            generation: Generation::new(generation).unwrap(),
            root_hash: Some(
                Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap(),
            ),
            root_object_id: Some(AsciiText::new(byte.to_string().repeat(64)).unwrap()),
        }
    }

    fn snapshot(snapshot_id: &str, generation: u64, byte: char) -> SnapshotGcRoot {
        SnapshotGcRoot {
            snapshot_id: Some(id(snapshot_id)),
            disk_id: id("disk_11111111111111111111111111111111"),
            volume_id: id("vol_22222222222222222222222222222222"),
            size_bytes: 4 * 1024 * 1024,
            head: head(generation, byte),
        }
    }

    #[test]
    fn root_digest_binds_current_and_every_sorted_snapshot_root() {
        let volume_id = id("vol_22222222222222222222222222222222");
        let first = snapshot("snapshot_11111111111111111111111111111111", 1, '2');
        let second = snapshot("snapshot_22222222222222222222222222222222", 2, '3');
        let digest = snapshot_gc_roots_digest(
            &volume_id,
            4 * 1024 * 1024,
            &head(3, '4'),
            &[first.clone(), second.clone()],
        )
        .unwrap();
        let changed_current = snapshot_gc_roots_digest(
            &volume_id,
            4 * 1024 * 1024,
            &head(4, '5'),
            &[first.clone(), second.clone()],
        )
        .unwrap();
        let changed_snapshot = snapshot_gc_roots_digest(
            &volume_id,
            4 * 1024 * 1024,
            &head(3, '4'),
            &[first, snapshot("snapshot_22222222222222222222222222222222", 3, '5')],
        )
        .unwrap();
        assert_ne!(digest, changed_current);
        assert_ne!(digest, changed_snapshot);
    }

    #[test]
    fn root_digest_rejects_an_unsorted_or_blank_retained_root() {
        let volume_id = id("vol_22222222222222222222222222222222");
        let first = snapshot("snapshot_11111111111111111111111111111111", 1, '2');
        let second = snapshot("snapshot_22222222222222222222222222222222", 2, '3');
        assert!(snapshot_gc_roots_digest(
            &volume_id,
            4 * 1024 * 1024,
            &head(3, '4'),
            &[second, first],
        )
        .is_err());
        assert!(snapshot_gc_roots_digest(
            &volume_id,
            4 * 1024 * 1024,
            &RemoteHead {
                generation: Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            &[],
        )
        .is_err());
    }
}

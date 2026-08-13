//! Repeatable-read composition for the public runtime Cat and Disk projections.

use cats_api::runtime_product_reads::{
    CatDesiredReadV2, CatObservedReadV2, CatReadV2, DiskReadAdminState, DiskReadBinding,
    DiskReadKind, DiskReadV2, ProductReadPage, ProductReadResource, RuntimeConditionKind,
};
use cats_api::runtime_reconciliation::{
    Condition, ContractVersion, DesiredRuntimeSpec, DiskKind, Durability, Id, VolumeDisposition,
};
use cats_storage::authority::VolumeDurability;
use postgres::{Row, Transaction};

use super::product::{CatRecord, DiskAdminState, DiskRecord, DiskRole};
use super::product_rows::{
    decode_cat, decode_desired, decode_disk, load_desired_unlocked, load_root_disk_by_cat_unlocked,
    CAT_COLUMNS, DESIRED_COLUMNS, DISK_COLUMNS,
};
use super::runtime_spine::load_product_cat_observation;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result as StoreResult, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductRead<T> {
    Found(Box<T>),
    NotFound,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductPageRead<T> {
    Found(ProductReadPage<T>),
    Corrupt,
}

impl Store {
    pub(crate) fn get_runtime_cat(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
    ) -> StoreResult<ProductRead<CatReadV2>> {
        self.authority_read_snapshot(|transaction| {
            let rows = exact_candidates(
                transaction,
                "cat_records",
                CAT_COLUMNS,
                "cat_id",
                workspace_id,
                cat_id,
            )?;
            if rows.len() != 1 {
                return Ok(if rows.is_empty() {
                    ProductRead::NotFound
                } else {
                    ProductRead::Corrupt
                });
            }
            let cat = match decode_cat(&rows[0]) {
                Ok(cat) if cat.workspace_id == *workspace_id && cat.cat_id == *cat_id => cat,
                _ => return Ok(ProductRead::Corrupt),
            };
            Ok(match compose_cat(transaction, cat) {
                Ok(cat) => ProductRead::Found(Box::new(cat)),
                Err(ComposeError::Corrupt) => ProductRead::Corrupt,
                Err(ComposeError::Store(error)) => return Err(error),
            })
        })
    }

    pub(crate) fn list_runtime_cats(
        &self,
        workspace_id: &Id,
        after: Option<&Id>,
        limit: usize,
    ) -> StoreResult<ProductPageRead<CatReadV2>> {
        self.authority_read_snapshot(|transaction| {
            let rows = list_candidates(
                transaction,
                "cat_records",
                CAT_COLUMNS,
                "cat_id",
                workspace_id,
                after,
                limit,
            )?;
            let has_more = rows.len() > limit;
            let mut items = Vec::with_capacity(rows.len());
            for row in &rows {
                let cat = match decode_cat(row) {
                    Ok(cat) if cat.workspace_id == *workspace_id => cat,
                    _ => return Ok(ProductPageRead::Corrupt),
                };
                match compose_cat(transaction, cat) {
                    Ok(cat) => items.push(cat),
                    Err(ComposeError::Corrupt) => return Ok(ProductPageRead::Corrupt),
                    Err(ComposeError::Store(error)) => return Err(error),
                }
            }
            items.truncate(limit);
            let next_cursor = has_more
                .then(|| items.last().map(|cat| cat.id.clone()))
                .flatten()
                .map(|id| {
                    cats_api::runtime_product_reads::encode_product_read_cursor(
                        ProductReadResource::Cats,
                        &id,
                    )
                });
            Ok(ProductPageRead::Found(ProductReadPage {
                items,
                next_cursor,
            }))
        })
    }

    pub(crate) fn get_runtime_disk(
        &self,
        workspace_id: &Id,
        disk_id: &Id,
    ) -> StoreResult<ProductRead<DiskReadV2>> {
        self.authority_read_snapshot(|transaction| {
            let rows = exact_candidates(
                transaction,
                "disk_records",
                DISK_COLUMNS,
                "disk_id",
                workspace_id,
                disk_id,
            )?;
            if rows.len() != 1 {
                return Ok(if rows.is_empty() {
                    ProductRead::NotFound
                } else {
                    ProductRead::Corrupt
                });
            }
            let disk = match decode_disk(&rows[0]) {
                Ok(disk) if disk.workspace_id == *workspace_id && disk.disk_id == *disk_id => disk,
                _ => return Ok(ProductRead::Corrupt),
            };
            Ok(match compose_disk(transaction, disk) {
                Ok(disk) => ProductRead::Found(Box::new(disk)),
                Err(ComposeError::Corrupt) => ProductRead::Corrupt,
                Err(ComposeError::Store(error)) => return Err(error),
            })
        })
    }

    pub(crate) fn list_runtime_disks(
        &self,
        workspace_id: &Id,
        after: Option<&Id>,
        limit: usize,
    ) -> StoreResult<ProductPageRead<DiskReadV2>> {
        self.authority_read_snapshot(|transaction| {
            let rows = list_candidates(
                transaction,
                "disk_records",
                DISK_COLUMNS,
                "disk_id",
                workspace_id,
                after,
                limit,
            )?;
            let has_more = rows.len() > limit;
            let mut items = Vec::with_capacity(rows.len());
            for row in &rows {
                let disk = match decode_disk(row) {
                    Ok(disk) if disk.workspace_id == *workspace_id => disk,
                    _ => return Ok(ProductPageRead::Corrupt),
                };
                match compose_disk(transaction, disk) {
                    Ok(disk) => items.push(disk),
                    Err(ComposeError::Corrupt) => return Ok(ProductPageRead::Corrupt),
                    Err(ComposeError::Store(error)) => return Err(error),
                }
            }
            items.truncate(limit);
            let next_cursor = has_more
                .then(|| items.last().map(|disk| disk.id.clone()))
                .flatten()
                .map(|id| {
                    cats_api::runtime_product_reads::encode_product_read_cursor(
                        ProductReadResource::Disks,
                        &id,
                    )
                });
            Ok(ProductPageRead::Found(ProductReadPage {
                items,
                next_cursor,
            }))
        })
    }
}

fn exact_candidates(
    transaction: &mut Transaction<'_>,
    table: &str,
    columns: &str,
    id_column: &str,
    workspace_id: &Id,
    id: &Id,
) -> AuthorityTxResult<Vec<Row>> {
    let sql = format!(
        "(SELECT {columns} FROM {table}
           WHERE workspace_id COLLATE \"C\"=$1 AND {id_column} COLLATE \"C\"=$2
           LIMIT 2)
         UNION ALL
         (SELECT {columns} FROM {table}
           WHERE workspace_id COLLATE \"C\"=$1
             AND (record->>'{id_column}') COLLATE \"C\"=$2
             AND {id_column} COLLATE \"C\"<>$2
             AND {id_column} COLLATE \"C\" IS DISTINCT FROM
                 (record->>'{id_column}') COLLATE \"C\"
           LIMIT 2)
         UNION ALL
         (SELECT {columns} FROM {table}
           WHERE (record->>'workspace_id') COLLATE \"C\"=$1
             AND {id_column} COLLATE \"C\"=$2
             AND workspace_id COLLATE \"C\"<>$1
             AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                 (record->>'workspace_id') COLLATE \"C\"
           LIMIT 2)
         UNION ALL
         (SELECT {columns} FROM {table}
           WHERE (record->>'workspace_id') COLLATE \"C\"=$1
             AND (record->>'{id_column}') COLLATE \"C\"=$2
             AND workspace_id COLLATE \"C\"<>$1
             AND {id_column} COLLATE \"C\"<>$2
             AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                 (record->>'workspace_id') COLLATE \"C\"
             AND {id_column} COLLATE \"C\" IS DISTINCT FROM
                 (record->>'{id_column}') COLLATE \"C\"
           LIMIT 2)"
    );
    transaction
        .query(&sql, &[&workspace_id.as_str(), &id.as_str()])
        .map_err(Into::into)
}

fn list_candidates(
    transaction: &mut Transaction<'_>,
    table: &str,
    columns: &str,
    id_column: &str,
    workspace_id: &Id,
    after: Option<&Id>,
    limit: usize,
) -> AuthorityTxResult<Vec<Row>> {
    let after = after.map(Id::as_str).unwrap_or("");
    let fetch = i64::try_from(limit.saturating_add(1)).map_err(corrupt)?;
    let sql = format!(
        "SELECT * FROM (
           SELECT candidates.*,
                  row_number() OVER (
                    PARTITION BY {id_column}
                    ORDER BY candidate_id COLLATE \"C\"
                  ) AS candidate_rank
             FROM (
           (SELECT {columns}, {id_column} AS candidate_id FROM {table}
             WHERE workspace_id COLLATE \"C\"=$1
               AND {id_column} COLLATE \"C\">$2
             ORDER BY {id_column} COLLATE \"C\" LIMIT $3)
           UNION ALL
           (SELECT {columns}, (record->>'{id_column}') AS candidate_id FROM {table}
             WHERE workspace_id COLLATE \"C\"=$1
               AND (record->>'{id_column}') COLLATE \"C\">$2
               AND {id_column} COLLATE \"C\" IS DISTINCT FROM
                   (record->>'{id_column}') COLLATE \"C\"
             ORDER BY (record->>'{id_column}') COLLATE \"C\" LIMIT $3)
           UNION ALL
           (SELECT {columns}, {id_column} AS candidate_id FROM {table}
             WHERE (record->>'workspace_id') COLLATE \"C\"=$1
               AND workspace_id COLLATE \"C\"<>$1
               AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                   (record->>'workspace_id') COLLATE \"C\"
               AND {id_column} COLLATE \"C\">$2
             ORDER BY {id_column} COLLATE \"C\" LIMIT $3)
           UNION ALL
           (SELECT {columns}, (record->>'{id_column}') AS candidate_id FROM {table}
             WHERE (record->>'workspace_id') COLLATE \"C\"=$1
               AND workspace_id COLLATE \"C\"<>$1
               AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                   (record->>'workspace_id') COLLATE \"C\"
               AND (record->>'{id_column}') COLLATE \"C\">$2
               AND {id_column} COLLATE \"C\" IS DISTINCT FROM
                   (record->>'{id_column}') COLLATE \"C\"
             ORDER BY (record->>'{id_column}') COLLATE \"C\" LIMIT $3)
             ) candidates
         ) ranked
         WHERE candidate_rank=1
         ORDER BY candidate_id COLLATE \"C\", {id_column} COLLATE \"C\"
         LIMIT $3"
    );
    transaction
        .query(&sql, &[&workspace_id.as_str(), &after, &fetch])
        .map_err(Into::into)
}

fn compose_cat(
    transaction: &mut Transaction<'_>,
    cat: CatRecord,
) -> std::result::Result<CatReadV2, ComposeError> {
    let desired = projection_result(load_desired_unlocked(transaction, &cat.cat_id))?;
    let desired = desired.ok_or(ComposeError::Corrupt)?;
    if desired.cat_id != cat.cat_id || desired.workspace_id != cat.workspace_id {
        return Err(ComposeError::Corrupt);
    }
    let roots: Vec<_> = desired
        .volumes
        .iter()
        .filter(|volume| volume.disk_kind == DiskKind::Root)
        .collect();
    let [root] = roots.as_slice() else {
        return Err(ComposeError::Corrupt);
    };
    let root_record = projection_result(load_root_disk_by_cat_unlocked(transaction, &cat.cat_id))?
        .ok_or(ComposeError::Corrupt)?;
    if root_record.workspace_id != cat.workspace_id
        || root_record.disk_id != root.disk_id
        || root_record.volume_id != root.volume_id
        || root_record.size_bytes != root.size_bytes
        || durability(root_record.durability) != root.durability
    {
        return Err(ComposeError::Corrupt);
    }
    let observed = projection_result(load_product_cat_observation(
        transaction,
        &desired.placement.node_id,
        &cat.cat_id,
    ))?
    .map(|(runtime, accepted_at_unix_ms)| CatObservedReadV2 {
        applied_desired_revision: runtime
            .applied_desired
            .map(|evidence| evidence.desired_revision),
        stable_state: runtime.stable_state,
        conditions: runtime.conditions.iter().map(condition_kind).collect(),
        accepted_at_unix_ms,
    });
    Ok(CatReadV2 {
        version: ContractVersion::V1,
        id: cat.cat_id,
        workspace_id: cat.workspace_id,
        name: cat.name,
        created_at_unix_ms: cat.created_at,
        desired: CatDesiredReadV2 {
            revision: desired.desired_revision,
            target: desired.target,
            node_id: desired.placement.node_id,
            vcpus: desired.runtime.vcpus,
            memory_bytes: desired.runtime.memory_bytes,
            boot_image_digest: desired.runtime.boot_image_digest,
            root_disk_id: root.disk_id.clone(),
        },
        observed,
    })
}

fn compose_disk(
    transaction: &mut Transaction<'_>,
    disk: DiskRecord,
) -> std::result::Result<DiskReadV2, ComposeError> {
    let kind = match &disk.role {
        DiskRole::Root { cat_id } => DiskReadKind::Root {
            cat_id: cat_id.clone(),
        },
        DiskRole::Persistent { .. } => DiskReadKind::Persistent,
    };
    let binding = binding_for_disk(transaction, &disk)?;
    Ok(DiskReadV2 {
        version: ContractVersion::V1,
        id: disk.disk_id,
        workspace_id: disk.workspace_id,
        name: disk.name,
        size_bytes: disk.size_bytes,
        durability: durability(disk.durability),
        created_at_unix_ms: disk.created_at,
        kind,
        admin_state: match disk.admin_state {
            DiskAdminState::Active => DiskReadAdminState::Active,
            DiskAdminState::Deleting { .. } => DiskReadAdminState::Deleting,
        },
        binding,
    })
}

fn binding_for_disk(
    transaction: &mut Transaction<'_>,
    disk: &DiskRecord,
) -> std::result::Result<Option<DiskReadBinding>, ComposeError> {
    let desired: Vec<_> = match &disk.role {
        DiskRole::Root { cat_id } => projection_result(load_desired_unlocked(transaction, cat_id))?
            .into_iter()
            .collect(),
        DiskRole::Persistent { .. } => desired_claiming_disk(transaction, &disk.disk_id)?,
    };
    if desired.len() > 1 {
        return Err(ComposeError::Corrupt);
    }
    let Some(desired) = desired.into_iter().next() else {
        return match &disk.role {
            DiskRole::Root { .. } => Err(ComposeError::Corrupt),
            DiskRole::Persistent { .. } => Ok(None),
        };
    };
    if desired.workspace_id != disk.workspace_id {
        return Err(ComposeError::Corrupt);
    }
    let intents: Vec<_> = desired
        .volumes
        .iter()
        .filter(|intent| intent.disk_id == disk.disk_id)
        .collect();
    let [intent] = intents.as_slice() else {
        return Err(ComposeError::Corrupt);
    };
    let expected_kind = match &disk.role {
        DiskRole::Root { .. } => DiskKind::Root,
        DiskRole::Persistent { .. } => DiskKind::Persistent,
    };
    if intent.disk_kind != expected_kind
        || intent.volume_id != disk.volume_id
        || intent.size_bytes != disk.size_bytes
        || intent.durability != durability(disk.durability)
    {
        return Err(ComposeError::Corrupt);
    }
    if !matches!(&intent.disposition, VolumeDisposition::Retain) {
        return Ok(None);
    }
    Ok(Some(DiskReadBinding {
        cat_id: desired.cat_id,
        desired_revision: desired.desired_revision,
    }))
}

fn desired_claiming_disk(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
) -> std::result::Result<Vec<DesiredRuntimeSpec>, ComposeError> {
    let needle = serde_json::json!([{ "disk_id": disk_id }]).to_string();
    let sql = format!(
        "SELECT {DESIRED_COLUMNS} FROM desired_runtime_specs
          WHERE (record->'volumes') @> $1::TEXT::jsonb
          ORDER BY cat_id COLLATE \"C\" LIMIT 2"
    );
    let rows = transaction
        .query(&sql, &[&needle])
        .map_err(AuthorityTransactionError::from)
        .map_err(ComposeError::Store)?;
    rows.iter()
        .map(|row| decode_desired(row).map_err(|_| ComposeError::Corrupt))
        .collect()
}

enum ComposeError {
    Corrupt,
    Store(AuthorityTransactionError),
}

fn projection_result<T>(result: AuthorityTxResult<T>) -> std::result::Result<T, ComposeError> {
    match result {
        Ok(value) => Ok(value),
        Err(error @ AuthorityTransactionError::Postgres(_)) => Err(ComposeError::Store(error)),
        Err(_) => Err(ComposeError::Corrupt),
    }
}

fn durability(value: VolumeDurability) -> Durability {
    match value {
        VolumeDurability::Strict => Durability::Strict,
        VolumeDurability::Relaxed => Durability::Relaxed,
    }
}

fn condition_kind(condition: &Condition) -> RuntimeConditionKind {
    match condition {
        Condition::Ready { .. } => RuntimeConditionKind::Ready,
        Condition::Progressing { .. } => RuntimeConditionKind::Progressing,
        Condition::Blocked { .. } => RuntimeConditionKind::Blocked,
        Condition::PreconditionFailed { .. } => RuntimeConditionKind::PreconditionFailed,
        Condition::Degraded { .. } => RuntimeConditionKind::Degraded,
        Condition::Quarantined { .. } => RuntimeConditionKind::Quarantined,
        Condition::DataLossPossible { .. } => RuntimeConditionKind::DataLossPossible,
    }
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

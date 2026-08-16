//! Repeatable-read composition for public runtime product projections.

use std::collections::BTreeSet;

use cats_api::runtime_product_reads::{
    CatDesiredReadV2, CatObservedReadV2, CatReadV2, DiskReadAdminState, DiskReadBinding,
    DiskReadKind, DiskReadV2, EndpointCollectionReadV2, EndpointReadV2, EndpointReadWakePolicy,
    ProductReadPage, ProductReadResource, RuntimeConditionKind, ENDPOINT_READ_MAX_ITEMS,
};
use cats_api::runtime_reconciliation::{
    AuthorizationConsumedReceipt, AuthorizationState, Condition, ContractVersion,
    DeleteCompletionReceipt, DesiredRuntimeSpec, DiskKind, Durability, Id, Revision, RuntimeTarget,
    VolumeAuthorization, VolumeDisposition,
};
use cats_storage::authority::VolumeDurability;
use postgres::{Row, Transaction};

use super::product::{CatRecord, DiskAdminState, DiskRecord, DiskRole};
use super::product_rows::{
    decode_cat, decode_desired, decode_disk, decode_endpoint, load_cat_by_id_unlocked,
    load_desired_unlocked, CAT_COLUMNS, DESIRED_COLUMNS, DISK_COLUMNS, ENDPOINT_COLUMNS,
};
use super::rows::{
    load_disposable_root_graph_authorizations, load_root_delete_completion_candidates,
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

/// The existing product facts needed to attribute one usage checkpoint.
/// DesiredRuntimeSpec remains the sole placement/generation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeUsageCatRead {
    pub(crate) workspace_id: Id,
    pub(crate) desired_revision: Revision,
    pub(crate) node_id: Id,
}

impl Store {
    pub(crate) fn get_runtime_cat_for_usage(
        &self,
        cat_id: &Id,
    ) -> StoreResult<Option<RuntimeUsageCatRead>> {
        self.authority_read_snapshot(|transaction| {
            let Some(cat) = load_cat_by_id_unlocked(transaction, cat_id)? else {
                return Ok(None);
            };
            let desired = load_desired_unlocked(transaction, cat_id)?
                .ok_or_else(|| corrupt("runtime Cat has no DesiredRuntimeSpec"))?;
            if cat.cat_id != *cat_id
                || desired.cat_id != cat.cat_id
                || desired.workspace_id != cat.workspace_id
            {
                return Err(corrupt("runtime Cat/Desired usage projection mismatch"));
            }
            Ok(Some(RuntimeUsageCatRead {
                workspace_id: cat.workspace_id,
                desired_revision: desired.desired_revision,
                node_id: desired.placement.node_id,
            }))
        })
    }

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

    pub(crate) fn list_runtime_endpoints(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
    ) -> StoreResult<ProductRead<EndpointCollectionReadV2>> {
        self.authority_read_snapshot(|transaction| {
            let cat_rows = exact_candidates(
                transaction,
                "cat_records",
                CAT_COLUMNS,
                "cat_id",
                workspace_id,
                cat_id,
            )?;
            if cat_rows.len() != 1 {
                return Ok(if cat_rows.is_empty() {
                    ProductRead::NotFound
                } else {
                    ProductRead::Corrupt
                });
            }
            let cat = match decode_cat(&cat_rows[0]) {
                Ok(cat) if cat.workspace_id == *workspace_id && cat.cat_id == *cat_id => cat,
                _ => return Ok(ProductRead::Corrupt),
            };
            let desired_rows = exact_candidates(
                transaction,
                "desired_runtime_specs",
                DESIRED_COLUMNS,
                "cat_id",
                workspace_id,
                cat_id,
            )?;
            let [desired_row] = desired_rows.as_slice() else {
                return Ok(ProductRead::Corrupt);
            };
            let desired = match decode_desired(desired_row) {
                Ok(desired)
                    if desired.workspace_id == cat.workspace_id && desired.cat_id == cat.cat_id =>
                {
                    desired
                }
                _ => return Ok(ProductRead::Corrupt),
            };
            Ok(match compose_endpoints(transaction, desired) {
                Ok(endpoints) => ProductRead::Found(Box::new(endpoints)),
                Err(ComposeError::Corrupt) => ProductRead::Corrupt,
                Err(ComposeError::Store(error)) => return Err(error),
            })
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
    let root_candidates = root_disk_candidates(transaction, &cat, root)?;
    match root_candidates.as_slice() {
        [root_record]
            if root_record.workspace_id == cat.workspace_id
                && root_record.disk_id == root.disk_id
                && root_record.volume_id == root.volume_id
                && root_record.size_bytes == root.size_bytes
                && durability(root_record.durability) == root.durability => {}
        [] => completed_root_sweep(transaction, &desired, root)?,
        _ => return Err(ComposeError::Corrupt),
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

fn compose_endpoints(
    transaction: &mut Transaction<'_>,
    desired: DesiredRuntimeSpec,
) -> std::result::Result<EndpointCollectionReadV2, ComposeError> {
    if desired.endpoints.len() > ENDPOINT_READ_MAX_ITEMS {
        return Err(ComposeError::Corrupt);
    }
    let workspace_id = desired.workspace_id.clone();
    let cat_id = desired.cat_id.clone();
    let desired_revision = desired.desired_revision;
    let mut names = BTreeSet::new();
    let mut items = Vec::with_capacity(desired.endpoints.len());
    for intent in desired.endpoints {
        let rows = projection_result(exact_candidates(
            transaction,
            "endpoint_records",
            ENDPOINT_COLUMNS,
            "endpoint_id",
            &workspace_id,
            &intent.endpoint_id,
        ))?;
        let [row] = rows.as_slice() else {
            return Err(ComposeError::Corrupt);
        };
        let record = projection_result(decode_endpoint(row))?;
        if record.endpoint_id != intent.endpoint_id
            || record.workspace_id != workspace_id
            || record.cat_id != cat_id
            || !names.insert(record.name.clone())
        {
            return Err(ComposeError::Corrupt);
        }
        items.push(EndpointReadV2 {
            version: ContractVersion::V1,
            endpoint_id: intent.endpoint_id,
            name: record.name,
            hostname: intent.hostname,
            target_port: intent.target_port,
            protocol: intent.protocol,
            wake_policy: EndpointReadWakePolicy::Disabled,
            route_epoch: intent.route_epoch,
        });
    }
    items.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    if items
        .windows(2)
        .any(|pair| pair[0].endpoint_id >= pair[1].endpoint_id)
    {
        return Err(ComposeError::Corrupt);
    }
    Ok(EndpointCollectionReadV2 {
        version: ContractVersion::V1,
        cat_id,
        desired_revision,
        complete: true,
        items,
    })
}

fn root_disk_candidates(
    transaction: &mut Transaction<'_>,
    cat: &CatRecord,
    root: &cats_api::runtime_reconciliation::VolumeIntent,
) -> std::result::Result<Vec<DiskRecord>, ComposeError> {
    let sql = format!(
        "WITH candidate_ids AS MATERIALIZED (
            (SELECT disk_id FROM disk_records
              WHERE workspace_id COLLATE \"C\"=$1
                AND disk_id COLLATE \"C\"=$2 LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE workspace_id COLLATE \"C\"=$1
                AND (record->>'disk_id') COLLATE \"C\"=$2
                AND disk_id COLLATE \"C\" IS DISTINCT FROM
                    (record->>'disk_id') COLLATE \"C\" LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE (record->>'workspace_id') COLLATE \"C\"=$1
                AND disk_id COLLATE \"C\"=$2
                AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                    (record->>'workspace_id') COLLATE \"C\" LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE (record->>'workspace_id') COLLATE \"C\"=$1
                AND (record->>'disk_id') COLLATE \"C\"=$2
                AND workspace_id COLLATE \"C\" IS DISTINCT FROM
                    (record->>'workspace_id') COLLATE \"C\"
                AND disk_id COLLATE \"C\" IS DISTINCT FROM
                    (record->>'disk_id') COLLATE \"C\" LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE root_cat_id=$3 LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE volume_id=$4 LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE record->'role'->>'cat_id'=$3 LIMIT 2)
            UNION
            (SELECT disk_id FROM disk_records
              WHERE record->>'volume_id'=$4 LIMIT 2)
         )
         SELECT {DISK_COLUMNS} FROM disk_records
          WHERE disk_id IN (SELECT disk_id FROM candidate_ids)
          ORDER BY disk_id COLLATE \"C\" LIMIT 2"
    );
    let rows = transaction
        .query(
            &sql,
            &[
                &cat.workspace_id.as_str(),
                &root.disk_id.as_str(),
                &cat.cat_id.as_str(),
                &root.volume_id.as_str(),
            ],
        )
        .map_err(AuthorityTransactionError::from)
        .map_err(ComposeError::Store)?;
    rows.iter()
        .map(|row| decode_disk(row).map_err(|_| ComposeError::Corrupt))
        .collect()
}

fn completed_root_sweep(
    transaction: &mut Transaction<'_>,
    desired: &DesiredRuntimeSpec,
    root: &cats_api::runtime_reconciliation::VolumeIntent,
) -> std::result::Result<(), ComposeError> {
    if desired.target != RuntimeTarget::Deleted {
        return Err(ComposeError::Corrupt);
    }
    let VolumeDisposition::DeleteDisposableRoot { delete_id } = &root.disposition else {
        return Err(ComposeError::Corrupt);
    };
    if deleted_root_volume_still_reachable(transaction, &root.volume_id, delete_id)? {
        return Err(ComposeError::Corrupt);
    }
    let completions = projection_result(load_root_delete_completion_candidates(
        transaction,
        delete_id,
        &root.disk_id,
        &root.volume_id,
    ))?;
    let [completion] = completions.as_slice() else {
        return Err(ComposeError::Corrupt);
    };
    let DeleteCompletionReceipt::DisposableRoot {
        disk_id,
        volume_id,
        delete_id: completed_delete_id,
        authorization_id,
        prior_attachment_id,
        deleting_epoch,
        deleting_head,
        completed_at,
    } = completion
    else {
        let DeleteCompletionReceipt::Normal { request, .. } = completion else {
            unreachable!()
        };
        return if request.delete_id == *delete_id
            && request.disk_id == root.disk_id
            && request.volume_id == root.volume_id
        {
            Ok(())
        } else {
            Err(ComposeError::Corrupt)
        };
    };
    if disk_id != &root.disk_id
        || volume_id != &root.volume_id
        || completed_delete_id != delete_id
        || prior_attachment_id != &root.attachment_id
    {
        return Err(ComposeError::Corrupt);
    }
    let authorizations = projection_result(load_disposable_root_graph_authorizations(
        transaction,
        authorization_id,
        &root.volume_id,
        delete_id,
        desired.desired_revision,
        desired.placement.placement_epoch,
    ))?;
    let [authorization] = authorizations.as_slice() else {
        return Err(ComposeError::Corrupt);
    };
    let (
        VolumeAuthorization::DisposableRootDelete(authorization),
        AuthorizationState::Consumed(consumed),
    ) = (&authorization.authorization, &authorization.state)
    else {
        return Err(ComposeError::Corrupt);
    };
    let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref() else {
        return Err(ComposeError::Corrupt);
    };
    if authorization.authorization_id != *authorization_id
        || authorization.authorized_node_id != desired.placement.node_id
        || authorization.delete_id != *delete_id
        || authorization.disk_id != root.disk_id
        || authorization.volume_id != root.volume_id
        || authorization.cat_id != desired.cat_id
        || authorization.desired_revision != desired.desired_revision
        || authorization.placement_epoch != desired.placement.placement_epoch
        || authorization.expected_attachment_id != root.attachment_id
        || consumed.authorization_id != authorization.authorization_id
        || consumed.delete_id != authorization.delete_id
        || consumed.disk_id != authorization.disk_id
        || consumed.volume_id != authorization.volume_id
        || consumed.cat_id != authorization.cat_id
        || consumed.prior_attachment_id != authorization.expected_attachment_id
        || consumed.prior_attachment_id != *prior_attachment_id
        || consumed.resulting_head != authorization.expected_head
        || authorization.expected_epoch.get().checked_add(1) != Some(consumed.resulting_epoch.get())
        || consumed.resulting_epoch != *deleting_epoch
        || consumed.resulting_head != *deleting_head
        || consumed.consumed_at > *completed_at
    {
        return Err(ComposeError::Corrupt);
    }
    Ok(())
}

fn deleted_root_volume_still_reachable(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
    delete_id: &Id,
) -> std::result::Result<bool, ComposeError> {
    // Completion means the Volume row is gone, not merely hidden behind a
    // drifted scalar projection. Cover both immutable identity projections and
    // both delete-lineage projections in the same repeatable-read snapshot as
    // the authorization and completion graph.
    let row = transaction
        .query_one(
            "SELECT EXISTS (
                (SELECT 1 FROM volume_records WHERE volume_id=$1 LIMIT 1)
                UNION ALL
                (SELECT 1 FROM volume_records
                  WHERE record->>'volume_id'=$1 LIMIT 1)
                UNION ALL
                (SELECT 1 FROM volume_records
                  WHERE COALESCE(delete_id, '')=$2 LIMIT 1)
                UNION ALL
                (SELECT 1 FROM volume_records
                  WHERE record->'admin_state'->>'delete_id'=$2 LIMIT 1)
             )",
            &[&volume_id.as_str(), &delete_id.as_str()],
        )
        .map_err(AuthorityTransactionError::from)
        .map_err(ComposeError::Store)?;
    Ok(row.get(0))
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

//! Repeatable-read public projections over the atomic v17 product catalog.
//!
//! Lifecycle state comes only from the Cat's exact terminal Operation
//! projection. Runtime inventory is optional telemetry and is never used to
//! manufacture a stable state, placement, or Operation result.

use std::collections::BTreeSet;

use cats_api::runtime_lifecycle::{
    decode_immutable_runtime_config, LifecycleOperationState, LifecycleTerminalResult, NodeResult,
};
use cats_api::runtime_product_reads::{
    CatLifecycleReadV2, CatObservedReadV2, CatReadV2, CatStableStateReadV2, DiskReadAdminState,
    DiskReadBinding, DiskReadKind, DiskReadV2, EndpointCollectionReadV2, EndpointReadBinding,
    EndpointReadV2, ProductReadPage, ProductReadResource, ENDPOINT_READ_MAX_ITEMS,
};
use cats_api::runtime_reconciliation::{
    ContractVersion, Durability, Epoch, Hostname, HttpProtocol, Id, RandomId128, Sha256Digest,
    UnixMillis,
};
use cats_storage::authority::VolumeDurability;
use postgres::{Row, Transaction};

use super::lifecycle_commands::load_operation_unlocked;
use super::pg_codec::PgBigInt;
use super::runtime_spine::load_current_cat_telemetry_unlocked;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result as StoreResult, Store};

const CAT_READ_COLUMNS: &str = "
    cat_id, record::text AS record_json, workspace_id, name, created_at,
    lifecycle_head_operation_id, stable_state,
    effective_runtime_ready_operation_id, runtime_incarnation,
    current_runtime_config_id, current_runtime_config_sha256, deleted_at";
const DISK_READ_COLUMNS: &str = "
    disk_id, record::text AS record_json, workspace_id, name, volume_id,
    size_bytes, durability, created_at, admin_state, delete_id,
    role_kind, root_cat_id";
const ENDPOINT_READ_COLUMNS: &str = "
    endpoint_id, record::text AS record_json, workspace_id, cat_id, name,
    binding_state, hostname, protocol, target_port, route_epoch, created_at";

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

#[derive(Debug, Clone)]
struct CatProductRow {
    cat_id: Id,
    workspace_id: Id,
    name: Id,
    created_at: UnixMillis,
    lifecycle_head_operation_id: Option<Id>,
    stable_state: Option<CatStableStateReadV2>,
    effective_runtime_ready_operation_id: Option<Id>,
    runtime_incarnation: Option<RandomId128>,
    current_runtime_config_id: Id,
    current_runtime_config_digest: Sha256Digest,
    deleted_at: Option<UnixMillis>,
}

#[derive(Debug, Clone)]
struct DiskProductRow {
    disk_id: Id,
    workspace_id: Id,
    name: Id,
    volume_id: Id,
    size_bytes: u64,
    durability: VolumeDurability,
    created_at: UnixMillis,
    admin_state: DiskReadAdminState,
    role: DiskProductRole,
}

#[derive(Debug, Clone)]
enum DiskProductRole {
    Root { cat_id: Id },
    Persistent,
}

impl Store {
    pub(crate) fn resolve_runtime_cat_id(
        &self,
        workspace_id: &Id,
        name_or_id: &Id,
    ) -> StoreResult<ProductRead<Id>> {
        self.authority_read_snapshot(|transaction| {
            let rows = transaction.query(
                "SELECT cat_id FROM cat_records
                  WHERE workspace_id=$1 AND deleted_at IS NULL
                    AND (cat_id=$2 OR name=$2)
                  LIMIT 2",
                &[&workspace_id.as_str(), &name_or_id.as_str()],
            )?;
            match rows.as_slice() {
                [] => Ok(ProductRead::NotFound),
                [row] => match Id::new(row.try_get::<_, String>("cat_id")?) {
                    Some(cat_id) => Ok(ProductRead::Found(Box::new(cat_id))),
                    None => Ok(ProductRead::Corrupt),
                },
                _ => Ok(ProductRead::Corrupt),
            }
        })
    }

    pub(crate) fn get_runtime_cat(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
    ) -> StoreResult<ProductRead<CatReadV2>> {
        self.authority_read_snapshot(|transaction| {
            let rows = transaction.query(
                &format!(
                    "SELECT {CAT_READ_COLUMNS} FROM cat_records
                      WHERE workspace_id=$1 AND cat_id=$2 LIMIT 2"
                ),
                &[&workspace_id.as_str(), &cat_id.as_str()],
            )?;
            if rows.len() != 1 {
                return Ok(if rows.is_empty() {
                    ProductRead::NotFound
                } else {
                    ProductRead::Corrupt
                });
            }
            let row = match decode_cat_row(&rows[0]) {
                Ok(row) if row.workspace_id == *workspace_id && row.cat_id == *cat_id => row,
                _ => return Ok(ProductRead::Corrupt),
            };
            compose_cat(transaction, row)
                .map(|cat| ProductRead::Found(Box::new(cat)))
                .or_else(|error| match error {
                    AuthorityTransactionError::Application(_) => Ok(ProductRead::Corrupt),
                    error => Err(error),
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
            let after = after.map(Id::as_str).unwrap_or("");
            let query_limit = i64::try_from(limit.saturating_add(1))
                .map_err(|_| corrupt("Cat read page limit is too large"))?;
            let rows = transaction.query(
                &format!(
                    "SELECT {CAT_READ_COLUMNS} FROM cat_records
                      WHERE workspace_id=$1 AND cat_id COLLATE \"C\" > $2
                      ORDER BY cat_id COLLATE \"C\" LIMIT $3"
                ),
                &[&workspace_id.as_str(), &after, &query_limit],
            )?;
            let has_more = rows.len() > limit;
            let mut items = Vec::with_capacity(rows.len().min(limit));
            for row in rows.iter().take(limit) {
                let row = match decode_cat_row(row) {
                    Ok(row) if row.workspace_id == *workspace_id => row,
                    _ => return Ok(ProductPageRead::Corrupt),
                };
                let cat = match compose_cat(transaction, row) {
                    Ok(cat) => cat,
                    Err(AuthorityTransactionError::Application(_)) => {
                        return Ok(ProductPageRead::Corrupt);
                    }
                    Err(error) => return Err(error),
                };
                items.push(cat);
            }
            let next_cursor = has_more.then(|| items.last()).flatten().map(|cat| {
                cats_api::runtime_product_reads::encode_product_read_cursor(
                    ProductReadResource::Cats,
                    &cat.id,
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
            let rows = transaction.query(
                &format!(
                    "SELECT {DISK_READ_COLUMNS} FROM disk_records
                      WHERE workspace_id=$1 AND disk_id=$2 LIMIT 2"
                ),
                &[&workspace_id.as_str(), &disk_id.as_str()],
            )?;
            if rows.len() != 1 {
                return Ok(if rows.is_empty() {
                    ProductRead::NotFound
                } else {
                    ProductRead::Corrupt
                });
            }
            let row = match decode_disk_row(&rows[0]) {
                Ok(row) if row.workspace_id == *workspace_id && row.disk_id == *disk_id => row,
                _ => return Ok(ProductRead::Corrupt),
            };
            compose_disk(transaction, row)
                .map(|disk| ProductRead::Found(Box::new(disk)))
                .or_else(|error| match error {
                    AuthorityTransactionError::Application(_) => Ok(ProductRead::Corrupt),
                    error => Err(error),
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
            let after = after.map(Id::as_str).unwrap_or("");
            let query_limit = i64::try_from(limit.saturating_add(1))
                .map_err(|_| corrupt("Disk read page limit is too large"))?;
            let rows = transaction.query(
                &format!(
                    "SELECT {DISK_READ_COLUMNS} FROM disk_records
                      WHERE workspace_id=$1 AND disk_id COLLATE \"C\" > $2
                      ORDER BY disk_id COLLATE \"C\" LIMIT $3"
                ),
                &[&workspace_id.as_str(), &after, &query_limit],
            )?;
            let has_more = rows.len() > limit;
            let mut items = Vec::with_capacity(rows.len().min(limit));
            for row in rows.iter().take(limit) {
                let row = match decode_disk_row(row) {
                    Ok(row) if row.workspace_id == *workspace_id => row,
                    _ => return Ok(ProductPageRead::Corrupt),
                };
                let disk = match compose_disk(transaction, row) {
                    Ok(disk) => disk,
                    Err(AuthorityTransactionError::Application(_)) => {
                        return Ok(ProductPageRead::Corrupt);
                    }
                    Err(error) => return Err(error),
                };
                items.push(disk);
            }
            let next_cursor = has_more.then(|| items.last()).flatten().map(|disk| {
                cats_api::runtime_product_reads::encode_product_read_cursor(
                    ProductReadResource::Disks,
                    &disk.id,
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
            let Some(cat) = load_cat_scalar(transaction, cat_id)? else {
                return Ok(ProductRead::NotFound);
            };
            if cat.workspace_id != *workspace_id {
                return Ok(ProductRead::NotFound);
            }
            let rows = transaction.query(
                &format!(
                    "SELECT {ENDPOINT_READ_COLUMNS} FROM endpoint_records
                      WHERE workspace_id=$1 AND cat_id=$2
                      ORDER BY endpoint_id COLLATE \"C\" LIMIT $3"
                ),
                &[
                    &workspace_id.as_str(),
                    &cat_id.as_str(),
                    &i64::try_from(ENDPOINT_READ_MAX_ITEMS + 1)
                        .map_err(|_| corrupt("Endpoint read bound is invalid"))?,
                ],
            )?;
            if rows.len() > ENDPOINT_READ_MAX_ITEMS {
                return Ok(ProductRead::Corrupt);
            }
            let mut seen = BTreeSet::new();
            let mut items = Vec::with_capacity(rows.len());
            for row in &rows {
                let endpoint = match decode_endpoint_row(row) {
                    Ok(endpoint)
                        if endpoint.0 == *workspace_id
                            && endpoint.1 == *cat_id
                            && seen.insert(endpoint.2.endpoint_id.clone()) =>
                    {
                        endpoint.2
                    }
                    _ => return Ok(ProductRead::Corrupt),
                };
                items.push(endpoint);
            }
            Ok(ProductRead::Found(Box::new(EndpointCollectionReadV2 {
                version: ContractVersion::V1,
                cat_id: cat_id.clone(),
                complete: true,
                items,
            })))
        })
    }
}

fn compose_cat(
    transaction: &mut Transaction<'_>,
    row: CatProductRow,
) -> AuthorityTxResult<CatReadV2> {
    let head_node = match &row.lifecycle_head_operation_id {
        Some(operation_id) => {
            let operation = load_operation_unlocked(transaction, operation_id)?
                .ok_or_else(|| corrupt("Cat lifecycle head Operation is missing"))?;
            if operation.workspace_id != row.workspace_id
                || operation.cat_id != row.cat_id
                || !matches!(operation.state, LifecycleOperationState::Terminal { .. })
            {
                return Err(corrupt("Cat lifecycle head projection is not exact"));
            }
            Some(operation.node_id)
        }
        None => {
            if row.stable_state.is_some() {
                return Err(corrupt("Cat without a lifecycle head has a stable state"));
            }
            None
        }
    };
    match (
        row.stable_state,
        row.effective_runtime_ready_operation_id.as_ref(),
        row.runtime_incarnation.as_ref(),
    ) {
        (Some(CatStableStateReadV2::Running), Some(effective_operation_id), Some(incarnation)) => {
            let operation = load_operation_unlocked(transaction, effective_operation_id)?
                .ok_or_else(|| corrupt("effective RuntimeReady Operation is missing"))?;
            if operation.workspace_id != row.workspace_id
                || operation.cat_id != row.cat_id
                || !operation_is_runtime_ready(&operation.state, incarnation)
            {
                return Err(corrupt("effective RuntimeReady projection is not exact"));
            }
        }
        (Some(CatStableStateReadV2::Suspended), None, Some(_))
        | (Some(CatStableStateReadV2::Warm | CatStableStateReadV2::Cold), None, None)
        | (None, None, None) => {}
        _ => {
            return Err(corrupt(
                "Cat stable/effective RuntimeReady/incarnation projection is invalid",
            ));
        }
    }
    let observed = match head_node {
        Some(node_id) => load_current_cat_telemetry_unlocked(transaction, &node_id, &row.cat_id)?
            .map(|current| {
                if current.telemetry.cat_id != row.cat_id
                    || current.telemetry.observed_placement.node_id != node_id
                {
                    return Err(corrupt("Cat telemetry identity projection is inconsistent"));
                }
                let mut conditions = current
                    .telemetry
                    .observed_conditions
                    .iter()
                    .map(|condition| condition.kind)
                    .collect::<Vec<_>>();
                conditions.sort_unstable();
                conditions.dedup();
                Ok(CatObservedReadV2 {
                    node_id,
                    physical_state: current.telemetry.observed_physical_state,
                    conditions,
                    source_report_id: current.source_report_id,
                    sequence: current.sequence,
                    accepted_at_unix_ms: current.accepted_at_unix_ms,
                })
            })
            .transpose()?,
        None => None,
    };

    Ok(CatReadV2 {
        version: ContractVersion::V1,
        id: row.cat_id,
        workspace_id: row.workspace_id,
        name: row.name,
        created_at_unix_ms: row.created_at,
        current_runtime_config_id: row.current_runtime_config_id,
        current_runtime_config_digest: row.current_runtime_config_digest,
        lifecycle: CatLifecycleReadV2 {
            head_operation_id: row.lifecycle_head_operation_id,
            stable_state: row.stable_state,
            effective_runtime_ready_operation_id: row.effective_runtime_ready_operation_id,
            runtime_incarnation: row.runtime_incarnation,
            deleted_at_unix_ms: row.deleted_at,
        },
        observed,
    })
}

fn compose_disk(
    transaction: &mut Transaction<'_>,
    row: DiskProductRow,
) -> AuthorityTxResult<DiskReadV2> {
    let (kind, expected_root) = match &row.role {
        DiskProductRole::Root { cat_id } => (
            DiskReadKind::Root {
                cat_id: cat_id.clone(),
            },
            Some(cat_id),
        ),
        DiskProductRole::Persistent => (DiskReadKind::Persistent, None),
    };
    let binding = current_disk_binding(
        transaction,
        &row.workspace_id,
        &row.disk_id,
        &row.volume_id,
        expected_root,
    )?;
    if expected_root.is_some() && binding.is_none() {
        return Err(corrupt("RootDisk is absent from its Cat runtime config"));
    }
    Ok(DiskReadV2 {
        version: ContractVersion::V1,
        id: row.disk_id,
        workspace_id: row.workspace_id,
        name: row.name,
        size_bytes: row.size_bytes,
        durability: match row.durability {
            VolumeDurability::Strict => Durability::Strict,
            VolumeDurability::Relaxed => Durability::Relaxed,
        },
        created_at_unix_ms: row.created_at,
        kind,
        admin_state: row.admin_state,
        binding,
    })
}

fn current_disk_binding(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    disk_id: &Id,
    volume_id: &Id,
    expected_root_cat: Option<&Id>,
) -> AuthorityTxResult<Option<DiskReadBinding>> {
    let rows = transaction.query(
        "SELECT c.cat_id, c.deleted_at, c.current_runtime_config_id,
                c.current_runtime_config_sha256,
                cfg.canonical_config_bytes
           FROM cat_records c
           JOIN cat_runtime_configs cfg
             ON cfg.workspace_id=c.workspace_id AND cfg.cat_id=c.cat_id
            AND cfg.config_id=c.current_runtime_config_id
            AND cfg.canonical_config_sha256=c.current_runtime_config_sha256
          WHERE c.workspace_id=$1
            AND EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(
                    convert_from(cfg.canonical_config_bytes, 'UTF8')::jsonb->'volumes'
                  ) AS volume
                 WHERE volume->>'disk_id'=$2
            )
          ORDER BY c.cat_id COLLATE \"C\" LIMIT 2",
        &[&workspace_id.as_str(), &disk_id.as_str()],
    )?;
    let mut bindings = Vec::new();
    for candidate in rows {
        let cat_id = parse_id(candidate.try_get("cat_id")?)?;
        let deleted_at = candidate
            .try_get::<_, Option<i64>>("deleted_at")?
            .map(UnixMillis::from_pg)
            .transpose()
            .map_err(corrupt)?;
        let config_id = parse_id(candidate.try_get("current_runtime_config_id")?)?;
        let config_digest = parse_digest(candidate.try_get("current_runtime_config_sha256")?)?;
        let bytes: Vec<u8> = candidate.try_get("canonical_config_bytes")?;
        let config = decode_immutable_runtime_config(&bytes).map_err(corrupt)?;
        if config.config_id != config_id || config.config_digest != config_digest {
            return Err(corrupt("current runtime config row projection diverged"));
        }
        let matching = config
            .volumes
            .iter()
            .filter(|volume| volume.disk_id == *disk_id)
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].volume_id != *volume_id {
            return Err(corrupt("runtime config Disk binding is not exact"));
        }
        if expected_root_cat.is_some_and(|expected| expected != &cat_id) {
            return Err(corrupt("RootDisk runtime config belongs to another Cat"));
        }
        if expected_root_cat.is_none() && deleted_at.is_some() {
            continue;
        }
        bindings.push(DiskReadBinding {
            cat_id,
            runtime_config_id: config_id,
        });
    }
    if bindings.len() > 1 {
        return Err(corrupt(
            "Disk occurs in more than one current immutable runtime config",
        ));
    }
    Ok(bindings.pop())
}

fn load_cat_scalar(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
) -> AuthorityTxResult<Option<CatProductRow>> {
    transaction
        .query_opt(
            &format!("SELECT {CAT_READ_COLUMNS} FROM cat_records WHERE cat_id=$1"),
            &[&cat_id.as_str()],
        )?
        .map(|row| decode_cat_row(&row))
        .transpose()
}

fn decode_cat_row(row: &Row) -> AuthorityTxResult<CatProductRow> {
    let cat_id = parse_id(row.try_get("cat_id")?)?;
    let workspace_id = parse_id(row.try_get("workspace_id")?)?;
    let name = parse_id(row.try_get("name")?)?;
    validate_record_identity(row, &cat_id, &workspace_id, Some(&name), None)?;
    let stable_state = row
        .try_get::<_, Option<String>>("stable_state")?
        .map(|state| match state.as_str() {
            "running" => Ok(CatStableStateReadV2::Running),
            "suspended" => Ok(CatStableStateReadV2::Suspended),
            "warm" => Ok(CatStableStateReadV2::Warm),
            "cold" => Ok(CatStableStateReadV2::Cold),
            _ => Err(corrupt("Cat stable state is outside the closed set")),
        })
        .transpose()?;
    let effective_runtime_ready_operation_id = row
        .try_get::<_, Option<String>>("effective_runtime_ready_operation_id")?
        .map(parse_id)
        .transpose()?;
    let runtime_incarnation = row
        .try_get::<_, Option<String>>("runtime_incarnation")?
        .map(parse_random_id)
        .transpose()?;
    match (
        stable_state,
        effective_runtime_ready_operation_id.as_ref(),
        runtime_incarnation.as_ref(),
    ) {
        (Some(CatStableStateReadV2::Running), Some(_), Some(_))
        | (Some(CatStableStateReadV2::Suspended), None, Some(_))
        | (Some(CatStableStateReadV2::Warm | CatStableStateReadV2::Cold), None, None)
        | (None, None, None) => {}
        _ => {
            return Err(corrupt(
                "Cat stable/effective RuntimeReady/incarnation shape is invalid",
            ));
        }
    }
    Ok(CatProductRow {
        cat_id,
        workspace_id,
        name,
        created_at: UnixMillis::from_pg(row.try_get("created_at")?).map_err(corrupt)?,
        lifecycle_head_operation_id: row
            .try_get::<_, Option<String>>("lifecycle_head_operation_id")?
            .map(parse_id)
            .transpose()?,
        stable_state,
        effective_runtime_ready_operation_id,
        runtime_incarnation,
        current_runtime_config_id: parse_id(row.try_get("current_runtime_config_id")?)?,
        current_runtime_config_digest: parse_digest(row.try_get("current_runtime_config_sha256")?)?,
        deleted_at: row
            .try_get::<_, Option<i64>>("deleted_at")?
            .map(UnixMillis::from_pg)
            .transpose()
            .map_err(corrupt)?,
    })
}

fn decode_disk_row(row: &Row) -> AuthorityTxResult<DiskProductRow> {
    let disk_id = parse_id(row.try_get("disk_id")?)?;
    let workspace_id = parse_id(row.try_get("workspace_id")?)?;
    let name = parse_id(row.try_get("name")?)?;
    validate_record_identity(row, &disk_id, &workspace_id, Some(&name), None)?;
    let admin_state = match (
        row.try_get::<_, String>("admin_state")?.as_str(),
        row.try_get::<_, Option<String>>("delete_id")?,
    ) {
        ("active", None) => DiskReadAdminState::Active,
        ("deleting", Some(delete_id)) if Id::new(delete_id.clone()).is_some() => {
            DiskReadAdminState::Deleting
        }
        _ => return Err(corrupt("Disk admin-state projection is invalid")),
    };
    let role = match (
        row.try_get::<_, String>("role_kind")?.as_str(),
        row.try_get::<_, Option<String>>("root_cat_id")?,
    ) {
        ("root", Some(cat_id)) => DiskProductRole::Root {
            cat_id: parse_id(cat_id)?,
        },
        ("persistent", None) => DiskProductRole::Persistent,
        _ => return Err(corrupt("Disk role projection is invalid")),
    };
    Ok(DiskProductRow {
        disk_id,
        workspace_id,
        name,
        volume_id: parse_id(row.try_get("volume_id")?)?,
        size_bytes: u64::try_from(row.try_get::<_, i64>("size_bytes")?)
            .map_err(|_| corrupt("Disk size is outside the positive u64 range"))?,
        durability: match row.try_get::<_, String>("durability")?.as_str() {
            "strict" => VolumeDurability::Strict,
            "relaxed" => VolumeDurability::Relaxed,
            _ => return Err(corrupt("Disk durability is outside the closed set")),
        },
        created_at: UnixMillis::from_pg(row.try_get("created_at")?).map_err(corrupt)?,
        admin_state,
        role,
    })
}

fn decode_endpoint_row(row: &Row) -> AuthorityTxResult<(Id, Id, EndpointReadV2)> {
    let workspace_id = parse_id(row.try_get("workspace_id")?)?;
    let cat_id = parse_id(row.try_get("cat_id")?)?;
    let endpoint_id = parse_id(row.try_get("endpoint_id")?)?;
    let name = parse_id(row.try_get("name")?)?;
    validate_record_identity(row, &endpoint_id, &workspace_id, Some(&name), Some(&cat_id))?;
    let route_epoch = Epoch::from_pg(row.try_get("route_epoch")?).map_err(corrupt)?;
    let binding = match row.try_get::<_, String>("binding_state")?.as_str() {
        "bound" => {
            let hostname = row
                .try_get::<_, Option<String>>("hostname")?
                .and_then(Hostname::new)
                .ok_or_else(|| corrupt("bound Endpoint hostname is invalid"))?;
            let target_port = row
                .try_get::<_, Option<i32>>("target_port")?
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| corrupt("bound Endpoint target port is invalid"))?;
            let protocol = match row.try_get::<_, Option<String>>("protocol")?.as_deref() {
                Some("http") => HttpProtocol::Http,
                _ => return Err(corrupt("bound Endpoint protocol is invalid")),
            };
            EndpointReadBinding::Bound {
                hostname,
                target_port,
                protocol,
            }
        }
        "unbound"
            if row.try_get::<_, Option<String>>("hostname")?.is_none()
                && row.try_get::<_, Option<String>>("protocol")?.is_none()
                && row.try_get::<_, Option<i32>>("target_port")?.is_none() =>
        {
            EndpointReadBinding::Unbound
        }
        _ => return Err(corrupt("Endpoint binding projection is invalid")),
    };
    Ok((
        workspace_id,
        cat_id,
        EndpointReadV2 {
            version: ContractVersion::V1,
            endpoint_id,
            name,
            route_epoch,
            binding,
        },
    ))
}

fn operation_is_runtime_ready(
    state: &LifecycleOperationState,
    runtime_incarnation: &RandomId128,
) -> bool {
    let LifecycleOperationState::Terminal { terminal, .. } = state else {
        return false;
    };
    matches!(
        terminal.as_ref(),
        LifecycleTerminalResult::NodeResult { response }
            if matches!(&response.result, NodeResult::RuntimeReady(result)
                if result.runtime_incarnation == *runtime_incarnation)
    )
}

fn validate_record_identity(
    row: &Row,
    id: &Id,
    workspace_id: &Id,
    name: Option<&Id>,
    cat_id: Option<&Id>,
) -> AuthorityTxResult<()> {
    let record: serde_json::Value =
        serde_json::from_str(&row.try_get::<_, String>("record_json")?).map_err(corrupt)?;
    let object = record
        .as_object()
        .ok_or_else(|| corrupt("product record JSON is not an object"))?;
    let stored_id = object
        .get("cat_id")
        .or_else(|| object.get("disk_id"))
        .or_else(|| object.get("endpoint_id"))
        .and_then(serde_json::Value::as_str);
    if stored_id != Some(id.as_str())
        || object
            .get("workspace_id")
            .and_then(serde_json::Value::as_str)
            != Some(workspace_id.as_str())
        || name.is_some_and(|name| {
            object.get("name").and_then(serde_json::Value::as_str) != Some(name.as_str())
        })
        || cat_id.is_some_and(|cat_id| {
            object.get("cat_id").and_then(serde_json::Value::as_str) != Some(cat_id.as_str())
        })
    {
        return Err(corrupt("product record JSON/scalar identity diverged"));
    }
    Ok(())
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored product identifier is invalid"))
}

fn parse_random_id(value: String) -> AuthorityTxResult<RandomId128> {
    RandomId128::new(value).ok_or_else(|| corrupt("stored random identifier is invalid"))
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored SHA-256 digest is invalid"))
}

fn corrupt(error: impl std::fmt::Display) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(crate::store::internal(format!(
        "atomic product read invariant failed: {error}"
    )))
}

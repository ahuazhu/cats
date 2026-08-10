//! PostgreSQL data-plane access to the final `volume_records` authority row.
//!
//! This adapter never creates a table and never touches the legacy
//! `cats_storage_volumes` schema. The Control Store owns schema creation; this
//! module only verifies and operates the exact projection it needs.

use std::sync::{mpsc, Arc};

use cats_storage::authority::{
    compare_and_swap_head, project_volume_record, renew_lease, validate_volume_owner_binding,
    AuthorityError, Epoch, FenceEpoch, Generation, Id, NodeOwnedVolume, NodeOwnedVolumeSnapshot,
    RenewLeaseRequest, RenewLeaseResult, Revision, RuntimeVolumeInventoryAuthority, UnixMillis,
    VolumeDataAuthority, VolumeHeadCasRequest, VolumeHeadCasResult, VolumeOwnerBinding,
    VolumeRecord, VolumeRecordProjection, AUTHORITY_RELEASE_SCHEMA_VERSION, MAX_NODE_OWNED_VOLUMES,
};
use cats_storage::{AdapterConfig, AdapterError, MetaError};
use postgres::{Client, IsolationLevel, Row, Transaction};

use super::{
    dispatch_on, dsn_source, session_setup, spawn_worker, DsnSource, Job, SchemaAccess,
    SessionSetup, ADAPTER_NAME,
};

const VOLUME_COLUMNS: &str = "
    volume_id, record::text AS record_json, size_bytes, durability,
    admin_state, delete_id, head_generation, head_root_hash,
    head_root_object_id, lease_owner, lease_epoch, lease_expires_at,
    last_transition_kind, last_transition_id, transition_desired_revision,
    transition_placement_epoch, transition_lease_duration_ms,
    owner_binding::text AS owner_binding_json, owner_node_id";

const DB_NOW_MS: &str = "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint";

pub struct PostgresVolumeDataAuthority {
    jobs: mpsc::SyncSender<Job>,
    // Renewal has a dedicated PostgreSQL session so a root publication cannot
    // delay its health timestamp. Owner + epoch remain the fencing token.
    lease_jobs: mpsc::SyncSender<Job>,
}

impl PostgresVolumeDataAuthority {
    pub fn connect(url: &str, ca_file: Option<&str>) -> cats_storage::metadata::Result<Self> {
        Self::connect_from_with_session_setup(
            &DsnSource::Literal(url.to_string()),
            ca_file,
            SessionSetup::Client,
        )
    }

    fn connect_from_with_session_setup(
        dsn: &DsnSource,
        ca_file: Option<&str>,
        session_setup: SessionSetup,
    ) -> cats_storage::metadata::Result<Self> {
        let jobs = spawn_worker(
            "cats-postgres-volume-authority",
            dsn.clone(),
            ca_file,
            session_setup,
            SchemaAccess::VolumeAuthority,
        )?;
        let lease_jobs = spawn_worker(
            "cats-postgres-volume-authority-lease",
            dsn.clone(),
            ca_file,
            session_setup,
            SchemaAccess::VolumeAuthority,
        )?;
        Ok(Self { jobs, lease_jobs })
    }

    /// Open the one production target adapter from the existing opaque
    /// PostgreSQL adapter configuration.
    pub fn open(
        config: &AdapterConfig,
    ) -> std::result::Result<Arc<dyn VolumeDataAuthority>, AdapterError> {
        config.ensure_only(
            ADAPTER_NAME,
            &["url-env", "url-file", "ca-file", "session-setup"],
        )?;
        let session_setup = session_setup(config)?;
        let dsn = dsn_source(config)?;
        Self::connect_from_with_session_setup(&dsn, config.optional("ca-file"), session_setup)
            .map(|store| Arc::new(store) as Arc<dyn VolumeDataAuthority>)
            .map_err(|error| AdapterError::Open {
                adapter: ADAPTER_NAME,
                message: error.to_string(),
            })
    }

    pub fn open_runtime_inventory(
        config: &AdapterConfig,
    ) -> std::result::Result<Arc<dyn RuntimeVolumeInventoryAuthority>, AdapterError> {
        config.ensure_only(
            ADAPTER_NAME,
            &["url-env", "url-file", "ca-file", "session-setup"],
        )?;
        let session_setup = session_setup(config)?;
        let dsn = dsn_source(config)?;
        Self::connect_from_with_session_setup(&dsn, config.optional("ca-file"), session_setup)
            .map(|store| Arc::new(store) as Arc<dyn RuntimeVolumeInventoryAuthority>)
            .map_err(|error| AdapterError::Open {
                adapter: ADAPTER_NAME,
                message: error.to_string(),
            })
    }

    fn dispatch<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> Result<T, AuthorityError> + Send + 'static,
    ) -> Result<T, AuthorityError>
    where
        T: Send + 'static,
    {
        dispatch_authority(&self.jobs, operation)
    }

    fn dispatch_lease<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> Result<T, AuthorityError> + Send + 'static,
    ) -> Result<T, AuthorityError>
    where
        T: Send + 'static,
    {
        dispatch_authority(&self.lease_jobs, operation)
    }
}

fn dispatch_authority<T>(
    jobs: &mpsc::SyncSender<Job>,
    operation: impl FnOnce(&mut Client) -> Result<T, AuthorityError> + Send + 'static,
) -> Result<T, AuthorityError>
where
    T: Send + 'static,
{
    // Queueing, connection and timeout failures all have an unknown outcome
    // at this boundary. The caller resolves them by rereading exact authority.
    dispatch_on(jobs, move |client| Ok(operation(client)))
        .map_err(|_| AuthorityError::BackendUnknown)?
}

impl VolumeDataAuthority for PostgresVolumeDataAuthority {
    fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
        let volume_id = volume_id.clone();
        self.dispatch(move |client| load_volume(client, &volume_id))
    }

    fn renew_lease(&self, request: &RenewLeaseRequest) -> Result<RenewLeaseResult, AuthorityError> {
        let request = request.clone();
        self.dispatch_lease(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let current = load_volume_for_update(&mut transaction, &request.volume_id)?;
            let db_now = database_now(&mut transaction)?;
            let (updated, result) = renew_lease(&current, &request, db_now)?;
            update_volume(&mut transaction, &updated)?;
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(result)
        })
    }

    fn compare_and_swap_head(
        &self,
        request: &VolumeHeadCasRequest,
    ) -> Result<VolumeHeadCasResult, AuthorityError> {
        let request = request.clone();
        self.dispatch(move |client| {
            let mut transaction = client
                .transaction()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            let current = load_volume_for_update(&mut transaction, &request.volume_id)?;
            let (updated, result) = compare_and_swap_head(&current, &request)?;
            update_volume(&mut transaction, &updated)?;
            transaction
                .commit()
                .map_err(|_| AuthorityError::BackendUnknown)?;
            Ok(result)
        })
    }
}

impl RuntimeVolumeInventoryAuthority for PostgresVolumeDataAuthority {
    fn load_node_owned_volumes(
        &self,
        node_id: &Id,
    ) -> Result<NodeOwnedVolumeSnapshot, AuthorityError> {
        let node_id = node_id.clone();
        self.dispatch(move |client| load_node_owned_volumes(client, &node_id))
    }
}

pub(super) fn verify_schema(client: &mut Client) -> cats_storage::metadata::Result<()> {
    let stamp = client
        .query_opt(
            "SELECT version FROM control_schema_version WHERE singleton",
            &[],
        )
        .map_err(|error| {
            MetaError::Backend(format!(
                "target volume authority schema stamp is unavailable or incompatible: {error}"
            ))
        })?
        .ok_or_else(|| {
            MetaError::Backend(
                "target volume authority schema stamp is missing its singleton row".into(),
            )
        })?;
    let stamped: i64 = stamp.try_get(0).map_err(|error| {
        MetaError::Backend(format!(
            "target volume authority schema stamp has an incompatible type: {error}"
        ))
    })?;
    if stamped != AUTHORITY_RELEASE_SCHEMA_VERSION {
        return Err(MetaError::Backend(format!(
            "target volume authority database is at schema version {stamped}, this build requires exact authority release version {AUTHORITY_RELEASE_SCHEMA_VERSION}"
        )));
    }
    let sql = format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE FALSE");
    client.query(&sql, &[]).map_err(|error| {
        MetaError::Backend(format!(
            "target volume authority schema is unavailable or incompatible: {error}"
        ))
    })?;
    for (index, first_key, expression_key, predicate) in [
        (
            "volume_records_owner_node",
            "owner_node_id",
            false,
            "(owner_node_id IS NOT NULL)",
        ),
        (
            "volume_records_owner_binding_node",
            "((owner_binding ->> 'owner_node_id'::text))",
            true,
            "(owner_binding IS NOT NULL)",
        ),
    ] {
        let present: bool = client
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname='volume_records'
                       AND index_relation.relname=$1
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=2 AND i.indnatts=2
                       AND i.indoption::TEXT='0 0'
                       AND access_method.amname='btree'
                       AND (($3 AND i.indexprs IS NOT NULL)
                            OR (NOT $3 AND i.indexprs IS NULL))
                       AND i.indpred IS NOT NULL
                       AND pg_get_indexdef(i.indexrelid, 1, FALSE)=$2
                       AND pg_get_indexdef(i.indexrelid, 2, FALSE)='volume_id'
                       AND i.indcollation[1]='pg_catalog.\"C\"'::regcollation
                       AND pg_get_expr(i.indpred, i.indrelid)=$4
                 )",
                &[&index, &first_key, &expression_key, &predicate],
            )
            .map_err(|error| {
                MetaError::Backend(format!(
                    "target volume authority owner index is unavailable: {error}"
                ))
            })?
            .get(0);
        if !present {
            return Err(MetaError::Backend(format!(
                "target volume authority owner index {index} is missing or incompatible"
            )));
        }
    }
    Ok(())
}

fn load_volume(client: &mut Client, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
    let sql = format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE volume_id=$1");
    client
        .query_opt(&sql, &[&volume_id.as_str()])
        .map_err(|_| AuthorityError::BackendUnknown)?
        .map(|row| decode_volume(&row))
        .transpose()?
        .ok_or(AuthorityError::NotFound)
}

fn load_volume_for_update(
    transaction: &mut Transaction<'_>,
    volume_id: &Id,
) -> Result<VolumeRecord, AuthorityError> {
    let sql = format!("SELECT {VOLUME_COLUMNS} FROM volume_records WHERE volume_id=$1 FOR UPDATE");
    transaction
        .query_opt(&sql, &[&volume_id.as_str()])
        .map_err(|_| AuthorityError::BackendUnknown)?
        .map(|row| decode_volume(&row))
        .transpose()?
        .ok_or(AuthorityError::NotFound)
}

fn load_node_owned_volumes(
    client: &mut Client,
    node_id: &Id,
) -> Result<NodeOwnedVolumeSnapshot, AuthorityError> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(|_| AuthorityError::BackendUnknown)?;
    let read_at_unix_ms = database_now(&mut transaction)?;
    let limit =
        i64::try_from(MAX_NODE_OWNED_VOLUMES + 1).map_err(|_| AuthorityError::BackendUnknown)?;
    let sql = node_owned_volumes_sql();
    let rows = transaction
        .query(&sql, &[&node_id.as_str(), &limit])
        .map_err(|_| AuthorityError::BackendUnknown)?;
    if rows.len() > MAX_NODE_OWNED_VOLUMES {
        return Err(AuthorityError::BackendUnknown);
    }
    let mut volumes = Vec::with_capacity(rows.len());
    for row in rows {
        let (volume, binding) = decode_stored_volume(&row)?;
        let binding = binding.ok_or(AuthorityError::BackendUnknown)?;
        if binding.owner_node_id != *node_id {
            return Err(AuthorityError::BackendUnknown);
        }
        volumes.push(NodeOwnedVolume { binding, volume });
    }
    transaction
        .commit()
        .map_err(|_| AuthorityError::BackendUnknown)?;
    Ok(NodeOwnedVolumeSnapshot {
        node_id: node_id.clone(),
        read_at_unix_ms,
        volumes,
    })
}

fn node_owned_volumes_sql() -> String {
    format!(
        "WITH candidate_ids AS MATERIALIZED (
            (
                SELECT volume_id
                  FROM volume_records
                 WHERE owner_node_id=$1
                 ORDER BY volume_id COLLATE \"C\"
                 LIMIT $2
            )
            UNION
            (
                SELECT volume_id
                  FROM volume_records
                 WHERE owner_binding->>'owner_node_id'=$1
                 ORDER BY volume_id COLLATE \"C\"
                 LIMIT $2
            )
        )
        SELECT {VOLUME_COLUMNS}
          FROM volume_records
         WHERE volume_id IN (SELECT volume_id FROM candidate_ids)
         ORDER BY volume_id COLLATE \"C\"
         LIMIT $2"
    )
}

fn database_now(transaction: &mut Transaction<'_>) -> Result<UnixMillis, AuthorityError> {
    let row = transaction
        .query_one(&format!("SELECT {DB_NOW_MS}"), &[])
        .map_err(|_| AuthorityError::BackendUnknown)?;
    unix_millis(row.try_get(0).map_err(|_| AuthorityError::BackendUnknown)?)
}

fn update_volume(
    transaction: &mut Transaction<'_>,
    record: &VolumeRecord,
) -> Result<(), AuthorityError> {
    let projection = project_volume_record(record)?;
    let record_json = serde_json::to_string(record).map_err(|_| AuthorityError::BackendUnknown)?;
    let size_bytes = to_pg(projection.size_bytes)?;
    let head_generation = to_pg(projection.head_generation.get())?;
    let lease_epoch = to_pg(projection.lease_epoch.get())?;
    let lease_expires_at = projection
        .lease_expires_at
        .map(|value| to_pg(value.get()))
        .transpose()?;
    let transition_revision = projection
        .transition_desired_revision
        .map(|value| to_pg(value.get()))
        .transpose()?;
    let transition_placement = projection
        .transition_placement_epoch
        .map(|value| to_pg(value.get()))
        .transpose()?;
    let transition_duration = projection
        .transition_lease_duration_ms
        .map(to_pg)
        .transpose()?;
    let changed = transaction
        .execute(
            "UPDATE volume_records SET
                record=$2::TEXT::jsonb, size_bytes=$3, durability=$4,
                admin_state=$5, delete_id=$6, head_generation=$7,
                head_root_hash=$8, head_root_object_id=$9, lease_owner=$10,
                lease_epoch=$11, lease_expires_at=$12,
                last_transition_kind=$13, last_transition_id=$14,
                transition_desired_revision=$15,
                transition_placement_epoch=$16,
                transition_lease_duration_ms=$17
              WHERE volume_id=$1",
            &[
                &projection.volume_id,
                &record_json,
                &size_bytes,
                &projection.durability,
                &projection.admin_state,
                &projection.delete_id,
                &head_generation,
                &projection.head_root_hash,
                &projection.head_root_object_id,
                &projection.lease_owner,
                &lease_epoch,
                &lease_expires_at,
                &projection.last_transition_kind,
                &projection.last_transition_id,
                &transition_revision,
                &transition_placement,
                &transition_duration,
            ],
        )
        .map_err(|_| AuthorityError::BackendUnknown)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(AuthorityError::BackendUnknown)
    }
}

fn decode_volume(row: &Row) -> Result<VolumeRecord, AuthorityError> {
    Ok(decode_stored_volume(row)?.0)
}

fn decode_stored_volume(
    row: &Row,
) -> Result<(VolumeRecord, Option<VolumeOwnerBinding>), AuthorityError> {
    let stored = projection_from_row(row)?;
    let record_json: String = row
        .try_get("record_json")
        .map_err(|_| AuthorityError::BackendUnknown)?;
    let record: VolumeRecord =
        serde_json::from_str(&record_json).map_err(|_| AuthorityError::BackendUnknown)?;
    let derived = project_volume_record(&record)?;
    if stored != derived {
        return Err(AuthorityError::BackendUnknown);
    }
    let owner_binding_json: Option<String> = row
        .try_get("owner_binding_json")
        .map_err(|_| AuthorityError::BackendUnknown)?;
    let owner_node_id: Option<String> = row
        .try_get("owner_node_id")
        .map_err(|_| AuthorityError::BackendUnknown)?;
    let owner_binding = owner_binding_json
        .map(|json| serde_json::from_str::<VolumeOwnerBinding>(&json))
        .transpose()
        .map_err(|_| AuthorityError::BackendUnknown)?;
    match (&owner_binding, owner_node_id.as_deref()) {
        (None, None) if record.lease_owner.is_none() => {}
        (Some(binding), Some(projected_node_id))
            if binding.owner_node_id.as_str() == projected_node_id =>
        {
            validate_volume_owner_binding(binding, &record)?;
        }
        _ => return Err(AuthorityError::BackendUnknown),
    }
    Ok((record, owner_binding))
}

fn projection_from_row(row: &Row) -> Result<VolumeRecordProjection, AuthorityError> {
    let durability = static_value(row, "durability", &["strict", "relaxed"])?;
    let admin_state = static_value(row, "admin_state", &["active", "deleting"])?;
    let last_transition_kind = match optional_string(row, "last_transition_kind")? {
        None => None,
        Some(value) => Some(static_str(
            value,
            &[
                "normal_acquire",
                "release",
                "takeover",
                "begin_delete",
                "begin_disposable_delete",
            ],
        )?),
    };
    Ok(VolumeRecordProjection {
        volume_id: string(row, "volume_id")?,
        size_bytes: unsigned(row, "size_bytes")?,
        durability,
        admin_state,
        delete_id: optional_string(row, "delete_id")?,
        head_generation: generation(integer(row, "head_generation")?)?,
        head_root_hash: optional_string(row, "head_root_hash")?,
        head_root_object_id: optional_string(row, "head_root_object_id")?,
        lease_owner: optional_string(row, "lease_owner")?,
        lease_epoch: fence_epoch(integer(row, "lease_epoch")?)?,
        lease_expires_at: optional_integer(row, "lease_expires_at")?
            .map(unix_millis)
            .transpose()?,
        last_transition_kind,
        last_transition_id: optional_string(row, "last_transition_id")?,
        transition_desired_revision: optional_integer(row, "transition_desired_revision")?
            .map(revision)
            .transpose()?,
        transition_placement_epoch: optional_integer(row, "transition_placement_epoch")?
            .map(epoch)
            .transpose()?,
        transition_lease_duration_ms: optional_integer(row, "transition_lease_duration_ms")?
            .map(|value| u64::try_from(value).map_err(|_| AuthorityError::BackendUnknown))
            .transpose()?,
    })
}

fn integer(row: &Row, column: &str) -> Result<i64, AuthorityError> {
    row.try_get(column)
        .map_err(|_| AuthorityError::BackendUnknown)
}

fn optional_integer(row: &Row, column: &str) -> Result<Option<i64>, AuthorityError> {
    row.try_get(column)
        .map_err(|_| AuthorityError::BackendUnknown)
}

fn unsigned(row: &Row, column: &str) -> Result<u64, AuthorityError> {
    u64::try_from(integer(row, column)?).map_err(|_| AuthorityError::BackendUnknown)
}

fn string(row: &Row, column: &str) -> Result<String, AuthorityError> {
    row.try_get(column)
        .map_err(|_| AuthorityError::BackendUnknown)
}

fn optional_string(row: &Row, column: &str) -> Result<Option<String>, AuthorityError> {
    row.try_get(column)
        .map_err(|_| AuthorityError::BackendUnknown)
}

fn static_value(
    row: &Row,
    column: &str,
    allowed: &[&'static str],
) -> Result<&'static str, AuthorityError> {
    static_str(string(row, column)?, allowed)
}

fn static_str(value: String, allowed: &[&'static str]) -> Result<&'static str, AuthorityError> {
    allowed
        .iter()
        .copied()
        .find(|candidate| *candidate == value.as_str())
        .ok_or(AuthorityError::BackendUnknown)
}

fn generation(value: i64) -> Result<Generation, AuthorityError> {
    u64::try_from(value)
        .ok()
        .and_then(Generation::new)
        .ok_or(AuthorityError::BackendUnknown)
}

fn fence_epoch(value: i64) -> Result<FenceEpoch, AuthorityError> {
    u64::try_from(value)
        .ok()
        .and_then(FenceEpoch::new)
        .ok_or(AuthorityError::BackendUnknown)
}

fn revision(value: i64) -> Result<Revision, AuthorityError> {
    u64::try_from(value)
        .ok()
        .and_then(Revision::new)
        .ok_or(AuthorityError::BackendUnknown)
}

fn epoch(value: i64) -> Result<Epoch, AuthorityError> {
    u64::try_from(value)
        .ok()
        .and_then(Epoch::new)
        .ok_or(AuthorityError::BackendUnknown)
}

fn unix_millis(value: i64) -> Result<UnixMillis, AuthorityError> {
    u64::try_from(value)
        .ok()
        .and_then(UnixMillis::new)
        .ok_or(AuthorityError::BackendUnknown)
}

fn to_pg(value: u64) -> Result<i64, AuthorityError> {
    i64::try_from(value).map_err(|_| AuthorityError::BackendUnknown)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use cats_control_plane::store::Store;
    use cats_storage::authority::{
        AsciiText, LastVolumeTransition, Sha256Digest, VolumeAdminState, VolumeDurability,
    };
    use postgres::NoTls;

    use super::*;

    const VOLUME_ID: &str = "volume-target-authority";
    const ATTACHMENT_ID: &str = "attachment-target-authority";
    const NODE_ID: &str = "node-target-authority";
    const VOLUME_SIZE: u64 = 8 * 1024 * 1024;

    struct Fixture {
        url: String,
        client: Client,
        authority: PostgresVolumeDataAuthority,
        record: VolumeRecord,
    }

    impl Fixture {
        fn new() -> Self {
            let url = cats_control_plane::testsupport::isolated_control_store_url();
            // The Control Store is the sole schema owner. The target adapter
            // must be able to start only after this canonical migration exists.
            drop(Store::connect(&url, None).expect("initialize final control-store schema"));
            let mut client = Client::connect(&url, NoTls).expect("connect test PostgreSQL");
            let record = owned_volume();
            insert_volume(&mut client, &record);
            let authority = PostgresVolumeDataAuthority::connect(&url, None)
                .expect("connect target volume authority");
            Self {
                url,
                client,
                authority,
                record,
            }
        }

        fn stored(&self) -> VolumeRecord {
            self.authority
                .load_volume(&self.record.volume_id)
                .expect("load stored target authority record")
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).expect("test id is valid")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test generation is valid")
    }

    fn fence_epoch(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).expect("test epoch is valid")
    }

    fn unix_millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).expect("test timestamp is valid")
    }

    fn head(generation_value: u64, marker: u8) -> cats_storage::authority::RemoteHead {
        cats_storage::authority::RemoteHead {
            generation: generation(generation_value),
            root_hash: (generation_value > 0).then(|| Sha256Digest::from_bytes([marker; 32])),
            root_object_id: (generation_value > 0).then(|| {
                AsciiText::new(format!("root-{generation_value}-{marker}.node"))
                    .expect("test object id is valid")
            }),
        }
    }

    fn owned_volume() -> VolumeRecord {
        VolumeRecord {
            volume_id: id(VOLUME_ID),
            size_bytes: VOLUME_SIZE,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            head: head(4, 4),
            lease_owner: Some(id(ATTACHMENT_ID)),
            lease_epoch: fence_epoch(7),
            // Deliberately expired: expiry lapse alone is not fencing.
            lease_expires_at: Some(unix_millis(1)),
            last_transition: Some(LastVolumeTransition::Takeover {
                authorization_id: id("takeover-target-authority"),
            }),
        }
    }

    fn insert_volume(client: &mut Client, record: &VolumeRecord) {
        let projection = project_volume_record(record).expect("test record is valid");
        let record_json = serde_json::to_string(record).expect("serialize test record");
        let size_bytes = to_pg(projection.size_bytes).unwrap();
        let head_generation = to_pg(projection.head_generation.get()).unwrap();
        let lease_epoch = to_pg(projection.lease_epoch.get()).unwrap();
        let lease_expires_at = projection
            .lease_expires_at
            .map(|value| to_pg(value.get()).unwrap());
        let transition_revision = projection
            .transition_desired_revision
            .map(|value| to_pg(value.get()).unwrap());
        let transition_placement = projection
            .transition_placement_epoch
            .map(|value| to_pg(value.get()).unwrap());
        let transition_duration = projection
            .transition_lease_duration_ms
            .map(|value| to_pg(value).unwrap());
        let owner_binding = VolumeOwnerBinding {
            volume_id: record.volume_id.clone(),
            owner_node_id: id(NODE_ID),
            attachment_id: record.lease_owner.clone().expect("test Volume is owned"),
            attachment_epoch: record.lease_epoch,
        };
        let owner_binding_json =
            serde_json::to_string(&owner_binding).expect("serialize test owner binding");
        client
            .execute(
                "INSERT INTO volume_records (
                    volume_id, record, size_bytes, durability, admin_state, delete_id,
                    head_generation, head_root_hash, head_root_object_id,
                    lease_owner, lease_epoch, lease_expires_at,
                    last_transition_kind, last_transition_id,
                    transition_desired_revision, transition_placement_epoch,
                    transition_lease_duration_ms, owner_binding, owner_node_id
                 ) VALUES (
                    $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9,
                    $10, $11, $12, $13, $14, $15, $16, $17,
                    $18::TEXT::jsonb, $19
                 )",
                &[
                    &projection.volume_id,
                    &record_json,
                    &size_bytes,
                    &projection.durability,
                    &projection.admin_state,
                    &projection.delete_id,
                    &head_generation,
                    &projection.head_root_hash,
                    &projection.head_root_object_id,
                    &projection.lease_owner,
                    &lease_epoch,
                    &lease_expires_at,
                    &projection.last_transition_kind,
                    &projection.last_transition_id,
                    &transition_revision,
                    &transition_placement,
                    &transition_duration,
                    &owner_binding_json,
                    &NODE_ID,
                ],
            )
            .expect("insert target authority test row");
    }

    fn insert_generated_owned_volumes(
        client: &mut Client,
        owner_node_id: &str,
        first: i64,
        last: i64,
    ) {
        client
            .execute(
                "INSERT INTO volume_records (
                    volume_id, record, size_bytes, durability, admin_state,
                    head_generation, lease_owner, lease_epoch, lease_expires_at,
                    last_transition_kind, last_transition_id, owner_binding,
                    owner_node_id
                 )
                 SELECT
                    'generated-volume-' || value,
                    jsonb_build_object(
                        'volume_id', 'generated-volume-' || value,
                        'size_bytes', 4096,
                        'durability', 'strict',
                        'admin_state', jsonb_build_object('kind', 'active'),
                        'head', jsonb_build_object(
                            'generation', 0,
                            'root_hash', NULL,
                            'root_object_id', NULL
                        ),
                        'lease_owner', 'generated-attachment-' || value,
                        'lease_epoch', 1,
                        'lease_expires_at', 9999999999999,
                        'last_transition', jsonb_build_object(
                            'kind', 'takeover',
                            'authorization_id', 'generated-auth-' || value
                        )
                    ),
                    4096, 'strict', 'active', 0,
                    'generated-attachment-' || value, 1, 9999999999999,
                    'takeover', 'generated-auth-' || value,
                    jsonb_build_object(
                        'volume_id', 'generated-volume-' || value,
                        'owner_node_id', $1::text,
                        'attachment_id', 'generated-attachment-' || value,
                        'attachment_epoch', 1
                    ),
                    $1::text
                   FROM generate_series($2::bigint, $3::bigint) value",
                &[&owner_node_id, &first, &last],
            )
            .expect("insert generated owned Volume rows");
    }

    fn renew_request(owner: &str, epoch_value: u64, duration_ms: u64) -> RenewLeaseRequest {
        RenewLeaseRequest {
            volume_id: id(VOLUME_ID),
            attachment_id: id(owner),
            expected_epoch: fence_epoch(epoch_value),
            lease_duration_ms: duration_ms,
        }
    }

    fn cas_request(
        expected: cats_storage::authority::RemoteHead,
        target: cats_storage::authority::RemoteHead,
    ) -> VolumeHeadCasRequest {
        VolumeHeadCasRequest {
            volume_id: id(VOLUME_ID),
            attachment_id: id(ATTACHMENT_ID),
            expected_epoch: fence_epoch(7),
            expected_size_bytes: VOLUME_SIZE,
            expected_head: expected,
            new_head: target,
        }
    }

    fn legacy_table(client: &mut Client) -> Option<String> {
        client
            .query_one("SELECT to_regclass('cats_storage_volumes')::text", &[])
            .unwrap()
            .get(0)
    }

    fn database_now(client: &mut Client) -> i64 {
        client
            .query_one(&format!("SELECT {DB_NOW_MS}"), &[])
            .unwrap()
            .get(0)
    }

    fn raw_volume_row_json(client: &mut Client) -> String {
        client
            .query_one(
                "SELECT row_to_json(volume_records)::text
                   FROM volume_records WHERE volume_id=$1",
                &[&VOLUME_ID],
            )
            .unwrap()
            .get(0)
    }

    fn assert_target_startup_rejected_without_volume_write(mutate_stamp: impl FnOnce(&mut Client)) {
        let url = cats_control_plane::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).expect("initialize final control-store schema"));
        let mut client = Client::connect(&url, NoTls).expect("connect test PostgreSQL");
        insert_volume(&mut client, &owned_volume());
        mutate_stamp(&mut client);
        let before = raw_volume_row_json(&mut client);

        let error = PostgresVolumeDataAuthority::connect(&url, None)
            .err()
            .expect("an incompatible schema stamp must reject target startup");
        assert!(
            error.to_string().contains("schema"),
            "unexpected startup error: {error}"
        );
        assert_eq!(raw_volume_row_json(&mut client), before);
        assert_eq!(legacy_table(&mut client), None);
    }

    #[test]
    fn target_requires_the_exact_existing_control_schema_stamp() {
        assert_target_startup_rejected_without_volume_write(|client| {
            client
                .batch_execute("DROP TABLE control_schema_version")
                .unwrap();
        });
        assert_target_startup_rejected_without_volume_write(|client| {
            client
                .execute("DELETE FROM control_schema_version", &[])
                .unwrap();
        });
        assert_target_startup_rejected_without_volume_write(|client| {
            client
                .execute(
                    "UPDATE control_schema_version SET version=$1 WHERE singleton",
                    &[&(AUTHORITY_RELEASE_SCHEMA_VERSION - 1)],
                )
                .unwrap();
        });
        assert_target_startup_rejected_without_volume_write(|client| {
            client
                .execute(
                    "UPDATE control_schema_version SET version=$1 WHERE singleton",
                    &[&(AUTHORITY_RELEASE_SCHEMA_VERSION + 1)],
                )
                .unwrap();
        });
        assert_target_startup_rejected_without_volume_write(|client| {
            client
                .batch_execute("ALTER TABLE volume_records DROP COLUMN head_root_object_id")
                .unwrap();
        });
    }

    #[test]
    fn target_rejects_missing_or_replaced_owner_indexes_without_repair() {
        for (index, ddl) in [
            (
                "volume_records_owner_node",
                "DROP INDEX volume_records_owner_node",
            ),
            (
                "volume_records_owner_binding_node",
                "DROP INDEX volume_records_owner_binding_node;
                 CREATE INDEX volume_records_owner_binding_node
                     ON volume_records(owner_node_id, volume_id)
                     WHERE owner_node_id IS NOT NULL",
            ),
        ] {
            let url = cats_control_plane::testsupport::isolated_control_store_url();
            drop(Store::connect(&url, None).unwrap());
            let mut client = Client::connect(&url, NoTls).unwrap();
            insert_volume(&mut client, &owned_volume());
            client.batch_execute(ddl).unwrap();
            let before = raw_volume_row_json(&mut client);

            let error = PostgresVolumeDataAuthority::connect(&url, None)
                .err()
                .expect("changed owner index must reject target startup");
            assert!(error.to_string().contains(index), "{error}");
            assert_eq!(raw_volume_row_json(&mut client), before);
            let definition: Option<String> = client
                .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&index])
                .unwrap()
                .get(0);
            if ddl.starts_with("DROP INDEX volume_records_owner_node") {
                assert!(definition.is_none());
            } else {
                assert!(definition
                    .as_deref()
                    .is_some_and(|value| value.contains("owner_node_id, volume_id")));
            }
        }
    }

    #[test]
    fn target_uses_only_the_final_authority_row_and_preserves_a_legacy_sentinel() {
        let mut fixture = Fixture::new();
        assert_eq!(legacy_table(&mut fixture.client), None);
        assert_eq!(fixture.stored(), fixture.record);

        fixture
            .client
            .batch_execute(
                "CREATE TABLE cats_storage_volumes (marker TEXT PRIMARY KEY);
                 INSERT INTO cats_storage_volumes VALUES ('do-not-touch')",
            )
            .unwrap();

        fixture
            .authority
            .renew_lease(&renew_request(ATTACHMENT_ID, 7, 30_000))
            .unwrap();
        fixture
            .authority
            .compare_and_swap_head(&cas_request(head(4, 4), head(5, 5)))
            .unwrap();

        let markers: Vec<String> = fixture
            .client
            .query("SELECT marker FROM cats_storage_volumes", &[])
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(markers, ["do-not-touch"]);
        assert_eq!(fixture.stored().head, head(5, 5));
    }

    #[test]
    fn runtime_inventory_returns_the_complete_node_index_and_rejects_binding_drift() {
        let mut fixture = Fixture::new();
        let snapshot = fixture
            .authority
            .load_node_owned_volumes(&id(NODE_ID))
            .unwrap();
        assert_eq!(snapshot.node_id, id(NODE_ID));
        assert_eq!(snapshot.volumes.len(), 1);
        assert_eq!(snapshot.volumes[0].volume, fixture.record);
        assert_eq!(snapshot.volumes[0].binding.owner_node_id, id(NODE_ID));
        assert!(fixture
            .authority
            .load_node_owned_volumes(&id("node-with-no-volumes"))
            .unwrap()
            .volumes
            .is_empty());

        // Model a storage-corruption shape that bypassed the database guard.
        // The bidirectional selector and strict decoder must still expose the
        // row to both projected owners and fail closed.
        fixture
            .client
            .batch_execute(
                "ALTER TABLE volume_records
                    DROP CONSTRAINT volume_records_owner_binding_check",
            )
            .unwrap();
        fixture
            .client
            .execute(
                "UPDATE volume_records SET owner_node_id='drifted-node' WHERE volume_id=$1",
                &[&VOLUME_ID],
            )
            .unwrap();
        assert_eq!(
            fixture.authority.load_node_owned_volumes(&id(NODE_ID)),
            Err(AuthorityError::BackendUnknown)
        );
        assert_eq!(
            fixture
                .authority
                .load_node_owned_volumes(&id("drifted-node")),
            Err(AuthorityError::BackendUnknown)
        );
    }

    #[test]
    fn runtime_inventory_query_uses_both_owner_indexes_with_large_foreign_history() {
        let mut fixture = Fixture::new();
        insert_generated_owned_volumes(&mut fixture.client, "foreign-node", 1, 50_000);
        fixture
            .client
            .batch_execute("ANALYZE volume_records")
            .unwrap();
        let explain = format!("EXPLAIN (COSTS OFF) {}", node_owned_volumes_sql());
        let plan = fixture
            .client
            .query(&explain, &[&"node-absent-from-large-history", &257_i64])
            .unwrap()
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains("volume_records_owner_node"), "{plan}");
        assert!(plan.contains("volume_records_owner_binding_node"), "{plan}");
        assert!(!plan.contains("Seq Scan on volume_records"), "{plan}");
    }

    #[test]
    fn runtime_inventory_accepts_the_exact_bound_and_rejects_one_more_row() {
        let mut fixture = Fixture::new();
        insert_generated_owned_volumes(
            &mut fixture.client,
            NODE_ID,
            2,
            i64::try_from(MAX_NODE_OWNED_VOLUMES).unwrap(),
        );
        let snapshot = fixture
            .authority
            .load_node_owned_volumes(&id(NODE_ID))
            .unwrap();
        assert_eq!(snapshot.volumes.len(), MAX_NODE_OWNED_VOLUMES);

        let overflow = i64::try_from(MAX_NODE_OWNED_VOLUMES + 1).unwrap();
        insert_generated_owned_volumes(&mut fixture.client, NODE_ID, overflow, overflow);
        assert_eq!(
            fixture.authority.load_node_owned_volumes(&id(NODE_ID)),
            Err(AuthorityError::BackendUnknown)
        );
    }

    #[test]
    fn wrong_owner_epoch_size_and_exact_predecessor_have_zero_side_effects() {
        let mut fixture = Fixture::new();
        let before = fixture.stored();

        assert_eq!(
            fixture
                .authority
                .renew_lease(&renew_request("other-attachment", 7, 30_000)),
            Err(AuthorityError::Fenced)
        );
        assert_eq!(fixture.stored(), before);

        assert_eq!(
            fixture
                .authority
                .renew_lease(&renew_request(ATTACHMENT_ID, 8, 30_000)),
            Err(AuthorityError::Fenced)
        );
        assert_eq!(fixture.stored(), before);

        assert_eq!(
            fixture
                .authority
                .compare_and_swap_head(&cas_request(head(4, 44), head(5, 5))),
            Err(AuthorityError::HeadConflict)
        );
        assert_eq!(fixture.stored(), before);

        let mut resized = fixture.stored();
        resized.size_bytes += 1024 * 1024;
        let mut transaction = fixture.client.transaction().unwrap();
        update_volume(&mut transaction, &resized).unwrap();
        transaction.commit().unwrap();
        let before_size_conflict = fixture.stored();
        assert_eq!(before_size_conflict.size_bytes, VOLUME_SIZE + 1024 * 1024);
        assert_eq!(
            fixture
                .authority
                .compare_and_swap_head(&cas_request(head(4, 4), head(5, 5))),
            Err(AuthorityError::HeadConflict)
        );
        assert_eq!(fixture.stored(), before_size_conflict);
    }

    #[test]
    fn renewal_uses_database_now_crosses_expiry_lapses_and_overflow_fails_closed() {
        let mut fixture = Fixture::new();
        assert_eq!(fixture.record.lease_expires_at, Some(unix_millis(1)));
        let before = database_now(&mut fixture.client);
        let renewed = fixture
            .authority
            .renew_lease(&renew_request(ATTACHMENT_ID, 7, 30_000))
            .unwrap();
        let after = database_now(&mut fixture.client);
        let renewed_at = i64::try_from(renewed.lease_expires_at.get()).unwrap();
        assert!(renewed_at >= before + 30_000);
        assert!(renewed_at <= after + 30_000);
        assert_eq!(
            fixture.stored().lease_expires_at,
            Some(renewed.lease_expires_at)
        );

        let before_overflow = fixture.stored();
        assert_eq!(
            fixture
                .authority
                .renew_lease(&renew_request(ATTACHMENT_ID, 7, i64::MAX as u64)),
            Err(AuthorityError::InvalidLeaseDuration)
        );
        assert_eq!(fixture.stored(), before_overflow);
    }

    #[test]
    fn head_cas_replay_and_two_writer_race_resolve_by_exact_authority() {
        let fixture = Fixture::new();
        let first_target = head(5, 5);
        fixture
            .authority
            .compare_and_swap_head(&cas_request(head(4, 4), first_target.clone()))
            .unwrap();
        assert_eq!(
            fixture
                .authority
                .compare_and_swap_head(&cas_request(head(4, 4), first_target.clone())),
            Err(AuthorityError::HeadConflict),
            "a response-loss replay must reread and recognize the exact target"
        );
        assert_eq!(fixture.stored().head, first_target);

        let race = Fixture::new();
        let left = PostgresVolumeDataAuthority::connect(&race.url, None).unwrap();
        let right = PostgresVolumeDataAuthority::connect(&race.url, None).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let left_barrier = barrier.clone();
        let left_thread = std::thread::spawn(move || {
            left_barrier.wait();
            left.compare_and_swap_head(&cas_request(head(4, 4), head(5, 51)))
        });
        let right_barrier = barrier.clone();
        let right_thread = std::thread::spawn(move || {
            right_barrier.wait();
            right.compare_and_swap_head(&cas_request(head(4, 4), head(5, 52)))
        });
        barrier.wait();
        let outcomes = [left_thread.join().unwrap(), right_thread.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(AuthorityError::HeadConflict))
                .count(),
            1
        );
        let stored = race.stored();
        assert!(stored.head == head(5, 51) || stored.head == head(5, 52));
    }

    #[test]
    fn failed_update_rolls_back_the_complete_authority_row() {
        let mut fixture = Fixture::new();
        let before = fixture.stored();
        fixture
            .client
            .batch_execute(
                "CREATE FUNCTION reject_target_authority_update() RETURNS trigger
                   LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$;
                 CREATE TRIGGER reject_target_authority_update
                   BEFORE UPDATE ON volume_records FOR EACH ROW
                   EXECUTE FUNCTION reject_target_authority_update()",
            )
            .unwrap();

        assert_eq!(
            fixture
                .authority
                .renew_lease(&renew_request(ATTACHMENT_ID, 7, 30_000)),
            Err(AuthorityError::BackendUnknown)
        );
        fixture
            .client
            .batch_execute(
                "DROP TRIGGER reject_target_authority_update ON volume_records;
                 DROP FUNCTION reject_target_authority_update()",
            )
            .unwrap();
        assert_eq!(fixture.stored(), before);
    }
}

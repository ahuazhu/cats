//! Control-plane persistence (SQLite dev implementation of the §17.3 tables).
//!
//! Every user-facing invariant that must hold under concurrency is enforced
//! here with constraints, not in handler code: unique names per project,
//! one mount binding per disk (RWO), at most one live attachment per disk,
//! monotonic generations.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::ids;
use cats_api::resources::*;

pub type Result<T> = std::result::Result<T, ApiError>;

pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() as i64
}

pub fn new_id(prefix: &str) -> String {
    ids::make_id(prefix, &Uuid::new_v4().simple().to_string()[..12])
}

pub struct Store {
    conn: Mutex<Connection>,
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e.to_string())
}

fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(internal)?;
        conn.busy_timeout(std::time::Duration::from_secs(10)).map_err(internal)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(internal)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(internal)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(internal)?;
        conn.execute_batch(SCHEMA).map_err(internal)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn).map_err(|e| {
            if is_constraint(&e) {
                ApiError::conflict(format!("constraint violation: {e}"))
            } else {
                internal(e)
            }
        })
    }

    // ------------------------------------------------------------------
    // Cats
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn create_cat(
        &self,
        project: &str,
        name: &str,
        image: &str,
        cpus: u32,
        memory_mib: u64,
        root_disk_size: u64,
        extra_disk: Option<(&str, u64, &str)>, // (name, size, mount_path)
    ) -> Result<(Cat, Vec<Disk>, Operation)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let now = now_unix();
        let cat_id = new_id(ids::CAT_PREFIX);
        let root_disk_id = new_id(ids::DISK_PREFIX);
        let root_volume = new_id(ids::VOLUME_PREFIX);

        let insert_disk = |tx: &rusqlite::Transaction<'_>,
                           id: &str,
                           dname: &str,
                           kind: &str,
                           size: u64,
                           vol: &str,
                           state: &str|
         -> rusqlite::Result<()> {
            tx.execute(
                "INSERT INTO disks (id, project, name, kind, size_bytes, state, volume_id, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![id, project, dname, kind, size as i64, state, vol, now],
            )?;
            Ok(())
        };

        let result: rusqlite::Result<()> = (|| {
            tx.execute(
                "INSERT INTO cats (id, project, name, image, cpus, memory_mib, root_disk_id,
                                   desired_state, observed_state, generation, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'running','creating',1,?8)",
                params![cat_id, project, name, image, cpus, memory_mib as i64, root_disk_id, now],
            )?;
            insert_disk(&tx, &root_disk_id, &format!("{name}-root"), "root", root_disk_size, &root_volume, "bound")?;
            tx.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES (?1,?2,?3,'/')",
                params![new_id(ids::MOUNT_PREFIX), root_disk_id, cat_id],
            )?;
            if let Some((dname, dsize, dpath)) = extra_disk {
                let disk_id = new_id(ids::DISK_PREFIX);
                insert_disk(&tx, &disk_id, dname, "persistent", dsize, &new_id(ids::VOLUME_PREFIX), "bound")?;
                tx.execute(
                    "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                     VALUES (?1,?2,?3,?4)",
                    params![new_id(ids::MOUNT_PREFIX), disk_id, cat_id, dpath],
                )?;
            }
            Ok(())
        })();
        result.map_err(|e| {
            if is_constraint(&e) {
                ApiError::new(ErrorCode::AlreadyExists, format!("cat or disk name in use: {e}"))
            } else {
                internal(e)
            }
        })?;

        let op = Self::insert_operation(&tx, "cat.create", &cat_id, 1)?;
        tx.commit().map_err(internal)?;
        drop(conn);

        let cat = self.must_get_cat_by_id(&cat_id)?;
        let disks = self.list_disks_for_cat(&cat_id)?;
        Ok((cat, disks, op))
    }

    fn insert_operation(
        tx: &rusqlite::Transaction<'_>,
        kind: &str,
        resource_id: &str,
        generation: i64,
    ) -> Result<Operation> {
        let now = now_unix();
        let id = new_id(ids::OPERATION_PREFIX);
        tx.execute(
            "INSERT INTO operations (id, kind, resource_id, resource_generation, phase, created_at, updated_at)
             VALUES (?1,?2,?3,?4,'pending',?5,?5)",
            params![id, kind, resource_id, generation, now],
        )
        .map_err(internal)?;
        Ok(Operation {
            id,
            kind: kind.to_string(),
            resource_id: resource_id.to_string(),
            resource_generation: generation,
            phase: OperationPhase::Pending,
            error: None,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    pub fn get_cat(&self, project: &str, name_or_id: &str) -> Result<Cat> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM cats WHERE project=?1 AND (name=?2 OR id=?2)",
                params![project, name_or_id],
                row_to_cat,
            )
            .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("cat {name_or_id}")))
    }

    pub fn must_get_cat_by_id(&self, id: &str) -> Result<Cat> {
        self.with(|c| {
            c.query_row("SELECT * FROM cats WHERE id=?1", params![id], row_to_cat).optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("cat {id}")))
    }

    pub fn list_cats(&self, project: &str) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM cats WHERE project=?1 ORDER BY created_at")?;
            let rows = stmt.query_map(params![project], row_to_cat)?;
            rows.collect()
        })
    }

    /// Bump generation and set a new desired state; returns the operation.
    pub fn set_desired(
        &self,
        cat_id: &str,
        desired: DesiredState,
        expected_generation: Option<i64>,
        op_kind: &str,
    ) -> Result<Operation> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let current: Option<i64> = tx
            .query_row("SELECT generation FROM cats WHERE id=?1", params![cat_id], |r| r.get(0))
            .optional()
            .map_err(internal)?;
        let current = current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        if let Some(expected) = expected_generation {
            if expected != current {
                return Err(ApiError::conflict(format!(
                    "generation mismatch: expected {expected}, current {current}"
                )));
            }
        }
        let new_gen = current + 1;
        tx.execute(
            "UPDATE cats SET desired_state=?2, generation=?3 WHERE id=?1",
            params![cat_id, desired_str(desired), new_gen],
        )
        .map_err(internal)?;
        let op = Self::insert_operation(&tx, op_kind, cat_id, new_gen)?;
        tx.commit().map_err(internal)?;
        Ok(op)
    }

    pub fn set_observed(&self, cat_id: &str, observed: ObservedState) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE cats SET observed_state=?2 WHERE id=?1",
                params![cat_id, observed_str(observed)],
            )
            .map(|_| ())
        })
    }

    pub fn set_placement(&self, cat_id: &str, node_id: Option<&str>) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE cats SET node_id=?2 WHERE id=?1", params![cat_id, node_id])
                .map(|_| ())
        })
    }

    pub fn delete_cat_row(&self, cat_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM mount_bindings WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM endpoints WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM routes WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM cats WHERE id=?1", params![cat_id]).map(|_| ())
        })
    }

    /// Cats whose desired/observed disagree (work for the reconciler).
    pub fn cats_needing_work(&self) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM cats WHERE
                   (desired_state='running'   AND observed_state NOT IN ('running'))
                OR (desired_state='suspended' AND observed_state NOT IN ('suspended'))
                OR (desired_state='warm'      AND observed_state NOT IN ('warm'))
                OR (desired_state='cold'      AND observed_state NOT IN ('cold'))
                OR (desired_state='deleted'   AND observed_state NOT IN ('deleted'))
                ORDER BY created_at",
            )?;
            let rows = stmt.query_map([], row_to_cat)?;
            rows.collect()
        })
    }

    // ------------------------------------------------------------------
    // Disks / bindings / attachments
    // ------------------------------------------------------------------

    pub fn create_disk(&self, project: &str, name: &str, size_bytes: u64) -> Result<Disk> {
        let id = new_id(ids::DISK_PREFIX);
        let vol = new_id(ids::VOLUME_PREFIX);
        let now = now_unix();
        self.with(|c| {
            c.execute(
                "INSERT INTO disks (id, project, name, kind, size_bytes, state, volume_id, created_at)
                 VALUES (?1,?2,?3,'persistent',?4,'available',?5,?6)",
                params![id, project, name, size_bytes as i64, vol, now],
            )
            .map(|_| ())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::new(ErrorCode::AlreadyExists, format!("disk name {name} in use"))
            } else {
                e
            }
        })?;
        self.get_disk(project, &id)
    }

    pub fn get_disk(&self, project: &str, name_or_id: &str) -> Result<Disk> {
        let mut disk = self
            .with(|c| {
                c.query_row(
                    "SELECT * FROM disks WHERE project=?1 AND (name=?2 OR id=?2)",
                    params![project, name_or_id],
                    row_to_disk,
                )
                .optional()
            })?
            .ok_or_else(|| ApiError::not_found(format!("disk {name_or_id}")))?;
        disk.bound_cat_id = self.with(|c| {
            c.query_row(
                "SELECT cat_id FROM mount_bindings WHERE disk_id=?1",
                params![disk.id],
                |r| r.get(0),
            )
            .optional()
        })?;
        Ok(disk)
    }

    pub fn list_disks(&self, project: &str) -> Result<Vec<Disk>> {
        let mut disks = self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM disks WHERE project=?1 ORDER BY created_at")?;
            let rows = stmt.query_map(params![project], row_to_disk)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for d in &mut disks {
            d.bound_cat_id = self.with(|c| {
                c.query_row(
                    "SELECT cat_id FROM mount_bindings WHERE disk_id=?1",
                    params![d.id],
                    |r| r.get(0),
                )
                .optional()
            })?;
        }
        Ok(disks)
    }

    pub fn list_disks_for_cat(&self, cat_id: &str) -> Result<Vec<Disk>> {
        let ids: Vec<String> = self.with(|c| {
            let mut stmt =
                c.prepare("SELECT disk_id FROM mount_bindings WHERE cat_id=?1 ORDER BY id")?;
            let rows = stmt.query_map(params![cat_id], |r| r.get(0))?;
            rows.collect()
        })?;
        let mut out = Vec::new();
        for id in ids {
            let d = self.with(|c| {
                c.query_row("SELECT * FROM disks WHERE id=?1", params![id], row_to_disk).optional()
            })?;
            if let Some(mut d) = d {
                d.bound_cat_id = Some(cat_id.to_string());
                out.push(d);
            }
        }
        Ok(out)
    }

    pub fn get_binding(&self, disk_id: &str) -> Result<Option<MountBinding>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, disk_id, cat_id, mount_path FROM mount_bindings WHERE disk_id=?1",
                params![disk_id],
                |r| {
                    Ok(MountBinding {
                        id: r.get(0)?,
                        disk_id: r.get(1)?,
                        cat_id: r.get(2)?,
                        mount_path: r.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn bindings_for_cat(&self, cat_id: &str) -> Result<Vec<MountBinding>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, disk_id, cat_id, mount_path FROM mount_bindings WHERE cat_id=?1 ORDER BY id",
            )?;
            let rows = stmt.query_map(params![cat_id], |r| {
                Ok(MountBinding {
                    id: r.get(0)?,
                    disk_id: r.get(1)?,
                    cat_id: r.get(2)?,
                    mount_path: r.get(3)?,
                })
            })?;
            rows.collect()
        })
    }

    /// RWO: unique index on mount_bindings.disk_id makes a second bind fail.
    pub fn bind_disk(&self, disk_id: &str, cat_id: &str, mount_path: &str) -> Result<MountBinding> {
        let id = new_id(ids::MOUNT_PREFIX);
        self.with(|c| {
            c.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path) VALUES (?1,?2,?3,?4)",
                params![id, disk_id, cat_id, mount_path],
            )?;
            c.execute("UPDATE disks SET state='bound' WHERE id=?1", params![disk_id])?;
            Ok(())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::conflict("disk is already bound (RWO)")
            } else {
                e
            }
        })?;
        Ok(MountBinding {
            id,
            disk_id: disk_id.to_string(),
            cat_id: cat_id.to_string(),
            mount_path: mount_path.to_string(),
        })
    }

    pub fn unbind_disk(&self, disk_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM mount_bindings WHERE disk_id=?1", params![disk_id])?;
            c.execute(
                "UPDATE disks SET state='available' WHERE id=?1 AND kind='persistent'",
                params![disk_id],
            )
            .map(|_| ())
        })
    }

    pub fn set_disk_state(&self, disk_id: &str, state: DiskState) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE disks SET state=?2 WHERE id=?1",
                params![disk_id, disk_state_str(state)],
            )
            .map(|_| ())
        })
    }

    pub fn set_disk_size(&self, disk_id: &str, size: u64) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE disks SET size_bytes=?2 WHERE id=?1", params![disk_id, size as i64])
                .map(|_| ())
        })
    }

    pub fn delete_disk_row(&self, disk_id: &str) -> Result<()> {
        self.with(|c| c.execute("DELETE FROM disks WHERE id=?1", params![disk_id]).map(|_| ()))
    }

    // ------------------------------------------------------------------
    // Nodes
    // ------------------------------------------------------------------

    pub fn register_node(
        &self,
        node_id: &str,
        agent_url: &str,
        gateway_url: &str,
        cpus: u32,
        memory_mib: u64,
    ) -> Result<()> {
        let now = now_ms();
        self.with(|c| {
            c.execute(
                "INSERT INTO nodes (id, agent_url, gateway_url, state, cpus, memory_mib, last_heartbeat_ms)
                 VALUES (?1,?2,?3,'ready',?4,?5,?6)
                 ON CONFLICT(id) DO UPDATE SET
                   agent_url=?2, gateway_url=?3, state='ready', cpus=?4, memory_mib=?5, last_heartbeat_ms=?6",
                params![node_id, agent_url, gateway_url, cpus, memory_mib as i64, now],
            )
            .map(|_| ())
        })
    }

    pub fn heartbeat_node(&self, node_id: &str) -> Result<()> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE nodes SET last_heartbeat_ms=?2, state=CASE WHEN state='lost' THEN 'ready' ELSE state END
                 WHERE id=?1",
                params![node_id, now_ms()],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn list_nodes(&self) -> Result<Vec<Node>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM nodes ORDER BY id")?;
            let rows = stmt.query_map([], row_to_node)?;
            rows.collect()
        })
    }

    pub fn set_node_state(&self, node_id: &str, state: NodeState) -> Result<()> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE nodes SET state=?2 WHERE id=?1",
                params![node_id, node_state_str(state)],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn cats_on_node(&self, node_id: &str) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM cats WHERE node_id=?1")?;
            let rows = stmt.query_map(params![node_id], row_to_cat)?;
            rows.collect()
        })
    }

    // ------------------------------------------------------------------
    // Operations / idempotency
    // ------------------------------------------------------------------

    pub fn get_operation(&self, id: &str) -> Result<Operation> {
        self.with(|c| {
            c.query_row("SELECT * FROM operations WHERE id=?1", params![id], row_to_operation)
                .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("operation {id}")))
    }

    pub fn pending_operations_for(&self, resource_id: &str) -> Result<Vec<Operation>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM operations WHERE resource_id=?1 AND phase IN ('pending','running')",
            )?;
            let rows = stmt.query_map(params![resource_id], row_to_operation)?;
            rows.collect()
        })
    }

    pub fn finish_operation(&self, op_id: &str, error: Option<&ErrorBody>) -> Result<()> {
        let phase = if error.is_some() { "failed" } else { "succeeded" };
        let err_json = error.map(|e| serde_json::to_string(e).expect("error serializes"));
        self.with(|c| {
            c.execute(
                "UPDATE operations SET phase=?2, error_json=?3, updated_at=?4
                 WHERE id=?1 AND phase IN ('pending','running')",
                params![op_id, phase, err_json, now_unix()],
            )
            .map(|_| ())
        })
    }

    /// Returns the previously stored operation id for this idempotency key.
    pub fn idempotency_lookup(&self, key: &str, route: &str) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row(
                "SELECT operation_id FROM idempotency WHERE key=?1 AND route=?2",
                params![key, route],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn idempotency_store(&self, key: &str, route: &str, operation_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO idempotency (key, route, operation_id) VALUES (?1,?2,?3)",
                params![key, route, operation_id],
            )
            .map(|_| ())
        })
    }

    // ------------------------------------------------------------------
    // Endpoints / routes
    // ------------------------------------------------------------------

    pub fn create_endpoint(
        &self,
        cat: &Cat,
        name: &str,
        target_port: u16,
        protocol: &str,
        wake: WakePolicy,
    ) -> Result<Endpoint> {
        let id = new_id(ids::ENDPOINT_PREFIX);
        let hostname = format!("{}.{}.{}.cats.local", name, cat.name, cat.project);
        self.with(|c| {
            c.execute(
                "INSERT INTO endpoints (id, cat_id, name, hostname, target_port, protocol, wake_policy)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    cat.id,
                    name,
                    hostname,
                    target_port,
                    protocol,
                    wake_str(wake)
                ],
            )?;
            c.execute(
                "INSERT INTO routes (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
                 VALUES (?1,?2,NULL,NULL,?3,0,'unbound')",
                params![hostname, cat.id, target_port],
            )
            .map(|_| ())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::new(ErrorCode::AlreadyExists, "endpoint name in use")
            } else {
                e
            }
        })?;
        Ok(Endpoint {
            id,
            cat_id: cat.id.clone(),
            name: name.to_string(),
            hostname,
            target_port,
            protocol: protocol.to_string(),
            wake_policy: wake,
        })
    }

    pub fn endpoints_for_cat(&self, cat_id: &str) -> Result<Vec<Endpoint>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM endpoints WHERE cat_id=?1 ORDER BY id")?;
            let rows = stmt.query_map(params![cat_id], row_to_endpoint)?;
            rows.collect()
        })
    }

    /// Publish routes for a cat now running on `node`; bumps each epoch.
    pub fn publish_routes(&self, cat_id: &str, node_id: &str, gateway_url: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE routes SET node_id=?2, gateway_url=?3, epoch=epoch+1, state='active'
                 WHERE cat_id=?1",
                params![cat_id, node_id, gateway_url],
            )
            .map(|_| ())
        })
    }

    pub fn unbind_routes(&self, cat_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE routes SET node_id=NULL, gateway_url=NULL, epoch=epoch+1, state='unbound'
                 WHERE cat_id=?1",
                params![cat_id],
            )
            .map(|_| ())
        })
    }

    pub fn resolve_route(&self, hostname: &str) -> Result<(RouteBinding, String)> {
        let row = self
            .with(|c| {
                c.query_row(
                    "SELECT r.hostname, r.cat_id, r.node_id, r.gateway_url, r.target_port, r.epoch,
                            r.state, e.wake_policy, c.project
                       FROM routes r
                       JOIN endpoints e ON e.hostname = r.hostname
                       JOIN cats c ON c.id = r.cat_id
                      WHERE r.hostname = ?1",
                    params![hostname],
                    |r| {
                        Ok((
                            RouteBinding {
                                hostname: r.get(0)?,
                                cat_id: r.get(1)?,
                                node_id: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                                gateway_url: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                                target_port: r.get::<_, u16>(4)?,
                                epoch: r.get(5)?,
                                wake_policy: parse_wake(&r.get::<_, String>(7)?),
                                project: r.get(8)?,
                            },
                            r.get::<_, String>(6)?,
                        ))
                    },
                )
                .optional()
            })?
            .ok_or_else(|| ApiError::not_found(format!("route {hostname}")))?;
        Ok(row)
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis() as i64
}

// ---------------------------------------------------------------------------
// Row mappers and enum codecs
// ---------------------------------------------------------------------------

fn desired_str(d: DesiredState) -> &'static str {
    match d {
        DesiredState::Running => "running",
        DesiredState::Suspended => "suspended",
        DesiredState::Warm => "warm",
        DesiredState::Cold => "cold",
        DesiredState::Deleted => "deleted",
    }
}

pub fn parse_desired(s: &str) -> DesiredState {
    match s {
        "running" => DesiredState::Running,
        "suspended" => DesiredState::Suspended,
        "warm" => DesiredState::Warm,
        "deleted" => DesiredState::Deleted,
        _ => DesiredState::Cold,
    }
}

fn observed_str(o: ObservedState) -> &'static str {
    match o {
        ObservedState::Creating => "creating",
        ObservedState::Starting => "starting",
        ObservedState::Running => "running",
        ObservedState::Suspending => "suspending",
        ObservedState::Suspended => "suspended",
        ObservedState::Warming => "warming",
        ObservedState::Warm => "warm",
        ObservedState::Stopping => "stopping",
        ObservedState::Cold => "cold",
        ObservedState::Failed => "failed",
        ObservedState::Deleted => "deleted",
        ObservedState::Unknown => "unknown",
    }
}

pub fn parse_observed(s: &str) -> ObservedState {
    match s {
        "creating" => ObservedState::Creating,
        "starting" => ObservedState::Starting,
        "running" => ObservedState::Running,
        "suspending" => ObservedState::Suspending,
        "suspended" => ObservedState::Suspended,
        "warming" => ObservedState::Warming,
        "warm" => ObservedState::Warm,
        "stopping" => ObservedState::Stopping,
        "failed" => ObservedState::Failed,
        "deleted" => ObservedState::Deleted,
        "unknown" => ObservedState::Unknown,
        _ => ObservedState::Cold,
    }
}

fn disk_state_str(s: DiskState) -> &'static str {
    match s {
        DiskState::Creating => "creating",
        DiskState::Available => "available",
        DiskState::Bound => "bound",
        DiskState::Deleting => "deleting",
        DiskState::Deleted => "deleted",
    }
}

fn node_state_str(s: NodeState) -> &'static str {
    match s {
        NodeState::Ready => "ready",
        NodeState::Cordoned => "cordoned",
        NodeState::Lost => "lost",
    }
}

fn wake_str(w: WakePolicy) -> &'static str {
    match w {
        WakePolicy::WakeOnRequest => "wake_on_request",
        WakePolicy::NoWake => "no_wake",
    }
}

pub fn parse_wake(s: &str) -> WakePolicy {
    if s == "no_wake" {
        WakePolicy::NoWake
    } else {
        WakePolicy::WakeOnRequest
    }
}

fn row_to_cat(r: &rusqlite::Row<'_>) -> rusqlite::Result<Cat> {
    Ok(Cat {
        id: r.get("id")?,
        project: r.get("project")?,
        name: r.get("name")?,
        image: r.get("image")?,
        spec: CatSpec { cpus: r.get("cpus")?, memory_mib: r.get::<_, i64>("memory_mib")? as u64 },
        root_disk_id: r.get("root_disk_id")?,
        desired_state: parse_desired(&r.get::<_, String>("desired_state")?),
        observed_state: parse_observed(&r.get::<_, String>("observed_state")?),
        generation: r.get("generation")?,
        node_id: r.get("node_id")?,
        created_at_unix: r.get("created_at")?,
    })
}

fn row_to_disk(r: &rusqlite::Row<'_>) -> rusqlite::Result<Disk> {
    let kind: String = r.get("kind")?;
    let state: String = r.get("state")?;
    Ok(Disk {
        id: r.get("id")?,
        project: r.get("project")?,
        name: r.get("name")?,
        kind: if kind == "root" { DiskKind::Root } else { DiskKind::Persistent },
        size_bytes: r.get::<_, i64>("size_bytes")? as u64,
        state: match state.as_str() {
            "creating" => DiskState::Creating,
            "bound" => DiskState::Bound,
            "deleting" => DiskState::Deleting,
            "deleted" => DiskState::Deleted,
            _ => DiskState::Available,
        },
        volume_id: r.get("volume_id")?,
        bound_cat_id: None,
        created_at_unix: r.get("created_at")?,
    })
}

fn row_to_node(r: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let state: String = r.get("state")?;
    Ok(Node {
        id: r.get("id")?,
        agent_url: r.get("agent_url")?,
        gateway_url: r.get("gateway_url")?,
        state: match state.as_str() {
            "cordoned" => NodeState::Cordoned,
            "lost" => NodeState::Lost,
            _ => NodeState::Ready,
        },
        capacity: NodeCapacity {
            cpus: r.get("cpus")?,
            memory_mib: r.get::<_, i64>("memory_mib")? as u64,
        },
        last_heartbeat_unix: r.get::<_, i64>("last_heartbeat_ms")? / 1000,
    })
}

fn row_to_operation(r: &rusqlite::Row<'_>) -> rusqlite::Result<Operation> {
    let phase: String = r.get("phase")?;
    let err_json: Option<String> = r.get("error_json")?;
    Ok(Operation {
        id: r.get("id")?,
        kind: r.get("kind")?,
        resource_id: r.get("resource_id")?,
        resource_generation: r.get("resource_generation")?,
        phase: match phase.as_str() {
            "running" => OperationPhase::Running,
            "succeeded" => OperationPhase::Succeeded,
            "failed" => OperationPhase::Failed,
            _ => OperationPhase::Pending,
        },
        error: err_json.and_then(|j| serde_json::from_str(&j).ok()),
        created_at_unix: r.get("created_at")?,
        updated_at_unix: r.get("updated_at")?,
    })
}

fn row_to_endpoint(r: &rusqlite::Row<'_>) -> rusqlite::Result<Endpoint> {
    Ok(Endpoint {
        id: r.get("id")?,
        cat_id: r.get("cat_id")?,
        name: r.get("name")?,
        hostname: r.get("hostname")?,
        target_port: r.get("target_port")?,
        protocol: r.get("protocol")?,
        wake_policy: parse_wake(&r.get::<_, String>("wake_policy")?),
    })
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cats (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    cpus INTEGER NOT NULL,
    memory_mib INTEGER NOT NULL,
    root_disk_id TEXT NOT NULL,
    desired_state TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    node_id TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE (project, name)
);
CREATE TABLE IF NOT EXISTS disks (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    state TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (project, name)
);
CREATE TABLE IF NOT EXISTS mount_bindings (
    id TEXT PRIMARY KEY,
    disk_id TEXT NOT NULL UNIQUE,
    cat_id TEXT NOT NULL,
    mount_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    agent_url TEXT NOT NULL,
    gateway_url TEXT NOT NULL,
    state TEXT NOT NULL,
    cpus INTEGER NOT NULL,
    memory_mib INTEGER NOT NULL,
    last_heartbeat_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_generation INTEGER NOT NULL,
    phase TEXT NOT NULL,
    error_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT NOT NULL,
    route TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    PRIMARY KEY (key, route)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL UNIQUE,
    target_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    wake_policy TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (
    hostname TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    node_id TEXT,
    gateway_url TEXT,
    target_port INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    state TEXT NOT NULL
);
";

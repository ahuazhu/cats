use super::*;

impl Store {
    // ------------------------------------------------------------------
    // Cats
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn create_cat(
        &self,
        workspace: &WorkspaceRecord,
        name: &str,
        image: &str,
        cpus: u32,
        memory_mib: u64,
        root_disk_size: u64,
        auto_suspend: bool,
        extra_disk: Option<(&str, u64, &str)>, // (name, size, mount_path)
        expires_at_unix: Option<i64>,
        durability: DiskDurability,
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
                "INSERT INTO disks (
                    id, workspace_id, name, kind, size_bytes,
                    state, volume_id, created_at, durability
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    id,
                    workspace.id,
                    dname,
                    kind,
                    size as i64,
                    state,
                    vol,
                    now,
                    durability.as_str()
                ],
            )?;
            Ok(())
        };

        let result: rusqlite::Result<()> = (|| {
            tx.execute(
                "INSERT INTO cats (
                    id, workspace_id, name, image, cpus, memory_mib,
                    root_disk_id, desired_state, observed_state, generation,
                    auto_suspend, created_at, observed_state_since_ms, expires_at_unix
                 ) VALUES (
                    ?1,?2,?3,?4,?5,?6,?7,
                    'running','creating',1,?8,?9,?10,?11
                 )",
                params![
                    cat_id,
                    workspace.id,
                    name,
                    image,
                    cpus,
                    memory_mib as i64,
                    root_disk_id,
                    i64::from(auto_suspend),
                    now,
                    now.saturating_mul(1000),
                    expires_at_unix
                ],
            )?;
            let default_endpoint_id = new_id(ids::ENDPOINT_PREFIX);
            let default_hostname = public_endpoint_hostname(
                &Cat {
                    id: cat_id.clone(),
                    workspace_id: workspace.id.clone(),
                    name: name.to_string(),
                    image: image.to_string(),
                    spec: CatSpec { cpus, memory_mib },
                    root_disk_id: root_disk_id.clone(),
                    desired_state: DesiredState::Running,
                    observed_state: ObservedState::Creating,
                    generation: 1,
                    auto_suspend,
                    node_id: None,
                    created_at_unix: now,
                    observed_state_since_unix_ms: now.saturating_mul(1000),
                    expires_at_unix,
                },
                DEFAULT_ENDPOINT_NAME,
            );
            tx.execute(
                "INSERT INTO endpoints
                    (id, cat_id, name, hostname, target_port, protocol, wake_policy)
                 VALUES (?1,?2,?3,?4,?5,'http','wake_on_request')",
                params![
                    default_endpoint_id,
                    cat_id,
                    DEFAULT_ENDPOINT_NAME,
                    default_hostname,
                    DEFAULT_ENDPOINT_PORT
                ],
            )?;
            tx.execute(
                "INSERT INTO routes
                    (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
                 VALUES (?1,?2,NULL,NULL,?3,0,'unbound')",
                params![default_hostname, cat_id, DEFAULT_ENDPOINT_PORT],
            )?;
            insert_disk(
                &tx,
                &root_disk_id,
                &format!("{name}-root"),
                "root",
                root_disk_size,
                &root_volume,
                "bound",
            )?;
            tx.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES (?1,?2,?3,'/')",
                params![new_id(ids::MOUNT_PREFIX), root_disk_id, cat_id],
            )?;
            if let Some((dname, dsize, dpath)) = extra_disk {
                let disk_id = new_id(ids::DISK_PREFIX);
                insert_disk(
                    &tx,
                    &disk_id,
                    dname,
                    "persistent",
                    dsize,
                    &new_id(ids::VOLUME_PREFIX),
                    "bound",
                )?;
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
                ApiError::new(
                    ErrorCode::AlreadyExists,
                    format!("cat or disk name in use: {e}"),
                )
            } else {
                internal(e)
            }
        })?;

        let op = Self::insert_operation(&tx, &workspace.id, "cat.create", &cat_id, 1)?;
        tx.commit().map_err(internal)?;
        drop(conn);

        let cat = self.must_get_cat_by_id(&cat_id)?;
        let disks = self.list_disks_for_cat(&cat_id)?;
        Ok((cat, disks, op))
    }

    pub fn get_cat(&self, workspace_id: &str, name_or_id: &str) -> Result<Cat> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM cats WHERE workspace_id=?1 AND (name=?2 OR id=?2)",
                params![workspace_id, name_or_id],
                row_to_cat,
            )
            .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("cat {name_or_id}")))
    }

    pub fn find_cat_by_id(&self, id: &str) -> Result<Option<Cat>> {
        self.with(|c| {
            c.query_row("SELECT * FROM cats WHERE id=?1", params![id], row_to_cat)
                .optional()
        })
    }

    pub fn must_get_cat_by_id(&self, id: &str) -> Result<Cat> {
        self.find_cat_by_id(id)?
            .ok_or_else(|| ApiError::not_found(format!("cat {id}")))
    }

    pub fn list_cats(&self, workspace_id: &str) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT * FROM cats WHERE workspace_id=?1 ORDER BY created_at")?;
            let rows = stmt.query_map(params![workspace_id], row_to_cat)?;
            rows.collect()
        })
    }

    pub fn list_all_cats(&self) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM cats ORDER BY created_at")?;
            let rows = stmt.query_map([], row_to_cat)?;
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
        let current: Option<(i64, String)> = tx
            .query_row(
                "SELECT generation, workspace_id FROM cats WHERE id=?1",
                params![cat_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(internal)?;
        let (current, workspace_id) =
            current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        if let Some(expected) = expected_generation {
            if expected != current {
                return Err(ApiError::conflict(format!(
                    "generation mismatch: expected {expected}, current {current}"
                )));
            }
        }
        if op_kind != "cat.auto_suspend" {
            Self::fail_pending_auto_tier(&tx, cat_id, "superseded by a newer Cat action")?;
        }
        let new_gen = current + 1;
        tx.execute(
            "UPDATE cats SET desired_state=?2, generation=?3 WHERE id=?1",
            params![cat_id, desired_str(desired), new_gen],
        )
        .map_err(internal)?;
        let op = Self::insert_operation(&tx, &workspace_id, op_kind, cat_id, new_gen)?;
        tx.commit().map_err(internal)?;
        Ok(op)
    }

    /// Atomically request Running only if no other caller has already done
    /// so. Gateway and exec can race on the first request after sleep; one
    /// generation and one wake operation is enough for all of them.
    pub fn ensure_desired_running(&self, cat_id: &str) -> Result<Option<Operation>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let current: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT generation, workspace_id, desired_state FROM cats WHERE id=?1",
                params![cat_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        let (generation, workspace_id, desired) =
            current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        if desired == "running" {
            return Ok(None);
        }
        Self::fail_pending_auto_tier(&tx, cat_id, "superseded by active work")?;
        let next = generation + 1;
        tx.execute(
            "UPDATE cats SET desired_state='running', generation=?2 WHERE id=?1",
            params![cat_id, next],
        )
        .map_err(internal)?;
        let operation = Self::insert_operation(&tx, &workspace_id, "cat.wake", cat_id, next)?;
        tx.commit().map_err(internal)?;
        Ok(Some(operation))
    }

    pub fn set_observed(&self, cat_id: &str, observed: ObservedState) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE cats
                    SET observed_state_since_ms = CASE
                            WHEN observed_state=?2 THEN observed_state_since_ms
                            ELSE ?3
                        END,
                        observed_state=?2
                  WHERE id=?1",
                params![cat_id, observed_str(observed), now_ms()],
            )
            .map(|_| ())
        })
    }

    /// Record a physical transition result only while its transitional state
    /// is still current. This lets a stale suspend result describe reality
    /// without overwriting a newer stable generation.
    pub fn finish_transition(
        &self,
        cat_id: &str,
        transitional: ObservedState,
        target: ObservedState,
    ) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE cats
                    SET observed_state=?3, observed_state_since_ms=?4
                 WHERE id=?1 AND observed_state=?2",
                params![
                    cat_id,
                    observed_str(transitional),
                    observed_str(target),
                    now_ms()
                ],
            )
            .map(|changed| changed == 1)
        })
    }

    /// Pick a node with room for this Cat and record the placement, in one step.
    ///
    /// Scheduling used to be a read (`list_nodes`, then `cats_on_node` per node)
    /// followed by a separate `set_placement` write. That is only safe while Cats
    /// are placed one at a time: two concurrent start flows would both read the
    /// same free capacity and both claim it, overcommitting the node. Choosing and
    /// claiming under one lock is what makes concurrent placement safe.
    ///
    /// Returns `None` when nothing fits, which the caller retries on a later tick.
    pub fn claim_node_for(
        &self,
        cat_id: &str,
        cpus: u32,
        memory_mib: u64,
        node_lease_timeout_ms: i64,
        now_ms: i64,
    ) -> Result<Option<Node>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM nodes ORDER BY id")?;
            let nodes = stmt
                .query_map([], row_to_node)?
                .collect::<rusqlite::Result<Vec<Node>>>()?;
            let mut best: Option<(u64, Node)> = None;
            for node in nodes {
                if node.state != NodeState::Ready {
                    continue;
                }
                if now_ms - node.last_heartbeat_unix * 1000 > node_lease_timeout_ms {
                    continue;
                }
                // This Cat's own row is excluded so re-placing it does not count
                // its resources against itself.
                let (used_cpus, used_mem): (u32, u64) = c.query_row(
                    "SELECT COALESCE(SUM(cpus), 0), COALESCE(SUM(memory_mib), 0)
                       FROM cats WHERE node_id = ?1 AND id <> ?2",
                    params![node.id, cat_id],
                    |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, i64>(1)? as u64)),
                )?;
                if used_cpus + cpus <= node.capacity.cpus
                    && used_mem + memory_mib <= node.capacity.memory_mib
                    && best.as_ref().is_none_or(|(mem, _)| used_mem < *mem)
                {
                    best = Some((used_mem, node));
                }
            }
            let Some((_, node)) = best else {
                return Ok(None);
            };
            c.execute(
                "UPDATE cats SET node_id = ?2 WHERE id = ?1",
                params![cat_id, node.id],
            )?;
            Ok(Some(node))
        })
    }

    pub fn set_placement(&self, cat_id: &str, node_id: Option<&str>) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE cats SET node_id=?2 WHERE id=?1",
                params![cat_id, node_id],
            )
            .map(|_| ())
        })
    }

    pub fn delete_cat_row(&self, cat_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1",
                params![cat_id],
            )?;
            c.execute(
                "DELETE FROM cat_work_sources WHERE cat_id=?1",
                params![cat_id],
            )?;
            c.execute(
                "DELETE FROM mount_bindings WHERE cat_id=?1",
                params![cat_id],
            )?;
            c.execute("DELETE FROM endpoints WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM routes WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM cats WHERE id=?1", params![cat_id])
                .map(|_| ())
        })
    }

    // ------------------------------------------------------------------
    // Work-driven auto-suspend
    // ------------------------------------------------------------------

    pub fn set_auto_suspend(&self, cat_id: &str, enabled: bool) -> Result<Cat> {
        self.with(|c| {
            c.execute(
                "UPDATE cats SET auto_suspend=?2 WHERE id=?1",
                params![cat_id, i64::from(enabled)],
            )
            .map(|_| ())
        })?;
        self.must_get_cat_by_id(cat_id)
    }

    /// Set or clear the absolute expiry. Does not bump the generation: expiry
    /// is bookkeeping about the future, not a lifecycle mutation.
    pub fn set_expiry(&self, cat_id: &str, expires_at_unix: Option<i64>) -> Result<Cat> {
        self.with(|c| {
            c.execute(
                "UPDATE cats SET expires_at_unix=?2 WHERE id=?1",
                params![cat_id, expires_at_unix],
            )
            .map(|_| ())
        })?;
        self.must_get_cat_by_id(cat_id)
    }

    /// Cats whose absolute expiry has passed and that are not already being
    /// deleted. The controller converges each one to Deleted.
    pub fn expired_cat_candidates(&self) -> Result<Vec<String>> {
        let now = now_unix();
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM cats
                 WHERE expires_at_unix IS NOT NULL
                   AND expires_at_unix <= ?1
                   AND desired_state != 'deleted'",
            )?;
            let rows = stmt.query_map(params![now], |row| row.get(0))?;
            rows.collect()
        })
    }
}

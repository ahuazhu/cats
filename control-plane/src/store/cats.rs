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
        self.create_cat_inner(
            workspace,
            name,
            image,
            cpus,
            memory_mib,
            root_disk_size,
            auto_suspend,
            extra_disk,
            expires_at_unix,
            durability,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_cat_idempotent(
        &self,
        workspace: &WorkspaceRecord,
        name: &str,
        image: &str,
        cpus: u32,
        memory_mib: u64,
        root_disk_size: u64,
        auto_suspend: bool,
        extra_disk: Option<(&str, u64, &str)>,
        expires_at_unix: Option<i64>,
        durability: DiskDurability,
        key: &str,
        route: &str,
    ) -> Result<(Cat, Vec<Disk>, Operation)> {
        self.create_cat_inner(
            workspace,
            name,
            image,
            cpus,
            memory_mib,
            root_disk_size,
            auto_suspend,
            extra_disk,
            expires_at_unix,
            durability,
            Some((key, route)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_cat_inner(
        &self,
        workspace: &WorkspaceRecord,
        name: &str,
        image: &str,
        cpus: u32,
        memory_mib: u64,
        root_disk_size: u64,
        auto_suspend: bool,
        extra_disk: Option<(&str, u64, &str)>,
        expires_at_unix: Option<i64>,
        durability: DiskDurability,
        idempotency: Option<(&str, &str)>,
    ) -> Result<(Cat, Vec<Disk>, Operation)> {
        // The lock covers exactly the transaction; the follow-up reads below
        // re-enter the store and would deadlock inside it.
        let (cat_id, op) = self.enter(|client| -> Result<(String, Operation)> {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            if let Some((key, route)) = idempotency {
                if let Some(operation) = Self::idempotency_operation_in(&mut tx, key, route)? {
                    let cat_exists = tx
                        .query_opt("SELECT 1 FROM cats WHERE id=$1", &[&operation.resource_id])
                        .map_err(internal)?
                        .is_some();
                    if cat_exists {
                        let cat_id = operation.resource_id.clone();
                        tx.commit().map_err(internal)?;
                        return Ok((cat_id, operation));
                    }
                    // A create key outlives the Cat it created. Once that Cat
                    // is gone, the key is stale and may create the name again.
                    tx.execute(
                        "DELETE FROM idempotency WHERE key=$1 AND route=$2",
                        &[&key, &route],
                    )
                    .map_err(internal)?;
                }
            }
            let now = now_unix();
            let cat_id = new_id(ids::CAT_PREFIX);
            let root_disk_id = new_id(ids::DISK_PREFIX);
            let root_volume = new_id(ids::VOLUME_PREFIX);

            let insert_disk = |tx: &mut postgres::Transaction<'_>,
                               id: &str,
                               dname: &str,
                               kind: &str,
                               size: u64,
                               vol: &str,
                               state: &str|
             -> std::result::Result<(), postgres::Error> {
                let size = size as i64;
                tx.execute(
                    "INSERT INTO disks (
                    id, workspace_id, name, kind, size_bytes,
                    state, volume_id, created_at, durability
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    &[
                        &id,
                        &workspace.id,
                        &dname,
                        &kind,
                        &size,
                        &state,
                        &vol,
                        &now,
                        &durability.as_str(),
                    ],
                )?;
                Ok(())
            };

            let result: std::result::Result<(), postgres::Error> = (|| {
                let cpus_param = cpus as i64;
                let memory_mib_param = memory_mib as i64;
                tx.execute(
                    "INSERT INTO cats (
                    id, workspace_id, name, image, cpus, memory_mib,
                    root_disk_id, desired_state, observed_state, generation,
                    auto_suspend, created_at, observed_state_since_ms, expires_at_unix
                 ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,
                    'running','creating',1,$8,$9,$10,$11
                 )",
                    &[
                        &cat_id,
                        &workspace.id,
                        &name,
                        &image,
                        &cpus_param,
                        &memory_mib_param,
                        &root_disk_id,
                        &auto_suspend,
                        &now,
                        &now.saturating_mul(1000),
                        &expires_at_unix,
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
                let default_endpoint_port = DEFAULT_ENDPOINT_PORT as i64;
                tx.execute(
                    "INSERT INTO endpoints
                    (id, cat_id, name, hostname, target_port, protocol, wake_policy)
                 VALUES ($1,$2,$3,$4,$5,'http','wake_on_request')",
                    &[
                        &default_endpoint_id,
                        &cat_id,
                        &DEFAULT_ENDPOINT_NAME,
                        &default_hostname,
                        &default_endpoint_port,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO routes
                    (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
                 VALUES ($1,$2,NULL,NULL,$3,0,'unbound')",
                    &[&default_hostname, &cat_id, &default_endpoint_port],
                )?;
                insert_disk(
                    &mut tx,
                    &root_disk_id,
                    &format!("{name}-root"),
                    "root",
                    root_disk_size,
                    &root_volume,
                    "bound",
                )?;
                tx.execute(
                    "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES ($1,$2,$3,'/')",
                    &[&new_id(ids::MOUNT_PREFIX), &root_disk_id, &cat_id],
                )?;
                if let Some((dname, dsize, dpath)) = extra_disk {
                    let disk_id = new_id(ids::DISK_PREFIX);
                    insert_disk(
                        &mut tx,
                        &disk_id,
                        dname,
                        "persistent",
                        dsize,
                        &new_id(ids::VOLUME_PREFIX),
                        "bound",
                    )?;
                    tx.execute(
                        "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                     VALUES ($1,$2,$3,$4)",
                        &[&new_id(ids::MOUNT_PREFIX), &disk_id, &cat_id, &dpath],
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

            let op = Self::insert_operation(&mut tx, &workspace.id, "cat.create", &cat_id, 1)?;
            if let Some((key, route)) = idempotency {
                Self::store_idempotency_in(&mut tx, key, route, &op.id)?;
            }
            tx.commit().map_err(internal)?;
            Ok((cat_id, op))
        })?;

        let cat = self.must_get_cat_by_id(&cat_id)?;
        let disks = self.list_disks_for_cat(&cat_id)?;
        Ok((cat, disks, op))
    }

    pub fn get_cat(&self, workspace_id: &str, name_or_id: &str) -> Result<Cat> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT * FROM cats WHERE workspace_id=$1 AND (name=$2 OR id=$2)",
                    &[&workspace_id, &name_or_id],
                )?
                .map(|row| row_to_cat(&row))
                .transpose()
        })?
        .ok_or_else(|| ApiError::not_found(format!("cat {name_or_id}")))
    }

    pub fn find_cat_by_id(&self, id: &str) -> Result<Option<Cat>> {
        self.with(|client| {
            client
                .query_opt("SELECT * FROM cats WHERE id=$1", &[&id])?
                .map(|row| row_to_cat(&row))
                .transpose()
        })
    }

    pub fn must_get_cat_by_id(&self, id: &str) -> Result<Cat> {
        self.find_cat_by_id(id)?
            .ok_or_else(|| ApiError::not_found(format!("cat {id}")))
    }

    pub fn list_cats(&self, workspace_id: &str) -> Result<Vec<Cat>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM cats WHERE workspace_id=$1 ORDER BY created_at",
                    &[&workspace_id],
                )?
                .iter()
                .map(row_to_cat)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    pub fn list_all_cats(&self) -> Result<Vec<Cat>> {
        self.with(|client| {
            client
                .query("SELECT * FROM cats ORDER BY created_at", &[])?
                .iter()
                .map(row_to_cat)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
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
        self.set_desired_inner(cat_id, desired, expected_generation, op_kind, None)
    }

    pub fn set_desired_idempotent(
        &self,
        cat_id: &str,
        desired: DesiredState,
        expected_generation: Option<i64>,
        op_kind: &str,
        key: &str,
        route: &str,
    ) -> Result<Operation> {
        self.set_desired_inner(
            cat_id,
            desired,
            expected_generation,
            op_kind,
            Some((key, route)),
        )
    }

    fn set_desired_inner(
        &self,
        cat_id: &str,
        desired: DesiredState,
        expected_generation: Option<i64>,
        op_kind: &str,
        idempotency: Option<(&str, &str)>,
    ) -> Result<Operation> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let current: Option<(i64, String, String, String, Option<String>, i64)> = tx
                .query_opt(
                    "SELECT generation, workspace_id, desired_state, observed_state,
                            lifecycle_dispatch_json, observed_generation
                       FROM cats WHERE id=$1 FOR UPDATE",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(|r| -> std::result::Result<_, postgres::Error> {
                    Ok((
                        r.try_get(0)?,
                        r.try_get(1)?,
                        r.try_get(2)?,
                        r.try_get(3)?,
                        r.try_get(4)?,
                        r.try_get(5)?,
                    ))
                })
                .transpose()
                .map_err(internal)?;
            let (current, workspace_id, current_desired, observed, dispatch, observed_generation) =
                current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
            if let Some(expected) = expected_generation {
                if expected != current {
                    return Err(ApiError::conflict(format!(
                        "generation mismatch: expected {expected}, current {current}"
                    )));
                }
            }
            if current_desired == "deleted" && desired != DesiredState::Deleted {
                return Err(ApiError::conflict(
                    "Cat deletion is terminal and cannot be superseded",
                ));
            }
            if let Some((key, route)) = idempotency {
                if let Some(operation) = Self::idempotency_operation_in(&mut tx, key, route)? {
                    tx.commit().map_err(internal)?;
                    return Ok(operation);
                }
            }
            if current_desired == desired_str(desired) && observed != "failed" {
                if let Some(operation) =
                    Self::lifecycle_operation_for_generation_in(&mut tx, cat_id, current)?
                {
                    if let Some((key, route)) = idempotency {
                        Self::store_idempotency_in(&mut tx, key, route, &operation.id)?;
                    }
                    tx.commit().map_err(internal)?;
                    return Ok(operation);
                }
                let operation =
                    Self::insert_operation(&mut tx, &workspace_id, op_kind, cat_id, current)?;
                let physically_converged = dispatch.is_none()
                    && observed_generation == current
                    && desired_matches_observed_state(&current_desired, &observed);
                if physically_converged {
                    Self::finish_operation_in(&mut tx, &operation.id, None)?;
                }
                if let Some((key, route)) = idempotency {
                    Self::store_idempotency_in(&mut tx, key, route, &operation.id)?;
                }
                tx.commit().map_err(internal)?;
                return Ok(row_to_finished_operation(operation, physically_converged));
            }
            if op_kind != "cat.auto_suspend" {
                Self::fail_pending_auto_tier(&mut tx, cat_id, "superseded by a newer Cat action")?;
            }
            let new_gen = current + 1;
            Self::fail_active_lifecycle_operations_before(&mut tx, cat_id, new_gen)?;
            tx.execute(
                "UPDATE cats SET desired_state=$2, generation=$3 WHERE id=$1",
                &[&cat_id, &desired_str(desired), &new_gen],
            )
            .map_err(internal)?;
            let op = Self::insert_operation(&mut tx, &workspace_id, op_kind, cat_id, new_gen)?;
            if let Some((key, route)) = idempotency {
                Self::store_idempotency_in(&mut tx, key, route, &op.id)?;
            }
            tx.commit().map_err(internal)?;
            Ok(op)
        })
    }

    /// Atomically request Running only if no other caller has already done
    /// so. Gateway and exec can race on the first request after sleep; one
    /// generation and one wake operation is enough for all of them.
    pub fn ensure_desired_running(&self, cat_id: &str) -> Result<Option<Operation>> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let current: Option<(i64, String, String)> = tx
                .query_opt(
                    "SELECT generation, workspace_id, desired_state FROM cats WHERE id=$1 FOR UPDATE",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(
                    |row| -> std::result::Result<(i64, String, String), postgres::Error> {
                        Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
                    },
                )
                .transpose()
                .map_err(internal)?;
            let (generation, workspace_id, desired) =
                current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
            if desired == "deleted" {
                return Err(ApiError::conflict(
                    "Cat deletion is terminal and cannot be superseded by work",
                ));
            }
            if desired == "running" {
                return Ok(None);
            }
            Self::fail_pending_auto_tier(&mut tx, cat_id, "superseded by active work")?;
            let next = generation + 1;
            Self::fail_active_lifecycle_operations_before(&mut tx, cat_id, next)?;
            tx.execute(
                "UPDATE cats SET desired_state='running', generation=$2 WHERE id=$1",
                &[&cat_id, &next],
            )
            .map_err(internal)?;
            let operation =
                Self::insert_operation(&mut tx, &workspace_id, "cat.wake", cat_id, next)?;
            tx.commit().map_err(internal)?;
            Ok(Some(operation))
        })
    }

    pub fn set_observed(&self, cat_id: &str, observed: ObservedState) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET observed_state_since_ms = CASE
                                WHEN observed_state=$2 THEN observed_state_since_ms
                                ELSE $3
                            END,
                            observed_state=$2
                      WHERE id=$1",
                    &[&cat_id, &observed_str(observed), &now_ms()],
                )
                .map(|_| ())
        })
    }

    pub fn set_observed_for_generation(
        &self,
        cat_id: &str,
        observed: ObservedState,
        generation: i64,
    ) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET observed_state_since_ms = CASE
                                WHEN observed_state=$2 THEN observed_state_since_ms
                                ELSE $4
                            END,
                            observed_state=$2,
                            observed_generation=$3
                      WHERE id=$1",
                    &[&cat_id, &observed_str(observed), &generation, &now_ms()],
                )
                .map(|_| ())
        })
    }

    pub fn observed_generation(&self, cat_id: &str) -> Result<i64> {
        self.with(|client| {
            client
                .query_one(
                    "SELECT observed_generation FROM cats WHERE id=$1",
                    &[&cat_id],
                )?
                .try_get(0)
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
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET observed_state=$3, observed_state_since_ms=$4
                     WHERE id=$1 AND observed_state=$2",
                    &[
                        &cat_id,
                        &observed_str(transitional),
                        &observed_str(target),
                        &now_ms(),
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
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            // Capacity is a fleet-wide invariant, not a per-row one. The
            // transaction lock serializes the read-sum-claim sequence across
            // Store instances without blocking node heartbeat row updates.
            lock_placement(&mut tx).map_err(internal)?;
            let nodes = tx
                .query("SELECT * FROM nodes ORDER BY id", &[])
                .map_err(internal)?
                .iter()
                .map(row_to_node)
                .collect::<std::result::Result<Vec<Node>, postgres::Error>>()
                .map_err(internal)?;
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
                let usage = tx
                    .query_one(
                    "SELECT COALESCE(SUM(cpus), 0)::BIGINT, COALESCE(SUM(memory_mib), 0)::BIGINT
                       FROM cats WHERE node_id = $1 AND id <> $2",
                    &[&node.id, &cat_id],
                )
                    .map_err(internal)?;
                let (used_cpus, used_mem): (u32, u64) = (
                    usage.try_get::<_, i64>(0).map_err(internal)? as u32,
                    usage.try_get::<_, i64>(1).map_err(internal)? as u64,
                );
                if used_cpus + cpus <= node.capacity.cpus
                    && used_mem + memory_mib <= node.capacity.memory_mib
                    && best.as_ref().is_none_or(|(mem, _)| used_mem < *mem)
                {
                    best = Some((used_mem, node));
                }
            }
            let Some((_, node)) = best else {
                tx.commit().map_err(internal)?;
                return Ok(None);
            };
            let changed = tx
                .execute(
                    "UPDATE cats SET node_id = $2 WHERE id = $1",
                    &[&cat_id, &node.id],
                )
                .map_err(internal)?;
            if changed == 0 {
                return Err(ApiError::not_found(format!("cat {cat_id}")));
            }
            tx.commit().map_err(internal)?;
            Ok(Some(node))
        })
    }

    pub fn set_placement(&self, cat_id: &str, node_id: Option<&str>) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats SET node_id=$2 WHERE id=$1",
                    &[&cat_id, &node_id],
                )
                .map(|_| ())
        })
    }

    pub fn delete_cat_row(&self, cat_id: &str) -> Result<()> {
        self.with(|client| {
            client.execute("DELETE FROM cat_work_leases WHERE cat_id=$1", &[&cat_id])?;
            client.execute("DELETE FROM cat_work_sources WHERE cat_id=$1", &[&cat_id])?;
            client.execute("DELETE FROM mount_bindings WHERE cat_id=$1", &[&cat_id])?;
            client.execute("DELETE FROM endpoints WHERE cat_id=$1", &[&cat_id])?;
            client.execute("DELETE FROM routes WHERE cat_id=$1", &[&cat_id])?;
            client.execute("DELETE FROM oci_deployments WHERE cat_id=$1", &[&cat_id])?;
            client
                .execute("DELETE FROM cats WHERE id=$1", &[&cat_id])
                .map(|_| ())
        })
    }

    // ------------------------------------------------------------------
    // Work-driven auto-suspend
    // ------------------------------------------------------------------

    pub fn set_auto_suspend(&self, cat_id: &str, enabled: bool) -> Result<Cat> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats SET auto_suspend=$2 WHERE id=$1",
                    &[&cat_id, &enabled],
                )
                .map(|_| ())
        })?;
        self.must_get_cat_by_id(cat_id)
    }

    /// Set or clear the absolute expiry. Does not bump the generation: expiry
    /// is bookkeeping about the future, not a lifecycle mutation.
    pub fn set_expiry(&self, cat_id: &str, expires_at_unix: Option<i64>) -> Result<Cat> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats SET expires_at_unix=$2 WHERE id=$1",
                    &[&cat_id, &expires_at_unix],
                )
                .map(|_| ())
        })?;
        self.must_get_cat_by_id(cat_id)
    }

    /// Cats whose absolute expiry has passed and that are not already being
    /// deleted. The controller converges each one to Deleted.
    pub fn expired_cat_candidates(&self) -> Result<Vec<String>> {
        let now = now_unix();
        self.with(|client| {
            client
                .query(
                    "SELECT id FROM cats
                     WHERE expires_at_unix IS NOT NULL
                       AND expires_at_unix <= $1
                       AND desired_state != 'deleted'",
                    &[&now],
                )?
                .iter()
                .map(|row| row.try_get(0))
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }
}

fn desired_matches_observed_state(desired: &str, observed: &str) -> bool {
    matches!(
        (desired, observed),
        ("running", "running") | ("suspended", "suspended") | ("warm", "warm") | ("cold", "cold")
    )
}

fn row_to_finished_operation(mut operation: Operation, finished: bool) -> Operation {
    if finished {
        operation.phase = OperationPhase::Succeeded;
        operation.updated_at_unix = now_unix();
    }
    operation
}

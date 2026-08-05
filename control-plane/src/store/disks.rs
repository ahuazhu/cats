use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskChangeMode {
    HotRunning,
    OfflineCold,
}

impl Store {
    // ------------------------------------------------------------------
    // Disks / bindings / attachments
    // ------------------------------------------------------------------

    pub fn create_disk(
        &self,
        workspace: &WorkspaceRecord,
        name: &str,
        size_bytes: u64,
        durability: DiskDurability,
    ) -> Result<Disk> {
        let id = new_id(ids::DISK_PREFIX);
        let vol = new_id(ids::VOLUME_PREFIX);
        let now = now_unix();
        let size_bytes = size_bytes as i64;
        self.with(|client| {
            client
                .execute(
                    "INSERT INTO disks (
                        id, workspace_id, name, kind, size_bytes,
                        state, volume_id, created_at, durability
                     ) VALUES ($1,$2,$3,'persistent',$4,'available',$5,$6,$7)",
                    &[
                        &id,
                        &workspace.id,
                        &name,
                        &size_bytes,
                        &vol,
                        &now,
                        &durability.as_str(),
                    ],
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
        self.get_disk(&workspace.id, &id)
    }

    pub fn get_disk(&self, workspace_id: &str, name_or_id: &str) -> Result<Disk> {
        let mut disk = self
            .with(|client| {
                client
                    .query_opt(
                        "SELECT * FROM disks WHERE workspace_id=$1 AND (name=$2 OR id=$2)",
                        &[&workspace_id, &name_or_id],
                    )?
                    .map(|row| row_to_disk(&row))
                    .transpose()
            })?
            .ok_or_else(|| ApiError::not_found(format!("disk {name_or_id}")))?;
        disk.bound_cat_id = self.with(|client| {
            client
                .query_opt(
                    "SELECT cat_id FROM mount_bindings WHERE disk_id=$1",
                    &[&disk.id],
                )?
                .map(|r| r.try_get(0))
                .transpose()
        })?;
        Ok(disk)
    }

    pub fn list_disks(&self, workspace_id: &str) -> Result<Vec<Disk>> {
        let mut disks = self.with(|client| {
            client
                .query(
                    "SELECT * FROM disks WHERE workspace_id=$1 ORDER BY created_at",
                    &[&workspace_id],
                )?
                .iter()
                .map(row_to_disk)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })?;
        for d in &mut disks {
            d.bound_cat_id = self.with(|client| {
                client
                    .query_opt(
                        "SELECT cat_id FROM mount_bindings WHERE disk_id=$1",
                        &[&d.id],
                    )?
                    .map(|r| r.try_get(0))
                    .transpose()
            })?;
        }
        Ok(disks)
    }

    pub fn list_disks_for_cat(&self, cat_id: &str) -> Result<Vec<Disk>> {
        let ids: Vec<String> = self.with(|client| {
            client
                .query(
                    "SELECT disk_id FROM mount_bindings WHERE cat_id=$1 ORDER BY id",
                    &[&cat_id],
                )?
                .iter()
                .map(|r| r.try_get(0))
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })?;
        let mut out = Vec::new();
        for id in ids {
            let d = self.with(|client| {
                client
                    .query_opt("SELECT * FROM disks WHERE id=$1", &[&id])?
                    .map(|row| row_to_disk(&row))
                    .transpose()
            })?;
            if let Some(mut d) = d {
                d.bound_cat_id = Some(cat_id.to_string());
                out.push(d);
            }
        }
        Ok(out)
    }

    pub fn bindings_for_cat(&self, cat_id: &str) -> Result<Vec<MountBinding>> {
        self.with(|client| {
            client
                .query(
                    "SELECT id, disk_id, cat_id, mount_path FROM mount_bindings WHERE cat_id=$1 ORDER BY id",
                    &[&cat_id],
                )?
                .iter()
                .map(|r| {
                    Ok(MountBinding {
                        id: r.try_get(0)?,
                        disk_id: r.try_get(1)?,
                        cat_id: r.try_get(2)?,
                        mount_path: r.try_get(3)?,
                    })
                })
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    /// RWO: unique index on mount_bindings.disk_id makes a second bind fail.
    pub fn bind_disk(&self, disk_id: &str, cat_id: &str, mount_path: &str) -> Result<MountBinding> {
        let id = new_id(ids::MOUNT_PREFIX);
        self.with(|client| {
            client.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path) VALUES ($1,$2,$3,$4)",
                &[&id, &disk_id, &cat_id, &mount_path],
            )?;
            client.execute("UPDATE disks SET state='bound' WHERE id=$1", &[&disk_id])?;
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

    /// Atomically require a fully converged Running generation before changing
    /// disk topology. A lifecycle marker owns the node runtime, so mount must
    /// have zero side effects until that marker settles.
    pub fn bind_disk_for_hot_change(
        &self,
        disk_id: &str,
        cat_id: &str,
        mount_path: &str,
    ) -> Result<(MountBinding, DiskChangeMode)> {
        let id = new_id(ids::MOUNT_PREFIX);
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let mode = ensure_disk_change_safe(&mut tx, cat_id)?;
            tx.query_one("SELECT 1 FROM disks WHERE id=$1 FOR UPDATE", &[&disk_id])
                .map_err(internal)?;
            tx.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES ($1,$2,$3,$4)",
                &[&id, &disk_id, &cat_id, &mount_path],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    ApiError::conflict("disk is already bound (RWO)")
                } else {
                    internal(error)
                }
            })?;
            tx.execute("UPDATE disks SET state='bound' WHERE id=$1", &[&disk_id])
                .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok((
                MountBinding {
                    id,
                    disk_id: disk_id.to_string(),
                    cat_id: cat_id.to_string(),
                    mount_path: mount_path.to_string(),
                },
                mode,
            ))
        })
    }

    /// The unbind itself is the transaction's linearization point. The API
    /// restores this exact binding if the following idempotent node detach does
    /// not complete.
    pub fn unbind_disk_for_hot_change(
        &self,
        disk_id: &str,
        cat_id: &str,
    ) -> Result<(MountBinding, DiskChangeMode)> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let mode = ensure_disk_change_safe(&mut tx, cat_id)?;
            let binding = tx
                .query_opt(
                    "SELECT id, disk_id, cat_id, mount_path
                       FROM mount_bindings WHERE disk_id=$1 AND cat_id=$2 FOR UPDATE",
                    &[&disk_id, &cat_id],
                )
                .map_err(internal)?
                .ok_or_else(|| ApiError::failed_precondition("disk is not mounted on this Cat"))?;
            let binding = MountBinding {
                id: binding.try_get(0).map_err(internal)?,
                disk_id: binding.try_get(1).map_err(internal)?,
                cat_id: binding.try_get(2).map_err(internal)?,
                mount_path: binding.try_get(3).map_err(internal)?,
            };
            tx.execute("DELETE FROM mount_bindings WHERE disk_id=$1", &[&disk_id])
                .map_err(internal)?;
            tx.execute(
                "UPDATE disks SET state='available' WHERE id=$1 AND kind='persistent'",
                &[&disk_id],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok((binding, mode))
        })
    }

    pub fn restore_binding(&self, binding: &MountBinding) -> Result<()> {
        self.with(|client| {
            client.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES ($1,$2,$3,$4) ON CONFLICT (disk_id) DO NOTHING",
                &[
                    &binding.id,
                    &binding.disk_id,
                    &binding.cat_id,
                    &binding.mount_path,
                ],
            )?;
            client
                .execute(
                    "UPDATE disks SET state='bound' WHERE id=$1",
                    &[&binding.disk_id],
                )
                .map(|_| ())
        })
    }

    pub fn unbind_disk(&self, disk_id: &str) -> Result<()> {
        self.with(|client| {
            client.execute("DELETE FROM mount_bindings WHERE disk_id=$1", &[&disk_id])?;
            client
                .execute(
                    "UPDATE disks SET state='available' WHERE id=$1 AND kind='persistent'",
                    &[&disk_id],
                )
                .map(|_| ())
        })
    }

    pub fn set_disk_size(&self, disk_id: &str, size: u64) -> Result<()> {
        let size = size as i64;
        self.with(|client| {
            client
                .execute(
                    "UPDATE disks SET size_bytes=$2 WHERE id=$1",
                    &[&disk_id, &size],
                )
                .map(|_| ())
        })
    }

    pub fn delete_disk_row(&self, disk_id: &str) -> Result<()> {
        self.with(|client| {
            client
                .execute("DELETE FROM disks WHERE id=$1", &[&disk_id])
                .map(|_| ())
        })
    }
}

fn ensure_disk_change_safe(
    tx: &mut postgres::Transaction<'_>,
    cat_id: &str,
) -> Result<DiskChangeMode> {
    let cat = tx
        .query_opt(
            "SELECT desired_state, observed_state, generation, observed_generation,
                    lifecycle_dispatch_json, node_id
               FROM cats WHERE id=$1 FOR UPDATE",
            &[&cat_id],
        )
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
    let desired: String = cat.try_get(0).map_err(internal)?;
    let observed: String = cat.try_get(1).map_err(internal)?;
    let generation: i64 = cat.try_get(2).map_err(internal)?;
    let observed_generation: i64 = cat.try_get(3).map_err(internal)?;
    let marker: Option<String> = cat.try_get(4).map_err(internal)?;
    let node_id: Option<String> = cat.try_get(5).map_err(internal)?;
    if observed_generation != generation || marker.is_some() {
        return Err(ApiError::conflict(
            "disk change requires a markerless, generation-converged Cat",
        ));
    }
    match (desired.as_str(), observed.as_str(), node_id) {
        ("running", "running", Some(_)) => Ok(DiskChangeMode::HotRunning),
        ("cold", "cold", None) => Ok(DiskChangeMode::OfflineCold),
        _ => Err(ApiError::conflict(
            "disk change requires a stable Running Cat or a fully offline Cold Cat",
        )),
    }
}

use super::*;

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
        self.with(|c| {
            c.execute(
                "INSERT INTO disks (
                    id, workspace_id, name, kind, size_bytes,
                    state, volume_id, created_at, durability
                 ) VALUES (?1,?2,?3,'persistent',?4,'available',?5,?6,?7)",
                params![
                    id,
                    workspace.id,
                    name,
                    size_bytes as i64,
                    vol,
                    now,
                    durability.as_str()
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
            .with(|c| {
                c.query_row(
                    "SELECT * FROM disks WHERE workspace_id=?1 AND (name=?2 OR id=?2)",
                    params![workspace_id, name_or_id],
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

    pub fn list_disks(&self, workspace_id: &str) -> Result<Vec<Disk>> {
        let mut disks = self.with(|c| {
            let mut stmt =
                c.prepare("SELECT * FROM disks WHERE workspace_id=?1 ORDER BY created_at")?;
            let rows = stmt.query_map(params![workspace_id], row_to_disk)?;
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
                c.query_row("SELECT * FROM disks WHERE id=?1", params![id], row_to_disk)
                    .optional()
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
            c.execute(
                "UPDATE disks SET state='bound' WHERE id=?1",
                params![disk_id],
            )?;
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
            c.execute(
                "DELETE FROM mount_bindings WHERE disk_id=?1",
                params![disk_id],
            )?;
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
            c.execute(
                "UPDATE disks SET size_bytes=?2 WHERE id=?1",
                params![disk_id, size as i64],
            )
            .map(|_| ())
        })
    }

    pub fn delete_disk_row(&self, disk_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM disks WHERE id=?1", params![disk_id])
                .map(|_| ())
        })
    }
}

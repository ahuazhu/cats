use super::*;

pub use cats_api::nodejob::VolumeLeaseAuthority;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DiskChangeMode {
    HotRunning,
    OfflineCold,
}

/// Durable ownership of one topology transition. The provisional binding is
/// also the disk-wide RWO claim: mount inserts it before attach, while unmount
/// keeps it until detach and exact lease revocation both finish.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TopologyClaim {
    pub claim_id: String,
    pub cat_id: String,
    pub node_id: Option<String>,
    pub cat_generation: i64,
    pub mode: DiskChangeMode,
    pub action: TopologyAction,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TopologyAction {
    Mount {
        binding: MountBinding,
    },
    Unmount {
        binding: MountBinding,
        original_lease: Option<VolumeLeaseAuthority>,
    },
}

impl TopologyClaim {
    pub fn binding(&self) -> &MountBinding {
        match &self.action {
            TopologyAction::Mount { binding } | TopologyAction::Unmount { binding, .. } => binding,
        }
    }
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

    /// Host-bound persistent bindings that may have been committed by a v3
    /// handler before the v4 maintenance freeze but not applied to the Host.
    /// The operator drain acknowledgement prevents the repair dispatch from
    /// racing the old request that created this ambiguity.
    pub fn legacy_topology_reconciliation_candidates(&self) -> Result<Vec<(Cat, MountBinding)>> {
        self.with(|client| {
            client
                .query(
                    "SELECT c.*, b.id AS binding_id,
                            b.disk_id AS binding_disk_id,
                            b.cat_id AS binding_cat_id,
                            b.mount_path AS binding_mount_path
                       FROM cats c
                       JOIN mount_bindings b ON b.cat_id=c.id
                       JOIN disks d ON d.id=b.disk_id AND d.kind='persistent'
                      WHERE c.desired_state=c.observed_state
                        AND c.observed_state IN ('running','suspended','warm')
                        AND c.observed_generation=c.generation
                        AND c.node_id IS NOT NULL
                        AND c.lifecycle_dispatch_json IS NULL
                        AND c.topology_claim_json IS NULL
                      ORDER BY c.id, b.id",
                    &[],
                )?
                .iter()
                .map(|row| {
                    Ok((
                        row_to_cat(row)?,
                        MountBinding {
                            id: row.try_get("binding_id")?,
                            disk_id: row.try_get("binding_disk_id")?,
                            cat_id: row.try_get("binding_cat_id")?,
                            mount_path: row.try_get("binding_mount_path")?,
                        },
                    ))
                })
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    pub fn legacy_topology_binding_matches(
        &self,
        cat: &Cat,
        binding: &MountBinding,
    ) -> Result<bool> {
        self.with(|client| {
            Ok(client
                .query_opt(
                    "SELECT 1 FROM cats c
                       JOIN mount_bindings b ON b.cat_id=c.id
                      WHERE c.id=$1 AND c.generation=$2
                        AND c.desired_state=c.observed_state
                        AND c.observed_state IN ('running','suspended','warm')
                        AND c.observed_generation=c.generation
                        AND c.node_id IS NOT DISTINCT FROM $3::TEXT
                        AND c.lifecycle_dispatch_json IS NULL
                        AND c.topology_claim_json IS NULL
                        AND b.id=$4 AND b.disk_id=$5 AND b.mount_path=$6",
                    &[
                        &cat.id,
                        &cat.generation,
                        &cat.node_id,
                        &binding.id,
                        &binding.disk_id,
                        &binding.mount_path,
                    ],
                )?
                .is_some())
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

    /// Persist the mount authority and provisional RWO binding in one
    /// transaction. Lifecycle work cannot begin until the claim is settled.
    pub fn begin_mount_topology_claim(
        &self,
        disk_id: &str,
        cat_id: &str,
        mount_path: &str,
    ) -> Result<TopologyClaim> {
        let id = new_id(ids::MOUNT_PREFIX);
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let mode = ensure_disk_change_safe(&mut tx, cat_id)?;
            let disk = tx
                .query_opt("SELECT kind FROM disks WHERE id=$1 FOR UPDATE", &[&disk_id])
                .map_err(internal)?
                .ok_or_else(|| ApiError::not_found(format!("disk {disk_id}")))?;
            let kind: String = disk.try_get(0).map_err(internal)?;
            if kind != "persistent" {
                return Err(ApiError::failed_precondition("cannot mount a root disk"));
            }
            let node_id: Option<String> = tx
                .query_one("SELECT node_id FROM cats WHERE id=$1", &[&cat_id])
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            let generation: i64 = tx
                .query_one("SELECT generation FROM cats WHERE id=$1", &[&cat_id])
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            let binding = MountBinding {
                id,
                disk_id: disk_id.to_string(),
                cat_id: cat_id.to_string(),
                mount_path: mount_path.to_string(),
            };
            let claim = TopologyClaim {
                claim_id: new_id("topology_"),
                cat_id: cat_id.to_string(),
                node_id,
                cat_generation: generation,
                mode,
                action: TopologyAction::Mount {
                    binding: binding.clone(),
                },
            };
            let json = serde_json::to_string(&claim).map_err(internal)?;
            let claimed = tx
                .execute(
                    "UPDATE cats SET topology_claim_json=$2
                      WHERE id=$1 AND topology_claim_json IS NULL",
                    &[&cat_id, &json],
                )
                .map_err(internal)?;
            if claimed != 1 {
                return Err(ApiError::conflict(
                    "a different topology claim owns this Cat",
                ));
            }
            tx.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES ($1,$2,$3,$4)",
                &[
                    &binding.id,
                    &binding.disk_id,
                    &binding.cat_id,
                    &binding.mount_path,
                ],
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
            Ok(claim)
        })
    }

    /// Persist the exact binding and writer inspected before detach. The
    /// binding remains in place as a disk-wide RWO claim until success, so a
    /// cancellation or delayed response cannot admit a remount.
    pub fn begin_unmount_topology_claim(
        &self,
        disk_id: &str,
        cat_id: &str,
        original_lease: Option<VolumeLeaseAuthority>,
    ) -> Result<TopologyClaim> {
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
            let row = tx
                .query_one(
                    "SELECT node_id, generation FROM cats WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?;
            let claim = TopologyClaim {
                claim_id: new_id("topology_"),
                cat_id: cat_id.to_string(),
                node_id: row.try_get(0).map_err(internal)?,
                cat_generation: row.try_get(1).map_err(internal)?,
                mode,
                action: TopologyAction::Unmount {
                    binding,
                    original_lease,
                },
            };
            let json = serde_json::to_string(&claim).map_err(internal)?;
            tx.execute(
                "UPDATE cats SET topology_claim_json=$2
                  WHERE id=$1 AND topology_claim_json IS NULL",
                &[&cat_id, &json],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(claim)
        })
    }

    pub fn topology_claim(&self, cat_id: &str) -> Result<Option<TopologyClaim>> {
        let json: Option<String> = self
            .with(|client| {
                client
                    .query_opt(
                        "SELECT topology_claim_json FROM cats WHERE id=$1",
                        &[&cat_id],
                    )?
                    .map(|row| row.try_get::<_, Option<String>>(0))
                    .transpose()
            })?
            .flatten();
        json.map(|json| serde_json::from_str(&json).map_err(internal))
            .transpose()
    }

    pub fn topology_claim_matches(&self, claim: &TopologyClaim) -> Result<bool> {
        let expected = serde_json::to_string(claim).map_err(internal)?;
        self.with(|client| {
            let row = client.query_opt(
                "SELECT 1 FROM cats
                      WHERE id=$1 AND generation=$2
                        AND node_id IS NOT DISTINCT FROM $3::TEXT
                        AND lifecycle_dispatch_json IS NULL
                        AND topology_claim_json=$4",
                &[
                    &claim.cat_id,
                    &claim.cat_generation,
                    &claim.node_id,
                    &expected,
                ],
            )?;
            Ok(row.is_some())
        })
    }

    pub fn complete_topology_claim(&self, claim: &TopologyClaim) -> Result<bool> {
        self.settle_topology_claim(claim, true)
    }

    pub fn rollback_topology_claim(&self, claim: &TopologyClaim) -> Result<bool> {
        self.settle_topology_claim(claim, false)
    }

    fn settle_topology_claim(&self, claim: &TopologyClaim, success: bool) -> Result<bool> {
        let expected = serde_json::to_string(claim).map_err(internal)?;
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let exact = tx
                .query_opt(
                    "SELECT 1 FROM cats
                      WHERE id=$1 AND generation=$2
                        AND node_id IS NOT DISTINCT FROM $3::TEXT
                        AND lifecycle_dispatch_json IS NULL
                        AND topology_claim_json=$4 FOR UPDATE",
                    &[
                        &claim.cat_id,
                        &claim.cat_generation,
                        &claim.node_id,
                        &expected,
                    ],
                )
                .map_err(internal)?
                .is_some();
            if !exact {
                tx.commit().map_err(internal)?;
                return Ok(false);
            }
            let binding = claim.binding();
            let remove_binding = matches!(&claim.action, TopologyAction::Mount { .. }) && !success
                || matches!(&claim.action, TopologyAction::Unmount { .. }) && success;
            if remove_binding {
                tx.execute(
                    "DELETE FROM mount_bindings
                      WHERE id=$1 AND disk_id=$2 AND cat_id=$3",
                    &[&binding.id, &binding.disk_id, &binding.cat_id],
                )
                .map_err(internal)?;
                tx.execute(
                    "UPDATE disks SET state='available'
                      WHERE id=$1 AND kind='persistent'",
                    &[&binding.disk_id],
                )
                .map_err(internal)?;
            }
            tx.execute(
                "UPDATE cats SET topology_claim_json=NULL
                  WHERE id=$1 AND topology_claim_json=$2",
                &[&claim.cat_id, &expected],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(true)
        })
    }

    /// Compatibility wrappers kept for store-level callers while topology
    /// execution moves through the durable claim driver.
    pub fn bind_disk_for_hot_change(
        &self,
        disk_id: &str,
        cat_id: &str,
        mount_path: &str,
    ) -> Result<(MountBinding, DiskChangeMode)> {
        let claim = self.begin_mount_topology_claim(disk_id, cat_id, mount_path)?;
        Ok((claim.binding().clone(), claim.mode))
    }

    pub fn unbind_disk_for_hot_change(
        &self,
        disk_id: &str,
        cat_id: &str,
    ) -> Result<(MountBinding, DiskChangeMode)> {
        let claim = self.begin_unmount_topology_claim(disk_id, cat_id, None)?;
        Ok((claim.binding().clone(), claim.mode))
    }

    pub fn restore_binding(&self, binding: &MountBinding) -> Result<()> {
        let Some(claim) = self.topology_claim(&binding.cat_id)? else {
            return Ok(());
        };
        if claim.binding().id != binding.id {
            return Err(ApiError::conflict(
                "a different topology claim owns this Cat",
            ));
        }
        self.rollback_topology_claim(&claim).map(|_| ())
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
    let frozen: bool = tx
        .query_one(
            "SELECT lifecycle_maintenance_frozen
               FROM control_schema_version WHERE singleton FOR SHARE",
            &[],
        )
        .map_err(internal)?
        .try_get(0)
        .map_err(internal)?;
    if frozen {
        return Err(ApiError::conflict(
            "disk topology is frozen during lifecycle provenance maintenance",
        ));
    }
    let cat = tx
        .query_opt(
            "SELECT desired_state, observed_state, generation, observed_generation,
                    lifecycle_dispatch_json, node_id, topology_claim_json
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
    let topology_claim: Option<String> = cat.try_get(6).map_err(internal)?;
    if observed_generation != generation || marker.is_some() || topology_claim.is_some() {
        return Err(ApiError::conflict(
            "disk change requires a markerless, generation-converged, topology-idle Cat",
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

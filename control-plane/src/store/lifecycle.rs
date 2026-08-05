use super::*;

use cats_api::nodejob::{NodeJobAction, StopCatDisposition, SuspendWorkFence};
use serde::{Deserialize, Serialize};

/// Exact durable provenance for one Cat lifecycle dispatch.
///
/// The desired state and Cat generation may change while the node is applying
/// this job.  This record therefore owns the physical transition until its
/// exact identity is settled; a successor must replay `job` byte-for-byte in
/// meaning before reconciling the newer desired state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleDispatch {
    pub dispatch_id: String,
    pub node_id: String,
    pub source_state: ObservedState,
    pub transitional_state: ObservedState,
    pub target_state: ObservedState,
    pub operation_ids: Vec<String>,
    /// Writer pairs observed before the node action. A successful Stop or wake
    /// fallback may revoke only these identities; a later owner is never
    /// rediscovered and treated as the old dispatch's writer.
    #[serde(default)]
    pub volume_leases: Vec<VolumeLeaseAuthority>,
    pub job: NodeJob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyLifecycleBegin {
    Begun,
    GateEnabled,
    Stale,
}

impl Store {
    pub fn lifecycle_maintenance_frozen(&self) -> Result<bool> {
        self.with(|client| {
            client
                .query_one(
                    "SELECT lifecycle_maintenance_frozen
                       FROM control_schema_version WHERE singleton",
                    &[],
                )?
                .try_get(0)
        })
    }

    /// Database-enforced Phase-A maintenance boundary. The PostgreSQL trigger
    /// also fences replicas from before this build: after this row commits they
    /// cannot create a Cat or change desired/generation, while their already
    /// persisted transition is still allowed to settle.
    pub fn set_lifecycle_maintenance_frozen(&self, frozen: bool) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE control_schema_version
                        SET lifecycle_maintenance_frozen=$1,
                            lifecycle_maintenance_epoch=CASE
                                WHEN $1 AND NOT lifecycle_maintenance_frozen
                                THEN lifecycle_maintenance_epoch+1
                                ELSE lifecycle_maintenance_epoch
                            END,
                            legacy_topology_handlers_drained=CASE
                                WHEN $1 AND NOT lifecycle_maintenance_frozen THEN FALSE
                                ELSE legacy_topology_handlers_drained
                            END,
                            legacy_topology_reconciled=CASE
                                WHEN $1 AND NOT lifecycle_maintenance_frozen THEN FALSE
                                ELSE legacy_topology_reconciled
                            END
                      WHERE singleton",
                    &[&frozen],
                )
                .map(|_| ())
        })
    }

    /// Operator acknowledgement that every pre-v4 topology handler has been
    /// removed and its at-most-60-second node request has drained. The
    /// reconciler may only repair database/Host ambiguity after this point;
    /// otherwise it could race an old attach or detach still in flight.
    pub fn confirm_legacy_topology_handlers_drained(&self) -> Result<()> {
        let changed = self.with(|client| {
            client.execute(
                "UPDATE control_schema_version
                    SET legacy_topology_handlers_drained=TRUE,
                        legacy_topology_reconciled=NOT EXISTS (
                            SELECT 1 FROM mount_bindings b
                            JOIN disks d ON d.id=b.disk_id AND d.kind='persistent'
                            JOIN cats c ON c.id=b.cat_id
                            WHERE c.observed_state IN ('running','suspended','warm')
                              AND c.desired_state=c.observed_state
                              AND c.observed_generation=c.generation
                              AND c.node_id IS NOT NULL
                        )
                  WHERE singleton AND lifecycle_maintenance_frozen",
                &[],
            )
        })?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ApiError::conflict(
                "legacy topology drain confirmation requires the maintenance freeze",
            ))
        }
    }

    pub fn legacy_topology_reconciliation_epoch(&self) -> Result<Option<i64>> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT lifecycle_maintenance_epoch
                       FROM control_schema_version
                      WHERE singleton
                        AND lifecycle_maintenance_frozen
                        AND legacy_topology_handlers_drained
                        AND NOT legacy_topology_reconciled
                        AND NOT lifecycle_provenance_writes_enabled",
                    &[],
                )?
                .map(|row| row.try_get(0))
                .transpose()
        })
    }

    pub fn mark_legacy_topology_reconciled(&self, epoch: i64) -> Result<bool> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE control_schema_version
                        SET legacy_topology_reconciled=TRUE
                      WHERE singleton
                        AND lifecycle_maintenance_frozen
                        AND legacy_topology_handlers_drained
                        AND lifecycle_maintenance_epoch=$1
                        AND NOT lifecycle_provenance_writes_enabled
                        AND NOT EXISTS (
                            SELECT 1 FROM cats
                             WHERE topology_claim_json IS NOT NULL
                        )",
                    &[&epoch],
                )
                .map(|changed| changed == 1)
        })
    }

    pub fn lifecycle_provenance_writes_enabled(&self) -> Result<bool> {
        self.with(|client| {
            client
                .query_one(
                    "SELECT lifecycle_provenance_writes_enabled
                       FROM control_schema_version WHERE singleton",
                    &[],
                )?
                .try_get(0)
        })
    }

    /// One-way phase-B activation after every live replica understands marker
    /// replay. The database gate, rather than a per-Pod branch, makes all
    /// already-running phase-A readers switch writers at the same instant.
    pub fn activate_lifecycle_provenance_writes(&self) -> Result<()> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let gate = tx
                .query_one(
                    "SELECT lifecycle_provenance_writes_enabled,
                            lifecycle_maintenance_frozen,
                            legacy_topology_handlers_drained,
                            legacy_topology_reconciled
                       FROM control_schema_version WHERE singleton FOR UPDATE",
                    &[],
                )
                .map_err(internal)?;
            let enabled: bool = gate.try_get(0).map_err(internal)?;
            if enabled {
                tx.commit().map_err(internal)?;
                return Ok(());
            }
            let frozen: bool = gate.try_get(1).map_err(internal)?;
            let cats: i64 = tx
                .query_one("SELECT COUNT(*) FROM cats", &[])
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            if !frozen && cats != 0 {
                return Err(ApiError::conflict(
                    "lifecycle provenance activation requires the database maintenance freeze",
                ));
            }
            let topology_drained: bool = gate.try_get(2).map_err(internal)?;
            let topology_reconciled: bool = gate.try_get(3).map_err(internal)?;
            if cats != 0 && (!topology_drained || !topology_reconciled) {
                return Err(ApiError::conflict(
                    "lifecycle provenance activation requires drained legacy topology handlers and a completed topology reconciliation",
                ));
            }
            let unsafe_rows: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM cats c
                      WHERE (c.lifecycle_dispatch_json IS NULL
                             AND c.observed_state IN
                                 ('starting','suspending','warming','stopping'))
                         OR c.topology_claim_json IS NOT NULL
                         OR NOT (
                             (c.desired_state='running' AND c.observed_state='running')
                          OR (c.desired_state='suspended' AND c.observed_state='suspended')
                          OR (c.desired_state='warm' AND c.observed_state='warm')
                          OR (c.desired_state='cold' AND c.observed_state='cold')
                          OR (c.desired_state='deleted' AND c.observed_state='deleted')
                         )
                         OR c.observed_generation<>c.generation
                         OR EXISTS (
                             SELECT 1 FROM operations o
                              WHERE o.resource_id=c.id
                                AND o.phase IN ('pending','running')
                                AND o.kind IN (
                                    'cat.create', 'cat.start', 'cat.resume',
                                    'cat.suspend', 'cat.warm', 'cat.stop', 'cat.delete',
                                    'cat.auto_suspend', 'cat.auto_warm', 'cat.auto_cold',
                                    'cat.work_wake', 'cat.wake',
                                    'cat.credit_exhausted', 'cat.expire'
                                )
                         )",
                    &[],
                )
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            if unsafe_rows != 0 {
                return Err(ApiError::conflict(format!(
                    "cannot activate lifecycle provenance while {unsafe_rows} Cat(s) are not idle and converged"
                )));
            }
            tx.execute(
                "UPDATE control_schema_version
                    SET lifecycle_provenance_writes_enabled=TRUE
                  WHERE singleton AND lifecycle_provenance_writes_enabled=FALSE",
                &[],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(())
        })
    }

    /// Linearize one phase-A transitional write against the one-way phase-B
    /// activation. The shared gate lock is held until the Cat boundary commits;
    /// activation waits for it, scans the resulting row, and refuses to enable
    /// while that legacy job remains in flight.
    pub fn begin_legacy_lifecycle(
        &self,
        cat_id: &str,
        node_id: &str,
        generation: i64,
        source: ObservedState,
        transitional: ObservedState,
    ) -> Result<LegacyLifecycleBegin> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let enabled: bool = tx
                .query_one(
                    "SELECT lifecycle_provenance_writes_enabled
                       FROM control_schema_version WHERE singleton FOR SHARE",
                    &[],
                )
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            if enabled {
                tx.commit().map_err(internal)?;
                return Ok(LegacyLifecycleBegin::GateEnabled);
            }
            let changed = tx
                .execute(
                    "UPDATE cats
                        SET observed_state=$5, observed_state_since_ms=$6
                      WHERE id=$1 AND node_id=$2 AND generation=$3
                        AND observed_state=$4 AND lifecycle_dispatch_json IS NULL
                        AND topology_claim_json IS NULL",
                    &[
                        &cat_id,
                        &node_id,
                        &generation,
                        &observed_str(source),
                        &observed_str(transitional),
                        &now_ms(),
                    ],
                )
                .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(if changed == 1 {
                LegacyLifecycleBegin::Begun
            } else {
                LegacyLifecycleBegin::Stale
            })
        })
    }

    pub fn lifecycle_dispatch(&self, cat_id: &str) -> Result<Option<LifecycleDispatch>> {
        self.enter(|client| {
            let client = client?;
            let json: Option<String> = client
                .query_opt(
                    "SELECT lifecycle_dispatch_json FROM cats WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(|row| row.try_get::<_, Option<String>>(0))
                .transpose()
                .map_err(internal)?
                .flatten();
            json.map(|json| serde_json::from_str(&json).map_err(internal))
                .transpose()
        })
    }

    /// Persist the writer identities inspected after a failed external action
    /// but before any revoke. This is needed for Start failure: Start itself
    /// may have acquired a lease that did not exist when its dispatch marker
    /// was first committed.
    pub fn persist_lifecycle_fence_leases(
        &self,
        dispatch: &LifecycleDispatch,
        volume_leases: Vec<VolumeLeaseAuthority>,
    ) -> Result<Option<LifecycleDispatch>> {
        let expected = serde_json::to_string(dispatch).map_err(internal)?;
        let mut updated = dispatch.clone();
        updated.volume_leases = volume_leases;
        let replacement = serde_json::to_string(&updated).map_err(internal)?;
        let changed = self.with(|client| {
            client
                .execute(
                    "UPDATE cats SET lifecycle_dispatch_json=$2
                      WHERE id=$1 AND lifecycle_dispatch_json=$3
                        AND node_id=$4 AND topology_claim_json IS NULL",
                    &[
                        &dispatch.job.action.cat_id(),
                        &replacement,
                        &expected,
                        &dispatch.node_id,
                    ],
                )
                .map(|changed| changed == 1)
        })?;
        Ok(changed.then_some(updated))
    }

    pub fn lifecycle_dispatch_authority_matches(
        &self,
        dispatch: &LifecycleDispatch,
    ) -> Result<bool> {
        let expected = serde_json::to_string(dispatch).map_err(internal)?;
        self.with(|client| {
            client
                .query_opt(
                    "SELECT 1 FROM cats
                      WHERE id=$1 AND node_id=$2
                        AND lifecycle_dispatch_json=$3
                        AND topology_claim_json IS NULL",
                    &[&dispatch.job.action.cat_id(), &dispatch.node_id, &expected],
                )
                .map(|row| row.is_some())
        })
    }

    pub fn unclaimed_cat_authority_matches(
        &self,
        cat_id: &str,
        generation: i64,
        node_id: Option<&str>,
    ) -> Result<bool> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT 1 FROM cats
                      WHERE id=$1 AND generation=$2
                        AND node_id IS NOT DISTINCT FROM $3::TEXT
                        AND lifecycle_dispatch_json IS NULL
                        AND topology_claim_json IS NULL",
                    &[&cat_id, &generation, &node_id],
                )
                .map(|row| row.is_some())
        })
    }

    pub fn fenced_cat_authority_matches(
        &self,
        cat_id: &str,
        node_id: &str,
        generation: i64,
    ) -> Result<bool> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT 1 FROM cats c JOIN nodes n ON n.id=c.node_id
                      WHERE c.id=$1 AND c.node_id=$2 AND c.generation=$3
                        AND c.topology_claim_json IS NULL AND n.state='fenced'",
                    &[&cat_id, &node_id, &generation],
                )
                .map(|row| row.is_some())
        })
    }

    pub fn fenced_topology_authority_matches(
        &self,
        claim: &TopologyClaim,
        node_id: &str,
    ) -> Result<bool> {
        let expected = serde_json::to_string(claim).map_err(internal)?;
        self.with(|client| {
            client
                .query_opt(
                    "SELECT 1 FROM cats c JOIN nodes n ON n.id=c.node_id
                      WHERE c.id=$1 AND c.node_id=$2 AND c.generation=$3
                        AND c.lifecycle_dispatch_json IS NULL
                        AND c.topology_claim_json=$4 AND n.state='fenced'",
                    &[&claim.cat_id, &node_id, &claim.cat_generation, &expected],
                )
                .map(|row| row.is_some())
        })
    }

    /// Atomically publish the transitional state and the exact node job that
    /// may execute after commit.  An existing marker always wins: overwriting
    /// it would make an ambiguous old result impossible to classify safely.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_lifecycle_dispatch(
        &self,
        cat_id: &str,
        node_id: &str,
        source_state: ObservedState,
        transitional_state: ObservedState,
        target_state: ObservedState,
        volume_leases: Vec<VolumeLeaseAuthority>,
        job: NodeJob,
    ) -> Result<Option<LifecycleDispatch>> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let row = tx
                .query_opt(
                    "SELECT generation, observed_state, node_id, lifecycle_dispatch_json,
                            topology_claim_json
                       FROM cats WHERE id=$1 FOR UPDATE",
                    &[&cat_id],
                )
                .map_err(internal)?
                .ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
            let existing: Option<String> = row.try_get(3).map_err(internal)?;
            if let Some(existing) = existing {
                return serde_json::from_str(&existing).map(Some).map_err(internal);
            }
            let generation: i64 = row.try_get(0).map_err(internal)?;
            let observed: String = row.try_get(1).map_err(internal)?;
            let assigned_node: Option<String> = row.try_get(2).map_err(internal)?;
            let topology_claim: Option<String> = row.try_get(4).map_err(internal)?;
            if generation != job.cat_generation
                || observed != observed_str(source_state)
                || assigned_node.as_deref() != Some(node_id)
                || topology_claim.is_some()
            {
                tx.commit().map_err(internal)?;
                return Ok(None);
            }
            let operation_ids = tx
                .query(
                    "SELECT id FROM operations
                      WHERE resource_id=$1 AND resource_generation=$2
                        AND phase IN ('pending','running')
                        AND kind IN (
                            'cat.create', 'cat.start', 'cat.resume',
                            'cat.suspend', 'cat.warm', 'cat.stop', 'cat.delete',
                            'cat.auto_suspend', 'cat.auto_warm', 'cat.auto_cold',
                            'cat.work_wake', 'cat.wake',
                            'cat.credit_exhausted', 'cat.expire'
                        )
                      ORDER BY id",
                    &[&cat_id, &job.cat_generation],
                )
                .map_err(internal)?
                .into_iter()
                .map(|row| row.try_get(0).map_err(internal))
                .collect::<Result<Vec<String>>>()?;
            let dispatch = LifecycleDispatch {
                dispatch_id: new_id("dispatch_"),
                node_id: node_id.to_string(),
                source_state,
                transitional_state,
                target_state,
                operation_ids,
                volume_leases,
                job,
            };
            let json = serde_json::to_string(&dispatch).map_err(internal)?;
            tx.execute(
                "UPDATE cats
                    SET observed_state=$2, observed_state_since_ms=$3,
                        lifecycle_dispatch_json=$4
                  WHERE id=$1 AND lifecycle_dispatch_json IS NULL
                    AND topology_claim_json IS NULL",
                &[&cat_id, &observed_str(transitional_state), &now_ms(), &json],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(Some(dispatch))
        })
    }

    /// CAS one exact dispatch result.  A late response can neither clear a
    /// replacement marker nor complete operations from a newer generation.
    /// `clear=false` records a trustworthy physical state while retaining the
    /// exact job for a source-preserving retry.
    pub fn settle_lifecycle_dispatch(
        &self,
        dispatch: &LifecycleDispatch,
        observed: ObservedState,
        clear: bool,
        operation_error: Option<&ErrorBody>,
        running_route: Option<(&str, &str)>,
        release_placement: bool,
    ) -> Result<bool> {
        let expected = serde_json::to_string(dispatch).map_err(internal)?;
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let row = tx
                .query_opt(
                    "SELECT generation, desired_state, lifecycle_dispatch_json, node_id
                       FROM cats WHERE id=$1 FOR UPDATE",
                    &[&dispatch.job.action.cat_id()],
                )
                .map_err(internal)?;
            let Some(row) = row else {
                return Ok(false);
            };
            let stored: Option<String> = row.try_get(2).map_err(internal)?;
            if stored.as_deref() != Some(expected.as_str()) {
                tx.commit().map_err(internal)?;
                return Ok(false);
            }
            if let Some((node_id, gateway_url)) = running_route {
                tx.execute(
                    "UPDATE routes
                        SET node_id=$2, gateway_url=$3, epoch=epoch+1, state='active'
                      WHERE cat_id=$1",
                    &[&dispatch.job.action.cat_id(), &node_id, &gateway_url],
                )
                .map_err(internal)?;
            }
            if release_placement {
                tx.execute(
                    "UPDATE routes
                        SET node_id=NULL, gateway_url=NULL, epoch=epoch+1, state='unbound'
                      WHERE cat_id=$1",
                    &[&dispatch.job.action.cat_id()],
                )
                .map_err(internal)?;
                tx.execute(
                    "UPDATE cats SET node_id=NULL
                      WHERE id=$1 AND lifecycle_dispatch_json=$2",
                    &[&dispatch.job.action.cat_id(), &expected],
                )
                .map_err(internal)?;
            }
            let generation: i64 = row.try_get(0).map_err(internal)?;
            let desired: String = row.try_get(1).map_err(internal)?;
            let assigned_node: Option<String> = row.try_get(3).map_err(internal)?;
            let mut next_observed = observed;
            let mut proven_generation = clear.then_some(dispatch.job.cat_generation);
            let mut next_marker = (!clear).then_some(expected.clone());

            // A newer API request may have superseded this exact physical job
            // while it was in flight.  If a runtime still exists, hand the row
            // directly to an idempotent current-generation action under the
            // same lock.  There must never be a durable markerless interval in
            // which state "Suspended" means generation 2 while an operation
            // for generation 4 is allowed to treat it as convergence.
            let mut handed_off = false;
            if clear && generation != dispatch.job.cat_generation && !release_placement {
                if let Some(node_id) = assigned_node.as_deref() {
                    if let Some((action, transitional, target)) =
                        successor_action(&mut tx, dispatch.job.action.cat_id(), &desired, observed)?
                    {
                        let job = NodeJob {
                            job_id: cats_api::nodejob::job_id(
                                dispatch.job.action.cat_id(),
                                generation,
                                action.kind(),
                            ),
                            cat_generation: generation,
                            action,
                        };
                        let operation_ids = tx
                            .query(
                                "SELECT id FROM operations
                                  WHERE resource_id=$1 AND resource_generation=$2
                                    AND phase IN ('pending','running')
                                    AND kind IN (
                                        'cat.create', 'cat.start', 'cat.resume',
                                        'cat.suspend', 'cat.warm', 'cat.stop', 'cat.delete',
                                        'cat.auto_suspend', 'cat.auto_warm', 'cat.auto_cold',
                                        'cat.work_wake', 'cat.wake',
                                        'cat.credit_exhausted', 'cat.expire'
                                    )
                                  ORDER BY id",
                                &[&dispatch.job.action.cat_id(), &generation],
                            )
                            .map_err(internal)?
                            .into_iter()
                            .map(|row| row.try_get(0).map_err(internal))
                            .collect::<Result<Vec<String>>>()?;
                        // A superseding Stop owns the same still-live runtime
                        // as the action it replaces. Carry the exact writer
                        // identities forward so Stop success can revoke them;
                        // rediscovering leases after the handoff could either
                        // miss the old writer or target a replacement.
                        let successor_volume_leases =
                            if matches!(&job.action, NodeJobAction::StopCat { .. }) {
                                dispatch.volume_leases.clone()
                            } else {
                                Vec::new()
                            };
                        let successor = LifecycleDispatch {
                            dispatch_id: new_id("dispatch_"),
                            node_id: node_id.to_string(),
                            source_state: observed,
                            transitional_state: transitional,
                            target_state: target,
                            operation_ids,
                            volume_leases: successor_volume_leases,
                            job,
                        };
                        next_observed = transitional;
                        next_marker = Some(serde_json::to_string(&successor).map_err(internal)?);
                        handed_off = true;
                    }
                }
            }
            if !handed_off
                && clear
                && generation != dispatch.job.cat_generation
                && (release_placement || observed == ObservedState::Cold)
            {
                // A confirmed stop/fence leaves no runtime to align.  Cold is
                // therefore physically true for the current control generation.
                proven_generation = Some(generation);
            }
            tx.execute(
                "UPDATE cats
                    SET observed_state=$2, observed_state_since_ms=$3,
                        observed_generation=CASE
                            WHEN $4::BIGINT IS NOT NULL THEN $4
                            ELSE observed_generation
                        END,
                        lifecycle_dispatch_json=$5
                  WHERE id=$1 AND lifecycle_dispatch_json=$6",
                &[
                    &dispatch.job.action.cat_id(),
                    &observed_str(next_observed),
                    &now_ms(),
                    &proven_generation,
                    &next_marker,
                    &expected,
                ],
            )
            .map_err(internal)?;

            if clear {
                let converged = desired_matches_observed(&desired, observed);
                for operation_id in &dispatch.operation_ids {
                    if let Some(error) = operation_error {
                        Self::finish_operation_in(&mut tx, operation_id, Some(error))?;
                    } else if generation == dispatch.job.cat_generation && converged {
                        Self::finish_operation_in(&mut tx, operation_id, None)?;
                    }
                }
            }
            tx.commit().map_err(internal)?;
            Ok(true)
        })
    }

    /// After external fencing has revoked every storage lease, atomically
    /// remove every remaining claim by the fenced Host.  Keeping placement,
    /// route, dispatch provenance and physical state in one transaction avoids
    /// both crash windows: an unreachable marker with no placement, and a
    /// markerless transitional Cat that still appears assigned.
    pub fn converge_fenced_cat(&self, cat_id: &str, node_id: &str) -> Result<bool> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let row = tx
                .query_opt(
                    "SELECT generation, node_id, topology_claim_json
                       FROM cats WHERE id=$1 FOR UPDATE",
                    &[&cat_id],
                )
                .map_err(internal)?;
            let Some(row) = row else {
                return Ok(false);
            };
            let generation: i64 = row.try_get(0).map_err(internal)?;
            let assigned_node: Option<String> = row.try_get(1).map_err(internal)?;
            let topology_claim: Option<String> = row.try_get(2).map_err(internal)?;
            if assigned_node.as_deref() != Some(node_id) || topology_claim.is_some() {
                tx.commit().map_err(internal)?;
                return Ok(false);
            }
            tx.execute(
                "UPDATE routes
                    SET node_id=NULL, gateway_url=NULL, epoch=epoch+1, state='unbound'
                  WHERE cat_id=$1",
                &[&cat_id],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE cats
                    SET node_id=NULL,
                        observed_state='cold',
                        observed_state_since_ms=$3,
                        observed_generation=$4,
                        lifecycle_dispatch_json=NULL
                  WHERE id=$1 AND node_id=$2",
                &[&cat_id, &node_id, &now_ms(), &generation],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(true)
        })
    }

    /// Claim the destructive cleanup phase with the exact persisted Destroy
    /// dispatch as authority. Desired Deleted is terminal, and callers hold the
    /// per-Cat cleanup session lock across the following external deletions.
    pub fn claim_destroy_cleanup(&self, dispatch: &LifecycleDispatch) -> Result<bool> {
        let expected = serde_json::to_string(dispatch).map_err(internal)?;
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET observed_state='deleted', observed_state_since_ms=$4,
                            observed_generation=generation
                      WHERE id=$1 AND generation=$2 AND desired_state='deleted'
                        AND node_id IS NULL AND lifecycle_dispatch_json=$3
                        AND topology_claim_json IS NULL
                        AND observed_state IN ('cold','deleted')",
                    &[
                        &dispatch.job.action.cat_id(),
                        &dispatch.job.cat_generation,
                        &expected,
                        &now_ms(),
                    ],
                )
                .map(|changed| changed == 1)
        })
    }

    pub fn claim_cold_delete_cleanup(&self, cat_id: &str, generation: i64) -> Result<bool> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET observed_state='deleted', observed_state_since_ms=$3,
                            observed_generation=generation
                      WHERE id=$1 AND generation=$2 AND desired_state='deleted'
                        AND node_id IS NULL AND lifecycle_dispatch_json IS NULL
                        AND topology_claim_json IS NULL
                        AND observed_state IN ('creating','cold','failed','deleted')",
                    &[&cat_id, &generation, &now_ms()],
                )
                .map(|changed| changed == 1)
        })
    }

    pub fn delete_cat_if_destroy_authorized(&self, dispatch: &LifecycleDispatch) -> Result<bool> {
        let expected = serde_json::to_string(dispatch).map_err(internal)?;
        self.delete_cat_if_authorized(
            dispatch.job.action.cat_id(),
            dispatch.job.cat_generation,
            Some(&expected),
        )
    }

    pub fn delete_cat_if_cold_delete_authorized(
        &self,
        cat_id: &str,
        generation: i64,
    ) -> Result<bool> {
        self.delete_cat_if_authorized(cat_id, generation, None)
    }

    fn delete_cat_if_authorized(
        &self,
        cat_id: &str,
        generation: i64,
        marker: Option<&str>,
    ) -> Result<bool> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let authorized = tx
                .query_opt(
                    "SELECT 1 FROM cats
                      WHERE id=$1 AND generation=$2 AND desired_state='deleted'
                        AND observed_state='deleted' AND node_id IS NULL
                        AND lifecycle_dispatch_json IS NOT DISTINCT FROM $3::TEXT
                        AND topology_claim_json IS NULL
                      FOR UPDATE",
                    &[&cat_id, &generation, &marker],
                )
                .map_err(internal)?
                .is_some();
            if !authorized {
                tx.commit().map_err(internal)?;
                return Ok(false);
            }
            for operation in tx
                .query(
                    "SELECT id FROM operations
                      WHERE resource_id=$1 AND phase IN ('pending','running')",
                    &[&cat_id],
                )
                .map_err(internal)?
            {
                let operation_id: String = operation.try_get(0).map_err(internal)?;
                Self::finish_operation_in(&mut tx, &operation_id, None)?;
            }
            tx.execute("DELETE FROM cat_work_leases WHERE cat_id=$1", &[&cat_id])
                .map_err(internal)?;
            tx.execute("DELETE FROM cat_work_sources WHERE cat_id=$1", &[&cat_id])
                .map_err(internal)?;
            tx.execute("DELETE FROM mount_bindings WHERE cat_id=$1", &[&cat_id])
                .map_err(internal)?;
            tx.execute("DELETE FROM endpoints WHERE cat_id=$1", &[&cat_id])
                .map_err(internal)?;
            tx.execute("DELETE FROM routes WHERE cat_id=$1", &[&cat_id])
                .map_err(internal)?;
            tx.execute("DELETE FROM oci_deployments WHERE cat_id=$1", &[&cat_id])
                .map_err(internal)?;
            let deleted = tx
                .execute(
                    "DELETE FROM cats
                      WHERE id=$1 AND generation=$2 AND desired_state='deleted'
                        AND observed_state='deleted' AND node_id IS NULL
                        AND lifecycle_dispatch_json IS NOT DISTINCT FROM $3::TEXT
                        AND topology_claim_json IS NULL",
                    &[&cat_id, &generation, &marker],
                )
                .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(deleted == 1)
        })
    }
}

fn desired_matches_observed(desired: &str, observed: ObservedState) -> bool {
    matches!(
        (desired, observed),
        ("running", ObservedState::Running)
            | ("suspended", ObservedState::Suspended)
            | ("warm", ObservedState::Warm)
            | ("cold", ObservedState::Cold)
    )
}

fn successor_action(
    tx: &mut postgres::Transaction<'_>,
    cat_id: &str,
    desired: &str,
    observed: ObservedState,
) -> Result<Option<(NodeJobAction, ObservedState, ObservedState)>> {
    use ObservedState as O;
    let action = match (desired, observed) {
        ("running", O::Running | O::Suspended) => (
            NodeJobAction::ResumeCat {
                cat_id: cat_id.to_string(),
            },
            O::Starting,
            O::Running,
        ),
        ("running" | "suspended", O::Warm) => (
            NodeJobAction::RestoreCat {
                cat_id: cat_id.to_string(),
            },
            O::Starting,
            O::Running,
        ),
        ("suspended", O::Running | O::Suspended) => {
            let row = tx
                .query_one(
                    "SELECT c.work_version, COALESCE(s.lease_sequence, 0)
                       FROM cats c LEFT JOIN cat_work_sources s ON s.cat_id=c.id
                      WHERE c.id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?;
            let guest_lease_sequence: i64 = row.try_get(1).map_err(internal)?;
            (
                NodeJobAction::SuspendCat {
                    cat_id: cat_id.to_string(),
                    work_fence: Some(SuspendWorkFence {
                        control_work_version: row.try_get(0).map_err(internal)?,
                        guest_lease_sequence: guest_lease_sequence as u64,
                    }),
                },
                O::Suspending,
                O::Suspended,
            )
        }
        ("warm", O::Running | O::Suspended | O::Warm) => (
            NodeJobAction::WarmCat {
                cat_id: cat_id.to_string(),
            },
            O::Warming,
            O::Warm,
        ),
        ("cold" | "deleted", O::Running | O::Suspended | O::Warm) => (
            NodeJobAction::StopCat {
                cat_id: cat_id.to_string(),
                disposition: StopCatDisposition::Cold,
            },
            O::Stopping,
            O::Cold,
        ),
        _ => return Ok(None),
    };
    Ok(Some(action))
}

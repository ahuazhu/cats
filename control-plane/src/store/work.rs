use super::*;

type AutoSuspendCatRow = (
    String,
    i64,
    bool,
    String,
    String,
    i64,
    Option<String>,
    Option<String>,
);
type AutoTierCatRow = (
    String,
    i64,
    bool,
    String,
    String,
    i64,
    i64,
    Option<String>,
    Option<String>,
);

impl Store {
    pub(super) fn fail_pending_auto_tier(
        tx: &mut postgres::Transaction<'_>,
        cat_id: &str,
        message: &str,
    ) -> Result<()> {
        let error = serde_json::to_string(&ErrorBody::new(ErrorCode::Conflict, message))
            .map_err(internal)?;
        tx.execute(
            "UPDATE operations SET phase='failed', error_json=$2, updated_at=$3
             WHERE resource_id=$1
               AND kind IN ('cat.auto_suspend','cat.auto_warm','cat.auto_cold')
               AND phase IN ('pending','running')",
            &[&cat_id, &error, &now_unix()],
        )
        .map_err(internal)?;
        Ok(())
    }
    pub fn acquire_work(
        &self,
        cat_id: &str,
        kind: WorkKind,
        owner_id: &str,
        label: &str,
        ttl_ms: u64,
    ) -> Result<WorkLease> {
        if owner_id.is_empty() || owner_id.len() > 128 {
            return Err(ApiError::invalid("work owner_id must be 1..128 bytes"));
        }
        if label.len() > 128 {
            return Err(ApiError::invalid("work label exceeds 128 bytes"));
        }
        if ttl_ms == 0 || ttl_ms > cats_api::guest::MAX_WORK_LEASE_TTL_MS {
            return Err(ApiError::invalid("work TTL is outside the allowed range"));
        }
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let cat_exists: Option<String> = tx
                .query_opt("SELECT workspace_id FROM cats WHERE id=$1", &[&cat_id])
                .map_err(internal)?
                .map(|row| row.try_get(0))
                .transpose()
                .map_err(internal)?;
            cat_exists.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
            let existing: Option<String> = tx
                .query_opt(
                    "SELECT id FROM cat_work_leases
                 WHERE cat_id=$1 AND kind=$2 AND owner_id=$3",
                    &[&cat_id, &work_kind_str(kind), &owner_id],
                )
                .map_err(internal)?
                .map(|row| row.try_get(0))
                .transpose()
                .map_err(internal)?;
            let id = existing.unwrap_or_else(|| new_id("work_"));
            let expires_at_ms = now_ms().saturating_add(ttl_ms as i64);
            tx.execute(
                "INSERT INTO cat_work_leases
                (id, cat_id, kind, owner_id, label, expires_at_ms, source_epoch)
             VALUES ($1,$2,$3,$4,$5,$6,NULL)
             ON CONFLICT(cat_id, kind, owner_id) DO UPDATE SET
                label=$5, expires_at_ms=$6",
                &[
                    &id,
                    &cat_id,
                    &work_kind_str(kind),
                    &owner_id,
                    &label,
                    &expires_at_ms,
                ],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=$1",
                &[&cat_id],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
            Ok(WorkLease {
                id,
                cat_id: cat_id.to_string(),
                kind,
                owner_id: owner_id.to_string(),
                label: label.to_string(),
                expires_at_unix_ms: expires_at_ms,
            })
        })
    }

    pub fn release_work(&self, lease_id: &str) -> Result<Option<String>> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let cat_id: Option<String> = tx
                .query_opt(
                    "SELECT cat_id FROM cat_work_leases WHERE id=$1",
                    &[&lease_id],
                )
                .map_err(internal)?
                .map(|row| row.try_get(0))
                .transpose()
                .map_err(internal)?;
            if let Some(cat_id) = &cat_id {
                tx.execute("DELETE FROM cat_work_leases WHERE id=$1", &[&lease_id])
                    .map_err(internal)?;
                tx.execute(
                    "UPDATE cats SET work_version=work_version+1 WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?;
            }
            tx.commit().map_err(internal)?;
            Ok(cat_id)
        })
    }

    /// Replace the complete set of user-program Guest leases for the current
    /// source epoch/sequence. Returns true when active Guest work must wake a
    /// concurrently auto-suspending Cat.
    pub fn ingest_guest_work(
        &self,
        request: &cats_api::requests::NodeWorkStatusRequest,
    ) -> Result<bool> {
        if request.guest_source_epoch.is_empty()
            || request.guest_source_epoch.len() > 128
            || !request
                .guest_source_epoch
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ApiError::invalid("invalid guest source epoch"));
        }
        if request.leases.len() > cats_api::guest::MAX_WORK_LEASES {
            return Err(ApiError::invalid("too many Guest work leases"));
        }
        for lease in &request.leases {
            if lease.id.is_empty() || lease.id.len() > 128 || lease.label.len() > 128 {
                return Err(ApiError::invalid("invalid Guest work lease"));
            }
        }
        let request_sequence = i64::try_from(request.guest_lease_sequence)
            .map_err(|_| ApiError::invalid("guest lease sequence is too large"))?;
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let cat: Option<(String, i64, String, String, Option<String>)> = tx
                .query_opt(
                    "SELECT workspace_id, generation, desired_state, observed_state, node_id
                 FROM cats WHERE id=$1",
                    &[&request.cat_id],
                )
                .map_err(internal)?
                .map(|row| -> std::result::Result<_, postgres::Error> {
                    Ok((
                        row.try_get(0)?,
                        row.try_get(1)?,
                        row.try_get(2)?,
                        row.try_get(3)?,
                        row.try_get(4)?,
                    ))
                })
                .transpose()
                .map_err(internal)?;
            let (workspace_id, generation, desired, observed, node_id) =
                cat.ok_or_else(|| ApiError::not_found(format!("cat {}", request.cat_id)))?;
            if node_id.as_deref() != Some(request.node_id.as_str()) {
                return Err(ApiError::conflict(
                    "work status came from a non-owning node",
                ));
            }
            let current_or_auto_transition = request.generation == generation
                || (request.generation + 1 == generation
                    && desired == "suspended"
                    && matches!(observed.as_str(), "running" | "suspending"));
            if !current_or_auto_transition {
                return Err(ApiError::conflict("work status generation is stale"));
            }

            let previous: Option<(String, i64)> = tx
                .query_opt(
                    "SELECT source_epoch, lease_sequence FROM cat_work_sources WHERE cat_id=$1",
                    &[&request.cat_id],
                )
                .map_err(internal)?
                .map(|row| -> std::result::Result<_, postgres::Error> {
                    Ok((row.try_get(0)?, row.try_get(1)?))
                })
                .transpose()
                .map_err(internal)?;
            if let Some((epoch, sequence)) = &previous {
                if epoch == &request.guest_source_epoch && request_sequence < *sequence {
                    return Ok(false);
                }
            }

            let now = now_ms();
            let changed = previous.as_ref().is_none_or(|(epoch, sequence)| {
                epoch != &request.guest_source_epoch || *sequence != request_sequence
            });
            tx.execute(
                "INSERT INTO cat_work_sources
                (cat_id, node_id, generation, source_epoch, lease_sequence, seen_at_ms)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT(cat_id) DO UPDATE SET
                node_id=$2, generation=$3, source_epoch=$4,
                lease_sequence=$5, seen_at_ms=$6",
                &[
                    &request.cat_id,
                    &request.node_id,
                    &request.generation,
                    &request.guest_source_epoch,
                    &request_sequence,
                    &now,
                ],
            )
            .map_err(internal)?;

            if changed {
                tx.execute(
                    "DELETE FROM cat_work_leases WHERE cat_id=$1 AND kind='guest'",
                    &[&request.cat_id],
                )
                .map_err(internal)?;
                for guest in request.leases.iter().take(cats_api::guest::MAX_WORK_LEASES) {
                    if guest.remaining_ttl_ms == 0 {
                        continue;
                    }
                    let ttl = guest
                        .remaining_ttl_ms
                        .min(cats_api::guest::MAX_WORK_LEASE_TTL_MS);
                    let id = format!(
                        "guest_{}_{}",
                        &request.guest_source_epoch[..request.guest_source_epoch.len().min(12)],
                        guest.id
                    );
                    let owner = format!("{}:{}", request.guest_source_epoch, guest.id);
                    tx.execute(
                        "INSERT INTO cat_work_leases
                        (id, cat_id, kind, owner_id, label, expires_at_ms, source_epoch)
                     VALUES ($1,$2,'guest',$3,$4,$5,$6)",
                        &[
                            &id,
                            &request.cat_id,
                            &owner,
                            &guest.label.chars().take(128).collect::<String>(),
                            &now.saturating_add(ttl as i64),
                            &request.guest_source_epoch,
                        ],
                    )
                    .map_err(internal)?;
                }
                tx.execute(
                    "UPDATE cats SET work_version=work_version+1 WHERE id=$1",
                    &[&request.cat_id],
                )
                .map_err(internal)?;
            }

            let has_guest_work = request
                .leases
                .iter()
                .any(|lease| lease.remaining_ttl_ms > 0);
            let cancel_inflight_suspend = has_guest_work
                && desired == "suspended"
                && matches!(observed.as_str(), "running" | "suspending");
            let wake_suspended = has_guest_work && desired != "running" && observed == "suspended";
            let should_wake = cancel_inflight_suspend || wake_suspended;
            if cancel_inflight_suspend {
                Self::fail_pending_auto_tier(&mut tx, &request.cat_id, "superseded by Guest work")?;
                // The physical suspend for this generation has not committed.
                // Cancel it in-place so the Node and its work watcher can both
                // converge on the job generation after ActivityChanged.
                tx.execute(
                    "UPDATE cats SET desired_state='running' WHERE id=$1",
                    &[&request.cat_id],
                )
                .map_err(internal)?;
            } else if wake_suspended {
                Self::fail_pending_auto_tier(&mut tx, &request.cat_id, "superseded by Guest work")?;
                let new_generation = generation + 1;
                Self::fail_active_lifecycle_operations_before(
                    &mut tx,
                    &request.cat_id,
                    new_generation,
                )?;
                tx.execute(
                    "UPDATE cats SET desired_state='running', generation=$2 WHERE id=$1",
                    &[&request.cat_id, &new_generation],
                )
                .map_err(internal)?;
                Self::insert_operation(
                    &mut tx,
                    &workspace_id,
                    "cat.work_wake",
                    &request.cat_id,
                    new_generation,
                )?;
            }
            tx.commit().map_err(internal)?;
            Ok(should_wake)
        })
    }

    pub fn work_status(&self, cat_id: &str, signal_stale_ms: i64) -> Result<CatWorkStatus> {
        let cat = self.must_get_cat_by_id(cat_id)?;
        let now = now_ms();
        let leases = self.with(|client| {
            client
                .query(
                    "SELECT id, cat_id, kind, owner_id, label, expires_at_ms
                     FROM cat_work_leases
                     WHERE cat_id=$1 AND expires_at_ms>$2
                     ORDER BY kind, id",
                    &[&cat_id, &now],
                )?
                .iter()
                .map(row_to_work_lease)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })?;
        let source: Option<i64> = self.with(|client| {
            client
                .query_opt(
                    "SELECT seen_at_ms FROM cat_work_sources WHERE cat_id=$1",
                    &[&cat_id],
                )?
                .map(|row| row.try_get(0))
                .transpose()
        })?;
        let age = source.map(|seen| now.saturating_sub(seen).max(0) as u64);
        let guest_signal_fresh = age.is_some_and(|age| age <= signal_stale_ms.max(0) as u64);
        let active_work_count = leases.len() as u32;
        let stable_running = cat.desired_state == DesiredState::Running
            && cat.observed_state == ObservedState::Running;
        let can_suspend_now =
            cat.auto_suspend && stable_running && guest_signal_fresh && leases.is_empty();
        let reason = if !cat.auto_suspend {
            "policy_off"
        } else if !stable_running {
            "lifecycle_in_progress"
        } else if !guest_signal_fresh {
            "guest_lease_signal_stale"
        } else if !leases.is_empty() {
            "active_work"
        } else {
            "eligible"
        };
        let work_version = self.with(|client| {
            client
                .query_one("SELECT work_version FROM cats WHERE id=$1", &[&cat_id])?
                .try_get(0)
        })?;
        Ok(CatWorkStatus {
            cat_id: cat_id.to_string(),
            auto_suspend: cat.auto_suspend,
            work_version,
            active_work_count,
            leases,
            guest_signal_fresh,
            guest_signal_age_ms: age,
            can_suspend_now,
            reason: reason.to_string(),
        })
    }

    pub fn suspend_work_fence(&self, cat_id: &str) -> Result<cats_api::nodejob::SuspendWorkFence> {
        self.with(|client| {
            let row = client.query_one(
                "SELECT c.work_version, COALESCE(s.lease_sequence, 0)
                 FROM cats c LEFT JOIN cat_work_sources s ON s.cat_id=c.id
                 WHERE c.id=$1",
                &[&cat_id],
            )?;
            Ok(cats_api::nodejob::SuspendWorkFence {
                control_work_version: row.try_get(0)?,
                guest_lease_sequence: row.try_get::<_, i64>(1)? as u64,
            })
        })
    }

    pub fn auto_suspend_candidates(&self) -> Result<Vec<String>> {
        self.with(|client| {
            client
                .query(
                    "SELECT id FROM cats
                     WHERE auto_suspend AND desired_state='running' AND observed_state='running'
                       AND observed_generation=generation
                       AND lifecycle_dispatch_json IS NULL
                       AND topology_claim_json IS NULL",
                    &[],
                )?
                .iter()
                .map(|row| row.try_get(0))
                .collect()
        })
    }

    pub fn try_auto_suspend(
        &self,
        cat_id: &str,
        signal_stale_ms: i64,
    ) -> Result<Option<Operation>> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let now = now_ms();
            let expired = tx
                .execute(
                    "DELETE FROM cat_work_leases WHERE cat_id=$1 AND expires_at_ms<=$2",
                    &[&cat_id, &now],
                )
                .map_err(internal)?;
            if expired > 0 {
                tx.execute(
                    "UPDATE cats SET work_version=work_version+1 WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?;
            }
            let cat: Option<AutoSuspendCatRow> = tx
                .query_opt(
                    "SELECT workspace_id, generation, auto_suspend,
                        desired_state, observed_state, observed_generation,
                        lifecycle_dispatch_json, topology_claim_json
                 FROM cats WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(|row| -> std::result::Result<_, postgres::Error> {
                    Ok((
                        row.try_get(0)?,
                        row.try_get(1)?,
                        row.try_get(2)?,
                        row.try_get(3)?,
                        row.try_get(4)?,
                        row.try_get(5)?,
                        row.try_get(6)?,
                        row.try_get(7)?,
                    ))
                })
                .transpose()
                .map_err(internal)?;
            let Some((
                workspace_id,
                generation,
                auto_suspend,
                desired,
                observed,
                observed_generation,
                dispatch,
                topology_claim,
            )) = cat
            else {
                return Ok(None);
            };
            if !auto_suspend
                || desired != "running"
                || observed != "running"
                || observed_generation != generation
                || dispatch.is_some()
                || topology_claim.is_some()
            {
                return Ok(None);
            }
            let source_seen: Option<i64> = tx
                .query_opt(
                    "SELECT seen_at_ms FROM cat_work_sources WHERE cat_id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(|row| row.try_get(0))
                .transpose()
                .map_err(internal)?;
            if !source_seen.is_some_and(|seen| now.saturating_sub(seen) <= signal_stale_ms) {
                return Ok(None);
            }
            let active: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM cat_work_leases
                 WHERE cat_id=$1 AND expires_at_ms>$2",
                    &[&cat_id, &now],
                )
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            if active != 0 {
                return Ok(None);
            }
            let next = generation + 1;
            Self::fail_active_lifecycle_operations_before(&mut tx, cat_id, next)?;
            let changed = tx
                .execute(
                    "UPDATE cats SET desired_state='suspended', generation=$2
                 WHERE id=$1 AND generation=$3 AND desired_state='running'
                   AND observed_state='running' AND auto_suspend
                   AND observed_generation=generation
                   AND lifecycle_dispatch_json IS NULL
                   AND topology_claim_json IS NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM cat_work_leases
                     WHERE cat_id=$1 AND expires_at_ms>$4)",
                    &[&cat_id, &next, &generation, &now],
                )
                .map_err(internal)?;
            if changed == 0 {
                return Ok(None);
            }
            let operation =
                Self::insert_operation(&mut tx, &workspace_id, "cat.auto_suspend", cat_id, next)?;
            tx.commit().map_err(internal)?;
            Ok(Some(operation))
        })
    }

    /// Stable sleeping Cats whose persisted state age has crossed the next
    /// automatic tier boundary. This is only a scan optimization; the
    /// transaction in `try_auto_tier` is the decision linearization point.
    pub fn auto_tier_candidates(
        &self,
        warm_after_ms: Option<i64>,
        cold_after_ms: Option<i64>,
    ) -> Result<Vec<String>> {
        let now = now_ms();
        self.with(|client| {
            let rows = client.query(
                "SELECT id, observed_state, observed_state_since_ms
                   FROM cats
                  WHERE auto_suspend
                    AND desired_state=observed_state
                    AND observed_state IN ('suspended','warm')
                    AND observed_generation=generation
                    AND lifecycle_dispatch_json IS NULL
                    AND topology_claim_json IS NULL",
                &[],
            )?;
            let mut candidates = Vec::new();
            for row in &rows {
                let (id, state, since_ms) = (
                    row.try_get::<_, String>(0)?,
                    row.try_get::<_, &str>(1)?,
                    row.try_get::<_, i64>(2)?,
                );
                let threshold = match state {
                    "suspended" => warm_after_ms,
                    "warm" => cold_after_ms,
                    _ => None,
                };
                if threshold.is_some_and(|threshold| now.saturating_sub(since_ms) >= threshold) {
                    candidates.push(id);
                }
            }
            Ok(candidates)
        })
    }

    /// Atomically deepen a stable, inactive Cat by one tier:
    /// Suspended -> Warm or Warm -> Cold.
    ///
    /// The elapsed clock is persisted with the observed state, so a control
    /// plane restart neither resets nor accelerates the policy. Any live work
    /// lease wins the race and blocks the transition.
    pub fn try_auto_tier(
        &self,
        cat_id: &str,
        warm_after_ms: Option<i64>,
        cold_after_ms: Option<i64>,
    ) -> Result<Option<Operation>> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let now = now_ms();
            let expired = tx
                .execute(
                    "DELETE FROM cat_work_leases WHERE cat_id=$1 AND expires_at_ms<=$2",
                    &[&cat_id, &now],
                )
                .map_err(internal)?;
            if expired > 0 {
                tx.execute(
                    "UPDATE cats SET work_version=work_version+1 WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?;
            }

            let cat: Option<AutoTierCatRow> = tx
                .query_opt(
                    "SELECT workspace_id, generation, auto_suspend,
                        desired_state, observed_state, observed_state_since_ms,
                        observed_generation, lifecycle_dispatch_json,
                        topology_claim_json
                   FROM cats WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(|row| -> std::result::Result<_, postgres::Error> {
                    Ok((
                        row.try_get(0)?,
                        row.try_get(1)?,
                        row.try_get(2)?,
                        row.try_get(3)?,
                        row.try_get(4)?,
                        row.try_get(5)?,
                        row.try_get(6)?,
                        row.try_get(7)?,
                        row.try_get(8)?,
                    ))
                })
                .transpose()
                .map_err(internal)?;
            let Some((
                workspace_id,
                generation,
                auto_suspend,
                desired,
                observed,
                since_ms,
                observed_generation,
                dispatch,
                topology_claim,
            )) = cat
            else {
                return Ok(None);
            };
            if !auto_suspend
                || desired != observed
                || observed_generation != generation
                || dispatch.is_some()
                || topology_claim.is_some()
            {
                return Ok(None);
            }
            let (threshold_ms, next_state, operation_kind) = match observed.as_str() {
                "suspended" => (warm_after_ms, "warm", "cat.auto_warm"),
                "warm" => (cold_after_ms, "cold", "cat.auto_cold"),
                _ => return Ok(None),
            };
            let Some(threshold_ms) = threshold_ms else {
                return Ok(None);
            };
            if now.saturating_sub(since_ms) < threshold_ms {
                return Ok(None);
            }
            let active: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM cat_work_leases
                  WHERE cat_id=$1 AND expires_at_ms>$2",
                    &[&cat_id, &now],
                )
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            if active != 0 {
                return Ok(None);
            }

            let next_generation = generation + 1;
            Self::fail_active_lifecycle_operations_before(&mut tx, cat_id, next_generation)?;
            let changed = tx
                .execute(
                    "UPDATE cats
                    SET desired_state=$2, generation=$3
                  WHERE id=$1
                    AND generation=$4
                    AND auto_suspend
                    AND desired_state=$5
                    AND observed_state=$5
                    AND observed_generation=generation
                    AND lifecycle_dispatch_json IS NULL
                    AND topology_claim_json IS NULL
                    AND observed_state_since_ms=$6
                    AND NOT EXISTS (
                        SELECT 1 FROM cat_work_leases
                         WHERE cat_id=$1 AND expires_at_ms>$7
                    )",
                    &[
                        &cat_id,
                        &next_state,
                        &next_generation,
                        &generation,
                        &observed,
                        &since_ms,
                        &now,
                    ],
                )
                .map_err(internal)?;
            if changed == 0 {
                return Ok(None);
            }
            let operation = Self::insert_operation(
                &mut tx,
                &workspace_id,
                operation_kind,
                cat_id,
                next_generation,
            )?;
            tx.commit().map_err(internal)?;
            Ok(Some(operation))
        })
    }

    pub fn cancel_rejected_suspend(&self, cat_id: &str, job_generation: i64) -> Result<()> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let current: Option<(i64, String, String)> = tx
                .query_opt(
                    "SELECT generation, desired_state, observed_state FROM cats WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?
                .map(|row| -> std::result::Result<_, postgres::Error> {
                    Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
                })
                .transpose()
                .map_err(internal)?;
            let Some((generation, desired, observed)) = current else {
                return Ok(());
            };
            let error = serde_json::to_string(&ErrorBody::new(
                ErrorCode::Conflict,
                "work arrived while preparing to suspend",
            ))
            .map_err(internal)?;
            tx.execute(
                "UPDATE operations SET phase='failed', error_json=$3, updated_at=$4
             WHERE resource_id=$1 AND resource_generation=$2
               AND phase IN ('pending','running')",
                &[&cat_id, &job_generation, &error, &now_unix()],
            )
            .map_err(internal)?;
            if observed == "suspending" {
                tx.execute(
                    "UPDATE cats
                    SET observed_state='running', observed_state_since_ms=$2
                  WHERE id=$1",
                    &[&cat_id, &now_ms()],
                )
                .map_err(internal)?;
            }
            if generation == job_generation && desired == "suspended" {
                tx.execute(
                    "UPDATE cats SET desired_state='running' WHERE id=$1",
                    &[&cat_id],
                )
                .map_err(internal)?;
            }
            tx.commit().map_err(internal)?;
            Ok(())
        })
    }

    /// Cats whose desired/observed disagree, plus converged Cats whose current
    /// generation still has an unfinished operation after a leader crash.
    pub fn cats_needing_work(&self) -> Result<Vec<Cat>> {
        self.with(|client| {
            client
                .query(
                    "SELECT c.* FROM cats c WHERE
                       (c.desired_state='running'   AND c.observed_state NOT IN ('running'))
                    OR (c.desired_state='suspended' AND c.observed_state NOT IN ('suspended'))
                    OR (c.desired_state='warm'      AND c.observed_state NOT IN ('warm'))
                    OR (c.desired_state='cold'      AND c.observed_state NOT IN ('cold'))
                    OR (c.desired_state='deleted'   AND c.observed_state NOT IN ('deleted'))
                    OR (
                        c.desired_state IN ('running','suspended','warm','cold')
                        AND c.desired_state=c.observed_state
                        AND c.observed_generation<>c.generation
                    )
                    OR (
                        ((c.desired_state='running' AND c.observed_state='running')
                         OR (c.desired_state='suspended' AND c.observed_state='suspended')
                         OR (c.desired_state='warm' AND c.observed_state='warm')
                         OR (c.desired_state='cold' AND c.observed_state='cold'))
                        AND EXISTS (
                            SELECT 1 FROM operations o
                             WHERE o.resource_id=c.id
                               AND o.resource_generation=c.generation
                               AND o.phase IN ('pending','running')
                               AND o.kind IN (
                                   'cat.create', 'cat.start', 'cat.resume',
                                   'cat.suspend', 'cat.warm', 'cat.stop', 'cat.delete',
                                   'cat.auto_suspend', 'cat.auto_warm', 'cat.auto_cold',
                                   'cat.work_wake', 'cat.wake',
                                   'cat.credit_exhausted', 'cat.expire'
                               )
                        )
                    )
                    ORDER BY c.created_at",
                    &[],
                )?
                .iter()
                .map(row_to_cat)
                .collect()
        })
    }
}

/// A work lease released when this value is dropped.
///
/// A long request can lose its client at any moment -- an intermediary idle
/// timeout is enough -- and dropping the handler future skips whatever release
/// call sits after the awaited work. That leaked a lease for its whole TTL and
/// pinned the Cat out of auto-suspend. `Drop` runs on cancellation too, so
/// tying the lease to a value makes the release unconditional.
///
/// Releasing does not nudge auto-suspend: the reconciler's `tick` already
/// re-examines every auto-suspend candidate, so a cancelled request converges
/// on the next tick instead of needing the handler to still be alive.
pub struct WorkLeaseGuard {
    store: Arc<Store>,
    lease: WorkLease,
}

impl WorkLeaseGuard {
    pub fn lease(&self) -> &WorkLease {
        &self.lease
    }
}

impl Drop for WorkLeaseGuard {
    fn drop(&mut self) {
        if let Err(error) = self.store.release_work(&self.lease.id) {
            tracing::warn!(
                lease = %self.lease.id,
                cat = %self.lease.cat_id,
                "releasing work lease failed; it expires with its TTL: {error}"
            );
        }
    }
}

impl Store {
    /// Acquire a work lease whose release survives request cancellation.
    pub fn acquire_work_guarded(
        self: &Arc<Self>,
        cat_id: &str,
        kind: WorkKind,
        owner_id: &str,
        label: &str,
        ttl_ms: u64,
    ) -> Result<WorkLeaseGuard> {
        let lease = self.acquire_work(cat_id, kind, owner_id, label, ttl_ms)?;
        Ok(WorkLeaseGuard {
            store: Arc::clone(self),
            lease,
        })
    }
}

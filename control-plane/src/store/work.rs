use super::*;

impl Store {
    pub(super) fn fail_pending_auto_tier(
        tx: &rusqlite::Transaction<'_>,
        cat_id: &str,
        message: &str,
    ) -> Result<()> {
        let error = serde_json::to_string(&ErrorBody::new(ErrorCode::Conflict, message))
            .map_err(internal)?;
        tx.execute(
            "UPDATE operations SET phase='failed', error_json=?2, updated_at=?3
             WHERE resource_id=?1
               AND kind IN ('cat.auto_suspend','cat.auto_warm','cat.auto_cold')
               AND phase IN ('pending','running')",
            params![cat_id, error, now_unix()],
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let cat_exists: Option<String> = tx
            .query_row(
                "SELECT workspace_id FROM cats WHERE id=?1",
                params![cat_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        cat_exists.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM cat_work_leases
                 WHERE cat_id=?1 AND kind=?2 AND owner_id=?3",
                params![cat_id, work_kind_str(kind), owner_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        let id = existing.unwrap_or_else(|| new_id("work_"));
        let expires_at_ms = now_ms().saturating_add(ttl_ms as i64);
        tx.execute(
            "INSERT INTO cat_work_leases
                (id, cat_id, kind, owner_id, label, expires_at_ms, source_epoch)
             VALUES (?1,?2,?3,?4,?5,?6,NULL)
             ON CONFLICT(cat_id, kind, owner_id) DO UPDATE SET
                label=?5, expires_at_ms=?6",
            params![
                id,
                cat_id,
                work_kind_str(kind),
                owner_id,
                label,
                expires_at_ms
            ],
        )
        .map_err(internal)?;
        tx.execute(
            "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
            params![cat_id],
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
    }

    pub fn release_work(&self, lease_id: &str) -> Result<Option<String>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let cat_id: Option<String> = tx
            .query_row(
                "SELECT cat_id FROM cat_work_leases WHERE id=?1",
                params![lease_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        if let Some(cat_id) = &cat_id {
            tx.execute("DELETE FROM cat_work_leases WHERE id=?1", params![lease_id])
                .map_err(internal)?;
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }
        tx.commit().map_err(internal)?;
        Ok(cat_id)
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let cat: Option<(String, i64, String, String, Option<String>)> = tx
            .query_row(
                "SELECT workspace_id, generation, desired_state, observed_state, node_id
                 FROM cats WHERE id=?1",
                params![request.cat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
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
            .query_row(
                "SELECT source_epoch, lease_sequence FROM cat_work_sources WHERE cat_id=?1",
                params![request.cat_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
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
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(cat_id) DO UPDATE SET
                node_id=?2, generation=?3, source_epoch=?4,
                lease_sequence=?5, seen_at_ms=?6",
            params![
                request.cat_id,
                request.node_id,
                request.generation,
                request.guest_source_epoch,
                request_sequence,
                now
            ],
        )
        .map_err(internal)?;

        if changed {
            tx.execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1 AND kind='guest'",
                params![request.cat_id],
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
                     VALUES (?1,?2,'guest',?3,?4,?5,?6)",
                    params![
                        id,
                        request.cat_id,
                        owner,
                        guest.label.chars().take(128).collect::<String>(),
                        now.saturating_add(ttl as i64),
                        request.guest_source_epoch
                    ],
                )
                .map_err(internal)?;
            }
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![request.cat_id],
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
            Self::fail_pending_auto_tier(&tx, &request.cat_id, "superseded by Guest work")?;
            // The physical suspend for this generation has not committed.
            // Cancel it in-place so the Node and its work watcher can both
            // converge on the job generation after ActivityChanged.
            tx.execute(
                "UPDATE cats SET desired_state='running' WHERE id=?1",
                params![request.cat_id],
            )
            .map_err(internal)?;
        } else if wake_suspended {
            Self::fail_pending_auto_tier(&tx, &request.cat_id, "superseded by Guest work")?;
            let new_generation = generation + 1;
            tx.execute(
                "UPDATE cats SET desired_state='running', generation=?2 WHERE id=?1",
                params![request.cat_id, new_generation],
            )
            .map_err(internal)?;
            Self::insert_operation(
                &tx,
                &workspace_id,
                "cat.work_wake",
                &request.cat_id,
                new_generation,
            )?;
        }
        tx.commit().map_err(internal)?;
        Ok(should_wake)
    }

    pub fn work_status(&self, cat_id: &str, signal_stale_ms: i64) -> Result<CatWorkStatus> {
        let cat = self.must_get_cat_by_id(cat_id)?;
        let now = now_ms();
        let leases = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, cat_id, kind, owner_id, label, expires_at_ms
                 FROM cat_work_leases
                 WHERE cat_id=?1 AND expires_at_ms>?2
                 ORDER BY kind, id",
            )?;
            let rows = stmt.query_map(params![cat_id, now], row_to_work_lease)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        let source: Option<i64> = self.with(|c| {
            c.query_row(
                "SELECT seen_at_ms FROM cat_work_sources WHERE cat_id=?1",
                params![cat_id],
                |row| row.get(0),
            )
            .optional()
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
        let work_version = self.with(|c| {
            c.query_row(
                "SELECT work_version FROM cats WHERE id=?1",
                params![cat_id],
                |row| row.get(0),
            )
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
        self.with(|c| {
            c.query_row(
                "SELECT c.work_version, COALESCE(s.lease_sequence, 0)
                 FROM cats c LEFT JOIN cat_work_sources s ON s.cat_id=c.id
                 WHERE c.id=?1",
                params![cat_id],
                |row| {
                    Ok(cats_api::nodejob::SuspendWorkFence {
                        control_work_version: row.get(0)?,
                        guest_lease_sequence: row.get::<_, i64>(1)? as u64,
                    })
                },
            )
        })
    }

    pub fn auto_suspend_candidates(&self) -> Result<Vec<String>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM cats
                 WHERE auto_suspend=1 AND desired_state='running' AND observed_state='running'",
            )?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    pub fn try_auto_suspend(
        &self,
        cat_id: &str,
        signal_stale_ms: i64,
    ) -> Result<Option<Operation>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let now = now_ms();
        let expired = tx
            .execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1 AND expires_at_ms<=?2",
                params![cat_id, now],
            )
            .map_err(internal)?;
        if expired > 0 {
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }
        let cat: Option<(String, i64, i64, String, String)> = tx
            .query_row(
                "SELECT workspace_id, generation, auto_suspend,
                        desired_state, observed_state
                 FROM cats WHERE id=?1",
                params![cat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?;
        let Some((workspace_id, generation, auto_suspend, desired, observed)) = cat else {
            return Ok(None);
        };
        if auto_suspend == 0 || desired != "running" || observed != "running" {
            return Ok(None);
        }
        let source_seen: Option<i64> = tx
            .query_row(
                "SELECT seen_at_ms FROM cat_work_sources WHERE cat_id=?1",
                params![cat_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        if !source_seen.is_some_and(|seen| now.saturating_sub(seen) <= signal_stale_ms) {
            return Ok(None);
        }
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM cat_work_leases
                 WHERE cat_id=?1 AND expires_at_ms>?2",
                params![cat_id, now],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if active != 0 {
            return Ok(None);
        }
        let next = generation + 1;
        let changed = tx
            .execute(
                "UPDATE cats SET desired_state='suspended', generation=?2
                 WHERE id=?1 AND generation=?3 AND desired_state='running'
                   AND observed_state='running' AND auto_suspend=1
                   AND NOT EXISTS (
                     SELECT 1 FROM cat_work_leases
                     WHERE cat_id=?1 AND expires_at_ms>?4)",
                params![cat_id, next, generation, now],
            )
            .map_err(internal)?;
        if changed == 0 {
            return Ok(None);
        }
        let operation =
            Self::insert_operation(&tx, &workspace_id, "cat.auto_suspend", cat_id, next)?;
        tx.commit().map_err(internal)?;
        Ok(Some(operation))
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
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, observed_state, observed_state_since_ms
                   FROM cats
                  WHERE auto_suspend=1
                    AND desired_state=observed_state
                    AND observed_state IN ('suspended','warm')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            let mut candidates = Vec::new();
            for row in rows {
                let (id, state, since_ms) = row?;
                let threshold = match state.as_str() {
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let now = now_ms();
        let expired = tx
            .execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1 AND expires_at_ms<=?2",
                params![cat_id, now],
            )
            .map_err(internal)?;
        if expired > 0 {
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }

        let cat: Option<(String, i64, i64, String, String, i64)> = tx
            .query_row(
                "SELECT workspace_id, generation, auto_suspend,
                        desired_state, observed_state, observed_state_since_ms
                   FROM cats WHERE id=?1",
                params![cat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?;
        let Some((workspace_id, generation, auto_suspend, desired, observed, since_ms)) = cat
        else {
            return Ok(None);
        };
        if auto_suspend == 0 || desired != observed {
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
            .query_row(
                "SELECT COUNT(*) FROM cat_work_leases
                  WHERE cat_id=?1 AND expires_at_ms>?2",
                params![cat_id, now],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if active != 0 {
            return Ok(None);
        }

        let next_generation = generation + 1;
        let changed = tx
            .execute(
                "UPDATE cats
                    SET desired_state=?2, generation=?3
                  WHERE id=?1
                    AND generation=?4
                    AND auto_suspend=1
                    AND desired_state=?5
                    AND observed_state=?5
                    AND observed_state_since_ms=?6
                    AND NOT EXISTS (
                        SELECT 1 FROM cat_work_leases
                         WHERE cat_id=?1 AND expires_at_ms>?7
                    )",
                params![
                    cat_id,
                    next_state,
                    next_generation,
                    generation,
                    observed,
                    since_ms,
                    now
                ],
            )
            .map_err(internal)?;
        if changed == 0 {
            return Ok(None);
        }
        let operation =
            Self::insert_operation(&tx, &workspace_id, operation_kind, cat_id, next_generation)?;
        tx.commit().map_err(internal)?;
        Ok(Some(operation))
    }

    pub fn cancel_rejected_suspend(&self, cat_id: &str, job_generation: i64) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let current: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT generation, desired_state, observed_state FROM cats WHERE id=?1",
                params![cat_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
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
            "UPDATE operations SET phase='failed', error_json=?3, updated_at=?4
             WHERE resource_id=?1 AND resource_generation=?2
               AND phase IN ('pending','running')",
            params![cat_id, job_generation, error, now_unix()],
        )
        .map_err(internal)?;
        if observed == "suspending" {
            tx.execute(
                "UPDATE cats
                    SET observed_state='running', observed_state_since_ms=?2
                  WHERE id=?1",
                params![cat_id, now_ms()],
            )
            .map_err(internal)?;
        }
        if generation == job_generation && desired == "suspended" {
            tx.execute(
                "UPDATE cats SET desired_state='running' WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }
        tx.commit().map_err(internal)?;
        Ok(())
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

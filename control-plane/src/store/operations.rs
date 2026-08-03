use super::*;

impl Store {
    pub(super) fn insert_operation(
        tx: &rusqlite::Transaction<'_>,
        workspace_id: &str,
        kind: &str,
        resource_id: &str,
        generation: i64,
    ) -> Result<Operation> {
        let now = now_unix();
        let id = new_id(ids::OPERATION_PREFIX);
        tx.execute(
            "INSERT INTO operations (
                id, workspace_id, kind, resource_id,
                resource_generation, phase, created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,'pending',?6,?6)",
            params![id, workspace_id, kind, resource_id, generation, now],
        )
        .map_err(internal)?;
        Ok(Operation {
            id,
            workspace_id: workspace_id.to_string(),
            kind: kind.to_string(),
            resource_id: resource_id.to_string(),
            resource_generation: generation,
            phase: OperationPhase::Pending,
            error: None,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }
    // ------------------------------------------------------------------
    // Operations / idempotency
    // ------------------------------------------------------------------

    pub fn find_operation(&self, id: &str) -> Result<Option<Operation>> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM operations WHERE id=?1",
                params![id],
                row_to_operation,
            )
            .optional()
        })
    }

    pub fn get_operation(&self, id: &str) -> Result<Operation> {
        self.find_operation(id)?
            .ok_or_else(|| ApiError::not_found(format!("operation {id}")))
    }

    pub fn list_operations(&self, workspace_id: &str) -> Result<Vec<Operation>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM operations WHERE workspace_id=?1
                  ORDER BY created_at DESC, id DESC",
            )?;
            let rows = stmt.query_map(params![workspace_id], row_to_operation)?;
            rows.collect()
        })
    }

    pub fn operation_counts(&self) -> Result<OperationCounts> {
        self.with(|c| {
            c.query_row(
                "SELECT
                    SUM(CASE WHEN phase='pending' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='running' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='succeeded' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='failed' THEN 1 ELSE 0 END)
                 FROM operations",
                [],
                |row| {
                    Ok(OperationCounts {
                        pending: row.get::<_, Option<i64>>(0)?.unwrap_or(0) as u64,
                        running: row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                        succeeded: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                        failed: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                    })
                },
            )
        })
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

    /// Move a freshly created operation to `Running`.
    ///
    /// Lets a poller tell "accepted, not started" from "in flight", which for a
    /// deploy is the difference between waiting on a queue and waiting on a
    /// registry transfer. A terminal operation is left alone.
    pub fn start_operation(&self, op_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE operations SET phase='running', updated_at=?2
                  WHERE id=?1 AND phase='pending'",
                params![op_id, now_unix()],
            )
            .map(|_| ())
        })
    }

    pub fn finish_operation(&self, op_id: &str, error: Option<&ErrorBody>) -> Result<()> {
        let phase = if error.is_some() {
            "failed"
        } else {
            "succeeded"
        };
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

    /// Drops a record whose operation or resource no longer exists, so the key
    /// can be used again instead of replaying a reference to something deleted.
    pub fn idempotency_forget(&self, key: &str, route: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM idempotency WHERE key=?1 AND route=?2",
                params![key, route],
            )
            .map(|_| ())
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
}

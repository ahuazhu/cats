use super::*;

impl Store {
    pub(super) fn idempotency_operation_in(
        tx: &mut postgres::Transaction<'_>,
        key: &str,
        route: &str,
    ) -> Result<Option<Operation>> {
        // The row may not exist yet, so a row lock cannot serialize the first
        // two requests. A transaction advisory lock supplies that absent-row
        // linearization point; the record and resource mutation then commit
        // together below it.
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':idempotency:' || $1 || ':' || $2,
                0::BIGINT
             ))",
            &[&key, &route],
        )
        .map_err(internal)?;
        let operation_id: Option<String> = tx
            .query_opt(
                "SELECT operation_id FROM idempotency WHERE key=$1 AND route=$2",
                &[&key, &route],
            )
            .map_err(internal)?
            .map(|row| row.try_get(0))
            .transpose()
            .map_err(internal)?;
        let Some(operation_id) = operation_id else {
            return Ok(None);
        };
        let operation = tx
            .query_opt("SELECT * FROM operations WHERE id=$1", &[&operation_id])
            .map_err(internal)?
            .map(|row| row_to_operation(&row))
            .transpose()
            .map_err(internal)?;
        if operation.is_none() {
            tx.execute(
                "DELETE FROM idempotency WHERE key=$1 AND route=$2",
                &[&key, &route],
            )
            .map_err(internal)?;
        }
        Ok(operation)
    }

    pub(super) fn store_idempotency_in(
        tx: &mut postgres::Transaction<'_>,
        key: &str,
        route: &str,
        operation_id: &str,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO idempotency (key, route, operation_id) VALUES ($1,$2,$3)",
            &[&key, &route, &operation_id],
        )
        .map_err(internal)
        .map(|_| ())
    }

    pub(super) fn insert_operation(
        tx: &mut postgres::Transaction<'_>,
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
             ) VALUES ($1,$2,$3,$4,$5,'pending',$6,$6)",
            &[&id, &workspace_id, &kind, &resource_id, &generation, &now],
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
        self.with(|client| {
            client
                .query_opt("SELECT * FROM operations WHERE id=$1", &[&id])?
                .map(|row| row_to_operation(&row))
                .transpose()
        })
    }

    pub fn get_operation(&self, id: &str) -> Result<Operation> {
        self.find_operation(id)?
            .ok_or_else(|| ApiError::not_found(format!("operation {id}")))
    }

    pub fn list_operations(&self, workspace_id: &str) -> Result<Vec<Operation>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM operations WHERE workspace_id=$1
                      ORDER BY created_at DESC, id DESC",
                    &[&workspace_id],
                )?
                .iter()
                .map(row_to_operation)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    pub fn operation_counts(&self) -> Result<OperationCounts> {
        self.with(|client| {
            let row = client.query_one(
                "SELECT
                    SUM(CASE WHEN phase='pending' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='running' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='succeeded' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='failed' THEN 1 ELSE 0 END)
                 FROM operations",
                &[],
            )?;
            Ok(OperationCounts {
                pending: row.try_get::<_, Option<i64>>(0)?.unwrap_or(0) as u64,
                running: row.try_get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                succeeded: row.try_get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                failed: row.try_get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
            })
        })
    }

    pub fn pending_operations_for(&self, resource_id: &str) -> Result<Vec<Operation>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM operations WHERE resource_id=$1 AND phase IN ('pending','running')",
                    &[&resource_id],
                )?
                .iter()
                .map(row_to_operation)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    /// Unfinished desired-state operations that the lifecycle reconciler owns.
    ///
    /// OCI deploy operations also use the Cat id and generation, but their
    /// worker owns their result and terminal phase. A stable Cat must never
    /// make such an operation succeed before its deployment result commits.
    pub fn pending_lifecycle_operations_for(&self, resource_id: &str) -> Result<Vec<Operation>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM operations
                      WHERE resource_id=$1
                        AND phase IN ('pending','running')
                        AND kind IN (
                            'cat.create', 'cat.start', 'cat.resume',
                            'cat.suspend', 'cat.warm', 'cat.stop', 'cat.delete',
                            'cat.auto_suspend', 'cat.auto_warm', 'cat.auto_cold',
                            'cat.work_wake', 'cat.wake',
                            'cat.credit_exhausted', 'cat.expire'
                        )",
                    &[&resource_id],
                )?
                .iter()
                .map(row_to_operation)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    /// Move a freshly created operation to `Running`.
    ///
    /// Lets a poller tell "accepted, not started" from "in flight", which for a
    /// deploy is the difference between waiting on a queue and waiting on a
    /// registry transfer. A terminal operation is left alone.
    pub fn start_operation(&self, op_id: &str) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE operations SET phase='running', updated_at=$2
                      WHERE id=$1 AND phase='pending'",
                    &[&op_id, &now_unix()],
                )
                .map(|_| ())
        })
    }

    /// `finish_operation`, inside a caller's transaction.
    ///
    /// Lets a resource's terminal state and its operation's terminal phase
    /// commit together, so a crash between them cannot leave a finished piece
    /// of work behind an operation that never resolves.
    pub(super) fn finish_operation_in(
        tx: &mut postgres::Transaction<'_>,
        op_id: &str,
        error: Option<&ErrorBody>,
    ) -> Result<()> {
        let phase = if error.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        let err_json = error
            .map(serde_json::to_string)
            .transpose()
            .map_err(internal)?;
        tx.execute(
            "UPDATE operations SET phase=$2, error_json=$3, updated_at=$4
              WHERE id=$1 AND phase IN ('pending','running')",
            &[&op_id, &phase, &err_json, &now_unix()],
        )
        .map_err(internal)
        .map(|_| ())
    }

    pub fn finish_operation(&self, op_id: &str, error: Option<&ErrorBody>) -> Result<()> {
        let phase = if error.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        let err_json = error.map(|e| serde_json::to_string(e).expect("error serializes"));
        self.with(|client| {
            client
                .execute(
                    "UPDATE operations SET phase=$2, error_json=$3, updated_at=$4
                     WHERE id=$1 AND phase IN ('pending','running')",
                    &[&op_id, &phase, &err_json, &now_unix()],
                )
                .map(|_| ())
        })
    }

    /// Returns the previously stored operation id for this idempotency key.
    pub fn idempotency_lookup(&self, key: &str, route: &str) -> Result<Option<String>> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT operation_id FROM idempotency WHERE key=$1 AND route=$2",
                    &[&key, &route],
                )?
                .map(|r| r.try_get(0))
                .transpose()
        })
    }

    /// Drops a record whose operation or resource no longer exists, so the key
    /// can be used again instead of replaying a reference to something deleted.
    pub fn idempotency_forget(&self, key: &str, route: &str) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "DELETE FROM idempotency WHERE key=$1 AND route=$2",
                    &[&key, &route],
                )
                .map(|_| ())
        })
    }

    pub fn idempotency_store(&self, key: &str, route: &str, operation_id: &str) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "INSERT INTO idempotency (key, route, operation_id) VALUES ($1,$2,$3)
                     ON CONFLICT DO NOTHING",
                    &[&key, &route, &operation_id],
                )
                .map(|_| ())
        })
    }
}

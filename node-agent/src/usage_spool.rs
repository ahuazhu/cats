//! Durable, node-local outbox for cumulative usage checkpoints.
//!
//! The outbox is not the billing source of truth. It prevents a control-plane
//! outage or node-agent restart from losing checkpoints before the
//! authoritative ingestion service acknowledges them.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use cats_api::metering::{CatUsageCheckpoint, IngestUsageCheckpointsRequest};
use cats_api::runtime_reconciliation::SessionBinding;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct UsageSpool {
    connection: Mutex<Connection>,
}

impl UsageSpool {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create usage spool directory {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open usage spool {}", path.display()))?;
        connection.busy_timeout(std::time::Duration::from_secs(10))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS usage_checkpoint_outbox (
                event_id TEXT PRIMARY KEY,
                observed_at_unix_ms INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                enqueued_at_unix_ms INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS usage_checkpoint_outbox_order
                ON usage_checkpoint_outbox(observed_at_unix_ms, event_id);
            "#,
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn enqueue(&self, checkpoints: &[CatUsageCheckpoint]) -> Result<()> {
        if checkpoints.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let enqueued_at_unix_ms = now_unix_ms()?;
        for checkpoint in checkpoints {
            let payload_json = serde_json::to_string(checkpoint)?;
            let inserted = transaction.execute(
                r#"
                INSERT OR IGNORE INTO usage_checkpoint_outbox(
                    event_id, observed_at_unix_ms, payload_json, enqueued_at_unix_ms
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    checkpoint.event_id,
                    checkpoint.observed_at_unix_ms,
                    payload_json,
                    enqueued_at_unix_ms,
                ],
            )?;
            if inserted == 0 {
                let existing: Option<String> = transaction
                    .query_row(
                        "SELECT payload_json FROM usage_checkpoint_outbox WHERE event_id = ?1",
                        [&checkpoint.event_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if existing.as_deref() != Some(payload_json.as_str()) {
                    bail!(
                        "usage spool event {} conflicts with existing payload",
                        checkpoint.event_id
                    );
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn peek(&self, limit: usize) -> Result<Vec<CatUsageCheckpoint>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).context("usage spool batch limit exceeds i64")?;
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            r#"
            SELECT payload_json
            FROM usage_checkpoint_outbox
            ORDER BY observed_at_unix_ms, event_id
            LIMIT ?1
            "#,
        )?;
        let rows = statement.query_map([limit], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let payload = row?;
            serde_json::from_str(&payload).context("decode usage checkpoint from spool")
        })
        .collect()
    }

    /// Returns the oldest consecutive checkpoint prefix whose serialized
    /// ingestion request fits `max_request_bytes` exactly. Selecting by the
    /// current wire encoding avoids the count-only batching failure where a
    /// valid 10,000-item request exceeded the HTTP body limit forever.
    pub fn peek_request_batch(
        &self,
        session: &SessionBinding,
        max_checkpoints: usize,
        max_request_bytes: usize,
    ) -> Result<Vec<CatUsageCheckpoint>> {
        if max_checkpoints == 0 {
            return Ok(Vec::new());
        }
        let empty_request_bytes = serde_json::to_vec(&IngestUsageCheckpointsRequest {
            session: session.clone(),
            node_id: session.node_id.to_string(),
            checkpoints: Vec::new(),
        })?
        .len();
        if empty_request_bytes > max_request_bytes {
            bail!(
                "usage request byte budget {max_request_bytes} cannot fit its {empty_request_bytes}-byte envelope"
            );
        }

        let limit =
            i64::try_from(max_checkpoints).context("usage spool batch limit exceeds i64")?;
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            r#"
            SELECT event_id, payload_json
            FROM usage_checkpoint_outbox
            ORDER BY observed_at_unix_ms, event_id
            LIMIT ?1
            "#,
        )?;
        let mut rows = statement.query([limit])?;
        let mut request_bytes = empty_request_bytes;
        let mut checkpoints = Vec::new();
        while let Some(row) = rows.next()? {
            let event_id = row.get::<_, String>(0)?;
            let payload = row.get::<_, String>(1)?;
            let checkpoint: CatUsageCheckpoint =
                serde_json::from_str(&payload).context("decode usage checkpoint from spool")?;
            // Re-serialize with the current wire type instead of assuming an
            // older durable row's exact bytes remain its current encoding.
            let checkpoint_bytes = serde_json::to_vec(&checkpoint)?.len();
            let separator_bytes = usize::from(!checkpoints.is_empty());
            let candidate_bytes = request_bytes
                .checked_add(separator_bytes)
                .and_then(|bytes| bytes.checked_add(checkpoint_bytes))
                .context("usage request byte count overflow")?;
            if candidate_bytes > max_request_bytes {
                if checkpoints.is_empty() {
                    bail!(
                        "usage checkpoint {event_id} cannot fit the {max_request_bytes}-byte request budget"
                    );
                }
                break;
            }
            checkpoints.push(checkpoint);
            request_bytes = candidate_bytes;
        }
        Ok(checkpoints)
    }

    pub fn acknowledge(&self, event_ids: &[String]) -> Result<()> {
        if event_ids.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for event_id in event_ids {
            transaction.execute(
                "DELETE FROM usage_checkpoint_outbox WHERE event_id = ?1",
                [event_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64> {
        let connection = self.connection.lock().unwrap();
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM usage_checkpoint_outbox", [], |row| {
                row.get(0)
            })?;
        u64::try_from(count).context("usage spool row count was negative")
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

fn now_unix_ms() -> Result<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(elapsed.as_millis()).context("current Unix time exceeds i64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::metering::{UsageMetric, MAX_USAGE_CHECKPOINTS_PER_REQUEST};
    use cats_api::runtime_reconciliation::{Epoch, Id, NodeBootId, RandomId128};

    fn session() -> SessionBinding {
        SessionBinding {
            node_id: Id::new("node-a").unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: Epoch::new(1).unwrap(),
        }
    }

    fn checkpoint(event_id: &str, sequence: u64) -> CatUsageCheckpoint {
        CatUsageCheckpoint {
            event_id: event_id.to_string(),
            source_id: "node/node-a/cat/cat-a".to_string(),
            source_epoch: "epoch-a".to_string(),
            sequence,
            observed_at_unix_ms: 1_000 + i64::try_from(sequence).unwrap(),
            cat_id: "cat-a".to_string(),
            cat_generation: 1,
            metric: UsageMetric::CpuUsec,
            cumulative_quantity: u128::from(sequence),
        }
    }

    #[test]
    fn survives_reopen_and_acknowledges_only_named_events() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-spool.sqlite3");
        {
            let spool = UsageSpool::open(&path).unwrap();
            spool
                .enqueue(&[checkpoint("event-1", 1), checkpoint("event-2", 2)])
                .unwrap();
            spool.enqueue(&[checkpoint("event-1", 1)]).unwrap();
            assert_eq!(spool.len().unwrap(), 2);
        }
        let spool = UsageSpool::open(&path).unwrap();
        assert_eq!(
            spool
                .peek(10)
                .unwrap()
                .iter()
                .map(|item| item.event_id.as_str())
                .collect::<Vec<_>>(),
            ["event-1", "event-2"]
        );
        spool.acknowledge(&["event-1".to_string()]).unwrap();
        assert_eq!(spool.len().unwrap(), 1);
        assert_eq!(spool.peek(10).unwrap()[0].event_id, "event-2");
    }

    #[test]
    fn rejects_same_event_id_with_different_payload() {
        let directory = tempfile::tempdir().unwrap();
        let spool = UsageSpool::open(&directory.path().join("usage-spool.sqlite3")).unwrap();
        spool.enqueue(&[checkpoint("event-1", 1)]).unwrap();
        let mut conflict = checkpoint("event-1", 1);
        conflict.cumulative_quantity = 999;
        assert!(spool.enqueue(&[conflict]).is_err());
    }

    #[test]
    fn request_batch_stops_at_the_exact_serialized_byte_budget() {
        let directory = tempfile::tempdir().unwrap();
        let spool = UsageSpool::open(&directory.path().join("usage-spool.sqlite3")).unwrap();
        let checkpoints = vec![
            checkpoint("event-1", 1),
            checkpoint("event-2", 2),
            checkpoint("event-3", 3),
        ];
        spool.enqueue(&checkpoints).unwrap();
        let session = session();
        let two_checkpoint_bytes = serde_json::to_vec(&IngestUsageCheckpointsRequest {
            session: session.clone(),
            node_id: "node-a".to_string(),
            checkpoints: checkpoints[..2].to_vec(),
        })
        .unwrap()
        .len();

        let batch = spool
            .peek_request_batch(&session, 10, two_checkpoint_bytes)
            .unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].event_id, "event-1");
        assert_eq!(batch[1].event_id, "event-2");
        assert_eq!(
            serde_json::to_vec(&IngestUsageCheckpointsRequest {
                session,
                node_id: "node-a".to_string(),
                checkpoints: batch,
            })
            .unwrap()
            .len(),
            two_checkpoint_bytes
        );
    }

    #[test]
    fn oversized_queue_head_is_retained_and_reported() {
        let directory = tempfile::tempdir().unwrap();
        let spool = UsageSpool::open(&directory.path().join("usage-spool.sqlite3")).unwrap();
        spool.enqueue(&[checkpoint("event-1", 1)]).unwrap();
        let session = session();
        let empty_request_bytes = serde_json::to_vec(&IngestUsageCheckpointsRequest {
            session: session.clone(),
            node_id: "node-a".to_string(),
            checkpoints: Vec::new(),
        })
        .unwrap()
        .len();

        let error = spool
            .peek_request_batch(&session, 10, empty_request_bytes)
            .unwrap_err();
        assert!(error.to_string().contains("event-1 cannot fit"));
        assert_eq!(spool.len().unwrap(), 1);
    }

    #[test]
    fn large_backlog_drains_in_order_without_exceeding_a_request_budget() {
        const BACKLOG: usize = 12_050;
        const REQUEST_BUDGET: usize = 1024 * 1024;

        let directory = tempfile::tempdir().unwrap();
        let spool = UsageSpool::open(&directory.path().join("usage-spool.sqlite3")).unwrap();
        let checkpoints = (0..BACKLOG)
            .map(|sequence| {
                checkpoint(
                    &format!("event-{sequence:05}"),
                    u64::try_from(sequence).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        spool.enqueue(&checkpoints).unwrap();
        let session = session();

        let mut next_sequence = 0_u64;
        let mut batches = 0;
        while !spool.is_empty().unwrap() {
            let batch = spool
                .peek_request_batch(&session, MAX_USAGE_CHECKPOINTS_PER_REQUEST, REQUEST_BUDGET)
                .unwrap();
            assert!(!batch.is_empty());
            assert!(batch.len() <= MAX_USAGE_CHECKPOINTS_PER_REQUEST);
            let request_bytes = serde_json::to_vec(&IngestUsageCheckpointsRequest {
                session: session.clone(),
                node_id: "node-a".to_string(),
                checkpoints: batch.clone(),
            })
            .unwrap()
            .len();
            assert!(request_bytes <= REQUEST_BUDGET);
            for checkpoint in &batch {
                assert_eq!(checkpoint.sequence, next_sequence);
                next_sequence += 1;
            }
            spool
                .acknowledge(
                    &batch
                        .iter()
                        .map(|checkpoint| checkpoint.event_id.clone())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            batches += 1;
        }
        assert_eq!(next_sequence, u64::try_from(BACKLOG).unwrap());
        assert!(batches > 1);
    }
}

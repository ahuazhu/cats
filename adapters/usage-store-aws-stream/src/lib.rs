//! AWS durable-stream adapter for production usage delivery.
//!
//! Ingestion acknowledges only after Kinesis accepts the immutable attributed
//! checkpoint. A background projector consumes every shard, writes the exact
//! JSON envelope to an immutable S3 key, applies the idempotent PostgreSQL
//! projection through `UsageStore`, and advances a DynamoDB checkpoint last.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kinesis::primitives::Blob;
use aws_sdk_kinesis::types::ShardIteratorType;
use aws_sdk_s3::primitives::ByteStream;
use cats_metering::{
    sha256_prefixed, target_terminal_marker, target_terminal_request_sha256,
    validate_target_terminal_receipt, validate_target_terminal_request, ArchivedUsageCheckpoint,
    ArchivedUsageTerminalBarrier, AttributedCheckpoint, IngestOutcome, MeteringError,
    UsageAttribution, UsageQuery, UsageSourceTerminalReceipt, UsageStore, UsageStoreFuture,
    UsageStreamRecord, UsageTargetBinding, UsageTargetTerminalReceipt, UsageTargetTerminalRequest,
    UsageTerminalPrepareOutcome, UsageTerminalShardTarget, UsageView,
};
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use sha2::{Digest, Sha256};

const KINESIS_RECORD_LIMIT: usize = 1_048_576;
const ARCHIVE_BATCH_MAX_BYTES: usize = 4 * 1_048_576;
const ARCHIVE_BATCH_MAX_RECORDS: usize = 1_000;
// Node checkpoints target ten seconds. A fifty-second archive window keeps
// end-to-end provisional-billing freshness within the sixty-second target.
const ARCHIVE_BATCH_MAX_AGE: Duration = Duration::from_secs(50);
// Kinesis permits five GetRecords calls per second per shard, but AWS
// recommends a full second between calls: an exact 200 ms loop has no margin
// for scheduling jitter, while the old non-empty-response path had no delay at
// all. One read can return far more than a shard can ingest in one second, so
// this remains sufficient to keep up without continuously throttling.
const KINESIS_READ_INTERVAL: Duration = Duration::from_secs(1);

fn kinesis_read_pacer() -> tokio::time::Interval {
    let mut pacer = tokio::time::interval(KINESIS_READ_INTERVAL);
    // A delayed projection/archive operation must not be followed by a burst
    // of nominally missed reads that immediately violates the shard limit.
    pacer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    pacer
}

struct PendingRecord {
    sequence_number: String,
    record: UsageStreamRecord,
}

struct ArchiveBatch {
    key: String,
    payload: Vec<u8>,
    sha256: String,
    last_sequence_number: String,
}

#[derive(Debug, Clone)]
pub struct AwsUsageStreamConfig {
    pub region: String,
    pub stream_name: String,
    pub archive_bucket: String,
    pub checkpoint_table: String,
}

impl AwsUsageStreamConfig {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.region.trim().is_empty(), "AWS region is required");
        anyhow::ensure!(
            !self.stream_name.trim().is_empty(),
            "Kinesis stream name is required"
        );
        anyhow::ensure!(
            !self.archive_bucket.trim().is_empty(),
            "usage archive bucket is required"
        );
        anyhow::ensure!(
            !self.checkpoint_table.trim().is_empty(),
            "usage checkpoint table is required"
        );
        Ok(())
    }
}

pub struct AwsUsageStreamStore {
    projection: Arc<dyn UsageStore>,
    kinesis: aws_sdk_kinesis::Client,
    s3: aws_sdk_s3::Client,
    dynamodb: aws_sdk_dynamodb::Client,
    config: AwsUsageStreamConfig,
    /// Serializes marker placement against producer PutRecord. The persisted
    /// target operation seeds this gate on restart, so retirement cannot
    /// accidentally reopen after process loss.
    terminal_gate: tokio::sync::RwLock<bool>,
}

impl AwsUsageStreamStore {
    pub async fn load(
        projection: Arc<dyn UsageStore>,
        config: AwsUsageStreamConfig,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let target_terminal_active = projection
            .active_target_terminal()
            .await
            .map_err(anyhow::Error::new)
            .context("discover persisted Usage target terminal gate")?
            .is_some();
        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()))
            .load()
            .await;
        Ok(Arc::new(Self {
            projection,
            kinesis: aws_sdk_kinesis::Client::new(&sdk_config),
            s3: aws_sdk_s3::Client::new(&sdk_config),
            dynamodb: aws_sdk_dynamodb::Client::new(&sdk_config),
            config,
            terminal_gate: tokio::sync::RwLock::new(target_terminal_active),
        }))
    }

    pub fn spawn_projector(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.clone().run_projector())
    }

    /// Project every shard until the caller cancels this future.
    ///
    /// Production runs it behind the control plane's PostgreSQL leadership
    /// fence. Keeping the loop as a future (rather than an untracked spawned
    /// task) lets leadership loss cancel every shard consumer before a standby
    /// takes over.
    pub async fn run_projector(self: Arc<Self>) {
        loop {
            if let Err(error) = self.project_all_shards().await {
                tracing::error!(%error, "usage stream projector supervisor failed");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn project_all_shards(self: &Arc<Self>) -> Result<()> {
        let output = self
            .kinesis
            .list_shards()
            .stream_name(&self.config.stream_name)
            .send()
            .await
            .context("list usage Kinesis shards")?;
        let shard_ids = output
            .shards()
            .iter()
            .map(|shard| shard.shard_id().to_string())
            .collect::<Vec<_>>();
        run_shard_workers(shard_ids, |shard_id| {
            let store = self.clone();
            async move {
                store.project_shard_forever(shard_id).await;
            }
        })
        .await
    }

    async fn project_shard_forever(&self, shard_id: String) {
        loop {
            if let Err(error) = self.project_shard(&shard_id).await {
                tracing::error!(shard_id, %error, "usage shard projection failed; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    async fn project_shard(&self, shard_id: &str) -> Result<()> {
        let checkpoint = self.load_checkpoint(shard_id).await?;
        let mut iterator_request = self
            .kinesis
            .get_shard_iterator()
            .stream_name(&self.config.stream_name)
            .shard_id(shard_id);
        iterator_request = if let Some(sequence) = checkpoint {
            iterator_request
                .shard_iterator_type(ShardIteratorType::AfterSequenceNumber)
                .starting_sequence_number(sequence)
        } else {
            iterator_request.shard_iterator_type(ShardIteratorType::TrimHorizon)
        };
        let mut iterator = iterator_request
            .send()
            .await
            .context("get usage Kinesis shard iterator")?
            .shard_iterator()
            .map(ToString::to_string);
        let mut pending = Vec::<PendingRecord>::new();
        let mut pending_bytes = 0_usize;
        let mut pending_since = None;
        let mut read_pacer = kinesis_read_pacer();

        while let Some(current_iterator) = iterator {
            // The first tick is immediate. Every later GetRecords request is
            // paced regardless of whether the preceding response was empty.
            read_pacer.tick().await;
            let output = self
                .kinesis
                .get_records()
                .shard_iterator(current_iterator)
                .limit(1_000)
                .send()
                .await
                .context("read usage Kinesis records")?;
            for record in output.records() {
                let stream_record: UsageStreamRecord =
                    serde_json::from_slice(record.data().as_ref())
                        .context("decode usage stream record from Kinesis")?;
                if pending.is_empty() {
                    pending_since = Some(std::time::Instant::now());
                }
                pending_bytes = pending_bytes
                    .checked_add(record.data().as_ref().len())
                    .context("usage archive batch byte count overflow")?;
                pending.push(PendingRecord {
                    sequence_number: record.sequence_number().to_string(),
                    record: stream_record,
                });
            }
            let terminal_barrier_seen = pending
                .iter()
                .any(|record| matches!(&record.record, UsageStreamRecord::TerminalBarrier(_)));
            let archive_due = !pending.is_empty()
                && (pending.len() >= ARCHIVE_BATCH_MAX_RECORDS
                    || pending_bytes >= ARCHIVE_BATCH_MAX_BYTES
                    || terminal_barrier_seen
                    || pending_since
                        .is_some_and(|started| started.elapsed() >= ARCHIVE_BATCH_MAX_AGE));
            if archive_due {
                if let Some(sequence) = self.project_batch(shard_id, &pending).await? {
                    self.save_checkpoint(shard_id, &sequence).await?;
                }
                pending.clear();
                pending_bytes = 0;
                pending_since = None;
            }
            iterator = output.next_shard_iterator().map(ToString::to_string);
        }
        if let Some(sequence) = self.project_batch(shard_id, &pending).await? {
            self.save_checkpoint(shard_id, &sequence).await?;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        Ok(())
    }

    async fn project_batch(
        &self,
        shard_id: &str,
        records: &[PendingRecord],
    ) -> Result<Option<String>> {
        let Some(batch) = encode_archive_batch(shard_id, records)? else {
            return Ok(None);
        };
        self.archive(&batch.key, batch.payload).await?;
        apply_projection(
            self.projection.as_ref(),
            records,
            &self.config.stream_name,
            &self.config.archive_bucket,
            &batch.key,
            &batch.sha256,
        )
        .await?;
        Ok(Some(batch.last_sequence_number))
    }

    async fn archive(&self, key: &str, payload: Vec<u8>) -> Result<()> {
        let put = self
            .s3
            .put_object()
            .bucket(&self.config.archive_bucket)
            .key(key)
            .content_type("application/x-ndjson")
            .if_none_match("*")
            .body(ByteStream::from(payload.clone()))
            .send()
            .await;
        if put.is_ok() {
            return Ok(());
        }

        // A replay after archive success but before the DynamoDB checkpoint
        // sees PreconditionFailed. Read and compare the immutable object so a
        // same-key/different-payload conflict fails closed.
        let existing = self
            .s3
            .get_object()
            .bucket(&self.config.archive_bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("read existing immutable usage archive object {key}"))?;
        let existing = existing
            .body
            .collect()
            .await
            .with_context(|| format!("collect immutable usage archive object {key}"))?
            .into_bytes();
        anyhow::ensure!(
            existing.as_ref() == payload.as_slice(),
            "immutable usage archive object {key} has conflicting content"
        );
        Ok(())
    }

    fn checkpoint_key(&self, shard_id: &str) -> String {
        format!("projection/{}/{shard_id}", self.config.stream_name)
    }

    async fn load_checkpoint(&self, shard_id: &str) -> Result<Option<String>> {
        let output = self
            .dynamodb
            .get_item()
            .table_name(&self.config.checkpoint_table)
            .key(
                "lease_key",
                AttributeValue::S(self.checkpoint_key(shard_id)),
            )
            .consistent_read(true)
            .send()
            .await
            .context("load usage projector checkpoint")?;
        output
            .item()
            .and_then(|item| item.get("sequence_number"))
            .map(|value| {
                value
                    .as_s()
                    .map(ToString::to_string)
                    .map_err(|_| anyhow::anyhow!("usage projector checkpoint is not a string"))
            })
            .transpose()
    }

    async fn save_checkpoint(&self, shard_id: &str, sequence: &str) -> Result<()> {
        let updated_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_millis()
            .to_string();
        self.dynamodb
            .put_item()
            .table_name(&self.config.checkpoint_table)
            .item(
                "lease_key",
                AttributeValue::S(self.checkpoint_key(shard_id)),
            )
            .item("sequence_number", AttributeValue::S(sequence.to_string()))
            .item("updated_at_unix_ms", AttributeValue::N(updated_at_unix_ms))
            .send()
            .await
            .context("save usage projector checkpoint")?;
        Ok(())
    }

    /// Return the exact open-shard routing targets used to construct a target
    /// terminal request. A stream with any closed shard is refused: a reshard
    /// must settle before this closed-set protocol can begin.
    pub async fn terminal_shard_targets(
        &self,
    ) -> cats_metering::Result<Vec<UsageTerminalShardTarget>> {
        self.list_stable_open_shards(&self.config.stream_name).await
    }

    /// Persist the closed source set, close producer ingress, then place one
    /// deterministic marker into every exact old-stream shard. A response-loss
    /// retry writes the same marker payload and remains safe; the projector
    /// chooses the earliest archived instance.
    pub async fn begin_target_terminal_operation(
        &self,
        request: &UsageTargetTerminalRequest,
    ) -> cats_metering::Result<UsageTerminalPrepareOutcome> {
        validate_target_terminal_request(request)?;
        self.verify_terminal_request_live(request).await?;

        // An ingest holds the read side through its PutRecord. Once this write
        // lock is acquired, every record it accepted is ordered before the
        // marker and every later ingest observes the closed bit.
        let mut terminal_gate = self.terminal_gate.write().await;
        self.verify_terminal_request_live(request).await?;
        let prepared = match self.projection.prepare_target_terminal(request).await {
            Ok(outcome) => outcome,
            Err(error) => {
                // Store errors can hide a committed response. Close locally
                // before discovery; a false-negative availability stop is
                // safer than admitting a record on the wrong side of markers.
                if matches!(error, MeteringError::Store(_)) {
                    *terminal_gate = true;
                    if let Some(state) = self.projection.active_target_terminal().await? {
                        if state.request == *request
                            && state.request_sha256 == target_terminal_request_sha256(request)?
                        {
                            UsageTerminalPrepareOutcome::ExactReplay
                        } else {
                            return Err(error);
                        }
                    } else {
                        return Err(error);
                    }
                } else {
                    return Err(error);
                }
            }
        };
        *terminal_gate = true;

        for shard in &request.shards {
            let marker = target_terminal_marker(request, &shard.shard_id)?;
            let payload = serde_json::to_vec(&UsageStreamRecord::TerminalBarrier(marker.clone()))?;
            if payload.len() > KINESIS_RECORD_LIMIT {
                return Err(MeteringError::Invalid(
                    "Usage terminal marker exceeds the Kinesis record limit".into(),
                ));
            }
            let output = self
                .kinesis
                .put_record()
                .stream_name(&request.old_target.stream_name)
                .partition_key(&marker.marker_id)
                .explicit_hash_key(&shard.explicit_hash_key)
                .data(Blob::new(payload))
                .send()
                .await
                .map_err(|error| {
                    MeteringError::Store(format!(
                        "put Usage terminal marker for shard {}: {error}",
                        shard.shard_id
                    ))
                })?;
            if output.shard_id() != shard.shard_id {
                return Err(MeteringError::Conflict(format!(
                    "Usage terminal marker for {} landed in foreign shard {}",
                    shard.shard_id,
                    output.shard_id()
                )));
            }
        }

        // Catch a reshard or identity replacement concurrent with marker
        // placement. The operation stays safely closed and can be investigated;
        // no receipt is manufactured from this call.
        self.verify_terminal_request_live(request).await?;
        Ok(prepared)
    }

    /// Discover whether every exact marker is archived/projected and its
    /// DynamoDB shard checkpoint has advanced. On closure, write the canonical
    /// receipt to Object-Locked S3 first and insert-only PostgreSQL second.
    pub async fn complete_target_terminal_operation(
        &self,
        request: &UsageTargetTerminalRequest,
    ) -> cats_metering::Result<Option<UsageTargetTerminalReceipt>> {
        validate_target_terminal_request(request)?;
        let terminal_gate = self.terminal_gate.read().await;
        if !*terminal_gate {
            return Err(MeteringError::Conflict(
                "Usage target terminal operation has not closed producer ingress".into(),
            ));
        }
        self.verify_terminal_request_live(request).await?;

        let terminal_epoch_id = request.terminal_epoch_id.to_string();
        let state = self
            .projection
            .target_terminal_state(&terminal_epoch_id)
            .await?
            .ok_or_else(|| {
                MeteringError::Conflict(
                    "Usage target terminal operation has no prepared projection".into(),
                )
            })?;
        let request_sha256 = target_terminal_request_sha256(request)?;
        if state.request != *request || state.request_sha256 != request_sha256 {
            return Err(MeteringError::Conflict(
                "Usage target terminal discovery request does not match the prepared operation"
                    .into(),
            ));
        }

        if let Some(receipt) = state.receipt {
            validate_target_terminal_receipt(&receipt)?;
            self.verify_target_receipt_object(&receipt).await?;
            return Ok(Some(receipt));
        }
        if state.barriers.len() != request.shards.len() {
            return Ok(None);
        }
        for barrier in &state.barriers {
            let Some(checkpoint) = self
                .load_checkpoint(&barrier.marker.shard_id)
                .await
                .map_err(|error| {
                    MeteringError::Store(format!("load terminal projector checkpoint: {error}"))
                })?
            else {
                return Ok(None);
            };
            if !canonical_decimal_at_least(&checkpoint, &barrier.archive.sequence_number)? {
                return Ok(None);
            }
        }

        // Verify the topology and provider identities again after observing
        // catch-up; otherwise a concurrent reshard could turn an old snapshot
        // of the shard set into a false global barrier.
        self.verify_terminal_request_live(request).await?;
        let mut source_receipts = Vec::with_capacity(request.sources.len());
        for source in &request.sources {
            let receipt = self
                .projection
                .source_terminal_receipt(&source.source_id, &source.source_epoch)
                .await?
                .ok_or_else(|| {
                    MeteringError::Conflict(format!(
                        "source {}/{} lost its terminal receipt",
                        source.source_id, source.source_epoch
                    ))
                })?;
            let actual_sha256 = sha256_prefixed(&serde_json::to_vec(&receipt)?);
            if actual_sha256 != source.receipt_sha256 {
                return Err(MeteringError::Conflict(format!(
                    "source {}/{} terminal receipt digest changed",
                    source.source_id, source.source_epoch
                )));
            }
            source_receipts.push(receipt);
        }
        let receipt = UsageTargetTerminalReceipt {
            contract_version: 1,
            request: request.clone(),
            request_sha256,
            source_receipts,
            barriers: state.barriers,
        };
        validate_target_terminal_receipt(&receipt)?;
        self.put_target_receipt_object(&receipt).await?;
        self.projection.commit_target_terminal(&receipt).await?;

        // Both writes are response-loss replayable. Rediscovery proves the PG
        // side contains the exact bytes just compared with immutable S3.
        let committed = self
            .projection
            .target_terminal_state(&terminal_epoch_id)
            .await?
            .and_then(|state| state.receipt)
            .ok_or_else(|| {
                MeteringError::Store(
                    "Usage target terminal receipt commit was not discoverable".into(),
                )
            })?;
        if committed != receipt {
            return Err(MeteringError::Conflict(
                "Usage target terminal receipt discovery returned conflicting bytes".into(),
            ));
        }
        self.verify_target_receipt_object(&committed).await?;
        Ok(Some(committed))
    }

    async fn verify_terminal_request_live(
        &self,
        request: &UsageTargetTerminalRequest,
    ) -> cats_metering::Result<()> {
        if self.config.region != request.old_target.aws_region
            || self.config.stream_name != request.old_target.stream_name
            || self.config.checkpoint_table != request.old_target.checkpoint_table_name
            || self.config.archive_bucket != request.old_target.archive_bucket_name
        {
            return Err(MeteringError::Invalid(
                "terminal old target does not match the running Usage adapter".into(),
            ));
        }
        self.verify_target_resources(&request.old_target).await?;
        self.verify_target_resources(&request.fresh_target).await?;
        let actual_shards = self
            .list_stable_open_shards(&request.old_target.stream_name)
            .await?;
        if actual_shards != request.shards {
            return Err(MeteringError::Conflict(
                "old Usage stream shard set or hash ranges changed".into(),
            ));
        }
        Ok(())
    }

    async fn verify_target_resources(
        &self,
        target: &UsageTargetBinding,
    ) -> cats_metering::Result<()> {
        if target.aws_region != self.config.region {
            return Err(MeteringError::Invalid(
                "Usage target region does not match the configured AWS client".into(),
            ));
        }
        let stream = self
            .kinesis
            .describe_stream_summary()
            .stream_name(&target.stream_name)
            .send()
            .await
            .map_err(|error| {
                MeteringError::Store(format!(
                    "describe Usage Kinesis stream {}: {error}",
                    target.stream_name
                ))
            })?;
        let stream = stream.stream_description_summary().ok_or_else(|| {
            MeteringError::Store("Kinesis omitted the Usage stream summary".into())
        })?;
        if stream.stream_arn() != target.stream_arn || stream.stream_status().as_str() != "ACTIVE" {
            return Err(MeteringError::Conflict(format!(
                "Usage Kinesis stream {} identity or state changed",
                target.stream_name
            )));
        }

        let table = self
            .dynamodb
            .describe_table()
            .table_name(&target.checkpoint_table_name)
            .send()
            .await
            .map_err(|error| {
                MeteringError::Store(format!(
                    "describe Usage checkpoint table {}: {error}",
                    target.checkpoint_table_name
                ))
            })?;
        let table = table.table().ok_or_else(|| {
            MeteringError::Store("DynamoDB omitted the Usage checkpoint table description".into())
        })?;
        if table.table_arn() != Some(target.checkpoint_table_arn.as_str())
            || table.table_status().map(|status| status.as_str()) != Some("ACTIVE")
        {
            return Err(MeteringError::Conflict(format!(
                "Usage checkpoint table {} identity or state changed",
                target.checkpoint_table_name
            )));
        }

        let bucket = self
            .s3
            .head_bucket()
            .bucket(&target.archive_bucket_name)
            .expected_bucket_owner(&target.aws_account_id)
            .send()
            .await
            .map_err(|error| {
                MeteringError::Store(format!(
                    "head Usage archive bucket {}: {error}",
                    target.archive_bucket_name
                ))
            })?;
        if bucket.bucket_region() != Some(target.aws_region.as_str()) {
            return Err(MeteringError::Conflict(format!(
                "Usage archive bucket {} region changed",
                target.archive_bucket_name
            )));
        }
        let lock = self
            .s3
            .get_object_lock_configuration()
            .bucket(&target.archive_bucket_name)
            .expected_bucket_owner(&target.aws_account_id)
            .send()
            .await
            .map_err(|error| {
                MeteringError::Store(format!(
                    "read Usage archive bucket {} Object Lock: {error}",
                    target.archive_bucket_name
                ))
            })?;
        let retention = lock
            .object_lock_configuration()
            .filter(|configuration| {
                configuration
                    .object_lock_enabled()
                    .is_some_and(|enabled| enabled.as_str() == "Enabled")
            })
            .and_then(|configuration| configuration.rule())
            .and_then(|rule| rule.default_retention())
            .ok_or_else(|| {
                MeteringError::Conflict(format!(
                    "Usage archive bucket {} has no default Object Lock retention",
                    target.archive_bucket_name
                ))
            })?;
        let mode_is_valid = retention
            .mode()
            .is_some_and(|mode| matches!(mode.as_str(), "GOVERNANCE" | "COMPLIANCE"));
        let period_is_valid = matches!(
            (retention.days(), retention.years()),
            (Some(days), None) if days > 0
        ) || matches!(
            (retention.days(), retention.years()),
            (None, Some(years)) if years > 0
        );
        if !mode_is_valid || !period_is_valid {
            return Err(MeteringError::Conflict(format!(
                "Usage archive bucket {} Object Lock retention is invalid",
                target.archive_bucket_name
            )));
        }
        Ok(())
    }

    async fn list_stable_open_shards(
        &self,
        stream_name: &str,
    ) -> cats_metering::Result<Vec<UsageTerminalShardTarget>> {
        let mut next_token = None::<String>;
        let mut targets = Vec::new();
        loop {
            let mut request = self.kinesis.list_shards();
            request = if let Some(token) = next_token.take() {
                request.next_token(token)
            } else {
                request.stream_name(stream_name)
            };
            let output = request.send().await.map_err(|error| {
                MeteringError::Store(format!(
                    "list terminal shards for Usage stream {stream_name}: {error}"
                ))
            })?;
            for shard in output.shards() {
                let sequence_range = shard.sequence_number_range().ok_or_else(|| {
                    MeteringError::Store(format!(
                        "Kinesis shard {} omitted its sequence range",
                        shard.shard_id()
                    ))
                })?;
                if sequence_range.ending_sequence_number().is_some() {
                    return Err(MeteringError::Conflict(format!(
                        "Usage stream contains closed shard {}; reshard is not terminal-stable",
                        shard.shard_id()
                    )));
                }
                let hash_range = shard.hash_key_range().ok_or_else(|| {
                    MeteringError::Store(format!(
                        "Kinesis shard {} omitted its hash-key range",
                        shard.shard_id()
                    ))
                })?;
                targets.push(UsageTerminalShardTarget {
                    shard_id: shard.shard_id().to_string(),
                    explicit_hash_key: hash_range.starting_hash_key().to_string(),
                });
            }
            next_token = output.next_token().map(ToString::to_string);
            if next_token.is_none() {
                break;
            }
        }
        targets.sort_by(|left, right| left.shard_id.cmp(&right.shard_id));
        if targets.is_empty() {
            return Err(MeteringError::Conflict(
                "Usage stream has no open terminal shards".into(),
            ));
        }
        if targets
            .windows(2)
            .any(|pair| pair[0].shard_id == pair[1].shard_id)
        {
            return Err(MeteringError::Store(
                "Kinesis returned a duplicate Usage shard identity".into(),
            ));
        }
        Ok(targets)
    }

    fn target_receipt_key(receipt: &UsageTargetTerminalReceipt) -> String {
        format!("terminal/v1/{}.json", receipt.request.terminal_epoch_id)
    }

    async fn put_target_receipt_object(
        &self,
        receipt: &UsageTargetTerminalReceipt,
    ) -> cats_metering::Result<()> {
        let key = Self::target_receipt_key(receipt);
        let payload = serde_json::to_vec(receipt)?;
        let put = self
            .s3
            .put_object()
            .bucket(&receipt.request.old_target.archive_bucket_name)
            .key(&key)
            .content_type("application/json")
            .expected_bucket_owner(&receipt.request.old_target.aws_account_id)
            .if_none_match("*")
            .body(ByteStream::from(payload.clone()))
            .send()
            .await;
        if put.is_ok() {
            return Ok(());
        }
        let existing = self
            .read_target_receipt_object(receipt)
            .await
            .map_err(|error| {
                MeteringError::Store(format!(
                    "write immutable Usage target receipt {key}, then discover postcondition: {error}"
                ))
            })?;
        if existing != payload {
            return Err(MeteringError::Conflict(format!(
                "immutable Usage target receipt object {key} has conflicting bytes"
            )));
        }
        Ok(())
    }

    async fn verify_target_receipt_object(
        &self,
        receipt: &UsageTargetTerminalReceipt,
    ) -> cats_metering::Result<()> {
        let expected = serde_json::to_vec(receipt)?;
        let actual = self.read_target_receipt_object(receipt).await?;
        if actual != expected || sha256_prefixed(&actual) != sha256_prefixed(&expected) {
            return Err(MeteringError::Conflict(format!(
                "immutable Usage target receipt object {} conflicts with PostgreSQL",
                Self::target_receipt_key(receipt)
            )));
        }
        Ok(())
    }

    async fn read_target_receipt_object(
        &self,
        receipt: &UsageTargetTerminalReceipt,
    ) -> cats_metering::Result<Vec<u8>> {
        let key = Self::target_receipt_key(receipt);
        let object = self
            .s3
            .get_object()
            .bucket(&receipt.request.old_target.archive_bucket_name)
            .key(&key)
            .expected_bucket_owner(&receipt.request.old_target.aws_account_id)
            .send()
            .await
            .map_err(|error| {
                MeteringError::Store(format!(
                    "read immutable Usage target receipt {key}: {error}"
                ))
            })?;
        object
            .body
            .collect()
            .await
            .map(|body| body.into_bytes().to_vec())
            .map_err(|error| {
                MeteringError::Store(format!(
                    "collect immutable Usage target receipt {key}: {error}"
                ))
            })
    }
}

fn canonical_decimal_at_least(actual: &str, expected: &str) -> cats_metering::Result<bool> {
    for (name, value) in [("actual", actual), ("expected", expected)] {
        if value.is_empty()
            || value.len() > 78
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.len() > 1 && value.starts_with('0')
        {
            return Err(MeteringError::Store(format!(
                "{name} Usage sequence number is not canonical unsigned decimal"
            )));
        }
    }
    Ok(actual.len() > expected.len()
        || actual.len() == expected.len() && actual.as_bytes() >= expected.as_bytes())
}

async fn run_shard_workers<I, F, Fut>(shards: I, mut make_worker: F) -> Result<()>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future<Output = ()>,
{
    // These workers must stay owned by the singleton role future. Spawning
    // them would make parent cancellation only schedule child cancellation;
    // direct polling makes dropping the role synchronously drop every shard.
    let mut tasks = FuturesUnordered::new();
    for shard in shards {
        tasks.push(AssertUnwindSafe(make_worker(shard)).catch_unwind());
    }
    drop(make_worker);
    anyhow::ensure!(!tasks.is_empty(), "usage Kinesis stream has no shards");
    while let Some(task) = tasks.next().await {
        anyhow::ensure!(task.is_ok(), "usage shard projector task panicked");
    }
    Ok(())
}

async fn apply_projection(
    projection: &dyn UsageStore,
    records: &[PendingRecord],
    stream_name: &str,
    archive_bucket: &str,
    archive_key: &str,
    archive_sha256: &str,
) -> Result<()> {
    for record in records {
        let archive = cats_metering::UsageArchiveEvidence {
            stream_name: stream_name.to_string(),
            archive_bucket: archive_bucket.to_string(),
            shard_id: archive_shard_id(archive_key)?.to_string(),
            sequence_number: record.sequence_number.clone(),
            archive_key: archive_key.to_string(),
            archive_sha256: archive_sha256.to_string(),
        };
        match &record.record {
            UsageStreamRecord::Checkpoint(value) => projection
                .project_archived(&ArchivedUsageCheckpoint {
                    value: value.as_ref().clone(),
                    archive,
                })
                .await
                .map_err(anyhow::Error::new)
                .context("apply archived usage checkpoint projection")?,
            UsageStreamRecord::TerminalBarrier(marker) => projection
                .project_terminal_barrier(&ArchivedUsageTerminalBarrier {
                    marker: marker.clone(),
                    archive,
                })
                .await
                .map_err(anyhow::Error::new)
                .context("apply archived Usage terminal barrier projection")?,
        };
    }
    Ok(())
}

fn archive_shard_id(key: &str) -> Result<&str> {
    key.split('/')
        .find_map(|component| component.strip_prefix("shard="))
        .filter(|value| !value.is_empty())
        .context("usage archive key has no shard identity")
}

fn encode_archive_batch(shard_id: &str, records: &[PendingRecord]) -> Result<Option<ArchiveBatch>> {
    let Some(first) = records.first() else {
        return Ok(None);
    };
    let last = records.last().context("usage archive batch vanished")?;
    let mut payload = Vec::new();
    for record in records {
        serde_json::to_writer(&mut payload, &record.record)
            .context("encode usage stream record for archive batch")?;
        payload.push(b'\n');
    }
    let day = match &first.record {
        UsageStreamRecord::Checkpoint(value) => value.checkpoint.observed_at_unix_ms / 86_400_000,
        UsageStreamRecord::TerminalBarrier(_) => 0,
    };
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&payload)));
    Ok(Some(ArchiveBatch {
        key: format!(
            "raw/day={day}/shard={shard_id}/{}-{}.ndjson",
            first.sequence_number, last.sequence_number
        ),
        payload,
        sha256,
        last_sequence_number: last.sequence_number.clone(),
    }))
}

impl UsageStore for AwsUsageStreamStore {
    fn ingest<'a>(
        &'a self,
        value: &'a AttributedCheckpoint,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        Box::pin(async move {
            let terminal_gate = self.terminal_gate.read().await;
            if *terminal_gate {
                return Err(MeteringError::Conflict(
                    "old Usage target is closed for terminal projection".into(),
                ));
            }
            let payload =
                serde_json::to_vec(&UsageStreamRecord::Checkpoint(Box::new(value.clone())))?;
            if payload.len() > KINESIS_RECORD_LIMIT {
                return Err(cats_metering::MeteringError::Invalid(
                    "attributed checkpoint exceeds the Kinesis record limit".to_string(),
                ));
            }
            self.kinesis
                .put_record()
                .stream_name(&self.config.stream_name)
                .partition_key(&value.attribution.billing_account_id)
                .data(Blob::new(payload))
                .send()
                .await
                .map_err(|error| cats_metering::MeteringError::Store(error.to_string()))?;
            drop(terminal_gate);
            Ok(IngestOutcome::Accepted)
        })
    }

    fn query<'a>(&'a self, query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageView> {
        self.projection.query(query)
    }

    fn source_epoch_attribution<'a>(
        &'a self,
        source_id: &'a str,
        source_epoch: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageAttribution>> {
        self.projection
            .source_epoch_attribution(source_id, source_epoch)
    }

    fn project_archived<'a>(
        &'a self,
        value: &'a ArchivedUsageCheckpoint,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        self.projection.project_archived(value)
    }

    fn source_terminal_receipt<'a>(
        &'a self,
        source_id: &'a str,
        source_epoch: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageSourceTerminalReceipt>> {
        self.projection
            .source_terminal_receipt(source_id, source_epoch)
    }

    fn active_target_terminal<'a>(
        &'a self,
    ) -> UsageStoreFuture<'a, Option<cats_metering::UsageTargetTerminalState>> {
        self.projection.active_target_terminal()
    }

    fn begin_target_terminal<'a>(
        &'a self,
        request: &'a UsageTargetTerminalRequest,
    ) -> UsageStoreFuture<'a, UsageTerminalPrepareOutcome> {
        Box::pin(async move { self.begin_target_terminal_operation(request).await })
    }

    fn complete_target_terminal<'a>(
        &'a self,
        request: &'a UsageTargetTerminalRequest,
    ) -> UsageStoreFuture<'a, Option<UsageTargetTerminalReceipt>> {
        Box::pin(async move { self.complete_target_terminal_operation(request).await })
    }

    fn prepare_target_terminal<'a>(
        &'a self,
        request: &'a UsageTargetTerminalRequest,
    ) -> UsageStoreFuture<'a, UsageTerminalPrepareOutcome> {
        self.projection.prepare_target_terminal(request)
    }

    fn project_terminal_barrier<'a>(
        &'a self,
        barrier: &'a ArchivedUsageTerminalBarrier,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        self.projection.project_terminal_barrier(barrier)
    }

    fn target_terminal_state<'a>(
        &'a self,
        terminal_epoch_id: &'a str,
    ) -> UsageStoreFuture<'a, Option<cats_metering::UsageTargetTerminalState>> {
        self.projection.target_terminal_state(terminal_epoch_id)
    }

    fn commit_target_terminal<'a>(
        &'a self,
        receipt: &'a UsageTargetTerminalReceipt,
    ) -> UsageStoreFuture<'a, UsageTerminalPrepareOutcome> {
        self.projection.commit_target_terminal(receipt)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    use cats_metering::AttributedCheckpoint;

    use super::*;

    struct ActiveRoleGuard {
        active: Arc<AtomicUsize>,
    }

    impl ActiveRoleGuard {
        fn enter(active: Arc<AtomicUsize>, max_active: &AtomicUsize) -> Self {
            let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_active.fetch_max(now_active, Ordering::SeqCst);
            Self { active }
        }
    }

    impl Drop for ActiveRoleGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct BlockingChildGuard {
        _role: Arc<ActiveRoleGuard>,
        active_children: Arc<AtomicUsize>,
        drops_started: Arc<AtomicUsize>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Drop for BlockingChildGuard {
        fn drop(&mut self) {
            self.drops_started.fetch_add(1, Ordering::SeqCst);
            let (released, wake) = &*self.release;
            let mut released = released.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            self.active_children.fetch_sub(1, Ordering::SeqCst);
        }
    }

    async fn wait_for_at_least(value: &AtomicUsize, expected: usize, context: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while value.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {context}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn shard_workers_stop_before_standby_acquires_leadership() {
        let leadership = Arc::new(tokio::sync::Mutex::new(()));
        let active_roles = Arc::new(AtomicUsize::new(0));
        let max_active_roles = Arc::new(AtomicUsize::new(0));
        let role_starts = Arc::new(AtomicUsize::new(0));
        let active_children = Arc::new(AtomicUsize::new(0));
        let child_starts = Arc::new(AtomicUsize::new(0));
        let drops_started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let standby_started = Arc::new(tokio::sync::Notify::new());
        let active_children_at_standby = Arc::new(AtomicUsize::new(usize::MAX));

        let first = tokio::spawn({
            let leadership = leadership.clone();
            let active_roles = active_roles.clone();
            let max_active_roles = max_active_roles.clone();
            let role_starts = role_starts.clone();
            let active_children = active_children.clone();
            let child_starts = child_starts.clone();
            let drops_started = drops_started.clone();
            let release = release.clone();
            async move {
                let _session = leadership.lock().await;
                role_starts.fetch_add(1, Ordering::SeqCst);
                let role = Arc::new(ActiveRoleGuard::enter(active_roles, &max_active_roles));
                run_shard_workers(0..2, move |_| {
                    let role = role.clone();
                    let active_children = active_children.clone();
                    let child_starts = child_starts.clone();
                    let drops_started = drops_started.clone();
                    let release = release.clone();
                    async move {
                        active_children.fetch_add(1, Ordering::SeqCst);
                        let _child = BlockingChildGuard {
                            _role: role,
                            active_children,
                            drops_started,
                            release,
                        };
                        child_starts.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                    }
                })
                .await
                .unwrap();
            }
        });
        wait_for_at_least(&child_starts, 2, "both old shard workers to start").await;

        let second = tokio::spawn({
            let leadership = leadership.clone();
            let active_roles = active_roles.clone();
            let max_active_roles = max_active_roles.clone();
            let role_starts = role_starts.clone();
            let active_children = active_children.clone();
            let standby_started = standby_started.clone();
            let active_children_at_standby = active_children_at_standby.clone();
            async move {
                let _session = leadership.lock().await;
                active_children_at_standby
                    .store(active_children.load(Ordering::SeqCst), Ordering::SeqCst);
                role_starts.fetch_add(1, Ordering::SeqCst);
                let _role = ActiveRoleGuard::enter(active_roles, &max_active_roles);
                standby_started.notify_waiters();
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(role_starts.load(Ordering::SeqCst), 1);

        first.abort();
        wait_for_at_least(&drops_started, 1, "an old shard worker to begin dropping").await;
        let standby_notification = standby_started.notified();
        let standby_overlapped = role_starts.load(Ordering::SeqCst) > 1
            || tokio::time::timeout(Duration::from_millis(250), standby_notification)
                .await
                .is_ok();

        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
        let _ = first.await;
        wait_for_at_least(&role_starts, 2, "the standby role to start").await;

        let children_at_standby = active_children_at_standby.load(Ordering::SeqCst);
        let observed_max_active = max_active_roles.load(Ordering::SeqCst);
        second.abort();
        let _ = second.await;

        assert!(
            !standby_overlapped,
            "the standby acquired leadership while an old shard worker was still dropping"
        );
        assert_eq!(
            children_at_standby, 0,
            "every old shard worker must drop before the standby starts"
        );
        assert_eq!(
            observed_max_active, 1,
            "old and replacement projector roles must never overlap"
        );
    }

    fn pending(sequence_number: &str, observed_at_unix_ms: i64) -> PendingRecord {
        PendingRecord {
            sequence_number: sequence_number.to_string(),
            record: serde_json::from_value(serde_json::json!({
                "kind": "checkpoint",
                "value": {
                "checkpoint": {
                    "event_id": format!("event-{sequence_number}"),
                    "source_id": "node/metal-1/cat/cat-1",
                    "source_epoch": "epoch-1",
                    "sequence": sequence_number.parse::<u64>().unwrap(),
                    "observed_at_unix_ms": observed_at_unix_ms,
                    "cat_id": "cat-1",
                    "cat_generation": 1,
                    "metric": "cpu_usec",
                    "epoch_marker": "open",
                    "cumulative_quantity": sequence_number
                },
                "source_binding": {
                    "session": {
                        "node_id": "metal-1",
                        "node_boot_id": "11111111111111111111111111111111",
                        "agent_instance_id": "22222222222222222222222222222222",
                        "agent_session_epoch": 1
                    },
                    "desired_revision": 1,
                    "runtime_incarnation": "33333333333333333333333333333333"
                },
                "attribution": {
                    "billing_account_id": "billing_account/workspace_default",
                    "workspace_id": "default",
                    "resource_type": "cat",
                    "resource_id": "cat-1",
                    "attributed_cat_id": "cat-1"
                }
                }
            }))
            .unwrap(),
        }
    }

    #[test]
    fn config_requires_every_aws_resource_name() {
        let valid = AwsUsageStreamConfig {
            region: "us-east-1".to_string(),
            stream_name: "usage".to_string(),
            archive_bucket: "usage-archive".to_string(),
            checkpoint_table: "usage-checkpoints".to_string(),
        };
        valid.validate().unwrap();

        for invalid in [
            AwsUsageStreamConfig {
                region: String::new(),
                ..valid.clone()
            },
            AwsUsageStreamConfig {
                stream_name: String::new(),
                ..valid.clone()
            },
            AwsUsageStreamConfig {
                archive_bucket: String::new(),
                ..valid.clone()
            },
            AwsUsageStreamConfig {
                checkpoint_table: String::new(),
                ..valid
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn archive_batch_is_deterministic_newline_delimited_json() {
        let records = [pending("41", 86_400_000), pending("42", 86_400_010)];
        let batch = encode_archive_batch("shardId-000000000000", &records)
            .unwrap()
            .unwrap();

        assert_eq!(
            batch.key,
            "raw/day=1/shard=shardId-000000000000/41-42.ndjson"
        );
        assert_eq!(batch.last_sequence_number, "42");
        assert!(batch.payload.ends_with(b"\n"));
        let decoded = batch
            .payload
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<UsageStreamRecord>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            records
                .iter()
                .map(|record| record.record.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_archive_batch_is_a_noop() {
        assert!(encode_archive_batch("shard", &[]).unwrap().is_none());
    }

    #[tokio::test]
    async fn shard_reads_use_the_non_bursting_one_second_pacer() {
        let mut pacer = kinesis_read_pacer();
        assert_eq!(
            pacer.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Delay
        );

        // Tokio intervals make their first tick immediately available. The
        // second proves that every loop iteration pays the interval, without
        // depending on whether a Kinesis response carried records.
        let first = pacer.tick().await;
        let second = pacer.tick().await;
        assert_eq!(
            second.duration_since(first),
            KINESIS_READ_INTERVAL,
            "the pacer did not schedule consecutive Kinesis reads one second apart"
        );
    }

    struct RecordingProjection {
        attempted: Mutex<Vec<u64>>,
        permanent_failure: Option<u64>,
        store_failure: Option<u64>,
    }

    impl RecordingProjection {
        fn new(permanent_failure: Option<u64>, store_failure: Option<u64>) -> Self {
            Self {
                attempted: Mutex::new(Vec::new()),
                permanent_failure,
                store_failure,
            }
        }
    }

    impl UsageStore for RecordingProjection {
        fn ingest<'a>(
            &'a self,
            value: &'a AttributedCheckpoint,
        ) -> UsageStoreFuture<'a, IngestOutcome> {
            Box::pin(async move {
                let sequence = value.checkpoint.sequence;
                self.attempted.lock().unwrap().push(sequence);
                if self.permanent_failure == Some(sequence) {
                    return Err(MeteringError::Conflict(
                        "counter epoch reopened".to_string(),
                    ));
                }
                if self.store_failure == Some(sequence) {
                    return Err(MeteringError::Store("database unavailable".to_string()));
                }
                Ok(IngestOutcome::Accepted)
            })
        }

        fn query<'a>(&'a self, _query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageView> {
            Box::pin(async { unreachable!("projection tests do not query usage") })
        }

        fn source_epoch_attribution<'a>(
            &'a self,
            _source_id: &'a str,
            _source_epoch: &'a str,
        ) -> UsageStoreFuture<'a, Option<UsageAttribution>> {
            Box::pin(async { unreachable!("projection tests do not query attribution") })
        }

        fn project_archived<'a>(
            &'a self,
            value: &'a ArchivedUsageCheckpoint,
        ) -> UsageStoreFuture<'a, IngestOutcome> {
            self.ingest(&value.value)
        }

        fn source_terminal_receipt<'a>(
            &'a self,
            _source_id: &'a str,
            _source_epoch: &'a str,
        ) -> UsageStoreFuture<'a, Option<UsageSourceTerminalReceipt>> {
            Box::pin(async { Ok(None) })
        }
    }

    #[tokio::test]
    async fn permanent_checkpoint_failure_stops_the_shard_before_false_ack() {
        let projection = RecordingProjection::new(Some(2), None);
        let records = [
            pending("1", 86_400_000),
            pending("2", 86_400_010),
            pending("3", 86_400_020),
        ];
        apply_projection(
            &projection,
            &records,
            "usage-stream",
            "usage-archive",
            "raw/day=1/shard=shard-1/1-3.ndjson",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .unwrap_err();
        assert_eq!(*projection.attempted.lock().unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn store_failure_still_retries_without_advancing_the_checkpoint() {
        let projection = RecordingProjection::new(None, Some(2));
        let records = [
            pending("1", 86_400_000),
            pending("2", 86_400_010),
            pending("3", 86_400_020),
        ];
        let error = apply_projection(
            &projection,
            &records,
            "usage-stream",
            "usage-archive",
            "raw/day=1/shard=shard-1/1-3.ndjson",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("apply archived usage checkpoint projection"));
        assert_eq!(*projection.attempted.lock().unwrap(), vec![1, 2]);
    }
}

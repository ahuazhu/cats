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
    AttributedCheckpoint, IngestOutcome, MeteringError, UsageAttribution, UsageQuery, UsageStore,
    UsageStoreFuture, UsageView,
};
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};

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
    envelope: AttributedCheckpoint,
}

struct ArchiveBatch {
    key: String,
    payload: Vec<u8>,
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
}

impl AwsUsageStreamStore {
    pub async fn load(
        projection: Arc<dyn UsageStore>,
        config: AwsUsageStreamConfig,
    ) -> Result<Arc<Self>> {
        config.validate()?;
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
                let envelope: AttributedCheckpoint = serde_json::from_slice(record.data().as_ref())
                    .context("decode attributed usage checkpoint from Kinesis")?;
                if pending.is_empty() {
                    pending_since = Some(std::time::Instant::now());
                }
                pending_bytes = pending_bytes
                    .checked_add(record.data().as_ref().len())
                    .context("usage archive batch byte count overflow")?;
                pending.push(PendingRecord {
                    sequence_number: record.sequence_number().to_string(),
                    envelope,
                });
            }
            let archive_due = !pending.is_empty()
                && (pending.len() >= ARCHIVE_BATCH_MAX_RECORDS
                    || pending_bytes >= ARCHIVE_BATCH_MAX_BYTES
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
        apply_projection(self.projection.as_ref(), records).await?;
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

async fn apply_projection(projection: &dyn UsageStore, records: &[PendingRecord]) -> Result<()> {
    for record in records {
        match projection.ingest(&record.envelope).await {
            Ok(_) => {}
            Err(
                error @ (MeteringError::Invalid(_)
                | MeteringError::Conflict(_)
                | MeteringError::Overflow
                | MeteringError::Serialization(_)),
            ) => {
                let checkpoint = &record.envelope.checkpoint;
                tracing::error!(
                    event_id = %checkpoint.event_id,
                    source_id = %checkpoint.source_id,
                    source_epoch = %checkpoint.source_epoch,
                    sequence = checkpoint.sequence,
                    metric = checkpoint.metric.slug(),
                    %error,
                    "permanently invalid usage checkpoint remains in the immutable archive; skipping PostgreSQL projection"
                );
            }
            Err(error @ MeteringError::Store(_)) => {
                return Err(anyhow::anyhow!(error)).context("apply usage checkpoint projection");
            }
        }
    }
    Ok(())
}

fn encode_archive_batch(shard_id: &str, records: &[PendingRecord]) -> Result<Option<ArchiveBatch>> {
    let Some(first) = records.first() else {
        return Ok(None);
    };
    let last = records.last().context("usage archive batch vanished")?;
    let mut payload = Vec::new();
    for record in records {
        serde_json::to_writer(&mut payload, &record.envelope)
            .context("encode attributed usage checkpoint for archive batch")?;
        payload.push(b'\n');
    }
    let day = first.envelope.checkpoint.observed_at_unix_ms / 86_400_000;
    Ok(Some(ArchiveBatch {
        key: format!(
            "raw/day={day}/shard={shard_id}/{}-{}.ndjson",
            first.sequence_number, last.sequence_number
        ),
        payload,
        last_sequence_number: last.sequence_number.clone(),
    }))
}

impl UsageStore for AwsUsageStreamStore {
    fn ingest<'a>(
        &'a self,
        value: &'a AttributedCheckpoint,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        Box::pin(async move {
            let payload = serde_json::to_vec(value)?;
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
            envelope: serde_json::from_value(serde_json::json!({
                "checkpoint": {
                    "event_id": format!("event-{sequence_number}"),
                    "source_id": "node/metal-1/cat/cat-1",
                    "source_epoch": "epoch-1",
                    "sequence": sequence_number.parse::<u64>().unwrap(),
                    "observed_at_unix_ms": observed_at_unix_ms,
                    "cat_id": "cat-1",
                    "cat_generation": 1,
                    "metric": "cpu_usec",
                    "cumulative_quantity": sequence_number
                },
                "attribution": {
                    "billing_account_id": "billing_account/workspace_default",
                    "workspace_id": "default",
                    "resource_type": "cat",
                    "resource_id": "cat-1",
                    "attributed_cat_id": "cat-1"
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
            .map(|line| serde_json::from_slice::<AttributedCheckpoint>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            records
                .iter()
                .map(|record| record.envelope.clone())
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
    }

    #[tokio::test]
    async fn permanent_checkpoint_failure_does_not_block_the_shard() {
        let projection = RecordingProjection::new(Some(2), None);
        let records = [
            pending("1", 86_400_000),
            pending("2", 86_400_010),
            pending("3", 86_400_020),
        ];
        apply_projection(&projection, &records).await.unwrap();
        assert_eq!(*projection.attempted.lock().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn store_failure_still_retries_without_advancing_the_checkpoint() {
        let projection = RecordingProjection::new(None, Some(2));
        let records = [
            pending("1", 86_400_000),
            pending("2", 86_400_010),
            pending("3", 86_400_020),
        ];
        let error = apply_projection(&projection, &records).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("apply usage checkpoint projection"));
        assert_eq!(*projection.attempted.lock().unwrap(), vec![1, 2]);
    }
}

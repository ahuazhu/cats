//! Provider-neutral cumulative metering, immutable raw checkpoints,
//! rebuildable usage intervals and exact integer rating.
//!
//! The SQLite implementation is the development adapter. Production keeps the
//! same event/rating contract while using a durable event stream, raw archive
//! and PostgreSQL ledger.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;

use cats_api::metering::{CatUsageCheckpoint, UsageMetric};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

const GIB: u128 = 1_073_741_824;
const MILLIS_PER_HOUR: u128 = 3_600_000;
const USEC_PER_HOUR: u128 = 3_600_000_000;

#[derive(Debug, thiserror::Error)]
pub enum MeteringError {
    #[error("invalid usage checkpoint: {0}")]
    Invalid(String),
    #[error("usage stream conflict: {0}")]
    Conflict(String),
    #[error("usage arithmetic overflow")]
    Overflow,
    #[error("metering store error: {0}")]
    Store(String),
    #[error("usage serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, MeteringError>;

impl From<rusqlite::Error> for MeteringError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageAttribution {
    pub billing_account_id: String,
    pub workspace_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub attributed_cat_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttributedCheckpoint {
    pub checkpoint: CatUsageCheckpoint,
    pub attribution: UsageAttribution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Accepted,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageInterval {
    pub interval_start_unix_ms: i64,
    pub interval_end_unix_ms: i64,
    pub attribution: UsageAttribution,
    pub metric: UsageMetric,
    pub quantity: u128,
    pub source_id: String,
    pub source_epoch: String,
    pub end_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageAggregate {
    pub metric: UsageMetric,
    pub quantity: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatAggregate {
    pub cat_id: String,
    pub items: Vec<UsageAggregate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageQuery {
    pub billing_account_id: String,
    pub workspace_id: Option<String>,
    pub attributed_cat_id: Option<String>,
    pub interval_start_unix_ms: i64,
    pub interval_end_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageView {
    pub totals: Vec<UsageAggregate>,
    pub cats: Vec<CatAggregate>,
    pub details: Vec<UsageInterval>,
    pub latest_interval_end_unix_ms: Option<i64>,
}

/// Per-metric totals for a query window, without the per-interval detail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageTotals {
    pub totals: Vec<UsageAggregate>,
    pub latest_interval_end_unix_ms: Option<i64>,
}

pub type UsageStoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Durable usage-ledger port used by the control plane.
///
/// Implementations must provide idempotent checkpoint ingestion and the same
/// cumulative-counter/query semantics. The boxed futures keep the port object
/// safe without forcing any particular async runtime or database client on
/// core metering types.
pub trait UsageStore: Send + Sync {
    fn ingest<'a>(&'a self, value: &'a AttributedCheckpoint)
        -> UsageStoreFuture<'a, IngestOutcome>;

    fn query<'a>(&'a self, query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageView>;

    /// Totals for the window, without materialising per-interval detail.
    ///
    /// Admission (`require_funded`) needs one fact -- whether the Account has
    /// anything left -- and answering it through [`UsageStore::query`] fetches,
    /// sorts and folds every interval the Account has ever accrued: the
    /// admission window is unbounded below, so the cost grows with the whole
    /// history. That sat on every paid operation and put a no-op `exec` at ~35 s
    /// while the node agent answered the identical call in 2 ms.
    ///
    /// Implementations should push the aggregation into the store. The default
    /// keeps an adapter correct until it does, so this can never be silently
    /// wrong -- only slow.
    fn query_totals<'a>(&'a self, query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageTotals> {
        Box::pin(async move {
            let view = self.query(query).await?;
            Ok(UsageTotals {
                totals: view.totals,
                latest_interval_end_unix_ms: view.latest_interval_end_unix_ms,
            })
        })
    }

    /// Return the immutable attribution already established for a producer
    /// epoch. This lets a durable node outbox replay the tail of a deleted
    /// resource without trusting the node to supply billing ownership.
    fn source_epoch_attribution<'a>(
        &'a self,
        source_id: &'a str,
        source_epoch: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageAttribution>>;
}

/// One billing account's append-only credit projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSummary {
    pub billing_account_id: String,
    /// Cats Account that owns this Billing Account. Workspaces never own funds.
    pub account_id: String,
    pub currency: String,
    /// Signed USD nanodollars. Credits are positive; reversals are negative.
    pub credit_nanos: i128,
    pub stripe_customer_id: Option<String>,
}

/// Durable intent created before contacting a payment provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutIntent {
    pub intent_id: String,
    pub billing_account_id: String,
    pub account_id: String,
    pub amount_cents: i64,
    pub currency: String,
    pub created_at_unix_ms: i64,
    pub stripe_session_id: Option<String>,
    pub checkout_url: Option<String>,
}

/// Verified Stripe Checkout result. The store revalidates it against the
/// persisted intent and commits the event receipt and credit atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutPayment {
    pub event_id: String,
    pub payload_sha256: String,
    pub intent_id: String,
    pub billing_account_id: String,
    pub stripe_session_id: String,
    pub stripe_payment_intent_id: String,
    pub stripe_customer_id: Option<String>,
    pub amount_cents: i64,
    pub currency: String,
    pub livemode: bool,
    pub processed_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutRefund {
    pub event_id: String,
    pub payload_sha256: String,
    pub stripe_refund_id: String,
    pub stripe_payment_intent_id: String,
    pub amount_cents: i64,
    pub currency: String,
    pub livemode: bool,
    pub processed_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditApplyOutcome {
    Accepted,
    Duplicate,
}

pub type CreditStoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Provider-neutral prepaid-funds ledger.
///
/// Implementations must make the signup grant idempotent, keep credit entries
/// insert-only, and atomically deduplicate verified provider events.
pub trait CreditStore: Send + Sync {
    fn ensure_account<'a>(
        &'a self,
        billing_account_id: &'a str,
        account_id: &'a str,
        currency: &'a str,
        signup_credit_nanos: i128,
        created_at_unix_ms: i64,
    ) -> CreditStoreFuture<'a, CreditSummary>;

    fn summary<'a>(&'a self, billing_account_id: &'a str) -> CreditStoreFuture<'a, CreditSummary>;

    fn create_checkout_intent<'a>(
        &'a self,
        intent: &'a CheckoutIntent,
    ) -> CreditStoreFuture<'a, CheckoutIntent>;

    fn attach_checkout_session<'a>(
        &'a self,
        intent_id: &'a str,
        stripe_session_id: &'a str,
        checkout_url: &'a str,
    ) -> CreditStoreFuture<'a, CheckoutIntent>;

    fn apply_checkout_payment<'a>(
        &'a self,
        payment: &'a CheckoutPayment,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome>;

    fn apply_checkout_refund<'a>(
        &'a self,
        refund: &'a CheckoutRefund,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterRate {
    pub metric: UsageMetric,
    /// Price numerator in USD nanodollars.
    pub numerator_nanos: u128,
    /// Number of canonical quantity units covered by the numerator.
    pub denominator_quantity: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCard {
    pub id: String,
    pub currency: String,
    pub rates: Vec<MeterRate>,
}

impl RateCard {
    /// Accepted compute price: $0.07/CPU-hour and $0.045/GiB-hour.
    ///
    /// "GiB" is explicit in the denominator even if product copy abbreviates
    /// it to GB; changing the byte convention requires a new rate-card id.
    pub fn sprites_compute_v1() -> Self {
        Self {
            id: "cats-compute-2026-07-25".to_string(),
            currency: "USD".to_string(),
            rates: vec![
                MeterRate {
                    metric: UsageMetric::CpuUsec,
                    numerator_nanos: 70_000_000,
                    denominator_quantity: USEC_PER_HOUR,
                },
                MeterRate {
                    metric: UsageMetric::MemoryByteMillis,
                    numerator_nanos: 45_000_000,
                    denominator_quantity: GIB * MILLIS_PER_HOUR,
                },
            ],
        }
    }

    pub fn rate(&self, metric: UsageMetric) -> Option<&MeterRate> {
        self.rates.iter().find(|rate| rate.metric == metric)
    }

    /// Rate an already-aggregated quantity, rounding half up exactly once.
    pub fn rate_quantity(&self, metric: UsageMetric, quantity: u128) -> Result<Option<u128>> {
        let Some(rate) = self.rate(metric) else {
            return Ok(None);
        };
        let scaled = quantity
            .checked_mul(rate.numerator_nanos)
            .ok_or(MeteringError::Overflow)?;
        let half = rate.denominator_quantity / 2;
        Ok(Some(
            scaled.checked_add(half).ok_or(MeteringError::Overflow)? / rate.denominator_quantity,
        ))
    }
}

pub fn deterministic_event_id(checkpoint: &CatUsageCheckpoint) -> String {
    let mut hasher = Sha256::new();
    for value in [
        checkpoint.source_id.as_str(),
        checkpoint.source_epoch.as_str(),
        checkpoint.metric.slug(),
        &checkpoint.sequence.to_string(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("usage_{}", hex::encode(hasher.finalize()))
}

/// Node-side exact integer accumulator for one Cat runtime cgroup.
///
/// Call `observe` at the high-frequency sampling cadence and `checkpoint` at
/// the lower transport cadence. Memory uses a left-continuous step integral:
/// the previous `memory.current` sample applies until the current timestamp.
#[derive(Debug, Clone)]
pub struct RuntimeMeterAccumulator {
    source_id: String,
    source_epoch: String,
    cat_id: String,
    cat_generation: i64,
    sequence: u64,
    last_observed_at_ms: Option<i64>,
    last_cpu_usage_usec: Option<u64>,
    last_memory_current_bytes: Option<u64>,
    memory_byte_millis: u128,
}

impl RuntimeMeterAccumulator {
    pub fn new(
        source_id: String,
        source_epoch: String,
        cat_id: String,
        cat_generation: i64,
    ) -> Result<Self> {
        if source_id.is_empty() || source_epoch.is_empty() || cat_id.is_empty() {
            return Err(MeteringError::Invalid(
                "meter source, epoch and Cat id must be non-empty".to_string(),
            ));
        }
        if cat_generation < 0 {
            return Err(MeteringError::Invalid(
                "Cat generation must be non-negative".to_string(),
            ));
        }
        Ok(Self {
            source_id,
            source_epoch,
            cat_id,
            cat_generation,
            sequence: 0,
            last_observed_at_ms: None,
            last_cpu_usage_usec: None,
            last_memory_current_bytes: None,
            memory_byte_millis: 0,
        })
    }

    pub fn observe(
        &mut self,
        observed_at_unix_ms: i64,
        cpu_usage_usec: u64,
        memory_current_bytes: u64,
    ) -> Result<()> {
        if observed_at_unix_ms < 0 {
            return Err(MeteringError::Invalid(
                "sample timestamp must be non-negative".to_string(),
            ));
        }
        if let Some(previous_time) = self.last_observed_at_ms {
            if observed_at_unix_ms <= previous_time {
                return Err(MeteringError::Conflict(
                    "sample timestamp did not increase".to_string(),
                ));
            }
            if cpu_usage_usec < self.last_cpu_usage_usec.unwrap_or(0) {
                return Err(MeteringError::Conflict(
                    "cgroup CPU counter reset; start a new source epoch".to_string(),
                ));
            }
            let elapsed = u64::try_from(observed_at_unix_ms - previous_time)
                .map_err(|_| MeteringError::Overflow)?;
            let memory_delta = u128::from(self.last_memory_current_bytes.unwrap_or(0));
            let memory_delta = memory_delta
                .checked_mul(u128::from(elapsed))
                .ok_or(MeteringError::Overflow)?;
            self.memory_byte_millis = self
                .memory_byte_millis
                .checked_add(memory_delta)
                .ok_or(MeteringError::Overflow)?;
        }
        self.last_observed_at_ms = Some(observed_at_unix_ms);
        self.last_cpu_usage_usec = Some(cpu_usage_usec);
        self.last_memory_current_bytes = Some(memory_current_bytes);
        Ok(())
    }

    pub fn last_observed_at_unix_ms(&self) -> Option<i64> {
        self.last_observed_at_ms
    }

    /// Emit CPU and memory checkpoints at the most recent observation.
    pub fn checkpoint(&mut self) -> Result<[CatUsageCheckpoint; 2]> {
        let observed_at_unix_ms = self.last_observed_at_ms.ok_or_else(|| {
            MeteringError::Invalid("cannot checkpoint before the first observation".to_string())
        })?;
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(MeteringError::Overflow)?;
        let make = |metric, cumulative_quantity| {
            let mut checkpoint = CatUsageCheckpoint {
                event_id: String::new(),
                source_id: self.source_id.clone(),
                source_epoch: self.source_epoch.clone(),
                sequence,
                observed_at_unix_ms,
                cat_id: self.cat_id.clone(),
                cat_generation: self.cat_generation,
                metric,
                cumulative_quantity,
            };
            checkpoint.event_id = deterministic_event_id(&checkpoint);
            checkpoint
        };
        Ok([
            make(
                UsageMetric::CpuUsec,
                u128::from(self.last_cpu_usage_usec.unwrap_or(0)),
            ),
            make(UsageMetric::MemoryByteMillis, self.memory_byte_millis),
        ])
    }
}

/// SQLite development adapter.
///
/// Production callers should inject a production `UsageStore` implementation;
/// this type remains useful for local development and deterministic contract
/// tests.
pub struct SqliteUsageStore {
    conn: Mutex<Connection>,
}

impl SqliteUsageStore {
    pub fn open(path: &Path) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(SCHEMA)?;
        migrate_sqlite_u128(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn ingest(&self, value: &AttributedCheckpoint) -> Result<IngestOutcome> {
        validate_checkpoint(value)?;
        let payload = serde_json::to_string(&value.checkpoint)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        if let Some(existing) = tx
            .query_row(
                "SELECT payload_json, billing_account_id, workspace_id,
                        resource_type, resource_id, attributed_cat_id
                   FROM usage_checkpoints WHERE event_id=?1",
                params![value.checkpoint.event_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        UsageAttribution {
                            billing_account_id: row.get(1)?,
                            workspace_id: row.get(2)?,
                            resource_type: row.get(3)?,
                            resource_id: row.get(4)?,
                            attributed_cat_id: row.get(5)?,
                        },
                    ))
                },
            )
            .optional()?
        {
            if existing.0 == payload && existing.1 == value.attribution {
                tx.commit()?;
                return Ok(IngestOutcome::Duplicate);
            }
            return Err(MeteringError::Conflict(format!(
                "event {} was replayed with a different payload",
                value.checkpoint.event_id
            )));
        }

        if let Some(existing_attribution) = tx
            .query_row(
                "SELECT billing_account_id, workspace_id, resource_type,
                        resource_id, attributed_cat_id
                   FROM usage_checkpoints
                  WHERE source_id=?1 AND source_epoch=?2
                  LIMIT 1",
                params![value.checkpoint.source_id, value.checkpoint.source_epoch],
                |row| {
                    Ok(UsageAttribution {
                        billing_account_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        resource_type: row.get(2)?,
                        resource_id: row.get(3)?,
                        attributed_cat_id: row.get(4)?,
                    })
                },
            )
            .optional()?
        {
            if existing_attribution != value.attribution {
                return Err(MeteringError::Conflict(
                    "attribution changed inside one source epoch".to_string(),
                ));
            }
        }
        let previous = adjacent_checkpoint(&tx, value, Adjacent::Previous)?;
        let next = adjacent_checkpoint(&tx, value, Adjacent::Next)?;
        validate_adjacent(value, previous.as_ref(), next.as_ref())?;

        let quantity = value.checkpoint.cumulative_quantity.to_string();
        let sequence = to_i64(value.checkpoint.sequence, "sequence")?;
        tx.execute(
            "INSERT INTO usage_checkpoints (
                event_id, source_id, source_epoch, sequence, observed_at_ms,
                metric, cumulative_quantity, billing_account_id, workspace_id,
                resource_type, resource_id, attributed_cat_id, payload_json
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                value.checkpoint.event_id,
                value.checkpoint.source_id,
                value.checkpoint.source_epoch,
                sequence,
                value.checkpoint.observed_at_unix_ms,
                value.checkpoint.metric.slug(),
                quantity,
                value.attribution.billing_account_id,
                value.attribution.workspace_id,
                value.attribution.resource_type,
                value.attribution.resource_id,
                value.attribution.attributed_cat_id,
                payload,
            ],
        )?;

        if let (Some(previous), Some(next)) = (&previous, &next) {
            tx.execute(
                "DELETE FROM usage_intervals
                  WHERE start_event_id=?1 AND end_event_id=?2",
                params![previous.event_id, next.event_id],
            )?;
        }
        if let Some(previous) = previous {
            insert_interval(&tx, &previous, &StoredCheckpoint::from_value(value)?)?;
        }
        if let Some(next) = next {
            insert_interval(&tx, &StoredCheckpoint::from_value(value)?, &next)?;
        }
        tx.commit()?;
        Ok(IngestOutcome::Accepted)
    }

    pub fn query(&self, query: &UsageQuery) -> Result<UsageView> {
        validate_usage_query(query)?;
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT interval_start_ms, interval_end_ms, quantity,
                    billing_account_id, workspace_id, resource_type, resource_id,
                    attributed_cat_id, metric, source_id, source_epoch, end_sequence
               FROM usage_intervals
              WHERE billing_account_id=?1
                AND interval_end_ms>?2 AND interval_start_ms<?3
              ORDER BY interval_start_ms, source_id, source_epoch, end_sequence, metric",
        )?;
        let rows = statement.query_map(
            params![
                query.billing_account_id,
                query.interval_start_unix_ms,
                query.interval_end_unix_ms
            ],
            row_to_interval,
        )?;

        let mut intervals = Vec::new();
        for row in rows {
            let interval = row?;
            if query
                .workspace_id
                .as_ref()
                .is_some_and(|workspace| workspace != &interval.attribution.workspace_id)
                || query
                    .attributed_cat_id
                    .as_ref()
                    .is_some_and(|cat| interval.attribution.attributed_cat_id.as_ref() != Some(cat))
            {
                continue;
            }
            intervals.push(interval);
        }

        usage_view_from_intervals(query, intervals)
    }

    pub fn source_epoch_attribution(
        &self,
        source_id: &str,
        source_epoch: &str,
    ) -> Result<Option<UsageAttribution>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT billing_account_id, workspace_id, resource_type,
                    resource_id, attributed_cat_id
               FROM usage_checkpoints
              WHERE source_id=?1 AND source_epoch=?2
              LIMIT 1",
            params![source_id, source_epoch],
            |row| {
                Ok(UsageAttribution {
                    billing_account_id: row.get(0)?,
                    workspace_id: row.get(1)?,
                    resource_type: row.get(2)?,
                    resource_id: row.get(3)?,
                    attributed_cat_id: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }
}

impl UsageStore for SqliteUsageStore {
    fn ingest<'a>(
        &'a self,
        value: &'a AttributedCheckpoint,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        Box::pin(async move { SqliteUsageStore::ingest(self, value) })
    }

    fn query<'a>(&'a self, query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageView> {
        Box::pin(async move { SqliteUsageStore::query(self, query) })
    }

    fn source_epoch_attribution<'a>(
        &'a self,
        source_id: &'a str,
        source_epoch: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageAttribution>> {
        Box::pin(async move {
            SqliteUsageStore::source_epoch_attribution(self, source_id, source_epoch)
        })
    }
}

impl CreditStore for SqliteUsageStore {
    fn ensure_account<'a>(
        &'a self,
        billing_account_id: &'a str,
        account_id: &'a str,
        currency: &'a str,
        signup_credit_nanos: i128,
        created_at_unix_ms: i64,
    ) -> CreditStoreFuture<'a, CreditSummary> {
        Box::pin(async move {
            validate_credit_account(
                billing_account_id,
                account_id,
                currency,
                signup_credit_nanos,
                created_at_unix_ms,
            )?;
            let mut conn = self.conn.lock().unwrap();
            let transaction = conn.transaction()?;
            transaction.execute(
                "INSERT OR IGNORE INTO billing_accounts (
                    billing_account_id, account_id, currency, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![billing_account_id, account_id, currency, created_at_unix_ms],
            )?;
            let summary = sqlite_credit_summary(&transaction, billing_account_id)?;
            if summary.account_id != account_id || summary.currency != currency {
                return Err(MeteringError::Conflict(format!(
                    "billing account {billing_account_id} identity changed"
                )));
            }
            if signup_credit_nanos > 0 {
                transaction.execute(
                    "INSERT OR IGNORE INTO credit_ledger_entries (
                        entry_id, billing_account_id, kind, amount_nanos, currency,
                        external_reference, effective_at_ms
                     ) VALUES (?1, ?2, 'signup_grant', ?3, ?4, ?5, ?6)",
                    params![
                        format!("signup-grant/{billing_account_id}"),
                        billing_account_id,
                        signup_credit_nanos.to_string(),
                        currency,
                        format!("signup-grant/{billing_account_id}"),
                        created_at_unix_ms,
                    ],
                )?;
            }
            let summary = sqlite_credit_summary(&transaction, billing_account_id)?;
            transaction.commit()?;
            Ok(summary)
        })
    }

    fn summary<'a>(&'a self, billing_account_id: &'a str) -> CreditStoreFuture<'a, CreditSummary> {
        Box::pin(async move {
            let conn = self.conn.lock().unwrap();
            sqlite_credit_summary(&conn, billing_account_id)
        })
    }

    fn create_checkout_intent<'a>(
        &'a self,
        intent: &'a CheckoutIntent,
    ) -> CreditStoreFuture<'a, CheckoutIntent> {
        let intent = intent.clone();
        Box::pin(async move {
            validate_checkout_intent(&intent)?;
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO checkout_intents (
                    intent_id, billing_account_id, account_id, amount_cents,
                    currency, created_at_ms, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
                params![
                    intent.intent_id,
                    intent.billing_account_id,
                    intent.account_id,
                    intent.amount_cents,
                    intent.currency,
                    intent.created_at_unix_ms,
                ],
            )?;
            let stored = sqlite_checkout_intent(&conn, &intent.intent_id)?;
            if stored.billing_account_id != intent.billing_account_id
                || stored.account_id != intent.account_id
                || stored.amount_cents != intent.amount_cents
                || stored.currency != intent.currency
            {
                return Err(MeteringError::Conflict(format!(
                    "checkout intent {} was replayed with different values",
                    intent.intent_id
                )));
            }
            Ok(stored)
        })
    }

    fn attach_checkout_session<'a>(
        &'a self,
        intent_id: &'a str,
        stripe_session_id: &'a str,
        checkout_url: &'a str,
    ) -> CreditStoreFuture<'a, CheckoutIntent> {
        Box::pin(async move {
            if intent_id.is_empty() || stripe_session_id.is_empty() || checkout_url.is_empty() {
                return Err(MeteringError::Invalid(
                    "checkout intent, session and URL must not be empty".to_string(),
                ));
            }
            let conn = self.conn.lock().unwrap();
            let stored = sqlite_checkout_intent(&conn, intent_id)?;
            if stored
                .stripe_session_id
                .as_deref()
                .is_some_and(|value| value != stripe_session_id)
                || stored
                    .checkout_url
                    .as_deref()
                    .is_some_and(|value| value != checkout_url)
            {
                return Err(MeteringError::Conflict(format!(
                    "checkout intent {intent_id} is already attached to another session"
                )));
            }
            conn.execute(
                "UPDATE checkout_intents
                    SET stripe_session_id=?2, checkout_url=?3
                  WHERE intent_id=?1",
                params![intent_id, stripe_session_id, checkout_url],
            )?;
            sqlite_checkout_intent(&conn, intent_id)
        })
    }

    fn apply_checkout_payment<'a>(
        &'a self,
        payment: &'a CheckoutPayment,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome> {
        let payment = payment.clone();
        Box::pin(async move {
            validate_checkout_payment(&payment)?;
            let mut conn = self.conn.lock().unwrap();
            let transaction = conn.transaction()?;
            if let Some(existing_fingerprint) = transaction
                .query_row(
                    "SELECT payload_sha256 FROM stripe_events WHERE event_id=?1",
                    params![payment.event_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                if existing_fingerprint != payment.payload_sha256 {
                    return Err(MeteringError::Conflict(format!(
                        "Stripe event {} was replayed with another payload",
                        payment.event_id
                    )));
                }
                transaction.commit()?;
                return Ok(CreditApplyOutcome::Duplicate);
            }
            let intent = sqlite_checkout_intent(&transaction, &payment.intent_id)?;
            validate_payment_against_intent(&payment, &intent)?;
            if intent
                .stripe_session_id
                .as_deref()
                .is_some_and(|value| value != payment.stripe_session_id)
            {
                return Err(MeteringError::Conflict(
                    "Stripe session does not match checkout intent".to_string(),
                ));
            }
            transaction.execute(
                "INSERT INTO stripe_events (
                    event_id, event_type, payload_sha256, livemode,
                    processed_at_ms
                 ) VALUES (?1, 'checkout.session.paid', ?2, ?3, ?4)",
                params![
                    payment.event_id,
                    payment.payload_sha256,
                    payment.livemode,
                    payment.processed_at_unix_ms,
                ],
            )?;
            let amount_nanos = cents_to_nanos(payment.amount_cents)?;
            transaction.execute(
                "INSERT OR IGNORE INTO credit_ledger_entries (
                    entry_id, billing_account_id, kind, amount_nanos, currency,
                    external_reference, effective_at_ms
                 ) VALUES (?1, ?2, 'stripe_topup', ?3, ?4, ?5, ?6)",
                params![
                    format!("stripe-topup/{}", payment.stripe_session_id),
                    payment.billing_account_id,
                    amount_nanos.to_string(),
                    payment.currency,
                    format!("stripe-payment/{}", payment.stripe_payment_intent_id),
                    payment.processed_at_unix_ms,
                ],
            )?;
            transaction.execute(
                "UPDATE checkout_intents
                    SET stripe_session_id=?2, stripe_payment_intent_id=?3,
                        status='paid'
                  WHERE intent_id=?1",
                params![
                    payment.intent_id,
                    payment.stripe_session_id,
                    payment.stripe_payment_intent_id,
                ],
            )?;
            if let Some(customer_id) = &payment.stripe_customer_id {
                transaction.execute(
                    "UPDATE billing_accounts
                        SET stripe_customer_id=COALESCE(stripe_customer_id, ?2)
                      WHERE billing_account_id=?1",
                    params![payment.billing_account_id, customer_id],
                )?;
            }
            transaction.commit()?;
            Ok(CreditApplyOutcome::Accepted)
        })
    }

    fn apply_checkout_refund<'a>(
        &'a self,
        refund: &'a CheckoutRefund,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome> {
        let refund = refund.clone();
        Box::pin(async move {
            validate_checkout_refund(&refund)?;
            let mut conn = self.conn.lock().unwrap();
            let transaction = conn.transaction()?;
            if let Some(existing_fingerprint) = transaction
                .query_row(
                    "SELECT payload_sha256 FROM stripe_events WHERE event_id=?1",
                    params![refund.event_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                if existing_fingerprint != refund.payload_sha256 {
                    return Err(MeteringError::Conflict(format!(
                        "Stripe event {} was replayed with another payload",
                        refund.event_id
                    )));
                }
                transaction.commit()?;
                return Ok(CreditApplyOutcome::Duplicate);
            }
            let (billing_account_id, original_cents, currency) = transaction
                .query_row(
                    "SELECT billing_account_id, amount_cents, currency
                       FROM checkout_intents
                      WHERE stripe_payment_intent_id=?1 AND status='paid'",
                    params![refund.stripe_payment_intent_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    MeteringError::Conflict("refund arrived before its paid checkout".to_string())
                })?;
            if refund.amount_cents > original_cents || refund.currency != currency {
                return Err(MeteringError::Conflict(
                    "Stripe refund does not match paid checkout".to_string(),
                ));
            }
            transaction.execute(
                "INSERT INTO stripe_events (
                    event_id, event_type, payload_sha256, livemode,
                    processed_at_ms
                 ) VALUES (?1, 'refund.succeeded', ?2, ?3, ?4)",
                params![
                    refund.event_id,
                    refund.payload_sha256,
                    refund.livemode,
                    refund.processed_at_unix_ms,
                ],
            )?;
            let amount_nanos = cents_to_nanos(refund.amount_cents)?
                .checked_neg()
                .ok_or(MeteringError::Overflow)?;
            transaction.execute(
                "INSERT OR IGNORE INTO credit_ledger_entries (
                    entry_id, billing_account_id, kind, amount_nanos, currency,
                    external_reference, effective_at_ms
                 ) VALUES (?1, ?2, 'stripe_refund', ?3, ?4, ?5, ?6)",
                params![
                    format!("stripe-refund/{}", refund.stripe_refund_id),
                    billing_account_id,
                    amount_nanos.to_string(),
                    refund.currency,
                    format!("stripe-refund/{}", refund.stripe_refund_id),
                    refund.processed_at_unix_ms,
                ],
            )?;
            transaction.commit()?;
            Ok(CreditApplyOutcome::Accepted)
        })
    }
}

fn validate_credit_account(
    billing_account_id: &str,
    account_id: &str,
    currency: &str,
    signup_credit_nanos: i128,
    created_at_unix_ms: i64,
) -> Result<()> {
    if billing_account_id.is_empty() || account_id.is_empty() {
        return Err(MeteringError::Invalid(
            "billing account and account must not be empty".to_string(),
        ));
    }
    if currency != "USD" {
        return Err(MeteringError::Invalid(
            "only USD credit accounts are supported".to_string(),
        ));
    }
    if signup_credit_nanos < 0 || created_at_unix_ms < 0 {
        return Err(MeteringError::Invalid(
            "signup credit and timestamp must be non-negative".to_string(),
        ));
    }
    Ok(())
}

/// Validate a checkout intent before an adapter starts a transaction.
pub fn validate_checkout_intent(intent: &CheckoutIntent) -> Result<()> {
    if intent.intent_id.is_empty()
        || intent.billing_account_id.is_empty()
        || intent.account_id.is_empty()
        || intent.amount_cents <= 0
        || intent.currency != "USD"
        || intent.created_at_unix_ms < 0
    {
        return Err(MeteringError::Invalid(
            "invalid checkout intent".to_string(),
        ));
    }
    Ok(())
}

/// Validate a Stripe payment event before an adapter starts a transaction.
pub fn validate_checkout_payment(payment: &CheckoutPayment) -> Result<()> {
    if payment.event_id.is_empty()
        || payment.payload_sha256.len() != 64
        || payment.intent_id.is_empty()
        || payment.billing_account_id.is_empty()
        || payment.stripe_session_id.is_empty()
        || payment.stripe_payment_intent_id.is_empty()
        || payment.amount_cents <= 0
        || payment.currency != "USD"
        || payment.processed_at_unix_ms < 0
    {
        return Err(MeteringError::Invalid(
            "invalid Stripe checkout payment".to_string(),
        ));
    }
    Ok(())
}

/// Validate a Stripe refund event before an adapter starts a transaction.
pub fn validate_checkout_refund(refund: &CheckoutRefund) -> Result<()> {
    if refund.event_id.is_empty()
        || refund.payload_sha256.len() != 64
        || refund.stripe_refund_id.is_empty()
        || refund.stripe_payment_intent_id.is_empty()
        || refund.amount_cents <= 0
        || refund.currency != "USD"
        || refund.processed_at_unix_ms < 0
    {
        return Err(MeteringError::Invalid(
            "invalid Stripe checkout refund".to_string(),
        ));
    }
    Ok(())
}

fn validate_payment_against_intent(
    payment: &CheckoutPayment,
    intent: &CheckoutIntent,
) -> Result<()> {
    if payment.billing_account_id != intent.billing_account_id
        || payment.amount_cents != intent.amount_cents
        || payment.currency != intent.currency
    {
        return Err(MeteringError::Conflict(
            "Stripe payment does not match checkout intent".to_string(),
        ));
    }
    Ok(())
}

fn cents_to_nanos(amount_cents: i64) -> Result<i128> {
    i128::from(amount_cents)
        .checked_mul(10_000_000)
        .ok_or(MeteringError::Overflow)
}

fn sqlite_credit_summary(conn: &Connection, billing_account_id: &str) -> Result<CreditSummary> {
    let (account_id, currency, stripe_customer_id) = conn
        .query_row(
            "SELECT account_id, currency, stripe_customer_id
               FROM billing_accounts WHERE billing_account_id=?1",
            params![billing_account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| MeteringError::Invalid("billing account does not exist".to_string()))?;
    let mut statement = conn.prepare(
        "SELECT amount_nanos FROM credit_ledger_entries
          WHERE billing_account_id=?1 ORDER BY entry_id",
    )?;
    let rows = statement.query_map(params![billing_account_id], |row| row.get::<_, String>(0))?;
    let mut credit_nanos = 0_i128;
    for row in rows {
        credit_nanos = credit_nanos
            .checked_add(
                row?.parse::<i128>()
                    .map_err(|_| MeteringError::Store("invalid credit amount".to_string()))?,
            )
            .ok_or(MeteringError::Overflow)?;
    }
    Ok(CreditSummary {
        billing_account_id: billing_account_id.to_string(),
        account_id,
        currency,
        credit_nanos,
        stripe_customer_id,
    })
}

fn sqlite_checkout_intent(conn: &Connection, intent_id: &str) -> Result<CheckoutIntent> {
    conn.query_row(
        "SELECT intent_id, billing_account_id, account_id, amount_cents,
                currency, created_at_ms, stripe_session_id, checkout_url
           FROM checkout_intents WHERE intent_id=?1",
        params![intent_id],
        |row| {
            Ok(CheckoutIntent {
                intent_id: row.get(0)?,
                billing_account_id: row.get(1)?,
                account_id: row.get(2)?,
                amount_cents: row.get(3)?,
                currency: row.get(4)?,
                created_at_unix_ms: row.get(5)?,
                stripe_session_id: row.get(6)?,
                checkout_url: row.get(7)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| MeteringError::Invalid(format!("checkout intent {intent_id} does not exist")))
}

#[derive(Debug, Clone)]
struct StoredCheckpoint {
    event_id: String,
    source_id: String,
    source_epoch: String,
    sequence: u64,
    observed_at_unix_ms: i64,
    metric: UsageMetric,
    cumulative_quantity: u128,
    attribution: UsageAttribution,
}

impl StoredCheckpoint {
    fn from_value(value: &AttributedCheckpoint) -> Result<Self> {
        Ok(Self {
            event_id: value.checkpoint.event_id.clone(),
            source_id: value.checkpoint.source_id.clone(),
            source_epoch: value.checkpoint.source_epoch.clone(),
            sequence: value.checkpoint.sequence,
            observed_at_unix_ms: value.checkpoint.observed_at_unix_ms,
            metric: value.checkpoint.metric,
            cumulative_quantity: value.checkpoint.cumulative_quantity,
            attribution: value.attribution.clone(),
        })
    }
}

#[derive(Clone, Copy)]
enum Adjacent {
    Previous,
    Next,
}

fn adjacent_checkpoint(
    tx: &Transaction<'_>,
    value: &AttributedCheckpoint,
    adjacent: Adjacent,
) -> Result<Option<StoredCheckpoint>> {
    let (comparison, order) = match adjacent {
        Adjacent::Previous => ("<", "DESC"),
        Adjacent::Next => (">", "ASC"),
    };
    let sql = format!(
        "SELECT event_id, source_id, source_epoch, sequence, observed_at_ms,
                metric, cumulative_quantity, billing_account_id, workspace_id,
                resource_type, resource_id, attributed_cat_id
           FROM usage_checkpoints
          WHERE source_id=?1 AND source_epoch=?2 AND metric=?3
            AND sequence {comparison} ?4
          ORDER BY sequence {order}
          LIMIT 1"
    );
    tx.query_row(
        &sql,
        params![
            value.checkpoint.source_id,
            value.checkpoint.source_epoch,
            value.checkpoint.metric.slug(),
            to_i64(value.checkpoint.sequence, "sequence")?
        ],
        row_to_checkpoint,
    )
    .optional()
    .map_err(Into::into)
}

/// Validate the storage-independent checkpoint and frozen-attribution
/// contract before an adapter starts a transaction.
pub fn validate_checkpoint(value: &AttributedCheckpoint) -> Result<()> {
    let checkpoint = &value.checkpoint;
    for (name, id) in [
        ("event_id", checkpoint.event_id.as_str()),
        ("source_id", checkpoint.source_id.as_str()),
        ("source_epoch", checkpoint.source_epoch.as_str()),
        ("cat_id", checkpoint.cat_id.as_str()),
        (
            "billing_account_id",
            value.attribution.billing_account_id.as_str(),
        ),
        ("workspace_id", value.attribution.workspace_id.as_str()),
        ("resource_type", value.attribution.resource_type.as_str()),
        ("resource_id", value.attribution.resource_id.as_str()),
    ] {
        if id.is_empty() || id.len() > 256 {
            return Err(MeteringError::Invalid(format!(
                "{name} must contain 1..=256 bytes"
            )));
        }
    }
    if checkpoint.observed_at_unix_ms < 0 {
        return Err(MeteringError::Invalid(
            "observed_at_unix_ms must be non-negative".to_string(),
        ));
    }
    if checkpoint.cat_generation < 0 {
        return Err(MeteringError::Invalid(
            "cat_generation must be non-negative".to_string(),
        ));
    }
    if value.attribution.resource_type == "cat"
        && (value.attribution.resource_id != checkpoint.cat_id
            || value.attribution.attributed_cat_id.as_deref() != Some(checkpoint.cat_id.as_str()))
    {
        return Err(MeteringError::Invalid(
            "Cat checkpoint attribution does not match cat_id".to_string(),
        ));
    }
    let expected = deterministic_event_id(checkpoint);
    if checkpoint.event_id != expected {
        return Err(MeteringError::Invalid(format!(
            "event_id must be deterministic; expected {expected}"
        )));
    }
    Ok(())
}

pub fn validate_usage_query(query: &UsageQuery) -> Result<()> {
    if query.billing_account_id.is_empty() {
        return Err(MeteringError::Invalid(
            "billing_account_id must not be empty".to_string(),
        ));
    }
    if query.interval_start_unix_ms < 0
        || query.interval_end_unix_ms <= query.interval_start_unix_ms
    {
        return Err(MeteringError::Invalid(
            "query interval must be non-negative and non-empty".to_string(),
        ));
    }
    Ok(())
}

/// Apply boundary proration and produce the canonical account/Cat/metric
/// views. Database adapters use this helper so local and production stores
/// cannot drift in their rating inputs.
pub fn usage_view_from_intervals(
    query: &UsageQuery,
    intervals: impl IntoIterator<Item = UsageInterval>,
) -> Result<UsageView> {
    validate_usage_query(query)?;
    let mut totals = BTreeMap::<&'static str, (UsageMetric, u128)>::new();
    let mut cats = BTreeMap::<String, BTreeMap<&'static str, (UsageMetric, u128)>>::new();
    let mut details = Vec::new();
    let mut latest_interval_end = None;
    for mut interval in intervals {
        if interval.attribution.billing_account_id != query.billing_account_id
            || query
                .workspace_id
                .as_ref()
                .is_some_and(|workspace| workspace != &interval.attribution.workspace_id)
            || query
                .attributed_cat_id
                .as_ref()
                .is_some_and(|cat| interval.attribution.attributed_cat_id.as_ref() != Some(cat))
        {
            continue;
        }
        let overlap_start = interval
            .interval_start_unix_ms
            .max(query.interval_start_unix_ms);
        let overlap_end = interval
            .interval_end_unix_ms
            .min(query.interval_end_unix_ms);
        if overlap_end <= overlap_start {
            continue;
        }
        let overlap =
            u128::try_from(overlap_end - overlap_start).map_err(|_| MeteringError::Overflow)?;
        let duration =
            u128::try_from(interval.interval_end_unix_ms - interval.interval_start_unix_ms)
                .map_err(|_| MeteringError::Overflow)?;
        interval.quantity = interval
            .quantity
            .checked_mul(overlap)
            .ok_or(MeteringError::Overflow)?
            / duration;
        interval.interval_start_unix_ms = overlap_start;
        interval.interval_end_unix_ms = overlap_end;
        latest_interval_end = Some(
            latest_interval_end
                .unwrap_or(i64::MIN)
                .max(interval.interval_end_unix_ms),
        );
        if interval.quantity == 0 {
            continue;
        }
        let entry = totals
            .entry(interval.metric.slug())
            .or_insert((interval.metric, 0));
        entry.1 = entry
            .1
            .checked_add(interval.quantity)
            .ok_or(MeteringError::Overflow)?;
        if let Some(cat_id) = &interval.attribution.attributed_cat_id {
            let entry = cats
                .entry(cat_id.clone())
                .or_default()
                .entry(interval.metric.slug())
                .or_insert((interval.metric, 0));
            entry.1 = entry
                .1
                .checked_add(interval.quantity)
                .ok_or(MeteringError::Overflow)?;
        }
        details.push(interval);
    }

    Ok(UsageView {
        totals: totals
            .into_values()
            .map(|(metric, quantity)| UsageAggregate { metric, quantity })
            .collect(),
        cats: cats
            .into_iter()
            .map(|(cat_id, values)| CatAggregate {
                cat_id,
                items: values
                    .into_values()
                    .map(|(metric, quantity)| UsageAggregate { metric, quantity })
                    .collect(),
            })
            .collect(),
        details,
        latest_interval_end_unix_ms: latest_interval_end,
    })
}

pub fn metric_from_slug(value: &str) -> Result<UsageMetric> {
    match value {
        "cats.compute.cpu.v1" => Ok(UsageMetric::CpuUsec),
        "cats.compute.memory.v1" => Ok(UsageMetric::MemoryByteMillis),
        "cats.storage.hot.v1" => Ok(UsageMetric::StorageHotByteMillis),
        "cats.storage.cold.v1" => Ok(UsageMetric::StorageColdByteMillis),
        "cats.network.egress.v1" => Ok(UsageMetric::NetworkEgressBytes),
        _ => Err(MeteringError::Store(format!(
            "unknown usage metric {value:?}"
        ))),
    }
}

fn validate_adjacent(
    current: &AttributedCheckpoint,
    previous: Option<&StoredCheckpoint>,
    next: Option<&StoredCheckpoint>,
) -> Result<()> {
    for adjacent in previous.into_iter().chain(next) {
        if adjacent.attribution != current.attribution {
            return Err(MeteringError::Conflict(
                "attribution changed inside one source epoch".to_string(),
            ));
        }
    }
    if let Some(previous) = previous {
        if previous.observed_at_unix_ms >= current.checkpoint.observed_at_unix_ms {
            return Err(MeteringError::Conflict(
                "timestamp did not increase with sequence".to_string(),
            ));
        }
        if previous.cumulative_quantity > current.checkpoint.cumulative_quantity {
            return Err(MeteringError::Conflict(
                "cumulative counter regressed without a new source epoch".to_string(),
            ));
        }
    }
    if let Some(next) = next {
        if current.checkpoint.observed_at_unix_ms >= next.observed_at_unix_ms {
            return Err(MeteringError::Conflict(
                "timestamp did not increase with sequence".to_string(),
            ));
        }
        if current.checkpoint.cumulative_quantity > next.cumulative_quantity {
            return Err(MeteringError::Conflict(
                "cumulative counter regressed without a new source epoch".to_string(),
            ));
        }
    }
    Ok(())
}

fn insert_interval(
    tx: &Transaction<'_>,
    start: &StoredCheckpoint,
    end: &StoredCheckpoint,
) -> Result<()> {
    debug_assert_eq!(start.source_id, end.source_id);
    debug_assert_eq!(start.source_epoch, end.source_epoch);
    debug_assert_eq!(start.metric, end.metric);
    let quantity = end
        .cumulative_quantity
        .checked_sub(start.cumulative_quantity)
        .ok_or_else(|| MeteringError::Conflict("cumulative counter regressed".to_string()))?;
    tx.execute(
        "INSERT OR REPLACE INTO usage_intervals (
            end_event_id, start_event_id, source_id, source_epoch, end_sequence,
            interval_start_ms, interval_end_ms, metric, quantity,
            billing_account_id, workspace_id, resource_type, resource_id,
            attributed_cat_id
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            end.event_id,
            start.event_id,
            end.source_id,
            end.source_epoch,
            to_i64(end.sequence, "sequence")?,
            start.observed_at_unix_ms,
            end.observed_at_unix_ms,
            end.metric.slug(),
            quantity.to_string(),
            end.attribution.billing_account_id,
            end.attribution.workspace_id,
            end.attribution.resource_type,
            end.attribution.resource_id,
            end.attribution.attributed_cat_id,
        ],
    )?;
    Ok(())
}

fn row_to_checkpoint(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredCheckpoint> {
    let metric = parse_metric(&row.get::<_, String>(5)?)?;
    Ok(StoredCheckpoint {
        event_id: row.get(0)?,
        source_id: row.get(1)?,
        source_epoch: row.get(2)?,
        sequence: from_i64(row.get(3)?, 3)?,
        observed_at_unix_ms: row.get(4)?,
        metric,
        cumulative_quantity: row_u128(row, 6)?,
        attribution: UsageAttribution {
            billing_account_id: row.get(7)?,
            workspace_id: row.get(8)?,
            resource_type: row.get(9)?,
            resource_id: row.get(10)?,
            attributed_cat_id: row.get(11)?,
        },
    })
}

fn row_to_interval(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageInterval> {
    let quantity = row_u128(row, 2)?;
    Ok(UsageInterval {
        interval_start_unix_ms: row.get(0)?,
        interval_end_unix_ms: row.get(1)?,
        quantity,
        attribution: UsageAttribution {
            billing_account_id: row.get(3)?,
            workspace_id: row.get(4)?,
            resource_type: row.get(5)?,
            resource_id: row.get(6)?,
            attributed_cat_id: row.get(7)?,
        },
        metric: parse_metric(&row.get::<_, String>(8)?)?,
        source_id: row.get(9)?,
        source_epoch: row.get(10)?,
        end_sequence: from_i64(row.get(11)?, 11)?,
    })
}

fn parse_metric(value: &str) -> rusqlite::Result<UsageMetric> {
    metric_from_slug(value).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "metric".to_string(), rusqlite::types::Type::Text)
    })
}

fn to_i64(value: u64, name: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| MeteringError::Invalid(format!("{name} exceeds SQLite V1 range")))
}

fn from_i64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn row_u128(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u128> {
    use rusqlite::types::{Type, ValueRef};

    match row.get_ref(column)? {
        ValueRef::Integer(value) => u128::try_from(value)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value)),
        ValueRef::Text(value) => std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u128>().ok())
            .ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(column, "decimal u128".to_string(), Type::Text)
            }),
        value => Err(rusqlite::Error::InvalidColumnType(
            column,
            "decimal u128".to_string(),
            value.data_type(),
        )),
    }
}

fn migrate_sqlite_u128(conn: &mut Connection) -> Result<()> {
    let quantity_type: String = conn.query_row(
        "SELECT type FROM pragma_table_info('usage_checkpoints')
          WHERE name='cumulative_quantity'",
        [],
        |row| row.get(0),
    )?;
    if quantity_type.eq_ignore_ascii_case("TEXT") {
        return Ok(());
    }

    let transaction = conn.transaction()?;
    transaction.execute_batch(
        "
DROP INDEX IF EXISTS usage_checkpoints_account_time;
DROP INDEX IF EXISTS usage_intervals_account_time;
DROP INDEX IF EXISTS usage_intervals_cat_time;
ALTER TABLE usage_checkpoints RENAME TO usage_checkpoints_i64_v1;
ALTER TABLE usage_intervals RENAME TO usage_intervals_i64_v1;
",
    )?;
    transaction.execute_batch(SCHEMA)?;
    transaction.execute_batch(
        "
INSERT INTO usage_checkpoints (
    event_id, source_id, source_epoch, sequence, observed_at_ms, metric,
    cumulative_quantity, billing_account_id, workspace_id, resource_type,
    resource_id, attributed_cat_id, payload_json
)
SELECT event_id, source_id, source_epoch, sequence, observed_at_ms, metric,
       CAST(cumulative_quantity AS TEXT), billing_account_id, workspace_id,
       resource_type, resource_id, attributed_cat_id, payload_json
  FROM usage_checkpoints_i64_v1;
INSERT INTO usage_intervals (
    end_event_id, start_event_id, source_id, source_epoch, end_sequence,
    interval_start_ms, interval_end_ms, metric, quantity,
    billing_account_id, workspace_id, resource_type, resource_id,
    attributed_cat_id
)
SELECT end_event_id, start_event_id, source_id, source_epoch, end_sequence,
       interval_start_ms, interval_end_ms, metric, CAST(quantity AS TEXT),
       billing_account_id, workspace_id, resource_type, resource_id,
       attributed_cat_id
  FROM usage_intervals_i64_v1;
DROP TABLE usage_intervals_i64_v1;
DROP TABLE usage_checkpoints_i64_v1;
",
    )?;
    transaction.commit()?;
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS usage_checkpoints (
    event_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    metric TEXT NOT NULL,
    cumulative_quantity TEXT NOT NULL,
    billing_account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attributed_cat_id TEXT,
    payload_json TEXT NOT NULL,
    UNIQUE (source_id, source_epoch, metric, sequence)
);
CREATE INDEX IF NOT EXISTS usage_checkpoints_account_time
ON usage_checkpoints(billing_account_id, observed_at_ms);

CREATE TABLE IF NOT EXISTS usage_intervals (
    end_event_id TEXT PRIMARY KEY,
    start_event_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    end_sequence INTEGER NOT NULL,
    interval_start_ms INTEGER NOT NULL,
    interval_end_ms INTEGER NOT NULL,
    metric TEXT NOT NULL,
    quantity TEXT NOT NULL,
    billing_account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attributed_cat_id TEXT,
    CHECK (interval_end_ms > interval_start_ms),
    CHECK (length(quantity) > 0)
);
CREATE INDEX IF NOT EXISTS usage_intervals_account_time
ON usage_intervals(billing_account_id, interval_start_ms, interval_end_ms);
CREATE INDEX IF NOT EXISTS usage_intervals_cat_time
ON usage_intervals(attributed_cat_id, interval_start_ms, interval_end_ms);

CREATE TABLE IF NOT EXISTS billing_accounts (
    billing_account_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency = 'USD'),
    stripe_customer_id TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
);
CREATE TABLE IF NOT EXISTS credit_ledger_entries (
    entry_id TEXT PRIMARY KEY,
    billing_account_id TEXT NOT NULL REFERENCES billing_accounts(billing_account_id),
    kind TEXT NOT NULL,
    amount_nanos TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency = 'USD'),
    external_reference TEXT NOT NULL UNIQUE,
    effective_at_ms INTEGER NOT NULL CHECK (effective_at_ms >= 0)
);
CREATE INDEX IF NOT EXISTS credit_ledger_account_time
ON credit_ledger_entries(billing_account_id, effective_at_ms);
CREATE TRIGGER IF NOT EXISTS credit_ledger_insert_only_update
BEFORE UPDATE ON credit_ledger_entries
BEGIN
    SELECT RAISE(ABORT, 'credit ledger entries are insert-only');
END;
CREATE TRIGGER IF NOT EXISTS credit_ledger_insert_only_delete
BEFORE DELETE ON credit_ledger_entries
BEGIN
    SELECT RAISE(ABORT, 'credit ledger entries are insert-only');
END;

CREATE TABLE IF NOT EXISTS checkout_intents (
    intent_id TEXT PRIMARY KEY,
    billing_account_id TEXT NOT NULL REFERENCES billing_accounts(billing_account_id),
    account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    currency TEXT NOT NULL CHECK (currency = 'USD'),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    stripe_session_id TEXT UNIQUE,
    checkout_url TEXT,
    stripe_payment_intent_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'paid'))
);
CREATE TABLE IF NOT EXISTS stripe_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    livemode INTEGER NOT NULL,
    processed_at_ms INTEGER NOT NULL CHECK (processed_at_ms >= 0)
);
";

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> SqliteUsageStore {
        SqliteUsageStore::open(Path::new(":memory:")).unwrap()
    }

    fn checkpoint(
        sequence: u64,
        observed_at_unix_ms: i64,
        cumulative_quantity: u128,
        metric: UsageMetric,
    ) -> AttributedCheckpoint {
        let mut checkpoint = CatUsageCheckpoint {
            event_id: String::new(),
            source_id: "node/node-a/cat/cat-a".to_string(),
            source_epoch: "runtime-7".to_string(),
            sequence,
            observed_at_unix_ms,
            cat_id: "cat-a".to_string(),
            cat_generation: 7,
            metric,
            cumulative_quantity,
        };
        checkpoint.event_id = deterministic_event_id(&checkpoint);
        AttributedCheckpoint {
            checkpoint,
            attribution: UsageAttribution {
                billing_account_id: "ba-org-a".to_string(),
                workspace_id: "workspace-a".to_string(),
                resource_type: "cat".to_string(),
                resource_id: "cat-a".to_string(),
                attributed_cat_id: Some("cat-a".to_string()),
            },
        }
    }

    fn query() -> UsageQuery {
        UsageQuery {
            billing_account_id: "ba-org-a".to_string(),
            workspace_id: None,
            attributed_cat_id: None,
            interval_start_unix_ms: 1_000,
            interval_end_unix_ms: 31_000,
        }
    }

    #[test]
    fn duplicate_checkpoint_does_not_double_count() {
        let ledger = ledger();
        let first = checkpoint(1, 1_000, 100, UsageMetric::CpuUsec);
        let second = checkpoint(2, 11_000, 900, UsageMetric::CpuUsec);
        assert_eq!(ledger.ingest(&first).unwrap(), IngestOutcome::Accepted);
        assert_eq!(ledger.ingest(&second).unwrap(), IngestOutcome::Accepted);
        assert_eq!(ledger.ingest(&second).unwrap(), IngestOutcome::Duplicate);
        assert_eq!(ledger.query(&query()).unwrap().totals[0].quantity, 800);
    }

    #[test]
    fn sqlite_preserves_quantities_above_signed_64_bit_range() {
        let ledger = ledger();
        let baseline = u128::try_from(i64::MAX).unwrap() + 10_000;
        ledger
            .ingest(&checkpoint(
                1,
                1_000,
                baseline,
                UsageMetric::MemoryByteMillis,
            ))
            .unwrap();
        ledger
            .ingest(&checkpoint(
                2,
                11_000,
                baseline + 50_000,
                UsageMetric::MemoryByteMillis,
            ))
            .unwrap();
        assert_eq!(ledger.query(&query()).unwrap().totals[0].quantity, 50_000);
    }

    #[test]
    fn cumulative_checkpoint_recovers_a_transport_gap() {
        let ledger = ledger();
        ledger
            .ingest(&checkpoint(1, 1_000, 100, UsageMetric::CpuUsec))
            .unwrap();
        ledger
            .ingest(&checkpoint(9, 21_000, 2_100, UsageMetric::CpuUsec))
            .unwrap();
        assert_eq!(ledger.query(&query()).unwrap().totals[0].quantity, 2_000);
    }

    #[test]
    fn out_of_order_checkpoint_rebuilds_adjacent_intervals() {
        let ledger = ledger();
        ledger
            .ingest(&checkpoint(1, 1_000, 100, UsageMetric::CpuUsec))
            .unwrap();
        ledger
            .ingest(&checkpoint(3, 21_000, 2_100, UsageMetric::CpuUsec))
            .unwrap();
        ledger
            .ingest(&checkpoint(2, 11_000, 900, UsageMetric::CpuUsec))
            .unwrap();
        let view = ledger.query(&query()).unwrap();
        assert_eq!(view.totals[0].quantity, 2_000);
        assert_eq!(view.details.len(), 2);
    }

    #[test]
    fn counter_reset_requires_a_new_source_epoch() {
        let ledger = ledger();
        ledger
            .ingest(&checkpoint(1, 1_000, 900, UsageMetric::CpuUsec))
            .unwrap();
        let error = ledger
            .ingest(&checkpoint(2, 11_000, 100, UsageMetric::CpuUsec))
            .unwrap_err();
        assert!(matches!(error, MeteringError::Conflict(_)));
    }

    #[test]
    fn replay_cannot_change_frozen_billing_attribution() {
        let ledger = ledger();
        let first = checkpoint(1, 1_000, 100, UsageMetric::CpuUsec);
        ledger.ingest(&first).unwrap();
        let mut forged = first;
        forged.attribution.billing_account_id = "ba-other".to_string();
        let error = ledger.ingest(&forged).unwrap_err();
        assert!(matches!(error, MeteringError::Conflict(_)));
    }

    #[test]
    fn all_metrics_in_a_source_epoch_share_attribution() {
        let ledger = ledger();
        ledger
            .ingest(&checkpoint(1, 1_000, 100, UsageMetric::CpuUsec))
            .unwrap();
        let mut memory = checkpoint(1, 1_000, 100, UsageMetric::MemoryByteMillis);
        memory.attribution.workspace_id = "workspace-other".to_string();
        let error = ledger.ingest(&memory).unwrap_err();
        assert!(matches!(error, MeteringError::Conflict(_)));
    }

    #[test]
    fn query_supports_org_cat_and_metric_views() {
        let ledger = ledger();
        for metric in [UsageMetric::CpuUsec, UsageMetric::MemoryByteMillis] {
            ledger.ingest(&checkpoint(1, 1_000, 0, metric)).unwrap();
            ledger
                .ingest(&checkpoint(2, 11_000, 1_000, metric))
                .unwrap();
        }
        let view = ledger.query(&query()).unwrap();
        assert_eq!(view.totals.len(), 2);
        assert_eq!(view.cats.len(), 1);
        assert_eq!(view.cats[0].items.len(), 2);
        assert_eq!(view.details.len(), 2);
    }

    #[test]
    fn boundary_query_prorates_only_the_overlapping_interval() {
        let ledger = ledger();
        ledger
            .ingest(&checkpoint(1, 1_000, 0, UsageMetric::CpuUsec))
            .unwrap();
        ledger
            .ingest(&checkpoint(2, 11_000, 1_000, UsageMetric::CpuUsec))
            .unwrap();
        let mut partial = query();
        partial.interval_start_unix_ms = 6_000;
        partial.interval_end_unix_ms = 11_000;
        assert_eq!(ledger.query(&partial).unwrap().totals[0].quantity, 500);
    }

    #[tokio::test]
    async fn signup_and_stripe_credits_are_exact_and_idempotent() {
        let ledger = ledger();
        let first = CreditStore::ensure_account(
            &ledger,
            "billing/account-a",
            "account-a",
            "USD",
            10_000_000_000,
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(first.credit_nanos, 10_000_000_000);
        let replay = CreditStore::ensure_account(
            &ledger,
            "billing/account-a",
            "account-a",
            "USD",
            10_000_000_000,
            2_000,
        )
        .await
        .unwrap();
        assert_eq!(replay.credit_nanos, 10_000_000_000);

        let intent = CheckoutIntent {
            intent_id: "checkout-a".into(),
            billing_account_id: "billing/account-a".into(),
            account_id: "account-a".into(),
            amount_cents: 2_500,
            currency: "USD".into(),
            created_at_unix_ms: 3_000,
            stripe_session_id: None,
            checkout_url: None,
        };
        CreditStore::create_checkout_intent(&ledger, &intent)
            .await
            .unwrap();
        CreditStore::attach_checkout_session(
            &ledger,
            "checkout-a",
            "cs_test_a",
            "https://checkout.stripe.com/c/pay/cs_test_a",
        )
        .await
        .unwrap();
        let payment = CheckoutPayment {
            event_id: "evt_a".into(),
            payload_sha256: "a".repeat(64),
            intent_id: "checkout-a".into(),
            billing_account_id: "billing/account-a".into(),
            stripe_session_id: "cs_test_a".into(),
            stripe_payment_intent_id: "pi_a".into(),
            stripe_customer_id: Some("cus_a".into()),
            amount_cents: 2_500,
            currency: "USD".into(),
            livemode: false,
            processed_at_unix_ms: 4_000,
        };
        assert_eq!(
            CreditStore::apply_checkout_payment(&ledger, &payment)
                .await
                .unwrap(),
            CreditApplyOutcome::Accepted
        );
        assert_eq!(
            CreditStore::apply_checkout_payment(&ledger, &payment)
                .await
                .unwrap(),
            CreditApplyOutcome::Duplicate
        );
        let summary = CreditStore::summary(&ledger, "billing/account-a")
            .await
            .unwrap();
        assert_eq!(summary.credit_nanos, 35_000_000_000);
        assert_eq!(summary.stripe_customer_id.as_deref(), Some("cus_a"));

        let refund = CheckoutRefund {
            event_id: "evt_refund_a".into(),
            payload_sha256: "b".repeat(64),
            stripe_refund_id: "re_a".into(),
            stripe_payment_intent_id: "pi_a".into(),
            amount_cents: 500,
            currency: "USD".into(),
            livemode: false,
            processed_at_unix_ms: 5_000,
        };
        assert_eq!(
            CreditStore::apply_checkout_refund(&ledger, &refund)
                .await
                .unwrap(),
            CreditApplyOutcome::Accepted
        );
        assert_eq!(
            CreditStore::summary(&ledger, "billing/account-a")
                .await
                .unwrap()
                .credit_nanos,
            30_000_000_000
        );
    }

    #[tokio::test]
    async fn organization_billing_account_can_start_without_signup_credit() {
        let ledger = ledger();
        let summary = CreditStore::ensure_account(
            &ledger,
            "billing/account-org",
            "org-default",
            "USD",
            0,
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(summary.credit_nanos, 0);
        assert_eq!(
            CreditStore::summary(&ledger, "billing/account-org")
                .await
                .unwrap()
                .credit_nanos,
            0
        );
    }

    #[tokio::test]
    async fn sqlite_credit_ledger_rejects_update_and_delete() {
        let ledger = ledger();
        CreditStore::ensure_account(
            &ledger,
            "billing/account-a",
            "account-a",
            "USD",
            10_000_000_000,
            1_000,
        )
        .await
        .unwrap();
        let conn = ledger.conn.lock().unwrap();
        assert!(conn
            .execute("UPDATE credit_ledger_entries SET amount_nanos='0'", [],)
            .is_err());
        assert!(conn
            .execute("DELETE FROM credit_ledger_entries", [])
            .is_err());
    }

    #[test]
    fn rates_aggregate_once_with_integer_math() {
        let card = RateCard::sprites_compute_v1();
        assert_eq!(
            card.rate_quantity(UsageMetric::CpuUsec, USEC_PER_HOUR)
                .unwrap(),
            Some(70_000_000)
        );
        assert_eq!(
            card.rate_quantity(UsageMetric::MemoryByteMillis, GIB * MILLIS_PER_HOUR)
                .unwrap(),
            Some(45_000_000)
        );
        assert_eq!(
            card.rate_quantity(UsageMetric::NetworkEgressBytes, 1)
                .unwrap(),
            None
        );
    }

    #[test]
    fn runtime_accumulator_integrates_one_second_samples_before_checkpointing() {
        let mut meter = RuntimeMeterAccumulator::new(
            "node/node-a/cat/cat-a".to_string(),
            "runtime-a".to_string(),
            "cat-a".to_string(),
            1,
        )
        .unwrap();
        meter.observe(1_000, 100, 1_000).unwrap();
        let baseline = meter.checkpoint().unwrap();
        assert_eq!(baseline[0].cumulative_quantity, 100);
        assert_eq!(baseline[1].cumulative_quantity, 0);

        meter.observe(2_000, 300, 2_000).unwrap();
        meter.observe(3_000, 600, 4_000).unwrap();
        let checkpoint = meter.checkpoint().unwrap();
        assert_eq!(checkpoint[0].cumulative_quantity, 600);
        assert_eq!(checkpoint[1].cumulative_quantity, 3_000_000);
        assert_eq!(checkpoint[0].sequence, 1);
        assert_eq!(
            checkpoint[0].event_id,
            deterministic_event_id(&checkpoint[0])
        );
    }

    #[test]
    fn runtime_accumulator_fails_closed_on_cpu_reset() {
        let mut meter = RuntimeMeterAccumulator::new(
            "source".to_string(),
            "epoch".to_string(),
            "cat-a".to_string(),
            1,
        )
        .unwrap();
        meter.observe(1_000, 500, 1_000).unwrap();
        let error = meter.observe(2_000, 100, 1_000).unwrap_err();
        assert!(matches!(error, MeteringError::Conflict(_)));
    }
}

//! PostgreSQL production adapter for the cumulative usage ledger.
//!
//! Raw checkpoints are insert-only at the database boundary. Each source
//! epoch is serialized with a transaction-scoped PostgreSQL advisory lock so
//! duplicate, cross-metric attribution and out-of-order interval repair stay
//! deterministic even when several consumers replay concurrently.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc as tokio_mpsc;

use cats_api::metering::UsageMetric;
use cats_metering::{
    metric_from_slug, usage_view_from_intervals, validate_checkout_intent,
    validate_checkout_payment, validate_checkout_refund, validate_checkpoint, validate_usage_query,
    AttributedCheckpoint, CheckoutIntent, CheckoutPayment, CheckoutRefund, CreditApplyOutcome,
    CreditStore, CreditStoreFuture, CreditSummary, IngestOutcome, MeteringError, Result,
    UsageAggregate, UsageAttribution, UsageInterval, UsageQuery, UsageStore, UsageStoreFuture,
    UsageTotals, UsageView,
};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Row, Transaction};
use postgres_native_tls::MakeTlsConnector;

pub const DEFAULT_SCHEMA: &str = "cats_usage";
pub const DEFAULT_WORKERS: usize = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const STATEMENT_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(10);
// One slot for each globally admitted signed-runtime request is sufficient
// even if all of them select the same worker. Other callers then backpressure
// instead of growing synchronous database work without a bound.
const JOBS_PER_WORKER: usize = 64;

/// A job receives the connection or the reason there is not one. Dropping it
/// unrun would reach the caller as "operation was canceled", which is the kind
/// of wrapper that hid a credential failure for thirteen hours.
type Job = Box<dyn for<'a> FnOnce(Result<&'a mut Client>) + Send + 'static>;

/// Where a worker obtains its DSN, consulted afresh for every connect.
///
/// Duplicated from `cats-metadata-store-postgres` rather than shared: the two
/// live on opposite sides of the storage/metering boundary with no common
/// crate, and their error types differ. A crate existing only to hold this
/// would be a worse trade than thirty lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DsnSource {
    /// A literal DSN, fixed for the life of the process.
    Literal(String),
    /// A file re-read on every connect, kept current by the platform.
    File(PathBuf),
}

impl DsnSource {
    /// Never include the file's contents in an error. It holds the password.
    fn resolve(&self) -> Result<String> {
        match self {
            Self::Literal(url) => Ok(url.clone()),
            Self::File(path) => {
                let contents = fs::read_to_string(path).map_err(|error| {
                    MeteringError::Store(format!(
                        "read PostgreSQL DSN from {}: {error}",
                        path.display()
                    ))
                })?;
                let url = contents.trim();
                if url.is_empty() {
                    return Err(MeteringError::Store(format!(
                        "PostgreSQL DSN file {} is empty",
                        path.display()
                    )));
                }
                Ok(url.to_string())
            }
        }
    }
}

/// A small fixed connection pool whose workers own synchronous PostgreSQL
/// clients. Callers await a Tokio oneshot, so database I/O never blocks an
/// async control-plane executor thread.
pub struct PostgresUsageStore {
    workers: Vec<tokio_mpsc::Sender<Job>>,
    next_worker: AtomicUsize,
    schema: String,
    poisoned: Arc<AtomicBool>,
    dispatch_timeout: Duration,
}

impl PostgresUsageStore {
    pub fn connect(url: &str, ca_file: Option<&str>, schema: &str, workers: usize) -> Result<Self> {
        Self::connect_from(
            &DsnSource::Literal(url.to_string()),
            ca_file,
            schema,
            workers,
        )
    }

    pub fn connect_from(
        dsn: &DsnSource,
        ca_file: Option<&str>,
        schema: &str,
        workers: usize,
    ) -> Result<Self> {
        Self::connect_from_with_timeouts(
            dsn,
            ca_file,
            schema,
            workers,
            WORKER_STARTUP_TIMEOUT,
            DISPATCH_TIMEOUT,
        )
    }

    fn connect_from_with_timeouts(
        dsn: &DsnSource,
        ca_file: Option<&str>,
        schema: &str,
        workers: usize,
        worker_startup_timeout: Duration,
        dispatch_timeout: Duration,
    ) -> Result<Self> {
        validate_schema_name(schema)?;
        if !(1..=64).contains(&workers) {
            return Err(MeteringError::Invalid(
                "PostgreSQL usage workers must be in 1..=64".to_string(),
            ));
        }
        let mut senders = Vec::with_capacity(workers);
        for worker_index in 0..workers {
            senders.push(spawn_worker(
                dsn.clone(),
                ca_file.map(str::to_string),
                schema.to_string(),
                worker_index,
                worker_startup_timeout,
            )?);
        }
        Ok(Self {
            workers: senders,
            next_worker: AtomicUsize::new(0),
            schema: schema.to_string(),
            poisoned: Arc::new(AtomicBool::new(false)),
            dispatch_timeout,
        })
    }

    async fn dispatch<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(poisoned_store_error());
        }
        let deadline = Instant::now()
            .checked_add(self.dispatch_timeout)
            .ok_or_else(poisoned_store_error)?;
        let mut poison_on_drop = PoisonStoreOnDrop::new(Arc::clone(&self.poisoned));
        let index = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let poisoned = Arc::clone(&self.poisoned);
        let job: Job = Box::new(move |client| {
            // A request that timed out while this job waited in the
            // bounded queue has dropped its receiver. Do not perform its
            // database effect after cancellation.
            if poisoned.load(Ordering::Acquire) || result_tx.is_closed() {
                return;
            }
            let _ = result_tx.send(match client {
                Ok(client) => operation(client),
                Err(error) => Err(error),
            });
        });
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.workers[index].send(job),
        )
        .await
        .map_err(|_| poisoned_store_error())?
        .map_err(|_| poisoned_store_error())?;
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), result_rx)
            .await
            .map_err(|_| poisoned_store_error())?
            .map_err(|_| poisoned_store_error())?;
        poison_on_drop.disarm();
        result
    }
}

struct PoisonStoreOnDrop {
    poisoned: Arc<AtomicBool>,
    armed: bool,
}

impl PoisonStoreOnDrop {
    fn new(poisoned: Arc<AtomicBool>) -> Self {
        Self {
            poisoned,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PoisonStoreOnDrop {
    fn drop(&mut self) {
        if self.armed {
            // Synchronous postgres work cannot be cancelled once it starts.
            // Fail the complete store closed so at most the fixed worker set
            // can remain stuck and a daemon restart is the only recovery.
            self.poisoned.store(true, Ordering::Release);
        }
    }
}

fn poisoned_store_error() -> MeteringError {
    MeteringError::Store(
        "PostgreSQL usage store timed out or lost a worker; restart required".to_string(),
    )
}

impl UsageStore for PostgresUsageStore {
    fn ingest<'a>(
        &'a self,
        value: &'a AttributedCheckpoint,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        let value = value.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| ingest_checkpoint(client, &schema, &value))
                .await
        })
    }

    fn query<'a>(&'a self, query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageView> {
        let query = query.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| query_usage(client, &schema, &query))
                .await
        })
    }

    fn query_totals<'a>(&'a self, query: &'a UsageQuery) -> UsageStoreFuture<'a, UsageTotals> {
        let query = query.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| query_usage_totals(client, &schema, &query))
                .await
        })
    }

    fn source_epoch_attribution<'a>(
        &'a self,
        source_id: &'a str,
        source_epoch: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageAttribution>> {
        let source_id = source_id.to_string();
        let source_epoch = source_epoch.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| {
                source_epoch_attribution(client, &schema, &source_id, &source_epoch)
            })
            .await
        })
    }
}

impl CreditStore for PostgresUsageStore {
    fn ensure_account<'a>(
        &'a self,
        billing_account_id: &'a str,
        account_id: &'a str,
        currency: &'a str,
        signup_credit_nanos: i128,
        created_at_unix_ms: i64,
    ) -> CreditStoreFuture<'a, CreditSummary> {
        let billing_account_id = billing_account_id.to_string();
        let account_id = account_id.to_string();
        let currency = currency.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| {
                pg_ensure_credit_account(
                    client,
                    &schema,
                    &billing_account_id,
                    &account_id,
                    &currency,
                    signup_credit_nanos,
                    created_at_unix_ms,
                )
            })
            .await
        })
    }

    fn summary<'a>(&'a self, billing_account_id: &'a str) -> CreditStoreFuture<'a, CreditSummary> {
        let billing_account_id = billing_account_id.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_credit_summary(client, &schema, &billing_account_id))
                .await
        })
    }

    fn create_checkout_intent<'a>(
        &'a self,
        intent: &'a CheckoutIntent,
    ) -> CreditStoreFuture<'a, CheckoutIntent> {
        let intent = intent.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_create_checkout_intent(client, &schema, &intent))
                .await
        })
    }

    fn attach_checkout_session<'a>(
        &'a self,
        intent_id: &'a str,
        stripe_session_id: &'a str,
        checkout_url: &'a str,
    ) -> CreditStoreFuture<'a, CheckoutIntent> {
        let intent_id = intent_id.to_string();
        let stripe_session_id = stripe_session_id.to_string();
        let checkout_url = checkout_url.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| {
                pg_attach_checkout_session(
                    client,
                    &schema,
                    &intent_id,
                    &stripe_session_id,
                    &checkout_url,
                )
            })
            .await
        })
    }

    fn apply_checkout_payment<'a>(
        &'a self,
        payment: &'a CheckoutPayment,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome> {
        let payment = payment.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_apply_checkout_payment(client, &schema, &payment))
                .await
        })
    }

    fn apply_checkout_refund<'a>(
        &'a self,
        refund: &'a CheckoutRefund,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome> {
        let refund = refund.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_apply_checkout_refund(client, &schema, &refund))
                .await
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
    if billing_account_id.is_empty()
        || account_id.is_empty()
        || currency != "USD"
        || signup_credit_nanos < 0
        || created_at_unix_ms < 0
    {
        return Err(MeteringError::Invalid(
            "invalid billing credit account".to_string(),
        ));
    }
    Ok(())
}

fn pg_ensure_credit_account(
    client: &mut Client,
    schema: &str,
    billing_account_id: &str,
    account_id: &str,
    currency: &str,
    signup_credit_nanos: i128,
    created_at_unix_ms: i64,
) -> Result<CreditSummary> {
    validate_credit_account(
        billing_account_id,
        account_id,
        currency,
        signup_credit_nanos,
        created_at_unix_ms,
    )?;
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start credit-account transaction", error))?;
    let account_sql = format!(
        "INSERT INTO {schema}.billing_accounts (
            billing_account_id, account_id, currency, created_at_ms
         ) VALUES ($1, $2, $3, $4)
         ON CONFLICT (billing_account_id) DO NOTHING"
    );
    transaction
        .execute(
            &account_sql,
            &[
                &billing_account_id,
                &account_id,
                &currency,
                &created_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("ensure billing account", error))?;
    let summary = pg_credit_summary_transaction(&mut transaction, schema, billing_account_id)?;
    if summary.account_id != account_id || summary.currency != currency {
        return Err(MeteringError::Conflict(format!(
            "billing account {billing_account_id} identity changed"
        )));
    }
    if signup_credit_nanos > 0 {
        let grant_sql = format!(
            "INSERT INTO {schema}.credit_ledger_entries (
                entry_id, billing_account_id, kind, amount_nanos, currency,
                external_reference, effective_at_ms
             ) VALUES ($1, $2, 'signup_grant', $3::text::numeric, $4, $5, $6)
             ON CONFLICT (entry_id) DO NOTHING"
        );
        let grant_id = format!("signup-grant/{billing_account_id}");
        let amount = signup_credit_nanos.to_string();
        transaction
            .execute(
                &grant_sql,
                &[
                    &grant_id,
                    &billing_account_id,
                    &amount,
                    &currency,
                    &grant_id,
                    &created_at_unix_ms,
                ],
            )
            .map_err(|error| pg_error("ensure signup credit", error))?;
    }
    let summary = pg_credit_summary_transaction(&mut transaction, schema, billing_account_id)?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit credit-account transaction", error))?;
    Ok(summary)
}

fn pg_credit_summary(
    client: &mut Client,
    schema: &str,
    billing_account_id: &str,
) -> Result<CreditSummary> {
    let account_sql = format!(
        "SELECT account_id, currency, stripe_customer_id
           FROM {schema}.billing_accounts WHERE billing_account_id=$1"
    );
    let row = client
        .query_opt(&account_sql, &[&billing_account_id])
        .map_err(|error| pg_error("query billing account", error))?
        .ok_or_else(|| MeteringError::Invalid("billing account does not exist".to_string()))?;
    let total_sql = format!(
        "SELECT COALESCE(SUM(amount_nanos), 0)::text
           FROM {schema}.credit_ledger_entries WHERE billing_account_id=$1"
    );
    let credit_nanos = client
        .query_one(&total_sql, &[&billing_account_id])
        .map_err(|error| pg_error("sum billing credits", error))?
        .get::<_, String>(0)
        .parse::<i128>()
        .map_err(|_| MeteringError::Store("invalid PostgreSQL credit total".to_string()))?;
    Ok(CreditSummary {
        billing_account_id: billing_account_id.to_string(),
        account_id: row.get(0),
        currency: row.get(1),
        stripe_customer_id: row.get(2),
        credit_nanos,
    })
}

fn pg_credit_summary_transaction(
    transaction: &mut Transaction<'_>,
    schema: &str,
    billing_account_id: &str,
) -> Result<CreditSummary> {
    let account_sql = format!(
        "SELECT account_id, currency, stripe_customer_id
           FROM {schema}.billing_accounts WHERE billing_account_id=$1"
    );
    let row = transaction
        .query_opt(&account_sql, &[&billing_account_id])
        .map_err(|error| pg_error("query billing account", error))?
        .ok_or_else(|| MeteringError::Invalid("billing account does not exist".to_string()))?;
    let total_sql = format!(
        "SELECT COALESCE(SUM(amount_nanos), 0)::text
           FROM {schema}.credit_ledger_entries WHERE billing_account_id=$1"
    );
    let credit_nanos = transaction
        .query_one(&total_sql, &[&billing_account_id])
        .map_err(|error| pg_error("sum billing credits", error))?
        .get::<_, String>(0)
        .parse::<i128>()
        .map_err(|_| MeteringError::Store("invalid PostgreSQL credit total".to_string()))?;
    Ok(CreditSummary {
        billing_account_id: billing_account_id.to_string(),
        account_id: row.get(0),
        currency: row.get(1),
        stripe_customer_id: row.get(2),
        credit_nanos,
    })
}

fn pg_checkout_intent(
    client: &mut impl postgres::GenericClient,
    schema: &str,
    intent_id: &str,
) -> Result<CheckoutIntent> {
    let sql = format!(
        "SELECT intent_id, billing_account_id, account_id, amount_cents,
                currency, created_at_ms, stripe_session_id, checkout_url
           FROM {schema}.checkout_intents WHERE intent_id=$1"
    );
    let row = client
        .query_opt(&sql, &[&intent_id])
        .map_err(|error| pg_error("query checkout intent", error))?
        .ok_or_else(|| MeteringError::Invalid(format!("checkout intent {intent_id} not found")))?;
    Ok(CheckoutIntent {
        intent_id: row.get(0),
        billing_account_id: row.get(1),
        account_id: row.get(2),
        amount_cents: row.get(3),
        currency: row.get(4),
        created_at_unix_ms: row.get(5),
        stripe_session_id: row.get(6),
        checkout_url: row.get(7),
    })
}

fn pg_create_checkout_intent(
    client: &mut Client,
    schema: &str,
    intent: &CheckoutIntent,
) -> Result<CheckoutIntent> {
    validate_checkout_intent(intent)?;
    let sql = format!(
        "INSERT INTO {schema}.checkout_intents (
            intent_id, billing_account_id, account_id, amount_cents,
            currency, created_at_ms, status
         ) VALUES ($1, $2, $3, $4, $5, $6, 'pending')
         ON CONFLICT (intent_id) DO NOTHING"
    );
    client
        .execute(
            &sql,
            &[
                &intent.intent_id,
                &intent.billing_account_id,
                &intent.account_id,
                &intent.amount_cents,
                &intent.currency,
                &intent.created_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("create checkout intent", error))?;
    let stored = pg_checkout_intent(client, schema, &intent.intent_id)?;
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
}

fn pg_attach_checkout_session(
    client: &mut Client,
    schema: &str,
    intent_id: &str,
    stripe_session_id: &str,
    checkout_url: &str,
) -> Result<CheckoutIntent> {
    if intent_id.is_empty() || stripe_session_id.is_empty() || checkout_url.is_empty() {
        return Err(MeteringError::Invalid(
            "checkout intent, session and URL must not be empty".to_string(),
        ));
    }
    let stored = pg_checkout_intent(client, schema, intent_id)?;
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
    let sql = format!(
        "UPDATE {schema}.checkout_intents
            SET stripe_session_id=$2, checkout_url=$3
          WHERE intent_id=$1"
    );
    client
        .execute(&sql, &[&intent_id, &stripe_session_id, &checkout_url])
        .map_err(|error| pg_error("attach Stripe checkout session", error))?;
    pg_checkout_intent(client, schema, intent_id)
}

fn pg_apply_checkout_payment(
    client: &mut Client,
    schema: &str,
    payment: &CheckoutPayment,
) -> Result<CreditApplyOutcome> {
    validate_checkout_payment(payment)?;
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start Stripe event transaction", error))?;
    let event_sql = format!("SELECT payload_sha256 FROM {schema}.stripe_events WHERE event_id=$1");
    if let Some(row) = transaction
        .query_opt(&event_sql, &[&payment.event_id])
        .map_err(|error| pg_error("query Stripe event", error))?
    {
        if row.get::<_, String>(0) != payment.payload_sha256 {
            return Err(MeteringError::Conflict(format!(
                "Stripe event {} was replayed with another payload",
                payment.event_id
            )));
        }
        transaction
            .commit()
            .map_err(|error| pg_error("commit duplicate Stripe event", error))?;
        return Ok(CreditApplyOutcome::Duplicate);
    }
    let intent = pg_checkout_intent(&mut transaction, schema, &payment.intent_id)?;
    if payment.billing_account_id != intent.billing_account_id
        || payment.amount_cents != intent.amount_cents
        || payment.currency != intent.currency
        || intent
            .stripe_session_id
            .as_deref()
            .is_some_and(|value| value != payment.stripe_session_id)
    {
        return Err(MeteringError::Conflict(
            "Stripe payment does not match checkout intent".to_string(),
        ));
    }
    let insert_event_sql = format!(
        "INSERT INTO {schema}.stripe_events (
            event_id, event_type, payload_sha256, livemode, processed_at_ms
         ) VALUES ($1, 'checkout.session.paid', $2, $3, $4)"
    );
    transaction
        .execute(
            &insert_event_sql,
            &[
                &payment.event_id,
                &payment.payload_sha256,
                &payment.livemode,
                &payment.processed_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("record Stripe event", error))?;
    let amount_nanos = i128::from(payment.amount_cents)
        .checked_mul(10_000_000)
        .ok_or(MeteringError::Overflow)?
        .to_string();
    let entry_id = format!("stripe-topup/{}", payment.stripe_session_id);
    let external_reference = format!("stripe-payment/{}", payment.stripe_payment_intent_id);
    let credit_sql = format!(
        "INSERT INTO {schema}.credit_ledger_entries (
            entry_id, billing_account_id, kind, amount_nanos, currency,
            external_reference, effective_at_ms
         ) VALUES ($1, $2, 'stripe_topup', $3::text::numeric, $4, $5, $6)
         ON CONFLICT (entry_id) DO NOTHING"
    );
    transaction
        .execute(
            &credit_sql,
            &[
                &entry_id,
                &payment.billing_account_id,
                &amount_nanos,
                &payment.currency,
                &external_reference,
                &payment.processed_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("credit Stripe top-up", error))?;
    let update_intent_sql = format!(
        "UPDATE {schema}.checkout_intents
            SET stripe_session_id=$2, stripe_payment_intent_id=$3, status='paid'
          WHERE intent_id=$1"
    );
    transaction
        .execute(
            &update_intent_sql,
            &[
                &payment.intent_id,
                &payment.stripe_session_id,
                &payment.stripe_payment_intent_id,
            ],
        )
        .map_err(|error| pg_error("mark checkout paid", error))?;
    if let Some(customer_id) = &payment.stripe_customer_id {
        let customer_sql = format!(
            "UPDATE {schema}.billing_accounts
                SET stripe_customer_id=COALESCE(stripe_customer_id, $2)
              WHERE billing_account_id=$1"
        );
        transaction
            .execute(&customer_sql, &[&payment.billing_account_id, customer_id])
            .map_err(|error| pg_error("attach Stripe customer", error))?;
    }
    transaction
        .commit()
        .map_err(|error| pg_error("commit Stripe event", error))?;
    Ok(CreditApplyOutcome::Accepted)
}

fn pg_apply_checkout_refund(
    client: &mut Client,
    schema: &str,
    refund: &CheckoutRefund,
) -> Result<CreditApplyOutcome> {
    validate_checkout_refund(refund)?;
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start Stripe refund transaction", error))?;
    let event_sql = format!("SELECT payload_sha256 FROM {schema}.stripe_events WHERE event_id=$1");
    if let Some(row) = transaction
        .query_opt(&event_sql, &[&refund.event_id])
        .map_err(|error| pg_error("query Stripe refund event", error))?
    {
        if row.get::<_, String>(0) != refund.payload_sha256 {
            return Err(MeteringError::Conflict(format!(
                "Stripe event {} was replayed with another payload",
                refund.event_id
            )));
        }
        transaction
            .commit()
            .map_err(|error| pg_error("commit duplicate Stripe refund", error))?;
        return Ok(CreditApplyOutcome::Duplicate);
    }
    let checkout_sql = format!(
        "SELECT billing_account_id, amount_cents, currency
           FROM {schema}.checkout_intents
          WHERE stripe_payment_intent_id=$1 AND status='paid'"
    );
    let row = transaction
        .query_opt(&checkout_sql, &[&refund.stripe_payment_intent_id])
        .map_err(|error| pg_error("query refunded checkout", error))?
        .ok_or_else(|| {
            MeteringError::Conflict("refund arrived before its paid checkout".to_string())
        })?;
    let billing_account_id: String = row.get(0);
    let original_cents: i64 = row.get(1);
    let original_currency: String = row.get(2);
    if refund.amount_cents > original_cents || refund.currency != original_currency {
        return Err(MeteringError::Conflict(
            "Stripe refund does not match paid checkout".to_string(),
        ));
    }
    let insert_event_sql = format!(
        "INSERT INTO {schema}.stripe_events (
            event_id, event_type, payload_sha256, livemode, processed_at_ms
         ) VALUES ($1, 'refund.succeeded', $2, $3, $4)"
    );
    transaction
        .execute(
            &insert_event_sql,
            &[
                &refund.event_id,
                &refund.payload_sha256,
                &refund.livemode,
                &refund.processed_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("record Stripe refund event", error))?;
    let amount_nanos = i128::from(refund.amount_cents)
        .checked_mul(10_000_000)
        .and_then(i128::checked_neg)
        .ok_or(MeteringError::Overflow)?
        .to_string();
    let entry_id = format!("stripe-refund/{}", refund.stripe_refund_id);
    let credit_sql = format!(
        "INSERT INTO {schema}.credit_ledger_entries (
            entry_id, billing_account_id, kind, amount_nanos, currency,
            external_reference, effective_at_ms
         ) VALUES ($1, $2, 'stripe_refund', $3::text::numeric, $4, $5, $6)
         ON CONFLICT (entry_id) DO NOTHING"
    );
    transaction
        .execute(
            &credit_sql,
            &[
                &entry_id,
                &billing_account_id,
                &amount_nanos,
                &refund.currency,
                &entry_id,
                &refund.processed_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("reverse refunded Stripe credit", error))?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit Stripe refund", error))?;
    Ok(CreditApplyOutcome::Accepted)
}

fn source_epoch_attribution(
    client: &mut Client,
    schema: &str,
    source_id: &str,
    source_epoch: &str,
) -> Result<Option<UsageAttribution>> {
    let sql = format!(
        "SELECT billing_account_id, workspace_id, resource_type,
                resource_id, attributed_cat_id
           FROM {schema}.usage_checkpoints
          WHERE source_id=$1 AND source_epoch=$2
          LIMIT 1"
    );
    client
        .query_opt(&sql, &[&source_id, &source_epoch])
        .map(|row| row.map(|row| attribution_from_row(&row, 0)))
        .map_err(|error| pg_error("look up usage source epoch attribution", error))
}

fn spawn_worker(
    dsn: DsnSource,
    ca_file: Option<String>,
    schema: String,
    worker_index: usize,
    startup_timeout: Duration,
) -> Result<tokio_mpsc::Sender<Job>> {
    let (jobs, mut receiver) = tokio_mpsc::channel::<Job>(JOBS_PER_WORKER);
    let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(format!("cats-postgres-usage-{worker_index}"))
        .spawn(move || {
            let mut client = match connect_resolved(&dsn, ca_file.as_deref(), &schema) {
                Ok(client) => {
                    let _ = ready_tx.send(Ok(()));
                    client
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            while let Some(job) = receiver.blocking_recv() {
                // This worker previously had no reconnect at all: a dropped
                // connection left it running every later job against a dead
                // client, so usage ingestion stayed broken until the process
                // restarted -- and after a credential rotation, restarting is
                // exactly what cannot succeed.
                if client.is_closed() {
                    match connect_resolved(&dsn, ca_file.as_deref(), &schema) {
                        Ok(reconnected) => client = reconnected,
                        Err(error) => {
                            job(Err(error));
                            continue;
                        }
                    }
                }
                job(Ok(&mut client));
            }
        })
        .map_err(|error| MeteringError::Store(format!("start PostgreSQL usage worker: {error}")))?;
    // The synchronous postgres handshake has no cancellation handle. A timed
    // out constructor drops the queue and fails startup; at most this one
    // fixed worker remains blocked until the daemon exits.
    match ready_rx.recv_timeout(startup_timeout) {
        Ok(result) => result?,
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            return Err(MeteringError::Store(
                "PostgreSQL usage worker startup timed out; restart required".into(),
            ));
        }
        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
            return Err(MeteringError::Store(
                "PostgreSQL usage worker exited at startup".into(),
            ));
        }
    }
    Ok(jobs)
}

/// The one place a connection is established, so the DSN is resolved on every
/// attempt -- first connect and every reconnect alike.
fn connect_resolved(dsn: &DsnSource, ca_file: Option<&str>, schema: &str) -> Result<Client> {
    connect_client(&dsn.resolve()?, ca_file, schema)
}

fn connect_client(url: &str, ca_file: Option<&str>, schema: &str) -> Result<Client> {
    let connector = tls_connector(ca_file)?;
    let config = client_config(url)?;
    let mut client = config
        .connect(MakeTlsConnector::new(connector))
        .map_err(|error| pg_error("connect PostgreSQL", error))?;
    configure_session(&mut client)?;
    migrate(&mut client, schema)?;
    Ok(client)
}

fn client_config(url: &str) -> Result<postgres::Config> {
    let mut config: postgres::Config = url
        .parse()
        .map_err(|error| MeteringError::Store(format!("parse PostgreSQL URL: {error}")))?;
    config.connect_timeout(CONNECT_TIMEOUT);
    Ok(config)
}

/// Apply the same server-side failure bounds on the initial connection and
/// every reconnect before either migrations or usage work can claim a worker.
fn configure_session(client: &mut Client) -> Result<()> {
    let sql = format!(
        "SET statement_timeout = '{}ms'; SET lock_timeout = '{}ms'",
        STATEMENT_TIMEOUT.as_millis(),
        LOCK_TIMEOUT.as_millis(),
    );
    client
        .batch_execute(&sql)
        .map_err(|error| pg_error("configure PostgreSQL usage session", error))
}

fn tls_connector(ca_file: Option<&str>) -> Result<TlsConnector> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = ca_file {
        let pem = fs::read(path).map_err(|error| {
            MeteringError::Store(format!("read PostgreSQL CA file {path:?}: {error}"))
        })?;
        let certificates = pem_certificates(&pem)?;
        if certificates.is_empty() {
            return Err(MeteringError::Invalid(format!(
                "PostgreSQL CA file {path:?} contains no certificates"
            )));
        }
        for certificate in certificates {
            builder.add_root_certificate(certificate);
        }
    }
    builder
        .build()
        .map_err(|error| MeteringError::Store(format!("build PostgreSQL TLS client: {error}")))
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<Certificate>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut rest = pem;
    while let Some(start) = find_bytes(rest, BEGIN) {
        let candidate = &rest[start..];
        let Some(end) = find_bytes(candidate, END) else {
            return Err(MeteringError::Invalid(
                "PostgreSQL CA file has an unterminated certificate".into(),
            ));
        };
        let end = end + END.len();
        certificates.push(Certificate::from_pem(&candidate[..end]).map_err(|error| {
            MeteringError::Invalid(format!("parse PostgreSQL CA certificate: {error}"))
        })?);
        rest = &candidate[end..];
    }
    Ok(certificates)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn validate_schema_name(schema: &str) -> Result<()> {
    let mut chars = schema.chars();
    let valid_start = chars
        .next()
        .is_some_and(|value| value == '_' || value.is_ascii_lowercase());
    if !valid_start
        || schema.len() > 63
        || !chars.all(|value| value == '_' || value.is_ascii_lowercase() || value.is_ascii_digit())
    {
        return Err(MeteringError::Invalid(
            "PostgreSQL usage schema must match [a-z_][a-z0-9_]{0,62}".to_string(),
        ));
    }
    Ok(())
}

fn migrate(client: &mut Client, schema: &str) -> Result<()> {
    let sql = migration_sql(schema);
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start usage migration", error))?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('cats-usage-schema-v1', 0))",
            &[],
        )
        .map_err(|error| pg_error("lock usage migration", error))?;
    transaction
        .batch_execute(&sql)
        .map_err(|error| pg_error("migrate usage schema", error))?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit usage migration", error))
}

fn migration_sql(schema: &str) -> String {
    format!(
        r#"
CREATE SCHEMA IF NOT EXISTS {schema};
CREATE TABLE IF NOT EXISTS {schema}.schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS {schema}.usage_checkpoints (
    event_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    observed_at_ms BIGINT NOT NULL CHECK (observed_at_ms >= 0),
    metric TEXT NOT NULL,
    cumulative_quantity NUMERIC(39, 0) NOT NULL CHECK (cumulative_quantity >= 0),
    billing_account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attributed_cat_id TEXT,
    payload_json TEXT NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (source_id, source_epoch, metric, sequence)
);
CREATE INDEX IF NOT EXISTS usage_checkpoints_account_time_idx
    ON {schema}.usage_checkpoints (billing_account_id, observed_at_ms);
CREATE TABLE IF NOT EXISTS {schema}.usage_intervals (
    end_event_id TEXT PRIMARY KEY
        REFERENCES {schema}.usage_checkpoints(event_id),
    start_event_id TEXT NOT NULL
        REFERENCES {schema}.usage_checkpoints(event_id),
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    end_sequence BIGINT NOT NULL CHECK (end_sequence >= 0),
    interval_start_ms BIGINT NOT NULL,
    interval_end_ms BIGINT NOT NULL,
    metric TEXT NOT NULL,
    quantity NUMERIC(39, 0) NOT NULL CHECK (quantity >= 0),
    billing_account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attributed_cat_id TEXT,
    CHECK (interval_end_ms > interval_start_ms)
);
CREATE INDEX IF NOT EXISTS usage_intervals_account_time_idx
    ON {schema}.usage_intervals
        (billing_account_id, interval_start_ms, interval_end_ms);
CREATE INDEX IF NOT EXISTS usage_intervals_cat_time_idx
    ON {schema}.usage_intervals
        (attributed_cat_id, interval_start_ms, interval_end_ms);
CREATE OR REPLACE FUNCTION {schema}.reject_usage_checkpoint_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'usage checkpoints are insert-only';
END
$function$;
DROP TRIGGER IF EXISTS usage_checkpoints_insert_only
    ON {schema}.usage_checkpoints;
CREATE TRIGGER usage_checkpoints_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_checkpoints
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_checkpoint_mutation();
INSERT INTO {schema}.schema_migrations (version)
VALUES (1) ON CONFLICT (version) DO NOTHING;
DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM {schema}.schema_migrations WHERE version = 2
    ) THEN
        ALTER TABLE {schema}.usage_checkpoints
            ALTER COLUMN cumulative_quantity TYPE NUMERIC(39, 0)
            USING cumulative_quantity::numeric;
        ALTER TABLE {schema}.usage_intervals
            ALTER COLUMN quantity TYPE NUMERIC(39, 0)
            USING quantity::numeric;
        INSERT INTO {schema}.schema_migrations (version) VALUES (2);
    END IF;
END
$migration$;
CREATE TABLE IF NOT EXISTS {schema}.billing_accounts (
    billing_account_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency = 'USD'),
    stripe_customer_id TEXT,
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0)
);
CREATE TABLE IF NOT EXISTS {schema}.credit_ledger_entries (
    entry_id TEXT PRIMARY KEY,
    billing_account_id TEXT NOT NULL
        REFERENCES {schema}.billing_accounts(billing_account_id),
    kind TEXT NOT NULL,
    amount_nanos NUMERIC(39, 0) NOT NULL,
    currency TEXT NOT NULL CHECK (currency = 'USD'),
    external_reference TEXT NOT NULL UNIQUE,
    effective_at_ms BIGINT NOT NULL CHECK (effective_at_ms >= 0)
);
CREATE INDEX IF NOT EXISTS credit_ledger_account_time_idx
    ON {schema}.credit_ledger_entries (billing_account_id, effective_at_ms);
CREATE OR REPLACE FUNCTION {schema}.reject_credit_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'credit ledger entries are insert-only';
END
$function$;
DROP TRIGGER IF EXISTS credit_ledger_insert_only
    ON {schema}.credit_ledger_entries;
CREATE TRIGGER credit_ledger_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.credit_ledger_entries
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_credit_ledger_mutation();
CREATE TABLE IF NOT EXISTS {schema}.checkout_intents (
    intent_id TEXT PRIMARY KEY,
    billing_account_id TEXT NOT NULL
        REFERENCES {schema}.billing_accounts(billing_account_id),
    account_id TEXT NOT NULL,
    amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
    currency TEXT NOT NULL CHECK (currency = 'USD'),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    stripe_session_id TEXT UNIQUE,
    checkout_url TEXT,
    stripe_payment_intent_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'paid'))
);
CREATE TABLE IF NOT EXISTS {schema}.stripe_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    livemode BOOLEAN NOT NULL,
    processed_at_ms BIGINT NOT NULL CHECK (processed_at_ms >= 0)
);
INSERT INTO {schema}.schema_migrations (version)
VALUES (3) ON CONFLICT (version) DO NOTHING;
DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM {schema}.schema_migrations WHERE version = 4
    ) THEN
        -- The Project -> Account rename (ADR-0018) changed this column in the
        -- CREATE DDL without migrating databases that already had the table.
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = '{schema}'
              AND table_name = 'billing_accounts'
              AND column_name = 'project_id'
        ) THEN
            ALTER TABLE {schema}.billing_accounts
                RENAME COLUMN project_id TO account_id;
        END IF;
        INSERT INTO {schema}.schema_migrations (version) VALUES (4);
    END IF;
END
$migration$;
DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM {schema}.schema_migrations WHERE version = 5
    ) THEN
        -- Remaining legacy project_id columns from the same pre-rename shape:
        -- the usage tables track the Workspace, checkout intents the Account.
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = '{schema}'
              AND table_name = 'usage_checkpoints'
              AND column_name = 'project_id'
        ) THEN
            ALTER TABLE {schema}.usage_checkpoints
                RENAME COLUMN project_id TO workspace_id;
        END IF;
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = '{schema}'
              AND table_name = 'usage_intervals'
              AND column_name = 'project_id'
        ) THEN
            ALTER TABLE {schema}.usage_intervals
                RENAME COLUMN project_id TO workspace_id;
        END IF;
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = '{schema}'
              AND table_name = 'checkout_intents'
              AND column_name = 'project_id'
        ) THEN
            ALTER TABLE {schema}.checkout_intents
                RENAME COLUMN project_id TO account_id;
        END IF;
        INSERT INTO {schema}.schema_migrations (version) VALUES (5);
    END IF;
END
$migration$;
"#
    )
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
    fn from_value(value: &AttributedCheckpoint) -> Self {
        Self {
            event_id: value.checkpoint.event_id.clone(),
            source_id: value.checkpoint.source_id.clone(),
            source_epoch: value.checkpoint.source_epoch.clone(),
            sequence: value.checkpoint.sequence,
            observed_at_unix_ms: value.checkpoint.observed_at_unix_ms,
            metric: value.checkpoint.metric,
            cumulative_quantity: value.checkpoint.cumulative_quantity,
            attribution: value.attribution.clone(),
        }
    }
}

fn ingest_checkpoint(
    client: &mut Client,
    schema: &str,
    value: &AttributedCheckpoint,
) -> Result<IngestOutcome> {
    validate_checkpoint(value)?;
    let sequence = signed(value.checkpoint.sequence, "sequence")?;
    let cumulative_quantity = value.checkpoint.cumulative_quantity.to_string();
    let payload = serde_json::to_string(&value.checkpoint)?;
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start usage ingestion", error))?;
    let epoch_lock = format!(
        "{}:{}{}",
        value.checkpoint.source_id.len(),
        value.checkpoint.source_id,
        value.checkpoint.source_epoch
    );
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&epoch_lock],
        )
        .map_err(|error| pg_error("lock usage source epoch", error))?;

    let existing_sql = format!(
        "SELECT payload_json, billing_account_id, workspace_id,
                resource_type, resource_id, attributed_cat_id
           FROM {schema}.usage_checkpoints WHERE event_id=$1"
    );
    if let Some(row) = transaction
        .query_opt(&existing_sql, &[&value.checkpoint.event_id])
        .map_err(|error| pg_error("look up usage event", error))?
    {
        let existing_payload: String = row.get(0);
        let existing_attribution = attribution_from_row(&row, 1);
        if existing_payload == payload && existing_attribution == value.attribution {
            transaction
                .commit()
                .map_err(|error| pg_error("commit duplicate usage event", error))?;
            return Ok(IngestOutcome::Duplicate);
        }
        return Err(MeteringError::Conflict(format!(
            "event {} was replayed with a different payload",
            value.checkpoint.event_id
        )));
    }

    let attribution_sql = format!(
        "SELECT billing_account_id, workspace_id, resource_type,
                resource_id, attributed_cat_id
           FROM {schema}.usage_checkpoints
          WHERE source_id=$1 AND source_epoch=$2
          LIMIT 1"
    );
    if let Some(row) = transaction
        .query_opt(
            &attribution_sql,
            &[&value.checkpoint.source_id, &value.checkpoint.source_epoch],
        )
        .map_err(|error| pg_error("look up usage attribution", error))?
    {
        if attribution_from_row(&row, 0) != value.attribution {
            return Err(MeteringError::Conflict(
                "attribution changed inside one source epoch".to_string(),
            ));
        }
    }

    let previous = adjacent_checkpoint(&mut transaction, schema, value, sequence, true)?;
    let next = adjacent_checkpoint(&mut transaction, schema, value, sequence, false)?;
    validate_adjacent(value, previous.as_ref(), next.as_ref())?;

    let insert_sql = format!(
        "INSERT INTO {schema}.usage_checkpoints (
            event_id, source_id, source_epoch, sequence, observed_at_ms,
            metric, cumulative_quantity, billing_account_id, workspace_id,
            resource_type, resource_id, attributed_cat_id, payload_json
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7::text::numeric,$8,$9,$10,$11,$12,$13
         )"
    );
    transaction
        .execute(
            &insert_sql,
            &[
                &value.checkpoint.event_id,
                &value.checkpoint.source_id,
                &value.checkpoint.source_epoch,
                &sequence,
                &value.checkpoint.observed_at_unix_ms,
                &value.checkpoint.metric.slug(),
                &cumulative_quantity,
                &value.attribution.billing_account_id,
                &value.attribution.workspace_id,
                &value.attribution.resource_type,
                &value.attribution.resource_id,
                &value.attribution.attributed_cat_id,
                &payload,
            ],
        )
        .map_err(|error| pg_error("insert usage checkpoint", error))?;

    if let (Some(previous), Some(next)) = (&previous, &next) {
        let delete_sql = format!(
            "DELETE FROM {schema}.usage_intervals
              WHERE start_event_id=$1 AND end_event_id=$2"
        );
        transaction
            .execute(&delete_sql, &[&previous.event_id, &next.event_id])
            .map_err(|error| pg_error("repair usage interval", error))?;
    }
    let current = StoredCheckpoint::from_value(value);
    if let Some(previous) = previous {
        insert_interval(&mut transaction, schema, &previous, &current)?;
    }
    if let Some(next) = next {
        insert_interval(&mut transaction, schema, &current, &next)?;
    }
    transaction
        .commit()
        .map_err(|error| pg_error("commit usage checkpoint", error))?;
    Ok(IngestOutcome::Accepted)
}

fn adjacent_checkpoint(
    transaction: &mut Transaction<'_>,
    schema: &str,
    value: &AttributedCheckpoint,
    sequence: i64,
    previous: bool,
) -> Result<Option<StoredCheckpoint>> {
    let (comparison, order) = if previous {
        ("<", "DESC")
    } else {
        (">", "ASC")
    };
    let sql = format!(
        "SELECT event_id, source_id, source_epoch, sequence, observed_at_ms,
                metric, cumulative_quantity::text, billing_account_id, workspace_id,
                resource_type, resource_id, attributed_cat_id
           FROM {schema}.usage_checkpoints
          WHERE source_id=$1 AND source_epoch=$2 AND metric=$3
            AND sequence {comparison} $4
          ORDER BY sequence {order}
          LIMIT 1"
    );
    transaction
        .query_opt(
            &sql,
            &[
                &value.checkpoint.source_id,
                &value.checkpoint.source_epoch,
                &value.checkpoint.metric.slug(),
                &sequence,
            ],
        )
        .map_err(|error| pg_error("look up adjacent usage checkpoint", error))?
        .map(|row| stored_checkpoint_from_row(&row))
        .transpose()
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
    transaction: &mut Transaction<'_>,
    schema: &str,
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
    let end_sequence = signed(end.sequence, "end sequence")?;
    let quantity = quantity.to_string();
    let sql = format!(
        "INSERT INTO {schema}.usage_intervals (
            end_event_id, start_event_id, source_id, source_epoch,
            end_sequence, interval_start_ms, interval_end_ms, metric,
            quantity, billing_account_id, workspace_id, resource_type,
            resource_id, attributed_cat_id
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11,$12,$13,$14
         )
         ON CONFLICT (end_event_id) DO UPDATE SET
            start_event_id=EXCLUDED.start_event_id,
            source_id=EXCLUDED.source_id,
            source_epoch=EXCLUDED.source_epoch,
            end_sequence=EXCLUDED.end_sequence,
            interval_start_ms=EXCLUDED.interval_start_ms,
            interval_end_ms=EXCLUDED.interval_end_ms,
            metric=EXCLUDED.metric,
            quantity=EXCLUDED.quantity,
            billing_account_id=EXCLUDED.billing_account_id,
            workspace_id=EXCLUDED.workspace_id,
            resource_type=EXCLUDED.resource_type,
            resource_id=EXCLUDED.resource_id,
            attributed_cat_id=EXCLUDED.attributed_cat_id"
    );
    transaction
        .execute(
            &sql,
            &[
                &end.event_id,
                &start.event_id,
                &end.source_id,
                &end.source_epoch,
                &end_sequence,
                &start.observed_at_unix_ms,
                &end.observed_at_unix_ms,
                &end.metric.slug(),
                &quantity,
                &end.attribution.billing_account_id,
                &end.attribution.workspace_id,
                &end.attribution.resource_type,
                &end.attribution.resource_id,
                &end.attribution.attributed_cat_id,
            ],
        )
        .map(|_| ())
        .map_err(|error| pg_error("write usage interval", error))
}

fn query_usage(client: &mut Client, schema: &str, query: &UsageQuery) -> Result<UsageView> {
    validate_usage_query(query)?;
    let sql = format!(
        "SELECT interval_start_ms, interval_end_ms, quantity::text,
                billing_account_id, workspace_id, resource_type, resource_id,
                attributed_cat_id, metric, source_id, source_epoch, end_sequence
           FROM {schema}.usage_intervals
          WHERE billing_account_id=$1
            AND interval_end_ms>$2 AND interval_start_ms<$3
            AND ($4::text IS NULL OR workspace_id=$4)
            AND ($5::text IS NULL OR attributed_cat_id=$5)
          ORDER BY interval_start_ms, source_id, source_epoch,
                   end_sequence, metric"
    );
    let rows = client
        .query(
            &sql,
            &[
                &query.billing_account_id,
                &query.interval_start_unix_ms,
                &query.interval_end_unix_ms,
                &query.workspace_id,
                &query.attributed_cat_id,
            ],
        )
        .map_err(|error| pg_error("query usage intervals", error))?;
    let intervals = rows
        .iter()
        .map(usage_interval_from_row)
        .collect::<Result<Vec<_>>>()?;
    usage_view_from_intervals(query, intervals)
}

/// Totals for the window, aggregated by PostgreSQL rather than by returning
/// every interval for the caller to fold.
///
/// This is the admission path. `query_usage` is unbounded below there
/// (`interval_start_unix_ms: 0`), so it selected, sorted and shipped every
/// interval a Billing Account had ever accrued -- growing without limit and
/// putting a no-op `exec` at ~35 s while the node agent answered the same call
/// in 2 ms.
///
/// The arithmetic mirrors `usage_view_from_intervals` exactly: prorate by the
/// overlap and truncate **per row** with `div`, then sum. `div` truncates toward
/// zero like the integer division the fold performs; summing before dividing
/// would round differently and mis-bill. `HAVING` reproduces the fold skipping
/// zero-quantity intervals, so a metric that contributes nothing is absent
/// rather than present with zero.
fn query_usage_totals(
    client: &mut Client,
    schema: &str,
    query: &UsageQuery,
) -> Result<UsageTotals> {
    validate_usage_query(query)?;
    let prorated = "div(quantity * (LEAST(interval_end_ms, $3) - GREATEST(interval_start_ms, $2))::numeric,                     (interval_end_ms - interval_start_ms)::numeric)";
    let sql = format!(
        "SELECT metric, SUM({prorated})::text, MAX(LEAST(interval_end_ms, $3))
           FROM {schema}.usage_intervals
          WHERE billing_account_id=$1
            AND interval_end_ms>$2 AND interval_start_ms<$3
            AND LEAST(interval_end_ms, $3) > GREATEST(interval_start_ms, $2)
            AND ($4::text IS NULL OR workspace_id=$4)
            AND ($5::text IS NULL OR attributed_cat_id=$5)
          GROUP BY metric"
    );
    let rows = client
        .query(
            &sql,
            &[
                &query.billing_account_id,
                &query.interval_start_unix_ms,
                &query.interval_end_unix_ms,
                &query.workspace_id,
                &query.attributed_cat_id,
            ],
        )
        .map_err(|error| pg_error("aggregate usage totals", error))?;
    let mut totals = Vec::new();
    let mut latest_interval_end_unix_ms: Option<i64> = None;
    for row in &rows {
        let metric: String = row.get(0);
        let quantity: String = row.get(1);
        let latest_end: i64 = row.get(2);
        let metric = metric_from_slug(&metric)?;
        let quantity = quantity
            .parse::<u128>()
            .map_err(|_| MeteringError::Invalid(format!("usage total {quantity} is not a u128")))?;
        // The fold records a row's clipped end before it discards a zero
        // quantity, so a metric that prorates entirely to zero still advances
        // how far usage is visible. Filtering zero here rather than in `HAVING`
        // keeps that: the group is dropped from the totals, not from the max.
        if quantity > 0 {
            totals.push(UsageAggregate { metric, quantity });
        }
        latest_interval_end_unix_ms = Some(
            latest_interval_end_unix_ms
                .unwrap_or(i64::MIN)
                .max(latest_end),
        );
    }
    totals.sort_by_key(|aggregate| aggregate.metric.slug());
    Ok(UsageTotals {
        totals,
        latest_interval_end_unix_ms,
    })
}

fn stored_checkpoint_from_row(row: &Row) -> Result<StoredCheckpoint> {
    Ok(StoredCheckpoint {
        event_id: row.get(0),
        source_id: row.get(1),
        source_epoch: row.get(2),
        sequence: unsigned(row.get(3), "stored sequence")?,
        observed_at_unix_ms: row.get(4),
        metric: metric_from_slug(&row.get::<_, String>(5))?,
        cumulative_quantity: decimal_u128(&row.get::<_, String>(6), "stored cumulative quantity")?,
        attribution: attribution_from_row(row, 7),
    })
}

fn usage_interval_from_row(row: &Row) -> Result<UsageInterval> {
    Ok(UsageInterval {
        interval_start_unix_ms: row.get(0),
        interval_end_unix_ms: row.get(1),
        quantity: decimal_u128(&row.get::<_, String>(2), "stored interval quantity")?,
        attribution: attribution_from_row(row, 3),
        metric: metric_from_slug(&row.get::<_, String>(8))?,
        source_id: row.get(9),
        source_epoch: row.get(10),
        end_sequence: unsigned(row.get(11), "stored end sequence")?,
    })
}

fn attribution_from_row(row: &Row, offset: usize) -> UsageAttribution {
    UsageAttribution {
        billing_account_id: row.get(offset),
        workspace_id: row.get(offset + 1),
        resource_type: row.get(offset + 2),
        resource_id: row.get(offset + 3),
        attributed_cat_id: row.get(offset + 4),
    }
}

fn signed(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        MeteringError::Invalid(format!("{field} exceeds PostgreSQL's signed 64-bit range"))
    })
}

fn unsigned(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| MeteringError::Store(format!("{field} is negative in PostgreSQL")))
}

fn decimal_u128(value: &str, field: &str) -> Result<u128> {
    value
        .parse()
        .map_err(|_| MeteringError::Store(format!("{field} is not a valid u128 in PostgreSQL")))
}

fn pg_error(context: &str, error: postgres::Error) -> MeteringError {
    if let Some(database_error) = error.as_db_error() {
        let detail = database_error
            .detail()
            .map(|value| format!("; {value}"))
            .unwrap_or_default();
        MeteringError::Store(format!(
            "{context}: {} [{}]{detail}",
            database_error.message(),
            database_error.code().code()
        ))
    } else {
        MeteringError::Store(format!("{context}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_metering::{deterministic_event_id, UsageAggregate};

    async fn drop_test_schema(url: String, schema: String) {
        tokio::task::spawn_blocking(move || {
            let mut cleanup = connect_client(&url, None, &schema).unwrap();
            cleanup
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                .unwrap();
        })
        .await
        .expect("join PostgreSQL test schema cleanup");
    }

    /// The worker resolves this on every connect, so a rotated credential
    /// reaches the next reconnect instead of waiting for a restart that a
    /// stale credential would prevent anyway.
    #[test]
    fn the_dsn_is_read_again_for_every_connect() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-postgres-url");
        let dsn = DsnSource::File(path.clone());

        fs::write(&path, "postgres://cats:before@db.example/cats\n").unwrap();
        assert_eq!(
            dsn.resolve().unwrap(),
            "postgres://cats:before@db.example/cats"
        );

        fs::write(&path, "postgres://cats:after@db.example/cats\n").unwrap();
        assert_eq!(
            dsn.resolve().unwrap(),
            "postgres://cats:after@db.example/cats"
        );
    }

    #[test]
    fn an_absent_or_empty_dsn_file_is_reported_as_such() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");
        let error = DsnSource::File(missing.clone()).resolve().unwrap_err();
        assert!(error.to_string().contains(&missing.display().to_string()));

        let empty = directory.path().join("empty");
        fs::write(&empty, "\n\n").unwrap();
        let error = DsnSource::File(empty).resolve().unwrap_err();
        assert!(error.to_string().contains("is empty"), "{error}");
    }

    #[test]
    fn a_literal_dsn_stays_fixed() {
        let dsn = DsnSource::Literal("postgres://cats@db.example/cats".to_string());
        assert_eq!(dsn.resolve().unwrap(), "postgres://cats@db.example/cats");
    }

    /// A renderer writes this file, and a trailing newline is the norm. Left
    /// in, it becomes part of the database name and the failure is baffling.
    #[test]
    fn surrounding_whitespace_is_not_part_of_the_dsn() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-postgres-url");
        fs::write(&path, "  postgres://cats@db.example/cats\n").unwrap();
        assert_eq!(
            DsnSource::File(path).resolve().unwrap(),
            "postgres://cats@db.example/cats"
        );
    }

    /// The DSN carries the password. An error about the file may name the
    /// file; it may never quote what is inside it.
    #[test]
    fn a_dsn_file_error_never_quotes_the_credential() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-postgres-url");
        fs::write(&path, "not a dsn but it contains hunter2\n").unwrap();
        let resolved = DsnSource::File(path).resolve().unwrap();
        // Resolution does not validate; the driver rejects a bad DSN. What
        // matters is that the value never lands in one of our messages.
        assert!(resolved.contains("hunter2"));

        // A directory cannot be read as a file, so this exercises the same
        // error path with contents that must not be echoed.
        let error = DsnSource::File(directory.path().to_path_buf())
            .resolve()
            .unwrap_err()
            .to_string();
        assert!(!error.contains("hunter2"), "credential leaked: {error}");
    }

    /// A worker that cannot reconnect must say so. Before this change the job
    /// was dropped unrun and the caller saw "operation was canceled", which
    /// says nothing about the credential that actually failed.
    #[test]
    fn a_worker_without_a_connection_reports_the_reason() {
        let (jobs, receiver) = std_mpsc::channel::<Job>();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        jobs.send(Box::new(move |client| {
            let _ = result_tx.send(match client {
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            });
        }))
        .unwrap();
        drop(jobs);

        for job in receiver {
            job(Err(MeteringError::Store(
                "connect PostgreSQL: FATAL password authentication failed [28P01]".to_string(),
            )));
        }

        let error = result_rx.recv().unwrap().unwrap_err();
        assert!(
            error.to_string().contains("password authentication failed"),
            "the reason must survive the worker boundary: {error}"
        );
    }

    #[test]
    fn schema_names_are_strictly_validated() {
        assert!(validate_schema_name("cats_usage_1").is_ok());
        for invalid in ["", "Cats", "1cats", "cats-usage", "cats.usage"] {
            assert!(matches!(
                validate_schema_name(invalid),
                Err(MeteringError::Invalid(_))
            ));
        }
    }

    #[test]
    fn credit_accounts_can_start_without_signup_credit() {
        assert!(validate_credit_account("billing/account-a", "account-a", "USD", 0, 0).is_ok());
        assert!(matches!(
            validate_credit_account("billing/account-a", "account-a", "USD", -1, 0),
            Err(MeteringError::Invalid(_))
        ));
    }

    #[test]
    fn migration_makes_raw_checkpoints_insert_only() {
        let sql = migration_sql("cats_usage");
        assert!(sql.contains("BEFORE UPDATE OR DELETE"));
        assert!(sql.contains("usage_intervals"));
        assert!(sql.contains("schema_migrations"));
        assert!(sql.contains("NUMERIC(39, 0)"));
        assert!(sql.contains("version = 2"));
        assert!(sql.contains("VALUES (3) ON CONFLICT"));
        // Rungs 4 and 5 heal databases created before the Project -> Account/
        // Workspace rename, where the tables still carry project_id.
        assert!(sql.contains("version = 4"));
        assert!(sql.contains("RENAME COLUMN project_id TO account_id"));
        assert!(sql.contains("version = 5"));
        assert!(sql.contains("RENAME COLUMN project_id TO workspace_id"));
        assert!(sql.contains("credit_ledger_entries"));
        assert!(sql.contains("checkout_intents"));
        assert!(sql.contains("stripe_events"));
        assert!(sql.contains("reject_credit_ledger_mutation"));
    }

    #[test]
    fn a_silent_postgres_peer_cannot_block_worker_startup() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, released) = std_mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            released.recv().unwrap();
            drop(stream);
        });
        let dsn = DsnSource::Literal(format!("postgres://cats@{address}/cats?sslmode=disable"));
        let started = Instant::now();
        let error = PostgresUsageStore::connect_from_with_timeouts(
            &dsn,
            None,
            "cats_usage_silent_startup",
            1,
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
        .err()
        .expect("silent PostgreSQL peer unexpectedly completed startup");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "silent peer exceeded the worker startup wall-clock bound"
        );
        assert!(error.to_string().contains("startup timed out"), "{error}");
        release.send(()).unwrap();
        peer.join().unwrap();
    }

    #[tokio::test]
    async fn a_dispatch_deadline_poisons_the_store_and_skips_queued_effects() {
        let url = std::env::var("CATS_TEST_POSTGRES_URL")
            .expect("CATS_TEST_POSTGRES_URL is required for PostgreSQL usage tests");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("cats_usage_poison_{}_{}", std::process::id(), suffix);
        let store = Arc::new(
            PostgresUsageStore::connect_from_with_timeouts(
                &DsnSource::Literal(url.clone()),
                None,
                &schema,
                1,
                Duration::from_secs(10),
                Duration::from_millis(200),
            )
            .unwrap(),
        );
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std_mpsc::channel();
        let slow_store = Arc::clone(&store);
        let slow = tokio::spawn(async move {
            slow_store
                .dispatch(move |_| {
                    let _ = entered.send(());
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        entered_rx.await.unwrap();

        struct Processed(std_mpsc::Sender<()>);
        impl Drop for Processed {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let effects = Arc::new(AtomicUsize::new(0));
        let (processed, processed_rx) = std_mpsc::channel();
        let queued_store = Arc::clone(&store);
        let queued_effects = Arc::clone(&effects);
        let queued = tokio::spawn(async move {
            let processed = Processed(processed);
            queued_store
                .dispatch(move |_| {
                    let _processed = processed;
                    queued_effects.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
        });
        tokio::task::yield_now().await;

        let error = slow.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("restart required"), "{error}");
        let dispatches_before_rejection = store.next_worker.load(Ordering::SeqCst);
        let rejected = store.dispatch(|_| Ok(())).await.unwrap_err();
        assert_eq!(
            store.next_worker.load(Ordering::SeqCst),
            dispatches_before_rejection,
            "a poisoned store admitted another worker job"
        );
        assert!(
            rejected.to_string().contains("restart required"),
            "{rejected}"
        );
        assert!(queued
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("restart required"));

        release.send(()).unwrap();
        processed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker did not discard the queued effect after poison");
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        drop(store);
        drop_test_schema(url, schema).await;
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_a_worker_poisons_the_store() {
        let url = std::env::var("CATS_TEST_POSTGRES_URL")
            .expect("CATS_TEST_POSTGRES_URL is required for PostgreSQL usage tests");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("cats_usage_cancel_{}_{}", std::process::id(), suffix);
        let store = Arc::new(
            PostgresUsageStore::connect_from_with_timeouts(
                &DsnSource::Literal(url.clone()),
                None,
                &schema,
                1,
                Duration::from_secs(10),
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std_mpsc::channel();
        let (finished, finished_rx) = std_mpsc::channel();
        let cancelled_store = Arc::clone(&store);
        let cancelled = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(100),
                cancelled_store.dispatch(move |_| {
                    struct Finished(std_mpsc::Sender<()>);
                    impl Drop for Finished {
                        fn drop(&mut self) {
                            let _ = self.0.send(());
                        }
                    }

                    let _finished = Finished(finished);
                    let _ = entered.send(());
                    release_rx.recv().unwrap();
                    Ok(())
                }),
            )
            .await
        });
        entered_rx.await.unwrap();
        assert!(cancelled.await.unwrap().is_err());
        assert!(store.dispatch(|_| Ok(())).await.is_err());
        release.send(()).unwrap();
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled worker effect did not exit after release");
        drop(store);
        drop_test_schema(url, schema).await;
    }

    #[tokio::test]
    async fn connection_statement_and_lock_stalls_are_bounded_and_the_worker_recovers() {
        let url = std::env::var("CATS_TEST_POSTGRES_URL")
            .expect("CATS_TEST_POSTGRES_URL is required for PostgreSQL usage tests");
        assert_eq!(
            client_config(&url).unwrap().get_connect_timeout(),
            Some(&CONNECT_TIMEOUT),
            "every initial connection and reconnect must bound its socket attempt"
        );

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("cats_usage_bounds_{}_{}", std::process::id(), suffix);
        let store = PostgresUsageStore::connect(&url, None, &schema, 1).unwrap();
        let settings = store
            .dispatch(|client| {
                client
                    .query(
                        "SELECT name, setting FROM pg_settings
                          WHERE name IN ('statement_timeout', 'lock_timeout')",
                        &[],
                    )
                    .map(|rows| {
                        rows.into_iter()
                            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
                            .collect::<Vec<_>>()
                    })
                    .map_err(|error| pg_error("read usage session failure bounds", error))
            })
            .await
            .unwrap();
        for (name, expected) in [
            ("statement_timeout", STATEMENT_TIMEOUT.as_millis()),
            ("lock_timeout", LOCK_TIMEOUT.as_millis()),
        ] {
            let expected = expected.to_string();
            assert_eq!(
                settings
                    .iter()
                    .find_map(|(setting, value)| (setting == name).then_some(value.as_str())),
                Some(expected.as_str()),
                "{name} was not installed on the worker session"
            );
        }

        let worker_pid = store
            .dispatch(|client| {
                client
                    .query_one("SELECT pg_backend_pid()", &[])
                    .map(|row| row.get::<_, i32>(0))
                    .map_err(|error| pg_error("read usage worker backend pid", error))
            })
            .await
            .unwrap();
        let blocker_url = url.clone();
        let blocker_schema = schema.clone();
        let mut blocker = tokio::task::spawn_blocking(move || {
            let mut blocker = connect_client(&blocker_url, None, &blocker_schema).unwrap();
            assert!(blocker
                .query_one("SELECT pg_terminate_backend($1)", &[&worker_pid])
                .unwrap()
                .get::<_, bool>(0));
            blocker
        })
        .await
        .expect("join PostgreSQL worker termination setup");
        let first_reconnect = tokio::time::timeout(
            Duration::from_secs(10),
            store.dispatch(|client| {
                client
                    .query_one("SELECT 1::INT", &[])
                    .map(|row| row.get::<_, i32>(0))
                    .map_err(|error| pg_error("probe first bounded usage reconnect", error))
            }),
        )
        .await
        .expect("usage reconnect exceeded its connection bound");
        let reconnected = match first_reconnect {
            Ok(value) => value,
            Err(_) => tokio::time::timeout(
                Duration::from_secs(10),
                store.dispatch(|client| {
                    client
                        .query_one("SELECT 1::INT", &[])
                        .map(|row| row.get::<_, i32>(0))
                        .map_err(|error| pg_error("probe retried bounded usage reconnect", error))
                }),
            )
            .await
            .expect("retried usage reconnect exceeded its connection bound")
            .unwrap(),
        };
        assert_eq!(reconnected, 1);

        let statement_error = tokio::time::timeout(
            Duration::from_secs(10),
            store.dispatch(|client| {
                client
                    .simple_query("SELECT pg_sleep(30)")
                    .map(|_| ())
                    .map_err(|error| pg_error("exercise usage statement timeout", error))
            }),
        )
        .await
        .expect("server-side statement_timeout did not bound the worker")
        .unwrap_err();
        assert!(
            statement_error.to_string().contains("[57014]"),
            "statement was not canceled by PostgreSQL: {statement_error}"
        );
        assert_eq!(
            store
                .dispatch(|client| {
                    client
                        .query_one("SELECT 1::INT", &[])
                        .map(|row| row.get::<_, i32>(0))
                        .map_err(|error| pg_error("reuse worker after statement timeout", error))
                })
                .await
                .unwrap(),
            1
        );

        let lock_key = i64::try_from(suffix % u128::try_from(i64::MAX).unwrap()).unwrap();
        blocker = tokio::task::spawn_blocking(move || {
            blocker
                .query_one("SELECT pg_advisory_lock($1)", &[&lock_key])
                .unwrap();
            blocker
        })
        .await
        .expect("join PostgreSQL advisory-lock setup");
        let lock_result = tokio::time::timeout(
            Duration::from_secs(7),
            store.dispatch(move |client| {
                client
                    .query_one("SELECT pg_advisory_lock($1)", &[&lock_key])
                    .map(|_| ())
                    .map_err(|error| pg_error("exercise usage lock timeout", error))
            }),
        )
        .await;
        tokio::task::spawn_blocking(move || drop(blocker))
            .await
            .expect("join PostgreSQL advisory-lock release");
        let lock_error = lock_result
            .expect("server-side lock_timeout did not bound the worker")
            .unwrap_err();
        assert!(
            lock_error.to_string().contains("[55P03]"),
            "lock wait was not canceled by PostgreSQL: {lock_error}"
        );
        assert_eq!(
            store
                .dispatch(|client| {
                    client
                        .query_one("SELECT 1::INT", &[])
                        .map(|row| row.get::<_, i32>(0))
                        .map_err(|error| pg_error("reuse worker after lock timeout", error))
                })
                .await
                .unwrap(),
            1
        );

        store
            .dispatch(move |client| {
                client
                    .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                    .map_err(|error| pg_error("drop failure-bounds test schema", error))
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn live_postgres_matches_usage_contract_when_configured() {
        let Ok(url) = std::env::var("CATS_TEST_POSTGRES_URL") else {
            return;
        };
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("cats_usage_test_{}_{}", std::process::id(), suffix);
        let store = PostgresUsageStore::connect(&url, None, &schema, 2).unwrap();

        let make = |metric, sequence, observed_at_unix_ms, cumulative_quantity| {
            let mut checkpoint = cats_api::metering::CatUsageCheckpoint {
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
        };
        let first = make(UsageMetric::CpuUsec, 1, 1_000, 100);
        let middle = make(UsageMetric::CpuUsec, 2, 11_000, 900);
        let last = make(UsageMetric::CpuUsec, 3, 21_000, 2_100);
        assert_eq!(
            UsageStore::ingest(&store, &first).await.unwrap(),
            IngestOutcome::Accepted
        );
        assert_eq!(
            UsageStore::ingest(&store, &last).await.unwrap(),
            IngestOutcome::Accepted
        );
        assert_eq!(
            UsageStore::ingest(&store, &middle).await.unwrap(),
            IngestOutcome::Accepted
        );
        assert_eq!(
            UsageStore::ingest(&store, &last).await.unwrap(),
            IngestOutcome::Duplicate
        );
        let large_baseline = u128::try_from(i64::MAX).unwrap() + 10_000;
        let memory_first = make(UsageMetric::MemoryByteMillis, 1, 1_000, large_baseline);
        let memory_last = make(
            UsageMetric::MemoryByteMillis,
            2,
            21_000,
            large_baseline + 50_000,
        );
        UsageStore::ingest(&store, &memory_first).await.unwrap();
        UsageStore::ingest(&store, &memory_last).await.unwrap();
        let view = UsageStore::query(
            &store,
            &UsageQuery {
                billing_account_id: "ba-org-a".to_string(),
                workspace_id: None,
                attributed_cat_id: Some("cat-a".to_string()),
                interval_start_unix_ms: 1_000,
                interval_end_unix_ms: 21_000,
            },
        )
        .await
        .unwrap();
        assert!(view.totals.contains(&UsageAggregate {
            metric: UsageMetric::CpuUsec,
            quantity: 2_000,
        }));
        assert!(view.totals.contains(&UsageAggregate {
            metric: UsageMetric::MemoryByteMillis,
            quantity: 50_000,
        }));
        assert_eq!(view.details.len(), 3);

        store
            .dispatch(move |client| {
                client
                    .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                    .map_err(|error| pg_error("drop live-test usage schema", error))
            })
            .await
            .unwrap();
    }
}

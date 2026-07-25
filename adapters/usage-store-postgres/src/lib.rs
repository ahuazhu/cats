//! PostgreSQL production adapter for the cumulative usage ledger.
//!
//! Raw checkpoints are insert-only at the database boundary. Each source
//! epoch is serialized with a transaction-scoped PostgreSQL advisory lock so
//! duplicate, cross-metric attribution and out-of-order interval repair stay
//! deterministic even when several consumers replay concurrently.

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use cats_api::metering::UsageMetric;
use cats_metering::{
    metric_from_slug, usage_view_from_intervals, validate_checkpoint, validate_usage_query,
    AttributedCheckpoint, CheckoutIntent, CheckoutPayment, CheckoutRefund, CreditApplyOutcome,
    CreditStore, CreditStoreFuture, CreditSummary, IngestOutcome, MeteringError, Result,
    UsageAttribution, UsageInterval, UsageQuery, UsageStore, UsageStoreFuture, UsageView,
};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Row, Transaction};
use postgres_native_tls::MakeTlsConnector;

pub const DEFAULT_SCHEMA: &str = "cats_usage";
pub const DEFAULT_WORKERS: usize = 4;

type Job = Box<dyn FnOnce(&mut Client) + Send + 'static>;

/// A small fixed connection pool whose workers own synchronous PostgreSQL
/// clients. Callers await a Tokio oneshot, so database I/O never blocks an
/// async control-plane executor thread.
pub struct PostgresUsageStore {
    workers: Vec<mpsc::Sender<Job>>,
    next_worker: AtomicUsize,
    schema: String,
}

impl PostgresUsageStore {
    pub fn connect(url: &str, ca_file: Option<&str>, schema: &str, workers: usize) -> Result<Self> {
        validate_schema_name(schema)?;
        if !(1..=64).contains(&workers) {
            return Err(MeteringError::Invalid(
                "PostgreSQL usage workers must be in 1..=64".to_string(),
            ));
        }
        let mut senders = Vec::with_capacity(workers);
        for worker_index in 0..workers {
            senders.push(spawn_worker(
                url.to_string(),
                ca_file.map(str::to_string),
                schema.to_string(),
                worker_index,
            )?);
        }
        Ok(Self {
            workers: senders,
            next_worker: AtomicUsize::new(0),
            schema: schema.to_string(),
        })
    }

    async fn dispatch<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        let index = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.workers[index]
            .send(Box::new(move |client| {
                let _ = result_tx.send(operation(client));
            }))
            .map_err(|_| MeteringError::Store("PostgreSQL usage worker exited".to_string()))?;
        result_rx.await.map_err(|_| {
            MeteringError::Store("PostgreSQL usage operation was canceled".to_string())
        })?
    }
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
        project_id: &'a str,
        currency: &'a str,
        signup_credit_nanos: i128,
        created_at_unix_ms: i64,
    ) -> CreditStoreFuture<'a, CreditSummary> {
        let billing_account_id = billing_account_id.to_string();
        let project_id = project_id.to_string();
        let currency = currency.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| {
                pg_ensure_credit_account(
                    client,
                    &schema,
                    &billing_account_id,
                    &project_id,
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
    project_id: &str,
    currency: &str,
    signup_credit_nanos: i128,
    created_at_unix_ms: i64,
) -> Result<()> {
    if billing_account_id.is_empty()
        || project_id.is_empty()
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

fn validate_checkout_intent(intent: &CheckoutIntent) -> Result<()> {
    if intent.intent_id.is_empty()
        || intent.billing_account_id.is_empty()
        || intent.project_id.is_empty()
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

fn pg_ensure_credit_account(
    client: &mut Client,
    schema: &str,
    billing_account_id: &str,
    project_id: &str,
    currency: &str,
    signup_credit_nanos: i128,
    created_at_unix_ms: i64,
) -> Result<CreditSummary> {
    validate_credit_account(
        billing_account_id,
        project_id,
        currency,
        signup_credit_nanos,
        created_at_unix_ms,
    )?;
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start credit-account transaction", error))?;
    let account_sql = format!(
        "INSERT INTO {schema}.billing_accounts (
            billing_account_id, project_id, currency, created_at_ms
         ) VALUES ($1, $2, $3, $4)
         ON CONFLICT (billing_account_id) DO NOTHING"
    );
    transaction
        .execute(
            &account_sql,
            &[
                &billing_account_id,
                &project_id,
                &currency,
                &created_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("ensure billing account", error))?;
    let summary = pg_credit_summary_transaction(&mut transaction, schema, billing_account_id)?;
    if summary.project_id != project_id || summary.currency != currency {
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
        "SELECT project_id, currency, stripe_customer_id
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
        project_id: row.get(0),
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
        "SELECT project_id, currency, stripe_customer_id
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
        project_id: row.get(0),
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
        "SELECT intent_id, billing_account_id, project_id, amount_cents,
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
        project_id: row.get(2),
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
            intent_id, billing_account_id, project_id, amount_cents,
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
                &intent.project_id,
                &intent.amount_cents,
                &intent.currency,
                &intent.created_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("create checkout intent", error))?;
    let stored = pg_checkout_intent(client, schema, &intent.intent_id)?;
    if stored.billing_account_id != intent.billing_account_id
        || stored.project_id != intent.project_id
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
        "SELECT billing_account_id, project_id, resource_type,
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
    url: String,
    ca_file: Option<String>,
    schema: String,
    worker_index: usize,
) -> Result<mpsc::Sender<Job>> {
    let (jobs, receiver) = mpsc::channel::<Job>();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(format!("cats-postgres-usage-{worker_index}"))
        .spawn(
            move || match connect_client(&url, ca_file.as_deref(), &schema) {
                Ok(mut client) => {
                    let _ = ready_tx.send(Ok(()));
                    for job in receiver {
                        job(&mut client);
                    }
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            },
        )
        .map_err(|error| MeteringError::Store(format!("start PostgreSQL usage worker: {error}")))?;
    ready_rx
        .recv()
        .map_err(|_| MeteringError::Store("PostgreSQL usage worker exited at startup".into()))??;
    Ok(jobs)
}

fn connect_client(url: &str, ca_file: Option<&str>, schema: &str) -> Result<Client> {
    let connector = tls_connector(ca_file)?;
    let mut client = Client::connect(url, MakeTlsConnector::new(connector))
        .map_err(|error| pg_error("connect PostgreSQL", error))?;
    migrate(&mut client, schema)?;
    Ok(client)
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
    project_id TEXT NOT NULL,
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
    project_id TEXT NOT NULL,
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
    project_id TEXT NOT NULL,
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
    project_id TEXT NOT NULL,
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
        "SELECT payload_json, billing_account_id, project_id,
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
        "SELECT billing_account_id, project_id, resource_type,
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
            metric, cumulative_quantity, billing_account_id, project_id,
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
                &value.attribution.project_id,
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
                metric, cumulative_quantity::text, billing_account_id, project_id,
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
            quantity, billing_account_id, project_id, resource_type,
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
            project_id=EXCLUDED.project_id,
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
                &end.attribution.project_id,
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
                billing_account_id, project_id, resource_type, resource_id,
                attributed_cat_id, metric, source_id, source_epoch, end_sequence
           FROM {schema}.usage_intervals
          WHERE billing_account_id=$1
            AND interval_end_ms>$2 AND interval_start_ms<$3
            AND ($4::text IS NULL OR project_id=$4)
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
                &query.project_id,
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
        project_id: row.get(offset + 1),
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
        assert!(sql.contains("credit_ledger_entries"));
        assert!(sql.contains("checkout_intents"));
        assert!(sql.contains("stripe_events"));
        assert!(sql.contains("reject_credit_ledger_mutation"));
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
                    project_id: "project-a".to_string(),
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
                project_id: None,
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

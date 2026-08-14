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
    build_source_terminal_receipt, decode_terminal_receipt, metric_from_slug, sha256_prefixed,
    target_terminal_marker, target_terminal_request_sha256, usage_view_from_intervals,
    validate_archive_evidence, validate_checkout_intent, validate_checkout_payment,
    validate_checkout_refund, validate_checkpoint, validate_target_terminal_receipt,
    validate_target_terminal_request, validate_usage_query, ArchivedUsageCheckpoint,
    ArchivedUsageTerminalBarrier, AttributedCheckpoint, CheckoutIntent, CheckoutPayment,
    CheckoutRefund, CreditApplyOutcome, CreditStore, CreditStoreFuture, CreditSummary,
    IngestOutcome, MeteringError, Result, RuntimeUsageSourceBinding, UsageAggregate,
    UsageArchiveEvidence, UsageAttribution, UsageInterval, UsageQuery, UsageSourceTerminalReceipt,
    UsageStore, UsageStoreFuture, UsageTargetTerminalReceipt, UsageTargetTerminalRequest,
    UsageTargetTerminalState, UsageTerminalBarrierProjection, UsageTerminalPrepareOutcome,
    UsageTotals, UsageView,
};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Row, Transaction};
use postgres_native_tls::MakeTlsConnector;

pub const DEFAULT_SCHEMA: &str = "cats_usage";
pub const DEFAULT_WORKERS: usize = 4;
pub const USAGE_SCHEMA_VERSION: i32 = 16;
/// SHA-256 of the PostgreSQL-16 normalized catalog rows selected by
/// `USAGE_SCHEMA_V16_CATALOG_SQL`. This is a release protocol constant, not a
/// migration hint: any mismatch is refused without repair.
pub const USAGE_SCHEMA_V16_CATALOG_SHA256: &str =
    "sha256:ec10b4afe112dba411466e9b2d67d1cef5d8d232da4ec52c11ced993d771f157";
pub const USAGE_SCHEMA_V16_FUNCTION_PROSRC_SHA256: &[(&str, &str)] = &[
    (
        "reject_credit_ledger_mutation",
        "sha256:cdb5c3f99782490aaab6986cffe264cbcae9dcecf5b50f2143390ed120183b11",
    ),
    (
        "reject_usage_checkpoint_mutation",
        "sha256:3f7dac6e76c38bd26adce3f6353d452244aeaa8f0476b66e3dc1366cea70872d",
    ),
    (
        "reject_usage_terminal_mutation",
        "sha256:cf292f5255d98ef61ca15dc3d801863fcf63b63675d86902ddf67b32d278c9e0",
    ),
];
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const STATEMENT_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(10);
// One slot for each globally admitted signed-runtime request is sufficient
// even if all of them select the same worker. Other callers then backpressure
// instead of growing synchronous database work without a bound.
const JOBS_PER_WORKER: usize = 64;

/// PostgreSQL 16 canonicalizes DDL before returning it from `pg_get_*def`.
/// Hashing this complete, schema-name-neutral row set detects extra, missing or
/// altered relations, columns, constraints, indexes, user triggers, functions,
/// policies, rules and schema-owned scalar types. Internal FK triggers are
/// deliberately represented by their constraints instead of unstable OIDs.
const USAGE_SCHEMA_V16_CATALOG_SQL: &str = r#"
WITH catalog(kind, key1, key2, definition) AS (
    SELECT 'relation', class_row.relname, '',
           jsonb_build_array(
               class_row.relkind::text,
               class_row.relpersistence::text,
               COALESCE(access_method_row.amname, ''),
               class_row.relrowsecurity,
               class_row.relforcerowsecurity,
               class_row.relreplident::text,
               COALESCE(array_to_string(class_row.reloptions, E'\x1f'), '')
           )::text
      FROM pg_catalog.pg_class class_row
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=class_row.relnamespace
      LEFT JOIN pg_catalog.pg_am access_method_row ON access_method_row.oid=class_row.relam
     WHERE namespace_row.nspname=$1
    UNION ALL
    SELECT 'column', class_row.relname, attribute_row.attname,
           jsonb_build_array(
               attribute_row.attnum,
               pg_catalog.format_type(attribute_row.atttypid, attribute_row.atttypmod),
               attribute_row.attnotnull,
               attribute_row.attidentity::text,
               attribute_row.attgenerated::text,
               attribute_row.attstorage::text,
               attribute_row.attcompression::text,
               attribute_row.attstattarget,
               COALESCE(collation_row.collname, ''),
               COALESCE(replace(
                   pg_catalog.pg_get_expr(default_row.adbin, default_row.adrelid, true),
                   $1 || '.', '<schema>.'
               ), '')
           )::text
      FROM pg_catalog.pg_attribute attribute_row
      JOIN pg_catalog.pg_class class_row ON class_row.oid=attribute_row.attrelid
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=class_row.relnamespace
      LEFT JOIN pg_catalog.pg_attrdef default_row
        ON default_row.adrelid=attribute_row.attrelid
       AND default_row.adnum=attribute_row.attnum
      LEFT JOIN pg_catalog.pg_collation collation_row ON collation_row.oid=attribute_row.attcollation
     WHERE namespace_row.nspname=$1
       AND class_row.relkind IN ('r','p')
       AND attribute_row.attnum > 0
       AND NOT attribute_row.attisdropped
    UNION ALL
    SELECT 'constraint', class_row.relname, constraint_row.conname,
           jsonb_build_array(
               constraint_row.contype::text,
               constraint_row.condeferrable,
               constraint_row.condeferred,
               constraint_row.convalidated,
               constraint_row.connoinherit,
               replace(
                   pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
                   $1 || '.', '<schema>.'
               )
           )::text
      FROM pg_catalog.pg_constraint constraint_row
      JOIN pg_catalog.pg_class class_row ON class_row.oid=constraint_row.conrelid
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=class_row.relnamespace
     WHERE namespace_row.nspname=$1
    UNION ALL
    SELECT 'index', table_class.relname, index_class.relname,
           jsonb_build_array(
               index_row.indisunique,
               index_row.indisprimary,
               index_row.indisvalid,
               index_row.indisready,
               index_row.indisclustered,
               index_row.indnullsnotdistinct,
               replace(
                   pg_catalog.pg_get_indexdef(index_row.indexrelid, 0, true),
                   $1 || '.', '<schema>.'
               )
           )::text
      FROM pg_catalog.pg_index index_row
      JOIN pg_catalog.pg_class index_class ON index_class.oid=index_row.indexrelid
      JOIN pg_catalog.pg_class table_class ON table_class.oid=index_row.indrelid
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=table_class.relnamespace
     WHERE namespace_row.nspname=$1
    UNION ALL
    SELECT 'trigger', class_row.relname, trigger_row.tgname,
           jsonb_build_array(
               trigger_row.tgenabled::text,
               CASE WHEN function_namespace.nspname=$1
                    THEN '<schema>' ELSE function_namespace.nspname END,
               function_row.proname,
               replace(
                   pg_catalog.pg_get_triggerdef(trigger_row.oid, true),
                   $1 || '.', '<schema>.'
               )
           )::text
      FROM pg_catalog.pg_trigger trigger_row
      JOIN pg_catalog.pg_class class_row ON class_row.oid=trigger_row.tgrelid
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=class_row.relnamespace
      JOIN pg_catalog.pg_proc function_row ON function_row.oid=trigger_row.tgfoid
      JOIN pg_catalog.pg_namespace function_namespace
        ON function_namespace.oid=function_row.pronamespace
     WHERE namespace_row.nspname=$1 AND NOT trigger_row.tgisinternal
    UNION ALL
    SELECT 'function', function_row.proname,
           pg_catalog.pg_get_function_identity_arguments(function_row.oid),
           jsonb_build_array(
               function_row.prokind::text,
               language_row.lanname,
               function_row.provolatile::text,
               function_row.proisstrict,
               function_row.prosecdef,
               function_row.proleakproof,
               function_row.proparallel::text,
               COALESCE(array_to_string(function_row.proconfig, E'\x1f'), ''),
               pg_catalog.pg_get_function_result(function_row.oid),
               replace(
                   pg_catalog.pg_get_functiondef(function_row.oid),
                   $1 || '.', '<schema>.'
               )
           )::text
      FROM pg_catalog.pg_proc function_row
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=function_row.pronamespace
      JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang
     WHERE namespace_row.nspname=$1
    UNION ALL
    SELECT 'policy', class_row.relname, policy_row.polname,
           jsonb_build_array(
               policy_row.polcmd::text,
               policy_row.polpermissive,
               COALESCE(pg_catalog.pg_get_expr(policy_row.polqual, policy_row.polrelid, true), ''),
               COALESCE(pg_catalog.pg_get_expr(policy_row.polwithcheck, policy_row.polrelid, true), '')
           )::text
      FROM pg_catalog.pg_policy policy_row
      JOIN pg_catalog.pg_class class_row ON class_row.oid=policy_row.polrelid
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=class_row.relnamespace
     WHERE namespace_row.nspname=$1
    UNION ALL
    SELECT 'rule', class_row.relname, rewrite_row.rulename,
           replace(
               pg_catalog.pg_get_ruledef(rewrite_row.oid, true),
               $1 || '.', '<schema>.'
           )
      FROM pg_catalog.pg_rewrite rewrite_row
      JOIN pg_catalog.pg_class class_row ON class_row.oid=rewrite_row.ev_class
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=class_row.relnamespace
     WHERE namespace_row.nspname=$1 AND rewrite_row.rulename <> '_RETURN'
    UNION ALL
    SELECT 'type', type_row.typname, '',
           jsonb_build_array(
               type_row.typtype::text,
               type_row.typcategory::text,
               type_row.typnotnull,
               COALESCE(type_row.typdefault, ''),
               COALESCE(pg_catalog.format_type(NULLIF(type_row.typbasetype, 0), type_row.typtypmod), '')
           )::text
      FROM pg_catalog.pg_type type_row
      JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=type_row.typnamespace
     WHERE namespace_row.nspname=$1 AND type_row.typrelid=0 AND type_row.typelem=0
)
SELECT kind, key1, key2, definition
  FROM catalog
 ORDER BY kind COLLATE "C", key1 COLLATE "C", key2 COLLATE "C", definition COLLATE "C"
"#;

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

    /// Read-only reset/preflight hook. Unlike normal startup this never
    /// installs an empty schema: absence, partial state and every catalog
    /// mismatch are returned as failure without making a database change.
    pub fn verify_existing_schema_v16(
        url: &str,
        ca_file: Option<&str>,
        schema: &str,
    ) -> Result<()> {
        validate_schema_name(schema)?;
        let mut client = connect_uninitialized_client(url, ca_file)?;
        let mut transaction = client
            .transaction()
            .map_err(|error| pg_error("start read-only Usage v16 verification", error))?;
        transaction
            .batch_execute("SET TRANSACTION READ ONLY")
            .map_err(|error| pg_error("make Usage v16 verification read-only", error))?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended('cats-usage-schema-v16', 0))",
                &[],
            )
            .map_err(|error| pg_error("lock read-only Usage v16 verification", error))?;
        verify_exact_usage_schema_v16(&mut transaction, schema)?;
        transaction
            .commit()
            .map_err(|error| pg_error("commit read-only Usage v16 verification", error))
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

    fn project_archived<'a>(
        &'a self,
        value: &'a ArchivedUsageCheckpoint,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        let value = value.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_project_archived(client, &schema, &value))
                .await
        })
    }

    fn source_terminal_receipt<'a>(
        &'a self,
        source_id: &'a str,
        source_epoch: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageSourceTerminalReceipt>> {
        let source_id = source_id.to_string();
        let source_epoch = source_epoch.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| {
                pg_source_terminal_receipt(client, &schema, &source_id, &source_epoch)
            })
            .await
        })
    }

    fn active_target_terminal<'a>(
        &'a self,
    ) -> UsageStoreFuture<'a, Option<UsageTargetTerminalState>> {
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_active_target_terminal(client, &schema))
                .await
        })
    }

    fn prepare_target_terminal<'a>(
        &'a self,
        request: &'a UsageTargetTerminalRequest,
    ) -> UsageStoreFuture<'a, UsageTerminalPrepareOutcome> {
        let request = request.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_prepare_target_terminal(client, &schema, &request))
                .await
        })
    }

    fn project_terminal_barrier<'a>(
        &'a self,
        barrier: &'a ArchivedUsageTerminalBarrier,
    ) -> UsageStoreFuture<'a, IngestOutcome> {
        let barrier = barrier.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_project_terminal_barrier(client, &schema, &barrier))
                .await
        })
    }

    fn target_terminal_state<'a>(
        &'a self,
        terminal_epoch_id: &'a str,
    ) -> UsageStoreFuture<'a, Option<UsageTargetTerminalState>> {
        let terminal_epoch_id = terminal_epoch_id.to_string();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| {
                pg_target_terminal_state(client, &schema, &terminal_epoch_id)
            })
            .await
        })
    }

    fn commit_target_terminal<'a>(
        &'a self,
        receipt: &'a UsageTargetTerminalReceipt,
    ) -> UsageStoreFuture<'a, UsageTerminalPrepareOutcome> {
        let receipt = receipt.clone();
        let schema = self.schema.clone();
        Box::pin(async move {
            self.dispatch(move |client| pg_commit_target_terminal(client, &schema, &receipt))
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

fn pg_project_archived(
    client: &mut Client,
    schema: &str,
    archived: &ArchivedUsageCheckpoint,
) -> Result<IngestOutcome> {
    validate_archive_evidence(&archived.archive)?;
    let outcome = ingest_checkpoint(client, schema, &archived.value)?;
    let evidence_json = serde_json::to_string(&archived.archive)?;
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start usage archive projection", error))?;
    let epoch_lock = format!(
        "{}:{}{}",
        archived.value.checkpoint.source_id.len(),
        archived.value.checkpoint.source_id,
        archived.value.checkpoint.source_epoch
    );
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&epoch_lock],
        )
        .map_err(|error| pg_error("lock archived usage source epoch", error))?;
    let insert_sql = format!(
        "INSERT INTO {schema}.usage_archive_projections (
             event_id, stream_name, archive_bucket, shard_id, sequence_number,
             sequence_number_text, archive_key, archive_sha256, evidence_json
         ) VALUES ($1,$2,$3,$4,$5::text::numeric,$5,$6,$7,$8)
         ON CONFLICT (event_id) DO NOTHING"
    );
    let inserted = transaction
        .execute(
            &insert_sql,
            &[
                &archived.value.checkpoint.event_id,
                &archived.archive.stream_name,
                &archived.archive.archive_bucket,
                &archived.archive.shard_id,
                &archived.archive.sequence_number,
                &archived.archive.archive_key,
                &archived.archive.archive_sha256,
                &evidence_json,
            ],
        )
        .map_err(|error| pg_error("insert usage archive projection", error))?;
    if inserted == 0 {
        let existing_sql = format!(
            "SELECT evidence_json FROM {schema}.usage_archive_projections WHERE event_id=$1"
        );
        let existing: String = transaction
            .query_one(&existing_sql, &[&archived.value.checkpoint.event_id])
            .map_err(|error| pg_error("read usage archive projection replay", error))?
            .get(0);
        if existing != evidence_json {
            return Err(MeteringError::Conflict(format!(
                "event {} was projected from conflicting archive evidence",
                archived.value.checkpoint.event_id
            )));
        }
    }
    pg_maybe_insert_source_terminal_receipt(
        &mut transaction,
        schema,
        &archived.value.checkpoint.source_id,
        &archived.value.checkpoint.source_epoch,
    )?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit usage archive projection", error))?;
    Ok(outcome)
}

fn pg_maybe_insert_source_terminal_receipt(
    transaction: &mut Transaction<'_>,
    schema: &str,
    source_id: &str,
    source_epoch: &str,
) -> Result<()> {
    let sql = format!(
        "SELECT checkpoint.payload_json, checkpoint.source_binding_json,
                archive.evidence_json
           FROM {schema}.usage_checkpoints checkpoint
           JOIN {schema}.usage_archive_projections archive
             ON archive.event_id=checkpoint.event_id
          WHERE checkpoint.source_id=$1 AND checkpoint.source_epoch=$2
          ORDER BY checkpoint.sequence, checkpoint.metric, checkpoint.event_id"
    );
    let rows = transaction
        .query(&sql, &[&source_id, &source_epoch])
        .map_err(|error| pg_error("read projected source epoch", error))?;
    let mut projected = Vec::<(
        cats_api::metering::CatUsageCheckpoint,
        RuntimeUsageSourceBinding,
        UsageArchiveEvidence,
    )>::with_capacity(rows.len());
    for row in rows {
        projected.push((
            serde_json::from_str(&row.get::<_, String>(0))?,
            serde_json::from_str(&row.get::<_, String>(1))?,
            serde_json::from_str(&row.get::<_, String>(2))?,
        ));
    }
    let Some(receipt) = build_source_terminal_receipt(source_id, source_epoch, &projected)? else {
        return Ok(());
    };
    let receipt_json = serde_json::to_string(&receipt)?;
    let receipt_sha256 = sha256_prefixed(receipt_json.as_bytes());
    let insert_sql = format!(
        "INSERT INTO {schema}.usage_source_terminal_receipts (
             source_id, source_epoch, receipt_json, receipt_sha256
         ) VALUES ($1,$2,$3,$4)
         ON CONFLICT (source_id, source_epoch) DO NOTHING"
    );
    let inserted = transaction
        .execute(
            &insert_sql,
            &[&source_id, &source_epoch, &receipt_json, &receipt_sha256],
        )
        .map_err(|error| pg_error("insert usage source terminal receipt", error))?;
    if inserted == 0 {
        let existing_sql = format!(
            "SELECT receipt_json, receipt_sha256
               FROM {schema}.usage_source_terminal_receipts
              WHERE source_id=$1 AND source_epoch=$2"
        );
        let row = transaction
            .query_one(&existing_sql, &[&source_id, &source_epoch])
            .map_err(|error| pg_error("read usage terminal receipt replay", error))?;
        let existing = (row.get::<_, String>(0), row.get::<_, String>(1));
        if existing != (receipt_json, receipt_sha256) {
            return Err(MeteringError::Conflict(
                "source terminal receipt conflicts with its immutable replay".to_string(),
            ));
        }
    }
    Ok(())
}

fn pg_source_terminal_receipt(
    client: &mut Client,
    schema: &str,
    source_id: &str,
    source_epoch: &str,
) -> Result<Option<UsageSourceTerminalReceipt>> {
    let sql = format!(
        "SELECT receipt_json, receipt_sha256
           FROM {schema}.usage_source_terminal_receipts
          WHERE source_id=$1 AND source_epoch=$2"
    );
    client
        .query_opt(&sql, &[&source_id, &source_epoch])
        .map_err(|error| pg_error("read usage source terminal receipt", error))?
        .map(|row| decode_terminal_receipt(&row.get::<_, String>(0), &row.get::<_, String>(1)))
        .transpose()
}

fn pg_prepare_target_terminal(
    client: &mut Client,
    schema: &str,
    request: &UsageTargetTerminalRequest,
) -> Result<UsageTerminalPrepareOutcome> {
    validate_target_terminal_request(request)?;
    if request.old_target.usage_schema != schema {
        return Err(MeteringError::Invalid(format!(
            "terminal old usage schema {} does not match opened projection {schema}",
            request.old_target.usage_schema
        )));
    }
    let request_json = serde_json::to_string(request)?;
    let request_sha256 = target_terminal_request_sha256(request)?;
    let terminal_epoch_id = request.terminal_epoch_id.to_string();
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start Usage target terminal preparation", error))?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('cats-usage-target-terminal-v1', 0))",
            &[],
        )
        .map_err(|error| pg_error("lock Usage target terminal preparation", error))?;
    let existing_sql = format!(
        "SELECT terminal_epoch_id, request_json, request_sha256
           FROM {schema}.usage_terminal_operations
          ORDER BY terminal_epoch_id
          LIMIT 2"
    );
    let existing = transaction
        .query(&existing_sql, &[])
        .map_err(|error| pg_error("read Usage target terminal operation", error))?;
    if let Some(row) = existing.first() {
        if existing.len() == 1
            && row.get::<_, String>(0) == terminal_epoch_id
            && row.get::<_, String>(1) == request_json
            && row.get::<_, String>(2) == request_sha256
        {
            transaction
                .commit()
                .map_err(|error| pg_error("commit Usage target terminal replay", error))?;
            return Ok(UsageTerminalPrepareOutcome::ExactReplay);
        }
        return Err(MeteringError::Conflict(
            "Usage target already has a different terminal operation".to_string(),
        ));
    }
    pg_verify_terminal_source_set(&mut transaction, schema, request)?;
    let insert_sql = format!(
        "INSERT INTO {schema}.usage_terminal_operations (
             terminal_epoch_id, request_json, request_sha256, created_at_ms
         ) VALUES ($1,$2,$3,$4)"
    );
    transaction
        .execute(
            &insert_sql,
            &[
                &terminal_epoch_id,
                &request_json,
                &request_sha256,
                &request.created_at_unix_ms,
            ],
        )
        .map_err(|error| pg_error("insert Usage target terminal operation", error))?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit Usage target terminal preparation", error))?;
    Ok(UsageTerminalPrepareOutcome::Prepared)
}

fn pg_verify_terminal_source_set(
    transaction: &mut Transaction<'_>,
    schema: &str,
    request: &UsageTargetTerminalRequest,
) -> Result<Vec<UsageSourceTerminalReceipt>> {
    let source_sql = format!(
        "SELECT DISTINCT source_id, source_epoch
           FROM {schema}.usage_checkpoints
          ORDER BY source_id COLLATE \"C\", source_epoch COLLATE \"C\""
    );
    let actual_keys = transaction
        .query(&source_sql, &[])
        .map_err(|error| pg_error("enumerate Usage terminal source set", error))?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect::<Vec<_>>();
    let expected_keys = request
        .sources
        .iter()
        .map(|source| (source.source_id.clone(), source.source_epoch.clone()))
        .collect::<Vec<_>>();
    if actual_keys != expected_keys {
        return Err(MeteringError::Conflict(
            "Usage target source closed set is incomplete or contains a foreign epoch".to_string(),
        ));
    }
    let receipt_sql = format!(
        "SELECT receipt_json, receipt_sha256
           FROM {schema}.usage_source_terminal_receipts
          WHERE source_id=$1 AND source_epoch=$2"
    );
    let mut receipts = Vec::with_capacity(request.sources.len());
    for expected in &request.sources {
        let row = transaction
            .query_opt(&receipt_sql, &[&expected.source_id, &expected.source_epoch])
            .map_err(|error| pg_error("read required source terminal receipt", error))?
            .ok_or_else(|| {
                MeteringError::Conflict(format!(
                    "source {}/{} has no terminal receipt",
                    expected.source_id, expected.source_epoch
                ))
            })?;
        let receipt_json: String = row.get(0);
        let receipt_sha256: String = row.get(1);
        if receipt_sha256 != expected.receipt_sha256 {
            return Err(MeteringError::Conflict(format!(
                "source {}/{} terminal receipt digest changed",
                expected.source_id, expected.source_epoch
            )));
        }
        receipts.push(decode_terminal_receipt(&receipt_json, &receipt_sha256)?);
    }
    Ok(receipts)
}

fn pg_project_terminal_barrier(
    client: &mut Client,
    schema: &str,
    barrier: &ArchivedUsageTerminalBarrier,
) -> Result<IngestOutcome> {
    validate_archive_evidence(&barrier.archive)?;
    let terminal_epoch_id = barrier.marker.terminal_epoch_id.to_string();
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start Usage terminal barrier projection", error))?;
    let operation_sql = format!(
        "SELECT request_json, request_sha256
           FROM {schema}.usage_terminal_operations
          WHERE terminal_epoch_id=$1"
    );
    let operation = transaction
        .query_opt(&operation_sql, &[&terminal_epoch_id])
        .map_err(|error| pg_error("read Usage terminal barrier operation", error))?
        .ok_or_else(|| {
            MeteringError::Conflict("terminal barrier has no prepared operation".into())
        })?;
    let request_json: String = operation.get(0);
    let request: UsageTargetTerminalRequest = serde_json::from_str(&request_json)?;
    if operation.get::<_, String>(1) != target_terminal_request_sha256(&request)?
        || barrier.marker != target_terminal_marker(&request, &barrier.marker.shard_id)?
        || barrier.archive.shard_id != barrier.marker.shard_id
        || barrier.archive.stream_name != request.old_target.stream_name
        || barrier.archive.archive_bucket != request.old_target.archive_bucket_name
    {
        return Err(MeteringError::Conflict(
            "terminal barrier does not match its prepared old Usage target".into(),
        ));
    }
    let marker_json = serde_json::to_string(&barrier.marker)?;
    let evidence_json = serde_json::to_string(&barrier.archive)?;
    let insert_sql = format!(
        "INSERT INTO {schema}.usage_terminal_barrier_projections (
             marker_id, sequence_number, sequence_number_text, terminal_epoch_id,
             shard_id, marker_json, evidence_json
         ) VALUES ($1,$2::text::numeric,$2,$3,$4,$5,$6)
         ON CONFLICT (marker_id, sequence_number) DO NOTHING"
    );
    let inserted = transaction
        .execute(
            &insert_sql,
            &[
                &barrier.marker.marker_id,
                &barrier.archive.sequence_number,
                &terminal_epoch_id,
                &barrier.marker.shard_id,
                &marker_json,
                &evidence_json,
            ],
        )
        .map_err(|error| pg_error("insert Usage terminal barrier projection", error))?;
    if inserted == 0 {
        let existing_sql = format!(
            "SELECT marker_json, evidence_json
               FROM {schema}.usage_terminal_barrier_projections
              WHERE marker_id=$1 AND sequence_number=$2::text::numeric"
        );
        let row = transaction
            .query_one(
                &existing_sql,
                &[&barrier.marker.marker_id, &barrier.archive.sequence_number],
            )
            .map_err(|error| pg_error("read Usage terminal barrier replay", error))?;
        if (row.get::<_, String>(0), row.get::<_, String>(1)) != (marker_json, evidence_json) {
            return Err(MeteringError::Conflict(
                "terminal barrier position was replayed with conflicting evidence".into(),
            ));
        }
    }
    transaction
        .commit()
        .map_err(|error| pg_error("commit Usage terminal barrier projection", error))?;
    Ok(if inserted == 0 {
        IngestOutcome::Duplicate
    } else {
        IngestOutcome::Accepted
    })
}

fn pg_target_terminal_state(
    client: &mut Client,
    schema: &str,
    terminal_epoch_id: &str,
) -> Result<Option<UsageTargetTerminalState>> {
    let operation_sql = format!(
        "SELECT request_json, request_sha256
           FROM {schema}.usage_terminal_operations
          WHERE terminal_epoch_id=$1"
    );
    let Some(operation) = client
        .query_opt(&operation_sql, &[&terminal_epoch_id])
        .map_err(|error| pg_error("discover Usage target terminal operation", error))?
    else {
        return Ok(None);
    };
    let request_json: String = operation.get(0);
    let request: UsageTargetTerminalRequest = serde_json::from_str(&request_json)?;
    let request_sha256: String = operation.get(1);
    if request_sha256 != target_terminal_request_sha256(&request)? {
        return Err(MeteringError::Store(
            "stored Usage terminal request digest is corrupt".into(),
        ));
    }
    let barriers = pg_load_canonical_barriers(client, schema, terminal_epoch_id)?;
    let receipt_sql = format!(
        "SELECT receipt_json, receipt_sha256
           FROM {schema}.usage_target_terminal_receipts
          WHERE terminal_epoch_id=$1"
    );
    let receipt = client
        .query_opt(&receipt_sql, &[&terminal_epoch_id])
        .map_err(|error| pg_error("discover Usage target terminal receipt", error))?
        .map(|row| {
            let json: String = row.get(0);
            let expected_sha256: String = row.get(1);
            if sha256_prefixed(json.as_bytes()) != expected_sha256 {
                return Err(MeteringError::Store(
                    "stored Usage target terminal receipt digest is corrupt".into(),
                ));
            }
            let receipt: UsageTargetTerminalReceipt = serde_json::from_str(&json)?;
            validate_target_terminal_receipt(&receipt)?;
            Ok(receipt)
        })
        .transpose()?;
    Ok(Some(UsageTargetTerminalState {
        request,
        request_sha256,
        barriers,
        receipt,
    }))
}

fn pg_active_target_terminal(
    client: &mut Client,
    schema: &str,
) -> Result<Option<UsageTargetTerminalState>> {
    let sql = format!(
        "SELECT terminal_epoch_id
           FROM {schema}.usage_terminal_operations
          ORDER BY terminal_epoch_id
          LIMIT 2"
    );
    let operations = client
        .query(&sql, &[])
        .map_err(|error| pg_error("discover active Usage target terminal operation", error))?;
    if operations.len() > 1 {
        return Err(MeteringError::Store(
            "multiple Usage target terminal operations violate the singleton authority".into(),
        ));
    }
    let Some(operation) = operations.first() else {
        return Ok(None);
    };
    pg_target_terminal_state(client, schema, &operation.get::<_, String>(0))
}

fn pg_load_canonical_barriers(
    client: &mut impl postgres::GenericClient,
    schema: &str,
    terminal_epoch_id: &str,
) -> Result<Vec<UsageTerminalBarrierProjection>> {
    let sql = format!(
        "SELECT DISTINCT ON (shard_id) marker_json, evidence_json
           FROM {schema}.usage_terminal_barrier_projections
          WHERE terminal_epoch_id=$1
          ORDER BY shard_id, sequence_number"
    );
    client
        .query(&sql, &[&terminal_epoch_id])
        .map_err(|error| pg_error("read canonical Usage terminal barriers", error))?
        .into_iter()
        .map(|row| {
            Ok(UsageTerminalBarrierProjection {
                marker: serde_json::from_str(&row.get::<_, String>(0))?,
                archive: serde_json::from_str(&row.get::<_, String>(1))?,
            })
        })
        .collect()
}

fn pg_commit_target_terminal(
    client: &mut Client,
    schema: &str,
    receipt: &UsageTargetTerminalReceipt,
) -> Result<UsageTerminalPrepareOutcome> {
    validate_target_terminal_receipt(receipt)?;
    if receipt.request.old_target.usage_schema != schema {
        return Err(MeteringError::Invalid(
            "target receipt old schema does not match opened projection".into(),
        ));
    }
    let terminal_epoch_id = receipt.request.terminal_epoch_id.to_string();
    let receipt_json = serde_json::to_string(receipt)?;
    let receipt_sha256 = sha256_prefixed(receipt_json.as_bytes());
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start Usage target terminal commit", error))?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('cats-usage-target-terminal-v1', 0))",
            &[],
        )
        .map_err(|error| pg_error("lock Usage target terminal commit", error))?;
    let operation_sql = format!(
        "SELECT request_json, request_sha256
           FROM {schema}.usage_terminal_operations
          WHERE terminal_epoch_id=$1"
    );
    let operation = transaction
        .query_opt(&operation_sql, &[&terminal_epoch_id])
        .map_err(|error| pg_error("read prepared Usage terminal operation", error))?
        .ok_or_else(|| {
            MeteringError::Conflict("target receipt has no prepared operation".into())
        })?;
    if operation.get::<_, String>(0) != serde_json::to_string(&receipt.request)?
        || operation.get::<_, String>(1) != receipt.request_sha256
    {
        return Err(MeteringError::Conflict(
            "target receipt does not match prepared operation".into(),
        ));
    }
    let source_receipts =
        pg_verify_terminal_source_set(&mut transaction, schema, &receipt.request)?;
    let barriers = pg_load_canonical_barriers(&mut transaction, schema, &terminal_epoch_id)?;
    if source_receipts != receipt.source_receipts || barriers != receipt.barriers {
        return Err(MeteringError::Conflict(
            "target receipt source or barrier evidence changed before commit".into(),
        ));
    }
    let existing_sql = format!(
        "SELECT receipt_json, receipt_sha256
           FROM {schema}.usage_target_terminal_receipts
          WHERE terminal_epoch_id=$1"
    );
    if let Some(row) = transaction
        .query_opt(&existing_sql, &[&terminal_epoch_id])
        .map_err(|error| pg_error("read Usage target terminal receipt replay", error))?
    {
        if (row.get::<_, String>(0), row.get::<_, String>(1)) != (receipt_json, receipt_sha256) {
            return Err(MeteringError::Conflict(
                "target terminal receipt conflicts with immutable replay".into(),
            ));
        }
        transaction
            .commit()
            .map_err(|error| pg_error("commit Usage target terminal receipt replay", error))?;
        return Ok(UsageTerminalPrepareOutcome::ExactReplay);
    }
    let insert_sql = format!(
        "INSERT INTO {schema}.usage_target_terminal_receipts (
             terminal_epoch_id, receipt_json, receipt_sha256
         ) VALUES ($1,$2,$3)"
    );
    transaction
        .execute(
            &insert_sql,
            &[&terminal_epoch_id, &receipt_json, &receipt_sha256],
        )
        .map_err(|error| pg_error("insert Usage target terminal receipt", error))?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit Usage target terminal receipt", error))?;
    Ok(UsageTerminalPrepareOutcome::Prepared)
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
    let mut client = connect_uninitialized_client(url, ca_file)?;
    migrate(&mut client, schema)?;
    Ok(client)
}

fn connect_uninitialized_client(url: &str, ca_file: Option<&str>) -> Result<Client> {
    let connector = tls_connector(ca_file)?;
    let config = client_config(url)?;
    let mut client = config
        .connect(MakeTlsConnector::new(connector))
        .map_err(|error| pg_error("connect PostgreSQL", error))?;
    configure_session(&mut client)?;
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
    let mut transaction = client
        .transaction()
        .map_err(|error| pg_error("start Usage v16 schema verification", error))?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('cats-usage-schema-v16', 0))",
            &[],
        )
        .map_err(|error| pg_error("lock Usage v16 schema verification", error))?;
    let schema_exists = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1)",
            &[&schema],
        )
        .map_err(|error| pg_error("discover Usage schema", error))?
        .get::<_, bool>(0);
    let install = if schema_exists {
        usage_schema_is_empty(&mut transaction, schema)?
    } else {
        transaction
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .map_err(|error| pg_error("create empty Usage v16 schema", error))?;
        true
    };
    if install {
        transaction
            .batch_execute(&fresh_schema_sql(schema))
            .map_err(|error| pg_error("install exact fresh Usage v16 schema", error))?;
    }
    verify_exact_usage_schema_v16(&mut transaction, schema)?;
    transaction
        .commit()
        .map_err(|error| pg_error("commit Usage v16 schema verification", error))
}

fn usage_schema_is_empty(transaction: &mut Transaction<'_>, schema: &str) -> Result<bool> {
    transaction
        .query_one(
            r#"SELECT NOT EXISTS (
                   SELECT 1 FROM pg_catalog.pg_class class_row
                   JOIN pg_catalog.pg_namespace namespace_row
                     ON namespace_row.oid=class_row.relnamespace
                   WHERE namespace_row.nspname=$1
                   UNION ALL
                   SELECT 1 FROM pg_catalog.pg_proc function_row
                   JOIN pg_catalog.pg_namespace namespace_row
                     ON namespace_row.oid=function_row.pronamespace
                   WHERE namespace_row.nspname=$1
                   UNION ALL
                   SELECT 1 FROM pg_catalog.pg_type type_row
                   JOIN pg_catalog.pg_namespace namespace_row
                     ON namespace_row.oid=type_row.typnamespace
                   WHERE namespace_row.nspname=$1
                     AND type_row.typrelid=0 AND type_row.typelem=0
               )"#,
            &[&schema],
        )
        .map(|row| row.get(0))
        .map_err(|error| pg_error("inspect empty Usage schema", error))
}

fn verify_exact_usage_schema_v16(transaction: &mut Transaction<'_>, schema: &str) -> Result<()> {
    let stamp_sql = format!("SELECT version FROM {schema}.schema_migrations ORDER BY version");
    let versions = transaction
        .query(&stamp_sql, &[])
        .map_err(|_| {
            MeteringError::Conflict(
                "nonempty Usage schema has no readable exact v16 stamp; refusing repair".into(),
            )
        })?
        .into_iter()
        .map(|row| row.get::<_, i32>(0))
        .collect::<Vec<_>>();
    if versions != [USAGE_SCHEMA_VERSION] {
        return Err(MeteringError::Conflict(format!(
            "Usage schema version rows {versions:?} are not the one exact v16 stamp"
        )));
    }
    let functions = transaction
        .query(
            "SELECT function_row.proname, function_row.prosrc
               FROM pg_catalog.pg_proc function_row
               JOIN pg_catalog.pg_namespace namespace_row
                 ON namespace_row.oid=function_row.pronamespace
              WHERE namespace_row.nspname=$1
              ORDER BY function_row.proname COLLATE \"C\"",
            &[&schema],
        )
        .map_err(|error| pg_error("read Usage v16 function bodies", error))?
        .into_iter()
        .map(|row| {
            let name = row.get::<_, String>(0);
            let body = row.get::<_, String>(1);
            (name, sha256_prefixed(body.as_bytes()))
        })
        .collect::<Vec<_>>();
    let expected_functions = USAGE_SCHEMA_V16_FUNCTION_PROSRC_SHA256
        .iter()
        .map(|(name, digest)| ((*name).to_string(), (*digest).to_string()))
        .collect::<Vec<_>>();
    if functions != expected_functions {
        return Err(MeteringError::Conflict(
            "Usage schema v16 function prosrc digest set differs from the release; refusing repair"
                .into(),
        ));
    }
    let actual = usage_schema_catalog_sha256(transaction, schema)?;
    if actual != USAGE_SCHEMA_V16_CATALOG_SHA256 {
        return Err(MeteringError::Conflict(format!(
            "Usage schema v16 catalog digest {actual} does not match release digest {USAGE_SCHEMA_V16_CATALOG_SHA256}; refusing repair"
        )));
    }
    Ok(())
}

fn usage_schema_catalog_sha256(transaction: &mut Transaction<'_>, schema: &str) -> Result<String> {
    let rows = transaction
        .query(USAGE_SCHEMA_V16_CATALOG_SQL, &[&schema])
        .map_err(|error| pg_error("read normalized Usage v16 catalog", error))?;
    let mut bytes = Vec::new();
    for row in rows {
        for column in 0..4 {
            let value = row.get::<_, String>(column);
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    Ok(sha256_prefixed(&bytes))
}

fn fresh_schema_sql(schema: &str) -> String {
    format!(
        r#"
CREATE TABLE {schema}.schema_migrations (
    version INTEGER NOT NULL,
    CONSTRAINT schema_migrations_pk PRIMARY KEY (version),
    CONSTRAINT schema_migrations_version_exact CHECK (version = 16),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE {schema}.usage_checkpoints (
    event_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    observed_at_ms BIGINT NOT NULL,
    metric TEXT NOT NULL,
    cumulative_quantity NUMERIC(39, 0) NOT NULL,
    billing_account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attributed_cat_id TEXT,
    payload_json TEXT NOT NULL,
    source_binding_json TEXT NOT NULL
        CONSTRAINT usage_checkpoints_source_binding_nonempty
        CHECK (source_binding_json <> ''),
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT usage_checkpoints_pk PRIMARY KEY (event_id),
    CONSTRAINT usage_checkpoints_sequence_nonnegative CHECK (sequence >= 0),
    CONSTRAINT usage_checkpoints_observed_nonnegative CHECK (observed_at_ms >= 0),
    CONSTRAINT usage_checkpoints_quantity_nonnegative CHECK (cumulative_quantity >= 0),
    CONSTRAINT usage_checkpoints_source_metric_sequence_unique
        UNIQUE (source_id, source_epoch, metric, sequence)
);
CREATE INDEX usage_checkpoints_account_time_idx
    ON {schema}.usage_checkpoints (billing_account_id, observed_at_ms);
CREATE TABLE {schema}.usage_archive_projections (
    event_id TEXT NOT NULL,
    stream_name TEXT NOT NULL,
    archive_bucket TEXT NOT NULL,
    shard_id TEXT NOT NULL,
    sequence_number NUMERIC(78, 0) NOT NULL,
    sequence_number_text TEXT NOT NULL,
    archive_key TEXT NOT NULL,
    archive_sha256 TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT usage_archive_projections_pk PRIMARY KEY (event_id),
    CONSTRAINT usage_archive_projections_event_fk FOREIGN KEY (event_id)
        REFERENCES {schema}.usage_checkpoints(event_id),
    CONSTRAINT usage_archive_projections_sequence_nonnegative
        CHECK (sequence_number >= 0),
    CONSTRAINT usage_archive_projections_sequence_text_canonical
        CHECK (sequence_number_text ~ '^(0|[1-9][0-9]{{0,77}})$'),
    CONSTRAINT usage_archive_projections_sequence_exact
        CHECK (sequence_number = sequence_number_text::numeric),
    CONSTRAINT usage_archive_projections_sha256_canonical
        CHECK (archive_sha256 ~ '^sha256:[0-9a-f]{{64}}$'),
    CONSTRAINT usage_archive_projections_evidence_nonempty
        CHECK (evidence_json <> ''),
    CONSTRAINT usage_archive_projections_stream_position_unique
        UNIQUE (stream_name, shard_id, sequence_number)
);
CREATE TABLE {schema}.usage_source_terminal_receipts (
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT usage_source_terminal_receipts_pk PRIMARY KEY (source_id, source_epoch),
    CONSTRAINT usage_source_terminal_receipts_json_nonempty CHECK (receipt_json <> ''),
    CONSTRAINT usage_source_terminal_receipts_sha256_canonical
        CHECK (receipt_sha256 ~ '^sha256:[0-9a-f]{{64}}$')
);
CREATE TABLE {schema}.usage_terminal_operations (
    terminal_epoch_id TEXT NOT NULL,
    singleton_key BOOLEAN NOT NULL DEFAULT TRUE,
    request_json TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT usage_terminal_operations_pk PRIMARY KEY (terminal_epoch_id),
    CONSTRAINT usage_terminal_operations_epoch_canonical
        CHECK (terminal_epoch_id ~ '^[0-9a-f]{{32}}$'
               AND terminal_epoch_id <> repeat('0', 32)),
    CONSTRAINT usage_terminal_operations_singleton_unique UNIQUE (singleton_key),
    CONSTRAINT usage_terminal_operations_singleton_true CHECK (singleton_key),
    CONSTRAINT usage_terminal_operations_request_nonempty CHECK (request_json <> ''),
    CONSTRAINT usage_terminal_operations_sha256_canonical
        CHECK (request_sha256 ~ '^sha256:[0-9a-f]{{64}}$'),
    CONSTRAINT usage_terminal_operations_created_nonnegative CHECK (created_at_ms >= 0)
);
CREATE TABLE {schema}.usage_terminal_barrier_projections (
    marker_id TEXT NOT NULL,
    sequence_number NUMERIC(78, 0) NOT NULL,
    sequence_number_text TEXT NOT NULL,
    terminal_epoch_id TEXT NOT NULL,
    shard_id TEXT NOT NULL,
    marker_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT usage_terminal_barrier_projections_pk
        PRIMARY KEY (marker_id, sequence_number),
    CONSTRAINT usage_terminal_barrier_projections_operation_fk
        FOREIGN KEY (terminal_epoch_id)
        REFERENCES {schema}.usage_terminal_operations(terminal_epoch_id),
    CONSTRAINT usage_terminal_barrier_projections_marker_canonical
        CHECK (marker_id ~ '^usage_terminal_marker_[0-9a-f]{{64}}$'),
    CONSTRAINT usage_terminal_barrier_projections_sequence_nonnegative
        CHECK (sequence_number >= 0),
    CONSTRAINT usage_terminal_barrier_projections_sequence_text_canonical
        CHECK (sequence_number_text ~ '^(0|[1-9][0-9]{{0,77}})$'),
    CONSTRAINT usage_terminal_barrier_projections_sequence_exact
        CHECK (sequence_number = sequence_number_text::numeric),
    CONSTRAINT usage_terminal_barrier_projections_marker_nonempty CHECK (marker_json <> ''),
    CONSTRAINT usage_terminal_barrier_projections_evidence_nonempty CHECK (evidence_json <> ''),
    CONSTRAINT usage_terminal_barrier_projections_position_unique
        UNIQUE (terminal_epoch_id, shard_id, sequence_number)
);
CREATE INDEX usage_terminal_barrier_operation_idx
    ON {schema}.usage_terminal_barrier_projections
       (terminal_epoch_id, shard_id, sequence_number);
CREATE TABLE {schema}.usage_target_terminal_receipts (
    terminal_epoch_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT usage_target_terminal_receipts_pk PRIMARY KEY (terminal_epoch_id),
    CONSTRAINT usage_target_terminal_receipts_operation_fk FOREIGN KEY (terminal_epoch_id)
        REFERENCES {schema}.usage_terminal_operations(terminal_epoch_id),
    CONSTRAINT usage_target_terminal_receipts_json_nonempty CHECK (receipt_json <> ''),
    CONSTRAINT usage_target_terminal_receipts_sha256_canonical
        CHECK (receipt_sha256 ~ '^sha256:[0-9a-f]{{64}}$')
);
CREATE FUNCTION {schema}.reject_usage_terminal_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'usage terminal evidence is insert-only';
END
$function$;
CREATE TRIGGER usage_archive_projections_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_archive_projections
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_terminal_mutation();
CREATE TRIGGER usage_source_terminal_receipts_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_source_terminal_receipts
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_terminal_mutation();
CREATE TRIGGER usage_terminal_operations_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_terminal_operations
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_terminal_mutation();
CREATE TRIGGER usage_terminal_barrier_projections_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_terminal_barrier_projections
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_terminal_mutation();
CREATE TRIGGER usage_target_terminal_receipts_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_target_terminal_receipts
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_terminal_mutation();
CREATE TABLE {schema}.usage_intervals (
    end_event_id TEXT NOT NULL,
    start_event_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_epoch TEXT NOT NULL,
    end_sequence BIGINT NOT NULL,
    interval_start_ms BIGINT NOT NULL,
    interval_end_ms BIGINT NOT NULL,
    metric TEXT NOT NULL,
    quantity NUMERIC(39, 0) NOT NULL,
    billing_account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attributed_cat_id TEXT,
    CONSTRAINT usage_intervals_pk PRIMARY KEY (end_event_id),
    CONSTRAINT usage_intervals_end_event_fk FOREIGN KEY (end_event_id)
        REFERENCES {schema}.usage_checkpoints(event_id),
    CONSTRAINT usage_intervals_start_event_fk FOREIGN KEY (start_event_id)
        REFERENCES {schema}.usage_checkpoints(event_id),
    CONSTRAINT usage_intervals_end_sequence_nonnegative CHECK (end_sequence >= 0),
    CONSTRAINT usage_intervals_quantity_nonnegative CHECK (quantity >= 0),
    CONSTRAINT usage_intervals_time_order CHECK (interval_end_ms > interval_start_ms)
);
CREATE INDEX usage_intervals_account_time_idx
    ON {schema}.usage_intervals
        (billing_account_id, interval_start_ms, interval_end_ms);
CREATE INDEX usage_intervals_cat_time_idx
    ON {schema}.usage_intervals
        (attributed_cat_id, interval_start_ms, interval_end_ms);
CREATE FUNCTION {schema}.reject_usage_checkpoint_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'usage checkpoints are insert-only';
END
$function$;
CREATE TRIGGER usage_checkpoints_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.usage_checkpoints
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_checkpoint_mutation();
CREATE TABLE {schema}.billing_accounts (
    billing_account_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    stripe_customer_id TEXT,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT billing_accounts_pk PRIMARY KEY (billing_account_id),
    CONSTRAINT billing_accounts_currency_usd CHECK (currency = 'USD'),
    CONSTRAINT billing_accounts_created_nonnegative CHECK (created_at_ms >= 0)
);
CREATE TABLE {schema}.credit_ledger_entries (
    entry_id TEXT NOT NULL,
    billing_account_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    amount_nanos NUMERIC(39, 0) NOT NULL,
    currency TEXT NOT NULL,
    external_reference TEXT NOT NULL,
    effective_at_ms BIGINT NOT NULL,
    CONSTRAINT credit_ledger_entries_pk PRIMARY KEY (entry_id),
    CONSTRAINT credit_ledger_entries_account_fk FOREIGN KEY (billing_account_id)
        REFERENCES {schema}.billing_accounts(billing_account_id),
    CONSTRAINT credit_ledger_entries_currency_usd CHECK (currency = 'USD'),
    CONSTRAINT credit_ledger_entries_external_reference_unique UNIQUE (external_reference),
    CONSTRAINT credit_ledger_entries_effective_nonnegative CHECK (effective_at_ms >= 0)
);
CREATE INDEX credit_ledger_account_time_idx
    ON {schema}.credit_ledger_entries (billing_account_id, effective_at_ms);
CREATE FUNCTION {schema}.reject_credit_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'credit ledger entries are insert-only';
END
$function$;
CREATE TRIGGER credit_ledger_insert_only
    BEFORE UPDATE OR DELETE ON {schema}.credit_ledger_entries
    FOR EACH ROW EXECUTE FUNCTION {schema}.reject_credit_ledger_mutation();
CREATE TABLE {schema}.checkout_intents (
    intent_id TEXT NOT NULL,
    billing_account_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    stripe_session_id TEXT,
    checkout_url TEXT,
    stripe_payment_intent_id TEXT,
    status TEXT NOT NULL,
    CONSTRAINT checkout_intents_pk PRIMARY KEY (intent_id),
    CONSTRAINT checkout_intents_account_fk FOREIGN KEY (billing_account_id)
        REFERENCES {schema}.billing_accounts(billing_account_id),
    CONSTRAINT checkout_intents_amount_positive CHECK (amount_cents > 0),
    CONSTRAINT checkout_intents_currency_usd CHECK (currency = 'USD'),
    CONSTRAINT checkout_intents_created_nonnegative CHECK (created_at_ms >= 0),
    CONSTRAINT checkout_intents_stripe_session_unique UNIQUE (stripe_session_id),
    CONSTRAINT checkout_intents_stripe_payment_unique UNIQUE (stripe_payment_intent_id),
    CONSTRAINT checkout_intents_status_valid CHECK (status IN ('pending', 'paid'))
);
CREATE TABLE {schema}.stripe_events (
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    livemode BOOLEAN NOT NULL,
    processed_at_ms BIGINT NOT NULL,
    CONSTRAINT stripe_events_pk PRIMARY KEY (event_id),
    CONSTRAINT stripe_events_processed_nonnegative CHECK (processed_at_ms >= 0)
);
INSERT INTO {schema}.schema_migrations (version) VALUES (16);
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
    let source_binding_json = serde_json::to_string(&value.source_binding)?;
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
        "SELECT payload_json, source_binding_json, billing_account_id, workspace_id,
                resource_type, resource_id, attributed_cat_id
           FROM {schema}.usage_checkpoints WHERE event_id=$1"
    );
    if let Some(row) = transaction
        .query_opt(&existing_sql, &[&value.checkpoint.event_id])
        .map_err(|error| pg_error("look up usage event", error))?
    {
        let existing_payload: String = row.get(0);
        let existing_source_binding: String = row.get(1);
        let existing_attribution = attribution_from_row(&row, 2);
        if existing_payload == payload
            && existing_source_binding == source_binding_json
            && existing_attribution == value.attribution
        {
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

    let target_terminal_sql = format!("SELECT 1 FROM {schema}.usage_terminal_operations LIMIT 1");
    if transaction
        .query_opt(&target_terminal_sql, &[])
        .map_err(|error| pg_error("look up Usage target terminal operation", error))?
        .is_some()
    {
        return Err(MeteringError::Conflict(
            "Usage target is terminal and accepts no brand-new event".to_string(),
        ));
    }

    let terminal_sql = format!(
        "SELECT 1 FROM {schema}.usage_source_terminal_receipts
          WHERE source_id=$1 AND source_epoch=$2"
    );
    if transaction
        .query_opt(
            &terminal_sql,
            &[&value.checkpoint.source_id, &value.checkpoint.source_epoch],
        )
        .map_err(|error| pg_error("look up usage source terminal receipt", error))?
        .is_some()
    {
        return Err(MeteringError::Conflict(
            "source epoch is already terminal".to_string(),
        ));
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

    let binding_sql = format!(
        "SELECT source_binding_json
           FROM {schema}.usage_checkpoints
          WHERE source_id=$1 AND source_epoch=$2
          LIMIT 1"
    );
    if let Some(row) = transaction
        .query_opt(
            &binding_sql,
            &[&value.checkpoint.source_id, &value.checkpoint.source_epoch],
        )
        .map_err(|error| pg_error("look up usage runtime binding", error))?
    {
        if row.get::<_, String>(0) != source_binding_json {
            return Err(MeteringError::Conflict(
                "runtime authority changed inside one source epoch".to_string(),
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
            resource_type, resource_id, attributed_cat_id, payload_json,
            source_binding_json
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7::text::numeric,$8,$9,$10,$11,$12,$13,$14
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
                &source_binding_json,
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
    fn fresh_v16_schema_has_one_stamp_and_no_upgrade_or_repair_path() {
        let sql = fresh_schema_sql("cats_usage");
        assert!(sql.contains("BEFORE UPDATE OR DELETE"));
        assert!(sql.contains("usage_intervals"));
        assert!(sql.contains("schema_migrations"));
        assert!(sql.contains("NUMERIC(39, 0)"));
        assert!(sql.contains("schema_migrations_version_exact CHECK (version = 16)"));
        assert!(sql.contains("schema_migrations (version) VALUES (16)"));
        assert_eq!(sql.matches("schema_migrations (version) VALUES").count(), 1);
        assert!(!sql.contains("IF NOT EXISTS"));
        assert!(!sql.contains("ON CONFLICT"));
        assert!(!sql.contains("ALTER TABLE"));
        assert!(!sql.contains("RENAME COLUMN"));
        assert!(!sql.contains("CREATE OR REPLACE"));
        assert!(!sql.contains("DROP TRIGGER"));
        assert!(sql.contains("credit_ledger_entries"));
        assert!(sql.contains("checkout_intents"));
        assert!(sql.contains("stripe_events"));
        assert!(sql.contains("reject_credit_ledger_mutation"));
        assert!(USAGE_SCHEMA_V16_CATALOG_SQL.contains("pg_get_constraintdef"));
        assert!(USAGE_SCHEMA_V16_CATALOG_SQL.contains("pg_get_indexdef"));
        assert!(USAGE_SCHEMA_V16_CATALOG_SQL.contains("pg_get_triggerdef"));
        assert!(USAGE_SCHEMA_V16_CATALOG_SQL.contains("pg_get_functiondef"));
        assert_eq!(USAGE_SCHEMA_V16_CATALOG_SHA256.len(), 71);
        assert!(USAGE_SCHEMA_V16_CATALOG_SHA256
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }));
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

    #[test]
    fn live_postgres_v16_refuses_old_partial_and_drifted_catalogs_without_repair() {
        let Ok(url) = std::env::var("CATS_TEST_POSTGRES_URL") else {
            return;
        };
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let short_suffix = suffix % 1_000_000_000;
        let mut admin = connect_uninitialized_client(&url, None).unwrap();
        let old_schema = format!("cats_usage_old_{}_{}", std::process::id(), short_suffix);
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {old_schema};
                 CREATE TABLE {old_schema}.schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO {old_schema}.schema_migrations VALUES (5);"
            ))
            .unwrap();
        let old_error = connect_client(&url, None, &old_schema)
            .err()
            .expect("old Usage schema unexpectedly started");
        assert!(old_error
            .to_string()
            .contains("not the one exact v16 stamp"));
        assert_eq!(
            admin
                .query_one(
                    &format!("SELECT version FROM {old_schema}.schema_migrations"),
                    &[],
                )
                .unwrap()
                .get::<_, i32>(0),
            5
        );

        let partial_schema = format!("cats_usage_partial_{}_{}", std::process::id(), short_suffix);
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {partial_schema};
                 CREATE TABLE {partial_schema}.schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO {partial_schema}.schema_migrations VALUES (16);"
            ))
            .unwrap();
        let partial_error = connect_client(&url, None, &partial_schema)
            .err()
            .expect("partial Usage schema unexpectedly started");
        assert!(partial_error.to_string().contains("prosrc digest"));
        assert_eq!(
            admin
                .query_one(
                    "SELECT count(*)::BIGINT FROM pg_catalog.pg_class class_row
                     JOIN pg_catalog.pg_namespace namespace_row
                       ON namespace_row.oid=class_row.relnamespace
                     WHERE namespace_row.nspname=$1",
                    &[&partial_schema],
                )
                .unwrap()
                .get::<_, i64>(0),
            2,
            "failed startup must not create or repair any partial relation"
        );

        fn catalog_digest(client: &mut Client, schema: &str) -> String {
            let mut transaction = client.transaction().unwrap();
            let digest = usage_schema_catalog_sha256(&mut transaction, schema).unwrap();
            transaction.rollback().unwrap();
            digest
        }

        for drift in [
            "extra_relation",
            "missing_relation",
            "missing_column",
            "constraint_definition",
            "index_definition",
            "trigger_definition",
            "function_body",
        ] {
            let schema = format!(
                "cats_usage_drift_{}_{}_{}",
                drift,
                std::process::id(),
                short_suffix
            );
            drop(connect_client(&url, None, &schema).unwrap());
            PostgresUsageStore::verify_existing_schema_v16(&url, None, &schema).unwrap();
            let mutation = match drift {
                "extra_relation" => format!("CREATE TABLE {schema}.foreign_table (id INTEGER)"),
                "missing_relation" => format!("DROP TABLE {schema}.stripe_events"),
                "missing_column" => {
                    format!("ALTER TABLE {schema}.stripe_events DROP COLUMN event_type")
                }
                "constraint_definition" => format!(
                    "ALTER TABLE {schema}.usage_checkpoints
                       DROP CONSTRAINT usage_checkpoints_sequence_nonnegative;
                     ALTER TABLE {schema}.usage_checkpoints
                       ADD CONSTRAINT usage_checkpoints_sequence_nonnegative CHECK (sequence >= -1)"
                ),
                "index_definition" => format!(
                    "DROP INDEX {schema}.usage_checkpoints_account_time_idx;
                     CREATE INDEX usage_checkpoints_account_time_idx
                       ON {schema}.usage_checkpoints (workspace_id, observed_at_ms)"
                ),
                "trigger_definition" => format!(
                    "DROP TRIGGER usage_checkpoints_insert_only ON {schema}.usage_checkpoints;
                     CREATE TRIGGER usage_checkpoints_insert_only
                       BEFORE DELETE ON {schema}.usage_checkpoints
                       FOR EACH ROW EXECUTE FUNCTION {schema}.reject_usage_checkpoint_mutation()"
                ),
                "function_body" => format!(
                    "CREATE OR REPLACE FUNCTION {schema}.reject_usage_checkpoint_mutation()
                     RETURNS trigger LANGUAGE plpgsql AS $body$
                     BEGIN RAISE EXCEPTION 'changed insert-only authority'; END
                     $body$"
                ),
                _ => unreachable!(),
            };
            admin.batch_execute(&mutation).unwrap();
            let before = catalog_digest(&mut admin, &schema);
            let error =
                PostgresUsageStore::verify_existing_schema_v16(&url, None, &schema).unwrap_err();
            assert!(
                error.to_string().contains("catalog digest")
                    || error.to_string().contains("prosrc digest"),
                "{drift} returned {error}"
            );
            assert_eq!(before, catalog_digest(&mut admin, &schema));
            assert_eq!(
                admin
                    .query_one(
                        &format!("SELECT version FROM {schema}.schema_migrations"),
                        &[],
                    )
                    .unwrap()
                    .get::<_, i32>(0),
                USAGE_SCHEMA_VERSION
            );
            admin
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                .unwrap();
        }
        admin
            .batch_execute(&format!(
                "DROP SCHEMA {old_schema} CASCADE;
                 DROP SCHEMA {partial_schema} CASCADE;"
            ))
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
                epoch_marker: cats_api::metering::UsageEpochMarker::Open,
                cumulative_quantity,
            };
            checkpoint.event_id = deterministic_event_id(&checkpoint);
            AttributedCheckpoint {
                checkpoint,
                source_binding: cats_metering::RuntimeUsageSourceBinding {
                    session: cats_api::runtime_reconciliation::SessionBinding {
                        node_id: cats_api::runtime_reconciliation::Id::new("node-a").unwrap(),
                        node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                            "11111111111111111111111111111111",
                        )
                        .unwrap(),
                        agent_instance_id: cats_api::runtime_reconciliation::RandomId128::new(
                            "22222222222222222222222222222222",
                        )
                        .unwrap(),
                        agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1)
                            .unwrap(),
                    },
                    desired_revision: cats_api::runtime_reconciliation::Revision::new(7).unwrap(),
                    runtime_incarnation: cats_api::runtime_reconciliation::RandomId128::new(
                        "33333333333333333333333333333333",
                    )
                    .unwrap(),
                },
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

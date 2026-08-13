//! Helpers for pointing a control Store at a disposable PostgreSQL schema.
//!
//! Not part of the public API: this exists so the crate's own tests and the
//! workspace's integration/E2E suites can isolate per test without each
//! reinventing the DSN handling. The server named by `CATS_TEST_POSTGRES_URL`
//! is treated as disposable; schemas are created and never dropped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use postgres::NoTls;

/// Hold an isolated test schema's runtime_operations table at an
/// ACCESS-EXCLUSIVE barrier and report when one production Store query is
/// waiting behind it. This is shared by unit and cross-router cancellation
/// tests so both prove that the blocking Store closure has been claimed.
pub struct RuntimeOperationsTableLockForTest {
    blocked: tokio::sync::oneshot::Receiver<bool>,
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RuntimeOperationsTableLockForTest {
    pub async fn acquire(dsn: &str) -> Self {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let dsn = dsn.to_owned();
        let worker = std::thread::spawn(move || {
            let mut client = postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
            client
                .batch_execute(
                    "BEGIN;
                     SET LOCAL lock_timeout='5s';
                     LOCK TABLE runtime_operations IN ACCESS EXCLUSIVE MODE",
                )
                .unwrap();
            let own_pid: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .unwrap()
                .get(0);
            ready_tx.send(()).unwrap();

            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if release_rx.try_recv().is_ok() {
                    client.batch_execute("ROLLBACK").unwrap();
                    return;
                }
                let blocked: bool = client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1
                              FROM pg_locks waiting
                              JOIN pg_class relation ON relation.oid=waiting.relation
                              JOIN pg_namespace namespace
                                ON namespace.oid=relation.relnamespace
                             WHERE waiting.pid<>$1 AND NOT waiting.granted
                               AND waiting.locktype='relation'
                               AND namespace.nspname=current_schema()
                               AND relation.relname='runtime_operations'
                         )",
                        &[&own_pid],
                    )
                    .unwrap()
                    .get(0);
                if blocked || Instant::now() >= deadline {
                    let _ = blocked_tx.send(blocked);
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            client.batch_execute("ROLLBACK").unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("runtime_operations table lock was not acquired")
            .expect("runtime_operations table-lock worker stopped");
        Self {
            blocked: blocked_rx,
            release: Some(release_tx),
            worker: Some(worker),
        }
    }

    pub async fn wait_until_query_blocked(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_secs(6), &mut self.blocked)
                .await
                .expect("runtime Operation query did not reach the PostgreSQL lock barrier")
                .expect("runtime_operations table-lock worker stopped"),
            "runtime Operation query never blocked on runtime_operations"
        );
    }

    pub fn release(mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

impl Drop for RuntimeOperationsTableLockForTest {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct UnavailableImageBlob;

impl cats_storage::BlobStore for UnavailableImageBlob {
    fn put_immutable(&self, key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
        Err(unavailable_blob_error(key))
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        Err(unavailable_blob_error(key))
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        Err(unavailable_blob_error(key))
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        Err(unavailable_blob_error(key))
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        Err(unavailable_blob_error(prefix))
    }
}

fn unavailable_blob_error(key: &str) -> cats_storage::BlobError {
    cats_storage::BlobError::Backend {
        key: key.to_string(),
        message: "test image blob is intentionally unavailable".into(),
    }
}

pub fn unavailable_image_blob() -> Arc<dyn cats_storage::BlobStore> {
    Arc::new(UnavailableImageBlob)
}

/// Explicit typed receipt injection for tests that never exercise the
/// production fixed-path filesystem reader.
pub fn test_guest_runtime_profile_receipt(
) -> cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt {
    use cats_api::runtime_reconciliation::{
        AsciiText, ContractVersion, GuestRuntimeProfileReceipt, Sha256Digest,
    };

    let digest = |byte: char| {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("test digest is valid")
    };
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest('1'),
        initramfs_digest: Some(digest('2')),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda")
            .expect("test command line is valid"),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

/// Revision-one deployment provisioner trust for HTTP/server tests. Tests
/// inject the typed value and therefore do not weaken the production fixed-
/// path filesystem reader.
pub fn test_runtime_provisioner_trust_bundle(
) -> cats_api::runtime_reconciliation::RuntimeProvisionerTrustBundle {
    use cats_api::runtime_reconciliation::{
        Base64UrlNoPad, ContractVersion, Epoch, Id, RuntimeProvisionerCredential,
        RuntimeProvisionerTrustBundle,
    };

    RuntimeProvisionerTrustBundle {
        version: ContractVersion::V1,
        deployment_id: Id::new("deployment_a".to_owned()).expect("valid test deployment ID"),
        trust_revision: Epoch::new(1).expect("positive test trust revision"),
        expected_previous: None,
        credentials: vec![RuntimeProvisionerCredential {
            credential_id: Id::new("provisioner_a".to_owned()).expect("valid test credential ID"),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
            )
            .expect("canonical test Ed25519 SPKI"),
        }],
    }
}

/// Seed a disposable schema with a typed provisioner-trust revision before a
/// server using the next revision is started.
pub fn seed_runtime_provisioner_trust_bundle(
    dsn: &str,
    bundle: &cats_api::runtime_reconciliation::RuntimeProvisionerTrustBundle,
) {
    let dsn = dsn.to_owned();
    let bundle = bundle.clone();
    crate::store::off_runtime(move || {
        let store = crate::store::Store::connect(&dsn, None).expect("connect test control Store");
        store
            .install_runtime_provisioner_trust_bundle(&bundle)
            .expect("install test runtime provisioner trust bundle");
    });
}

/// Advance provisioner trust through the production typed Store while an
/// isolated HTTP server remains live.
pub async fn install_runtime_provisioner_trust_bundle(
    store: &Arc<crate::store::Store>,
    bundle: cats_api::runtime_reconciliation::RuntimeProvisionerTrustBundle,
) {
    store
        .execute(move |store| store.install_runtime_provisioner_trust_bundle(&bundle))
        .await
        .expect("install test runtime provisioner trust bundle");
}

pub fn route_grant_signer() -> Arc<crate::route_grant::RouteGrantSigner> {
    Arc::new(
        crate::route_grant::RouteGrantSigner::from_ed25519_pem(
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
            include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem"),
            120,
        )
        .expect("test Route Grant key is valid"),
    )
}

/// Base DSN of the disposable test server.
///
/// Panics with instructions when unset: silently skipping the store tests
/// would let the quality gate pass without exercising persistence at all.
pub fn base_url() -> String {
    std::env::var("CATS_TEST_POSTGRES_URL").expect(
        "control-plane tests need CATS_TEST_POSTGRES_URL pointing at a disposable PostgreSQL \
         server. quality.sh and CI provide one; locally:\n  docker run --rm -d --name cats-test-pg \
         -p 5433:5432 -e POSTGRES_PASSWORD=cats postgres:16\n  export \
         CATS_TEST_POSTGRES_URL=postgres://postgres:cats@127.0.0.1:5433/postgres",
    )
}

/// Create a fresh schema on the test server and return a DSN scoped to it via
/// `search_path`, suitable for `Store::connect` or a literal `Config` DSN.
pub fn isolated_control_store_url() -> String {
    let base = base_url();
    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
    // The sync postgres client cannot run on an async runtime thread, and
    // this helper is called from #[tokio::test] bodies.
    crate::store::off_runtime(|| {
        let mut admin =
            postgres::Client::connect(&base, NoTls).expect("connect disposable test PostgreSQL");
        admin
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create test schema");
    });
    isolated_schema_url(&base, &schema)
}

fn isolated_schema_url(base: &str, schema: &str) -> String {
    // Preserve the supplied DSN byte-for-byte. In particular, postgres treats
    // a raw `+` in a query value literally rather than as an HTML-form space.
    // A final `options` parameter matches the helper's historical last-value
    // behavior while adding the exact marker to the existing search path.
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}%20-ccats.test_schema_bootstrap%3Don")
}

#[cfg(test)]
mod isolated_schema_url_tests {
    use super::isolated_schema_url;

    #[test]
    fn preserves_raw_query_and_appends_postgres_encoded_options() {
        let dsn = isolated_schema_url(
            "postgres://user:password@db.invalid/control?application_name=cats+test&options=-cfoo.bar%3Da+b",
            "t_fixed",
        );
        assert!(dsn.starts_with(
            "postgres://user:password@db.invalid/control?application_name=cats+test&options=-cfoo.bar%3Da+b&"
        ));

        let config = dsn.parse::<postgres::Config>().unwrap();
        assert_eq!(config.get_application_name(), Some("cats+test"));
        assert_eq!(
            config.get_options(),
            Some("-csearch_path=t_fixed -ccats.test_schema_bootstrap=on")
        );
    }
}

/// Provision one runtime identity through the production Store transaction.
///
/// This is intentionally test support rather than a second management API:
/// the provisioning HTTP surface belongs to a later cutover slice, while
/// transport tests need a real PostgreSQL identity authority now.
pub async fn provision_node_identity(
    store: &Arc<crate::store::Store>,
    identity: cats_api::runtime_reconciliation::NodeIdentity,
) {
    store
        .execute(move |store| store.provision_node_identity(&identity))
        .await
        .expect("provision test NodeIdentity");
}

/// Canonical database fingerprint for proving that a rejected signed runtime
/// request neither advances a sequence nor renews the current session.
pub async fn runtime_spine_state_fingerprint(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) -> String {
    store
        .execute(move |store| {
            store.with(|client| {
                client
                    .query_one(
                        "SELECT jsonb_build_object(
                            'session', (SELECT to_jsonb(s) FROM current_agent_sessions s
                                         WHERE s.node_id=$1),
                            'desired', (SELECT to_jsonb(d) FROM runtime_desired_read_states d
                                         WHERE d.node_id=$1),
                            'receive', (SELECT to_jsonb(r) FROM runtime_observation_receive_states r
                                         WHERE r.node_id=$1),
                            'inventory', (SELECT to_jsonb(i) FROM runtime_admission_inventory_states i
                                           WHERE i.node_id=$1),
                            'cat_observations', (SELECT count(*)
                                                   FROM runtime_current_cat_observations c
                                                  WHERE c.node_id=$1)
                         )::text",
                        &[&node_id.as_str()],
                    )
                    .map(|row| row.get(0))
            })
        })
        .await
        .expect("fingerprint runtime spine state")
}

/// Exact PostgreSQL tuple identity plus bytes for one Volume Authority row.
///
/// Value equality alone cannot prove that an idempotent Runtime restart made
/// no same-value `UPDATE`: PostgreSQL assigns that write a new `xmin`. This
/// narrow test projection therefore binds both the canonical row and its MVCC
/// creator before and after production reconciliation.
pub async fn runtime_volume_row_fingerprint(
    store: &Arc<crate::store::Store>,
    volume_id: cats_api::runtime_reconciliation::Id,
) -> String {
    store
        .execute(move |store| {
            store.with(|client| {
                client
                    .query_one(
                        "SELECT jsonb_build_object(
                            'xmin', xmin::text,
                            'ctid', ctid::text,
                            'row', to_jsonb(v)
                         )::text
                           FROM volume_records v
                          WHERE volume_id=$1",
                        &[&volume_id.as_str()],
                    )
                    .map(|row| row.get(0))
            })
        })
        .await
        .expect("fingerprint Runtime Volume row")
}

enum RuntimeSchemaWriteBarrierCommand {
    Finish {
        result: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Shutdown,
}

/// Hold every ordinary table in one isolated test schema against DML while a
/// negative HTTP mutation probe runs.
///
/// A before/after row snapshot alone cannot see an INSERT followed by DELETE.
/// PostgreSQL INSERT, UPDATE and DELETE all acquire `ROW EXCLUSIVE`, which
/// conflicts with the `SHARE` locks retained here. Sequence state remains in
/// the coherent before/after fingerprint because `nextval` is intentionally
/// non-transactional. The owner uses a connection independent of `Store`, so
/// holding this barrier never occupies the production Store executor.
///
/// Callers must join the bounded request/handler set under test before
/// settlement. This is not a server drain and cannot rule out a detached
/// producer which decides to issue a new write only after settlement begins.
pub struct RuntimeSchemaWriteBarrierForTest {
    dsn: String,
    command: Option<std::sync::mpsc::Sender<RuntimeSchemaWriteBarrierCommand>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RuntimeSchemaWriteBarrierForTest {
    pub async fn acquire(dsn: &str) -> Self {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let worker_dsn = dsn.to_owned();
        let worker = std::thread::spawn(move || {
            let opened = RuntimeSchemaWriteBarrierWorker::open(&worker_dsn);
            match opened {
                Ok(mut barrier) => {
                    if ready_tx.send(Ok(())).is_err() {
                        barrier.rollback();
                        return;
                    }
                    barrier.run(command_rx);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("Runtime schema write barrier did not acquire its bounded table locks")
            .expect("Runtime schema write-barrier worker stopped")
            .unwrap_or_else(|error| panic!("acquire Runtime schema write barrier: {error}"));
        Self {
            dsn: dsn.to_owned(),
            command: Some(command_tx),
            worker: Some(worker),
        }
    }

    /// Calibrate the barrier against one known-positive INSERT, UPDATE and
    /// DELETE. Each must reach PostgreSQL's table-lock wait and terminate with
    /// the configured lock timeout; another SQLSTATE is not accepted.
    pub async fn calibrate_dml_blocked(&self) {
        let dsn = self.dsn.clone();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || calibrate_runtime_schema_dml_barrier(&dsn)),
        )
        .await
        .expect("Runtime schema DML calibration exceeded its deadline")
        .expect("Runtime schema DML calibration worker panicked")
        .unwrap_or_else(|error| panic!("calibrate Runtime schema DML barrier: {error}"));
    }

    /// Compare the coherent snapshot, sample that no writer is then queued
    /// behind the barrier, roll the transaction back and join its owning
    /// thread.
    pub async fn finish_unchanged(mut self) {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.command
            .as_ref()
            .expect("Runtime schema write-barrier command channel")
            .send(RuntimeSchemaWriteBarrierCommand::Finish { result: result_tx })
            .expect("Runtime schema write-barrier worker stopped");
        let result = tokio::time::timeout(Duration::from_secs(10), result_rx)
            .await
            .expect("Runtime schema write-barrier settlement exceeded its deadline")
            .expect("Runtime schema write-barrier worker stopped before settlement");
        self.command.take();
        if let Some(worker) = self.worker.take() {
            tokio::time::timeout(
                Duration::from_secs(2),
                tokio::task::spawn_blocking(move || worker.join()),
            )
            .await
            .expect("Runtime schema write-barrier worker did not join")
            .expect("Runtime schema write-barrier join task panicked")
            .expect("Runtime schema write-barrier worker panicked");
        }
        result.unwrap_or_else(|error| panic!("Runtime schema write barrier changed: {error}"));
    }
}

impl Drop for RuntimeSchemaWriteBarrierForTest {
    fn drop(&mut self) {
        if let Some(command) = self.command.take() {
            let _ = command.send(RuntimeSchemaWriteBarrierCommand::Shutdown);
        }
        // Drop can run during panic/cancellation and must not synchronously
        // join a PostgreSQL call. Session statement/lock timeouts bound any
        // in-flight command; disconnecting the command channel then makes the
        // worker roll back and close its connection.
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

struct RuntimeSchemaWriteBarrierWorker {
    client: postgres::Client,
    tables: Vec<(String, String)>,
    before: String,
    transaction_open: bool,
}

impl RuntimeSchemaWriteBarrierWorker {
    fn open(dsn: &str) -> Result<Self, String> {
        let mut client =
            postgres::Client::connect(dsn, NoTls).map_err(|error| error.to_string())?;
        client
            .batch_execute(
                "SET statement_timeout='5s';
                 SET lock_timeout='5s';
                 BEGIN ISOLATION LEVEL READ COMMITTED",
            )
            .map_err(|error| error.to_string())?;
        let tables =
            runtime_schema_ordinary_tables(&mut client).map_err(|error| error.to_string())?;
        if tables.is_empty() {
            let _ = client.batch_execute("ROLLBACK");
            return Err("isolated Runtime schema contains no ordinary tables".to_owned());
        }
        let qualified = tables
            .iter()
            .map(|(_, qualified)| qualified.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        client
            .batch_execute(&format!("LOCK TABLE {qualified} IN SHARE MODE"))
            .map_err(|error| error.to_string())?;
        let locked_tables =
            runtime_schema_ordinary_tables(&mut client).map_err(|error| error.to_string())?;
        if locked_tables != tables {
            let _ = client.batch_execute("ROLLBACK");
            return Err(
                "isolated Runtime schema table set changed while locks were acquired".to_owned(),
            );
        }
        let before =
            runtime_schema_fingerprint(&mut client, &tables).map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            tables,
            before,
            transaction_open: true,
        })
    }

    fn run(&mut self, commands: std::sync::mpsc::Receiver<RuntimeSchemaWriteBarrierCommand>) {
        match commands.recv() {
            Ok(RuntimeSchemaWriteBarrierCommand::Finish { result }) => {
                let settled = self.settle();
                let _ = result.send(settled);
            }
            Ok(RuntimeSchemaWriteBarrierCommand::Shutdown) | Err(_) => self.rollback(),
        }
    }

    fn settle(&mut self) -> Result<(), String> {
        let after = runtime_schema_fingerprint(&mut self.client, &self.tables)
            .map_err(|error| error.to_string());
        // This is deliberately a point-in-time diagnostic before ROLLBACK,
        // not an atomic promise about future writers. The caller must already
        // have joined every request producer whose behavior this barrier is
        // intended to cover.
        let waiters =
            runtime_schema_waiting_writers(&mut self.client).map_err(|error| error.to_string());
        let rollback = self.rollback_result();
        let after = after?;
        let waiters = waiters?;
        rollback?;
        if !waiters.is_empty() {
            return Err(format!(
                "DML remained queued behind the table barrier: {}",
                waiters.join(", ")
            ));
        }
        if after != self.before {
            return Err(
                "MVCC rows or sequence state differ from the locked before snapshot".to_owned(),
            );
        }
        Ok(())
    }

    fn rollback_result(&mut self) -> Result<(), String> {
        if !self.transaction_open {
            return Ok(());
        }
        self.transaction_open = false;
        self.client
            .batch_execute("ROLLBACK")
            .map_err(|error| error.to_string())
    }

    fn rollback(&mut self) {
        let _ = self.rollback_result();
    }
}

impl Drop for RuntimeSchemaWriteBarrierWorker {
    fn drop(&mut self) {
        self.rollback();
    }
}

fn runtime_schema_ordinary_tables(
    client: &mut postgres::Client,
) -> Result<Vec<(String, String)>, postgres::Error> {
    client
        .query(
            "SELECT c.relname, format('%I.%I', n.nspname, c.relname)
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=current_schema()
                AND c.relkind='r'
              ORDER BY c.relname",
            &[],
        )
        .map(|rows| {
            rows.into_iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect()
        })
}

fn runtime_schema_fingerprint(
    client: &mut postgres::Client,
    tables: &[(String, String)],
) -> Result<String, postgres::Error> {
    let mut fingerprint = String::new();
    for (table, qualified) in tables {
        let rows: String = client
            .query_one(
                &format!(
                    "SELECT COALESCE(
                        jsonb_agg(
                            jsonb_build_object(
                                'xmin', t.xmin::text,
                                'ctid', t.ctid::text,
                                'row', to_jsonb(t)
                            ) ORDER BY t.ctid
                        ),
                        '[]'::jsonb
                     )::text
                       FROM {qualified} AS t"
                ),
                &[],
            )?
            .get(0);
        fingerprint.push_str(table);
        fingerprint.push('\0');
        fingerprint.push_str(&rows);
        fingerprint.push('\0');
    }
    let sequences: String = client
        .query_one(
            "SELECT COALESCE(
                jsonb_agg(to_jsonb(s) ORDER BY s.sequencename),
                '[]'::jsonb
             )::text
               FROM pg_catalog.pg_sequences s
              WHERE s.schemaname=current_schema()",
            &[],
        )?
        .get(0);
    fingerprint.push_str("sequences\0");
    fingerprint.push_str(&sequences);
    Ok(fingerprint)
}

fn runtime_schema_waiting_writers(
    client: &mut postgres::Client,
) -> Result<Vec<String>, postgres::Error> {
    client
        .query(
            "SELECT DISTINCT format('%s:%I', waiting.pid, relation.relname)
               FROM pg_catalog.pg_locks waiting
               JOIN pg_catalog.pg_class relation ON relation.oid=waiting.relation
               JOIN pg_catalog.pg_namespace namespace
                 ON namespace.oid=relation.relnamespace
              WHERE waiting.pid<>pg_backend_pid()
                AND NOT waiting.granted
                AND waiting.locktype='relation'
                AND namespace.nspname=current_schema()
              ORDER BY 1",
            &[],
        )
        .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
}

fn calibrate_runtime_schema_dml_barrier(dsn: &str) -> Result<(), String> {
    let mut client = postgres::Client::connect(dsn, NoTls).map_err(|error| error.to_string())?;
    let event_id = format!("cats-schema-barrier-{}", uuid::Uuid::new_v4());
    for (name, statement) in [
        (
            "INSERT",
            "INSERT INTO workos_event_receipts
                 (workos_event_id, event_name, processed_at)
             VALUES ($1, 'runtime-schema-barrier-calibration', 0)",
        ),
        (
            "UPDATE",
            "UPDATE workos_event_receipts
                SET event_name=event_name
              WHERE workos_event_id=$1",
        ),
        (
            "DELETE",
            "DELETE FROM workos_event_receipts WHERE workos_event_id=$1",
        ),
    ] {
        client
            .batch_execute(
                "BEGIN;
                 SET LOCAL statement_timeout='2s';
                 SET LOCAL lock_timeout='250ms'",
            )
            .map_err(|error| error.to_string())?;
        let result = client.execute(statement, &[&event_id]);
        let rollback = client.batch_execute("ROLLBACK");
        match result {
            Err(error) if error.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {}
            Err(error) => {
                let _ = rollback;
                return Err(format!(
                    "known-positive {name} failed before the table-lock barrier: {error}"
                ));
            }
            Ok(_) => {
                let _ = rollback;
                return Err(format!(
                    "known-positive {name} crossed the Runtime schema table-lock barrier"
                ));
            }
        }
        rollback.map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Persisted facts used by the cross-router runtime cutover acceptance test.
///
/// The test drives only public/machine HTTP routes. This final projection is
/// deliberately read-only: it proves that replay barriers produced one
/// authority graph, that Cat-create did not fall back to the retired product
/// tables, and that observation renewed only the mutable current session.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeCutoverAcceptanceFacts {
    pub node_identity_count: i64,
    pub node_credential_lineage_count: i64,
    pub node_policy_count: i64,
    pub node_authority_apply_count: i64,
    pub registration_attempt_count: i64,
    pub current_session_count: i64,
    pub desired_read_state_count: i64,
    pub observation_receive_state_count: i64,
    pub admission_inventory_state_count: i64,
    pub current_cat_observation_count: i64,
    pub cat_record_count: i64,
    pub disk_record_count: i64,
    pub volume_record_count: i64,
    pub desired_spec_count: i64,
    pub endpoint_record_count: i64,
    pub hostname_lookup_count: i64,
    pub runtime_operation_count: i64,
    pub api_result_count: i64,
    pub retired_node_count: i64,
    pub retired_cat_count: i64,
    pub registration_attempt_lease_deadline_unix_ms: Option<i64>,
    pub current_session_lease_deadline_unix_ms: Option<i64>,
    pub desired_read_last_request_sequence: Option<i64>,
    pub stored_api_response_body: Option<Vec<u8>>,
    pub stored_persistent_disk_response_body: Option<Vec<u8>>,
}

pub async fn runtime_cutover_acceptance_facts(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) -> RuntimeCutoverAcceptanceFacts {
    store
        .execute(move |store| {
            store.with(|client| {
                client
                    .query_one(
                        "SELECT
                            (SELECT count(*) FROM node_identities),
                            (SELECT count(*) FROM runtime_node_credential_lineage),
                            (SELECT count(*) FROM runtime_node_placement_policies),
                            (SELECT count(*) FROM runtime_node_authority_apply_records),
                            (SELECT count(*) FROM agent_registration_attempts),
                            (SELECT count(*) FROM current_agent_sessions),
                            (SELECT count(*) FROM runtime_desired_read_states),
                            (SELECT count(*) FROM runtime_observation_receive_states),
                            (SELECT count(*) FROM runtime_admission_inventory_states),
                            (SELECT count(*) FROM runtime_current_cat_observations),
                            (SELECT count(*) FROM cat_records),
                            (SELECT count(*) FROM disk_records),
                            (SELECT count(*) FROM volume_records),
                            (SELECT count(*) FROM desired_runtime_specs),
                            (SELECT count(*) FROM endpoint_records),
                            (SELECT count(*) FROM hostname_desired_lookups),
                            (SELECT count(*) FROM runtime_operations),
                            (SELECT count(*) FROM api_idempotency_results),
                            (SELECT count(*) FROM nodes),
                            (SELECT count(*) FROM cats),
                            (SELECT lease_deadline_unix_ms
                               FROM agent_registration_attempts WHERE node_id=$1),
                            (SELECT lease_deadline_unix_ms
                               FROM current_agent_sessions WHERE node_id=$1),
                            (SELECT last_request_sequence
                               FROM runtime_desired_read_states WHERE node_id=$1),
                            (SELECT response_body FROM api_idempotency_results
                              WHERE canonical_route='POST /v1/workspaces/{workspace}/cats'
                              LIMIT 1),
                            (SELECT response_body FROM api_idempotency_results
                              WHERE canonical_route='POST /v1/workspaces/{workspace}/disks'
                                AND http_status=201
                              LIMIT 1)",
                        &[&node_id.as_str()],
                    )
                    .map(|row| RuntimeCutoverAcceptanceFacts {
                        node_identity_count: row.get(0),
                        node_credential_lineage_count: row.get(1),
                        node_policy_count: row.get(2),
                        node_authority_apply_count: row.get(3),
                        registration_attempt_count: row.get(4),
                        current_session_count: row.get(5),
                        desired_read_state_count: row.get(6),
                        observation_receive_state_count: row.get(7),
                        admission_inventory_state_count: row.get(8),
                        current_cat_observation_count: row.get(9),
                        cat_record_count: row.get(10),
                        disk_record_count: row.get(11),
                        volume_record_count: row.get(12),
                        desired_spec_count: row.get(13),
                        endpoint_record_count: row.get(14),
                        hostname_lookup_count: row.get(15),
                        runtime_operation_count: row.get(16),
                        api_result_count: row.get(17),
                        retired_node_count: row.get(18),
                        retired_cat_count: row.get(19),
                        registration_attempt_lease_deadline_unix_ms: row.get(20),
                        current_session_lease_deadline_unix_ms: row.get(21),
                        desired_read_last_request_sequence: row.get(22),
                        stored_api_response_body: row.get(23),
                        stored_persistent_disk_response_body: row.get(24),
                    })
            })
        })
        .await
        .expect("load runtime cutover acceptance facts")
}

/// Replace only the mutable settlement fields of one runtime Operation in an
/// isolated schema. The canonical encoder validates the complete fixture;
/// immutable identity and placement projections remain those written by the
/// production Cat-create transaction.
pub async fn settle_runtime_operation_for_test(
    store: &Arc<crate::store::Store>,
    operation: cats_api::runtime_reconciliation::Operation,
) {
    use cats_api::runtime_reconciliation::{encode_operation, OperationPhase};

    let record = String::from_utf8(encode_operation(&operation).expect("valid test Operation"))
        .expect("runtime wire JSON is UTF-8");
    let phase = match operation.phase {
        OperationPhase::Pending => "pending",
        OperationPhase::Succeeded => "succeeded",
        OperationPhase::Failed => "failed",
        OperationPhase::Superseded => "superseded",
    };
    let terminal_kind = operation.terminal.as_ref().map(|_| phase);
    let updated_at = i64::try_from(operation.updated_at_unix_ms.get())
        .expect("test Operation timestamp fits PostgreSQL");
    let operation_id = operation.operation_id;
    store
        .execute(move |store| {
            store.with(|client| {
                let changed = client.execute(
                    "UPDATE runtime_operations
                        SET record=$2::TEXT::jsonb, phase=$3,
                            terminal_kind=$4, updated_at=$5
                      WHERE operation_id=$1",
                    &[
                        &operation_id.as_str(),
                        &record,
                        &phase,
                        &terminal_kind,
                        &updated_at,
                    ],
                )?;
                assert_eq!(changed, 1, "test Operation must already exist");
                Ok(())
            })
        })
        .await
        .expect("settle isolated test Operation");
}

/// Introduce one deterministic projection mismatch in an isolated runtime
/// Operation row so an HTTP test can exercise fatal-corruption policy.
pub async fn corrupt_runtime_operation_projection_for_test(
    store: &Arc<crate::store::Store>,
    operation_id: cats_api::runtime_reconciliation::Id,
) {
    store
        .execute(move |store| {
            store.with(|client| {
                let changed = client.execute(
                    "UPDATE runtime_operations SET updated_at=updated_at+1
                      WHERE operation_id=$1",
                    &[&operation_id.as_str()],
                )?;
                assert_eq!(changed, 1, "test Operation must already exist");
                Ok(())
            })
        })
        .await
        .expect("corrupt isolated test Operation projection");
}

/// Move one Cat Desired through a fully closed disposable-Root completion and
/// one independent PersistentDisk to Deleting. The Root Disk/Volume rows are
/// then swept exactly as the terminal production lifecycle permits.
pub async fn set_runtime_product_read_states_for_test(
    store: &Arc<crate::store::Store>,
    cat_id: cats_api::runtime_reconciliation::Id,
    disk_id: cats_api::runtime_reconciliation::Id,
) {
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, encode_desired_runtime_spec, spec_digest, Epoch, RandomId128,
        RuntimeTarget, Sha256Digest, UnixMillis, VolumeDisposition,
    };
    use cats_storage::authority::{
        complete_disposable_root_delete, consume_disposable_root_delete, normal_acquire,
        AuthorizationRecord, AuthorizationState, DisposableDeleteIsolationBasis,
        DisposableRootDeleteAuthorization, NormalAcquireRequest, VolumeAuthorization, VolumeRecord,
    };

    store
        .execute(move |store| {
            store.with(|client| {
                let mut transaction = client.transaction()?;
                let desired_json: String = transaction
                    .query_one(
                        "SELECT record::text FROM desired_runtime_specs WHERE cat_id=$1",
                        &[&cat_id.as_str()],
                    )?
                    .get(0);
                let mut desired = decode_desired_runtime_spec(desired_json.as_bytes())
                    .expect("test DesiredRuntimeSpec is valid");
                let root = desired.volumes[0].clone();
                let delete_id =
                    cats_api::runtime_reconciliation::Id::new("delete_read_test").unwrap();
                desired.target = RuntimeTarget::Deleted;
                desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
                    delete_id: delete_id.clone(),
                };
                desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
                desired.spec_digest = spec_digest(&desired).expect("Deleted test Desired is valid");
                let encoded = String::from_utf8(
                    encode_desired_runtime_spec(&desired).expect("encode Deleted test Desired"),
                )
                .expect("runtime wire JSON is UTF-8");
                let changed = transaction.execute(
                    "UPDATE desired_runtime_specs
                        SET record=$2::TEXT::jsonb, target='deleted', spec_digest=$3
                      WHERE cat_id=$1",
                    &[&cat_id.as_str(), &encoded, &desired.spec_digest.as_str()],
                )?;
                assert_eq!(changed, 1, "test Cat Desired must already exist");

                let volume_json: String = transaction
                    .query_one(
                        "SELECT record::text FROM volume_records WHERE volume_id=$1",
                        &[&root.volume_id.as_str()],
                    )?
                    .get(0);
                let unowned: VolumeRecord =
                    serde_json::from_str(&volume_json).expect("test Root Volume is valid");
                let cats_api::runtime_reconciliation::VolumeAcquire::Normal {
                    transition_id,
                    expected_unowned_epoch,
                } = &root.acquire
                else {
                    panic!("initial test Root must use normal acquire")
                };
                let (owned, _) = normal_acquire(
                    &unowned,
                    &NormalAcquireRequest {
                        volume_id: root.volume_id.clone(),
                        transition_id: transition_id.clone(),
                        attachment_id: root.attachment_id.clone(),
                        expected_unowned_epoch: *expected_unowned_epoch,
                        desired_revision: desired.desired_revision,
                        placement_epoch: desired.placement.placement_epoch,
                        lease_duration_ms: 30_000,
                    },
                    UnixMillis::new(10_000).unwrap(),
                )
                .expect("test Root normal acquire is valid");
                let authorization_id =
                    cats_api::runtime_reconciliation::Id::new("authorization_read_test").unwrap();
                let original = AuthorizationRecord {
                    authorization: VolumeAuthorization::DisposableRootDelete(
                        DisposableRootDeleteAuthorization {
                            authorization_id: authorization_id.clone(),
                            authorized_node_id: desired.placement.node_id.clone(),
                            delete_id: delete_id.clone(),
                            disk_id: root.disk_id.clone(),
                            volume_id: root.volume_id.clone(),
                            cat_id: desired.cat_id.clone(),
                            desired_revision: desired.desired_revision,
                            placement_epoch: desired.placement.placement_epoch,
                            expected_attachment_id: root.attachment_id.clone(),
                            expected_epoch: owned.lease_epoch,
                            expected_head: owned.head.clone(),
                            isolation_basis: DisposableDeleteIsolationBasis::RuntimeStopped {
                                node_id: desired.placement.node_id.clone(),
                                agent_session_epoch: Epoch::new(1).unwrap(),
                                runtime_incarnation: RandomId128::new(
                                    "91919191919191919191919191919191",
                                )
                                .unwrap(),
                                observation_id: RandomId128::new(
                                    "92929292929292929292929292929292",
                                )
                                .unwrap(),
                            },
                            not_after: UnixMillis::new(50_000).unwrap(),
                        },
                    ),
                    state: AuthorizationState::Unconsumed,
                };
                let (deleting, consumed, consumed_receipt) = consume_disposable_root_delete(
                    &owned,
                    None,
                    &original,
                    &authorization_id,
                    UnixMillis::new(20_000).unwrap(),
                )
                .expect("test disposable Root authorization is valid");
                let completion = complete_disposable_root_delete(
                    &deleting,
                    &consumed,
                    UnixMillis::new(40_000).unwrap(),
                )
                .expect("test disposable Root completion is valid");
                let authorization_json = serde_json::to_string(&consumed)
                    .expect("encode test disposable Root authorization");
                let completion_json = serde_json::to_string(&completion)
                    .expect("encode test disposable Root completion");
                let desired_revision =
                    i64::try_from(desired.desired_revision.get()).expect("test revision fits PG");
                let placement_epoch = i64::try_from(desired.placement.placement_epoch.get())
                    .expect("test placement epoch fits PG");
                let consumed_at = i64::try_from(consumed_receipt.consumed_at.get())
                    .expect("test consumed time fits PG");
                assert_eq!(
                    transaction.execute(
                        "INSERT INTO volume_authorizations (
                            authorization_id, record, kind, authorized_node_id,
                            host_fence_event_id, volume_id, state,
                            desired_revision, placement_epoch, lease_duration_ms,
                            not_after, consumed_at
                         ) VALUES (
                            $1, $2::TEXT::jsonb, 'disposable_root_delete', $3,
                            NULL, $4, 'consumed', $5, $6, NULL, $7, $8
                         )",
                        &[
                            &authorization_id.as_str(),
                            &authorization_json,
                            &desired.placement.node_id.as_str(),
                            &root.volume_id.as_str(),
                            &desired_revision,
                            &placement_epoch,
                            &50_000_i64,
                            &consumed_at,
                        ],
                    )?,
                    1
                );
                let cats_storage::authority::DeleteCompletionReceipt::DisposableRoot {
                    deleting_epoch,
                    deleting_head,
                    completed_at,
                    ..
                } = &completion
                else {
                    unreachable!()
                };
                let deleting_epoch =
                    i64::try_from(deleting_epoch.get()).expect("test deleting epoch fits PG");
                let head_generation = i64::try_from(deleting_head.generation.get())
                    .expect("test head generation fits PG");
                let completed_at =
                    i64::try_from(completed_at.get()).expect("test completion time fits PG");
                assert_eq!(
                    transaction.execute(
                        "INSERT INTO delete_completion_receipts (
                            delete_id, record, kind, disk_id, volume_id,
                            authorization_id, prior_attachment_id, deleting_epoch,
                            head_generation, head_root_hash, head_root_object_id,
                            completed_at
                         ) VALUES (
                            $1, $2::TEXT::jsonb, 'disposable_root', $3, $4,
                            $5, $6, $7, $8, $9, $10, $11
                         )",
                        &[
                            &delete_id.as_str(),
                            &completion_json,
                            &root.disk_id.as_str(),
                            &root.volume_id.as_str(),
                            &authorization_id.as_str(),
                            &root.attachment_id.as_str(),
                            &deleting_epoch,
                            &head_generation,
                            &deleting_head.root_hash.as_ref().map(ToString::to_string),
                            &deleting_head
                                .root_object_id
                                .as_ref()
                                .map(ToString::to_string),
                            &completed_at,
                        ],
                    )?,
                    1
                );
                assert_eq!(
                    transaction.execute(
                        "DELETE FROM disk_records WHERE disk_id=$1",
                        &[&root.disk_id.as_str()],
                    )?,
                    1
                );
                assert_eq!(
                    transaction.execute(
                        "DELETE FROM volume_records WHERE volume_id=$1",
                        &[&root.volume_id.as_str()],
                    )?,
                    1
                );

                let changed = transaction.execute(
                    "UPDATE disk_records
                        SET record=jsonb_set(
                                record,
                                '{admin_state}',
                                '{\"kind\":\"deleting\",\"delete_id\":\"delete_read_test\"}'::jsonb
                            ),
                            admin_state='deleting', delete_id='delete_read_test'
                      WHERE disk_id=$1",
                    &[&disk_id.as_str()],
                )?;
                assert_eq!(changed, 1, "test PersistentDisk must already exist");
                transaction.commit()
            })
        })
        .await
        .expect("set isolated runtime product read states");
}

/// Break only one scalar authorization projection after a valid completed
/// Root sweep, so a public read must fail closed and poison local readiness.
pub async fn corrupt_deleted_root_authorization_projection_for_test(
    store: &Arc<crate::store::Store>,
) {
    store
        .execute(move |store| {
            store.with(|client| {
                let changed = client.execute(
                    "UPDATE volume_authorizations
                        SET desired_revision=desired_revision+1
                      WHERE authorization_id='authorization_read_test'",
                    &[],
                )?;
                assert_eq!(changed, 1, "test disposable authorization must exist");
                Ok(())
            })
        })
        .await
        .expect("corrupt isolated disposable Root authorization projection");
}

/// Put one Cat's JSON workspace and ID projections on the far side of a
/// keyset cursor while its scalar projections remain on the near side. The
/// row must still be reachable through the bounded record/record list index.
pub async fn corrupt_runtime_cat_list_boundary_for_test(
    store: &Arc<crate::store::Store>,
    cat_id: cats_api::runtime_reconciliation::Id,
    claimed_workspace_id: cats_api::runtime_reconciliation::Id,
) {
    store
        .execute(move |store| {
            store.with(|client| {
                let changed = client.execute(
                    "UPDATE cat_records
                        SET record=jsonb_set(
                            jsonb_set(record, '{workspace_id}', to_jsonb($2::TEXT)),
                            '{cat_id}', to_jsonb('cat_zz'::TEXT)
                        )
                      WHERE cat_id=$1",
                    &[&cat_id.as_str(), &claimed_workspace_id.as_str()],
                )?;
                assert_eq!(changed, 1, "test Cat must already exist");
                Ok(())
            })
        })
        .await
        .expect("corrupt isolated Cat list projections across cursor boundary");
}

/// Expire one isolated test session while preserving every JSON/projection
/// invariant. The immutable-attempt trigger is disabled only inside this
/// disposable-schema transaction and is restored before commit.
pub async fn expire_agent_session_for_test(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) {
    store
        .execute(move |store| {
            store.with(|client| {
                let mut transaction = client.transaction()?;
                transaction.batch_execute(
                    "ALTER TABLE agent_registration_attempts DISABLE TRIGGER USER",
                )?;
                let attempts = transaction.execute(
                    "UPDATE agent_registration_attempts
                        SET session_record=jsonb_set(
                                session_record, '{lease_deadline_unix_ms}', '1'::jsonb, FALSE),
                            lease_deadline_unix_ms=1
                      WHERE node_id=$1",
                    &[&node_id.as_str()],
                )?;
                let current = transaction.execute(
                    "UPDATE current_agent_sessions
                        SET record=jsonb_set(
                                record, '{lease_deadline_unix_ms}', '1'::jsonb, FALSE),
                            lease_deadline_unix_ms=1
                      WHERE node_id=$1",
                    &[&node_id.as_str()],
                )?;
                transaction
                    .batch_execute("ALTER TABLE agent_registration_attempts ENABLE TRIGGER USER")?;
                assert_eq!((attempts, current), (1, 1));
                transaction.commit()
            })
        })
        .await
        .expect("expire isolated test AgentSession");
}

/// Move the current Desired cursor just into the past without changing its
/// sequence/read position, retaining a valid issued-before-expires interval.
pub async fn expire_runtime_cursor_for_test(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) {
    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, encode_desired_read_snapshot, UnixMillis,
    };

    store
        .execute(move |store| {
            store.with(|client| {
                let row = client.query_one(
                    "SELECT response::text,
                            (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                       FROM runtime_desired_read_states WHERE node_id=$1",
                    &[&node_id.as_str()],
                )?;
                let response: String = row.get(0);
                let now: i64 = row.get(1);
                let mut snapshot = decode_desired_read_snapshot(response.as_bytes())
                    .expect("stored Desired snapshot is valid");
                let expires = u64::try_from(now).expect("database clock is nonnegative");
                snapshot.issued_at_unix_ms =
                    UnixMillis::new(expires.saturating_sub(1)).expect("issued time is valid");
                snapshot.expires_at_unix_ms =
                    UnixMillis::new(expires).expect("expiry time is valid");
                let encoded = String::from_utf8(
                    encode_desired_read_snapshot(&snapshot).expect("expired cursor still encodes"),
                )
                .expect("runtime wire JSON is UTF-8");
                client.execute(
                    "UPDATE runtime_desired_read_states
                        SET response=$2::TEXT::jsonb, issued_at_unix_ms=$3,
                            expires_at_unix_ms=$4
                      WHERE node_id=$1",
                    &[
                        &node_id.as_str(),
                        &encoded,
                        &i64::try_from(snapshot.issued_at_unix_ms.get())
                            .expect("issued time fits PostgreSQL"),
                        &i64::try_from(snapshot.expires_at_unix_ms.get())
                            .expect("expiry time fits PostgreSQL"),
                    ],
                )?;
                Ok(())
            })
        })
        .await
        .expect("expire isolated test Desired cursor");
}

/// Insert one valid assignment after a cursor was issued. This is a transport
/// regression fixture: the observation must reject the changed assigned set
/// before trying to infer a missing runtime.
pub async fn insert_assigned_desired_after_cursor_for_test(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) {
    use cats_api::runtime_reconciliation::{
        encode_desired_runtime_spec, spec_digest, AssignedKind, AssignedPlacement, ContractVersion,
        DesiredRuntimeSpec, Epoch, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig,
        Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, Sha256Digest,
    };

    let digest = |byte: char| {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("test digest is valid")
    };
    store
        .execute(move |store| {
            store.with(|client| {
                let mut transaction = client.transaction()?;
                let row = transaction.query_one(
                    "SELECT id, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                       FROM workspaces WHERE is_default ORDER BY id LIMIT 1",
                    &[],
                )?;
                let workspace_id =
                    Id::new(row.get::<_, String>(0)).expect("bootstrap workspace id is valid");
                let now: i64 = row.get(1);
                let cat_id = Id::new("cat_http_assigned").expect("test Cat id is valid");
                let mut desired = DesiredRuntimeSpec {
                    version: ContractVersion::V1,
                    workspace_id: workspace_id.clone(),
                    cat_id: cat_id.clone(),
                    desired_revision: Revision::new(1).expect("one is valid"),
                    target: RuntimeTarget::Running,
                    placement: AssignedPlacement {
                        kind: AssignedKind::Assigned,
                        node_id,
                        placement_epoch: Epoch::new(1).expect("one is valid"),
                    },
                    runtime: RuntimeConfig {
                        vcpus: 1,
                        memory_bytes: 512 * 1024 * 1024,
                        boot_image_digest: digest('3'),
                        guest_config_digest: digest('4'),
                        network_config: NetworkConfig {
                            kind: IsolatedIpv4Kind::IsolatedIpv4,
                            network_id: Id::new("net_http_assigned")
                                .expect("test Network id is valid"),
                            guest_mac: MacAddress::new("02:00:00:00:00:01")
                                .expect("test MAC is valid"),
                            guest_ipv4: Ipv4Address::new("10.0.0.1")
                                .expect("test guest IPv4 is valid"),
                            prefix_length: 30,
                            gateway_ipv4: Ipv4Address::new("10.0.0.2")
                                .expect("test gateway IPv4 is valid"),
                        },
                    },
                    volumes: Vec::new(),
                    endpoints: Vec::new(),
                    transition: RuntimeTransition::CancelAndDrain,
                    spec_digest: digest('0'),
                };
                desired.spec_digest = spec_digest(&desired).expect("test Desired is valid");
                let desired_json = String::from_utf8(
                    encode_desired_runtime_spec(&desired).expect("test Desired encodes"),
                )
                .expect("runtime wire JSON is UTF-8");
                let cat_json = serde_json::json!({
                    "cat_id": cat_id.as_str(),
                    "workspace_id": workspace_id.as_str(),
                    "name": "assigned_after_cursor",
                    "created_at": u64::try_from(now).expect("database clock is nonnegative"),
                })
                .to_string();
                transaction.execute(
                    "INSERT INTO cat_records
                        (cat_id, record, workspace_id, name, created_at)
                     VALUES ($1, $2::TEXT::jsonb, $3, 'assigned_after_cursor', $4)",
                    &[&cat_id.as_str(), &cat_json, &workspace_id.as_str(), &now],
                )?;
                transaction.execute(
                    "INSERT INTO desired_runtime_specs
                        (cat_id, record, workspace_id, desired_revision, spec_digest,
                         target, node_id, placement_epoch)
                     VALUES ($1, $2::TEXT::jsonb, $3, 1, $4, 'running', $5, 1)",
                    &[
                        &cat_id.as_str(),
                        &desired_json,
                        &workspace_id.as_str(),
                        &desired.spec_digest.as_str(),
                        &desired.placement.node_id.as_str(),
                    ],
                )?;
                transaction.commit()
            })
        })
        .await
        .expect("insert assigned Desired after cursor");
}

/// Transitional V1 lifecycle fixture. Runtime-session production code never
/// calls this; the broad pre-cutover E2E suite still schedules through the old
/// `nodes` table while F3c replaces that consumer.
#[allow(clippy::too_many_arguments)]
pub async fn register_legacy_test_node(
    store: &Arc<crate::store::Store>,
    node_id: String,
    agent_url: String,
    gateway_url: String,
    cpus: u32,
    memory_mib: u64,
    route_grant_public_key_sha256: String,
) {
    store
        .execute(move |store| {
            store.register_node_with_admission(
                &node_id,
                &agent_url,
                &gateway_url,
                cpus,
                memory_mib,
                crate::store::NodeAdmission::for_route_grant_for_test(
                    false,
                    &route_grant_public_key_sha256,
                ),
            )
        })
        .await
        .expect("register legacy lifecycle test Node");
}

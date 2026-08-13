//! PostgreSQL production adapter for authoritative volume metadata.
//!
//! Lease expiry uses the database clock so workers on different hosts cannot
//! disagree because of local clock skew. Root publication remains one
//! conditional `UPDATE ... RETURNING` over generation, owner, epoch and lease
//! fencing token; a caller may acknowledge a remote-durable FLUSH only after
//! that statement commits.

use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cats_storage::metadata::{MetaError, MetadataStore, Result, SnapshotRow, VolumeHead};
use cats_storage::{AdapterConfig, AdapterError, MetadataStoreFactory};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Row};
use postgres_native_tls::MakeTlsConnector;

mod target_authority;

pub use target_authority::PostgresVolumeDataAuthority;

pub const ADAPTER_NAME: &str = "postgres";
pub const DEFAULT_URL_ENV: &str = "CATS_POSTGRES_URL";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS cats_storage_volumes (
    volume_id TEXT PRIMARY KEY,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    generation BIGINT NOT NULL DEFAULT 0,
    root_hash BYTEA,
    root_object_id TEXT,
    lease_owner TEXT,
    lease_epoch BIGINT NOT NULL DEFAULT 0,
    lease_expires_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cats_storage_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    volume_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    root_hash BYTEA,
    root_object_id TEXT,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS cats_storage_snapshots_volume_created_idx
    ON cats_storage_snapshots (volume_id, created_at_ms);
"#;

const DB_NOW_MS: &str = "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint";

pub struct PostgresMetadataStore {
    jobs: mpsc::SyncSender<Job>,
    /// Lease operations get their own connection and worker.
    ///
    /// Every operation on a shared worker is serial, so a renewal queued behind
    /// a commit's metadata work waits for it. Renewals use a separate connection
    /// to keep the lease fresh and make takeover latency predictable. A bare
    /// expiry lapse is not itself a fence: only an external Volume Authority
    /// transition changes the owner/epoch token.
    lease_jobs: mpsc::SyncSender<Job>,
}

type JobOperation =
    Box<dyn for<'a> FnOnce(std::result::Result<&'a mut Client, MetaError>) + Send + 'static>;

const JOB_PENDING: u8 = 0;
const JOB_RUNNING: u8 = 1;
const JOB_CANCELED: u8 = 2;
const JOB_FINISHED: u8 = 3;

struct Job {
    state: Arc<AtomicU8>,
    operation: JobOperation,
}

impl Job {
    /// Claim immediately before touching PostgreSQL. A caller whose deadline
    /// expires while this job is still queued changes `PENDING` to `CANCELED`,
    /// so an expired mutation can never execute later behind its back.
    fn run(self, client: std::result::Result<&mut Client, MetaError>) {
        if self
            .state
            .compare_exchange(JOB_PENDING, JOB_RUNNING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        (self.operation)(client);
        self.state.store(JOB_FINISHED, Ordering::SeqCst);
    }
}

const WORK_QUEUE_DEPTH: usize = 64;
const OPERATION_DEADLINE: Duration = Duration::from_secs(7);
const STATEMENT_TIMEOUT_MS: &str = "5000";
const LOCK_TIMEOUT_MS: &str = "2000";

/// How PostgreSQL session defaults reach each adapter connection.
///
/// RDS Proxy pins a PostgreSQL client to one backend connection after a client
/// issues `SET`. That would preserve the adapter's current two-backend-
/// connections-per-Cat scaling problem behind a proxy. In proxy deployments,
/// the proxy initialization query owns the settings and the client only proves
/// they are present before it performs any metadata operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SessionSetup {
    #[default]
    Client,
    ServerVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemaAccess {
    LegacyMetadata,
    VolumeAuthority,
}

/// Where a worker obtains its DSN, consulted afresh for every connect.
///
/// The password is part of the DSN, and RDS rotates the managed master
/// password underneath a running process. Capturing the string once meant a
/// reconnect reused a password the server had already stopped accepting: a
/// process that had been healthy for hours could never get back in, and
/// nothing said why, because PostgreSQL only authenticates on connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DsnSource {
    /// A literal DSN, fixed for the life of the process. Correct for a
    /// development credential that nothing rotates.
    Literal(String),
    /// A file re-read on every connect, kept current by the platform: a
    /// systemd timer on a metal worker, a mounted Secret in Kubernetes.
    File(PathBuf),
}

impl DsnSource {
    /// Never include the file's contents in an error. It holds the password.
    fn resolve(&self) -> Result<String> {
        match self {
            Self::Literal(url) => Ok(url.clone()),
            Self::File(path) => {
                let contents = fs::read_to_string(path).map_err(|error| {
                    MetaError::Backend(format!(
                        "read PostgreSQL DSN from {}: {error}",
                        path.display()
                    ))
                })?;
                // A renderer writes this file; a trailing newline is the norm
                // and would otherwise become part of the database name.
                let url = contents.trim();
                if url.is_empty() {
                    return Err(MetaError::Backend(format!(
                        "PostgreSQL DSN file {} is empty",
                        path.display()
                    )));
                }
                Ok(url.to_string())
            }
        }
    }
}

impl PostgresMetadataStore {
    pub fn connect(url: &str, ca_file: Option<&str>) -> Result<Self> {
        Self::connect_from(&DsnSource::Literal(url.to_string()), ca_file)
    }

    pub fn connect_from(dsn: &DsnSource, ca_file: Option<&str>) -> Result<Self> {
        Self::connect_from_with_session_setup(dsn, ca_file, SessionSetup::Client)
    }

    fn connect_from_with_session_setup(
        dsn: &DsnSource,
        ca_file: Option<&str>,
        session_setup: SessionSetup,
    ) -> Result<Self> {
        let jobs = spawn_worker(
            "cats-postgres-metadata",
            dsn.clone(),
            ca_file,
            session_setup,
            SchemaAccess::LegacyMetadata,
        )?;
        let lease_jobs = spawn_worker(
            "cats-postgres-lease",
            dsn.clone(),
            ca_file,
            session_setup,
            SchemaAccess::LegacyMetadata,
        )?;
        Ok(Self { jobs, lease_jobs })
    }

    fn dispatch<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        dispatch_on(&self.jobs, operation)
    }

    /// Dispatch on the lease connection, which no bulk work shares.
    fn dispatch_lease<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        dispatch_on(&self.lease_jobs, operation)
    }

    /// Test-only stand-in for the external Volume Authority. This is not part
    /// of `MetadataStore` and therefore cannot become a production ownership
    /// transition through the compatibility port.
    #[cfg(test)]
    fn install_grant_for_tests(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
    ) -> Result<()> {
        if epoch <= 0 {
            return Err(MetaError::InvalidArgument(
                "test attachment epoch must be positive".into(),
            ));
        }
        let volume_id = volume_id.to_string();
        let attachment_id = attachment_id.to_string();
        self.dispatch(move |client| {
            let changed = client
                .execute(
                    "UPDATE cats_storage_volumes
                        SET lease_owner = $2, lease_epoch = $3,
                            lease_expires_at_ms = 9223372036854775807
                      WHERE volume_id = $1",
                    &[&volume_id, &attachment_id, &epoch],
                )
                .map_err(pg_err)?;
            if changed != 1 {
                return Err(MetaError::NotFound(volume_id));
            }
            Ok(())
        })
    }
}

fn spawn_worker(
    name: &str,
    dsn: DsnSource,
    ca_file: Option<&str>,
    session_setup: SessionSetup,
    schema_access: SchemaAccess,
) -> Result<mpsc::SyncSender<Job>> {
    let ca_file = ca_file.map(str::to_string);
    let (jobs, receiver) = mpsc::sync_channel::<Job>(WORK_QUEUE_DEPTH);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let mut client =
                match connect_resolved(&dsn, ca_file.as_deref(), session_setup, schema_access) {
                    Ok(client) => {
                        let _ = ready_tx.send(Ok(()));
                        client
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
            for job in receiver {
                if client.is_closed() {
                    // Resolve again rather than reuse the DSN this worker
                    // started with: the credential in it may have been rotated
                    // since, and reconnecting with the old one fails forever.
                    match connect_resolved(&dsn, ca_file.as_deref(), session_setup, schema_access) {
                        Ok(reconnected) => client = reconnected,
                        Err(error) => {
                            job.run(Err(error));
                            continue;
                        }
                    }
                }
                job.run(Ok(&mut client));
            }
        })
        .map_err(|error| {
            MetaError::Backend(format!("start PostgreSQL metadata thread: {error}"))
        })?;
    ready_rx
        .recv()
        .map_err(|_| MetaError::Backend("PostgreSQL metadata thread exited at startup".into()))??;
    Ok(jobs)
}

/// The one place a connection is established, so the DSN is resolved on every
/// attempt -- first connect and every reconnect alike.
fn connect_resolved(
    dsn: &DsnSource,
    ca_file: Option<&str>,
    session_setup: SessionSetup,
    schema_access: SchemaAccess,
) -> Result<Client> {
    connect_client(&dsn.resolve()?, ca_file, session_setup, schema_access)
}

fn dispatch_on<T>(
    jobs: &mpsc::SyncSender<Job>,
    operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
) -> Result<T>
where
    T: Send + 'static,
{
    dispatch_on_with_deadline(jobs, operation, OPERATION_DEADLINE)
}

fn dispatch_on_with_deadline<T>(
    jobs: &mpsc::SyncSender<Job>,
    operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
    deadline: Duration,
) -> Result<T>
where
    T: Send + 'static,
{
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let state = Arc::new(AtomicU8::new(JOB_PENDING));
    jobs.try_send(Job {
        state: state.clone(),
        operation: Box::new(move |client| {
            let result = match client {
                Ok(client) => operation(client),
                Err(error) => Err(error),
            };
            let _ = result_tx.send(result);
        }),
    })
    .map_err(|error| match error {
        mpsc::TrySendError::Full(_) => {
            MetaError::Backend("PostgreSQL metadata work queue is full".into())
        }
        mpsc::TrySendError::Disconnected(_) => {
            MetaError::Backend("PostgreSQL metadata thread exited".into())
        }
    })?;
    match result_rx.recv_timeout(deadline) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(MetaError::Backend(
            "PostgreSQL metadata operation was canceled".into(),
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            if state
                .compare_exchange(
                    JOB_PENDING,
                    JOB_CANCELED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return Err(MetaError::Backend(
                    "PostgreSQL metadata operation timed out before execution; operation canceled"
                        .into(),
                ));
            }

            // The operation crossed the only safe cancellation boundary. It
            // may have committed, so never report a definite failure. Close
            // races prefer an already-delivered result when one is available.
            match result_rx.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => Err(MetaError::Backend(
                    "PostgreSQL metadata operation timed out while executing; outcome unknown"
                        .into(),
                )),
                Err(mpsc::TryRecvError::Disconnected) => Err(MetaError::Backend(
                    "PostgreSQL metadata operation ended without a result; outcome unknown".into(),
                )),
            }
        }
    }
}

fn connect_client(
    url: &str,
    ca_file: Option<&str>,
    session_setup: SessionSetup,
    schema_access: SchemaAccess,
) -> Result<Client> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = ca_file {
        let pem = fs::read(path)
            .map_err(|error| MetaError::Backend(format!("read PostgreSQL CA file: {error}")))?;
        let certificates = pem_certificates(&pem)?;
        if certificates.is_empty() {
            return Err(MetaError::Backend(format!(
                "PostgreSQL CA file {path:?} contains no certificates"
            )));
        }
        for certificate in certificates {
            builder.add_root_certificate(certificate);
        }
    }
    let connector = builder
        .build()
        .map_err(|error| MetaError::Backend(format!("build PostgreSQL TLS client: {error}")))?;
    let mut config: postgres::Config = url
        .parse()
        .map_err(|error| MetaError::Backend(format!("parse PostgreSQL URL: {error}")))?;
    config.connect_timeout(Duration::from_secs(5));
    let mut client = config
        .connect(MakeTlsConnector::new(connector))
        .map_err(|error| MetaError::Backend(connect_failure(error)))?;
    configure_session(&mut client, session_setup)?;
    match schema_access {
        SchemaAccess::LegacyMetadata => client.batch_execute(SCHEMA).map_err(pg_err)?,
        SchemaAccess::VolumeAuthority => target_authority::verify_schema(&mut client)?,
    }
    Ok(client)
}

fn configure_session(client: &mut Client, session_setup: SessionSetup) -> Result<()> {
    match session_setup {
        SessionSetup::Client => client
            .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
            .map_err(pg_err),
        SessionSetup::ServerVerified => {
            let settings = client
                .query(
                    "SELECT name, setting FROM pg_settings
                       WHERE name IN ('statement_timeout', 'lock_timeout')",
                    &[],
                )
                .map_err(pg_err)?
                .into_iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
                .collect::<Vec<_>>();
            validate_server_session_settings(&settings)
        }
    }
}

fn validate_server_session_settings(settings: &[(String, String)]) -> Result<()> {
    for (name, expected) in [
        ("statement_timeout", STATEMENT_TIMEOUT_MS),
        ("lock_timeout", LOCK_TIMEOUT_MS),
    ] {
        let actual = settings
            .iter()
            .find_map(|(setting_name, value)| (setting_name == name).then_some(value.as_str()));
        if actual != Some(expected) {
            return Err(MetaError::Backend(format!(
                "PostgreSQL server session setup is unsafe: {name} must be {expected} ms, got {}",
                actual.unwrap_or("missing")
            )));
        }
    }
    Ok(())
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<Certificate>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut rest = pem;
    while let Some(start) = find_bytes(rest, BEGIN) {
        let candidate = &rest[start..];
        let Some(end) = find_bytes(candidate, END) else {
            return Err(MetaError::Backend(
                "PostgreSQL CA file has an unterminated certificate".into(),
            ));
        };
        let end = end + END.len();
        certificates.push(Certificate::from_pem(&candidate[..end]).map_err(|error| {
            MetaError::Backend(format!("parse PostgreSQL CA certificate: {error}"))
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

/// Describe a failed connect using the server's own words.
///
/// `postgres::Error`'s `Display` renders a server-side failure as just
/// "db error", so the reason -- which PostgreSQL states plainly, e.g.
/// `FATAL: password authentication failed for user "catsadmin"` -- is only
/// reachable through `as_db_error`. Losing it cost real time: a rotated master
/// password surfaced to operators as `connect PostgreSQL: db error`, and the
/// caller above it guessed at causes it had no evidence for.
fn connect_failure(error: postgres::Error) -> String {
    match error.as_db_error() {
        Some(database_error) => {
            let detail = database_error
                .detail()
                .map(|value| format!("; {value}"))
                .unwrap_or_default();
            format!(
                "connect PostgreSQL: {} {} [{}]{detail}",
                database_error.severity(),
                database_error.message(),
                database_error.code().code()
            )
        }
        // Not a server response: DNS, TCP, TLS or timeout. `Display` alone can
        // still be terse, so include the source chain.
        None => {
            let mut described = format!("connect PostgreSQL: {error}");
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                described.push_str(&format!(": {cause}"));
                source = cause.source();
            }
            described
        }
    }
}

fn pg_err(error: postgres::Error) -> MetaError {
    MetaError::Backend(error.to_string())
}

fn signed(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        MetaError::InvalidArgument(format!("{field} exceeds PostgreSQL's signed 64-bit range"))
    })
}

fn validate_lease_ttl(ttl_ms: i64) -> Result<()> {
    if ttl_ms <= 0 {
        return Err(MetaError::InvalidArgument(
            "lease TTL must be positive".into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    now.checked_add(ttl_ms)
        .ok_or_else(|| MetaError::InvalidArgument("lease expiry overflows i64".into()))?;
    Ok(())
}

fn decode_hash(hash: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    hash.map(|bytes| {
        let length = bytes.len();
        bytes
            .try_into()
            .map_err(|_| MetaError::Backend(format!("expected a 32-byte hash, got {length} bytes")))
    })
    .transpose()
}

fn row_to_head(row: &Row) -> Result<VolumeHead> {
    let size_bytes: i64 = row.get(1);
    Ok(VolumeHead {
        volume_id: row.get(0),
        size_bytes: u64::try_from(size_bytes)
            .map_err(|error| MetaError::Backend(format!("invalid volume size: {error}")))?,
        generation: row.get(2),
        root_hash: decode_hash(row.get(3))?,
        root_object_id: row.get(4),
        lease_owner: row.get(5),
        lease_epoch: row.get(6),
    })
}

impl MetadataStore for PostgresMetadataStore {
    fn create_volume(&self, volume_id: &str, size_bytes: u64) -> Result<()> {
        let size_bytes = signed(size_bytes, "size_bytes")?;
        let volume_id = volume_id.to_string();
        self.dispatch(move |client| {
            let rows = client
                .execute(
                    "INSERT INTO cats_storage_volumes (volume_id, size_bytes)
                     VALUES ($1, $2) ON CONFLICT (volume_id) DO NOTHING",
                    &[&volume_id, &size_bytes],
                )
                .map_err(pg_err)?;
            if rows == 0 {
                return Err(MetaError::AlreadyExists(volume_id));
            }
            Ok(())
        })
    }

    fn load_head(&self, volume_id: &str) -> Result<VolumeHead> {
        let volume_id = volume_id.to_string();
        self.dispatch(move |client| {
            client
                .query_opt(
                    "SELECT volume_id, size_bytes, generation, root_hash, root_object_id,
                            lease_owner, lease_epoch
                       FROM cats_storage_volumes WHERE volume_id = $1",
                    &[&volume_id],
                )
                .map_err(pg_err)?
                .map(|row| row_to_head(&row))
                .transpose()?
                .ok_or(MetaError::NotFound(volume_id))
        })
    }

    fn delete_volume(&self, volume_id: &str) -> Result<()> {
        let volume_id = volume_id.to_string();
        self.dispatch(move |client| {
            let mut transaction = client.transaction().map_err(pg_err)?;
            transaction
                .execute(
                    "DELETE FROM cats_storage_snapshots WHERE volume_id = $1",
                    &[&volume_id],
                )
                .map_err(pg_err)?;
            transaction
                .execute(
                    "DELETE FROM cats_storage_volumes WHERE volume_id = $1",
                    &[&volume_id],
                )
                .map_err(pg_err)?;
            transaction.commit().map_err(pg_err)
        })
    }

    fn renew_lease(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
        ttl_ms: i64,
    ) -> Result<()> {
        validate_lease_ttl(ttl_ms)?;
        let volume_id = volume_id.to_string();
        let attachment_id = attachment_id.to_string();
        // Deliberately no expiry check: an expired-but-unclaimed lease means
        // nobody revoked or acquired it in between (both bump the epoch), so
        // the holder renews straight through a lapse. A slow attach or a
        // metadata hiccup must not become a permanent self-fence; everything
        // that must fence does so via the epoch.
        let sql = format!(
            "UPDATE cats_storage_volumes
                SET lease_expires_at_ms = {DB_NOW_MS} + $4
              WHERE volume_id = $1 AND lease_owner = $2 AND lease_epoch = $3"
        );
        self.dispatch_lease(move |client| {
            let rows = client
                .execute(&sql, &[&volume_id, &attachment_id, &epoch, &ttl_ms])
                .map_err(pg_err)?;
            if rows == 0 {
                return Err(MetaError::Fenced);
            }
            Ok(())
        })
    }

    fn release_lease(&self, volume_id: &str, attachment_id: &str, epoch: i64) -> Result<()> {
        let volume_id = volume_id.to_string();
        let attachment_id = attachment_id.to_string();
        self.dispatch_lease(move |client| {
            client
                .execute(
                    "UPDATE cats_storage_volumes
                        SET lease_owner = NULL, lease_expires_at_ms = 0
                      WHERE volume_id = $1 AND lease_owner = $2 AND lease_epoch = $3",
                    &[&volume_id, &attachment_id, &epoch],
                )
                .map(|_| ())
                .map_err(pg_err)
        })
    }

    fn cas_head(
        &self,
        volume_id: &str,
        expected_generation: i64,
        new_generation: i64,
        new_root_hash: [u8; 32],
        new_root_object_id: &str,
        attachment_id: &str,
        epoch: i64,
    ) -> Result<i64> {
        if new_generation <= expected_generation {
            return Err(MetaError::InvalidArgument(format!(
                "cas_head must advance the generation: {expected_generation} -> {new_generation}"
            )));
        }
        let volume_id = volume_id.to_string();
        let new_root_object_id = new_root_object_id.to_string();
        let attachment_id = attachment_id.to_string();
        let sql = "UPDATE cats_storage_volumes
                SET root_hash = $3, root_object_id = $4, generation = $7
              WHERE volume_id = $1
                AND generation = $2
                AND lease_owner = $5
                AND lease_epoch = $6
              RETURNING generation";
        self.dispatch(move |client| {
            client
                .query_opt(
                    sql,
                    &[
                        &volume_id,
                        &expected_generation,
                        &&new_root_hash[..],
                        &new_root_object_id,
                        &attachment_id,
                        &epoch,
                        &new_generation,
                    ],
                )
                .map_err(pg_err)?
                .map(|row| row.get(0))
                .ok_or(MetaError::CasConflict {
                    expected: expected_generation,
                })
        })
    }

    fn create_snapshot(&self, snapshot_id: &str, volume_id: &str) -> Result<SnapshotRow> {
        let snapshot_id = snapshot_id.to_string();
        let volume_id = volume_id.to_string();
        let sql = format!(
            "INSERT INTO cats_storage_snapshots
                    (snapshot_id, volume_id, generation, root_hash, root_object_id, created_at_ms)
             SELECT $1, volume_id, generation, root_hash, root_object_id, {DB_NOW_MS}
               FROM cats_storage_volumes WHERE volume_id = $2
             RETURNING snapshot_id, volume_id, generation, root_hash, root_object_id"
        );
        self.dispatch(move |client| {
            let row = client
                .query_opt(&sql, &[&snapshot_id, &volume_id])
                .map_err(pg_err)?
                .ok_or(MetaError::NotFound(volume_id))?;
            Ok(SnapshotRow {
                snapshot_id: row.get(0),
                volume_id: row.get(1),
                generation: row.get(2),
                root_hash: decode_hash(row.get(3))?,
                root_object_id: row.get(4),
            })
        })
    }

    fn list_snapshots(&self, volume_id: &str) -> Result<Vec<SnapshotRow>> {
        let volume_id = volume_id.to_string();
        self.dispatch(move |client| {
            client
                .query(
                    "SELECT snapshot_id, volume_id, generation, root_hash, root_object_id
                       FROM cats_storage_snapshots
                      WHERE volume_id = $1 ORDER BY created_at_ms, snapshot_id",
                    &[&volume_id],
                )
                .map_err(pg_err)?
                .into_iter()
                .map(|row| {
                    Ok(SnapshotRow {
                        snapshot_id: row.get(0),
                        volume_id: row.get(1),
                        generation: row.get(2),
                        root_hash: decode_hash(row.get(3))?,
                        root_object_id: row.get(4),
                    })
                })
                .collect()
        })
    }
}

/// `url-file` wins nothing by default: an operator asks for it explicitly, and
/// asking for both is rejected rather than silently ranked, because which one
/// holds the current password is exactly the question that cost an outage.
fn dsn_source(config: &AdapterConfig) -> std::result::Result<DsnSource, AdapterError> {
    match (config.optional("url-file"), config.optional("url-env")) {
        (Some(_), Some(_)) => Err(AdapterError::InvalidConfig {
            adapter: ADAPTER_NAME,
            message: "set url-file or url-env, not both".to_string(),
        }),
        (Some(path), None) => Ok(DsnSource::File(PathBuf::from(path))),
        (None, url_env) => {
            let url_env = url_env.unwrap_or(DEFAULT_URL_ENV);
            let url = std::env::var(url_env).map_err(|_| AdapterError::InvalidConfig {
                adapter: ADAPTER_NAME,
                message: format!("environment variable {url_env} is not set"),
            })?;
            Ok(DsnSource::Literal(url))
        }
    }
}

fn session_setup(config: &AdapterConfig) -> std::result::Result<SessionSetup, AdapterError> {
    match config.optional("session-setup").unwrap_or("client") {
        "client" => Ok(SessionSetup::Client),
        "server-verified" => Ok(SessionSetup::ServerVerified),
        value => Err(AdapterError::InvalidConfig {
            adapter: ADAPTER_NAME,
            message: format!("session-setup must be client or server-verified, got {value:?}"),
        }),
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PostgresMetadataStoreFactory;

impl MetadataStoreFactory for PostgresMetadataStoreFactory {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn open(
        &self,
        config: &AdapterConfig,
    ) -> std::result::Result<std::sync::Arc<dyn MetadataStore>, AdapterError> {
        config.ensure_only(
            ADAPTER_NAME,
            &["url-env", "url-file", "ca-file", "session-setup"],
        )?;
        let session_setup = session_setup(config)?;
        let dsn = dsn_source(config)?;
        PostgresMetadataStore::connect_from_with_session_setup(
            &dsn,
            config.optional("ca-file"),
            session_setup,
        )
        .map(|store| std::sync::Arc::new(store) as std::sync::Arc<dyn MetadataStore>)
        .map_err(|error| AdapterError::Open {
            adapter: ADAPTER_NAME,
            message: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_lease_ttls_fail_before_database_io() {
        assert!(matches!(
            validate_lease_ttl(0),
            Err(MetaError::InvalidArgument(_))
        ));
        assert!(matches!(
            validate_lease_ttl(i64::MAX),
            Err(MetaError::InvalidArgument(_))
        ));
    }

    #[test]
    fn empty_ca_bundle_is_rejected() {
        assert!(matches!(pem_certificates(b"not a certificate"), Ok(v) if v.is_empty()));
        assert!(matches!(
            pem_certificates(b"-----BEGIN CERTIFICATE-----"),
            Err(MetaError::Backend(_))
        ));
    }

    #[test]
    fn a_queued_mutation_cannot_execute_after_its_caller_times_out() {
        let (jobs, receiver) = mpsc::sync_channel(1);
        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let operation_executed = executed.clone();
        let caller = std::thread::spawn(move || {
            dispatch_on_with_deadline(
                &jobs,
                move |_client| {
                    operation_executed.store(true, Ordering::SeqCst);
                    Ok(())
                },
                Duration::from_millis(20),
            )
        });

        // Simulate the worker having dequeued the job but being stuck before
        // the last-moment claim (for example while reconnecting).
        let job = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let error = caller.join().unwrap().unwrap_err();
        assert!(
            error.to_string().contains("timed out before execution"),
            "unexpected timeout classification: {error}"
        );
        assert_eq!(
            job.state.load(Ordering::SeqCst),
            JOB_CANCELED,
            "the deadline must win the PENDING -> CANCELED transition"
        );
        let state = job.state.clone();
        job.run(Err(MetaError::Backend("unused test client".into())));
        assert_eq!(state.load(Ordering::SeqCst), JOB_CANCELED);
        assert!(
            !executed.load(Ordering::SeqCst),
            "an expired queued mutation executed after its caller returned"
        );
    }

    /// The defect this crate carried: a worker captured its DSN once, so every
    /// reconnect reused a password the server may have stopped accepting.
    #[test]
    fn the_dsn_is_read_again_for_every_connect() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("postgres-url");
        let dsn = DsnSource::File(path.clone());

        fs::write(&path, "postgres://cats:before@db.example/cats").unwrap();
        assert_eq!(
            dsn.resolve().unwrap(),
            "postgres://cats:before@db.example/cats"
        );

        // What a rotation looks like from the process's point of view.
        fs::write(&path, "postgres://cats:after@db.example/cats").unwrap();
        assert_eq!(
            dsn.resolve().unwrap(),
            "postgres://cats:after@db.example/cats",
            "a rotated credential must reach the next connect, not the next restart"
        );
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
        let path = directory.path().join("postgres-url");
        fs::write(&path, "  postgres://cats@db.example/cats\n").unwrap();
        assert_eq!(
            DsnSource::File(path).resolve().unwrap(),
            "postgres://cats@db.example/cats"
        );
    }

    #[test]
    fn an_absent_or_empty_dsn_file_is_reported_as_such() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");
        let error = DsnSource::File(missing.clone()).resolve().unwrap_err();
        assert!(
            error.to_string().contains(&missing.display().to_string()),
            "the error must name the file an operator has to fix: {error}"
        );

        let empty = directory.path().join("empty");
        fs::write(&empty, "   \n").unwrap();
        let error = DsnSource::File(empty).resolve().unwrap_err();
        assert!(
            error.to_string().contains("is empty"),
            "a whitespace-only file must not be handed to the driver: {error}"
        );
    }

    /// The DSN carries the password. An error about the file may name the
    /// file; it may never quote what is inside it.
    #[test]
    fn a_dsn_file_error_never_quotes_the_credential() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("postgres-url");
        fs::write(&path, "not a dsn but it contains hunter2\n").unwrap();
        let resolved = DsnSource::File(path.clone()).resolve().unwrap();
        // Resolution itself does not validate; the driver rejects it. What
        // matters is that the value never lands in one of our messages.
        assert!(resolved.contains("hunter2"));

        let unreadable = DsnSource::File(directory.path().to_path_buf());
        let error = unreadable.resolve().unwrap_err().to_string();
        assert!(!error.contains("hunter2"), "credential leaked: {error}");
    }

    #[test]
    fn asking_for_both_dsn_sources_is_rejected() {
        let config = AdapterConfig::from_pairs([
            ("url-file", "/run/cats/postgres-url"),
            ("url-env", "CATS_POSTGRES_URL"),
        ])
        .unwrap();
        let error = dsn_source(&config).unwrap_err();
        assert!(
            error.to_string().contains("not both"),
            "which source holds the current password must never be ambiguous: {error}"
        );
    }

    #[test]
    fn url_file_selects_the_file_source() {
        let config = AdapterConfig::from_pairs([("url-file", "/run/cats/postgres-url")]).unwrap();
        assert_eq!(
            dsn_source(&config).unwrap(),
            DsnSource::File(PathBuf::from("/run/cats/postgres-url"))
        );
    }

    #[test]
    fn client_session_setup_remains_the_compatible_default() {
        let config = AdapterConfig::default();
        assert_eq!(session_setup(&config).unwrap(), SessionSetup::Client);

        let config = AdapterConfig::from_pairs([("session-setup", "client")]).unwrap();
        assert_eq!(session_setup(&config).unwrap(), SessionSetup::Client);
    }

    #[test]
    fn proxy_session_setup_is_explicit_and_invalid_values_fail_before_connect() {
        let config = AdapterConfig::from_pairs([("session-setup", "server-verified")]).unwrap();
        assert_eq!(
            session_setup(&config).unwrap(),
            SessionSetup::ServerVerified
        );

        let config = AdapterConfig::from_pairs([("session-setup", "trust-server")]).unwrap();
        let error = session_setup(&config).unwrap_err();
        assert!(
            error.to_string().contains("client or server-verified"),
            "an invalid mode must state the closed set: {error}"
        );

        let error = match PostgresMetadataStoreFactory.open(&config) {
            Err(error) => error,
            Ok(_) => panic!("factory accepted an invalid session setup"),
        };
        assert!(
            matches!(error, AdapterError::InvalidConfig { .. }),
            "factory must reject the mode before resolving a DSN or connecting: {error}"
        );
    }

    #[test]
    fn proxy_session_setup_fails_closed_unless_both_timeouts_are_exact() {
        let safe = vec![
            ("lock_timeout".to_string(), "2000".to_string()),
            ("statement_timeout".to_string(), "5000".to_string()),
        ];
        validate_server_session_settings(&safe).unwrap();

        for unsafe_settings in [
            vec![("statement_timeout".to_string(), "5000".to_string())],
            vec![
                ("lock_timeout".to_string(), "0".to_string()),
                ("statement_timeout".to_string(), "5000".to_string()),
            ],
            vec![
                ("lock_timeout".to_string(), "2000".to_string()),
                ("statement_timeout".to_string(), "0".to_string()),
            ],
        ] {
            let error = validate_server_session_settings(&unsafe_settings).unwrap_err();
            assert!(
                error.to_string().contains("server session setup is unsafe"),
                "unsafe proxy defaults were not diagnosed: {error}"
            );
        }
    }

    #[test]
    fn shared_metadata_store_contract_when_postgres_is_configured() {
        let Ok(url) = std::env::var(DEFAULT_URL_ENV) else {
            eprintln!("skipped: {DEFAULT_URL_ENV} not set");
            return;
        };
        let store = std::sync::Arc::new(PostgresMetadataStore::connect(&url, None).unwrap());
        let authority = store.clone();
        cats_test_support::metadata_store_contract(store, move |volume, attachment, epoch| {
            authority
                .install_grant_for_tests(volume, attachment, epoch)
                .unwrap();
        });
    }
}

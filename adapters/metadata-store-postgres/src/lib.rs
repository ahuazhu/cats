//! PostgreSQL production adapter for authoritative volume metadata.
//!
//! Lease expiry uses the database clock so workers on different hosts cannot
//! disagree because of local clock skew. Root publication remains one
//! conditional `UPDATE ... RETURNING` over generation, owner, epoch and lease
//! fencing token; a caller may acknowledge a remote-durable FLUSH only after
//! that statement commits.

use std::fs;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cats_storage::metadata::{MetaError, MetadataStore, Result, SnapshotRow, VolumeHead};
use cats_storage::{AdapterConfig, AdapterError, MetadataStoreFactory};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Row};
use postgres_native_tls::MakeTlsConnector;

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
    /// expiry lapse is not itself a fence: only a revoke or competing acquire
    /// changes the owner/epoch token.
    lease_jobs: mpsc::SyncSender<Job>,
}

type Job = Box<dyn for<'a> FnOnce(std::result::Result<&'a mut Client, MetaError>) + Send + 'static>;

const WORK_QUEUE_DEPTH: usize = 64;
const OPERATION_DEADLINE: Duration = Duration::from_secs(7);

impl PostgresMetadataStore {
    pub fn connect(url: &str, ca_file: Option<&str>) -> Result<Self> {
        let jobs = spawn_worker("cats-postgres-metadata", url, ca_file)?;
        let lease_jobs = spawn_worker("cats-postgres-lease", url, ca_file)?;
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
}

fn spawn_worker(name: &str, url: &str, ca_file: Option<&str>) -> Result<mpsc::SyncSender<Job>> {
    let url = url.to_string();
    let ca_file = ca_file.map(str::to_string);
    let (jobs, receiver) = mpsc::sync_channel::<Job>(WORK_QUEUE_DEPTH);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || match connect_client(&url, ca_file.as_deref()) {
            Ok(mut client) => {
                let _ = ready_tx.send(Ok(()));
                for job in receiver {
                    if client.is_closed() {
                        match connect_client(&url, ca_file.as_deref()) {
                            Ok(reconnected) => client = reconnected,
                            Err(error) => {
                                job(Err(error));
                                continue;
                            }
                        }
                    }
                    job(Ok(&mut client));
                }
            }
            Err(error) => {
                let _ = ready_tx.send(Err(error));
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

fn dispatch_on<T>(
    jobs: &mpsc::SyncSender<Job>,
    operation: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
) -> Result<T>
where
    T: Send + 'static,
{
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    jobs.try_send(Box::new(move |client| {
        let result = match client {
            Ok(client) => operation(client),
            Err(error) => Err(error),
        };
        let _ = result_tx.send(result);
    }))
    .map_err(|error| match error {
        mpsc::TrySendError::Full(_) => {
            MetaError::Backend("PostgreSQL metadata work queue is full".into())
        }
        mpsc::TrySendError::Disconnected(_) => {
            MetaError::Backend("PostgreSQL metadata thread exited".into())
        }
    })?;
    result_rx
        .recv_timeout(OPERATION_DEADLINE)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => {
                MetaError::Backend("PostgreSQL metadata operation timed out".into())
            }
            mpsc::RecvTimeoutError::Disconnected => {
                MetaError::Backend("PostgreSQL metadata operation was canceled".into())
            }
        })?
}

fn connect_client(url: &str, ca_file: Option<&str>) -> Result<Client> {
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
        .map_err(|error| MetaError::Backend(format!("connect PostgreSQL: {error}")))?;
    client
        .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
        .map_err(pg_err)?;
    client.batch_execute(SCHEMA).map_err(pg_err)?;
    Ok(client)
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
                    "SELECT volume_id, size_bytes, generation, root_hash, root_object_id
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

    fn resize_volume(&self, volume_id: &str, new_size_bytes: u64) -> Result<()> {
        let new_size_bytes = signed(new_size_bytes, "new_size_bytes")?;
        let volume_id = volume_id.to_string();
        let sql = format!(
            "UPDATE cats_storage_volumes SET size_bytes = $2
              WHERE volume_id = $1 AND size_bytes <= $2
                AND (lease_owner IS NULL OR lease_expires_at_ms <= {DB_NOW_MS})"
        );
        self.dispatch(move |client| {
            let rows = client
                .execute(&sql, &[&volume_id, &new_size_bytes])
                .map_err(pg_err)?;
            if rows == 0 {
                let exists = client
                    .query_opt(
                        "SELECT 1 FROM cats_storage_volumes WHERE volume_id = $1",
                        &[&volume_id],
                    )
                    .map_err(pg_err)?
                    .is_some();
                return if exists {
                    Err(MetaError::Backend(
                        "resize rejected: shrink not allowed or lease active".into(),
                    ))
                } else {
                    Err(MetaError::NotFound(volume_id))
                };
            }
            Ok(())
        })
    }

    fn acquire_lease(&self, volume_id: &str, attachment_id: &str, ttl_ms: i64) -> Result<i64> {
        validate_lease_ttl(ttl_ms)?;
        let volume_id = volume_id.to_string();
        let attachment_id = attachment_id.to_string();
        let sql = format!(
            "UPDATE cats_storage_volumes
                SET lease_owner = $2,
                    lease_epoch = lease_epoch + 1,
                    lease_expires_at_ms = {DB_NOW_MS} + $3
              WHERE volume_id = $1
                AND (lease_owner IS NULL
                     OR lease_expires_at_ms <= {DB_NOW_MS}
                     OR lease_owner = $2)
              RETURNING lease_epoch"
        );
        self.dispatch_lease(move |client| {
            if let Some(row) = client
                .query_opt(&sql, &[&volume_id, &attachment_id, &ttl_ms])
                .map_err(pg_err)?
            {
                return Ok(row.get(0));
            }
            let exists = client
                .query_opt(
                    "SELECT 1 FROM cats_storage_volumes WHERE volume_id = $1",
                    &[&volume_id],
                )
                .map_err(pg_err)?
                .is_some();
            if exists {
                Err(MetaError::LeaseHeld)
            } else {
                Err(MetaError::NotFound(volume_id))
            }
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

    // The epoch bump is what makes a revoke stick: renewal tolerates a bare
    // expiry, so expiring the row alone would let the old holder renew back in.
    fn revoke_lease(&self, volume_id: &str) -> Result<()> {
        let volume_id = volume_id.to_string();
        self.dispatch(move |client| {
            client
                .execute(
                    "UPDATE cats_storage_volumes
                        SET lease_expires_at_ms = 0, lease_epoch = lease_epoch + 1
                      WHERE volume_id = $1",
                    &[&volume_id],
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
        config.ensure_only(ADAPTER_NAME, &["url-env", "ca-file"])?;
        let url_env = config.optional("url-env").unwrap_or(DEFAULT_URL_ENV);
        let url = std::env::var(url_env).map_err(|_| AdapterError::InvalidConfig {
            adapter: ADAPTER_NAME,
            message: format!("environment variable {url_env} is not set"),
        })?;
        PostgresMetadataStore::connect(&url, config.optional("ca-file"))
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
    fn shared_metadata_store_contract_when_postgres_is_configured() {
        let Ok(url) = std::env::var(DEFAULT_URL_ENV) else {
            eprintln!("skipped: {DEFAULT_URL_ENV} not set");
            return;
        };
        cats_test_support::metadata_store_contract(|| {
            std::sync::Arc::new(PostgresMetadataStore::connect(&url, None).unwrap())
        });
    }
}

//! cats-blockd: one process serves one volume under one attachment lease.
//!
//! The node agent spawns one instance per active attachment. Lifecycle:
//! attach (acquire lease, recover packs) -> serve NBD -> killed by the
//! supervisor. Durability never depends on a graceful shutdown; the control
//! plane revokes the lease before handing the volume to a new attachment.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;

use cats_blockd::blobstore::{BlobStore, FileBlobStore};
use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::meta::{MetaError, MetadataStore, SqliteMeta};
use cats_blockd::nbd;
use cats_blockd::s3::{S3BlobStore, S3Config};

#[derive(Parser, Debug)]
#[command(name = "cats-blockd", about = "Cats ChunkStore block backend")]
struct Args {
    #[arg(long)]
    volume_id: String,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    attachment_id: String,

    /// SQLite metadata store path (dev stand-in for PostgreSQL).
    #[arg(long)]
    meta_sqlite: PathBuf,

    /// File blobstore root. Exactly one of --blob-file-root / --blob-s3-* .
    #[arg(long)]
    blob_file_root: Option<PathBuf>,
    #[arg(long)]
    blob_s3_endpoint: Option<String>,
    #[arg(long)]
    blob_s3_bucket: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    blob_s3_region: String,
    #[arg(long, default_value = "")]
    blob_s3_prefix: String,

    /// Serve NBD on this unix socket path.
    #[arg(long)]
    listen_unix: Option<PathBuf>,
    /// ... or on this TCP address (host:port).
    #[arg(long)]
    listen_tcp: Option<String>,

    /// Dev helper: create the volume row with this size if it is missing.
    #[arg(long)]
    create_volume_size: Option<u64>,

    #[arg(long, default_value_t = 5_000)]
    lease_ttl_ms: i64,

    /// How long to wait for a held lease to expire before giving up
    /// (design: a new attachment waits out the old holder's TTL).
    #[arg(long, default_value_t = 15_000)]
    acquire_wait_ms: u64,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMeta::open(&args.meta_sqlite).context("open sqlite metadata store")?);

    if let Some(size) = args.create_volume_size {
        let size = cats_api::chunk::round_up_to_chunk(size);
        match meta.create_volume(&args.volume_id, size) {
            Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
            Err(e) => return Err(e).context("create volume"),
        }
    }

    let blob: Arc<dyn BlobStore> = match (&args.blob_file_root, &args.blob_s3_endpoint) {
        (Some(root), None) => Arc::new(FileBlobStore::open(root).context("open file blobstore")?),
        (None, Some(endpoint)) => {
            let bucket = args
                .blob_s3_bucket
                .clone()
                .context("--blob-s3-bucket is required with --blob-s3-endpoint")?;
            let access_key = std::env::var("CATS_S3_ACCESS_KEY")
                .context("CATS_S3_ACCESS_KEY must be set for the S3 backend")?;
            let secret_key = std::env::var("CATS_S3_SECRET_KEY")
                .context("CATS_S3_SECRET_KEY must be set for the S3 backend")?;
            Arc::new(S3BlobStore::new(S3Config {
                endpoint: endpoint.clone(),
                bucket,
                region: args.blob_s3_region.clone(),
                access_key,
                secret_key,
                prefix: args.blob_s3_prefix.clone(),
            })?)
        }
        _ => bail!("exactly one of --blob-file-root or --blob-s3-endpoint must be given"),
    };

    let cfg = EngineConfig {
        volume_id: args.volume_id.clone(),
        data_dir: args.data_dir.clone(),
        attachment_id: args.attachment_id.clone(),
        lease_ttl_ms: args.lease_ttl_ms,
    };
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(args.acquire_wait_ms);
    let engine = loop {
        match ChunkEngine::attach(cfg.clone(), blob.clone(), meta.clone()) {
            Ok(engine) => break engine,
            Err(cats_blockd::engine::EngineError::Meta(MetaError::LeaseHeld))
                if std::time::Instant::now() < deadline =>
            {
                tracing::info!("lease held by another attachment; waiting for expiry");
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return Err(e).context("attach chunk engine"),
        }
    };

    tracing::info!(
        volume = %args.volume_id,
        epoch = engine.epoch(),
        generation = engine.generation(),
        "attached"
    );

    match (&args.listen_unix, &args.listen_tcp) {
        (Some(path), None) => {
            if path.exists() {
                std::fs::remove_file(path).ok();
            }
            let listener = UnixListener::bind(path)
                .with_context(|| format!("bind unix socket {}", path.display()))?;
            // Readiness marker for supervisors/tests.
            println!("READY {}", path.display());
            nbd::serve_unix(listener, engine);
        }
        (None, Some(addr)) => {
            let listener =
                std::net::TcpListener::bind(addr).with_context(|| format!("bind tcp {addr}"))?;
            println!("READY {addr}");
            for conn in listener.incoming() {
                let conn = conn?;
                conn.set_nodelay(true).ok();
                let engine = engine.clone();
                std::thread::spawn(move || {
                    let _ = nbd::handle_connection(conn, engine);
                });
            }
        }
        _ => bail!("exactly one of --listen-unix or --listen-tcp must be given"),
    }
    Ok(())
}

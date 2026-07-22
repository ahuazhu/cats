//! cats-blockd composition root: selects storage adapters and serves one
//! volume under one attachment lease.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::nbd;
use cats_metadata_store_postgres::PostgresMetadataStoreFactory;
use cats_metadata_store_sqlite::SqliteMetadataStoreFactory;
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStoreFactory;
use cats_storage::{
    open_blob_store, open_metadata_store, AdapterConfig, BlobStoreFactory, MetaError,
    MetadataStoreFactory,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-blockd", about = "Cats ChunkStore block backend")]
struct Args {
    #[arg(long)]
    volume_id: String,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    attachment_id: String,

    /// Provider-neutral metadata-store adapter name.
    #[arg(long)]
    metadata_store_adapter: String,
    /// Opaque metadata adapter option (`key=value`); may be repeated.
    #[arg(long = "metadata-store-option", value_name = "KEY=VALUE")]
    metadata_store_options: Vec<String>,

    /// Provider-neutral immutable-object adapter name.
    #[arg(long)]
    object_store_adapter: String,
    /// Opaque object adapter option (`key=value`); may be repeated.
    #[arg(long = "object-store-option", value_name = "KEY=VALUE")]
    object_store_options: Vec<String>,

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

    /// How long to wait for a held lease to expire before giving up.
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

    let metadata_config =
        AdapterConfig::from_cli(args.metadata_store_options).context("metadata adapter options")?;
    let metadata_factories: [&dyn MetadataStoreFactory; 2] =
        [&SqliteMetadataStoreFactory, &PostgresMetadataStoreFactory];
    let meta = open_metadata_store(
        &args.metadata_store_adapter,
        &metadata_config,
        &metadata_factories,
    )
    .context("open metadata store")?;

    if let Some(size) = args.create_volume_size {
        let size = cats_api::chunk::round_up_to_chunk(size);
        match meta.create_volume(&args.volume_id, size) {
            Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
            Err(error) => return Err(error).context("create volume"),
        }
    }

    let object_config =
        AdapterConfig::from_cli(args.object_store_options).context("object adapter options")?;
    let object_factories: [&dyn BlobStoreFactory; 2] =
        [&FileBlobStoreFactory, &AwsS3BlobStoreFactory];
    let blob = open_blob_store(
        &args.object_store_adapter,
        &object_config,
        &object_factories,
    )
    .context("open object store")?;

    let config = EngineConfig {
        volume_id: args.volume_id.clone(),
        data_dir: args.data_dir.clone(),
        attachment_id: args.attachment_id.clone(),
        lease_ttl_ms: args.lease_ttl_ms,
    };
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(args.acquire_wait_ms);
    let engine = loop {
        match ChunkEngine::attach(config.clone(), blob.clone(), meta.clone()) {
            Ok(engine) => break engine,
            Err(cats_blockd::engine::EngineError::Meta(MetaError::LeaseHeld))
                if std::time::Instant::now() < deadline =>
            {
                tracing::info!("lease held by another attachment; waiting for expiry");
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(error) => return Err(error).context("attach chunk engine"),
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
            println!("READY {}", path.display());
            nbd::serve_unix(listener, engine);
        }
        (None, Some(address)) => {
            let listener = std::net::TcpListener::bind(address)
                .with_context(|| format!("bind tcp {address}"))?;
            println!("READY {address}");
            for connection in listener.incoming() {
                let connection = connection?;
                connection.set_nodelay(true).ok();
                let engine = engine.clone();
                std::thread::spawn(move || {
                    let _ = nbd::handle_connection(connection, engine);
                });
            }
        }
        _ => bail!("exactly one of --listen-unix or --listen-tcp must be given"),
    }
    Ok(())
}

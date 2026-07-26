//! cats-blockd composition root: selects storage adapters and serves one
//! volume under one attachment lease.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

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

    /// Serve vhost-user-blk on this unix socket path (Linux only). May be
    /// combined with an NBD listener: the VMM uses vhost-user while seeding and
    /// recovery tooling keeps using NBD on the same engine.
    #[arg(long)]
    listen_vhost_user: Option<PathBuf>,
    /// virtio-blk virtqueues to expose (must match the VMM's num_queues).
    #[arg(long, default_value_t = 1)]
    vhost_user_queues: usize,
    /// Depth of each virtqueue (power of two).
    #[arg(long, default_value_t = 256)]
    vhost_user_queue_size: u16,

    /// Dev helper: create the volume row with this size if it is missing.
    #[arg(long)]
    create_volume_size: Option<u64>,

    /// Provision an empty volume from this raw image, sharing one published copy
    /// of it across every volume that starts from it (ADR-0017).
    ///
    /// Publishing is idempotent and keyed by the image's digest, so passing this
    /// on every launch is the intended usage: the first launch uploads the image,
    /// every later one references it. A volume that already has a generation is
    /// left alone, which is what makes this safe to pass on a resume too.
    #[arg(long)]
    seed_image: Option<PathBuf>,

    #[arg(long, default_value_t = 5_000)]
    lease_ttl_ms: i64,

    /// How long to wait for a held lease to expire before giving up.
    #[arg(long, default_value_t = 15_000)]
    acquire_wait_ms: u64,
}

/// Provision a fresh volume from a shared base image, or do nothing if it already
/// has data. Publishing the image happens here rather than in a separate step so
/// a node needs no image-management state of its own.
fn seed_from_image(
    engine: &cats_blockd::engine::ChunkEngine,
    blob: &dyn cats_storage::BlobStore,
    path: &Path,
) -> Result<()> {
    if engine.generation() != 0 {
        tracing::info!(
            generation = engine.generation(),
            "volume already has data; not seeding from the image"
        );
        return Ok(());
    }
    let started = std::time::Instant::now();
    let published = cats_blockd::image::publish(blob, path).context("publish base image")?;
    let publish_us = started.elapsed().as_micros();
    let provision = std::time::Instant::now();
    let generation = engine
        .provision_from_image(&published.manifest)
        .context("provision from base image")?;
    tracing::info!(
        image = %published.manifest.image_id,
        chunks = published.manifest.chunks.len(),
        image_already_published = published.already_present,
        uploaded_objects = published.objects_written,
        uploaded_bytes = published.bytes_written,
        publish_us,
        provision_us = provision.elapsed().as_micros(),
        generation,
        "seeded volume from a shared base image"
    );
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    // Copied out before the adapter option vectors are consumed below.
    let vhost_user_args = VhostUserArgs {
        socket: args.listen_vhost_user.clone(),
        queues: args.vhost_user_queues,
        queue_size: args.vhost_user_queue_size,
    };

    // Reject an impossible listener set before taking the attachment lease.
    if args.listen_unix.is_some() && args.listen_tcp.is_some() {
        bail!("--listen-unix and --listen-tcp are mutually exclusive");
    }
    if args.listen_unix.is_none() && args.listen_tcp.is_none() && args.listen_vhost_user.is_none() {
        bail!("give at least one of --listen-unix, --listen-tcp or --listen-vhost-user");
    }

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

    if let Some(path) = &args.seed_image {
        seed_from_image(&engine, blob.as_ref(), path)
            .with_context(|| format!("seed volume from image {}", path.display()))?;
    }

    // Bind every requested socket before printing READY: a VMM told to start on
    // readiness must never race a socket that does not exist yet.
    let nbd_unix = match &args.listen_unix {
        Some(path) => {
            if path.exists() {
                std::fs::remove_file(path).ok();
            }
            Some(
                UnixListener::bind(path)
                    .with_context(|| format!("bind unix socket {}", path.display()))?,
            )
        }
        None => None,
    };
    let nbd_tcp = match &args.listen_tcp {
        Some(address) => Some(
            std::net::TcpListener::bind(address).with_context(|| format!("bind tcp {address}"))?,
        ),
        None => None,
    };
    let vhost_user = bind_vhost_user(&vhost_user_args)?;

    let ready = args
        .listen_vhost_user
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| args.listen_unix.as_ref().map(|p| p.display().to_string()))
        .or_else(|| args.listen_tcp.clone())
        .expect("a listener was validated above");
    println!("READY {ready}");

    // An NBD frontend serves until its listener stops; the vhost-user daemon
    // returns when the VMM disconnects, which is the signal to release the lease
    // and exit. Whichever the Guest uses governs the process lifetime.
    let mut nbd_threads = Vec::new();
    if let Some(listener) = nbd_unix {
        let engine = engine.clone();
        nbd_threads.push(std::thread::spawn(move || nbd::serve_unix(listener, engine)));
    }
    if let Some(listener) = nbd_tcp {
        let engine = engine.clone();
        nbd_threads.push(std::thread::spawn(move || {
            for connection in listener.incoming() {
                let Ok(connection) = connection else { return };
                connection.set_nodelay(true).ok();
                let engine = engine.clone();
                std::thread::spawn(move || {
                    let _ = nbd::handle_connection(connection, engine);
                });
            }
        }));
    }
    serve_vhost_user(vhost_user, &vhost_user_args, engine, nbd_threads)
}

/// NBD-only mode: the listener threads own the work, so the process lives as
/// long as they do.
fn serve_nbd_only(nbd_threads: Vec<std::thread::JoinHandle<()>>) -> Result<()> {
    for thread in nbd_threads {
        let _ = thread.join();
    }
    Ok(())
}

/// vhost-user CLI settings, kept separate so the serving code does not depend on
/// the parts of `Args` consumed during adapter setup.
struct VhostUserArgs {
    socket: Option<PathBuf>,
    // Only the Linux build has a frontend to configure; elsewhere `socket` is
    // rejected outright.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    queues: usize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    queue_size: u16,
}

#[cfg(target_os = "linux")]
fn vhost_user_options(args: &VhostUserArgs) -> cats_blockd::vhost_user::VhostUserOptions {
    cats_blockd::vhost_user::VhostUserOptions {
        num_queues: args.queues,
        queue_size: args.queue_size,
    }
}

#[cfg(target_os = "linux")]
fn bind_vhost_user(args: &VhostUserArgs) -> Result<Option<vhost::vhost_user::Listener>> {
    match &args.socket {
        Some(path) => Ok(Some(
            cats_blockd::vhost_user::bind(path, vhost_user_options(args))
                .with_context(|| format!("bind vhost-user socket {}", path.display()))?,
        )),
        None => Ok(None),
    }
}

#[cfg(not(target_os = "linux"))]
fn bind_vhost_user(args: &VhostUserArgs) -> Result<Option<()>> {
    if args.socket.is_some() {
        bail!("--listen-vhost-user requires Linux (vhost-user needs eventfd and shared Guest memory)");
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn serve_vhost_user(
    listener: Option<vhost::vhost_user::Listener>,
    args: &VhostUserArgs,
    engine: std::sync::Arc<ChunkEngine>,
    nbd_threads: Vec<std::thread::JoinHandle<()>>,
) -> Result<()> {
    match listener {
        Some(mut listener) => {
            cats_blockd::vhost_user::serve_listener(&mut listener, engine, vhost_user_options(args))
                .context("serve vhost-user-blk")?;
            tracing::info!("vhost-user client disconnected; detaching");
            Ok(())
        }
        None => serve_nbd_only(nbd_threads),
    }
}

#[cfg(not(target_os = "linux"))]
fn serve_vhost_user(
    _listener: Option<()>,
    _args: &VhostUserArgs,
    _engine: std::sync::Arc<ChunkEngine>,
    nbd_threads: Vec<std::thread::JoinHandle<()>>,
) -> Result<()> {
    serve_nbd_only(nbd_threads)
}

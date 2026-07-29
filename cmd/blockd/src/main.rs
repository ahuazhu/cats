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
    /// Required unless `--publish-image` is given, which serves no volume.
    #[arg(long)]
    volume_id: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    attachment_id: Option<String>,

    /// Provider-neutral metadata-store adapter name. Not needed to publish an
    /// image, which touches no volume metadata.
    #[arg(long)]
    metadata_store_adapter: Option<String>,
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

    /// Delete objects this volume no longer references, then exit (spec §9).
    ///
    /// Takes the volume's lease like any attachment, which is what makes it safe:
    /// no other writer can be publishing objects the Root does not name yet.
    /// Never touches `images/` — those belong to the image, not to any volume.
    #[arg(long)]
    collect_garbage: bool,

    /// Publish this raw image as a shared base image and exit, printing
    /// `IMAGE <image-id>` (ADR-0017).
    ///
    /// Separate from serving a volume on purpose: publishing uploads the whole
    /// image and belongs to the fleet, not to one attachment. Doing it while
    /// holding a volume's lease means holding a lease (1.5 s as the node agent
    /// configures it) across a multi-second upload, which real hardware showed
    /// loses the lease and fails the launch. Idempotent and keyed by the image's
    /// digest, so calling it on every node start is the intended usage.
    #[arg(long)]
    publish_image: Option<PathBuf>,

    /// Provision an empty volume from an already-published image (ADR-0017).
    ///
    /// This is the per-launch path: it costs one manifest GET plus a map write,
    /// no data bytes. A volume that already has a generation is left alone, so it
    /// is safe to pass on a resume too.
    #[arg(long, conflicts_with = "seed_image")]
    seed_image_id: Option<String>,

    /// Provision an empty volume from this raw image, publishing it first if
    /// needed. Convenient for standalone and dev use; a node agent should
    /// `--publish-image` once and then pass `--seed-image-id`, because this path
    /// re-hashes the image on every launch to learn its id.
    #[arg(long)]
    seed_image: Option<PathBuf>,

    /// Sweep unreachable objects every N ms while serving (0 disables it).
    ///
    /// On by default: without it, superseded objects accumulate for the life of a
    /// volume and nothing else is in a position to remove them, because a sweep
    /// needs the volume's lease and this process holds it.
    #[arg(long, default_value_t = 600_000)]
    gc_interval_ms: u64,

    #[arg(long, default_value_t = 5_000)]
    lease_ttl_ms: i64,

    /// How long to wait for a held lease to expire before giving up.
    #[arg(long, default_value_t = 15_000)]
    acquire_wait_ms: u64,

    /// When a FLUSH acknowledgment reaches the Guest (ADR-0021).
    ///
    /// `strict` (default): after the commit is durable in the object store.
    /// `relaxed`: after the pack is durable on local disk; a background
    /// committer publishes every `drain_interval_ms`. Relaxed trades a bounded
    /// loss window on host loss for local-latency fsync.
    #[arg(long, default_value = "strict")]
    durability: String,

    /// Relaxed mode: how often the background committer publishes staged
    /// packs. Bounds the loss window together with the staged-pack cap.
    #[arg(long, default_value_t = 5_000)]
    drain_interval_ms: u64,

    /// Host-side control socket. One command per connection, one line each
    /// way: `drain` publishes every staged pack and answers `OK <generation>`
    /// or `ERR <message>`. The node agent uses it at the forced flush points
    /// of the relaxed contract (ADR-0021); on a strict volume it is a no-op.
    #[arg(long)]
    listen_control: Option<PathBuf>,
}

/// Publish a shared base image and report what it cost.
fn publish_image(blob: &dyn cats_storage::BlobStore, path: &Path) -> Result<()> {
    let started = std::time::Instant::now();
    let published = cats_blockd::image::publish(blob, path).context("publish base image")?;
    tracing::info!(
        image = %published.manifest.image_id,
        chunks = published.manifest.chunks.len(),
        already_published = published.already_present,
        uploaded_objects = published.objects_written,
        uploaded_bytes = published.bytes_written,
        publish_ms = started.elapsed().as_millis(),
        "published base image"
    );
    // Machine-readable, so a node agent can publish once and then pass
    // --seed-image-id to every launch.
    println!("IMAGE {}", published.manifest.image_id);
    Ok(())
}

/// Provision a fresh volume from a shared base image, or do nothing if it already
/// has data.
///
/// The manifest is resolved *before* attaching, so no lease is held while the
/// image is being read or uploaded; only the map write happens under the lease.
fn seed_from_image(
    engine: &cats_blockd::engine::ChunkEngine,
    manifest: &cats_blockd::format::ImageManifest,
) -> Result<()> {
    if engine.generation() != 0 {
        tracing::info!(
            generation = engine.generation(),
            "volume already has data; not seeding from the image"
        );
        return Ok(());
    }
    let started = std::time::Instant::now();
    let generation = engine
        .provision_from_image(manifest)
        .context("provision from base image")?;
    tracing::info!(
        image = %manifest.image_id,
        chunks = manifest.chunks.len(),
        provision_ms = started.elapsed().as_millis(),
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

    // Publishing an image serves no volume, so it needs neither a lease nor a
    // metadata store, and it must not hold one: the upload takes seconds.
    if let Some(path) = &args.publish_image {
        return publish_image(blob.as_ref(), path);
    }

    // Reject an impossible listener set before taking the attachment lease.
    if args.listen_unix.is_some() && args.listen_tcp.is_some() {
        bail!("--listen-unix and --listen-tcp are mutually exclusive");
    }
    // A GC pass attaches to the volume but serves no Guest, so it needs no socket.
    if !args.collect_garbage
        && args.listen_unix.is_none()
        && args.listen_tcp.is_none()
        && args.listen_vhost_user.is_none()
    {
        bail!("give at least one of --listen-unix, --listen-tcp or --listen-vhost-user");
    }
    let volume_id = args
        .volume_id
        .clone()
        .context("--volume-id is required to serve a volume")?;
    let data_dir = args
        .data_dir
        .clone()
        .context("--data-dir is required to serve a volume")?;
    let attachment_id = args
        .attachment_id
        .clone()
        .context("--attachment-id is required to serve a volume")?;
    let metadata_store_adapter = args
        .metadata_store_adapter
        .clone()
        .context("--metadata-store-adapter is required to serve a volume")?;

    // Resolve the image before attaching, for the same reason: reading and
    // uploading it must not happen under the volume's lease.
    let seed = match (&args.seed_image_id, &args.seed_image) {
        (Some(image_id), _) => Some(
            cats_blockd::image::load(blob.as_ref(), image_id)
                .with_context(|| format!("load base image {image_id}"))?,
        ),
        (None, Some(path)) => Some(
            cats_blockd::image::publish(blob.as_ref(), path)
                .with_context(|| format!("publish base image {}", path.display()))?
                .manifest,
        ),
        (None, None) => None,
    };

    let metadata_config =
        AdapterConfig::from_cli(args.metadata_store_options).context("metadata adapter options")?;
    let metadata_factories: [&dyn MetadataStoreFactory; 2] =
        [&SqliteMetadataStoreFactory, &PostgresMetadataStoreFactory];
    let meta = open_metadata_store(
        &metadata_store_adapter,
        &metadata_config,
        &metadata_factories,
    )
    .context("open metadata store")?;

    if let Some(size) = args.create_volume_size {
        let size = cats_api::chunk::round_up_to_chunk(size);
        match meta.create_volume(&volume_id, size) {
            Ok(()) | Err(MetaError::AlreadyExists(_)) => {}
            Err(error) => return Err(error).context("create volume"),
        }
    }

    let durability = match args.durability.as_str() {
        "strict" => cats_blockd::engine::DurabilityMode::Strict,
        "relaxed" => cats_blockd::engine::DurabilityMode::Relaxed {
            drain_interval_ms: args.drain_interval_ms,
        },
        other => anyhow::bail!("unknown --durability {other:?}; expected strict or relaxed"),
    };
    let config = EngineConfig {
        volume_id: volume_id.clone(),
        data_dir,
        attachment_id,
        lease_ttl_ms: args.lease_ttl_ms,
        durability,
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
        volume = %volume_id,
        epoch = engine.epoch(),
        generation = engine.generation(),
        "attached"
    );

    if let Some(manifest) = &seed {
        seed_from_image(&engine, manifest)
            .with_context(|| format!("seed volume {volume_id} from image {}", manifest.image_id))?;
    }

    if args.collect_garbage {
        let stats = engine.collect_garbage().context("collect garbage")?;
        engine.detach();
        println!(
            "GC data_live={} data_deleted={} nodes_live={} nodes_deleted={}",
            stats.data_objects_live,
            stats.data_objects_deleted,
            stats.map_nodes_live,
            stats.map_nodes_deleted
        );
        return Ok(());
    }

    engine.start_gc_thread(std::time::Duration::from_millis(args.gc_interval_ms));

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
    if let Some(path) = &args.listen_control {
        if path.exists() {
            std::fs::remove_file(path).ok();
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("bind control socket {}", path.display()))?;
        let engine = engine.clone();
        std::thread::spawn(move || serve_control(listener, engine));
    }

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

/// The host-side control plane of one blockd: line-oriented, one command per
/// connection. Failure to serve one connection never takes the loop down.
fn serve_control(listener: UnixListener, engine: std::sync::Arc<cats_blockd::engine::ChunkEngine>) {
    use std::io::{BufRead, BufReader, Write};
    for connection in listener.incoming() {
        let Ok(connection) = connection else { return };
        let engine = engine.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(&connection);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                return;
            }
            let reply = match line.trim() {
                "drain" => match engine.drain_staged() {
                    Ok(generation) => format!("OK {generation}\n"),
                    Err(error) => format!("ERR {error}\n"),
                },
                other => format!("ERR unknown command {other:?}\n"),
            };
            let _ = (&connection).write_all(reply.as_bytes());
        });
    }
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

//! cats-blockd composition root: selects storage adapters and serves one
//! volume under one attachment lease.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse};
use cats_api::runtime_reconciliation::{Id, RandomId128};
use cats_blockd::engine::{ChunkEngine, EngineConfig, ProvisionRootImageEffectError};
use cats_blockd::nbd;
use cats_metadata_store_postgres::{PostgresMetadataStoreFactory, PostgresVolumeDataAuthority};
use cats_metadata_store_sqlite::SqliteMetadataStoreFactory;
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStoreFactory;
use cats_storage::authority::AuthorizedServingAttachment;
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

    /// Adopt an already-granted owner/epoch and expose only the A14 root-image
    /// provision control command. This mode never binds a Guest data frontend.
    #[arg(long)]
    control_only: bool,

    /// Adopt the exact target-authority grant in this bounded canonical JSON
    /// file and expose a serving Guest frontend. This mode never acquires,
    /// increments, releases, or otherwise changes attachment ownership.
    #[arg(long, value_name = "PATH")]
    authorized_serving_spec: Option<PathBuf>,

    /// Complete exact grant for the signed root-provision control process.
    /// This shares the frozen grant shape with serving but never opens a Guest
    /// frontend.
    #[arg(long, value_name = "PATH", requires = "control_only")]
    authorized_control_spec: Option<PathBuf>,

    /// Exact transient-unit identity already fsynced by Runtime.
    #[arg(long, value_name = "ID")]
    runtime_scope_id: Option<String>,

    /// Fresh process-attempt token already fsynced by Runtime.
    #[arg(long, value_name = "RANDOM_ID_128")]
    process_identity_token: Option<String>,

    /// Exact grant epoch to adopt in `--control-only` mode.
    #[arg(long, requires = "control_only")]
    attachment_epoch: Option<i64>,

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
    // Temporary V1-only baseline. The runtime vertical cutover deletes both
    // seed flags; the new reconciler never invokes or parses this implicit
    // effect and control-only mode rejects it.
    #[arg(long, conflicts_with = "seed_image", hide = true)]
    seed_image_id: Option<String>,

    /// Provision an empty volume from this raw image, publishing it first if
    /// needed. Convenient for standalone and dev use; a node agent should
    /// `--publish-image` once and then pass `--seed-image-id`, because this path
    /// re-hashes the image on every launch to learn its id.
    #[arg(long, hide = true)]
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
    /// committer publishes every `drain_interval_ms`. Relaxed trades the
    /// currently observed unpublished age/bytes on Host loss for local-latency
    /// fsync; the interval is a publication target, not an RPO guarantee.
    #[arg(long, default_value = "strict")]
    durability: String,

    /// Relaxed mode: target interval for publishing staged packs. A remote
    /// outage can extend the actual RPO; query `status` on the control socket
    /// for the authoritative unpublished age and bytes.
    #[arg(long, default_value_t = 5_000)]
    drain_interval_ms: u64,

    /// Relaxed mode: local NVMe bytes reserved for acknowledged generations
    /// that have not reached the remote durability watermark.
    #[arg(long, default_value_t = cats_blockd::engine::DEFAULT_MAX_STAGED_BYTES)]
    max_staged_bytes: u64,

    /// Relaxed mode: maximum number of locally durable, remotely unpublished
    /// generations. Complements the byte cap for tiny fsync-heavy workloads.
    #[arg(long, default_value_t = cats_blockd::engine::DEFAULT_MAX_STAGED_PACKS)]
    max_staged_packs: usize,

    /// Physical local footprint ceiling for this volume's cache blocks plus
    /// remotely unpublished packs. Clean LRU chunks are hole-punched first;
    /// authoritative local state is backpressured, never evicted.
    #[arg(long, default_value_t = cats_blockd::engine::DEFAULT_MAX_LOCAL_BYTES)]
    max_local_bytes: u64,

    /// Host-side control socket. One command per connection, one line each
    /// way: `drain` publishes every staged pack and answers `OK <generation>`
    /// or `ERR <message>`; `status` answers `OK <json>` with both durability
    /// watermarks and the local backlog. The node agent uses `drain` at forced
    /// flush points; on a strict volume it is a no-op.
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

fn read_authorized_serving_attachment(path: &Path) -> Result<AuthorizedServingAttachment> {
    const MAX_BYTES: u64 = 32 * 1024;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open authorized serving spec {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect authorized serving spec {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.len() > MAX_BYTES {
        bail!(
            "authorized serving spec {} is not one bounded regular file",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read authorized serving spec {}", path.display()))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("authorized serving spec exceeds {MAX_BYTES} bytes");
    }
    let attachment: AuthorizedServingAttachment =
        serde_json::from_slice(&bytes).context("decode authorized serving spec")?;
    let canonical = serde_json::to_vec(&attachment).context("encode authorized serving spec")?;
    if canonical != bytes {
        bail!("authorized serving spec is not canonical JSON");
    }
    Ok(attachment)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    validate_process_mode(&args)?;
    let runtime_process_identity = runtime_process_identity(&args)?;
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
    if !args.control_only
        && !args.collect_garbage
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
        max_staged_bytes: args.max_staged_bytes,
        max_staged_packs: args.max_staged_packs,
        max_local_bytes: args.max_local_bytes,
    };
    let authorized_serving = args
        .authorized_serving_spec
        .as_deref()
        .map(read_authorized_serving_attachment)
        .transpose()?;
    let authorized_control = args
        .authorized_control_spec
        .as_deref()
        .map(read_authorized_serving_attachment)
        .transpose()?;
    let engine = if args.control_only {
        let authority = PostgresVolumeDataAuthority::open(&metadata_config)
            .context("open target volume authority")?;
        let attachment = authorized_control
            .as_ref()
            .context("process-mode validation requires an authorized control grant")?;
        let presented_epoch = args
            .attachment_epoch
            .context("process-mode validation requires an attachment epoch")?;
        if u64::try_from(presented_epoch).ok() != Some(attachment.identity.attachment_epoch.get()) {
            bail!("--attachment-epoch does not match --authorized-control-spec");
        }
        ChunkEngine::attach_authorized_control_only(
            config,
            attachment.clone(),
            blob.clone(),
            authority,
        )
        .context("adopt exact authorized control-only chunk engine")?
    } else if let Some(attachment) = authorized_serving.as_ref() {
        let authority = PostgresVolumeDataAuthority::open(&metadata_config)
            .context("open target volume authority")?;
        ChunkEngine::attach_authorized_serving(config, attachment.clone(), blob.clone(), authority)
            .context("adopt authorized serving chunk engine")?
    } else {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(args.acquire_wait_ms);
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
        loop {
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
        }
    };

    tracing::info!(
        volume = %volume_id,
        epoch = engine.epoch(),
        generation = engine.generation(),
        "attached"
    );

    if args.control_only {
        let path = args
            .listen_control
            .as_ref()
            .expect("process-mode validation requires a control socket");
        if path.exists() {
            bail!(
                "control socket {} already exists; refusing to replace an unverified owner",
                path.display()
            );
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("bind control socket {}", path.display()))?;
        println!("READY {}", path.display());
        // Deliberately no detach/release: this process adopted, rather than
        // created, the grant. The runtime owns release and the later serving
        // process must be able to restart under the same exact owner/epoch.
        serve_root_provision_control(
            listener,
            engine,
            runtime_process_identity
                .clone()
                .context("process-mode validation requires Runtime process identity")?,
        );
        return Ok(());
    }

    if let Some(manifest) = &seed {
        seed_from_image(&engine, manifest)
            .with_context(|| format!("seed volume {volume_id} from image {}", manifest.image_id))?;
    }

    if args.collect_garbage {
        let stats = engine.collect_garbage().context("collect garbage")?;
        engine.detach().context("detach after garbage collection")?;
        println!(
            "GC data_live={} data_deleted={} nodes_live={} nodes_deleted={}",
            stats.data_objects_live,
            stats.data_objects_deleted,
            stats.map_nodes_live,
            stats.map_nodes_deleted
        );
        return Ok(());
    }

    // The signed Runtime slice does not invoke the legacy attachment-owned GC
    // loop. Object reclamation remains fail-closed until it has its own typed
    // target authority/evidence boundary.
    if authorized_serving.is_none() {
        engine.start_gc_thread(std::time::Duration::from_millis(args.gc_interval_ms));
    }

    // Bind every requested socket before printing READY: a VMM told to start on
    // readiness must never race a socket that does not exist yet.
    let nbd_unix = match &args.listen_unix {
        Some(path) => {
            if path.exists() {
                if authorized_serving.is_some() {
                    bail!(
                        "authorized serving socket {} already exists; refusing to replace an unverified owner",
                        path.display()
                    );
                }
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
    let vhost_user = bind_vhost_user(&vhost_user_args, authorized_serving.is_none())?;
    if let Some(path) = &args.listen_control {
        if path.exists() {
            if authorized_serving.is_some() {
                bail!(
                    "authorized control socket {} already exists; refusing to replace an unverified owner",
                    path.display()
                );
            }
            std::fs::remove_file(path).ok();
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("bind control socket {}", path.display()))?;
        let engine = engine.clone();
        let process_identity = runtime_process_identity.clone();
        std::thread::spawn(move || serve_legacy_control(listener, engine, process_identity));
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
        nbd_threads.push(std::thread::spawn(move || {
            nbd::serve_unix(listener, engine)
        }));
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
    let serving = serve_vhost_user(vhost_user, &vhost_user_args, engine.clone(), nbd_threads);
    let detached = if authorized_serving.is_some() {
        engine
            .stop_authorized_serving()
            .context("final authorized blockd drain and stop")
    } else {
        engine.detach().context("final blockd drain and detach")
    };
    serving?;
    detached
}

/// The host-side control plane of one blockd: line-oriented, one command per
/// connection. Failure to serve one connection never takes the loop down.
fn serve_legacy_control(
    listener: UnixListener,
    engine: std::sync::Arc<cats_blockd::engine::ChunkEngine>,
    process_identity: Option<RuntimeProcessIdentity>,
) {
    use std::io::{BufRead, BufReader, Write};
    for connection in listener.incoming() {
        let Ok(connection) = connection else { return };
        let engine = engine.clone();
        let process_identity = process_identity.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(&connection);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                return;
            }
            let reply = match line.trim().parse::<BlockdControlCommand>() {
                Ok(BlockdControlCommand::Drain) => match engine.drain_staged() {
                    Ok(generation) => BlockdControlResponse::ok(generation.to_string()),
                    Err(error) => BlockdControlResponse::error(error.to_string()),
                },
                Ok(BlockdControlCommand::Status) => {
                    match runtime_status_json(&engine, process_identity.as_ref()) {
                        Ok(status) => BlockdControlResponse::ok(status),
                        Err(error) => {
                            BlockdControlResponse::error(format!("serialize status: {error}"))
                        }
                    }
                }
                Err(error) => {
                    BlockdControlResponse::error(format!("unknown command {:?}", error.command()))
                }
            };
            let _ = (&connection).write_all(reply.to_wire().as_bytes());
        });
    }
}

const PROVISION_COMMAND_PREFIX: &[u8] = b"provision_root_image ";
const PROVISION_CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct RuntimeProcessIdentity {
    scope_id: Id,
    process_identity_token: RandomId128,
    control_only: bool,
}

fn runtime_status_json(
    engine: &cats_blockd::engine::ChunkEngine,
    process_identity: Option<&RuntimeProcessIdentity>,
) -> serde_json::Result<String> {
    let mut status = engine.durability_status();
    if let Some(identity) = process_identity {
        status.size_bytes = Some(engine.size());
        status.scope_id = Some(identity.scope_id.clone());
        status.process_identity_token = Some(identity.process_identity_token.clone());
        status.control_only = Some(identity.control_only);
    }
    serde_json::to_string(&status)
}

/// Serve only the A14 provision effect. Connections are handled serially: a
/// single transition is the only useful work and this keeps admission memory
/// bounded without adding a second concurrency policy to the daemon.
fn serve_root_provision_control(
    listener: UnixListener,
    engine: std::sync::Arc<cats_blockd::engine::ChunkEngine>,
    process_identity: RuntimeProcessIdentity,
) {
    for connection in listener.incoming() {
        let Ok(mut connection) = connection else {
            return;
        };
        if connection.set_nonblocking(true).is_err() {
            continue;
        }
        let Some(frame) = read_first_lf_frame(
            &mut connection,
            cats_api::runtime_reconciliation::PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
            PROVISION_CONTROL_IO_TIMEOUT,
        ) else {
            continue;
        };
        if frame == BlockdControlCommand::Status.as_wire().as_bytes() {
            if let Ok(status) = runtime_status_json(&engine, Some(&process_identity)) {
                let response = BlockdControlResponse::ok(status).to_wire();
                let _ = write_all_before(
                    &mut connection,
                    response.as_bytes(),
                    PROVISION_CONTROL_IO_TIMEOUT,
                );
            }
            continue;
        }
        let Some(payload) = frame.strip_prefix(PROVISION_COMMAND_PREFIX) else {
            continue;
        };
        let Ok(request) =
            cats_api::runtime_reconciliation::decode_provision_root_image_request(payload)
        else {
            continue;
        };
        let response = match engine.provision_root_image(&request) {
            Ok(result) => {
                cats_api::runtime_reconciliation::encode_provision_root_image_result(&result)
                    .ok()
                    .map(|json| (b"OK ".as_slice(), json))
            }
            Err(ProvisionRootImageEffectError::Closed(error)) => {
                cats_api::runtime_reconciliation::encode_provision_root_image_error(&error)
                    .ok()
                    .map(|json| (b"ERR ".as_slice(), json))
            }
            Err(ProvisionRootImageEffectError::ResultUnknown(_)) => None,
        };
        if let Some((prefix, payload)) = response {
            let mut frame = Vec::with_capacity(prefix.len() + payload.len() + 1);
            frame.extend_from_slice(prefix);
            frame.extend_from_slice(&payload);
            frame.push(b'\n');
            let _ = write_all_before(&mut connection, &frame, PROVISION_CONTROL_IO_TIMEOUT);
        }
    }
}

/// Read one first-LF frame without ever retaining byte `maximum + 1` of the
/// JSON payload. Bytes after the first LF belong to neither this request nor a
/// second command; the caller responds and closes the connection immediately.
fn read_first_lf_frame(
    stream: &mut UnixStream,
    maximum: usize,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now().checked_add(timeout)?;
    let maximum = maximum.checked_add(PROVISION_COMMAND_PREFIX.len())?;
    let mut frame = Vec::with_capacity(maximum.min(4096));
    let mut buffer = [0_u8; 512];
    loop {
        ensure_before(deadline)?;
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for_io(deadline)?;
                continue;
            }
            Err(_) => return None,
        };
        if read == 0 {
            return None;
        }
        for &byte in &buffer[..read] {
            if byte == b'\n' {
                if frame.last() == Some(&b'\r') {
                    return None;
                }
                return Some(frame);
            }
            if frame.len() == maximum {
                return None;
            }
            frame.push(byte);
        }
    }
}

fn write_all_before(stream: &mut UnixStream, mut bytes: &[u8], timeout: Duration) -> Option<()> {
    let deadline = Instant::now().checked_add(timeout)?;
    while !bytes.is_empty() {
        ensure_before(deadline)?;
        match stream.write(bytes) {
            Ok(0) => return None,
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for_io(deadline)?;
            }
            Err(_) => return None,
        }
    }
    Some(())
}

fn wait_for_io(deadline: Instant) -> Option<()> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    if remaining.is_zero() {
        return None;
    }
    std::thread::sleep(remaining.min(Duration::from_millis(1)));
    Some(())
}

fn ensure_before(deadline: Instant) -> Option<()> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
}

fn validate_process_mode(args: &Args) -> Result<()> {
    if args.control_only {
        if args.authorized_serving_spec.is_some() {
            bail!("--control-only conflicts with --authorized-serving-spec");
        }
        if args.authorized_control_spec.is_none() {
            bail!("--control-only requires --authorized-control-spec");
        }
        if args.attachment_epoch.is_none() {
            bail!("--control-only requires --attachment-epoch");
        }
        if args.listen_control.is_none() {
            bail!("--control-only requires --listen-control");
        }
        if args.listen_unix.is_some()
            || args.listen_tcp.is_some()
            || args.listen_vhost_user.is_some()
        {
            bail!("--control-only forbids every NBD and vhost-user listener");
        }
        if args.seed_image_id.is_some()
            || args.seed_image.is_some()
            || args.publish_image.is_some()
            || args.collect_garbage
            || args.create_volume_size.is_some()
        {
            bail!(
                "--control-only forbids legacy seed, image publish, GC, and volume creation modes"
            );
        }
        if args.metadata_store_adapter.as_deref() != Some("postgres") {
            bail!("--control-only requires --metadata-store-adapter postgres");
        }
    } else if args.authorized_serving_spec.is_some() {
        if args.authorized_control_spec.is_some() {
            bail!("--authorized-serving-spec conflicts with --authorized-control-spec");
        }
        if args.attachment_epoch.is_some() {
            bail!("--authorized-serving-spec carries its own exact attachment epoch");
        }
        if args.seed_image_id.is_some()
            || args.seed_image.is_some()
            || args.publish_image.is_some()
            || args.collect_garbage
            || args.create_volume_size.is_some()
        {
            bail!(
                "--authorized-serving-spec forbids legacy seed, image publish, GC, and volume creation modes"
            );
        }
        if args.metadata_store_adapter.as_deref() != Some("postgres") {
            bail!("--authorized-serving-spec requires --metadata-store-adapter postgres");
        }
        if args.listen_tcp.is_some() {
            bail!("--authorized-serving-spec forbids the unscoped TCP frontend");
        }
        let control = args
            .listen_control
            .as_ref()
            .context("--authorized-serving-spec requires --listen-control for exact handshake")?;
        if args.listen_unix.as_ref() == Some(control)
            || args.listen_vhost_user.as_ref() == Some(control)
            || matches!(
                (&args.listen_unix, &args.listen_vhost_user),
                (Some(nbd), Some(vhost)) if nbd == vhost
            )
        {
            bail!("authorized serving listener paths must be pairwise distinct");
        }
    } else if args.attachment_epoch.is_some() {
        bail!("--attachment-epoch is only valid with --control-only");
    } else if args.authorized_control_spec.is_some() {
        bail!("--authorized-control-spec is only valid with --control-only");
    }
    let _ = runtime_process_identity(args)?;
    Ok(())
}

fn runtime_process_identity(args: &Args) -> Result<Option<RuntimeProcessIdentity>> {
    let target_mode = args.control_only || args.authorized_serving_spec.is_some();
    match (
        target_mode,
        args.runtime_scope_id.as_deref(),
        args.process_identity_token.as_deref(),
    ) {
        (false, None, None) => Ok(None),
        (false, _, _) => bail!(
            "--runtime-scope-id and --process-identity-token are only valid for signed target modes"
        ),
        (true, Some(scope), Some(token)) => Ok(Some(RuntimeProcessIdentity {
            scope_id: Id::new(scope.to_owned()).context("--runtime-scope-id is not a valid Id")?,
            process_identity_token: RandomId128::new(token.to_owned())
                .context("--process-identity-token is not a valid RandomId128")?,
            control_only: args.control_only,
        })),
        (true, _, _) => bail!(
            "signed target modes require --runtime-scope-id and --process-identity-token together"
        ),
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
fn bind_vhost_user(
    args: &VhostUserArgs,
    replace_existing: bool,
) -> Result<Option<vhost::vhost_user::Listener>> {
    match &args.socket {
        Some(path) => {
            let listener = if replace_existing {
                cats_blockd::vhost_user::bind(path, vhost_user_options(args))
            } else {
                cats_blockd::vhost_user::bind_new(path, vhost_user_options(args))
            };
            Ok(Some(listener.with_context(|| {
                format!("bind vhost-user socket {}", path.display())
            })?))
        }
        None => Ok(None),
    }
}

#[cfg(not(target_os = "linux"))]
fn bind_vhost_user(args: &VhostUserArgs, _replace_existing: bool) -> Result<Option<()>> {
    if args.socket.is_some() {
        bail!(
            "--listen-vhost-user requires Linux (vhost-user needs eventfd and shared Guest memory)"
        );
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
            cats_blockd::vhost_user::serve_listener(
                &mut listener,
                engine,
                vhost_user_options(args),
            )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_target(extra: &[&str]) -> Args {
        let mut arguments = vec![
            "cats-blockd",
            "--object-store-adapter",
            "file",
            "--metadata-store-adapter",
            "postgres",
            "--authorized-serving-spec",
            "/runtime/attachment.json",
            "--listen-control",
            "/runtime/control.sock",
            "--runtime-scope-id",
            "cats-cat_01-root.scope",
            "--process-identity-token",
            "13579bdf2468ace013579bdf2468ace0",
        ];
        arguments.extend_from_slice(extra);
        Args::try_parse_from(arguments).unwrap()
    }

    #[test]
    fn authorized_serving_process_mode_is_a_closed_nonlegacy_surface() {
        assert!(
            validate_process_mode(&parse_target(&["--listen-unix", "/runtime/block.sock"])).is_ok()
        );

        for forbidden in [
            vec!["--listen-tcp", "127.0.0.1:10809"],
            vec!["--collect-garbage"],
            vec!["--create-volume-size", "4194304"],
            vec!["--seed-image-id", "legacy-image"],
        ] {
            assert!(
                validate_process_mode(&parse_target(&forbidden)).is_err(),
                "authorized serving unexpectedly accepted {forbidden:?}"
            );
        }
    }

    #[test]
    fn authorized_serving_requires_distinct_local_handshake_and_frontend_names() {
        let missing_control = Args::try_parse_from([
            "cats-blockd",
            "--object-store-adapter",
            "file",
            "--metadata-store-adapter",
            "postgres",
            "--authorized-serving-spec",
            "/runtime/attachment.json",
            "--listen-unix",
            "/runtime/block.sock",
        ])
        .unwrap();
        assert!(validate_process_mode(&missing_control).is_err());

        let same_name = parse_target(&["--listen-unix", "/runtime/control.sock"]);
        assert!(validate_process_mode(&same_name).is_err());
    }
}

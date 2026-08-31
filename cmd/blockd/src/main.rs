//! cats-blockd composition root: selects storage adapters and serves one
//! volume under one attachment lease.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use cats_blockd::engine::{ChunkEngine, EngineConfig, ProvisionRootImageEffectError};
use cats_blockd::nbd;
use cats_metadata_store_postgres::PostgresVolumeDataAuthority;
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStoreFactory;
use cats_protocol::blockd::{BlockdControlCommand, BlockdControlResponse};
use cats_protocol::runtime_reconciliation::{
    HostPath, Id, ProvisionRootImageRequest, ProvisionRootImageResult, RandomId128,
    GUEST_DEVICE_SERIAL_MAX_BYTES_V1,
};
use cats_storage::authority::AuthorizedServingAttachment;
use cats_storage::{open_blob_store, AdapterConfig, BlobStoreFactory};
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

    /// Exact checkpointed provision transition which owns the managed Root
    /// control socket.
    #[arg(long, value_name = "RANDOM_ID_128", requires = "control_only")]
    provision_transition_id: Option<String>,

    /// Exact transient-unit identity already fsynced by Runtime.
    #[arg(long, value_name = "ID")]
    runtime_scope_id: Option<String>,

    /// Fresh process-attempt token already fsynced by Runtime.
    #[arg(long, value_name = "RANDOM_ID_128")]
    process_identity_token: Option<String>,

    /// Fresh Guest-device token already fsynced by Runtime. Authorized serving
    /// requires this even for kernel NBD; vhost-user binds the owned listener
    /// atomically with process startup.
    #[arg(long, value_name = "RANDOM_ID_128")]
    device_ownership_token: Option<String>,

    /// Exact Cloud Hypervisor V53 Guest-visible virtio-blk serial. Every
    /// authorized serving mode requires this even on the kernel-NBD path so
    /// process status and the later VMM launch share one sealed identity.
    #[arg(long, value_name = "ID")]
    guest_device_serial: Option<String>,

    /// Volume Authority adapter. The terminal release accepts only PostgreSQL;
    /// the option remains explicit so deployment cannot silently select a
    /// different authority.
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
    /// Serve vhost-user-blk on this unix socket path (Linux only). Signed
    /// serving chooses exactly one Guest frontend.
    #[arg(long)]
    listen_vhost_user: Option<PathBuf>,
    /// virtio-blk virtqueues to expose (must match the VMM's num_queues).
    #[arg(long, default_value_t = 1)]
    vhost_user_queues: usize,
    /// Depth of each virtqueue (power of two).
    #[arg(long, default_value_t = 256)]
    vhost_user_queue_size: u16,

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

    #[arg(long, default_value_t = 5_000)]
    lease_ttl_ms: i64,

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
    // Machine-readable so the external provisioning effect can persist and
    // reference the immutable manifest without coupling publication to serve.
    println!("IMAGE {}", published.manifest.image_id);
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

/// Process-local authority for the Runtime-selected data directory.
///
/// PID 1 cannot inherit the Node Agent's descriptor table, so Runtime argv
/// carries the canonical pathname. Once blockd has opened that pathname with a
/// no-follow traversal, Linux engine I/O is rooted through blockd's own live
/// descriptor. The trailing `/.` is deliberate: engine startup applies
/// `O_NOFOLLOW` to the final component, while the trusted procfs magic link is
/// an intermediate component naming this already-retained descriptor.
struct RetainedEngineDataDirectory {
    canonical_path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
    lexical_chain: Vec<LocalDirectoryIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalDirectoryIdentity {
    device: u64,
    inode: u64,
}

impl RetainedEngineDataDirectory {
    fn open(canonical_path: &Path) -> Result<Self> {
        let (directory, lexical_chain) = open_private_directory_with_chain(canonical_path)?;
        let metadata = directory
            .metadata()
            .with_context(|| format!("inspect data directory {}", canonical_path.display()))?;
        Ok(Self {
            canonical_path: canonical_path.to_path_buf(),
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
            lexical_chain,
        })
    }

    fn assert_current(&self) -> Result<()> {
        let retained = self
            .directory
            .metadata()
            .context("reinspect retained engine data directory")?;
        let (lexical, lexical_chain) = open_private_directory_with_chain(&self.canonical_path)?;
        let lexical = lexical
            .metadata()
            .context("reinspect lexical engine data directory")?;
        if retained.dev() != self.device
            || retained.ino() != self.inode
            || lexical.dev() != self.device
            || lexical.ino() != self.inode
            || lexical_chain != self.lexical_chain
        {
            bail!("engine data directory ancestor chain changed identity before attach");
        }
        Ok(())
    }

    fn engine_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from(format!("/proc/self/fd/{}/.", self.directory.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // fdescfs on macOS does not support descendant lookup through a
            // directory fd. Production transient services are Linux-only; the
            // retained/fresh identity closure still protects portable startup.
            self.canonical_path.clone()
        }
    }
}

fn open_private_directory_with_chain(path: &Path) -> Result<(File, Vec<LocalDirectoryIdentity>)> {
    if !path.is_absolute() {
        bail!("engine data directory must be absolute");
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut directory = options
        .open(Path::new("/"))
        .context("open engine data filesystem root")?;
    let mut chain = vec![local_directory_identity(&directory)?];
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let name = CString::new(name.as_bytes())
                    .context("engine data directory component contains NUL")?;
                directory = open_directory_at(&directory, &name).with_context(|| {
                    format!(
                        "open engine data directory without symlink ancestors {}",
                        path.display()
                    )
                })?;
                chain.push(local_directory_identity(&directory)?);
            }
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => {
                bail!("engine data directory path is not canonical")
            }
        }
    }
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect engine data directory {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!(
            "engine data directory {} has unsafe metadata",
            path.display()
        );
    }
    Ok((directory, chain))
}

fn local_directory_identity(directory: &File) -> Result<LocalDirectoryIdentity> {
    let metadata = directory
        .metadata()
        .context("inspect engine data directory component")?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && metadata.ino() != 0,
        "engine data directory component lacks a stable identity"
    );
    Ok(LocalDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn open_directory_at(directory: &File, name: &CStr) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
}

fn open_at(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    loop {
        // SAFETY: the directory descriptor and NUL-terminated name remain
        // live for this call. openat retains neither and returns one owned fd.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor >= 0 {
            // SAFETY: openat returned one fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments and does not dereference memory.
    unsafe { libc::geteuid() }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut args = Args::parse();
    validate_process_mode(&args)?;
    validate_runtime_socket_paths(&args)?;
    let runtime_process_identity = runtime_process_identity(&args)?;
    // Copied out before the adapter option vectors are consumed below.
    let vhost_user_args = VhostUserArgs {
        socket: args.listen_vhost_user.clone(),
        queues: args.vhost_user_queues,
        queue_size: args.vhost_user_queue_size,
        guest_device_serial: args
            .guest_device_serial
            .as_deref()
            .map(parse_guest_device_serial)
            .transpose()?,
    };

    let object_config = AdapterConfig::from_cli(std::mem::take(&mut args.object_store_options))
        .context("object adapter options")?;
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

    if !args.control_only && args.listen_unix.is_none() && args.listen_vhost_user.is_none() {
        bail!("give exactly one of --listen-unix or --listen-vhost-user");
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
    let metadata_config = AdapterConfig::from_cli(std::mem::take(&mut args.metadata_store_options))
        .context("metadata adapter options")?;
    let durability = match args.durability.as_str() {
        "strict" => cats_blockd::engine::DurabilityMode::Strict,
        "relaxed" => cats_blockd::engine::DurabilityMode::Relaxed {
            drain_interval_ms: args.drain_interval_ms,
        },
        other => anyhow::bail!("unknown --durability {other:?}; expected strict or relaxed"),
    };
    let mut config = EngineConfig {
        volume_id: volume_id.clone(),
        data_dir,
        attachment_id,
        lease_ttl_ms: args.lease_ttl_ms,
        durability,
        max_staged_bytes: args.max_staged_bytes,
        max_staged_packs: args.max_staged_packs,
        max_local_bytes: args.max_local_bytes,
    };
    let retained_engine_data_directory = runtime_process_identity
        .as_ref()
        .map(|_| RetainedEngineDataDirectory::open(&config.data_dir))
        .transpose()?;
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
    if let Some(directory) = &retained_engine_data_directory {
        // Close the pathname-to-descriptor window only after every canonical
        // authorization input has been parsed, and before the engine can
        // renew authority or touch local state.
        directory.assert_current()?;
        config.data_dir = directory.engine_path();
    }
    let engine = if args.control_only {
        let authority = PostgresVolumeDataAuthority::open(&metadata_config)
            .context("open target volume authority")?;
        let attachment = authorized_control
            .context("process-mode validation requires an authorized control grant")?;
        ChunkEngine::attach_authorized_control_only(config, attachment, blob.clone(), authority)
            .context("adopt exact authorized control-only chunk engine")?
    } else {
        let attachment = authorized_serving
            .context("process-mode validation requires an authorized serving input")?;
        let authority = PostgresVolumeDataAuthority::open(&metadata_config)
            .context("open target volume authority")?;
        ChunkEngine::attach_authorized_serving(config, attachment, blob.clone(), authority)
            .context("adopt authorized serving chunk engine")?
    };
    // EngineConfig may name blockd's procfs descriptor on Linux. Keep that
    // descriptor alive until every engine/frontend thread has stopped.
    let _retained_engine_data_directory = retained_engine_data_directory;

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

    // Bind every requested socket before printing READY: a VMM told to start on
    // readiness must never race a socket that does not exist yet.
    let nbd_unix = match &args.listen_unix {
        Some(path) => {
            if path.exists() {
                bail!(
                    "authorized serving socket {} already exists; refusing to replace an unverified owner",
                    path.display()
                );
            }
            Some(
                UnixListener::bind(path)
                    .with_context(|| format!("bind unix socket {}", path.display()))?,
            )
        }
        None => None,
    };
    let vhost_user = bind_vhost_user(&vhost_user_args)?;
    if let Some(path) = &args.listen_control {
        if path.exists() {
            bail!(
                "authorized control socket {} already exists; refusing to replace an unverified owner",
                path.display()
            );
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("bind control socket {}", path.display()))?;
        let engine = engine.clone();
        let process_identity = runtime_process_identity.clone();
        std::thread::spawn(move || serve_authorized_control(listener, engine, process_identity));
    }

    let ready = args
        .listen_vhost_user
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| args.listen_unix.as_ref().map(|p| p.display().to_string()))
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
    let serving = serve_vhost_user(vhost_user, &vhost_user_args, engine.clone(), nbd_threads);
    let detached = engine
        .stop_authorized_serving()
        .context("final authorized blockd drain and stop");
    serving?;
    detached
}

/// The host-side control plane of one blockd: line-oriented, one command per
/// connection. Failure to serve one connection never takes the loop down.
fn serve_authorized_control(
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
    device_ownership_token: Option<RandomId128>,
    guest_device_serial: Option<Id>,
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
        status.device_ownership_token = identity.device_ownership_token.clone();
        status.guest_device_serial = identity.guest_device_serial.clone();
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
            cats_protocol::runtime_reconciliation::PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
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
            cats_protocol::runtime_reconciliation::decode_provision_root_image_request(payload)
        else {
            continue;
        };
        let response = encode_root_provision_response(&request, |request| {
            engine.provision_root_image(request)
        });
        if let Some((prefix, payload)) = response {
            let mut frame = Vec::with_capacity(prefix.len() + payload.len() + 1);
            frame.extend_from_slice(prefix);
            frame.extend_from_slice(&payload);
            frame.push(b'\n');
            let _ = write_all_before(&mut connection, &frame, PROVISION_CONTROL_IO_TIMEOUT);
        }
    }
}

fn encode_root_provision_response(
    request: &ProvisionRootImageRequest,
    effect: impl FnOnce(
        &ProvisionRootImageRequest,
    )
        -> std::result::Result<ProvisionRootImageResult, ProvisionRootImageEffectError>,
) -> Option<(&'static [u8], Vec<u8>)> {
    match effect(request) {
        Ok(result) => {
            cats_protocol::runtime_reconciliation::encode_provision_root_image_result(&result)
                .ok()
                .map(|json| (b"OK ".as_slice(), json))
        }
        Err(ProvisionRootImageEffectError::Closed(error)) => {
            cats_protocol::runtime_reconciliation::encode_provision_root_image_error(&error)
                .ok()
                .map(|json| (b"ERR ".as_slice(), json))
        }
        Err(ProvisionRootImageEffectError::ResultUnknown(_)) => None,
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
    let authorized_serving = args.authorized_serving_spec.is_some();
    if args.control_only {
        if authorized_serving {
            bail!("--control-only conflicts with authorized serving input");
        }
        if args.authorized_control_spec.is_none() {
            bail!("--control-only requires --authorized-control-spec");
        }
        if args.provision_transition_id.is_none() {
            bail!("--authorized-control-spec requires --provision-transition-id");
        }
        if args.listen_control.is_none() {
            bail!("--control-only requires --listen-control");
        }
        if args.listen_unix.is_some() || args.listen_vhost_user.is_some() {
            bail!("--control-only forbids every NBD and vhost-user listener");
        }
        if args.publish_image.is_some() {
            bail!("--control-only forbids image publication");
        }
        if args.metadata_store_adapter.as_deref() != Some("postgres") {
            bail!("--control-only requires --metadata-store-adapter postgres");
        }
    } else if authorized_serving {
        if args.authorized_control_spec.is_some() {
            bail!("authorized serving input conflicts with authorized control input");
        }
        if args.provision_transition_id.is_some() {
            bail!("authorized serving input forbids a provision transition");
        }
        if args.publish_image.is_some() {
            bail!("authorized serving input forbids image publication");
        }
        if args.metadata_store_adapter.as_deref() != Some("postgres") {
            bail!("authorized serving input requires --metadata-store-adapter postgres");
        }
        let control = args
            .listen_control
            .as_ref()
            .context("authorized serving input requires --listen-control for exact handshake")?;
        if !matches!(
            (args.listen_unix.is_some(), args.listen_vhost_user.is_some()),
            (true, false) | (false, true)
        ) {
            bail!("authorized serving input requires exactly one NBD or vhost-user frontend");
        }
        if args.listen_unix.as_ref() == Some(control)
            || args.listen_vhost_user.as_ref() == Some(control)
            || matches!(
                (&args.listen_unix, &args.listen_vhost_user),
                (Some(nbd), Some(vhost)) if nbd == vhost
            )
        {
            bail!("authorized serving listener paths must be pairwise distinct");
        }
        if args.listen_vhost_user.is_some() {
            cats_blockd::frontend_contract::validate_authorized_vhost_shape(
                args.vhost_user_queues,
                args.vhost_user_queue_size,
            )
            .context("authorized-serving vhost-user shape is outside the frozen contract")?;
        }
    } else if args.publish_image.is_some() {
        if args.volume_id.is_some()
            || args.data_dir.is_some()
            || args.attachment_id.is_some()
            || args.metadata_store_adapter.is_some()
        {
            bail!("--publish-image is a standalone object-store operation");
        }
    } else if args.authorized_control_spec.is_some() {
        bail!("authorized control input is only valid with --control-only");
    } else if args.provision_transition_id.is_some() {
        bail!("--provision-transition-id is only valid with --control-only");
    } else {
        bail!("volume serving requires one complete authorized serving artifact");
    }
    if args.listen_vhost_user.is_some() && args.guest_device_serial.is_none() {
        bail!("--listen-vhost-user requires --guest-device-serial");
    }
    let _ = runtime_process_identity(args)?;
    Ok(())
}

/// Reject an arbitrary Runtime-supplied AF_UNIX pathname before opening an
/// engine or binding a listener. The public CLI fields remain persisted wire
/// values, but only the provider-owned mapping may reach a signed process.
fn validate_runtime_socket_paths(args: &Args) -> Result<()> {
    let socket_root = admitted_runtime_socket_root()?;
    if args.control_only {
        let transition = RandomId128::new(
            args.provision_transition_id
                .clone()
                .context("control-only mode requires --provision-transition-id")?,
        )
        .context("--provision-transition-id is not a valid RandomId128")?;
        let paths = socket_root
            .root_paths(&transition)
            .context("derive managed Root blockd socket paths")?;
        let control = args
            .listen_control
            .as_deref()
            .context("control-only mode requires --listen-control")?;
        anyhow::ensure!(
            control == Path::new(paths.control_socket().as_str()),
            "control-only listener is outside the transition-owned blockd namespace"
        );
        return Ok(());
    }

    if args.authorized_serving_spec.is_some() {
        let ownership = RandomId128::new(
            args.device_ownership_token
                .clone()
                .context("authorized serving requires --device-ownership-token")?,
        )
        .context("--device-ownership-token is not a valid RandomId128")?;
        let paths = socket_root
            .serving_paths(&ownership)
            .context("derive managed serving blockd socket paths")?;
        let control = args
            .listen_control
            .as_deref()
            .context("authorized serving requires --listen-control")?;
        let frontend = args
            .listen_unix
            .as_deref()
            .or(args.listen_vhost_user.as_deref())
            .context("authorized serving requires one Guest frontend")?;
        anyhow::ensure!(
            control == Path::new(paths.control_socket().as_str())
                && frontend == Path::new(paths.io_socket().as_str()),
            "authorized serving listeners are outside the device-owned blockd namespace"
        );
    }
    Ok(())
}

/// Production admits only the installed socket namespace. Debug artifacts
/// used by real-binary integration tests may opt into one canonical temporary
/// root through an environment capability; the branch and its capability name
/// are absent from release binaries and there is no CLI switch for it.
fn admitted_runtime_socket_root(
) -> Result<cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot> {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os("CATS_BLOCKD_TEST_SOCKET_ROOT") {
        let value = value
            .into_string()
            .map_err(|_| anyhow::anyhow!("test socket root is not UTF-8"))?;
        let path = HostPath::new(value).context("test socket root is not a canonical HostPath")?;
        return cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::from_canonical_path(
            path,
        )
        .context("test socket root does not fit the managed socket contract");
    }
    Ok(cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed())
}

fn runtime_process_identity(args: &Args) -> Result<Option<RuntimeProcessIdentity>> {
    let target_mode = args.control_only || args.authorized_serving_spec.is_some();
    if !target_mode {
        if args.runtime_scope_id.is_some()
            || args.process_identity_token.is_some()
            || args.device_ownership_token.is_some()
        {
            bail!(
                "--runtime-scope-id, --process-identity-token and --device-ownership-token are only valid for signed target modes"
            );
        }
        if let Some(serial) = args.guest_device_serial.as_deref() {
            anyhow::ensure!(
                args.listen_vhost_user.is_some(),
                "--guest-device-serial outside signed serving requires --listen-vhost-user"
            );
            let _ = parse_guest_device_serial(serial)?;
        }
        return Ok(None);
    }

    let scope = args
        .runtime_scope_id
        .as_deref()
        .context("signed target modes require --runtime-scope-id")?;
    let process_token = args
        .process_identity_token
        .as_deref()
        .context("signed target modes require --process-identity-token")?;
    let process_identity_token = RandomId128::new(process_token.to_owned())
        .context("--process-identity-token is not a valid RandomId128")?;
    let device_ownership_token = match (args.control_only, args.device_ownership_token.as_deref()) {
        (true, None) => None,
        (true, Some(_)) => bail!("--control-only forbids --device-ownership-token"),
        (false, Some(token)) => Some(
            RandomId128::new(token.to_owned())
                .context("--device-ownership-token is not a valid RandomId128")?,
        ),
        (false, None) => bail!("authorized serving requires --device-ownership-token"),
    };
    if device_ownership_token.as_ref() == Some(&process_identity_token) {
        bail!("process and device ownership tokens must differ");
    }
    let guest_device_serial = match (args.control_only, args.guest_device_serial.as_deref()) {
        (true, None) => None,
        (true, Some(_)) => bail!("--control-only forbids --guest-device-serial"),
        (false, Some(serial)) => Some(parse_guest_device_serial(serial)?),
        (false, None) => bail!("authorized serving requires --guest-device-serial"),
    };
    Ok(Some(RuntimeProcessIdentity {
        scope_id: Id::new(scope.to_owned()).context("--runtime-scope-id is not a valid Id")?,
        process_identity_token,
        device_ownership_token,
        guest_device_serial,
        control_only: args.control_only,
    }))
}

fn parse_guest_device_serial(value: &str) -> Result<Id> {
    let serial = Id::new(value.to_owned()).context("--guest-device-serial is not a valid Id")?;
    anyhow::ensure!(
        (1..=GUEST_DEVICE_SERIAL_MAX_BYTES_V1).contains(&serial.as_str().len()),
        "--guest-device-serial must contain 1..={} UTF-8 bytes",
        GUEST_DEVICE_SERIAL_MAX_BYTES_V1
    );
    Ok(serial)
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
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    guest_device_serial: Option<Id>,
}

#[cfg(target_os = "linux")]
fn vhost_user_options(args: &VhostUserArgs) -> Result<cats_blockd::vhost_user::VhostUserOptions> {
    let serial = args
        .guest_device_serial
        .as_ref()
        .context("--listen-vhost-user requires --guest-device-serial")?;
    Ok(cats_blockd::vhost_user::VhostUserOptions {
        num_queues: args.queues,
        queue_size: args.queue_size,
        guest_device_serial: cats_blockd::vhost_user::VhostUserDeviceId::from_guest_device_serial(
            serial,
        )
        .context("validate vhost-user Guest device serial")?,
    })
}

#[cfg(target_os = "linux")]
fn bind_vhost_user(args: &VhostUserArgs) -> Result<Option<vhost::vhost_user::Listener>> {
    match &args.socket {
        Some(path) => {
            let options = vhost_user_options(args)?;
            let listener = cats_blockd::vhost_user::bind_new(path, options);
            Ok(Some(listener.with_context(|| {
                format!("bind vhost-user socket {}", path.display())
            })?))
        }
        None => Ok(None),
    }
}

#[cfg(not(target_os = "linux"))]
fn bind_vhost_user(args: &VhostUserArgs) -> Result<Option<()>> {
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
                vhost_user_options(args)?,
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
    use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    const TARGET_VOLUME_ID: &str = "vol_target";
    const TARGET_ATTACHMENT_ID: &str = "att_target";
    const TARGET_TRANSITION: &str = "13579bdf2468ace013579bdf2468ace0";

    fn managed_root_control_socket(transition: &RandomId128) -> PathBuf {
        PathBuf::from(
            ManagedBlockdSocketRoot::installed()
                .root_paths(transition)
                .unwrap()
                .control_socket()
                .as_str(),
        )
    }

    fn managed_serving_sockets(ownership_token: &RandomId128) -> (PathBuf, PathBuf) {
        let paths = ManagedBlockdSocketRoot::installed()
            .serving_paths(ownership_token)
            .unwrap();
        (
            PathBuf::from(paths.control_socket().as_str()),
            PathBuf::from(paths.io_socket().as_str()),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_engine_root_survives_a_canonical_directory_replacement() {
        let temp = tempfile::tempdir().expect("create retained engine root fixture");
        let parent = temp.path().join("node");
        let canonical = parent.join("data");
        std::fs::create_dir_all(&canonical).expect("create canonical data directory");
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700))
            .expect("make canonical data directory private");
        let retained =
            RetainedEngineDataDirectory::open(&canonical).expect("retain canonical data directory");
        let engine_path = retained.engine_path();
        assert!(engine_path.starts_with("/proc/self/fd"));
        assert_ne!(engine_path, canonical);

        let displaced_parent = temp.path().join("node-displaced");
        std::fs::rename(&parent, &displaced_parent).expect("displace retained data parent");
        std::fs::create_dir(&parent).expect("create replacement data parent");
        std::fs::rename(displaced_parent.join("data"), &canonical)
            .expect("move exact retained data leaf beneath replacement parent");
        assert_eq!(
            std::fs::metadata(&canonical).unwrap().dev(),
            retained.device
        );
        assert_eq!(std::fs::metadata(&canonical).unwrap().ino(), retained.inode);
        let error = retained
            .assert_current()
            .expect_err("replacement ancestor with the exact leaf must fail closed");
        assert!(error
            .to_string()
            .contains("ancestor chain changed identity"));

        std::fs::rename(&canonical, displaced_parent.join("data"))
            .expect("return retained data leaf to its original parent");
        std::fs::create_dir(&canonical).expect("create replacement data directory");
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700))
            .expect("make replacement data directory private");

        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let reopened = options
            .open(&engine_path)
            .expect("engine O_NOFOLLOW startup can reopen retained root");
        assert_eq!(reopened.metadata().unwrap().dev(), retained.device);
        assert_eq!(reopened.metadata().unwrap().ino(), retained.inode);

        std::fs::write(engine_path.join("probe"), b"retained")
            .expect("write through process-local retained root");
        assert_eq!(
            std::fs::read(displaced_parent.join("data/probe")).unwrap(),
            b"retained"
        );
        assert!(!canonical.join("probe").exists());
    }

    fn control_mode() -> Args {
        let transition = RandomId128::new(TARGET_TRANSITION).unwrap();
        let control_socket = managed_root_control_socket(&transition);
        Args::try_parse_from(vec![
            "cats-blockd".to_owned(),
            "--volume-id".to_owned(),
            TARGET_VOLUME_ID.to_owned(),
            "--data-dir".to_owned(),
            "/runtime/root-data".to_owned(),
            "--attachment-id".to_owned(),
            TARGET_ATTACHMENT_ID.to_owned(),
            "--object-store-adapter".to_owned(),
            "file".to_owned(),
            "--metadata-store-adapter".to_owned(),
            "postgres".to_owned(),
            "--control-only".to_owned(),
            "--authorized-control-spec".to_owned(),
            "/runtime/root-data/authorized-serving.json".to_owned(),
            "--provision-transition-id".to_owned(),
            transition.as_str().to_owned(),
            "--listen-control".to_owned(),
            control_socket.display().to_string(),
            "--runtime-scope-id".to_owned(),
            "cats-root-fixed.service".to_owned(),
            "--process-identity-token".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ])
        .unwrap()
    }

    #[test]
    fn authorized_control_requires_the_transition_owner() {
        let control = control_mode();
        assert!(validate_process_mode(&control).is_ok());
        assert!(validate_runtime_socket_paths(&control).is_ok());
        assert_eq!(
            runtime_process_identity(&control)
                .unwrap()
                .unwrap()
                .guest_device_serial,
            None
        );

        let mut missing_transition = control_mode();
        missing_transition.provision_transition_id = None;
        assert!(validate_process_mode(&missing_transition).is_err());

        let mut missing_authorization = control_mode();
        missing_authorization.authorized_control_spec = None;
        assert!(validate_process_mode(&missing_authorization).is_err());
    }

    #[test]
    fn signed_runtime_socket_paths_are_exactly_owner_mapped_before_any_effect() {
        let transition = RandomId128::new(TARGET_TRANSITION).unwrap();
        let other_transition = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab").unwrap();
        let mut root = control_mode();
        assert!(validate_runtime_socket_paths(&root).is_ok());
        root.listen_control = Some(managed_root_control_socket(&other_transition));
        assert!(validate_runtime_socket_paths(&root).is_err());

        let ownership = RandomId128::new("2468ace013579bdf2468ace013579bdf").unwrap();
        let other_ownership = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac").unwrap();
        let (control, frontend) = managed_serving_sockets(&ownership);
        let (other_control, other_frontend) = managed_serving_sockets(&other_ownership);
        let mut serving = parse_target(&["--listen-unix", "/runtime/placeholder.sock"]);
        serving.listen_control = Some(control.clone());
        serving.listen_unix = Some(frontend.clone());
        assert!(validate_process_mode(&serving).is_ok());
        assert!(validate_runtime_socket_paths(&serving).is_ok());

        serving.listen_control = Some(other_control.clone());
        assert!(validate_runtime_socket_paths(&serving).is_err());
        serving.listen_control = Some(control.clone());
        serving.listen_unix = Some(other_frontend);
        assert!(validate_runtime_socket_paths(&serving).is_err());
        serving.listen_unix = Some(frontend);
        serving.device_ownership_token = Some(other_ownership.as_str().to_owned());
        assert!(validate_runtime_socket_paths(&serving).is_err());

        serving.device_ownership_token = Some(ownership.as_str().to_owned());
        serving.listen_control = Some(other_control);
        assert!(validate_runtime_socket_paths(&serving).is_err());

        // The exact Root mapping is independently keyed by the provision
        // transition and cannot be substituted for a Serving mapping.
        serving.listen_control = Some(managed_root_control_socket(&transition));
        assert!(validate_runtime_socket_paths(&serving).is_err());
    }

    fn try_parse_target(extra: &[&str]) -> Result<Args, clap::Error> {
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
            "--device-ownership-token",
            "2468ace013579bdf2468ace013579bdf",
            "--guest-device-serial",
            "cats-root",
        ];
        arguments.extend_from_slice(extra);
        Args::try_parse_from(arguments)
    }

    fn parse_target(extra: &[&str]) -> Args {
        try_parse_target(extra).unwrap()
    }

    #[test]
    fn authorized_serving_process_mode_is_a_closed_nonlegacy_surface() {
        assert!(
            validate_process_mode(&parse_target(&["--listen-unix", "/runtime/block.sock"])).is_ok()
        );
        assert!(validate_process_mode(&parse_target(&[
            "--listen-vhost-user",
            "/runtime/vhost.sock",
        ]))
        .is_ok());
        assert!(validate_process_mode(&parse_target(&[])).is_err());
        assert!(validate_process_mode(&parse_target(&[
            "--listen-unix",
            "/runtime/block.sock",
            "--listen-vhost-user",
            "/runtime/vhost.sock",
        ]))
        .is_err());

        for forbidden in [
            vec!["--listen-tcp", "127.0.0.1:10809"],
            vec!["--collect-garbage"],
            vec!["--create-volume-size", "4194304"],
            vec!["--seed-image-id", "legacy-image"],
            vec!["--seed-image", "/legacy/image.raw"],
        ] {
            assert!(
                try_parse_target(&forbidden).is_err(),
                "legacy CLI flag parsed: {forbidden:?}"
            );
        }
    }

    #[test]
    fn authorized_serving_vhost_bounds_fail_before_the_engine_effect() {
        for (queues, queue_size) in [(0, 256), (65, 256), (1, 0), (1, 1), (1, 3), (1, 32_769)] {
            let args = parse_target(&[
                "--listen-vhost-user",
                "/runtime/vhost.sock",
                "--vhost-user-queues",
                &queues.to_string(),
                "--vhost-user-queue-size",
                &queue_size.to_string(),
            ]);
            let effect_calls = std::cell::Cell::new(0_u64);
            let result = validate_process_mode(&args).map(|()| {
                effect_calls.set(effect_calls.get() + 1);
            });
            assert!(
                result.is_err(),
                "accepted vhost shape {queues}/{queue_size}"
            );
            assert_eq!(effect_calls.get(), 0);
        }
        for (queues, queue_size) in [(1, 2), (64, 32_768)] {
            let args = parse_target(&[
                "--listen-vhost-user",
                "/runtime/vhost.sock",
                "--vhost-user-queues",
                &queues.to_string(),
                "--vhost-user-queue-size",
                &queue_size.to_string(),
            ]);
            assert!(validate_process_mode(&args).is_ok());
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

    #[test]
    fn authorized_serving_requires_a_distinct_canonical_device_token() {
        let missing = Args::try_parse_from([
            "cats-blockd",
            "--object-store-adapter",
            "file",
            "--metadata-store-adapter",
            "postgres",
            "--authorized-serving-spec",
            "/runtime/attachment.json",
            "--listen-control",
            "/runtime/control.sock",
            "--listen-unix",
            "/runtime/block.sock",
            "--runtime-scope-id",
            "cats-cat_01-root.scope",
            "--process-identity-token",
            "13579bdf2468ace013579bdf2468ace0",
            "--guest-device-serial",
            "cats-root",
        ])
        .unwrap();
        assert!(validate_process_mode(&missing).is_err());

        let mut malformed = parse_target(&["--listen-unix", "/runtime/block.sock"]);
        malformed.device_ownership_token = Some("not-a-random-id".to_owned());
        assert!(validate_process_mode(&malformed).is_err());

        let same = Args::try_parse_from([
            "cats-blockd",
            "--object-store-adapter",
            "file",
            "--metadata-store-adapter",
            "postgres",
            "--authorized-serving-spec",
            "/runtime/attachment.json",
            "--listen-control",
            "/runtime/control.sock",
            "--listen-unix",
            "/runtime/block.sock",
            "--runtime-scope-id",
            "cats-cat_01-root.scope",
            "--process-identity-token",
            "13579bdf2468ace013579bdf2468ace0",
            "--device-ownership-token",
            "13579bdf2468ace013579bdf2468ace0",
            "--guest-device-serial",
            "cats-root",
        ])
        .unwrap();
        assert!(validate_process_mode(&same).is_err());

        let identity = runtime_process_identity(&parse_target(&[
            "--listen-vhost-user",
            "/runtime/vhost.sock",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            identity.device_ownership_token.as_ref().unwrap().as_str(),
            "2468ace013579bdf2468ace013579bdf"
        );
        assert_ne!(
            identity.device_ownership_token.as_ref(),
            Some(&identity.process_identity_token)
        );
        assert_eq!(
            identity.guest_device_serial.as_ref().unwrap().as_str(),
            "cats-root"
        );

        let mut missing_serial = parse_target(&["--listen-unix", "/runtime/block.sock"]);
        missing_serial.guest_device_serial = None;
        assert!(validate_process_mode(&missing_serial).is_err());

        let mut boundary = parse_target(&["--listen-unix", "/runtime/block.sock"]);
        boundary.guest_device_serial = Some("12345678901234567890".to_owned());
        assert!(validate_process_mode(&boundary).is_ok());
        boundary.guest_device_serial = Some("123456789012345678901".to_owned());
        assert!(validate_process_mode(&boundary).is_err());

        let mut control = control_mode();
        control.guest_device_serial = Some("cats-root".to_owned());
        assert!(validate_process_mode(&control).is_err());
    }
}

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
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse};
use cats_api::runtime_reconciliation::{
    HostPath, Id, ProvisionRootImageDefiniteConflictProblem, ProvisionRootImageError,
    ProvisionRootImageRequest, ProvisionRootImageResult, RandomId128, Sha256Digest,
    GUEST_DEVICE_SERIAL_MAX_BYTES_V1,
};
use cats_blockd::engine::{ChunkEngine, EngineConfig, ProvisionRootImageEffectError};
use cats_blockd::nbd;
use cats_blockd::serving_handoff::{
    decode_serving_handoff_record, ServingHandoffRecord, SERVING_HANDOFF_RECORD_FILE,
    SERVING_HANDOFF_RECORD_MAX_BYTES,
};
use cats_blockd::target_control::{
    decode_target_control_authorization, target_control_authorization_file_name,
    StableDirectoryIdentity, StableFileIdentity, TargetControlAuthorizationArtifact,
    TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
};
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

    /// Sealed first-Root handoff record. Unlike `--authorized-serving-spec`,
    /// this mode derives the target-head attachment only after it validates
    /// both this record and its physically bound target-control artifact.
    #[arg(long, value_name = "PATH")]
    authorized_serving_handoff_record: Option<PathBuf>,

    /// Exact ProvisionRootImage checkpoint digest named by the persisted
    /// PrepareDevice handoff provenance.
    #[arg(long, value_name = "SHA256")]
    authorized_serving_handoff_predecessor_checkpoint_content_digest: Option<String>,

    /// Descriptor identity of the sealed record persisted in PrepareDevice.
    #[arg(long, value_name = "U64")]
    authorized_serving_handoff_record_device: Option<u64>,
    #[arg(long, value_name = "U64")]
    authorized_serving_handoff_record_inode: Option<u64>,
    #[arg(long, value_name = "U64")]
    authorized_serving_handoff_record_length: Option<u64>,
    #[arg(long, value_name = "SHA256")]
    authorized_serving_handoff_record_content_sha256: Option<String>,

    /// Complete exact grant for the signed root-provision control process.
    /// This shares the frozen grant shape with serving but never opens a Guest
    /// frontend.
    #[arg(long, value_name = "PATH", requires = "control_only")]
    authorized_control_spec: Option<PathBuf>,

    /// Target-head wrapper for restarting or adopting the exact root-provision
    /// control process after its generation-one CAS. This is never a serving
    /// grant and is mutually exclusive with the blank control input.
    #[arg(long, value_name = "PATH", requires = "control_only")]
    authorized_target_control_spec: Option<PathBuf>,

    /// Exact checkpointed provision transition which owns the managed Root
    /// control socket. Both blank and target control-only modes require it.
    #[arg(long, value_name = "RANDOM_ID_128", requires = "control_only")]
    provision_transition_id: Option<String>,

    /// Stable RuntimeCheckpoint authorization context expected in the wrapper.
    #[arg(
        long,
        value_name = "SHA256",
        requires = "authorized_target_control_spec"
    )]
    provision_root_authorization_context_digest: Option<String>,

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

    /// Exact externally granted attachment epoch to adopt. Target modes also
    /// bind this value through their complete authorization artifact.
    #[arg(long)]
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
    /// This never grants ownership; `--attachment-epoch` must name an owner
    /// already installed by an external authority.
    #[arg(long)]
    create_volume_size: Option<u64>,

    /// Delete objects this volume no longer references, then exit (spec §9).
    /// The caller must first install and pass an exact attachment grant.
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
    #[arg(long, conflicts_with = "seed_image", hide = true)]
    seed_image_id: Option<String>,

    /// Provision an empty volume from this raw image, publishing it first if
    /// needed. This compatibility path still requires an external grant.
    #[arg(long, hide = true)]
    seed_image: Option<PathBuf>,

    /// Sweep unreachable objects every N ms while serving (0 disables it).
    #[arg(long, default_value_t = 600_000)]
    gc_interval_ms: u64,

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
    // Machine-readable, so a node agent can publish once and then pass
    // --seed-image-id to every launch.
    println!("IMAGE {}", published.manifest.image_id);
    Ok(())
}

/// Provision a fresh volume from a shared base image, or do nothing if it
/// already has data. The image is resolved before the externally granted
/// attachment is adopted, so the grant is not held across an image upload.
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

struct TargetControlExpectation<'a> {
    data_dir: &'a Path,
    volume_id: &'a str,
    attachment_id: &'a str,
    attachment_epoch: i64,
    provision_transition_id: &'a RandomId128,
    provision_context_digest: &'a Sha256Digest,
    runtime_scope_id: &'a Id,
    control_socket_path: &'a Path,
}

fn read_target_control_authorization(
    path: &Path,
    expected: &TargetControlExpectation<'_>,
) -> Result<TargetControlAuthorizationArtifact> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open target-control authorization {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect target-control authorization {}", path.display()))?;
    let before_identity = LocalFileMetadata::from_metadata(&before);
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != effective_uid()
        || before.mode() & 0o777 != 0o600
        || before.len() > TARGET_CONTROL_AUTHORIZATION_MAX_BYTES as u64
    {
        bail!(
            "target-control authorization {} is not one bounded regular file",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(TARGET_CONTROL_AUTHORIZATION_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read target-control authorization {}", path.display()))?;
    if bytes.len() > TARGET_CONTROL_AUTHORIZATION_MAX_BYTES {
        bail!(
            "target-control authorization exceeds {} bytes",
            TARGET_CONTROL_AUTHORIZATION_MAX_BYTES
        );
    }
    let after = file
        .metadata()
        .with_context(|| format!("reinspect target-control authorization {}", path.display()))?;
    if before_identity != LocalFileMetadata::from_metadata(&after) {
        bail!("target-control authorization changed while it was read");
    }
    let artifact = decode_target_control_authorization(&bytes)
        .context("decode target-control authorization")?;
    let expected_name = target_control_authorization_file_name(expected.provision_transition_id);
    let expected_epoch = u64::try_from(expected.attachment_epoch)
        .context("--attachment-epoch is negative for target-control authorization")?;
    if artifact.provision_transition_id != *expected.provision_transition_id
        || artifact.provision_context_digest.as_sha256_digest() != expected.provision_context_digest
        || artifact.runtime_scope_id != *expected.runtime_scope_id
        || Path::new(artifact.control_socket_path.as_str()) != expected.control_socket_path
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        || path.parent() != Some(expected.data_dir)
        || Path::new(artifact.local_state.attachment_directory.path.as_str()) != expected.data_dir
        || artifact.attachment.identity.volume_id.as_str() != expected.volume_id
        || artifact.attachment.identity.attachment_id.as_str() != expected.attachment_id
        || artifact.attachment.identity.attachment_epoch.get() != expected_epoch
    {
        bail!(
            "target-control authorization does not match its transition, stable checkpoint context, process binding, path, or attachment context"
        );
    }
    validate_target_local_directory(&artifact.local_state.state_directory)?;
    validate_target_local_directory(&artifact.local_state.attachment_directory)?;
    validate_target_local_file(&artifact.local_state.attachment_identity_file)?;
    validate_target_local_file(&artifact.local_state.acquire_authorization_file)?;
    validate_target_local_file(&artifact.local_state.launch_checkpoint_file)?;
    validate_target_local_directory(&artifact.local_state.state_directory)?;
    validate_target_local_directory(&artifact.local_state.attachment_directory)?;
    let rebound = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("reopen target-control authorization {}", path.display()))?;
    let rebound_metadata = rebound
        .metadata()
        .with_context(|| format!("reinspect target-control authorization {}", path.display()))?;
    if before_identity != LocalFileMetadata::from_metadata(&rebound_metadata) {
        bail!("target-control authorization path changed during validation");
    }
    Ok(artifact)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalFileMetadata {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl LocalFileMetadata {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
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

#[derive(Debug, Clone)]
struct ServingHandoffRecordExpectation {
    path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    content_sha256: Sha256Digest,
    predecessor_checkpoint_content_digest: Sha256Digest,
}

enum AuthorizedServingInput {
    Direct(Box<AuthorizedServingAttachment>),
    RootHandoff(Box<ValidatedServingHandoff>),
}

impl AuthorizedServingInput {
    fn attachment(&self) -> &AuthorizedServingAttachment {
        match self {
            Self::Direct(attachment) => attachment,
            Self::RootHandoff(handoff) => handoff.attachment(),
        }
    }

    fn assert_current(&self) -> Result<()> {
        match self {
            Self::Direct(_) => Ok(()),
            Self::RootHandoff(handoff) => handoff.assert_current(),
        }
    }

    fn apply<T>(self, effect: impl FnOnce(AuthorizedServingAttachment) -> Result<T>) -> Result<T> {
        self.assert_current()?;
        let attachment = self.attachment().clone();
        // Keep every handoff descriptor live until the engine has consumed
        // the closed attachment. No effect is invoked before this point.
        let result = effect(attachment);
        drop(self);
        result
    }
}

struct ValidatedServingHandoff {
    data_directory: RetainedPrivateDirectory,
    local_state: RetainedTargetLocalState,
    record: RetainedPrivateFile,
    target: RetainedPrivateFile,
    decoded: ServingHandoffRecord,
}

impl ValidatedServingHandoff {
    fn attachment(&self) -> &AuthorizedServingAttachment {
        &self
            .decoded
            .target_control_authorization
            .artifact
            .attachment
    }

    fn assert_current(&self) -> Result<()> {
        let lexical_directory = self.local_state.assert_current(&self.data_directory)?;
        self.record.assert_current(
            &self.data_directory.file,
            &lexical_directory,
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        )?;
        self.target.assert_current(
            &self.data_directory.file,
            &lexical_directory,
            TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
        )?;
        Ok(())
    }
}

struct RetainedPrivateDirectory {
    path: PathBuf,
    file: File,
    identity: LocalFileMetadata,
}

impl RetainedPrivateDirectory {
    fn open(path: &Path) -> Result<Self> {
        let file = open_private_directory(path)?;
        let identity = LocalFileMetadata::from_metadata(
            &file
                .metadata()
                .with_context(|| format!("inspect retained directory {}", path.display()))?,
        );
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
        })
    }

    fn assert_retained(&self) -> Result<()> {
        let current =
            LocalFileMetadata::from_metadata(&self.file.metadata().with_context(|| {
                format!("reinspect retained directory {}", self.path.display())
            })?);
        if current != self.identity {
            bail!(
                "retained directory {} changed identity",
                self.path.display()
            );
        }
        Ok(())
    }

    fn open_current_lexical(&self) -> Result<File> {
        self.assert_retained()?;
        let lexical = open_private_directory(&self.path)?;
        let lexical_identity = LocalFileMetadata::from_metadata(
            &lexical
                .metadata()
                .with_context(|| format!("reinspect lexical directory {}", self.path.display()))?,
        );
        if lexical_identity != self.identity {
            bail!("directory path {} changed identity", self.path.display());
        }
        Ok(lexical)
    }
}

struct RetainedTargetLocalState {
    state_directory: RetainedPrivateDirectory,
    attachment_relative_path: PathBuf,
    attachment_identity_file: RetainedPrivateFile,
    acquire_authorization_file: RetainedPrivateFile,
    launch_checkpoint_file: RetainedPrivateFile,
}

impl RetainedTargetLocalState {
    fn retain(
        expected: &cats_blockd::target_control::TargetControlLocalStateIdentity,
        attachment_directory: &RetainedPrivateDirectory,
    ) -> Result<Self> {
        let state_path = Path::new(expected.state_directory.path.as_str());
        let attachment_path = Path::new(expected.attachment_directory.path.as_str());
        if attachment_directory.path != attachment_path
            || attachment_directory.identity.device != expected.attachment_directory.device.get()
            || attachment_directory.identity.inode != expected.attachment_directory.inode.get()
        {
            bail!("retained target-control attachment directory changed identity");
        }
        let attachment_relative_path = strict_descendant_path(state_path, attachment_path)
            .context("target-control attachment directory is not below its state directory")?;
        let state_directory = RetainedPrivateDirectory::open(state_path)?;
        if state_directory.identity.device != expected.state_directory.device.get()
            || state_directory.identity.inode != expected.state_directory.inode.get()
        {
            bail!("retained target-control state directory changed identity");
        }
        let relative_attachment = open_private_directory_at_path(
            &state_directory.file,
            &attachment_relative_path,
            attachment_path,
        )?;
        assert_directory_identity(
            &relative_attachment,
            attachment_directory.identity,
            attachment_path,
        )?;

        let attachment_identity_file = retain_target_local_file(
            &attachment_directory.file,
            attachment_path,
            &expected.attachment_identity_file,
        )?;
        let acquire_authorization_file = retain_target_local_file(
            &attachment_directory.file,
            attachment_path,
            &expected.acquire_authorization_file,
        )?;
        let launch_checkpoint_file = retain_target_local_file(
            &attachment_directory.file,
            attachment_path,
            &expected.launch_checkpoint_file,
        )?;

        Ok(Self {
            state_directory,
            attachment_relative_path,
            attachment_identity_file,
            acquire_authorization_file,
            launch_checkpoint_file,
        })
    }

    fn assert_current(&self, attachment_directory: &RetainedPrivateDirectory) -> Result<File> {
        attachment_directory.assert_retained()?;
        let lexical_state = self.state_directory.open_current_lexical()?;

        let retained_relative_attachment = open_private_directory_at_path(
            &self.state_directory.file,
            &self.attachment_relative_path,
            &attachment_directory.path,
        )?;
        assert_directory_identity(
            &retained_relative_attachment,
            attachment_directory.identity,
            &attachment_directory.path,
        )?;
        let lexical_attachment = open_private_directory_at_path(
            &lexical_state,
            &self.attachment_relative_path,
            &attachment_directory.path,
        )?;
        assert_directory_identity(
            &lexical_attachment,
            attachment_directory.identity,
            &attachment_directory.path,
        )?;

        for retained in [
            &self.attachment_identity_file,
            &self.acquire_authorization_file,
            &self.launch_checkpoint_file,
        ] {
            retained.assert_current(
                &attachment_directory.file,
                &lexical_attachment,
                TARGET_LOCAL_STATE_FILE_MAX_BYTES,
            )?;
        }
        Ok(lexical_attachment)
    }
}

const TARGET_LOCAL_STATE_FILE_MAX_BYTES: usize = 512 * 1024;

struct RetainedPrivateFile {
    path: PathBuf,
    file: File,
    identity: LocalFileMetadata,
    bytes: Vec<u8>,
}

impl RetainedPrivateFile {
    fn assert_current(
        &self,
        retained_directory: &File,
        lexical_directory: &File,
        maximum: usize,
    ) -> Result<()> {
        let current = LocalFileMetadata::from_metadata(
            &self
                .file
                .metadata()
                .with_context(|| format!("reinspect retained {}", self.path.display()))?,
        );
        if current != self.identity {
            bail!("retained serving handoff file changed identity");
        }
        for directory in [retained_directory, lexical_directory] {
            let reopened = read_private_file_at(directory, &self.path, maximum)?;
            if reopened.identity != self.identity || reopened.bytes != self.bytes {
                bail!(
                    "serving handoff file {} changed identity or bytes",
                    self.path.display()
                );
            }
        }
        Ok(())
    }
}

fn read_authorized_serving_input(
    args: &Args,
    config: &EngineConfig,
    process_identity: Option<&RuntimeProcessIdentity>,
) -> Result<Option<AuthorizedServingInput>> {
    match (
        args.authorized_serving_spec.as_deref(),
        args.authorized_serving_handoff_record.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => {
            bail!("direct authorized serving conflicts with serving-from-handoff")
        }
        (Some(path), None) => read_authorized_serving_attachment(path)
            .map(Box::new)
            .map(AuthorizedServingInput::Direct)
            .map(Some),
        (None, Some(path)) => {
            let predecessor_checkpoint_content_digest = Sha256Digest::new(
                args.authorized_serving_handoff_predecessor_checkpoint_content_digest
                    .clone()
                    .context("serving-from-handoff requires its predecessor checkpoint digest")?,
            )
            .context(
                "--authorized-serving-handoff-predecessor-checkpoint-content-digest is invalid",
            )?;
            let content_sha256 = Sha256Digest::new(
                args.authorized_serving_handoff_record_content_sha256
                    .clone()
                    .context("serving-from-handoff requires its record content digest")?,
            )
            .context("--authorized-serving-handoff-record-content-sha256 is invalid")?;
            let expectation = ServingHandoffRecordExpectation {
                path: path.to_path_buf(),
                device: args
                    .authorized_serving_handoff_record_device
                    .context("serving-from-handoff requires its record device")?,
                inode: args
                    .authorized_serving_handoff_record_inode
                    .context("serving-from-handoff requires its record inode")?,
                length: args
                    .authorized_serving_handoff_record_length
                    .context("serving-from-handoff requires its record length")?,
                content_sha256,
                predecessor_checkpoint_content_digest,
            };
            let process_identity = process_identity
                .context("serving-from-handoff requires Runtime process identity")?;
            read_serving_handoff_authorization(config, args, process_identity, &expectation)
                .map(Box::new)
                .map(AuthorizedServingInput::RootHandoff)
                .map(Some)
        }
    }
}

fn read_serving_handoff_authorization(
    config: &EngineConfig,
    args: &Args,
    process_identity: &RuntimeProcessIdentity,
    expected: &ServingHandoffRecordExpectation,
) -> Result<ValidatedServingHandoff> {
    if !config.data_dir.is_absolute()
        || expected.path != config.data_dir.join(SERVING_HANDOFF_RECORD_FILE)
        || expected.device == 0
        || expected.inode == 0
        || expected.length == 0
        || expected.length > SERVING_HANDOFF_RECORD_MAX_BYTES as u64
    {
        bail!("serving-from-handoff record identity is outside its exact data directory");
    }
    let data_directory = RetainedPrivateDirectory::open(&config.data_dir)?;
    let data_directory_identity = data_directory.identity;
    let record = read_private_file_at(
        &data_directory.file,
        &expected.path,
        SERVING_HANDOFF_RECORD_MAX_BYTES,
    )?;
    let record_digest = Sha256Digest::from_bytes(cats_blockd::format::sha256(&record.bytes));
    if record.identity.device != expected.device
        || record.identity.inode != expected.inode
        || record.identity.length != expected.length
        || record_digest != expected.content_sha256
    {
        bail!("serving-from-handoff record changed its persisted physical identity");
    }
    let decoded = decode_serving_handoff_record(&record.bytes)
        .context("decode canonical serving handoff record")?;
    let target_identity = &decoded.target_control_authorization;
    let target_path = Path::new(target_identity.path.as_str());
    let expected_target_name =
        target_control_authorization_file_name(&decoded.provision_transition_id);
    if decoded.checkpoint_content_digest != expected.predecessor_checkpoint_content_digest
        || decoded.volume_id.as_str() != config.volume_id
        || decoded.attachment_id.as_str() != config.attachment_id
        || Path::new(decoded.old_control_process.data_directory.as_str()) != config.data_dir
        || Path::new(
            decoded
                .target_control_authorization
                .artifact
                .local_state
                .attachment_directory
                .path
                .as_str(),
        ) != config.data_dir
        || target_path.parent() != Some(config.data_dir.as_path())
        || target_path.file_name().and_then(|name| name.to_str())
            != Some(expected_target_name.as_str())
        || data_directory_identity.device != target_identity.device.get()
        || data_directory_identity.device
            != decoded
                .target_control_authorization
                .artifact
                .local_state
                .attachment_directory
                .device
                .get()
        || data_directory_identity.inode
            != decoded
                .target_control_authorization
                .artifact
                .local_state
                .attachment_directory
                .inode
                .get()
    {
        bail!(
            "serving-from-handoff record is stale for its predecessor, attachment, or data directory"
        );
    }
    let target = read_private_file_at(
        &data_directory.file,
        target_path,
        TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
    )?;
    let target_digest = Sha256Digest::from_bytes(cats_blockd::format::sha256(&target.bytes));
    if target.identity.device != target_identity.device.get()
        || target.identity.inode != target_identity.inode.get()
        || target.identity.length != target_identity.length.get()
        || target_digest != target_identity.content_sha256
    {
        bail!("serving-from-handoff target-control artifact changed physical identity");
    }
    let target_artifact = decode_target_control_authorization(&target.bytes)
        .context("decode serving-from-handoff target-control authorization")?;
    if target_artifact != target_identity.artifact {
        bail!("serving-from-handoff target-control bytes differ from the sealed record");
    }
    let local_state =
        RetainedTargetLocalState::retain(&target_artifact.local_state, &data_directory)?;

    let attachment = &target_artifact.attachment;
    let lease_ttl_ms = u64::try_from(config.lease_ttl_ms)
        .context("serving-from-handoff lease duration is not positive")?;
    let durability_matches = matches!(
        (&config.durability, attachment.durability),
        (
            cats_blockd::engine::DurabilityMode::Strict,
            cats_storage::authority::VolumeDurability::Strict
        ) | (
            cats_blockd::engine::DurabilityMode::Relaxed { .. },
            cats_storage::authority::VolumeDurability::Relaxed
        )
    );
    let device_token = process_identity
        .device_ownership_token
        .as_ref()
        .context("serving-from-handoff requires a device ownership token")?;
    let old_process = &decoded.old_control_process;
    let serving_control = args
        .listen_control
        .as_deref()
        .context("serving-from-handoff requires a control socket")?;
    let serving_frontend = args
        .listen_unix
        .as_deref()
        .or(args.listen_vhost_user.as_deref())
        .context("serving-from-handoff requires one Guest frontend")?;
    if attachment.identity.volume_id.as_str() != config.volume_id
        || attachment.identity.attachment_id.as_str() != config.attachment_id
        || attachment.identity != old_process.handshake.identity
        || attachment.head != decoded.expected_provisioned_head
        || attachment.lease_duration_ms() != lease_ttl_ms
        || !durability_matches
        || process_identity.control_only
        || process_identity.process_identity_token == old_process.ownership_token
        || *device_token == old_process.ownership_token
        || process_identity.scope_id == old_process.scope_id
        || serving_control == Path::new(old_process.control_socket_path.as_str())
        || serving_frontend == Path::new(old_process.control_socket_path.as_str())
    {
        bail!(
            "serving-from-handoff does not bind one fresh serving process to the sealed attachment"
        );
    }

    let ready = ValidatedServingHandoff {
        data_directory,
        local_state,
        record,
        target,
        decoded,
    };
    ready.assert_current()?;
    Ok(ready)
}

fn open_private_directory(path: &Path) -> Result<File> {
    open_private_directory_with_chain(path).map(|(directory, _)| directory)
}

fn open_private_directory_with_chain(path: &Path) -> Result<(File, Vec<LocalDirectoryIdentity>)> {
    if !path.is_absolute() {
        bail!("serving handoff directory must be absolute");
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut directory = options
        .open(Path::new("/"))
        .context("open serving handoff filesystem root")?;
    let mut chain = vec![local_directory_identity(&directory)?];
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let name = CString::new(name.as_bytes())
                    .context("serving handoff directory component contains NUL")?;
                directory = open_directory_at(&directory, &name).with_context(|| {
                    format!(
                        "open serving handoff directory without symlink ancestors {}",
                        path.display()
                    )
                })?;
                chain.push(local_directory_identity(&directory)?);
            }
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => {
                bail!("serving handoff directory path is not canonical")
            }
        }
    }
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect serving handoff directory {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!(
            "serving handoff directory {} has unsafe metadata",
            path.display()
        );
    }
    Ok((directory, chain))
}

fn local_directory_identity(directory: &File) -> Result<LocalDirectoryIdentity> {
    let metadata = directory
        .metadata()
        .context("inspect serving handoff directory component")?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && metadata.ino() != 0,
        "serving handoff directory component lacks a stable identity"
    );
    Ok(LocalDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn strict_descendant_path(parent: &Path, child: &Path) -> Option<PathBuf> {
    let relative = child.strip_prefix(parent).ok()?;
    let mut saw_component = false;
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return None;
        }
        saw_component = true;
    }
    saw_component.then(|| relative.to_path_buf())
}

fn open_private_directory_at_path(
    parent: &File,
    relative: &Path,
    display_path: &Path,
) -> Result<File> {
    let mut directory = parent
        .try_clone()
        .with_context(|| format!("retain parent directory for {}", display_path.display()))?;
    let mut saw_component = false;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!(
                "retained directory path {} is not a strict canonical descendant",
                display_path.display()
            );
        };
        saw_component = true;
        let name =
            CString::new(name.as_bytes()).context("retained directory component contains NUL")?;
        directory = open_directory_at(&directory, &name).with_context(|| {
            format!(
                "open retained directory descriptor-relative {}",
                display_path.display()
            )
        })?;
    }
    if !saw_component {
        bail!(
            "retained directory path {} is not a strict descendant",
            display_path.display()
        );
    }
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect retained directory {}", display_path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!(
            "retained directory {} has unsafe metadata",
            display_path.display()
        );
    }
    Ok(directory)
}

fn assert_directory_identity(
    directory: &File,
    expected: LocalFileMetadata,
    path: &Path,
) -> Result<()> {
    let current = LocalFileMetadata::from_metadata(
        &directory
            .metadata()
            .with_context(|| format!("reinspect retained directory {}", path.display()))?,
    );
    if current != expected {
        bail!("retained directory {} changed identity", path.display());
    }
    Ok(())
}

fn retain_target_local_file(
    attachment_directory: &File,
    attachment_path: &Path,
    expected: &StableFileIdentity,
) -> Result<RetainedPrivateFile> {
    let path = Path::new(expected.path.as_str());
    if path.parent() != Some(attachment_path) {
        bail!(
            "retained target-control file {} is outside its attachment directory",
            path.display()
        );
    }
    let retained = read_private_file_at(
        attachment_directory,
        path,
        TARGET_LOCAL_STATE_FILE_MAX_BYTES,
    )?;
    let digest = Sha256Digest::from_bytes(cats_blockd::format::sha256(&retained.bytes));
    if retained.identity.device != expected.device.get()
        || retained.identity.inode != expected.inode.get()
        || retained.identity.length != expected.length.get()
        || digest != expected.content_sha256
    {
        bail!(
            "retained target-control file {} changed identity or bytes",
            path.display()
        );
    }
    Ok(retained)
}

fn read_private_file_at(
    directory: &File,
    path: &Path,
    maximum: usize,
) -> Result<RetainedPrivateFile> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("serving handoff path lacks a canonical basename")?;
    let name = CString::new(name).context("serving handoff basename contains NUL")?;
    let mut file = open_file_at(directory, &name)
        .with_context(|| format!("open serving handoff file {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect serving handoff file {}", path.display()))?;
    let before_identity = LocalFileMetadata::from_metadata(&before);
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != effective_uid()
        || before.mode() & 0o7777 != 0o600
        || before.len() > maximum as u64
    {
        bail!(
            "serving handoff file {} is not one private bounded regular file",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity((before.len() as usize).min(maximum));
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read serving handoff file {}", path.display()))?;
    if bytes.len() > maximum {
        bail!(
            "serving handoff file {} exceeds {maximum} bytes",
            path.display()
        );
    }
    let after = file
        .metadata()
        .with_context(|| format!("reinspect serving handoff file {}", path.display()))?;
    if before_identity != LocalFileMetadata::from_metadata(&after)
        || before.len() != bytes.len() as u64
    {
        bail!("serving handoff file changed while it was read");
    }
    Ok(RetainedPrivateFile {
        path: path.to_path_buf(),
        file,
        identity: before_identity,
        bytes,
    })
}

fn open_file_at(directory: &File, name: &CStr) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
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

fn validate_target_local_directory(identity: &StableDirectoryIdentity) -> Result<()> {
    let path = Path::new(identity.path.as_str());
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let directory = options
        .open(path)
        .with_context(|| format!("open retained target-control directory {}", path.display()))?;
    let metadata = directory.metadata().with_context(|| {
        format!(
            "inspect retained target-control directory {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.dev() != identity.device.get()
        || metadata.ino() != identity.inode.get()
    {
        bail!(
            "retained target-control directory {} changed identity",
            path.display()
        );
    }
    Ok(())
}

fn validate_target_local_file(identity: &StableFileIdentity) -> Result<()> {
    let path = Path::new(identity.path.as_str());
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open retained target-control file {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect retained target-control file {}", path.display()))?;
    let before_identity = LocalFileMetadata::from_metadata(&before);
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != effective_uid()
        || before.mode() & 0o7777 != 0o600
        || before.dev() != identity.device.get()
        || before.ino() != identity.inode.get()
        || before.len() != identity.length.get()
    {
        bail!(
            "retained target-control file {} changed identity",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(identity.length.get() as usize);
    std::io::Read::by_ref(&mut file)
        .take(identity.length.get().saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read retained target-control file {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect retained target-control file {}", path.display()))?;
    if before_identity != LocalFileMetadata::from_metadata(&after)
        || bytes.len() as u64 != identity.length.get()
        || Sha256Digest::from_bytes(cats_blockd::format::sha256(&bytes)) != identity.content_sha256
    {
        bail!(
            "retained target-control file {} changed bytes or metadata",
            path.display()
        );
    }
    Ok(())
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

    // Reject an impossible listener set before taking the attachment lease.
    if args.listen_unix.is_some() && args.listen_tcp.is_some() {
        bail!("--listen-unix and --listen-tcp are mutually exclusive");
    }
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

    // Resolve the image before adopting the externally installed grant. Image
    // publication must not consume any of the attachment lease window.
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
    let authorized_serving =
        read_authorized_serving_input(&args, &config, runtime_process_identity.as_ref())?;
    let authorized_serving_mode = authorized_serving.is_some();
    let authorized_control = args
        .authorized_control_spec
        .as_deref()
        .map(read_authorized_serving_attachment)
        .transpose()?;
    let authorized_target_control =
        if let Some(path) = args.authorized_target_control_spec.as_deref() {
            let provision_transition_id = RandomId128::new(
                args.provision_transition_id
                    .clone()
                    .context("process-mode validation requires a provision transition ID")?,
            )
            .context("--provision-transition-id is not a valid RandomId128")?;
            let provision_context_digest = Sha256Digest::new(
                args.provision_root_authorization_context_digest
                    .clone()
                    .context("process-mode validation requires a provision context digest")?,
            )
            .context("--provision-root-authorization-context-digest is not a valid Sha256Digest")?;
            let attachment_epoch = args
                .attachment_epoch
                .context("process-mode validation requires an attachment epoch")?;
            let process_identity = runtime_process_identity
                .as_ref()
                .context("process-mode validation requires Runtime process identity")?;
            let control_socket_path = args
                .listen_control
                .as_deref()
                .context("process-mode validation requires a control socket")?;
            Some(read_target_control_authorization(
                path,
                &TargetControlExpectation {
                    data_dir: &config.data_dir,
                    volume_id: &volume_id,
                    attachment_id: &config.attachment_id,
                    attachment_epoch,
                    provision_transition_id: &provision_transition_id,
                    provision_context_digest: &provision_context_digest,
                    runtime_scope_id: &process_identity.scope_id,
                    control_socket_path,
                },
            )?)
        } else {
            None
        };
    let expected_target_request = authorized_target_control
        .as_ref()
        .map(|artifact| artifact.request.clone());
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
        let attachment = authorized_target_control
            .as_ref()
            .map(|artifact| &artifact.attachment)
            .or(authorized_control.as_ref())
            .context("process-mode validation requires an authorized control grant")?;
        let presented_epoch = args
            .attachment_epoch
            .context("process-mode validation requires an attachment epoch")?;
        if u64::try_from(presented_epoch).ok() != Some(attachment.identity.attachment_epoch.get()) {
            bail!("--attachment-epoch does not match the authorized control input");
        }
        ChunkEngine::attach_authorized_control_only(
            config,
            attachment.clone(),
            blob.clone(),
            authority,
        )
        .context("adopt exact authorized control-only chunk engine")?
    } else if let Some(input) = authorized_serving {
        // Opening PostgreSQL may block. Complete it before `apply` performs
        // the final descriptor-relative handoff revalidation, so the closure
        // crosses directly into the engine effect with no intervening setup.
        let authority = PostgresVolumeDataAuthority::open(&metadata_config)
            .context("open target volume authority")?;
        input.apply(|attachment| {
            ChunkEngine::attach_authorized_serving(config, attachment, blob.clone(), authority)
                .context("adopt authorized serving chunk engine")
        })?
    } else {
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
        let expected_epoch = args
            .attachment_epoch
            .context("compatibility serving requires --attachment-epoch")?;
        ChunkEngine::attach_granted_epoch(config, expected_epoch, blob.clone(), meta)
            .context("adopt exact externally granted chunk engine")?
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
            expected_target_request,
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

    // The signed target Runtime does not invoke the compatibility-owned GC
    // loop. The explicit-grant dev/data-plane composition preserves its
    // existing collector without gaining any ownership transition.
    if !authorized_serving_mode {
        engine.start_gc_thread(std::time::Duration::from_millis(args.gc_interval_ms));
    }

    // Bind every requested socket before printing READY: a VMM told to start on
    // readiness must never race a socket that does not exist yet.
    let nbd_unix = match &args.listen_unix {
        Some(path) => {
            if path.exists() {
                if authorized_serving_mode {
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
    let vhost_user = bind_vhost_user(&vhost_user_args, !authorized_serving_mode)?;
    if let Some(path) = &args.listen_control {
        if path.exists() {
            if authorized_serving_mode {
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
    let detached = if authorized_serving_mode {
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
    expected_target_request: Option<ProvisionRootImageRequest>,
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
        let response =
            encode_root_provision_response(&request, expected_target_request.as_ref(), |request| {
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
    expected_target_request: Option<&ProvisionRootImageRequest>,
    effect: impl FnOnce(
        &ProvisionRootImageRequest,
    )
        -> std::result::Result<ProvisionRootImageResult, ProvisionRootImageEffectError>,
) -> Option<(&'static [u8], Vec<u8>)> {
    if expected_target_request.is_some_and(|expected| expected != request) {
        let error = ProvisionRootImageError::DefiniteConflict {
            provision_transition_id: request.provision_transition_id.clone(),
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            attachment_epoch: request.attachment_epoch,
            problem: ProvisionRootImageDefiniteConflictProblem::RequestBinding,
        };
        let payload = cats_api::runtime_reconciliation::encode_provision_root_image_error(&error)
            .expect("an already-decoded request always forms a canonical binding error");
        return Some((b"ERR ", payload));
    }
    match effect(request) {
        Ok(result) => cats_api::runtime_reconciliation::encode_provision_root_image_result(&result)
            .ok()
            .map(|json| (b"OK ".as_slice(), json)),
        Err(ProvisionRootImageEffectError::Closed(error)) => {
            cats_api::runtime_reconciliation::encode_provision_root_image_error(&error)
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

fn validate_handoff_listener_path(path: &Path, label: &str) -> Result<()> {
    let wire = path
        .to_str()
        .with_context(|| format!("serving-from-handoff {label} path is not UTF-8"))?;
    HostPath::new(wire.to_owned()).with_context(|| {
        format!("serving-from-handoff {label} path is not one canonical absolute HostPath")
    })?;
    Ok(())
}

fn validate_process_mode(args: &Args) -> Result<()> {
    let direct_serving = args.authorized_serving_spec.is_some();
    let handoff_serving = args.authorized_serving_handoff_record.is_some();
    if direct_serving && handoff_serving {
        bail!("--authorized-serving-spec conflicts with --authorized-serving-handoff-record");
    }
    let handoff_expectations = [
        args.authorized_serving_handoff_predecessor_checkpoint_content_digest
            .is_some(),
        args.authorized_serving_handoff_record_device.is_some(),
        args.authorized_serving_handoff_record_inode.is_some(),
        args.authorized_serving_handoff_record_length.is_some(),
        args.authorized_serving_handoff_record_content_sha256
            .is_some(),
    ];
    if handoff_serving && handoff_expectations.iter().any(|present| !present) {
        bail!(
            "--authorized-serving-handoff-record requires predecessor digest and complete record physical identity"
        );
    }
    if !handoff_serving && handoff_expectations.iter().any(|present| *present) {
        bail!("serving handoff expectations require --authorized-serving-handoff-record");
    }
    let authorized_serving = direct_serving || handoff_serving;
    if args.control_only {
        if authorized_serving {
            bail!("--control-only conflicts with authorized serving input");
        }
        if args.authorized_control_spec.is_none() && args.authorized_target_control_spec.is_none() {
            bail!("--control-only requires --authorized-control-spec");
        }
        if args.authorized_control_spec.is_some() && args.authorized_target_control_spec.is_some() {
            bail!("--authorized-control-spec conflicts with --authorized-target-control-spec");
        }
        if args.authorized_target_control_spec.is_some()
            && (args.provision_transition_id.is_none()
                || args.provision_root_authorization_context_digest.is_none())
        {
            bail!(
                "--authorized-target-control-spec requires --provision-transition-id and --provision-root-authorization-context-digest"
            );
        }
        if args.authorized_control_spec.is_some()
            && (args.provision_transition_id.is_none()
                || args.provision_root_authorization_context_digest.is_some())
        {
            bail!(
                "blank --authorized-control-spec requires --provision-transition-id and forbids target checkpoint expectations"
            );
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
                "--control-only forbids compatibility seed, image publish, GC, and volume creation modes"
            );
        }
        if args.metadata_store_adapter.as_deref() != Some("postgres") {
            bail!("--control-only requires --metadata-store-adapter postgres");
        }
    } else if authorized_serving {
        if args.authorized_control_spec.is_some() || args.authorized_target_control_spec.is_some() {
            bail!("authorized serving input conflicts with authorized control input");
        }
        if args.attachment_epoch.is_some()
            || args.provision_transition_id.is_some()
            || args.provision_root_authorization_context_digest.is_some()
        {
            bail!("authorized serving input carries its own target lineage and epoch");
        }
        if args.seed_image_id.is_some()
            || args.seed_image.is_some()
            || args.publish_image.is_some()
            || args.collect_garbage
            || args.create_volume_size.is_some()
        {
            bail!(
                "authorized serving input forbids compatibility seed, image publish, GC, and volume creation modes"
            );
        }
        if args.metadata_store_adapter.as_deref() != Some("postgres") {
            bail!("authorized serving input requires --metadata-store-adapter postgres");
        }
        if args.listen_tcp.is_some() {
            bail!("authorized serving input forbids the unscoped TCP frontend");
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
        if handoff_serving {
            validate_handoff_listener_path(control, "control listener")?;
            let frontend = args
                .listen_unix
                .as_deref()
                .or(args.listen_vhost_user.as_deref())
                .context("serving-from-handoff requires one active frontend")?;
            validate_handoff_listener_path(frontend, "Guest frontend")?;
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
    } else if args.authorized_control_spec.is_some()
        || args.authorized_target_control_spec.is_some()
    {
        bail!("authorized control input is only valid with --control-only");
    } else if args.provision_transition_id.is_some()
        || args.provision_root_authorization_context_digest.is_some()
    {
        bail!("target-control expectations require --authorized-target-control-spec");
    } else if args.attachment_epoch.is_none() {
        bail!("compatibility serving requires an explicit --attachment-epoch grant");
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
    if args.control_only {
        let transition = RandomId128::new(
            args.provision_transition_id
                .clone()
                .context("control-only mode requires --provision-transition-id")?,
        )
        .context("--provision-transition-id is not a valid RandomId128")?;
        let paths = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
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

    if args.authorized_serving_spec.is_some() || args.authorized_serving_handoff_record.is_some() {
        let ownership = RandomId128::new(
            args.device_ownership_token
                .clone()
                .context("authorized serving requires --device-ownership-token")?,
        )
        .context("--device-ownership-token is not a valid RandomId128")?;
        let paths = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
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

fn runtime_process_identity(args: &Args) -> Result<Option<RuntimeProcessIdentity>> {
    let target_mode = args.control_only
        || args.authorized_serving_spec.is_some()
        || args.authorized_serving_handoff_record.is_some();
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
fn bind_vhost_user(
    args: &VhostUserArgs,
    replace_existing: bool,
) -> Result<Option<vhost::vhost_user::Listener>> {
    match &args.socket {
        Some(path) => {
            let options = vhost_user_options(args)?;
            let listener = if replace_existing {
                cats_blockd::vhost_user::bind(path, options)
            } else {
                cats_blockd::vhost_user::bind_new(path, options)
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
    use cats_api::runtime_reconciliation::{
        AcquireOrigin, AsciiText, ContractVersion, Durability, Epoch, FenceEpoch, Generation,
        HostPath, NormalAcquireRequest, NormalAcquireResult, RemoteHead, Revision, UnixMillis,
        WireU64,
    };
    use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;
    use cats_blockd::serving_handoff::{
        encode_serving_handoff_record, ServingControlProcessIdentity,
        ServingControlReloadHandshake, TargetControlAuthorizationIdentity,
    };
    use cats_blockd::target_control::{
        encode_target_control_authorization, ProvisionRootAuthorizationContextDigest,
        TargetControlLocalStateIdentity,
    };
    use cats_storage::authority::{AttachmentLineageIdentity, VolumeDurability};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    const TARGET_VOLUME_ID: &str = "vol_target";
    const TARGET_ATTACHMENT_ID: &str = "att_target";
    const TARGET_TRANSITION: &str = "13579bdf2468ace013579bdf2468ace0";
    const TARGET_DEVICE_OWNERSHIP_TOKEN: &str = "cccccccccccccccccccccccccccccccc";

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

    struct TargetControlFixture {
        _root: tempfile::TempDir,
        state_dir: PathBuf,
        data_dir: PathBuf,
        path: PathBuf,
        transition: RandomId128,
        context_digest: Sha256Digest,
        runtime_scope_id: Id,
        control_socket_path: PathBuf,
        artifact: TargetControlAuthorizationArtifact,
    }

    impl TargetControlFixture {
        fn expectation(&self) -> TargetControlExpectation<'_> {
            TargetControlExpectation {
                data_dir: &self.data_dir,
                volume_id: TARGET_VOLUME_ID,
                attachment_id: TARGET_ATTACHMENT_ID,
                attachment_epoch: 7,
                provision_transition_id: &self.transition,
                provision_context_digest: &self.context_digest,
                runtime_scope_id: &self.runtime_scope_id,
                control_socket_path: &self.control_socket_path,
            }
        }

        fn parse(&self) -> Result<TargetControlAuthorizationArtifact> {
            read_target_control_authorization(&self.path, &self.expectation())
        }

        fn write(&self, bytes: &[u8]) {
            std::fs::write(&self.path, bytes).unwrap();
        }
    }

    fn target_control_fixture() -> TargetControlFixture {
        let root = tempfile::tempdir().unwrap();
        let state_dir = root.path().canonicalize().unwrap().join("state-a");
        let data_dir = state_dir
            .join("data")
            .join("cat-cat_01")
            .join(format!("volume-{TARGET_VOLUME_ID}"))
            .join(format!("attachment-{TARGET_ATTACHMENT_ID}"))
            .join("epoch-7");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transition = RandomId128::new(TARGET_TRANSITION).unwrap();
        let acquire_transition = RandomId128::new("2468ace013579bdf2468ace013579bdf").unwrap();
        let blank_head = RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        let target_head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([0x5a; 32])),
            root_object_id: Some(AsciiText::new("roots/generation-1.node").unwrap()),
        };
        let acquire_request = NormalAcquireRequest {
            volume_id: Id::new(TARGET_VOLUME_ID).unwrap(),
            transition_id: acquire_transition.clone(),
            attachment_id: Id::new(TARGET_ATTACHMENT_ID).unwrap(),
            expected_unowned_epoch: FenceEpoch::new(6).unwrap(),
            desired_revision: Revision::new(11).unwrap(),
            placement_epoch: Epoch::new(3).unwrap(),
            lease_duration_ms: 60_000,
        };
        let acquire_result = NormalAcquireResult {
            volume_id: acquire_request.volume_id.clone(),
            transition_id: acquire_transition.clone(),
            attachment_id: acquire_request.attachment_id.clone(),
            resulting_epoch: FenceEpoch::new(7).unwrap(),
            resulting_head: blank_head.clone(),
            lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
        };
        let attachment = AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: acquire_request.volume_id.clone(),
                attachment_id: acquire_request.attachment_id.clone(),
                attachment_epoch: acquire_result.resulting_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: acquire_transition,
                },
                node_id: Id::new("node_a").unwrap(),
                placement_epoch: acquire_request.placement_epoch,
            },
            size_bytes: 4 * 1024 * 1024,
            durability: VolumeDurability::Strict,
            head: target_head,
            lease_expires_at: acquire_result.lease_expires_at,
            acquire: cats_storage::authority::AuthorizedServingAcquire::Normal {
                request: acquire_request,
                result: acquire_result,
            },
        };
        let identity_path = data_dir.join("identity.json");
        let blank_path = data_dir.join("authorized-serving.json");
        let launch_path = data_dir.join("launch-checkpoint.json");
        let identity_bytes = serde_json::to_vec(&attachment.identity).unwrap();
        let mut blank_attachment = attachment.clone();
        blank_attachment.head = blank_head;
        let blank_bytes = serde_json::to_vec(&blank_attachment).unwrap();
        let launch_bytes = br#"{"launch":"checkpoint"}"#;
        std::fs::write(&identity_path, &identity_bytes).unwrap();
        std::fs::write(&blank_path, &blank_bytes).unwrap();
        std::fs::write(&launch_path, launch_bytes).unwrap();
        for path in [&identity_path, &blank_path, &launch_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let context_digest = Sha256Digest::from_bytes([0x6b; 32]);
        let runtime_scope_id = Id::new("cats-root-fixed.service").unwrap();
        let control_socket_path = managed_root_control_socket(&transition);
        let request = ProvisionRootImageRequest {
            provision_transition_id: transition.clone(),
            volume_id: attachment.identity.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            size_bytes: attachment.size_bytes,
            boot_image_digest: Sha256Digest::from_bytes([0x4a; 32]),
            expected_blank_head: attachment.initial_head().clone(),
            expected_provisioned_head: attachment.head.clone(),
        };
        let artifact = TargetControlAuthorizationArtifact {
            version: ContractVersion::V1,
            provision_transition_id: transition.clone(),
            request,
            provision_context_digest: ProvisionRootAuthorizationContextDigest::new(
                context_digest.clone(),
            ),
            runtime_scope_id: runtime_scope_id.clone(),
            control_socket_path: HostPath::new(control_socket_path.to_str().unwrap()).unwrap(),
            local_state: TargetControlLocalStateIdentity {
                state_directory: stable_directory(&state_dir),
                attachment_directory: stable_directory(&data_dir),
                attachment_identity_file: stable_file(&identity_path, &identity_bytes),
                acquire_authorization_file: stable_file(&blank_path, &blank_bytes),
                launch_checkpoint_file: stable_file(&launch_path, launch_bytes),
            },
            attachment,
        };
        let path = data_dir.join(target_control_authorization_file_name(&transition));
        std::fs::write(
            &path,
            encode_target_control_authorization(&artifact).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        TargetControlFixture {
            _root: root,
            state_dir,
            data_dir,
            path,
            transition,
            context_digest,
            runtime_scope_id,
            control_socket_path,
            artifact,
        }
    }

    fn stable_directory(path: &Path) -> StableDirectoryIdentity {
        let metadata = std::fs::metadata(path).unwrap();
        StableDirectoryIdentity {
            path: HostPath::new(path.to_str().unwrap()).unwrap(),
            device: WireU64::new(metadata.dev()).unwrap(),
            inode: WireU64::new(metadata.ino()).unwrap(),
        }
    }

    fn stable_file(path: &Path, bytes: &[u8]) -> StableFileIdentity {
        let metadata = std::fs::metadata(path).unwrap();
        StableFileIdentity {
            path: HostPath::new(path.to_str().unwrap()).unwrap(),
            device: WireU64::new(metadata.dev()).unwrap(),
            inode: WireU64::new(metadata.ino()).unwrap(),
            length: WireU64::new(bytes.len() as u64).unwrap(),
            content_sha256: Sha256Digest::from_bytes(cats_blockd::format::sha256(bytes)),
        }
    }

    struct ServingHandoffFixture {
        target: TargetControlFixture,
        record_path: PathBuf,
        record_bytes: Vec<u8>,
        predecessor_checkpoint_content_digest: Sha256Digest,
    }

    impl ServingHandoffFixture {
        fn args(&self) -> Args {
            let metadata = std::fs::metadata(&self.record_path).unwrap();
            let digest = Sha256Digest::from_bytes(cats_blockd::format::sha256(&self.record_bytes));
            let device_ownership_token = RandomId128::new(TARGET_DEVICE_OWNERSHIP_TOKEN).unwrap();
            let (control_socket, frontend_socket) =
                managed_serving_sockets(&device_ownership_token);
            Args::try_parse_from(vec![
                "cats-blockd".to_owned(),
                "--volume-id".to_owned(),
                TARGET_VOLUME_ID.to_owned(),
                "--data-dir".to_owned(),
                self.target.data_dir.display().to_string(),
                "--attachment-id".to_owned(),
                TARGET_ATTACHMENT_ID.to_owned(),
                "--object-store-adapter".to_owned(),
                "file".to_owned(),
                "--metadata-store-adapter".to_owned(),
                "postgres".to_owned(),
                "--authorized-serving-handoff-record".to_owned(),
                self.record_path.display().to_string(),
                "--authorized-serving-handoff-predecessor-checkpoint-content-digest".to_owned(),
                self.predecessor_checkpoint_content_digest
                    .as_str()
                    .to_owned(),
                "--authorized-serving-handoff-record-device".to_owned(),
                metadata.dev().to_string(),
                "--authorized-serving-handoff-record-inode".to_owned(),
                metadata.ino().to_string(),
                "--authorized-serving-handoff-record-length".to_owned(),
                metadata.len().to_string(),
                "--authorized-serving-handoff-record-content-sha256".to_owned(),
                digest.as_str().to_owned(),
                "--lease-ttl-ms".to_owned(),
                "60000".to_owned(),
                "--listen-control".to_owned(),
                control_socket.display().to_string(),
                "--listen-unix".to_owned(),
                frontend_socket.display().to_string(),
                "--runtime-scope-id".to_owned(),
                "cats-serving-fixed.service".to_owned(),
                "--process-identity-token".to_owned(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "--device-ownership-token".to_owned(),
                device_ownership_token.as_str().to_owned(),
                "--guest-device-serial".to_owned(),
                "cats-root".to_owned(),
            ])
            .unwrap()
        }

        fn refresh_record_expectation(&self, args: &mut Args) {
            set_record_expectation(args, &self.record_path);
        }
    }

    fn serving_handoff_fixture() -> ServingHandoffFixture {
        let target = target_control_fixture();
        let target_bytes = std::fs::read(&target.path).unwrap();
        let target_metadata = std::fs::metadata(&target.path).unwrap();
        let predecessor_checkpoint_content_digest = Sha256Digest::from_bytes([0x7d; 32]);
        let process_id = WireU64::new(4242).unwrap();
        let ownership_token = RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let executable_path = HostPath::new("/usr/bin/cats-blockd").unwrap();
        let record = ServingHandoffRecord {
            version: ContractVersion::V1,
            checkpoint_content_digest: predecessor_checkpoint_content_digest.clone(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(11).unwrap(),
            spec_digest: Sha256Digest::from_bytes([0xcc; 32]),
            provision_transition_id: target.transition.clone(),
            volume_id: target.artifact.attachment.identity.volume_id.clone(),
            attachment_id: target.artifact.attachment.identity.attachment_id.clone(),
            attachment_epoch: target.artifact.attachment.identity.attachment_epoch,
            acquire_origin: target.artifact.attachment.identity.acquire_origin.clone(),
            node_id: target.artifact.attachment.identity.node_id.clone(),
            placement_epoch: target.artifact.attachment.identity.placement_epoch,
            expected_provisioned_head: target.artifact.attachment.head.clone(),
            expected_control_executable_path: executable_path.clone(),
            target_control_authorization: TargetControlAuthorizationIdentity {
                path: HostPath::new(target.path.to_str().unwrap()).unwrap(),
                device: WireU64::new(target_metadata.dev()).unwrap(),
                inode: WireU64::new(target_metadata.ino()).unwrap(),
                length: WireU64::new(target_metadata.len()).unwrap(),
                content_sha256: Sha256Digest::from_bytes(cats_blockd::format::sha256(
                    &target_bytes,
                )),
                artifact: target.artifact.clone(),
            },
            old_control_process: ServingControlProcessIdentity {
                process_id,
                unit_main_process_id: process_id,
                process_start_time_ticks: WireU64::new(9001).unwrap(),
                executable_path,
                scope_id: target.runtime_scope_id.clone(),
                cgroup_path: HostPath::new(format!(
                    "/sys/fs/cgroup/system.slice/{}",
                    target.runtime_scope_id.as_str()
                ))
                .unwrap(),
                cgroup_process_ids: vec![process_id],
                control_socket_path: HostPath::new(target.control_socket_path.to_str().unwrap())
                    .unwrap(),
                data_directory: HostPath::new(target.data_dir.to_str().unwrap()).unwrap(),
                ownership_token: ownership_token.clone(),
                handshake: ServingControlReloadHandshake {
                    peer_process_id: process_id,
                    identity: target.artifact.attachment.identity.clone(),
                    size_bytes: target.artifact.attachment.size_bytes,
                    durability: Durability::Strict,
                    remote_head: target.artifact.attachment.head.clone(),
                    process_identity_token: ownership_token,
                    control_only: true,
                    guest_io_enabled: false,
                },
            },
        };
        let record_bytes = encode_serving_handoff_record(&record).unwrap();
        let record_path = target.data_dir.join(SERVING_HANDOFF_RECORD_FILE);
        std::fs::write(&record_path, &record_bytes).unwrap();
        std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        ServingHandoffFixture {
            target,
            record_path,
            record_bytes,
            predecessor_checkpoint_content_digest,
        }
    }

    fn serving_config(args: &Args) -> EngineConfig {
        EngineConfig {
            volume_id: args.volume_id.clone().unwrap(),
            data_dir: args.data_dir.clone().unwrap(),
            attachment_id: args.attachment_id.clone().unwrap(),
            lease_ttl_ms: args.lease_ttl_ms,
            durability: cats_blockd::engine::DurabilityMode::Strict,
            max_staged_bytes: args.max_staged_bytes,
            max_staged_packs: args.max_staged_packs,
            max_local_bytes: args.max_local_bytes,
        }
    }

    fn invoke_authorized_serving_effect(
        args: &Args,
        effect_calls: &std::cell::Cell<u64>,
    ) -> Result<AuthorizedServingAttachment> {
        validate_process_mode(args)?;
        let process_identity = runtime_process_identity(args)?;
        read_authorized_serving_input(args, &serving_config(args), process_identity.as_ref())?
            .context("test expected authorized serving input")?
            .apply(|attachment| {
                effect_calls.set(effect_calls.get() + 1);
                Ok(attachment)
            })
    }

    fn set_record_expectation(args: &mut Args, path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        let metadata = std::fs::metadata(path).unwrap();
        args.authorized_serving_handoff_record_device = Some(metadata.dev());
        args.authorized_serving_handoff_record_inode = Some(metadata.ino());
        args.authorized_serving_handoff_record_length = Some(metadata.len());
        args.authorized_serving_handoff_record_content_sha256 = Some(
            Sha256Digest::from_bytes(cats_blockd::format::sha256(&bytes))
                .as_str()
                .to_owned(),
        );
    }

    fn assert_authorized_serving_rejected(args: &Args) {
        let effect_calls = std::cell::Cell::new(0_u64);
        let error = invoke_authorized_serving_effect(args, &effect_calls).unwrap_err();
        assert_eq!(
            effect_calls.get(),
            0,
            "effect ran before rejection: {error:#}"
        );
    }

    fn serving_expectation(args: &Args) -> ServingHandoffRecordExpectation {
        ServingHandoffRecordExpectation {
            path: args.authorized_serving_handoff_record.clone().unwrap(),
            device: args.authorized_serving_handoff_record_device.unwrap(),
            inode: args.authorized_serving_handoff_record_inode.unwrap(),
            length: args.authorized_serving_handoff_record_length.unwrap(),
            content_sha256: Sha256Digest::new(
                args.authorized_serving_handoff_record_content_sha256
                    .clone()
                    .unwrap(),
            )
            .unwrap(),
            predecessor_checkpoint_content_digest: Sha256Digest::new(
                args.authorized_serving_handoff_predecessor_checkpoint_content_digest
                    .clone()
                    .unwrap(),
            )
            .unwrap(),
        }
    }

    fn invoke_handoff_before_effect_revalidation(
        args: &Args,
        engine_calls: &std::cell::Cell<u64>,
        before_revalidation: impl FnOnce(),
    ) -> Result<AuthorizedServingAttachment> {
        validate_process_mode(args)?;
        let process_identity = runtime_process_identity(args)?.unwrap();
        let input = read_serving_handoff_authorization(
            &serving_config(args),
            args,
            &process_identity,
            &serving_expectation(args),
        )
        .map(Box::new)
        .map(AuthorizedServingInput::RootHandoff)?;
        before_revalidation();
        input.apply(|attachment| {
            engine_calls.set(engine_calls.get() + 1);
            Ok(attachment)
        })
    }

    fn replace_with_fifo(path: &Path) {
        std::fs::remove_file(path).unwrap();
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is NUL-terminated and the mode contains only
        // permission bits. The test owns the absent destination path.
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(result, 0, "mkfifo failed: {}", io::Error::last_os_error());
    }

    fn rename_and_recreate_private_file(path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        let backup = path.with_extension("retained-old");
        std::fs::rename(path, backup).unwrap();
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn serving_from_handoff_is_one_distinct_closed_authorization_mode() {
        let fixture = serving_handoff_fixture();
        let args = fixture.args();
        let effect_calls = std::cell::Cell::new(0_u64);
        let attachment = invoke_authorized_serving_effect(&args, &effect_calls).unwrap();
        assert_eq!(effect_calls.get(), 1);
        assert_eq!(attachment, fixture.target.artifact.attachment);

        let direct_conflict = serving_handoff_fixture();
        let mut args = direct_conflict.args();
        args.authorized_serving_spec = Some(PathBuf::from("/runtime/legacy-serving.json"));
        assert_authorized_serving_rejected(&args);

        let control_conflict = serving_handoff_fixture();
        let mut args = control_conflict.args();
        args.control_only = true;
        assert_authorized_serving_rejected(&args);

        let missing_identity = serving_handoff_fixture();
        let mut args = missing_identity.args();
        args.authorized_serving_handoff_record_inode = None;
        assert_authorized_serving_rejected(&args);

        let missing_frontend = serving_handoff_fixture();
        let mut args = missing_frontend.args();
        args.listen_unix = None;
        assert_authorized_serving_rejected(&args);

        let duplicate_frontend = serving_handoff_fixture();
        let mut args = duplicate_frontend.args();
        args.listen_vhost_user = Some(duplicate_frontend.target.data_dir.join("vhost.sock"));
        assert_authorized_serving_rejected(&args);

        let mut target_control_only = parse_target_control_mode(&[]);
        target_control_only.listen_unix = Some(PathBuf::from("/runtime/root-data/block.sock"));
        assert_authorized_serving_rejected(&target_control_only);
    }

    #[test]
    fn serving_from_handoff_rejects_stale_or_unsealed_record_inputs_before_effect() {
        let wrong_predecessor = serving_handoff_fixture();
        let mut args = wrong_predecessor.args();
        args.authorized_serving_handoff_predecessor_checkpoint_content_digest =
            Some(Sha256Digest::from_bytes([0xee; 32]).as_str().to_owned());
        assert_authorized_serving_rejected(&args);

        let wrong_device = serving_handoff_fixture();
        let mut args = wrong_device.args();
        args.authorized_serving_handoff_record_device = Some(
            args.authorized_serving_handoff_record_device
                .unwrap()
                .saturating_add(1),
        );
        assert_authorized_serving_rejected(&args);

        let wrong_inode = serving_handoff_fixture();
        let mut args = wrong_inode.args();
        args.authorized_serving_handoff_record_inode = Some(
            args.authorized_serving_handoff_record_inode
                .unwrap()
                .saturating_add(1),
        );
        assert_authorized_serving_rejected(&args);

        let wrong_length = serving_handoff_fixture();
        let mut args = wrong_length.args();
        args.authorized_serving_handoff_record_length = Some(
            args.authorized_serving_handoff_record_length
                .unwrap()
                .saturating_add(1),
        );
        assert_authorized_serving_rejected(&args);

        let wrong_digest = serving_handoff_fixture();
        let mut args = wrong_digest.args();
        args.authorized_serving_handoff_record_content_sha256 =
            Some(Sha256Digest::from_bytes([0xef; 32]).as_str().to_owned());
        assert_authorized_serving_rejected(&args);

        let blank = serving_handoff_fixture();
        let mut args = blank.args();
        let blank_path = PathBuf::from(
            blank
                .target
                .artifact
                .local_state
                .acquire_authorization_file
                .path
                .as_str(),
        );
        args.authorized_serving_handoff_record = Some(blank_path.clone());
        set_record_expectation(&mut args, &blank_path);
        assert_authorized_serving_rejected(&args);

        let stale_process_token = serving_handoff_fixture();
        let mut args = stale_process_token.args();
        args.process_identity_token = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned());
        assert_authorized_serving_rejected(&args);

        let stale_device_token = serving_handoff_fixture();
        let mut args = stale_device_token.args();
        args.device_ownership_token = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned());
        assert_authorized_serving_rejected(&args);

        let stale_scope = serving_handoff_fixture();
        let mut args = stale_scope.args();
        args.runtime_scope_id = Some(stale_scope.target.runtime_scope_id.as_str().to_owned());
        assert_authorized_serving_rejected(&args);
    }

    #[test]
    fn serving_from_handoff_rejects_noncanonical_unknown_and_oversize_records_before_effect() {
        let noncanonical = serving_handoff_fixture();
        let mut args = noncanonical.args();
        let mut bytes = b" ".to_vec();
        bytes.extend_from_slice(&noncanonical.record_bytes);
        std::fs::write(&noncanonical.record_path, bytes).unwrap();
        noncanonical.refresh_record_expectation(&mut args);
        assert_authorized_serving_rejected(&args);

        let unknown = serving_handoff_fixture();
        let mut args = unknown.args();
        let mut value = serde_json::from_slice::<serde_json::Value>(&unknown.record_bytes).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        std::fs::write(&unknown.record_path, serde_json::to_vec(&value).unwrap()).unwrap();
        unknown.refresh_record_expectation(&mut args);
        assert_authorized_serving_rejected(&args);

        let oversized = serving_handoff_fixture();
        let mut args = oversized.args();
        std::fs::write(
            &oversized.record_path,
            vec![b' '; SERVING_HANDOFF_RECORD_MAX_BYTES + 1],
        )
        .unwrap();
        oversized.refresh_record_expectation(&mut args);
        assert_authorized_serving_rejected(&args);
    }

    #[test]
    fn serving_from_handoff_rejects_unsafe_record_target_and_local_files_without_blocking() {
        let permissive_record = serving_handoff_fixture();
        let args = permissive_record.args();
        std::fs::set_permissions(
            &permissive_record.record_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_authorized_serving_rejected(&args);

        let hardlinked_record = serving_handoff_fixture();
        let args = hardlinked_record.args();
        std::fs::hard_link(
            &hardlinked_record.record_path,
            hardlinked_record.record_path.with_extension("alias"),
        )
        .unwrap();
        assert_authorized_serving_rejected(&args);

        let symlinked_record = serving_handoff_fixture();
        let args = symlinked_record.args();
        let real_record = symlinked_record.record_path.with_extension("real");
        std::fs::rename(&symlinked_record.record_path, &real_record).unwrap();
        symlink(&real_record, &symlinked_record.record_path).unwrap();
        assert_authorized_serving_rejected(&args);

        let fifo_record = serving_handoff_fixture();
        let args = fifo_record.args();
        replace_with_fifo(&fifo_record.record_path);
        let started = Instant::now();
        assert_authorized_serving_rejected(&args);
        assert!(started.elapsed() < Duration::from_secs(2));

        let permissive_target = serving_handoff_fixture();
        let args = permissive_target.args();
        std::fs::set_permissions(
            &permissive_target.target.path,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_authorized_serving_rejected(&args);

        let hardlinked_target = serving_handoff_fixture();
        let args = hardlinked_target.args();
        std::fs::hard_link(
            &hardlinked_target.target.path,
            hardlinked_target.target.path.with_extension("alias"),
        )
        .unwrap();
        assert_authorized_serving_rejected(&args);

        let symlinked_target = serving_handoff_fixture();
        let args = symlinked_target.args();
        let real_target = symlinked_target.target.path.with_extension("real");
        std::fs::rename(&symlinked_target.target.path, &real_target).unwrap();
        symlink(&real_target, &symlinked_target.target.path).unwrap();
        assert_authorized_serving_rejected(&args);

        let fifo_target = serving_handoff_fixture();
        let args = fifo_target.args();
        replace_with_fifo(&fifo_target.target.path);
        let started = Instant::now();
        assert_authorized_serving_rejected(&args);
        assert!(started.elapsed() < Duration::from_secs(2));

        let permissive_directory = serving_handoff_fixture();
        let args = permissive_directory.args();
        std::fs::set_permissions(
            &permissive_directory.target.data_dir,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_authorized_serving_rejected(&args);

        let changed_local_file = serving_handoff_fixture();
        let args = changed_local_file.args();
        std::fs::write(
            changed_local_file
                .target
                .artifact
                .local_state
                .launch_checkpoint_file
                .path
                .as_str(),
            b"changed launch checkpoint",
        )
        .unwrap();
        assert_authorized_serving_rejected(&args);
    }

    #[test]
    fn serving_from_handoff_revalidation_rejects_every_retained_artifact_aba_before_effect() {
        let record_aba = serving_handoff_fixture();
        let args = record_aba.args();
        let effect_calls = std::cell::Cell::new(0_u64);
        let backup = record_aba.record_path.with_extension("old");
        let bytes = record_aba.record_bytes.clone();
        let result = invoke_handoff_before_effect_revalidation(&args, &effect_calls, || {
            std::fs::rename(&record_aba.record_path, &backup).unwrap();
            std::fs::write(&record_aba.record_path, bytes).unwrap();
            std::fs::set_permissions(
                &record_aba.record_path,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        });
        assert!(result.is_err());
        assert_eq!(effect_calls.get(), 0);

        let target_aba = serving_handoff_fixture();
        let args = target_aba.args();
        let effect_calls = std::cell::Cell::new(0_u64);
        let backup = target_aba.target.path.with_extension("old");
        let bytes = std::fs::read(&target_aba.target.path).unwrap();
        let result = invoke_handoff_before_effect_revalidation(&args, &effect_calls, || {
            std::fs::rename(&target_aba.target.path, &backup).unwrap();
            std::fs::write(&target_aba.target.path, bytes).unwrap();
            std::fs::set_permissions(
                &target_aba.target.path,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        });
        assert!(result.is_err());
        assert_eq!(effect_calls.get(), 0);

        let attachment_directory_aba = serving_handoff_fixture();
        let args = attachment_directory_aba.args();
        let effect_calls = std::cell::Cell::new(0_u64);
        let moved = attachment_directory_aba
            .target
            .data_dir
            .with_extension("retained-old");
        let result = invoke_handoff_before_effect_revalidation(&args, &effect_calls, || {
            std::fs::rename(&attachment_directory_aba.target.data_dir, moved).unwrap();
            std::fs::create_dir_all(&attachment_directory_aba.target.data_dir).unwrap();
            std::fs::set_permissions(
                &attachment_directory_aba.target.data_dir,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        });
        assert!(result.is_err());
        assert_eq!(effect_calls.get(), 0);

        let local_paths: [fn(&ServingHandoffFixture) -> PathBuf; 3] = [
            |fixture: &ServingHandoffFixture| {
                PathBuf::from(
                    fixture
                        .target
                        .artifact
                        .local_state
                        .attachment_identity_file
                        .path
                        .as_str(),
                )
            },
            |fixture: &ServingHandoffFixture| {
                PathBuf::from(
                    fixture
                        .target
                        .artifact
                        .local_state
                        .acquire_authorization_file
                        .path
                        .as_str(),
                )
            },
            |fixture: &ServingHandoffFixture| {
                PathBuf::from(
                    fixture
                        .target
                        .artifact
                        .local_state
                        .launch_checkpoint_file
                        .path
                        .as_str(),
                )
            },
        ];
        for local_path in local_paths {
            let local_file_aba = serving_handoff_fixture();
            let args = local_file_aba.args();
            let path = local_path(&local_file_aba);
            let effect_calls = std::cell::Cell::new(0_u64);
            let result = invoke_handoff_before_effect_revalidation(&args, &effect_calls, || {
                rename_and_recreate_private_file(&path);
            });
            assert!(
                result.is_err(),
                "accepted ABA replacement of {}",
                path.display()
            );
            assert_eq!(effect_calls.get(), 0);
        }

        let ancestor_symlink = serving_handoff_fixture();
        let args = ancestor_symlink.args();
        let moved = ancestor_symlink.target.state_dir.with_extension("moved");
        std::fs::rename(&ancestor_symlink.target.state_dir, &moved).unwrap();
        symlink(&moved, &ancestor_symlink.target.state_dir).unwrap();
        assert_authorized_serving_rejected(&args);

        let state_directory_aba = serving_handoff_fixture();
        let args = state_directory_aba.args();
        let effect_calls = std::cell::Cell::new(0_u64);
        let moved = state_directory_aba.target.state_dir.with_extension("moved");
        let result = invoke_handoff_before_effect_revalidation(&args, &effect_calls, || {
            std::fs::rename(&state_directory_aba.target.state_dir, &moved).unwrap();
            std::fs::create_dir_all(&state_directory_aba.target.data_dir).unwrap();
            std::fs::set_permissions(
                &state_directory_aba.target.state_dir,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::set_permissions(
                &state_directory_aba.target.data_dir,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        });
        assert!(result.is_err());
        assert_eq!(effect_calls.get(), 0);
    }

    #[test]
    fn target_control_parser_accepts_only_the_exact_closed_context() {
        let fixture = target_control_fixture();
        let parsed = fixture.parse().unwrap();
        assert_eq!(parsed, fixture.artifact);
        assert_eq!(parsed.request, fixture.artifact.request);

        let wrong_transition = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let mut expected = fixture.expectation();
        expected.provision_transition_id = &wrong_transition;
        assert!(read_target_control_authorization(&fixture.path, &expected).is_err());

        let wrong_digest = Sha256Digest::from_bytes([0x7c; 32]);
        let mut expected = fixture.expectation();
        expected.provision_context_digest = &wrong_digest;
        assert!(read_target_control_authorization(&fixture.path, &expected).is_err());

        let wrong_scope = Id::new("cats-root-foreign.service").unwrap();
        let mut expected = fixture.expectation();
        expected.runtime_scope_id = &wrong_scope;
        assert!(read_target_control_authorization(&fixture.path, &expected).is_err());

        let mut expected = fixture.expectation();
        expected.control_socket_path = Path::new("/tmp/foreign-root-provision.sock");
        assert!(read_target_control_authorization(&fixture.path, &expected).is_err());

        let mut expected = fixture.expectation();
        expected.data_dir = Path::new("/tmp/foreign-root-data");
        assert!(read_target_control_authorization(&fixture.path, &expected).is_err());

        let mut expected = fixture.expectation();
        expected.volume_id = "vol_foreign";
        assert!(read_target_control_authorization(&fixture.path, &expected).is_err());
    }

    #[test]
    fn target_control_parser_rejects_bare_blank_and_malformed_inputs() {
        let bare_blank = target_control_fixture();
        let blank_path = Path::new(
            bare_blank
                .artifact
                .local_state
                .acquire_authorization_file
                .path
                .as_str(),
        );
        assert!(read_target_control_authorization(blank_path, &bare_blank.expectation()).is_err());

        let noncanonical = target_control_fixture();
        let mut bytes = b" ".to_vec();
        bytes.extend_from_slice(&std::fs::read(&noncanonical.path).unwrap());
        noncanonical.write(&bytes);
        assert!(noncanonical.parse().is_err());

        let unknown = target_control_fixture();
        let mut bytes = std::fs::read(&unknown.path).unwrap();
        assert_eq!(bytes.pop(), Some(b'}'));
        bytes.extend_from_slice(br#","unknown":true}"#);
        unknown.write(&bytes);
        assert!(unknown.parse().is_err());

        let oversized = target_control_fixture();
        oversized.write(&vec![b' '; TARGET_CONTROL_AUTHORIZATION_MAX_BYTES + 1]);
        assert!(oversized.parse().is_err());

        let blank_head = target_control_fixture();
        let mut artifact = blank_head.artifact.clone();
        artifact.attachment.head = artifact.attachment.initial_head().clone();
        blank_head.write(&serde_json::to_vec(&artifact).unwrap());
        assert!(blank_head.parse().is_err());

        let wrong_version = target_control_fixture();
        let mut value = serde_json::to_value(&wrong_version.artifact).unwrap();
        value["version"] = serde_json::json!(2);
        wrong_version.write(&serde_json::to_vec(&value).unwrap());
        assert!(wrong_version.parse().is_err());

        let changed_local_file = target_control_fixture();
        std::fs::write(
            changed_local_file
                .artifact
                .local_state
                .launch_checkpoint_file
                .path
                .as_str(),
            b"changed launch checkpoint",
        )
        .unwrap();
        assert!(changed_local_file.parse().is_err());

        let permissive = target_control_fixture();
        std::fs::set_permissions(&permissive.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(permissive.parse().is_err());

        let hardlinked = target_control_fixture();
        std::fs::hard_link(&hardlinked.path, hardlinked.path.with_extension("alias")).unwrap();
        assert!(hardlinked.parse().is_err());

        let symlinked = target_control_fixture();
        let real_path = symlinked.path.with_extension("real");
        std::fs::rename(&symlinked.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &symlinked.path).unwrap();
        assert!(symlinked.parse().is_err());
    }

    #[test]
    fn target_request_drift_is_typed_and_never_reaches_the_engine_effect() {
        let fixture = target_control_fixture();
        let expected = fixture.parse().unwrap().request;
        let mut cases = Vec::new();

        let mut changed = expected.clone();
        changed.provision_transition_id =
            RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        cases.push(changed);
        let mut changed = expected.clone();
        changed.volume_id = Id::new("vol_foreign").unwrap();
        cases.push(changed);
        let mut changed = expected.clone();
        changed.attachment_id = Id::new("att_foreign").unwrap();
        cases.push(changed);
        let mut changed = expected.clone();
        changed.attachment_epoch = FenceEpoch::new(8).unwrap();
        cases.push(changed);
        let mut changed = expected.clone();
        changed.size_bytes += 4096;
        cases.push(changed);
        let mut changed = expected.clone();
        changed.boot_image_digest = Sha256Digest::from_bytes([0x7d; 32]);
        cases.push(changed);
        let mut changed = expected.clone();
        changed.expected_blank_head = changed.expected_provisioned_head.clone();
        cases.push(changed);
        let mut changed = expected.clone();
        changed.expected_provisioned_head.root_hash = Some(Sha256Digest::from_bytes([0x7e; 32]));
        cases.push(changed);

        let effect_calls = std::cell::Cell::new(0_u64);
        for incoming in cases {
            let incoming_wire =
                cats_api::runtime_reconciliation::encode_provision_root_image_request(&incoming)
                    .unwrap();
            let incoming = cats_api::runtime_reconciliation::decode_provision_root_image_request(
                &incoming_wire,
            )
            .unwrap();
            let (prefix, payload) =
                encode_root_provision_response(&incoming, Some(&expected), |_| {
                    effect_calls.set(effect_calls.get() + 1);
                    unreachable!("mismatched target request reached the engine effect")
                })
                .expect("request drift must return a typed response rather than EOF");
            assert_eq!(prefix, b"ERR ");
            let error =
                cats_api::runtime_reconciliation::decode_provision_root_image_error(&payload)
                    .unwrap();
            assert!(matches!(
                error,
                ProvisionRootImageError::DefiniteConflict {
                    provision_transition_id,
                    volume_id,
                    attachment_id,
                    attachment_epoch,
                    problem: ProvisionRootImageDefiniteConflictProblem::RequestBinding,
                } if provision_transition_id == incoming.provision_transition_id
                    && volume_id == incoming.volume_id
                    && attachment_id == incoming.attachment_id
                    && attachment_epoch == incoming.attachment_epoch
            ));
        }
        assert_eq!(effect_calls.get(), 0);
    }

    #[test]
    fn exact_target_request_replays_across_process_attempt_tokens() {
        let fixture = target_control_fixture();
        let expected = fixture.parse().unwrap().request;
        let process_tokens = [
            RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
        ];
        assert_ne!(process_tokens[0], process_tokens[1]);
        let effect_calls = std::cell::Cell::new(0_u64);

        // The attempt token is deliberately not part of the retained request:
        // Runtime may rotate it only after proving the old process absent.
        for _process_token in process_tokens {
            let request_wire =
                cats_api::runtime_reconciliation::encode_provision_root_image_request(&expected)
                    .unwrap();
            let request = cats_api::runtime_reconciliation::decode_provision_root_image_request(
                &request_wire,
            )
            .unwrap();
            let (prefix, payload) =
                encode_root_provision_response(&request, Some(&expected), |request| {
                    effect_calls.set(effect_calls.get() + 1);
                    Ok(ProvisionRootImageResult {
                        provision_transition_id: request.provision_transition_id.clone(),
                        volume_id: request.volume_id.clone(),
                        attachment_id: request.attachment_id.clone(),
                        attachment_epoch: request.attachment_epoch,
                        resulting_head: request.expected_provisioned_head.clone(),
                    })
                })
                .expect("an exact request must return success for either process attempt");
            assert_eq!(prefix, b"OK ");
            let result =
                cats_api::runtime_reconciliation::decode_provision_root_image_result(&payload)
                    .unwrap();
            assert_eq!(
                result.provision_transition_id,
                expected.provision_transition_id
            );
            assert_eq!(result.resulting_head, expected.expected_provisioned_head);
        }
        assert_eq!(effect_calls.get(), 2);
    }

    fn parse_target_control_mode(extra: &[&str]) -> Args {
        let transition = RandomId128::new(TARGET_TRANSITION).unwrap();
        let control_socket = managed_root_control_socket(&transition);
        let mut arguments = vec![
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
            "--authorized-target-control-spec".to_owned(),
            "/runtime/root-data/authorized-target-control-13579bdf2468ace013579bdf2468ace0.json"
                .to_owned(),
            "--provision-transition-id".to_owned(),
            transition.as_str().to_owned(),
            "--provision-root-authorization-context-digest".to_owned(),
            "sha256:6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b".to_owned(),
            "--attachment-epoch".to_owned(),
            "7".to_owned(),
            "--listen-control".to_owned(),
            control_socket.display().to_string(),
            "--runtime-scope-id".to_owned(),
            "cats-root-fixed.service".to_owned(),
            "--process-identity-token".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ];
        arguments.extend(extra.iter().map(|argument| (*argument).to_owned()));
        Args::try_parse_from(arguments).unwrap()
    }

    #[test]
    fn target_control_cli_is_distinct_and_blank_mode_requires_the_transition_owner() {
        let target = parse_target_control_mode(&[]);
        assert!(validate_process_mode(&target).is_ok());
        assert!(validate_runtime_socket_paths(&target).is_ok());

        let transition = RandomId128::new(TARGET_TRANSITION).unwrap();
        let control_socket = managed_root_control_socket(&transition);
        let blank_arguments = |include_transition: bool| {
            let mut arguments = vec![
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
                "--attachment-epoch".to_owned(),
                "7".to_owned(),
                "--listen-control".to_owned(),
                control_socket.display().to_string(),
                "--runtime-scope-id".to_owned(),
                "cats-root-fixed.service".to_owned(),
                "--process-identity-token".to_owned(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            ];
            if include_transition {
                arguments.extend([
                    "--provision-transition-id".to_owned(),
                    transition.as_str().to_owned(),
                ]);
            }
            Args::try_parse_from(arguments).unwrap()
        };
        assert!(validate_process_mode(&blank_arguments(false)).is_err());

        let blank = blank_arguments(true);
        assert!(validate_process_mode(&blank).is_ok());
        assert!(validate_runtime_socket_paths(&blank).is_ok());
        assert_eq!(
            runtime_process_identity(&blank)
                .unwrap()
                .unwrap()
                .guest_device_serial,
            None
        );

        let conflicting = parse_target_control_mode(&[
            "--authorized-control-spec",
            "/runtime/root-data/authorized-serving.json",
        ]);
        assert!(validate_process_mode(&conflicting).is_err());
    }

    #[test]
    fn signed_runtime_socket_paths_are_exactly_owner_mapped_before_any_effect() {
        let transition = RandomId128::new(TARGET_TRANSITION).unwrap();
        let other_transition = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab").unwrap();
        let mut root = parse_target_control_mode(&[]);
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
            "--device-ownership-token",
            "2468ace013579bdf2468ace013579bdf",
            "--guest-device-serial",
            "cats-root",
        ];
        arguments.extend_from_slice(extra);
        Args::try_parse_from(arguments).unwrap()
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
                validate_process_mode(&parse_target(&forbidden)).is_err(),
                "authorized serving unexpectedly accepted {forbidden:?}"
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

        // The same queue values remain untouched in a legacy NBD-only mode.
        let legacy = Args::try_parse_from([
            "cats-blockd",
            "--volume-id",
            TARGET_VOLUME_ID,
            "--data-dir",
            "/runtime/root-data",
            "--attachment-id",
            TARGET_ATTACHMENT_ID,
            "--object-store-adapter",
            "file",
            "--listen-unix",
            "/runtime/block.sock",
            "--vhost-user-queues",
            "0",
            "--vhost-user-queue-size",
            "1",
        ])
        .unwrap();
        assert!(validate_process_mode(&legacy).is_ok());
    }

    #[test]
    fn legacy_vhost_requires_the_exact_guest_serial_before_the_engine_effect() {
        let mut args = Args::try_parse_from([
            "cats-blockd",
            "--volume-id",
            TARGET_VOLUME_ID,
            "--data-dir",
            "/runtime/root-data",
            "--attachment-id",
            TARGET_ATTACHMENT_ID,
            "--object-store-adapter",
            "file",
            "--listen-vhost-user",
            "/runtime/vhost.sock",
        ])
        .unwrap();
        let effect_calls = std::cell::Cell::new(0_u64);
        let result = validate_process_mode(&args).map(|()| {
            effect_calls.set(effect_calls.get() + 1);
        });
        assert!(result.is_err());
        assert_eq!(effect_calls.get(), 0);

        args.guest_device_serial = Some("12345678901234567890".to_owned());
        assert!(validate_process_mode(&args).is_ok());
        args.guest_device_serial = Some("123456789012345678901".to_owned());
        assert!(validate_process_mode(&args).is_err());
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
    fn serving_from_handoff_rejects_noncanonical_active_listener_paths_before_effect() {
        let invalid_paths = [
            PathBuf::from("relative.sock"),
            PathBuf::from("/runtime/./listener.sock"),
            PathBuf::from("/runtime/child/../listener.sock"),
            PathBuf::from("/runtime//listener.sock"),
            PathBuf::from("/runtime/listener.sock/"),
            PathBuf::from(OsString::from_vec(b"/runtime/non-utf8-\xff.sock".to_vec())),
        ];
        for invalid in invalid_paths {
            let control = serving_handoff_fixture();
            let mut args = control.args();
            args.listen_control = Some(invalid.clone());
            assert_authorized_serving_rejected(&args);

            let kernel_nbd = serving_handoff_fixture();
            let mut args = kernel_nbd.args();
            args.listen_unix = Some(invalid.clone());
            assert_authorized_serving_rejected(&args);

            let vhost_user = serving_handoff_fixture();
            let mut args = vhost_user.args();
            args.listen_unix = None;
            args.listen_vhost_user = Some(invalid);
            assert_authorized_serving_rejected(&args);
        }
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

        let mut control = parse_target_control_mode(&[]);
        control.guest_device_serial = Some("cats-root".to_owned());
        assert!(validate_process_mode(&control).is_err());
    }
}

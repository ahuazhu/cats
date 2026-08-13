//! The ChunkStore block engine (spec §5/§6).
//!
//! One engine instance serves exactly one volume under exactly one lease
//! epoch. In strict mode local state is a deletable cache. In relaxed mode,
//! acknowledged generations between the local and remote durability
//! watermarks live in the pending-pack journal and therefore make that Host
//! state authoritative until the background publisher advances the remote
//! watermark.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use cats_api::blockd::{
    DurabilityStatus, DEFAULT_MAX_LOCAL_BYTES, DEFAULT_MAX_STAGED_BYTES, DEFAULT_MAX_STAGED_PACKS,
};
use cats_api::blockd::{PACK_FILE_SUFFIX, PENDING_PACK_DIR};
use cats_api::chunk::{self, CHUNKS_PER_LEAF, CHUNK_SIZE};

use crate::crashpoint;
use crate::format::{
    self, ChunkRef, LeafRef, PackByteRange, PackEntry, PackHeader, BITMAP_HEADER_LEN,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_authorized_serving_record, AsciiText,
    AttachmentLineageIdentity, AuthorityError, AuthorizedServingAttachment, FenceEpoch, Generation,
    Id, RemoteHead, RenewLeaseRequest, Sha256Digest, VolumeDataAuthority, VolumeDurability,
    VolumeHeadCasRequest,
};
use cats_storage::{BlobError, BlobStore, MetaError, MetadataStore, VolumeHead};

mod gc;
mod hydrate;
mod lease;
mod pack;
mod plan;
mod provision;
mod publish;
mod quota;
mod recovery;
mod status;

pub use gc::GcStats;
#[cfg(test)]
use pack::StageWriteFailureGuard;
use pack::{apply_local_entry, merge_dirty_range, DirtyByteRange, StagedPack, StagedQueue};
use plan::{copy_planned_pages, plan_commit, ChunkPlan};
pub use provision::ProvisionRootImageEffectError;
#[cfg(test)]
use publish::is_background_publisher_context;
use publish::{CommitterSignal, EAGER_DRAIN_WATERMARK, MAX_UPLOAD_CONCURRENCY};
use quota::{pack_reservation_upper, punch_hole};
pub use status::DurabilityMode;

/// Maximum transient encoded/decoded/materialized publisher working set for
/// one CAS prefix. Pack boundaries use the provider-neutral formula documented
/// beside `pack_working_set_bytes`; this is not an allocator-size estimate.
const MAX_PUBLISHER_WORKING_SET_BYTES: usize = 256 << 20;

#[cfg(test)]
std::thread_local! {
    static TEST_PUBLISHER_WORKING_SET_BYTES: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

fn publisher_working_set_limit() -> usize {
    #[cfg(test)]
    if let Some(limit) = TEST_PUBLISHER_WORKING_SET_BYTES.get() {
        return limit;
    }
    MAX_PUBLISHER_WORKING_SET_BYTES
}

fn materialized_entry_bytes(entry: &PackEntry) -> Option<usize> {
    if entry.is_discard() {
        return Some(0);
    }
    materialized_page_mask_bytes(entry.page_mask)
}

fn materialized_page_mask_bytes(page_mask: u64) -> Option<usize> {
    (page_mask.count_ones() as usize).checked_mul(cats_api::chunk::DIRTY_PAGE_SIZE as usize)
}

fn materialized_pack_bytes(header: &PackHeader) -> Option<usize> {
    header.entries.iter().try_fold(0usize, |total, entry| {
        total.checked_add(materialized_entry_bytes(entry)?)
    })
}

/// Cross-implementation publisher budget: twice the exact encoded pack bytes,
/// plus its worst-case materialized output, plus one full-chunk scratch image.
/// Every operation is checked before comparing with the fixed cap.
fn pack_working_set_bytes(encoded_bytes: usize, materialized_bytes: usize) -> Option<usize> {
    encoded_bytes
        .checked_mul(2)?
        .checked_add(materialized_bytes)?
        .checked_add(CHUNK_SIZE as usize)
}

#[cfg(test)]
struct PublisherWorkingSetLimitGuard {
    previous: Option<usize>,
}

#[cfg(test)]
impl PublisherWorkingSetLimitGuard {
    fn set(limit: usize) -> Self {
        let previous = TEST_PUBLISHER_WORKING_SET_BYTES.replace(Some(limit));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for PublisherWorkingSetLimitGuard {
    fn drop(&mut self) {
        TEST_PUBLISHER_WORKING_SET_BYTES.set(self.previous);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("i/o out of bounds: offset {offset} len {len} volume size {size}")]
    OutOfBounds { offset: u64, len: u64, size: u64 },
    #[error("attachment is fenced; refusing writes")]
    Fenced,
    #[error("Guest block I/O is disabled for this control-only engine")]
    GuestIoDisabled,
    #[error("volume corrupt: {0}")]
    Corrupt(String),
    #[error("invalid engine configuration: {0}")]
    InvalidConfig(String),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    Meta(#[from] MetaError),
    #[error("local i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EngineError>;

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub volume_id: String,
    pub data_dir: PathBuf,
    pub attachment_id: String,
    /// How long a lease stays valid without a renewal.
    ///
    /// This bounds how long another Host must wait to take a lost Host's
    /// volume, so it stays in the same order as node fencing rather than being
    /// made arbitrarily long. An expiry lapse alone does not end the
    /// attachment: renewal succeeds as long as the row still names this
    /// attachment and epoch, and only a revoke or a competing acquire (both
    /// bump the epoch) fences it for good. Publishes are independently guarded
    /// by the epoch CAS, so a lapse can never let two writers commit.
    pub lease_ttl_ms: i64,
    pub durability: DurabilityMode,
    /// Maximum locally durable, remotely unpublished pack bytes.
    pub max_staged_bytes: u64,
    /// Maximum number of locally durable, remotely unpublished packs.
    pub max_staged_packs: usize,
    /// Maximum physical bytes consumed by cache blocks plus pending packs.
    pub max_local_bytes: u64,
}

impl EngineConfig {
    pub fn new(
        volume_id: impl Into<String>,
        data_dir: impl Into<PathBuf>,
        attachment_id: impl Into<String>,
    ) -> Self {
        Self {
            volume_id: volume_id.into(),
            data_dir: data_dir.into(),
            attachment_id: attachment_id.into(),
            lease_ttl_ms: 15_000,
            durability: DurabilityMode::Strict,
            max_staged_bytes: DEFAULT_MAX_STAGED_BYTES,
            max_staged_packs: DEFAULT_MAX_STAGED_PACKS,
            max_local_bytes: DEFAULT_MAX_LOCAL_BYTES,
        }
    }
}

struct EngineState {
    /// Volatile dirty bitmap; one u64 word per chunk (64 x 64KiB pages).
    dirty: Vec<u64>,
    /// Exact byte overlays since the last local durability barrier. Relaxed
    /// mode persists these ranges verbatim, so a cold-cache WRITE never needs
    /// to read the old page from S3 on the Guest thread.
    dirty_ranges: Vec<Vec<DirtyByteRange>>,
    /// Chunks the Guest discarded in full since the last commit. Kept apart from
    /// `dirty` because the commit publishes nothing for them: the chunk's map
    /// entry becomes a Hole, which is what actually frees the old objects.
    /// Mutually exclusive with a non-zero `dirty` word for the same chunk.
    discarded: HashSet<u64>,
    /// Committed chunk references at `generation`.
    map: Vec<ChunkRef>,
    /// Committed leaf references matching `map`.
    leaf_refs: Vec<LeafRef>,
    /// Complete remote authority tuple matching `generation` and `map`.
    /// Keeping the hashes here lets the control handshake prove the exact
    /// checkpointed root without a second, weaker generation-only protocol.
    remote_head: RemoteHead,
    generation: i64,
    /// Chunk cache holds the full authoritative-local content of the chunk.
    hydrated: Vec<bool>,
    /// The sparse cache has physical data for this chunk, whether complete or
    /// only a Relaxed byte overlay. Clean remote-durable partial cache is just
    /// as evictable as a complete cache chunk.
    cache_present: Vec<bool>,
    /// Chunks currently being hydrated (singleflight).
    hydrating: HashSet<u64>,
    /// Chunks whose dirty byte overlays have been frozen out of `dirty_ranges`
    /// but whose durable pack is not visible in `staged` yet. A cold read must
    /// wait: hydrating from the remote map in this interval would overwrite the
    /// only live cache copy of those bytes.
    freezing: HashSet<u64>,
    /// Monotonic access sequence for clean-cache eviction.
    last_access: Vec<u64>,
    access_clock: u64,
}

pub struct ChunkEngine {
    cfg: EngineConfig,
    size: u64,
    chunk_count: u64,
    blob: Arc<dyn BlobStore>,
    authority: AuthorityBackend,
    cache: File,
    bitmap: Mutex<File>,
    state: Mutex<EngineState>,
    hydration_cv: Condvar,
    /// Writers hold `read`; the flush freeze holds `write` so a pack is an
    /// atomic point-in-time image of the barrier.
    io_gate: RwLock<()>,
    flush_lock: Mutex<()>,
    /// Serializes publishing staged packs. Distinct from `flush_lock` so a
    /// relaxed FLUSH can stage (and ack) while a slow publish is in flight.
    /// Anything that must not race a commit against the object store — GC,
    /// provisioning — takes `flush_lock` first, then this.
    publish_lock: Mutex<()>,
    staged: Mutex<StagedQueue>,
    /// Signaled (with `staged` held) whenever a drain pops a batch, so a FLUSH
    /// blocked on the backpressure cap wakes as soon as there is room.
    staged_space: Condvar,
    /// Serializes physical cache allocation and hole-punch eviction. It is
    /// separate from `staged` so normal status reads never block data I/O.
    cache_space: Mutex<()>,
    local_space: Condvar,
    fenced: AtomicBool,
    epoch: i64,
    /// A root-provision process adopts an existing grant with Guest I/O
    /// disabled. It is intentionally unable to turn into a serving engine;
    /// the reconciler must stop it and start the later frontend phase.
    guest_io_enabled: bool,
    /// Present only for the target-authority serving path. It is the exact
    /// startup grant/lineage echoed by status and bound into every new pack.
    authorized_attachment: Option<AuthorizedServingAttachment>,
    /// Signals the lease-renewal thread to stop, and wakes it so a detach does not
    /// have to wait out its sleep interval.
    stop_renew: Arc<(Mutex<bool>, Condvar)>,
    /// Wakes the background committer: `stop` ends it, `kick` asks for an
    /// immediate drain (a relaxed stage sets it once the queue crosses the
    /// eager watermark, so bursts drain continuously instead of waiting out
    /// the timer).
    committer_signal: Arc<(Mutex<CommitterSignal>, Condvar)>,
    renew_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    gc_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    committer_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Most recent asynchronous publication failure. It is cleared only after a
    /// later batch reaches the remote watermark.
    last_publish_error: Mutex<Option<String>>,
    evicted_cache_chunks: AtomicU64,
    /// A frozen pack between dirty-set capture and insertion into `staged`.
    inflight_staging_bytes: AtomicU64,
    backpressure_waiters: AtomicU64,
}

#[derive(Clone, Copy)]
enum AttachmentMode {
    Granted { expected_epoch: i64 },
    ControlOnly { expected_epoch: i64 },
    AuthorizedControlOnly { expected_epoch: i64 },
    AuthorizedServing { expected_epoch: i64 },
}

enum AuthorityBackend {
    Legacy(Arc<dyn MetadataStore>),
    Target(Arc<dyn VolumeDataAuthority>),
}

impl AuthorityBackend {
    fn load_head(&self, volume_id: &str) -> cats_storage::metadata::Result<VolumeHead> {
        match self {
            Self::Legacy(metadata) => metadata.load_head(volume_id),
            Self::Target(authority) => {
                let volume_id = Id::new(volume_id.to_string()).ok_or_else(|| {
                    MetaError::InvalidArgument("volume_id is not a target authority Id".into())
                })?;
                let record = authority
                    .load_volume(&volume_id)
                    .map_err(|error| map_target_error(error, volume_id.as_str(), 0))?;
                if record.volume_id != volume_id {
                    return Err(MetaError::Backend(
                        "target authority returned a different volume".into(),
                    ));
                }
                Ok(VolumeHead {
                    volume_id: record.volume_id.to_string(),
                    size_bytes: record.size_bytes,
                    generation: i64::try_from(record.head.generation.get()).map_err(|_| {
                        MetaError::Backend("target authority generation exceeds i64".into())
                    })?,
                    root_hash: record
                        .head
                        .root_hash
                        .as_ref()
                        .map(|digest| *digest.as_bytes()),
                    root_object_id: record.head.root_object_id.as_ref().map(ToString::to_string),
                    lease_owner: record.lease_owner.as_ref().map(ToString::to_string),
                    lease_epoch: i64::try_from(record.lease_epoch.get()).map_err(|_| {
                        MetaError::Backend("target authority epoch exceeds i64".into())
                    })?,
                })
            }
        }
    }

    fn renew_lease(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
        ttl_ms: i64,
    ) -> cats_storage::metadata::Result<()> {
        match self {
            Self::Legacy(metadata) => metadata.renew_lease(volume_id, attachment_id, epoch, ttl_ms),
            Self::Target(authority) => {
                let volume_id = target_id(volume_id, "volume_id")?;
                let attachment_id = target_id(attachment_id, "attachment_id")?;
                let expected_epoch = target_epoch(epoch)?;
                let lease_duration_ms = u64::try_from(ttl_ms)
                    .ok()
                    .filter(|duration| *duration > 0)
                    .ok_or_else(|| {
                        MetaError::InvalidArgument("lease duration must be positive".into())
                    })?;
                let result = authority
                    .renew_lease(&RenewLeaseRequest {
                        volume_id: volume_id.clone(),
                        attachment_id: attachment_id.clone(),
                        expected_epoch,
                        lease_duration_ms,
                    })
                    .map_err(|error| map_target_error(error, volume_id.as_str(), 0))?;
                if result.volume_id != volume_id
                    || result.attachment_id != attachment_id
                    || result.epoch != expected_epoch
                {
                    return Err(MetaError::Backend(
                        "target authority returned a mismatched renew result".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn compare_and_swap_head(
        &self,
        volume_id: &str,
        expected_size_bytes: u64,
        expected_head: &RemoteHead,
        new_head: &RemoteHead,
        attachment_id: &str,
        epoch: i64,
    ) -> cats_storage::metadata::Result<i64> {
        match self {
            Self::Legacy(metadata) => {
                let root_hash = new_head
                    .root_hash
                    .as_ref()
                    .ok_or_else(|| MetaError::InvalidArgument("new root hash is absent".into()))?;
                let root_object_id = new_head.root_object_id.as_ref().ok_or_else(|| {
                    MetaError::InvalidArgument("new root object id is absent".into())
                })?;
                metadata.cas_head(
                    volume_id,
                    i64::try_from(expected_head.generation.get()).map_err(|_| {
                        MetaError::InvalidArgument("expected generation exceeds i64".into())
                    })?,
                    i64::try_from(new_head.generation.get()).map_err(|_| {
                        MetaError::InvalidArgument("new generation exceeds i64".into())
                    })?,
                    *root_hash.as_bytes(),
                    root_object_id.as_str(),
                    attachment_id,
                    epoch,
                )
            }
            Self::Target(authority) => {
                let volume_id = target_id(volume_id, "volume_id")?;
                let attachment_id = target_id(attachment_id, "attachment_id")?;
                let expected_epoch = target_epoch(epoch)?;
                let result = authority
                    .compare_and_swap_head(&VolumeHeadCasRequest {
                        volume_id: volume_id.clone(),
                        attachment_id: attachment_id.clone(),
                        expected_epoch,
                        expected_size_bytes,
                        expected_head: expected_head.clone(),
                        new_head: new_head.clone(),
                    })
                    .map_err(|error| {
                        map_target_error(
                            error,
                            volume_id.as_str(),
                            i64::try_from(expected_head.generation.get()).unwrap_or(i64::MAX),
                        )
                    })?;
                if result.volume_id != volume_id
                    || result.attachment_id != attachment_id
                    || result.epoch != expected_epoch
                    || result.resulting_head != *new_head
                {
                    return Err(MetaError::Backend(
                        "target authority returned a mismatched head CAS result".into(),
                    ));
                }
                i64::try_from(result.resulting_head.generation.get()).map_err(|_| {
                    MetaError::Backend("target authority generation exceeds i64".into())
                })
            }
        }
    }
}

fn target_id(value: &str, field: &str) -> cats_storage::metadata::Result<Id> {
    Id::new(value.to_string())
        .ok_or_else(|| MetaError::InvalidArgument(format!("{field} is not a target authority Id")))
}

fn target_epoch(value: i64) -> cats_storage::metadata::Result<FenceEpoch> {
    u64::try_from(value)
        .ok()
        .and_then(FenceEpoch::new)
        .filter(|epoch| epoch.get() > 0)
        .ok_or_else(|| MetaError::InvalidArgument("attachment epoch must be positive".into()))
}

fn map_target_error(error: AuthorityError, volume_id: &str, expected: i64) -> MetaError {
    match error {
        AuthorityError::NotFound => MetaError::NotFound(volume_id.to_string()),
        AuthorityError::OtherWriter | AuthorityError::Fenced | AuthorityError::AdminBusy => {
            MetaError::Fenced
        }
        AuthorityError::HeadConflict => MetaError::CasConflict { expected },
        AuthorityError::InvalidLeaseDuration => {
            MetaError::InvalidArgument("lease duration is invalid".into())
        }
        AuthorityError::BackendUnknown => {
            MetaError::Backend("target volume authority outcome is unknown".into())
        }
        AuthorityError::StaleTransition
        | AuthorityError::EpochExhausted
        | AuthorityError::SnapshotInUse
        | AuthorityError::InvalidAuthorization => MetaError::Backend(
            "target volume authority rejected an operation outside the data-plane port".into(),
        ),
    }
}

fn validate_authorized_serving_config(
    cfg: &EngineConfig,
    attachment: &AuthorizedServingAttachment,
) -> Result<()> {
    validate_authorized_serving_attachment(attachment).map_err(|_| {
        EngineError::InvalidConfig("authorized serving attachment is not internally closed".into())
    })?;
    if cfg.volume_id != attachment.identity.volume_id.as_str()
        || cfg.attachment_id != attachment.identity.attachment_id.as_str()
    {
        return Err(EngineError::InvalidConfig(
            "engine IDs do not match the authorized serving attachment".into(),
        ));
    }
    let lease_ttl_ms = u64::try_from(cfg.lease_ttl_ms).map_err(|_| {
        EngineError::InvalidConfig("lease_ttl_ms must fit the target authority range".into())
    })?;
    if lease_ttl_ms != attachment.lease_duration_ms() {
        return Err(EngineError::InvalidConfig(
            "lease_ttl_ms does not match the exact acquire receipt".into(),
        ));
    }
    let durability_matches = matches!(
        (&cfg.durability, attachment.durability),
        (DurabilityMode::Strict, VolumeDurability::Strict)
            | (DurabilityMode::Relaxed { .. }, VolumeDurability::Relaxed)
    );
    if !durability_matches {
        return Err(EngineError::InvalidConfig(
            "durability mode does not match the immutable Volume".into(),
        ));
    }
    Ok(())
}

fn preflight_authorized_serving(
    cfg: &EngineConfig,
    attachment: &AuthorizedServingAttachment,
    authority: &dyn VolumeDataAuthority,
) -> Result<()> {
    validate_attachment_identity_file(&cfg.data_dir, &attachment.identity)?;
    let initial = authority
        .load_volume(&attachment.identity.volume_id)
        .map_err(|error| {
            EngineError::Meta(map_target_error(
                error,
                attachment.identity.volume_id.as_str(),
                0,
            ))
        })?;
    validate_authorized_serving_record(&initial, attachment, None).map_err(|_| {
        EngineError::Meta(MetaError::Backend(
            "target authority does not match the authorized serving grant".into(),
        ))
    })?;

    let renewed = authority
        .renew_lease(&RenewLeaseRequest {
            volume_id: attachment.identity.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            expected_epoch: attachment.identity.attachment_epoch,
            lease_duration_ms: attachment.lease_duration_ms(),
        })
        .map_err(|error| {
            EngineError::Meta(map_target_error(
                error,
                attachment.identity.volume_id.as_str(),
                0,
            ))
        })?;
    if renewed.volume_id != attachment.identity.volume_id
        || renewed.attachment_id != attachment.identity.attachment_id
        || renewed.epoch != attachment.identity.attachment_epoch
    {
        return Err(EngineError::Meta(MetaError::Backend(
            "target authority returned a mismatched startup renewal".into(),
        )));
    }
    let after_renew = authority
        .load_volume(&attachment.identity.volume_id)
        .map_err(|error| {
            EngineError::Meta(map_target_error(
                error,
                attachment.identity.volume_id.as_str(),
                0,
            ))
        })?;
    validate_authorized_serving_record(&after_renew, attachment, Some(renewed.lease_expires_at))
        .map_err(|_| {
            EngineError::Meta(MetaError::Backend(
                "target authority changed outside the exact startup renewal".into(),
            ))
        })
}

fn validate_attachment_identity_file(
    data_dir: &Path,
    expected: &AttachmentLineageIdentity,
) -> Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    const MAX_IDENTITY_BYTES: u64 = 4_096;
    let path = CString::new(data_dir.as_os_str().as_bytes()).map_err(|_| {
        EngineError::InvalidConfig("data directory contains an interior NUL".into())
    })?;
    // SAFETY: `path` is NUL-terminated and the returned descriptor, when
    // nonnegative, is uniquely adopted by `File` below.
    let directory_fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if directory_fd < 0 {
        return Err(EngineError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `directory_fd` is a newly opened, owned descriptor.
    let directory = unsafe { File::from_raw_fd(directory_fd) };
    let name = c"identity.json";
    // SAFETY: `directory` remains live, `name` is NUL-terminated, and the
    // returned descriptor is uniquely adopted below.
    let identity_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if identity_fd < 0 {
        return Err(EngineError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `identity_fd` is a newly opened, owned descriptor.
    let mut file = unsafe { File::from_raw_fd(identity_fd) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > MAX_IDENTITY_BYTES
    {
        return Err(EngineError::Corrupt(
            "attachment identity is not one bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(EngineError::Corrupt(
            "attachment identity exceeds its byte limit".into(),
        ));
    }
    let identity: AttachmentLineageIdentity = serde_json::from_slice(&bytes)
        .map_err(|_| EngineError::Corrupt("attachment identity is malformed".into()))?;
    let canonical = serde_json::to_vec(&identity)
        .map_err(|_| EngineError::Corrupt("attachment identity cannot serialize".into()))?;
    if canonical != bytes || identity != *expected {
        return Err(EngineError::Corrupt(
            "attachment identity is noncanonical or does not match the grant".into(),
        ));
    }
    Ok(())
}

fn remote_head_from_legacy_projection(head: &VolumeHead) -> Result<RemoteHead> {
    let generation = u64::try_from(head.generation)
        .ok()
        .and_then(Generation::new)
        .ok_or_else(|| EngineError::Corrupt("authority generation is outside V1".into()))?;
    let root_object_id = head
        .root_object_id
        .as_ref()
        .map(|value| {
            AsciiText::new(value.clone())
                .ok_or_else(|| EngineError::Corrupt("authority root object ID is invalid".into()))
        })
        .transpose()?;
    Ok(RemoteHead {
        generation,
        root_hash: head.root_hash.map(Sha256Digest::from_bytes),
        root_object_id,
    })
}

impl ChunkEngine {
    fn validate_pack_lineage(&self, header: &PackHeader) -> Result<()> {
        let epoch = header
            .attachment_epoch_value()
            .map_err(|error| EngineError::Corrupt(error.to_string()))?;
        match &self.authorized_attachment {
            Some(attachment)
                if epoch == self.epoch
                    && header.lease_epoch.is_none()
                    && header.attachment_id.as_deref()
                        == Some(attachment.identity.attachment_id.as_str())
                    && header.attachment_epoch == Some(self.epoch)
                    && header.acquire_origin.as_ref()
                        == Some(&attachment.identity.acquire_origin) =>
            {
                Ok(())
            }
            Some(_) => Err(EngineError::Corrupt(
                "pack lineage does not match identity.json and the current grant".into(),
            )),
            // Preserve the existing legacy restart semantics for the
            // compatibility-only caller: it historically replays its v1
            // journal after reacquiring a later epoch. The signed target path
            // above has no such exception and binds every pack to the exact
            // immutable grant.
            None if header.lease_epoch.is_some()
                && header.attachment_id.is_none()
                && header.attachment_epoch.is_none()
                && header.acquire_origin.is_none() =>
            {
                Ok(())
            }
            None => Err(EngineError::Corrupt(
                "target-v2 pack cannot be adopted without a complete authorized lineage".into(),
            )),
        }
    }

    /// Adopt the caller's exact externally granted owner/epoch tuple through
    /// the compatibility metadata data plane. Unlike the retired attach path,
    /// this performs no acquire, expiry takeover, or epoch mutation.
    #[doc(hidden)]
    pub fn attach_granted_epoch(
        cfg: EngineConfig,
        expected_epoch: i64,
        blob: Arc<dyn BlobStore>,
        meta: Arc<dyn MetadataStore>,
    ) -> Result<Arc<Self>> {
        if expected_epoch <= 0 {
            return Err(EngineError::Meta(MetaError::Fenced));
        }
        Self::open(
            cfg,
            blob,
            AuthorityBackend::Legacy(meta),
            AttachmentMode::Granted { expected_epoch },
            None,
        )
    }

    /// Adopt an already-authorized attachment for the root-provision effect.
    ///
    /// This does not acquire or bump the lease epoch,
    /// replay pending packs, start a publisher, or enable any Guest I/O entry
    /// point. The caller obtained the exact owner/epoch grant before spawning
    /// blockd; every publication remains guarded by that same tuple.
    pub fn attach_control_only(
        cfg: EngineConfig,
        expected_epoch: i64,
        blob: Arc<dyn BlobStore>,
        authority: Arc<dyn VolumeDataAuthority>,
    ) -> Result<Arc<Self>> {
        if expected_epoch <= 0 {
            return Err(EngineError::InvalidConfig(
                "an adopted attachment epoch must be positive".into(),
            ));
        }
        Self::open(
            cfg,
            blob,
            AuthorityBackend::Target(authority),
            AttachmentMode::ControlOnly { expected_epoch },
            None,
        )
    }

    /// Adopt the complete Node-authorized grant for the root-provision effect.
    ///
    /// This is the signed Runtime form of [`Self::attach_control_only`]. It
    /// performs the same strict read/renew/reread grant proof as authorized
    /// serving, retains the complete lineage for status handshakes, and still
    /// exposes no Guest data frontend or publisher.
    pub fn attach_authorized_control_only(
        cfg: EngineConfig,
        attachment: AuthorizedServingAttachment,
        blob: Arc<dyn BlobStore>,
        authority: Arc<dyn VolumeDataAuthority>,
    ) -> Result<Arc<Self>> {
        validate_authorized_serving_config(&cfg, &attachment)?;
        let expected_epoch =
            i64::try_from(attachment.identity.attachment_epoch.get()).map_err(|_| {
                EngineError::InvalidConfig("attachment epoch exceeds the engine range".into())
            })?;
        Self::open(
            cfg,
            blob,
            AuthorityBackend::Target(authority),
            AttachmentMode::AuthorizedControlOnly { expected_epoch },
            Some(attachment),
        )
    }

    /// Adopt an exact target-authority grant as a serving block data plane.
    ///
    /// This path has no acquire capability and never increments an epoch. It
    /// validates the complete Node-supplied grant against a strict authority
    /// read, renews that same owner/epoch, and validates a second strict read
    /// before creating or opening any local block state. Guest frontends are
    /// usable only after recovery completes and this function returns.
    pub fn attach_authorized_serving(
        cfg: EngineConfig,
        attachment: AuthorizedServingAttachment,
        blob: Arc<dyn BlobStore>,
        authority: Arc<dyn VolumeDataAuthority>,
    ) -> Result<Arc<Self>> {
        validate_authorized_serving_config(&cfg, &attachment)?;
        let expected_epoch =
            i64::try_from(attachment.identity.attachment_epoch.get()).map_err(|_| {
                EngineError::InvalidConfig("attachment epoch exceeds the engine range".into())
            })?;
        Self::open(
            cfg,
            blob,
            AuthorityBackend::Target(authority),
            AttachmentMode::AuthorizedServing { expected_epoch },
            Some(attachment),
        )
    }

    fn open(
        cfg: EngineConfig,
        blob: Arc<dyn BlobStore>,
        authority: AuthorityBackend,
        mode: AttachmentMode,
        authorized_attachment: Option<AuthorizedServingAttachment>,
    ) -> Result<Arc<Self>> {
        if cfg.volume_id.is_empty() || cfg.attachment_id.is_empty() {
            return Err(EngineError::InvalidConfig(
                "volume_id and attachment_id must not be empty".into(),
            ));
        }
        if cfg.lease_ttl_ms <= 0 {
            return Err(EngineError::InvalidConfig(
                "lease_ttl_ms must be positive".into(),
            ));
        }
        if cfg.max_staged_bytes == 0 || cfg.max_staged_packs == 0 || cfg.max_local_bytes == 0 {
            return Err(EngineError::InvalidConfig(
                "local cache, staging byte and pack limits must be positive".into(),
            ));
        }
        if cfg.max_local_bytes < CHUNK_SIZE as u64 {
            return Err(EngineError::InvalidConfig(format!(
                "max_local_bytes must be at least one chunk ({CHUNK_SIZE} bytes)"
            )));
        }
        match (&mode, &authority, &authorized_attachment) {
            (
                AttachmentMode::AuthorizedServing { .. }
                | AttachmentMode::AuthorizedControlOnly { .. },
                AuthorityBackend::Target(target),
                Some(attachment),
            ) => preflight_authorized_serving(&cfg, attachment, target.as_ref())?,
            (
                AttachmentMode::AuthorizedServing { .. }
                | AttachmentMode::AuthorizedControlOnly { .. },
                _,
                _,
            ) => {
                return Err(EngineError::InvalidConfig(
                    "authorized target attach requires one complete authority grant".into(),
                ));
            }
            (_, _, Some(_)) => {
                return Err(EngineError::InvalidConfig(
                    "an authorized attachment was supplied to another mode".into(),
                ));
            }
            _ => {}
        }
        let head = authority.load_head(&cfg.volume_id)?;
        let size = head.size_bytes;
        if size == 0 || size % CHUNK_SIZE as u64 != 0 {
            return Err(EngineError::Corrupt(format!(
                "volume size {size} is not a positive multiple of the chunk size"
            )));
        }
        if size > chunk::MAX_VOLUME_BYTES {
            return Err(EngineError::Corrupt(
                "volume exceeds the V1 size limit".into(),
            ));
        }
        let chunk_count = chunk::chunk_count(size);

        let epoch = match (mode, &authority) {
            (AttachmentMode::Granted { expected_epoch }, AuthorityBackend::Legacy(_)) => {
                if head.lease_owner.as_deref() != Some(cfg.attachment_id.as_str())
                    || head.lease_epoch != expected_epoch
                {
                    return Err(EngineError::Meta(MetaError::Fenced));
                }
                expected_epoch
            }
            (AttachmentMode::ControlOnly { expected_epoch }, AuthorityBackend::Target(_)) => {
                if head.lease_owner.is_some() && head.lease_epoch <= 0 {
                    return Err(EngineError::Corrupt(
                        "an owned volume cannot have lease epoch zero".into(),
                    ));
                }
                if head.lease_owner.as_deref() != Some(cfg.attachment_id.as_str())
                    || head.lease_epoch != expected_epoch
                {
                    return Err(EngineError::Meta(MetaError::Fenced));
                }
                expected_epoch
            }
            (
                AttachmentMode::AuthorizedServing { expected_epoch }
                | AttachmentMode::AuthorizedControlOnly { expected_epoch },
                AuthorityBackend::Target(_),
            ) => {
                let attachment = authorized_attachment.as_ref().ok_or_else(|| {
                    EngineError::InvalidConfig(
                        "authorized serving attachment disappeared before open".into(),
                    )
                })?;
                if head.lease_owner.as_deref() != Some(cfg.attachment_id.as_str())
                    || head.lease_epoch != expected_epoch
                    || head.size_bytes != attachment.size_bytes
                    || remote_head_from_legacy_projection(&head)? != attachment.head
                {
                    return Err(EngineError::Meta(MetaError::Fenced));
                }
                expected_epoch
            }
            (AttachmentMode::Granted { .. }, AuthorityBackend::Target(_))
            | (AttachmentMode::ControlOnly { .. }, AuthorityBackend::Legacy(_))
            | (AttachmentMode::AuthorizedControlOnly { .. }, AuthorityBackend::Legacy(_))
            | (AttachmentMode::AuthorizedServing { .. }, AuthorityBackend::Legacy(_)) => {
                return Err(EngineError::InvalidConfig(
                    "attachment mode and authority backend do not match".into(),
                ));
            }
        };
        let control_only = matches!(
            mode,
            AttachmentMode::ControlOnly { .. } | AttachmentMode::AuthorizedControlOnly { .. }
        );

        fs::create_dir_all(cfg.data_dir.join(PENDING_PACK_DIR))?;
        let cache_path = cfg.data_dir.join("cache.data");
        let cache = if control_only {
            Self::open_or_initialize_control_file(
                &cfg.data_dir,
                "cache.data",
                ".cache.data.init",
                |file| file.set_len(size),
            )?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&cache_path)?
        };
        #[cfg(unix)]
        let cache_was_allocated = {
            use std::os::unix::fs::MetadataExt;
            cache.metadata()?.blocks() != 0
        };
        if control_only && cache.metadata()?.len() != size {
            return Err(EngineError::Corrupt(
                "control-only cache length does not match the immutable volume size".into(),
            ));
        }
        if cache.metadata()?.len() != size {
            cache.set_len(size)?;
        }

        let (bitmap_file, dirty) = Self::open_bitmap(&cfg.data_dir, chunk_count, control_only)?;

        let engine = Arc::new(Self {
            size,
            chunk_count,
            blob,
            authority,
            cache,
            bitmap: Mutex::new(bitmap_file),
            state: Mutex::new(EngineState {
                dirty,
                dirty_ranges: vec![Vec::new(); chunk_count as usize],
                map: vec![ChunkRef::Hole; chunk_count as usize],
                leaf_refs: vec![LeafRef::Empty; chunk::leaf_count(size) as usize],
                remote_head: RemoteHead {
                    generation: Generation::new(0).expect("zero is a valid generation"),
                    root_hash: None,
                    root_object_id: None,
                },
                generation: 0,
                discarded: HashSet::new(),
                hydrated: vec![false; chunk_count as usize],
                // A cache that survived a restart may contain any subset of
                // chunks. Marking all present is conservative: quota eviction
                // may punch a few already-sparse ranges, but never misses stale
                // physical blocks that still count against the Host budget.
                cache_present: vec![cache_was_allocated; chunk_count as usize],
                hydrating: HashSet::new(),
                freezing: HashSet::new(),
                last_access: vec![0; chunk_count as usize],
                access_clock: 0,
            }),
            hydration_cv: Condvar::new(),
            io_gate: RwLock::new(()),
            flush_lock: Mutex::new(()),
            publish_lock: Mutex::new(()),
            staged_space: Condvar::new(),
            cache_space: Mutex::new(()),
            local_space: Condvar::new(),
            staged: Mutex::new(StagedQueue {
                packs: std::collections::VecDeque::new(),
                bytes: 0,
                next_base: 0,
            }),
            fenced: AtomicBool::new(false),
            epoch,
            guest_io_enabled: !control_only,
            authorized_attachment,
            stop_renew: Arc::new((Mutex::new(false), Condvar::new())),
            committer_signal: Arc::new((
                Mutex::new(CommitterSignal {
                    stop: false,
                    kick: false,
                }),
                Condvar::new(),
            )),
            renew_thread: Mutex::new(None),
            gc_thread: Mutex::new(None),
            committer_thread: Mutex::new(None),
            last_publish_error: Mutex::new(None),
            evicted_cache_chunks: AtomicU64::new(0),
            inflight_staging_bytes: AtomicU64::new(0),
            backpressure_waiters: AtomicU64::new(0),
            cfg,
        });

        // Renewal starts before recovery, not after: map load and pack replay
        // walk the object store and scale with volume size and commit history,
        // so on a large volume attach alone can outlive the lease TTL (a 60 GiB
        // volume at generation 2112 measured 1.9 s against a 1.5 s TTL, which
        // fenced every start of that Cat). Publishes issued by recovery are
        // still guarded by the epoch CAS.
        engine.start_renew_thread();
        let recovered = engine.load_committed_map().and_then(|()| {
            if control_only {
                Ok(())
            } else {
                engine.recover_pending_packs()
            }
        });
        if let Err(error) = recovered {
            engine.stop_renewal();
            return Err(error);
        }
        // Strict recovery publishes every pack. Relaxed recovery reconstructs
        // the local queue without requiring S3/DB writes, so preserve the
        // recovered local watermark when one exists.
        {
            let mut staged = engine.staged.lock().unwrap();
            if staged.packs.is_empty() {
                staged.next_base = engine.generation();
            }
        }
        if engine.is_fenced() {
            // The lease was revoked or taken while recovery ran. Serving the
            // Guest read-only from here would end at its first write with an
            // I/O error it cannot interpret; fail the attach with the reason.
            engine.stop_renewal();
            return Err(EngineError::Meta(MetaError::Fenced));
        }
        if !control_only {
            engine.start_committer_thread();
            if engine.staged.lock().unwrap().packs.len() > EAGER_DRAIN_WATERMARK {
                engine.kick_committer();
            }
        }
        Ok(engine)
    }

    fn open_bitmap(
        data_dir: &std::path::Path,
        chunk_count: u64,
        preserve_existing: bool,
    ) -> Result<(File, Vec<u64>)> {
        let path = data_dir.join("dirty.bitmap");
        let expected_len = BITMAP_HEADER_LEN + chunk_count * 8;
        if preserve_existing {
            let file = Self::open_or_initialize_control_file(
                data_dir,
                "dirty.bitmap",
                ".dirty.bitmap.init",
                |file| {
                    file.write_all_at(&format::encode_bitmap_header(chunk_count), 0)?;
                    file.set_len(expected_len)
                },
            )?;
            if file.metadata()?.len() != expected_len {
                return Err(EngineError::Corrupt(
                    "control-only dirty bitmap has an unexpected length".into(),
                ));
            }
            return Self::read_bitmap(file, chunk_count);
        }

        let existed = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if existed && file.metadata()?.len() == expected_len {
            return Self::read_bitmap(file, chunk_count);
        } else {
            file.set_len(0)?;
            file.write_all_at(&format::encode_bitmap_header(chunk_count), 0)?;
            file.set_len(expected_len)?;
            file.sync_data()?;
        }
        Ok((file, vec![0u64; chunk_count as usize]))
    }

    fn read_bitmap(file: File, chunk_count: u64) -> Result<(File, Vec<u64>)> {
        let mut header = vec![0u8; BITMAP_HEADER_LEN as usize];
        file.read_exact_at(&mut header, 0)?;
        let stored = format::decode_bitmap_header(&header)
            .map_err(|error| EngineError::Corrupt(error.to_string()))?;
        if stored != chunk_count {
            return Err(EngineError::Corrupt(
                "dirty bitmap chunk count mismatch".into(),
            ));
        }
        let mut words = vec![0u8; (chunk_count * 8) as usize];
        file.read_exact_at(&mut words, BITMAP_HEADER_LEN)?;
        let dirty = words
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
            .collect();
        Ok((file, dirty))
    }

    /// Install one new control-only local file without ever exposing a
    /// partially initialized final name. `hard_link` is the std-only atomic
    /// no-replace primitive on the same filesystem; an existing final file is
    /// opened and validated by the caller, never overwritten.
    fn open_or_initialize_control_file(
        data_dir: &Path,
        final_name: &str,
        temp_name: &str,
        initialize: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<File> {
        let path = data_dir.join(final_name);
        let temp = data_dir.join(temp_name);

        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(EngineError::Corrupt(format!(
                        "control-only {final_name} is not a regular file"
                    )));
                }
                Self::remove_control_init_temp(data_dir, &temp)?;
                return Ok(OpenOptions::new().read(true).write(true).open(path)?);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        Self::remove_control_init_temp(data_dir, &temp)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let initialized = initialize(&file).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = initialized {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }

        match fs::hard_link(&temp, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                let _ = fs::remove_file(&temp);
                return Err(error.into());
            }
        }
        fs::remove_file(&temp)?;
        File::open(data_dir)?.sync_all()?;

        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(EngineError::Corrupt(format!(
                "control-only {final_name} is not a regular file"
            )));
        }
        Ok(OpenOptions::new().read(true).write(true).open(path)?)
    }

    fn remove_control_init_temp(data_dir: &Path, temp: &Path) -> Result<()> {
        match fs::remove_file(temp) {
            Ok(()) => File::open(data_dir)?.sync_all().map_err(Into::into),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn load_committed_map(&self) -> Result<()> {
        let head = self.authority.load_head(&self.cfg.volume_id)?;
        let mut refs = vec![ChunkRef::Hole; self.chunk_count as usize];
        let mut leaf_refs = vec![LeafRef::Empty; chunk::leaf_count(self.size) as usize];

        if let (Some(root_hash), Some(root_object)) = (head.root_hash, &head.root_object_id) {
            let root_bytes = self.blob.get(&chunk::keys::map_node(
                &self.cfg.volume_id,
                root_object_hex(root_object),
            ))?;
            if format::sha256(&root_bytes) != root_hash {
                return Err(EngineError::Corrupt("root node hash mismatch".into()));
            }
            let (vol_size, leaves) = format::decode_root(&root_bytes)
                .map_err(|e| EngineError::Corrupt(e.to_string()))?;
            if vol_size != self.size {
                return Err(EngineError::Corrupt("root volume size mismatch".into()));
            }
            if leaves.len() != leaf_refs.len() {
                return Err(EngineError::Corrupt("root leaf count mismatch".into()));
            }
            for (leaf_idx, leaf) in leaves.iter().enumerate() {
                if let LeafRef::Present { hash, object_id } = leaf {
                    let bytes = self.blob.get(&chunk::keys::map_node(
                        &self.cfg.volume_id,
                        object_id_hex(object_id),
                    ))?;
                    if &format::sha256(&bytes) != hash {
                        return Err(EngineError::Corrupt(format!(
                            "leaf {leaf_idx} hash mismatch"
                        )));
                    }
                    let (first_chunk, entries) = format::decode_leaf(&bytes)
                        .map_err(|e| EngineError::Corrupt(e.to_string()))?;
                    if first_chunk != leaf_idx as u64 * CHUNKS_PER_LEAF as u64 {
                        return Err(EngineError::Corrupt("leaf first_chunk mismatch".into()));
                    }
                    for (i, e) in entries.into_iter().enumerate() {
                        let idx = first_chunk as usize + i;
                        if idx < refs.len() {
                            refs[idx] = e;
                        }
                    }
                }
            }
            leaf_refs = leaves;
        }

        let mut st = self.state.lock().unwrap();
        st.generation = head.generation;
        st.remote_head = remote_head_from_legacy_projection(&head)?;
        st.map = refs;
        st.leaf_refs = leaf_refs;
        // Dirty chunks carry uncommitted local data: their cache content is
        // authoritative and must never be re-hydrated from a committed base.
        for i in 0..self.chunk_count as usize {
            st.hydrated[i] = st.dirty[i] != 0;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Public I/O surface
    // -----------------------------------------------------------------

    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn epoch(&self) -> i64 {
        self.epoch
    }
    pub fn generation(&self) -> i64 {
        self.state.lock().unwrap().generation
    }
    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::SeqCst)
    }
    pub fn volume_id(&self) -> &str {
        &self.cfg.volume_id
    }

    /// Provision an empty volume from a shared base image (ADR-0017).
    ///
    /// This is the golden-root fast path: instead of streaming the image through
    /// the block frontend and committing a private copy of every chunk, the volume
    /// publishes a Map that references the image's already-durable objects. It
    /// moves **zero data bytes** — the only writes are the map nodes and the
    /// commit record — and it goes through the same `publish_map` as any commit,
    /// so fencing, the CAS and the durability point are unchanged.
    ///
    /// Refuses anything but a fresh volume. Provisioning replaces the whole map,
    /// so on a volume that already committed data it would silently discard it,
    /// and on a volume holding unflushed writes the cache would disagree with the
    /// map it just published.
    pub fn provision_from_image(&self, manifest: &format::ImageManifest) -> Result<i64> {
        if !self.guest_io_enabled {
            return Err(EngineError::GuestIoDisabled);
        }
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        let _flush = self.flush_lock.lock().unwrap();
        let _publish = self.publish_lock.lock().unwrap();
        let _gate = self.io_gate.write().unwrap();

        if !self.staged.lock().unwrap().packs.is_empty() {
            // Staged packs are acknowledged writes; publishing an image map
            // over them would discard them just as silently as dirty bits.
            return Err(EngineError::InvalidConfig(format!(
                "volume {} has staged commits; refusing to provision over them",
                self.cfg.volume_id
            )));
        }
        let new_map = {
            let st = self.state.lock().unwrap();
            if st.generation != 0 {
                return Err(EngineError::InvalidConfig(format!(
                    "volume {} is at generation {}; only an empty volume can be \
                     provisioned from an image",
                    self.cfg.volume_id, st.generation
                )));
            }
            if st.dirty.iter().any(|w| *w != 0) {
                return Err(EngineError::InvalidConfig(format!(
                    "volume {} has unflushed writes; refusing to provision over them",
                    self.cfg.volume_id
                )));
            }
            format::image_base_map(manifest, self.size).map_err(|_| {
                EngineError::Corrupt(format!(
                    "image {} does not fit volume {} of {} bytes",
                    manifest.image_id, self.cfg.volume_id, self.size
                ))
            })?
        };

        let chunks: Vec<u64> = manifest.chunks.iter().map(|c| c.chunk_idx).collect();
        let txn = format!("img-{}", &manifest.image_id.as_str()[..16]);
        let mut new_leaves = vec![LeafRef::Empty; chunk::leaf_count(self.size) as usize];
        let (new_gen, remote_head) = self.publish_map(
            &txn,
            0,
            1,
            self.epoch,
            &new_map,
            &mut new_leaves,
            &chunks,
            &chunks,
        )?;

        let mut st = self.state.lock().unwrap();
        st.map = new_map;
        st.leaf_refs = new_leaves;
        st.generation = new_gen;
        st.remote_head = remote_head;
        // Provisioning published a generation without going through the staged
        // queue; the next staged pack chains onto it. (The queue is empty —
        // checked above — so next_base is exactly the committed generation.)
        self.staged.lock().unwrap().next_base = new_gen;
        // Unlike a commit, the cache does not hold this content: the chunks are in
        // the image namespace and get hydrated on first read. A reader that ran
        // before this point cannot have left stale content behind either — at
        // generation 0 every ref was a hole, and a hole is "hydrated" under this
        // same lock without touching the cache file.
        st.hydrated.iter_mut().for_each(|h| *h = false);
        tracing::info!(
            volume = %self.cfg.volume_id,
            image = %manifest.image_id,
            chunks = chunks.len(),
            generation = new_gen,
            "provisioned volume from a shared base image"
        );
        Ok(new_gen)
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if !self.guest_io_enabled {
            return Err(EngineError::GuestIoDisabled);
        }
        self.check_bounds(offset, buf.len() as u64)?;
        if buf.is_empty() {
            return Ok(());
        }
        let first = offset / CHUNK_SIZE as u64;
        let last = (offset + buf.len() as u64 - 1) / CHUNK_SIZE as u64;
        loop {
            self.hydrate_range(first, last)?;
            let _cache_space = self.cache_space.lock().unwrap();
            let _gate = self.io_gate.read().unwrap();
            if !(first..=last).all(|chunk| self.state.lock().unwrap().hydrated[chunk as usize]) {
                continue;
            }
            self.cache.read_exact_at(buf, offset)?;
            self.touch_range(first, last);
            return Ok(());
        }
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> Result<()> {
        if !self.guest_io_enabled {
            return Err(EngineError::GuestIoDisabled);
        }
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        self.check_bounds(offset, data.len() as u64)?;
        if data.is_empty() {
            return Ok(());
        }
        let first_chunk = offset / CHUNK_SIZE as u64;
        let last_chunk = (offset + data.len() as u64 - 1) / CHUNK_SIZE as u64;
        let protected: HashSet<u64> = (first_chunk..=last_chunk).collect();
        let required = self.write_admission_bytes(offset, data.len());
        self.stage_before_write_pressure(required)?;
        if matches!(self.cfg.durability, DurabilityMode::Relaxed { .. }) {
            let _cache_space = self.ensure_local_capacity(required, &protected)?;
            let _gate = self.io_gate.read().unwrap();
            self.cache.write_all_at(data, offset)?;
            self.mark_dirty(offset, data.len() as u64)?;
            self.touch_range(first_chunk, last_chunk);
            return Ok(());
        }
        loop {
            self.hydrate_range(first_chunk, last_chunk)?;
            let _cache_space = self.ensure_local_capacity(required, &protected)?;
            let _gate = self.io_gate.read().unwrap();
            if !(first_chunk..=last_chunk)
                .all(|chunk| self.state.lock().unwrap().hydrated[chunk as usize])
            {
                continue;
            }
            self.cache.write_all_at(data, offset)?;
            self.mark_dirty(offset, data.len() as u64)?;
            self.touch_range(first_chunk, last_chunk);
            return Ok(());
        }
    }

    fn touch_range(&self, first: u64, last: u64) {
        let mut st = self.state.lock().unwrap();
        st.access_clock = st.access_clock.saturating_add(1);
        let access = st.access_clock;
        for chunk in first..=last {
            st.last_access[chunk as usize] = access;
        }
    }

    /// TRIM / WRITE_ZEROES: V1 writes literal zeros (spec §7).
    pub fn write_zeroes(&self, offset: u64, len: u64) -> Result<()> {
        if !self.guest_io_enabled {
            return Err(EngineError::GuestIoDisabled);
        }
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        self.check_bounds(offset, len)?;
        if len == 0 {
            return Ok(());
        }
        // Whole chunks are discarded rather than filled with zeros: the commit
        // publishes nothing for them and their map entry becomes a Hole, so the
        // objects they used to reference stop being reachable and GC can take
        // them. Writing literal zeros instead would publish 4 MiB of zeros per
        // chunk and keep the old objects alive, which is the opposite of what a
        // Guest asking for space back wants.
        let chunk = CHUNK_SIZE as u64;
        let first_whole = offset.div_ceil(chunk);
        let last_whole = (offset + len) / chunk; // exclusive
        let (head_end, tail_start) = if first_whole < last_whole {
            (first_whole * chunk, last_whole * chunk)
        } else {
            // No chunk is covered end to end; it is all partial.
            (offset + len, offset + len)
        };

        self.write_literal_zeroes(offset, head_end - offset)?;
        if first_whole < last_whole {
            self.discard_chunks(first_whole, last_whole)?;
            self.write_literal_zeroes(tail_start, offset + len - tail_start)?;
        }
        Ok(())
    }

    fn write_literal_zeroes(&self, offset: u64, len: u64) -> Result<()> {
        const ZBUF: usize = 1 << 20;
        if len == 0 {
            return Ok(());
        }
        let zeros = vec![0u8; ZBUF.min(len as usize).max(1)];
        let mut done = 0u64;
        while done < len {
            let step = ZBUF.min((len - done) as usize);
            self.write(offset + done, &zeros[..step])?;
            done += step as u64;
        }
        Ok(())
    }

    /// Mark `first..last` as discarded and make the local cache read as zeros.
    ///
    /// The cache still gets zeroed because it outlives the discard and readers
    /// come straight off it; what changes is that nothing is published. A crash
    /// before the next commit simply loses the discard — the old content comes
    /// back, which TRIM allows — and the cache is re-hydrated from the map on the
    /// next attach either way.
    fn discard_chunks(&self, first: u64, last: u64) -> Result<()> {
        let _cache_space = self.cache_space.lock().unwrap();
        let _gate = self.io_gate.write().unwrap();
        let chunk = CHUNK_SIZE as u64;
        for chunk_idx in first..last {
            punch_hole(&self.cache, chunk_idx * chunk, chunk)?;
        }
        let mut st = self.state.lock().unwrap();
        let bitmap = self.bitmap.lock().unwrap();
        for chunk_idx in first..last {
            // A discard supersedes any uncommitted write to the same chunk.
            st.dirty[chunk_idx as usize] = 0;
            st.dirty_ranges[chunk_idx as usize].clear();
            bitmap.write_all_at(&0u64.to_le_bytes(), BITMAP_HEADER_LEN + chunk_idx * 8)?;
            st.discarded.insert(chunk_idx);
            st.hydrated[chunk_idx as usize] = true;
            st.cache_present[chunk_idx as usize] = false;
        }
        bitmap.sync_data()?;
        Ok(())
    }

    /// FLUSH (spec §6): freeze the dirty set into a staged pack, then publish
    /// according to the durability mode (ADR-0022).
    ///
    /// Strict: returns only after this pack — and anything staged before it —
    /// is committed to the object store; the acknowledgment IS the durability
    /// point. Relaxed: returns once the pack is durable on local disk and
    /// leaves publishing to the background committer. DB/S3 failures never get
    /// pulled back into this relaxed fast path. When the finite local staging
    /// reservation is exhausted, a new dirty barrier parks until the publisher
    /// reclaims room; it does not turn a transient remote failure into Guest
    /// `EIO`.
    ///
    /// Returns the generation the acknowledged state is (or, staged, will be)
    /// committed at.
    pub fn flush(&self) -> Result<i64> {
        if !self.guest_io_enabled {
            return Err(EngineError::GuestIoDisabled);
        }
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        let local_generation = {
            let _flush = self.flush_lock.lock().unwrap();
            if matches!(self.cfg.durability, DurabilityMode::Relaxed { .. })
                && self.has_unstaged_changes()
            {
                self.wait_for_staging_space()?;
            }
            self.stage_pack()?;
            self.staged.lock().unwrap().next_base
        };
        match self.cfg.durability {
            DurabilityMode::Strict => self.drain_staged(),
            DurabilityMode::Relaxed { .. } => Ok(local_generation),
        }
    }

    fn has_unstaged_changes(&self) -> bool {
        let st = self.state.lock().unwrap();
        !st.discarded.is_empty() || st.dirty.iter().any(|word| *word != 0)
    }

    fn kick_committer(&self) {
        let (lock, cv) = &*self.committer_signal;
        lock.lock().unwrap().kick = true;
        cv.notify_all();
    }

    fn mark_dirty(&self, offset: u64, len: u64) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let mut changed: Vec<u64> = Vec::new();
        let mut pos = offset;
        let end = offset + len;
        while pos < end {
            let chunk_idx = pos / CHUNK_SIZE as u64;
            let chunk_start = chunk_idx * CHUNK_SIZE as u64;
            let in_chunk = (pos - chunk_start) as u32;
            let span = ((end - pos) as u32).min(CHUNK_SIZE - in_chunk);
            let mask = format::page_mask(in_chunk, span);
            // A write landing on a chunk discarded since the last commit cannot
            // simply cancel the discard: the discard zeroed the rest of the chunk
            // in the cache, and if the commit published only the written pages
            // those zeros would never reach the store and the discarded data
            // would come back on the next cold read. The cache holds the truth,
            // so promote the whole chunk to dirty and publish all of it.
            let discarded = st.discarded.remove(&chunk_idx);
            let mask = if discarded {
                format::full_page_mask()
            } else {
                mask
            };
            let range = if discarded {
                DirtyByteRange {
                    start: 0,
                    end: CHUNK_SIZE,
                }
            } else {
                DirtyByteRange {
                    start: in_chunk,
                    end: in_chunk + span,
                }
            };
            st.cache_present[chunk_idx as usize] = true;
            merge_dirty_range(&mut st.dirty_ranges[chunk_idx as usize], range);
            let word = &mut st.dirty[chunk_idx as usize];
            if *word | mask != *word {
                *word |= mask;
                changed.push(chunk_idx);
            }
            pos += span as u64;
        }
        // Relaxed recovery uses exact immutable packs as its durability oracle
        // and intentionally discards unflushed writes after a process crash.
        // Syncing the coarse bitmap on every ordinary WRITE would add local
        // metadata fsync latency without preserving any promised state.
        if !changed.is_empty() && matches!(self.cfg.durability, DurabilityMode::Strict) {
            let bitmap = self.bitmap.lock().unwrap();
            for c in &changed {
                let word = st.dirty[*c as usize];
                bitmap.write_all_at(&word.to_le_bytes(), BITMAP_HEADER_LEN + c * 8)?;
            }
            bitmap.sync_data()?;
        }
        Ok(())
    }

    fn check_bounds(&self, offset: u64, len: u64) -> Result<()> {
        if offset.checked_add(len).is_none_or(|end| end > self.size) {
            return Err(EngineError::OutOfBounds {
                offset,
                len,
                size: self.size,
            });
        }
        Ok(())
    }
}

impl Drop for ChunkEngine {
    fn drop(&mut self) {
        self.stop_renewal();
    }
}

fn object_id_hex(object_id: &str) -> &str {
    object_id.strip_suffix(".node").unwrap_or(object_id)
}
fn root_object_hex(object_id: &str) -> &str {
    object_id_hex(object_id)
}

/// Deltas a chunk may accumulate before the next commit rewrites its base.
///
/// Every layer is one more object a cold read of that chunk has to fetch, so this
/// trades cold-read round trips against write amplification: with a cap of four,
/// a cold chunk read costs at most five GETs, and a chunk that keeps being
/// written gets a fresh full base at least every fourth commit. A background
/// compactor would let this be raised; there is none yet.
pub const MAX_DELTA_LAYERS: usize = 4;

#[cfg(test)]
mod tests;
